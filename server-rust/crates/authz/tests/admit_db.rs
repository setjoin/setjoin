//! `admit` against a real database (#354 B0): the refusal class for every member,
//! guest and drive scenario, the six fail-closed read faults (never `Ok`) and the
//! evaluation order (credential, token, then live reads).
//!
//! Every case runs under [`scenario`]: it takes the file-wide lock, saves the
//! registry singleton, runs the body under `catch_unwind` and then, panic or not,
//! restores privileges, the registry and any held lock, and sweeps the rows the
//! case created (by its own name prefix, so a killed earlier run is swept too).
use std::future::Future;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use futures_util::FutureExt;
use hyper::header::{HeaderMap, HeaderValue, AUTHORIZATION, COOKIE};
use serde_json::{json, Value};
use setjoin_authz::{
    admit,
    jwks::Jwks,
    legacy_jwt::{sign_hs256, LegacyKeys},
    Authorized, Refusal, Scope,
};
use setjoin_conformance::{
    fixture,
    harness::{BoxError, Db},
};
use setjoin_pg::ScopedExecutor;

const SECRET: &[u8] = b"admit-db-test-secret-32-bytes-long!";
const ISSUER: &str = "mailserver";
/// Per-read bound for this file. Used only when the environment does not set one;
/// the harness would otherwise widen it to 15 s, which makes the timeout cases crawl.
const BOUND_MS: &str = "250";
const PLAIN: &str = "/api/admit-test";
const DRIVE: &str = "/api/drive/admit-test";
const ALL_SCOPES: [Scope; 4] = [Scope::Member, Scope::User, Scope::Drive, Scope::DriveUser];

/// The cases share one database and mutate global state (privileges, the registry).
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn db(case: &str) -> Option<Db> {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if std::env::var_os(setjoin_authz::PRECHECK_TIMEOUT_ENV).is_none() {
            std::env::set_var(setjoin_authz::PRECHECK_TIMEOUT_ENV, BOUND_MS);
        }
    });
    Db::for_case(case)
}

struct Ctx {
    db: Db,
    exec: ScopedExecutor,
    case: String,
    registry: Option<String>,
    revoked: std::sync::Mutex<Vec<String>>,
    held: std::sync::Mutex<Vec<Box<dyn std::any::Any + Send>>>,
}

const TABLES: [&str; 3] = ["mailboxes", "session_revocations", "admin_role_assignments"];
/// The guest read is a SECURITY DEFINER function, so revoking SELECT on `guest_accounts`
/// from the app role would not fault it; the fault revokes EXECUTE on this function instead.
const GUEST_STATUS_FN: &str = "guest_account_status(bigint)";

impl Ctx {
    fn prefix(&self) -> String {
        format!("admitdb-{}", self.case)
    }

    async fn uniq(&self) -> Result<String, BoxError> {
        let c = self.db.connect().await?;
        Ok(
            c.query_one("SELECT replace(gen_random_uuid()::text,'-','')", &[])
                .await?
                .get(0),
        )
    }

    /// A member with a primary mailbox (committed fixture rows).
    async fn member(&self) -> Result<fixture::Account, BoxError> {
        let c = self.db.connect().await?;
        fixture::account(&c, &self.prefix()).await
    }

    async fn domain(&self) -> Result<i64, BoxError> {
        let u = self.uniq().await?;
        let c = self.db.connect().await?;
        Ok(c.query_one(
            "INSERT INTO domains(name,is_local) VALUES($1,true) RETURNING id",
            &[&format!("{}-{u}.test", self.prefix())],
        )
        .await?
        .get(0))
    }

    /// A guest satellite row in the given status (`active`, `disabled`, ...).
    async fn guest(&self, status: &str) -> Result<i64, BoxError> {
        let host = self.domain().await?;
        let u = self.uniq().await?;
        let c = self.db.connect().await?;
        let name = format!("{}.guest.{u}", self.prefix());
        let email = format!("{name}@example.test");
        let user: i64 = c
            .query_one(
                "INSERT INTO users(username,domain_id,email,display_name,password_hash) \
                 VALUES($1,(SELECT id FROM domains WHERE name='guest.invalid'),$2,'admit guest','x') RETURNING id",
                &[&name, &email],
            )
            .await?
            .get(0);
        c.execute(
            "INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status) \
             VALUES($1,$2,'inviter@example.test',$3,$4)",
            &[&user, &email, &host, &status],
        )
        .await?;
        Ok(user)
    }

    /// A user with no mailbox at all.
    async fn no_mailbox_user(&self) -> Result<i64, BoxError> {
        let domain = self.domain().await?;
        let u = self.uniq().await?;
        let c = self.db.connect().await?;
        let name = format!("{}.nomb.{u}", self.prefix());
        Ok(c.query_one(
            "INSERT INTO users(username,domain_id,email,display_name,password_hash) \
             VALUES($1,$2,$3,'admit nomb','x') RETURNING id",
            &[&name, &domain, &format!("{name}@example.test")],
        )
        .await?
        .get(0))
    }

    async fn revocation(
        &self,
        user: i64,
        scope: &str,
        jti: &str,
        family: &str,
    ) -> Result<(), BoxError> {
        let c = self.db.connect().await?;
        c.execute(
            "INSERT INTO session_revocations(user_id,scope,jti,family_id,not_before,reason,expires_at) \
             VALUES($1,$2,NULLIF($3::text,''),NULLIF($4::text,''),now(),'admitdb',now()+interval '1 hour')",
            &[&user, &scope, &jti, &family],
        )
        .await?;
        Ok(())
    }

    async fn clear_revocations(&self, user: i64) -> Result<(), BoxError> {
        let c = self.db.connect().await?;
        c.execute("DELETE FROM session_revocations WHERE user_id=$1", &[&user])
            .await?;
        Ok(())
    }

    /// Make `mailbox_lifecycle_access_allowed` false, whichever lifecycle mode the DB is in.
    async fn suspend(&self, mailbox: i64) -> Result<(), BoxError> {
        let c = self.db.connect().await?;
        c.execute(
            "UPDATE mailboxes SET enabled=false WHERE id=$1",
            &[&mailbox],
        )
        .await?;
        c.execute(
            "UPDATE mailbox_lifecycle SET access_state='suspended' WHERE mailbox_id=$1",
            &[&mailbox],
        )
        .await?;
        let allowed: bool = c
            .query_one("SELECT mailbox_lifecycle_access_allowed($1)", &[&mailbox])
            .await?
            .get(0);
        assert!(!allowed, "fixture did not suspend the mailbox");
        Ok(())
    }

    /// Fault: the app role loses SELECT on `table` (restored by `cleanup`).
    async fn revoke(&self, table: &str) -> Result<(), BoxError> {
        assert!(TABLES.contains(&table));
        assert!(
            self.db.app.is_some(),
            "a privilege fault needs DB_APP_DSN (the setjoin_app credential)"
        );
        let c = self.db.connect().await?;
        let query = "SELECT has_table_privilege('setjoin_app',$1::text,'SELECT')";
        let qualified = format!("public.{table}");
        let before: bool = c.query_one(query, &[&qualified]).await?.get(0);
        assert!(
            before,
            "setjoin_app must hold SELECT on {table} before the fault"
        );
        self.revoked.lock().unwrap().push(table.to_owned());
        c.batch_execute(&format!("REVOKE SELECT ON public.{table} FROM setjoin_app"))
            .await?;
        let after: bool = c.query_one(query, &[&qualified]).await?.get(0);
        assert!(
            !after,
            "REVOKE on {table} did not take effect (granted another way?)"
        );
        Ok(())
    }

    /// Fault: the app role loses EXECUTE on the guest status read (restored by `cleanup`).
    async fn revoke_guest_status(&self) -> Result<(), BoxError> {
        assert!(
            self.db.app.is_some(),
            "a privilege fault needs DB_APP_DSN (the setjoin_app credential)"
        );
        let c = self.db.connect().await?;
        let query = "SELECT has_function_privilege('setjoin_app',$1::text::regprocedure,'EXECUTE')";
        let qualified = format!("public.{GUEST_STATUS_FN}");
        let before: bool = c.query_one(query, &[&qualified]).await?.get(0);
        assert!(
            before,
            "setjoin_app must hold EXECUTE on {GUEST_STATUS_FN} before the fault"
        );
        self.revoked
            .lock()
            .unwrap()
            .push(GUEST_STATUS_FN.to_owned());
        c.batch_execute(&format!(
            "REVOKE EXECUTE ON FUNCTION public.{GUEST_STATUS_FN} FROM setjoin_app"
        ))
        .await?;
        let after: bool = c.query_one(query, &[&qualified]).await?.get(0);
        assert!(!after, "REVOKE on {GUEST_STATUS_FN} did not take effect");
        Ok(())
    }

    /// Fault: the registry singleton is gone (restored by `cleanup`).
    async fn drop_registry(&self) -> Result<(), BoxError> {
        assert!(self.registry.is_some(), "no registry row to drop");
        let c = self.db.connect().await?;
        c.execute(
            "DELETE FROM feature_toggle_registry_state WHERE singleton",
            &[],
        )
        .await?;
        Ok(())
    }

    /// Fault: another transaction holds ACCESS EXCLUSIVE on `table` until `cleanup`.
    async fn lock(&self, table: &str) -> Result<(), BoxError> {
        assert!(TABLES.contains(&table));
        let c = self.db.connect().await?;
        c.batch_execute("BEGIN").await?;
        c.batch_execute(&format!(
            "LOCK TABLE public.{table} IN ACCESS EXCLUSIVE MODE"
        ))
        .await?;
        self.held.lock().unwrap().push(Box::new(c));
        Ok(())
    }

    async fn prepare(&mut self) -> Result<(), BoxError> {
        let c = self.db.connect().await?;
        // A killed earlier run may have left a revoked table: always start granted.
        for table in TABLES {
            c.batch_execute(&format!("GRANT SELECT ON public.{table} TO setjoin_app"))
                .await?;
        }
        c.batch_execute(&format!(
            "GRANT EXECUTE ON FUNCTION public.{GUEST_STATUS_FN} TO setjoin_app"
        ))
        .await?;
        self.registry = c
            .query_opt(
                "SELECT row_to_json(s)::text FROM feature_toggle_registry_state s WHERE singleton",
                &[],
            )
            .await?
            .map(|r| r.get(0));
        if self.registry.is_none() {
            return Err("the feature_toggle_registry_state singleton is missing at start".into());
        }
        drop(c);
        self.sweep().await
    }

    /// Undo faults, then remove this case's rows. Runs on every exit path.
    async fn cleanup(&self) -> Result<(), BoxError> {
        let mut errors: Vec<String> = Vec::new();
        self.held.lock().unwrap().clear();
        match self.db.connect().await {
            Err(e) => errors.push(format!("connect: {e}")),
            Ok(c) => {
                let tables: Vec<String> = self.revoked.lock().unwrap().clone();
                for table in tables {
                    let grant = if table == GUEST_STATUS_FN {
                        format!("GRANT EXECUTE ON FUNCTION public.{table} TO setjoin_app")
                    } else {
                        format!("GRANT SELECT ON public.{table} TO setjoin_app")
                    };
                    if let Err(e) = c.batch_execute(&grant).await {
                        errors.push(format!("regrant {table}: {e}"));
                    }
                }
                if let Some(saved) = &self.registry {
                    if let Err(e) = c
                        .execute(
                            "INSERT INTO feature_toggle_registry_state \
                             SELECT * FROM json_populate_record(NULL::feature_toggle_registry_state,$1::text::json) \
                             ON CONFLICT DO NOTHING",
                            &[saved],
                        )
                        .await
                    {
                        errors.push(format!("registry: {e}"));
                    }
                }
            }
        }
        if let Err(e) = self.sweep().await {
            errors.push(format!("sweep: {e}"));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; ").into())
        }
    }

    /// Delete every row whose name carries this case's prefix. Idempotent.
    async fn sweep(&self) -> Result<(), BoxError> {
        let c = self.db.connect().await?;
        let p = self.prefix();
        let members = format!("{p}@%");
        let others = format!("{p}.%");
        let domains = format!("{p}-%");
        let ids = "SELECT id FROM users WHERE username LIKE $1 OR username LIKE $2";
        for sql in [
            format!("DELETE FROM session_revocations WHERE user_id IN ({ids})"),
            format!("DELETE FROM guest_accounts WHERE user_id IN ({ids})"),
        ] {
            c.execute(sql.as_str(), &[&members, &others]).await?;
        }
        let boxes = c
            .query(
                "SELECT m.id, m.user_id, m.domain_id FROM mailboxes m JOIN users u ON u.id=m.user_id \
                 WHERE u.username LIKE $1",
                &[&members],
            )
            .await?;
        for row in boxes {
            let account = fixture::Account {
                domain: row.get(2),
                user: row.get(1),
                mailbox: row.get(0),
                inbox: 0,
                label: 0,
                two_labels: 0,
                inbox_only: 0,
            };
            fixture::remove(&c, &account).await?;
        }
        c.execute(
            "DELETE FROM users WHERE username LIKE $1 OR username LIKE $2",
            &[&members, &others],
        )
        .await?;
        c.execute("DELETE FROM domains WHERE name LIKE $1", &[&domains])
            .await?;
        Ok(())
    }
}

async fn scenario<F, Fut>(case: &str, body: F)
where
    F: FnOnce(Arc<Ctx>) -> Fut,
    Fut: Future<Output = Result<(), BoxError>>,
{
    let _serial = SERIAL.lock().await;
    let Some(db) = db(case) else { return };
    let exec = ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).expect("executor");
    let mut ctx = Ctx {
        db,
        exec,
        case: case.to_owned(),
        registry: None,
        revoked: Default::default(),
        held: Default::default(),
    };
    ctx.prepare().await.expect("prepare");
    let ctx = Arc::new(ctx);
    let shared = ctx.clone();
    let result = std::panic::AssertUnwindSafe(async move { body(shared).await })
        .catch_unwind()
        .await;
    let cleanup = ctx.cleanup().await;
    match result {
        Err(panic) => {
            if let Err(e) = cleanup {
                eprintln!("cleanup after a panicking case {case} also failed: {e}");
            }
            std::panic::resume_unwind(panic)
        }
        Ok(outcome) => {
            outcome.expect("case body");
            cleanup.expect("cleanup");
        }
    }
}

fn keys() -> Jwks {
    Jwks::with_fetch(Box::new(|| {
        Box::pin(async { Err::<Vec<u8>, String>("HS256 must not fetch JWKS".into()) })
    }))
    .with_legacy_keys(LegacyKeys::new(SECRET, &["authserver-hmac-1"], None).unwrap())
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn jti(uid: i64) -> String {
    format!("admitdb-jti-{uid}")
}

fn family(uid: i64) -> String {
    format!("admitdb-fam-{uid}")
}

fn claims(uid: i64) -> Value {
    json!({"uid":uid,"email":"admitdb@example.test","typ":"access","jti":jti(uid),"fam":family(uid),
        "iss":ISSUER,"aud":["mailserver-gateway"],"iat":now()-10,"exp":now()+600})
}

fn guest_claims(uid: i64) -> Value {
    let mut c = claims(uid);
    c["acct"] = json!("guest");
    c
}

fn without(mut claims: Value, key: &str) -> Value {
    claims.as_object_mut().unwrap().remove(key);
    claims
}

fn with(mut claims: Value, key: &str, value: Value) -> Value {
    claims[key] = value;
    claims
}

fn sign(claims: &Value) -> String {
    sign_hs256(SECRET, &claims.to_string())
}

fn bearer(claims: &Value) -> HeaderMap {
    bearer_token(&sign(claims))
}

fn bearer_token(token: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    h
}

async fn run(
    ctx: &Ctx,
    keys: &Jwks,
    headers: &HeaderMap,
    path: &str,
    scope: Scope,
) -> Result<Authorized, Refusal> {
    admit(&ctx.exec, keys, ISSUER, headers, path, scope).await
}

#[track_caller]
fn refused(result: Result<Authorized, Refusal>, want: Refusal, what: &str) {
    match result {
        Ok(_) => panic!("{what}: admitted, expected {want:?}"),
        Err(got) => assert_eq!(got, want, "{what}"),
    }
}

#[track_caller]
fn admitted(result: Result<Authorized, Refusal>, what: &str) -> Authorized {
    match result {
        Ok(a) => a,
        Err(r) => panic!("{what}: refused with {r:?}, expected Ok"),
    }
}

#[tokio::test]
async fn member_scope_names_every_live_state() {
    scenario("member-scope", |ctx| async move {
        let keys = keys();
        let m = ctx.member().await?;
        let headers = bearer(&claims(m.user));

        let a = admitted(
            run(&ctx, &keys, &headers, PLAIN, Scope::Member).await,
            "member",
        );
        assert_eq!(a.context().user_id(), m.user);
        assert_eq!(a.context().mailbox_id(), m.mailbox);
        assert!(!a.context().is_guest());

        // Revocation: all / jti / family each give Revoked, and clearing it admits again.
        for (name, scope) in [("all", "all"), ("jti", "jti"), ("family", "family")] {
            let (j, f) = match scope {
                "jti" => (jti(m.user), String::new()),
                "family" => (String::new(), family(m.user)),
                _ => (String::new(), String::new()),
            };
            ctx.revocation(m.user, scope, &j, &f).await?;
            refused(
                run(&ctx, &keys, &headers, PLAIN, Scope::Member).await,
                Refusal::Revoked,
                &format!("revocation {name}"),
            );
            ctx.clear_revocations(m.user).await?;
            admitted(
                run(&ctx, &keys, &headers, PLAIN, Scope::Member).await,
                &format!("after clearing {name}"),
            );
        }

        // A member-shaped token whose user has a guest row.
        let g = ctx.guest("active").await?;
        refused(
            run(&ctx, &keys, &bearer(&claims(g)), PLAIN, Scope::Member).await,
            Refusal::Guest,
            "guest row",
        );
        // And the guest claim itself.
        refused(
            run(&ctx, &keys, &bearer(&guest_claims(g)), PLAIN, Scope::Member).await,
            Refusal::Guest,
            "guest claim",
        );

        let nobody = ctx.no_mailbox_user().await?;
        refused(
            run(&ctx, &keys, &bearer(&claims(nobody)), PLAIN, Scope::Member).await,
            Refusal::NoPrimaryMailbox,
            "no mailbox",
        );

        let suspended = ctx.member().await?;
        let h = bearer(&claims(suspended.user));
        admitted(
            run(&ctx, &keys, &h, PLAIN, Scope::Member).await,
            "before suspension",
        );
        ctx.suspend(suspended.mailbox).await?;
        refused(
            run(&ctx, &keys, &h, PLAIN, Scope::Member).await,
            Refusal::MailboxBlocked,
            "suspended lifecycle",
        );
        Ok::<(), BoxError>(())
    })
    .await;
}

#[tokio::test]
async fn user_and_drive_user_scopes_name_guest_states() {
    scenario("user-scope", |ctx| async move {
        let keys = keys();
        let member = ctx.member().await?;
        let active = ctx.guest("active").await?;
        let inactive = ctx.guest("disabled").await?;
        let revoked = ctx.guest("active").await?;
        ctx.revocation(revoked, "all", "", "").await?;

        for (scope, path) in [
            (Scope::User, PLAIN),
            (Scope::DriveUser, PLAIN),
            (Scope::DriveUser, DRIVE),
        ] {
            let at = format!("{scope:?} {path}");
            refused(
                run(&ctx, &keys, &bearer(&guest_claims(inactive)), path, scope).await,
                Refusal::GuestInactive,
                &format!("{at}: inactive guest"),
            );
            let a = admitted(
                run(&ctx, &keys, &bearer(&guest_claims(active)), path, scope).await,
                &format!("{at}: active guest"),
            );
            assert!(
                a.context().is_guest(),
                "{at}: the admitted guest must say so"
            );
            assert_eq!(a.context().user_id(), active);
            refused(
                run(&ctx, &keys, &bearer(&guest_claims(revoked)), path, scope).await,
                Refusal::Revoked,
                &format!("{at}: revoked guest"),
            );
            refused(
                run(
                    &ctx,
                    &keys,
                    &bearer(&with(guest_claims(active), "act", json!(1))),
                    path,
                    scope,
                )
                .await,
                Refusal::Impersonation,
                &format!("{at}: act + guest"),
            );
            refused(
                run(
                    &ctx,
                    &keys,
                    &bearer(&with(claims(member.user), "act", json!(1))),
                    path,
                    scope,
                )
                .await,
                Refusal::Impersonation,
                &format!("{at}: act + member"),
            );
            admitted(
                run(&ctx, &keys, &bearer(&claims(member.user)), path, scope).await,
                &format!("{at}: plain member"),
            );
        }

        // A guest token without iat is refused wherever iat is required: any non-drive path.
        for (scope, path) in [(Scope::User, PLAIN), (Scope::DriveUser, PLAIN)] {
            refused(
                run(
                    &ctx,
                    &keys,
                    &bearer(&without(guest_claims(active), "iat")),
                    path,
                    scope,
                )
                .await,
                Refusal::MissingIssuedAt,
                &format!("{scope:?} {path}: guest without iat"),
            );
        }
        // Malformed (non-integer) iat/act fail the claims-shape check before the accessors run.
        for scope in [Scope::User, Scope::DriveUser] {
            for (label, bad) in [("string", json!("12345")), ("float", json!(1.5))] {
                refused(
                    run(
                        &ctx,
                        &keys,
                        &bearer(&with(guest_claims(active), "iat", bad.clone())),
                        PLAIN,
                        scope,
                    )
                    .await,
                    Refusal::InvalidToken,
                    &format!("{scope:?}: guest with {label} iat"),
                );
            }
            for (label, act) in [
                ("string", json!("admin")),
                ("float", json!(1.5)),
                ("object", json!({})),
            ] {
                refused(
                    run(
                        &ctx,
                        &keys,
                        &bearer(&with(guest_claims(active), "act", act)),
                        PLAIN,
                        scope,
                    )
                    .await,
                    Refusal::InvalidToken,
                    &format!("{scope:?}: guest with {label} act"),
                );
            }
        }
        let drive_string_iat = with(
            with(guest_claims(active), "scp", json!("drive")),
            "iat",
            json!("12345"),
        );
        refused(
            run(
                &ctx,
                &keys,
                &bearer(&drive_string_iat),
                DRIVE,
                Scope::DriveUser,
            )
            .await,
            Refusal::InvalidToken,
            "guest drive token with string iat on a drive path",
        );
        // The drive-scoped guest token without iat is parsed on a drive path and still refused.
        let drive_guest = without(with(guest_claims(active), "scp", json!("drive")), "iat");
        refused(
            run(&ctx, &keys, &bearer(&drive_guest), DRIVE, Scope::DriveUser).await,
            Refusal::MissingIssuedAt,
            "guest drive token without iat on a drive path",
        );
        Ok::<(), BoxError>(())
    })
    .await;
}

#[tokio::test]
async fn zero_uid_cookie_with_basic_is_unserved_never_remapped() {
    scenario("uid-zero", |ctx| async move {
        let keys = keys();
        let token = sign(&claims(0));
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("access_token={token}")).unwrap(),
        );
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic Zm9vOmJhcg=="),
        );
        for scope in ALL_SCOPES {
            for path in [PLAIN, DRIVE] {
                refused(
                    run(&ctx, &keys, &headers, path, scope).await,
                    Refusal::UnservedSubject,
                    &format!("{scope:?} {path}: uid 0 cookie + Basic"),
                );
            }
        }
        // The control: an invalid cookie with the same Basic header does fall through.
        let mut bad = HeaderMap::new();
        bad.insert(COOKIE, HeaderValue::from_static("access_token=not-a-jwt"));
        bad.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Basic Zm9vOmJhcg=="),
        );
        refused(
            run(&ctx, &keys, &bad, PLAIN, Scope::Member).await,
            Refusal::AlternativeCredential,
            "invalid cookie + Basic",
        );
        Ok::<(), BoxError>(())
    })
    .await;
}

// ---- #387 items 1, 2, 6 ----

/// A member `scp:drive` token is admitted only when the scope is a drive scope AND the
/// path is a drive path. Pins the `&&` in `admit`'s `let drive = matches!(scope, Drive | DriveUser)
/// && drive_path(path)` (lib.rs:275 at this head; #387 cites it as :403): a `&&`->`||` mutant
/// would admit the token on a non-drive scope with a drive path, and on a drive scope with a
/// non-drive path.
#[tokio::test]
async fn member_drive_scope_token_is_admitted_only_on_drive_scope_and_drive_path() {
    scenario("member-drive-scp", |ctx| async move {
        let keys = keys();
        let m = ctx.member().await?;
        let headers = bearer(&with(claims(m.user), "scp", json!("drive")));
        for scope in ALL_SCOPES {
            for path in [PLAIN, DRIVE] {
                let drive_scope = matches!(scope, Scope::Drive | Scope::DriveUser);
                let what = format!("{scope:?} {path}: member scp:drive");
                if drive_scope && path == DRIVE {
                    let a = admitted(run(&ctx, &keys, &headers, path, scope).await, &what);
                    assert_eq!(a.context().user_id(), m.user, "{what}");
                } else {
                    refused(
                        run(&ctx, &keys, &headers, path, scope).await,
                        Refusal::InvalidToken,
                        &what,
                    );
                }
            }
        }
        Ok::<(), BoxError>(())
    })
    .await;
}

/// `GuestUnavailable` (the guest status read errors) maps to `Unavailable`, never to an
/// admit or to `GuestInactive`. Both a member and a guest token reach that read on the
/// user scopes; `Scope::Member` never does and stays admitted.
#[tokio::test]
async fn fault_guest_status_unreadable_is_unavailable() {
    scenario("fault-guest-status", |ctx| async move {
        let keys = keys();
        let m = ctx.member().await?;
        let g = ctx.guest("active").await?;
        let member = bearer(&claims(m.user));
        let guest = bearer(&guest_claims(g));
        for scope in [Scope::User, Scope::DriveUser] {
            admitted(
                run(&ctx, &keys, &member, PLAIN, scope).await,
                &format!("{scope:?} member control"),
            );
            admitted(
                run(&ctx, &keys, &guest, PLAIN, scope).await,
                &format!("{scope:?} guest control"),
            );
        }
        ctx.revoke_guest_status().await?;
        for scope in [Scope::User, Scope::DriveUser] {
            for (who, headers) in [("member", &member), ("guest", &guest)] {
                refused(
                    run(&ctx, &keys, headers, PLAIN, scope).await,
                    Refusal::Unavailable,
                    &format!("{scope:?}: {who}, guest status unreadable"),
                );
            }
        }
        admitted(
            run(&ctx, &keys, &member, PLAIN, Scope::Member).await,
            "Member scope does not read guest status",
        );
        Ok::<(), BoxError>(())
    })
    .await;
}

/// A valid cookie with a `Negotiate` Authorization header is an `Ok` from `admit`, as Go's
/// JWT method runs first and succeeds (the `credential` unit test covers only the string).
#[tokio::test]
async fn valid_cookie_with_negotiate_header_is_admitted() {
    scenario("cookie-negotiate", |ctx| async move {
        let keys = keys();
        let m = ctx.member().await?;
        let token = sign(&claims(m.user));
        let mut headers = HeaderMap::new();
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("access_token={token}")).unwrap(),
        );
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Negotiate YII="));
        for scope in [Scope::Member, Scope::User] {
            let a = admitted(
                run(&ctx, &keys, &headers, PLAIN, scope).await,
                &format!("{scope:?}: cookie + Negotiate"),
            );
            assert_eq!(a.context().user_id(), m.user);
        }
        // The control: an invalid cookie with the same header falls through to Negotiate.
        let mut bad = HeaderMap::new();
        bad.insert(COOKIE, HeaderValue::from_static("access_token=not-a-jwt"));
        bad.insert(AUTHORIZATION, HeaderValue::from_static("Negotiate YII="));
        refused(
            run(&ctx, &keys, &bad, PLAIN, Scope::Member).await,
            Refusal::AlternativeCredential,
            "invalid cookie + Negotiate",
        );
        Ok::<(), BoxError>(())
    })
    .await;
}

// ---- T6: each read fault is Unavailable, never Ok ----

#[tokio::test]
async fn fault_mailboxes_unreadable_is_unavailable() {
    scenario("fault-mailboxes", |ctx| async move {
        let keys = keys();
        let m = ctx.member().await?;
        let headers = bearer(&claims(m.user));
        admitted(
            run(&ctx, &keys, &headers, PLAIN, Scope::Member).await,
            "control",
        );
        ctx.revoke("mailboxes").await?;
        refused(
            run(&ctx, &keys, &headers, PLAIN, Scope::Member).await,
            Refusal::Unavailable,
            "mailboxes unreadable",
        );
        Ok::<(), BoxError>(())
    })
    .await;
}

#[tokio::test]
async fn fault_registry_singleton_missing_is_unavailable() {
    scenario("fault-registry", |ctx| async move {
        let keys = keys();
        let m = ctx.member().await?;
        let headers = bearer(&claims(m.user));
        admitted(
            run(&ctx, &keys, &headers, PLAIN, Scope::Member).await,
            "control",
        );
        let g = ctx.guest("active").await?;
        let guest_headers = bearer(&guest_claims(g));
        for scope in [Scope::User, Scope::DriveUser] {
            admitted(
                run(&ctx, &keys, &guest_headers, PLAIN, scope).await,
                &format!("{scope:?} guest control"),
            );
        }
        ctx.drop_registry().await?;
        refused(
            run(&ctx, &keys, &headers, PLAIN, Scope::Member).await,
            Refusal::Unavailable,
            "registry singleton deleted",
        );
        for scope in [Scope::User, Scope::DriveUser] {
            refused(
                run(&ctx, &keys, &guest_headers, PLAIN, scope).await,
                Refusal::Unavailable,
                &format!("{scope:?}: guest, registry singleton deleted"),
            );
        }
        Ok::<(), BoxError>(())
    })
    .await;
}

#[tokio::test]
async fn fault_roles_unreadable_is_unavailable() {
    scenario("fault-roles", |ctx| async move {
        let keys = keys();
        let m = ctx.member().await?;
        let headers = bearer(&with(claims(m.user), "admin", json!(true)));
        admitted(
            run(&ctx, &keys, &headers, PLAIN, Scope::Member).await,
            "control",
        );
        ctx.revoke("admin_role_assignments").await?;
        refused(
            run(&ctx, &keys, &headers, PLAIN, Scope::Member).await,
            Refusal::Unavailable,
            "admin roles unreadable",
        );
        Ok::<(), BoxError>(())
    })
    .await;
}

#[tokio::test]
async fn fault_guest_revocation_unreadable_is_unavailable() {
    scenario("fault-guest-revocation", |ctx| async move {
        let keys = keys();
        let g = ctx.guest("active").await?;
        let headers = bearer(&guest_claims(g));
        for scope in [Scope::User, Scope::DriveUser] {
            admitted(
                run(&ctx, &keys, &headers, PLAIN, scope).await,
                &format!("{scope:?} control"),
            );
        }
        ctx.revoke("session_revocations").await?;
        for scope in [Scope::User, Scope::DriveUser] {
            refused(
                run(&ctx, &keys, &headers, PLAIN, scope).await,
                Refusal::Unavailable,
                &format!("{scope:?}: guest revocation unreadable"),
            );
        }
        // The member path reads the same table inside `caller`.
        let m = ctx.member().await?;
        refused(
            run(&ctx, &keys, &bearer(&claims(m.user)), PLAIN, Scope::Member).await,
            Refusal::Unavailable,
            "member: revocation unreadable",
        );
        Ok::<(), BoxError>(())
    })
    .await;
}

#[tokio::test]
async fn fault_table_lock_past_the_bound_is_unavailable() {
    scenario("fault-lock", |ctx| async move {
        let keys = keys();
        let m = ctx.member().await?;
        let headers = bearer(&claims(m.user));
        admitted(
            run(&ctx, &keys, &headers, PLAIN, Scope::Member).await,
            "control",
        );
        ctx.lock("mailboxes").await?;
        let started = Instant::now();
        refused(
            run(&ctx, &keys, &headers, PLAIN, Scope::Member).await,
            Refusal::Unavailable,
            "mailboxes locked past the bound",
        );
        assert!(
            started.elapsed() < setjoin_authz::precheck_timeout() + Duration::from_secs(5),
            "the bound did not cut the wait: {:?}",
            started.elapsed()
        );
        Ok::<(), BoxError>(())
    })
    .await;
}

#[tokio::test]
async fn fault_guest_revocation_lock_past_the_bound_is_unavailable() {
    scenario("fault-guest-lock", |ctx| async move {
        let keys = keys();
        let g = ctx.guest("active").await?;
        let headers = bearer(&guest_claims(g));
        for scope in [Scope::User, Scope::DriveUser] {
            admitted(
                run(&ctx, &keys, &headers, PLAIN, scope).await,
                &format!("{scope:?} control"),
            );
        }
        ctx.lock("session_revocations").await?;
        for scope in [Scope::User, Scope::DriveUser] {
            let started = Instant::now();
            refused(
                run(&ctx, &keys, &headers, PLAIN, scope).await,
                Refusal::Unavailable,
                &format!("{scope:?}: guest, session_revocations locked past the bound"),
            );
            assert!(
                started.elapsed() < setjoin_authz::precheck_timeout() + Duration::from_secs(5),
                "the bound did not cut the wait: {:?}",
                started.elapsed()
            );
        }
        Ok::<(), BoxError>(())
    })
    .await;
}

/// An ES256-shaped token whose kid no key source knows; only the key lookup can answer.
fn unknown_kid_token() -> String {
    let header = B64.encode(br#"{"alg":"ES256","kid":"admitdb-unknown","typ":"JWT"}"#);
    let payload = B64.encode(claims(1).to_string());
    format!(
        "{header}.{payload}.{}",
        B64.encode([1u8; setjoin_authz::es256::SIGNATURE_LEN])
    )
}

#[tokio::test]
async fn fault_verify_timeout_is_unavailable() {
    scenario("fault-verify", |ctx| async move {
        let headers = bearer_token(&unknown_kid_token());
        for scope in ALL_SCOPES {
            // A fresh source per call: the first attempt arms the 30 s refresh cooldown.
            let sleeping = Jwks::with_fetch(Box::new(|| {
                Box::pin(async {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                    Err::<Vec<u8>, String>("too slow".into())
                })
            }));
            let started = Instant::now();
            refused(
                run(&ctx, &sleeping, &headers, PLAIN, scope).await,
                Refusal::Unavailable,
                &format!("{scope:?}: JWKS fetch past the bound"),
            );
            assert!(
                started.elapsed() < setjoin_authz::precheck_timeout() + Duration::from_secs(5),
                "{scope:?}: the bound did not cut the fetch"
            );
        }
        Ok::<(), BoxError>(())
    })
    .await;
}

// ---- Ordering: credential, then token, then live reads ----

#[tokio::test]
async fn no_credential_and_bad_token_are_decided_before_any_database_read() {
    scenario("ordering", |ctx| async move {
        let keys = keys();
        let m = ctx.member().await?;
        // Everything the live reads touch is gone.
        for table in TABLES {
            ctx.revoke(table).await?;
        }
        ctx.drop_registry().await?;

        for scope in ALL_SCOPES {
            for path in [PLAIN, DRIVE] {
                refused(
                    run(&ctx, &keys, &HeaderMap::new(), path, scope).await,
                    Refusal::NoCredential,
                    &format!("{scope:?} {path}: no headers"),
                );
                refused(
                    run(&ctx, &keys, &bearer_token("not.a.jwt"), path, scope).await,
                    Refusal::InvalidToken,
                    &format!("{scope:?} {path}: garbage bearer"),
                );
            }
        }
        // A valid token is where the database starts to matter.
        refused(
            run(&ctx, &keys, &bearer(&claims(m.user)), PLAIN, Scope::Member).await,
            Refusal::Unavailable,
            "valid member token with the database faulted",
        );
        Ok::<(), BoxError>(())
    })
    .await;
}

#[tokio::test]
async fn unknown_kid_inside_the_cooldown_answers_at_once_without_fetching() {
    scenario("cooldown", |ctx| async move {
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        // The first fetch fails fast (arming the refresh cooldown); any later one would sleep.
        let source = Jwks::with_fetch(Box::new(move || {
            let n = counter.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                if n > 0 {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
                Err::<Vec<u8>, String>("jwks down".into())
            })
        }));
        let headers = bearer_token(&unknown_kid_token());
        refused(
            run(&ctx, &source, &headers, PLAIN, Scope::Member).await,
            Refusal::InvalidToken,
            "first unknown kid",
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        for scope in ALL_SCOPES {
            let started = Instant::now();
            refused(
                run(&ctx, &source, &headers, PLAIN, scope).await,
                Refusal::InvalidToken,
                &format!("{scope:?}: unknown kid in the cooldown"),
            );
            assert!(
                started.elapsed() < setjoin_authz::precheck_timeout(),
                "{scope:?}: the cooldown must answer inside the bound, took {:?}",
                started.elapsed()
            );
        }
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "the cooldown must not fetch"
        );
        Ok::<(), BoxError>(())
    })
    .await;
}
