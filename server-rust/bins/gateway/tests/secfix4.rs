//! Owner-approved security fixes of 2026-11-05 (#510): domain-scoped admin boundaries
//! (#373 alias, #376 AD field policy, #384 scope sets, #393 JIT activation policy, #402
//! departments, #467 conditional-access policies). Each test drives the real Rust command
//! or read with three actors: a domain-scoped admin on a foreign object (refused), on its
//! own domain's object (allowed) and an organization-wide admin (allowed). The mutants
//! (feature `oracle-mutants`, `SETJOIN_SECFIX3_MUTANT`, scripts/test-secfix4-mutants.py)
//! restore frozen Go's behaviour and must make these tests fail.
mod common;
use common::BoxError;
use serde_json::json;
use setjoin_admin_identity::{org_policies, scope_sets, sod};
use setjoin_authz::principals::{AdminPermissionProof, TxFactory, UserPrincipal};
use setjoin_conditional_access::policies as ca;
use setjoin_conformance::{fixture, harness::Db};
use setjoin_pg::{CommandOutcome, Rejection, ScopedExecutor, StatementFailure};
use tokio_postgres::Client;

fn op() -> [u8; 16] {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64;
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&nanos.to_be_bytes());
    out[8..].copy_from_slice(
        &NEXT
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
            .to_be_bytes(),
    );
    out
}

async fn actor(exec: &ScopedExecutor, user: i64) -> Result<setjoin_authz::Authorized, BoxError> {
    let mut headers = hyper::HeaderMap::new();
    headers.insert("host", "mail.test".parse()?);
    headers.insert("origin", "http://mail.test".parse()?);
    let token = common::recovery_token_with(user, json!({"admin": true}));
    headers.insert("authorization", format!("Bearer {token}").parse()?);
    Ok(setjoin_authz::authorize_request(
        exec,
        &common::recovery_keys(),
        "mailserver",
        &headers,
        "http",
    )
    .await
    .ok_or("verified actor")?)
}

/// One role group holding `perms`, assigned to `user`; `domain` makes it domain-scoped and
/// `ou` additionally confines the assignment to a department subtree.
async fn grant(
    owner: &Client,
    user: i64,
    perms: &[&str],
    domain: Option<i64>,
    ou: Option<i64>,
) -> Result<i64, BoxError> {
    let name = format!("secfix4-{user}-{}", perms.join("+"));
    let perms: Vec<String> = perms.iter().map(|p| p.to_string()).collect();
    let role: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,$3) RETURNING id",
            &[&name, &perms, &domain],
        )
        .await?
        .get(0);
    let scope_type = ou.map(|_| "ou");
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,scope_type,scope_id) VALUES($1,$2,$1,$3,$4)",
            &[&user, &role, &scope_type, &ou],
        )
        .await?;
    Ok(role)
}

async fn domain_name(owner: &Client, id: i64) -> Result<String, BoxError> {
    Ok(owner
        .query_one("SELECT name FROM domains WHERE id=$1", &[&id])
        .await?
        .get(0))
}

async fn cleanup_roles(owner: &Client) -> Result<(), BoxError> {
    owner.execute("DELETE FROM admin_role_assignments WHERE role_group_id IN (SELECT id FROM admin_role_groups WHERE name LIKE 'secfix4-%')", &[]).await?;
    owner.execute("DELETE FROM admin_role_activation_policy WHERE role_group_id IN (SELECT id FROM admin_role_groups WHERE name LIKE 'secfix4-%')", &[]).await?;
    owner
        .execute(
            "DELETE FROM admin_role_groups WHERE name LIKE 'secfix4-%'",
            &[],
        )
        .await?;
    Ok(())
}

/// A failed assertion skips the test's own cleanup (it panics), so every test starts by removing
/// whatever an earlier failing run (for example a mutant run) left behind.
async fn purge_leftovers(owner: &Client) -> Result<(), BoxError> {
    owner.batch_execute(
        "BEGIN; SET LOCAL session_replication_role=replica; \
         DELETE FROM session_revocations WHERE reason='secfix4'; \
         DELETE FROM conditional_access_policies WHERE name LIKE 'secfix4-%'; \
         DELETE FROM admin_scope_set_members WHERE set_id IN (SELECT id FROM admin_scope_sets WHERE name LIKE 'secfix4-%'); \
         DELETE FROM admin_scope_sets WHERE name LIKE 'secfix4-%'; \
         DELETE FROM sync_conflicts WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'secfix4-%'); \
         DELETE FROM field_policy WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'secfix4-%'); \
         DELETE FROM aliases WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix4-%') AND NOT is_primary; \
         DELETE FROM departments WHERE name LIKE 'secfix4-%' AND parent_id IS NOT NULL; \
         DELETE FROM departments WHERE name LIKE 'secfix4-%'; \
         CREATE TEMP TABLE secfix4_domains ON COMMIT DROP AS SELECT DISTINCT domain_id FROM users WHERE email LIKE 'secfix4-%'; \
         DELETE FROM admin_role_assignments WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'secfix4-%'); \
         DELETE FROM mailbox_audit_log WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix4-%'); \
         DELETE FROM messages WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix4-%'); \
         DELETE FROM message_trace WHERE details->>'mailbox_id' IN (SELECT id::text FROM mailboxes WHERE email LIKE 'secfix4-%'); \
         DELETE FROM message_tags WHERE tag_id IN (SELECT id FROM tags WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix4-%')); \
         DELETE FROM imap_membership_uid_ledger WHERE tag_id IN (SELECT id FROM tags WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix4-%')); \
         DELETE FROM tags WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix4-%'); \
         DELETE FROM folders WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix4-%'); \
         DELETE FROM jmap_changes_journal WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix4-%'); \
         DELETE FROM jmap_entity_state WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix4-%'); \
         DELETE FROM mailbox_address_claims WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix4-%'); \
         DELETE FROM mailbox_lifecycle WHERE mailbox_id IN (SELECT id FROM mailboxes WHERE email LIKE 'secfix4-%') OR bound_user_id IN (SELECT id FROM users WHERE email LIKE 'secfix4-%'); \
         DELETE FROM sender_control_state WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'secfix4-%'); \
         DELETE FROM user_lifecycle_authorities WHERE user_id IN (SELECT id FROM users WHERE email LIKE 'secfix4-%'); \
         DELETE FROM mailboxes WHERE email LIKE 'secfix4-%'; \
         DELETE FROM users WHERE email LIKE 'secfix4-%'; \
         DELETE FROM domains WHERE id IN (SELECT domain_id FROM secfix4_domains); \
         COMMIT;",
    )
    .await?;
    Ok(())
}

struct World {
    owner: Client,
    exec: ScopedExecutor,
    worker: ScopedExecutor,
    a: fixture::Account,
    b: fixture::Account,
    scoped: fixture::Account,
    global: fixture::Account,
}

async fn world(case: &str) -> Result<Option<World>, BoxError> {
    let Some(db) = Db::for_case(case) else {
        return Ok(None);
    };
    let owner = db.connect().await?;
    cleanup_roles(&owner).await?;
    purge_leftovers(&owner).await?;
    let a = fixture::account(&owner, "secfix4-a").await?;
    let b = fixture::account(&owner, "secfix4-b").await?;
    let scoped = fixture::account(&owner, "secfix4-scoped").await?;
    let global = fixture::account(&owner, "secfix4-global").await?;
    let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 4)?
        .with_audit_keys("22".repeat(32), String::new());
    let worker = common::patient_exec(&db.dsn, 4)?.with_audit_keys("22".repeat(32), String::new());
    Ok(Some(World {
        owner,
        exec,
        worker,
        a,
        b,
        scoped,
        global,
    }))
}

impl World {
    fn factory(&self) -> Result<TxFactory, BoxError> {
        setjoin_gateway::policy_composition::tx_factory_from_executors(
            &self.exec,
            Some(&self.worker),
        )
        .ok_or_else(|| BoxError::from("tx_factory unavailable"))
    }
    async fn user(&self, auth: &setjoin_authz::Authorized) -> Result<UserPrincipal, BoxError> {
        self.factory()?
            .mint_user_from_authorized(auth, "127.0.0.1")
            .await
            .map_err(|e| BoxError::from(e.to_string()))
    }
    async fn admin(
        &self,
        auth: &setjoin_authz::Authorized,
        perms: &[&str],
    ) -> Result<AdminPermissionProof, BoxError> {
        let principal = self
            .factory()?
            .mint_admin_from_authorized(auth, "127.0.0.1")
            .await
            .map_err(|e| BoxError::from(e.to_string()))?;
        principal
            .require_any_permission(perms)
            .map_err(|e| BoxError::from(e.to_string()))
    }
    async fn worker_contract<T, P>(
        &self,
        _proof: &AdminPermissionProof,
        contract: &'static setjoin_pg::SqlContract,
        values: &[&(dyn setjoin_pg::ToSql + Sync)],
        project: P,
    ) -> CommandOutcome<T, StatementFailure>
    where
        P: FnOnce(&[setjoin_pg::Row]) -> Result<T, StatementFailure>,
    {
        let Some(pool) = self.worker.try_worker_pool() else {
            return CommandOutcome::RolledBack(Rejection::Unavailable);
        };
        let mut tx = match pool.begin_read_write().await {
            Ok(tx) => tx,
            Err(e) => return CommandOutcome::RolledBack(Rejection::Statement(e)),
        };
        match tx
            .query_contract(contract, values)
            .await
            .and_then(|rows| project(&rows))
        {
            Ok(value) => match tx.commit().await {
                Ok(()) => CommandOutcome::Committed(value),
                Err(e) => CommandOutcome::RolledBack(Rejection::Statement(e)),
            },
            Err(e) => {
                let _ = tx.rollback().await;
                CommandOutcome::RolledBack(Rejection::Body(e))
            }
        }
    }
    async fn finish(self) -> Result<(), BoxError> {
        cleanup_roles(&self.owner).await?;
        for account in [&self.a, &self.b, &self.scoped, &self.global] {
            fixture::remove(&self.owner, account).await?;
        }
        Ok(())
    }
}

fn refused<T: std::fmt::Debug>(
    outcome: CommandOutcome<T, setjoin_pg::StatementFailure>,
) -> Option<scope_sets::Problem> {
    match outcome {
        CommandOutcome::RolledBack(e) => scope_sets::problem_of(&e).or(Some(scope_sets::Problem {
            status: 500,
            detail: format!("{e:?}"),
        })),
        other => {
            let _ = other;
            None
        }
    }
}

/// The cases share one database, fixed fixtures and reducers: libtest's threads must take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn alias_must_belong_to_the_mailbox_domain_for_a_scoped_admin() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix4-alias").await? else {
        return Ok(());
    };
    let result = async {
        grant(
            &w.owner,
            w.scoped.user,
            &["users.create"],
            Some(w.a.domain),
            None,
        )
        .await?;
        grant(&w.owner, w.global.user, &["users.create"], None, None).await?;
        let (own, foreign) = (
            domain_name(&w.owner, w.a.domain).await?,
            domain_name(&w.owner, w.b.domain).await?,
        );
        let scoped = actor(&w.exec, w.scoped.user).await?;
        let global = actor(&w.exec, w.global.user).await?;
        let factory = w.factory()?;
        let scoped_admin = w.admin(&scoped, &["users.create"]).await?;
        let global_admin = w.admin(&global, &["users.create"]).await?;
        let (mailbox, _) =
            setjoin_admin_identity::primary_mailbox(&factory, &scoped_admin, w.a.domain, w.a.user)
                .await
                .ok_or("primary mailbox")?;
        let enforce_domain = setjoin_admin_identity::alias_enforce_domain();
        async fn add_alias(
            w: &World,
            proof: &AdminPermissionProof,
            mailbox: i64,
            scope: i64,
            email: String,
            enforce_domain: bool,
        ) -> CommandOutcome<Option<i64>, StatementFailure> {
            w.worker_contract(
                proof,
                &setjoin_admin_identity::sql::USER_ALIAS_ADD,
                &[&mailbox, &w.a.user, &scope, &email, &enforce_domain],
                setjoin_admin_identity::parse_alias_id,
            )
            .await
        }
        // Pre-check used by the HTTP route for its 403.
        assert!(
            !setjoin_admin_identity::alias_domain_allowed(
                &factory,
                &scoped_admin,
                w.a.domain,
                mailbox,
                &format!("x@{foreign}")
            )
            .await,
            "foreign address allowed for a scoped admin"
        );
        assert!(
            setjoin_admin_identity::alias_domain_allowed(
                &factory,
                &scoped_admin,
                w.a.domain,
                mailbox,
                &format!("X@{}", own.to_uppercase())
            )
            .await,
            "own-domain address refused"
        );
        // The statement repeats the check (R3): a foreign address inserts nothing.
        let denied = add_alias(
            &w,
            &scoped_admin,
            mailbox,
            w.a.domain,
            format!("claim@{foreign}"),
            enforce_domain,
        )
        .await;
        assert!(
            matches!(denied, CommandOutcome::Committed(None)),
            "scoped admin bound a foreign-domain alias: {denied:?}"
        );
        let n: i64 = w
            .owner
            .query_one(
                "SELECT count(*) FROM aliases WHERE email=$1",
                &[&format!("claim@{foreign}")],
            )
            .await?
            .get(0);
        assert_eq!(n, 0);
        let allowed = add_alias(
            &w,
            &scoped_admin,
            mailbox,
            w.a.domain,
            format!("own@{own}"),
            enforce_domain,
        )
        .await;
        assert!(
            matches!(allowed, CommandOutcome::Committed(Some(_))),
            "own-domain alias refused: {allowed:?}"
        );
        // An organization-wide admin keeps Go's behaviour for the address domain.
        let wide = add_alias(
            &w,
            &global_admin,
            mailbox,
            0,
            format!("wide@{foreign}"),
            enforce_domain,
        )
        .await;
        assert!(
            matches!(wide, CommandOutcome::Committed(Some(_))),
            "global admin refused: {wide:?}"
        );
        Ok::<_, BoxError>(())
    }
    .await;
    w.owner
        .execute(
            "DELETE FROM aliases WHERE email LIKE '%@%' AND mailbox_id=$1 AND NOT is_primary",
            &[&w.a.mailbox],
        )
        .await?;
    w.finish().await?;
    result
}

#[tokio::test]
async fn field_policy_is_readable_only_inside_the_callers_reach() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix4-field-policy").await? else {
        return Ok(());
    };
    let result = async {
        grant(&w.owner, w.scoped.user, &["users.read"], Some(w.a.domain), None).await?;
        grant(&w.owner, w.global.user, &["users.read"], None, None).await?;
        for user in [w.a.user, w.b.user] {
            w.owner.execute("INSERT INTO field_policy(user_id,field,policy) VALUES($1,'title','local_only')", &[&user]).await?;
        }
        let scoped = actor(&w.exec, w.scoped.user).await?;
        let global = actor(&w.exec, w.global.user).await?;
        let factory = w.factory()?;
        let scoped_admin = w.admin(&scoped, &["users.read"]).await?;
        let global_admin = w.admin(&global, &["users.read"]).await?;
        assert!(!setjoin_directory_sync::reach(&factory, &scoped_admin, w.b.user).await.map_err(|e| e.message)?, "foreign user reachable");
        assert!(setjoin_directory_sync::reach(&factory, &scoped_admin, w.a.user).await.map_err(|e| e.message)?);
        assert_eq!(setjoin_directory_sync::field_policy(&factory, &scoped_admin, w.b.user).await.map_err(|e| e.message)?.trim(), "{}", "scoped admin read a foreign user's field policy");
        assert!(setjoin_directory_sync::field_policy(&factory, &scoped_admin, w.a.user).await.map_err(|e| e.message)?.contains("local_only"), "own-domain policy hidden");
        assert!(setjoin_directory_sync::field_policy(&factory, &global_admin, w.b.user).await.map_err(|e| e.message)?.contains("local_only"), "global admin refused");
        Ok::<_, BoxError>(())
    }
    .await;
    w.owner
        .execute(
            "DELETE FROM field_policy WHERE user_id IN ($1,$2)",
            &[&w.a.user, &w.b.user],
        )
        .await?;
    w.finish().await?;
    result
}

#[tokio::test]
async fn scope_sets_are_confined_to_the_callers_domain() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix4-scope-sets").await? else {
        return Ok(());
    };
    let result = async {
        grant(&w.owner, w.scoped.user, &["scope_sets.manage"], Some(w.a.domain), None).await?;
        grant(&w.owner, w.global.user, &["scope_sets.manage"], None, None).await?;
        let mut ids = Vec::new();
        for (name, domain) in [("secfix4-set-a", Some(w.a.domain)), ("secfix4-set-b", Some(w.b.domain)), ("secfix4-set-org", None)] {
            let id: i64 = w.owner.query_one("INSERT INTO admin_scope_sets(name,domain_id,description) VALUES($1,$2,'') RETURNING id", &[&name, &domain]).await?.get(0);
            ids.push(id);
        }
        let (set_a, set_b, set_org) = (ids[0], ids[1], ids[2]);
        let scoped = actor(&w.exec, w.scoped.user).await?;
        let global = actor(&w.exec, w.global.user).await?;
        let factory = w.factory()?;
        let scoped_admin = w.admin(&scoped, &["scope_sets.manage"]).await?;
        let global_admin = w.admin(&global, &["scope_sets.manage"]).await?;
        // Reads.
        let listed = scope_sets::list(&factory, &scoped_admin).await.map_err(|e| e.message)?;
        assert!(listed.contains("secfix4-set-a"), "own set hidden: {listed}");
        assert!(!listed.contains("secfix4-set-b") && !listed.contains("secfix4-set-org"), "foreign sets listed: {listed}");
        for hidden in [set_b, set_org] {
            assert!(scope_sets::get(&factory, &scoped_admin, hidden).await.map_err(|e| e.message)?.is_none(), "foreign set readable");
        }
        assert!(scope_sets::get(&factory, &scoped_admin, set_a).await.map_err(|e| e.message)?.is_some());
        let all = scope_sets::list(&factory, &global_admin).await.map_err(|e| e.message)?;
        assert!(all.contains("secfix4-set-a") && all.contains("secfix4-set-b") && all.contains("secfix4-set-org"));
        assert!(scope_sets::get(&factory, &global_admin, set_b).await.map_err(|e| e.message)?.is_some());

        // Writes: a foreign or domain-less set is as if missing; nothing changes.
        for victim in [set_b, set_org] {
            let update = refused(scope_sets::update(&factory, &scoped_admin, victim, Some("hijacked"), None, "", op()).await);
            assert_eq!(update.map(|p| p.status), Some(404), "scoped admin renamed a foreign set");
            let member = scope_sets::add_member(&factory, &scoped_admin, victim, "user", w.a.user, "", op()).await;
            assert_eq!(refused(member).map(|p| p.status), Some(404), "scoped admin added a member to a foreign set");
            let delete = refused(scope_sets::delete(&factory, &scoped_admin, victim, "", op()).await);
            assert_eq!(delete.map(|p| p.status), Some(404), "scoped admin deleted a foreign set");
        }
        let names: i64 = w.owner.query_one("SELECT count(*) FROM admin_scope_sets WHERE id IN ($1,$2) AND name LIKE 'secfix4-set-%'", &[&set_b, &set_org]).await?.get(0);
        assert_eq!(names, 2, "a foreign set was changed or deleted");
        for (domain, what) in [(Some(w.b.domain), "foreign domain"), (None, "no domain")] {
            let create = refused(scope_sets::create(&factory, &scoped_admin, "secfix4-new", domain, "", "", op()).await);
            assert_eq!(create.map(|p| p.status), Some(403), "scoped admin created a set with {what}");
        }
        let own = scope_sets::create(&factory, &scoped_admin, "secfix4-new", Some(w.a.domain), "", "", op()).await;
        assert!(matches!(own, CommandOutcome::Committed(_)), "own-domain create refused: {own:?}");
        let renamed = scope_sets::update(&factory, &scoped_admin, set_a, Some("secfix4-set-a2"), None, "", op()).await;
        assert!(matches!(renamed, CommandOutcome::Committed(())), "own-domain update refused");

        // The organization-wide admin keeps full control.
        let renamed = scope_sets::update(&factory, &global_admin, set_b, Some("secfix4-set-b2"), None, "", op()).await;
        assert!(matches!(renamed, CommandOutcome::Committed(())), "global update refused");
        let deleted = scope_sets::delete(&factory, &global_admin, set_org, "", op()).await;
        assert!(matches!(deleted, CommandOutcome::Committed(())), "global delete refused");
        Ok::<_, BoxError>(())
    }
    .await;
    w.owner.execute("DELETE FROM admin_scope_set_members WHERE set_id IN (SELECT id FROM admin_scope_sets WHERE name LIKE 'secfix4-%')", &[]).await?;
    w.owner
        .execute(
            "DELETE FROM admin_scope_sets WHERE name LIKE 'secfix4-%'",
            &[],
        )
        .await?;
    w.finish().await?;
    result
}

#[tokio::test]
async fn activation_policy_is_confined_to_roles_the_caller_owns() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix4-jit-policy").await? else {
        return Ok(());
    };
    let result = async {
        grant(&w.owner, w.scoped.user, &["roles.manage"], Some(w.a.domain), None).await?;
        grant(&w.owner, w.global.user, &["roles.manage"], None, None).await?;
        let mut roles = Vec::new();
        for (name, domain) in [("secfix4-role-a", Some(w.a.domain)), ("secfix4-role-b", Some(w.b.domain)), ("secfix4-role-global", None)] {
            let id: i64 = w.owner.query_one("INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,'{users.read}',$2) RETURNING id", &[&name, &domain]).await?.get(0);
            roles.push(id);
        }
        let (role_a, role_b, role_global) = (roles[0], roles[1], roles[2]);
        let scoped = actor(&w.exec, w.scoped.user).await?;
        let global = actor(&w.exec, w.global.user).await?;
        let factory = w.factory()?;
        let scoped_user = w.user(&scoped).await?;
        let global_user = w.user(&global).await?;
        let scoped_admin = w.admin(&scoped, &["roles.manage"]).await?;
        let global_admin = w.admin(&global, &["roles.manage"]).await?;
        assert!(sod::role_in_scope(&factory, &scoped_admin, role_a).await, "own role refused");
        for foreign in [role_b, role_global] {
            assert!(!sod::role_in_scope(&factory, &scoped_admin, foreign).await, "foreign or global role visible to a scoped admin");
            // The write repeats the ownership predicate inside its statement (R3).
            let put = sod::put_policy(&factory, &scoped_user, &scoped_admin, foreign, 30, true, op()).await;
            assert!(matches!(put, CommandOutcome::RolledBack(_)), "scoped admin overwrote a foreign role's activation policy: {put:?}");
        }
        let rows: i64 = w.owner.query_one("SELECT count(*) FROM admin_role_activation_policy WHERE role_group_id IN ($1,$2)", &[&role_b, &role_global]).await?.get(0);
        assert_eq!(rows, 0, "a foreign activation policy was written");
        let put = sod::put_policy(&factory, &scoped_user, &scoped_admin, role_a, 30, true, op()).await;
        assert!(matches!(put, CommandOutcome::Committed(_)), "own role's policy refused: {put:?}");
        let put = sod::put_policy(&factory, &global_user, &global_admin, role_global, 45, false, op()).await;
        assert!(matches!(put, CommandOutcome::Committed(_)), "global admin refused: {put:?}");
        assert!(sod::role_in_scope(&factory, &global_admin, role_global).await);
        Ok::<_, BoxError>(())
    }
    .await;
    w.finish().await?;
    result
}

#[tokio::test]
async fn departments_are_organization_wide_objects() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix4-departments").await? else {
        return Ok(());
    };
    let ou_admin = fixture::account(&w.owner, "secfix4-ou").await?;
    let result = async {
        let root: i64 = w.owner.query_one("INSERT INTO departments(name,path,ldap_ou) VALUES('secfix4-root','secfix4-root','ou=r') RETURNING id", &[]).await?.get(0);
        let other: i64 = w.owner.query_one("INSERT INTO departments(name,path,ldap_ou) VALUES('secfix4-other','secfix4-other','ou=o') RETURNING id", &[]).await?.get(0);
        grant(&w.owner, w.scoped.user, &["users.create"], Some(w.a.domain), None).await?;
        grant(&w.owner, w.global.user, &["users.create"], None, None).await?;
        grant(&w.owner, ou_admin.user, &["users.create"], Some(w.a.domain), Some(root)).await?;
        let scoped = actor(&w.exec, w.scoped.user).await?;
        let global = actor(&w.exec, w.global.user).await?;
        let confined = actor(&w.exec, ou_admin.user).await?;
        let scoped_admin = w.admin(&scoped, &["users.create"]).await?;
        let global_admin = w.admin(&global, &["users.create"]).await?;
        let confined_admin = w.admin(&confined, &["users.create"]).await?;
        let dom = Some(w.a.domain);
        let no_dom: Option<i64> = None;
        let no_parent: Option<i64> = None;
        let no_sort: Option<i64> = None;

        // A domain-scoped admin reaching its whole domain may not shape the org-wide tree.
        let create = refused(w.worker_contract(&scoped_admin, &setjoin_admin_identity::sql::DEPARTMENT_CREATE, &[&w.scoped.user, &"secfix4-new-root", &no_parent, &"ou=n", &dom], org_policies::parse_department_create).await);
        assert_eq!(create.map(|p| p.status), Some(403), "scoped admin created a root department");
        let child = refused(w.worker_contract(&scoped_admin, &setjoin_admin_identity::sql::DEPARTMENT_CREATE, &[&w.scoped.user, &"secfix4-kid", &Some(other), &"ou=k", &dom], org_policies::parse_department_create).await);
        assert_eq!(child.map(|p| p.status), Some(403), "scoped admin created a department under another subtree");
        let update = refused(w.worker_contract(&scoped_admin, &setjoin_admin_identity::sql::DEPARTMENT_UPDATE, &[&w.scoped.user, &other, &"secfix4-renamed", &no_parent, &"", &no_sort, &dom], org_policies::parse_department_update).await);
        assert_eq!(update.map(|p| p.status), Some(403), "scoped admin renamed a department");
        let delete = refused(w.worker_contract(&scoped_admin, &setjoin_admin_identity::sql::DEPARTMENT_DELETE, &[&w.scoped.user, &other, &dom], org_policies::parse_department_mut).await);
        assert_eq!(delete.map(|p| p.status), Some(403), "scoped admin deleted a department");
        let rows: i64 = w.owner.query_one("SELECT count(*) FROM departments WHERE name IN ('secfix4-root','secfix4-other')", &[]).await?.get(0);
        assert_eq!(rows, 2);

        // An OU-confined admin keeps its own subtree (and only that).
        let inside = w.worker_contract(&confined_admin, &setjoin_admin_identity::sql::DEPARTMENT_CREATE, &[&ou_admin.user, &"secfix4-inside", &Some(root), &"ou=i", &dom], org_policies::parse_department_create).await;
        assert!(matches!(inside, CommandOutcome::Committed(_)), "OU-confined create inside its subtree refused: {inside:?}");
        let outside = refused(w.worker_contract(&confined_admin, &setjoin_admin_identity::sql::DEPARTMENT_CREATE, &[&ou_admin.user, &"secfix4-outside", &Some(other), &"ou=x", &dom], org_policies::parse_department_create).await);
        assert_eq!(outside.map(|p| p.status), Some(403), "OU-confined admin escaped its subtree");

        // An organization-wide admin manages the whole tree.
        let made = w.worker_contract(&global_admin, &setjoin_admin_identity::sql::DEPARTMENT_CREATE, &[&w.global.user, &"secfix4-wide", &no_parent, &"ou=w", &no_dom], org_policies::parse_department_create).await;
        assert!(matches!(made, CommandOutcome::Committed(_)), "global create refused: {made:?}");
        let renamed = w.worker_contract(&global_admin, &setjoin_admin_identity::sql::DEPARTMENT_UPDATE, &[&w.global.user, &other, &"secfix4-renamed", &no_parent, &"", &no_sort, &no_dom], org_policies::parse_department_update).await;
        assert!(matches!(renamed, CommandOutcome::Committed(204)), "global update refused: {renamed:?}");
        let gone = w.worker_contract(&global_admin, &setjoin_admin_identity::sql::DEPARTMENT_DELETE, &[&w.global.user, &other, &no_dom], org_policies::parse_department_mut).await;
        assert!(matches!(gone, CommandOutcome::Committed(())), "global delete refused: {gone:?}");
        Ok::<_, BoxError>(())
    }
    .await;
    w.owner
        .execute(
            "DELETE FROM departments WHERE name LIKE 'secfix4-%' AND parent_id IS NOT NULL",
            &[],
        )
        .await?;
    w.owner
        .execute("DELETE FROM departments WHERE name LIKE 'secfix4-%'", &[])
        .await?;
    cleanup_roles(&w.owner).await?;
    fixture::remove(&w.owner, &ou_admin).await?;
    w.finish().await?;
    result
}

fn policy<'a>(name: &'a str, scope_type: &'a str, scope_target: &'a str) -> ca::Policy<'a> {
    ca::Policy {
        name,
        description: "",
        state: "off",
        scope_type,
        scope_target,
        priority: None,
        conditions: None,
        actions: None,
        exclude_users: None,
        exclude_groups: None,
        session_control: None,
    }
}

#[tokio::test]
async fn conditional_access_policies_are_confined_to_the_callers_reach() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix4-ca-policies").await? else {
        return Ok(());
    };
    let result = async {
        let perms = ["access.policy_read", "access.policy_write"];
        grant(&w.owner, w.scoped.user, &perms, Some(w.a.domain), None).await?;
        grant(&w.owner, w.global.user, &perms, None, None).await?;
        let (ta, tb) = (w.a.user.to_string(), w.b.user.to_string());
        let mut ids = Vec::new();
        for (name, kind, target) in [("secfix4-p-global", "global", ""), ("secfix4-p-a", "user", ta.as_str()), ("secfix4-p-b", "user", tb.as_str())] {
            let priority = 940_000 + ids.len() as i32;
            let id: i64 = w.owner.query_one("INSERT INTO conditional_access_policies(priority,name,state,scope_type,scope_target) VALUES($4,$1,'off',$2,$3) RETURNING id", &[&name, &kind, &target, &priority]).await?.get(0);
            ids.push(id);
        }
        let (p_global, p_a, p_b) = (ids[0], ids[1], ids[2]);
        let scoped = actor(&w.exec, w.scoped.user).await?;
        let global = actor(&w.exec, w.global.user).await?;
        let factory = w.factory()?;
        let sctx = w.admin(&scoped, &perms).await?;
        let gctx = w.admin(&global, &perms).await?;

        // Reads: only the policies scoped to reachable users.
        let listed = ca::list(&factory, &sctx, false).await.map_err(|e| e.message)?;
        assert!(listed.contains("secfix4-p-a"), "own-domain policy hidden: {listed}");
        assert!(!listed.contains("secfix4-p-b") && !listed.contains("secfix4-p-global"), "foreign or org-wide policies listed to a scoped admin");
        let all = ca::list(&factory, &gctx, false).await.map_err(|e| e.message)?;
        assert!(all.contains("secfix4-p-a") && all.contains("secfix4-p-b") && all.contains("secfix4-p-global"));
        let read_gate = |id: i64| {
            let (factory, sctx) = (&factory, &sctx);
            async move { ca::gate(factory, sctx, Some(id), None, None, true).await.map_err(|e| e.message) }
        };
        assert_eq!(read_gate(p_a).await?, ca::Gate::Allowed);
        assert_eq!(read_gate(p_b).await?, ca::Gate::NotFound);
        assert_eq!(read_gate(p_global).await?, ca::Gate::NotFound);

        // Writes: the stored policy and the scope being written must both be in reach.
        let write_gate = |id: Option<i64>, scope: Option<(&'static str, String)>| {
            let (factory, sctx) = (&factory, &sctx);
            async move {
                let scope = scope.as_ref().map(|(a, b)| (*a, b.as_str()));
                ca::gate(factory, sctx, id, None, scope, false).await.map_err(|e| e.message)
            }
        };
        assert_eq!(write_gate(Some(p_global), None).await?, ca::Gate::NotFound);
        assert_eq!(write_gate(Some(p_b), None).await?, ca::Gate::NotFound);
        assert_eq!(write_gate(Some(p_a), None).await?, ca::Gate::Allowed);
        assert_eq!(write_gate(None, Some(("global", String::new()))).await?, ca::Gate::Forbidden);
        assert_eq!(write_gate(None, Some(("user", tb.clone()))).await?, ca::Gate::Forbidden);
        assert_eq!(write_gate(None, Some(("group", "1".into()))).await?, ca::Gate::Forbidden);
        assert_eq!(write_gate(None, Some(("user", ta.clone()))).await?, ca::Gate::Allowed);
        assert_eq!(ca::gate(&factory, &gctx, Some(p_global), None, Some(("global", "")), false).await.map_err(|e| e.message)?, ca::Gate::Allowed);

        // The statements repeat the predicate (R3): nothing is written or deleted.
        let denied = ca::save(&factory, &sctx, "127.0.0.1", None, &policy("secfix4-wide", "global", ""), op()).await;
        assert!(matches!(denied, CommandOutcome::RolledBack(_)), "scoped admin created an org-wide policy: {denied:?}");
        let denied = ca::save(&factory, &sctx, "127.0.0.1", Some(p_b), &policy("secfix4-p-b", "user", &ta), op()).await;
        assert!(matches!(denied, CommandOutcome::RolledBack(_)), "scoped admin retargeted a foreign policy: {denied:?}");
        let denied = ca::soft_delete(&factory, &sctx, p_global, op()).await;
        assert!(matches!(denied, CommandOutcome::RolledBack(_)), "scoped admin deleted an org-wide policy: {denied:?}");
        let denied = ca::reorder(&factory, &sctx, "127.0.0.1", &vec![p_a, p_b], op()).await;
        assert!(matches!(denied, CommandOutcome::RolledBack(_)), "scoped admin reordered a foreign policy: {denied:?}");
        let live: i64 = w.owner.query_one("SELECT count(*) FROM conditional_access_policies WHERE name LIKE 'secfix4-%' AND deleted_at IS NULL", &[]).await?.get(0);
        assert_eq!(live, 3, "a refused write still changed policies");
        let own = ca::save(&factory, &sctx, "127.0.0.1", Some(p_a), &policy("secfix4-p-a2", "user", &ta), op()).await;
        assert!(matches!(own, CommandOutcome::Committed(_)), "own-scope update refused: {own:?}");
        let made = ca::save(&factory, &sctx, "127.0.0.1", None, &policy("secfix4-p-a3", "user", &ta), op()).await;
        assert!(matches!(made, CommandOutcome::Committed(_)), "own-scope create refused: {made:?}");

        // Organization-wide admins keep full control.
        let wide = ca::save(&factory, &gctx, "127.0.0.1", None, &policy("secfix4-wide", "global", ""), op()).await;
        assert!(matches!(wide, CommandOutcome::Committed(_)), "global create refused: {wide:?}");
        let gone = ca::soft_delete(&factory, &gctx, p_global, op()).await;
        assert!(matches!(gone, CommandOutcome::Committed(())), "global delete refused: {gone:?}");
        // A missing id keeps the reducer's own answer for an org-wide admin (Go's behaviour).
        assert_eq!(ca::gate(&factory, &gctx, Some(999_999_999), None, None, false).await.map_err(|e| e.message)?, ca::Gate::Allowed);
        assert!(ca::org_wide(&factory, &gctx, false).await.map_err(|e| e.message)?);
        assert!(!ca::org_wide(&factory, &sctx, false).await.map_err(|e| e.message)?);
        Ok::<_, BoxError>(())
    }
    .await;
    w.owner
        .execute(
            "DELETE FROM conditional_access_policies WHERE name LIKE 'secfix4-%'",
            &[],
        )
        .await?;
    w.finish().await?;
    result
}

/// A confined holder without any domain-scoped (or org-wide) grant of the permission is treated as
/// neither: nothing is listed, created, changed or readable (frozen Go and the first fix treated
/// a domain-less OU/set-confined holder as organization-wide).
#[tokio::test]
async fn confined_holders_without_a_domain_get_nothing() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix4-confined").await? else {
        return Ok(());
    };
    let result = async {
        let dept: i64 = w.owner.query_one("INSERT INTO departments(name,path,ldap_ou) VALUES('secfix4-conf','secfix4-conf','ou=c') RETURNING id", &[]).await?.get(0);
        grant(&w.owner, w.scoped.user, &["scope_sets.manage", "roles.manage"], None, Some(dept)).await?;
        let set: i64 = w.owner.query_one("INSERT INTO admin_scope_sets(name,domain_id,description) VALUES('secfix4-conf-set',$1,'') RETURNING id", &[&w.a.domain]).await?.get(0);
        let org: i64 = w.owner.query_one("INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES('secfix4-conf-role','{users.read}',NULL) RETURNING id", &[]).await?.get(0);
        let auth = actor(&w.exec, w.scoped.user).await?;
        let factory = w.factory()?;
        let user = w.user(&auth).await?;
        let admin = w.admin(&auth, &["scope_sets.manage", "roles.manage"]).await?;
        let listed = scope_sets::list(&factory, &admin).await.map_err(|e| e.message)?;
        assert!(!listed.contains("secfix4-conf-set"), "a domain-less confined holder listed sets: {listed}");
        assert!(scope_sets::get(&factory, &admin, set).await.map_err(|e| e.message)?.is_none());
        for domain in [Some(w.a.domain), None] {
            let create = refused(scope_sets::create(&factory, &admin, "secfix4-conf-new", domain, "", "", op()).await);
            assert_eq!(create.map(|p| p.status), Some(403), "confined holder created a set");
        }
        let update = refused(scope_sets::update(&factory, &admin, set, Some("x"), None, "", op()).await);
        assert_eq!(update.map(|p| p.status), Some(404));
        assert!(!sod::role_in_scope(&factory, &admin, org).await, "confined holder reached a global role's policy");
        let put = sod::put_policy(&factory, &user, &admin, org, 30, true, op()).await;
        assert!(matches!(put, CommandOutcome::RolledBack(_)), "confined holder wrote a policy: {put:?}");
        Ok::<_, BoxError>(())
    }
    .await;
    w.owner
        .execute(
            "DELETE FROM admin_scope_sets WHERE name LIKE 'secfix4-%'",
            &[],
        )
        .await?;
    cleanup_roles(&w.owner).await?;
    w.owner
        .execute(
            "DELETE FROM admin_role_groups WHERE name LIKE 'secfix4-%'",
            &[],
        )
        .await?;
    w.owner
        .execute("DELETE FROM departments WHERE name LIKE 'secfix4-%'", &[])
        .await?;
    w.finish().await?;
    result
}

/// CA reach counts only grants that carry access.policy_*; a missing id is as missing as a foreign
/// one; the session log and sign-in lookups follow the same reach.
#[tokio::test]
async fn ca_reach_uses_policy_grants_and_logs_follow_it() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix4-ca-reach").await? else {
        return Ok(());
    };
    let result = async {
        let dept: i64 = w.owner.query_one("INSERT INTO departments(name,path,ldap_ou) VALUES('secfix4-ca','secfix4-ca','ou=c') RETURNING id", &[]).await?.get(0);
        // A policy grant confined to an empty department, plus an unrelated domain-wide grant.
        grant(&w.owner, w.scoped.user, &["access.policy_read", "access.policy_write"], None, Some(dept)).await?;
        grant(&w.owner, w.scoped.user, &["users.read"], Some(w.a.domain), None).await?;
        let (ta, tb) = (w.a.user.to_string(), w.b.user.to_string());
        let id: i64 = w.owner.query_one("INSERT INTO conditional_access_policies(priority,name,state,scope_type,scope_target) VALUES(940010,'secfix4-ca-p','off','user',$1) RETURNING id", &[&ta]).await?.get(0);
        for user in [w.a.user, w.b.user] {
            w.owner.execute("INSERT INTO session_revocations(user_id,scope,reason,expires_at) VALUES($1,'all','secfix4',now()+interval '1 day')", &[&user]).await?;
        }
        let scoped = actor(&w.exec, w.scoped.user).await?;
        let factory = w.factory()?;
        let sctx = w.admin(&scoped, &["access.policy_read", "access.policy_write"]).await?;
        let gate = |id: i64| {
            let (factory, sctx) = (&factory, &sctx);
            async move { ca::gate(factory, sctx, Some(id), None, None, false).await.map_err(|e| e.message) }
        };
        assert_eq!(gate(id).await?, ca::Gate::NotFound, "an unrelated domain-wide grant extended policy reach");
        assert_eq!(gate(999_999_999).await?, ca::Gate::NotFound, "a missing policy id is not a plain not-found");
        assert!(!ca::user_in_reach(&factory, &sctx, w.a.user).await.map_err(|e| e.message)?);
        let log = setjoin_conditional_access::console::sessions_log(&factory, &sctx).await.map_err(|e| e.message)?;
        assert!(!log.contains("secfix4"), "session log leaked to a confined caller: {log}");
        // With a domain-scoped policy grant the same caller reaches its own domain only.
        grant(&w.owner, w.scoped.user, &["access.policy_read"], Some(w.a.domain), None).await?;
        let sctx = w.admin(&scoped, &["access.policy_read", "access.policy_write"]).await?;
        assert!(ca::user_in_reach(&factory, &sctx, w.a.user).await.map_err(|e| e.message)?);
        assert!(!ca::user_in_reach(&factory, &sctx, w.b.user).await.map_err(|e| e.message)?);
        let log = setjoin_conditional_access::console::sessions_log(&factory, &sctx).await.map_err(|e| e.message)?;
        assert_eq!(log.matches("secfix4").count(), 1, "session log must list only reachable users: {log}");
        assert!(log.contains(&format!("\"user_id\":{}", w.a.user)) && !log.contains(&format!("\"user_id\":{}", w.b.user)));
        let _ = tb;
        Ok::<_, BoxError>(())
    }
    .await;
    w.owner
        .execute(
            "DELETE FROM session_revocations WHERE reason='secfix4'",
            &[],
        )
        .await?;
    w.owner
        .execute(
            "DELETE FROM conditional_access_policies WHERE name LIKE 'secfix4-%'",
            &[],
        )
        .await?;
    cleanup_roles(&w.owner).await?;
    w.owner
        .execute("DELETE FROM departments WHERE name LIKE 'secfix4-%'", &[])
        .await?;
    w.finish().await?;
    result
}

/// AD conflict resolution and the conflict list use the permission-aware reach; email-address
/// policy writes need an organization-wide identity.write grant.
#[tokio::test]
async fn ad_conflicts_and_email_policies_follow_the_grant() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix4-ad-conflicts").await? else {
        return Ok(());
    };
    let result = async {
        // Domain-wide users.read on A must not make identity.write reach A's users.
        grant(
            &w.owner,
            w.scoped.user,
            &["users.read"],
            Some(w.a.domain),
            None,
        )
        .await?;
        grant(
            &w.owner,
            w.scoped.user,
            &["identity.write"],
            Some(w.b.domain),
            None,
        )
        .await?;
        grant(&w.owner, w.global.user, &["identity.write"], None, None).await?;
        for user in [w.a.user, w.b.user] {
            w.owner
                .execute(
                    "INSERT INTO sync_conflicts(user_id,field,source) VALUES($1,'title','ad')",
                    &[&user],
                )
                .await?;
        }
        // Department assignment: users.create reaches B only, so A's user is refused.
        grant(
            &w.owner,
            w.scoped.user,
            &["users.create"],
            Some(w.b.domain),
            None,
        )
        .await?;
        let scoped = actor(&w.exec, w.scoped.user).await?;
        let global = actor(&w.exec, w.global.user).await?;
        let factory = w.factory()?;
        let scoped_admin = w.admin(&scoped, &["identity.write"]).await?;
        let global_admin = w.admin(&global, &["identity.write"]).await?;
        let no_dept: Option<i64> = None;
        let no_dom: Option<i64> = None;
        let assign = refused(
            w.worker_contract(
                &scoped_admin,
                &setjoin_admin_identity::sql::DEPARTMENT_ASSIGN_USER,
                &[&w.scoped.user, &w.a.user, &no_dept, &no_dom],
                org_policies::parse_department_mut,
            )
            .await,
        );
        assert_eq!(
            assign.map(|p| p.status),
            Some(403),
            "a users.read grant reached a user for department assignment"
        );
        let ok = w
            .worker_contract(
                &scoped_admin,
                &setjoin_admin_identity::sql::DEPARTMENT_ASSIGN_USER,
                &[&w.scoped.user, &w.b.user, &no_dept, &no_dom],
                org_policies::parse_department_mut,
            )
            .await;
        assert!(
            matches!(ok, CommandOutcome::Committed(())),
            "own users.create reach refused: {ok:?}"
        );
        let listed = setjoin_directory_sync::conflicts(&factory, &scoped_admin)
            .await
            .map_err(|e| e.message)?;
        assert!(
            listed.contains(&format!("\"userId\":{}", w.a.user)),
            "own users.read reach hidden: {listed}"
        );
        assert!(
            listed.contains(&format!("\"userId\":{}", w.b.user)),
            "identity.write reach hidden: {listed}"
        );
        let scoped_user = w.user(&scoped).await?;
        let global_user = w.user(&global).await?;
        let resolved = setjoin_directory_sync::resolve_all(
            &factory,
            &scoped_user,
            &scoped_admin,
            "kept_local",
            op(),
        )
        .await;
        assert!(
            matches!(resolved, CommandOutcome::Committed(1)),
            "resolve-all must touch only the identity.write reach: {resolved:?}"
        );
        let open: i64 = w
            .owner
            .query_one(
                "SELECT count(*) FROM sync_conflicts WHERE user_id=$1 AND resolved_at IS NULL",
                &[&w.a.user],
            )
            .await?
            .get(0);
        assert_eq!(open, 1, "a users.read grant resolved a conflict");
        let all = setjoin_directory_sync::resolve_all(
            &factory,
            &global_user,
            &global_admin,
            "kept_local",
            op(),
        )
        .await;
        assert!(
            matches!(all, CommandOutcome::Committed(_)),
            "global resolve refused: {all:?}"
        );
        assert!(!org_policies::org_wide(&factory, &scoped_admin).await);
        assert!(org_policies::org_wide(&factory, &global_admin).await);
        Ok::<_, BoxError>(())
    }
    .await;
    w.owner
        .execute(
            "DELETE FROM sync_conflicts WHERE user_id IN ($1,$2)",
            &[&w.a.user, &w.b.user],
        )
        .await?;
    w.owner
        .execute("DELETE FROM departments WHERE name LIKE 'secfix4-%'", &[])
        .await?;
    w.finish().await?;
    result
}

/// Owner decision 2026-11-06: a domain-limited admin's policies never take effect before an
/// org-wide policy (explicit priority refused, reorder restepped from the floor); org-wide admins
/// are unchanged.
#[tokio::test]
async fn scoped_policies_stay_behind_org_wide_policies() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(w) = world("secfix4-ca-priority").await? else {
        return Ok(());
    };
    let result = async {
        let perms = ["access.policy_read", "access.policy_write"];
        grant(&w.owner, w.scoped.user, &perms, Some(w.a.domain), None).await?;
        grant(&w.owner, w.global.user, &perms, None, None).await?;
        let ta = w.a.user.to_string();
        // An org-wide "MFA" policy at a distinctive priority, and two scoped policies.
        let mfa: i64 = w.owner.query_one("INSERT INTO conditional_access_policies(priority,name,state,scope_type,scope_target) VALUES(960100,'secfix4-mfa','off','global','') RETURNING id", &[]).await?.get(0);
        let mut mine = Vec::new();
        for (i, name) in ["secfix4-mine1", "secfix4-mine2"].iter().enumerate() {
            let id: i64 = w.owner.query_one("INSERT INTO conditional_access_policies(priority,name,state,scope_type,scope_target) VALUES($3,$1,'off','user',$2) RETURNING id", &[name, &ta, &(960200 + i as i32)]).await?.get(0);
            mine.push(id);
        }
        let scoped = actor(&w.exec, w.scoped.user).await?;
        let global = actor(&w.exec, w.global.user).await?;
        let factory = w.factory()?;
        let sctx = w.admin(&scoped, &perms).await?;
        let gctx = w.admin(&global, &perms).await?;
        let floor: i32 = w.owner.query_one("SELECT rust_ca_priority_floor($1,'{access.policy_write}')", &[&w.scoped.user]).await?.get::<_, Option<i32>>(0).ok_or("scoped floor")?;
        assert!(floor >= 960100, "the org-wide policy must raise the floor");
        let none: Option<i32> = w.owner.query_one("SELECT rust_ca_priority_floor($1,'{access.policy_write}')", &[&w.global.user]).await?.get(0);
        assert_eq!(none, None, "an org-wide admin has no floor");

        // Explicit priorities at or before the floor are refused (route 403, statement no rows).
        for p in [1_i64, floor as i64] {
            assert!(!ca::priority_allowed(&factory, &sctx, Some(p), None).await.map_err(|e| e.message)?, "scoped admin may take priority {p}");
            let mut request = policy("secfix4-top", "user", &ta);
            request.priority = Some(p);
            let denied = ca::save(&factory, &sctx, "127.0.0.1", None, &request, op()).await;
            assert!(matches!(denied, CommandOutcome::RolledBack(_)), "statement accepted priority {p}: {denied:?}");
            let moved = ca::save(&factory, &sctx, "127.0.0.1", Some(mine[0]), &request, op()).await;
            assert!(matches!(moved, CommandOutcome::RolledBack(_)), "statement moved a policy to priority {p}: {moved:?}");
        }
        assert!(ca::priority_allowed(&factory, &sctx, Some(floor as i64 + 1), None).await.map_err(|e| e.message)?);
        assert!(ca::priority_allowed(&factory, &sctx, None, None).await.map_err(|e| e.message)?, "automatic priority is max+10");
        let mut ok = policy("secfix4-after", "user", &ta);
        ok.priority = Some(floor as i64 + 5);
        let made = ca::save(&factory, &sctx, "127.0.0.1", None, &ok, op()).await;
        assert!(matches!(made, CommandOutcome::Committed(_)), "priority after the floor refused: {made:?}");
        // Org-wide admins may still place a policy first.
        let mut first = policy("secfix4-first", "global", "");
        first.priority = Some(1);
        let wide = ca::save(&factory, &gctx, "127.0.0.1", None, &first, op()).await;
        assert!(matches!(wide, CommandOutcome::Committed(_)), "org-wide priority refused: {wide:?}");

        // Reorder: a scoped admin's policies are restepped from the floor, never ahead of org-wide ones.
        let reorder = ca::reorder(&factory, &sctx, "127.0.0.1", &vec![mine[1], mine[0]], op()).await;
        assert!(matches!(reorder, CommandOutcome::Committed(())), "own reorder refused: {reorder:?}");
        let prio = |id: i64| {
            let owner = &w.owner;
            async move { owner.query_one("SELECT priority FROM conditional_access_policies WHERE id=$1", &[&id]).await.map(|r| r.get::<_, i32>(0)) }
        };
        let (p1, p0) = (prio(mine[1]).await?, prio(mine[0]).await?);
        assert!(p1 > 960100 && p0 > p1, "scoped reorder placed policies ahead of the org-wide policy: {p1} {p0}");
        assert_eq!(prio(mfa).await?, 960100, "the org-wide policy must not move");
        // Reordering around an org-wide policy is refused outright.
        let mixed = ca::reorder(&factory, &sctx, "127.0.0.1", &vec![mine[0], mfa], op()).await;
        assert!(matches!(mixed, CommandOutcome::RolledBack(_)), "scoped reorder touched an org-wide policy: {mixed:?}");
        // An org-wide admin's reorder keeps Go's stepping from 10.
        let wide = ca::reorder(&factory, &gctx, "127.0.0.1", &vec![mfa], op()).await;
        assert!(matches!(wide, CommandOutcome::Committed(())), "org-wide reorder refused: {wide:?}");
        assert_eq!(prio(mfa).await?, 10);
        Ok::<_, BoxError>(())
    }
    .await;
    w.owner
        .execute(
            "DELETE FROM conditional_access_policies WHERE name LIKE 'secfix4-%'",
            &[],
        )
        .await?;
    w.finish().await?;
    result
}
