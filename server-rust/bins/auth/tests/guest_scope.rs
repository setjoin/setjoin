//! #353 native guest scope at login and MFA completion. Go is not involved:
//! these cases pin Rust's own guest decisions. Every DB case takes the shared
//! identity-login advisory lock and proves `is_guest_account` pristine first.
// Shared fixtures only; this binary uses a subset of the helpers.
#[allow(dead_code)]
mod common;
use base64::Engine as _;
use http_body_util::BodyExt;
use hyper::Request;
use serde_json::{json, Value};
use setjoin_auth::{body, AuthServer, Config};
use setjoin_conformance::{fixture, harness::Db};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

type Err = Box<dyn std::error::Error + Send + Sync>;

/// Fable 353-2: no case may run against a replaced is_guest_account. Restore
/// from the reducer source, or fail hard.
async fn guest_function_pristine(c: &tokio_postgres::Client) -> Result<(), Err> {
    let def = |c: &tokio_postgres::Client| async move {
        c.query_one(
            "SELECT pg_get_functiondef('is_guest_account(bigint)'::regprocedure)",
            &[],
        )
        .await
        .map(|r| r.get::<_, String>(0))
    };
    let ok = |d: &str| {
        d.contains("SECURITY DEFINER")
            && d.contains("public.guest_accounts")
            && !d.contains("gofree_")
    };
    if ok(&def(c).await?) {
        return Ok(());
    }
    c.batch_execute(include_str!(
        "../../../../mailserver/sql/reducers/guest_account.sql"
    ))
    .await?;
    c.batch_execute("DROP SEQUENCE IF EXISTS gofree_idmfa1_guest_calls; DROP SEQUENCE IF EXISTS gofree_guest353_calls").await?;
    if ok(&def(c).await?) {
        Ok(())
    } else {
        Err("is_guest_account is not pristine after restore; refusing to run".into())
    }
}

/// Go-free static guard: the guest handoffs removed by #353 must not return.
#[test]
fn no_guest_forward_or_406_left_in_auth_src() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    for entry in std::fs::read_dir(&src).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "rs") {
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(!text.contains("totp_guest"), "{}", path.display());
            assert!(!text.contains("#406"), "{}", path.display());
        }
    }
}

/// Replace is_guest_account with a call-counting branch. The sequence is
/// granted to the app role, which runs the lookup.
async fn install_counting_guest(c: &tokio_postgres::Client, branch: &str) -> Result<(), Err> {
    c.batch_execute("DROP SEQUENCE IF EXISTS gofree_guest353_calls;CREATE SEQUENCE gofree_guest353_calls;GRANT USAGE ON SEQUENCE gofree_guest353_calls TO setjoin_app").await?;
    c.batch_execute(&format!("CREATE OR REPLACE FUNCTION is_guest_account(p_user_id bigint) RETURNS boolean LANGUAGE plpgsql AS $$BEGIN {branch} END$$")).await?;
    Ok(())
}

fn claims_of(token: &str) -> Result<Value, Err> {
    let segment = token.split('.').nth(1).ok_or("jwt without payload")?;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(segment)?;
    Ok(serde_json::from_slice(&raw)?)
}

/// Case assertions return Err (not panic) so the restore in `finish` always runs.
fn check(ok: bool, what: &str) -> Result<(), Err> {
    if ok {
        Ok(())
    } else {
        Err(what.into())
    }
}

/// Native login through the front-door handler (no gateway, no Go upstream).
async fn login(auth: &AuthServer, email: &str) -> Result<(u16, Value), Err> {
    let payload = json!({"email": email, "password": "Password1!"}).to_string();
    let req = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header("content-type", "application/json")
        .extension(setjoin_auth::ConnectionMeta {
            peer: "127.0.0.1:9".parse()?,
            tls: false,
        })
        .body(body(payload))?;
    let resp = auth.handle(req).await;
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await?.to_bytes();
    Ok((status, serde_json::from_slice(&bytes)?))
}

/// Shared arrangement: an enabled, MFA-exempt, password-bearing account, with
/// or without an active guest row, and the auth server loaded on the app DSN.
async fn arrange(
    db: &Db,
    c: &tokio_postgres::Client,
    label: &str,
    guest: bool,
) -> Result<(String, AuthServer), Err> {
    common::signing_key(c).await;
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false", &[]).await?;
    let a = fixture::account(c, label).await?;
    c.execute("DELETE FROM guest_accounts WHERE user_id=$1", &[&a.user])
        .await?;
    c.execute(
        "UPDATE users SET password_hash=$1,mfa_exempt=true WHERE id=$2",
        &[&bcrypt::hash("Password1!", 4)?, &a.user],
    )
    .await?;
    if guest {
        c.execute(
            "INSERT INTO guest_accounts(user_id,invited_email,invited_by_email,host_domain_id,status) SELECT id,email,'inviter@guest353.test',$2,'active' FROM users WHERE id=$1",
            &[&a.user, &a.domain],
        )
        .await?;
    }
    let keys: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))?;
    let cfg = Config::for_secret(keys["secret"].as_str().unwrap().into());
    let exec = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
        .map_err(|e| e.0)?;
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await?
        .get(0);
    Ok((email, AuthServer::load(exec, cfg).await?))
}

/// Takes the in-binary serial lock and the shared identity-login advisory
/// lock, then proves is_guest_account pristine before the case runs.
async fn begin(
    case: &str,
) -> Result<
    (
        tokio::sync::MutexGuard<'static, ()>,
        Db,
        tokio_postgres::Client,
    ),
    Err,
> {
    let serial = SERIAL.lock().await;
    let db = Db::for_case(case).expect("assigned DB required");
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    guest_function_pristine(&c).await?;
    Ok((serial, db, c))
}

/// Restores is_guest_account and releases the advisory lock, even after a
/// failed case, then reports the case result.
async fn finish(c: &tokio_postgres::Client, result: Result<(), Err>) -> Result<(), Err> {
    guest_function_pristine(c).await?;
    c.query_one(
        "SELECT pg_advisory_unlock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    result
}

#[tokio::test]
async fn guest_login_access_carries_acct_and_refresh_does_not() {
    let (_serial, db, c) = begin("GUEST353-login-guest").await.unwrap();
    let result: Result<(), Err> = async {
        let (email, auth) = arrange(&db, &c, "guest353-login-guest", true).await?;
        let (status, v) = login(&auth, &email).await?;
        check(status == 200, &format!("login status {status}: {v}"))?;
        let access = claims_of(v["access_token"].as_str().ok_or("no access_token")?)?;
        check(
            access["acct"] == json!("guest"),
            "access token must carry acct guest",
        )?;
        let refresh = claims_of(v["refresh_token"].as_str().ok_or("no refresh_token")?)?;
        check(
            refresh.get("acct").is_none(),
            "refresh token must not carry acct",
        )?;
        Ok(())
    }
    .await;
    finish(&c, result).await.unwrap();
}

#[tokio::test]
async fn member_login_access_has_no_acct() {
    let (_serial, db, c) = begin("GUEST353-login-member").await.unwrap();
    let result: Result<(), Err> = async {
        let (email, auth) = arrange(&db, &c, "guest353-login-member", false).await?;
        let (status, v) = login(&auth, &email).await?;
        check(status == 200, &format!("login status {status}: {v}"))?;
        let access = claims_of(v["access_token"].as_str().ok_or("no access_token")?)?;
        check(
            access.get("acct").is_none(),
            "member access token must not carry acct",
        )?;
        Ok(())
    }
    .await;
    finish(&c, result).await.unwrap();
}

/// N5: the scope lookup (call 1) says guest, the mint lookup (call 2) says
/// member. The mint lookup decides, as in Go.
#[tokio::test]
async fn split_lookup_first_guest_then_member_mints_member_token() {
    let (_serial, db, c) = begin("GUEST353-split-member").await.unwrap();
    let result: Result<(), Err> = async {
        let (email, auth) = arrange(&db, &c, "guest353-split-member", false).await?;
        install_counting_guest(&c, "RETURN nextval('gofree_guest353_calls')=1;").await?;
        let (status, v) = login(&auth, &email).await?;
        check(status == 200, &format!("login status {status}: {v}"))?;
        let access = claims_of(v["access_token"].as_str().ok_or("no access_token")?)?;
        check(
            access.get("acct").is_none(),
            "mint lookup said member; token must not carry acct",
        )?;
        Ok(())
    }
    .await;
    finish(&c, result).await.unwrap();
}

/// N5b: the scope lookup (call 1) says member, the mint lookup (call 2) says
/// guest. The mint lookup decides, so the token carries acct guest.
#[tokio::test]
async fn split_lookup_first_member_then_guest_mints_guest_token() {
    let (_serial, db, c) = begin("GUEST353-split-guest").await.unwrap();
    let result: Result<(), Err> = async {
        let (email, auth) = arrange(&db, &c, "guest353-split-guest", false).await?;
        install_counting_guest(&c, "RETURN nextval('gofree_guest353_calls')>1;").await?;
        let (status, v) = login(&auth, &email).await?;
        check(status == 200, &format!("login status {status}: {v}"))?;
        let access = claims_of(v["access_token"].as_str().ok_or("no access_token")?)?;
        check(
            access["acct"] == json!("guest"),
            "mint lookup said guest; token must carry acct guest",
        )?;
        Ok(())
    }
    .await;
    finish(&c, result).await.unwrap();
}
