//! #454/#455: identity reads that fail must refuse, never answer "no MFA", "no risk",
//! "not common" or verify against an empty TOTP key (security Go bugs fixed in Rust; see
//! tests/conformance/identity-{login,mfa,webauthn,rp}/divergences.json). Faults revoke SELECT
//! from the request role through `common/revoke.rs`; cleanup always runs before assertions.
use crate::common;
use crate::revoke;
use http_body_util::BodyExt;
use hyper::Request;
use serde_json::{json, Value};
use setjoin_auth::{body, AuthServer, Config};
use setjoin_authz::legacy_jwt::sign_hs256;
use setjoin_conformance::{fixture, harness::Db};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type Err = revoke::Err;
type Client = tokio_postgres::Client;
type Risk = Result<Option<Value>, setjoin_pg::StatementFailure>;
struct Env {
    db: Db,
    c: Client,
    secret: String,
    exec: setjoin_pg::ScopedExecutor,
}
struct Reply {
    status: u16,
    retry_after: Option<String>,
    cookies: Vec<String>,
    body: String,
}
const ENC: &str = "2222222222222222222222222222222222222222222222222222222222222222";
/// A fresh absent address per run, so its auth_event_log rows match this run only.
fn absent() -> String {
    format!(
        "nobody-failclosed-{}@nowhere.invalid",
        uuid::Uuid::new_v4().simple()
    )
}
/// A per-run source address for this test's failed sign-ins (X-Forwarded-For through the
/// trusted proxy). The address is not used for cleanup; it keeps the assertions per-run.
fn fixture_ip() -> String {
    let b = uuid::Uuid::new_v4().into_bytes();
    format!("10.{}.{}.{}", b[0], b[1], b[2].max(1))
}
/// A Set-Cookie value that carries a credential: a non-empty value whose name contains "token".
fn credential_cookie(cookie: &str) -> bool {
    let (name, rest) = cookie.split_once('=').unwrap_or((cookie, ""));
    let value = rest.split(';').next().unwrap_or("");
    name.trim().to_ascii_lowercase().contains("token") && !value.is_empty()
}
/// The fixture's own auth_event_log rows: by user id, or by the per-run unique address (failed
/// sign-ins store no user id). login_events and receipts are left for the throwaway database.
async fn login_residue(e: &Env, user: i64, emails: &[String]) -> Result<(), Err> {
    let lowered: Vec<String> = emails.iter().map(|m| m.to_lowercase()).collect();
    e.c.execute(
        "DELETE FROM auth_event_log WHERE user_id=$1 OR lower(email)=ANY($2)",
        &[&user, &lowered],
    )
    .await?;
    Ok(())
}

/// Setup before any account exists may panic; nothing needs undoing yet.
async fn env(case: &str) -> Option<Env> {
    let db = Db::for_case(case)?;
    let c = db.connect().await.unwrap();
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await
    .unwrap();
    common::signing_key(&c).await;
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let app = db
        .app
        .clone()
        .expect("fail-closed faults revoke privileges from the distinct app role: set DB_APP_DSN");
    let exec = setjoin_pg::ScopedExecutor::from_dsn(&app, 4).unwrap();
    Some(Env {
        db,
        c,
        secret: f["secret"].as_str().unwrap().into(),
        exec,
    })
}
fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}
fn token(secret: &str, mut claims: Value) -> String {
    let n = now();
    claims["typ"] = json!("access");
    claims["iss"] = json!("mailserver");
    claims["aud"] = json!(["mailserver-gateway"]);
    claims["iat"] = json!(n - 5);
    claims["nbf"] = json!(n - 5);
    claims["exp"] = json!(n + 600);
    sign_hs256(secret.as_bytes(), &claims.to_string())
}
fn sf(f: setjoin_pg::StatementFailure) -> Err {
    format!("{f:?}").into()
}
/// Keeps the case error and appends a cleanup error; a cleanup error alone fails the case.
fn settle<T>(case: Result<T, Err>, cleanup: Result<(), Err>) -> Result<T, Err> {
    match (case, cleanup) {
        (Ok(v), Ok(())) => Ok(v),
        (Ok(_), Err(c)) => Err(format!("cleanup failed: {c}").into()),
        (Err(e), Ok(())) => Err(e),
        (Err(e), Err(c)) => Err(format!("{e}; cleanup also failed: {c}").into()),
    }
}
async fn cleanup(e: &Env, a: &fixture::Account) -> Result<(), Err> {
    // Every step runs; the account is always removed, and failures are aggregated.
    let mut outcome: Result<(), Err> = Ok(());
    for sql in [
        "DELETE FROM oauth_tokens WHERE user_id=$1",
        "DELETE FROM sessions WHERE user_id=$1",
        "DELETE FROM user_risk WHERE user_id=$1",
        "DELETE FROM mfa_reauth_step_ups WHERE user_id=$1",
        "DELETE FROM session_revocations WHERE user_id=$1",
        "DELETE FROM login_events WHERE user_id=$1",
    ] {
        let step: Result<(), Err> =
            e.c.execute(sql, &[&a.user])
                .await
                .map(|_| ())
                .map_err(Into::into);
        outcome = settle(outcome, step);
    }
    let removed: Result<(), Err> = fixture::remove(&e.c, a)
        .await
        .map(|_| ())
        .map_err(Into::into);
    settle(outcome, removed)
}
/// Creates and seeds an account; a seeding error removes it before returning.
async fn account(e: &Env, label: &str) -> Result<(fixture::Account, String), Err> {
    let a = fixture::account(&e.c, label).await?;
    let seeded = async {
        e.c.execute(
            "UPDATE users SET password_hash=$1,mfa_exempt=true WHERE id=$2",
            &[&bcrypt::hash("Password1!", 4)?, &a.user],
        )
        .await?;
        let email: String =
            e.c.query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
                .await?
                .get(0);
        Ok::<_, Err>(email)
    }
    .await;
    match seeded {
        Ok(email) => Ok((a, email)),
        Err(err) => Err(match cleanup(e, &a).await {
            Ok(()) => err,
            Err(c) => format!("{err}; cleanup also failed: {c}").into(),
        }),
    }
}
async fn save_flags(c: &Client) -> Result<String, Err> {
    Ok(c.query_one("SELECT coalesce(jsonb_agg(to_jsonb(t)),'[]')::text FROM feature_toggles t WHERE key IN ('feature.user_risk','feature.rate_limit')", &[]).await?.get(0))
}
async fn restore_flags(c: &Client, saved: &str) -> Result<(), Err> {
    c.batch_execute(
        "DELETE FROM feature_toggles WHERE key IN ('feature.user_risk','feature.rate_limit')",
    )
    .await?;
    c.execute("INSERT INTO feature_toggles SELECT * FROM jsonb_populate_recordset(NULL::feature_toggles,$1::text::jsonb)", &[&saved]).await?;
    Ok(())
}
async fn set_flag(c: &Client, key: &str, on: bool) -> Result<(), Err> {
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET enabled=EXCLUDED.enabled", &[&key, &on]).await?;
    Ok(())
}
const RATE_FLAG: &str = "feature.rate_limit";
async fn save_rate(c: &Client) -> Result<Option<bool>, Err> {
    Ok(c.query_opt(
        "SELECT enabled FROM feature_toggles WHERE key=$1",
        &[&RATE_FLAG],
    )
    .await?
    .map(|row| row.get(0)))
}
async fn restore_rate(c: &Client, saved: Option<bool>) -> Result<(), Err> {
    if let Some(enabled) = saved {
        set_flag(c, RATE_FLAG, enabled).await?;
    } else {
        c.execute("DELETE FROM feature_toggles WHERE key=$1", &[&RATE_FLAG])
            .await?;
    }
    Ok(())
}
fn config(e: &Env) -> Config {
    let mut cfg = Config::for_secret(e.secret.clone());
    cfg.worker_dsn = None;
    // Forwarded addresses are honoured only from the trusted proxy (fixture IPs per test).
    cfg.client_proxy = "127.0.0.1".into();
    cfg.dsn = e.db.dsn.clone();
    cfg.db_encryption_key = ENC.into();
    cfg
}
async fn server(e: &Env) -> Result<AuthServer, Err> {
    Ok(AuthServer::load(e.exec.clone(), config(e))
        .await?
        .with_threat_gate(&e.db.dsn)
        .await?)
}
async fn send(s: &AuthServer, r: Request<setjoin_auth::Body>) -> Result<Reply, Err> {
    let r = s.handle(r).await;
    let status = r.status().as_u16();
    let retry_after = r
        .headers()
        .get("retry-after")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let cookies: Vec<String> = r
        .headers()
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .map(str::to_owned)
        .collect();
    let body = String::from_utf8_lossy(&r.into_body().collect().await?.to_bytes()).into_owned();
    Ok(Reply {
        status,
        retry_after,
        cookies,
        body,
    })
}
/// A JSON POST from one fixture source address (X-Forwarded-For through the trusted proxy).
fn anonymous_from(
    ip: &str,
    path: &str,
    payload: Value,
) -> Result<Request<setjoin_auth::Body>, Err> {
    Ok(Request::post(path)
        .header("content-type", "application/json")
        .header("x-forwarded-for", ip)
        .body(body(payload.to_string()))?)
}
fn anonymous(path: &str, payload: Value) -> Result<Request<setjoin_auth::Body>, Err> {
    Ok(Request::post(path)
        .header("content-type", "application/json")
        .body(body(payload.to_string()))?)
}
fn bearer(
    method: &str,
    path: &str,
    token: &str,
    payload: Value,
) -> Result<Request<setjoin_auth::Body>, Err> {
    Ok(Request::builder()
        .method(method)
        .uri(path)
        .header("host", "mail.test")
        .header("origin", "http://mail.test")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/json")
        .body(body(payload.to_string()))?)
}
async fn oauth_state(e: &Env, user: i64) -> Result<(i64, i64), Err> {
    let r = e.c.query_one("SELECT count(*), count(*) FILTER (WHERE revoked_at IS NOT NULL OR rotated_at IS NOT NULL) FROM oauth_tokens WHERE user_id=$1", &[&user]).await?;
    Ok((r.get(0), r.get(1)))
}
async fn stored_hash(e: &Env, user: i64) -> Result<String, Err> {
    Ok(e.c
        .query_one("SELECT password_hash FROM users WHERE id=$1", &[&user])
        .await?
        .get(0))
}
async fn three(
    e: &Env,
    proof: &setjoin_identity::login::PasswordProof,
    session: &setjoin_identity::session::Session,
    user: &setjoin_identity::totp::CompletionUser,
) -> Vec<Risk> {
    let auth_db = setjoin_pg::AuthDb::from_executors(e.exec.clone(), e.exec.clone());
    vec![
        setjoin_identity::login::risk(&auth_db, proof).await,
        session.risk(&auth_db).await,
        user.risk(&auth_db).await,
    ]
}

struct DomainSeen {
    risky: Vec<Risk>,
    malformed: Vec<Risk>,
    clean: Vec<Risk>,
    risk_fault: Vec<Risk>,
    flag_fault: Vec<Risk>,
}

/// Domain level: all three risk readers answer a claim for a risky user, None without a row,
/// and Err (never None) when the risk read or the flag read fails, also with the flag off.
#[tokio::test]
async fn risk_lookup_errors_fail_closed_in_every_issuer() {
    let Some(e) = env("failclosed-risk-domain").await else {
        return;
    };
    let saved = save_flags(&e.c).await.unwrap();
    let (a, email) = account(&e, "failclosed-risk-domain").await.unwrap();
    let observed = async {
        let bypass: bool = e.c.query_one("SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=current_user", &[]).await?.get(0);
        if !bypass {
            return Err("STOP: the owner DSN is neither superuser nor BYPASSRLS; user_risk (FORCE RLS) cannot be seeded".into());
        }
        set_flag(&e.c, "feature.user_risk", true).await?;
        let legacy = setjoin_authz::legacy_jwt::LegacyKeys::new(e.secret.as_bytes(), &["authserver-hmac-1"], None)?;
        let t = token(&e.secret, json!({"uid":a.user,"email":email,"jti":"failclosed-risk-domain-jti"}));
        let session = setjoin_identity::session::Session::verify(&t, None, &legacy, "mailserver").ok_or("HS256 session did not verify")?;
        let worker_dsn = std::env::var("DB_WORKER_DSN").unwrap_or_else(|_| e.db.dsn.clone());
        let worker_exec = setjoin_pg::ScopedExecutor::from_dsn(&worker_dsn, 2).unwrap();
        let auth_db = setjoin_pg::AuthDb::from_executors(e.exec.clone(), worker_exec);
        let proof = setjoin_identity::login::verify(&auth_db, &email, "Password1!", setjoin_config_secret::CryptoProfile::Standard).await.map_err(sf)?.ok_or("no password proof")?;
        let user = setjoin_identity::totp::CompletionUser::load(&auth_db, &session).await.map_err(sf)?.ok_or("no completion user")?;
        e.c.execute("INSERT INTO user_risk(user_id,score,level,signals) VALUES($1,55,'medium','[\"geo\"]'::jsonb)", &[&a.user]).await?;
        let risky = three(&e, &proof, &session, &user).await;
        let mut malformed = Vec::new();
        for bad in ["{\"geo\":1}", "null", "[1]", "\"geo\""] {
            e.c.execute("UPDATE user_risk SET signals=$2::text::jsonb WHERE user_id=$1", &[&a.user, &bad]).await?;
            malformed.extend(three(&e, &proof, &session, &user).await);
        }
        e.c.execute("DELETE FROM user_risk WHERE user_id=$1", &[&a.user]).await?;
        let clean = three(&e, &proof, &session, &user).await;
        let guard = revoke::table(&e.db.dsn, &e.c, &e.exec, "user_risk").await?;
        let risk_fault = three(&e, &proof, &session, &user).await;
        guard.restore(&e.c).await?;
        set_flag(&e.c, "feature.user_risk", false).await?;
        let guard = revoke::table(&e.db.dsn, &e.c, &e.exec, "feature_toggles").await?;
        let flag_fault = three(&e, &proof, &session, &user).await;
        guard.restore(&e.c).await?;
        Ok::<_, Err>(DomainSeen { risky, malformed, clean, risk_fault, flag_fault })
    }
    .await;
    let cleaned = async { settle(restore_flags(&e.c, &saved).await, cleanup(&e, &a).await) }.await;
    let seen = settle(observed, cleaned).unwrap();
    for r in &seen.risky {
        let v = r
            .as_ref()
            .expect("risky user")
            .as_ref()
            .expect("risk claim");
        assert_eq!(v["user_score"], json!(55), "{v}");
        assert_eq!(v["requires_mfa"], json!(true), "{v}");
    }
    for r in &seen.clean {
        assert_eq!(r, &Ok(None), "no row is no claim");
    }
    for r in seen
        .risk_fault
        .iter()
        .chain(seen.flag_fault.iter())
        .chain(seen.malformed.iter())
    {
        assert!(r.is_err(), "a failed read must not be 'no risk': {r:?}");
    }
}

struct LoginSeen {
    control: Reply,
    faulted: Reply,
    absent_clear: Reply,
    absent_faulted: Reply,
    wrong_faulted: Reply,
    before: (i64, i64),
    after: (i64, i64),
}

#[tokio::test]
async fn unreadable_login_hash_matches_absent() {
    use setjoin_config_secret::CryptoProfile::Standard;
    use std::time::{Duration, Instant};

    let Some(e) = env("failclosed-unreadable-login-hash").await else {
        return;
    };
    let saved = save_rate(&e.c).await.unwrap();
    let absent = absent();
    let ip = fixture_ip();
    let (a, email) = account(&e, "failclosed-unreadable-login-hash")
        .await
        .unwrap();
    let observed = async {
        set_flag(&e.c, RATE_FLAG, false).await?;
        let s = server(&e).await?;
        let password = "Wrong-Password1!";
        let login = |who: &str| {
            anonymous_from(&ip, "/auth/login", json!({"email":who,"password":password}))
        };
        let worker_dsn = std::env::var("DB_WORKER_DSN").unwrap_or_else(|_| e.db.dsn.clone());
        let worker_exec = setjoin_pg::ScopedExecutor::from_dsn(&worker_dsn, 2).unwrap();
        let exec = setjoin_pg::AuthDb::from_executors(e.exec.clone(), worker_exec);
        let exec = &exec;
        let address = email.as_str();
        let time_verify = |unreadable: bool| async move {
            // Use the fastest of three reads to limit the effect of DB and scheduler stalls.
            let mut fastest = Duration::MAX;
            for _ in 0..3 {
                let start = Instant::now();
                let result =
                    setjoin_identity::login::verify(exec, address, password, Standard).await;
                fastest = fastest.min(start.elapsed());
                match (unreadable, result) {
                    (false, Ok(None)) | (true, Err(_)) => {}
                    _ => return Err("unexpected password verification result".into()),
                }
            }
            Ok::<_, Err>(fastest)
        };
        // Calibrate with the same bcrypt cost and domain query as the dummy path.
        e.c.execute(
            "UPDATE users SET password_hash=$1 WHERE id=$2",
            &[&setjoin_identity::login::dummy_hash(Standard), &a.user],
        )
        .await?;
        let known_cost = time_verify(false).await?;
        e.c.execute(
            "UPDATE users SET password_hash=NULL WHERE id=$1",
            &[&a.user],
        )
        .await?;
        let unreadable_cost = time_verify(true).await?;
        let absent_reply = send(&s, login(&absent)?).await?;
        let unreadable_reply = send(&s, login(&email)?).await?;
        Ok::<_, Err>((absent_reply, unreadable_reply, known_cost, unreadable_cost))
    }
    .await;
    let residue = login_residue(&e, a.user, &[email, absent]).await;
    let cleaned = settle(
        settle(restore_rate(&e.c, saved).await, residue),
        cleanup(&e, &a).await,
    );
    let (absent_reply, unreadable_reply, known_cost, unreadable_cost) =
        settle(observed, cleaned).unwrap();
    assert_eq!(absent_reply.status, 401);
    assert!(absent_reply.body.contains("invalid credentials"));
    assert_eq!(
        (
            unreadable_reply.status,
            unreadable_reply.body,
            unreadable_reply.cookies
        ),
        (absent_reply.status, absent_reply.body, absent_reply.cookies),
    );
    assert!(
        known_cost > Duration::from_millis(10),
        "bcrypt cost must be measurable: {known_cost:?}"
    );
    assert!(
        unreadable_cost * 2 >= known_cost,
        "unreadable hash skipped dummy verification: {unreadable_cost:?} vs {known_cost:?}"
    );
}

#[tokio::test]
async fn scim_revoke_query_error_is_500() {
    let Some(e) = env("failclosed-scim-revoke").await else {
        return;
    };
    let mut cfg = config(&e);
    let key = uuid::Uuid::new_v4().to_string();
    cfg.internal_api_key = key.clone();
    let s = AuthServer::load(e.exec.clone(), cfg).await.unwrap();
    let external = uuid::Uuid::new_v4().to_string();
    let request = || {
        bearer(
            "POST",
            "/auth/scim/disable",
            &key,
            json!({"external_id":external}),
        )
    };
    let absent = send(&s, request().unwrap()).await.unwrap();
    let guard = revoke::revoke(
        &e.db.dsn,
        &e.c,
        &e.exec,
        "users",
        "REVOKE SELECT ON users FROM setjoin_app, setjoin_worker",
        "GRANT SELECT ON users TO setjoin_app, setjoin_worker",
        "SELECT 1 FROM users LIMIT 1",
    )
    .await
    .unwrap();
    let faulted = async { send(&s, request()?).await }.await;
    let faulted = settle(faulted, guard.restore(&e.c).await).unwrap();
    assert_eq!(absent.status, 200);
    assert_eq!(
        absent.body,
        "{\"reason\":\"user not found\",\"revoked\":false}\n"
    );
    assert_eq!(faulted.status, 500);
    let problem: Value = serde_json::from_str(&faulted.body).unwrap();
    assert_eq!(problem["detail"], "session revocation failed");
}

/// HTTP: password login with a failing risk read issues no token and stores no anchor. Under
/// the fault an absent account and an existing account with a wrong password answer alike,
/// and the absent reply equals the one without the fault.
#[tokio::test]
async fn password_login_risk_lookup_error_issues_no_token() {
    let Some(e) = env("failclosed-risk-login").await else {
        return;
    };
    let saved = save_flags(&e.c).await.unwrap();
    let absent = absent();
    let ip = fixture_ip();
    let (a, email) = account(&e, "failclosed-risk-login").await.unwrap();
    let observed = async {
        set_flag(&e.c, "feature.rate_limit", false).await?;
        set_flag(&e.c, "feature.user_risk", true).await?;
        let s = server(&e).await?;
        let login = |who: &str, pw: &str| {
            anonymous_from(&ip, "/auth/login", json!({"email":who,"password":pw}))
        };
        let absent_clear = send(&s, login(&absent, "Password1!")?).await?;
        let control = send(&s, login(&email, "Password1!")?).await?;
        let before = oauth_state(&e, a.user).await?;
        let guard = revoke::table(&e.db.dsn, &e.c, &e.exec, "user_risk").await?;
        let faulted = send(&s, login(&email, "Password1!")?).await?;
        let absent_faulted = send(&s, login(&absent, "Password1!")?).await?;
        let wrong_faulted = send(&s, login(&email, "Wrong-Password1!")?).await?;
        guard.restore(&e.c).await?;
        let after = oauth_state(&e, a.user).await?;
        Ok::<_, Err>(LoginSeen {
            control,
            faulted,
            absent_clear,
            absent_faulted,
            wrong_faulted,
            before,
            after,
        })
    }
    .await;
    let cleaned = async {
        let residue = login_residue(&e, a.user, &[email.clone(), absent.clone()]).await;
        settle(
            settle(restore_flags(&e.c, &saved).await, residue),
            cleanup(&e, &a).await,
        )
    }
    .await;
    let s = settle(observed, cleaned).unwrap();
    assert_eq!(s.control.status, 200, "{}", s.control.body);
    assert!(
        s.control.body.contains("access_token"),
        "{}",
        s.control.body
    );
    assert_eq!(s.faulted.status, 500, "{}", s.faulted.body);
    assert!(
        s.faulted.body.contains("token issue failed"),
        "{}",
        s.faulted.body
    );
    assert!(!s.faulted.body.contains("access_token") && !s.faulted.body.contains("refresh_token"));
    assert_eq!(
        s.after, s.before,
        "a refused login stores no refresh anchor"
    );
    assert_eq!(
        (
            s.wrong_faulted.status,
            &s.wrong_faulted.body,
            &s.wrong_faulted.cookies
        ),
        (
            s.absent_faulted.status,
            &s.absent_faulted.body,
            &s.absent_faulted.cookies
        ),
        "under the fault an existing account with a wrong password answers like an absent one"
    );
    assert_eq!(
        (
            s.absent_faulted.status,
            &s.absent_faulted.body,
            &s.absent_faulted.cookies
        ),
        (
            s.absent_clear.status,
            &s.absent_clear.body,
            &s.absent_clear.cookies
        ),
        "the fault does not change an absent account's reply"
    );
    assert!(
        !s.faulted.cookies.iter().any(|c| credential_cookie(c)),
        "a refused login sets no credential cookie: {:?}",
        s.faulted.cookies
    );
}

struct RefreshSeen {
    login: Reply,
    refresh_token: String,
    faulted: Reply,
    recovered: Reply,
    before: (i64, i64),
    after: (i64, i64),
}

/// HTTP (owner Q1): a refresh whose risk read fails answers 503 with Retry-After: 5, signs and
/// rotates nothing; the same refresh token works once the read works again.
#[tokio::test]
async fn refresh_risk_lookup_error_is_a_retryable_503() {
    let Some(e) = env("failclosed-risk-refresh").await else {
        return;
    };
    let saved = save_flags(&e.c).await.unwrap();
    let (a, email) = account(&e, "failclosed-risk-refresh").await.unwrap();
    let observed = async {
        set_flag(&e.c, "feature.rate_limit", false).await?;
        set_flag(&e.c, "feature.user_risk", true).await?;
        let s = server(&e).await?;
        let login = send(
            &s,
            anonymous(
                "/auth/login",
                json!({"email":email,"password":"Password1!"}),
            )?,
        )
        .await?;
        let refresh_token = serde_json::from_str::<Value>(&login.body)
            .ok()
            .and_then(|v| v["refresh_token"].as_str().map(str::to_owned))
            .unwrap_or_default();
        let before = oauth_state(&e, a.user).await?;
        let guard = revoke::table(&e.db.dsn, &e.c, &e.exec, "user_risk").await?;
        let faulted = send(
            &s,
            anonymous("/auth/refresh", json!({"refresh_token":refresh_token}))?,
        )
        .await?;
        guard.restore(&e.c).await?;
        let after = oauth_state(&e, a.user).await?;
        let recovered = send(
            &s,
            anonymous("/auth/refresh", json!({"refresh_token":refresh_token}))?,
        )
        .await?;
        Ok::<_, Err>(RefreshSeen {
            login,
            refresh_token,
            faulted,
            recovered,
            before,
            after,
        })
    }
    .await;
    let cleaned = async {
        let residue = login_residue(&e, a.user, &[email.clone()]).await;
        settle(
            settle(restore_flags(&e.c, &saved).await, residue),
            cleanup(&e, &a).await,
        )
    }
    .await;
    let s = settle(observed, cleaned).unwrap();
    assert_eq!(s.login.status, 200, "{}", s.login.body);
    assert!(
        !s.faulted.cookies.iter().any(|c| credential_cookie(c)),
        "a refused refresh sets no credential cookie: {:?}",
        s.faulted.cookies
    );
    assert!(
        !s.refresh_token.is_empty(),
        "login must return a refresh_token: {}",
        s.login.body
    );
    assert_eq!(s.faulted.status, 503, "{}", s.faulted.body);
    assert_eq!(s.faulted.retry_after.as_deref(), Some("5"));
    assert!(
        s.faulted
            .body
            .contains("Token refresh temporarily unavailable"),
        "{}",
        s.faulted.body
    );
    assert!(!s.faulted.body.contains("access_token") && !s.faulted.body.contains("refresh_token"));
    assert_eq!(
        s.after, s.before,
        "a refused refresh rotates and revokes nothing"
    );
    assert_eq!(s.recovered.status, 200, "{}", s.recovered.body);
}

struct CommonSeen {
    control: Reply,
    faulted: Reply,
    before: String,
    after: String,
}

/// HTTP: a failed common-password lookup refuses the change; the stored hash is unchanged.
#[tokio::test]
async fn common_password_lookup_error_refuses_the_change() {
    let Some(e) = env("failclosed-common").await else {
        return;
    };
    let (a, email) = account(&e, "failclosed-common").await.unwrap();
    let listed = "Zq9#listed-common-phrase";
    let digest = Sha256::digest(listed.trim().to_lowercase().as_bytes()).to_vec();
    let mut inserted = false;
    let observed = async {
        // Only a row this test inserted is removed again (a pre-existing listing is kept).
        let row = e
            .c
            .query_opt(
                "INSERT INTO common_passwords(password_hash) VALUES($1) ON CONFLICT DO NOTHING RETURNING 1",
                &[&digest],
            )
            .await?;
        inserted = row.is_some();
        let t = token(
            &e.secret,
            json!({"uid":a.user,"email":email,"jti":"failclosed-common-jti"}),
        );
        let s = server(&e).await?;
        let change = |new: &str| {
            bearer(
                "PUT",
                "/auth/password",
                &t,
                json!({"old_password":"Password1!","new_password":new}),
            )
        };
        let control = send(&s, change(listed)?).await?;
        let before = stored_hash(&e, a.user).await?;
        let guard = revoke::table(&e.db.dsn, &e.c, &e.exec, "common_passwords").await?;
        let faulted = send(&s, change("Zq9#long-new-passphrase")?).await?;
        guard.restore(&e.c).await?;
        let after = stored_hash(&e, a.user).await?;
        Ok::<_, Err>(CommonSeen {
            control,
            faulted,
            before,
            after,
        })
    }
    .await;
    let cleaned = async {
        let deleted: Result<(), Err> = if inserted {
            e.c.execute(
                "DELETE FROM common_passwords WHERE password_hash=$1",
                &[&digest],
            )
            .await
            .map(|_| ())
            .map_err(Into::into)
        } else {
            Ok(())
        };
        settle(deleted, cleanup(&e, &a).await)
    }
    .await;
    let s = settle(observed, cleaned).unwrap();
    assert_eq!(s.control.status, 400, "{}", s.control.body);
    assert!(s.control.body.contains("too common"), "{}", s.control.body);
    assert_eq!(s.faulted.status, 500, "{}", s.faulted.body);
    assert!(
        s.faulted.body.contains("internal error"),
        "{}",
        s.faulted.body
    );
    assert_eq!(s.after, s.before, "a refused change writes no credential");
}

struct TotpSeen {
    control: Reply,
    empty: Reply,
    grants: i64,
    failures: i32,
}

/// HTTP (#455): a TOTP secret that decrypts to "" verifies nothing. Go accepts the empty-key
/// code; Rust answers the evaluated 403 and counts the failure. Control: a real secret issues.
#[tokio::test]
async fn empty_totp_secret_proves_no_possession() {
    let Some(e) = env("failclosed-empty-totp").await else {
        return;
    };
    let saved = save_flags(&e.c).await.unwrap();
    let (a, _email) = account(&e, "failclosed-empty-totp").await.unwrap();
    let observed = async {
        set_flag(&e.c, "feature.rate_limit", false).await?;
        let seed = "UPDATE users SET totp_enabled=true,totp_secret_enc=pgp_sym_encrypt($2,$3),totp_enabled_at=now(),totp_failed_attempts=0,totp_locked_until=NULL WHERE id=$1";
        let t = token(&e.secret, json!({"uid":a.user,"jti":"failclosed-empty-totp-jti"}));
        let s = server(&e).await?;
        let prove = |code: String| bearer("POST", "/auth/mfa/possession/totp", &t, json!({"code":code,"operation":"recovery.regenerate"}));
        e.c.execute(seed, &[&a.user, &"JBSWY3DPEHPK3PXP", &ENC]).await?;
        let control = send(&s, prove(setjoin_identity::totp::code("JBSWY3DPEHPK3PXP", now()).ok_or("control code")?)?).await?;
        e.c.execute("DELETE FROM mfa_reauth_step_ups WHERE user_id=$1", &[&a.user]).await?;
        e.c.execute(seed, &[&a.user, &"", &ENC]).await?;
        let empty = send(&s, prove(setjoin_identity::totp::code("", now()).ok_or("empty-key code")?)?).await?;
        let grants: i64 = e.c.query_one("SELECT count(*) FROM mfa_reauth_step_ups WHERE user_id=$1", &[&a.user]).await?.get(0);
        let failures: i32 = e.c.query_one("SELECT totp_failed_attempts FROM users WHERE id=$1", &[&a.user]).await?.get(0);
        Ok::<_, Err>(TotpSeen { control, empty, grants, failures })
    }
    .await;
    let cleaned = async { settle(restore_flags(&e.c, &saved).await, cleanup(&e, &a).await) }.await;
    let s = settle(observed, cleaned).unwrap();
    assert_eq!(
        s.control.status, 200,
        "control must reach the verifier and issue: {}",
        s.control.body
    );
    assert_eq!(s.empty.status, 403, "{}", s.empty.body);
    assert!(
        s.empty.body.contains("invalid TOTP code"),
        "{}",
        s.empty.body
    );
    assert_eq!(s.grants, 0, "an empty key issues no grant");
    assert_eq!(s.failures, 1, "an empty key is an evaluated wrong code");
}

struct AuthoritySeen {
    replay: Reply,
    revoked: Reply,
    live_after_replay: i64,
    all_revocations: i64,
}

/// HTTP (Codex r1 P1-1): the reducer decides authority before the risk read. Under a risk
/// fault, a rotated parent replayed outside the 30 s grace still gets the existing 401 and
/// still revokes every session, and a revoked token still gets 401 (never 503).
#[tokio::test]
async fn refresh_authority_decides_before_the_risk_read() {
    let Some(e) = env("failclosed-risk-authority").await else {
        return;
    };
    let saved = save_flags(&e.c).await.unwrap();
    let (a, email) = account(&e, "failclosed-risk-authority").await.unwrap();
    let observed = async {
        set_flag(&e.c, "feature.rate_limit", false).await?;
        set_flag(&e.c, "feature.user_risk", true).await?;
        let s = server(&e).await?;
        let token_of = |reply: &Reply| {
            serde_json::from_str::<Value>(&reply.body)
                .ok()
                .and_then(|v| v["refresh_token"].as_str().map(str::to_owned))
        };
        let login = send(&s, anonymous("/auth/login", json!({"email":email,"password":"Password1!"}))?).await?;
        let parent = token_of(&login).ok_or_else(|| format!("login returned no refresh_token: {}", login.body))?;
        let rotated = send(&s, anonymous("/auth/refresh", json!({"refresh_token":parent}))?).await?;
        let child = token_of(&rotated).ok_or_else(|| format!("first refresh did not rotate: {} {}", rotated.status, rotated.body))?;
        let parent_hash = Sha256::digest(parent.as_bytes()).to_vec();
        e.c.execute("UPDATE oauth_tokens SET rotated_at=now()-interval '60 seconds' WHERE user_id=$1 AND token_hash=$2", &[&a.user, &parent_hash]).await?;
        let guard = revoke::table(&e.db.dsn, &e.c, &e.exec, "user_risk").await?;
        let replay = send(&s, anonymous("/auth/refresh", json!({"refresh_token":parent}))?).await?;
        let revoked = send(&s, anonymous("/auth/refresh", json!({"refresh_token":child}))?).await?;
        guard.restore(&e.c).await?;
        let live_after_replay: i64 = e.c.query_one("SELECT count(*) FROM oauth_tokens WHERE user_id=$1 AND revoked_at IS NULL", &[&a.user]).await?.get(0);
        let all_revocations: i64 = e.c.query_one("SELECT count(*) FROM session_revocations WHERE user_id=$1 AND scope='all'", &[&a.user]).await?.get(0);
        Ok::<_, Err>(AuthoritySeen { replay, revoked, live_after_replay, all_revocations })
    }
    .await;
    let cleaned = async {
        let residue = login_residue(&e, a.user, &[email.clone()]).await;
        settle(
            settle(restore_flags(&e.c, &saved).await, residue),
            cleanup(&e, &a).await,
        )
    }
    .await;
    let s = settle(observed, cleaned).unwrap();
    assert_eq!(s.replay.status, 401, "{}", s.replay.body);
    assert!(
        s.replay.body.contains("invalid or revoked refresh token"),
        "{}",
        s.replay.body
    );
    assert_eq!(
        s.live_after_replay, 0,
        "reuse detection must still revoke every refresh token"
    );
    assert_eq!(
        s.all_revocations, 1,
        "reuse detection must still record the all-session revocation"
    );
    assert_eq!(s.revoked.status, 401, "{}", s.revoked.body);
    assert!(
        s.revoked.body.contains("invalid or revoked refresh token"),
        "{}",
        s.revoked.body
    );
    for r in [&s.replay, &s.revoked] {
        assert!(
            r.retry_after.is_none(),
            "a denied token is not retryable: {:?}",
            r.retry_after
        );
        assert!(!r.cookies.iter().any(|c| credential_cookie(c)));
    }
}
