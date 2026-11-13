//! Owner-approved security fixes of 2026-11-05 (#490 #491 #495 #487): each test
//! asserts the secure behaviour; `scripts/test-secfix3-mutants.py` restores the
//! frozen-Go bug (feature `oracle-mutants`, `SETJOIN_SECFIX3_MUTANT`) and requires
//! the test to fail. Tests hold the family advisory lock like the other auth cases.
mod common;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use http_body_util::BodyExt;
use hyper::Request;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::{json, Value};
use setjoin_auth::{body, AuthServer, Config};
use setjoin_authz::legacy_jwt::sign_hs256;
use setjoin_conformance::{fixture, harness::Db};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

type Client = tokio_postgres::Client;
struct Env {
    c: Client,
    secret: String,
    exec: setjoin_pg::ScopedExecutor,
}
async fn env(case: &str) -> Option<Env> {
    let db = Db::for_case(case)?;
    let c = db.connect().await.unwrap();
    c.query_one("SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))", &[]).await.unwrap();
    common::signing_key(&c).await;
    let f: Value = serde_json::from_str(include_str!("../../../tests/conformance/identity-login/keys.json")).unwrap();
    let exec = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).unwrap();
    Some(Env { c, secret: f["secret"].as_str().unwrap().into(), exec })
}
fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
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
async fn send(server: &AuthServer, req: Request<setjoin_auth::Body>) -> (u16, String) {
    let r = server.handle(req).await;
    let s = r.status().as_u16();
    (s, String::from_utf8_lossy(&r.into_body().collect().await.unwrap().to_bytes()).into_owned())
}
async fn server(e: &Env, dsn: Option<&str>) -> AuthServer {
    let mut cfg = Config::for_secret(e.secret.clone());
    cfg.worker_dsn = None;
    if let Some(d) = dsn {
        cfg.dsn = d.into();
    }
    AuthServer::load(e.exec.clone(), cfg).await.unwrap()
}
fn post(path: &str, token: &str, extra: &[(&str, String)], payload: String) -> Request<setjoin_auth::Body> {
    let mut b = Request::post(path)
        .header("host", "mail.test")
        .header("origin", "http://mail.test")
        .header("authorization", format!("Bearer {token}"));
    for (k, v) in extra {
        b = b.header(*k, v);
    }
    b.body(body(payload)).unwrap()
}

#[tokio::test]
async fn unknown_email_login_costs_a_password_hash_under_every_profile() {
    use setjoin_config_secret::CryptoProfile::{Hybrid, Smx, Standard};
    let Some(e) = env("secfix3-login-timing").await else { return };
    // The dummy hash has the algorithm of the profile's own writes.
    for (profile, sm3) in [(Standard, false), (Smx, true), (Hybrid, true)] {
        assert_eq!(setjoin_identity::login::dummy_hash(profile).starts_with("$sm3$"), sm3, "{profile:?}");
    }
    let a = fixture::account(&e.c, "secfix3-timing").await.unwrap();
    let email: String = e.c.query_one("SELECT email FROM users WHERE id=$1", &[&a.user]).await.unwrap().get(0);
    let mut seen = Vec::new();
    for profile in [Standard, Smx] {
        let hash = setjoin_authz::password::hash("Password1!", profile).unwrap();
        e.c.execute("UPDATE users SET password_hash=$1 WHERE id=$2", &[&hash, &a.user]).await.unwrap();
        let time = |who: String| {
            let exec = e.exec.clone();
            async move {
                let t = std::time::Instant::now();
                let r = setjoin_identity::login::verify(&exec, &who, "wrong-Password1!", profile).await.unwrap();
                assert!(r.is_none());
                t.elapsed()
            }
        };
        let known = time(email.clone()).await;
        let unknown = time("nobody-secfix3@nowhere.invalid".into()).await;
        seen.push((profile, known, unknown));
    }
    fixture::remove(&e.c, &a).await.unwrap();
    for (profile, known, unknown) in seen {
        assert!(known > std::time::Duration::from_millis(10), "{profile:?}: hash cost must be measurable: {known:?}");
        assert!(unknown * 2 >= known, "{profile:?}: unknown email skipped the password hash: unknown {unknown:?} vs known {known:?}");
    }
}

#[tokio::test]
async fn revocations_fail_closed_until_the_first_load() {
    let Some(e) = env("secfix3-revocations").await else { return };
    let a = fixture::account(&e.c, "secfix3-rev").await.unwrap();
    let t = token(&e.secret, json!({"uid":a.user,"email":"x@y","jti":"secfix3-rev-jti"}));
    let get = |t: &str| Request::get("/auth/me").header("authorization", format!("Bearer {t}")).body(body("")).unwrap();
    let good = server(&e, None).await;
    let (ok, _) = send(&good, get(&t)).await;
    let bad = server(&e, Some("postgres://nobody@127.0.0.1:1/none")).await;
    let (closed, _) = send(&bad, get(&t)).await;
    fixture::remove(&e.c, &a).await.unwrap();
    assert_eq!(ok, 200, "loaded list admits a live token");
    assert_eq!(closed, 401, "a never-loaded revocation list must refuse tokens");
}

#[tokio::test]
async fn oversized_password_and_internal_key_bodies_are_refused() {
    let Some(e) = env("secfix3-body-caps").await else { return };
    let a = fixture::account(&e.c, "secfix3-caps").await.unwrap();
    let t = token(&e.secret, json!({"uid":a.user,"email":"x@y","jti":"secfix3-caps-jti"}));
    let mut cfg = Config::for_secret(e.secret.clone());
    cfg.worker_dsn = None;
    cfg.internal_api_key = "secfix3-internal-key".into();
    let s = AuthServer::load(e.exec.clone(), cfg).await.unwrap();
    let flags: String = e.c.query_one("SELECT coalesce(jsonb_agg(to_jsonb(t)),'[]')::text FROM feature_toggles t WHERE key='feature.rate_limit'", &[]).await.unwrap().get(0);
    e.c.batch_execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false").await.unwrap();
    let huge = format!("{{\"old_password\":\"{}\"}}", "a".repeat((1 << 20) + 16));
    let put = Request::put("/auth/password").header("host", "mail.test").header("origin", "http://mail.test").header("authorization", format!("Bearer {t}")).body(body(huge.clone())).unwrap();
    let (p, pb) = send(&s, put).await;
    let scim = Request::post("/auth/scim/disable").header("authorization", "Bearer secfix3-internal-key").body(body(huge)).unwrap();
    let (i, ib) = send(&s, scim).await;
    e.c.batch_execute("DELETE FROM feature_toggles WHERE key='feature.rate_limit'").await.unwrap();
    e.c.execute("INSERT INTO feature_toggles SELECT * FROM jsonb_populate_recordset(NULL::feature_toggles,$1::text::jsonb)", &[&flags]).await.unwrap();
    fixture::remove(&e.c, &a).await.unwrap();
    assert_eq!(p, 400, "{pb}");
    assert!(pb.contains("invalid JSON"), "{pb}");
    assert_eq!(i, 400, "{ib}");
}

#[tokio::test]
async fn password_change_is_keyed_on_the_signed_uid_not_the_signed_email() {
    let Some(e) = env("secfix3-password-uid").await else { return };
    let a = fixture::account(&e.c, "secfix3-pw-a").await.unwrap();
    let b = fixture::account(&e.c, "secfix3-pw-b").await.unwrap();
    let hb = bcrypt::hash("VictimPass-1!", 4).unwrap();
    let ha = bcrypt::hash("AttackerPass-1!", 4).unwrap();
    e.c.execute("UPDATE users SET password_hash=$1 WHERE id=$2", &[&hb, &b.user]).await.unwrap();
    e.c.execute("UPDATE users SET password_hash=$1 WHERE id=$2", &[&ha, &a.user]).await.unwrap();
    let b_email: String = e.c.query_one("SELECT email FROM users WHERE id=$1", &[&b.user]).await.unwrap().get(0);
    // A's token carries B's (stale) email.
    let t = token(&e.secret, json!({"uid":a.user,"email":b_email,"jti":"secfix3-pw-jti"}));
    let s = server(&e, None).await;
    let req = Request::put("/auth/password").header("host", "mail.test").header("origin", "http://mail.test").header("authorization", format!("Bearer {t}"))
        .body(body(json!({"old_password":"VictimPass-1!","new_password":"Zq9#long-new-passphrase"}).to_string())).unwrap();
    let (status, text) = send(&s, req).await;
    let after_b: String = e.c.query_one("SELECT password_hash FROM users WHERE id=$1", &[&b.user]).await.unwrap().get(0);
    let after_a: String = e.c.query_one("SELECT password_hash FROM users WHERE id=$1", &[&a.user]).await.unwrap().get(0);
    fixture::remove(&e.c, &a).await.unwrap();
    fixture::remove(&e.c, &b).await.unwrap();
    assert_eq!(status, 403, "{text}");
    assert_eq!(after_b, hb, "another user's credential row was changed");
    assert_eq!(after_a, ha);
}

#[tokio::test]
async fn refresh_grace_never_accepts_a_revoked_or_expired_rotated_parent() {
    let Some(e) = env("secfix3-refresh-grace").await else { return };
    let a = fixture::account(&e.c, "secfix3-grace").await.unwrap();
    let fam = "5e5f3c0a-0000-4000-8000-000000000333";
    let mut seen = Vec::new();
    for (name, revoked, expires) in [("live", "NULL", "now()+interval '1 hour'"), ("revoked", "now()", "now()+interval '1 hour'"), ("expired", "NULL", "now()-interval '1 minute'")] {
        e.c.execute("DELETE FROM oauth_tokens WHERE user_id=$1", &[&a.user]).await.unwrap();
        let parent = Sha256::digest(format!("parent-{name}").as_bytes()).to_vec();
        let tip = Sha256::digest(format!("tip-{name}").as_bytes()).to_vec();
        e.c.execute(&format!("INSERT INTO oauth_tokens(user_id,token_hash,token_type,expires_at,family_id,rotated_at,revoked_at) VALUES($1,$2,'refresh',{expires},$3::text::uuid,now()-interval '5 seconds',{revoked})"), &[&a.user, &parent, &fam]).await.unwrap();
        e.c.execute("INSERT INTO oauth_tokens(user_id,token_hash,token_type,expires_at,family_id,previous_token_hash) VALUES($1,$2,'refresh',now()+interval '1 hour',$3::text::uuid,$4)", &[&a.user, &tip, &fam, &parent]).await.unwrap();
        let r: String = e.c.query_one("SELECT rust_identity_refresh($1,$2,$3,NULL,NULL,0,NULL)::text", &[&a.user, &parent, &fam]).await.unwrap().get(0);
        seen.push((name, serde_json::from_str::<Value>(&r).unwrap()["status"].as_str().unwrap().to_owned()));
    }
    e.c.execute("DELETE FROM oauth_tokens WHERE user_id=$1", &[&a.user]).await.unwrap();
    fixture::remove(&e.c, &a).await.unwrap();
    assert_eq!(seen, vec![("live", "mint".to_owned()), ("revoked", "denied".to_owned()), ("expired", "denied".to_owned())]);
}

async fn role(c: &Client, user: i64, perms: &[&str], scope: Option<i64>, name: &str) {
    let perms: Vec<String> = perms.iter().map(|s| s.to_string()).collect();
    c.execute("INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,$3)", &[&name, &perms, &scope]).await.unwrap();
    c.execute("INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,eligible) SELECT $1,id,$1,false FROM admin_role_groups WHERE name=$2", &[&user, &name]).await.unwrap();
}
async fn drop_role(c: &Client, user: i64, name: &str) {
    c.execute("DELETE FROM admin_role_assignments WHERE user_id=$1", &[&user]).await.unwrap();
    c.execute("DELETE FROM admin_role_groups WHERE name=$1", &[&name]).await.unwrap();
}

#[tokio::test]
async fn scoped_admin_impersonates_only_inside_its_domains() {
    let Some(e) = env("secfix3-impersonate").await else { return };
    let admin = fixture::account(&e.c, "secfix3-adm").await.unwrap();
    let own = fixture::account(&e.c, "secfix3-own").await.unwrap();
    let foreign = fixture::account(&e.c, "secfix3-foreign").await.unwrap();
    e.c.execute("UPDATE users SET domain_id=$1 WHERE id=$2", &[&admin.domain, &own.user]).await.unwrap();
    let rname = format!("secfix3-scoped-{}", admin.user);
    role(&e.c, admin.user, &["users.impersonate"], Some(admin.domain), &rname).await;
    let s = server(&e, None).await;
    let t = token(&e.secret, json!({"uid":admin.user,"email":"adm@x","admin":true,"jti":"secfix3-imp-jti"}));
    let imp = |id: i64| post(&format!("/auth/admin/users/{id}/impersonate"), &t, &[], String::new());
    let (own_s, own_b) = send(&s, imp(own.user)).await;
    let (foreign_s, foreign_b) = send(&s, imp(foreign.user)).await;
    drop_role(&e.c, admin.user, &rname).await;
    role(&e.c, admin.user, &["users.impersonate"], None, &rname).await;
    let (global_s, global_b) = send(&s, imp(foreign.user)).await;
    drop_role(&e.c, admin.user, &rname).await;
    e.c.execute("UPDATE users SET domain_id=$1 WHERE id=$2", &[&own.domain, &own.user]).await.unwrap();
    for a in [&admin, &own, &foreign] {
        fixture::remove(&e.c, a).await.unwrap();
    }
    assert_eq!(own_s, 200, "{own_b}");
    assert_eq!(foreign_s, 403, "{foreign_b}");
    assert_eq!(global_s, 200, "{global_b}");
}

fn dpop(key: &SigningKey, method: &str, uri: &str, access: &str, jti: &str) -> (String, String) {
    let point = key.verifying_key().to_sec1_point(false);
    let (x, y) = (B64.encode(point.x().unwrap()), B64.encode(point.y().unwrap()));
    let jwk = json!({"kty":"EC","crv":"P-256","x":x,"y":y});
    let jkt = setjoin_authz::dpop::thumbprint(&jwk).unwrap();
    let h = B64.encode(json!({"typ":"dpop+jwt","alg":"ES256","jwk":jwk}).to_string());
    let p = B64.encode(json!({"htm":method,"htu":uri,"iat":now(),"jti":jti,"ath":B64.encode(Sha256::digest(access.as_bytes()))}).to_string());
    let sig: Signature = key.sign(format!("{h}.{p}").as_bytes());
    (format!("{h}.{p}.{}", B64.encode(sig.to_bytes())), jkt)
}
fn device_body() -> String {
    json!({"fingerprint":"f".repeat(40),"platform":"linux","device_name":"secfix3"}).to_string()
}

#[tokio::test]
async fn revoked_token_gets_no_device_secret() {
    let Some(e) = env("secfix3-device-revoked").await else { return };
    let a = fixture::account(&e.c, "secfix3-devrev").await.unwrap();
    e.c.execute("INSERT INTO session_revocations(user_id,scope,jti,reason,not_before,expires_at) VALUES($1,'jti','secfix3-devrev-jti','fixture',now(),now()+interval '1 hour')", &[&a.user]).await.unwrap();
    let t = token(&e.secret, json!({"uid":a.user,"email":"x@y","jti":"secfix3-devrev-jti"}));
    let s = server(&e, None).await;
    let (status, text) = send(&s, post("/device/register", &t, &[], device_body())).await;
    e.c.execute("DELETE FROM devices WHERE user_id=$1", &[&a.user]).await.unwrap();
    e.c.execute("DELETE FROM session_revocations WHERE user_id=$1", &[&a.user]).await.unwrap();
    fixture::remove(&e.c, &a).await.unwrap();
    assert_eq!(status, 401, "{text}");
    assert!(!text.contains("hmac_secret\":\"") || text.contains("hmac_secret\":\"\""), "{text}");
}

#[tokio::test]
async fn bound_token_needs_a_dpop_proof_on_device_register() {
    let Some(e) = env("secfix3-device-bound").await else { return };
    let a = fixture::account(&e.c, "secfix3-devbound").await.unwrap();
    let key = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let uri = "https://mail.test/device/register";
    let (_, jkt) = dpop(&key, "POST", uri, "x", "probe");
    let t = token(&e.secret, json!({"uid":a.user,"email":"x@y","jti":"secfix3-devbound-jti","cnf":{"jkt":jkt}}));
    let s = server(&e, None).await;
    let (none_s, none_b) = send(&s, post("/device/register", &t, &[], device_body())).await;
    let (other, _) = dpop(&key, "POST", uri, "some-other-token", "j2");
    let (wrong_ath, _) = send(&s, post("/device/register", &t, &[("dpop", other)], device_body())).await;
    let (good, _) = dpop(&key, "POST", uri, &t, "j3");
    let (ok_s, ok_b) = send(&s, post("/device/register", &t, &[("dpop", good)], device_body())).await;
    e.c.execute("DELETE FROM devices WHERE user_id=$1", &[&a.user]).await.unwrap();
    fixture::remove(&e.c, &a).await.unwrap();
    assert_eq!(none_s, 401, "{none_b}");
    assert_eq!(wrong_ath, 401);
    assert_eq!(ok_s, 201, "{ok_b}");
}

#[tokio::test]
async fn drive_native_token_keeps_act_provenance() {
    let Some(e) = env("secfix3-drive-act").await else { return };
    let a = fixture::account(&e.c, "secfix3-drive").await.unwrap();
    let keys = setjoin_authz::jwks::Jwks::with_fetch(Box::new(|| Box::pin(async { panic!("no JWKS") })))
        .with_legacy_keys(setjoin_authz::legacy_jwt::LegacyKeys::new(e.secret.as_bytes(), &["authserver-hmac-1"], None).unwrap());
    let t = token(&e.secret, json!({"uid":a.user,"email":"x@y","jti":"secfix3-drive-jti","act":4242}));
    let id = setjoin_authz::push::authenticate_drive(&e.exec, &keys, "mailserver", &t).await.ok().unwrap();
    let out = setjoin_identity::drive_token::Issuer::new(b"secfix3-drive-secret-32-bytes-long!", "mailserver".into()).issue(&id, now()).ok().unwrap();
    fixture::remove(&e.c, &a).await.unwrap();
    let v: Value = serde_json::from_str(&out).unwrap();
    let payload = v["token"].as_str().unwrap().split('.').nth(1).unwrap();
    let claims: Value = serde_json::from_slice(&B64.decode(payload).unwrap()).unwrap();
    assert_eq!(claims["act"], json!(4242), "{claims}");
}
