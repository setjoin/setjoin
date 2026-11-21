//! #351 Conditional Access, Device Trust Claims, and Session Controls across all 7 sign-in families.
#![allow(dead_code)]
mod common;
#[path = "common/revoke.rs"]
mod revoke;
#[path = "../../../crates/domains/identity/tests/saml_acs/support.rs"]
mod saml_support;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_auth::{body, AuthServer, Config};
use setjoin_conformance::{fixture, harness::Db};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    path::Path,
    sync::{Arc, Mutex},
};
use tokio_postgres::Client;

type Err = Box<dyn std::error::Error + Send + Sync>;

const ENC: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const SAML_ENC: &str = "idfed3-test-encryption-key-at-least-32-bytes";
const PASSWORD: &str = "Password1!";
const TOTP_SECRET: &str = "JBSWY3DPEHPK3PXP";
const STAGED_SECRET: &str = "KRSXG5CTMVRXEZLU";
const BACKUP_CODE: &str = "BACKUP-351-CODE";
const VAPID: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const OIDC_ISSUER: &str = "https://idp.ca351.test";
const OIDC_CLIENT: &str = "setjoin-ca-351";
const OIDC_REDIRECT: &str = "https://auth.ca351.test/auth/oidc/callback";
const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) CA351/1.0";

const TOGGLES: [&str; 7] = [
    "feature.rate_limit",
    "feature.conditional_access",
    "feature.device_trust_enforcement",
    "feature.token_binding",
    "feature.identity_model_v2",
    "feature.identity_normalized_reads",
    "feature.require_mfa",
];

macro_rules! check {
    ($cond:expr) => {
        check!($cond, "assertion failed: {}", stringify!($cond))
    };
    ($cond:expr, $($arg:tt)+) => {
        if !$cond {
            return Err(format!($($arg)+).into());
        }
    };
}

macro_rules! check_eq {
    ($left:expr, $right:expr) => {
        match (&$left, &$right) {
            (left, right) => {
                if !(*left == *right) {
                    return Err(format!("expected {:?} == {:?}", left, right).into());
                }
            }
        }
    };
    ($left:expr, $right:expr, $($arg:tt)+) => {
        match (&$left, &$right) {
            (left, right) => {
                if !(*left == *right) {
                    return Err(format!($($arg)+).into());
                }
            }
        }
    };
}

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn master_secret() -> String {
    let keys: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    keys["secret"].as_str().unwrap().to_owned()
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn jwt_claims(token: &str) -> Result<Value, Err> {
    let payload = token.split('.').nth(1).ok_or("jwt missing payload")?;
    let bytes = URL_SAFE_NO_PAD.decode(payload)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn build_request(
    method: &str,
    uri: &str,
    peer_ip: &str,
    ua: &str,
    raw: Vec<u8>,
    headers: &[(&str, &str)],
) -> Result<Request<setjoin_auth::Body>, Err> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "auth.ca351.test")
        .header("origin", "https://auth.ca351.test")
        .header("x-forwarded-proto", "https")
        .header("user-agent", ua);
    if !headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
    {
        builder = builder.header("content-type", "application/json");
    }
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let peer: SocketAddr = format!("{peer_ip}:40000").parse()?;
    let mut req = builder.body(body(raw))?;
    req.extensions_mut()
        .insert(setjoin_auth::ConnectionMeta { peer, tls: false });
    Ok(req)
}

async fn read_body(
    resp: Response<setjoin_auth::Body>,
) -> Result<(u16, hyper::HeaderMap, String), Err> {
    let status = resp.status().as_u16();
    let headers = resp.headers().clone();
    let bytes = resp.into_body().collect().await?.to_bytes();
    Ok((status, headers, String::from_utf8(bytes.to_vec())?))
}

use http_body_util::BodyExt as _;

async fn snapshot_toggles(c: &Client) -> Result<Vec<(&'static str, Option<bool>)>, Err> {
    let mut out = Vec::with_capacity(TOGGLES.len());
    for key in TOGGLES {
        let val = c
            .query_opt("SELECT enabled FROM feature_toggles WHERE key=$1", &[&key])
            .await?
            .map(|r| r.get(0));
        out.push((key, val));
    }
    Ok(out)
}

async fn restore_toggles(c: &Client, saved: &[(&'static str, Option<bool>)]) -> Result<(), Err> {
    for (key, val) in saved {
        match val {
            Some(v) => {
                c.execute(
                    "INSERT INTO feature_toggles(key,enabled) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET enabled=excluded.enabled",
                    &[key, v],
                )
                .await?;
            }
            None => {
                c.execute("DELETE FROM feature_toggles WHERE key=$1", &[key])
                    .await?;
            }
        }
    }
    Ok(())
}

async fn set_toggles(c: &Client, ca: bool, dt: bool, rate_limit: bool) -> Result<(), Err> {
    for (key, enabled) in [
        ("feature.rate_limit", rate_limit),
        ("feature.conditional_access", ca),
        ("feature.device_trust_enforcement", dt),
        ("feature.token_binding", false),
        ("feature.identity_model_v2", false),
        ("feature.identity_normalized_reads", false),
        ("feature.require_mfa", true),
    ] {
        c.execute(
            "INSERT INTO feature_toggles(key,enabled) VALUES($1,$2) ON CONFLICT(key) DO UPDATE SET enabled=excluded.enabled",
            &[&key, &enabled],
        )
        .await?;
    }
    Ok(())
}

fn device_hash_for(ua: &str, ip: &str) -> String {
    let fp = setjoin_threat::fingerprint(ua, ip);
    format!("{:x}", Sha256::digest(fp.as_bytes()))
}

async fn insert_managed_device(
    c: &Client,
    user_id: i64,
    ua: &str,
    ip: &str,
    status: &str,
) -> Result<String, Err> {
    let hash = device_hash_for(ua, ip);
    c.execute(
        "INSERT INTO managed_devices(device_hash,user_id,device_name,os_type,compliance_status) VALUES($1,$2,'CA351 Box','windows',$3) ON CONFLICT(device_hash) DO UPDATE SET compliance_status=excluded.compliance_status WHERE managed_devices.user_id=excluded.user_id",
        &[&hash, &user_id, &status],
    )
    .await?;
    Ok(hash)
}

async fn insert_policy(
    c: &Client,
    policy_ids: &mut Vec<i64>,
    priority: i32,
    name: &str,
    state: &str,
    scope_type: &str,
    scope_target: &str,
    conditions: Value,
    actions: Value,
    session_control: Value,
) -> Result<i64, Err> {
    let cond = conditions.to_string();
    let act = actions.to_string();
    let sc = session_control.to_string();
    let id: i64 = c.query_one(
        "INSERT INTO conditional_access_policies(priority,name,description,state,scope_type,scope_target,conditions,actions,session_control) VALUES($1,$2,'ca351 test',$3,$4,$5,$6::text::jsonb,$7::text::jsonb,$8::text::jsonb) RETURNING id",
        &[&priority, &name, &state, &scope_type, &scope_target, &cond, &act, &sc],
    )
    .await?
    .get(0);
    policy_ids.push(id);
    Ok(id)
}

async fn delete_policies(c: &Client, policy_ids: &mut Vec<i64>) -> Result<(), Err> {
    if !policy_ids.is_empty() {
        c.execute(
            "DELETE FROM conditional_access_policies WHERE id = ANY($1)",
            &[&policy_ids],
        )
        .await?;
        policy_ids.clear();
    }
    Ok(())
}

async fn ca_log_count(c: &Client, user_id: i64) -> Result<i64, Err> {
    Ok(c.query_one(
        "SELECT count(*) FROM ca_signin_log WHERE user_id=$1",
        &[&user_id],
    )
    .await?
    .get(0))
}

async fn cleanup_ca(
    c: &Client,
    policy_ids: &[i64],
    users: &[i64],
    emails: &[String],
    device_hashes: &[String],
) -> Result<(), Err> {
    if !policy_ids.is_empty() {
        let _ = c
            .execute(
                "DELETE FROM conditional_access_policies WHERE id = ANY($1)",
                &[&policy_ids],
            )
            .await;
    }
    let _ = c
        .execute(
            "DELETE FROM rate_limit_counters WHERE key LIKE 'auth:http:127.0.51.%'",
            &[],
        )
        .await;
    for h in device_hashes {
        let _ = c
            .execute(
                "DELETE FROM managed_devices WHERE device_hash=$1 AND user_id = ANY($2)",
                &[h, &users],
            )
            .await;
    }
    for &uid in users {
        let _ = c
            .batch_execute(&format!(
                "BEGIN;SET LOCAL ca.signin_log_prune='on';DELETE FROM ca_signin_log WHERE user_id={uid};COMMIT"
            ))
            .await;
        let _ = c
            .batch_execute(&format!(
                "BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={uid};COMMIT"
            ))
            .await;
        for table in [
            "push_devices",
            "push_mfa_challenges",
            "passkey_credentials",
            "totp_counter_claims",
            "totp_pending_enrollments",
            "mfa_reauth_step_ups",
            "admin_role_assignments",
            "login_events",
            "sessions",
            "oauth_tokens",
        ] {
            let _ = c
                .execute(&format!("DELETE FROM {table} WHERE user_id=$1"), &[&uid])
                .await;
        }
    }
    for email in emails {
        let _ = c
            .execute("DELETE FROM auth_event_log WHERE email=$1", &[email])
            .await;
        let _ = c
            .execute(
                "DELETE FROM auth_attempts WHERE target_username=$1",
                &[email],
            )
            .await;
    }
    Ok(())
}

async fn cleanup_identity_source(c: &Client, provider_key: &str) {
    let _ = c
        .execute(
            "WITH s AS (SELECT x.id FROM identity_sources x WHERE x.provider_key=$1 AND NOT EXISTS (SELECT 1 FROM user_identity_links l WHERE l.source_id=x.id)), a AS (DELETE FROM identity_auth_shadow_hours WHERE source_id IN (SELECT id FROM s)), b AS (DELETE FROM identity_auth_shadow_link_evidence WHERE source_id IN (SELECT id FROM s)), d AS (DELETE FROM identity_shadow_divergences WHERE source_id IN (SELECT id FROM s)) DELETE FROM identity_sources WHERE id IN (SELECT id FROM s)",
            &[&provider_key],
        )
        .await;
}

async fn start_oidc_flow(
    srv: &AuthServer,
    fake: &FakeOidcHttp,
    ip: &str,
    email: &str,
    groups: Vec<String>,
) -> Result<(u16, hyper::HeaderMap, String), Err> {
    let r_in = srv
        .handle(build_request(
            "GET",
            "/auth/oidc/login?provider=ca351",
            ip,
            UA,
            Vec::new(),
            &[],
        )?)
        .await;
    let (mut state, mut nonce, mut verifier) = (String::new(), String::new(), String::new());
    let mut pairs = Vec::new();
    for sc in r_in.headers().get_all("set-cookie") {
        let nv = sc.to_str()?.split(';').next().unwrap().to_owned();
        if let Some(v) = nv.strip_prefix("oidc_state=") {
            state = v.to_owned();
        }
        if let Some(v) = nv.strip_prefix("oidc_nonce=") {
            nonce = v.to_owned();
        }
        if let Some(v) = nv.strip_prefix("oidc_verifier=") {
            verifier = v.to_owned();
        }
        pairs.push(nv);
    }
    let code = fake.issue_code(&verifier, &nonce, "ca351-oidc-sub", email, groups);
    let cb = format!("/auth/oidc/callback?code={code}&state={state}");
    let cookie_hdr = pairs.join("; ");
    read_body(
        srv.handle(build_request(
            "GET",
            &cb,
            ip,
            UA,
            Vec::new(),
            &[("cookie", &cookie_hdr)],
        )?)
        .await,
    )
    .await
}

async fn post_saml_flow(
    srv: &AuthServer,
    ip: &str,
    email: &str,
) -> Result<(u16, hyper::HeaderMap, String), Err> {
    let r_in = srv
        .handle(build_request(
            "GET",
            "/auth/saml/https:%2F%2Fidp.example.test%2Fmetadata/login",
            ip,
            UA,
            Vec::new(),
            &[],
        )?)
        .await;
    let sc = r_in.headers().get("set-cookie").unwrap().to_str()?;
    let pair = sc.split(';').next().unwrap().to_owned();
    let (cname, cjwt) = pair.split_once('=').unwrap();
    let relay = cname.strip_prefix("saml_").unwrap();
    let req_id = jwt_claims(cjwt)?["id"].as_str().unwrap().to_owned();
    let now = now_secs();
    let xml = saml_support::signed_assertion(
        &saml_support::Opts {
            name_id: email.to_owned(),
            irt: Some(req_id),
            assertion_id: format!("id-ca351-{}", uuid::Uuid::new_v4()),
            not_before: now - 30,
            not_on_or_after: now + 300,
            scd_not_on_or_after: now + 300,
            ..Default::default()
        },
        &saml_support::SigSpec::new(saml_support::rsa_idp()),
    );
    let form_body = format!(
        "SAMLResponse={}&RelayState={}",
        percent_encoding::utf8_percent_encode(
            &STANDARD.encode(xml),
            percent_encoding::NON_ALPHANUMERIC,
        ),
        percent_encoding::utf8_percent_encode(relay, percent_encoding::NON_ALPHANUMERIC),
    );
    read_body(
        srv.handle(build_request(
            "POST",
            "/auth/saml/https:%2F%2Fidp.example.test%2Fmetadata/acs",
            ip,
            UA,
            form_body.into_bytes(),
            &[
                ("content-type", "application/x-www-form-urlencoded"),
                ("cookie", &pair),
            ],
        )?)
        .await,
    )
    .await
}

fn access_cookie_headers(headers: &hyper::HeaderMap) -> Vec<String> {
    headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter(|s| s.starts_with("access_token="))
        .map(str::to_owned)
        .collect()
}

fn load_config(secret: String, dsn: &str) -> Config {
    let mut cfg = Config::for_secret(secret);
    cfg.signing_alg = "ES256".into();
    cfg.dsn = dsn.to_owned();
    cfg.direct_dsn = dsn.to_owned();
    cfg.db_encryption_key = ENC.into();
    cfg.vapid_private_key = VAPID.into();
    cfg
}

struct FakeOidcHttp {
    key: setjoin_identity::oidc::SigningKey,
    codes: Mutex<BTreeMap<String, (String, String, String, String, Vec<String>)>>,
}

impl FakeOidcHttp {
    fn new() -> Result<Self, Err> {
        let op =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/identity-oidc");
        Ok(Self {
            key: setjoin_identity::oidc::SigningKey::load(
                op.join("op-private.pem").to_str().unwrap(),
                op.join("op-public.pem").to_str().unwrap(),
            )?,
            codes: Mutex::new(BTreeMap::new()),
        })
    }

    fn issue_code(
        &self,
        verifier: &str,
        nonce: &str,
        sub: &str,
        email: &str,
        groups: Vec<String>,
    ) -> String {
        let code = format!("code-{}", uuid::Uuid::new_v4());
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        self.codes.lock().unwrap().insert(
            code.clone(),
            (
                challenge,
                nonce.to_owned(),
                sub.to_owned(),
                email.to_owned(),
                groups,
            ),
        );
        code
    }
}

impl setjoin_identity::rp::Http for FakeOidcHttp {
    fn send(&self, request: hyper::Request<Vec<u8>>) -> setjoin_identity::rp::HttpFuture<'_> {
        let path = request.uri().path().to_owned();
        let raw = request.into_body();
        let (status, body_json) = match path.as_str() {
            "/.well-known/openid-configuration" => (
                200,
                json!({
                    "issuer": OIDC_ISSUER,
                    "authorization_endpoint": format!("{OIDC_ISSUER}/authorize"),
                    "token_endpoint": format!("{OIDC_ISSUER}/token"),
                    "jwks_uri": format!("{OIDC_ISSUER}/keys"),
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "token_endpoint_auth_methods_supported": ["client_secret_basic"],
                    "code_challenge_methods_supported": ["S256"]
                })
                .to_string(),
            ),
            "/keys" => (200, self.key.jwks()),
            "/token" => {
                let fields = setjoin_identity::issuance::query(&String::from_utf8_lossy(&raw));
                let code = fields.get("code").cloned().unwrap_or_default();
                let entry = self.codes.lock().unwrap().remove(&code);
                match entry {
                    Some((challenge, nonce, sub, email, groups))
                        if fields.get("code_verifier").is_some_and(|v| {
                            URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes())) == challenge
                        }) =>
                    {
                        let now = now_secs() as u64;
                        let claims = json!({
                            "iss": OIDC_ISSUER,
                            "sub": sub,
                            "aud": OIDC_CLIENT,
                            "iat": now,
                            "exp": now + 300,
                            "nonce": nonce,
                            "email": email,
                            "email_verified": true,
                            "groups": groups
                        });
                        let id_token = self.key.sign(&claims).unwrap();
                        (
                            200,
                            json!({
                                "access_token": "oidc-upstream-access",
                                "token_type": "Bearer",
                                "expires_in": 300,
                                "id_token": id_token
                            })
                            .to_string(),
                        )
                    }
                    _ => (400, json!({"error": "invalid_grant"}).to_string()),
                }
            }
            _ => (404, json!({"error": "not_found"}).to_string()),
        };
        Box::pin(async move {
            hyper::Response::builder()
                .status(status)
                .header("content-type", "application/json")
                .body(body_json.into_bytes())
                .map_err(std::io::Error::other)
        })
    }
}

#[tokio::test]
async fn ca_351_password_decisions_session_controls_refresh_and_threat_gate() -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("CA351-password") else {
        return Ok(());
    };
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let saved = snapshot_toggles(&c).await?;
    let a = fixture::account(&c, "ca351-pw").await?;
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await?
        .get(0);
    c.execute(
        "UPDATE users SET password_hash=$1,mfa_exempt=true,totp_enabled=false,push_mfa_enabled=false WHERE id=$2",
        &[&bcrypt::hash(PASSWORD, 4)?, &a.user],
    )
    .await?;
    let ip = "127.0.51.10";
    let mut device_hashes = Vec::new();
    let mut policy_ids = Vec::new();
    let secret = master_secret();
    let mk_cfg = || load_config(secret.clone(), &db.dsn);
    let access_secs = mk_cfg().access_seconds;
    let result: Result<(), Err> = async {
        set_toggles(&c, true, true, true).await?;
        let dh = insert_managed_device(&c, a.user, UA, ip, "compliant").await?;
        device_hashes.push(dh.clone());
        let exec = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
            .map_err(|e| e.0)?;

        // 1. Report-only block alone: does NOT block, logs report_only=true + would_decision='block'.
        insert_policy(
            &c,
            &mut policy_ids,
            90001,
            "ca351-ro-block",
            "report_only",
            "user",
            &a.user.to_string(),
            json!({}),
            json!({"action":"block","reason":"ro-only"}),
            json!({}),
        )
        .await?;
        let srv_ro = AuthServer::load(exec.clone(), mk_cfg())
            .await?
            .with_threat_gate(&db.dsn)
            .await?;
        let body_no_stay = json!({"email": email, "password": PASSWORD, "stay_signed_in": false}).to_string();
        let (st_ro, _, raw_ro) = read_body(
            srv_ro
                .handle(build_request("POST", "/auth/login", ip, UA, body_no_stay.clone().into_bytes(), &[])?)
                .await,
        )
        .await?;
        check_eq!(st_ro, 200, "report-only login: {raw_ro}");
        check_eq!(ca_log_count(&c, a.user).await?, 1);
        let ro_row: (bool, Option<String>) = c
            .query_one(
                "SELECT report_only, would_decision FROM ca_signin_log WHERE user_id=$1 ORDER BY id DESC LIMIT 1",
                &[&a.user],
            )
            .await
            .map(|r| (r.get(0), r.get(1)))?;
        check_eq!(ro_row, (true, Some("block".into())));

        // 2. Active allow with user_choice + 4h sif.
        insert_policy(
            &c,
            &mut policy_ids,
            90002,
            "ca351-pw-allow-uc",
            "on",
            "user",
            &a.user.to_string(),
            json!({}),
            json!({"action":"allow"}),
            json!({"sign_in_frequency":{"value":4,"unit":"hours"},"persistent_session":"user_choice"}),
        )
        .await?;
        let server = AuthServer::load(exec.clone(), mk_cfg())
            .await?
            .with_threat_gate(&db.dsn)
            .await?;

        // 2a. stay_signed_in: false + user_choice => NO Max-Age; BOTH tokens have sif=14400, auth_time, compliant device.
        let (st, hdrs, raw) = read_body(
            server
                .handle(build_request("POST", "/auth/login", ip, UA, body_no_stay.into_bytes(), &[])?)
                .await,
        )
        .await?;
        check_eq!(st, 200, "allow login: {raw}");
        check_eq!(ca_log_count(&c, a.user).await?, 2);
        let cookies = access_cookie_headers(&hdrs);
        check_eq!(cookies.len(), 1);
        check!(!cookies[0].contains("Max-Age="), "user_choice unchecked must omit Max-Age: {}", cookies[0]);
        let v: Value = serde_json::from_str(&raw)?;
        let access_tok = v["access_token"].as_str().unwrap();
        let refresh_tok = v["refresh_token"].as_str().unwrap();
        let ac = jwt_claims(access_tok)?;
        let rc = jwt_claims(refresh_tok)?;
        check_eq!(ac["sif"], json!(14400));
        check_eq!(rc["sif"], json!(14400));
        check_eq!(ac["auth_time"], rc["auth_time"]);
        check!(ac["auth_time"].as_i64().is_some(), "missing auth_time");
        check_eq!(ac["device"]["trust_tier"], json!("compliant"));
        check_eq!(ac["device"]["compliance_status"], json!("ok"));
        check_eq!(rc["device"]["trust_tier"], json!("compliant"));

        // /auth/refresh rotation retains original auth_time, sif, and device claim.
        let ref_body = json!({"refresh_token": refresh_tok}).to_string();
        let (st_ref, _, raw_ref) = read_body(
            server
                .handle(build_request("POST", "/auth/refresh", ip, UA, ref_body.into_bytes(), &[])?)
                .await,
        )
        .await?;
        check_eq!(st_ref, 200, "refresh: {raw_ref}");
        let v_ref: Value = serde_json::from_str(&raw_ref)?;
        let ac2 = jwt_claims(v_ref["access_token"].as_str().unwrap())?;
        let rc2 = jwt_claims(v_ref["refresh_token"].as_str().unwrap())?;
        check_eq!(ac2["sif"], json!(14400));
        check_eq!(rc2["sif"], json!(14400));
        check_eq!(ac2["auth_time"], ac["auth_time"]);
        check_eq!(rc2["auth_time"], ac["auth_time"]);
        check_eq!(ac2["device"]["trust_tier"], json!("compliant"));
        check_eq!(ca_log_count(&c, a.user).await?, 2, "refresh must not re-evaluate login CA");

        // 2b. stay_signed_in: true + user_choice => sets Max-Age={access_secs}.
        let body_stay = json!({"email": email, "password": PASSWORD, "stay_signed_in": true}).to_string();
        let (st, hdrs, _) = read_body(
            server
                .handle(build_request("POST", "/auth/login", ip, UA, body_stay.clone().into_bytes(), &[])?)
                .await,
        )
        .await?;
        check_eq!(st, 200);
        check!(
            access_cookie_headers(&hdrs)[0].contains(&format!("Max-Age={access_secs}")),
            "stay_signed_in=true must set Max-Age"
        );
        check_eq!(ca_log_count(&c, a.user).await?, 3);

        // 2. persistent_session: "never" omits Max-Age even when stay_signed_in: true.
        delete_policies(&c, &mut policy_ids).await?;
        insert_policy(
            &c,
            &mut policy_ids,
            90003,
            "ca351-pw-never",
            "on",
            "user",
            &a.user.to_string(),
            json!({}),
            json!({"action":"allow"}),
            json!({"persistent_session":"never"}),
        )
        .await?;
        let server_never = AuthServer::load(exec.clone(), mk_cfg())
            .await?
            .with_threat_gate(&db.dsn)
            .await?;
        let (st, hdrs, _) = read_body(
            server_never
                .handle(build_request("POST", "/auth/login", ip, UA, body_stay.clone().into_bytes(), &[])?)
                .await,
        )
        .await?;
        check_eq!(st, 200);
        check!(!access_cookie_headers(&hdrs)[0].contains("Max-Age="), "never must omit Max-Age");

        // 3. Remediable block (require_terms) allows token issuance for runtime remediation.
        delete_policies(&c, &mut policy_ids).await?;
        insert_policy(
            &c,
            &mut policy_ids,
            90004,
            "ca351-pw-remediable",
            "on",
            "user",
            &a.user.to_string(),
            json!({}),
            json!({"action":"require_terms"}),
            json!({}),
        )
        .await?;
        let server_rem = AuthServer::load(exec.clone(), mk_cfg())
            .await?
            .with_threat_gate(&db.dsn)
            .await?;
        let (st, _, raw_rem) = read_body(
            server_rem
                .handle(build_request("POST", "/auth/login", ip, UA, body_stay.clone().into_bytes(), &[])?)
                .await,
        )
        .await?;
        check_eq!(st, 200, "remediable block must issue token: {raw_rem}");

        // 4. Hard block returns 403 + X-CA-Correlation-Id, logs 1 row, writes NO session/cookie.
        c.execute("DELETE FROM sessions WHERE user_id=$1", &[&a.user]).await?;
        delete_policies(&c, &mut policy_ids).await?;
        insert_policy(
            &c,
            &mut policy_ids,
            90005,
            "ca351-pw-hard-block",
            "on",
            "user",
            &a.user.to_string(),
            json!({}),
            json!({"action":"block","reason":"hard block test"}),
            json!({}),
        )
        .await?;
        let server_blk = AuthServer::load(exec.clone(), mk_cfg())
            .await?
            .with_threat_gate(&db.dsn)
            .await?;
        let before_logs = ca_log_count(&c, a.user).await?;
        let (st, hdrs, raw_blk) = read_body(
            server_blk
                .handle(build_request("POST", "/auth/login", ip, UA, body_stay.clone().into_bytes(), &[])?)
                .await,
        )
        .await?;
        check_eq!(st, 403, "hard block: {raw_blk}");
        check!(hdrs.get("x-ca-correlation-id").is_some(), "missing X-CA-Correlation-Id on block");
        check!(access_cookie_headers(&hdrs).is_empty(), "block must not set access cookie");
        let sess_after: i64 = c.query_one("SELECT count(*) FROM sessions WHERE user_id=$1", &[&a.user]).await?.get(0);
        check_eq!(sess_after, 0, "block must not create session");
        check_eq!(ca_log_count(&c, a.user).await?, before_logs + 1);

        // 5. Step-up returns 202 + mfa_required + mfa_token + reason/methods/cid + verified_no_outcome (never locks out).
        c.execute("DELETE FROM auth_attempts WHERE target_username=$1", &[&email]).await?;
        delete_policies(&c, &mut policy_ids).await?;
        insert_policy(
            &c,
            &mut policy_ids,
            90006,
            "ca351-pw-stepup",
            "on",
            "user",
            &a.user.to_string(),
            json!({}),
            json!({"action":"step_up","reason":"step up required","methods":["totp"]}),
            json!({}),
        )
        .await?;
        let server_su = AuthServer::load(exec, mk_cfg())
            .await?
            .with_threat_gate(&db.dsn)
            .await?;
        for attempt in 0..6 {
            let before = ca_log_count(&c, a.user).await?;
            let (st, hdrs, raw_su) = read_body(
                server_su
                    .handle(build_request("POST", "/auth/login", ip, UA, body_stay.clone().into_bytes(), &[])?)
                    .await,
            )
            .await?;
            check_eq!(st, 202, "step-up attempt {attempt}: {raw_su}");
            let j: Value = serde_json::from_str(&raw_su)?;
            check_eq!(j["mfa_required"], json!(true));
            check_eq!(j["step_up_reason"], json!("step up required"));
            check!(j["mfa_token"].as_str().is_some_and(|s| !s.is_empty()));
            check!(j["step_up_methods"].as_array().is_some());
            check!(j["correlation_id"].as_str().is_some_and(|s| !s.is_empty()));
            check!(hdrs.get("x-ca-correlation-id").is_some());
            check!(access_cookie_headers(&hdrs).is_empty(), "step-up must not set access cookie");
            check_eq!(ca_log_count(&c, a.user).await?, before + 1);
        }
        let failure_attempts: i64 = c
            .query_one(
                "SELECT count(*) FROM auth_attempts WHERE target_username=$1 AND outcome='failure'",
                &[&email],
            )
            .await?
            .get(0);
        check_eq!(failure_attempts, 0, "step-up must stamp verified_no_outcome");
        Ok(())
    }
    .await;

    let clean = cleanup_ca(&c, &policy_ids, &[a.user], &[email], &device_hashes).await;
    let rem = fixture::remove(&c, &a)
        .await
        .map(|_| ())
        .map_err(Into::into);
    let _ = restore_toggles(&c, &saved).await;
    result.and(clean).and(rem)
}

#[tokio::test]
async fn ca_351_mfa_completions_and_step_up_hard_block() -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("CA351-mfa") else {
        return Ok(());
    };
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let saved = snapshot_toggles(&c).await?;
    let a = fixture::account(&c, "ca351-mfa").await?;
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await?
        .get(0);
    let backup_hashes = vec![bcrypt::hash(BACKUP_CODE, 4)?];
    c.execute(
        "UPDATE users SET password_hash=$1,mfa_exempt=false,totp_enabled=true,totp_secret_enc=pgp_sym_encrypt($2,$3),totp_enabled_at=now(),totp_backup_codes_enc=$4,factor_generation=2 WHERE id=$5",
        &[&bcrypt::hash(PASSWORD, 4)?, &TOTP_SECRET, &ENC, &backup_hashes, &a.user],
    )
    .await?;
    let ip = "127.0.51.20";
    let mut device_hashes = Vec::new();
    let mut policy_ids = Vec::new();
    let secret = master_secret();
    let mk_cfg = || load_config(secret.clone(), &db.dsn);
    let access_secs = mk_cfg().access_seconds;
    let result: Result<(), Err> = async {
        set_toggles(&c, true, true, false).await?;
        let exec = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
            .map_err(|e| e.0)?;

        // Managed device compliant + CA step-up policy with 2-day sif + persistent_session='never'.
        device_hashes.push(insert_managed_device(&c, a.user, UA, ip, "compliant").await?);
        insert_policy(
            &c,
            &mut policy_ids,
            90010,
            "ca351-mfa-stepup",
            "on",
            "user",
            &a.user.to_string(),
            json!({}),
            json!({"action":"step_up","reason":"mfa stepup","methods":["totp"]}),
            json!({"sign_in_frequency":{"value":2,"unit":"days"},"persistent_session":"never"}),
        )
        .await?;
        let server = AuthServer::load(exec.clone(), mk_cfg())
            .await?
            .with_threat_gate(&db.dsn)
            .await?;

        // A. Step-up from password -> TOTP verify suppresses repeated step-up & embeds sif=172800 + device claim + full-TTL cookie.
        let login_raw = json!({"email": email, "password": PASSWORD}).to_string();
        let (st_pw, _, raw_pw) = read_body(
            server
                .handle(build_request("POST", "/auth/login", ip, UA, login_raw.into_bytes(), &[])?)
                .await,
        )
        .await?;
        check_eq!(st_pw, 202, "pw stepup: {raw_pw}");
        let mfa_tok = serde_json::from_str::<Value>(&raw_pw)?["mfa_token"]
            .as_str()
            .unwrap()
            .to_owned();
        let totp_code = setjoin_identity::totp::code(TOTP_SECRET, now_secs()).unwrap();
        let before_totp = ca_log_count(&c, a.user).await?;
        let (st_totp, hdrs_totp, raw_totp) = read_body(
            server
                .handle(build_request(
                    "POST",
                    "/auth/totp/verify",
                    ip,
                    UA,
                    json!({"mfa_token": mfa_tok, "code": totp_code}).to_string().into_bytes(),
                    &[],
                )?)
                .await,
        )
        .await?;
        check_eq!(st_totp, 200, "totp verify: {raw_totp}");
        check_eq!(ca_log_count(&c, a.user).await?, before_totp + 1);
        check!(access_cookie_headers(&hdrs_totp)[0].contains(&format!("Max-Age={access_secs}")));
        let vt: Value = serde_json::from_str(&raw_totp)?;
        let ac = jwt_claims(vt["access_token"].as_str().unwrap())?;
        let rc = jwt_claims(vt["refresh_token"].as_str().unwrap())?;
        check_eq!(ac["sif"], json!(172800));
        check_eq!(rc["sif"], json!(172800));
        check_eq!(ac["auth_time"], rc["auth_time"]);
        check_eq!(ac["device"]["trust_tier"], json!("compliant"));
        check_eq!(rc["device"]["trust_tier"], json!("compliant"));

        // B. Backup verify with non_compliant managed device => quarantined device claim & suppressed step-up.
        device_hashes.push(insert_managed_device(&c, a.user, UA, ip, "non_compliant").await?);
        let now = now_secs();
        let pending_claims = json!({
            "uid": a.user, "email": email, "typ": "mfa_pending", "amr": ["pwd"],
            "iss": "mailserver", "aud": ["mailserver-gateway"], "iat": now, "exp": now + 300,
            "jti": "ca351-backup-jti"
        });
        let pending_tok = setjoin_authz::legacy_jwt::sign_hs256(secret.as_bytes(), &pending_claims.to_string());
        let before_bak = ca_log_count(&c, a.user).await?;
        let (st_bak, _, raw_bak) = read_body(
            server
                .handle(build_request(
                    "POST",
                    "/auth/backup-codes/verify",
                    ip,
                    UA,
                    json!({"mfa_token": pending_tok, "code": BACKUP_CODE}).to_string().into_bytes(),
                    &[],
                )?)
                .await,
        )
        .await?;
        check_eq!(st_bak, 200, "backup verify: {raw_bak}");
        check_eq!(ca_log_count(&c, a.user).await?, before_bak + 1);
        let vb: Value = serde_json::from_str(&raw_bak)?;
        let bac = jwt_claims(vb["access_token"].as_str().unwrap())?;
        check_eq!(bac["device"]["trust_tier"], json!("quarantined"));
        check_eq!(bac["device"]["compliance_status"], json!(""));

        // C. Push status with unknown managed device => NO device claim, full-TTL cookie.
        device_hashes.push(insert_managed_device(&c, a.user, UA, ip, "unknown").await?);
        delete_policies(&c, &mut policy_ids).await?;
        insert_policy(
            &c,
            &mut policy_ids,
            90011,
            "ca351-push-always",
            "on",
            "user",
            &a.user.to_string(),
            json!({}),
            json!({"action":"allow"}),
            json!({"persistent_session":"always"}),
        )
        .await?;
        let server_push = AuthServer::load(exec.clone(), mk_cfg())
            .await?
            .with_threat_gate(&db.dsn)
            .await?;
        let push_pending = setjoin_authz::legacy_jwt::sign_hs256(secret.as_bytes(), &pending_claims.to_string());
        let push_nonce = "22".repeat(32);
        c.execute(
            "INSERT INTO push_mfa_challenges(user_id,challenge_code,nonce,session_id,expires_at,verified_at,approved_at) VALUES($1,'42',decode($2,'hex'),$3,now()+interval '120 seconds',now(),now())",
            &[&a.user, &push_nonce, &push_pending],
        )
        .await?;
        let before_push = ca_log_count(&c, a.user).await?;
        let (st_push, hdrs_push, raw_push) = read_body(
            server_push
                .handle(build_request(
                    "POST",
                    "/auth/push/status",
                    ip,
                    UA,
                    json!({"mfa_token": push_pending, "nonce": push_nonce}).to_string().into_bytes(),
                    &[],
                )?)
                .await,
        )
        .await?;
        check_eq!(st_push, 200, "push status: {raw_push}");
        check_eq!(ca_log_count(&c, a.user).await?, before_push + 1);
        check!(access_cookie_headers(&hdrs_push)[0].contains(&format!("Max-Age={access_secs}")));
        let vp: Value = serde_json::from_str(&raw_push)?;
        check!(jwt_claims(vp["access_token"].as_str().unwrap())?.get("device").is_none(), "unknown device must omit claim");

        // D. TOTP enrollment bootstrap confirm exercises CA + session controls + device claim.
        c.execute(
            "UPDATE users SET totp_enabled=false,push_mfa_enabled=false,totp_secret_enc=NULL,totp_enabled_at=NULL WHERE id=$1",
            &[&a.user],
        )
        .await?;
        device_hashes.push(insert_managed_device(&c, a.user, UA, ip, "compliant").await?);
        let enroll_jti = "ca351-enroll-jti";
        let enroll_id = "00000000-0000-4000-8000-000000000351";
        let enroll_pending = setjoin_authz::legacy_jwt::sign_hs256(
            secret.as_bytes(),
            &json!({"uid":a.user,"email":email,"typ":"mfa_pending","amr":["pwd"],"iss":"mailserver","aud":["mailserver-gateway"],"iat":now,"exp":now+300,"jti":enroll_jti}).to_string(),
        );
        let enroll_hash = format!("{:x}", Sha256::digest(enroll_pending.as_bytes()));
        c.execute(
            "INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,proof_method,bound_factor_generation,token_scope,expires_at,target_ref) VALUES($1,$2,$3,'bootstrap.totp.enroll','password',2,'mfa_pending',now()+interval '5 minutes',$4)",
            &[&enroll_hash, &a.user, &enroll_jti, &enroll_id],
        )
        .await?;
        c.execute(
            "INSERT INTO totp_pending_enrollments(id,user_id,secret_enc,staged_by_jti,staged_via,expires_at) VALUES($1::text::uuid,$2,pgp_sym_encrypt($3,$4),$5,'enroll_setup',now()+interval '15 minutes')",
            &[&enroll_id, &a.user, &STAGED_SECRET, &ENC, &enroll_jti],
        )
        .await?;
        let staged_code = setjoin_identity::totp::code(STAGED_SECRET, now).unwrap();
        let before_enr = ca_log_count(&c, a.user).await?;
        let (st_enr, _, raw_enr) = read_body(
            server_push
                .handle(build_request(
                    "POST",
                    "/auth/totp/enroll/confirm",
                    ip,
                    UA,
                    json!({"mfa_token": enroll_pending, "code": staged_code, "enrollment_id": enroll_id}).to_string().into_bytes(),
                    &[],
                )?)
                .await,
        )
        .await?;
        check_eq!(st_enr, 200, "enroll confirm: {raw_enr}");
        check_eq!(ca_log_count(&c, a.user).await?, before_enr + 1);
        let ve: Value = serde_json::from_str(&raw_enr)?;
        check_eq!(jwt_claims(ve["access_token"].as_str().unwrap())?["device"]["trust_tier"], json!("compliant"));

        // E. Fresh hard block during step-up completion returns 403 + X-CA-Correlation-Id without issuing session.
        delete_policies(&c, &mut policy_ids).await?;
        insert_policy(
            &c,
            &mut policy_ids,
            90012,
            "ca351-stepup-hard-block",
            "on",
            "user",
            &a.user.to_string(),
            json!({"auth_method":"totp"}),
            json!({"action":"block","reason":"blocked during completion"}),
            json!({}),
        )
        .await?;
        let server_blk = AuthServer::load(exec, mk_cfg())
            .await?
            .with_threat_gate(&db.dsn)
            .await?;
        let totp_code_2 = setjoin_identity::totp::code(STAGED_SECRET, now + 30)
            .unwrap_or_else(|| setjoin_identity::totp::code(STAGED_SECRET, now).unwrap());
        let step_pending = setjoin_authz::legacy_jwt::sign_hs256(
            secret.as_bytes(),
            &json!({"uid":a.user,"email":email,"typ":"mfa_pending","amr":["pwd"],"iss":"mailserver","aud":["mailserver-gateway"],"iat":now,"exp":now+300,"jti":"ca351-blk-totp"}).to_string(),
        );
        let sess_before: i64 = c.query_one("SELECT count(*) FROM sessions WHERE user_id=$1", &[&a.user]).await?.get(0);
        let before_blk = ca_log_count(&c, a.user).await?;
        let (st_blk, hdrs_blk, raw_blk) = read_body(
            server_blk
                .handle(build_request(
                    "POST",
                    "/auth/totp/verify",
                    ip,
                    UA,
                    json!({"mfa_token": step_pending, "code": totp_code_2}).to_string().into_bytes(),
                    &[],
                )?)
                .await,
        )
        .await?;
        check_eq!(st_blk, 403, "completion hard block: {raw_blk}");
        check!(hdrs_blk.get("x-ca-correlation-id").is_some(), "missing correlation header");
        check!(access_cookie_headers(&hdrs_blk).is_empty());
        let sess_after: i64 = c.query_one("SELECT count(*) FROM sessions WHERE user_id=$1", &[&a.user]).await?.get(0);
        check_eq!(sess_after, sess_before, "hard block must not mint session");
        check_eq!(ca_log_count(&c, a.user).await?, before_blk + 1);
        Ok(())
    }
    .await;

    let clean = cleanup_ca(&c, &policy_ids, &[a.user], &[email], &device_hashes).await;
    let rem = fixture::remove(&c, &a)
        .await
        .map(|_| ())
        .map_err(Into::into);
    let _ = restore_toggles(&c, &saved).await;
    result.and(clean).and(rem)
}

#[tokio::test]
async fn ca_351_webauthn_gate_none_before_mfa_and_device_claim() -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("CA351-webauthn") else {
        return Ok(());
    };
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let saved = snapshot_toggles(&c).await?;
    let a = fixture::account(&c, "ca351-wa").await?;
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await?
        .get(0);
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-webauthn/vectors.json"
    ))?;
    let vec0 = &vectors["cases"][0];
    let cred_id = URL_SAFE_NO_PAD.decode(vec0["id"].as_str().unwrap())?;
    let handle = URL_SAFE_NO_PAD.decode(vec0["handle"].as_str().unwrap())?;
    let pub_key: Vec<u8> = (0..vec0["key"].as_str().unwrap().len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&vec0["key"].as_str().unwrap()[i..i + 2], 16).unwrap())
        .collect();
    c.execute(
        "UPDATE users SET webauthn_user_handle=$2,totp_enabled=true WHERE id=$1",
        &[&a.user, &handle],
    )
    .await?;
    c.execute("INSERT INTO passkey_credentials(id,user_id,public_key,attestation_type,sign_count,device_name,created_at,uv_capable) VALUES($1,$2,$3,'none',7,'CA351 key','2026-10-01T02:03:04Z',true)", &[&cred_id, &a.user, &pub_key]).await?;

    let ip = "127.0.51.30";
    let secret = master_secret();
    let codec = setjoin_identity::webauthn::CookieCipher::new(secret.as_bytes());
    let make_cookies = || -> Result<String, Err> {
        let sess = json!({"challenge": vec0["challenge"], "rpId": "localhost", "user_id": STANDARD.encode(&handle), "allowed_credentials": [STANDARD.encode(&cred_id)], "expires": "0001-01-01T00:00:00Z"});
        Ok(format!(
            "wa_login_sess={}; wa_login_uid={}",
            codec.seal(sess.to_string().as_bytes())?,
            codec.seal(a.user.to_string().as_bytes())?
        ))
    };
    let mut device_hashes = Vec::new();
    let mut policy_ids = Vec::new();
    let mk_cfg = || load_config(secret.clone(), &db.dsn);
    let access_secs = mk_cfg().access_seconds;
    let result: Result<(), Err> = async {
        set_toggles(&c, true, true, false).await?;
        let exec = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
            .map_err(|e| e.0)?;

        // 1. gate == None: blocking CA policy STILL blocks with 403 + X-CA-Correlation-Id AND runs BEFORE second-factor challenge.
        insert_policy(
            &c,
            &mut policy_ids,
            90020,
            "ca351-wa-block",
            "on",
            "user",
            &a.user.to_string(),
            json!({}),
            json!({"action":"block","reason":"wa gate-none block"}),
            json!({}),
        )
        .await?;
        let server_nogate = AuthServer::load(exec.clone(), mk_cfg()).await?;
        let wa_body = vec0["assertions"]["success"]["request"].to_string();
        let (st, hdrs, raw) = read_body(
            server_nogate
                .handle(build_request(
                    "POST",
                    "/auth/webauthn/login/finish",
                    ip,
                    UA,
                    wa_body.clone().into_bytes(),
                    &[("cookie", &make_cookies()?)],
                )?)
                .await,
        )
        .await?;
        check_eq!(st, 403, "gate=None block before second-factor: {raw}");
        check!(hdrs.get("x-ca-correlation-id").is_some());
        check!(
            !raw.contains("mfa_token"),
            "block must precede MFA challenge"
        );
        check_eq!(ca_log_count(&c, a.user).await?, 1);

        // 2. Step-up on WebAuthn triggers 202 CA step-up BEFORE normal MFA challenge.
        c.execute(
            "UPDATE passkey_credentials SET sign_count=7 WHERE user_id=$1",
            &[&a.user],
        )
        .await?;
        delete_policies(&c, &mut policy_ids).await?;
        insert_policy(
            &c,
            &mut policy_ids,
            90021,
            "ca351-wa-stepup",
            "on",
            "user",
            &a.user.to_string(),
            json!({}),
            json!({"action":"step_up","reason":"wa stepup","methods":["totp"]}),
            json!({}),
        )
        .await?;
        let server_su = AuthServer::load(exec.clone(), mk_cfg()).await?;
        let (st_su, hdrs_su, raw_su) = read_body(
            server_su
                .handle(build_request(
                    "POST",
                    "/auth/webauthn/login/finish",
                    ip,
                    UA,
                    wa_body.clone().into_bytes(),
                    &[("cookie", &make_cookies()?)],
                )?)
                .await,
        )
        .await?;
        check_eq!(st_su, 202, "CA stepup precedes standard 2FA: {raw_su}");
        check!(hdrs_su.get("x-ca-correlation-id").is_some());
        check_eq!(ca_log_count(&c, a.user).await?, 2);

        // 3. Direct passwordless allow + compliant device + sif + full-TTL cookie.
        c.execute(
            "UPDATE users SET totp_enabled=false WHERE id=$1",
            &[&a.user],
        )
        .await?;
        c.execute(
            "UPDATE passkey_credentials SET sign_count=7 WHERE user_id=$1",
            &[&a.user],
        )
        .await?;
        device_hashes.push(insert_managed_device(&c, a.user, UA, ip, "compliant").await?);
        delete_policies(&c, &mut policy_ids).await?;
        insert_policy(
            &c,
            &mut policy_ids,
            90022,
            "ca351-wa-allow",
            "on",
            "user",
            &a.user.to_string(),
            json!({}),
            json!({"action":"allow"}),
            json!({"sign_in_frequency":{"value":1,"unit":"hours"},"persistent_session":"never"}),
        )
        .await?;
        let server_allow = AuthServer::load(exec, mk_cfg()).await?;
        let (st_ok, hdrs_ok, raw_ok) = read_body(
            server_allow
                .handle(build_request(
                    "POST",
                    "/auth/webauthn/login/finish",
                    ip,
                    UA,
                    wa_body.into_bytes(),
                    &[("cookie", &make_cookies()?)],
                )?)
                .await,
        )
        .await?;
        check_eq!(st_ok, 200, "direct webauthn allow: {raw_ok}");
        check_eq!(ca_log_count(&c, a.user).await?, 3);
        check!(access_cookie_headers(&hdrs_ok)[0].contains(&format!("Max-Age={access_secs}")));
        let vw: Value = serde_json::from_str(&raw_ok)?;
        let ac = jwt_claims(vw["access_token"].as_str().unwrap())?;
        let rc = jwt_claims(vw["refresh_token"].as_str().unwrap())?;
        check_eq!(ac["sif"], json!(3600));
        check_eq!(rc["sif"], json!(3600));
        check_eq!(ac["device"]["trust_tier"], json!("compliant"));
        check_eq!(rc["device"]["trust_tier"], json!("compliant"));
        Ok(())
    }
    .await;

    let clean = cleanup_ca(&c, &policy_ids, &[a.user], &[email], &device_hashes).await;
    let rem = fixture::remove(&c, &a)
        .await
        .map(|_| ())
        .map_err(Into::into);
    let _ = restore_toggles(&c, &saved).await;
    result.and(clean).and(rem)
}

#[tokio::test]
async fn ca_351_oidc_rp_settled_groups_step_up_and_block() -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("CA351-oidc") else {
        return Ok(());
    };
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let saved = snapshot_toggles(&c).await?;
    let cfg_key = "oidc_provider_ca351_config";
    let old_cfg = c
        .query_opt(
            "SELECT value::text,encrypted FROM system_config WHERE key=$1",
            &[&cfg_key],
        )
        .await?
        .map(|r| (r.get::<_, String>(0), r.get::<_, bool>(1)));
    let a = fixture::account(&c, "ca351-oidc").await?;
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await?
        .get(0);
    c.execute(
        "UPDATE users SET password_hash=$3,oidc_subject='ca351-oidc-sub',oidc_issuer=$2,mfa_exempt=true WHERE id=$1",
        &[&a.user, &OIDC_ISSUER, &bcrypt::hash(PASSWORD, 4)?],
    )
    .await?;
    let auditor_role_id: i64 = c
        .query_one(
            "SELECT id FROM admin_role_groups WHERE name='Audit Reader' LIMIT 1",
            &[],
        )
        .await?
        .get(0);
    let doc = json!({
        "name": "ca351",
        "provider_url": OIDC_ISSUER,
        "client_id": OIDC_CLIENT,
        "client_secret": "",
        "redirect_url": OIDC_REDIRECT,
        "enabled": true,
        "jit_enabled": false,
        "group_claim": "groups",
        "group_mappings": [{"idp_group": "engineering", "admin_role": "Audit Reader"}]
    })
    .to_string();
    c.execute(
        "INSERT INTO system_config(key,value,encrypted) VALUES($1,$2::text::jsonb,false) ON CONFLICT(key) DO UPDATE SET value=excluded.value,encrypted=false",
        &[&cfg_key, &doc],
    )
    .await?;
    let fake_idp = Arc::new(FakeOidcHttp::new()?);
    let ip = "127.0.51.40";
    let mut device_hashes = Vec::new();
    let mut policy_ids = Vec::new();
    let secret = master_secret();
    let mk_cfg = || {
        let mut cfg = load_config(secret.clone(), &db.dsn);
        cfg.oidc_rp_enabled = true;
        cfg
    };
    let access_secs = mk_cfg().access_seconds;
    let result: Result<(), Err> = async {
        set_toggles(&c, true, true, false).await?;
        let exec = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
            .map_err(|e| e.0)?;

        // Role-scoped policy targets freshly settled SSO role mapping -> triggers even if user scope cached empty before login!
        insert_policy(
            &c,
            &mut policy_ids,
            90030,
            "ca351-oidc-role-block",
            "on",
            "role",
            &auditor_role_id.to_string(),
            json!({}),
            json!({"action":"block","reason":"settled role blocked"}),
            json!({}),
        )
        .await?;
        let server =
            AuthServer::load_with_rp_http(exec.clone(), mk_cfg(), fake_idp.clone()).await?;
        // Pre-warm cache with empty roles for a.user via valid password login before SSO settlement.
        let (st_warm, _, raw_warm) = read_body(
            server
                .handle(build_request(
                    "POST",
                    "/auth/login",
                    ip,
                    UA,
                    json!({"email":email,"password":PASSWORD})
                        .to_string()
                        .into_bytes(),
                    &[],
                )?)
                .await,
        )
        .await?;
        check_eq!(st_warm, 200, "pre-warm login: {raw_warm}");
        c.execute("DELETE FROM sessions WHERE user_id=$1", &[&a.user])
            .await?;

        // 1. Freshly settled role is visible immediately (invalidate_user_scope) => 403 block, 1 more log row, 0 sessions.
        let (st_blk, hdrs_blk, raw_blk) =
            start_oidc_flow(&server, &fake_idp, ip, &email, vec!["engineering".into()]).await?;
        check_eq!(st_blk, 403, "oidc role block: {raw_blk}");
        check!(hdrs_blk.get("x-ca-correlation-id").is_some());
        check_eq!(ca_log_count(&c, a.user).await?, 2);
        check_eq!(
            c.query_one("SELECT count(*) FROM sessions WHERE user_id=$1", &[&a.user])
                .await?
                .get::<_, i64>(0),
            0
        );

        // 2. Step-up on OIDC RP returns 202 + mfa_token + zero sessions + 1 more log row.
        delete_policies(&c, &mut policy_ids).await?;
        insert_policy(
            &c,
            &mut policy_ids,
            90031,
            "ca351-oidc-stepup",
            "on",
            "user",
            &a.user.to_string(),
            json!({}),
            json!({"action":"step_up","reason":"oidc stepup","methods":["totp"]}),
            json!({}),
        )
        .await?;
        let server2 =
            AuthServer::load_with_rp_http(exec.clone(), mk_cfg(), fake_idp.clone()).await?;
        let (st_su, hdrs_su, raw_su) =
            start_oidc_flow(&server2, &fake_idp, ip, &email, vec![]).await?;
        check_eq!(st_su, 202, "oidc step-up: {raw_su}");
        check!(hdrs_su.get("x-ca-correlation-id").is_some());
        check_eq!(ca_log_count(&c, a.user).await?, 3);
        check_eq!(
            c.query_one("SELECT count(*) FROM sessions WHERE user_id=$1", &[&a.user])
                .await?
                .get::<_, i64>(0),
            0
        );

        // 3. OIDC RP allow + compliant device preserves legacy SSO full-TTL cookie & sif=None while attaching DeviceClaim.
        device_hashes.push(insert_managed_device(&c, a.user, UA, ip, "compliant").await?);
        delete_policies(&c, &mut policy_ids).await?;
        insert_policy(
            &c,
            &mut policy_ids,
            90032,
            "ca351-oidc-allow",
            "on",
            "user",
            &a.user.to_string(),
            json!({}),
            json!({"action":"allow"}),
            json!({"sign_in_frequency":{"value":1,"unit":"hours"},"persistent_session":"never"}),
        )
        .await?;
        let server3 = AuthServer::load_with_rp_http(exec, mk_cfg(), fake_idp.clone()).await?;
        let (st_ok, hdrs_ok, raw_ok) =
            start_oidc_flow(&server3, &fake_idp, ip, &email, vec![]).await?;
        check_eq!(st_ok, 200, "oidc allow: {raw_ok}");
        check_eq!(ca_log_count(&c, a.user).await?, 4);
        check!(access_cookie_headers(&hdrs_ok)[0].contains(&format!("Max-Age={access_secs}")));
        let vo: Value = serde_json::from_str(&raw_ok)?;
        let ac = jwt_claims(vo["access_token"].as_str().unwrap())?;
        check!(ac.get("sif").is_none());
        check_eq!(ac["device"]["trust_tier"], json!("compliant"));
        Ok(())
    }
    .await;

    let _ = match old_cfg {
        Some((v, enc)) => {
            c.execute("INSERT INTO system_config(key,value,encrypted) VALUES($1,$2::text::jsonb,$3) ON CONFLICT(key) DO UPDATE SET value=excluded.value,encrypted=excluded.encrypted", &[&cfg_key, &v, &enc]).await
        }
        None => c.execute("DELETE FROM system_config WHERE key=$1", &[&cfg_key]).await,
    };
    let clean = cleanup_ca(&c, &policy_ids, &[a.user], &[email], &device_hashes).await;
    let rem = fixture::remove(&c, &a)
        .await
        .map(|_| ())
        .map_err(Into::into);
    cleanup_identity_source(&c, "oidc:ca351").await;
    let _ = restore_toggles(&c, &saved).await;
    result.and(clean).and(rem)
}

#[tokio::test]
async fn ca_351_saml_acs_decisions_session_cookie_and_503_flag_fault() -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("CA351-saml") else {
        return Ok(());
    };
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let saved = snapshot_toggles(&c).await?;
    let a = fixture::account(&c, "ca351-saml").await?;
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await?
        .get(0);
    c.execute(
        "UPDATE users SET saml_name_id=$2,saml_idp_entity_id=$3 WHERE id=$1",
        &[&a.user, &email, &saml_support::IDP],
    )
    .await?;
    let metadata = "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"https://idp.example.test/metadata\"><IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp.example.test/sso\"/></IDPSSODescriptor></EntityDescriptor>";
    let reg_id: i64 = c
        .query_one(
            "INSERT INTO saml_sp_registrations(idp_entity_id,idp_metadata_url,idp_sso_url,idp_cert_enc,sp_entity_id,sp_acs_url,group_mappings,jit_enabled,allow_idp_initiated) VALUES($1,$2,'https://ignored.invalid/sso',pgp_sym_encrypt($3,$4),'https://sp.example.test/ignored/path','https://ignored.invalid/acs','[]',false,false) RETURNING id",
            &[&saml_support::IDP, &metadata, &saml_support::rsa_idp().cert_pem, &SAML_ENC],
        )
        .await?
        .get(0);
    let saml_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/identity-saml");
    let ip = "127.0.51.50";
    let mut feature_guard: Option<revoke::Revoked> = None;
    let mut policy_ids = Vec::new();
    let secret = master_secret();
    let saml_cert = saml_dir.join("sp-cert.pem").display().to_string();
    let saml_key = saml_dir.join("sp-key.pem").display().to_string();
    let mk_cfg = || {
        let mut cfg = load_config(secret.clone(), &db.dsn);
        cfg.saml_enabled = true;
        cfg.saml_cert_file = saml_cert.clone();
        cfg.saml_key_file = saml_key.clone();
        cfg.db_encryption_key = SAML_ENC.into();
        cfg
    };
    let access_secs = mk_cfg().access_seconds;
    let result: Result<(), Err> = async {
        set_toggles(&c, true, true, false).await?;
        let exec = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
            .map_err(|e| e.0)?;

        // 1. SAML allow preserves legacy SSO full-TTL cookie even when policy specifies persistent_session='never', 1 log row.
        insert_policy(
            &c,
            &mut policy_ids,
            90040,
            "ca351-saml-allow",
            "on",
            "user",
            &a.user.to_string(),
            json!({}),
            json!({"action":"allow"}),
            json!({"persistent_session":"never"}),
        )
        .await?;
        let srv1 = AuthServer::load(exec.clone(), mk_cfg()).await?;
        let (st1, hdrs1, raw1) = post_saml_flow(&srv1, ip, &email).await?;
        check_eq!(st1, 303, "saml allow: {raw1}");
        let scs = access_cookie_headers(&hdrs1);
        check_eq!(scs.len(), 1);
        check!(scs[0].contains(&format!("Max-Age={access_secs}")));
        check_eq!(ca_log_count(&c, a.user).await?, 1);

        // 2. SAML hard block => 403 + X-CA-Correlation-Id, no access_token cookie, 1 log row.
        delete_policies(&c, &mut policy_ids).await?;
        insert_policy(
            &c,
            &mut policy_ids,
            90041,
            "ca351-saml-block",
            "on",
            "user",
            &a.user.to_string(),
            json!({}),
            json!({"action":"block","reason":"saml blocked"}),
            json!({}),
        )
        .await?;
        let srv2 = AuthServer::load(exec.clone(), mk_cfg()).await?;
        let (st2, hdrs2, raw2) = post_saml_flow(&srv2, ip, &email).await?;
        check_eq!(st2, 403, "saml block: {raw2}");
        check!(hdrs2.get("x-ca-correlation-id").is_some());
        check!(access_cookie_headers(&hdrs2).is_empty());
        check_eq!(ca_log_count(&c, a.user).await?, 2);

        // 3. Genuine feature_toggles lookup failure => preserved SAML 503.
        if let Some(app_dsn) = db.app.as_deref() {
            let probe = setjoin_pg::ScopedExecutor::from_dsn(app_dsn, 1).map_err(|e| e.0)?;
            feature_guard = Some(revoke::table(&db.dsn, &c, &probe, "feature_toggles").await?);
            let (st3, _, raw3) = post_saml_flow(&srv2, ip, &email).await?;
            check_eq!(st3, 503, "saml flag fault: {raw3}");
            check!(raw3.contains("SAML authentication unavailable"));
        }
        Ok(())
    }
    .await;

    if let Some(g) = feature_guard {
        let _ = g.restore(&c).await;
    }
    let _ = c
        .execute("DELETE FROM saml_sp_registrations WHERE id=$1", &[&reg_id])
        .await;
    let clean = cleanup_ca(&c, &policy_ids, &[a.user], &[email], &[]).await;
    let rem = fixture::remove(&c, &a)
        .await
        .map(|_| ())
        .map_err(Into::into);
    cleanup_identity_source(&c, &format!("saml:{reg_id}")).await;
    let _ = restore_toggles(&c, &saved).await;
    result.and(clean).and(rem)
}

#[tokio::test]
async fn ca_351_foreign_fingerprint_isolation_and_fail_closed_faults() -> Result<(), Err> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("CA351-faults") else {
        return Ok(());
    };
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let saved = snapshot_toggles(&c).await?;
    let a = fixture::account(&c, "ca351-user-a").await?;
    let b = fixture::account(&c, "ca351-user-b").await?;
    let email_a: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await?
        .get(0);
    let email_b: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&b.user])
        .await?
        .get(0);
    let pw = bcrypt::hash(PASSWORD, 4)?;
    for uid in [a.user, b.user] {
        c.execute(
            "UPDATE users SET password_hash=$1,mfa_exempt=true,totp_enabled=false,push_mfa_enabled=false WHERE id=$2",
            &[&pw, &uid],
        )
        .await?;
    }
    let orig_session_view: String = c
        .query_one(
            "SELECT pg_get_functiondef('policy_session_view(bigint)'::regprocedure)",
            &[],
        )
        .await?
        .get(0);
    let orig_guest_fn: String = c
        .query_one(
            "SELECT pg_get_functiondef('is_guest_account(bigint)'::regprocedure)",
            &[],
        )
        .await?
        .get(0);

    let ip = "127.0.51.60";
    let mut device_hashes = Vec::new();
    let mut policy_ids = Vec::new();
    let mut mdm_guard: Option<revoke::Revoked> = None;
    let mut flag_guard: Option<revoke::Revoked> = None;
    let secret = master_secret();
    let mk_cfg = || load_config(secret.clone(), &db.dsn);
    let result: Result<(), Err> = async {
        set_toggles(&c, true, true, false).await?;
        let dh = insert_managed_device(&c, a.user, UA, ip, "compliant").await?;
        device_hashes.push(dh);
        let exec = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
            .map_err(|e| e.0)?;
        let server = AuthServer::load(exec.clone(), mk_cfg())
            .await?
            .with_threat_gate(&db.dsn)
            .await?;

        // 1. Two users sharing identical UA+IP fingerprint: only User A gets device claim; User B gets none.
        let (_, _, raw_a) = read_body(
            server
                .handle(build_request("POST", "/auth/login", ip, UA, json!({"email":email_a,"password":PASSWORD}).to_string().into_bytes(), &[])?)
                .await,
        )
        .await?;
        let (_, _, raw_b) = read_body(
            server
                .handle(build_request("POST", "/auth/login", ip, UA, json!({"email":email_b,"password":PASSWORD}).to_string().into_bytes(), &[])?)
                .await,
        )
        .await?;
        check_eq!(jwt_claims(serde_json::from_str::<Value>(&raw_a)?["access_token"].as_str().unwrap())?["device"]["trust_tier"], json!("compliant"));
        check!(jwt_claims(serde_json::from_str::<Value>(&raw_b)?["access_token"].as_str().unwrap())?.get("device").is_none(), "foreign user sharing fingerprint must not get device claim");

        if let Some(app_dsn) = db.app.as_deref() {
            let probe = setjoin_pg::ScopedExecutor::from_dsn(app_dsn, 1).map_err(|e| e.0)?;
            // 2. managed_devices lookup fault fails open for device claim (still 200, no device claim).
            mdm_guard = Some(revoke::table(&db.dsn, &c, &probe, "managed_devices").await?);
            let (st_mdm, _, raw_mdm) = read_body(
                server
                    .handle(build_request("POST", "/auth/login", ip, UA, json!({"email":email_a,"password":PASSWORD}).to_string().into_bytes(), &[])?)
                    .await,
            )
            .await?;
            check_eq!(st_mdm, 200, "managed_devices read fault should omit claim cleanly: {raw_mdm}");
            check!(jwt_claims(serde_json::from_str::<Value>(&raw_mdm)?["access_token"].as_str().unwrap())?.get("device").is_none());
            if let Some(g) = mdm_guard.take() {
                g.restore(&c).await?;
            }
        }

        // 3. Matched-policy policy_session_view failure fails closed: sif = 3600, persistent_session = 'never'.
        insert_policy(
            &c,
            &mut policy_ids,
            90050,
            "ca351-fault-session-view",
            "on",
            "user",
            &a.user.to_string(),
            json!({}),
            json!({"action":"allow"}),
            json!({}),
        )
        .await?;
        let srv_sv = AuthServer::load(exec.clone(), mk_cfg())
            .await?
            .with_threat_gate(&db.dsn)
            .await?;
        c.batch_execute("CREATE OR REPLACE FUNCTION policy_session_view(p_policy_id bigint) RETURNS jsonb LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'ca351-session-view-fault'; END $$").await?;
        let (st_sv, hdrs_sv, raw_sv) = read_body(
            srv_sv
                .handle(build_request("POST", "/auth/login", ip, UA, json!({"email":email_a,"password":PASSWORD,"stay_signed_in":true}).to_string().into_bytes(), &[])?)
                .await,
        )
        .await?;
        c.batch_execute(&orig_session_view).await?;
        check_eq!(st_sv, 200);
        check!(!access_cookie_headers(&hdrs_sv)[0].contains("Max-Age="), "policy_session_view fault must fail closed to persist=never");
        let v_sv: Value = serde_json::from_str(&raw_sv)?;
        check_eq!(jwt_claims(v_sv["access_token"].as_str().unwrap())?["sif"], json!(3600));
        check_eq!(jwt_claims(v_sv["refresh_token"].as_str().unwrap())?["sif"], json!(3600));

        // 4. is_guest_account failure answers 503 conditional access context unavailable.
        c.batch_execute("CREATE OR REPLACE FUNCTION is_guest_account(p_user_id bigint) RETURNS boolean LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'ca351-guest-fault'; END $$").await?;
        let (st_g, _, raw_g) = read_body(
            srv_sv
                .handle(build_request("POST", "/auth/login", ip, UA, json!({"email":email_a,"password":PASSWORD}).to_string().into_bytes(), &[])?)
                .await,
        )
        .await?;
        c.batch_execute(&orig_guest_fn).await?;
        check_eq!(st_g, 503);
        check!(raw_g.contains("conditional access context unavailable"));

        // 5. feature_toggles read fault fails closed with 500 on login, totp/verify, and webauthn/login/finish.
        if let Some(app_dsn) = db.app.as_deref() {
            let probe = setjoin_pg::ScopedExecutor::from_dsn(app_dsn, 1).map_err(|e| e.0)?;
            flag_guard = Some(revoke::table(&db.dsn, &c, &probe, "feature_toggles").await?);
            let mut cfg_wa = mk_cfg();
            cfg_wa.oidc_rp_enabled = true;
            let srv_fault = AuthServer::load(exec, cfg_wa)
                .await?
                .with_threat_gate(&db.dsn)
                .await?;
            for (method, path) in [
                ("POST", "/auth/login"),
                ("POST", "/auth/totp/verify"),
                ("POST", "/auth/webauthn/login/finish"),
                ("GET", "/auth/oidc/callback?code=x&state=y"),
            ] {
                let (st_f, _, _) = read_body(
                    srv_fault
                        .handle(build_request(method, path, ip, UA, b"{}".to_vec(), &[])?)
                        .await,
                )
                .await?;
                check_eq!(st_f, 500, "{method} {path} flag fault expected 500, got {st_f}");
            }
        }
        Ok(())
    }
    .await;

    let _ = c.batch_execute(&orig_session_view).await;
    let _ = c.batch_execute(&orig_guest_fn).await;
    if let Some(g) = mdm_guard {
        let _ = g.restore(&c).await;
    }
    if let Some(g) = flag_guard {
        let _ = g.restore(&c).await;
    }
    let clean = cleanup_ca(
        &c,
        &policy_ids,
        &[a.user, b.user],
        &[email_a, email_b],
        &device_hashes,
    )
    .await;
    let ra = fixture::remove(&c, &a)
        .await
        .map(|_| ())
        .map_err(Into::into);
    let rb = fixture::remove(&c, &b)
        .await
        .map(|_| ())
        .map_err(Into::into);
    let _ = restore_toggles(&c, &saved).await;
    result.and(clean).and(ra).and(rb)
}
