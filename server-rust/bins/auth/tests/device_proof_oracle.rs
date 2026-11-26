//! #350 native device-proof admission across auth POSTs and SSO completions.
//! Verifies device-proof binding, replay protection, #499 foreign-ownership
//! nonce preservation, legacy secret re-sealing under app RLS, and webpush
//! ignoring `X-Device-*` headers without forwarding or burning nonces.
#![allow(dead_code)]
mod common;
#[path = "../../../crates/domains/identity/tests/saml_acs/support.rs"]
mod saml_support;

use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine as _,
};
use hyper::{HeaderMap, Request, Response};
use serde_json::{json, Value};
use setjoin_auth::{body, AuthServer, Config};
use setjoin_authz::device::{DeviceRequest, DeviceResolver};
use setjoin_authz::legacy_jwt::sign_hs256;
use setjoin_config_secret::{open_column, seal_column, CryptoProfile};
use setjoin_conformance::{fixture, harness::Db};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::{Arc, Mutex},
};
use tokio::{net::TcpListener, sync::mpsc};
use tokio_postgres::Client;

type Err = Box<dyn std::error::Error + Send + Sync>;

const ENC: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const PASSWORD: &str = "Password1!";
const TOTP_SECRET: &str = "JBSWY3DPEHPK3PXP";
const STAGED_SECRET: &str = "KRSXG5CTMVRXEZLU";
const BACKUP_CODE: &str = "BACKUP-350-CODE";
const VAPID: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const OIDC_ISSUER: &str = "https://idp.device350.test";
const OIDC_CLIENT: &str = "setjoin-device-350";
const OIDC_REDIRECT: &str = "https://auth.device350.test/auth/oidc/callback";
const SAML_ENC: &str = "idfed3-test-encryption-key-at-least-32-bytes";

const TOGGLES: [&str; 6] = [
    "feature.rate_limit",
    "feature.conditional_access",
    "feature.device_trust_enforcement",
    "feature.token_binding",
    "feature.identity_model_v2",
    "feature.identity_normalized_reads",
];

macro_rules! check {
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

fn keys_fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap()
}

fn master_secret() -> String {
    keys_fixture()["secret"].as_str().unwrap().to_owned()
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn sign_device_headers(
    device_id: i64,
    device_secret: &str,
    ts: &str,
    nonce: &str,
    method: &str,
    uri: &str,
    body_bytes: &[u8],
) -> Vec<(&'static str, String)> {
    let body_hash = hex_sha256(body_bytes);
    let challenge = format!("{device_id}:{ts}:{method}:{uri}:{body_hash}:{nonce}");
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, device_secret.as_bytes());
    let mac: String = ring::hmac::sign(&key, challenge.as_bytes())
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    vec![
        ("x-device-id", device_id.to_string()),
        ("x-device-timestamp", ts.to_owned()),
        ("x-device-nonce", nonce.to_owned()),
        ("x-device-body-sha256", body_hash),
        ("x-device-hmac", mac),
    ]
}

fn build_request(
    method: &str,
    uri: &str,
    raw_body: Vec<u8>,
    extra_headers: &[(&str, &str)],
    device_headers: &[(&'static str, String)],
) -> Result<Request<setjoin_auth::Body>, Err> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "auth.device350.test")
        .header("origin", "http://auth.device350.test");
    for (k, v) in extra_headers {
        builder = builder.header(*k, *v);
    }
    for (k, v) in device_headers {
        builder = builder.header(*k, v.as_str());
    }
    let mut req = builder.body(body(raw_body))?;
    req.extensions_mut().insert(setjoin_auth::ConnectionMeta {
        peer: "127.0.0.1:40000".parse()?,
        tls: false,
    });
    Ok(req)
}

async fn spy() -> Result<
    (
        std::net::SocketAddr,
        mpsc::Receiver<(String, String)>,
        tokio::task::JoinHandle<()>,
    ),
    Err,
> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (tx, rx) = mpsc::channel(8);
    let task = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let tx = tx.clone();
            tasks.spawn(async move {
                let service =
                    hyper::service::service_fn(move |r: Request<hyper::body::Incoming>| {
                        let tx = tx.clone();
                        async move {
                            let _ = tx.send((r.method().to_string(), r.uri().to_string())).await;
                            Ok::<_, std::convert::Infallible>(
                                Response::builder().status(418).body(body("")).unwrap(),
                            )
                        }
                    });
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Ok((addr, rx, task))
}

async fn save_toggles(c: &Client) -> Result<String, Err> {
    Ok(c.query_one(
        "SELECT coalesce(jsonb_agg(to_jsonb(t)),'[]')::text FROM feature_toggles t WHERE key = ANY($1::text[])",
        &[&TOGGLES.as_slice()],
    )
    .await?
    .get(0))
}

async fn set_native_toggles(c: &Client) -> Result<(), Err> {
    c.execute(
        "INSERT INTO feature_toggles(key,enabled) SELECT k,false FROM unnest($1::text[]) AS k ON CONFLICT(key) DO UPDATE SET enabled=false",
        &[&TOGGLES.as_slice()],
    )
    .await?;
    Ok(())
}

async fn restore_toggles(c: &Client, saved: &str) -> Result<(), Err> {
    c.execute(
        "DELETE FROM feature_toggles WHERE key = ANY($1::text[])",
        &[&TOGGLES.as_slice()],
    )
    .await?;
    c.execute(
        "INSERT INTO feature_toggles SELECT * FROM jsonb_populate_recordset(NULL::feature_toggles,$1::text::jsonb)",
        &[&saved],
    )
    .await?;
    Ok(())
}

async fn nonce_count(c: &Client, device_id: i64, nonce: &str) -> Result<i64, Err> {
    Ok(c.query_one(
        "SELECT count(*) FROM device_auth_nonces WHERE device_id=$1 AND nonce=$2",
        &[&device_id, &nonce],
    )
    .await?
    .get(0))
}

async fn insert_sealed_device(
    c: &Client,
    user_id: i64,
    fp: &str,
    device_secret: &str,
    master: &str,
    enroll_state: &str,
) -> Result<i64, Err> {
    let sealed = seal_column(
        device_secret.as_bytes(),
        master.as_bytes(),
        CryptoProfile::Standard,
    )?;
    Ok(c.query_one(
        "INSERT INTO devices(user_id,fingerprint,hmac_secret_enc,hmac_secret_key_id,enroll_state) VALUES($1,$2,$3,'v1',$4) RETURNING id",
        &[&user_id, &fp, &sealed, &enroll_state],
    )
    .await?
    .get(0))
}

async fn insert_legacy_device(
    c: &Client,
    user_id: i64,
    fp: &str,
    device_secret: &str,
    enroll_state: &str,
) -> Result<i64, Err> {
    Ok(c.query_one(
        "INSERT INTO devices(user_id,fingerprint,hmac_secret,enroll_state) VALUES($1,$2,$3,$4) RETURNING id",
        &[&user_id, &fp, &device_secret, &enroll_state],
    )
    .await?
    .get(0))
}

async fn cleanup_user_artifacts(
    c: &Client,
    users: &[i64],
    emails: &[String],
    devices: &[i64],
) -> Result<(), Err> {
    for &did in devices {
        let _ = c
            .execute("DELETE FROM device_auth_nonces WHERE device_id=$1", &[&did])
            .await;
        let _ = c.execute("DELETE FROM devices WHERE id=$1", &[&did]).await;
    }
    for &uid in users {
        let _ = c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={uid};COMMIT")).await;
        for table in [
            "push_devices",
            "push_mfa_challenges",
            "passkey_credentials",
            "totp_pending_enrollments",
            "mfa_reauth_step_ups",
            "auth_event_log",
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
    }
    Ok(())
}

struct FakeOidcHttp {
    key: setjoin_identity::oidc::SigningKey,
    codes: Mutex<BTreeMap<String, (String, String, String)>>,
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

    fn issue_code(&self, verifier: &str, nonce: &str, email: &str) -> String {
        let code = format!("code-{}", uuid::Uuid::new_v4());
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        self.codes.lock().unwrap().insert(
            code.clone(),
            (challenge, nonce.to_owned(), email.to_owned()),
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
                    Some((challenge, nonce, email))
                        if fields.get("code_verifier").is_some_and(|v| {
                            URL_SAFE_NO_PAD.encode(Sha256::digest(v.as_bytes())) == challenge
                        }) =>
                    {
                        let now = now_secs() as u64;
                        let claims = json!({
                            "iss": OIDC_ISSUER,
                            "sub": "device350-oidc-sub",
                            "aud": OIDC_CLIENT,
                            "iat": now,
                            "exp": now + 300,
                            "nonce": nonce,
                            "email": email,
                            "email_verified": true,
                            "groups": ["engineering"]
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
async fn login_device_proof_cases_reseal_and_foreign_ownership() -> Result<(), Err> {
    let Some(db) = Db::for_case("IDDEVPROOF-login") else {
        return Ok(());
    };
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let receipts = common::receipt_ids(&c).await;
    let saved = save_toggles(&c).await?;

    let a = fixture::account(&c, "dev350-login-a").await?;
    let b = fixture::account(&c, "dev350-login-b").await?;
    let pw_hash = bcrypt::hash(PASSWORD, 4)?;
    for uid in [a.user, b.user] {
        c.execute(
            "UPDATE users SET password_hash=$1,mfa_exempt=true,totp_enabled=false,push_mfa_enabled=false WHERE id=$2",
            &[&pw_hash, &uid],
        )
        .await?;
    }
    let email_a: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await?
        .get(0);
    let email_b: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&b.user])
        .await?
        .get(0);

    let secret = master_secret();
    let sealed_secret = "sealed-device-secret-350";
    let legacy_secret = "legacy-device-secret-350";
    let dev_a = insert_sealed_device(
        &c,
        a.user,
        "fp-a-sealed",
        sealed_secret,
        &secret,
        "approved",
    )
    .await?;
    let dev_b_legacy =
        insert_legacy_device(&c, b.user, "fp-b-legacy", legacy_secret, "approved").await?;
    let (_spy_addr, mut seen, spy_task) = spy().await?;

    let result: Result<(), Err> = async {
        set_native_toggles(&c).await?;
        let mut cfg = Config::for_secret(secret.clone());
        cfg.signing_alg = "ES256".into();
        let app_dsn = db
            .app
            .as_deref()
            .ok_or("DB_APP_DSN is required for setjoin_app RLS reseal oracle")?;
        let exec = setjoin_pg::ScopedExecutor::from_dsn(app_dsn, 4).map_err(|e| e.0)?;
        let server = AuthServer::load(exec.clone(), cfg)
            .await?
            .with_threat_gate(&db.dsn)
            .await?;

        let path = "/auth/login?next=%2F";
        let raw_a = json!({"email": email_a, "password": PASSWORD}).to_string();
        let raw_b = json!({"email": email_b, "password": PASSWORD}).to_string();
        let ts = now_secs().to_string();

        // 1. Missing headers: login succeeds natively with zero nonces claimed.
        let r_missing = server
            .handle(build_request("POST", path, raw_a.as_bytes().to_vec(), &[], &[])?)
            .await;
        check_eq!(r_missing.status().as_u16(), 200);

        // 2. Partial headers (missing x-device-hmac): does not claim nonce.
        let nonce_partial = "nonce-partial-350";
        let partial = [
            ("x-device-id", dev_a.to_string()),
            ("x-device-timestamp", ts.clone()),
            ("x-device-nonce", nonce_partial.to_owned()),
            ("x-device-body-sha256", hex_sha256(raw_a.as_bytes())),
        ];
        let r_partial = server
            .handle(build_request("POST", path, raw_a.as_bytes().to_vec(), &[], &partial)?)
            .await;
        check_eq!(r_partial.status().as_u16(), 200);
        check_eq!(nonce_count(&c, dev_a, nonce_partial).await?, 0);

        // 3. Invalid HMAC: does not claim nonce.
        let nonce_bad_hmac = "nonce-bad-hmac-350";
        let mut bad_hmac = sign_device_headers(
            dev_a,
            "wrong-device-secret",
            &ts,
            nonce_bad_hmac,
            "POST",
            path,
            raw_a.as_bytes(),
        );
        let r_bad_hmac = server
            .handle(build_request("POST", path, raw_a.as_bytes().to_vec(), &[], &bad_hmac)?)
            .await;
        check_eq!(r_bad_hmac.status().as_u16(), 200);
        check_eq!(nonce_count(&c, dev_a, nonce_bad_hmac).await?, 0);
        bad_hmac.clear();

        // 4. Expired / skewed timestamp (> 300s): does not claim nonce.
        let nonce_skew = "nonce-skew-350";
        let stale_ts = (now_secs() - 600).to_string();
        let skew_hdrs = sign_device_headers(
            dev_a,
            sealed_secret,
            &stale_ts,
            nonce_skew,
            "POST",
            path,
            raw_a.as_bytes(),
        );
        let r_skew = server
            .handle(build_request("POST", path, raw_a.as_bytes().to_vec(), &[], &skew_hdrs)?)
            .await;
        check_eq!(r_skew.status().as_u16(), 200);
        check_eq!(nonce_count(&c, dev_a, nonce_skew).await?, 0);

        // 5. Body-digest mismatch (signed over different bytes): does not claim nonce.
        let nonce_body_mismatch = "nonce-body-mismatch-350";
        let mismatch_hdrs = sign_device_headers(
            dev_a,
            sealed_secret,
            &ts,
            nonce_body_mismatch,
            "POST",
            path,
            br#"{"email":"other@example.com","password":"x"}"#,
        );
        let r_mismatch = server
            .handle(build_request("POST", path, raw_a.as_bytes().to_vec(), &[], &mismatch_hdrs)?)
            .await;
        check_eq!(r_mismatch.status().as_u16(), 200);
        check_eq!(nonce_count(&c, dev_a, nonce_body_mismatch).await?, 0);

        // 6. Wrong password: must NOT resolve device or claim nonce.
        let nonce_wrong_pw = "nonce-wrong-pw-350";
        let wrong_pw_body = json!({"email": email_a, "password": "WrongPassword!"}).to_string();
        let wrong_pw_hdrs = sign_device_headers(
            dev_a,
            sealed_secret,
            &ts,
            nonce_wrong_pw,
            "POST",
            path,
            wrong_pw_body.as_bytes(),
        );
        let r_wrong_pw = server
            .handle(build_request(
                "POST",
                path,
                wrong_pw_body.into_bytes(),
                &[],
                &wrong_pw_hdrs,
            )?)
            .await;
        check_eq!(r_wrong_pw.status().as_u16(), 401);
        check_eq!(nonce_count(&c, dev_a, nonce_wrong_pw).await?, 0);

        // 7. Valid proof on sealed device: claims nonce once; replay fails second use.
        let nonce_valid = format!("nonce-valid-{}", uuid::Uuid::new_v4());
        let valid_hdrs = sign_device_headers(
            dev_a,
            sealed_secret,
            &ts,
            &nonce_valid,
            "POST",
            path,
            raw_a.as_bytes(),
        );
        let r_valid = server
            .handle(build_request("POST", path, raw_a.as_bytes().to_vec(), &[], &valid_hdrs)?)
            .await;
        check_eq!(r_valid.status().as_u16(), 200);
        check_eq!(nonce_count(&c, dev_a, &nonce_valid).await?, 1);

        let resolver = DeviceResolver::new(exec, secret.as_bytes().to_vec(), CryptoProfile::Standard);
        let mut hmap = HeaderMap::new();
        for (k, v) in &valid_hdrs {
            hmap.insert(
                hyper::header::HeaderName::from_bytes(k.as_bytes())?,
                v.parse()?,
            );
        }
        let replay = resolver
            .resolve_for_user(
                a.user,
                DeviceRequest {
                    headers: &hmap,
                    method: "POST",
                    uri: path,
                    body: raw_a.as_bytes(),
                },
            )
            .await;
        check!(!replay.bound, "replayed X-Device-Nonce must fail second use");

        // 8. Foreign user proof (#499) + legacy secret re-sealing under app RLS:
        // User A presents User B's device ID; User B's nonce must NOT be burned and legacy
        // plaintext secret must remain untouched until owner B proves with it.
        let nonce_foreign = format!("nonce-foreign-{}", uuid::Uuid::new_v4());
        let foreign_hdrs = sign_device_headers(
            dev_b_legacy,
            legacy_secret,
            &ts,
            &nonce_foreign,
            "POST",
            path,
            raw_a.as_bytes(),
        );
        let r_foreign = server
            .handle(build_request("POST", path, raw_a.as_bytes().to_vec(), &[], &foreign_hdrs)?)
            .await;
        check_eq!(r_foreign.status().as_u16(), 200);
        check_eq!(
            nonce_count(&c, dev_b_legacy, &nonce_foreign).await?,
            0,
            "foreign caller must not burn owner's nonce (#499)"
        );
        let still_plain: bool = c
            .query_one(
                "SELECT hmac_secret IS NOT NULL AND hmac_secret_enc IS NULL FROM devices WHERE id=$1",
                &[&dev_b_legacy],
            )
            .await?
            .get(0);
        check!(still_plain, "foreign attempt must not re-seal owner's legacy secret");

        // Owner B now uses the exact same nonce_foreign on B's login -> succeeds and re-seals!
        let owner_hdrs = sign_device_headers(
            dev_b_legacy,
            legacy_secret,
            &ts,
            &nonce_foreign,
            "POST",
            path,
            raw_b.as_bytes(),
        );
        let r_owner = server
            .handle(build_request("POST", path, raw_b.as_bytes().to_vec(), &[], &owner_hdrs)?)
            .await;
        check_eq!(r_owner.status().as_u16(), 200);
        check_eq!(nonce_count(&c, dev_b_legacy, &nonce_foreign).await?, 1);

        let resealed = c
            .query_one(
                "SELECT hmac_secret IS NULL, hmac_secret_enc, hmac_secret_key_id FROM devices WHERE id=$1",
                &[&dev_b_legacy],
            )
            .await?;
        let cleared: bool = resealed.get(0);
        let enc: Option<Vec<u8>> = resealed.get(1);
        let key_id: Option<String> = resealed.get(2);
        check!(cleared, "legacy plaintext hmac_secret must be cleared after re-seal");
        check_eq!(key_id.as_deref(), Some("v1"));
        check_eq!(
            open_column(&enc.ok_or("sealed envelope")?, secret.as_bytes())?,
            legacy_secret.as_bytes()
        );

        check!(seen.try_recv().is_err(), "native device proof must never forward to Go");
        drop(server);
        Ok(())
    }
    .await;

    spy_task.abort();
    let _ = spy_task.await;
    cleanup_user_artifacts(
        &c,
        &[a.user, b.user],
        &[email_a, email_b],
        &[dev_a, dev_b_legacy],
    )
    .await?;
    fixture::remove(&c, &a).await?;
    fixture::remove(&c, &b).await?;
    common::restore_receipts(&c, &receipts).await;
    restore_toggles(&c, &saved).await?;
    result
}

#[tokio::test]
async fn mfa_completions_and_webpush_device_proof_parity() -> Result<(), Err> {
    let Some(db) = Db::for_case("IDDEVPROOF-mfa-webpush") else {
        return Ok(());
    };
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let receipts = common::receipt_ids(&c).await;
    let saved = save_toggles(&c).await?;

    let a = fixture::account(&c, "dev350-mfa-a").await?;
    let secret = master_secret();
    let device_secret = "mfa-device-secret-350";
    let dev_a =
        insert_sealed_device(&c, a.user, "fp-mfa-a", device_secret, &secret, "approved").await?;

    let backup_hash = bcrypt::hash(BACKUP_CODE, 4)?;
    c.execute(
        "UPDATE users SET totp_enabled=true,totp_secret_enc=pgp_sym_encrypt($2,$3),totp_enabled_at=now(),totp_backup_codes_enc=ARRAY[$4],factor_generation=2 WHERE id=$1",
        &[&a.user, &TOTP_SECRET, &ENC, &backup_hash],
    )
    .await?;

    let (_spy_addr, mut seen, spy_task) = spy().await?;

    let result: Result<(), Err> = async {
        set_native_toggles(&c).await?;
        let mut cfg = Config::for_secret(secret.clone());
        cfg.signing_alg = "ES256".into();
        cfg.db_encryption_key = ENC.into();
        cfg.vapid_private_key = VAPID.into();
        let exec = setjoin_pg::ScopedExecutor::from_dsn(
            db.app.as_deref().unwrap_or(&db.dsn),
            4,
        )
        .map_err(|e| e.0)?;
        let server = AuthServer::load(exec, cfg)
            .await?
            .with_threat_gate(&db.dsn)
            .await?;

        let now = now_secs() as u64;
        let ts = now.to_string();
        let pending_claims = json!({
            "uid": a.user,
            "email": "actor@device350.test",
            "typ": "mfa_pending",
            "amr": ["pwd"],
            "iss": "mailserver",
            "aud": ["mailserver-gateway"],
            "iat": now,
            "exp": now + 3600,
            "jti": "dev350-pending-jti"
        });
        let pending_token = sign_hs256(secret.as_bytes(), &pending_claims.to_string());

        // 1. POST /auth/totp/verify: invalid code must NOT burn nonce; valid code consumes nonce.
        let totp_code = setjoin_identity::totp::code(TOTP_SECRET, now as i64).unwrap();
        let bad_totp_body = json!({"mfa_token": pending_token, "code": "000000"}).to_string();
        let nonce_totp_bad = "nonce-totp-bad-350";
        let hdrs_totp_bad = sign_device_headers(
            dev_a,
            device_secret,
            &ts,
            nonce_totp_bad,
            "POST",
            "/auth/totp/verify",
            bad_totp_body.as_bytes(),
        );
        let r = server
            .handle(build_request(
                "POST",
                "/auth/totp/verify",
                bad_totp_body.into_bytes(),
                &[],
                &hdrs_totp_bad,
            )?)
            .await;
        check_eq!(r.status().as_u16(), 401);
        check_eq!(nonce_count(&c, dev_a, nonce_totp_bad).await?, 0);

        let ok_totp_body = json!({"mfa_token": pending_token, "code": totp_code}).to_string();
        let nonce_totp_ok = "nonce-totp-ok-350";
        let hdrs_totp_ok = sign_device_headers(
            dev_a,
            device_secret,
            &ts,
            nonce_totp_ok,
            "POST",
            "/auth/totp/verify",
            ok_totp_body.as_bytes(),
        );
        let r = server
            .handle(build_request(
                "POST",
                "/auth/totp/verify",
                ok_totp_body.into_bytes(),
                &[],
                &hdrs_totp_ok,
            )?)
            .await;
        check_eq!(r.status().as_u16(), 200);
        check_eq!(nonce_count(&c, dev_a, nonce_totp_ok).await?, 1);

        // 2. POST /auth/backup-codes/verify: consumes nonce once.
        let backup_body = json!({"mfa_token": pending_token, "code": BACKUP_CODE}).to_string();
        let nonce_backup = "nonce-backup-ok-350";
        let hdrs_backup = sign_device_headers(
            dev_a,
            device_secret,
            &ts,
            nonce_backup,
            "POST",
            "/auth/backup-codes/verify",
            backup_body.as_bytes(),
        );
        let r = server
            .handle(build_request(
                "POST",
                "/auth/backup-codes/verify",
                backup_body.into_bytes(),
                &[],
                &hdrs_backup,
            )?)
            .await;
        check_eq!(r.status().as_u16(), 200);
        check_eq!(nonce_count(&c, dev_a, nonce_backup).await?, 1);

        // 3. POST /auth/push/status: unapproved poll does NOT burn nonce; approved harvest DOES.
        let push_nonce_hex = "11".repeat(32);
        c.execute(
            "INSERT INTO push_mfa_challenges(user_id,challenge_code,nonce,session_id,expires_at,verified_at,approved_at) VALUES($1,'42',decode($2,'hex'),$3,now()+interval '120 seconds',NULL,NULL)",
            &[&a.user, &push_nonce_hex, &pending_token],
        )
        .await?;
        let push_body = json!({"mfa_token": pending_token, "nonce": push_nonce_hex}).to_string();
        let nonce_push_unapproved = "nonce-push-unapproved-350";
        let hdrs_push_unapproved = sign_device_headers(
            dev_a,
            device_secret,
            &ts,
            nonce_push_unapproved,
            "POST",
            "/auth/push/status",
            push_body.as_bytes(),
        );
        let r = server
            .handle(build_request(
                "POST",
                "/auth/push/status",
                push_body.as_bytes().to_vec(),
                &[],
                &hdrs_push_unapproved,
            )?)
            .await;
        check_eq!(r.status().as_u16(), 200);
        check_eq!(nonce_count(&c, dev_a, nonce_push_unapproved).await?, 0);

        c.execute(
            "UPDATE push_mfa_challenges SET verified_at=now(), approved_at=now() WHERE user_id=$1",
            &[&a.user],
        )
        .await?;
        let nonce_push_ok = "nonce-push-ok-350";
        let hdrs_push_ok = sign_device_headers(
            dev_a,
            device_secret,
            &ts,
            nonce_push_ok,
            "POST",
            "/auth/push/status",
            push_body.as_bytes(),
        );
        let r = server
            .handle(build_request(
                "POST",
                "/auth/push/status",
                push_body.into_bytes(),
                &[],
                &hdrs_push_ok,
            )?)
            .await;
        check_eq!(r.status().as_u16(), 200);
        check_eq!(nonce_count(&c, dev_a, nonce_push_ok).await?, 1);

        // 4. POST /auth/totp/enroll/confirm: bootstrap enrollment confirm consumes nonce.
        c.execute(
            "UPDATE users SET totp_enabled=false,totp_secret_enc=NULL,totp_enabled_at=NULL WHERE id=$1",
            &[&a.user],
        )
        .await?;
        let enrollment_id = uuid::Uuid::new_v4().to_string();
        let pending_hash = hex_sha256(pending_token.as_bytes());
        c.execute(
            "INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,proof_method,bound_factor_generation,token_scope,target_ref,expires_at) VALUES($1,$2,'dev350-pending-jti','bootstrap.totp.enroll','password',2,'mfa_pending',$3,now()+interval '5 minutes')",
            &[&pending_hash, &a.user, &enrollment_id],
        )
        .await?;
        c.execute(
            "INSERT INTO totp_pending_enrollments(id,user_id,secret_enc,staged_by_jti,staged_via,expires_at) VALUES($1::text::uuid,$2,pgp_sym_encrypt($3,$4),'dev350-pending-jti','enroll_setup',now()+interval '15 minutes')",
            &[&enrollment_id, &a.user, &STAGED_SECRET, &ENC],
        )
        .await?;
        let staged_code = setjoin_identity::totp::code(STAGED_SECRET, now as i64).unwrap();
        let boot_body = json!({
            "mfa_token": pending_token,
            "code": staged_code,
            "enrollment_id": enrollment_id
        })
        .to_string();
        let nonce_boot = "nonce-bootstrap-ok-350";
        let hdrs_boot = sign_device_headers(
            dev_a,
            device_secret,
            &ts,
            nonce_boot,
            "POST",
            "/auth/totp/enroll/confirm",
            boot_body.as_bytes(),
        );
        let r = server
            .handle(build_request(
                "POST",
                "/auth/totp/enroll/confirm",
                boot_body.into_bytes(),
                &[],
                &hdrs_boot,
            )?)
            .await;
        check_eq!(r.status().as_u16(), 200);
        check_eq!(nonce_count(&c, dev_a, nonce_boot).await?, 1);

        // 5. POST /auth/webauthn/login/finish: consumes nonce on valid assertion.
        let vectors: Value = serde_json::from_str(include_str!(
            "../../../tests/conformance/identity-webauthn/vectors.json"
        ))?;
        let vector = &vectors["cases"][0];
        let cred_id = URL_SAFE_NO_PAD.decode(vector["id"].as_str().unwrap())?;
        let handle = URL_SAFE_NO_PAD.decode(vector["handle"].as_str().unwrap())?;
        let pub_hex = vector["key"].as_str().unwrap();
        let pub_bytes: Vec<u8> = (0..pub_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&pub_hex[i..i + 2], 16).unwrap())
            .collect();
        c.execute(
            "UPDATE users SET webauthn_user_handle=$2,totp_enabled=false,push_mfa_enabled=false WHERE id=$1",
            &[&a.user, &handle],
        )
        .await?;
        c.execute(
            "INSERT INTO passkey_credentials(id,user_id,public_key,attestation_type,sign_count,device_name,created_at,uv_capable) VALUES($1,$2,$3,'none',7,'Key350','2026-10-01T02:03:04Z',true)",
            &[&cred_id, &a.user, &pub_bytes],
        )
        .await?;
        let cookie_codec = setjoin_identity::webauthn::CookieCipher::new(secret.as_bytes());
        let wa_session = json!({
            "challenge": vector["challenge"],
            "rpId": "localhost",
            "user_id": STANDARD.encode(&handle),
            "allowed_credentials": [STANDARD.encode(&cred_id)],
            "expires": "0001-01-01T00:00:00Z"
        });
        let wa_cookies = format!(
            "wa_login_sess={}; wa_login_uid={}",
            cookie_codec.seal(wa_session.to_string().as_bytes())?,
            cookie_codec.seal(a.user.to_string().as_bytes())?
        );
        let wa_body = vector["assertions"]["success"]["request"].to_string();
        let nonce_wa = "nonce-webauthn-ok-350";
        let hdrs_wa = sign_device_headers(
            dev_a,
            device_secret,
            &ts,
            nonce_wa,
            "POST",
            "/auth/webauthn/login/finish",
            wa_body.as_bytes(),
        );
        let r = server
            .handle(build_request(
                "POST",
                "/auth/webauthn/login/finish",
                wa_body.into_bytes(),
                &[("cookie", &wa_cookies)],
                &hdrs_wa,
            )?)
            .await;
        check_eq!(r.status().as_u16(), 200);
        check_eq!(nonce_count(&c, dev_a, nonce_wa).await?, 1);

        // 6. POST /auth/device/register (webpush): MUST ignore X-Device-* headers,
        // NOT forward to Go, and NOT consume X-Device-Nonce.
        let access_claims = json!({
            "uid": a.user,
            "email": "actor@device350.test",
            "typ": "access",
            "iss": "mailserver",
            "aud": ["mailserver-gateway"],
            "iat": now,
            "exp": now + 3600,
            "jti": "dev350-access-jti"
        });
        let bearer = format!("Bearer {}", sign_hs256(secret.as_bytes(), &access_claims.to_string()));
        let webpush_body = json!({
            "provider": "webpush",
            "push_token": json!({"endpoint": "https://push.example.com/sub/350"}).to_string(),
            "device_name": "Browser350"
        })
        .to_string();
        let nonce_webpush = "nonce-webpush-ignored-350";
        let hdrs_webpush = sign_device_headers(
            dev_a,
            device_secret,
            &ts,
            nonce_webpush,
            "POST",
            "/auth/device/register",
            webpush_body.as_bytes(),
        );
        let r = server
            .handle(build_request(
                "POST",
                "/auth/device/register",
                webpush_body.into_bytes(),
                &[("authorization", &bearer)],
                &hdrs_webpush,
            )?)
            .await;
        check_eq!(r.status().as_u16(), 204);
        check_eq!(
            nonce_count(&c, dev_a, nonce_webpush).await?,
            0,
            "webpush must never consume X-Device-Nonce"
        );

        check!(seen.try_recv().is_err(), "none of these routes may forward to Go");
        drop(server);
        Ok(())
    }
    .await;

    spy_task.abort();
    let _ = spy_task.await;
    cleanup_user_artifacts(&c, &[a.user], &[], &[dev_a]).await?;
    fixture::remove(&c, &a).await?;
    common::restore_receipts(&c, &receipts).await;
    restore_toggles(&c, &saved).await?;
    result
}

#[tokio::test]
async fn sso_oidc_callback_and_saml_acs_device_proof_parity() -> Result<(), Err> {
    let Some(db) = Db::for_case("IDDEVPROOF-sso") else {
        return Ok(());
    };
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let receipts = common::receipt_ids(&c).await;
    let saved = save_toggles(&c).await?;

    let a = fixture::account(&c, "dev350-sso-a").await?;
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await?
        .get(0);
    let secret = master_secret();
    let device_secret = "sso-device-secret-350";
    let dev_a =
        insert_sealed_device(&c, a.user, "fp-sso-a", device_secret, &secret, "approved").await?;

    let oidc_cfg_key = "oidc_provider_device350_config";
    let old_oidc = c
        .query_opt(
            "SELECT value::text,encrypted FROM system_config WHERE key=$1",
            &[&oidc_cfg_key],
        )
        .await?
        .map(|r| (r.get::<_, String>(0), r.get::<_, bool>(1)));
    let oidc_doc = json!({
        "name": "device350",
        "provider_url": OIDC_ISSUER,
        "client_id": OIDC_CLIENT,
        "client_secret": "",
        "redirect_url": OIDC_REDIRECT,
        "enabled": true,
        "jit_enabled": false,
        "group_claim": "groups",
        "group_mappings": []
    })
    .to_string();
    c.execute(
        "INSERT INTO system_config(key,value,encrypted) VALUES($1,$2::text::jsonb,false) ON CONFLICT(key) DO UPDATE SET value=excluded.value,encrypted=false",
        &[&oidc_cfg_key, &oidc_doc],
    )
    .await?;
    c.execute(
        "UPDATE users SET oidc_subject='device350-oidc-sub',oidc_issuer=$2,saml_name_id=$3,saml_idp_entity_id=$4 WHERE id=$1",
        &[&a.user, &OIDC_ISSUER, &email, &saml_support::IDP],
    )
    .await?;

    let metadata = "<EntityDescriptor xmlns=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"https://idp.example.test/metadata\"><IDPSSODescriptor protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://idp.example.test/sso\"/></IDPSSODescriptor></EntityDescriptor>";
    let saml_reg_id: i64 = c
        .query_one(
            "INSERT INTO saml_sp_registrations(idp_entity_id,idp_metadata_url,idp_sso_url,idp_cert_enc,sp_entity_id,sp_acs_url,group_mappings,jit_enabled,allow_idp_initiated) VALUES($1,$2,'https://ignored.invalid/sso',pgp_sym_encrypt($3,$4),'https://sp.example.test/ignored/path','https://ignored.invalid/acs','[]',false,false) RETURNING id",
            &[&saml_support::IDP, &metadata, &saml_support::rsa_idp().cert_pem, &SAML_ENC],
        )
        .await?
        .get(0);

    let fake_idp = Arc::new(FakeOidcHttp::new()?);
    let saml_dir =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/identity-saml");
    let (_spy_addr, mut seen, spy_task) = spy().await?;

    let result: Result<(), Err> = async {
        set_native_toggles(&c).await?;
        let mut cfg = Config::for_secret(secret.clone());
        cfg.signing_alg = "ES256".into();
        cfg.oidc_rp_enabled = true;
        cfg.saml_enabled = true;
        cfg.saml_cert_file = saml_dir.join("sp-cert.pem").display().to_string();
        cfg.saml_key_file = saml_dir.join("sp-key.pem").display().to_string();
        cfg.db_encryption_key = SAML_ENC.into();
        let exec = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
            .map_err(|e| e.0)?;
        let server = AuthServer::load_with_rp_http(exec, cfg, fake_idp.clone()).await?;
        let ts = now_secs().to_string();

        // 1. GET /auth/oidc/callback: staged query URI + empty body consumes nonce.
        let r_login = server
            .handle(build_request(
                "GET",
                "/auth/oidc/login?provider=device350",
                Vec::new(),
                &[],
                &[],
            )?)
            .await;
        check_eq!(r_login.status().as_u16(), 302);
        let mut flow_cookies = Vec::new();
        let (mut state, mut nonce_oidc, mut verifier) =
            (String::new(), String::new(), String::new());
        for sc in r_login.headers().get_all("set-cookie") {
            let s = sc.to_str()?;
            let nv = s.split(';').next().unwrap();
            flow_cookies.push(nv.to_owned());
            if let Some(v) = nv.strip_prefix("oidc_state=") {
                state = v.to_owned();
            } else if let Some(v) = nv.strip_prefix("oidc_nonce=") {
                nonce_oidc = v.to_owned();
            } else if let Some(v) = nv.strip_prefix("oidc_verifier=") {
                verifier = v.to_owned();
            }
        }
        let code = fake_idp.issue_code(&verifier, &nonce_oidc, &email);
        let cb_uri = format!("/auth/oidc/callback?code={code}&state={state}");
        let nonce_oidc_dev = "nonce-oidc-callback-350";
        let hdrs_oidc = sign_device_headers(
            dev_a,
            device_secret,
            &ts,
            nonce_oidc_dev,
            "GET",
            &cb_uri,
            b"",
        );
        let cookie_hdr = flow_cookies.join("; ");
        let r_cb = server
            .handle(build_request(
                "GET",
                &cb_uri,
                Vec::new(),
                &[("cookie", &cookie_hdr)],
                &hdrs_oidc,
            )?)
            .await;
        check_eq!(r_cb.status().as_u16(), 200);
        check_eq!(nonce_count(&c, dev_a, nonce_oidc_dev).await?, 1);

        // 2. POST /auth/saml/{idp}/acs: staged form POST body bytes consume nonce without 503.
        let saml_login_path = "/auth/saml/https:%2F%2Fidp.example.test%2Fmetadata/login";
        let saml_acs_path = "/auth/saml/https:%2F%2Fidp.example.test%2Fmetadata/acs";
        let r_saml_login = server
            .handle(build_request("GET", saml_login_path, Vec::new(), &[], &[])?)
            .await;
        check_eq!(r_saml_login.status().as_u16(), 302);
        let sc = r_saml_login
            .headers()
            .get("set-cookie")
            .ok_or("missing saml tracking cookie")?
            .to_str()?;
        let cookie_pair = sc.split(';').next().unwrap().to_owned();
        let (cookie_name, cookie_jwt) = cookie_pair.split_once('=').unwrap();
        let relay = cookie_name.strip_prefix("saml_").unwrap();
        let claims_json: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD.decode(cookie_jwt.split('.').nth(1).unwrap())?,
        )?;
        let req_id = claims_json["id"].as_str().unwrap().to_owned();
        let now = now_secs();
        let assertion_id = format!("id-acs-{}", uuid::Uuid::new_v4());
        let xml = saml_support::signed_assertion(
            &saml_support::Opts {
                name_id: email.clone(),
                irt: Some(req_id),
                assertion_id,
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
                percent_encoding::NON_ALPHANUMERIC
            ),
            percent_encoding::utf8_percent_encode(relay, percent_encoding::NON_ALPHANUMERIC),
        );
        let nonce_saml_dev = "nonce-saml-acs-350";
        let hdrs_saml = sign_device_headers(
            dev_a,
            device_secret,
            &ts,
            nonce_saml_dev,
            "POST",
            saml_acs_path,
            form_body.as_bytes(),
        );
        let r_acs = server
            .handle(build_request(
                "POST",
                saml_acs_path,
                form_body.into_bytes(),
                &[
                    ("content-type", "application/x-www-form-urlencoded"),
                    ("cookie", &cookie_pair),
                ],
                &hdrs_saml,
            )?)
            .await;
        check_eq!(r_acs.status().as_u16(), 303);
        check_eq!(nonce_count(&c, dev_a, nonce_saml_dev).await?, 1);

        check!(
            seen.try_recv().is_err(),
            "SSO completions must not forward for device proof"
        );
        drop(server);
        Ok(())
    }
    .await;

    spy_task.abort();
    let _ = spy_task.await;
    let _ = c
        .execute(
            "DELETE FROM saml_sp_registrations WHERE id=$1",
            &[&saml_reg_id],
        )
        .await;
    match old_oidc {
        Some((value, encrypted)) => {
            let _ = c
                .execute(
                    "UPDATE system_config SET value=$2::text::jsonb,encrypted=$3 WHERE key=$1",
                    &[&oidc_cfg_key, &value, &encrypted],
                )
                .await;
        }
        None => {
            let _ = c
                .execute("DELETE FROM system_config WHERE key=$1", &[&oidc_cfg_key])
                .await;
        }
    }
    cleanup_user_artifacts(&c, &[a.user], &[email], &[dev_a]).await?;
    fixture::remove(&c, &a).await?;
    common::restore_receipts(&c, &receipts).await;
    restore_toggles(&c, &saved).await?;
    result
}
