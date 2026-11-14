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
    async fn def(c: &tokio_postgres::Client) -> Result<String, tokio_postgres::Error> {
        c.query_one(
            "SELECT pg_get_functiondef('is_guest_account(bigint)'::regprocedure)",
            &[],
        )
        .await
        .map(|r| r.get::<_, String>(0))
    }
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
    Ok((
        email,
        AuthServer::load(exec, cfg)
            .await?
            .with_threat_gate(&db.dsn)
            .await?,
    ))
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

// ---------------------------------------------------------------------------
// E10 N1-N4, T-P, T-F, T-R: the six native entry routes, driven through the
// front-door handler. Material mirrors the oracles (mfa_oracle, push_oracle,
// webauthn_oracle) so the same fixtures and token shapes are exercised.
// ---------------------------------------------------------------------------

const ENC: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const SECRET: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const STAGED: &str = "JBSWY3DPEHPK3PXP";
const ENROLLMENT: &str = "00000000-0000-4000-8000-000000000353";
const VAPID: &str = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE";
const TOTP_SQL: &str = "UPDATE users SET totp_enabled=true,totp_secret_enc=pgp_sym_encrypt($2,$3),totp_enabled_at=now(),totp_backup_codes_enc=$4,factor_generation=2 WHERE id=$1";
const BACKUP: &str = "backup353";
const ROUTES: [&str; 6] = ["login", "verify", "confirm", "backup", "push", "webauthn"];
const FLAGS: &str = "('feature.rate_limit','feature.conditional_access','feature.device_trust_enforcement','feature.token_binding')";

struct Mat {
    method: &'static str,
    path: &'static str,
    body: String,
    headers: Vec<(&'static str, String)>,
}

struct Case {
    a: fixture::Account,
    email: String,
    mat: Mat,
    auth: AuthServer,
    route: String,
}

fn unhex(raw: &str) -> Vec<u8> {
    (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap())
        .collect()
}

fn b64(s: &str) -> Result<Vec<u8>, Err> {
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s)?)
}

impl Case {
    /// Seeds one account (guest or member) with exactly the material `route`
    /// needs, and loads the auth server (optionally with a Go upstream).
    async fn new(
        db: &Db,
        c: &tokio_postgres::Client,
        route: &str,
        guest: bool,
        label: &str,
        upstream: Option<String>,
    ) -> Result<Case, Err> {
        use sha2::{Digest, Sha256};
        common::signing_key(c).await;
        let a = fixture::account(c, label).await?;
        let keys: Value = serde_json::from_str(include_str!(
            "../../../tests/conformance/identity-login/keys.json"
        ))?;
        let secret = keys["secret"].as_str().unwrap().to_owned();
        c.execute("DELETE FROM guest_accounts WHERE user_id=$1", &[&a.user])
            .await?;
        c.execute(
            "UPDATE users SET password_hash=$1,mfa_exempt=false,totp_enabled=false,push_mfa_enabled=false WHERE id=$2",
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
        let email: String = c
            .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
            .await?
            .get(0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let jti = format!("guest353-{label}");
        let pending = |uid: i64| {
            let claims = json!({"uid":uid,"email":email,"typ":"mfa_pending","amr":["pwd"],"iss":"mailserver","aud":["mailserver-gateway"],"iat":now,"exp":now+3600,"jti":jti});
            setjoin_authz::legacy_jwt::sign_hs256(secret.as_bytes(), &claims.to_string())
        };
        let token = pending(a.user);
        let backup_hashes = vec![bcrypt::hash(BACKUP, 4)?];
        let mut headers: Vec<(&'static str, String)> = Vec::new();
        let mat = match route {
            "login" => {
                c.execute("UPDATE users SET mfa_exempt=true WHERE id=$1", &[&a.user])
                    .await?;
                Mat {
                    method: "POST",
                    path: "/auth/login",
                    body: json!({"email":email,"password":"Password1!"}).to_string(),
                    headers,
                }
            }
            "verify" => {
                c.execute(TOTP_SQL, &[&a.user, &SECRET, &ENC, &backup_hashes])
                    .await?;
                Mat {
                    method: "POST",
                    path: "/auth/totp/verify",
                    body: json!({"mfa_token":token,"code":setjoin_identity::totp::code(SECRET, now as i64).unwrap()}).to_string(),
                    headers,
                }
            }
            "confirm" => {
                let hash = format!("{:x}", Sha256::digest(token.as_bytes()));
                c.execute("INSERT INTO mfa_reauth_step_ups(token_hash,user_id,session_jti,operation,proof_method,bound_factor_generation,token_scope,expires_at,target_ref) VALUES($1,$2,$3,'bootstrap.totp.enroll','password',2,'mfa_pending',now()+interval '5 minutes',$4)",&[&hash,&a.user,&jti,&ENROLLMENT]).await?;
                c.execute("INSERT INTO totp_pending_enrollments(id,user_id,secret_enc,staged_by_jti,staged_via,expires_at) VALUES($1::text::uuid,$2,pgp_sym_encrypt($3,$4),$5,'enroll_setup',now()+interval '15 minutes')",&[&ENROLLMENT,&a.user,&STAGED,&ENC,&jti]).await?;
                Mat {
                    method: "POST",
                    path: "/auth/totp/enroll/confirm",
                    body: json!({"mfa_token":token,"code":setjoin_identity::totp::code(STAGED, now as i64).unwrap(),"enrollment_id":ENROLLMENT}).to_string(),
                    headers,
                }
            }
            "backup" => {
                c.execute(TOTP_SQL, &[&a.user, &SECRET, &ENC, &backup_hashes])
                    .await?;
                Mat {
                    method: "POST",
                    path: "/auth/backup-codes/verify",
                    body: json!({"mfa_token":token,"code":BACKUP}).to_string(),
                    headers,
                }
            }
            "push" => {
                c.execute(TOTP_SQL, &[&a.user, &SECRET, &ENC, &backup_hashes])
                    .await?;
                c.execute("INSERT INTO push_mfa_challenges(user_id,challenge_code,nonce,session_id,expires_at,verified_at,approved_at) VALUES($1,'42',decode($2,'hex'),$3,now()+interval '120 seconds',now(),now())",&[&a.user,&"11".repeat(32),&token]).await?;
                Mat {
                    method: "POST",
                    path: "/auth/push/status",
                    body: json!({"mfa_token":token,"nonce":"11".repeat(32)}).to_string(),
                    headers,
                }
            }
            "webauthn" => {
                let vectors: Value = serde_json::from_str(include_str!(
                    "../../../tests/conformance/identity-webauthn/vectors.json"
                ))?;
                let v = &vectors["cases"][0];
                let id = b64(v["id"].as_str().unwrap())?;
                let handle = b64(v["handle"].as_str().unwrap())?;
                c.execute(
                    "UPDATE users SET webauthn_user_handle=$2 WHERE id=$1",
                    &[&a.user, &handle],
                )
                .await?;
                c.execute("INSERT INTO passkey_credentials(id,user_id,public_key,attestation_type,sign_count,device_name,created_at,uv_capable) VALUES($1,$2,$3,'none',7,'My key','2026-10-01T02:03:04Z',true)",&[&id,&a.user,&unhex(v["key"].as_str().unwrap())]).await?;
                let std = base64::engine::general_purpose::STANDARD;
                let session = json!({"challenge":v["challenge"],"rpId":"localhost","user_id":std.encode(&handle),"allowed_credentials":[std.encode(&id)],"expires":"0001-01-01T00:00:00Z"});
                let codec = setjoin_identity::webauthn::CookieCipher::new(secret.as_bytes());
                headers.push((
                    "cookie",
                    format!(
                        "wa_login_sess={}; wa_login_uid={}",
                        codec.seal(session.to_string().as_bytes())?,
                        codec.seal(a.user.to_string().as_bytes())?
                    ),
                ));
                Mat {
                    method: "POST",
                    path: "/auth/webauthn/login/finish",
                    body: v["assertions"]["success"]["request"].to_string(),
                    headers,
                }
            }
            other => return Err(format!("unknown route {other}").into()),
        };
        let mut cfg = Config::for_secret(secret.clone());
        cfg.signing_alg = "ES256".into();
        cfg.db_encryption_key = ENC.into();
        cfg.vapid_private_key = VAPID.into();
        cfg.go_upstream = upstream;
        let exec = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
            .map_err(|e| e.0)?;
        let auth = AuthServer::load(exec, cfg)
            .await?
            .with_threat_gate(&db.dsn)
            .await?;
        Ok(Case {
            a,
            email,
            mat,
            auth,
            route: route.to_owned(),
        })
    }

    /// Sends the seeded request; `query` is appended to the path.
    async fn send(&self, query: &str) -> Result<(u16, String), Err> {
        let uri = format!("{}{query}", self.mat.path);
        post(
            &self.auth,
            self.mat.method,
            &uri,
            &self.mat.body,
            &self.mat.headers,
        )
        .await
    }

    /// Everything the route's factor consumes, as one comparable string.
    async fn snap(&self, c: &tokio_postgres::Client) -> Result<String, Err> {
        let u = self.a.user;
        let tokens: String = c.query_one("SELECT (SELECT count(*) FROM sessions WHERE user_id=$1)::text||'/'||(SELECT count(*) FROM oauth_tokens WHERE user_id=$1)::text||'/'||(SELECT count(*) FROM login_events WHERE user_id=$1)::text",&[&u]).await?.get(0);
        let sql = match self.route.as_str() {
            "login" => "SELECT (SELECT count(*) FROM auth_event_log WHERE email=(SELECT email FROM users WHERE id=$1))::text",
            "verify" => "SELECT (SELECT count(*) FROM totp_counter_claims WHERE user_id=$1)::text||'|'||coalesce((SELECT last_totp_used_at::text FROM users WHERE id=$1),'null')||'|'||(SELECT totp_failed_attempts FROM users WHERE id=$1)::text",
            "confirm" => "SELECT (SELECT count(*) FROM totp_pending_enrollments WHERE user_id=$1)::text||'|'||(SELECT count(*) FROM mfa_reauth_step_ups WHERE user_id=$1)::text||'|'||(SELECT totp_enabled::text FROM users WHERE id=$1)",
            "backup" => "SELECT coalesce((SELECT totp_backup_codes_enc::text FROM users WHERE id=$1),'null')",
            "push" => "SELECT coalesce((SELECT string_agg(session_id||':'||coalesce(verified_at::text,'-')||':'||failed_attempts::text,',') FROM push_mfa_challenges WHERE user_id=$1),'none')",
            _ => "SELECT coalesce((SELECT string_agg(sign_count::text,',') FROM passkey_credentials WHERE user_id=$1),'none')",
        };
        let own: String = c.query_one(sql, &[&u]).await?.get(0);
        Ok(format!("{tokens}#{own}"))
    }

    async fn cleanup(self, c: &tokio_postgres::Client) -> Result<(), Err> {
        let u = self.a.user;
        c.execute("DELETE FROM auth_event_log WHERE email=$1", &[&self.email])
            .await?;
        for t in [
            "login_events",
            "sessions",
            "oauth_tokens",
            "totp_counter_claims",
            "push_mfa_challenges",
            "mfa_reauth_step_ups",
            "totp_pending_enrollments",
            "passkey_credentials",
            "guest_accounts",
        ] {
            c.execute(&format!("DELETE FROM {t} WHERE user_id=$1"), &[&u])
                .await?;
        }
        c.batch_execute(&format!("BEGIN;SET LOCAL session_replication_role=replica;DELETE FROM admin_audit_log WHERE user_id={u};COMMIT")).await?;
        let a = self.a.clone();
        drop(self);
        fixture::remove(c, &a).await?;
        Ok(())
    }
}

async fn post(
    auth: &AuthServer,
    method: &str,
    uri: &str,
    payload: &str,
    headers: &[(&'static str, String)],
) -> Result<(u16, String), Err> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "auth.guest353.test")
        .header("content-type", "application/json")
        .extension(setjoin_auth::ConnectionMeta {
            peer: "127.0.0.1:9".parse()?,
            tls: false,
        });
    for (k, v) in headers {
        req = req.header(*k, v.as_str());
    }
    let resp = auth.handle(req.body(body(payload.to_owned()))?).await;
    let status = resp.status().as_u16();
    let bytes = resp.into_body().collect().await?.to_bytes();
    Ok((status, String::from_utf8_lossy(&bytes).into_owned()))
}

/// A fake Go upstream that records (method, uri, body) and answers 200.
async fn spy() -> Result<
    (
        std::net::SocketAddr,
        tokio::sync::mpsc::Receiver<(String, String, Vec<u8>)>,
        tokio::task::JoinHandle<()>,
    ),
    Err,
> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (tx, rx) = tokio::sync::mpsc::channel(8);
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let tx = tx.clone();
            tokio::spawn(async move {
                let service =
                    hyper::service::service_fn(move |r: Request<hyper::body::Incoming>| {
                        let tx = tx.clone();
                        async move {
                            let method = r.method().to_string();
                            let uri = r.uri().to_string();
                            let b = r.into_body().collect().await.unwrap().to_bytes().to_vec();
                            let _ = tx.send((method, uri, b)).await;
                            Ok::<_, std::convert::Infallible>(
                                hyper::Response::builder()
                                    .status(200)
                                    .body(body("forwarded"))
                                    .unwrap(),
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

/// Flags are saved verbatim and restored in every path.
async fn save_flags(c: &tokio_postgres::Client) -> Result<String, Err> {
    Ok(c.query_one(&format!("SELECT coalesce(jsonb_agg(to_jsonb(t)),'[]')::text FROM feature_toggles t WHERE key IN {FLAGS}"), &[]).await?.get(0))
}
async fn restore_flags(c: &tokio_postgres::Client, saved: &str) -> Result<(), Err> {
    c.batch_execute("GRANT SELECT ON feature_toggles TO setjoin_app")
        .await?;
    c.execute(
        &format!("DELETE FROM feature_toggles WHERE key IN {FLAGS}"),
        &[],
    )
    .await?;
    c.execute("INSERT INTO feature_toggles SELECT * FROM jsonb_populate_recordset(NULL::feature_toggles,$1::text::jsonb)", &[&saved]).await?;
    Ok(())
}
async fn set_flags(c: &tokio_postgres::Client, ca: bool, dt: bool) -> Result<(), Err> {
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false),('feature.token_binding',false),('feature.conditional_access',$1),('feature.device_trust_enforcement',$2) ON CONFLICT(key) DO UPDATE SET enabled=EXCLUDED.enabled", &[&ca, &dt]).await?;
    Ok(())
}

fn tokens_of(raw: &str) -> Result<(Value, Value), Err> {
    let v: Value = serde_json::from_str(raw)?;
    Ok((
        claims_of(
            v["access_token"]
                .as_str()
                .ok_or_else(|| format!("no access_token in {raw}"))?,
        )?,
        claims_of(v["refresh_token"].as_str().ok_or("no refresh_token")?)?,
    ))
}

#[derive(Clone, Copy, Debug)]
enum Cond {
    Ca,
    Dt,
    FlagErr,
    Clear,
}

/// N1: one cell of the 6 routes x 4 conditions matrix.
async fn n1_cell(
    db: &Db,
    c: &tokio_postgres::Client,
    route: &str,
    cond: Cond,
    n: usize,
) -> Result<(), Err> {
    let (addr, mut seen, spy_task) = spy().await?;
    let what = format!("{route}/{cond:?}");
    let case = Case::new(
        db,
        c,
        route,
        true,
        &format!("guest353-n1-{n}"),
        Some(format!("http://{addr}")),
    )
    .await;
    let case = match case {
        Ok(k) => k,
        Err(e) => {
            spy_task.abort();
            return Err(e);
        }
    };
    let result: Result<(), Err> = async {
        match cond {
            Cond::Ca => set_flags(c, true, false).await?,
            Cond::Dt => set_flags(c, false, true).await?,
            Cond::FlagErr => {
                set_flags(c, false, false).await?;
                check(
                    db.app.is_some(),
                    "flag-error cell needs a distinct app role DSN",
                )?;
                c.batch_execute("REVOKE SELECT ON feature_toggles FROM setjoin_app")
                    .await?;
                let probe = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap(), 1)
                    .map_err(|e| e.0)?;
                check(
                    probe
                        .read("SELECT enabled FROM feature_toggles LIMIT 1", &[])
                        .await
                        .is_err(),
                    "precondition: the app read of feature_toggles must fail",
                )?;
            }
            Cond::Clear => {
                set_flags(c, false, false).await?;
                c.execute(
                    "DELETE FROM feature_toggles WHERE key='feature.device_trust_enforcement'",
                    &[],
                )
                .await?;
            }
        }
        let before = case.snap(c).await?;
        let query = if matches!(cond, Cond::Clear) {
            ""
        } else {
            "?n=353"
        };
        let (status, raw) = case.send(query).await?;
        let after = case.snap(c).await?;
        if matches!(cond, Cond::Clear) {
            check(
                status == 200,
                &format!("{what}: native status {status}: {raw}"),
            )?;
            check(
                seen.try_recv().is_err(),
                &format!("{what}: native cell reached the upstream"),
            )?;
            let (access, refresh) = tokens_of(&raw)?;
            check(
                access["acct"] == json!("guest"),
                &format!("{what}: access needs acct guest"),
            )?;
            check(
                refresh.get("acct").is_none(),
                &format!("{what}: refresh must not carry acct"),
            )?;
        } else {
            let got = tokio::time::timeout(std::time::Duration::from_secs(10), seen.recv())
                .await
                .map_err(|_| format!("{what}: nothing forwarded"))?
                .ok_or("spy closed")?;
            let want = (
                case.mat.method.to_owned(),
                format!("{}{query}", case.mat.path),
                case.mat.body.clone().into_bytes(),
            );
            check(
                got == want,
                &format!("{what}: forwarded request differs from the original"),
            )?;
            check(
                status == 200 && raw == "forwarded",
                &format!("{what}: upstream answer not relayed: {status} {raw}"),
            )?;
            check(
                before == after,
                &format!("{what}: forward consumed state: {before} -> {after}"),
            )?;
        }
        Ok(())
    }
    .await;
    spy_task.abort();
    let grant = c
        .batch_execute("GRANT SELECT ON feature_toggles TO setjoin_app")
        .await;
    let cleaned = case.cleanup(c).await;
    grant?;
    cleaned?;
    result
}

#[tokio::test]
async fn n1_handoff_matrix_forwards_whole_and_clear_is_native() {
    let (_serial, db, c) = begin("GUEST353-n1").await.unwrap();
    let saved = save_flags(&c).await.unwrap();
    let mut result: Result<(), Err> = Ok(());
    let mut n = 0;
    'outer: for route in ROUTES {
        for cond in [Cond::Ca, Cond::Dt, Cond::FlagErr, Cond::Clear] {
            n += 1;
            if let Err(e) = n1_cell(&db, &c, route, cond, n).await {
                result = Err(format!("{route}/{cond:?}: {e}").into());
                break 'outer;
            }
        }
    }
    let restored = restore_flags(&c, &saved).await;
    finish(&c, result).await.unwrap();
    restored.unwrap();
}

/// Runs one native completion for `route` and returns (status, body).
async fn native(
    db: &Db,
    c: &tokio_postgres::Client,
    route: &str,
    guest: bool,
    label: &str,
    guest_fn: Option<&str>,
) -> Result<(Case, String, u16, String), Err> {
    let case = Case::new(db, c, route, guest, label, None).await?;
    if let Some(branch) = guest_fn {
        install_counting_guest(c, branch).await?;
    }
    let before = case.snap(c).await?;
    let (status, raw) = case.send("").await?;
    Ok((case, before, status, raw))
}

/// Native-case wrapper: flags clear, cleanup in every path, pristine after.
async fn clear_flags_case<F, Fut>(name: &str, body_fn: F)
where
    F: FnOnce(Db, &'static tokio_postgres::Client) -> Fut,
    Fut: std::future::Future<Output = Result<(), Err>>,
{
    let (_serial, db, c) = begin(name).await.unwrap();
    let saved = save_flags(&c).await.unwrap();
    // The client lives for the test; leaking one connection handle per case is
    // cheaper than threading lifetimes through the closure.
    let c: &'static tokio_postgres::Client = Box::leak(Box::new(c));
    let result = async {
        set_flags(c, false, false).await?;
        c.execute(
            "DELETE FROM feature_toggles WHERE key='feature.device_trust_enforcement'",
            &[],
        )
        .await?;
        body_fn(db, c).await
    }
    .await;
    let restored = restore_flags(c, &saved).await;
    finish(c, result).await.unwrap();
    restored.unwrap();
}

/// N4: members of every route mint no acct claim anywhere.
#[tokio::test]
async fn n4_member_completions_carry_no_acct() {
    clear_flags_case("GUEST353-n4", |db, c| async move {
        for (n, route) in ROUTES.iter().enumerate() {
            let (case, _before, status, raw) =
                native(&db, c, route, false, &format!("guest353-n4-{n}"), None).await?;
            let checked = (|| -> Result<(), Err> {
                check(status == 200, &format!("{route}: status {status}: {raw}"))?;
                let (access, refresh) = tokens_of(&raw)?;
                check(
                    access.get("acct").is_none(),
                    &format!("{route}: member access has acct"),
                )?;
                check(
                    refresh.get("acct").is_none(),
                    &format!("{route}: member refresh has acct"),
                )
            })();
            case.cleanup(c).await?;
            checked?;
        }
        Ok::<(), Err>(())
    })
    .await;
}

/// T-R: every natively minted guest pair refreshes into a guest access token
/// and an acct-free refresh token.
#[tokio::test]
async fn tr_guest_pairs_refresh_with_acct_on_access_only() {
    clear_flags_case("GUEST353-tr", |db, c| async move {
        for (n, route) in ROUTES.iter().enumerate() {
            let (case, _before, status, raw) =
                native(&db, c, route, true, &format!("guest353-tr-{n}"), None).await?;
            let checked = async {
                check(status == 200, &format!("{route}: status {status}: {raw}"))?;
                let (access, refresh) = tokens_of(&raw)?;
                check(
                    access["acct"] == json!("guest"),
                    &format!("{route}: access needs acct guest"),
                )?;
                check(
                    refresh.get("acct").is_none(),
                    &format!("{route}: refresh has acct"),
                )?;
                let v: Value = serde_json::from_str(&raw)?;
                let (st, again) = post(
                    &case.auth,
                    "POST",
                    "/auth/refresh",
                    &json!({"refresh_token":v["refresh_token"]}).to_string(),
                    &[],
                )
                .await?;
                check(st == 200, &format!("{route}: refresh status {st}: {again}"))?;
                let (access2, refresh2) = tokens_of(&again)?;
                check(
                    access2["acct"] == json!("guest"),
                    &format!("{route}: refreshed access needs acct guest"),
                )?;
                check(
                    refresh2.get("acct").is_none(),
                    &format!("{route}: refreshed refresh has acct"),
                )
            }
            .await;
            case.cleanup(c).await?;
            checked?;
        }
        Ok::<(), Err>(())
    })
    .await;
}

/// N2: backup and push completions, guest scope failure ordering.
#[tokio::test]
async fn n2_backup_and_push_guest_scope_and_failure_order() {
    clear_flags_case("GUEST353-n2", |db, c| async move {
        // Guest 200 acct guest was proven by N1(d) and T-R; here: the faults.
        for (n, route) in ["backup", "push"].iter().enumerate() {
            // Scope lookup raises: 503 after the factor is consumed; retry parity.
            let (case, before, status, raw) = native(&db, c, route, true, &format!("guest353-n2a-{n}"), Some("RAISE EXCEPTION 'gofree-guest353 scope fault';")).await?;
            let r: Result<(), Err> = async {
                check(status == 503 && raw.contains("conditional access context unavailable"), &format!("{route}: want 503 scope, got {status} {raw}"))?;
                check(!raw.contains("access_token"), &format!("{route}: 503 leaked tokens"))?;
                let after = case.snap(c).await?;
                check(after != before, &format!("{route}: factor must be consumed before the 503"))?;
                let (st2, raw2) = case.send("").await?;
                if *route == "backup" {
                    check(st2 == 401 && raw2.contains("invalid or used backup code"), &format!("backup retry: {st2} {raw2}"))?;
                } else {
                    check(st2 == 200 && raw2 == "{\"approved\":false}\n", &format!("push retry: {st2} {raw2}"))?;
                }
                Ok(())
            }
            .await;
            case.cleanup(c).await?;
            guest_function_pristine(c).await?;
            r?;
            // Split: first lookup true, second raises: 500 account type.
            let (case, _before, status, raw) = native(&db, c, route, true, &format!("guest353-n2b-{n}"), Some("IF nextval('gofree_guest353_calls')>1 THEN RAISE EXCEPTION 'gofree-guest353 account type fault'; END IF; RETURN true;")).await?;
            let r: Result<(), Err> = (|| {
                check(status == 500 && raw.contains("account type resolution failed"), &format!("{route}: want 500 account type, got {status} {raw}"))?;
                check(!raw.contains("access_token"), &format!("{route}: 500 leaked tokens"))
            })();
            case.cleanup(c).await?;
            guest_function_pristine(c).await?;
            r?;
        }
        Ok::<(), Err>(())
    })
    .await;
}

/// N3: WebAuthn finish for a guest.
#[tokio::test]
async fn n3_webauthn_guest_direct_mfa_and_scope_failure() {
    clear_flags_case("GUEST353-n3", |db, c| async move {
        // Direct: acct guest (covered with refresh by T-R; asserted here too).
        let (case, _before, status, raw) = native(&db, c, "webauthn", true, "guest353-n3-direct", None).await?;
        let r: Result<(), Err> = (|| {
            check(status == 200, &format!("direct: {status} {raw}"))?;
            let (access, _) = tokens_of(&raw)?;
            check(access["acct"] == json!("guest"), "direct: access needs acct guest")
        })();
        case.cleanup(c).await?;
        r?;
        // MFA enrolled: mfa_required, mfa_pending without acct, no guest lookup effect.
        let case = Case::new(&db, c, "webauthn", true, "guest353-n3-mfa", None).await?;
        let r: Result<(), Err> = async {
            c.execute("UPDATE users SET totp_enabled=true,totp_secret_enc=pgp_sym_encrypt($2,$3),totp_enabled_at=now() WHERE id=$1", &[&case.a.user, &SECRET, &ENC]).await?;
            let (status, raw) = case.send("").await?;
            check(status == 200, &format!("mfa: {status} {raw}"))?;
            let v: Value = serde_json::from_str(&raw)?;
            check(v["mfa_required"] == json!(true), &format!("mfa: not mfa_required: {raw}"))?;
            check(v.get("access_token").is_none(), "mfa: tokens issued before the second factor")?;
            let pending = claims_of(v["mfa_token"].as_str().ok_or("no mfa_token")?)?;
            check(pending.get("acct").is_none(), "mfa_pending must not carry acct")
        }
        .await;
        case.cleanup(c).await?;
        r?;
        // Raising lookup: 503, assertion counter already advanced (Go order).
        let case = Case::new(&db, c, "webauthn", true, "guest353-n3-503", None).await?;
        install_counting_guest(c, "RAISE EXCEPTION 'gofree-guest353 scope fault';").await?;
        let r: Result<(), Err> = async {
            let before = case.snap(c).await?;
            let (status, raw) = case.send("").await?;
            let after = case.snap(c).await?;
            check(status == 503 && raw.contains("conditional access context unavailable"), &format!("503 case: {status} {raw}"))?;
            check(!raw.contains("access_token"), "503 leaked tokens")?;
            check(before != after, "assertion counter must advance before the 503")
        }
        .await;
        case.cleanup(c).await?;
        guest_function_pristine(c).await?;
        r
    })
    .await;
}

/// T-P: a guest with push MFA gets a push challenge; the pending token has no acct.
#[tokio::test]
async fn tp_guest_push_login_challenge_pending_has_no_acct() {
    clear_flags_case("GUEST353-tp", |db, c| async move {
        let case = Case::new(&db, c, "login", true, "guest353-tp", None).await?;
        let r: Result<(), Err> = async {
            c.execute(
                "UPDATE users SET mfa_exempt=false,push_mfa_enabled=true WHERE id=$1",
                &[&case.a.user],
            )
            .await?;
            let (status, raw) = case.send("").await?;
            let v: Value = serde_json::from_str(&raw)?;
            check(
                status == 202 && v["mfa_method"] == json!("push"),
                &format!("push challenge expected: {status} {raw}"),
            )?;
            let pending = claims_of(v["mfa_token"].as_str().ok_or("no mfa_token")?)?;
            check(
                pending.get("acct").is_none(),
                "push mfa_pending must not carry acct",
            )
        }
        .await;
        case.cleanup(c).await?;
        r
    })
    .await;
}

/// T-F: a guest who must change the password gets only a force token, no acct.
#[tokio::test]
async fn tf_guest_force_password_change_token_has_no_acct() {
    clear_flags_case("GUEST353-tf", |db, c| async move {
        let case = Case::new(&db, c, "login", true, "guest353-tf", None).await?;
        let r: Result<(), Err> = async {
            c.execute(
                "UPDATE users SET must_change_password=true WHERE id=$1",
                &[&case.a.user],
            )
            .await?;
            let (status, raw) = case.send("").await?;
            let v: Value = serde_json::from_str(&raw)?;
            check(
                status == 403 && v["status"] == json!("force_password_change"),
                &format!("force change expected: {status} {raw}"),
            )?;
            check(
                v.get("access_token").is_none(),
                "force change issued an access token",
            )?;
            let force = claims_of(v["force_token"].as_str().ok_or("no force_token")?)?;
            check(
                force.get("acct").is_none(),
                "force_token must not carry acct",
            )
        }
        .await;
        case.cleanup(c).await?;
        r
    })
    .await;
}
