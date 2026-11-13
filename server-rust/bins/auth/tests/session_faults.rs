mod common;
#[path = "common/session_commit.rs"]
mod wire;
use http_body_util::BodyExt;
use hyper::Request;
use serde_json::{json, Value};
use setjoin_auth::{body, AuthServer, Config};
use setjoin_conformance::{fixture, harness::Db};
struct Wire(tokio::task::JoinHandle<std::io::Result<wire::Cut>>);
impl Drop for Wire {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn refresh(cut: wire::Cut) {
    let db = Db::for_case("IDLOGIN2-refresh-commit").unwrap();
    let c = db.connect().await.unwrap();
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await
    .unwrap();
    common::signing_key(&c).await;
    let a = fixture::account(&c, "idlogin2-commit").await.unwrap();
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await
        .unwrap()
        .get(0);
    c.execute(
        "UPDATE users SET password_hash=$1,mfa_exempt=true WHERE id=$2",
        &[&bcrypt::hash("Password1!", 4).unwrap(), &a.user],
    )
    .await
    .unwrap();
    let flags:String=c.query_one("SELECT coalesce(jsonb_agg(to_jsonb(t)),'[]')::text FROM feature_toggles t WHERE key='feature.rate_limit'",&[]).await.unwrap().get(0);
    c.batch_execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false").await.unwrap();
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let clean =
        setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).unwrap();
    let server = AuthServer::load(
        clean,
        Config::for_secret(f["secret"].as_str().unwrap().into()),
    )
    .await
    .unwrap();
    let resp = server
        .handle(
            Request::post("/auth/login")
                .body(body(
                    json!({"email":email,"password":"Password1!"}).to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), 200);
    let login: Value =
        serde_json::from_slice(&resp.into_body().collect().await.unwrap().to_bytes()).unwrap();
    drop(server);
    c.execute("DELETE FROM auth_event_log WHERE user_id=$1", &[&a.user])
        .await
        .unwrap();
    let record = std::env::var_os("GOFREE_RECORD_REFRESH_FAULTS").is_some();
    let (dsn, task, active) = wire::armable(
        db.app.as_deref().unwrap_or(&db.dsn),
        cut,
        if record { 1 } else { 2 },
    )
    .await;
    let mut wire = Wire(task);
    let mut go = None;
    let mut native = None;
    let resp = if record {
        let (process, addr) = go_server(&dsn, &db.dsn, f["secret"].as_str().unwrap(), cut).await;
        active.store(true, std::sync::atomic::Ordering::SeqCst);
        go = Some(process);
        let client: hyper_util::client::legacy::Client<_, setjoin_auth::Body> =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build_http();
        client
            .request(
                Request::post(format!("http://{addr}/auth/refresh"))
                    .body(body(
                        json!({"refresh_token":login["refresh_token"]}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap()
            .map(|b| b.map_err(std::io::Error::other).boxed())
    } else {
        active.store(true, std::sync::atomic::Ordering::SeqCst);
        let exec = setjoin_pg::ScopedExecutor::from_dsn(&dsn, 4).unwrap();
        let server = AuthServer::load(
            exec,
            Config::for_secret(f["secret"].as_str().unwrap().into()),
        )
        .await
        .unwrap();
        let response = server
            .handle(
                Request::post("/auth/refresh")
                    .body(body(
                        json!({"refresh_token":login["refresh_token"]}).to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        native = Some(server);
        response
    };
    let status = resp.status();
    let operation = resp.headers().get("x-operation-id").cloned();
    let cookie = resp.headers().contains_key("set-cookie");
    let raw = resp.into_body().collect().await.unwrap().to_bytes();
    drop(native);
    drop(go);
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(10), &mut wire.0)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        cut
    );
    let rows: i64 = c
        .query_one(
            "SELECT count(*) FROM oauth_tokens WHERE user_id=$1",
            &[&a.user],
        )
        .await
        .unwrap()
        .get(0);
    let audit:i64=c.query_one("SELECT count(*) FROM auth_event_log WHERE user_id=$1 AND event='login' AND provider='jwt'",&[&a.user]).await.unwrap().get(0);
    if let Some(header) = &operation {
        let id = uuid::Uuid::parse_str(header.to_str().unwrap()).unwrap();
        let legacy = setjoin_authz::legacy_jwt::LegacyKeys::new(
            f["secret"].as_str().unwrap().as_bytes(),
            &["authserver-hmac-1"],
            None,
        )
        .unwrap();
        let proof = setjoin_identity::session::Session::verify(
            login["refresh_token"].as_str().unwrap(),
            None,
            &legacy,
            "mailserver",
        )
        .unwrap();
        let clean =
            setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).unwrap();
        assert_eq!(
            proof
                .lookup_refresh(&clean, setjoin_contracts::ids::OperationId(*id.as_bytes()))
                .await
                .unwrap(),
            cut == wire::Cut::After
        );
        c.execute(
            "DELETE FROM rust_operation_receipts WHERE operation_id=$1::text::uuid",
            &[&id.to_string()],
        )
        .await
        .unwrap();
    }
    c.execute("DELETE FROM auth_event_log WHERE user_id=$1", &[&a.user])
        .await
        .unwrap();
    fixture::remove(&c, &a).await.unwrap();
    c.batch_execute("DELETE FROM feature_toggles WHERE key='feature.rate_limit'")
        .await
        .unwrap();
    c.execute("INSERT INTO feature_toggles SELECT * FROM jsonb_populate_recordset(NULL::feature_toggles,$1::text::jsonb)",&[&flags]).await.unwrap();
    let raw = std::str::from_utf8(&raw).unwrap();
    assert!(!raw.contains("access_token") && !raw.contains("refresh_token"));
    let observation =
        json!({"status":status.as_u16(),"body":raw,"rows":rows,"audit":audit,"cookie":cookie});
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/identity-login/security")
        .join(if cut == wire::Cut::Before {
            "refresh-commit-before.json"
        } else {
            "refresh-commit-after.json"
        });
    let value = json!({"format":1,"go_source":f["go_source"],"route":"POST /auth/refresh","case":if cut==wire::Cut::Before{"refresh-commit-before"}else{"refresh-commit-after"},"observation":observation});
    if record && !path.exists() {
        setjoin_conformance::golden::record(&path, &value).unwrap();
    } else {
        let expected: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        setjoin_conformance::golden::compare(&expected, &value).unwrap();
    }
    if !record {
        assert!(operation.is_some());
    }
    assert!(!cookie);
    assert_eq!(rows, if cut == wire::Cut::After { 2 } else { 1 });
    assert_eq!(audit,1,"Go writes its independent auth event before COMMIT, including a lost COMMIT acknowledgement");
}
#[tokio::test]
async fn refresh_lost_commit_before_never_releases_credentials() {
    refresh(wire::Cut::Before).await;
}
#[tokio::test]
async fn refresh_lost_commit_after_never_releases_credentials() {
    refresh(wire::Cut::After).await;
}

struct Go(String);
impl Drop for Go {
    fn drop(&mut self) {
        let _ = std::process::Command::new("docker")
            .args(["stop", &self.0])
            .output();
        let _ = std::process::Command::new("docker")
            .args(["rm", &self.0])
            .output();
    }
}
async fn go_server(
    dsn: &str,
    owner: &str,
    secret: &str,
    cut: wire::Cut,
) -> (Go, std::net::SocketAddr) {
    let listener = setjoin_conformance::ports::listener().await;
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let tools = root.join("server-rust/target/gofree-idlogin2-tools");
    let envfile = tools.join(format!("fault-{cut:?}.env"));
    std::fs::write(&envfile,format!("DB_DSN={dsn} sslmode=disable\nDB_DIRECT_DSN={owner}\nDB_WORKER_DSN={owner}\nJWT_SECRET={secret}\nJWT_ISSUER=mailserver\nJWT_SIGNING_ALG=HS256\nAUTHSERVER_URL=http://{addr}\nLISTEN_ADDR={addr}\nTHREAT_FEED_ENABLED=false\nGEO_BLOCK_ENABLED=false\nSPRAY_DETECT_ENABLED=false\nCAPTCHA_ENABLED=false\nTARPIT_ENABLED=false\nGOCOVERDIR=/src/server-rust/target/gofree-idlogin2-tools/cover\n")).unwrap();
    let name = format!("gofree-idlogin2-fault-{cut:?}-{}", std::process::id()).to_lowercase();
    let mount = format!("{}:/src", root.display());
    let result = std::process::Command::new("docker")
        .args([
            "run",
            "-d",
            "--name",
            &name,
            "--label",
            "org.setjoin.task=gofree-idlogin2",
            "--network",
            "host",
            "--env-file",
            envfile.to_str().unwrap(),
            "-v",
            &mount,
            "-w",
            "/src",
            "setjoin-ci-linux-tc:local-amd64",
            "/src/server-rust/target/gofree-idlogin2-tools/authserver",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let process = Go(name);
    let client: hyper_util::client::legacy::Client<_, setjoin_auth::Body> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        loop {
            if client
                .request(
                    Request::get(format!("http://{addr}/health"))
                        .body(body(""))
                        .unwrap(),
                )
                .await
                .is_ok()
            {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|e| {
        let logs = std::process::Command::new("docker")
            .args(["logs", &process.0])
            .output()
            .unwrap();
        let path = tools.join(format!("go-fault-{cut:?}.log"));
        let mut bytes = logs.stdout;
        bytes.extend(logs.stderr);
        std::fs::write(&path, bytes).unwrap();
        panic!("Go startup timeout {e}; see {}", path.display());
    });
    (process, addr)
}

#[tokio::test]
async fn session_tokens_interchange_across_the_process_swap() {
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/identity-login/security/session-swap.json");
    if std::env::var_os("GOFREE_RECORD_REFRESH_FAULTS").is_some() {
        let db = Db::for_case("IDLOGIN2-swap").unwrap();
        let c = db.connect().await.unwrap();
        c.query_one(
            "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
            &[],
        )
        .await
        .unwrap();
        common::signing_key(&c).await;
        let a = fixture::account(&c, "idlogin2-swap").await.unwrap();
        let email: String = c
            .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
            .await
            .unwrap()
            .get(0);
        c.execute(
            "UPDATE users SET password_hash=$1,mfa_exempt=true WHERE id=$2",
            &[&bcrypt::hash("Password1!", 4).unwrap(), &a.user],
        )
        .await
        .unwrap();
        let flags:String=c.query_one("SELECT coalesce(jsonb_agg(to_jsonb(t)),'[]')::text FROM feature_toggles t WHERE key='feature.rate_limit'",&[]).await.unwrap().get(0);
        c.batch_execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false").await.unwrap();
        let receipts = common::receipt_ids(&c).await;
        let native = AuthServer::load(
            setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).unwrap(),
            Config::for_secret(f["secret"].as_str().unwrap().into()),
        )
        .await
        .unwrap();
        let r = native
            .handle(
                Request::post("/auth/login")
                    .body(body(
                        json!({"email":email,"password":"Password1!"}).to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(r.status(), 200);
        let issued: Value =
            serde_json::from_slice(&r.into_body().collect().await.unwrap().to_bytes()).unwrap();
        let (dsn, task, _active) =
            wire::armable(db.app.as_deref().unwrap_or(&db.dsn), wire::Cut::After, 1).await;
        let _wire = Wire(task);
        let (go, addr) = go_server(
            &dsn,
            &db.dsn,
            f["secret"].as_str().unwrap(),
            wire::Cut::After,
        )
        .await;
        let client: hyper_util::client::legacy::Client<_, setjoin_auth::Body> =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build_http();
        let r = client
            .request(
                Request::post(format!("http://{addr}/auth/refresh"))
                    .body(body(
                        json!({"refresh_token":issued["refresh_token"]}).to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        let go_refresh_status = r.status().as_u16();
        assert_eq!(go_refresh_status, 200);
        let tokens: Value =
            serde_json::from_slice(&r.into_body().collect().await.unwrap().to_bytes()).unwrap();
        let r = native
            .handle(
                Request::post("/auth/refresh")
                    .body(body(
                        json!({"refresh_token":tokens["refresh_token"]}).to_string(),
                    ))
                    .unwrap(),
            )
            .await;
        assert_eq!(r.status(), 200);
        let swapped: Value =
            serde_json::from_slice(&r.into_body().collect().await.unwrap().to_bytes()).unwrap();
        let r = client
            .request(
                Request::get(format!("http://{addr}/auth/session/token"))
                    .header(
                        "authorization",
                        format!("Bearer {}", swapped["access_token"].as_str().unwrap()),
                    )
                    .body(body(""))
                    .unwrap(),
            )
            .await
            .unwrap();
        let go_access_status = r.status().as_u16();
        assert_eq!(go_access_status, 200);
        let returned: Value =
            serde_json::from_slice(&r.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(returned["access_token"], swapped["access_token"]);
        let r = native
            .handle(
                Request::get("/auth/session/token")
                    .header(
                        "authorization",
                        format!("Bearer {}", tokens["access_token"].as_str().unwrap()),
                    )
                    .body(body(""))
                    .unwrap(),
            )
            .await;
        assert_eq!(r.status(), 200);
        let returned: Value =
            serde_json::from_slice(&r.into_body().collect().await.unwrap().to_bytes()).unwrap();
        assert_eq!(returned["access_token"], tokens["access_token"]);
        drop(native);
        drop(go);
        common::restore_receipts(&c, &receipts).await;
        let value = json!({"format":1,"go_source":f["go_source"],"clock":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),"tokens":tokens,"go_refresh_status":go_refresh_status,"go_access_status":go_access_status});
        c.execute("DELETE FROM auth_event_log WHERE user_id=$1", &[&a.user])
            .await
            .unwrap();
        c.execute("DELETE FROM login_events WHERE user_id=$1", &[&a.user])
            .await
            .unwrap();
        fixture::remove(&c, &a).await.unwrap();
        c.batch_execute("DELETE FROM feature_toggles WHERE key='feature.rate_limit'")
            .await
            .unwrap();
        c.execute("INSERT INTO feature_toggles SELECT * FROM jsonb_populate_recordset(NULL::feature_toggles,$1::text::jsonb)",&[&flags]).await.unwrap();
        assert!(!path.exists(), "immutable swap recording exists");
        setjoin_conformance::golden::record(&path, &value).unwrap();
    }
    let recorded: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let legacy = setjoin_authz::legacy_jwt::LegacyKeys::new(
        f["secret"].as_str().unwrap().as_bytes(),
        &["authserver-hmac-1"],
        None,
    )
    .unwrap();
    let mut family = None;
    for field in ["access_token", "refresh_token"] {
        let claims = legacy
            .validate(
                recorded["tokens"][field].as_str().unwrap(),
                "mailserver",
                "mailserver-gateway",
                recorded["clock"].as_f64().unwrap(),
            )
            .expect("frozen Go token must verify in Rust");
        assert_eq!(
            claims["typ"],
            if field == "access_token" {
                "access"
            } else {
                "refresh"
            }
        );
        if let Some(family) = &family {
            assert_eq!(&claims["fam"], family);
        }
        family = Some(claims["fam"].clone());
    }
    assert_eq!(recorded["go_refresh_status"], 200);
    assert_eq!(recorded["go_access_status"], 200);
}

// Credential publish is a separate transaction shape from token rotation. The
// reset proof is deliberately consumed before the intercepted publish COMMIT.
async fn credential_commit(cut: wire::Cut, reset: bool) {
    let db = Db::for_case("IDLOGIN2-credential-commit").unwrap();
    let c = db.connect().await.unwrap();
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await
    .unwrap();
    common::signing_key(&c).await;
    let receipts = common::receipt_ids(&c).await;
    let a = fixture::account(&c, "idlogin2-credential-commit")
        .await
        .unwrap();
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await
        .unwrap()
        .get(0);
    let old = bcrypt::hash("Password1!", 4).unwrap();
    c.execute(
        "UPDATE users SET password_hash=$1,mfa_exempt=true WHERE id=$2",
        &[&old, &a.user],
    )
    .await
    .unwrap();
    let flags:String=c.query_one("SELECT coalesce(jsonb_agg(to_jsonb(t)),'[]')::text FROM feature_toggles t WHERE key='feature.rate_limit'",&[]).await.unwrap().get(0);
    c.batch_execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false").await.unwrap();
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let cfg = || Config::for_secret(f["secret"].as_str().unwrap().into());
    let server = AuthServer::load(
        setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4).unwrap(),
        cfg(),
    )
    .await
    .unwrap();
    let r = server
        .handle(
            Request::post("/auth/login")
                .body(body(
                    json!({"email":email,"password":"Password1!"}).to_string(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(r.status(), 200);
    let login: Value =
        serde_json::from_slice(&r.into_body().collect().await.unwrap().to_bytes()).unwrap();
    drop(server);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let proof=setjoin_authz::legacy_jwt::sign_hs256(f["secret"].as_str().unwrap().as_bytes(),&json!({"uid":a.user,"email":email,"typ":"password_reset","jti":uuid::Uuid::new_v4().to_string(),"iss":"mailserver","sub":a.user.to_string(),"aud":["mailserver-gateway"],"iat":now,"nbf":now,"exp":now+300}).to_string());
    use sha2::{Digest, Sha256};
    let proof_hash = Sha256::digest(proof.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let record = std::env::var_os("GOFREE_RECORD_REFRESH_FAULTS").is_some();
    let (dsn, task, active) = wire::armable(
        db.app.as_deref().unwrap_or(&db.dsn),
        cut,
        if reset && !record { 2 } else { 1 },
    )
    .await;
    let mut wire = Wire(task);
    let path = if reset {
        "/auth/forgot-password/reset"
    } else {
        "/auth/password"
    };
    let method = if reset { "POST" } else { "PUT" };
    let input = if reset {
        json!({"email":email,"reset_token":proof,"new_password":"NewPassword2!"})
    } else {
        json!({"old_password":"Password1!","new_password":"NewPassword2!"})
    };
    let mut go = None;
    let mut native = None;
    let r = if record {
        let (process, addr) = go_server(&dsn, &db.dsn, f["secret"].as_str().unwrap(), cut).await;
        go = Some(process);
        active.store(true, std::sync::atomic::Ordering::SeqCst);
        let client: hyper_util::client::legacy::Client<_, setjoin_auth::Body> =
            hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
                .build_http();
        client
            .request(
                Request::builder()
                    .method(method)
                    .uri(format!("http://{addr}{path}"))
                    .header(
                        "authorization",
                        format!("Bearer {}", login["access_token"].as_str().unwrap()),
                    )
                    .body(body(input.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
            .map(|b| b.map_err(std::io::Error::other).boxed())
    } else {
        let server = AuthServer::load(
            setjoin_pg::ScopedExecutor::from_dsn(&dsn, 4).unwrap(),
            cfg(),
        )
        .await
        .unwrap();
        active.store(true, std::sync::atomic::Ordering::SeqCst);
        let r = server
            .handle(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header(
                        "authorization",
                        format!("Bearer {}", login["access_token"].as_str().unwrap()),
                    )
                    .body(body(input.to_string()))
                    .unwrap(),
            )
            .await;
        native = Some(server);
        r
    };
    let status = r.status().as_u16();
    let operation = r.headers().get("x-operation-id").cloned();
    let cookie = r.headers().contains_key("set-cookie");
    let bytes = r.into_body().collect().await.unwrap().to_bytes();
    let raw = std::str::from_utf8(&bytes).unwrap();
    drop(go);
    drop(native);
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(10), &mut wire.0)
            .await
            .unwrap()
            .unwrap()
            .unwrap(),
        cut
    );
    let stored: String = c
        .query_one("SELECT password_hash FROM users WHERE id=$1", &[&a.user])
        .await
        .unwrap()
        .get(0);
    let revoked: i64 = c
        .query_one(
            "SELECT count(*) FROM oauth_tokens WHERE user_id=$1 AND revoked_at IS NOT NULL",
            &[&a.user],
        )
        .await
        .unwrap()
        .get(0);
    let audit:i64=c.query_one("SELECT count(*) FROM admin_audit_log WHERE target_type='user' AND target_id=$1 AND action='revoke_user_sessions'",&[&a.user]).await.unwrap().get(0);
    let consumed: bool = c
        .query_one(
            "SELECT EXISTS(SELECT 1 FROM used_password_reset_tokens WHERE token_hash=$1)",
            &[&proof_hash],
        )
        .await
        .unwrap()
        .get(0);
    let changed = stored != old;
    assert_eq!(changed, cut == wire::Cut::After);
    assert_eq!(revoked, if changed { 1 } else { 0 });
    assert_eq!(audit, revoked);
    assert_eq!(consumed, reset);
    if changed {
        assert!(setjoin_authz::password::verify(&stored, "NewPassword2!"));
    }
    if let Some(header) = &operation {
        let op = header.to_str().unwrap();
        let committed:bool=c.query_one("SELECT EXISTS(SELECT 1 FROM rust_operation_receipts WHERE operation_id=$1::text::uuid)",&[&op]).await.unwrap().get(0);
        assert_eq!(committed, changed);
    }
    let case = format!(
        "{}-commit-{}",
        if reset { "reset" } else { "password" },
        if cut == wire::Cut::Before {
            "before"
        } else {
            "after"
        }
    );
    let value = json!({"format":1,"go_source":f["go_source"],"route":format!("{method} {path}"),"case":case,"observation":{"status":status,"body":raw,"cookie":cookie,"changed":changed,"revoked":revoked,"audit":audit,"consumed":consumed}});
    common::restore_receipts(&c, &receipts).await;
    c.execute(
        "DELETE FROM used_password_reset_tokens WHERE token_hash=$1",
        &[&proof_hash],
    )
    .await
    .unwrap();
    c.batch_execute("SET session_replication_role=replica")
        .await
        .unwrap();
    c.execute(
        "DELETE FROM admin_audit_log WHERE target_type='user' AND target_id=$1",
        &[&a.user],
    )
    .await
    .unwrap();
    c.batch_execute("SET session_replication_role=origin")
        .await
        .unwrap();
    c.execute("DELETE FROM auth_event_log WHERE user_id=$1", &[&a.user])
        .await
        .unwrap();
    c.execute("DELETE FROM login_events WHERE user_id=$1", &[&a.user])
        .await
        .unwrap();
    fixture::remove(&c, &a).await.unwrap();
    c.batch_execute("DELETE FROM feature_toggles WHERE key='feature.rate_limit'")
        .await
        .unwrap();
    c.execute("INSERT INTO feature_toggles SELECT * FROM jsonb_populate_recordset(NULL::feature_toggles,$1::text::jsonb)",&[&flags]).await.unwrap();
    let target = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/identity-login/security")
        .join(format!("{case}.json"));
    if record && !target.exists() {
        setjoin_conformance::golden::record(&target, &value).unwrap();
    } else {
        let expected: Value = serde_json::from_slice(&std::fs::read(target).unwrap()).unwrap();
        setjoin_conformance::golden::compare(&expected, &value).unwrap();
    }
    assert_eq!(status, 500);
    assert!(!cookie);
    if !record {
        assert!(operation.is_some());
    }
}
#[tokio::test]
async fn password_publish_commit_before() {
    credential_commit(wire::Cut::Before, false).await;
}
#[tokio::test]
async fn password_publish_commit_after() {
    credential_commit(wire::Cut::After, false).await;
}
#[tokio::test]
async fn reset_publish_commit_before() {
    credential_commit(wire::Cut::Before, true).await;
}
#[tokio::test]
async fn reset_publish_commit_after() {
    credential_commit(wire::Cut::After, true).await;
}
