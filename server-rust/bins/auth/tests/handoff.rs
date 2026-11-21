//! Whole-request handoff only to explicitly unported owners: CA policy (#351).
//! Threat admission (#349), device proof (#350), and DPoP (#352) are native.
mod common;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use http_body_util::BodyExt;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_auth::{body, AuthServer, Config};
use setjoin_conformance::{fixture, harness::Db};
use sha2::{Digest, Sha256};
use tokio::{net::TcpListener, sync::mpsc};
type Error = Box<dyn std::error::Error + Send + Sync>;
async fn check_policy() -> Result<(), Error> {
    let db = Db::for_case("IDLOGIN1-handoff").unwrap();
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let flags:String=c.query_one("SELECT coalesce(jsonb_agg(to_jsonb(t)),'[]')::text FROM feature_toggles t WHERE key IN ('feature.rate_limit','feature.conditional_access','feature.token_binding')",&[]).await?.get(0);
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false),('feature.conditional_access',true),('feature.token_binding',false) ON CONFLICT(key) DO UPDATE SET enabled=EXCLUDED.enabled",&[]).await?;
    let a = fixture::account(&c, "idlogin1-handoff").await?;
    c.execute(
        "UPDATE users SET password_hash=$1,mfa_exempt=true,totp_enabled=false,push_mfa_enabled=$2 WHERE id=$3",
        &[
            &bcrypt::hash("Password1!", 4)?,
            &false,
            &a.user,
        ],
    )
    .await?;
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await?
        .get(0);
    let (listener_addr, mut seen, spy) = spy().await?;
    let result=async{
  let f:Value=serde_json::from_str(include_str!("../../../tests/conformance/identity-login/keys.json"))?;
  let mut cfg=Config::for_secret(f["secret"].as_str().unwrap().into());cfg.go_upstream=Some(format!("http://{listener_addr}"));
  let exec=setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),2).map_err(|e|e.0)?;
  let server=AuthServer::load(exec,cfg).await?.with_threat_gate(&db.dsn).await?;
  let raw="{deliberately-not-decoded".to_owned();
  let path="/auth/login?next=%2F";
  let request=Request::post(path).header("host","auth.idlogin1.test");
  let response=server.handle(request.body(body(raw.clone()))?).await;
  let status=response.status().as_u16();let returned=response.into_body().collect().await?.to_bytes();
  let event=tokio::time::timeout(std::time::Duration::from_secs(10),seen.recv()).await?.ok_or("no handoff request")?;
  let rows:i64=c.query_one("SELECT (SELECT count(*) FROM oauth_tokens WHERE user_id=$1)+(SELECT count(*) FROM sessions WHERE user_id=$1)+(SELECT count(*) FROM login_events WHERE user_id=$1)+(SELECT count(*) FROM auth_event_log WHERE email=$2)",&[&a.user,&email]).await?.get(0);
  drop(server);
  Ok::<_,Error>((raw,path,status,returned,event,rows))
 }.await;
    spy.abort();
    let _ = spy.await;
    c.execute("DELETE FROM auth_event_log WHERE email=$1", &[&email])
        .await?;
    c.execute("DELETE FROM login_events WHERE user_id=$1", &[&a.user])
        .await?;
    fixture::remove(&c, &a).await?;
    c.execute("DELETE FROM feature_toggles WHERE key IN ('feature.rate_limit','feature.conditional_access','feature.token_binding')",&[]).await?;
    c.execute("INSERT INTO feature_toggles SELECT * FROM jsonb_populate_recordset(NULL::feature_toggles,$1::text::jsonb)",&[&flags]).await?;
    let (raw, path, status, returned, event, rows) = result?;
    assert_eq!(
        event,
        ("POST".to_owned(), path.to_owned(), raw.into_bytes())
    );
    assert_eq!(
        rows, 0,
        "an unported dependency must be selected before effects"
    );
    assert_eq!(status, 403);
    assert_eq!(
        &returned[..],
        include_bytes!("../../gateway/tests/golden/go-threat-blocked.json")
    );
    Ok(())
}
async fn spy() -> Result<
    (
        std::net::SocketAddr,
        mpsc::Receiver<(String, String, Vec<u8>)>,
        tokio::task::JoinHandle<()>,
    ),
    Error,
> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let (tx, rx) = mpsc::channel(1);
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
                            let method = r.method().to_string();
                            let path = r.uri().to_string();
                            let b = r.into_body().collect().await.unwrap().to_bytes().to_vec();
                            let _ = tx.send((method, path, b)).await;
                            Ok::<_, std::convert::Infallible>(
                                Response::builder()
                                    .status(403)
                                    .header("content-type", "application/json")
                                    .body(body(
                                        include_bytes!(
                                            "../../gateway/tests/golden/go-threat-blocked.json"
                                        )
                                        .as_slice(),
                                    ))
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
#[tokio::test]
async fn policy_owner_405_receives_the_original_undecoded_request() {
    check_policy().await.unwrap();
}
#[tokio::test]
async fn device_proof_login_resolves_natively_without_forwarding() {
    let db = Db::for_case("IDLOGIN1-handoff-device").unwrap();
    let c = db.connect().await.unwrap();
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await
    .unwrap();
    common::signing_key(&c).await;
    let flags: String = c
        .query_one(
            "SELECT coalesce(jsonb_agg(to_jsonb(t)),'[]')::text FROM feature_toggles t WHERE key IN ('feature.rate_limit','feature.conditional_access','feature.device_trust_enforcement','feature.token_binding')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    c.execute(
        "INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false),('feature.conditional_access',false),('feature.device_trust_enforcement',false),('feature.token_binding',false) ON CONFLICT(key) DO UPDATE SET enabled=EXCLUDED.enabled",
        &[],
    )
    .await
    .unwrap();
    let a = fixture::account(&c, "idlogin1-handoff-device")
        .await
        .unwrap();
    c.execute(
        "UPDATE users SET password_hash=$1,mfa_exempt=true,totp_enabled=false,push_mfa_enabled=false WHERE id=$2",
        &[&bcrypt::hash("Password1!", 4).unwrap(), &a.user],
    )
    .await
    .unwrap();
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await
        .unwrap()
        .get(0);
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let device_secret = "handoff-device-secret-350";
    let sealed = setjoin_config_secret::seal_column(
        device_secret.as_bytes(),
        f["secret"].as_str().unwrap().as_bytes(),
        setjoin_config_secret::CryptoProfile::Standard,
    )
    .unwrap();
    let device_id: i64 = c
        .query_one(
            "INSERT INTO devices(user_id,fingerprint,hmac_secret_enc,hmac_secret_key_id,enroll_state) VALUES($1,'handoff-device-350',$2,'v1','approved') RETURNING id",
            &[&a.user, &sealed],
        )
        .await
        .unwrap()
        .get(0);
    let (listener_addr, mut seen, spy) = spy().await.unwrap();
    let result: Result<(), Error> = async {
        let mut cfg = Config::for_secret(f["secret"].as_str().unwrap().into());
        cfg.go_upstream = Some(format!("http://{listener_addr}"));
        let exec = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2)
            .map_err(|e| e.0)?;
        let server = AuthServer::load(exec, cfg)
            .await?
            .with_threat_gate(&db.dsn)
            .await?;
        let path = "/auth/login?next=%2F";
        let raw = json!({"email": email, "password": "Password1!"}).to_string();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs()
            .to_string();
        let nonce = format!("handoff-nonce-{}", uuid::Uuid::new_v4());
        let hash = format!("{:x}", Sha256::digest(raw.as_bytes()));
        let challenge = format!("{device_id}:{ts}:POST:{path}:{hash}:{nonce}");
        let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, device_secret.as_bytes());
        let mac: String = ring::hmac::sign(&key, challenge.as_bytes())
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        let response = server
            .handle(
                Request::post(path)
                    .header("host", "auth.idlogin1.test")
                    .header("x-device-id", device_id.to_string())
                    .header("x-device-timestamp", ts)
                    .header("x-device-nonce", nonce.as_str())
                    .header("x-device-body-sha256", hash)
                    .header("x-device-hmac", mac)
                    .body(body(raw))?,
            )
            .await;
        let status = response.status().as_u16();
        let returned = response.into_body().collect().await?.to_bytes();
        let claimed: i64 = c
            .query_one(
                "SELECT count(*) FROM device_auth_nonces WHERE device_id=$1 AND nonce=$2",
                &[&device_id, &nonce],
            )
            .await?
            .get(0);
        drop(server);
        assert!(seen.try_recv().is_err(), "device proof must not forward");
        assert_eq!(status, 200, "body={}", String::from_utf8_lossy(&returned));
        assert_eq!(claimed, 1, "device proof nonce must be consumed natively");
        Ok(())
    }
    .await;
    spy.abort();
    let _ = spy.await;
    let _ = c
        .execute(
            "DELETE FROM device_auth_nonces WHERE device_id=$1",
            &[&device_id],
        )
        .await;
    let _ = c
        .execute("DELETE FROM devices WHERE id=$1", &[&device_id])
        .await;
    let _ = c
        .execute("DELETE FROM sessions WHERE user_id=$1", &[&a.user])
        .await;
    let _ = c
        .execute("DELETE FROM auth_event_log WHERE email=$1", &[&email])
        .await;
    let _ = c
        .execute("DELETE FROM login_events WHERE user_id=$1", &[&a.user])
        .await;
    let _ = fixture::remove(&c, &a).await;
    c.execute(
        "DELETE FROM feature_toggles WHERE key IN ('feature.rate_limit','feature.conditional_access','feature.device_trust_enforcement','feature.token_binding')",
        &[],
    )
    .await
    .unwrap();
    c.execute(
        "INSERT INTO feature_toggles SELECT * FROM jsonb_populate_recordset(NULL::feature_toggles,$1::text::jsonb)",
        &[&flags],
    )
    .await
    .unwrap();
    result.unwrap();
}

fn jwt_cnf_jkt(token: &str) -> Option<String> {
    let payload = token.split('.').nth(1)?;
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    v["cnf"]["jkt"].as_str().map(str::to_owned)
}

#[tokio::test]
async fn duplicate_dpop_map_binds_natively_without_forwarding() {
    let db = Db::for_case("IDLOGIN1-handoff-dpop").unwrap();
    let c = db.connect().await.unwrap();
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await
    .unwrap();
    common::signing_key(&c).await;
    let flags: String = c
        .query_one(
            "SELECT coalesce(jsonb_agg(to_jsonb(t)),'[]')::text FROM feature_toggles t WHERE key IN ('feature.rate_limit','feature.conditional_access','feature.token_binding')",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    c.execute(
        "INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false),('feature.conditional_access',false),('feature.token_binding',true) ON CONFLICT(key) DO UPDATE SET enabled=EXCLUDED.enabled",
        &[],
    )
    .await
    .unwrap();
    let a = fixture::account(&c, "idlogin1-handoff-dpop").await.unwrap();
    c.execute(
        "UPDATE users SET password_hash=$1,mfa_exempt=true,totp_enabled=false,push_mfa_enabled=false WHERE id=$2",
        &[&bcrypt::hash("Password1!", 4).unwrap(), &a.user],
    )
    .await
    .unwrap();
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await
        .unwrap()
        .get(0);
    let (listener_addr, mut seen, spy) = spy().await.unwrap();
    let result: Result<(), Error> = async {
        let f: Value = serde_json::from_str(include_str!(
            "../../../tests/conformance/identity-login/keys.json"
        ))?;
        let mut cfg = Config::for_secret(f["secret"].as_str().unwrap().into());
        cfg.go_upstream = Some(format!("http://{listener_addr}"));
        let exec = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2)
            .map_err(|e| e.0)?;
        let server = AuthServer::load(exec, cfg)
            .await?
            .with_threat_gate(&db.dsn)
            .await?;
        let jwk = &f["jwks"]["keys"][0];
        let expected_jkt = setjoin_authz::dpop::thumbprint(jwk).unwrap();
        let raw = format!(
            r#"{{"email":{},"password":"Password1!","dpop_jwk":{},"dpop_jwk":{{}}}}"#,
            serde_json::to_string(&email)?,
            jwk
        );
        let response = server
            .handle(
                Request::post("/auth/login?next=%2F")
                    .header("host", "auth.idlogin1.test")
                    .body(body(raw))?,
            )
            .await;
        let status = response.status().as_u16();
        let returned = response.into_body().collect().await?.to_bytes();
        drop(server);
        assert!(seen.try_recv().is_err(), "DPoP issuance must not forward");
        assert_eq!(status, 200, "body={}", String::from_utf8_lossy(&returned));
        let json: Value = serde_json::from_slice(&returned)?;
        let access = json["access_token"].as_str().ok_or("missing access_token")?;
        let refresh = json["refresh_token"].as_str().ok_or("missing refresh_token")?;
        assert_eq!(jwt_cnf_jkt(access).as_deref(), Some(expected_jkt.as_str()));
        assert_eq!(jwt_cnf_jkt(refresh).as_deref(), Some(expected_jkt.as_str()));
        Ok(())
    }
    .await;
    spy.abort();
    let _ = spy.await;
    let _ = c
        .execute("DELETE FROM sessions WHERE user_id=$1", &[&a.user])
        .await;
    let _ = c
        .execute("DELETE FROM auth_event_log WHERE email=$1", &[&email])
        .await;
    let _ = c
        .execute("DELETE FROM login_events WHERE user_id=$1", &[&a.user])
        .await;
    let _ = fixture::remove(&c, &a).await;
    c.execute(
        "DELETE FROM feature_toggles WHERE key IN ('feature.rate_limit','feature.conditional_access','feature.token_binding')",
        &[],
    )
    .await
    .unwrap();
    c.execute(
        "INSERT INTO feature_toggles SELECT * FROM jsonb_populate_recordset(NULL::feature_toggles,$1::text::jsonb)",
        &[&flags],
    )
    .await
    .unwrap();
    result.unwrap();
}

