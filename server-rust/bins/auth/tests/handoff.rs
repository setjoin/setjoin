//! Whole-request handoff only to explicitly unported owners: #420 threat,
//! #405 policy, #420 refresh interception. No completed-shape switch.
mod common;
use http_body_util::BodyExt;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_auth::{body, AuthServer, Config};
use setjoin_conformance::{fixture, harness::Db};
use tokio::{net::TcpListener, sync::mpsc};
#[derive(Clone, Copy)]
enum Mode {
    Threat,
    Device,
    Dpop,
    Policy,
    ThreatRefresh,
    ThreatReset,
}
type Error = Box<dyn std::error::Error + Send + Sync>;
async fn check(mode: Mode) -> Result<(), Error> {
    let db = Db::for_case("IDLOGIN1-handoff").unwrap();
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let flags:String=c.query_one("SELECT coalesce(jsonb_agg(to_jsonb(t)),'[]')::text FROM feature_toggles t WHERE key IN ('feature.rate_limit','feature.conditional_access','feature.token_binding')",&[]).await?.get(0);
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false),('feature.conditional_access',false),('feature.token_binding',false) ON CONFLICT(key) DO UPDATE SET enabled=EXCLUDED.enabled",&[]).await?;
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
    if matches!(mode, Mode::Policy) {
        c.execute(
            "UPDATE feature_toggles SET enabled=true WHERE key='feature.conditional_access'",
            &[],
        )
        .await?;
    }
    if matches!(mode, Mode::Dpop) {
        c.execute(
            "UPDATE feature_toggles SET enabled=true WHERE key='feature.token_binding'",
            &[],
        )
        .await?;
    }
    let (listener_addr, mut seen, spy) = spy().await?;
    let result=async{
  let f:Value=serde_json::from_str(include_str!("../../../tests/conformance/identity-login/keys.json"))?;
  let mut cfg=Config::for_secret(f["secret"].as_str().unwrap().into());cfg.go_upstream=Some(format!("http://{listener_addr}"));
  if matches!(mode,Mode::Threat|Mode::ThreatRefresh|Mode::ThreatReset){cfg.threat_controls[0]=true;}
  let exec=setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),2).map_err(|e|e.0)?;
  let server=AuthServer::load(exec,cfg).await?;
  let raw=if matches!(mode,Mode::Dpop){format!(r#"{{"email":{},"password":"Password1!","dpop_jwk":{},"dpop_jwk":{{}}}}"#,serde_json::to_string(&email)?,f["jwks"]["keys"][0])}else if matches!(mode,Mode::Threat|Mode::Policy|Mode::Device){"{deliberately-not-decoded".to_owned()}else{json!({"email":email,"password":"Password1!","ignored":"\\ud800"}).to_string()+" {}"};
  let path=if matches!(mode,Mode::ThreatReset){"/auth/forgot-password/reset?next=%2F"}else if matches!(mode,Mode::ThreatRefresh){"/auth/refresh?next=%2F"}else{"/auth/login?next=%2F"};
  let mut request=Request::post(path).header("host","auth.idlogin1.test");
  if matches!(mode,Mode::Device){request=request.header("x-device-hmac","unported-proof");}
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
async fn threat_owner_420_receives_the_original_undecoded_request() {
    check(Mode::Threat).await.unwrap();
}
#[tokio::test]
async fn policy_owner_405_receives_the_original_undecoded_request() {
    check(Mode::Policy).await.unwrap();
}
#[tokio::test]
async fn threat_refresh_owner_420_receives_the_original_request() {
    check(Mode::ThreatRefresh).await.unwrap();
}

#[tokio::test]
async fn device_proof_owner_420_receives_the_original_undecoded_request() {
    check(Mode::Device).await.unwrap();
}

#[tokio::test]
async fn duplicate_dpop_map_stays_with_policy_owner_405() {
    check(Mode::Dpop).await.unwrap();
}

#[tokio::test]
async fn reset_threat_whole_request_belongs_to_420() {
    check(Mode::ThreatReset).await.unwrap();
}
