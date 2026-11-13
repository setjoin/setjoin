//! #417: real public HTTP health with fake LiveKit, Egress and ASR services.
mod common;
use common::BoxError;
use http_body_util::BodyExt;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_none_http_matches_frozen_go() -> Result<(), BoxError> {
    run("none").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_sfu_http_matches_frozen_go() -> Result<(), BoxError> {
    run("sfu").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_egress_http_matches_frozen_go() -> Result<(), BoxError> {
    run("egress").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn health_asr_http_matches_frozen_go() -> Result<(), BoxError> {
    run("asr").await
}

async fn run(failed: &'static str) -> Result<(), BoxError> {
    let Some(db) = Db::for_case("static2-health") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let config: String = owner
        .query_one(
            "SELECT coalesce(jsonb_agg(to_jsonb(s)),'[]'::jsonb)::text FROM system_config s",
            &[],
        )
        .await?
        .get(0);
    let rows: String = owner
        .query_one(
            "SELECT coalesce(jsonb_agg(to_jsonb(s)),'[]'::jsonb)::text FROM health_history s",
            &[],
        )
        .await?
        .get(0);
    let actor = fixture::account(&owner, "static2-health").await?;
    owner.batch_execute("DELETE FROM health_history; INSERT INTO health_history(check_name,status,details) VALUES('static2_base','ok','oracle')").await?;
    let record = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
    let result = observe(&db, failed, record).await;
    if record {
        owner
            .batch_execute("BEGIN; DELETE FROM system_config")
            .await?;
        owner.execute("INSERT INTO system_config SELECT r.* FROM jsonb_populate_recordset(NULL::system_config,$1::text::jsonb) r",&[&config]).await?;
        owner.batch_execute("COMMIT").await?;
    }
    owner
        .batch_execute("BEGIN; DELETE FROM health_history")
        .await?;
    owner.execute("INSERT INTO health_history SELECT r.* FROM jsonb_populate_recordset(NULL::health_history,$1::text::jsonb) r",&[&rows]).await?;
    owner.batch_execute("COMMIT").await?;
    fixture::remove(&owner, &actor).await?;
    result
}
async fn observe(db: &Db, failed: &'static str, record: bool) -> Result<(), BoxError> {
    let seen: Arc<Mutex<Vec<Value>>> = Arc::default();
    let log = seen.clone();
    let peer=common::fake_upstream(move |request| {
        let log=log.clone();
        async move {
            let path=request.uri().path().to_owned();
            let component=if path.ends_with("ListRooms") {"sfu"} else if path.ends_with("ListEgress") {"egress"} else {"asr"};
            let auth=request.headers().get("authorization").and_then(|v|v.to_str().ok()).unwrap_or("");
            let authenticated=if component=="asr" {auth=="Bearer static2-asr"} else {valid_token(auth, component)};
            let protobuf=request.headers().get("content-type").is_some_and(|v|v=="application/protobuf");
            let method=request.method().as_str().to_owned();
            let bytes=request.into_body().collect().await.unwrap().to_bytes();
            let body=if protobuf { assert!(bytes.is_empty(), "probe request must have no filters"); "{}".to_owned() } else if component=="asr" { assert!(bytes.is_empty()); "".to_owned() } else { let fields:Value=serde_json::from_slice(&bytes).unwrap(); assert_eq!(fields,json!({})); "{}".to_owned() };
            log.lock().unwrap().push(json!({"component":component,"method":method,"path":path,"authenticated":authenticated,"body":body}));
            Response::builder().status(if component==failed {503} else {200}).header("content-type",if protobuf {"application/protobuf"} else {"application/json"}).body(common::full(if protobuf && component!=failed {""} else if component=="asr" {r#"{"rooms":[]}"#} else {"{}"})).unwrap()
        }
    }).await;
    let s3=common::fake_upstream(|_|async { Response::builder().header("content-type","application/xml").body(common::full("<ListMultipartUploadsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Bucket>mailblobs</Bucket><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>")).unwrap() }).await;
    let oracle = if record {
        std::env::set_var("GOFREE_ORACLE_EXTRA_ENV",format!("LIVEKIT_URL=http://{peer}\nLIVEKIT_API_KEY=static2-key\nLIVEKIT_API_SECRET=static2-secret\nMEET_EGRESS_ENABLED=true\nASR_URL=http://{peer}\nASR_TOKEN=static2-asr"));
        let result = common::go_oracle::start_named(db, s3, None, "gofree-static2-health").await;
        std::env::remove_var("GOFREE_ORACLE_EXTRA_ENV");
        result?
    } else {
        None
    };
    let table = if record {
        RouteTable::proxy_all()
    } else {
        let livekit = setjoin_gateway::meet_livekit::LiveKit::new(
            "static2-key",
            "static2-secret",
            &format!("http://{peer}"),
            true,
            true,
        )
        .with_asr(&format!("http://{peer}"), "static2-asr");
        let probes: setjoin_static::health::Probes = Arc::new(move || {
            let livekit = livekit.clone();
            Box::pin(async move { setjoin_gateway::platform::any_probe_failed(&livekit).await })
        });
        RouteTable::proxy_all().with(setjoin_gateway::surface::SurfaceRoute {
            discovery: None,
            exec: common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 2)?,
            keys: Arc::new(common::recovery_keys()),
            issuer: "mailserver".into(),
            config: Arc::new(setjoin_gateway::surface::SurfaceConfig::from_env()),
            health: Arc::new(setjoin_static::health::HealthGate::new(true).with_probes(probes)),
            fallback: None,
        })
    };
    let gateway = Gateway::new(
        Config {
            upstream: oracle
                .as_ref()
                .map(|g| format!("http://{}", g.address).parse())
                .transpose()?,
            trusted_proxies: TrustedProxies::parse("")?,
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: None,
        },
        table,
    )?;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(gateway.serve(listener));
    // The boot recorder waits on /health; let that verdict expire before observation.
    if record {
        tokio::time::sleep(std::time::Duration::from_secs(6)).await;
    }
    seen.lock().unwrap().clear();
    let response = common::send(
        address,
        Request::builder().uri("/health").body(common::full(""))?,
    )
    .await;
    let status = response.status().as_u16();
    let content_type = response
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let body = String::from_utf8(common::body_bytes(response).await.to_vec())?;
    let observation = json!({"request":{"method":"GET","path":"/health"},"effects":{},"audit":[],"notify":[],"response":{"status":status,"headers":{"content-type":content_type},"body_text":body},"sidecars":seen.lock().unwrap().clone()});
    let metrics = common::send(
        address,
        Request::builder()
            .uri("/_gateway/metrics")
            .body(common::full(""))?,
    )
    .await;
    let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
    task.abort();
    let _ = task.await;
    drop(oracle);
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../tests/conformance/static2/health-http-{failed}.json"
    ));
    if record {
        assert_eq!(
            status,
            if failed == "none" { 200 } else { 503 },
            "{observation}"
        );
        golden::record(
            &path,
            &json!({"format":1,"route":"GET /health","case":failed,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}),
        )?;
    } else {
        let expected: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        golden::compare(&expected["observation"], &observation)?;
        assert!(metrics
            .lines()
            .any(|l| l == "setjoin_gateway_proxied_to_go_total 0"));
        println!("GOLDEN-REPLAY: GET /health :: {failed}");
    }
    Ok(())
}
fn valid_token(header: &str, component: &str) -> bool {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use hmac::{Hmac, Mac};
    let Some(raw) = header.strip_prefix("Bearer ") else {
        return false;
    };
    let Some((message, signature)) = raw.rsplit_once('.') else {
        return false;
    };
    let Ok(signature) = URL_SAFE_NO_PAD.decode(signature) else {
        return false;
    };
    let mut mac = Hmac::<sha2::Sha256>::new_from_slice(b"static2-secret").unwrap();
    mac.update(message.as_bytes());
    if mac.verify_slice(&signature).is_err() {
        return false;
    }
    let Some(payload) = raw
        .split('.')
        .nth(1)
        .and_then(|p| URL_SAFE_NO_PAD.decode(p).ok())
        .and_then(|p| serde_json::from_slice::<Value>(&p).ok())
    else {
        return false;
    };
    payload["iss"] == "static2-key"
        && payload["video"][if component == "sfu" {
            "roomList"
        } else {
            "roomRecord"
        }] == true
}
