//! Seed + real PUT + cleanup ticks: WORM producer/consumer handoff at S3/DB seams.
mod common;
mod drain_oracle;
use http_body_util::BodyExt;
use hyper::{Method, Request, Response};
use serde::Deserialize;
use serde_json::{Value, json};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{
    Config, Gateway, RouteTable, TrustedProxies,
    blob_cleanup::BlobCleanup,
    blobs::{BlobCommands, BlobRoute},
    recovery_worker::S3Store,
};
use setjoin_pg::{ScopedExecutor, workers::WorkerDatabase};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

const PAYLOAD: &str = "blobs3 retry payload";
const CASE: &str = "worm-retention-retry-worker";
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[derive(Default)]
struct Peer {
    objects: BTreeMap<String, bool>,
    operations: Vec<Value>,
    retention_calls: usize,
    accept_all: bool,
}
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Retention {
    mode: String,
    retain_until_date: String,
}

struct Env(Vec<(&'static str, Option<std::ffi::OsString>)>);
impl Env {
    fn worm() -> Self {
        let mut old = vec![];
        for (key, value) in [("WORM_MODE", "governance"), ("WORM_RETENTION_DAYS", "30")] {
            old.push((key, std::env::var_os(key)));
            std::env::set_var(key, value);
        }
        Self(old)
    }
}
impl Drop for Env {
    fn drop(&mut self) {
        for (k, v) in self.0.drain(..) {
            if let Some(v) = v {
                std::env::set_var(k, v)
            } else {
                std::env::remove_var(k)
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worm_put_retry_is_drained_by_blob_cleanup() -> Result<(), common::BoxError> {
    run_case(false).await
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn worm_retry_oracle_rejects_a_missing_cleanup_tick() -> Result<(), common::BoxError> {
    let error = run_case(true)
        .await
        .expect_err("missing cleanup must differ");
    assert!(error.to_string().contains("/objects"), "{error}");
    eprintln!("MUTANT-REJECTED: blob-cleanup :: missing-retention-tick");
    Ok(())
}

async fn run_case(skip_ticks: bool) -> Result<(), common::BoxError> {
    let _serial = SERIAL.lock().await;
    let _env = Env::worm();
    let Some(db) = Db::for_case("blobs3-retention") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    // The worker scans these entire queues: isolate its seed in our disposable DB.
    owner.batch_execute("DELETE FROM blob_cleanup_queue; DELETE FROM orphaned_message_blobs; DELETE FROM blobs WHERE ref_count=0").await?;
    let account = fixture::account(&owner, "blobs3-retention").await?;
    let hash = format!("{:x}", Sha256::digest(PAYLOAD.as_bytes()));
    let peer = Arc::new(Mutex::new(Peer::default()));
    let state = peer.clone();
    let expected_hash = hash.clone();
    let endpoint=common::fake_upstream(move |mut request|{
        let state=state.clone();let hash=expected_hash.clone();
        async move{
            let body=request.body_mut().collect().await.unwrap().to_bytes();
            if request.uri().query()==Some("location="){return Response::new(common::full("<LocationConstraint>us-east-1</LocationConstraint>"));}
            let signed=common::s3::observe(&request,&body).expect("independent SigV4 verification");
            let key=request.uri().path().strip_prefix("/mailblobs/").unwrap();
            let mut peer=state.lock().unwrap();
            if request.method()==Method::PUT&&request.uri().query()==Some("retention="){
                assert_eq!(key,hash);assert!(peer.objects.contains_key(key));
                let retention:Retention=quick_xml::de::from_reader(body.as_ref()).unwrap();
                let until=chrono::DateTime::parse_from_rfc3339(&retention.retain_until_date).unwrap().with_timezone(&chrono::Utc);
                let seconds=(until-chrono::Utc::now()).num_seconds();
                assert!((30*86400-300..=30*86400+300).contains(&seconds));
                peer.retention_calls+=1;
                let status=if peer.accept_all||peer.retention_calls>2{200}else{403};
                peer.operations.push(json!({"operation":"retention","key":"<hash>","mode":retention.mode,"retain_days":30,"bypass_governance":request.headers().contains_key("x-amz-bypass-governance-retention"),"signature_valid":signed["signature_valid"],"status":status}));
                if status==403{return Response::builder().status(403).header("content-type","application/xml").body(common::full("<Error><Code>AccessDenied</Code><Message>retention refused</Message></Error>")).unwrap();}
                return Response::new(common::full(""));
            }
            if request.method()==Method::PUT&&key.starts_with("tmp/upload/"){
                assert_eq!(key.len(),43);assert!(key[11..].bytes().all(|v|v.is_ascii_hexdigit()));
                assert_eq!(signed["body"]["sha256"],hash);assert_eq!(signed["body"]["length"],PAYLOAD.len());
                assert_eq!(request.headers()["content-type"],"text/plain");
                peer.objects.insert(key.to_owned(),true);
                peer.operations.push(json!({"operation":"put-temp","sha256":"<hash>","length":PAYLOAD.len(),"content_type":"text/plain","signature_valid":true}));
                return Response::builder().header("etag","\"temp-etag\"").body(common::full("")).unwrap();
            }
            if request.method()==Method::PUT&&key==hash&&request.headers().contains_key("x-amz-copy-source"){
                assert!(signed["signed_headers"].as_str().unwrap().split(';').any(|v|v=="x-amz-copy-source"));
                let source=request.headers()["x-amz-copy-source"].to_str().unwrap().trim_start_matches('/').strip_prefix("mailblobs/").unwrap();
                assert!(peer.objects.contains_key(source));
                peer.objects.insert(key.to_owned(),true);
                peer.operations.push(json!({"operation":"promote","signature_valid":true}));
                return Response::builder().header("content-type","application/xml").body(common::full("<CopyObjectResult><LastModified>2026-10-31T00:00:00Z</LastModified><ETag>\"canonical\"</ETag></CopyObjectResult>")).unwrap();
            }
            if request.method()==Method::DELETE&&key.starts_with("tmp/upload/"){
                assert!(peer.objects.remove(key).is_some());
                peer.operations.push(json!({"operation":"delete-temp","signature_valid":true}));
                return Response::builder().status(204).body(common::full("")).unwrap();
            }
            panic!("unexpected fake S3 operation {} {}",request.method(),request.uri());
        }
    }).await;
    let store = Arc::new(S3Store::new(
        &format!("http://{endpoint}"),
        "mailblobs",
        "test-access",
        "test-secret",
    )?);
    let worker = BlobCleanup::new(WorkerDatabase::new(&db.dsn)?, store.clone());
    let recording = std::env::var_os("GOFREE_RECORD_BLOBS3_RETENTION").is_some();
    let result=async{
        let audit_before: i64=owner.query_one("SELECT count(*) FROM admin_audit_log WHERE user_id=$1",&[&account.user]).await?.get(0);
        let mut notify=db.listen(&format!("tag:{}",account.mailbox)).await?;
        let put=if recording{
            let relative=format!("test-results/gofree-drainw/blobs3-put-{}.json",account.user);
            let output=drain_oracle::repo_root()?.join(&relative);
            if let Ok(ledger)=std::env::var("GOFREE_RESOURCE_LEDGER"){
                use std::io::Write;
                writeln!(std::fs::OpenOptions::new().append(true).open(ledger)?,"Planned WORM PUT recording {} (temporary, assigned fixture actor)",output.display())?;
            }
            drain_oracle::GoTick{package:"internal/blob",overlay:"blobs3_retention_tick_test.go.txt",test:"TestGoFreeBlobs3RetentionTicks",file:"gofree_blobs3_retention_tick_test.go",env:vec![
                ("GOFREE_DRAIN_DSN".into(),db.dsn.clone()),("GOFREE_DRAIN_S3".into(),endpoint.to_string()),("GOFREE_DRAIN_USER".into(),account.user.to_string()),("GOFREE_DRAIN_OUTPUT".into(),format!("/src/{relative}")),
            ],docker:vec![]}.run()?;
            let put:Value=serde_json::from_slice(&std::fs::read(&output)?)?;std::fs::remove_file(output)?;put
        }else{
            let route=BlobRoute(Arc::new(BlobCommands{exec:ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?,worker_exec:ScopedExecutor::from_dsn(&db.dsn,4).map_err(|e|e.0)?,keys:common::recovery_keys(),issuer:"mailserver".into(),store:store.clone()}));
            let gateway=Gateway::new(Config{upstream:None,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},RouteTable::proxy_all().with(route))?.with_inventory(include_str!("../route-inventory.json"))?;
            let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;let task=tokio::spawn(gateway.serve(listener));
            let response=common::send(address,Request::put(format!("/api/blobs/{hash}")).header("host","mail.test").header("origin","http://mail.test").header("content-type","text/plain").header("authorization",format!("Bearer {}",common::recovery_token(account.user))).body(common::full(PAYLOAD))?).await;
            let status=response.status().as_u16();let body=String::from_utf8(common::body_bytes(response).await.to_vec())?;
            let metrics=common::send(address,Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics=String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            task.abort();let _=task.await;
            if !metrics.lines().any(|v|v=="setjoin_gateway_proxied_to_go_total 0"){return Err(format!("WORM PUT forwarded: {metrics}").into());}
            if !skip_ticks{for _ in 0..4{worker.tick().await;}}
            json!({"status":status,"body":body})
        };
        let mut effects=vec![];
        for (table,predicate) in [("blobs","sha256=$1"),("blob_user_charges","blob_sha256=$1"),("blob_user_usage","user_id=$2 AND $1::text IS NOT NULL"),("blob_cleanup_queue","blob_sha256=$1")]{
            for row in owner.query(&format!("SELECT to_jsonb(t)::text FROM {table} t WHERE {predicate} AND $2::bigint IS NOT NULL"),&[&hash,&account.user]).await?{
                let mut value:Value=serde_json::from_str(&row.get::<_,String>(0))?;
                for (key,value) in value.as_object_mut().unwrap(){
                    if key=="user_id"{assert_eq!(value.as_i64(),Some(account.user));*value=json!("<actor>");}
                    else if matches!(key.as_str(),"sha256"|"blob_sha256"){assert_eq!(value.as_str(),Some(hash.as_str()));*value=json!("<hash>");}
                    else if key=="minio_ref"{assert_eq!(value.as_str(),Some(format!("mailblobs/{hash}").as_str()));*value=json!("mailblobs/<hash>");}
                    else if key.ends_with("_at")&&!value.is_null(){chrono::DateTime::parse_from_rfc3339(value.as_str().ok_or("timestamp type")?)?;*value=json!("<timestamp>");}
                }
                effects.push(json!({"table":table,"after":value}));
            }
        }
        let state:i64=owner.query_one("SELECT jmap_email_state FROM mailboxes WHERE id=$1 AND user_id=$2",&[&account.mailbox,&account.user]).await?.get(0);
        let audit_after:i64=owner.query_one("SELECT count(*) FROM admin_audit_log WHERE user_id=$1",&[&account.user]).await?.get(0);
        if audit_before!=audit_after{return Err("WORM PUT/ticks unexpectedly wrote audit".into());}
        let notifications=notify.drain(&owner).await?;
        let peer=peer.lock().unwrap();
        let keys=peer.objects.keys().map(|key|if key==&hash{"<hash>".to_owned()}else{key.clone()}).collect::<Vec<_>>();
        let observation=json!({"put":put,"effects":effects,"email_state":state,"objects":peer.operations,"keys":keys,"audit":[],"notify":notifications});
        Ok::<_,common::BoxError>(observation)
    }.await;
    // Remove an intentionally undrained mutant ledger through the real public
    // tick, after observing it. No private retry-state hooks are used.
    peer.lock().unwrap().accept_all = true;
    if !recording {
        worker.tick().await;
    }
    owner
        .execute("DELETE FROM blobs WHERE sha256=$1", &[&hash])
        .await?;
    common::remove_blob_account(&owner, &account).await?;
    let observation = result?;
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../tests/conformance/blobs/goldens/{CASE}.json"));
    if recording {
        let retention = observation["objects"]
            .as_array()
            .ok_or("missing S3 observations")?
            .iter()
            .filter(|o| o["operation"] == "retention")
            .collect::<Vec<_>>();
        if retention
            .iter()
            .map(|r| r["status"].as_u64())
            .collect::<Vec<_>>()
            != vec![Some(403), Some(403), Some(200)]
            || observation["keys"] != json!(["<hash>"])
            || observation["effects"]
                .as_array()
                .is_none_or(|r| r.len() != 4)
        {
            return Err(format!(
                "Go recorder did not exercise successful retry/drain: {observation}"
            )
            .into());
        }
        if skip_ticks {
            return Err("mutants never record".into());
        }
        let document = json!({"format":1,"worker":"blob-cleanup","case":CASE,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"normalization":["fixture actor/hash and random temp key","validated database timestamps and 30-day retain-until","retention Content-Type differs by SDK and is not compared; signatures are independently verified"],"observation":observation});
        if path.exists() {
            let expected: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
            setjoin_conformance::golden::compare(&expected, &document)?;
        } else {
            setjoin_conformance::golden::record(&path, &document)?;
        }
    } else {
        let expected: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        setjoin_conformance::golden::compare(&expected["observation"], &observation)?;
        eprintln!("GOLDEN-REPLAY: blob-cleanup :: {CASE}");
    }
    Ok(())
}
