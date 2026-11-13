//! PUT accounting, promotion and dedup observed through HTTP and the S3 peer.
mod common;
use common::BoxError;
use http_body_util::BodyExt;
use hyper::{Request, Response};
use serde_json::{Value, json};
use setjoin_conformance::{fixture, harness::Db};
use setjoin_gateway::{
    Config, Gateway, RouteTable, TrustedProxies,
    blobs::{BlobCommands, BlobRoute},
    recovery_worker::S3Store,
};
use setjoin_pg::ScopedExecutor;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

#[tokio::test]
async fn upload_accounts_and_promotes_verified_bytes() -> Result<(), BoxError> {
    run_case("success", false).await
}

async fn run_case(case: &str, mutant: bool) -> Result<(), BoxError> {
    let _serial = common::recovery::SERIAL.lock().await;
    let Some(db) = Db::for_case("blob-upload") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = fixture::account(&owner, "blobs1-put").await?;
    let foreign = fixture::account(&owner, "blobs1-put-foreign").await?;
    let worm = case.starts_with("worm");
    let bytes = if matches!(case, "success" | "worm" | "worm-failure") {
        "blobs1 uploaded payload"
    } else {
        "blobs1 uploaded payload!"
    }
    .to_owned();
    let hash = format!("{:x}", Sha256::digest(&bytes));
    let result=async {
 let fail_retention=case=="worm-failure";
 let operations=Arc::new(Mutex::new(Vec::<Value>::new()));let observed=operations.clone();let expected=bytes.clone();let digest=hash.clone();
 let endpoint=common::fake_upstream(move |mut r|{
  let observed=observed.clone();let expected=expected.clone();let digest=digest.clone();async move {
   let body=r.body_mut().collect().await.unwrap().to_bytes();
   if r.uri().query()==Some("location="){return Response::new(common::full("<LocationConstraint>us-east-1</LocationConstraint>"))}
   let path=r.uri().path();let key=path.strip_prefix("/mailblobs/").unwrap_or("");
   if r.method()==hyper::Method::PUT && key.starts_with("tmp/upload/") {
    assert_eq!(key.len(),43);assert!(key[11..].bytes().all(|b|b.is_ascii_hexdigit()));
    let stored=common::s3::observe(&r,&body).unwrap();assert_eq!(stored["body"]["length"],expected.len());assert_eq!(stored["body"]["sha256"],digest);
    observed.lock().unwrap().push(json!({"operation":"upload-temp","type":r.headers()["content-type"].to_str().unwrap(),"length":expected.len()}));
    Response::builder().header("etag","\"temp-etag\"").body(common::full("")).unwrap()
   } else if r.method()==hyper::Method::PUT && key==digest && r.headers().contains_key("x-amz-copy-source") {
    let source=r.headers()["x-amz-copy-source"].to_str().unwrap();assert!(source.contains("mailblobs/tmp/upload/"));
    observed.lock().unwrap().push(json!({"operation":"promote"}));
    Response::builder().header("content-type","application/xml").body(common::full("<CopyObjectResult><LastModified>2026-10-31T00:00:00Z</LastModified><ETag>\"canonical-etag\"</ETag></CopyObjectResult>")).unwrap()
   } else if r.method()==hyper::Method::PUT && key==digest && r.uri().query().is_some_and(|q|q.starts_with("retention")) {
    // WORM (#301): the retention request as the object store sees it. The content type is
    // not observed: rust-s3 always sends one (Go sends none) and S3 ignores it here.
    let text=String::from_utf8_lossy(&body).into_owned();
    let tag=|name:&str|{let open=format!("<{name}>");let start=text.find(&open)?+open.len();let end=text[start..].find("</")?+start;Some(text[start..end].to_owned())};
    let until=tag("RetainUntilDate").and_then(|d|chrono::DateTime::parse_from_rfc3339(&d).ok());
    let days=until.map(|u|(u.with_timezone(&chrono::Utc)-chrono::Utc::now()+chrono::Duration::minutes(5)).num_days());
    observed.lock().unwrap().push(json!({"operation":"retention","mode":tag("Mode"),"retain_days":days,"bypass_governance":r.headers().contains_key("x-amz-bypass-governance-retention")}));
    if fail_retention {Response::builder().status(500).header("content-type","application/xml").body(common::full("<Error><Code>InternalError</Code><Message>retention refused</Message></Error>")).unwrap()} else {Response::new(common::full(""))}
   } else if r.method()==hyper::Method::DELETE && key.starts_with("tmp/upload/") {
    observed.lock().unwrap().push(json!({"operation":"delete-temp"}));Response::builder().status(204).body(common::full("")).unwrap()
   } else {Response::new(common::full(""))}
  }
 }).await;
 let worm_env=[("WORM_MODE",if case=="worm-compliance"{"compliance".to_owned()}else{"governance".to_owned()}),("WORM_RETENTION_DAYS","30".to_owned())];
 let oracle=if worm {common::go_oracle::start_named_with_env(&db,endpoint,"gofree-plat3-worm",&worm_env).await?} else {common::go_oracle::start(&db,endpoint).await?};let recording=oracle.is_some();
 if worm&&!recording {for (k,v) in &worm_env {std::env::set_var(k,v);}}
 let adapter=BlobRoute(Arc::new(BlobCommands{exec:ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn),4).map_err(|e|e.0)?,worker_exec:ScopedExecutor::from_dsn(&db.dsn,4).map_err(|e|e.0)?,keys:common::recovery_keys(),issuer:"mailserver".into(),store:Arc::new(S3Store::new(&format!("http://{endpoint}"),"mailblobs","test-access","test-secret")?)}));
 let mut inventory:Value=serde_json::from_str(include_str!("../route-inventory.json"))?;let route=inventory["routes"].as_array_mut().unwrap().iter_mut().find(|r|r["method"]=="PUT" && r["path"]=="/blobs/{sha256}").unwrap();route["state"]="ON".into();route["upstream"]="local-rust".into();
 let gateway=Gateway::new(Config{upstream:oracle.as_ref().map(|o|format!("http://{}",o.address).parse()).transpose()?,trusted_proxies:TrustedProxies::parse("")?,upstream_header_timeout:setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,edge_limit:None},if recording{RouteTable::proxy_all()}else if mutant{RouteTable::proxy_all().with(ChangedStatus(adapter))}else{RouteTable::proxy_all().with(adapter)})?.with_inventory(&inventory.to_string())?;
 let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await?;let address=listener.local_addr()?;let task=tokio::spawn(gateway.serve(listener));
 let audit_before=owner.query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE user_id=ANY($1) ORDER BY id",&[&vec![account.user,foreign.user]]).await?.iter().map(|r|r.get::<_,String>(0)).collect::<Vec<_>>();
 let mut notify=db.listen(&format!("tag:{}",account.mailbox)).await?;
 let mut responses=Vec::new();
 for iteration in 0..if case=="repeat" || case=="foreign"{2}else{1} {
 let response=common::send(address,Request::put(format!("/api/blobs/{}",if case=="invalid"{"invalid"}else{&hash})).header("host","mail.test").header("origin","http://mail.test").header("x-request-id","blobs1-upload-oracle").header("content-type","text/plain").header("authorization",format!("Bearer {}",common::recovery_token(if case=="foreign" && iteration==1{foreign.user}else{account.user}))).body(common::full(bytes.clone()))?).await;
 let status=response.status().as_u16();let mut headers=serde_json::Map::new();for name in response.headers().keys(){headers.insert(name.to_string(),json!(response.headers().get_all(name).iter().map(|v|if name=="date"{"<timestamp>".to_owned()}else{v.to_str().unwrap().to_owned()}).collect::<Vec<_>>()));}let body=String::from_utf8(common::body_bytes(response).await.to_vec())?;responses.push(json!({"status":status,"headers":headers,"body":body}));
 }
 task.abort();
 let mut effects=Vec::new();for (table,predicate) in [("blobs","sha256=$1"),("blob_user_charges","blob_sha256=$1"),("blob_user_usage","user_id=$2 AND $1::text IS NOT NULL"),("blob_cleanup_queue","blob_sha256=$1")]{
  for row in owner.query(&format!("SELECT to_jsonb(t)::text FROM {table} t WHERE {predicate} AND $2::bigint IS NOT NULL"),&[&hash,&account.user]).await? {let mut row:Value=serde_json::from_str(&row.get::<_,String>(0))?;for (k,v) in row.as_object_mut().unwrap(){if k=="user_id"{assert_eq!(v.as_i64(),Some(account.user));*v=json!("<actor>");}else if k=="sha256"||k=="blob_sha256"{assert_eq!(v.as_str(),Some(hash.as_str()));*v=json!("<hash>");}else if k=="minio_ref"{assert_eq!(v.as_str(),Some(format!("mailblobs/{hash}").as_str()));*v=json!("mailblobs/<hash>");}else if k.ends_with("_at"){assert!(v.is_string());*v=json!("<timestamp>");}}
  effects.push(json!({"table":table,"after":row}));}
 }
 let mut observation=json!({"response":responses[0],"effects":effects,"objects":operations.lock().unwrap().clone()});
 if !matches!(case,"success"|"worm"|"worm-failure") {observation["responses"]=json!(responses);}
 let path=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../tests/conformance/blobs/goldens/blob-upload-{case}.json"));

 let audit_after=owner.query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE user_id=ANY($1) ORDER BY id",&[&vec![account.user,foreign.user]]).await?.iter().map(|r|r.get::<_,String>(0)).collect::<Vec<_>>();
 if audit_before!=audit_after {return Err("PUT unexpectedly wrote audit".into());}
 let notifications=notify.drain(&owner).await?;
 if path.exists(){let old:Value=serde_json::from_slice(&std::fs::read(&path)?)?;setjoin_conformance::golden::compare(&old["observation"],&observation)?;}
 else if recording{setjoin_conformance::golden::record(&path,&json!({"format":1,"route":"PUT /blobs/{sha256}","case":case,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation,"effects":effects}))?;}
 observation["request"]=json!({"method":"PUT","path":"/blobs/{sha256}","case":case});observation["audit"]=json!([]);observation["notify"]=json!(notifications);
 let qualified=path.with_file_name(format!("blob-upload-{case}-qualified.json"));let row_path=path.with_file_name(format!("blob-upload-{case}-row-effects.json"));
 if recording{let source=std::env::var("GOFREE_GO_SOURCE")?;setjoin_conformance::golden::record(&qualified,&json!({"format":1,"route":"PUT /blobs/{sha256}","case":case,"go_source":source,"observation":observation}))?;setjoin_conformance::golden::record(&row_path,&json!({"format":1,"route":"PUT /blobs/{sha256}","case":format!("{case}-row-effects"),"go_source":source,"effects":effects}))?;}
 else{let expected:Value=serde_json::from_slice(&std::fs::read(qualified)?)?;let rows:Value=serde_json::from_slice(&std::fs::read(row_path)?)?;setjoin_conformance::golden::compare(&rows["effects"],&json!(effects))?;setjoin_conformance::golden::compare(&expected["observation"],&observation)?;eprintln!("GOLDEN-REPLAY: PUT /blobs/{{sha256}} :: {case}");}
 Ok::<_,BoxError>(())
 }.await;
    std::env::remove_var("WORM_MODE");
    std::env::remove_var("WORM_RETENTION_DAYS");
    owner
        .execute("DELETE FROM blobs WHERE sha256=$1", &[&hash])
        .await?;
    common::remove_blob_account(&owner, &account).await?;
    common::remove_blob_account(&owner, &foreign).await?;
    result
}

#[tokio::test]
async fn repeated_upload_does_not_charge_again() -> Result<(), BoxError> {
    run_case("repeat", false).await
}

#[tokio::test]
async fn another_user_can_deduplicate_without_taking_the_charge() -> Result<(), BoxError> {
    run_case("foreign", false).await
}

/// `WORM_MODE` set: Go arms Object Lock retention on the canonical key after the upload.
#[tokio::test]
async fn worm_upload_applies_retention_to_the_canonical_key() -> Result<(), BoxError> {
    run_case("worm", false).await
}

/// A refused retention is non-fatal: SDK 5xx retries still end in 201 and a queued cleanup retry.
#[tokio::test]
async fn worm_retention_failure_is_not_fatal() -> Result<(), BoxError> {
    run_case("worm-failure", false).await
}

#[tokio::test]
async fn invalid_hash_does_not_upload_or_charge() -> Result<(), BoxError> {
    run_case("invalid", false).await
}

struct ChangedStatus<K: setjoin_authz::token::KeySource + 'static>(BlobRoute<K>);
impl<K: setjoin_authz::token::KeySource + 'static> setjoin_gateway::Intercept for ChangedStatus<K> {
    fn matches(&self, r: &Request<setjoin_gateway::Body>) -> bool {
        self.0.matches(r)
    }
    fn handle(
        &self,
        r: Request<setjoin_gateway::Body>,
        c: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<Response<setjoin_gateway::Body>> {
        let f = self.0.handle(r, c);
        Box::pin(async move {
            let mut r = f.await;
            *r.status_mut() = hyper::StatusCode::ACCEPTED;
            r
        })
    }
}
#[tokio::test]
async fn upload_oracle_rejects_changed_status() -> Result<(), BoxError> {
    let e = run_case("success", true)
        .await
        .expect_err("mutant must differ");
    assert!(e.to_string().contains("/response/status"), "{e}");
    eprintln!("MUTANT-REJECTED: PUT /blobs/{{sha256}} :: changed-status");
    Ok(())
}

#[tokio::test]
async fn worm_compliance_upload_applies_retention_to_the_canonical_key() -> Result<(), BoxError> {
    run_case("worm-compliance", false).await
}
