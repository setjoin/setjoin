//! #274 real executable, all 19 registrations, native and rollback paths.
use crate::common::boot::CommandBootExt;
use crate::common::boot::Child;
mod common;
#[path = "common/drive_s3.rs"]
mod storage_wire;
use common::BoxError;
use futures_util::FutureExt;
use http_body_util::BodyExt;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, harness::Db};
use std::{
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
const BYTES: &[u8] = b"drive2 chunk";
const PDF: &[u8] = b"%PDF-1.7\nDrive2 executable\n%%EOF\n";
#[tokio::test]
async fn executable_serves_all_nineteen_core_routes_without_go() -> Result<(), BoxError> {
    run(false, false).await
}
#[tokio::test]
async fn executable_global_kill_preserves_all_core_requests() -> Result<(), BoxError> {
    run(true, false).await
}
#[tokio::test]
async fn executable_inventory_rollback_preserves_all_core_requests() -> Result<(), BoxError> {
    run(false, true).await
}
struct Owned(Child);
impl Drop for Owned {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            unsafe {
                libc::kill(self.0.id() as i32, libc::SIGTERM);
            }
            for _ in 0..50 {
                if self.0.try_wait().ok().flatten().is_some() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}
fn token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let h = B.encode(json!({"alg":"ES256","kid":"test-es256-1","typ":"JWT"}).to_string());
    let b=B.encode(json!({"uid":user,"email":"drive2-executable@test","typ":"access","jti":"drive2-executable","fam":"drive2-executable","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+600}).to_string());
    let s: p256::ecdsa::Signature = SigningKey::from_slice(&[0x11; 32])
        .unwrap()
        .sign(format!("{h}.{b}").as_bytes());
    format!("{h}.{b}.{}", B.encode(s.to_bytes()))
}
async fn run(kill: bool, rollback: bool) -> Result<(), BoxError> {
    use sha2::{Digest, Sha256};
    use std::os::unix::process::CommandExt;
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case("drive2-executable") else {
        return Ok(());
    };
    let c = db.connect().await?;
    let a = fixture::account(&c, "drive2-exec-owner").await?;
    let b = fixture::account(&c, "drive2-exec-grantee").await?;
    let enabled: bool = c
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='feature.drive'",
            &[],
        )
        .await?
        .get(0);
    let directory = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(format!("../../../test-results/{}",std::env::var("GOFREE_RESOURCE_PREFIX").unwrap_or_else(|_|"gofree-drive2".into())));
    std::fs::create_dir_all(&directory)?;
    let inventory_file = directory.join(format!(
        "gofree-drive2-inventory-{}-{kill}-{rollback}.json",
        a.user
    ));
    let result=std::panic::AssertUnwindSafe(async{
  c.execute("UPDATE feature_toggles SET enabled=true WHERE key='feature.drive'",&[]).await?;
  let space:i64=c.query_one("SELECT drive_space_create($1,'Executable project','regular')",&[&a.user]).await?.get(0);
  let node:i64=c.query_one("SELECT drive_node_create($1,$2,NULL,'folder','Documents')",&[&a.user,&space]).await?.get(0);
  let file:i64=c.query_one("SELECT drive_node_create($1,$2,NULL,'file','Preview.docx')",&[&a.user,&space]).await?.get(0);
  let sha=format!("{:x}",Sha256::digest(BYTES));c.query_one("SELECT drive_chunk_register($1,$2,$3,$4)",&[&a.user,&space,&sha,&(BYTES.len() as i32)]).await?;
  let manifest=json!([{"sha256":sha,"size":BYTES.len()}]).to_string();let raw:String=c.query_one("SELECT drive_file_put_version($1,$2,$3,$4,'application/vnd.openxmlformats-officedocument.wordprocessingml.document',NULL,$5::text::jsonb,'drive2','executable')::text",&[&a.user,&file,&sha,&(BYTES.len() as i64),&manifest]).await?.get(0);let version:Value=serde_json::from_str(&raw)?;let version=version["versionId"].as_i64().ok_or("fixture version")?;
  let preview_sha=format!("{:x}",Sha256::digest(PDF));let manifest=json!([{"sha256":preview_sha,"size":PDF.len()}]).to_string();c.query_one("SELECT drive_preview_attach($1,$2,$3::text::jsonb,'ready')",&[&version,&preview_sha,&manifest]).await?;
  let hits=Arc::new(AtomicUsize::new(0));let observed=hits.clone();let go_requests=Arc::new(std::sync::Mutex::new(Vec::<Value>::new()));let captured=go_requests.clone();
  let go=common::fake_upstream(move|mut r|{let hits=observed.clone();let captured=captured.clone();async move{hits.fetch_add(1,Ordering::SeqCst);let bytes=r.body_mut().collect().await.unwrap().to_bytes();let observation=json!({"method":r.method().as_str(),"uri":r.uri().to_string(),"body":String::from_utf8_lossy(&bytes),"probe":r.headers()["x-drive-probe"].to_str().unwrap()});captured.lock().unwrap().push(observation.clone());Response::builder().status(218).body(common::full(observation.to_string())).unwrap()}}).await;
  let jwks=common::fake_upstream(|_|async{Response::builder().header("content-type","application/json").body(common::full(include_bytes!("../../../tests/conformance/jmap/test-jwks.json").as_slice())).unwrap()}).await;
  let io=Arc::new(AtomicUsize::new(0));let observed=io.clone();
  let s3=common::fake_upstream(move|r|{let io=observed.clone();async move{
   if r.uri().query()==Some("location="){return Response::new(common::full("<LocationConstraint>us-east-1</LocationConstraint>"))}
   // Complete server boot precedes dispatch, including rollback dispatch.
   // Count only route object operations in the native-only I/O assertion.
   if matches!(r.uri().path(),"/mailblobs"|"/mailblobs/") {
    if r.method()==hyper::Method::HEAD{return Response::new(common::full(""))}
    if r.method()==hyper::Method::GET&&r.uri().query().is_some_and(|q|q.split('&').any(|p|matches!(p,"uploads"|"uploads="))){return Response::new(common::full("<ListMultipartUploadsResult><Bucket>mailblobs</Bucket><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>"))}
   }
   let method=r.method().clone();let uri=r.uri().path().to_owned();let query=r.uri().query().unwrap_or("").to_owned();let copy=r.headers().contains_key("x-amz-copy-source");let(parts,body)=r.into_parts();let bytes=body.collect().await.unwrap().to_bytes();let request=Request::from_parts(parts,());storage_wire::observe(&request,&bytes).expect("executable S3 signature and payload");io.fetch_add(1,Ordering::SeqCst);
   if method==hyper::Method::POST&&matches!(query.as_str(),"uploads"|"uploads="){return Response::new(common::full(format!("<InitiateMultipartUploadResult><Bucket>mailblobs</Bucket><Key>{}</Key><UploadId>drive2-upload</UploadId></InitiateMultipartUploadResult>",uri.strip_prefix("/mailblobs/").unwrap())))}
   if method==hyper::Method::POST{return Response::new(common::full("<CompleteMultipartUploadResult><Location>http://storage.test/temp</Location><Bucket>mailblobs</Bucket><Key>temporary</Key><ETag>drive2</ETag></CompleteMultipartUploadResult>"))}
   if method==hyper::Method::PUT{return Response::builder().header("etag","\"drive2\"").body(common::full(if copy{"<CopyObjectResult><LastModified>2026-11-01T00:00:00.000Z</LastModified><ETag>\"drive2\"</ETag></CopyObjectResult>"}else{""})).unwrap()}
   if method==hyper::Method::DELETE{return Response::builder().status(204).body(common::full("")).unwrap()}
   Response::builder().header("content-type","application/pdf").header("content-length",PDF.len().to_string()).body(common::full(PDF.to_vec())).unwrap()
  }}).await;
  let listener = setjoin_conformance::ports::listener().await;let address=listener.local_addr()?;drop(listener);
  let log=std::fs::File::create(directory.join(format!("gofree-drive2-executable-{}-{kill}-{rollback}.log",a.user)))?;
  let mut command=Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));command.arg0(format!("{}-gateway",std::env::var("GOFREE_RESOURCE_PREFIX").unwrap_or_else(|_|"gofree-drive2".into()))).env_clear();
  for(key,value)in[("GATEWAY_LISTEN",address.to_string()),("GATEWAY_ENABLED",(!kill).to_string()),("GATEWAY_AUTH_UPSTREAM",format!("http://{jwks}")),("AUTHSERVER_JWKS_URL",format!("http://{jwks}/.well-known/jwks.json")),("DB_DSN",db.app.as_deref().unwrap_or(&db.dsn).to_owned()),("DB_WORKER_DSN",db.dsn.clone()),("DB_DIRECT_DSN",db.direct.clone()),("DB_ENCRYPTION_KEY","22".repeat(32)),("CORE_RATE_LIMIT","100000".into()),("ADMIN_RATE_LIMIT","100000".into()),("S3_ENDPOINT",format!("http://{s3}")),("S3_SECURE","false".into()),("S3_BUCKET","mailblobs".into()),("S3_ACCESS_KEY","test-access".into()),("S3_SECRET_KEY","test-secret".into())]{command.env(key,value);}
  if kill||rollback{command.env("GATEWAY_UPSTREAM",format!("http://{go}"));}
  if rollback{let mut inventory:Value=serde_json::from_str(setjoin_gateway::inventory::BUNDLED)?;for row in inventory["routes"].as_array_mut().unwrap(){if row["family"]=="F14"&&row["slice"]=="sub-router-a"{row["state"]="OFF".into();row["upstream"]="go-mail".into();}}std::fs::write(&inventory_file,inventory.to_string())?;command.env("GATEWAY_ROUTE_INVENTORY",&inventory_file);}
  if let Ok(profile)=std::env::var("LLVM_PROFILE_FILE"){command.env("LLVM_PROFILE_FILE",profile);}
  ledger(&format!("Plan gofree-drive2-gateway executable at {address}; own assigned DB only"))?;
  let mut child=Owned(command.stdout(Stdio::from(log.try_clone()?)).stderr(Stdio::from(log)).spawn_boot()?);ledger(&format!("Started gofree-drive2-gateway PID {} at {:?}",child.0.id(),std::time::SystemTime::now()))?;
  let deadline=tokio::time::Instant::now()+Duration::from_secs(60);loop{if let Some(status)=child.0.try_wait()?{return Err(format!("gateway exited: {status}").into())}if tokio::net::TcpStream::connect(address).await.is_ok(){break}if tokio::time::Instant::now()>deadline{return Err("gateway startup timeout".into())}tokio::time::sleep(Duration::from_millis(20)).await;}
  let requests=vec![
   ("GET","/drive/spaces","/api/drive/spaces".to_owned(),String::new(),200),
   ("POST","/drive/spaces","/api/drive/spaces".to_owned(),json!({"name":"Created through executable"}).to_string(),201),
   ("PATCH","/drive/spaces/{id}",format!("/api/drive/spaces/{space}"),json!({"classification":"regular"}).to_string(),204),
   ("GET","/drive/spaces/{id}/members",format!("/api/drive/spaces/{space}/members"),String::new(),200),
   ("POST","/drive/spaces/{id}/members",format!("/api/drive/spaces/{space}/members"),json!({"userId":b.user,"role":"viewer"}).to_string(),200),
   ("DELETE","/drive/spaces/{id}/members/{userId}",format!("/api/drive/spaces/{space}/members/{}",b.user),String::new(),204),
   ("GET","/drive/spaces/{id}/tree",format!("/api/drive/spaces/{space}/tree"),String::new(),200),
   ("GET","/drive/changes",format!("/api/drive/changes?space={space}&since=0"),String::new(),200),
   ("GET","/drive/access-invalidations",format!("/api/drive/access-invalidations?space={space}"),String::new(),200),
   ("GET","/drive/visibility-snapshot",format!("/api/drive/visibility-snapshot?space={space}"),String::new(),200),
   ("GET","/drive/nodes",format!("/api/drive/nodes?ids={node}"),String::new(),200),
   ("POST","/drive/nodes","/api/drive/nodes".to_owned(),json!({"spaceId":space,"kind":"file","name":"Created.txt"}).to_string(),201),
   ("PATCH","/drive/nodes/{id}",format!("/api/drive/nodes/{node}"),json!({"newName":"Renamed"}).to_string(),204),
   ("POST","/drive/nodes/{id}/trash",format!("/api/drive/nodes/{node}/trash"),String::new(),204),
   ("POST","/drive/nodes/{id}/restore",format!("/api/drive/nodes/{node}/restore"),String::new(),204),
   ("POST","/drive/nodes/{id}/trash",format!("/api/drive/nodes/{node}/trash"),String::new(),204),
   ("DELETE","/drive/nodes/{id}",format!("/api/drive/nodes/{node}"),String::new(),204),
   ("HEAD","/drive/chunks/{sha256}",format!("/api/drive/chunks/{sha}?space={space}"),String::new(),200),
   ("PUT","/drive/chunks/{sha256}",format!("/api/drive/chunks/{sha}?space={space}"),String::from_utf8(BYTES.to_vec())?,201),
   ("GET","/drive/versions/{id}/preview",format!("/api/drive/versions/{version}/preview"),String::new(),200),
  ];
  let declared:std::collections::BTreeSet<_>=requests.iter().map(|r|(r.0.to_owned(),r.1.to_owned())).collect();let inventory:Value=serde_json::from_str(setjoin_gateway::inventory::BUNDLED)?;let expected=inventory["routes"].as_array().unwrap().iter().filter(|r|r["family"]=="F14"&&r["slice"]=="sub-router-a").map(|r|(r["method"].as_str().unwrap().to_owned(),r["path"].as_str().unwrap().to_owned())).collect();assert_eq!(declared,expected,"executable probes cover exact assigned slice");
  for(index,(method,_,path,body,status))in requests.iter().enumerate(){let uri=format!("{path}{}probe={index}",if path.contains('?'){"&"}else{"?"});let response=common::send(address,Request::builder().method(*method).uri(&uri).header("host","mail.test").header("origin","http://mail.test").header("authorization",format!("Bearer {}",token(a.user))).header("content-type","application/json").header("x-drive-probe",index.to_string()).body(common::full(body.clone()))?).await;let got=response.status().as_u16();let bytes=common::body_bytes(response).await;
   if kill||rollback{assert_eq!(got,218,"rollback {uri}");let observed:Value=if *method=="HEAD"{go_requests.lock().unwrap().last().unwrap().clone()}else{serde_json::from_slice(&bytes)?};assert_eq!(observed,json!({"method":method,"uri":uri,"body":body,"probe":index.to_string()}),"rollback preserves request");}else if got!=*status{return Err(format!("native {method} {uri}: {got}: {}",String::from_utf8_lossy(&bytes)).into())}
  }
  if !kill{let metrics=common::send(address,Request::builder().uri("/_gateway/metrics").body(common::full(""))?).await;let text=String::from_utf8(common::body_bytes(metrics).await.to_vec())?;let count=if rollback{requests.len()}else{0};assert!(text.contains(&format!("setjoin_gateway_proxied_to_go_total {count}\n")),"{text}");assert!(text.contains(&format!("setjoin_gateway_proxied_to_go_by_family_total{{family=\"F14\"}} {count}\n")),"{text}");}
  assert_eq!(hits.load(Ordering::SeqCst),if kill||rollback{requests.len()}else{0});assert_eq!(io.load(Ordering::SeqCst)>0,!(kill||rollback),"S3 is native-only");let pid=child.0.id();drop(child);ledger(&format!("Stopped/reaped gofree-drive2-gateway PID {pid}"))?;Ok::<_,BoxError>(())
 }).catch_unwind().await;
    let chunks=c.query("SELECT scope_key,sha256 FROM drive_chunks t WHERE EXISTS(SELECT 1 FROM drive_upload_claims c WHERE c.scope_key=t.scope_key AND c.sha256=t.sha256 AND c.user_id=$1) OR EXISTS(SELECT 1 FROM drive_version_chunks vc JOIN drive_file_versions v ON v.id=vc.version_id JOIN drive_spaces s ON s.id=v.space_id WHERE vc.scope_key=t.scope_key AND vc.chunk_sha256=t.sha256 AND s.owner_user_id=$1)",&[&a.user]).await?;
    c.execute("DELETE FROM drive_nodes WHERE space_id IN(SELECT id FROM drive_spaces WHERE owner_user_id=$1)",&[&a.user]).await?;
    c.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM drive_audit_log WHERE space_id IN(SELECT id FROM drive_spaces WHERE owner_user_id={0}); DELETE FROM admin_audit_log WHERE user_id IN({0},{1}); COMMIT;",a.user,b.user)).await?;
    c.execute(
        "DELETE FROM drive_spaces WHERE owner_user_id=$1",
        &[&a.user],
    )
    .await?;
    c.execute(
        "DELETE FROM drive_upload_claims WHERE user_id=$1",
        &[&a.user],
    )
    .await?;
    for row in chunks {
        let scope: String = row.get(0);
        let sha: String = row.get(1);
        c.execute(
            "DELETE FROM drive_chunk_gc_queue WHERE scope_key=$1 AND sha256=$2",
            &[&scope, &sha],
        )
        .await?;
        c.execute("DELETE FROM drive_chunks WHERE scope_key=$1 AND sha256=$2 AND ref_count=0 AND NOT EXISTS(SELECT 1 FROM drive_upload_claims c WHERE c.scope_key=$1 AND c.sha256=$2)",&[&scope,&sha]).await?;
    }
    c.execute(
        "DELETE FROM rate_limit_counters WHERE key='drive:name-mutation:'||$1::bigint::text",
        &[&a.user],
    )
    .await?;
    c.execute(
        "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.drive'",
        &[&enabled],
    )
    .await?;
    fixture::remove(&c, &a).await?;
    fixture::remove(&c, &b).await?;
    if inventory_file.exists() {
        std::fs::remove_file(inventory_file)?;
    }
    match result {
        Ok(r) => r,
        Err(p) => std::panic::resume_unwind(p),
    }
}
fn ledger(line: &str) -> Result<(), BoxError> {
    use std::io::Write;
    if let Ok(path) = std::env::var("GOFREE_RESOURCE_LEDGER") {
        writeln!(
            std::fs::OpenOptions::new().append(true).open(path)?,
            "{line}"
        )?;
    }
    Ok(())
}
