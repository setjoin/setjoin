//! Real executable: native B dispatch, exact rollback requests, identity signer.
use crate::common::boot::CommandBootExt;
use crate::common::boot::Child;
mod common;
#[path = "common/office_fixture.rs"]
mod office_fixture;
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
#[tokio::test]
async fn executable_serves_28_routes_without_go() -> Result<(), BoxError> {
    run(false, false, false).await
}
#[tokio::test]
async fn global_kill_preserves_28_requests() -> Result<(), BoxError> {
    run(true, false, false).await
}
#[tokio::test]
async fn inventory_rollback_preserves_28_requests() -> Result<(), BoxError> {
    run(false, true, false).await
}
#[tokio::test]
async fn native_token_uses_identity_signer_without_go() -> Result<(), BoxError> {
    run(false, false, true).await
}
struct Owned(Child);
impl Drop for Owned {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            // The unreaped Child owns this PID; it cannot be reused by another task.
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

async fn run(kill: bool, rollback: bool, future: bool) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    use std::os::unix::process::CommandExt;
    let Some(db) = Db::for_case("drive3-executable") else {
        return Ok(());
    };
    let c = db.connect().await?;
    let a = fixture::account(&c, "drive3-exec").await?;
    let toggles=c.query("SELECT key,enabled FROM feature_toggles WHERE key IN('feature.drive','feature.drive_history','feature.office_editing','feature.office_local_open')",&[]).await?;
    let result=std::panic::AssertUnwindSafe(async{
  c.batch_execute("UPDATE feature_toggles SET enabled=true WHERE key IN('feature.drive','feature.drive_history','feature.office_editing','feature.office_local_open')").await?;
  let hits=Arc::new(AtomicUsize::new(0));let observed=hits.clone();let go=common::fake_upstream(move|mut request|{let observed=observed.clone();async move{observed.fetch_add(1,Ordering::SeqCst);let bytes=request.body_mut().collect().await.unwrap().to_bytes();Response::builder().status(218).body(common::full(json!({"method":request.method().as_str(),"uri":request.uri().to_string(),"body":String::from_utf8_lossy(&bytes),"probe":request.headers()["x-drive-probe"].to_str().unwrap()}).to_string())).unwrap()}}).await;
  let jwks=common::fake_upstream(|_|async{Response::builder().header("content-type","application/json").body(common::full(include_bytes!("../../../tests/conformance/jmap/test-jwks.json").as_slice())).unwrap()}).await;
  let socket = setjoin_conformance::ports::listener().await;let address=socket.local_addr()?;drop(socket);
  let dir=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!("../../../test-results/{}",std::env::var("GOFREE_RESOURCE_PREFIX").unwrap_or_else(|_|"gofree-drive3".into())));std::fs::create_dir_all(&dir)?;let log=std::fs::File::create(dir.join(format!("gofree-drive3-exec-{}-{kill}-{rollback}-{future}.log",a.user)))?;
  let mut command=Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));command.arg0(format!("{}-gateway",std::env::var("GOFREE_RESOURCE_PREFIX").unwrap_or_else(|_|"gofree-drive3".into()))).env_clear().env("JWT_SECRET", "idlogin1-fixture-secret-at-least-32-bytes");
  for(key,value)in[("GATEWAY_LISTEN",address.to_string()),("GATEWAY_ENABLED",(!kill).to_string()),("GATEWAY_AUTH_UPSTREAM",format!("http://{jwks}")),("DB_DSN",db.app.as_deref().unwrap_or(&db.dsn).to_owned()),("DB_WORKER_DSN",db.dsn.clone()),("DB_DIRECT_DSN",db.direct.clone()),("DB_ENCRYPTION_KEY","22".repeat(32)),("AUTHSERVER_JWKS_URL",format!("http://{jwks}/.well-known/jwks.json")),("CORE_RATE_LIMIT","100000".into()),("ADMIN_RATE_LIMIT","100000".into())]{command.env(key,value);}
  if kill||rollback{command.env("GATEWAY_UPSTREAM",format!("http://{go}"));}
  let override_path=dir.join(format!("gofree-drive3-rollback-{}.json",a.user));
  if rollback{let mut inventory:Value=serde_json::from_str(setjoin_gateway::inventory::BUNDLED)?;for row in inventory["routes"].as_array_mut().unwrap(){if row["family"]=="F14"&&row["slice"]=="sub-router-b"{row["state"]="OFF".into();row["upstream"]="go-mail".into();}}std::fs::write(&override_path,inventory.to_string())?;command.env("GATEWAY_ROUTE_INVENTORY",&override_path);}
  if let Ok(path)=std::env::var("LLVM_PROFILE_FILE"){command.env("LLVM_PROFILE_FILE",path);}
  ledger(&format!("Plan gofree-drive3-gateway at {address}, assigned DB only"))?;let mut child=Owned(command.stdout(Stdio::from(log.try_clone()?)).stderr(Stdio::from(log)).spawn_boot()?);ledger(&format!("Started gofree-drive3-gateway PID {}",child.0.id()))?;
  let deadline=tokio::time::Instant::now()+Duration::from_secs(60);loop{if let Some(status)=child.0.try_wait()?{return Err(format!("gateway exited: {status}").into())}if tokio::net::TcpStream::connect(address).await.is_ok(){break}if tokio::time::Instant::now()>deadline{return Err("gateway startup timeout".into())}tokio::time::sleep(Duration::from_millis(20)).await;}
  let mut requests=vec![
("GET","/api/drive/export/bad","{",409u16),
("GET","/api/drive/versions/bad/content","{",400u16),
("POST","/api/drive/export","{",400u16),
("POST","/api/drive/files/bad/office/launches","{",400u16),
("POST","/api/drive/files/bad/versions/bad/restore","{",400u16),
("POST","/api/drive/files/bad/versions","{",400u16),
("GET","/api/drive/audit?space=bad","{",400u16),
("GET","/api/drive/files/bad/history","{",400u16),
("DELETE","/api/drive/files/bad/office/launches/bad","{",400u16),
("POST","/api/drive/files/bad/office/local-open","{",400u16),
("GET","/api/drive/files/bad/office/choices","{",400u16),
("POST","/api/drive/nodes/bad/purge-restore","{",400u16),
("GET","/api/drive/spaces/bad/trash","{",400u16),
("GET","/api/drive/spaces/bad/audit/verify","{",400u16),
("GET","/api/drive/audit-alarms","{",403u16),
("PATCH","/api/drive/audit-alarms/bad","{",400u16),
("PATCH","/api/drive/branches/bad","{",400u16),
("DELETE","/api/drive/audit-alarms/bad","{",400u16),
("POST","/api/drive/audit-alarms","{",400u16),
("GET","/api/drive/audit-actions","{",200u16),
("POST","/api/drive/branches/bad/resolve","{",400u16),
("DELETE","/api/drive/versions/bad/labels/bad","{",400u16),
("POST","/api/drive/versions/bad/labels","{",400u16),
("GET","/api/drive/files/bad/branches","{",400u16),
("GET","/api/drive/files/bad/versions","{",400u16),
("POST","/api/drive/files/bad/branches","{",400u16),
("GET","/api/drive/search?space=bad","{",400u16),
("GET","/api/drive/spaces/bad/activity","{",400u16)];if future{requests=vec![("POST","/api/drive/native-token","{\"lifetime\":123}",200u16)];}
  for(index,(method,path,body,status))in requests.iter().enumerate(){let uri=format!("{path}{}probe={index}",if path.contains('?'){"&"}else{"?"});let response=common::send(address,Request::builder().method(*method).uri(&uri).header("host","mail.test").header("origin","http://mail.test").header("authorization",format!("Bearer {}",if future {setjoin_authz::legacy_jwt::sign_hs256(b"idlogin1-fixture-secret-at-least-32-bytes",&json!({"uid":a.user,"typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"exp":chrono::Utc::now().timestamp()+3600,"iat":chrono::Utc::now().timestamp()}).to_string())}else{office_fixture::token(a.user,false)})).header("x-drive-probe",index.to_string()).header("content-type","application/json").body(common::full(*body))?).await;let got=response.status().as_u16();let bytes=common::body_bytes(response).await;
   if kill||rollback{if got!=218{return Err(format!("forward {uri}: {got}").into())}let observed:Value=serde_json::from_slice(&bytes)?;if observed!=json!({"method":method,"uri":uri,"body":body,"probe":index.to_string()}){return Err(format!("changed forwarded request: {observed}").into())}}else if got!=*status{return Err(format!("native {uri}: {got} {}",String::from_utf8_lossy(&bytes)).into())}
  }
  let expected=if kill||rollback{requests.len()}else{0};if hits.load(Ordering::SeqCst)!=expected{return Err("unexpected upstream requests".into())}
  if !kill{let response=common::send(address,Request::builder().uri("/_gateway/metrics").body(common::full("")).unwrap()).await;let text=String::from_utf8(common::body_bytes(response).await.to_vec())?;for sample in[format!("setjoin_gateway_proxied_to_go_total {expected}\n"),format!("setjoin_gateway_proxied_to_go_by_family_total{{family=\"F14\"}} {expected}\n")]{if !text.contains(&sample){return Err(format!("proxy metrics: {text}").into())}}}
  let pid=child.0.id();drop(child);ledger(&format!("Reaped gofree-drive3-gateway PID {pid}"))?;if rollback{std::fs::remove_file(override_path)?;}Ok::<_,BoxError>(())
 }).catch_unwind().await;
    for toggle in toggles {
        c.execute(
            "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
            &[&toggle.get::<_, String>(0), &toggle.get::<_, bool>(1)],
        )
        .await?;
    }
    fixture::remove(&c, &a).await?;
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
