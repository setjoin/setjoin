//! Executable F14 registration, both rollback switches and proxy metrics.
use crate::common::boot::CommandBootExt;
use crate::common::boot::Child;
mod common;
use common::BoxError;
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

#[tokio::test]
async fn executable_serves_all_ten_sharing_routes_without_go() -> Result<(), BoxError> {
    run(false, false).await
}
#[tokio::test]
async fn executable_global_kill_preserves_all_ten_requests() -> Result<(), BoxError> {
    run(true, false).await
}
#[tokio::test]
async fn executable_inventory_rollback_preserves_all_ten_requests() -> Result<(), BoxError> {
    run(false, true).await
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
async fn run(kill: bool, rollback: bool) -> Result<(), BoxError> {
    use std::os::unix::process::CommandExt;
    let Some(db) = Db::for_case("drive1-executable") else {
        return Ok(());
    };
    let c = db.connect().await?;
    let a = fixture::account(&c, "drive1-exec-owner").await?;
    let b = fixture::account(&c, "drive1-exec-grantee").await?;
    let role:i64=c.query_one("INSERT INTO admin_role_groups(name,permissions) VALUES('drive1-exec-'||$1::bigint::text,ARRAY['sharing.read','sharing.manage']) RETURNING id",&[&a.user]).await?.get(0);
    let result=std::panic::AssertUnwindSafe(async{
        c.execute("INSERT INTO admin_role_assignments(user_id,role_group_id) VALUES($1,$2)",&[&a.user,&role]).await?;
        let calendar:i64=c.query_one("INSERT INTO calendars(mailbox_id,name,is_default) VALUES($1,'Drive executable',true) RETURNING id",&[&a.mailbox]).await?.get(0);
        let user_default:i64=c.query_one("INSERT INTO sharing_defaults(resource,owner_scope,owner_ref,audience,audience_ref,level,created_by) VALUES('calendar','user',$1,'everyone',$2,'none',$1) RETURNING id",&[&a.user,&a.domain]).await?.get(0);
        let org_default:i64=c.query_one("INSERT INTO sharing_defaults(resource,owner_scope,owner_ref,audience,audience_ref,level,created_by) VALUES('calendar','org',$1,'everyone',$1,'none',$2) RETURNING id",&[&a.domain,&a.user]).await?.get(0);
        let email:String=c.query_one("SELECT email FROM users WHERE id=$1",&[&b.user]).await?.get(0);
        let hits=Arc::new(AtomicUsize::new(0));let observed=hits.clone();
        let go=common::fake_upstream(move|mut request|{let observed=observed.clone();async move{
            observed.fetch_add(1,Ordering::SeqCst);let bytes=request.body_mut().collect().await.unwrap().to_bytes();
            Response::builder().status(218).body(common::full(json!({"method":request.method().as_str(),"uri":request.uri().to_string(),"body":String::from_utf8_lossy(&bytes),"probe":request.headers()["x-drive-probe"].to_str().unwrap()}).to_string())).unwrap()
        }}).await;
        let jwks=common::fake_upstream(|_|async{Response::builder().header("content-type","application/json").body(common::full(include_bytes!("../../../tests/conformance/jmap/test-jwks.json").as_slice())).unwrap()}).await;
        let reserved = setjoin_conformance::ports::listener().await;let address=reserved.local_addr()?;drop(reserved);
        let dir=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../test-results/gofree-drive1");std::fs::create_dir_all(&dir)?;
        let log=std::fs::File::create(dir.join(format!("gofree-drive1-exec-{}-{kill}-{rollback}.log",a.user)))?;
        let mut command=Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));command.arg0("gofree-drive1-gateway").env_clear();
        for(key,value)in[
            ("GATEWAY_LISTEN",address.to_string()),("GATEWAY_ENABLED",(!kill).to_string()),("GATEWAY_AUTH_UPSTREAM",format!("http://{jwks}")),
            ("DB_DSN",db.app.as_deref().unwrap_or(&db.dsn).to_owned()),("DB_WORKER_DSN",db.dsn.clone()),("DB_DIRECT_DSN",db.direct.clone()),
            ("DB_ENCRYPTION_KEY","22".repeat(32)),("AUTHSERVER_JWKS_URL",format!("http://{jwks}/.well-known/jwks.json")),("CORE_RATE_LIMIT","100000".into()),("ADMIN_RATE_LIMIT","100000".into()),
        ]{command.env(key,value);}
        if kill||rollback{command.env("GATEWAY_UPSTREAM",format!("http://{go}"));}
        if rollback{let mut inventory:Value=serde_json::from_str(setjoin_gateway::inventory::BUNDLED)?;for row in inventory["routes"].as_array_mut().unwrap(){if row["family"]=="F14"&&row["slice"]=="golden-routes"{row["state"]="OFF".into();row["upstream"]="go-mail".into();}}let file=dir.join(format!("gofree-drive1-rollback-{}.json",a.user));std::fs::write(&file,inventory.to_string())?;command.env("GATEWAY_ROUTE_INVENTORY",file);}
        if let Ok(path)=std::env::var("LLVM_PROFILE_FILE"){command.env("LLVM_PROFILE_FILE",path);}
        ledger(&format!("Plan gofree-drive1-gateway executable at {address}, assigned DB only"))?;
        let mut child=Owned(command.stdout(Stdio::from(log.try_clone()?)).stderr(Stdio::from(log)).spawn_boot()?);ledger(&format!("Started gofree-drive1-gateway PID {}",child.0.id()))?;
        let deadline=tokio::time::Instant::now()+Duration::from_secs(60);
        loop{if let Some(status)=child.0.try_wait()?{return Err(format!("gateway exited: {status}").into())}if tokio::net::TcpStream::connect(address).await.is_ok(){break}if tokio::time::Instant::now()>deadline{return Err("gateway startup timeout".into())}tokio::time::sleep(Duration::from_millis(20)).await;}
        let requests=vec![
            ("GET","/api/me/sharing".to_owned(),String::new(),200),
            ("POST","/api/me/sharing/delegates".to_owned(),json!({"granteeEmail":email,"permission":"read"}).to_string(),201),
            ("DELETE",format!("/api/me/sharing/delegates/{}",b.user),String::new(),204),
            ("PUT","/api/me/sharing/default".to_owned(),json!({"audience":"everyone","level":"read"}).to_string(),200),
            ("DELETE",format!("/api/me/sharing/default/{user_default}"),String::new(),204),
            ("GET","/api/admin/sharing/defaults".to_owned(),String::new(),200),
            ("POST","/api/admin/sharing/defaults".to_owned(),json!({"ownerScope":"org","ownerRef":a.domain,"audience":"everyone","audienceRef":a.domain,"level":"read"}).to_string(),200),
            ("DELETE",format!("/api/admin/sharing/defaults/{org_default}"),String::new(),204),
            ("GET",format!("/api/admin/sharing/users/{}",a.user),String::new(),200),
            ("GET",format!("/api/admin/sharing/audit?user_id={}",a.user),String::new(),200),
        ];
        for(index,(method,path,body,status))in requests.iter().enumerate(){
            let uri=format!("{path}{}probe={index}",if path.contains('?'){"&"}else{"?"});
            let response=common::send(address,Request::builder().method(*method).uri(&uri).header("host","mail.test").header("origin","http://mail.test").header("authorization",format!("Bearer {}",token(a.user))).header("x-drive-probe",index.to_string()).header("x-audit-reason","executable fixture").header("content-type","application/json").body(common::full(body.clone()))?).await;
            let got=response.status().as_u16();let headers=response.headers().clone();let bytes=common::body_bytes(response).await;
            if kill||rollback{if got!=218{return Err(format!("rollback {uri}: {got}").into())}let observed:Value=serde_json::from_slice(&bytes)?;if observed!=json!({"method":method,"uri":uri,"body":body,"probe":index.to_string()}){return Err(format!("changed rollback request: {observed}").into())}}
            else if got!=*status{return Err(format!("native {uri}: {got} {} headers={:?} gateway log: {}",String::from_utf8_lossy(&bytes),headers,std::fs::read_to_string(dir.join(format!("gofree-drive1-exec-{}-{kill}-{rollback}.log",a.user))).unwrap_or_default()).into())}
        }
        if !kill{let response=common::send(address,Request::builder().uri("/_gateway/metrics").body(common::full(""))?).await;let text=String::from_utf8(common::body_bytes(response).await.to_vec())?;let n=if rollback{10}else{0};if !text.contains(&format!("setjoin_gateway_proxied_to_go_total {n}\n"))||!text.contains(&format!("setjoin_gateway_proxied_to_go_by_family_total{{family=\"F14\"}} {n}\n")){return Err(format!("proxy counters: {text}").into())}}
        if hits.load(Ordering::SeqCst)!=if kill||rollback{10}else{0}{return Err("unexpected Go request count".into())}
        let state:i64=c.query_one("SELECT jmap_state FROM calendars WHERE id=$1 AND mailbox_id=$2",&[&calendar,&a.mailbox]).await?.get(0);
        if state!=if kill||rollback{0}else{2}{return Err("rollback wrote calendar state or native writes missing".into())}
        let pid=child.0.id();drop(child);ledger(&format!("Stopped/reaped gofree-drive1-gateway PID {pid}"))?;Ok::<_,BoxError>(())
    }).catch_unwind().await;
    c.execute(
        "DELETE FROM sharing_defaults WHERE created_by=$1",
        &[&a.user],
    )
    .await?;
    c.execute(
        "DELETE FROM calendars WHERE mailbox_id IN($1,$2)",
        &[&a.mailbox, &b.mailbox],
    )
    .await?;
    c.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE user_id={} OR before_state->>'actor'='drive1@test'; DELETE FROM admin_role_assignments WHERE role_group_id={role}; COMMIT;",a.user)).await?;
    c.execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role])
        .await?;
    fixture::remove(&c, &a).await?;
    fixture::remove(&c, &b).await?;
    match result {
        Ok(r) => r,
        Err(p) => std::panic::resume_unwind(p),
    }
}
use futures_util::FutureExt;
fn token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let h = B.encode(json!({"alg":"ES256","kid":"test-es256-1","typ":"JWT"}).to_string());
    let b=B.encode(json!({"uid":user,"email":"drive1@test","admin":true,"perms":["sharing.manage"],"typ":"access","jti":"drive1-exec","fam":"drive1-exec","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+600}).to_string());
    let sig: p256::ecdsa::Signature = SigningKey::from_slice(&[0x11; 32])
        .unwrap()
        .sign(format!("{h}.{b}").as_bytes());
    format!("{h}.{b}.{}", B.encode(sig.to_bytes()))
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
