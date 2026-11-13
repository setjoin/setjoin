//! Real Go process vs Rust process: seed, notify, observe no writes/outbound I/O.
//! Go's dispatcher refuses device_policy before the named worker starts. Keep
//! that dormant behavior, including with GO_WORKERS_OFF=mdm-notify.
mod common;
use common::BoxError;
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use std::{
    os::unix::process::CommandExt,
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Log(PathBuf);
impl Drop for Log {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}
fn messages(log: &str) -> Value {
    let entries:Vec<Value>=log.lines().filter_map(|s|serde_json::from_str::<Value>(s).ok()).filter(|v|matches!(v["msg"].as_str(),Some("mam: failed to subscribe to device_policy channel"|"mam: device_policy notification subscription active (logged, not WS-pushed)"|"mam: malformed device_policy notification"|"mam: device_policy change (no WS push wired; clients refresh on next check-in)"))).map(|mut v|{v.as_object_mut().unwrap().remove("time");v}).collect();
    json!(entries)
}
fn go_off(enabled: bool) -> String {
    include_str!("../../../../mailserver/cmd/mailserverd/testdata/worker_launch_inventory.golden")
        .lines()
        .filter_map(|line| {
            let mut p = line.split('|');
            let kind = p.next()?;
            let name = p.next()?;
            (matches!(kind, "named" | "managed" | "cron-task")
                && !matches!(
                    name,
                    "http-h2c"
                        | "db-listener"
                        | "config-reload"
                        | "session-denylist-refresh"
                        | "auth-chain-reload"
                )
                && (!enabled || name != "mdm-notify"))
                .then_some(name)
        })
        .collect::<Vec<_>>()
        .join(",")
}
async fn snapshot(c: &tokio_postgres::Client, user: i64) -> Result<Value, BoxError> {
    let devices:Vec<String>=c.query("SELECT jsonb_build_object('id',id,'user_id',user_id,'device_name',device_name,'enroll_state',enroll_state)::text FROM devices WHERE user_id=$1 ORDER BY id",&[&user]).await?.iter().map(|r|r.get::<_,String>(0).replace(&format!("\"user_id\": {user}"),"\"user_id\": \"<owner>\"")).collect();
    let audits: i64 = c
        .query_one(
            "SELECT count(*) FROM admin_audit_log WHERE user_id=$1",
            &[&user],
        )
        .await?
        .get(0);
    Ok(json!({"devices":devices,"audit_count":audits}))
}
#[tokio::test]
async fn mdm_notify_seed_plus_one_tick_and_go_off_switch() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("mdm-notify") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "dev3-mdm-observer").await?;
    owner.execute("INSERT INTO devices(id,user_id,fingerprint,hmac_secret,device_name) VALUES(987501,$1,'dev3-observer','secret','Observer phone')",&[&a.user]).await?;
    let result=async{
 let recording=std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();let mut observations=Vec::new();
 for enabled in [true,false]{
 let count=Arc::new(AtomicUsize::new(0));let outbound=count.clone();
 let s3=common::fake_upstream(move |_|{outbound.fetch_add(1,Ordering::SeqCst);async{hyper::Response::new(common::full(""))}}).await;
 let mut process=None;let mut log=None;
 let go=if recording{common::go_oracle::start_named_with_env(&db,s3,"gofree-devices3-mdm",&[("GO_WORKERS_OFF",go_off(enabled)),("LOG_LEVEL","debug".into())]).await?}else{None};
 if !recording{
 let socket = setjoin_conformance::ports::listener().await;let address=socket.local_addr()?;drop(socket);
 let path=Log(std::env::temp_dir().join(format!("gofree-devices3-mdm-{}-{enabled}.log",std::process::id())));
 if let Ok(ledger)=std::env::var("GOFREE_RESOURCE_LEDGER"){use std::io::Write;writeln!(std::fs::OpenOptions::new().append(true).open(ledger)?,"Planned owned gofree-devices3-mdm-{enabled}, log {}",path.0.display())?;}
 let output=std::fs::File::create(&path.0)?;
 let mut p=Process(Command::new(env!("CARGO_BIN_EXE_setjoin-gateway")).arg0("gofree-devices3-mdm").env_clear().env("GATEWAY_LISTEN",address.to_string()).env("GATEWAY_ENABLED","false").env("RUST_WORKERS_ON",if enabled{"mdm-notify"}else{""}).env("GO_WORKERS_OFF",if enabled{"mdm-notify"}else{""}).stdout(Stdio::null()).stderr(output).spawn()?);
 let mut ready=false;
 for _ in 0..300{if tokio::net::TcpStream::connect(address).await.is_ok(){ready=true;break;}if let Some(status)=p.0.try_wait()?{return Err(format!("Rust mdm-notify exited {status}: {}",std::fs::read_to_string(&path.0)?).into());}tokio::time::sleep(std::time::Duration::from_millis(10)).await;}
 if !ready{return Err("Rust mdm-notify did not bind".into());}
 process=Some(p);log=Some(path);
 }
 let before=snapshot(&owner,a.user).await?;let baseline=count.load(Ordering::SeqCst);
 let mut seen=db.listen("device_policy").await?;
 let inputs=[r#"{"device_id":987501,"version":2,"action":"wipe_armed"}"#,r#"{"device_id":0,"version":3,"action":"policy_updated"}"#,"not JSON"];
 for payload in inputs{owner.execute("SELECT pg_notify('device_policy',$1)",&[&payload]).await?;}
 let delivered=seen.drain(&owner).await?;
 if delivered.len()!=3{return Err("seed notifications were not committed".into());}
 // Subscription rejection is structural; the barrier above proves all seed
 // events committed. Allow buffered process logs to reach their file as well.
 tokio::time::sleep(std::time::Duration::from_millis(100)).await;
 let logs=if let Some(go)=&go{go.logs()?}else{std::fs::read_to_string(&log.as_ref().ok_or("log")?.0)?};
 let msgs=messages(&logs);
 if recording&&(!msgs.as_array().is_some_and(|v|v.len()==2)||msgs[0]["error"]!="channel \"device_policy\" is not in the dispatcher's NOTIFY channel grammar"){return Err(format!("Go MDM subscription behavior changed: {msgs}").into());}
 if recording {
 let started=logs.lines().filter_map(|l|serde_json::from_str::<Value>(l).ok()).any(|v|v["msg"]=="background worker started"&&v["worker"]=="mdm-notify");
 if started!=enabled{return Err("GO_WORKERS_OFF failed to stop precisely the Go MDM goroutine".into());}
 }
 let after=snapshot(&owner,a.user).await?;
 let delta=count.load(Ordering::SeqCst)-baseline;
 observations.push(json!({"go_worker_enabled":enabled,"inputs":inputs,"messages":msgs,"before":before,"after":after,"outbound":delta}));
 if let Some(mut p)=process{unsafe{libc::kill(p.0.id() as i32,libc::SIGTERM);}
 let mut stopped=false;for _ in 0..300{if let Some(status)=p.0.try_wait()?{if !status.success(){return Err(format!("MDM task failed to drain: {status}").into());}stopped=true;break;}tokio::time::sleep(std::time::Duration::from_millis(10)).await;}if !stopped{return Err("MDM observer task did not stop".into());}}
 drop(go);
 }
 let file=std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/offline/goldens/worker-mdm-notify.json");
 let observation=json!(observations);
 if recording{let value=json!({"format":1,"route":"worker mdm-notify","case":"seed-plus-one-tick","go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation});if file.exists(){golden::compare(&serde_json::from_slice::<Value>(&std::fs::read(file)?)?,&value)?;}else{golden::record(&file,&value)?;}}
 else{let expected:Value=serde_json::from_slice(&std::fs::read(file)?)?;golden::compare(&expected["observation"],&observation)?;}
 Ok::<_,BoxError>(())
 }.await;
    fixture::remove(&owner, &a).await?;
    result
}
