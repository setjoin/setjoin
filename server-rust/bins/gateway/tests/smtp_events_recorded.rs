//! Frozen Go SMTP delivery events replay through the shared gateway Dispatcher.
mod common;
mod drain_oracle;
use common::webhook_receiver as hooks;
use drain_oracle::{settle, BoxError, GoTick};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smtp_received_webhooks() -> Result<(), BoxError> {
    let Some(db) = setjoin_conformance::harness::Db::for_case("smtp1-webhooks") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let oracle =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../crates/protocols/smtp/oracle");
    let read = |name: &str| std::fs::read_to_string(oracle.join(name));
    owner.batch_execute(&read("cleanup.sql")?).await?;
    owner.batch_execute(&read("seed.sql")?).await?;
    let seen = hooks::Seen::default();
    let receiver = hooks::receiver(seen.clone()).await;
    let recording = std::env::var_os("GOFREE_RECORD_DRAIN").is_some();
    let result=async {
  hooks::clear(&owner).await?;
  for (user,path,scope,active,types) in [(9348011,"/org","organization",true,"[\"mail.received\"]"),(9348011,"/self","self",true,"[\"mail.received\"]"),(9348012,"/foreign","self",true,"[\"mail.received\"]"),(9348011,"/inactive","organization",false,"[\"mail.received\"]"),(9348011,"/other-type","organization",true,"[\"mail.sent\"]")] {
   hooks::subscribe(&owner,user,receiver,path,types,scope,active).await?;
  }
  let dispatcher=hooks::unguarded(&db.dsn)?;
  if recording {
   let docker=std::env::var("SMTP1_GO_CACHE").ok().map(|p|vec!["-v".into(),format!("{p}:/src/test-results/gofree-drainw/go-cache")]).unwrap_or_default();
   GoTick{package:"internal/smtp",overlay:"smtp_received_tick_test.go.txt",test:"TestGoFreeSMTPReceived",file:"gofree_smtp_received_test.go",env:vec![("GOFREE_DRAIN_DSN".into(),db.dsn.clone()),("GOFREE_WEBHOOK_MASTER".into(),hooks::MASTER.into()),("SMTP_ORACLE_DIR".into(),"/src/server-rust/crates/protocols/smtp/oracle".into())],docker}.run_with(&[("internal/webhook","gofree_unguarded_export.go","webhook_unguarded_export.go.txt")])?;
  }else{
   let listener=TcpListener::bind("127.0.0.1:0").await?;let addr=listener.local_addr()?;let(stop,rx)=watch::channel(false);
   let server=setjoin_smtp::Server::new().with_database(setjoin_pg::workers::WorkerDatabase::new(&db.dsn)?).with_delivery_events(Arc::new(setjoin_gateway::smtp_events::DeliveryEvents(dispatcher.clone())));
   let task=tokio::spawn(Arc::new(server).serve(listener,rx));
   let mut socket=TcpStream::connect(addr).await?;
   let corpus:Value=serde_json::from_str(&read("delivery-go.json")?)?;
   for step in corpus[0]["steps"].as_array().unwrap(){
    socket.write_all(step["send"].as_str().unwrap().as_bytes()).await?;
    let reply=step["reply"].as_str().unwrap_or("");let mut got=vec![0;reply.len()];
    tokio::time::timeout(Duration::from_secs(15),socket.read_exact(&mut got)).await??;
    assert_eq!(got,reply.as_bytes());
   }
   drop(socket);stop.send(true)?;task.await??;
  }
  dispatcher.shutdown().await;
  let observation=json!({"requests":hooks::requests(&seen),"deliveries":hooks::deliveries(&owner).await?});
  settle("smtp-received-webhooks",observation,recording)
 }.await;
    let _ = hooks::clear(&owner).await;
    owner.batch_execute(&read("cleanup.sql")?).await?;
    result
}
