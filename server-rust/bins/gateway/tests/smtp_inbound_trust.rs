//! Native SMTP consumes the exact cache invalidated by the real config listener.
use futures_util::FutureExt;
use serde_json::Value;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::{oneshot, watch},
};

struct Flags;
impl setjoin_smtp::submission::Flags for Flags {
    fn enabled(&self, key: &str) -> bool {
        key == "feature.smime_verify"
    }
}
async fn deliver(address: std::net::SocketAddr, case: &Value, suffix: &str) {
    let mut peer = BufReader::new(TcpStream::connect(address).await.unwrap());
    let name = case["name"].as_str().unwrap();
    for step in case["steps"].as_array().unwrap() {
        let send = step["send"]
            .as_str()
            .unwrap()
            .replace(&format!("<{name}@"), &format!("<{name}{suffix}@"));
        peer.get_mut().write_all(send.as_bytes()).await.unwrap();
        let mut reply = String::new();
        for _ in 0..step["lines"].as_u64().unwrap() {
            let mut line = String::new();
            assert!(
                tokio::time::timeout(Duration::from_secs(10), peer.read_line(&mut line))
                    .await
                    .unwrap()
                    .unwrap()
                    > 0
            );
            reply.push_str(&line);
        }
        assert_eq!(reply, step["reply"].as_str().unwrap());
    }
}
#[tokio::test]
async fn inbound_badges_follow_the_shared_trust_listener_cache() {
    let db = setjoin_conformance::harness::Db::for_case("smtp6-trust").unwrap();
    let owner = db.connect().await.unwrap();
    let corpus: Value = serde_json::from_str(include_str!(
        "../../../crates/protocols/smtp/oracle/security-smime-go.json"
    ))
    .unwrap();
    let case = &corpus[0];
    let cleanup = include_str!("../../../crates/protocols/smtp/oracle/cleanup.sql");
    owner.batch_execute(cleanup).await.unwrap();
    owner
        .batch_execute(include_str!(
            "../../../crates/protocols/smtp/oracle/seed.sql"
        ))
        .await
        .unwrap();
    owner
        .batch_execute(case["setup_sql"].as_str().unwrap())
        .await
        .unwrap();
    let cache = Arc::new(setjoin_mail_security::smime::trust::TrustCache::new());
    let listener = Arc::new(setjoin_gateway::smime_trust::SmimeTrustListener::new(
        cache.clone(),
        db.dsn.clone(),
    ));
    let (stop_listener, stopped) = oneshot::channel();
    let task_listener = tokio::spawn(listener.clone().run_until(async {
        let _ = stopped.await;
    }));
    let smtp = Arc::new(
        setjoin_smtp::Server::new()
            .with_database(setjoin_pg::workers::WorkerDatabase::new(&db.dsn).unwrap())
            .with_flags(Arc::new(Flags))
            .with_inbound_config(setjoin_smtp::inbound::Config {
                trust_cache: cache.clone(),
                ..Default::default()
            }),
    );
    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let (stop_smtp, stopped) = watch::channel(false);
    let task_smtp = tokio::spawn(smtp.serve(socket, stopped));
    let outcome=std::panic::AssertUnwindSafe(async{
        tokio::time::timeout(Duration::from_secs(10),async {while !listener.listening(){tokio::time::sleep(Duration::from_millis(10)).await;}}).await.unwrap();
        deliver(address,case,"-first").await;
        assert_eq!(cache.cached_domains(),1,"SMTP must consume the listener's cache");
        owner.batch_execute("DELETE FROM smime_trust_anchors WHERE label='smtp6-fixture'").await.unwrap();
        deliver(address,case,"-cached").await;
        owner.query_one("SELECT pg_notify('smime_trust_changed','')",&[]).await.unwrap();
        tokio::time::timeout(Duration::from_secs(10),async {while cache.cached_domains()!=0{tokio::time::sleep(Duration::from_millis(10)).await;}}).await.unwrap();
        deliver(address,case,"-revoked").await;
        for (suffix,status) in [("-first","valid"),("-cached","valid"),("-revoked","untrusted")]{
            let message=format!("<{}{suffix}@smtp6.test>",case["name"].as_str().unwrap());
            assert_eq!(owner.query_one("SELECT smime_status FROM messages WHERE mailbox_id=9348021 AND message_id=$1",&[&message]).await.unwrap().get::<_,String>(0),status);
        }
    }).catch_unwind().await;
    let _ = stop_smtp.send(true);
    task_smtp.await.unwrap().unwrap();
    let _ = stop_listener.send(());
    task_listener.await.unwrap();
    owner
        .batch_execute(case["teardown_sql"].as_str().unwrap())
        .await
        .unwrap();
    owner.batch_execute(cleanup).await.unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic);
    }
}
