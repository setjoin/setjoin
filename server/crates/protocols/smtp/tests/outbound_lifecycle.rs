//! Scheduling and cancellation observed by a real silent MX socket.
use futures_util::future::BoxFuture;
use setjoin_pg::workers::WorkerDatabase;
use setjoin_smtp::outbound::{Network, OutboundWorker, RawSource};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    sync::oneshot,
};
struct Peer(std::net::SocketAddr);
impl Network for Peer {
    fn mx<'a>(&'a self, _domain: &'a str) -> BoxFuture<'a, Result<Vec<String>, String>> {
        Box::pin(async { Ok(vec!["localhost.".into()]) })
    }
    fn connect<'a>(&'a self, _host: &'a str) -> BoxFuture<'a, Result<TcpStream, String>> {
        Box::pin(async move { TcpStream::connect(self.0).await.map_err(|e| e.to_string()) })
    }
}
struct InlineOnly;
impl RawSource for InlineOnly {
    fn get<'a>(&'a self, _: &'a str) -> BoxFuture<'a, Result<Vec<u8>, String>> {
        Box::pin(async { panic!("fixture raw_ref is inline") })
    }
}
#[tokio::test]
async fn worker_waits_for_its_first_tick_and_cancellation_closes_a_silent_mx() {
    let _serial = SERIAL.lock().await;
    let Some(db) = setjoin_conformance::harness::Db::for_case("smtp3-lifecycle") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    owner
        .batch_execute(include_str!("../oracle/outbound-cleanup.sql"))
        .await
        .unwrap();
    owner
        .batch_execute(include_str!("../oracle/seed.sql"))
        .await
        .unwrap();
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/outbound-go.json")).unwrap();
    owner
        .batch_execute(corpus[0]["case"]["sql"].as_str().unwrap())
        .await
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let worker = OutboundWorker::new(
        WorkerDatabase::new(&db.dsn).unwrap(),
        Arc::new(InlineOnly),
        Arc::new(Peer(listener.local_addr().unwrap())),
        "fixture.local".into(),
    );
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(worker.run_until(async {
        let _ = stopped.await;
    }));
    assert!(
        tokio::time::timeout(Duration::from_millis(300), listener.accept())
            .await
            .is_err(),
        "Go has no eager first tick"
    );
    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(12), listener.accept())
        .await
        .unwrap()
        .unwrap();
    socket.write_all(b"220 silent MX\r\n").await.unwrap();
    let mut socket = BufReader::new(socket);
    let mut line = String::new();
    tokio::time::timeout(Duration::from_secs(2), socket.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(line, "EHLO fixture.local\r\n");
    stop.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .expect("worker must drain on cancellation")
        .unwrap();
    line.clear();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(2), socket.read_line(&mut line))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    owner
        .batch_execute(include_str!("../oracle/outbound-cleanup.sql"))
        .await
        .unwrap();
}

/// The cases share one database and fixed fixtures: libtest's threads must take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
