//! Lost PostgreSQL COMMIT acknowledgements observed through SMTP and the DB.
#[path = "../../../../bins/gateway/tests/common/commit.rs"]
mod commit;
use commit::{commit_cut_proxy, CommitCut};
use futures_util::FutureExt;
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinHandle,
};
struct OwnedTask<T>(JoinHandle<T>);
impl<T> Drop for OwnedTask<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Multiplex the foundation's one-connection fault seam: intake/monitoring reads
/// pass through, while the delivery transaction's actual COMMIT is intercepted.
async fn proxy(
    dsn: &str,
    cut: CommitCut,
) -> (
    String,
    watch::Sender<bool>,
    JoinHandle<()>,
    Arc<AtomicUsize>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (template, first) = commit_cut_proxy(dsn, cut).await;
    let config: tokio_postgres::Config = template.parse().unwrap();
    let first_port = config.get_ports()[0];
    // This prefix is produced by the foundation helper, not parsed from a request.
    // Keep its already escaped credential/options tail verbatim; never print it.
    let (_, tail) = template.split_once(" port=").unwrap();
    let tail = tail.split_once(' ').map(|(_, tail)| tail).unwrap_or("");
    let proxied = format!("host=127.0.0.1 port={port} {tail}");
    let backend = dsn.to_owned();
    let (stop, mut rx) = watch::channel(false);
    let cuts = Arc::new(AtomicUsize::new(0));
    let seen = cuts.clone();
    let task = tokio::spawn(async move {
        let mut first = Some((first_port, first));
        let mut bridges = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
             _=rx.changed()=>break,
             accepted=listener.accept()=>{
              let(mut client,_)=accepted.unwrap();
              let(port,inner)=if let Some(first)=first.take(){first}else{let(dsn,task)=commit_cut_proxy(&backend,cut).await;let cfg:tokio_postgres::Config=dsn.parse().unwrap();(cfg.get_ports()[0],task)};
              let seen=seen.clone();
              bridges.spawn(async move{
               let mut inner=OwnedTask(inner);
               let mut server=TcpStream::connect(("127.0.0.1",port)).await.unwrap();
               let _=tokio::io::copy_bidirectional(&mut client,&mut server).await;
               if matches!((&mut inner.0).await,Ok(Ok(_))){seen.fetch_add(1,Ordering::SeqCst);}
              });
             },
             Some(_)=bridges.join_next()=>{}
            }
        }
        if let Some((_, task)) = first.take() {
            task.abort();
            let _ = task.await;
        }
        bridges.abort_all();
        while bridges.join_next().await.is_some() {}
    });
    (proxied, stop, task, cuts)
}
async fn lost_commit(cut: CommitCut) {
    let _serial = SERIAL.lock().await;
    let db = setjoin_conformance::harness::Db::for_case("smtp1-commit-cut").unwrap();
    let owner = db.connect().await.unwrap();
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    owner
        .batch_execute(include_str!("../oracle/seed.sql"))
        .await
        .unwrap();
    let (dsn, proxy_stop, proxy_task, cuts) = proxy(&db.dsn, cut).await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let server = setjoin_smtp::Server::new()
        .with_database(setjoin_pg::workers::WorkerDatabase::new(&dsn).unwrap());
    let task = tokio::spawn(Arc::new(server).serve(listener, rx));
    let outcome = std::panic::AssertUnwindSafe(async {
        let mut socket = TcpStream::connect(addr).await.unwrap();
        let corpus: serde_json::Value =
            serde_json::from_str(include_str!("../oracle/delivery-go.json")).unwrap();
        for (index, step) in corpus[0]["steps"]
            .as_array()
            .unwrap()
            .iter()
            .take(6)
            .enumerate()
        {
            socket
                .write_all(step["send"].as_str().unwrap().as_bytes())
                .await
                .unwrap();
            let expected = if index == 5 {
                "451 4.3.0 Temporary failure, please try again later\r\n"
            } else {
                step["reply"].as_str().unwrap()
            };
            let mut actual = vec![0; expected.len()];
            tokio::time::timeout(Duration::from_secs(15), socket.read_exact(&mut actual))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(
                actual,
                expected.as_bytes(),
                "a lost COMMIT must never report success"
            );
        }
        socket.write_all(b"QUIT\r\n").await.unwrap();
        let mut end = Vec::new();
        tokio::time::timeout(Duration::from_secs(15), socket.read_to_end(&mut end))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(end, b"221 Bye\r\n");
        tokio::time::timeout(Duration::from_secs(3), async {
            while cuts.load(Ordering::SeqCst) == 0 {
                tokio::task::yield_now().await
            }
        })
        .await
        .unwrap();
        let count: i64 = owner
            .query_one(
                "SELECT count(*) FROM messages WHERE mailbox_id=9348021",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let state: i64 = owner
            .query_one(
                "SELECT jmap_email_state FROM mailboxes WHERE id=9348021",
                &[],
            )
            .await
            .unwrap()
            .get(0);
        let expected = if cut == CommitCut::BeforeCommit { 0 } else { 1 };
        assert_eq!(count, expected, "commit outcome");
        assert_eq!(state, expected, "atomic state bump");
    })
    .catch_unwind()
    .await;
    let _ = stop.send(true);
    let server_result = task.await;
    let _ = proxy_stop.send(true);
    proxy_task.await.unwrap();
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic)
    }
    server_result.unwrap().unwrap();
}
#[tokio::test]
async fn commit_not_sent_returns_temporary_failure_and_leaves_no_delivery() {
    lost_commit(CommitCut::BeforeCommit).await;
}
#[tokio::test]
async fn lost_commit_ack_returns_temporary_failure_with_one_committed_delivery() {
    lost_commit(CommitCut::AfterCommit).await;
}

/// The cases share one database and fixed fixtures: libtest's threads must take turns.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
