//! Immutable frozen-Go IMAP transcripts replayed at the listener's TCP boundary,
//! with the recorded audit/credential effects compared per session.
mod common;
use common::*;
use setjoin_imap::{ProtocolSessionRegistry, RevocationRow};
use std::{
    sync::Arc,
    time::{Duration, SystemTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
};

enum Stream {
    Plain(TcpStream),
    Tls(Box<tokio_rustls::client::TlsStream<TcpStream>>),
}
impl Stream {
    async fn write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        match self {
            Stream::Plain(s) => s.write_all(bytes).await,
            Stream::Tls(s) => s.write_all(bytes).await,
        }
    }
    async fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf).await,
            Stream::Tls(s) => s.read(buf).await,
        }
    }
}

/// Read until `want` bytes arrived, EOF, or the deadline; never hangs.
async fn read_upto(stream: &mut Stream, want: usize, wait: Duration) -> Vec<u8> {
    let mut out = Vec::new();
    let deadline = tokio::time::Instant::now() + wait;
    let mut chunk = [0u8; 8192];
    while out.len() < want {
        match tokio::time::timeout_at(deadline, stream.read(&mut chunk)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
            Ok(Ok(n)) => out.extend_from_slice(&chunk[..n]),
        }
    }
    out
}

async fn replay(filter: impl Fn(&serde_json::Value) -> bool, case: &str) {
    let Some(db) = setjoin_conformance::harness::Db::for_case(case) else {
        return;
    };
    let owner = db.connect().await.unwrap();
    let outcome = {
        use futures_util::FutureExt;
        std::panic::AssertUnwindSafe(run(&db, &owner, filter))
            .catch_unwind()
            .await
    };
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic)
    }
}

async fn run(
    db: &setjoin_conformance::harness::Db,
    owner: &tokio_postgres::Client,
    filter: impl Fn(&serde_json::Value) -> bool,
) {
    seed(owner).await;
    let hashes: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/password-hashes.json")).unwrap();
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/go-sessions.json")).unwrap();
    let mut ran = 0;
    for session in corpus.as_array().unwrap().iter().filter(|s| filter(s)) {
        ran += 1;
        let name = session["name"].as_str().unwrap();
        reset_fixture(owner, &hashes).await;
        let registry = Arc::new(ProtocolSessionRegistry::default());
        let mut server = server(db, session["transport"].as_str().unwrap());
        if let Some(max) = session["per_user_max"].as_i64() {
            server = server.with_per_user_max(max);
        }
        if session["registry"] == true {
            server = server.with_session_registry(registry.clone());
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, rx) = watch::channel(false);
        let task = tokio::spawn(Arc::new(server).serve(listener, rx));
        let tls = session["transport"] == "tls";
        let mut conns: Vec<Option<Stream>> = Vec::new();
        for (i, step) in session["steps"].as_array().unwrap().iter().enumerate() {
            let at = format!("{name} step {i}");
            if let Some(ms) = step["sleep_ms"].as_u64() {
                tokio::time::sleep(Duration::from_millis(ms)).await;
            }
            if let Some(action) = step.get("action") {
                assert_eq!(action["kind"], "revoke_all", "{at}");
                registry.apply(&RevocationRow {
                    user_id: action["user"].as_i64().unwrap(),
                    not_before: SystemTime::now()
                        + Duration::from_secs(action["not_before_offset_s"].as_u64().unwrap()),
                    expires_at: None,
                    scope_all: true,
                });
                continue;
            }
            let idx = step["conn"].as_u64().unwrap_or(0) as usize;
            while conns.len() <= idx {
                conns.push(None);
            }
            if conns[idx].is_none() {
                let socket = TcpStream::connect(addr).await.unwrap();
                conns[idx] = Some(if tls {
                    Stream::Tls(Box::new(tls_client(socket).await))
                } else {
                    Stream::Plain(socket)
                });
            }
            let stream = conns[idx].as_mut().unwrap();
            let request = step["request"].as_str().unwrap();
            if !request.is_empty() {
                // A write to an already-closed peer is a recorded outcome, not a failure.
                let _ = stream.write(request.as_bytes()).await;
            }
            let expected = step["response"].as_str().unwrap().as_bytes();
            let wait = match step["until"].as_str().unwrap() {
                "eof" | "none" => Duration::from_millis(1500),
                _ => Duration::from_secs(5),
            };
            let actual = read_upto(stream, expected.len(), wait).await;
            assert_eq!(
                String::from_utf8_lossy(&actual),
                String::from_utf8_lossy(expected),
                "{at}"
            );
            if step["until"] == "eof" {
                let mut one = [0u8; 1];
                let end = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut one))
                    .await
                    .unwrap_or(Ok(1));
                assert!(matches!(end, Ok(0) | Err(_)), "{at}: server must close");
            }
            if step["upgrade"] == true {
                let Some(Stream::Plain(socket)) = conns[idx].take() else {
                    panic!("{at}: upgrade needs a plain stream")
                };
                conns[idx] = Some(Stream::Tls(Box::new(tls_client(socket).await)));
            }
        }
        // Nothing unrecorded may follow the last recorded byte.
        for (i, stream) in conns.iter_mut().enumerate() {
            if let Some(stream) = stream {
                let extra = read_upto(stream, 1, Duration::from_millis(200)).await;
                assert!(
                    extra.is_empty(),
                    "{name} conn {i}: unrecorded output {:?}",
                    String::from_utf8_lossy(&extra)
                );
            }
        }
        drop(conns);
        tokio::time::sleep(Duration::from_millis(100)).await;
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
        assert_effects(owner, session, &hashes, name).await;
    }
    assert!(ran > 0, "filter matched no recorded session");
}

#[tokio::test]
async fn recorded_plain_listener_sessions() {
    replay(|s| s["transport"] == "plain", "imap-plain").await
}
#[tokio::test]
async fn recorded_starttls_listener_sessions() {
    replay(|s| s["transport"] == "starttls", "imap-starttls").await
}
#[tokio::test]
async fn recorded_implicit_tls_listener_sessions() {
    replay(|s| s["transport"] == "tls", "imap-tls").await
}
