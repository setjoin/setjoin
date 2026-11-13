//! Immutable frozen-Go LIST/STATUS/EXPUNGE/CLOSE/CREATE/DELETE/RENAME/COPY/MOVE/
//! APPEND/IDLE transcripts (#345) replayed at the listener's TCP boundary: reply
//! bytes, nothing unrecorded behind them, and the recorded row effects (the query
//! text is oracle/session-observe.json, shared with the Go recorder).
mod common;
use common::server;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
};

async fn read_upto(stream: &mut TcpStream, want: usize, wait: Duration) -> Vec<u8> {
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

async fn observe(owner: &tokio_postgres::Client, query: &str) -> serde_json::Value {
    let rows = owner
        .query(&format!("SELECT to_jsonb(r)::text FROM ({query}) r"), &[])
        .await
        .unwrap();
    serde_json::Value::Array(
        rows.iter()
            .map(|r| serde_json::from_str(&r.get::<_, String>(0)).unwrap())
            .collect(),
    )
}

async fn replay(only: Option<&str>, case: &str) {
    let Some(db) = setjoin_conformance::harness::Db::for_case(case) else {
        return;
    };
    let owner = db.connect().await.unwrap();
    let corpus: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/session-go-sessions.json")).unwrap();
    let outcome = {
        use futures_util::FutureExt;
        std::panic::AssertUnwindSafe(run(&db, &owner, &corpus, only))
            .catch_unwind()
            .await
    };
    owner
        .batch_execute(include_str!("../oracle/session-cleanup.sql"))
        .await
        .unwrap();
    if let Err(panic) = outcome {
        std::panic::resume_unwind(panic)
    }
}

async fn run(
    db: &setjoin_conformance::harness::Db,
    owner: &tokio_postgres::Client,
    corpus: &serde_json::Value,
    only: Option<&str>,
) {
    let mut ran = 0;
    for session in corpus.as_array().unwrap() {
        let name = session["name"].as_str().unwrap();
        if only.is_some_and(|o| o != name) {
            continue;
        }
        ran += 1;
        for sql in [
            include_str!("../oracle/session-cleanup.sql"),
            include_str!("../oracle/session-seed.sql"),
        ] {
            owner.batch_execute(sql).await.unwrap();
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, rx) = watch::channel(false);
        let task = tokio::spawn(Arc::new(server(db, "plain")).serve(listener, rx));
        let mut conns: Vec<Option<TcpStream>> = vec![None, None];
        for (i, step) in session["steps"].as_array().unwrap().iter().enumerate() {
            let at = format!("{name} step {i}");
            if let Some(action) = step.get("action") {
                assert_eq!(action["kind"], "sql", "{at}");
                owner
                    .batch_execute(action["sql"].as_str().unwrap())
                    .await
                    .unwrap();
                continue;
            }
            let idx = step.get("conn").and_then(|c| c.as_u64()).unwrap_or(0) as usize;
            if conns[idx].is_none() {
                conns[idx] = Some(TcpStream::connect(addr).await.unwrap());
            }
            let stream = conns[idx].as_mut().unwrap();
            let request = step["request"].as_str().unwrap();
            if !request.is_empty() {
                stream.write_all(request.as_bytes()).await.unwrap();
            }
            if step.get("shutdown").is_some_and(|v| v == true) {
                stream.shutdown().await.unwrap();
            }
            let expected = step["response"].as_str().unwrap().as_bytes();
            let actual = read_upto(stream, expected.len(), Duration::from_secs(5)).await;
            assert_eq!(
                String::from_utf8_lossy(&actual),
                String::from_utf8_lossy(expected),
                "{at}: {request:?}"
            );
        }
        for stream in conns.iter_mut().flatten() {
            let extra = read_upto(stream, 1, Duration::from_millis(200)).await;
            assert!(
                extra.is_empty(),
                "{name}: unrecorded output {:?}",
                String::from_utf8_lossy(&extra)
            );
        }
        drop(conns);
        tokio::time::sleep(Duration::from_millis(200)).await;
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
        let observe_sql: serde_json::Value =
            serde_json::from_str(include_str!("../oracle/session-observe.json")).unwrap();
        for (key, query) in observe_sql.as_object().unwrap() {
            let actual = observe(owner, query.as_str().unwrap()).await;
            let want = &session["effects"][key];
            if &actual != want {
                let brief =
                    |v: &serde_json::Value| v.to_string().chars().take(1500).collect::<String>();
                panic!(
                    "{name}: effect {key}\n actual: {}\n recorded: {}",
                    brief(&actual),
                    brief(want)
                );
            }
        }
    }
    assert!(ran > 0, "no recorded session matched");
}

#[tokio::test]
async fn recorded_session_commands() {
    replay(None, "imap-session").await
}

/// Debug aid: `IMAP_SESSION_ONLY=<name>` replays one recorded session.
#[tokio::test]
async fn recorded_session_commands_single() {
    if let Ok(name) = std::env::var("IMAP_SESSION_ONLY") {
        replay(Some(&name), "imap-session-single").await
    }
}
