//! Immutable frozen-Go FETCH/SEARCH/STORE/UID transcripts (#344) replayed at the
//! listener's TCP boundary: reply bytes, nothing unrecorded behind them, and the
//! recorded message flag, tag counter and audit effects.
use crate::common;
use common::server;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
};

/// Wave 2.7 (#554): authenticated LOGIN/AUTHENTICATE/CAPABILITY replies now
/// advertise `CONDSTORE QRESYNC` (recorded in oracle/divergences.json).
fn wave27_expected_reply(expected: &str, authed: bool) -> String {
    let mut out = String::with_capacity(expected.len() + 36);
    for line in expected.split_inclusive("\r\n") {
        let is_auth_cap = line.contains("OK [CAPABILITY ")
            && (line.contains("LOGIN completed") || line.contains("AUTHENTICATE completed"));
        let is_post_auth_cap_list = authed && line.starts_with("* CAPABILITY ");
        if (is_auth_cap || is_post_auth_cap_list) && !line.contains("CONDSTORE") {
            out.push_str(&line.replacen(
                "IMAP4rev2 LOGIN-REFERRALS ID ENABLE",
                "IMAP4rev2 LOGIN-REFERRALS ID ENABLE CONDSTORE QRESYNC",
                1,
            ));
        } else {
            out.push_str(line);
        }
    }
    out
}

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

/// The recorder's observation queries; both sides read them as `to_jsonb(row)`.
const OBSERVE: [(&str, &str); 3] = [
    (
        "messages",
        "SELECT message_id, is_read, is_flagged, is_answered, is_draft, is_deleted \
         FROM messages WHERE mailbox_id BETWEEN 9344021 AND 9344029 ORDER BY message_id",
    ),
    (
        "tags",
        "SELECT mailbox_id, name, total_count, unread_count, jmap_state \
         FROM tags WHERE mailbox_id BETWEEN 9344021 AND 9344029 ORDER BY mailbox_id, name",
    ),
    (
        "audit",
        "SELECT mailbox_id, actor_user_id, action, message_id \
         FROM mailbox_audit_log WHERE mailbox_id BETWEEN 9344021 AND 9344029 ORDER BY id",
    ),
];

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
        serde_json::from_str(include_str!("../oracle/messages-go-sessions.json")).unwrap();
    let outcome = {
        use futures_util::FutureExt;
        std::panic::AssertUnwindSafe(run(&db, &owner, &corpus, only))
            .catch_unwind()
            .await
    };
    owner
        .batch_execute(include_str!("../oracle/messages-cleanup.sql"))
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
            include_str!("../oracle/messages-cleanup.sql"),
            include_str!("../oracle/messages-seed.sql"),
        ] {
            owner.batch_execute(sql).await.unwrap();
        }
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, rx) = watch::channel(false);
        let task = tokio::spawn(Arc::new(server(db, "plain")).serve(listener, rx));
        let mut conn: Option<TcpStream> = None;
        let mut authed = false;
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
            if conn.is_none() {
                conn = Some(TcpStream::connect(addr).await.unwrap());
            }
            let stream = conn.as_mut().unwrap();
            let request = step["request"].as_str().unwrap();
            if !request.is_empty() {
                stream.write_all(request.as_bytes()).await.unwrap();
            }
            let raw_expected = step["response"].as_str().unwrap();
            if raw_expected.contains("LOGIN completed")
                || raw_expected.contains("AUTHENTICATE completed")
            {
                authed = true;
            }
            let expected_str = wave27_expected_reply(raw_expected, authed);
            let expected = expected_str.as_bytes();
            let actual = read_upto(stream, expected.len(), Duration::from_secs(5)).await;
            assert_eq!(
                String::from_utf8_lossy(&actual),
                String::from_utf8_lossy(expected),
                "{at}: {request:?}"
            );
        }
        if let Some(stream) = conn.as_mut() {
            let extra = read_upto(stream, 1, Duration::from_millis(200)).await;
            assert!(
                extra.is_empty(),
                "{name}: unrecorded output {:?}",
                String::from_utf8_lossy(&extra)
            );
        }
        drop(conn);
        tokio::time::sleep(Duration::from_millis(200)).await;
        stop.send(true).unwrap();
        task.await.unwrap().unwrap();
        for (key, query) in OBSERVE {
            assert_eq!(
                observe(owner, query).await,
                session["effects"][key],
                "{name}: effect {key}"
            );
        }
    }
    assert!(ran > 0, "no recorded session matched");
}

#[tokio::test]
async fn recorded_message_sessions() {
    replay(None, "imap-messages").await
}
