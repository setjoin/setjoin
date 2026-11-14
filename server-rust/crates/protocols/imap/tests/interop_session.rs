//! The existing `test-imap` container image (plus a Python layer) runs CPython
//! `imaplib` against the Rust plaintext socket for STATUS, CREATE, RENAME, DELETE,
//! APPEND, COPY, MOVE, EXPUNGE, CLOSE, IDLE and LIST (#345), on the corpus-3
//! fixture, and the database effects are checked afterwards. The client image is the pinned
//! `setjoin-interop-imap:local` (never built or removed here, #141) and the
//! client container is `--rm`; Docker is required, never skipped. The
//! client carries the same two Go-parity patches as `interop_client.py`.
mod common;
use common::server;
use std::{process::Command, sync::Arc};
use tokio::{net::TcpListener, sync::watch};

/// Pinned in `.github/ci/images.lock` and preloaded by the lane (`scripts/build-interop-images.sh`
/// on a dev host); the test never builds, tags or removes images (#141).
const IMAGE: &str = "setjoin-interop-imap:local";

#[tokio::test]
async fn test_imap_container_session_commands() {
    let Some(db) = setjoin_conformance::harness::Db::for_case("imap-interop-session") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    for sql in [
        include_str!("../oracle/session-cleanup.sql"),
        include_str!("../oracle/session-seed.sql"),
    ] {
        owner.batch_execute(sql).await.unwrap();
    }
    let pid = std::process::id();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(Arc::new(server(&db, "plain")).serve(listener, rx));
    let name = format!("gofree-imap3-interop-client-{pid}");
    let image_name = IMAGE.to_string();
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/interop_session_client.py"
    );
    let output = tokio::task::spawn_blocking(move || {
        Command::new("docker")
            .args([
                "run",
                "--pull",
                "never",
                "--rm",
                "--name",
                &name,
                "--network",
                "host",
                "-v",
                &format!("{script}:/client.py:ro"),
                "--entrypoint",
                "timeout",
                &image_name,
                "60",
                "python3",
                "/client.py",
                &port.to_string(),
            ])
            .output()
    })
    .await
    .unwrap()
    .unwrap();
    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
    let rows = |sql: &'static str| {
        let owner = &owner;
        async move {
            owner
                .query(&format!("SELECT to_jsonb(r)::text FROM ({sql}) r"), &[])
                .await
                .unwrap()
                .iter()
                .map(|r| serde_json::from_str::<serde_json::Value>(&r.get::<_, String>(0)).unwrap())
                .collect::<Vec<_>>()
        }
    };
    let memberships = rows(
        "SELECT m.message_id, t.name AS tag FROM message_tags mt \
         JOIN messages m ON m.id = mt.message_id AND m.received_at = mt.received_at \
         JOIN tags t ON t.id = mt.tag_id \
         WHERE m.mailbox_id = 9345021 AND t.name IN ('Dup','Project','Empty','Label') \
         ORDER BY t.name, m.message_id",
    )
    .await;
    let tags = rows(
        "SELECT name FROM tags WHERE mailbox_id = 9345021 AND name LIKE 'Interop%' ORDER BY name",
    )
    .await;
    let audited =
        rows("SELECT DISTINCT action FROM mailbox_audit_log WHERE mailbox_id = 9345021 ORDER BY 1")
            .await;
    let remaining = rows(
        "SELECT message_id FROM messages WHERE mailbox_id = 9345021 AND message_id = '<mid-3@imap3.test>'",
    )
    .await;
    owner
        .batch_execute(include_str!("../oracle/session-cleanup.sql"))
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "client failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let got: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    // Untagged lines depend on imaplib's tags; the checked facts are the verbs'
    // statuses and Go's recorded data (UIDVALIDITY/UIDs come from the fixture).
    let text = |key: &str| got[key].to_string();
    assert_eq!(got["login"], "OK", "{got}");
    assert_eq!(
        got["status"],
        serde_json::json!([
            "OK",
            "\"Project\" (MESSAGES 2 UNSEEN 1 UIDVALIDITY 4444 UIDNEXT 3) "
        ]),
        "{got}"
    );
    assert_eq!(got["create"], serde_json::json!(["OK"]));
    assert_eq!(got["rename"], serde_json::json!(["OK"]));
    assert_eq!(got["select_new"], "OK");
    assert_eq!(got["delete_selected"], serde_json::json!(["OK"]));
    assert_eq!(got["select_inbox"], "OK");
    assert!(text("append").contains("[APPENDUID 7777 1]"), "{got}");
    assert_eq!(got["copy"], serde_json::json!(["OK", "COPY completed"]));
    assert!(text("copy_again").starts_with("[\"NO\""), "{got}");
    assert!(text("copy_again").contains("[CANNOT]"), "{got}");
    assert_eq!(got["move"], serde_json::json!(["OK", "MOVE completed"]));
    assert_eq!(got["uid_copy"], serde_json::json!(["OK"]));
    assert_eq!(got["expunge"], serde_json::json!(["OK", "1", "2"]), "{got}");
    assert_eq!(got["idle_continuation"], "zz1 + idling");
    assert_eq!(got["idle_done"], "zz1 OK IDLE completed");
    assert_eq!(got["close"], serde_json::json!(["OK"]));
    // Go's LIST fails on the first NULL parent_id after one row.
    assert_eq!(got["list"], serde_json::json!(["NO"]));
    assert_eq!(got["logout"], "BYE");
    assert!(tags.is_empty(), "the selected folder was deleted: {tags:?}");
    assert_eq!(
        remaining,
        Vec::<serde_json::Value>::new(),
        "STORE+EXPUNGE removed message 1"
    );
    let pairs: Vec<(String, String)> = memberships
        .iter()
        .map(|v| {
            (
                v["tag"].as_str().unwrap().into(),
                v["message_id"].as_str().unwrap().into(),
            )
        })
        .collect();
    // Message 1 was copied to Project, then expunged everywhere with its row.
    assert!(
        !pairs.iter().any(|(_, m)| m == "<mid-3@imap3.test>"),
        "{pairs:?}"
    );
    assert!(
        pairs.contains(&("Empty".into(), "<mid-5@imap3.test>".into())),
        "{pairs:?}"
    );
    assert!(
        pairs.contains(&("Label".into(), "<mid-20@imap3.test>".into())),
        "{pairs:?}"
    );
    assert!(
        pairs
            .iter()
            .any(|(t, m)| t == "Dup" && m == "<append-1@setjoin.local>"),
        "{pairs:?}"
    );
    let audited: Vec<&str> = audited
        .iter()
        .map(|v| v["action"].as_str().unwrap())
        .collect();
    assert_eq!(
        audited,
        ["imap_copy", "imap_expunge", "imap_move", "imap_store"]
    );
}
