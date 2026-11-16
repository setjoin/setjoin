//! The existing `test-imap` container image (plus a Python layer) runs CPython
//! `imaplib` against the Rust plaintext socket for FETCH, SEARCH, STORE and UID
//! (#344), on the recorder's message fixture, and the database effects are
//! checked afterwards. The client image is the pinned `setjoin-interop-imap:local` (never built
//! or removed here, #141) and the client container is `--rm`; Docker is required, never skipped. The
//! client carries the same two Go-parity patches as `interop_client.py`.
mod common;
use common::server;
use std::{process::Command, sync::Arc};
use tokio::{net::TcpListener, sync::watch};

/// Pinned in `.github/ci/images.lock` and preloaded by the lane (`scripts/build-interop-images.sh`
/// on a dev host); the test never builds, tags or removes images (#141).
const IMAGE: &str = "setjoin-interop-imap:local";

#[tokio::test]
async fn test_imap_container_message_commands() {
    let Some(db) = setjoin_conformance::harness::Db::for_case("imap-interop-messages") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    for sql in [
        include_str!("../oracle/messages-cleanup.sql"),
        include_str!("../oracle/messages-seed.sql"),
    ] {
        owner.batch_execute(sql).await.unwrap();
    }
    let pid = std::process::id();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(Arc::new(server(&db, "plain")).serve(listener, rx));
    let name = format!("gofree-imap2-interop-client-{pid}");
    let image_name = IMAGE.to_string();
    let script = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/interop_messages_client.py"
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
    let flags: Vec<(String, bool, bool, bool, bool)> = owner
        .query(
            "SELECT message_id, is_read, is_flagged, is_answered, is_deleted FROM messages \
             WHERE mailbox_id = 9344021 AND message_id IN \
             ('<mid-3@imap2.test>','<mid-5@imap2.test>','<mid-11@imap2.test>') ORDER BY message_id",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3), r.get(4)))
        .collect();
    let audited: Vec<String> = owner
        .query(
            "SELECT DISTINCT action FROM mailbox_audit_log WHERE mailbox_id = 9344021 ORDER BY 1",
            &[],
        )
        .await
        .unwrap()
        .iter()
        .map(|r| r.get(0))
        .collect();
    owner
        .batch_execute(include_str!("../oracle/messages-cleanup.sql"))
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "client failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let got: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let want = serde_json::json!({
        "login": "OK",
        "select": "OK",
        "fetch": ["OK", "__FETCH1__", "__FETCH2__"],
        "uid_fetch": ["OK", "__UIDFETCH__"],
        "search_unseen": ["OK", "(TAG \"__\") ALL 1,2,3"],
        "uid_search_from": ["OK", "(TAG \"__\") UID ALL 3,14,20"],
        "search_subject": ["OK", "(TAG \"__\") ALL 1"],
        "store_add": ["OK", "1 (UID 3 FLAGS (\\Seen \\Flagged))"],
        "uid_store_replace": ["OK", "2 (UID 5 FLAGS (\\Seen \\Answered))"],
        "store_silent": ["OK"],
        "search_deleted_now": ["OK", "(TAG \"__\")"],
        "search_undeleted": ["OK", "(TAG \"__\") UID ALL 3,5,14,20"],
        "fetch_missing": ["OK"],
        "store_bad": "STORE command error: BAD [b'Invalid sequence number']",
        "logout": "BYE",
    });
    // Tags are chosen by imaplib; compare structure with the tag normalised.
    let mut got = got;
    for key in [
        "search_unseen",
        "uid_search_from",
        "search_subject",
        "search_deleted_now",
        "search_undeleted",
    ] {
        if let Some(line) = got[key].get_mut(1) {
            let text = line.as_str().unwrap().to_string();
            let start = text.find("(TAG \"").unwrap() + 6;
            let end = start + text[start..].find('"').unwrap();
            *line = serde_json::Value::String(format!("{}__{}", &text[..start], &text[end..]));
        }
    }
    let fetch = got["fetch"].as_array().unwrap().clone();
    assert_eq!(fetch.len(), 3, "{got}");
    for (i, uid) in [(1, "3"), (2, "5")] {
        let line = fetch[i].as_str().unwrap();
        assert!(
            line.starts_with(&format!("{i} (UID {uid} FLAGS ("))
                && line.contains(" RFC822.SIZE ")
                && line.contains(" ENVELOPE ("),
            "{line}"
        );
    }
    let uid_fetch = got["uid_fetch"][1].as_str().unwrap();
    assert!(uid_fetch.starts_with("3 (UID 11 FLAGS (\\Seen \\Flagged \\Answered \\Draft) RFC822.SIZE 77 ENVELOPE (\"Sat, 08 Mar 2025 14:24:34 +0000\" NIL ((NIL NIL \"nohost\" NIL))"), "{uid_fetch}");
    got["fetch"] = serde_json::json!(["OK", "__FETCH1__", "__FETCH2__"]);
    got["uid_fetch"] = serde_json::json!(["OK", "__UIDFETCH__"]);
    assert_eq!(got, want);
    assert_eq!(
        flags,
        vec![
            ("<mid-11@imap2.test>".to_string(), true, true, true, true),
            ("<mid-3@imap2.test>".to_string(), true, true, false, false),
            ("<mid-5@imap2.test>".to_string(), true, false, true, false),
        ]
    );
    assert_eq!(audited, ["imap_fetch", "imap_store"]);
}
