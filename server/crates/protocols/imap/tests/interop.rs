//! A third-party IMAP client (CPython `imaplib`) runs in a container derived from
//! the existing `test-imap` image and exercises the Rust sockets: plaintext
//! profile, STARTTLS and implicit TLS with CA verification. The client image is the pinned
//! `setjoin-interop-imap:local` (`.github/ci/images.lock`, `scripts/build-interop-images.sh`), never
//! built, tagged or removed here (#141); the client container is named
//! `gofree-imap1-interop-client-*`, bounded and `--rm`. Docker is required,
//! never skipped. Dovecot's own `imapc` client is not usable here: it insists on
//! IMAP4rev1 in CAPABILITY, which frozen Go (and so Rust) deliberately does not
//! advertise. Staged scope: login, capability, namespace, SELECT/EXAMINE;
//! message-level commands are exercised by #344/#345.
mod common;
use common::*;
use std::{process::Command, sync::Arc};
use tokio::{net::TcpListener, sync::watch};

/// Pinned in `.github/ci/images.lock` and preloaded by the lane (`scripts/build-interop-images.sh`
/// on a dev host); the test never builds, tags or removes images (#141).
const IMAGE: &str = "setjoin-interop-imap:local";

#[tokio::test]
async fn test_imap_container_client_session() {
    let Some(db) = setjoin_conformance::harness::Db::for_case("imap-interop") else {
        return;
    };
    let owner = db.connect().await.unwrap();
    seed(&owner).await;
    let hashes: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/password-hashes.json")).unwrap();
    reset_fixture(&owner, &hashes).await;
    let pid = std::process::id();

    let mut ports = Vec::new();
    let mut tasks = Vec::new();
    let (stop, rx) = watch::channel(false);
    for transport in ["plain", "starttls", "tls"] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        ports.push(listener.local_addr().unwrap().port());
        tasks.push(tokio::spawn(
            Arc::new(server(&db, transport)).serve(listener, rx.clone()),
        ));
    }
    let name = format!("gofree-imap1-interop-client-{pid}");
    let image_name = IMAGE.to_string();
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/interop_client.py");
    let ca = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/conformance/directory-sync/ldap-fixture/ca.pem"
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
                "-v",
                &format!("{ca}:/ca.pem:ro"),
                "--entrypoint",
                "timeout",
                &image_name,
                "60",
                "python3",
                "/client.py",
                &ports[0].to_string(),
                &ports[1].to_string(),
                &ports[2].to_string(),
            ])
            .output()
    })
    .await
    .unwrap()
    .unwrap();
    stop.send(true).unwrap();
    for task in tasks {
        task.await.unwrap().unwrap();
    }
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
    assert!(
        output.status.success(),
        "client failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let got: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    // imaplib upper-cases capability atoms.
    let caps = "IMAP4REV2 LOGIN-REFERRALS ID ENABLE";
    let want = serde_json::json!({
        "plain_capabilities": caps.split(' ').collect::<Vec<_>>(),
        "plain_bad_login": "Authentication failed",
        "plain_login": "OK",
        "plain_select_inbox": {"typ": "OK", "exists": "3", "validity": "1111", "uidnext": "7"},
        "plain_select_missing": "NO",
        "plain_examine": {"typ": "OK", "exists": "5", "validity": "4444", "uidnext": "12"},
        "plain_namespace": "((\"\" \"/\")) NIL NIL",
        "plain_noop": "OK",
        "plain_logout": "BYE",
        "starttls_capabilities_before": format!("{caps} STARTTLS LOGINDISABLED").split(' ').collect::<Vec<_>>(),
        "starttls_plaintext_login": "[PRIVACYREQUIRED] Must issue STARTTLS first",
        "starttls_upgrade": "OK",
        "starttls_capabilities_after": caps.split(' ').collect::<Vec<_>>(),
        "starttls_authenticate": "OK",
        "starttls_select": {"typ": "OK", "exists": "0", "validity": "2222", "uidnext": "1"},
        "starttls_logout": "BYE",
        "tls_capabilities": caps.split(' ').collect::<Vec<_>>(),
        "tls_login": "OK",
        "tls_select": {"typ": "OK", "exists": "3", "validity": "1111", "uidnext": "7"},
        "tls_logout": "BYE",
    });
    assert_eq!(got, want);
}
