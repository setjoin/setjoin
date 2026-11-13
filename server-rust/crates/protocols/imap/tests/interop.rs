//! A third-party IMAP client (CPython `imaplib`) runs in a container derived from
//! the existing `test-imap` image and exercises the Rust sockets: plaintext
//! profile, STARTTLS and implicit TLS with CA verification. The images are owned
//! PID-specific `gofree-imap1-interop-*` tags removed afterwards; the client
//! container is named with that prefix, bounded and `--rm`. Docker is required,
//! never skipped. Dovecot's own `imapc` client is not usable here: it insists on
//! IMAP4rev1 in CAPABILITY, which frozen Go (and so Rust) deliberately does not
//! advertise. Staged scope: login, capability, namespace, SELECT/EXAMINE;
//! message-level commands are exercised by #344/#345.
mod common;
use common::*;
use std::{process::Command, sync::Arc};
use tokio::{net::TcpListener, sync::watch};

struct Image(String);
impl Drop for Image {
    fn drop(&mut self) {
        let output = Command::new("docker")
            .args(["image", "rm", "-f", &self.0])
            .output()
            .expect("remove owned interop image");
        if !output.status.success() {
            eprintln!(
                "owned image cleanup failed: {}: {}",
                self.0,
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(std::thread::panicking(), "owned image cleanup failed");
        }
    }
}

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
    let base = Image(format!("gofree-imap1-interop-base-{pid}"));
    let image = Image(format!("gofree-imap1-interop-{pid}"));
    let context = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../../mailserver/deploy/docker/test-imap"
    );
    let built = Command::new("docker")
        .args(["build", "-q", "-t", &base.0, context])
        .output()
        .expect("docker is required for the interop suite");
    assert!(
        built.status.success(),
        "docker build: {}",
        String::from_utf8_lossy(&built.stderr)
    );
    // The derived layer only adds a Python runtime for the client script.
    let mut derived = Command::new("docker")
        .args(["build", "-q", "-t", &image.0, "-"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        write!(
            derived.stdin.take().unwrap(),
            "FROM {}\nRUN apk add --no-cache python3\n",
            base.0
        )
        .unwrap();
    }
    let derived = derived.wait_with_output().unwrap();
    assert!(
        derived.status.success(),
        "derived build: {}",
        String::from_utf8_lossy(&derived.stderr)
    );

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
    let image_name = image.0.clone();
    let script = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/interop_client.py");
    let ca = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/conformance/directory-sync/ldap-fixture/ca.pem"
    );
    let output = tokio::task::spawn_blocking(move || {
        Command::new("docker")
            .args([
                "run",
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
