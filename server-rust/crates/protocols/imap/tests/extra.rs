//! Behaviour the frozen-Go corpus cannot hold: random UID validity, staged
//! commands, hostile transports and admission. Each is derived from the Go
//! source named beside it.
mod common;
use common::*;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};

struct Running {
    addr: std::net::SocketAddr,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}
async fn start(server: setjoin_imap::Server) -> Running {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(Arc::new(server).serve(listener, rx));
    Running { addr, stop, task }
}
impl Running {
    async fn finish(self) {
        self.stop.send(true).unwrap();
        self.task.await.unwrap().unwrap();
    }
}

async fn read_for(socket: &mut TcpStream, wait: Duration) -> Vec<u8> {
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        match tokio::time::timeout_at(deadline, socket.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => out.extend_from_slice(&chunk[..n]),
            _ => return out,
        }
    }
}
async fn say(socket: &mut TcpStream, request: &str, until: &str) -> String {
    socket.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let n = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut chunk))
            .await
            .expect("reply timed out")
            .unwrap();
        assert!(n > 0, "closed: {}", String::from_utf8_lossy(&out));
        out.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&out).into_owned();
        if text.lines().any(|l| l.starts_with(until)) && text.ends_with("\r\n") {
            return text;
        }
    }
}

async fn fixture(case: &str) -> Option<(setjoin_conformance::harness::Db, tokio_postgres::Client)> {
    let db = setjoin_conformance::harness::Db::for_case(case)?;
    let owner = db.connect().await.unwrap();
    seed(&owner).await;
    let hashes: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/password-hashes.json")).unwrap();
    reset_fixture(&owner, &hashes).await;
    Some((db, owner))
}
async fn cleanup(owner: &tokio_postgres::Client) {
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
}

const LOGIN: &str = "l1 LOGIN \"alice@imap1.test\" \"IMAP1-correct-password!\"\r\n";

#[tokio::test]
async fn no_command_answers_a_serverbug_and_unknown_stays_bad() {
    let Some((db, owner)) = fixture("imap-staged").await else {
        return;
    };
    let running = start(server(&db, "plain")).await;
    let mut socket = TcpStream::connect(running.addr).await.unwrap();
    say(&mut socket, LOGIN, "l1 ").await;
    // IDLE and APPEND wait for the client and are covered by the recorded corpus.
    for command in [
        "LIST \"\" \"*\"",
        "STATUS Inbox (MESSAGES)",
        "EXPUNGE",
        "CREATE X",
        "DELETE X",
        "RENAME X Y",
        "MOVE 1 Sent",
        "COPY 1 Sent",
        "CLOSE",
        "UID COPY 1 Sent",
    ] {
        let reply = say(&mut socket, &format!("x {command}\r\n"), "x ").await;
        assert!(!reply.contains("SERVERBUG"), "{command}: {reply}");
    }
    assert_eq!(
        say(&mut socket, "y XYZZY\r\n", "y ").await,
        "y BAD Command not implemented\r\n"
    );
    drop(socket);
    running.finish().await;
    cleanup(&owner).await;
}

#[tokio::test]
async fn zero_uid_validity_is_a_fresh_clock_seeded_value() {
    // Go: uidValidity == 0 becomes UnixMicro()+rand(1e6); next UID comes from the tag.
    let Some((db, owner)) = fixture("imap-zero-validity").await else {
        return;
    };
    let running = start(server(&db, "plain")).await;
    let mut socket = TcpStream::connect(running.addr).await.unwrap();
    say(&mut socket, LOGIN, "l1 ").await;
    let reply = say(&mut socket, "a1 SELECT Zero\r\n", "a1 ").await;
    let line = reply.lines().find(|l| l.contains("UIDVALIDITY")).unwrap();
    let value: i64 = line
        .split("UIDVALIDITY ")
        .nth(1)
        .and_then(|rest| rest.split(']').next())
        .unwrap()
        .parse()
        .unwrap();
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_micros() as i64;
    assert!(
        (micros - 5_000_000..=micros + 5_000_000).contains(&value),
        "{value} vs {micros}"
    );
    assert!(reply.contains("[UIDNEXT 5]"));
    drop(socket);
    running.finish().await;
    cleanup(&owner).await;
}

#[tokio::test]
async fn plaintext_peer_on_the_implicit_tls_listener_is_dropped_silently() {
    let Some((db, owner)) = fixture("imap-tls-plaintext").await else {
        return;
    };
    let running = start(server(&db, "tls")).await;
    let mut socket = TcpStream::connect(running.addr).await.unwrap();
    socket.write_all(b"a1 NOOP\r\n").await.unwrap();
    let mut buf = [0u8; 256];
    let got = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut buf))
        .await
        .expect("server must end the handshake");
    // A TLS alert (handshake failure) or a plain close; never IMAP text.
    if let Ok(n) = got {
        assert!(
            !String::from_utf8_lossy(&buf[..n]).contains("OK"),
            "no IMAP over a failed handshake"
        );
    }
    running.finish().await;
    cleanup(&owner).await;
}

#[tokio::test]
async fn failed_starttls_handshake_ends_the_connection() {
    let Some((db, owner)) = fixture("imap-starttls-garbage").await else {
        return;
    };
    let running = start(server(&db, "starttls")).await;
    let mut socket = TcpStream::connect(running.addr).await.unwrap();
    say(&mut socket, "a1 STARTTLS\r\n", "a1 ").await;
    socket
        .write_all(b"this is not a ClientHello\r\n")
        .await
        .unwrap();
    let rest = read_for(&mut socket, Duration::from_secs(3)).await;
    assert!(
        !String::from_utf8_lossy(&rest).contains("NOOP"),
        "no plaintext command processing"
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), socket.read(&mut [0u8; 8]))
            .await
            .expect("closed")
            .unwrap_or(0),
        0
    );
    running.finish().await;
    cleanup(&owner).await;
}

#[tokio::test]
async fn connection_cap_queues_the_second_client_until_a_slot_frees() {
    // Go: tlsutil.LimitListener — accept blocks, the client waits for its greeting.
    let Some((db, owner)) = fixture("imap-conn-cap").await else {
        return;
    };
    let running = start(server(&db, "plain").with_max_connections(1)).await;
    let mut first = TcpStream::connect(running.addr).await.unwrap();
    say(&mut first, "", "* ").await;
    let mut second = TcpStream::connect(running.addr).await.unwrap();
    assert!(read_for(&mut second, Duration::from_millis(400))
        .await
        .is_empty());
    drop(first);
    let greeting = say(&mut second, "", "* ").await;
    assert!(greeting.contains("mailserver ready"));
    drop(second);
    running.finish().await;
    cleanup(&owner).await;
}

#[tokio::test]
async fn invalid_utf8_and_binary_lines_never_crash_a_session() {
    let Some((db, owner)) = fixture("imap-binary").await else {
        return;
    };
    let running = start(server(&db, "plain")).await;
    let mut socket = TcpStream::connect(running.addr).await.unwrap();
    say(&mut socket, "", "* ").await;
    socket
        .write_all(b"\xff\xfe\x00 \xc3\x28\r\n")
        .await
        .unwrap();
    let reply = say(&mut socket, "", "").await;
    assert!(reply.contains("BAD Command not implemented"), "{reply}");
    assert_eq!(
        say(&mut socket, "z NOOP\r\n", "z ").await,
        "z OK NOOP completed\r\n"
    );
    drop(socket);
    running.finish().await;
    cleanup(&owner).await;
}

/// Owner-approved security fix 2026-11-05 (#449, mutant `imap-idle-spins-on-close`): a client
/// that disconnects during IDLE ends its session, so the connection slot is released. Frozen
/// Go swallowed the read error in a 100 ms loop and the slot leaked for good.
#[tokio::test]
async fn disconnect_during_idle_frees_the_connection_slot() {
    let Some((db, owner)) = fixture("imap-idle-disconnect-slot").await else {
        return;
    };
    let running = start(server(&db, "plain").with_max_connections(1)).await;
    let addr = running.addr;
    // The client steps run in a task so a failing assertion still reaches the cleanup below.
    let client = tokio::spawn(async move {
        let mut first = TcpStream::connect(addr).await.unwrap();
        say(&mut first, "", "* ").await;
        say(&mut first, LOGIN, "l1 ").await;
        let idling = say(&mut first, "i1 IDLE\r\n", "i1 +").await;
        assert!(idling.contains("idling"), "{idling}");
        drop(first);
        let mut second = TcpStream::connect(addr).await.unwrap();
        let greeting = tokio::time::timeout(Duration::from_secs(3), say(&mut second, "", "* "))
            .await
            .expect("the slot of a client that disconnected during IDLE must be freed");
        assert!(greeting.contains("mailserver ready"));
    });
    let outcome = client.await;
    running.finish().await;
    cleanup(&owner).await;
    outcome.expect("IDLE slot test");
}
