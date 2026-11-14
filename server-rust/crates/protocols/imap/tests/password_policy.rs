//! #355-0: the shared password check wired through one IMAP `Server`:
//! warm-cache revocation, the owner-approved TOTP refusal (security
//! divergence, oracle/divergences.json), the post-verify gates on a cache hit,
//! and app passwords never cached.
mod common;
use common::*;
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
};

const PW: &str = "IMAP1-correct-password!";
const LOW: &str = "IMAP1-low-cost-password!";

async fn exchange(socket: &mut TcpStream, request: &str, tag: &str) -> String {
    socket.write_all(request.as_bytes()).await.unwrap();
    let mut out = Vec::new();
    let mut chunk = [0u8; 4096];
    let marker = format!("\r\n{tag} ");
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), socket.read(&mut chunk))
            .await
            .expect("reply")
            .unwrap();
        assert!(n > 0, "closed early: {}", String::from_utf8_lossy(&out));
        out.extend_from_slice(&chunk[..n]);
        let text = String::from_utf8_lossy(&out);
        if (text.contains(&marker) || text.starts_with(&format!("{tag} ")))
            && text.ends_with("\r\n")
        {
            return text.into_owned();
        }
    }
}

struct Listener {
    server: Arc<setjoin_imap::Server>,
    addr: std::net::SocketAddr,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

async fn listener(db: &setjoin_conformance::harness::Db) -> Listener {
    let server = Arc::new(server(db, "plain"));
    let socket = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.clone().serve(socket, rx));
    Listener {
        server,
        addr,
        stop,
        task,
    }
}

impl Listener {
    async fn login(&self, user: &str, password: &str) -> String {
        let mut socket = TcpStream::connect(self.addr).await.unwrap();
        exchange(&mut socket, "", "*").await;
        exchange(
            &mut socket,
            &format!("a1 LOGIN \"{user}\" \"{password}\"\r\n"),
            "a1",
        )
        .await
    }
    async fn finish(self) {
        self.stop.send(true).unwrap();
        self.task.await.unwrap().unwrap();
    }
}

async fn setup(
    case: &str,
) -> Option<(
    setjoin_conformance::harness::Db,
    tokio_postgres::Client,
    serde_json::Value,
)> {
    let db = setjoin_conformance::harness::Db::for_case(case)?;
    let owner = db.connect().await.unwrap();
    seed(&owner).await;
    let hashes: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/password-hashes.json")).unwrap();
    reset_fixture(&owner, &hashes).await;
    Some((db, owner, hashes))
}

async fn cleanup(owner: &tokio_postgres::Client) {
    owner
        .batch_execute(include_str!("../oracle/cleanup.sql"))
        .await
        .unwrap();
}

fn ok(reply: &str) -> bool {
    reply.contains("a1 OK ")
}

#[tokio::test]
async fn password_change_misses_a_warm_cache() {
    let Some((db, owner, hashes)) = setup("imap-cache-rotation").await else {
        return;
    };
    let l = listener(&db).await;
    assert!(ok(&l.login("alice@imap1.test", PW).await));
    assert_eq!(l.server.cached_passwords(), 1);
    owner
        .execute(
            "UPDATE users SET password_hash=$1 WHERE id=9343011",
            &[&hashes["low"].as_str().unwrap()],
        )
        .await
        .unwrap();
    assert!(l
        .login("alice@imap1.test", PW)
        .await
        .ends_with("a1 NO Authentication failed\r\n"));
    assert!(ok(&l.login("alice@imap1.test", LOW).await));
    l.finish().await;
    cleanup(&owner).await;
}

#[tokio::test]
async fn totp_user_account_password_is_refused_even_on_a_warm_cache() {
    let record: serde_json::Value =
        serde_json::from_str(include_str!("../oracle/divergences.json")).unwrap();
    assert_eq!(
        record["totp-account-password"]["secure_test"],
        "password_policy::totp_user_account_password_is_refused_even_on_a_warm_cache"
    );
    let Some((db, owner, _)) = setup("imap-totp-divergence").await else {
        return;
    };
    let l = listener(&db).await;
    assert!(ok(&l.login("alice@imap1.test", PW).await));
    assert_eq!(l.server.cached_passwords(), 1, "cache is warm");
    owner
        .execute("UPDATE users SET totp_enabled=true WHERE id=9343011", &[])
        .await
        .unwrap();
    assert!(l
        .login("alice@imap1.test", PW)
        .await
        .ends_with("a1 NO Authentication failed\r\n"));
    // AUTHENTICATE PLAIN follows the same rule.
    {
        use base64::Engine;
        let mut socket = TcpStream::connect(l.addr).await.unwrap();
        exchange(&mut socket, "", "*").await;
        exchange(&mut socket, "a2 AUTHENTICATE PLAIN\r\n", "+").await;
        let plain =
            base64::engine::general_purpose::STANDARD.encode(format!("\0alice@imap1.test\0{PW}"));
        let reply = exchange(&mut socket, &format!("{plain}\r\n"), "a2").await;
        assert!(
            reply.ends_with("a2 NO Authentication failed\r\n"),
            "{reply}"
        );
    }
    assert!(ok(&l
        .login("alice@imap1.test", "imap1-app-token-valid")
        .await));
    l.finish().await;
    cleanup(&owner).await;
}

#[tokio::test]
async fn post_verify_gates_hold_on_a_cache_hit() {
    let Some((db, owner, _)) = setup("imap-cache-gates").await else {
        return;
    };
    let l = listener(&db).await;
    assert!(l
        .login("bob@imap1.test", PW)
        .await
        .ends_with("a1 NO IMAP access disabled for this account by policy\r\n"));
    assert_eq!(
        l.server.cached_password_hits(),
        0,
        "first bob login verifies"
    );
    assert!(l
        .login("bob@imap1.test", PW)
        .await
        .ends_with("a1 NO IMAP access disabled for this account by policy\r\n"));
    assert_eq!(
        l.server.cached_password_hits(),
        1,
        "second bob login was a cache hit"
    );
    assert_eq!(l.server.cached_passwords(), 1);
    for _ in 0..2 {
        assert!(l
            .login("carol@imap1.test", PW)
            .await
            .ends_with("a1 NO Mailbox access suspended\r\n"));
    }
    assert_eq!(l.server.cached_passwords(), 2);
    assert_eq!(
        l.server.cached_password_hits(),
        2,
        "second carol login was a cache hit"
    );
    l.finish().await;
    cleanup(&owner).await;
}

#[tokio::test]
async fn app_passwords_are_never_cached_and_expire_at_once() {
    let Some((db, owner, _)) = setup("imap-cache-app").await else {
        return;
    };
    let l = listener(&db).await;
    assert!(ok(&l
        .login("alice@imap1.test", "imap1-app-token-valid")
        .await));
    assert_eq!(l.server.cached_passwords(), 0);
    owner
        .execute(
            "UPDATE app_passwords SET expires_at=now()-interval '1 second' WHERE user_id=9343011 AND name='valid'",
            &[],
        )
        .await
        .unwrap();
    assert!(l
        .login("alice@imap1.test", "imap1-app-token-valid")
        .await
        .ends_with("a1 NO Authentication failed\r\n"));
    l.finish().await;
    cleanup(&owner).await;
}
