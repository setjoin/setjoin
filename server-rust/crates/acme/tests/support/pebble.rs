//! Pebble ACME test server process and an HTTP-01 validation endpoint (test support).
#![allow(dead_code)]
use setjoin_acme::Http01Store;
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const DIRECTORY: &str = "https://localhost:14070/dir";
pub const HTTP_PORT: u16 = 5072;

pub fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/acme/pebble")
}

pub fn ca_root() -> PathBuf {
    fixtures().join("certs/pebble.minica.pem")
}

/// Pebble and the validation responder bind fixed ports, so the cases of one test
/// binary take turns (parallel libtest would race for 14070/5072).
static TURN: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The running server; the second field is the turn, released after the process is killed.
pub struct Pebble(
    Child,
    #[allow(dead_code)] tokio::sync::MutexGuard<'static, ()>,
);

impl Pebble {
    /// `None` (with the repository's skip marker) only when no binary is configured and the DB
    /// requirement is not asserted; with `REQUIRE_DB=1` a missing binary is a failure.
    pub async fn start() -> Option<Self> {
        let turn = TURN.lock().await;
        let Some(bin) = std::env::var_os("PEBBLE_BIN") else {
            assert!(
                std::env::var_os("REQUIRE_DB").is_none(),
                "PEBBLE_BIN is required when REQUIRE_DB is set"
            );
            println!("ACME-SKIP (reason=PEBBLE_BIN not set)");
            return None;
        };
        // A listening port is not permission to borrow another worker's CA.
        for port in [14070, 15070] {
            assert!(
                tokio::net::TcpStream::connect(("127.0.0.1", port))
                    .await
                    .is_err(),
                "pebble port {port} is already owned; do not reuse or stop that service"
            );
        }
        if let Ok(path) = std::env::var("GOFREE_RESOURCE_LEDGER") {
            use std::io::Write as _;
            writeln!(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .unwrap(),
                "planned Pebble {:?}, ports 14070/15070, parent {}; child is killed/joined on Drop",
                bin,
                std::process::id()
            )
            .unwrap();
        }
        let child = Command::new(bin)
            .current_dir(fixtures())
            .args(["-config", "config.json"])
            .env("PEBBLE_VA_NOSLEEP", "1")
            .env("PEBBLE_WFE_NONCEREJECT", "0")
            .env("PEBBLE_AUTHZREUSE", "0")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start pebble");
        let pebble = Self(child, turn);
        if let Ok(path) = std::env::var("GOFREE_RESOURCE_LEDGER") {
            use std::io::Write as _;
            writeln!(
                std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .unwrap(),
                "started Pebble PID {}",
                pebble.0.id()
            )
            .unwrap();
        }
        for _ in 0..100 {
            if tokio::net::TcpStream::connect("127.0.0.1:14070")
                .await
                .is_ok()
            {
                return Some(pebble);
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        panic!("pebble did not listen");
    }
}

impl Drop for Pebble {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

pub struct Responder {
    task: tokio::task::JoinHandle<()>,
    /// Challenge-path requests the store did not answer (what Go's overlay calls misses).
    pub misses: std::sync::Arc<std::sync::atomic::AtomicU64>,
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Minimal HTTP/1.1 responder on port 5072 serving `store` like the :80 listener would; with
/// `answer == false` it never answers, which makes every validation fail.
pub async fn serve_http01_with(store: Http01Store, answer: bool) -> Responder {
    use std::sync::atomic::{AtomicU64, Ordering};
    let misses = std::sync::Arc::new(AtomicU64::new(0));
    let counter = misses.clone();
    // Pebble resolves `*.localhost` to both ::1 and 127.0.0.1; a dual-stack socket serves both.
    let listener = match tokio::net::TcpListener::bind(("::", HTTP_PORT)).await {
        Ok(l) => l,
        Err(_) => tokio::net::TcpListener::bind(("127.0.0.1", HTTP_PORT))
            .await
            .expect("bind 5072"),
    };
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let store = store.clone();
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let head = String::from_utf8_lossy(&buf[..n]).into_owned();
                let path = head.split_whitespace().nth(1).unwrap_or("/");
                let found = if answer { store.answer(path) } else { None };
                if found.is_none() && path.starts_with(setjoin_acme::HTTP01_PREFIX) {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
                let (status, body) = match found {
                    Some(body) => ("200 OK", body),
                    None => ("404 Not Found", "404 page not found\n".into()),
                };
                let _ = stream
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await;
            });
        }
    });
    Responder { task, misses }
}

pub async fn serve_http01(store: Http01Store) -> Responder {
    serve_http01_with(store, true).await
}
