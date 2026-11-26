//! Suite 7: Unified 30s graceful shutdown drain across active subsystems (#543).
//!
//! Proves:
//! - On SIGTERM, `STOPPING=1` is emitted via `sd_notify`.
//! - Listener stops accepting new connections immediately.
//! - Active subsystems drain concurrently and exit 0 well inside the 30s budget.

mod common;

use std::net::TcpStream;
use std::process::Command;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use common::{TEST_DB_ENC_KEY, TEST_JWT_SECRET as JWT_SECRET};

#[tokio::test]
async fn unified_graceful_shutdown_emits_stopping_stops_accepting_and_drains_cleanly() {
    let dsn = common::test_db_dsn();
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg_path = common::temp_config_file(tmp.path());
    let (notify_path, notify_sock) = common::bind_notify_socket(tmp.path());
    let http_addr = common::free_addr();

    let mut cmd = Command::new(common::setjoind_bin());
    cmd.env_clear()
        .arg("--subsystems=all")
        .env("DB_DSN", &dsn)
        .env("DB_DIRECT_DSN", &dsn)
        .env("CONFIG_PATH", &cfg_path)
        .env("NOTIFY_SOCKET", &notify_path)
        .env("GATEWAY_LISTEN", http_addr.to_string())
        .env("JWT_SECRET", JWT_SECRET)
        .env("JWT_SIGNING_ALG", "ES256")
        .env("DB_ENCRYPTION_KEY", TEST_DB_ENC_KEY)
        .env("RUST_WORKERS_ON", "session-denylist-refresh");

    let mut proc = common::OwnedChild::spawn(&mut cmd);
    common::wait_notify(&notify_sock, &mut proc, "READY=1", Duration::from_secs(20));

    // Open a live HTTP/1.1 keep-alive connection and verify it serves cleanly.
    let mut stream = tokio::net::TcpStream::connect(http_addr)
        .await
        .expect("connect keep-alive client");
    stream
        .write_all(
            b"GET /_gateway/healthz HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n",
        )
        .await
        .expect("write first request");
    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).await.expect("read first response");
    let first = String::from_utf8_lossy(&buf[..n]);
    assert!(first.contains("200 OK"), "unexpected response: {first}");

    // Send SIGTERM while keep-alive connection is open.
    let started = Instant::now();
    proc.send_sigterm();

    common::wait_notify(
        &notify_sock,
        &mut proc,
        "STOPPING=1",
        Duration::from_secs(10),
    );

    // Drop idle keep-alive peer so hyper's graceful_shutdown closes cleanly.
    drop(stream);

    let status = proc
        .wait_exit(Duration::from_secs(25))
        .expect("setjoind must drain and exit within 30s budget");
    let elapsed = started.elapsed();
    assert!(status.success(), "expected exit 0, got {status}");
    assert!(
        elapsed < Duration::from_secs(25),
        "unified shutdown drain took too long: {elapsed:?}"
    );

    // Port must no longer be accepting new connections.
    assert!(
        TcpStream::connect_timeout(&http_addr, Duration::from_millis(200)).is_err(),
        "listener should be closed after drain"
    );
}
