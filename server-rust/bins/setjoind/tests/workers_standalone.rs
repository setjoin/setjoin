//! Suite 3: Standalone `--subsystems=workers` binds ZERO HTTP/auth/protocol
//! listeners and drains cleanly on SIGTERM (#543).

mod common;

use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;

#[test]
fn workers_standalone_binds_no_listeners_and_drains_cleanly() {
    let dsn = common::test_db_dsn();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (notify_path, notify_sock) = common::bind_notify_socket(tmp.path());

    let unused_http = common::free_addr();
    let unused_auth = common::free_addr();

    let mut cmd = Command::new(common::setjoind_bin());
    cmd.env_clear()
        .arg("--subsystems=workers")
        .env("DB_DSN", &dsn)
        .env("DB_DIRECT_DSN", &dsn)
        .env("NOTIFY_SOCKET", &notify_path)
        .env("DB_ENCRYPTION_KEY", "setjoind-test-db-enc-key-32-bytes!!")
        .env("GATEWAY_LISTEN", unused_http.to_string())
        .env("LISTEN_ADDR", unused_auth.to_string());

    let mut proc = common::OwnedChild::spawn(&mut cmd);
    common::wait_notify(&notify_sock, &mut proc, "READY=1", Duration::from_secs(20));

    // Neither HTTP nor auth listener may be bound in `--subsystems=workers`.
    assert!(
        TcpStream::connect_timeout(&unused_http, Duration::from_millis(300)).is_err(),
        "workers-only node must not bind GATEWAY_LISTEN ({unused_http})"
    );
    assert!(
        TcpStream::connect_timeout(&unused_auth, Duration::from_millis(300)).is_err(),
        "workers-only node must not bind LISTEN_ADDR ({unused_auth})"
    );

    proc.send_sigterm();
    common::wait_notify(
        &notify_sock,
        &mut proc,
        "STOPPING=1",
        Duration::from_secs(10),
    );
    let status = proc
        .wait_exit(Duration::from_secs(15))
        .expect("workers clean exit");
    assert!(status.success(), "expected exit 0, got {status}");
}
