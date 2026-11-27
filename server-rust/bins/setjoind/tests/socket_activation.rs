//! Suite 5: Systemd socket activation (`LISTEN_FDS` / `LISTEN_FDNAMES` /
//! `LISTEN_PID`) + `SdNotify` (`READY=1`, `STOPPING=1`) + fail-closed rejection
//! of unexpected or unknown FD slots (#543).

mod common;

use std::net::TcpListener;
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::Duration;

use common::TEST_JWT_SECRET as JWT_SECRET;

fn spawn_activated(
    listener: &TcpListener,
    fd_name: &str,
    subsystems_flag: &str,
    envs: &[(&str, &str)],
) -> common::OwnedChild {
    let fd = listener.as_raw_fd();
    let mut cmd = Command::new("/bin/sh");
    cmd.env_clear()
        .arg("-c")
        .arg("export LISTEN_PID=$$ LISTEN_FDS=1 LISTEN_FDNAMES=\"$1\"; exec \"$2\" \"$3\"")
        .arg("setjoind-sd-launcher")
        .arg(fd_name)
        .arg(common::setjoind_bin())
        .arg(subsystems_flag);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    unsafe {
        cmd.pre_exec(move || {
            if libc::dup2(fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    common::OwnedChild::spawn(&mut cmd)
}

#[tokio::test]
async fn socket_activation_http_and_auth_slots_emit_ready_and_stopping() {
    let dsn = common::test_db_dsn();

    // 1. Activate Slot::Http on `--subsystems=all`.
    {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg_path = common::temp_config_file(tmp.path());
        let (notify_path, notify_sock) = common::bind_notify_socket(tmp.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind activated http");
        let addr = listener.local_addr().unwrap();

        let cfg_str = cfg_path.to_str().unwrap();
        let notify_str = notify_path.to_str().unwrap();
        let mut proc = spawn_activated(
            &listener,
            "http",
            "--subsystems=all",
            &[
                ("DB_DSN", &dsn),
                ("DB_DIRECT_DSN", &dsn),
                ("CONFIG_PATH", cfg_str),
                ("NOTIFY_SOCKET", notify_str),
                ("JWT_SECRET", JWT_SECRET),
                ("JWT_SIGNING_ALG", "ES256"),
                ("DB_ENCRYPTION_KEY", "setjoind-test-db-enc-key-32-bytes!!"),
            ],
        );
        drop(listener);

        common::wait_notify(&notify_sock, &mut proc, "READY=1", Duration::from_secs(20));

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let resp = client
            .get(format!("http://{addr}/_gateway/healthz"))
            .send()
            .await
            .expect("healthz over activated http FD");
        assert_eq!(resp.status(), 200);

        proc.send_sigterm();
        common::wait_notify(
            &notify_sock,
            &mut proc,
            "STOPPING=1",
            Duration::from_secs(10),
        );
        let status = proc.wait_exit(Duration::from_secs(15)).expect("exit");
        assert!(status.success(), "expected exit 0, got {status}");
    }

    // 2. Activate Slot::Auth on `--subsystems=auth`.
    {
        let tmp = tempfile::tempdir().expect("tempdir");
        let cfg_path = common::temp_config_file(tmp.path());
        let (notify_path, notify_sock) = common::bind_notify_socket(tmp.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind activated auth");
        let addr = listener.local_addr().unwrap();

        let cfg_str = cfg_path.to_str().unwrap();
        let notify_str = notify_path.to_str().unwrap();
        let mut proc = spawn_activated(
            &listener,
            "auth",
            "--subsystems=auth",
            &[
                ("DB_DSN", &dsn),
                ("DB_DIRECT_DSN", &dsn),
                ("CONFIG_PATH", cfg_str),
                ("NOTIFY_SOCKET", notify_str),
                ("JWT_SECRET", JWT_SECRET),
                ("JWT_SIGNING_ALG", "ES256"),
                ("DB_ENCRYPTION_KEY", "setjoind-test-db-enc-key-32-bytes!!"),
            ],
        );
        drop(listener);

        common::wait_notify(&notify_sock, &mut proc, "READY=1", Duration::from_secs(20));

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let resp = client
            .get(format!("http://{addr}/health"))
            .send()
            .await
            .expect("health over activated auth FD");
        assert_eq!(resp.status(), 200);
        assert_eq!(resp.text().await.unwrap(), r#"{"status":"ok"}"#);

        proc.send_sigterm();
        common::wait_notify(
            &notify_sock,
            &mut proc,
            "STOPPING=1",
            Duration::from_secs(10),
        );
        let status = proc.wait_exit(Duration::from_secs(15)).expect("exit");
        assert!(status.success(), "expected exit 0, got {status}");
    }
}

#[test]
fn socket_activation_refuses_unexpected_and_unknown_fd_slots() {
    let dsn = common::test_db_dsn();

    // 1. Passing `Slot::Auth` when `--subsystems=http` (auth disabled) MUST fail closed.
    {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (notify_path, notify_sock) = common::bind_notify_socket(tmp.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind unexpected auth slot");
        let notify_str = notify_path.to_str().unwrap();

        let mut proc = spawn_activated(
            &listener,
            "auth",
            "--subsystems=http",
            &[
                ("DB_DSN", &dsn),
                ("DB_DIRECT_DSN", &dsn),
                ("NOTIFY_SOCKET", notify_str),
            ],
        );
        drop(listener);

        let status = proc
            .wait_exit(Duration::from_secs(10))
            .expect("expected immediate refusal");
        assert!(
            !status.success(),
            "unexpected auth FD on http-only must fail"
        );
        let stderr = proc.read_stderr();
        assert!(
            stderr.contains("auth") && stderr.contains("disabled"),
            "expected disabled-slot error in stderr, got: {stderr}"
        );
        assert!(
            !common::drain_notify(&notify_sock)
                .iter()
                .any(|m| m == "READY=1"),
            "READY=1 must never be emitted on rejected FD slot"
        );
    }

    // 2. Passing an unknown FD name (`authh`) MUST fail closed.
    {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (notify_path, notify_sock) = common::bind_notify_socket(tmp.path());
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind unknown slot");
        let notify_str = notify_path.to_str().unwrap();

        let mut proc = spawn_activated(
            &listener,
            "authh",
            "--subsystems=all",
            &[
                ("DB_DSN", &dsn),
                ("DB_DIRECT_DSN", &dsn),
                ("NOTIFY_SOCKET", notify_str),
                ("JWT_SECRET", JWT_SECRET),
            ],
        );
        drop(listener);

        let status = proc
            .wait_exit(Duration::from_secs(10))
            .expect("expected immediate refusal");
        assert!(!status.success(), "unknown FD name must fail closed");
        let stderr = proc.read_stderr();
        assert!(
            stderr.contains("unknown descriptor name"),
            "expected unknown descriptor error in stderr, got: {stderr}"
        );
        assert!(
            !common::drain_notify(&notify_sock)
                .iter()
                .any(|m| m == "READY=1"),
            "READY=1 must never be emitted on unknown FD name"
        );
    }
}
