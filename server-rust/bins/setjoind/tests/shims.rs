//! Release N compiled ELF shims, 9-FD (including FD 10 & 11) socket activation,
//! `--version` compatibility, fail-closed subsystem immutability, and unified
//! `setjoind --subsystems=all` static-TLS & ACME smoke tests (#544).

mod common;

use std::net::TcpListener;
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use common::{TEST_DB_ENC_KEY, TEST_INTERNAL_KEY, TEST_JWT_SECRET};

fn server_shim_bin() -> &'static str {
    env!("CARGO_BIN_EXE_setjoin-server-shim")
}

fn auth_shim_bin() -> &'static str {
    env!("CARGO_BIN_EXE_setjoin-auth-shim")
}

/// Stage a packaged Release N directory containing `setjoind`, `setjoin-server`,
/// and `setjoin-auth` as regular single-link 0755 executables.
fn stage_release_n_dir(dir: &Path) -> (PathBuf, PathBuf, PathBuf) {
    let setjoind = dir.join("setjoind");
    let server = dir.join("setjoin-server");
    let auth = dir.join("setjoin-auth");
    std::fs::copy(common::setjoind_bin(), &setjoind).expect("copy setjoind");
    std::fs::copy(server_shim_bin(), &server).expect("copy setjoin-server-shim");
    std::fs::copy(auth_shim_bin(), &auth).expect("copy setjoin-auth-shim");
    for p in [&setjoind, &server, &auth] {
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o755)).expect("chmod 0755");
    }
    (setjoind, server, auth)
}

fn generate_self_signed_cert(dir: &Path) -> (PathBuf, PathBuf) {
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let out = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            key.to_str().unwrap(),
            "-out",
            cert.to_str().unwrap(),
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ])
        .output()
        .expect("run openssl");
    assert!(
        out.status.success(),
        "openssl failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    (cert, key)
}

/// Spawn `exe` directly with inherited socket-activation listeners dup2'd onto
/// FDs `3..3+listeners.len()` and `LISTEN_PID` set to the child PID in `pre_exec`
/// without invoking `/bin/sh` (which would collide with FD 10).
fn spawn_with_activated_fds(
    exe: &Path,
    args: &[&str],
    listeners: &[TcpListener],
    fd_names: &str,
    envs: &[(&str, &str)],
) -> common::OwnedChild {
    let raw_fds: Vec<i32> = listeners.iter().map(AsRawFd::as_raw_fd).collect();
    let count_str = listeners.len().to_string();
    let mut cmd = Command::new("python3");
    cmd.env_clear()
        .arg("-c")
        .arg("import os, sys; os.environ['LISTEN_PID'] = str(os.getpid()); os.execv(sys.argv[1], sys.argv[1:])")
        .arg(exe)
        .args(args)
        .env("LISTEN_FDS", &count_str)
        .env("LISTEN_FDNAMES", fd_names);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    unsafe {
        cmd.pre_exec(move || {
            // Move source FDs above the target range [3..3+N) first to avoid clobbering.
            let n = raw_fds.len() as i32;
            let high_base = 3 + n + 8;
            let mut staged = Vec::with_capacity(raw_fds.len());
            for (i, &src) in raw_fds.iter().enumerate() {
                let tmp_fd = high_base + i as i32;
                if libc::dup2(src, tmp_fd) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                staged.push(tmp_fd);
            }
            for (i, &tmp_fd) in staged.iter().enumerate() {
                let dst = 3 + i as i32;
                if libc::dup2(tmp_fd, dst) < 0 || libc::fcntl(dst, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::close(tmp_fd);
            }
            Ok(())
        });
    }
    common::OwnedChild::spawn(&mut cmd)
}

#[test]
fn shim_version_flag_matches_smoke_rust_floor_contract() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_, server, auth) = stage_release_n_dir(tmp.path());
    let expected_ver = env!("CARGO_PKG_VERSION");

    for (bin, name) in [(&server, "setjoin-server"), (&auth, "setjoin-auth")] {
        for flag in ["--version", "-V"] {
            let out = Command::new(bin)
                .env_clear()
                .arg(flag)
                .output()
                .expect("run shim --version");
            assert!(
                out.status.success(),
                "{name} {flag} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert_eq!(
                String::from_utf8_lossy(&out.stdout),
                format!("{name} {expected_ver}\n")
            );
        }
    }
}

#[test]
fn shim_refuses_conflicting_subsystems_and_symlinked_setjoind_fail_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_, server, auth) = stage_release_n_dir(tmp.path());

    // Conflicting CLI flags and env vars MUST exit 2.
    for (bin, args, env_val) in [
        (&server, vec!["--subsystems=all"], None),
        (&server, vec!["--subsystems", "auth"], None),
        (
            &server,
            vec![
                "--subsystems=http,protocols,workers",
                "--subsystems=http,protocols,workers",
            ],
            None,
        ),
        (&server, vec![], Some("all")),
        (&server, vec![], Some("auth")),
        (&auth, vec!["--subsystems=all"], None),
        (&auth, vec!["--subsystems", "http"], None),
        (&auth, vec![], Some("http,protocols,workers")),
    ] {
        let mut cmd = Command::new(bin);
        cmd.env_clear().args(&args);
        if let Some(v) = env_val {
            cmd.env("SETJOIND_SUBSYSTEMS", v);
        }
        let out = cmd.output().expect("run shim refusal case");
        assert_eq!(
            out.status.code(),
            Some(2),
            "expected exit 2 for {:?} {:?} env={:?}, stderr={}",
            bin.file_name(),
            args,
            env_val,
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // Symlinked sibling setjoind MUST be refused.
    let sym_dir = tempfile::tempdir().expect("symlink tempdir");
    let real_target = sym_dir.path().join("real-setjoind");
    std::fs::copy(common::setjoind_bin(), &real_target).expect("copy real setjoind");
    std::os::unix::fs::symlink(&real_target, sym_dir.path().join("setjoind"))
        .expect("symlink setjoind");
    let sym_server = sym_dir.path().join("setjoin-server");
    std::fs::copy(server_shim_bin(), &sym_server).expect("copy shim");
    std::fs::set_permissions(&sym_server, std::fs::Permissions::from_mode(0o755)).unwrap();

    let out = Command::new(&sym_server)
        .env_clear()
        .output()
        .expect("run shim against symlinked setjoind");
    assert!(!out.status.success(), "symlinked setjoind must be refused");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("symlink")
            || stderr.contains("regular file")
            || stderr.contains("Too many levels"),
        "unexpected stderr: {stderr}"
    );
}

#[tokio::test]
async fn server_shim_inherits_eight_fds_including_fd_10_without_jwt_secret() {
    let dsn = common::test_db_dsn();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (_, server_shim, _) = stage_release_n_dir(tmp.path());
    let cfg_path = common::temp_config_file(tmp.path());
    let (cert_path, key_path) = generate_self_signed_cert(tmp.path());
    let (notify_path, notify_sock) = common::bind_notify_socket(tmp.path());

    // Bind 8 loopback TCP listeners mapped onto FDs 3..=10 (explicitly exercising FD 10;
    // the retired `acme` socket slot was removed in #560).
    let slot_names = [
        "setjoin-gateway.socket",
        "https",
        "federation",
        "imap",
        "imaps",
        "smtp",
        "smtps",
        "submission",
    ];
    let listeners: Vec<TcpListener> = (0..slot_names.len())
        .map(|_| TcpListener::bind("127.0.0.1:0").expect("bind loopback slot"))
        .collect();
    let http_addr = listeners[0].local_addr().unwrap();
    let https_addr = listeners[1].local_addr().unwrap();
    let fd_names = slot_names.join(":");

    let cfg_str = cfg_path.to_str().unwrap();
    let cert_str = cert_path.to_str().unwrap();
    let key_str = key_path.to_str().unwrap();
    let notify_str = notify_path.to_str().unwrap();

    // Deliberately omit JWT_SECRET and SM2_PRIVATE_KEY_FILE: setjoin-server-shim
    // must run http,protocols,workers (no auth) and reach READY=1.
    let mut proc = spawn_with_activated_fds(
        &server_shim,
        &[],
        &listeners,
        &fd_names,
        &[
            ("DB_DSN", &dsn),
            ("DB_DIRECT_DSN", &dsn),
            ("CONFIG_PATH", cfg_str),
            ("NOTIFY_SOCKET", notify_str),
            ("TLS_CERT", cert_str),
            ("TLS_KEY", key_str),
            ("FEDERATION_LOCAL_DOMAIN", "localhost"),
            ("FEDERATION_CERT", cert_str),
            ("FEDERATION_KEY", key_str),
            ("RUST_WORKERS_ON", "http-tls,http-h2c"),
            ("GO_LISTENERS_OFF", "imap,smtp,submission"),
            ("GATEWAY_RUST_AUTH_UPSTREAM", "http://127.0.0.1:9"),
            ("DB_ENCRYPTION_KEY", TEST_DB_ENC_KEY),
            ("INTERNAL_API_KEY", TEST_INTERNAL_KEY),
        ],
    );
    drop(listeners);

    common::wait_notify(&notify_sock, &mut proc, "READY=1", Duration::from_secs(25));

    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    let healthz = client
        .get(format!("http://{http_addr}/_gateway/healthz"))
        .send()
        .await
        .expect("GET /_gateway/healthz over FD 3");
    assert_eq!(healthz.status(), 200);
    assert_eq!(healthz.text().await.unwrap(), "ok\n");

    let ready = client
        .get(format!("https://{https_addr}/ready"))
        .header("connection", "close")
        .send()
        .await
        .expect("GET /ready over HTTPS FD 4");
    assert_eq!(ready.status(), 200);
    let _ = ready.bytes().await;
    drop(client);

    // Verify no leaked non-CLOEXEC execveat FD pointing to sibling `setjoind` on Linux.
    #[cfg(target_os = "linux")]
    {
        let fd_dir = format!("/proc/{}/fd", proc.pid());
        let entries = std::fs::read_dir(&fd_dir).expect("read /proc/<pid>/fd");
        for entry in entries.flatten() {
            if let Ok(target) = std::fs::read_link(entry.path()) {
                assert!(
                    !target.to_string_lossy().ends_with("/setjoind"),
                    "leaked execveat FD {:?} -> {}",
                    entry.file_name(),
                    target.display()
                );
            }
        }
    }

    proc.send_sigterm();
    common::wait_notify(
        &notify_sock,
        &mut proc,
        "STOPPING=1",
        Duration::from_secs(10),
    );
    let status = proc.wait_exit(Duration::from_secs(35)).expect("exit");
    assert!(status.success(), "expected clean exit, got {status}");
}

#[tokio::test]
async fn auth_shim_serves_health_and_jwks_and_unified_mode_supports_static_tls_and_proxy() {
    let dsn = common::test_db_dsn();

    // 1. Real setjoin-auth-shim with config.env + auth.env semantics.
    {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (_, _, auth_shim) = stage_release_n_dir(tmp.path());
        let cfg_path = common::temp_config_file(tmp.path());
        let (notify_path, notify_sock) = common::bind_notify_socket(tmp.path());
        let auth_addr = common::free_addr();
        let listen_str = auth_addr.to_string();

        let mut cmd = Command::new(&auth_shim);
        cmd.env_clear()
            .env("DB_DSN", &dsn)
            .env("DB_DIRECT_DSN", &dsn)
            .env("DB_WORKER_DSN", &dsn)
            .env("CONFIG_PATH", &cfg_path)
            .env("NOTIFY_SOCKET", &notify_path)
            .env("LISTEN_ADDR", &listen_str)
            .env("TLS_CERT", "")
            .env("TLS_KEY", "")
            .env("TRUSTED_PROXY_IP", "127.0.0.1")
            .env("JWT_SECRET", TEST_JWT_SECRET)
            .env("JWT_SIGNING_ALG", "ES256")
            .env("DB_ENCRYPTION_KEY", TEST_DB_ENC_KEY)
            .env("INTERNAL_API_KEY", TEST_INTERNAL_KEY);
        let mut proc = common::OwnedChild::spawn(&mut cmd);

        common::wait_notify(&notify_sock, &mut proc, "READY=1", Duration::from_secs(20));

        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let health = client
            .get(format!("http://{auth_addr}/health"))
            .send()
            .await
            .expect("auth /health");
        assert_eq!(health.status(), 200);
        assert_eq!(health.text().await.unwrap(), r#"{"status":"ok"}"#);

        let jwks = client
            .get(format!("http://{auth_addr}/.well-known/jwks.json"))
            .send()
            .await
            .expect("auth /.well-known/jwks.json");
        assert_eq!(jwks.status(), 200);
        let jwks_json: serde_json::Value = jwks.json().await.expect("parse jwks json");
        assert!(jwks_json["keys"].is_array());

        proc.send_sigterm();
        common::wait_notify(
            &notify_sock,
            &mut proc,
            "STOPPING=1",
            Duration::from_secs(10),
        );
        let status = proc.wait_exit(Duration::from_secs(15)).expect("exit");
        assert!(status.success(), "expected clean auth exit, got {status}");
    }

    // 2. Unified `setjoind --subsystems=all` under static-TLS AND proxy (empty TLS_CERT=) envs.
    for is_proxy in [false, true] {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (setjoind_exe, _, _) = stage_release_n_dir(tmp.path());
        let cfg_path = common::temp_config_file(tmp.path());
        let (notify_path, notify_sock) = common::bind_notify_socket(tmp.path());
        let http_addr = common::free_addr();
        let http_str = http_addr.to_string();

        let mut cmd = Command::new(&setjoind_exe);
        cmd.env_clear()
            .arg("--subsystems=all")
            .env("DB_DSN", &dsn)
            .env("DB_DIRECT_DSN", &dsn)
            .env("DB_WORKER_DSN", &dsn)
            .env("CONFIG_PATH", &cfg_path)
            .env("NOTIFY_SOCKET", &notify_path)
            .env("GATEWAY_ENABLED", "true")
            .env("GATEWAY_LISTEN", &http_str)
            .env("LISTEN_ADDR", "127.0.0.1:0")
            .env("JWT_SECRET", TEST_JWT_SECRET)
            .env("JWT_SIGNING_ALG", "ES256")
            .env("DB_ENCRYPTION_KEY", TEST_DB_ENC_KEY)
            .env("INTERNAL_API_KEY", TEST_INTERNAL_KEY);

        if is_proxy {
            cmd.env("TLS_CERT", "")
                .env("TLS_KEY", "")
                .env("HTTP_MODE", "proxy");
        } else {
            let (cert_path, key_path) = generate_self_signed_cert(tmp.path());
            cmd.env("TLS_CERT", &cert_path).env("TLS_KEY", &key_path);
        }

        let mut proc = common::OwnedChild::spawn(&mut cmd);
        common::wait_notify(&notify_sock, &mut proc, "READY=1", Duration::from_secs(25));

        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap();
        let ready = client
            .get(format!("http://{http_addr}/ready"))
            .send()
            .await
            .expect("unified /ready");
        assert_eq!(ready.status(), 200);

        let jwks = client
            .get(format!("http://{http_addr}/.well-known/jwks.json"))
            .send()
            .await
            .expect("unified /.well-known/jwks.json");
        assert_eq!(jwks.status(), 200);
        let ct = jwks
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert!(ct.starts_with("application/json"), "unexpected ct={ct}");
        let body: serde_json::Value = jwks.json().await.expect("parse unified jwks");
        assert!(body["keys"].is_array(), "missing keys array: {body}");

        proc.send_sigterm();
        common::wait_notify(
            &notify_sock,
            &mut proc,
            "STOPPING=1",
            Duration::from_secs(10),
        );
        let status = proc.wait_exit(Duration::from_secs(15)).expect("exit");
        assert!(
            status.success(),
            "unified (proxy={is_proxy}) exit failed: {status}"
        );
    }
}
