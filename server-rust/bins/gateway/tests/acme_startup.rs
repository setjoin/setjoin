//! #305: the executable's ACME and setup-control startup guards and lifecycle. Rust takes
//! `acme-renewal`, the :80 descriptor and the control socket only with Go's copy switched off.
use crate::common::boot::CommandBootExt;
mod common;
use std::{
    io::{Read, Write},
    os::{fd::AsRawFd, unix::fs::PermissionsExt, unix::process::CommandExt},
    path::Path,
    process::{Command, Stdio},
    time::Duration,
};

fn base() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
    c.env_clear()
        .env("GATEWAY_ENABLED", "false")
        .env("GATEWAY_LISTEN", "127.0.0.1:0");
    c
}

fn refused(mut command: Command) -> String {
    let out = command
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output_boot()
        .unwrap();
    assert!(!out.status.success());
    String::from_utf8_lossy(&out.stderr).into_owned()
}

struct Child(crate::common::boot::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn sigterm(child: &mut Child) {
    unsafe { libc::kill(child.0.id() as i32, libc::SIGTERM) };
    let _ = child.0.wait();
}

fn tmp(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("gofree-plat7-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn acme_renewal_needs_go_off_and_the_challenge_descriptor() {
    let mut c = base();
    c.env("RUST_WORKERS_ON", "acme-renewal");
    assert!(refused(c).contains("acme-renewal requires GO_WORKERS_OFF=acme-renewal"));

    let mut c = base();
    c.env("RUST_WORKERS_ON", "acme-renewal")
        .env("TLS_AUTOCERT_CHALLENGE", "http-01")
        .env("GO_WORKERS_OFF", "acme-renewal");
    assert!(refused(c).contains("socket-activated :80 descriptor named `acme`"));
}

/// Parent-owned sockets stand in for systemd's: fd 3 is the gateway, fd 4 the `acme` :80 listener.
fn activated(mut command: Command, extra: &[&std::net::TcpListener]) -> Child {
    let fds: Vec<i32> = extra.iter().map(|l| l.as_raw_fd()).collect();
    let names = ["gateway", "acme"][..extra.len()].join(":");
    command
        .arg("-c")
        .arg(format!(
            "export LISTEN_PID=$$ LISTEN_FDS={} LISTEN_FDNAMES={names}; exec \"$1\"",
            extra.len()
        ))
        .arg("launcher")
        .arg(env!("CARGO_BIN_EXE_setjoin-gateway"));
    unsafe {
        command.pre_exec(move || {
            unsafe extern "C" {
                fn dup2(oldfd: i32, newfd: i32) -> i32;
                fn fcntl(fd: i32, cmd: i32, ...) -> i32;
            }
            for (i, fd) in fds.iter().enumerate() {
                let target = 3 + i as i32;
                if dup2(*fd, target) < 0 || fcntl(target, 2, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Child(
        command
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn_boot()
            .unwrap(),
    )
}

fn bash() -> Command {
    let mut c = Command::new("bash");
    c.env_clear()
        .env("GATEWAY_ENABLED", "false")
        .env("HOSTNAME", "mail.test");
    c
}

fn get(addr: std::net::SocketAddr, target: &str) -> String {
    let mut s = std::net::TcpStream::connect(addr).unwrap();
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    write!(
        s,
        "GET {target} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

#[test]
fn the_activated_acme_descriptor_needs_go_port80_off_and_then_redirects() {
    let http = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let acme = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = acme.local_addr().unwrap();
    let c = activated(bash(), &[&http, &acme]);
    let mut c = c;
    let mut stderr = String::new();
    c.0.stderr
        .take()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    assert!(
        stderr.contains("requires GO_WORKERS_OFF=http-port80"),
        "{stderr}"
    );

    let mut command = bash();
    command.env("GO_WORKERS_OFF", "http-port80");
    let mut child = activated(command, &[&http, &acme]);
    let mut response = String::new();
    for _ in 0..100 {
        std::thread::sleep(Duration::from_millis(100));
        if let Ok(r) = std::panic::catch_unwind(|| get(addr, "/page?x=1")) {
            response = r;
            break;
        }
    }
    assert!(response.starts_with("HTTP/1.1 301"), "{response}");
    assert!(
        response.contains("location: https://mail.test/page?x=1"),
        "{response}"
    );
    sigterm(&mut child);
}

#[test]
fn acme_renewal_with_a_fresh_certificate_starts_without_contacting_a_ca() {
    let dir = tmp("acme-fresh");
    let run = |args: &[&str]| {
        assert!(Command::new("openssl")
            .args(args)
            .current_dir(&dir)
            .output_boot()
            .unwrap()
            .status
            .success());
    };
    run(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "k.pem",
        "-out",
        "c.pem",
        "-days",
        "60",
        "-subj",
        "/CN=mail.test",
        "-addext",
        "subjectAltName=DNS:mail.test",
    ]);
    let mut blob = std::fs::read(dir.join("k.pem")).unwrap();
    blob.extend(std::fs::read(dir.join("c.pem")).unwrap());
    let cache = dir.join("cache");
    setjoin_acme::cache::DirCache::new(&cache)
        .put("mail.test", &blob)
        .unwrap();
    let http = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let acme = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut command = bash();
    command
        .env("RUST_WORKERS_ON", "acme-renewal")
        .env("GO_WORKERS_OFF", "acme-renewal,http-port80")
        .env("TLS_AUTOCERT_DOMAINS", "mail.test")
        .env("TLS_AUTOCERT_CHALLENGE", "http-01")
        .env("TLS_AUTOCERT_EMAIL", "ops@example.test")
        .env("TLS_AUTOCERT_CACHE_DIR", &cache);
    let mut child = activated(command, &[&http, &acme]);
    for _ in 0..100 {
        if cache.join("account.key").exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(
        cache.join("account.key").exists(),
        "the worker created the account key"
    );
    assert_eq!(
        std::fs::metadata(cache.join("account.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    sigterm(&mut child);
    assert!(child.0.try_wait().unwrap().is_some());

    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn setup_control_needs_go_off_then_serves_a_0600_socket_and_removes_it_on_sigterm() {
    let mut c = base();
    c.env("RUST_WORKERS_ON", "setup-control");
    assert!(refused(c).contains("setup-control requires GO_WORKERS_OFF=setup-control"));

    let dir = tmp("control");
    let socket = dir.join("run").join("control.sock");
    let mut child = Child(
        base()
            .env("RUST_WORKERS_ON", "setup-control")
            .env("GO_WORKERS_OFF", "setup-control")
            .env("DB_DSN", &std::env::var("TEST_DB_DSN").expect("disposable boot database"))
            .env("SETJOIN_CONTROL_SOCKET", &socket)
            .env("SETJOIN_SETUP_TOKEN", "tok")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn_boot()
            .unwrap(),
    );
    for _ in 0..100 {
        if socket.exists() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert_eq!(
        std::fs::metadata(&socket).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let ask = |token: Option<&str>| {
        let mut s = std::os::unix::net::UnixStream::connect(&socket).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let header = token
            .map(|t| format!("X-Setup-Token: {t}\r\n"))
            .unwrap_or_default();
        write!(s, "POST /setup/preflight HTTP/1.1\r\nHost: c\r\nConnection: close\r\nContent-Length: 2\r\n{header}\r\n{{}}").unwrap();
        let mut out = String::new();
        s.read_to_string(&mut out).unwrap();
        out
    };
    assert!(ask(None).starts_with("HTTP/1.1 403"));
    assert!(ask(Some("wrong")).starts_with("HTTP/1.1 403"));
    // The right token passes the gate (validation then fails on the empty body).
    assert!(ask(Some("tok")).starts_with("HTTP/1.1 400"));
    sigterm(&mut child);
    assert!(
        !Path::new(&socket).exists(),
        "the socket is removed at shutdown"
    );
}
