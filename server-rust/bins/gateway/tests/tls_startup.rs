//! #413 executable seam: listener and worker ownership must be unambiguous.
use std::process::{Command, Stdio};

fn base() -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
    c.env_clear()
        .env("GATEWAY_ENABLED", "false")
        .env("GATEWAY_LISTEN", "127.0.0.1:0");
    c
}
#[test]
fn tls_workers_require_their_go_copies_off() {
    for name in ["cert-monitor", "tls-ticket-keys", "http-tls", "http-h2c"] {
        let output = base()
            .env("RUST_WORKERS_ON", name)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .output()
            .unwrap();
        assert!(!output.status.success());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            error.contains(&format!("{name} requires GO_WORKERS_OFF={name}")),
            "{name}: {error}"
        );
    }
}

struct Child(std::process::Child);
impl Drop for Child {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Files(std::path::PathBuf);
impl Drop for Files {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[tokio::test]
async fn activated_https_listener_serves_and_drains_with_the_plain_front_door() {
    check_https(&[], None).await;
}

#[tokio::test]
async fn dns_configuration_failure_keeps_native_https_serving() {
    for settings in [
        vec![("TLS_DNS_PROVIDER", "unknown")],
        vec![("TLS_DNS_PROVIDER", "cloudflare"), ("TLS_DNS_CONFIG", "{}")],
        vec![("TLS_DNS_PROVIDER", "cloudflare"), ("TLS_DNS_CONFIG", "/missing/gofree-tlsfront-dns.json")],
    ] {
        check_https(&settings, Some("managed ACME client creation failed")).await;
    }
}

async fn check_https(settings: &[(&str, &str)], warning: Option<&str>) {
    use http_body_util::BodyExt;
    use hyper_util::rt::TokioIo;
    use std::os::{fd::AsRawFd, unix::process::CommandExt};
    use std::{sync::Arc, time::Duration};
    use tokio_rustls::rustls::{
        self,
        pki_types::{pem::PemObject, CertificateDer, ServerName},
    };
    let prefix = std::env::var("GOFREE_RESOURCE_PREFIX").unwrap_or_else(|_| "gofree-tlsfront".into());
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../test-results").join(&prefix)
        .join(format!("activated-{}-{}", std::process::id(), {
            // Both cases run in this process on parallel threads: one directory each.
            static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            NEXT.fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        }));
    std::fs::create_dir_all(&root).unwrap();
    let files = Files(root);
    let recorded: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/tlsfront/tls13-resumed.json"
    ))
    .unwrap();
    std::fs::write(
        files.0.join("cert.pem"),
        recorded["certificate_pem"].as_str().unwrap(),
    )
    .unwrap();
    std::fs::write(
        files.0.join("key.pem"),
        recorded["public_test_key_pem"].as_str().unwrap(),
    )
    .unwrap();
    let executable = files.0.join(format!("{prefix}-gateway"));
    std::fs::hard_link(env!("CARGO_BIN_EXE_setjoin-gateway"), &executable).unwrap();
    let http = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let https = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = https.local_addr().unwrap();
    let fds = [http.as_raw_fd(), https.as_raw_fd()];
    let mut command = Command::new("bash");
    command
        .env_clear()
        .env("GATEWAY_AUTH_UPSTREAM", "http://127.0.0.1:1")
        .env("RUST_WORKERS_ON", "http-tls")
        .env("GO_WORKERS_OFF", "http-tls,http-h2c")
        .env("TLS_CERT_FILE", files.0.join("cert.pem"))
        .env("TLS_KEY_FILE", files.0.join("key.pem"));
    if warning.is_some() {
        command
            .env("RUST_WORKERS_ON", "http-tls,acme-renewal")
            .env("GO_WORKERS_OFF", "http-tls,http-h2c,acme-renewal")
            .env("TLS_AUTOCERT_DOMAINS", "localhost")
            .env("TLS_AUTOCERT_EMAIL", "ops@example.test")
            .env("TLS_AUTOCERT_CACHE_DIR", files.0.join("cache"))
            .env("TLS_AUTOCERT_CHALLENGE", "dns-01")
            .envs(settings.iter().copied());
    }
    command
        .args([
            "-c",
            "export LISTEN_PID=$$ LISTEN_FDS=2 LISTEN_FDNAMES=http:https; exec \"$1\"",
            "gofree-tlsfront-launcher",
        ])
        .arg(&executable);
    unsafe {
        command.pre_exec(move || {
            let mut saved = [0; 2];
            for (i, fd) in fds.iter().enumerate() {
                saved[i] = libc::fcntl(*fd, libc::F_DUPFD_CLOEXEC, 64);
                if saved[i] < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            for (i, fd) in saved.into_iter().enumerate() {
                let target = 3 + i as i32;
                if libc::dup2(fd, target) < 0 || libc::fcntl(target, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                libc::close(fd);
            }
            Ok(())
        });
    }
    let mut child = Child(
        command
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(files.0.join("stderr.log")).unwrap(),
            ))
            .spawn()
            .unwrap(),
    );
    drop(http);
    drop(https);
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_file(files.0.join("cert.pem")).unwrap())
        .unwrap();
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let mut connected = None;
    for _ in 0..100 {
        if let Some(status) = child.0.try_wait().unwrap() {
            panic!(
                "gateway exited {status}: {}",
                std::fs::read_to_string(files.0.join("stderr.log")).unwrap()
            )
        }
        if let Ok(tcp) = tokio::net::TcpStream::connect(addr).await {
            connected = Some(
                tokio::time::timeout(
                    Duration::from_secs(5),
                    connector.connect(ServerName::try_from("localhost").unwrap(), tcp),
                )
                .await
                .expect("TLS startup timed out")
                .unwrap(),
            );
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let tls = connected.expect("HTTPS listener did not start");
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let response = sender
        .send_request(
            hyper::Request::get("/_gateway/healthz")
                .header("host", "localhost")
                .body(http_body_util::Empty::<bytes::Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    drop(sender);
    driver.await.unwrap().unwrap();
    unsafe {
        libc::kill(child.0.id() as i32, libc::SIGTERM);
    }
    let status = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        status.success(),
        "{}",
        std::fs::read_to_string(files.0.join("stderr.log")).unwrap()
    );
    if let Some(warning) = warning {
        let error = std::fs::read_to_string(files.0.join("stderr.log")).unwrap();
        assert!(error.contains(warning), "{error}");
    }
    assert_eq!(body, "ok\n");
    assert!(tokio::net::TcpStream::connect(addr).await.is_err());
}

#[tokio::test]
async fn invalid_connection_capacity_refuses_startup() {
    for value in ["0", "-1", "many", "18446744073709551615"] {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
        command
            .env_clear()
            .env("GATEWAY_LISTEN", "127.0.0.1:0")
            .env("GATEWAY_AUTH_UPSTREAM", "http://127.0.0.1:1")
            .env("GATEWAY_MAX_CONNECTIONS", value)
            .kill_on_drop(true);
        let output = tokio::time::timeout(std::time::Duration::from_secs(5), command.output())
            .await
            .expect("invalid capacity opened a listener")
            .unwrap();
        assert!(
            !output.status.success(),
            "invalid capacity {value} was accepted"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("GATEWAY_MAX_CONNECTIONS"));
    }
}
