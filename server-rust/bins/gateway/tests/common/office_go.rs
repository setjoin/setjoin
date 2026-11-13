//! Frozen Go recording process. Never used by ordinary Rust replay.
use crate::common::{fake_upstream, full, BoxError};
use hyper::Response;
use setjoin_conformance::harness::Db;
use std::{
    io::Write,
    net::SocketAddr,
    path::PathBuf,
    process::{Child, Command, Stdio},
};

pub struct GoOracle {
    pub address: SocketAddr,
    name: String,
    child: Child,
    key: PathBuf,
}

fn ledger(line: &str) -> Result<(), BoxError> {
    if let Ok(path) = std::env::var("GOFREE_RESOURCE_LEDGER") {
        writeln!(
            std::fs::OpenOptions::new().append(true).open(path)?,
            "{line}"
        )?;
    }
    Ok(())
}

impl Drop for GoOracle {
    fn drop(&mut self) {
        let result = Command::new("docker")
            .args(["stop", "--time", "10", &self.name])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.key);
        if !result.is_ok_and(|result| result.success()) {
            let absent = Command::new("docker")
                .args(["inspect", "--type", "container", &self.name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|status| !status.success());
            if !absent {
                eprintln!("oracle cleanup failed for {}", self.name);
            }
        }
        let _ = ledger(&format!(
            "Stopped owned oracle container {}; removed test key {}",
            self.name,
            self.key.display()
        ));
    }
}

/// Each case gets its own Go process pointed at that case's fake S3 endpoint.
/// Its only database is the explicitly supplied disposable fixture database.
pub async fn start(db: &Db, s3: SocketAddr) -> Result<Option<GoOracle>, BoxError> {
    start_with_clamd(db, s3, None).await
}

pub async fn start_with_clamd(
    db: &Db,
    s3: SocketAddr,
    clamd: Option<SocketAddr>,
) -> Result<Option<GoOracle>, BoxError> {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::os::unix::fs::OpenOptionsExt;
    let Some(binary) = std::env::var_os("GOFREE_RECORD_GO_BINARY") else {
        return Ok(None);
    };
    let binary = std::fs::canonicalize(binary)?;
    let parent = binary
        .parent()
        .ok_or("Go binary needs an absolute parent")?;
    let file = binary
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("invalid Go binary filename")?;
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_nanos();
    let name = format!("gofree-office1-http-oracle-{unique}");
    let key = std::env::temp_dir().join(format!("gofree-office1-continuity-{unique}.pem"));
    ledger(&format!("Planned oracle container {name}, default local Docker context; key {} (temporary); binary {}; assigned fixture DB only",key.display(),binary.display()))?;
    let mut der = vec![
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ];
    der.extend_from_slice(&[0x22; 32]);
    let mut output = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&key)?;
    writeln!(
        output,
        "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----",
        STANDARD.encode(der)
    )?;
    drop(output);
    let jwks = fake_upstream(|_| async {
        Response::builder()
            .header("content-type", "application/json")
            .body(full(
                include_bytes!("../../../../tests/conformance/jmap/test-jwks.json").as_slice(),
            ))
            .unwrap()
    })
    .await;
    let reserved = setjoin_conformance::ports::listener().await;
    let address = reserved.local_addr()?;
    drop(reserved);
    let workers = include_str!(
        "../../../../../mailserver/cmd/mailserverd/testdata/worker_launch_inventory.golden"
    )
    .lines()
    .filter_map(|line| {
        let mut fields = line.split('|');
        let kind = fields.next()?;
        let name = fields.next()?;
        (matches!(kind, "named" | "managed" | "cron-task")
            && !matches!(
                name,
                "http-h2c"
                    | "db-listener"
                    | "config-reload"
                    | "session-denylist-refresh"
                    | "auth-chain-reload"
            ))
        .then_some(name)
    })
    .collect::<Vec<_>>()
    .join(",");
    let mut command = Command::new("docker");
    command
        .args([
            "run",
            "--rm",
            "--name",
            &name,
            "--label",
            "org.setjoin.task=gofree-office1",
            "--network",
            "host",
            "--tmpfs",
            "/etc/mail:rw,mode=0700",
            "-w",
            "/src",
        ])
        .arg("-v")
        .arg(format!(
            "{}:/src:ro",
            PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                .join("../../..")
                .canonicalize()?
                .display()
        ))
        .arg("-v")
        .arg(format!("{}:/evidence", parent.display()))
        .arg("-v")
        .arg(format!("{}:/run/continuity.pem:ro", key.display()));
    let direct = db.dsn.clone();
    for (key, value) in [
        ("DB_DSN", db.dsn.clone()),
        ("DB_WORKER_DSN", db.dsn.clone()),
        ("DB_OWNER_DSN", db.dsn.clone()),
        ("DB_DIRECT_DSN", direct),
        ("DB_ENCRYPTION_KEY", "22".repeat(32)),
        ("JWT_SECRET", "blobs1-test-jwt-secret-for-recording".into()),
        (
            "AUTHSERVER_JWKS_URL",
            format!("http://{jwks}/.well-known/jwks.json"),
        ),
        ("AUTHSERVER_URL", "http://127.0.0.1:1".into()),
        ("CONTINUITY_SIGNING_KEY_FILE", "/run/continuity.pem".into()),
        ("CONTINUITY_SIGNING_KEY_ID", "blobs1-test-continuity".into()),
        ("S3_ENDPOINT", format!("http://{s3}")),
        ("S3_ACCESS_KEY", "test-access".into()),
        ("S3_SECRET_KEY", "test-secret".into()),
        ("S3_BUCKET", "mailblobs".into()),
        ("S3_SECURE", "false".into()),
        ("LISTEN_ADDR", address.to_string()),
        ("HTTP_MODE", "serve".into()),
        ("SMTP_INBOUND_ADDR", "127.0.0.1:0".into()),
        ("SMTP_SUBMISSION_ADDR", "127.0.0.1:0".into()),
        ("IMAP_ADDR", "127.0.0.1:0".into()),
        ("NETWORK_MODE", "airgap".into()),
        ("DNSSEC_ENABLED", "false".into()),
        ("GO_WORKERS_OFF", workers),
        ("GOMAXPROCS", "1".into()),
        ("CORE_RATE_LIMIT", "100000".into()),
        ("ADMIN_RATE_LIMIT", "100000".into()),
    ] {
        command.arg("-e").arg(format!("{key}={value}"));
    }
    if let Ok(path) = std::env::var("SSL_CERT_FILE") {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../..")
            .canonicalize()?;
        let cert = std::path::Path::new(&path);
        let path = if let Ok(relative) = cert.strip_prefix(&root) {
            format!("/src/{}", relative.display())
        } else {
            command
                .arg("-v")
                .arg(format!("{path}:/run/office-oracle-ca.pem:ro"));
            "/run/office-oracle-ca.pem".into()
        };
        command.arg("-e").arg(format!("SSL_CERT_FILE={path}"));
    }
    if let Some(clamd) = clamd {
        command.arg("-e").arg(format!("CLAMAV_ADDR={clamd}"));
    }
    if let Ok(dir) = std::env::var("GOFREE_GO_COVERAGE_DIR") {
        std::fs::create_dir_all(&dir)?;
        command
            .arg("-v")
            .arg(format!("{dir}:/coverage"))
            .args(["-e", "GOCOVERDIR=/coverage"]);
    }
    let log = parent.join(format!("{name}.log"));
    let stdout = std::fs::File::create(&log)?;
    command
        .arg("setjoin-ci-linux-tc:local-amd64")
        .arg(format!("/evidence/{file}"))
        .stdout(stdout.try_clone()?)
        .stderr(stdout);
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = std::fs::remove_file(&key);
            return Err(error.into());
        }
    };
    let mut server = GoOracle {
        address,
        name,
        child,
        key,
    };
    ledger(&format!(
        "Started oracle Docker client PID {}, container {}; log {}",
        server.child.id(),
        server.name,
        log.display()
    ))?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        if server.child.try_wait()?.is_some() {
            return Err(format!("Go oracle exited; see {}", log.display()).into());
        }
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let ready = tokio::time::timeout(std::time::Duration::from_millis(500), async {
            let mut stream = tokio::net::TcpStream::connect(address).await?;
            stream
                .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .await?;
            let mut response = [0; 64];
            let n = stream.read(&mut response).await?;
            Ok::<_, std::io::Error>(n > 0 && response[..n].starts_with(b"HTTP/1.1 "))
        })
        .await;
        if matches!(ready, Ok(Ok(true))) {
            return Ok(Some(server));
        }
        if tokio::time::Instant::now() > deadline {
            return Err(format!("Go oracle did not listen; see {}", log.display()).into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
}
