//! Shared test harness for `setjoind` end-to-end integration suites (#543).

#![allow(dead_code)]

use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tokio_postgres::NoTls;

/// Shared test JWT secret used across suites sharing one disposable DB
/// (because `signing_keys.private_key_enc` is sealed under `JWT_SECRET`).
pub const TEST_JWT_SECRET: &str = "setjoind-test-jwt-secret-at-least-32-bytes-long!!";
pub const TEST_DB_ENC_KEY: &str = "setjoind-test-db-enc-key-32-bytes!!";
pub const TEST_INTERNAL_KEY: &str = "setjoind-internal-api-key-32-bytes-long!!";

/// RAII child process wrapper that always kills and reaps on drop.
pub struct OwnedChild {
    pub child: Child,
}

impl OwnedChild {
    pub fn spawn(cmd: &mut Command) -> Self {
        let child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn setjoind");
        Self { child }
    }

    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    pub fn send_sigterm(&self) {
        unsafe {
            libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM);
        }
    }

    pub fn wait_exit(&mut self, timeout: Duration) -> Option<std::process::ExitStatus> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait().expect("try_wait") {
                return Some(status);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    pub fn read_stderr(&mut self) -> String {
        let mut buf = String::new();
        if let Some(stderr) = self.child.stderr.as_mut() {
            let _ = stderr.read_to_string(&mut buf);
        }
        buf
    }

    pub fn read_stdout(&mut self) -> String {
        let mut buf = String::new();
        if let Some(stdout) = self.child.stdout.as_mut() {
            let _ = stdout.read_to_string(&mut buf);
        }
        buf
    }
}

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

/// Path to the compiled `setjoind` executable.
pub fn setjoind_bin() -> &'static str {
    env!("CARGO_BIN_EXE_setjoind")
}

/// Required live PostgreSQL DSN (`TEST_DB_DSN` or `DB_DSN`).
pub fn test_db_dsn() -> String {
    std::env::var("TEST_DB_DSN")
        .ok()
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("DB_DSN").ok().filter(|s| !s.is_empty()))
        .expect("TEST_DB_DSN (or DB_DSN) must point to a live schema-loaded PostgreSQL database")
}

/// Reserve a free loopback port and drop the listener immediately.
pub fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    listener.local_addr().expect("local_addr")
}

/// Create a pre-populated 0600 `config.env` file inside `dir` so
/// `setjoin_boot::secrets::bootstrap` never attempts to write `/etc/mail/config.env`.
pub fn temp_config_file(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("config.env");
    std::fs::write(&path, "# test config.env\n").expect("write temp config.env");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .expect("chmod 0600 temp config.env");
    path
}

/// Bind a temporary Unix datagram socket for `NOTIFY_SOCKET` inspection.
pub fn bind_notify_socket(dir: &Path) -> (PathBuf, UnixDatagram) {
    let path = dir.join("notify.sock");
    let sock = UnixDatagram::bind(&path).expect("bind notify socket");
    sock.set_nonblocking(true).expect("nonblocking notify sock");
    (path, sock)
}

/// Wait until a specific `sd_notify` message (e.g. `"READY=1"` or `"STOPPING=1"`)
/// arrives on `sock`, failing early with child stderr if `proc` exits.
pub fn wait_notify(
    sock: &UnixDatagram,
    proc: &mut OwnedChild,
    expected: &str,
    timeout: Duration,
) -> Vec<String> {
    let deadline = Instant::now() + timeout;
    let mut seen = Vec::new();
    let mut buf = [0u8; 256];
    loop {
        match sock.recv(&mut buf) {
            Ok(n) => {
                let msg = String::from_utf8_lossy(&buf[..n]).into_owned();
                seen.push(msg.clone());
                if msg == expected {
                    return seen;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => panic!("notify recv error: {e}"),
        }
        if let Some(status) = proc.child.try_wait().expect("try_wait") {
            let stderr = proc.read_stderr();
            panic!(
                "setjoind exited early ({status}) before {expected:?}; seen={seen:?}\nstderr:\n{stderr}"
            );
        }
        if Instant::now() >= deadline {
            let _ = proc.child.kill();
            let _ = proc.child.wait();
            let stderr = proc.read_stderr();
            panic!("timed out waiting for {expected:?}; seen={seen:?}\nstderr:\n{stderr}");
        }
        std::thread::sleep(Duration::from_millis(15));
    }
}

/// Drain any immediately queued datagrams from `sock`.
pub fn drain_notify(sock: &UnixDatagram) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = [0u8; 256];
    while let Ok(n) = sock.recv(&mut buf) {
        out.push(String::from_utf8_lossy(&buf[..n]).into_owned());
    }
    out
}

/// Seed an enabled test user + primary mailbox in PostgreSQL for real login + JMAP tests.
pub async fn seed_test_user(dsn: &str, email: &str, password: &str) -> i64 {
    let (client, conn) = tokio_postgres::connect(dsn, NoTls)
        .await
        .expect("connect test DB");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let domain = email.split('@').nth(1).unwrap_or("example.test");
    let username = email.split('@').next().unwrap_or("testuser");
    let domain_row = client
        .query_one(
            "INSERT INTO domains (name, is_local) VALUES ($1, TRUE)
             ON CONFLICT (name) DO UPDATE SET is_local = TRUE
             RETURNING id",
            &[&domain],
        )
        .await
        .expect("seed domain");
    let domain_id: i64 = domain_row.get(0);

    let hash = bcrypt::hash_with_result(password, 4)
        .expect("bcrypt hash")
        .format_for_version(bcrypt::Version::TwoA);

    let user_id: i64 = match client
        .query_opt(
            "SELECT id FROM users WHERE lower(email) = lower($1) LIMIT 1",
            &[&email],
        )
        .await
        .expect("lookup user")
    {
        Some(row) => {
            let id: i64 = row.get(0);
            client
                .execute(
                    "UPDATE users SET password_hash = $1, enabled = TRUE, must_change_password = FALSE, mfa_exempt = TRUE WHERE id = $2",
                    &[&hash, &id],
                )
                .await
                .expect("update user");
            id
        }
        None => client
            .query_one(
                "INSERT INTO users (username, domain_id, email, password_hash, display_name, enabled, is_local_admin, must_change_password, mfa_exempt)
                 VALUES ($1, $2, $3, $4, $5, TRUE, FALSE, FALSE, TRUE)
                 RETURNING id",
                &[&username, &domain_id, &email, &hash, &"Test User"],
            )
            .await
            .expect("insert user")
            .get(0),
    };

    if client
        .query_opt(
            "SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1",
            &[&user_id],
        )
        .await
        .expect("lookup primary mailbox")
        .is_none()
    {
        client
            .execute(
                "INSERT INTO mailboxes (domain_id, user_id, email, display_name, is_primary, enabled)
                 VALUES ($1, $2, $3, $4, TRUE, TRUE)",
                &[&domain_id, &user_id, &email, &"Test User"],
            )
            .await
            .expect("seed primary mailbox");
    }

    user_id
}

/// Wait until a loopback TCP endpoint answers an HTTP GET on `path`.
pub async fn wait_http_ready(addr: SocketAddr, path: &str, timeout: Duration) {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("http client");
    let url = format!("http://{addr}{path}");
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(resp) = client.get(&url).send().await {
            if resp.status().is_success() {
                return;
            }
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for HTTP readiness on {url}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
