//! Complete, owned boot inputs for executable tests that configure DB_DSN.
//! Serial process tests only: each child restores the secret rows it can upgrade.
use base64::Engine;
use std::{
    io::{self, Read, Write},
    net::TcpListener,
    ops::{Deref, DerefMut},
    os::unix::{fs::OpenOptionsExt, process::CommandExt},
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    thread::JoinHandle,
    time::Duration,
};
static NEXT: AtomicU64 = AtomicU64::new(0);
const CANDIDATES: &str = "((key LIKE 'ad_sync_%' OR key LIKE 'ldap_sync_%') AND (encrypted OR right(key,4)='_enc')) OR key='assist.api_key'";

pub struct Child {
    inner: Option<std::process::Child>,
    _fixture: Option<Fixture>,
}
impl std::fmt::Debug for Child {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootChild")
            .field("id", &self.inner.as_ref().map(|c| c.id()))
            .finish()
    }
}
impl Deref for Child {
    type Target = std::process::Child;
    fn deref(&self) -> &Self::Target {
        self.inner.as_ref().unwrap()
    }
}
impl DerefMut for Child {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.inner.as_mut().unwrap()
    }
}
impl Child {
    pub fn wait_with_output(mut self) -> io::Result<Output> {
        self.inner.take().unwrap().wait_with_output()
    }
}
impl Drop for Child {
    fn drop(&mut self) {
        if let Some(child) = self.inner.as_mut() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub trait CommandBootExt {
    fn spawn_boot(&mut self) -> io::Result<Child>;
    fn output_boot(&mut self) -> io::Result<Output>;
}
impl CommandBootExt for Command {
    fn spawn_boot(&mut self) -> io::Result<Child> {
        let fixture = Fixture::prepare(self)?;
        Ok(Child {
            inner: Some(self.spawn()?),
            _fixture: fixture,
        })
    }
    fn output_boot(&mut self) -> io::Result<Output> {
        let _fixture = Fixture::prepare(self)?;
        self.output()
    }
}
struct Fixture {
    dir: PathBuf,
    dsn: String,
    snapshot: String,
    health_before: Option<i64>,
    stop: Arc<AtomicBool>,
    server: Option<JoinHandle<()>>,
}
fn has(command: &Command, key: &str) -> bool {
    command
        .get_envs()
        .any(|(k, v)| k == key && v.is_some_and(|v| !v.is_empty()))
}
fn specified(command: &Command, key: &str) -> bool {
    command.get_envs().any(|(k, v)| k == key && v.is_some())
}
fn psql(dsn: &str, query: &str) -> io::Result<String> {
    let mut child = Command::new("psql")
        .args([dsn, "-XAt", "-v", "ON_ERROR_STOP=1"])
        .env(
            "PGOPTIONS",
            "-c lock_timeout=5000 -c statement_timeout=10000",
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    child.stdin.take().unwrap().write_all(query.as_bytes())?;
    let output = child.wait_with_output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "boot fixture SQL failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    String::from_utf8(output.stdout).map_err(io::Error::other)
}
impl Fixture {
    fn prepare(command: &mut Command) -> io::Result<Option<Self>> {
        if !has(command, "DB_DSN") {
            return Ok(None);
        }
        let dsn = std::env::var("TEST_DB_DSN")
            .map_err(|_| io::Error::other("TEST_DB_DSN required for server boot fixture"))?;
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("gofree-boot-startup-{}-{id}", std::process::id()));
        std::fs::create_dir(&dir)?;
        let mut fixture = Self {
            dir,
            dsn,
            snapshot: String::new(),
            health_before: None,
            stop: Arc::new(AtomicBool::new(false)),
            server: None,
        };
        fixture.snapshot=psql(&fixture.dsn,&format!("SELECT coalesce(jsonb_agg(to_jsonb(s)),'[]'::jsonb) FROM system_config s WHERE {CANDIDATES};"))?;
        fixture.health_before = Some(
            psql(
                &fixture.dsn,
                "SELECT coalesce(max(id),0) FROM health_history;",
            )?
            .trim()
            .parse()
            .map_err(io::Error::other)?,
        );
        if !has(command, "CONFIG_PATH") {
            let path = fixture.dir.join("config.env");
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)?
                .write_all(b"owned executable test configuration\n")?;
            command.env("CONFIG_PATH", path);
        }
        if !specified(command, "DB_OWNER_DSN") {
            command.env("DB_OWNER_DSN", &fixture.dsn);
        }
        if !specified(command, "DB_WORKER_DSN") {
            command.env("DB_WORKER_DSN", &fixture.dsn);
        }
        if !specified(command, "DB_ENCRYPTION_KEY") {
            command.env("DB_ENCRYPTION_KEY", "22".repeat(32));
        }
        if !specified(command, "S3_ACCESS_KEY") && !specified(command, "MINIO_ACCESS_KEY") {
            command.env("S3_ACCESS_KEY", "test-access");
        }
        if !specified(command, "S3_SECRET_KEY") && !specified(command, "MINIO_SECRET_KEY") {
            command.env("S3_SECRET_KEY", "test-secret");
        }
        if !specified(command, "S3_ENDPOINT") && !specified(command, "MINIO_ENDPOINT") {
            let listener = TcpListener::bind("127.0.0.1:0")?;
            command.env("MINIO_ENDPOINT", listener.local_addr()?.to_string());
            listener.set_nonblocking(true)?;
            let stop = fixture.stop.clone();
            fixture.server=Some(std::thread::Builder::new().name(format!("gofree-boot-s3-{id}")).spawn(move|| {
                while !stop.load(Ordering::Acquire) {
                    let (mut stream,_)=match listener.accept() { Ok(value)=>value, Err(e) if e.kind()==io::ErrorKind::WouldBlock=>{std::thread::sleep(Duration::from_millis(5));continue;},Err(_)=>break };
                    let _=stream.set_read_timeout(Some(Duration::from_secs(2)));
                    let _=stream.set_write_timeout(Some(Duration::from_secs(2)));
                    let mut request=Vec::new();let mut buffer=[0u8;4096];
                    while !request.windows(4).any(|w|w==b"\r\n\r\n") && request.len()<65536 {
                        match stream.read(&mut buffer) { Ok(0)|Err(_)=>break,Ok(n)=>request.extend_from_slice(&buffer[..n]) }
                    }
                    let text=String::from_utf8_lossy(&request);
                    let header_end=text.find("\r\n\r\n").map(|i|i+4).unwrap_or(request.len());
                    let length=text.lines().find_map(|line|line.to_ascii_lowercase().strip_prefix("content-length:").and_then(|s|s.trim().parse::<usize>().ok())).unwrap_or(0).min(1<<20);
                    let first=text.lines().next().unwrap_or("").to_string();
                    while request.len()<header_end+length { match stream.read(&mut buffer) { Ok(0)|Err(_)=>break,Ok(n)=>request.extend_from_slice(&buffer[..n]) } }
                    let body=if first.contains("location") { "<LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>" }
                        else if first.contains("uploads") { "<ListMultipartUploadsResult><Bucket>mailblobs</Bucket><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>" }
                        else { "" };
                    let response=format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\nContent-Type: application/xml\r\n\r\n{body}",body.len());
                    let _=stream.write_all(response.as_bytes());
                }
            })?);
        }
        if !specified(command, "NETWORK_MODE") && !specified(command, "SETJOIN_CONFIG") {
            command.env("NETWORK_MODE", "airgap");
        }
        let prefix =
            std::env::var("GOFREE_RESOURCE_PREFIX").unwrap_or_else(|_| "gofree-boot".into());
        command.arg0(format!("{prefix}-gateway-{}-{id}", std::process::id()));
        Ok(Some(fixture))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let mut errors = Vec::new();
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.server.take() {
            let _ = thread.join();
        }
        if !self.snapshot.is_empty() {
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(self.snapshot.as_bytes());
            let query=format!("INSERT INTO system_config SELECT * FROM jsonb_populate_recordset(NULL::system_config,convert_from(decode('{encoded}','base64'),'UTF8')::jsonb) ON CONFLICT(key) DO UPDATE SET value=excluded.value,encrypted=excluded.encrypted,description=excluded.description,updated_at=excluded.updated_at,updated_by=excluded.updated_by;");
            if let Err(error) = psql(&self.dsn, &query) {
                errors.push(format!("owned boot secret restoration failed: {error}"));
            }
        }
        if let Some(before) = self.health_before {
            if let Err(error) = psql(
                &self.dsn,
                &format!(
                    "DELETE FROM health_history WHERE check_name='minio_connectivity' AND id>{};",
                    before
                ),
            ) {
                errors.push(format!("owned boot health restoration failed: {error}"));
            }
        }
        if let Err(error) = std::fs::remove_dir_all(&self.dir) {
            errors.push(format!(
                "owned boot fixture cleanup failed for {}: {error}",
                self.dir.display()
            ));
        }
        if !errors.is_empty() {
            if std::thread::panicking() {
                eprintln!("{}", errors.join("\n"));
            } else {
                panic!("{}", errors.join("\n"));
            }
        }
    }
}
