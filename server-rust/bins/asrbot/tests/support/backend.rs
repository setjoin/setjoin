//! Runs the frozen Go `asrbotd` (in the CI image, host network) or the Rust one,
//! for the recorded-oracle tests.

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};

pub const GO_IMAGE: &str = "setjoin-ci-linux-tc:local-amd64";

#[derive(Clone)]
pub enum Backend {
    /// The frozen Go binary (built from `asrbot/` at the recorded source revision).
    Go(PathBuf),
    Rust,
}

impl Backend {
    /// `GOFREE_RECORD_ASRBOT_GO_BINARY` selects recording against Go; otherwise replay on Rust.
    pub fn from_env() -> Self {
        match std::env::var("GOFREE_RECORD_ASRBOT_GO_BINARY") {
            Ok(path) if !path.is_empty() => Backend::Go(PathBuf::from(path)),
            _ => Backend::Rust,
        }
    }

    pub fn recording(&self) -> bool {
        matches!(self, Backend::Go(_))
    }
}

static COUNTER: AtomicU32 = AtomicU32::new(0);

pub struct Proc {
    pub child: Child,
    container: Option<String>,
}

pub fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("free port");
    listener.local_addr().expect("addr").port()
}

pub fn spawn(backend: &Backend, env: &[(String, String)]) -> Proc {
    match backend {
        Backend::Rust => {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_asrbotd"));
            cmd.env_clear()
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true);
            for (k, v) in env {
                cmd.env(k, v);
            }
            Proc {
                child: cmd.spawn().expect("spawn rust asrbotd"),
                container: None,
            }
        }
        Backend::Go(binary) => {
            let dir = binary.parent().expect("binary dir").to_owned();
            let file = binary
                .file_name()
                .expect("binary name")
                .to_string_lossy()
                .into_owned();
            let name = format!(
                "gofree-asrbot-{}-{}",
                std::process::id(),
                COUNTER.fetch_add(1, Ordering::SeqCst)
            );
            let mut cmd = Command::new("docker");
            cmd.args(["run", "--rm", "--name", &name, "--network", "host", "-v"])
                .arg(format!("{}:/out:ro", dir.display()));
            for (k, v) in env {
                cmd.arg("-e").arg(format!("{k}={v}"));
            }
            cmd.arg(GO_IMAGE)
                .arg(format!("/out/{file}"))
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true);
            Proc {
                child: cmd.spawn().expect("spawn docker"),
                container: Some(name),
            }
        }
    }
}

impl Proc {
    /// SIGTERM, as systemd stops the unit.
    pub async fn terminate(&mut self) {
        match &self.container {
            Some(name) => {
                let _ = Command::new("docker")
                    .args(["stop", "-t", "10", name])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .await;
            }
            None => {
                if let Some(pid) = self.child.id() {
                    // SAFETY: plain kill(2) on our own child.
                    #[allow(unsafe_code)]
                    unsafe {
                        libc::kill(pid as i32, libc::SIGTERM);
                    }
                }
            }
        }
    }

    /// Wait for exit and return (exit code, stdout lines without the `time` field).
    pub async fn finish(mut self, timeout: Duration) -> (i32, Vec<String>) {
        let mut stdout = self.child.stdout.take().expect("stdout");
        let mut text = String::new();
        let read = async {
            let _ = stdout.read_to_string(&mut text).await;
            self.child.wait().await
        };
        let status = tokio::time::timeout(timeout, read)
            .await
            .expect("process exit timed out")
            .expect("wait");
        let lines = text.lines().map(strip_time).collect();
        (status.code().unwrap_or(-1), lines)
    }

    pub async fn kill(mut self) {
        if let Some(name) = &self.container {
            let _ = Command::new("docker")
                .args(["rm", "-f", name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .await;
        }
        let _ = self.child.kill().await;
    }
}

/// Drop the run-specific `time` attribute from a slog JSON line.
pub fn strip_time(line: &str) -> String {
    let Ok(serde_json::Value::Object(mut map)) = serde_json::from_str::<serde_json::Value>(line)
    else {
        return line.to_owned();
    };
    map.remove("time");
    // Order is checked by the log-format unit test; compare as an object here.
    serde_json::to_string(&serde_json::Value::Object(map)).unwrap_or_default()
}

pub async fn wait_ready(port: u16) {
    for _ in 0..400 {
        if tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("asrbotd did not listen on {port}");
}
