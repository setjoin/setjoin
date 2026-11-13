//! CI-image execution for the frozen-Go recording/client peripheral. No host Go checks.
#![allow(dead_code)]
use serde_json::Value;
use std::{
    path::Path,
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);

fn mapped(value: &Value, root: &str) -> Value {
    match value {
        Value::String(s) => Value::String(
            s.strip_prefix(root)
                .map(|suffix| format!("/src{suffix}"))
                .unwrap_or_else(|| s.clone()),
        ),
        Value::Array(a) => Value::Array(a.iter().map(|v| mapped(v, root)).collect()),
        Value::Object(o) => Value::Object(
            o.iter()
                .map(|(k, v)| (k.clone(), mapped(v, root)))
                .collect(),
        ),
        _ => value.clone(),
    }
}
fn command(root: &Path, config: &Value, role: &str) -> (Command, String) {
    use sha2::{Digest, Sha256};
    use std::io::Write;
    let receipt: Value = serde_json::from_slice(
        &std::fs::read(root.join("test-results/gofree-tlsfront/peer-receipt.json"))
            .expect("build frozen Go peer first"),
    )
    .unwrap();
    let hash = Sha256::digest(
        std::fs::read(root.join("server-rust/tests/conformance/tlsfront/peer.go.txt")).unwrap(),
    )
    .iter()
    .map(|b| format!("{b:02x}"))
    .collect::<String>();
    assert_eq!(
        receipt["template_sha256"].as_str(),
        Some(hash.as_str()),
        "stale Go peer; rebuild with build-peer.py"
    );
    let dns_hash = Sha256::digest(
        std::fs::read(root.join("server-rust/tests/conformance/tlsfront/dns.go.txt")).unwrap(),
    )
    .iter()
    .map(|b| format!("{b:02x}"))
    .collect::<String>();
    assert_eq!(
        receipt["dns_sha256"].as_str(),
        Some(dns_hash.as_str()),
        "stale DNS peripheral; rebuild peer"
    );
    assert!(
        root.join("test-results/gofree-tlsfront/gofree-tlsfront-peer")
            .is_file(),
        "build the peer with python3 server-rust/tests/conformance/tlsfront/build-peer.py"
    );
    let name = format!(
        "gofree-tlsfront-{role}-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    writeln!(std::fs::OpenOptions::new().create(true).append(true).open(root.join("test-results/gofree-tlsfront/resources.txt")).unwrap(),"planned --rm {name}; local Docker; CI image; mount this worktree and shared Go module cache").unwrap();
    let mut command = Command::new("docker");
    command
        .args([
            "run",
            "--rm",
            "--name",
            &name,
            "--label",
            "org.setjoin.task=gofree-tlsfront",
            "--network",
            "host",
            "-v",
        ])
        .arg(format!("{}:/src", root.display()))
        .args([
            "-v",
            &gofree_go_mod_mount(),
            "-w",
            "/src",
            "-e",
            "GOMAXPROCS=1",
            "-e",
            "GOMEMLIMIT=768MiB",
            "-e",
        ])
        .arg(format!(
            "GOFREE_TLS_PEER={}",
            mapped(config, &root.display().to_string())
        ));
    if config["DisableAES"] == true {
        command.args(["-e", "GODEBUG=cpu.aes=off"]);
    }
    command.args([
        "setjoin-ci-linux-tc:local-amd64",
        "/src/test-results/gofree-tlsfront/gofree-tlsfront-peer",
        "-test.run=^TestGoFreeTLSFrontPeer$",
        "-test.timeout=5m",
    ]);
    (command, name)
}
pub fn run(root: &Path, config: &Value) -> Output {
    command(root, config, "probe").0.output().unwrap()
}
pub struct Server {
    child: Child,
    name: String,
}
impl Server {
    pub fn spawn(root: &Path, config: &Value, log: &Path) -> Self {
        let (mut command, name) = command(root, config, "server");
        Self {
            child: command
                .stdout(Stdio::null())
                .stderr(Stdio::from(std::fs::File::create(log).unwrap()))
                .spawn()
                .unwrap(),
            name,
        }
    }
    pub fn try_wait(&mut self) -> std::io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = Command::new("docker")
                .args(["stop", "--time", "1", &self.name])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Host Go module cache for the Go recorder container (GOFREE_GO_MOD_CACHE, default $HOME/go/pkg/mod).
#[allow(dead_code)]
fn gofree_go_mod_mount() -> String {
    let host = std::env::var("GOFREE_GO_MOD_CACHE").unwrap_or_else(|_| {
        format!(
            "{}/go/pkg/mod",
            std::env::var("HOME").unwrap_or_else(|_| "/root".into())
        )
    });
    format!("{host}:/root/go/pkg/mod")
}
