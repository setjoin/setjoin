//! Recording-only, CI-image execution of the frozen managed-worker seam.
#![allow(dead_code)]
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
static NEXT: AtomicU64 = AtomicU64::new(0);
pub fn repo_root() -> Result<PathBuf, BoxError> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()?)
}
pub fn dns_tick(config: Value) -> Result<(), BoxError> {
    use std::io::Write;
    let root = repo_root()?;
    let dir = root.join("test-results/gofree-tlsfront/ticks");
    std::fs::create_dir_all(&dir)?;
    let id = format!(
        "gofree-tlsfront-dns-tick-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let overlay = dir.join(format!("{id}.json"));
    std::fs::write(
        &overlay,
        serde_json::to_vec(
            &json!({"Replace":{"/src/mailserver/internal/acme/gofree_dns_tick_test.go":"/src/server-rust/tests/conformance/tlsfront/dns_tick.go.txt"}}),
        )?,
    )?;
    writeln!(
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.join("test-results/gofree-tlsfront/resources.txt"))?,
        "planned --rm {id}; local Docker; test ACME/fake DNS only; task Go cache retained"
    )?;
    let out = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--name",
            &id,
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
            "/src/mailserver",
            "-e",
            "GOMAXPROCS=1",
            "-e",
            "GOGC=50",
            "-e",
            "GOMEMLIMIT=768MiB",
            "-e",
            "GOCACHE=/src/test-results/gofree-tlsfront/go-cache",
            "-e",
        ])
        .arg(format!("GOFREE_DNS_CASE={config}"))
        .args([
            "setjoin-ci-linux-tc:local-amd64",
            "go",
            "test",
            "-p=1",
            "-vet=off",
            "-v",
        ])
        .arg(format!(
            "-overlay=/src/{}",
            overlay.strip_prefix(&root)?.display()
        ))
        .args(["./internal/acme", "-run", "^TestGoFreeDNSTick$", "-count=1"])
        .output()?;
    let log = [out.stdout.as_slice(), out.stderr.as_slice()].concat();
    std::fs::write(dir.join(format!("{id}.log")), &log)?;
    if !out.status.success() {
        return Err(String::from_utf8_lossy(&log).into_owned().into());
    }
    Ok(())
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
