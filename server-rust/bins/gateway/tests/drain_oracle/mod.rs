//! Shared helpers for the #408 drain-worker oracles: run one tick of frozen
//! Go's real worker (recording overlay test, never a tracked Go change) in the
//! CI image against the assigned disposable database.
#![allow(dead_code)]
use serde_json::{json, Value};
use std::process::Command;

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// `/src` inside the container is the worktree root.
pub fn repo_root() -> Result<std::path::PathBuf, BoxError> {
    Ok(std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()?)
}

pub struct GoTick<'a> {
    /// Go package directory under `mailserver/`, e.g. `internal/notifyjobs`.
    pub package: &'a str,
    /// Overlay source under `server-rust/tests/conformance/drain/`.
    pub overlay: &'a str,
    pub test: &'a str,
    /// Name of the overlay's file inside the package.
    pub file: &'a str,
    pub env: Vec<(String, String)>,
    /// Extra docker arguments (e.g. mounts).
    pub docker: Vec<String>,
}

impl GoTick<'_> {
    pub fn run(&self) -> Result<(), BoxError> {
        self.run_with(&[])
    }

    /// `run` with further Go files of the package replaced by overlay sources
    /// (`(file in the package, overlay under tests/conformance/drain/)`), for a worker
    /// whose collaborator is built inline and cannot be swapped from the test file.
    pub fn run_replacing(&self, also: &[(&str, &str)]) -> Result<(), BoxError> {
        let extra: Vec<(&str, &str, &str)> = also
            .iter()
            .map(|(file, source)| (self.package, *file, *source))
            .collect();
        self.run_with(&extra)
    }

    /// Like `run`, with extra overlay files added to other packages:
    /// `(package, name inside it, overlay source)`.
    pub fn run_with(&self, extra: &[(&str, &str, &str)]) -> Result<(), BoxError> {
        use std::io::Write;
        let root = repo_root()?;
        let folder = root.join("test-results/gofree-drainw");
        std::fs::create_dir_all(&folder)?;
        let overlay = folder.join(format!("{}.overlay.json", self.test));
        let mut replace = serde_json::Map::new();
        replace.insert(
            format!("/src/mailserver/{}/{}", self.package, self.file),
            json!(format!(
                "/src/server-rust/tests/conformance/drain/{}",
                self.overlay
            )),
        );
        for (package, file, source) in extra {
            replace.insert(
                format!("/src/mailserver/{package}/{file}"),
                json!(format!("/src/server-rust/tests/conformance/drain/{source}")),
            );
        }
        std::fs::write(&overlay, serde_json::to_vec(&json!({ "Replace": replace }))?)?;
        // A run owner can prefix its containers (e.g. `gofree-drive5-`) so cleanup
        // by prefix finds only its own.
        let prefix = std::env::var("GOFREE_ORACLE_CONTAINER_PREFIX")
            .unwrap_or_else(|_| "gofree-drainw-oracle".into());
        let name = format!("{prefix}-{}", std::process::id());
        if let Ok(ledger) = std::env::var("GOFREE_RESOURCE_LEDGER") {
            writeln!(
                std::fs::OpenOptions::new().append(true).open(ledger)?,
                "Planned {name}, local Docker, go cache {}/go-cache; assigned DB only; --rm",
                folder.display()
            )?;
        }
        let mut command = Command::new("docker");
        command
            .args(["run", "--rm", "--name", &name, "--network", "host", "-v"])
            .arg(format!("{}:/src", root.display()))
            .args(["-v", &gofree_go_mod_mount()])
            .args(&self.docker)
            .args(["-w", "/src/mailserver"]);
        for (key, value) in &self.env {
            command.args(["-e", &format!("{key}={value}")]);
        }
        let output = command
            .args([
                "-e",
                "GOMAXPROCS=1",
                "-e",
                "GOGC=50",
                "-e",
                "GOMEMLIMIT=768MiB",
                "-e",
                "GOCACHE=/src/test-results/gofree-drainw/go-cache",
                "setjoin-ci-linux-tc:local-amd64",
                "go",
                "test",
                "-p=1",
                "-vet=off",
                "-v",
            ])
            .arg(format!(
                "-overlay=/src/test-results/gofree-drainw/{}.overlay.json",
                self.test
            ))
            .arg(format!("./{}", self.package))
            .args(["-run", &format!("^{}$", self.test), "-count=1"])
            .output()?;
        std::fs::write(
            folder.join(format!("{}.log", self.test)),
            [output.stdout.as_slice(), output.stderr.as_slice()].concat(),
        )?;
        if !output.status.success() {
            return Err(format!(
                "frozen Go tick failed: {}",
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .rev()
                    .take(8)
                    .collect::<Vec<_>>()
                    .join(" | ")
            )
            .into());
        }
        Ok(())
    }
}

pub fn golden_path(case: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/drain/goldens")
        .join(format!("{case}.json"))
}

/// Record (never overwriting) or compare one case's observation.
pub fn settle(case: &str, observation: Value, recording: bool) -> Result<(), BoxError> {
    let path = golden_path(case);
    if recording {
        let _ = std::fs::remove_file(&path);
        setjoin_conformance::golden::record(
            &path,
            &json!({"format":1,"case":case,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}),
        )?;
    } else {
        let Ok(bytes) = std::fs::read(&path) else {
            return Err(format!("no golden for {case}; native observation: {observation}").into());
        };
        let golden: Value = serde_json::from_slice(&bytes)?;
        setjoin_conformance::golden::compare(&golden["observation"], &observation)?;
        println!("GOLDEN-REPLAY: drain {case} :: seed-plus-one-tick");
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
