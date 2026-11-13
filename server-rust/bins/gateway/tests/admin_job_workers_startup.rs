//! Startup guards of the four Admin identity job workers (#412): each refuses to start
//! under `RUST_WORKERS_ON=<name>` unless `GO_WORKERS_OFF` lists that exact name.
use crate::common::boot::CommandBootExt;
use crate::common::boot::Child;
mod common;
use common::{full, BoxError};
use hyper::Response;
use setjoin_conformance::harness::Db;
use std::{
    os::unix::process::CommandExt,
    process::{Command, Stdio},
};
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
struct Inventory(std::path::PathBuf);
impl Drop for Inventory {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

fn spawn(
    name: &str,
    address: std::net::SocketAddr,
    go: std::net::SocketAddr,
    keys: std::net::SocketAddr,
    db: &Db,
    inventory: &std::path::Path,
    enabled: bool,
    workers: &[(&str, &str)],
) -> Result<Process, BoxError> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
    command
        .arg0(format!("gofree-admin11-gateway-{name}"))
        .env_clear()
        .env("GATEWAY_LISTEN", address.to_string())
        .env("GATEWAY_UPSTREAM", format!("http://{go}"))
        .env("GATEWAY_AUTH_UPSTREAM", format!("http://{go}"))
        .env("GATEWAY_ENABLED", if enabled { "true" } else { "false" })
        .env("GATEWAY_ROUTE_INVENTORY", inventory)
        .env("DB_DSN", db.app.as_deref().unwrap_or(&db.dsn))
        .env("DB_WORKER_DSN", &db.dsn)
        .env("DB_DIRECT_DSN", &db.dsn)
        .env("DB_ENCRYPTION_KEY", "22".repeat(32))
        .env("JWT_SECRET", "blobs1-test-jwt-secret-for-recording")
        .env(
            "AUTHSERVER_JWKS_URL",
            format!("http://{keys}/.well-known/jwks.json"),
        )
        .env("CORE_RATE_LIMIT", "100000")
        .env("ADMIN_RATE_LIMIT", "100000")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for (key, value) in workers {
        command.env(key, value);
    }
    Ok(Process(command.spawn_boot()?))
}

#[tokio::test]
async fn admin_job_workers_refuse_to_start_while_go_still_runs_them() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("admin-job-workers-startup-guard") else {
        return Ok(());
    };
    let go = common::fake_upstream(|_| async { Response::new(full("go")) }).await;
    let keys = common::fake_upstream(|_| async { Response::new(full("{}")) }).await;
    let inventory = Inventory(
        std::env::temp_dir().join(format!("gofree-admin11-guard-{}.json", std::process::id())),
    );
    std::fs::write(&inventory.0, include_str!("../route-inventory.json"))?;
    for name in [
        "bulk-role-jobs",
        "identity-operations",
        "identity-transitions",
        "email-address-policy-jobs",
    ] {
        for (label, go_off, must_run) in [
            ("no-go-off", String::new(), false),
            ("other-go-off", "drive-watch".to_owned(), false),
            ("prefix-only", format!("{name}-x"), false),
            ("go-off", format!("other, {name}"), true),
        ] {
            let socket = setjoin_conformance::ports::listener().await;
            let address = socket.local_addr()?;
            drop(socket);
            let mut process = spawn(
                label,
                address,
                go,
                keys,
                &db,
                &inventory.0,
                true,
                &[("RUST_WORKERS_ON", name), ("GO_WORKERS_OFF", &go_off)],
            )?;
            let mut bound = false;
            let mut exited = None;
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
            while tokio::time::Instant::now() < deadline {
                if tokio::net::TcpStream::connect(address).await.is_ok() {
                    bound = true;
                    break;
                }
                if let Some(status) = process.0.try_wait()? {
                    exited = Some(status);
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            if must_run {
                assert!(bound && exited.is_none(), "{name}/{label}: must run with Go's copy off");
            } else {
                assert!(!bound, "{name}/{label}: gateway must not bind");
                assert!(
                    exited.is_some_and(|s| !s.success()),
                    "{name}/{label}: gateway must refuse to start"
                );
            }
        }
    }
    Ok(())
}
