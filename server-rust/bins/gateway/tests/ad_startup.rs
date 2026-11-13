//! AD workers through the executable (#381): `RUST_WORKERS_ON` takes `ad-sync`,
//! `ad-toggle-observer`, `identity-toggle-observer` and `identity-metrics` only when Go's
//! copy of the same worker is off, and the AD ones need `AD_SYNC_ENABLED=true` because
//! the gateway cannot read Go's config file.
use crate::common::boot::CommandBootExt;
use crate::common::boot::Child;
mod common;
use common::BoxError;
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
    label: &str,
    address: std::net::SocketAddr,
    go: std::net::SocketAddr,
    keys: std::net::SocketAddr,
    db: &Db,
    inventory: &std::path::Path,
    workers: &[(&str, &str)],
) -> Result<Process, BoxError> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
    command
        .arg0(format!("gofree-dirsync6-gateway-{label}"))
        .env_clear()
        .env("GATEWAY_LISTEN", address.to_string())
        .env("GATEWAY_UPSTREAM", format!("http://{go}"))
        .env("GATEWAY_AUTH_UPSTREAM", format!("http://{go}"))
        .env("GATEWAY_ENABLED", "true")
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
        .stderr(Stdio::piped());
    for (key, value) in workers {
        command.env(key, value);
    }
    Ok(Process(command.spawn_boot()?))
}

#[tokio::test]
async fn ad_workers_refuse_to_start_while_go_still_runs_them() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("ad-startup-guard") else {
        return Ok(());
    };
    let go = common::fake_upstream(|_| async { Response::new(common::full("go")) }).await;
    let keys = common::fake_upstream(|_| async { Response::new(common::full("{}")) }).await;
    let inventory = Inventory(
        std::env::temp_dir().join(format!("gofree-dirsync6-guard-{}.json", std::process::id())),
    );
    std::fs::write(&inventory.0, include_str!("../route-inventory.json"))?;
    // (label, RUST_WORKERS_ON, GO_WORKERS_OFF, AD_SYNC_ENABLED, must run)
    let cases = [
        ("ad-no-go-off", "ad-sync", "", "true", false),
        ("ad-other-go-off", "ad-sync", "ldap-sync", "true", false),
        ("ad-env-off", "ad-sync", "ad-sync", "", false),
        ("ad-go-off", "ad-sync", "ad-sync", "true", true),
        (
            "ad-observer-no-go-off",
            "ad-toggle-observer",
            "",
            "true",
            false,
        ),
        (
            "ad-observer-env-off",
            "ad-toggle-observer",
            "ad-toggle-observer",
            "",
            false,
        ),
        (
            "ad-observer-go-off",
            "ad-toggle-observer",
            "ad-toggle-observer",
            "true",
            true,
        ),
        (
            "identity-observer-no-go-off",
            "identity-toggle-observer",
            "",
            "",
            false,
        ),
        (
            "identity-observer-go-off",
            "identity-toggle-observer",
            "identity-toggle-observer",
            "",
            true,
        ),
        ("metrics-no-go-off", "identity-metrics", "", "", false),
        (
            "metrics-go-off",
            "identity-metrics",
            "identity-metrics",
            "",
            true,
        ),
        (
            "all-go-off",
            "ad-sync,ad-toggle-observer,identity-toggle-observer,identity-metrics",
            "ad-sync,ad-toggle-observer,identity-toggle-observer,identity-metrics",
            "true",
            true,
        ),
    ];
    for (label, rust_on, go_off, ad_enabled, must_run) in cases {
        let socket = setjoin_conformance::ports::listener().await;
        let address = socket.local_addr()?;
        drop(socket);
        let mut env = vec![("RUST_WORKERS_ON", rust_on), ("GO_WORKERS_OFF", go_off)];
        if !ad_enabled.is_empty() {
            env.push(("AD_SYNC_ENABLED", ad_enabled));
        }
        let mut process = spawn(label, address, go, keys, &db, &inventory.0, &env)?;
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
            let mut logs = String::new();
            if !bound || exited.is_some() {
                let _ = process.0.kill();
                let _ = process.0.wait();
                use std::io::Read;
                process.0.stderr.as_mut().unwrap().read_to_string(&mut logs)?;
            }
            assert!(
                bound && exited.is_none(),
                "{label}: gateway must run with Go's copy off; status={exited:?}: {logs}"
            );
        } else {
            assert!(!bound, "{label}: gateway must not bind");
            assert!(
                exited.is_some_and(|s| !s.success()),
                "{label}: gateway must refuse to start"
            );
        }
    }
    Ok(())
}
