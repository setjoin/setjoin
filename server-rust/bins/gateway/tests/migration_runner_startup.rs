//! The migration job runner through the executable (#431): the startup guard, the
//! native provider/control shapes, and the existing global/inventory switches.
use crate::common::boot::Child;
use crate::common::boot::CommandBootExt;
mod common;
use common::{body_bytes, full, send, BoxError};
use hyper::{Request, Response};
use setjoin_conformance::{fixture, harness::Db};
use std::{
    os::unix::process::CommandExt,
    process::{Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
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

fn listens_here(pid: u32, addr: std::net::SocketAddr) -> bool {
    setjoin_conformance::ports::listens_here(pid, addr)
}

fn gateway(
    go: std::net::SocketAddr,
    keys: std::net::SocketAddr,
    listen: std::net::SocketAddr,
    db: &Db,
    inventory: &std::path::Path,
    enabled: bool,
    rust_on: &str,
    go_off: &str,
    s3: std::net::SocketAddr,
) -> Result<Process, BoxError> {
    Ok(Process(
        Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"))
            .arg0("gofree-mbox7-gateway")
            .env_clear()
            .env("GATEWAY_LISTEN", listen.to_string())
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
            .env("S3_ENDPOINT", format!("http://{s3}"))
            .env("S3_ACCESS_KEY", "test-access")
            .env("S3_SECRET_KEY", "test-secret")
            .env("S3_BUCKET", "mailblobs")
            .env("GO_WORKERS_OFF", go_off)
            .env("RUST_WORKERS_ON", rust_on)
            .env("CORE_RATE_LIMIT", "100000")
            .env("ADMIN_RATE_LIMIT", "100000")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn_boot()?,
    ))
}

#[tokio::test]
async fn runner_needs_go_off_and_serves_native_provider_shapes() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("migration-runner-executable") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "mbox6-executable").await?;
    let last: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipt_ids = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F05'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    let result = async {
        let go_count = Arc::new(AtomicUsize::new(0));
        let count = go_count.clone();
        let go = common::fake_upstream(move |_| {
            count.fetch_add(1, Ordering::SeqCst);
            async {
                Response::builder()
                    .status(218)
                    .header("x-gofree-mbox7-go", "yes")
                    .body(full("frozen rollback sentinel"))
                    .unwrap()
            }
        })
        .await;
        let keys = common::fake_upstream(|_| async {
            Response::builder()
                .header("content-type", "application/json")
                .body(full(
                    include_bytes!("../../../tests/conformance/jmap/test-jwks.json").as_slice(),
                ))
                .unwrap()
        })
        .await;
        let s3 = common::fake_upstream(|_| async { Response::new(full("")) }).await;
        let inventory = Inventory(std::env::temp_dir().join(format!(
            "gofree-mbox7-inventory-{}.json",
            std::process::id()
        )));
        std::fs::write(&inventory.0, include_str!("../route-inventory.json"))?;
        // Reserved ports (below the ephemeral range, one process each): see setjoin_conformance::ports.
        let free = || async { setjoin_conformance::ports::address() };
        // The guard: the runner without Go's copy off refuses to start.
        let mut refused = gateway(
            go,
            keys,
            free().await,
            &db,
            &inventory.0,
            true,
            "migration-runner",
            "",
            s3,
        )?;
        let status = tokio::task::spawn_blocking(move || {
            let status = refused.0.wait();
            let mut text = String::new();
            use std::io::Read;
            if let Some(mut err) = refused.0.stderr.take() {
                let _ = err.read_to_string(&mut text);
            }
            (status, text)
        })
        .await?;
        if status.0?.success()
            || !status
                .1
                .contains("migration-runner requires GO_WORKERS_OFF=migration-runner")
        {
            return Err(format!("the runner started without the guard: {}", status.1).into());
        }
        let runner_routes = [
            ("POST", "/api/admin/migration/start"),
            ("POST", "/api/admin/migration/jobs/1/cancel"),
            ("POST", "/api/admin/migration/jobs/1/pause"),
            ("POST", "/api/admin/migration/jobs/1/resume"),
            ("POST", "/api/admin/migration/jobs/1/retry"),
            ("POST", "/api/admin/migration/test-connection"),
        ];
        let native_callbacks = [("GET", "/api/admin/migration/m365/callback")];
        for mode in ["native", "all-go", "routes-off", "runner-off"] {
            let listen = free().await;
            let mut config: serde_json::Value =
                serde_json::from_str(include_str!("../route-inventory.json"))?;
            if mode == "routes-off" {
                for route in config["routes"].as_array_mut().ok_or("routes")? {
                    if route["family"] == "F05" {
                        route["state"] = "OFF".into();
                        route["upstream"] = "go-mail".into();
                    }
                }
            }
            std::fs::write(&inventory.0, config.to_string())?;
            let (rust_on, go_off) = if mode == "runner-off" {
                ("", "")
            } else {
                ("migration-runner", "migration-runner")
            };
            let mut process = gateway(
                go,
                keys,
                listen,
                &db,
                &inventory.0,
                mode != "all-go",
                rust_on,
                go_off,
                s3,
            )?;
            let mut ready = false;
            for _ in 0..3000 {
                // Ready only when this child holds the listening socket: a connect alone also
                // succeeds against a stranger that took the port.
                if tokio::net::TcpStream::connect(listen).await.is_ok()
                    && listens_here(process.0.id(), listen)
                {
                    ready = true;
                    break;
                }
                if let Some(status) = process.0.try_wait()? {
                    return Err(format!("gateway {mode} exited {status}").into());
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            if !ready {
                return Err("gateway did not bind".into());
            }
            let before = go_count.load(Ordering::SeqCst);
            for (method, path) in runner_routes.iter().chain(native_callbacks.iter()) {
                let response = send(
                    listen,
                    Request::builder()
                        .method(*method)
                        .uri(*path)
                        .header("host", "mail.test")
                        .header("origin", "http://mail.test")
                        .header("x-request-id", "gofree-mbox7-startup")
                        .header(
                            "authorization",
                            format!("Bearer {}", common::recovery_token(a.user)),
                        )
                        .body(full("{}"))?,
                )
                .await;
                let status = response.status().as_u16();
                let marker = response.headers().contains_key("x-gofree-mbox7-go");
                let bytes = body_bytes(response).await;
                // An unprivileged account: the native chain refuses it (403), Go's sentinel is 218.
                let expected = if matches!(mode, "native" | "runner-off") {
                    403
                } else {
                    218
                };
                if status != expected || marker != (expected == 218) {
                    return Err(format!(
                        "{mode}: {method} {path}: {status}, expected {expected}: {bytes:?}"
                    )
                    .into());
                }
            }
            let forwarded = go_count.load(Ordering::SeqCst) - before;
            let wanted = if matches!(mode, "native" | "runner-off") {
                0
            } else {
                runner_routes.len() + native_callbacks.len()
            };
            if forwarded != wanted {
                return Err(format!(
                    "wrong Go forwarding count in {mode}: {forwarded}, wanted {wanted}"
                )
                .into());
            }
            unsafe {
                libc::kill(process.0.id() as i32, libc::SIGTERM);
            }
            let mut stopped = false;
            for _ in 0..300 {
                if let Some(status) = process.0.try_wait()? {
                    if !status.success() {
                        return Err(format!("gateway shutdown {status}").into());
                    }
                    stopped = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
            if !stopped {
                return Err("migration gateway did not drain".into());
            }
        }
        Ok::<_, BoxError>(())
    }
    .await;
    owner
        .batch_execute("BEGIN; SET LOCAL session_replication_role=replica")
        .await?;
    owner.execute("DELETE FROM admin_audit_log WHERE id>$1 AND action='console.denied' AND before_state->>'target' LIKE '/admin/migration%'",&[&last]).await?;
    owner.batch_execute("COMMIT").await?;
    for row in owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F05'",
            &[],
        )
        .await?
    {
        let id: String = row.get(0);
        if !receipt_ids.contains(&id) {
            owner
                .execute(
                    "DELETE FROM rust_operation_receipts WHERE operation_id=$1::text::uuid",
                    &[&id],
                )
                .await?;
        }
    }
    common::remove_blob_account(&owner, &a).await?;
    result
}
