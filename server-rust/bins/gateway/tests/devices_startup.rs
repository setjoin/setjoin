//! All36 F07 routes default native; both executable rollback switches restore Go.
use crate::common::boot::CommandBootExt;
use crate::common::boot::Child;
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
#[tokio::test]
async fn bundled_devices_all_routes_are_native_and_both_kill_switches_forward(
) -> Result<(), BoxError> {
    let Some(db) = Db::for_case("devices-executable") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "devices1-executable").await?;
    let receipt_ids = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F07'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    let last: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let result = async {
        let go_count = Arc::new(AtomicUsize::new(0));
        let count = go_count.clone();
        let go = common::fake_upstream(move |_| {
            count.fetch_add(1, Ordering::SeqCst);
            async {
                Response::builder()
                    .status(218)
                    .header("x-gofree-devices3-go", "yes")
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
        let cases = [
            ("DELETE", "/api/admin/mdm/policies/1", "{}", 403),
            ("GET", "/api/admin/devices", "{}", 403),
            ("GET", "/api/admin/devices/queue", "{}", 403),
            ("GET", "/api/admin/mdm/devices", "{}", 403),
            (
                "GET",
                "/api/admin/mdm/devices/00000000-0000-4000-8000-000000000001",
                "{}",
                403,
            ),
            ("GET", "/api/admin/mdm/policies", "{}", 403),
            ("POST", "/api/admin/devices/1/approve", "{}", 403),
            (
                "POST",
                "/api/admin/mdm/devices/00000000-0000-4000-8000-000000000001/wipe",
                "{}",
                403,
            ),
            ("POST", "/api/admin/mdm/policies", "{}", 403),
            ("PUT", "/api/admin/mdm/policies/1", "{}", 403),
            ("PUT", "/api/admin/mdm/policies/reorder", "{}", 403),
            // MAM and offline complete the Devices family.
            ("GET", "/api/admin/mam/devices", "{}", 403),
            ("GET", "/api/admin/mam/policies", "{}", 403),
            ("GET", "/api/admin/mam/devices/1/events", "{}", 403),
            ("PUT", "/api/admin/mam/policies", "{}", 403),
            ("PUT", "/api/admin/mam/policies/group", "{}", 403),
            (
                "DELETE",
                "/api/admin/mam/policies/group/role/1/key",
                "{}",
                403,
            ),
            ("POST", "/api/admin/mam/devices/1/unlock", "{}", 403),
            ("PUT", "/api/admin/mam/devices/1/policy", "{}", 403),
            ("DELETE", "/api/admin/mam/devices/1/policy/key", "{}", 403),
            ("GET", "/api/admin/offline/enabled", "{}", 403),
            ("GET", "/api/admin/offline/policies", "{}", 403),
            ("GET", "/api/admin/offline/policies/1", "{}", 403),
            ("GET", "/api/admin/offline/devices/pending", "{}", 403),
            ("POST", "/api/admin/offline/policies", "{}", 403),
            ("PUT", "/api/admin/offline/policies/1", "{}", 403),
            ("DELETE", "/api/admin/offline/policies/1", "{}", 403),
            ("PUT", "/api/admin/offline/enabled", "{}", 403),
            ("POST", "/api/admin/offline/policy-preview", "{}", 403),
            ("POST", "/api/admin/offline/devices/1/approve", "{}", 403),
            ("POST", "/api/admin/offline/devices/1/deny", "{}", 403),
            ("POST", "/api/admin/offline/devices/1/revoke", "{}", 403),
            ("POST", "/api/admin/offline/devices/1/wipe", "{}", 403),
            ("GET", "/api/offline/size-estimate", "{}", 200),
            (
                "POST",
                "/api/offline/wipe-ack",
                "{\"device_id\":9999999}",
                200,
            ),
            ("POST", "/api/admin/mam/devices/1/lock", "{}", 403),
        ];
        let go_routes = cases.iter().filter(|c| c.3 == 218).count();
        for mode in ["native", "all-go", "routes-off"] {
            let socket = setjoin_conformance::ports::listener().await;
            let address = socket.local_addr()?;
            drop(socket);
            let inventory = Inventory(std::env::temp_dir().join(format!(
                "gofree-devices3-inventory-{}-{mode}.json",
                std::process::id()
            )));
            let mut config: serde_json::Value =
                serde_json::from_str(include_str!("../route-inventory.json"))?;
            if mode == "routes-off" {
                for route in config["routes"].as_array_mut().ok_or("routes")? {
                    if route["family"] == "F07" {
                        route["state"] = "OFF".into();
                        route["upstream"] = "go-mail".into();
                    }
                }
            }
            std::fs::write(&inventory.0, config.to_string())?;
            if let Ok(path) = std::env::var("GOFREE_RESOURCE_LEDGER") {
                use std::io::Write;
                writeln!(
                    std::fs::OpenOptions::new().append(true).open(path)?,
                    "Planned owned gofree-devices3-gateway-{mode}; temporary inventory {}",
                    inventory.0.display()
                )?;
            }
            let mut process = Process(
                Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"))
                    .arg0(format!("gofree-devices3-gateway-{mode}"))
                    .env_clear()
                    .env("GATEWAY_LISTEN", address.to_string())
                    .env("GATEWAY_UPSTREAM", format!("http://{go}"))
                    .env("GATEWAY_AUTH_UPSTREAM", format!("http://{go}"))
                    .env(
                        "GATEWAY_ENABLED",
                        if mode == "all-go" { "false" } else { "true" },
                    )
                    .env("GATEWAY_ROUTE_INVENTORY", &inventory.0)
                    .env("DB_DSN", db.app.as_deref().unwrap_or(&db.dsn))
                    .env("DB_WORKER_DSN", &db.dsn)
                    .env("DB_DIRECT_DSN", &db.dsn)
                    .env("DB_ENCRYPTION_KEY", "22".repeat(32))
                    .env("JWT_SECRET", "blobs1-test-jwt-secret-for-recording")
                    .env(
                        "AUTHSERVER_JWKS_URL",
                        format!("http://{keys}/.well-known/jwks.json"),
                    )
                    .env("GO_WORKERS_OFF", "")
                    .env("RUST_WORKERS_ON", "")
                    .env("CORE_RATE_LIMIT", "100000")
                    .env("ADMIN_RATE_LIMIT", "100000")
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn_boot()?,
            );
            let mut ready = false;
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
            while tokio::time::Instant::now() < deadline {
                if tokio::net::TcpStream::connect(address).await.is_ok() {
                    ready = true;
                    break;
                }
                if let Some(status) = process.0.try_wait()? {
                    return Err(format!("gateway {mode} exited {status}").into());
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            if !ready {
                return Err("gateway did not bind".into());
            }
            let before = go_count.load(Ordering::SeqCst);
            for (method, path, body, native_status) in cases {
                let response = send(
                    address,
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("host", "mail.test")
                        .header("origin", "http://mail.test")
                        .header("x-request-id", "gofree-devices3-startup")
                        .header(
                            "authorization",
                            format!("Bearer {}", common::recovery_token(a.user)),
                        )
                        .body(full(body))?,
                )
                .await;
                let status = response.status().as_u16();
                let marker = response.headers().contains_key("x-gofree-devices3-go");
                let bytes = body_bytes(response).await;
                let expected = if mode == "native" { native_status } else { 218 };
                if status != expected || marker != (expected == 218) {
                    return Err(format!(
                        "{mode}: {method} {path}: {status}, expected {expected}: {bytes:?}"
                    )
                    .into());
                }
            }
            let forwarded = go_count.load(Ordering::SeqCst) - before;
            if forwarded
                != if mode == "native" {
                    go_routes
                } else {
                    cases.len()
                }
            {
                return Err(format!("wrong Go forwarding count in {mode}: {forwarded}").into());
            }
            if mode == "native" {
                let response =
                    send(address, Request::get("/_gateway/metrics").body(full(""))?).await;
                let metrics = String::from_utf8(body_bytes(response).await.to_vec())?;
                if !metrics.contains(&format!(
                    "setjoin_gateway_proxied_to_go_by_family_total{{family=\"F07\"}} {go_routes}"
                )) {
                    return Err(metrics.into());
                }
            }
            if mode == "routes-off" {
                let response =
                    send(address, Request::get("/_gateway/metrics").body(full(""))?).await;
                let body = String::from_utf8(body_bytes(response).await.to_vec())?;
                if !body.contains(&format!(
                    "setjoin_gateway_proxied_to_go_by_family_total{{family=\"F07\"}} {}",
                    cases.len()
                )) {
                    return Err(format!("rollback counter: {body}").into());
                }
            }
            unsafe {
                libc::kill(process.0.id() as i32, libc::SIGTERM);
            }
            let mut stopped = false;
            for _ in 0..200 {
                if let Some(status) = process.0.try_wait()? {
                    if !status.success() {
                        return Err(format!("gateway shutdown {status}").into());
                    }
                    stopped = true;
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            if !stopped {
                return Err("migration gateway did not drain".into());
            }
            drop(process);
        }
        Ok::<_, BoxError>(())
    }
    .await;
    owner
        .batch_execute("BEGIN; SET LOCAL session_replication_role=replica")
        .await?;
    owner.execute("DELETE FROM admin_audit_log WHERE id>$1 AND action='console.denied' AND before_state->>'target' LIKE '/admin/%'",&[&last]).await?;
    owner.batch_execute("COMMIT").await?;
    for row in owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F07'",
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
