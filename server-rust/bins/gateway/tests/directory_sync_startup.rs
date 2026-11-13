//! Bundled F02 slice 1 admission and both operator rollback switches through the executable.
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
const NATIVE: [(&str, &str); 15] = [
    ("GET", "/api/admin/ldap/config"),
    ("PUT", "/api/admin/ldap/config"),
    ("GET", "/api/admin/ldap/health"),
    ("GET", "/api/admin/ldap/preview"),
    ("POST", "/api/admin/ldap/sync"),
    ("POST", "/api/admin/ldap/test-connection"),
    ("GET", "/api/admin/ldap/sync-log"),
    ("GET", "/api/admin/ad/config"),
    ("GET", "/api/admin/ad/sync-log"),
    ("GET", "/api/admin/ad/conflicts"),
    ("POST", "/api/admin/ad/conflicts/1/resolve"),
    ("POST", "/api/admin/ad/conflicts/resolve-all"),
    ("GET", "/api/admin/ad/field-policy"),
    ("PUT", "/api/admin/ad/field-policy"),
    ("POST", "/api/admin/ad/principal"),
];
// The AD runtime routes (#381) are native only with `AD_SYNC_ENABLED=true` in the
// process environment (Go pins `feature.ad_sync` to it); otherwise they forward.
const AD_RUNTIME: [(&str, &str); 4] = [
    ("GET", "/api/admin/ad/health"),
    ("PUT", "/api/admin/ad/config"),
    ("POST", "/api/admin/ad/sync"),
    ("POST", "/api/admin/ad/test-connection"),
];

#[tokio::test]
async fn bundled_directory_sync_is_native_and_both_kill_switches_forward() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("dirsync-executable") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "dirsync1-executable").await?;
    let receipt_ids = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F02'",
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
                    .header("x-gofree-dirsync1-go", "yes")
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
        for mode in ["native", "all-go", "routes-off", "ad-disabled"] {
            let socket = setjoin_conformance::ports::listener().await;
            let address = socket.local_addr()?;
            drop(socket);
            let inventory = Inventory(std::env::temp_dir().join(format!(
                "gofree-dirsync1-inventory-{}-{mode}.json",
                std::process::id()
            )));
            let mut config: serde_json::Value =
                serde_json::from_str(include_str!("../route-inventory.json"))?;
            if mode == "routes-off" {
                for route in config["routes"].as_array_mut().ok_or("routes")? {
                    if route["family"] == "F02" {
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
                    "Planned owned gofree-dirsync1-gateway-{mode}; temporary inventory {}",
                    inventory.0.display()
                )?;
            }
            let mut process = Process(
                Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"))
                    .arg0(format!("gofree-dirsync1-gateway-{mode}"))
                    .env_clear()
                    .env("GATEWAY_LISTEN", address.to_string())
                    .env("GATEWAY_UPSTREAM", format!("http://{go}"))
                    .env("GATEWAY_AUTH_UPSTREAM", format!("http://{go}"))
                    .env(
                        "GATEWAY_ENABLED",
                        if mode == "all-go" { "false" } else { "true" },
                    )
                    .env("GATEWAY_ROUTE_INVENTORY", &inventory.0)
                    .envs((mode != "ad-disabled").then_some(("AD_SYNC_ENABLED", "true")))
                    .env("DB_DSN", db.app.as_deref().unwrap_or(&db.dsn))
                    .env("DB_WORKER_DSN", &db.dsn)
                    .env("DB_DIRECT_DSN", &db.dsn)
                    .env("DB_ENCRYPTION_KEY", "22".repeat(32))
                    .env("JWT_SECRET", "blobs1-test-jwt-secret-for-recording")
                    .env(
                        "AUTHSERVER_JWKS_URL",
                        format!("http://{keys}/.well-known/jwks.json"),
                    )
                    .env("NETWORK_MODE", "airgap")
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
            for (method, path) in NATIVE.iter().chain(AD_RUNTIME.iter()) {
                let native = (mode == "native" && NATIVE.contains(&(method, path)))
                    || (mode == "native" && AD_RUNTIME.contains(&(method, path)))
                    || (mode == "ad-disabled" && (NATIVE.contains(&(method, path)) || AD_RUNTIME.contains(&(method, path))));
                let response = send(
                    address,
                    Request::builder()
                        .method(*method)
                        .uri(*path)
                        .header("host", "mail.test")
                        .header("origin", "http://mail.test")
                        .header("x-request-id", "gofree-dirsync1-startup")
                        .header(
                            "authorization",
                            format!("Bearer {}", common::recovery_token(a.user)),
                        )
                        .body(full("{}"))?,
                )
                .await;
                let status = response.status().as_u16();
                let marker = response.headers().contains_key("x-gofree-dirsync1-go");
                let bytes = body_bytes(response).await;
                // A member without an admin grant is denied natively with Go's 403.
                let expected = if native { 403 } else { 218 };
                if status != expected || marker == native {
                    return Err(format!(
                        "{mode}: {method} {path}: {status}, expected {expected}: {bytes:?}"
                    )
                    .into());
                }
            }
            let forwarded = go_count.load(Ordering::SeqCst) - before;
            let expected = match mode {
                "native" => 0,
                "ad-disabled" => 0,
                _ => NATIVE.len() + AD_RUNTIME.len(),
            };
            if forwarded != expected {
                return Err(format!("wrong Go forwarding count in {mode}: {forwarded}").into());
            }
            let response = send(address, Request::get("/_gateway/metrics").body(full(""))?).await;
            let metrics = String::from_utf8(body_bytes(response).await.to_vec())?;
            // The ldap route is F02 as well; every forwarded F02 request is counted, native ones never.
            let wanted = match mode {
                "native" => {
                    "setjoin_gateway_proxied_to_go_by_family_total{family=\"F02\"} 0".to_owned()
                }
                "ad-disabled" => "setjoin_gateway_proxied_to_go_by_family_total{family=\"F02\"} 0".to_owned(),
                "routes-off" => format!(
                    "setjoin_gateway_proxied_to_go_by_family_total{{family=\"F02\"}} {}",
                    NATIVE.len() + AD_RUNTIME.len()
                ),
                _ => String::new(),
            };
            if mode != "all-go" && !metrics.contains(&wanted) {
                return Err(format!("{mode} counter: {metrics}").into());
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
                return Err("directory sync gateway did not drain".into());
            }
            drop(process);
        }
        Ok::<_, BoxError>(())
    }
    .await;
    owner
        .batch_execute("BEGIN; SET LOCAL session_replication_role=replica")
        .await?;
    owner.execute("DELETE FROM admin_audit_log WHERE id>$1 AND action='console.denied' AND (notes LIKE '/admin/ad/%' OR notes LIKE '/admin/ldap/%')", &[&last]).await?;
    owner.batch_execute("COMMIT").await?;
    for row in owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F02'",
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
