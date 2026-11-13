//! Bundled F02 SCIM admission through the executable: native when SCIM is enabled in
//! the environment, and every kill switch (gateway off, slice OFF, SCIM disabled)
//! returns the twelve routes to Go.
use crate::common::boot::CommandBootExt;
use crate::common::boot::Child;
mod common;
use common::{body_bytes, full, send, BoxError};
use hyper::{Request, Response};
use setjoin_conformance::harness::Db;
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
const ROUTES: [(&str, &str); 12] = [
    ("GET", "/scim/v2/Users"),
    ("POST", "/scim/v2/Users"),
    ("GET", "/scim/v2/Users/1"),
    ("PUT", "/scim/v2/Users/1"),
    ("PATCH", "/scim/v2/Users/1"),
    ("DELETE", "/scim/v2/Users/1"),
    ("GET", "/scim/v2/Groups"),
    ("POST", "/scim/v2/Groups"),
    ("GET", "/scim/v2/Groups/1"),
    ("PATCH", "/scim/v2/Groups/1"),
    ("DELETE", "/scim/v2/Groups/1"),
    ("GET", "/scim/v2/ServiceProviderConfig"),
];

#[tokio::test]
async fn bundled_scim_is_native_and_every_kill_switch_forwards() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("scim-executable") else {
        return Ok(());
    };
    let go_count = Arc::new(AtomicUsize::new(0));
    let count = go_count.clone();
    let go = common::fake_upstream(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        async {
            Response::builder()
                .status(218)
                .header("x-gofree-scim-go", "yes")
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
    for mode in ["native", "scim-disabled", "all-go", "routes-off"] {
        let socket = setjoin_conformance::ports::listener().await;
        let address = socket.local_addr()?;
        drop(socket);
        let inventory = Inventory(std::env::temp_dir().join(format!(
            "gofree-dirsync3-inventory-{}-{mode}.json",
            std::process::id()
        )));
        let mut config: serde_json::Value =
            serde_json::from_str(include_str!("../route-inventory.json"))?;
        if mode == "routes-off" {
            for route in config["routes"].as_array_mut().ok_or("routes")? {
                if route["family"] == "F02" && route["slice"] == "scim" {
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
                "Planned owned gofree-dirsync3-gateway-{mode}; temporary inventory {}",
                inventory.0.display()
            )?;
        }
        let mut process = Process(
            Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"))
                .arg0(format!("gofree-dirsync3-gateway-{mode}"))
                .env_clear()
                .env("GATEWAY_LISTEN", address.to_string())
                .env("GATEWAY_UPSTREAM", format!("http://{go}"))
                .env("GATEWAY_AUTH_UPSTREAM", format!("http://{go}"))
                .env(
                    "GATEWAY_ENABLED",
                    if mode == "all-go" { "false" } else { "true" },
                )
                .env("GATEWAY_ROUTE_INVENTORY", &inventory.0)
                .env(
                    "SCIM_ENABLED",
                    if mode == "scim-disabled" {
                        "false"
                    } else {
                        "true"
                    },
                )
                .env("SCIM_RATE_LIMIT", "100000")
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
                .stderr(Stdio::null())
                .spawn_boot()?,
        );
        let mut ready = false;
        for _ in 0..6000 {
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
        for (method, path) in ROUTES {
            let native = matches!(mode, "native" | "scim-disabled");
            let response = send(
                address,
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("host", "mail.test")
                    .header("origin", "http://mail.test")
                    .header("x-request-id", "gofree-dirsync3-startup")
                    .header("content-type", "application/scim+json")
                    .header("authorization", "Bearer not-a-scim-token")
                    .body(full("{}"))?,
            )
            .await;
            let status = response.status().as_u16();
            let marker = response.headers().contains_key("x-gofree-scim-go");
            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned();
            let bytes = body_bytes(response).await;
            // Enabled: Go's SCIM 401. Disabled: the unregistered root-mux 404.
            if mode == "scim-disabled" { assert_eq!(bytes, "404 page not found\n"); }
            let expected = match mode { "native" => 401, "scim-disabled" => 404, _ => 218 };
            let scim = content_type == "application/scim+json";
            if status != expected || marker == native || scim != (mode == "native") {
                return Err(format!(
                    "{mode}: {method} {path}: {status} {content_type}, expected {expected}: {bytes:?}"
                )
                .into());
            }
        }
        let forwarded = go_count.load(Ordering::SeqCst) - before;
        let expected = if matches!(mode, "native" | "scim-disabled") { 0 } else { ROUTES.len() };
        if forwarded != expected {
            return Err(format!("wrong Go forwarding count in {mode}: {forwarded}").into());
        }
        let response = send(address, Request::get("/_gateway/metrics").body(full(""))?).await;
        let metrics = String::from_utf8(body_bytes(response).await.to_vec())?;
        let wanted = match mode {
            "native" | "scim-disabled" => Some(0),
            "routes-off" => Some(ROUTES.len()),
            _ => None,
        };
        if let Some(wanted) = wanted {
            let line =
                format!("setjoin_gateway_proxied_to_go_by_family_total{{family=\"F02\"}} {wanted}");
            if !metrics.contains(&line) {
                return Err(format!("{mode} counter: {metrics}").into());
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
            return Err("scim gateway did not drain".into());
        }
        drop(process);
    }
    Ok(())
}
