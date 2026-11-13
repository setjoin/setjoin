//! Bundled F01 slices `users`, `roles`, `scope-sets`, `sod`, `user-lifecycle`, `idv2-sources`, `idv2-transitions`, `idv2-upgrade` and `org-policies` admission and both operator rollback switches through the executable.
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
const NATIVE: [(&str, &str, u16); 116] = [
    ("GET", "/api/admin/users", 403),
    ("GET", "/api/admin/users/1", 403),
    ("GET", "/api/admin/users/1/aliases", 403),
    ("POST", "/api/admin/users/1/aliases", 403),
    ("DELETE", "/api/admin/users/1/aliases/2", 403),
    ("GET", "/api/admin/users/1/quota", 403),
    ("PUT", "/api/admin/users/1/quota", 403),
    ("GET", "/api/admin/users/1/app-passwords", 403),
    ("GET", "/api/admin/users/1/app-access", 403),
    ("PUT", "/api/admin/users/1/app-access/mail", 403),
    ("GET", "/api/admin/users/1/sessions", 403),
    ("GET", "/api/admin/roles", 403),
    ("POST", "/api/admin/roles", 403),
    ("GET", "/api/admin/roles/1", 403),
    ("PUT", "/api/admin/roles/1", 403),
    ("DELETE", "/api/admin/roles/1", 403),
    ("POST", "/api/admin/roles/1/members", 403),
    ("DELETE", "/api/admin/roles/1/members/2", 403),
    ("POST", "/api/admin/roles/1/members:bulk", 403),
    ("DELETE", "/api/admin/roles/1/members:bulk", 403),
    ("GET", "/api/admin/users/1/effective-permissions", 403),
    ("GET", "/api/admin/permissions", 403),
    ("GET", "/api/admin/scope-sets", 403),
    ("POST", "/api/admin/scope-sets", 403),
    ("GET", "/api/admin/scope-sets/1", 403),
    ("PUT", "/api/admin/scope-sets/1", 403),
    ("DELETE", "/api/admin/scope-sets/1", 403),
    ("POST", "/api/admin/scope-sets/1/members", 403),
    ("DELETE", "/api/admin/scope-sets/1/members/user/2", 403),
    ("GET", "/api/admin/access-reviews", 403),
    ("POST", "/api/admin/access-reviews", 403),
    ("GET", "/api/admin/access-reviews/1", 403),
    ("PUT", "/api/admin/access-reviews/1/items/2", 403),
    ("PUT", "/api/admin/access-reviews/1/items", 403),
    ("POST", "/api/admin/access-reviews/1/close", 403),
    // Just-in-time activation is self-service: any authenticated member is served natively.
    ("GET", "/api/admin/me/roles", 200),
    ("POST", "/api/admin/me/roles/1/activate", 400),
    ("POST", "/api/admin/me/roles/1/deactivate", 200),
    ("GET", "/api/admin/roles/1/activation-policy", 403),
    ("PUT", "/api/admin/roles/1/activation-policy", 403),
    // Slice `idv2-sources` read half (#369).
    ("GET", "/api/admin/identity/v2/sources", 403),
    ("GET", "/api/admin/identity/v2/people", 403),
    ("GET", "/api/admin/identity/v2/people/1", 403),
    ("GET", "/api/admin/identity/v2/conflicts", 403),
    (
        "GET",
        "/api/admin/identity/v2/conflicts/95000000-0000-4000-8000-000000000001",
        403,
    ),
    ("GET", "/api/admin/identity/v2/events", 403),
    ("GET", "/api/admin/identity/group-mappings", 403),
    ("GET", "/api/admin/identity/inventory", 403),
    ("GET", "/api/admin/identity/v2/inventory/export", 403),
    (
        "GET",
        "/api/admin/identity/v2/jobs/95100000-0000-4000-8000-000000000001",
        403,
    ),
    (
        "GET",
        "/api/admin/identity/v2/jobs/95100000-0000-4000-8000-000000000001/results",
        403,
    ),
    ("GET", "/api/admin/identity/v2/sources/admin7-alpha", 403),
    (
        "GET",
        "/api/admin/identity/v2/sources/admin7-alpha/export",
        403,
    ),
    (
        "POST",
        "/api/admin/identity/v2/sources/admin7-alpha/pause",
        403,
    ),
    (
        "POST",
        "/api/admin/identity/v2/sources/admin7-alpha/resume",
        403,
    ),
    (
        "POST",
        "/api/admin/identity/v2/sources/admin7-alpha/retire",
        403,
    ),
    (
        "POST",
        "/api/admin/identity/v2/sources/admin7-alpha/activate",
        403,
    ),
    (
        "POST",
        "/api/admin/identity/v2/jobs/95100000-0000-4000-8000-000000000001/cancel",
        403,
    ),
    (
        "POST",
        "/api/admin/identity/v2/conflicts/95000000-0000-4000-8000-000000000001/decision",
        403,
    ),
    ("POST", "/api/admin/identity/v2/sources", 403),
    ("POST", "/api/admin/identity/v2/sources/plan", 403),
    ("PUT", "/api/admin/identity/v2/sources/admin7-alpha", 403),
    (
        "PUT",
        "/api/admin/identity/v2/sources/admin7-alpha/secrets/bindPassword",
        403,
    ),
    (
        "POST",
        "/api/admin/identity/v2/sources/admin7-alpha/secrets/bindPassword/rotate",
        403,
    ),
    (
        "POST",
        "/api/admin/identity/v2/sources/admin7-alpha/dry-run",
        403,
    ),
    (
        "PUT",
        "/api/admin/identity/group-mappings/saml/admin7-idp-a",
        403,
    ),
    // Slice `idv2-transitions` (#370): every gate refuses a member without the grant before any effect.
    ("GET", "/api/admin/identity/v2/transitions", 403),
    ("GET", "/api/admin/identity/v2/transitions/95400000-0000-4000-8000-000000000001", 403),
    ("GET", "/api/admin/identity/v2/transitions/95400000-0000-4000-8000-000000000001/report", 403),
    ("POST", "/api/admin/identity/v2/transitions/preview", 403),
    ("POST", "/api/admin/identity/v2/transitions/95400000-0000-4000-8000-000000000001/request", 403),
    ("POST", "/api/admin/identity/v2/transitions/95400000-0000-4000-8000-000000000001/approve", 403),
    ("POST", "/api/admin/identity/v2/transitions/95400000-0000-4000-8000-000000000001/deny", 403),
    ("POST", "/api/admin/identity/v2/transitions/95400000-0000-4000-8000-000000000001/execute", 403),
    ("POST", "/api/admin/identity/v2/transitions/95400000-0000-4000-8000-000000000001/cancel", 403),
    ("POST", "/api/admin/identity/v2/transitions/95400000-0000-4000-8000-000000000001/rollback", 403),
    ("POST", "/api/admin/identity/v2/transitions/95400000-0000-4000-8000-000000000001/rollback-preview", 403),
    ("POST", "/api/admin/identity/v2/transitions/95400000-0000-4000-8000-000000000001/step-up/challenge", 403),
    ("POST", "/api/admin/identity/v2/transitions/95400000-0000-4000-8000-000000000001/step-up/complete", 403),
    ("POST", "/api/admin/identity/v2/transitions/95400000-0000-4000-8000-000000000001/effects/95400000-0000-4000-8000-000000000002/retry", 403),
    // Slice `idv2-upgrade` (#371): the audited gates refuse a member without the grant.
    ("GET", "/api/admin/identity/v2/upgrade/status", 403),
    ("POST", "/api/admin/identity/v2/upgrade/preflight", 403),
    ("POST", "/api/admin/identity/v2/upgrade/backfill", 403),
    ("GET", "/api/admin/identity/v2/upgrade/shadow", 403),
    ("POST", "/api/admin/identity/v2/upgrade/canary", 403),
    ("POST", "/api/admin/identity/v2/upgrade/rollback", 403),
    (
        "GET",
        "/api/admin/identity/v2/upgrade/retirement-check",
        403,
    ),
    ("GET", "/api/admin/identity/v2/doctor", 403),
    ("POST", "/api/admin/identity/v2/diagnostics", 403),
    (
        "GET",
        "/api/admin/identity/v2/diagnostics/96100000-0000-4000-8000-000000000001",
        403,
    ),
    (
        "GET",
        "/api/admin/identity/v2/diagnostics/96100000-0000-4000-8000-000000000001/download",
        403,
    ),
    (
        "DELETE",
        "/api/admin/identity/v2/diagnostics/96100000-0000-4000-8000-000000000001",
        403,
    ),
    // User lifecycle: every gate refuses a member without the grant before any effect.
    ("POST", "/api/admin/users", 403),
    ("POST", "/api/admin/users/import", 403),
    ("PUT", "/api/admin/users/1", 403),
    ("DELETE", "/api/admin/users/1", 403),
    ("PUT", "/api/admin/users/1/password", 403),
    ("POST", "/api/admin/users/1/secure-account", 403),
    ("GET", "/api/admin/users/1/sign-ins", 403),
    ("DELETE", "/api/admin/users/1/app-passwords/2", 403),
    // Slice `org-policies` (#372).
    ("GET", "/api/admin/departments", 403),
    ("GET", "/api/admin/departments/tree", 403),
    ("POST", "/api/admin/departments", 403),
    ("PUT", "/api/admin/departments/1", 403),
    ("DELETE", "/api/admin/departments/1", 403),
    ("POST", "/api/admin/departments/assign-user", 403),
    ("GET", "/api/admin/email-address-policies-list", 403),
    ("POST", "/api/admin/email-address-policies", 403),
    ("PUT", "/api/admin/email-address-policies/1", 403),
    ("DELETE", "/api/admin/email-address-policies/1", 403),
    ("POST", "/api/admin/email-address-policies/reorder", 403),
    ("POST", "/api/admin/email-address-policies/1/preview", 403),
    ("POST", "/api/admin/email-address-policies/match-count", 403),
    ("POST", "/api/admin/email-address-policies/apply", 403),
    ("GET", "/api/admin/email-address-policies/apply/1", 403),
    ("GET", "/api/admin/distribution-groups", 403),
];
// Every F01 slice is native now (#370 closed the last one), so nothing stays with Go in every mode.
const GO_ONLY: [(&str, &str); 0] = [];

#[tokio::test]
async fn bundled_admin_identity_users_is_native_and_both_kill_switches_forward(
) -> Result<(), BoxError> {
    let Some(db) = Db::for_case("admin1-executable") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "admin1-executable").await?;
    let receipt_ids = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F01'",
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
                    .header("x-gofree-admin1-go", "yes")
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
        for mode in ["native", "all-go", "routes-off"] {
            let socket = setjoin_conformance::ports::listener().await;
            let address = socket.local_addr()?;
            drop(socket);
            let inventory = Inventory(std::env::temp_dir().join(format!(
                "gofree-admin1-inventory-{}-{mode}.json",
                std::process::id()
            )));
            let mut config: serde_json::Value =
                serde_json::from_str(include_str!("../route-inventory.json"))?;
            if mode == "routes-off" {
                for route in config["routes"].as_array_mut().ok_or("routes")? {
                    if route["family"] == "F01" {
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
                    "Planned owned gofree-admin1-gateway-{mode}; temporary inventory {}",
                    inventory.0.display()
                )?;
            }
            let mut process = Process(
                Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"))
                    .arg0(format!("gofree-admin1-gateway-{mode}"))
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
            for (method, path, served) in NATIVE
                .iter()
                .copied()
                .chain(GO_ONLY.iter().map(|(m, p)| (*m, *p, 0)))
            {
                let native = mode == "native" && served != 0;
                let response = send(
                    address,
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("host", "mail.test")
                        .header("origin", "http://mail.test")
                        .header("x-request-id", "gofree-admin1-startup")
                        .header(
                            "authorization",
                            format!("Bearer {}", common::recovery_token(a.user)),
                        )
                        .body(full("{}"))?,
                )
                .await;
                let status = response.status().as_u16();
                let marker = response.headers().contains_key("x-gofree-admin1-go");
                let bytes = body_bytes(response).await;
                // A member without an admin grant is denied natively with Go's 403.
                let expected = if native { served } else { 218 };
                if status != expected || marker == native {
                    return Err(format!(
                        "{mode}: {method} {path}: {status}, expected {expected}: {bytes:?}"
                    )
                    .into());
                }
            }
            let forwarded = go_count.load(Ordering::SeqCst) - before;
            let expected = if mode == "native" {
                GO_ONLY.len()
            } else {
                NATIVE.len() + GO_ONLY.len()
            };
            if forwarded != expected {
                return Err(format!("wrong Go forwarding count in {mode}: {forwarded}").into());
            }
            let response = send(address, Request::get("/_gateway/metrics").body(full(""))?).await;
            let metrics = String::from_utf8(body_bytes(response).await.to_vec())?;
            // Every forwarded F01 request is counted, native ones never.
            let wanted = match mode {
                "native" => format!(
                    "setjoin_gateway_proxied_to_go_by_family_total{{family=\"F01\"}} {}",
                    GO_ONLY.len()
                ),
                "routes-off" => format!(
                    "setjoin_gateway_proxied_to_go_by_family_total{{family=\"F01\"}} {}",
                    NATIVE.len() + GO_ONLY.len()
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
                return Err("admin identity gateway did not drain".into());
            }
            drop(process);
        }
        Ok::<_, BoxError>(())
    }
    .await;
    owner
        .batch_execute("BEGIN; SET LOCAL session_replication_role=replica")
        .await?;
    owner.execute("DELETE FROM admin_audit_log WHERE id>$1 AND action='console.denied' AND (notes LIKE '/admin/users%' OR notes LIKE '/admin/roles%' OR notes LIKE '/admin/permissions%' OR notes LIKE '/admin/scope-sets%' OR notes LIKE '/admin/access-reviews%')", &[&last]).await?;
    owner.batch_execute("COMMIT").await?;
    for row in owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F01'",
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
