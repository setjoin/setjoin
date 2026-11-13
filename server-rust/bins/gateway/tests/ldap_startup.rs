//! Bundled LDAP runtime admission through the executable (#380): the routes are native,
//! every kill switch returns them to Go, and `RUST_WORKERS_ON=ldap-sync` refuses to start
//! unless Go's copy of the worker is off.
use crate::common::boot::CommandBootExt;
use crate::common::boot::Child;
mod common;
use common::{body_bytes, full, send, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
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

fn admin_token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let source = common::recovery_token(user);
    let fields = source.split('.').collect::<Vec<_>>();
    let mut claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(fields[1]).unwrap()).unwrap();
    claims["admin"] = json!(true);
    claims["perms"] = json!(["forged.permission"]);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let signed = format!("{}.{payload}", fields[0]);
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let signature: p256::ecdsa::Signature = key.sign(signed.as_bytes());
    format!("{signed}.{}", URL_SAFE_NO_PAD.encode(signature.to_bytes()))
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
        .arg0(format!("gofree-dirsync5-gateway-{name}"))
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
async fn ldap_worker_refuses_to_start_while_go_still_runs_it() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("ldap-startup-guard") else {
        return Ok(());
    };
    let go = common::fake_upstream(|_| async { Response::new(full("go")) }).await;
    let keys = common::fake_upstream(|_| async { Response::new(full("{}")) }).await;
    let inventory = Inventory(
        std::env::temp_dir().join(format!("gofree-dirsync5-guard-{}.json", std::process::id())),
    );
    std::fs::write(&inventory.0, include_str!("../route-inventory.json"))?;
    for (label, go_off, must_run) in [
        ("no-go-off", "", false),
        ("other-go-off", "drive-watch", false),
        ("go-off", "ldap-sync", true),
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
            &[("RUST_WORKERS_ON", "ldap-sync"), ("GO_WORKERS_OFF", go_off)],
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
            assert!(
                bound && exited.is_none(),
                "{label}: gateway must run with Go's copy off"
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

#[tokio::test]
async fn bundled_ldap_routes_are_native_and_every_kill_switch_forwards() -> Result<(), BoxError> {
    let Some(db) = Db::for_case("ldap-executable") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "ldap5-startup").await?;
    let saved = owner
        .query(
            "SELECT key,value::text,encrypted FROM system_config WHERE key LIKE 'ldap_sync_%'",
            &[],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM system_config WHERE key LIKE 'ldap_sync_%'",
            &[],
        )
        .await?;
    let role: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,NULL) RETURNING id",
            &[&format!("ldap5-startup-{}", a.user), &vec!["users.read", "identity.write"]],
        )
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role],
        )
        .await?;
    let go_count = Arc::new(AtomicUsize::new(0));
    let count = go_count.clone();
    let go = common::fake_upstream(move |_| {
        count.fetch_add(1, Ordering::SeqCst);
        async {
            Response::builder()
                .status(218)
                .header("x-gofree-ldap-go", "yes")
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
    let result = async {
        for mode in ["native", "all-go", "routes-off"] {
            let socket = setjoin_conformance::ports::listener().await;
            let address = socket.local_addr()?;
            drop(socket);
            let inventory = Inventory(std::env::temp_dir().join(format!(
                "gofree-dirsync5-inventory-{}-{mode}.json",
                std::process::id()
            )));
            let mut config: Value = serde_json::from_str(include_str!("../route-inventory.json"))?;
            if mode == "routes-off" {
                for route in config["routes"].as_array_mut().ok_or("routes")? {
                    if route["family"] == "F02" && route["slice"] == "ldap-runtime" {
                        route["state"] = "OFF".into();
                        route["upstream"] = "go-mail".into();
                    }
                }
            }
            std::fs::write(&inventory.0, config.to_string())?;
            let mut process = spawn(
                mode,
                address,
                go,
                keys,
                &db,
                &inventory.0,
                mode != "all-go",
                &[],
            )?;
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
            let routes = [
                ("GET", "/api/admin/ldap/health"),
                ("GET", "/api/admin/ldap/preview"),
                ("POST", "/api/admin/ldap/sync"),
                ("POST", "/api/admin/ldap/test-connection"),
                ("PUT", "/api/admin/ldap/config"),
            ];
            for (method, path) in routes {
                let before = go_count.load(Ordering::SeqCst);
                let response = send(
                    address,
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("host", "mail.test")
                        .header("origin", "http://mail.test")
                        .header("content-type", "application/json")
                        .header("authorization", format!("Bearer {}", admin_token(a.user)))
                        .body(full("{\"ldap_sync_enabled\":\"false\"}"))?,
                )
                .await;
                let forwarded = response.headers().contains_key("x-gofree-ldap-go");
                let status = response.status().as_u16();
                let _ = body_bytes(response).await;
                let native = mode == "native";
                assert_eq!(
                    forwarded, !native,
                    "{mode} {method} {path}: status {status}"
                );
                assert_eq!(
                    go_count.load(Ordering::SeqCst) - before,
                    usize::from(!native),
                    "{mode} {method} {path}"
                );
            }
        }
        Ok::<_, BoxError>(())
    }
    .await;
    owner.execute("UPDATE admin_role_assignments SET expires_at=now()-interval '1 hour' WHERE role_group_id=$1", &[&role]).await?;
    owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE role_group_id=$1",
            &[&role],
        )
        .await?;
    owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role])
        .await?;
    owner
        .execute(
            "DELETE FROM system_config WHERE key LIKE 'ldap_sync_%'",
            &[],
        )
        .await?;
    for row in &saved {
        owner.execute("INSERT INTO system_config(key,value,encrypted) VALUES($1,$2::text::jsonb,$3) ON CONFLICT (key) DO NOTHING", &[&row.get::<_, String>(0), &row.get::<_, String>(1), &row.get::<_, bool>(2)]).await?;
    }
    common::remove_blob_account(&owner, &a).await?;
    result
}
