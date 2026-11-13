//! Operator configuration is tested through the executable's HTTP listener.
mod common;
use common::boot::CommandBootExt;

use common::{body_bytes, fake_upstream, full, send};
use hyper::{Request, Response};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};

struct Process(common::boot::Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        self.0.wait().expect("reap owned gateway process");
    }
}

struct TempInventory(std::path::PathBuf);
impl Drop for TempInventory {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn executable_rejects_unqualified_routes_in_a_custom_inventory() {
    let path = TempInventory(std::env::temp_dir().join(format!(
        "gofree-oracle-inventory-{}.json",
        std::process::id()
    )));
    let data = r#"{"version":1,"routes":[{"listener":"gateway","method":"GET","path":"/unqualified","family":"F16","slice":"routes","upstream":"local-rust","state":"ON"}]}"#;
    std::fs::write(&path.0, data).unwrap();
    let mut process = Process(
        Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"))
            .env_clear()
            .env("GATEWAY_LISTEN", "127.0.0.1:0")
            .env("GATEWAY_AUTH_UPSTREAM", "http://127.0.0.1:1")
            .env("GATEWAY_ROUTE_INVENTORY", &path.0)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn_boot()
            .unwrap(),
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let status = loop {
        if let Some(status) = process.0.try_wait().unwrap() {
            break Some(status);
        }
        if std::time::Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    };
    assert!(
        status.is_some_and(|status| !status.success()),
        "unqualified ON route started the executable"
    );
    let mut stderr = String::new();
    std::io::Read::read_to_string(process.0.stderr.as_mut().unwrap(), &mut stderr).unwrap();
    assert!(stderr.contains("unqualified"), "{stderr}");
}

#[tokio::test]
async fn executable_accepts_qualified_custom_inventory_and_rollback() {
    for demote in [false, true] {
        let mut inventory: serde_json::Value =
            serde_json::from_str(include_str!("../route-inventory.json")).unwrap();
        if demote {
            let route = inventory["routes"]
                .as_array_mut()
                .unwrap()
                .iter_mut()
                .find(|route| {
                    route["listener"] == "gateway"
                        && route["method"] == "POST"
                        && route["path"] == "/jmap"
                })
                .unwrap();
            route["state"] = "OFF".into();
        }
        let path = TempInventory(std::env::temp_dir().join(format!(
            "gofree-oracle-inventory-{}-{demote}.json",
            std::process::id()
        )));
        std::fs::write(&path.0, inventory.to_string()).unwrap();
        let reserved = setjoin_conformance::ports::listener().await;
        let addr = reserved.local_addr().unwrap();
        drop(reserved);
        let mut process = Process(
            Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"))
                .env_clear()
                .env("GATEWAY_LISTEN", addr.to_string())
                .env("GATEWAY_AUTH_UPSTREAM", "http://127.0.0.1:1")
                .env("GATEWAY_ROUTE_INVENTORY", &path.0)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn_boot()
                .unwrap(),
        );
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "qualified inventory was rejected"
            );
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "gateway never listened"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let response = send(
            addr,
            Request::get("/_gateway/healthz").body(full("")).unwrap(),
        )
        .await;
        assert_eq!(response.status(), hyper::StatusCode::OK);
    }
}

#[test]
fn executable_prints_version_without_configuration() {
    let output = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"))
        .env_clear()
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success(), "{:?}", output);
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        format!("setjoin-gateway {}\n", env!("CARGO_PKG_VERSION"))
    );
}

#[tokio::test]
async fn executable_defaults_on_and_environment_kill_switch_restores_go() {
    let mail = fake_upstream(|_| async { Response::new(full("mail")) }).await;
    let auth = fake_upstream(|_| async { Response::new(full("auth")) }).await;
    let native = fake_upstream(|_| async { Response::new(full("rust auth")) }).await;
    for (flag, expected) in [
        (None, "rust auth"),
        (Some("false"), "mail"),
        (Some("true"), "rust auth"),
    ] {
        let reserved = setjoin_conformance::ports::listener().await;
        let addr = reserved.local_addr().unwrap();
        drop(reserved);
        let mut command = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
        command
            .env_clear()
            .env("GATEWAY_LISTEN", addr.to_string())
            .env("GATEWAY_UPSTREAM", format!("http://{mail}"))
            .env("GATEWAY_AUTH_UPSTREAM", format!("http://{auth}"))
            .env("GATEWAY_RUST_AUTH_UPSTREAM", format!("http://{native}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(flag) = flag {
            command.env("GATEWAY_ENABLED", flag);
        }
        let mut process = Process(command.spawn_boot().unwrap());
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "gateway exited before listening"
            );
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "gateway never listened"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let response = send(
            addr,
            Request::post("/auth/login").body(full("opaque")).unwrap(),
        )
        .await;
        assert_eq!(
            body_bytes(response).await,
            expected,
            "GATEWAY_ENABLED={flag:?}"
        );
    }
}

#[tokio::test]
async fn executable_enforces_core_budget_without_jmap_and_kill_switch_bypasses_it() {
    let mail = fake_upstream(|_| async { Response::new(full("mail")) }).await;
    let auth = fake_upstream(|_| async { Response::new(full("auth")) }).await;
    for enabled in [true, false] {
        let reserved = setjoin_conformance::ports::listener().await;
        let addr = reserved.local_addr().unwrap();
        drop(reserved);
        let mut process = Process(
            Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"))
                .env_clear()
                .env("GATEWAY_LISTEN", addr.to_string())
                .env("GATEWAY_UPSTREAM", format!("http://{mail}"))
                .env("GATEWAY_AUTH_UPSTREAM", format!("http://{auth}"))
                .env("GATEWAY_ENABLED", enabled.to_string())
                .env("CORE_RATE_LIMIT", "0")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn_boot()
                .unwrap(),
        );
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "gateway exited before listening"
            );
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "gateway never listened"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let response = send(addr, Request::post("/auth/login").body(full("{}")).unwrap()).await;
        if enabled {
            assert_eq!(response.status(), hyper::StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(
                &body_bytes(response).await[..],
                include_bytes!("golden/go-rate-limited.json")
            );
        } else {
            assert_eq!(body_bytes(response).await, "mail");
        }
    }
}

#[tokio::test]
async fn executable_honors_route_budget_overrides_on_the_served_paths() {
    let mail = fake_upstream(|_| async { Response::new(full("mail")) }).await;
    let auth = fake_upstream(|_| async { Response::new(full("auth")) }).await;
    let reserved = setjoin_conformance::ports::listener().await;
    let addr = reserved.local_addr().unwrap();
    drop(reserved);
    let mut command = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
    command
        .env_clear()
        .env("GATEWAY_LISTEN", addr.to_string())
        .env("GATEWAY_UPSTREAM", format!("http://{mail}"))
        .env("GATEWAY_AUTH_UPSTREAM", format!("http://{auth}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    for name in [
        "BOOKING_READ_RATE_LIMIT",
        "MEET_GUEST_READ_RATE_LIMIT",
        "MEET_GUEST_WRITE_RATE_LIMIT",
        "SETUP_RATE_LIMIT",
        "RECOVERY_UPLOAD_RATE_LIMIT",
        "TELEMETRY_RATE_LIMIT",
        "LINK_PROTECT_RATE_LIMIT",
    ] {
        command.env(name, "0");
    }
    let mut process = Process(command.spawn_boot().unwrap());
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "gateway exited before listening"
        );
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "gateway never listened"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    for (method, path) in [
        ("GET", "/api/public/booking/calendar"),
        ("GET", "/api/public/meet/meeting/join-request/123"),
        ("POST", "/api/public/meet/meeting/join-request"),
        ("GET", "/setup/status"),
        ("PUT", "/api/recovery/uploads/session/items/item"),
        ("POST", "/api/telemetry"),
        ("GET", "/link-protect"),
    ] {
        let response = send(
            addr,
            Request::builder()
                .method(method)
                .uri(path)
                .body(full(""))
                .unwrap(),
        )
        .await;
        assert_eq!(
            response.status(),
            hyper::StatusCode::TOO_MANY_REQUESTS,
            "{method} {path}"
        );
        assert_eq!(
            &body_bytes(response).await[..],
            include_bytes!("golden/go-rate-limited.json")
        );
    }
}

#[tokio::test]
async fn scim_rate_budget_only_applies_when_scim_is_enabled() {
    let mail = fake_upstream(|_| async { Response::new(full("mail")) }).await;
    let auth = fake_upstream(|_| async { Response::new(full("auth")) }).await;
    for enabled in [true, false] {
        let reserved = setjoin_conformance::ports::listener().await;
        let addr = reserved.local_addr().unwrap();
        drop(reserved);
        let mut process = Process(
            Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"))
                .env_clear()
                .env("GATEWAY_LISTEN", addr.to_string())
                .env("GATEWAY_UPSTREAM", format!("http://{mail}"))
                .env("GATEWAY_AUTH_UPSTREAM", format!("http://{auth}"))
                .env("SCIM_ENABLED", enabled.to_string())
                .env("SCIM_RATE_LIMIT", "0")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn_boot()
                .unwrap(),
        );
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            assert!(
                process.0.try_wait().unwrap().is_none(),
                "gateway exited before listening"
            );
            if tokio::net::TcpStream::connect(addr).await.is_ok() {
                break;
            }
            assert!(
                tokio::time::Instant::now() < deadline,
                "gateway never listened"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let response = send(addr, Request::get("/scim/v2/Users").body(full("")).unwrap()).await;
        assert_eq!(
            response.status(),
            if enabled {
                hyper::StatusCode::TOO_MANY_REQUESTS
            } else {
                hyper::StatusCode::NOT_FOUND
            }
        );
    }
}

#[tokio::test]
async fn executable_starts_the_transferred_worker_using_its_direct_connection() {
    let dsn = std::env::var("TEST_DB_DSN").expect("disposable test database");
    let request = std::env::var("DB_APP_DSN").expect("restricted request credential");
    let direct = std::env::var("DB_DIRECT_DSN").expect("direct connection");
    let prefix=std::env::var("GOFREE_RESOURCE_PREFIX").unwrap_or_else(|_|"gofree-t9".into());
    let listener_name=format!("{prefix}-gateway-listener-{}",std::process::id());
    let separator = if direct.contains('?') { '&' } else { '?' };
    let direct = format!("{direct}{separator}application_name={listener_name}");
    let mail = fake_upstream(|_| async { Response::new(full("mail")) }).await;
    let auth = fake_upstream(|_| async { Response::new(full("auth")) }).await;
    let reserved = setjoin_conformance::ports::listener().await;
    let addr = reserved.local_addr().unwrap();
    drop(reserved);
    let mut command = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
    command
        .arg0(format!("{prefix}-gateway"))
        .env_clear()
        .env("GATEWAY_LISTEN", addr.to_string())
        .env("GATEWAY_UPSTREAM", format!("http://{mail}"))
        .env("GATEWAY_AUTH_UPSTREAM", format!("http://{auth}"))
        .env("RUST_WORKERS_ON", "session-denylist-refresh")
        // The auth-chain cache also needs a working request pool at startup.
        .env("DB_DSN", &request)
        .env("DB_WORKER_DSN", &dsn)
        .env("DB_DIRECT_DSN", &direct)
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let mut process = Process(command.spawn_boot().unwrap());
    let (observer, connection) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let connection = tokio::spawn(connection);
    let observed=tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            assert!(process.0.try_wait().unwrap().is_none(), "gateway exited");
            // Identity has its own config_changed listener on the same direct
            // DSN; require the session worker's actual LISTEN statement.
            let count: i64 = observer.query_one("SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1 AND query='LISTEN \"session_revoke\"'", &[&listener_name]).await.unwrap().get(0);
            if count == 1 { break; }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    }).await;
    if observed.is_err(){
        let rows=observer.query("SELECT application_name,state,query,coalesce(wait_event,'') FROM pg_stat_activity WHERE datname=current_database() AND application_name=$1",&[&listener_name]).await.unwrap();
        panic!("gateway did not open the direct LISTEN connection: {rows:?}");
    }
    drop(process);
    drop(observer);
    connection.await.unwrap().unwrap();
}

#[tokio::test]
async fn activated_listener_keeps_connections_queued_across_restart() {
    use std::os::fd::AsRawFd;
    use std::time::Duration;

    let mail = fake_upstream(|_| async { Response::new(full("mail")) }).await;
    let auth = fake_upstream(|_| async { Response::new(full("auth")) }).await;
    // This parent-owned socket stands in for systemd's retained listener.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let start = || {
        let fd = listener.as_raw_fd();
        let mut command = Command::new("bash");
        command
            .env_clear()
            .env("GATEWAY_UPSTREAM", format!("http://{mail}"))
            .env("GATEWAY_AUTH_UPSTREAM", format!("http://{auth}"))
            .env("GATEWAY_RUST_AUTH_UPSTREAM", format!("http://{auth}"))
            .arg("-c")
            .arg("export LISTEN_PID=$$ LISTEN_FDS=1; exec -a gofree-t13-gateway \"$1\"")
            .arg("gofree-t13-launcher")
            .arg(env!("CARGO_BIN_EXE_setjoin-gateway"))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // The child inherits the listener as descriptor 3, as systemd specifies.
        unsafe {
            command.pre_exec(move || {
                unsafe extern "C" {
                    fn dup2(oldfd: i32, newfd: i32) -> i32;
                    fn fcntl(fd: i32, cmd: i32, ...) -> i32;
                }
                if dup2(fd, 3) < 0 || fcntl(3, 2, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Process(command.spawn_boot().unwrap())
    };
    let first = start();
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        send(addr, Request::post("/auth/login").body(full("")).unwrap()),
    )
    .await
    .expect("activated gateway did not serve");
    assert_eq!(body_bytes(response).await, "auth");
    drop(first);

    // The connection is established while neither gateway process is alive.
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let second = start();
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(hyper_util::rt::TokioIo::new(stream))
            .await
            .unwrap();
    let task = tokio::spawn(connection);
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        sender.send_request(Request::post("/auth/login").body(full("")).unwrap()),
    )
    .await
    .expect("queued connection was not served")
    .unwrap();
    assert_eq!(body_bytes(response).await, "auth");
    drop(sender);
    task.await.unwrap().unwrap();
    drop(second);
}

#[test]
fn activation_rejects_missing_listener_and_multiple_descriptors() {
    for count in ["1", "2"] {
        let output = Command::new("bash")
            .env_clear()
            .env("GATEWAY_ENABLED", "false")
            .env("LISTEN_FDS", count)
            .arg("-c")
            .arg("export LISTEN_PID=$$; exec -a gofree-t13-gateway \"$1\"")
            .arg("gofree-t13-launcher")
            .arg(env!("CARGO_BIN_EXE_setjoin-gateway"))
            .output()
            .unwrap();
        assert!(!output.status.success(), "LISTEN_FDS={count}");
        assert!(String::from_utf8_lossy(&output.stderr).contains("socket activation"));
    }
}

#[tokio::test]
async fn sigterm_drains_an_in_flight_http_response() {
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Notify;

    let entered = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let mail = fake_upstream({
        let entered = entered.clone();
        let release = release.clone();
        move |_| {
            let entered = entered.clone();
            let release = release.clone();
            async move {
                entered.notify_one();
                release.notified().await;
                Response::new(full("completed"))
            }
        }
    })
    .await;
    let reserved = setjoin_conformance::ports::listener().await;
    let addr = reserved.local_addr().unwrap();
    drop(reserved);
    let mut process = Process(
        Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"))
            .arg0("gofree-t13-gateway")
            .env_clear()
            .env("GATEWAY_LISTEN", addr.to_string())
            .env("GATEWAY_ENABLED", "false")
            .env("GATEWAY_UPSTREAM", format!("http://{mail}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn_boot()
            .unwrap(),
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        while tokio::net::TcpStream::connect(addr).await.is_err() {
            assert!(process.0.try_wait().unwrap().is_none(), "gateway exited");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("gateway did not listen");
    let response = tokio::spawn(async move {
        let response = send(addr, Request::get("/").body(full("")).unwrap()).await;
        body_bytes(response).await
    });
    tokio::time::timeout(Duration::from_secs(10), entered.notified())
        .await
        .expect("upstream did not receive request");
    assert_eq!(
        unsafe { libc::kill(process.0.id() as i32, libc::SIGTERM) },
        0
    );
    tokio::time::timeout(Duration::from_secs(10), async {
        while tokio::net::TcpStream::connect(addr).await.is_ok() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("gateway did not stop accepting");
    release.notify_one();
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(10), response)
            .await
            .expect("in-flight response did not finish")
            .expect("in-flight response failed"),
        "completed"
    );
    let status = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(status) = process.0.try_wait().unwrap() {
                break status;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("gateway did not finish draining");
    assert!(status.success());
}

#[tokio::test]
async fn activation_for_another_pid_does_not_replace_configured_listener() {
    let mail = fake_upstream(|_| async { Response::new(full("mail")) }).await;
    let reserved = setjoin_conformance::ports::listener().await;
    let addr = reserved.local_addr().unwrap();
    drop(reserved);
    let mut process = Process(
        Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"))
            .arg0("gofree-t13-gateway")
            .env_clear()
            .env("LISTEN_PID", "0")
            .env("LISTEN_FDS", "1")
            .env("GATEWAY_LISTEN", addr.to_string())
            .env("GATEWAY_ENABLED", "false")
            .env("GATEWAY_UPSTREAM", format!("http://{mail}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn_boot()
            .unwrap(),
    );
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        assert!(process.0.try_wait().unwrap().is_none(), "gateway exited");
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "gateway never listened"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let response = send(addr, Request::get("/").body(full("")).unwrap()).await;
    assert_eq!(body_bytes(response).await, "mail");
}
