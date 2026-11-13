//! Operator seams: native catch-alls without Go, both rollbacks and build refusal.
mod common;
use common::BoxError;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use std::{
    path::PathBuf,
    process::{Child, Command, Stdio},
};
#[path = "catchall_oracle/assets.rs"]
mod assets;

fn ledger(text: &str) {
    use std::io::Write;
    if let Ok(path) = std::env::var("GOFREE_RESOURCE_LEDGER") {
        writeln!(
            std::fs::OpenOptions::new().append(true).open(path).unwrap(),
            "{text}"
        )
        .unwrap();
    }
}
struct Process {
    child: Child,
    dir: PathBuf,
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        self.child.wait().expect("reap owned gateway");
        std::fs::remove_dir_all(&self.dir).expect("remove owned gateway link");
    }
}
fn start(
    address: std::net::SocketAddr,
    auth: std::net::SocketAddr,
    upstream: Option<std::net::SocketAddr>,
    enabled: bool,
    website: Option<&std::path::Path>,
    config: bool,
) -> Process {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "gofree-catchall-startup-{}-{unique}",
        std::process::id()
    ));
    ledger(&format!(
        "Planned startup process; owned link directory {}",
        dir.display()
    ));
    std::fs::create_dir(&dir).unwrap();
    let binary = dir.join("gofree-catchall-gateway");
    std::os::unix::fs::symlink(env!("CARGO_BIN_EXE_setjoin-gateway"), &binary).unwrap();
    let mut command = Command::new(binary);
    command
        .env_clear()
        .env("GATEWAY_LISTEN", address.to_string())
        .env("GATEWAY_AUTH_UPSTREAM", format!("http://{auth}"))
        .env("GATEWAY_ENABLED", enabled.to_string())
        .env("CORE_RATE_LIMIT", "10000")
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    if let Some(upstream) = upstream {
        command.env("GATEWAY_UPSTREAM", format!("http://{upstream}"));
    }
    if let Some(website) = website {
        command.env("WEBSITE_DIR", website);
    }
    if config {
        command.env("SETJOIN_CONFIG", "/operator/setjoin.yaml");
    }
    let child = command.spawn().unwrap();
    ledger(&format!(
        "Started owned gofree-catchall-gateway pid {}",
        child.id()
    ));
    Process { child, dir }
}
async fn reserve() -> std::net::SocketAddr {
    setjoin_conformance::ports::address()
}
fn listens_here(pid: u32, addr: std::net::SocketAddr) -> bool {
    setjoin_conformance::ports::listens_here(pid, addr)
}
async fn ready(process: &mut Process, address: std::net::SocketAddr) {
    let end = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        assert!(
            process.child.try_wait().unwrap().is_none(),
            "gateway exited before listening"
        );
        if tokio::net::TcpStream::connect(address).await.is_ok() && listens_here(process.child.id(), address) {
            return;
        }
        assert!(tokio::time::Instant::now() < end, "gateway did not start");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
}
#[tokio::test]
async fn executable_answers_all_six_catchalls_without_go_and_global_rollback_preserves_requests(
) -> Result<(), BoxError> {
    let go = common::fake_upstream(|r| async move {
        use http_body_util::BodyExt;
        let method = r.method().to_string();
        let uri = r.uri().to_string();
        let bytes = r.into_body().collect().await.unwrap().to_bytes();
        Response::builder()
            .status(207)
            .body(common::full(format!(
                "{method} {uri} {}",
                String::from_utf8_lossy(&bytes)
            )))
            .unwrap()
    })
    .await;
    for enabled in [true, false] {
        let address = reserve().await;
        let mut process = start(address, go, (!enabled).then_some(go), enabled, None, false);
        ready(&mut process, address).await;
        for (method, path, status) in [
            ("GET", "/catchall-unknown", 404),
            ("PATCH", "/api/phantom", 404),
            ("GET", "/api/chat/phantom", 401),
            ("GET", "/api/drive/phantom", 401),
            ("GET", "/api/meet/phantom/path", 401),
            ("PATCH", "/api/meet", 401),
            ("GET", "/a//b?x=%20", 307),
        ] {
            let reply = common::send(
                address,
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(common::full("opaque"))?,
            )
            .await;
            if enabled {
                assert_eq!(reply.status().as_u16(), status, "{method} {path}");
                common::body_bytes(reply).await;
            } else {
                assert_eq!(reply.status().as_u16(), 207);
                assert_eq!(
                    common::body_bytes(reply).await,
                    format!("{method} {path} opaque")
                );
            }
        }
        if enabled {
            let response = common::send(
                address,
                Request::get("/_gateway/metrics").body(common::full(""))?,
            )
            .await;
            let metrics = String::from_utf8(common::body_bytes(response).await.to_vec())?;
            assert!(
                metrics
                    .lines()
                    .any(|s| s == "setjoin_gateway_proxied_to_go_total 0"),
                "{metrics}"
            );
        }
    }
    Ok(())
}
#[tokio::test]
async fn inventory_rollback_forwards_each_fallback_and_counts_its_family() -> Result<(), BoxError> {
    let go = common::fake_upstream(|r| async move {
        Response::builder()
            .status(207)
            .body(common::full(format!("{} {}", r.method(), r.uri())))
            .unwrap()
    })
    .await;
    for (logical, method, path, family) in [
        ("/", "GET", "/a//b?x=1", "F22"),
        ("/api/", "PATCH", "/api/phantom", "F22"),
        ("/chat/", "GET", "/api/chat/phantom", "F12"),
        ("/drive/", "GET", "/api/drive/phantom", "F14"),
        ("/meet/", "GET", "/api/meet/phantom/path", "F13"),
        ("/meet", "PATCH", "/api/meet", "F13"),
    ] {
        let mut inventory: Value = serde_json::from_str(setjoin_gateway::inventory::BUNDLED)?;
        let row = inventory["routes"]
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .find(|r| r["listener"] == "gateway" && r["method"] == "*" && r["path"] == logical)
            .unwrap();
        row["state"] = json!("OFF");
        row["upstream"] = json!("go-mail");
        let gateway = Gateway::new(
            Config {
                upstream: Some(format!("http://{go}").parse()?),
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                trusted_proxies: TrustedProxies::parse("")?,
                edge_limit: None,
            },
            RouteTable::proxy_all().with_catchall(setjoin_gateway::catchall::CatchallRoute::new()),
        )?
        .with_inventory(&inventory.to_string())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(gateway.serve_until(listener, async {
            let _ = stopped.await;
        }));
        let response = common::send(
            address,
            Request::builder()
                .method(method)
                .uri(path)
                .body(common::full(""))?,
        )
        .await;
        assert_eq!(response.status().as_u16(), 207, "{logical}");
        assert_eq!(
            common::body_bytes(response).await,
            format!("{method} {path}")
        );
        let response = common::send(
            address,
            Request::get("/_gateway/metrics").body(common::full(""))?,
        )
        .await;
        let metrics = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        assert!(
            metrics
                .lines()
                .any(|s| s == "setjoin_gateway_proxied_to_go_total 1"),
            "{metrics}"
        );
        assert!(
            metrics.contains(&format!(
                "setjoin_gateway_proxied_to_go_by_family_total{{family=\"{family}\"}} 1"
            )),
            "{metrics}"
        );
        let _ = stop.send(());
        task.await?;
    }
    Ok(())
}
#[tokio::test]
async fn executable_serves_a_valid_build_and_refuses_invalid_artifacts() -> Result<(), BoxError> {
    let go = common::fake_upstream(|_| async {
        Response::builder()
            .status(418)
            .body(common::full("unexpected Go request"))
            .unwrap()
    })
    .await;
    let website = assets::website("startup-valid")?;
    let address = reserve().await;
    {
        let mut process = start(address, go, None, true, Some(&website.0), false);
        ready(&mut process, address).await;
        let response =
            common::send(address, Request::get("/style.css").body(common::full(""))?).await;
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(response.headers()["cache-control"], "public, max-age=3600");
        assert_eq!(
            response.headers()["content-type"],
            "text/css; charset=utf-8"
        );
        assert_eq!(common::body_bytes(response).await, "body {color: red}\n");
    }
    for kind in [
        "missing-manifest",
        "wrong-build",
        "corrupt-identity",
        "undeclared-file",
        "symlink",
        "escape",
    ] {
        let website = assets::website(kind)?;
        match kind {
            "missing-manifest" => {
                std::fs::remove_file(website.0.join("static-representations.v1.json"))?
            }
            "corrupt-identity" => std::fs::write(website.0.join("style.css"), "corrupt")?,
            "undeclared-file" => std::fs::write(website.0.join("extra.txt"), "undeclared")?,
            "symlink" => std::os::unix::fs::symlink(
                website.0.join("style.css"),
                website.0.join("linked.css"),
            )?,
            _ => {
                let file = website.0.join("static-representations.v1.json");
                let mut manifest: Value = serde_json::from_slice(&std::fs::read(&file)?)?;
                if kind == "wrong-build" {
                    manifest["buildId"] = json!("wrong");
                } else {
                    manifest["assets"][0]["path"] = json!("/../escape");
                }
                std::fs::write(file, serde_json::to_vec(&manifest)?)?;
            }
        }
        let address = reserve().await;
        let mut process = start(address, go, None, true, Some(&website.0), false);
        let end = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if let Some(status) = process.child.try_wait()? {
                assert!(!status.success(), "accepted {kind}");
                break;
            }
            assert!(
                tokio::time::Instant::now() < end,
                "invalid artifact started a listener: {kind}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        assert!(
            tokio::net::TcpStream::connect(address).await.is_err(),
            "invalid artifact opened a listener: {kind}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn executable_refuses_unreadable_operator_config() -> Result<(), BoxError> {
    let address = reserve().await;
    let mut process = start(address, address, None, true, None, true);
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if let Some(status) = process.child.try_wait()? {
            assert!(!status.success());
            break;
        }
        assert!(tokio::time::Instant::now() < deadline, "unreadable config did not refuse startup");
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(tokio::net::TcpStream::connect(address).await.is_err());
    Ok(())
}
