//! The Go root mux mounts recovery JSON routes under /api, not at bare GETs.
mod common;

use hyper::{Request, Response};
use setjoin_gateway::{
    Body, BoxFuture, Config, Gateway, Intercept, RequestContext, RouteTable, TrustedProxies,
};

struct Local;

impl Intercept for Local {
    fn matches(&self, _req: &Request<Body>) -> bool {
        true
    }

    fn handle(&self, _req: Request<Body>, _ctx: RequestContext) -> BoxFuture<Response<Body>> {
        Box::pin(async { Response::new(common::full("rust")) })
    }
}

#[tokio::test]
async fn recovery_api_mount_does_not_transfer_the_bare_spa_path() {
    let upstream = common::fake_upstream(|_| async { Response::new(common::full("go")) }).await;
    let mut inventory: serde_json::Value =
        serde_json::from_str(include_str!("../route-inventory.json")).unwrap();
    let original = inventory["routes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|r| {
            r["listener"] == "gateway" && r["method"] == "GET" && r["path"] == "/recovery/incidents"
        })
        .unwrap();
    original["state"] = "ON".into();
    original["upstream"] = "local-rust".into();
    let gateway = Gateway::new(
        Config {
            upstream: Some(format!("http://{upstream}").parse().unwrap()),
            trusted_proxies: TrustedProxies::parse("").unwrap(),
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: None,
        },
        RouteTable::proxy_all().with(Local),
    )
    .unwrap()
    .with_inventory(&inventory.to_string())
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(gateway.serve(listener));
    for (path, expected) in [
        ("/recovery/incidents", "go"),
        ("/api/recovery/incidents", "rust"),
    ] {
        let response =
            common::send(address, Request::get(path).body(common::full("")).unwrap()).await;
        assert_eq!(common::body_bytes(response).await, expected);
    }
    task.abort();

    // Go checks a literal /api registration before stripping the mount.
    // A distinct literal route must beat the mounted recovery adapter.
    let mut literal = original_entry();
    literal["path"] = "/api/recovery/incidents".into();
    literal["state"] = "OFF".into();
    literal["upstream"] = "go-mail".into();
    inventory["routes"].as_array_mut().unwrap().push(literal);
    let gateway = Gateway::new(
        Config {
            upstream: Some(format!("http://{upstream}").parse().unwrap()),
            trusted_proxies: TrustedProxies::parse("").unwrap(),
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: None,
        },
        RouteTable::proxy_all().with(Local),
    )
    .unwrap()
    .with_inventory(&inventory.to_string())
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(gateway.serve(listener));
    let response = common::send(
        address,
        Request::get("/api/recovery/incidents")
            .body(common::full(""))
            .unwrap(),
    )
    .await;
    assert_eq!(common::body_bytes(response).await, "go");
    task.abort();
}

fn original_entry() -> serde_json::Value {
    let inventory: serde_json::Value =
        serde_json::from_str(include_str!("../route-inventory.json")).unwrap();
    inventory["routes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| {
            r["listener"] == "gateway" && r["method"] == "GET" && r["path"] == "/recovery/incidents"
        })
        .unwrap()
        .clone()
}

#[tokio::test]
async fn blob_download_api_mount_preserves_the_bare_spa_path() {
    let upstream = common::fake_upstream(|_| async { Response::new(common::full("go")) }).await;
    let mut inventory: serde_json::Value =
        serde_json::from_str(include_str!("../route-inventory.json")).unwrap();
    let entry = inventory["routes"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|entry| {
            entry["family"] == "F16"
                && entry["method"] == "GET"
                && entry["path"] == "/blobs/{sha256}"
        })
        .unwrap();
    entry["state"] = "ON".into();
    entry["upstream"] = "local-rust".into();
    let gateway = Gateway::new(
        Config {
            upstream: Some(format!("http://{upstream}").parse().unwrap()),
            trusted_proxies: TrustedProxies::parse("").unwrap(),
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: None,
        },
        RouteTable::proxy_all().with(Local),
    )
    .unwrap()
    .with_inventory(&inventory.to_string())
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(gateway.serve(listener));
    for (path, expected) in [("/blobs/abc", "go"), ("/api/blobs/abc", "rust")] {
        let response =
            common::send(address, Request::get(path).body(common::full("")).unwrap()).await;
        assert_eq!(common::body_bytes(response).await, expected, "{path}");
    }
    task.abort();
}
