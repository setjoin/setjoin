//! The wildcard subtree rows (`/chat/`, `/drive/`, `/meet`, `/meet/`) belong to the
//! catch-all alone, and a rolled-back F15/F16 request is counted under its owning family (#472).
mod common;

use hyper::{Request, Response};
use setjoin_gateway::{
    Body, BoxFuture, Config, Gateway, Intercept, RequestContext, RouteTable, TrustedProxies,
};

/// A loosely matching concrete adapter: claims every request.
struct Loose;

impl Intercept for Loose {
    fn matches(&self, _req: &Request<Body>) -> bool {
        true
    }
    fn handle(&self, _req: Request<Body>, _ctx: RequestContext) -> BoxFuture<Response<Body>> {
        Box::pin(async { Response::new(common::full("rust")) })
    }
}

async fn boot(inventory: &serde_json::Value, routes: RouteTable) -> std::net::SocketAddr {
    let upstream = common::fake_upstream(|_| async { Response::new(common::full("go")) }).await;
    let gateway = Gateway::new(
        Config {
            upstream: Some(format!("http://{upstream}").parse().unwrap()),
            trusted_proxies: TrustedProxies::parse("").unwrap(),
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: None,
        },
        routes,
    )
    .unwrap()
    .with_inventory(&inventory.to_string())
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(gateway.serve(listener));
    address
}

fn bundled() -> serde_json::Value {
    serde_json::from_str(include_str!("../route-inventory.json")).unwrap()
}

#[tokio::test]
async fn bare_spa_subtree_paths_never_reach_a_loosely_matching_adapter() {
    let address = boot(&bundled(), RouteTable::proxy_all().with(Loose)).await;
    for (method, path) in [
        ("GET", "/chat/x"),
        ("GET", "/drive/x"),
        ("GET", "/meet/x"),
        ("PUT", "/meet"),
        // Go mounts the subtree handlers under /api; the rows are still catch-all only.
        ("GET", "/api/chat/x"),
        ("GET", "/api/drive/x"),
        ("PUT", "/api/meet"),
    ] {
        let response = common::send(
            address,
            Request::builder().method(method).uri(path).body(common::full("")).unwrap(),
        )
        .await;
        assert_eq!(common::body_bytes(response).await, "go", "{method} {path} reached the adapter");
    }
}

#[tokio::test]
async fn concrete_rows_beside_a_subtree_row_keep_their_adapter() {
    // `GET /api/meet` is the concrete F13 row (not the `/meet` subtree row) and stays native.
    let address = boot(&bundled(), RouteTable::proxy_all().with(Loose)).await;
    let response = common::send(
        address,
        Request::get("/api/meet").body(common::full("")).unwrap(),
    )
    .await;
    assert_eq!(common::body_bytes(response).await, "rust");
}

#[tokio::test]
async fn rolled_back_f15_f16_requests_count_under_their_owning_family() {
    let mut inventory = bundled();
    for row in inventory["routes"].as_array_mut().unwrap() {
        if row["family"] == "F16" || row["family"] == "F15" {
            row["state"] = "OFF".into();
            row["upstream"] = "go-mail".into();
        }
    }
    let address = boot(&inventory, RouteTable::proxy_all()).await;
    for (path, family) in [
        ("/api/blobs/abc", "F16"),
        ("/api/recovery/incidents", "F16"),
        ("/api/office/wopi/files/1", "F15"),
        ("/api/admin/office", "F15"),
    ] {
        let response = common::send(address, Request::get(path).body(common::full("")).unwrap()).await;
        assert_eq!(common::body_bytes(response).await, "go", "{path}");
        let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full("")).unwrap()).await;
        let text = String::from_utf8(common::body_bytes(metrics).await.to_vec()).unwrap();
        let count = |fam: &str| -> u64 {
            text.lines()
                .find_map(|l| l.strip_prefix(&format!("setjoin_gateway_proxied_to_go_by_family_total{{family=\"{fam}\"}} ")))
                .unwrap()
                .parse()
                .unwrap()
        };
        assert!(count(family) >= 1, "{path} not counted under {family}: {text}");
    }
    let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full("")).unwrap()).await;
    let text = String::from_utf8(common::body_bytes(metrics).await.to_vec()).unwrap();
    assert!(text.contains("family=\"F22\"} 0\n"), "killed F15/F16 requests leaked into F22: {text}");
    assert!(text.contains("family=\"F16\"} 2\n") && text.contains("family=\"F15\"} 2\n"), "{text}");
}
