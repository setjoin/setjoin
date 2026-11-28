//! Owner-approved security fix 2026-11-05 (#491): the global CSRF gate runs before
//! the over-budget branch. With the budget exhausted and the limiter's flag read
//! OFF, the request used to skip the gate (the only other gate runs without an
//! edge limiter) and reach the routes. Mutant: `csrf-after-over-budget`.
mod common;
use common::{body_bytes, full, send};
use hyper::{Request, Response, StatusCode};
use setjoin_gateway::RouteTable;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

#[tokio::test]
async fn over_budget_cross_site_mutation_is_denied_by_csrf() {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let upstream = common::fake_upstream(move |_| {
        counter.fetch_add(1, Ordering::SeqCst);
        async { Response::new(full("ok")) }
    })
    .await;
    // A zero budget makes every request over budget; CSRF still answers first (#491).
    let gw = common::gateway_limited(upstream, RouteTable::proxy_all(), common::edge(0)).await;
    let cross = Request::builder()
        .method("POST")
        .uri("/api/settings")
        .header("host", "mail.test")
        .header("origin", "https://evil.test")
        .body(full("{}"))
        .unwrap();
    let resp = send(gw, cross).await;
    let status = resp.status();
    let text = String::from_utf8_lossy(&body_bytes(resp).await).into_owned();
    assert_eq!(status, StatusCode::FORBIDDEN, "{text}");
    assert!(text.contains("csrf_failed"), "{text}");
    assert_eq!(hits.load(Ordering::SeqCst), 0, "the cross-site request reached the routes");
}
