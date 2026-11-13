//! Review item 1: a stalled database makes the `/jmap` route fail closed
//! quickly — the request is forwarded to Go within a bound — and requests
//! the route never claims do not wait on the database at all. The database
//! here is a black hole (accepts TCP, never answers), so no schema is needed.
mod common;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{body_bytes, fake_upstream, full, send};
use hyper::{Request, Response};
use setjoin_gateway::jmap::jwks::Jwks;
use setjoin_gateway::jmap::{JmapCommands, JmapRoute};
use setjoin_gateway::RouteTable;
use setjoin_pg::ScopedExecutor;
use tokio::net::TcpListener;

async fn black_hole() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((sock, _)) = listener.accept().await {
            held.push(sock);
        }
    });
    addr
}

const SEEN: &str = r#"{"using":["urn:ietf:params:jmap:mail"],"methodCalls":[["Email/set",{"accountId":"1","update":{"11":{"keywords":{"$seen":true}}}},"0"]]}"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_stalled_database_forwards_to_go_within_the_bound() {
    let hits = Arc::new(AtomicUsize::new(0));
    let counter = hits.clone();
    let upstream = fake_upstream(move |_req| {
        counter.fetch_add(1, Ordering::SeqCst);
        async {
            Response::builder()
                .status(299)
                .body(full("from go"))
                .unwrap()
        }
    })
    .await;
    let db = black_hole().await;
    // Production defaults: the route must not need tuned test values.
    let exec = ScopedExecutor::from_dsn(
        &format!(
            "host={} port={} user=x password=y dbname=z",
            db.ip(),
            db.port()
        ),
        2,
    )
    .unwrap();
    let route = JmapRoute(Arc::new(JmapCommands {
        services: None,
        worker: None,
        denylist: None,
        exec,
        keys: Jwks::with_fetch(Box::new(|| Box::pin(async { Err("unused".to_string()) }))),
        issuer: "mailserver".into(),
    }));
    let gw = common::gateway(upstream, "", RouteTable::proxy_all().with(route)).await;

    // A claimed shape: the security read stalls, fails closed, and Go answers.
    let t = Instant::now();
    let resp = send(
        gw,
        Request::post("/jmap")
            .header("host", "mail.test")
            .body(full(SEEN))
            .unwrap(),
    )
    .await;
    let took = t.elapsed();
    assert_eq!(resp.status().as_u16(), 299);
    assert_eq!(&body_bytes(resp).await[..], b"from go");
    assert!(
        took < Duration::from_secs(3),
        "claimed request took {took:?}"
    );

    // Not claimed (another method, another path): no database wait at all.
    for (path, body) in [
        ("/jmap", r#"{"using":[],"methodCalls":[]}"#),
        ("/api/other", ""),
    ] {
        let t = Instant::now();
        let resp = send(
            gw,
            Request::post(path)
                .header("host", "mail.test")
                .body(full(body))
                .unwrap(),
        )
        .await;
        assert_eq!(resp.status().as_u16(), 299, "{path}");
        assert!(
            t.elapsed() < Duration::from_millis(500),
            "{path} {:?}",
            t.elapsed()
        );
    }
    assert_eq!(hits.load(Ordering::SeqCst), 3);
}
