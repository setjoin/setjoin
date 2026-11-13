//! Shutdown observed through the gateway's HTTP listener.
mod common;

use common::{body_bytes, fake_upstream, full, send, within};
use hyper::{Request, Response};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use std::sync::Arc;
use tokio::sync::{oneshot, Notify};

#[tokio::test]
async fn shutdown_stops_accepting_and_drains_an_active_request() {
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let upstream = fake_upstream({
        let started = started.clone();
        let release = release.clone();
        move |_| {
            let started = started.clone();
            let release = release.clone();
            async move {
                started.notify_one();
                release.notified().await;
                Response::new(full("completed"))
            }
        }
    })
    .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway = Gateway::new(
        Config {
            upstream: Some(format!("http://{upstream}").parse().unwrap()),
            upstream_header_timeout: std::time::Duration::from_secs(10),
            trusted_proxies: TrustedProxies::parse("").unwrap(),
            edge_limit: None,
        },
        RouteTable::proxy_all(),
    )
    .unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(gateway.serve_until(listener, async {
        let _ = stopped.await;
    }));
    let request =
        tokio::spawn(
            async move { send(addr, Request::get("/test").body(full("")).unwrap()).await },
        );
    within(started.notified()).await;
    stop.send(()).unwrap();
    within(async {
        loop {
            if tokio::net::TcpStream::connect(addr).await.is_err() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        !server.is_finished(),
        "shutdown returned before the active request completed"
    );
    release.notify_one();
    let response = within(request).await.unwrap();
    assert_eq!(body_bytes(response).await, "completed");
    within(server).await.unwrap();
}

#[tokio::test]
async fn shutdown_bounds_an_unfinished_request_to_go_thirty_second_budget() {
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let started = Arc::new(Notify::new());
    let upstream = fake_upstream({
        let started = started.clone();
        move |_| {
            started.notify_one();
            std::future::pending::<Response<common::TestBody>>()
        }
    })
    .await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway = Gateway::new(
        Config {
            upstream: Some(format!("http://{upstream}").parse().unwrap()),
            // Ensure the shutdown budget, rather than the proxy timeout,
            // ends this request.
            upstream_header_timeout: Duration::from_secs(120),
            trusted_proxies: TrustedProxies::parse("").unwrap(),
            edge_limit: None,
        },
        RouteTable::proxy_all(),
    )
    .unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(gateway.serve_until(listener, async {
        let _ = stopped.await;
    }));
    let mut client = tokio::net::TcpStream::connect(addr).await.unwrap();
    client
        .write_all(b"GET /pending HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    within(started.notified()).await;
    let shutdown_at = tokio::time::Instant::now();
    stop.send(()).unwrap();
    tokio::time::sleep(Duration::from_secs(29)).await;
    assert!(
        !server.is_finished(),
        "active request lost its drain budget"
    );
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
    assert!(shutdown_at.elapsed() >= Duration::from_secs(30));
    let mut response = Vec::new();
    within(client.read_to_end(&mut response)).await.unwrap();
    assert!(
        response.is_empty(),
        "unfinished request received a response"
    );
    assert!(tokio::net::TcpStream::connect(addr).await.is_err());
}
