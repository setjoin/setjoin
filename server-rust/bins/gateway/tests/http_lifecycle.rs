//! Shutdown observed through the gateway's HTTP listener.
mod common;

use common::{body_bytes, full, send, within};
use http_body_util::{BodyExt, Full};
use hyper::{body::Bytes, Request, Response};
use setjoin_gateway::{
    BoxFuture, Config, Gateway, Intercept, RequestContext, RouteTable, TrustedProxies,
};
use std::sync::Arc;
use tokio::sync::{oneshot, Notify};

struct HoldRoute {
    started: Arc<Notify>,
    release: Option<Arc<Notify>>,
}
impl Intercept for HoldRoute {
    fn matches(&self, _req: &Request<setjoin_gateway::Body>) -> bool {
        true
    }
    fn handle(
        &self,
        _req: Request<setjoin_gateway::Body>,
        _ctx: RequestContext,
    ) -> BoxFuture<Response<setjoin_gateway::Body>> {
        let started = self.started.clone();
        let release = self.release.clone();
        Box::pin(async move {
            started.notify_one();
            match release {
                Some(r) => {
                    r.notified().await;
                    Response::new(
                        Full::new(Bytes::from_static(b"completed"))
                            .map_err(|never| match never {})
                            .boxed(),
                    )
                }
                None => std::future::pending().await,
            }
        })
    }
}

#[tokio::test]
async fn shutdown_stops_accepting_and_drains_an_active_request() {
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway = Gateway::new(
        Config {
            upstream: None,
            upstream_header_timeout: std::time::Duration::from_secs(10),
            trusted_proxies: TrustedProxies::parse("").unwrap(),
            edge_limit: None,
        },
        RouteTable::proxy_all().with_catchall(HoldRoute {
            started: started.clone(),
            release: Some(release.clone()),
        }),
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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let gateway = Gateway::new(
        Config {
            upstream: None,
            // Ensure the shutdown budget, rather than any upstream timeout,
            // ends this request.
            upstream_header_timeout: Duration::from_secs(120),
            trusted_proxies: TrustedProxies::parse("").unwrap(),
            edge_limit: None,
        },
        RouteTable::proxy_all().with_catchall(HoldRoute {
            started: started.clone(),
            release: None,
        }),
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
