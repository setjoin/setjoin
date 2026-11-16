//! #359b: the chained deployment (setjoin-auth -> authserverd). The Go hop carries
//! the resolved client IP, and the readiness path `/_setjoin/readiness` is a
//! credential-free fallthrough hand-off: it never becomes a native reply or a login.
mod common;
use http_body_util::BodyExt;
use hyper::Request;
use setjoin_auth::{body, AuthServer, Config};
use setjoin_conformance::harness::Db;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};

type Err = Box<dyn std::error::Error + Send + Sync>;
const SECRET: &str = "chained-handoff-secret-0123456789abcdef";
const READINESS: &str = "/_setjoin/readiness";

struct Server {
    stop: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<()>,
    addr: std::net::SocketAddr,
}
impl Server {
    async fn close(mut self) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(());
        }
        let _ = (&mut self.task).await;
    }
}
async fn serve(server: Arc<AuthServer>) -> Server {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        tokio::pin!(rx);
        loop {
            tokio::select! {
                _ = &mut rx => break,
                accepted = listener.accept() => {
                    let (stream, peer) = accepted.unwrap();
                    let server = server.clone();
                    tokio::spawn(async move {
                        let service = hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
                            let server = server.clone();
                            req.extensions_mut().insert(setjoin_auth::ConnectionMeta { peer, tls: false });
                            async move {
                                Ok::<_, std::convert::Infallible>(
                                    server.handle(req.map(|b| b.map_err(std::io::Error::other).boxed())).await,
                                )
                            }
                        });
                        let _ = hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new())
                            .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                            .await;
                    });
                }
            }
        }
    });
    Server {
        stop: Some(tx),
        task,
        addr,
    }
}
/// Fake Go: counts hits, reports X-Forwarded-For, answers like Go's mux 404.
async fn fake_go(
    hits: Arc<AtomicUsize>,
    xff: mpsc::UnboundedSender<Option<String>>,
) -> Result<std::net::SocketAddr, Err> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (hits, xff) = (hits.clone(), xff.clone());
            tokio::spawn(async move {
                let service =
                    hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                        hits.fetch_add(1, Ordering::SeqCst);
                        let _ = xff.send(
                            req.headers()
                                .get("x-forwarded-for")
                                .and_then(|v| v.to_str().ok())
                                .map(str::to_owned),
                        );
                        async move {
                            let mut r = hyper::Response::new(body("404 page not found\n"));
                            *r.status_mut() = hyper::StatusCode::NOT_FOUND;
                            Ok::<_, std::convert::Infallible>(r)
                        }
                    });
                let _ = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .await;
            });
        }
    });
    Ok(addr)
}
async fn send(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    payload: &'static str,
    headers: &[(&str, &str)],
) -> Result<u16, Err> {
    let client: hyper_util::client::legacy::Client<_, setjoin_auth::Body> =
        hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
            .build_http();
    let mut req = Request::builder()
        .method(method)
        .uri(format!("http://{addr}{path}"));
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let resp = client.request(req.body(body(payload))?).await?;
    let status = resp.status().as_u16();
    let _ = resp.into_body().collect().await?;
    Ok(status)
}
async fn start(
    db: &Db,
    threat: [bool; 5],
    go: Option<std::net::SocketAddr>,
    proxy: &str,
) -> Result<Server, Err> {
    let mut cfg = Config::for_secret(SECRET.into());
    cfg.threat_controls = threat;
    cfg.go_upstream = go.map(|a| format!("http://{a}"));
    cfg.client_proxy = proxy.into();
    let exec = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
        .map_err(|e| e.0)?;
    Ok(serve(Arc::new(AuthServer::load(exec, cfg).await?)).await)
}

#[tokio::test]
async fn go_handoff_carries_the_resolved_client_ip() -> Result<(), Err> {
    let db = Db::for_case("chained-handoff-xff").expect("database required");
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let (tx, mut rx) = mpsc::unbounded_channel();
    let go = fake_go(Arc::new(AtomicUsize::new(0)), tx).await?;
    for (proxy, expected) in [("127.0.0.1", "203.0.113.7"), ("", "127.0.0.1")] {
        let server = start(&db, [true; 5], Some(go), proxy).await?;
        let status = send(
            server.addr,
            "POST",
            "/auth/login",
            "{}",
            &[
                ("content-type", "application/json"),
                ("x-forwarded-for", "203.0.113.7"),
            ],
        )
        .await?;
        assert_eq!(
            status, 404,
            "login must reach the fake Go (TRUSTED_PROXY_IP={proxy:?})"
        );
        assert_eq!(
            rx.recv().await.flatten().as_deref(),
            Some(expected),
            "TRUSTED_PROXY_IP={proxy:?}"
        );
        server.close().await;
    }
    Ok(())
}

/// N1: the readiness probe path is a credential-free Go hand-off in every threat
/// posture (Go answers 404), and a broken chain is 502/503, never a native 404.
#[tokio::test]
async fn readiness_path_is_a_credential_free_go_handoff() -> Result<(), Err> {
    let db = Db::for_case("chained-handoff-readiness").expect("database required");
    let c = db.connect().await?;
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await?;
    common::signing_key(&c).await;
    let hits = Arc::new(AtomicUsize::new(0));
    let (tx, _rx) = mpsc::unbounded_channel();
    let go = fake_go(hits.clone(), tx).await?;
    for threat in [[true; 5], [false; 5]] {
        let server = start(&db, threat, Some(go), "127.0.0.1").await?;
        let before = hits.load(Ordering::SeqCst);
        let status = send(server.addr, "GET", READINESS, "", &[]).await?;
        assert_eq!(
            hits.load(Ordering::SeqCst) - before,
            1,
            "readiness must reach Go exactly once (threat={threat:?})"
        );
        assert_eq!(
            status, 404,
            "Go's answer must pass through (threat={threat:?})"
        );
        server.close().await;
    }
    let server = start(&db, [true; 5], None, "127.0.0.1").await?;
    let before = hits.load(Ordering::SeqCst);
    let status = send(server.addr, "GET", READINESS, "", &[]).await?;
    assert_eq!(hits.load(Ordering::SeqCst), before);
    assert!(
        matches!(status, 502 | 503),
        "a broken chain must not look ready: {status}"
    );
    server.close().await;
    // Unreachable Go is a broken chain too.
    let dead = TcpListener::bind("127.0.0.1:0").await?.local_addr()?;
    let server = start(&db, [false; 5], Some(dead), "127.0.0.1").await?;
    let status = send(server.addr, "GET", READINESS, "", &[]).await?;
    assert!(
        matches!(status, 502 | 503),
        "an unreachable authserverd must not look ready: {status}"
    );
    server.close().await;
    Ok(())
}
