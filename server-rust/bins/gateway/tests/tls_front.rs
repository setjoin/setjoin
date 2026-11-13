//! #413 external listener seam: TLS/ALPN, prior-knowledge h2c, certificates and resumption.
mod common;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Request, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use std::time::Duration;

fn gateway() -> Gateway {
    Gateway::new(
        Config {
            upstream: None,
            upstream_header_timeout: Duration::from_secs(5),
            trusted_proxies: TrustedProxies::default(),
            edge_limit: None,
        },
        RouteTable::proxy_all(),
    )
    .unwrap()
}

#[tokio::test]
async fn h2c_prior_knowledge_serves_the_front_door() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(gateway().serve_until(listener, async {
        let _ = stopped.await;
    }));
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .unwrap();
        let driver = tokio::spawn(connection);
        let response = sender
            .send_request(
                Request::get(format!("http://{addr}/_gateway/healthz"))
                    .body(Empty::<Bytes>::new())
                    .unwrap(),
            )
            .await;
        let result = match response {
            Ok(response) => {
                assert_eq!(response.version(), Version::HTTP_2);
                assert_eq!(response.status(), 200);
                response.into_body().collect().await.unwrap().to_bytes()
            }
            Err(error) => {
                driver.abort();
                panic!("h2c request failed: {error}");
            }
        };
        drop(sender);
        driver.await.unwrap().unwrap();
        result
    })
    .await;
    let _ = stop.send(());
    server.await.unwrap();
    assert_eq!(result.unwrap(), "ok\n");
}

struct TlsFixture(std::path::PathBuf);
impl TlsFixture {
    fn new(case: &str) -> Self {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../../test-results/gofree-tlsfront")
            .join(format!("gateway-{case}-{}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        let recorded: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/conformance/tlsfront/tls13-resumed.json"
        ))
        .unwrap();
        std::fs::write(
            path.join("cert.pem"),
            recorded["certificate_pem"].as_str().unwrap(),
        )
        .unwrap();
        std::fs::write(
            path.join("key.pem"),
            recorded["public_test_key_pem"].as_str().unwrap(),
        )
        .unwrap();
        Self(path)
    }
    fn frontend(&self) -> std::sync::Arc<setjoin_tls::Frontend> {
        setjoin_tls::Frontend::from_env(&|name| match name {
            "TLS_CERT_FILE" => Some(self.0.join("cert.pem").display().to_string()),
            "TLS_KEY_FILE" => Some(self.0.join("key.pem").display().to_string()),
            _ => None,
        })
        .unwrap()
        .unwrap()
    }
    fn client(&self, alpn: &[u8]) -> std::sync::Arc<tokio_rustls::rustls::ClientConfig> {
        use tokio_rustls::rustls::{
            self,
            pki_types::{pem::PemObject, CertificateDer},
        };
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(CertificateDer::from_pem_file(self.0.join("cert.pem")).unwrap())
            .unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];
        std::sync::Arc::new(config)
    }
}
impl Drop for TlsFixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[tokio::test]
async fn tls_alpn_h2_and_http11_serve_the_native_gateway() {
    use tokio_rustls::rustls::pki_types::ServerName;
    let files = TlsFixture::new("alpn");
    for alpn in [b"h2".as_slice(), b"http/1.1".as_slice()] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(
            gateway().serve_tls_until(listener, files.frontend(), async {
                let _ = stopped.await;
            }),
        );
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tls = tokio_rustls::TlsConnector::from(files.client(alpn))
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(alpn));
        let response = if alpn == b"h2" {
            let (mut sender, connection) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                    .await
                    .unwrap();
            let driver = tokio::spawn(connection);
            let response = sender
                .send_request(
                    Request::get("https://localhost/_gateway/healthz")
                        .body(Empty::<Bytes>::new())
                        .unwrap(),
                )
                .await
                .unwrap();
            let body = response.into_body().collect().await.unwrap().to_bytes();
            drop(sender);
            driver.await.unwrap().unwrap();
            body
        } else {
            let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
                .await
                .unwrap();
            let driver = tokio::spawn(connection);
            let response = sender
                .send_request(
                    Request::get("/_gateway/healthz")
                        .header("host", "localhost")
                        .body(Empty::<Bytes>::new())
                        .unwrap(),
                )
                .await
                .unwrap();
            let body = response.into_body().collect().await.unwrap().to_bytes();
            drop(sender);
            driver.await.unwrap().unwrap();
            body
        };
        let _ = stop.send(());
        server.await.unwrap();
        assert_eq!(response, "ok\n");
    }
}

#[tokio::test]
async fn direct_tls_is_authoritative_and_http2_authority_is_preserved() {
    use tokio_rustls::rustls::pki_types::ServerName;
    let upstream=common::fake_upstream(|req|async move {
        let text=|name| req.headers().get(name).and_then(|v|v.to_str().ok()).unwrap_or("").to_owned();
        hyper::Response::new(common::full(serde_json::json!({"proto":text("x-forwarded-proto"),"host":text("host"),"forwarded_host":text("x-forwarded-host")}).to_string()))
    }).await;
    let files = TlsFixture::new("identity");
    let gateway = Gateway::new(
        Config {
            upstream: Some(format!("http://{upstream}").parse().unwrap()),
            upstream_header_timeout: Duration::from_secs(5),
            trusted_proxies: TrustedProxies::parse("127.0.0.1").unwrap(),
            edge_limit: None,
        },
        RouteTable::proxy_all(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(gateway.serve_tls_until(listener, files.frontend(), async {
        let _ = stopped.await;
    }));
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let tls = tokio_rustls::TlsConnector::from(files.client(b"h2"))
        .connect(ServerName::try_from("localhost").unwrap(), stream)
        .await
        .unwrap();
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
            .await
            .unwrap();
    let driver = tokio::spawn(connection);
    let response = sender
        .send_request(
            Request::get("https://public.example:443/tlsfront-unported-probe")
                .header("x-forwarded-proto", "http")
                .header("x-forwarded-host", "forged.example")
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    drop(sender);
    driver.await.unwrap().unwrap();
    let _ = stop.send(());
    server.await.unwrap();
    let actual: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        actual,
        serde_json::json!({"proto":"https","host":"public.example:443","forwarded_host":"public.example:443"})
    );
}

#[tokio::test]
async fn persisted_keys_resume_after_restart_and_monitor_reads_the_served_chain() {
    use tokio_rustls::rustls::{pki_types::ServerName, HandshakeKind};
    let Some(db) = setjoin_conformance::harness::Db::for_case("tlsfront-live-workers") else {
        return;
    };
    let (client, connection) = tokio_postgres::connect(&db.dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    let before=client.query_opt("SELECT value::text,encrypted,description,updated_at::text,updated_by FROM system_config WHERE key='tls_session_ticket_keys'",&[]).await.unwrap();
    let max_id: i64 = client
        .query_one("SELECT coalesce(max(id),0) FROM health_history", &[])
        .await
        .unwrap()
        .get(0);
    let seed =
        serde_json::json!({"current":"BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=","previous":""})
            .to_string();
    // Owner-approved security fix 2026-11-05 (#503): the worker reads only a sealed row.
    const SECRET: &str = "tlsfront-ticket-secret-key-0123456789abcdef";
    let deployment_before = client.query_opt("SELECT value::text FROM system_config WHERE key='identity.deployment_id'", &[]).await.unwrap().map(|r| r.get::<_, String>(0));
    client.execute("INSERT INTO system_config(key,value) VALUES('identity.deployment_id','\"tlsfront-deployment\"'::jsonb) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",&[]).await.unwrap();
    let codec = setjoin_config_secret::ConfigSecretCodec::new(setjoin_config_secret::keyring_from_lookup("tlsfront-deployment", |n| (n == "DB_ENCRYPTION_KEY").then(|| SECRET.to_owned())).unwrap()).unwrap();
    let seed = String::from_utf8(codec.encrypt("tls_session_ticket_keys", seed.as_bytes()).unwrap()).unwrap();
    client.execute("INSERT INTO system_config(key,value,encrypted,description) VALUES('tls_session_ticket_keys',$1::text::jsonb,true,'TLSFRONT fixture') ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value",&[&seed]).await.unwrap();
    let files = TlsFixture::new("workers");
    let subject = format!("gofree-tlsfront-{}", std::process::id());
    let output = std::process::Command::new("openssl")
        .current_dir(&files.0)
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "key.pem",
            "-out",
            "cert.pem",
            "-days",
            "8",
            "-subj",
            &format!("/CN={subject}"),
            "-addext",
            "subjectAltName=DNS:localhost",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let cfg = files.client(b"h2");
    let mut kinds = Vec::new();
    for _ in 0..2 {
        let frontend = files.frontend();
        let workers = setjoin_gateway::tls_runtime::start(frontend.clone(), &|name| match name {
            "RUST_WORKERS_ON" => Some("tls-ticket-keys,cert-monitor".into()),
            "GO_WORKERS_OFF" => Some("tls-ticket-keys,cert-monitor,http-tls,http-h2c".into()),
            "DB_DSN" | "DB_WORKER_DSN" => Some(db.dsn.clone()),
            "DB_ENCRYPTION_KEY" => Some(SECRET.into()),
            _ => None,
        })
        .await
        .unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(gateway().serve_tls_until(listener, frontend, async {
            let _ = stopped.await;
        }));
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let tls = tokio_rustls::TlsConnector::from(cfg.clone())
            .connect(ServerName::try_from("localhost").unwrap(), tcp)
            .await
            .unwrap();
        kinds.push(tls.get_ref().1.handshake_kind());
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .unwrap();
        let request_driver = tokio::spawn(connection);
        let response = sender
            .send_request(
                Request::get("https://localhost/_gateway/healthz")
                    .body(Empty::<Bytes>::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        response.into_body().collect().await.unwrap();
        drop(sender);
        request_driver.await.unwrap().unwrap();
        let _ = stop.send(());
        server.await.unwrap();
        tokio::time::timeout(Duration::from_secs(10),async {
            loop {let row=client.query_one("SELECT count(*)::int FROM health_history WHERE id>$1 AND check_name='tls_cert' AND details LIKE $2",&[&max_id,&format!("%{subject}%")]).await.unwrap();if row.get::<_,i32>(0)>=kinds.len() as i32 {break}tokio::time::sleep(Duration::from_millis(20)).await;}
        }).await.unwrap();
        workers.shutdown().await.unwrap();
    }
    let rows=client.query("SELECT id,status,value::int,threshold::int,details FROM health_history WHERE id>$1 AND check_name='tls_cert' AND details LIKE $2 ORDER BY id",&[&max_id,&format!("%{subject}%")]).await.unwrap();
    let observed:Vec<_>=rows.iter().map(|row| {
        let details:String=row.get(4);let mut normalized=details.replace(&subject,"SUBJECT");
        if let Some(date)=details.split('(').nth(1).and_then(|s|s.split(')').next()) {normalized=normalized.replace(date,"DATE");}
        serde_json::json!({"case":"seven","check_name":"tls_cert","status":row.get::<_,String>(1),"value":row.get::<_,i32>(2),"threshold":row.get::<_,i32>(3),"details":normalized})
    }).collect();
    for row in rows {
        client
            .execute(
                "DELETE FROM health_history WHERE id=$1",
                &[&row.get::<_, i64>(0)],
            )
            .await
            .unwrap();
    }
    match deployment_before {
        Some(v) => { client.execute("UPDATE system_config SET value=$1::text::jsonb WHERE key='identity.deployment_id'",&[&v]).await.unwrap(); }
        None => { client.execute("DELETE FROM system_config WHERE key='identity.deployment_id'",&[]).await.unwrap(); }
    }
    if let Some(row) = before {
        client.execute("UPDATE system_config SET value=$1::text::jsonb,encrypted=$2,description=$3,updated_at=$4::text::timestamptz,updated_by=$5 WHERE key='tls_session_ticket_keys'",&[&row.get::<_,String>(0),&row.get::<_,bool>(1),&row.get::<_,Option<String>>(2),&row.get::<_,String>(3),&row.get::<_,Option<i64>>(4)]).await.unwrap();
    } else {
        client
            .execute(
                "DELETE FROM system_config WHERE key='tls_session_ticket_keys'",
                &[],
            )
            .await
            .unwrap();
    }
    drop(client);
    driver.await.unwrap().unwrap();
    assert_eq!(
        kinds,
        [Some(HandshakeKind::Full), Some(HandshakeKind::Resumed)]
    );
    let golden: serde_json::Value =
        serde_json::from_str(include_str!("golden/go-cert-monitor.json")).unwrap();
    let expected = golden
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["case"] == "seven")
        .unwrap();
    assert_eq!(observed, vec![expected.clone(), expected.clone()]);
}

fn short_limits() -> setjoin_gateway::http_limits::HttpLimits {
    setjoin_gateway::http_limits::HttpLimits {
        read: Duration::from_millis(300),
        write: Duration::from_millis(900),
        idle: Duration::from_millis(600),
        max_connections: 16,
    }
}

trait ClientIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> ClientIo for T {}

async fn listener_client(
    addr: std::net::SocketAddr,
    files: Option<&TlsFixture>,
    alpn: &[u8],
) -> Box<dyn ClientIo> {
    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    match files {
        Some(files) => Box::new(
            tokio_rustls::TlsConnector::from(files.client(alpn))
                .connect(
                    tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap(),
                    tcp,
                )
                .await
                .unwrap(),
        ),
        None => Box::new(tcp),
    }
}

#[tokio::test]
async fn idle_h2_is_closed_on_public_tls_and_loopback_even_when_peer_answers_pings() {
    let files = TlsFixture::new("idle-h2");
    for secure in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let gateway = gateway().with_http_limits(short_limits()).unwrap();
        let frontend = files.frontend();
        let server = tokio::spawn(async move {
            let shutdown = async {
                let _ = stopped.await;
            };
            if secure {
                gateway.serve_tls_until(listener, frontend, shutdown).await;
            } else {
                gateway.serve_until(listener, shutdown).await;
            }
        });
        let stream = listener_client(addr, secure.then_some(&files), b"h2").await;
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .unwrap();
        let mut driver = tokio::spawn(connection);
        let started = tokio::time::Instant::now();
        let response = sender
            .send_request(
                Request::get("http://localhost/_gateway/healthz")
                    .body(Empty::<Bytes>::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "ok\n"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(200), &mut driver)
                .await
                .is_err(),
            "h2 connection closed before its idle budget"
        );
        let closed = tokio::time::timeout(Duration::from_secs(2), &mut driver).await;
        let _ = stop.send(());
        drop(sender);
        if closed.is_err() {
            driver.abort();
            let _ = driver.await;
        }
        server.await.unwrap();
        assert!(
            closed.is_ok(),
            "idle h2 remained open beyond deadline (TLS={secure})"
        );
        assert!(started.elapsed() >= short_limits().idle);
    }
}

struct ConsumeBody;
impl setjoin_gateway::Intercept for ConsumeBody {
    fn matches(&self, req: &Request<setjoin_gateway::Body>) -> bool {
        req.uri().path() == "/health"
    }
    fn handle(
        &self,
        req: Request<setjoin_gateway::Body>,
        _: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<hyper::Response<setjoin_gateway::Body>> {
        Box::pin(async move {
            match req.into_body().collect().await {
                Ok(body) => hyper::Response::new(common::full(body.to_bytes())),
                Err(_) => hyper::Response::new(common::full("read failed")),
            }
        })
    }
}

#[tokio::test]
async fn slow_h1_request_body_is_closed_on_public_tls_and_loopback() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let files = TlsFixture::new("slow-h1");
    for secure in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let gateway = Gateway::new(
            Config {
                upstream: None,
                upstream_header_timeout: Duration::from_secs(5),
                trusted_proxies: TrustedProxies::default(),
                edge_limit: None,
            },
            RouteTable::proxy_all().with(ConsumeBody),
        )
        .unwrap()
        .with_http_limits(short_limits())
        .unwrap();
        let frontend = files.frontend();
        let server = tokio::spawn(async move {
            let shutdown = async {
                let _ = stopped.await;
            };
            if secure {
                gateway.serve_tls_until(listener, frontend, shutdown).await;
            } else {
                gateway.serve_until(listener, shutdown).await;
            }
        });
        let started = tokio::time::Instant::now();
        let mut client = listener_client(addr, secure.then_some(&files), b"http/1.1").await;
        client
            .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\na")
            .await
            .unwrap();
        // Keep sending: the total read budget must not restart for each byte.
        tokio::time::sleep(Duration::from_millis(200)).await;
        client.write_all(b"b").await.unwrap();
        let mut response = Vec::new();
        let closed = tokio::time::timeout(
            Duration::from_millis(450),
            client.read_to_end(&mut response),
        )
        .await;
        let elapsed = started.elapsed();
        drop(client);
        let _ = stop.send(());
        server.await.unwrap();
        assert!(
            closed.is_ok(),
            "slow request outlived read budget (TLS={secure})"
        );
        assert!(elapsed >= short_limits().read);
        assert!(
            response.is_empty(),
            "unfinished request received a response"
        );
    }
}

struct PendingResponse;
impl setjoin_gateway::Intercept for PendingResponse {
    fn matches(&self, req: &Request<setjoin_gateway::Body>) -> bool {
        req.uri().path() == "/health"
    }
    fn handle(
        &self,
        _: Request<setjoin_gateway::Body>,
        _: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<hyper::Response<setjoin_gateway::Body>> {
        Box::pin(std::future::pending())
    }
}

#[tokio::test]
async fn response_write_deadline_covers_pending_handlers_on_h1_h2_tls_and_loopback() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let files = TlsFixture::new("write-deadline");
    for secure in [false, true] {
        for h2 in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let gateway = Gateway::new(
                Config {
                    upstream: None,
                    upstream_header_timeout: Duration::from_secs(5),
                    trusted_proxies: TrustedProxies::default(),
                    edge_limit: None,
                },
                RouteTable::proxy_all().with(PendingResponse),
            )
            .unwrap()
            .with_http_limits(short_limits())
            .unwrap();
            let frontend = files.frontend();
            let mut server = tokio::spawn(async move {
                let shutdown = async {
                    let _ = stopped.await;
                };
                if secure {
                    gateway.serve_tls_until(listener, frontend, shutdown).await;
                } else {
                    gateway.serve_until(listener, shutdown).await;
                }
            });
            let mut client = listener_client(
                addr,
                secure.then_some(&files),
                if h2 { b"h2" } else { b"http/1.1" },
            )
            .await;
            let started = tokio::time::Instant::now();
            let closed = if h2 {
                let (mut sender, connection) = hyper::client::conn::http2::handshake(
                    TokioExecutor::new(),
                    TokioIo::new(client),
                )
                .await
                .unwrap();
                let driver = tokio::spawn(connection);
                let result = tokio::time::timeout(
                    Duration::from_millis(1500),
                    sender.send_request(
                        Request::get("http://localhost/health")
                            .body(Empty::<Bytes>::new())
                            .unwrap(),
                    ),
                )
                .await;
                drop(sender);
                driver.abort();
                let _ = driver.await;
                matches!(result, Ok(Err(_)))
            } else {
                client
                    .write_all(b"GET /health HTTP/1.1\r\nHost: localhost\r\n\r\n")
                    .await
                    .unwrap();
                let mut response = Vec::new();
                let result = tokio::time::timeout(
                    Duration::from_millis(1500),
                    client.read_to_end(&mut response),
                )
                .await;
                assert!(response.is_empty());
                result.is_ok()
            };
            let elapsed = started.elapsed();
            let _ = stop.send(());
            if tokio::time::timeout(Duration::from_secs(2), &mut server)
                .await
                .is_err()
            {
                server.abort();
                let _ = server.await;
            }
            assert!(
                closed,
                "pending handler exceeded write deadline (TLS={secure},h2={h2})"
            );
            assert!(
                elapsed >= short_limits().write,
                "active request was treated as idle"
            );
        }
    }
}

#[tokio::test]
async fn connection_cap_sheds_overflow_across_tls_and_loopback_and_recovers() {
    use tokio::io::AsyncReadExt;
    let files = TlsFixture::new("connection-cap");
    for hold_tls in [false, true] {
        let plain = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let secure = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let plain_addr = plain.local_addr().unwrap();
        let secure_addr = secure.local_addr().unwrap();
        let limits = setjoin_gateway::http_limits::HttpLimits {
            read: Duration::from_secs(5),
            write: Duration::from_secs(5),
            idle: Duration::from_secs(5),
            max_connections: 1,
        };
        let gateway = gateway().with_http_limits(limits).unwrap();
        let (stop_plain, stopped_plain) = tokio::sync::oneshot::channel();
        let (stop_tls, stopped_tls) = tokio::sync::oneshot::channel();
        let plain_server = tokio::spawn(gateway.clone().serve_until(plain, async {
            let _ = stopped_plain.await;
        }));
        let tls_server = tokio::spawn(gateway.serve_tls_until(secure, files.frontend(), async {
            let _ = stopped_tls.await;
        }));
        let held_addr = if hold_tls { secure_addr } else { plain_addr };
        let overflow_addr = if hold_tls { plain_addr } else { secure_addr };
        let held = listener_client(held_addr, hold_tls.then_some(&files), b"http/1.1").await;
        let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(held))
            .await
            .unwrap();
        let driver = tokio::spawn(connection);
        let response = sender
            .send_request(
                Request::get("/_gateway/healthz")
                    .header("host", "localhost")
                    .body(Empty::<Bytes>::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "ok\n"
        );
        let mut overflow = tokio::net::TcpStream::connect(overflow_addr).await.unwrap();
        let rejected =
            tokio::time::timeout(Duration::from_secs(1), overflow.read(&mut [0; 1])).await;
        drop(overflow);
        // Saturation must leave the existing connection usable.
        let response = sender
            .send_request(
                Request::get("/_gateway/healthz")
                    .header("host", "localhost")
                    .body(Empty::<Bytes>::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "ok\n"
        );
        drop(sender);
        driver.await.unwrap().unwrap();
        // Dropping the held connection returns the permit to both accept loops.
        let recovered = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let stream = tokio::net::TcpStream::connect(plain_addr).await.unwrap();
                let (mut sender, connection) =
                    hyper::client::conn::http1::handshake(TokioIo::new(stream))
                        .await
                        .unwrap();
                let driver = tokio::spawn(connection);
                let response = sender
                    .send_request(
                        Request::get("/_gateway/healthz")
                            .header("host", "localhost")
                            .body(Empty::<Bytes>::new())
                            .unwrap(),
                    )
                    .await;
                drop(sender);
                let _ = driver.await;
                if let Ok(response) = response {
                    if response.into_body().collect().await.unwrap().to_bytes() == "ok\n" {
                        break;
                    }
                }
                tokio::task::yield_now().await;
            }
        })
        .await;
        let _ = stop_plain.send(());
        let _ = stop_tls.send(());
        plain_server.await.unwrap();
        tls_server.await.unwrap();
        assert!(
            matches!(rejected, Ok(Ok(0)) | Ok(Err(_))),
            "overflow was queued instead of shed (held TLS={hold_tls})"
        );
        assert!(
            recovered.is_ok(),
            "capacity did not recover after disconnect"
        );
    }
}

struct LargeResponse;
impl setjoin_gateway::Intercept for LargeResponse {
    fn matches(&self, req: &Request<setjoin_gateway::Body>) -> bool {
        req.uri().path() == "/health"
    }
    fn handle(
        &self,
        _: Request<setjoin_gateway::Body>,
        _: setjoin_gateway::RequestContext,
    ) -> setjoin_gateway::BoxFuture<hyper::Response<setjoin_gateway::Body>> {
        Box::pin(async { hyper::Response::new(common::full(vec![b'x'; 32 * 1024 * 1024])) })
    }
}

#[tokio::test]
async fn blocked_h1_response_keeps_write_budget_then_closes_even_after_body_was_produced() {
    let files = TlsFixture::new("blocked-write");
    for secure in [false, true] {
        for resume_early in [true, false] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let limits = setjoin_gateway::http_limits::HttpLimits {
                read: Duration::from_secs(3),
                write: Duration::from_secs(3),
                idle: Duration::from_millis(300),
                max_connections: 16,
            };
            let gateway = Gateway::new(
                Config {
                    upstream: None,
                    upstream_header_timeout: Duration::from_secs(5),
                    trusted_proxies: TrustedProxies::default(),
                    edge_limit: None,
                },
                RouteTable::proxy_all().with(LargeResponse),
            )
            .unwrap()
            .with_http_limits(limits)
            .unwrap();
            let frontend = files.frontend();
            let server = tokio::spawn(async move {
                let shutdown = async {
                    let _ = stopped.await;
                };
                if secure {
                    gateway.serve_tls_until(listener, frontend, shutdown).await;
                } else {
                    gateway.serve_until(listener, shutdown).await;
                }
            });
            let client = listener_client(addr, secure.then_some(&files), b"http/1.1").await;
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(client))
                    .await
                    .unwrap();
            let driver = tokio::spawn(connection);
            let response = sender
                .send_request(
                    Request::get("/health")
                        .header("host", "localhost")
                        .body(Empty::<Bytes>::new())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.headers()["content-length"], "33554432");
            // The client driver answers no body demand while we hold the body.
            tokio::time::sleep(if resume_early {
                limits.idle * 2
            } else {
                limits.write + Duration::from_millis(200)
            })
            .await;
            let body =
                tokio::time::timeout(Duration::from_secs(4), response.into_body().collect()).await;
            drop(sender);
            let _ = driver.await;
            let _ = stop.send(());
            server.await.unwrap();
            if resume_early {
                assert_eq!(
                    body.expect("response stalled")
                        .expect("write lost its budget to idle timeout")
                        .to_bytes()
                        .len(),
                    32 * 1024 * 1024
                );
            } else {
                assert!(
                    matches!(body, Ok(Err(_))),
                    "slow reader escaped write deadline (TLS={secure})"
                );
            }
        }
    }
}

#[tokio::test]
async fn incomplete_h2_preface_has_a_read_deadline_after_tls_and_on_loopback() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let files = TlsFixture::new("preface-read");
    for secure in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let gateway = gateway().with_http_limits(short_limits()).unwrap();
        let frontend = files.frontend();
        let server = tokio::spawn(async move {
            let shutdown = async {
                let _ = stopped.await;
            };
            if secure {
                gateway.serve_tls_until(listener, frontend, shutdown).await;
            } else {
                gateway.serve_until(listener, shutdown).await;
            }
        });
        let started = tokio::time::Instant::now();
        let mut client = listener_client(addr, secure.then_some(&files), b"h2").await;
        client.write_all(b"PRI * HTTP/2.0\r\n").await.unwrap();
        let mut frames = Vec::new();
        let closed =
            tokio::time::timeout(Duration::from_millis(500), client.read_to_end(&mut frames)).await;
        let elapsed = started.elapsed();
        drop(client);
        let _ = stop.send(());
        server.await.unwrap();
        assert!(
            closed.is_ok(),
            "partial h2 preface escaped read deadline (TLS={secure})"
        );
        assert!(elapsed >= short_limits().read);
    }
}

#[tokio::test]
async fn late_h1_keepalive_request_gets_its_full_header_read_budget() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let files = TlsFixture::new("late-h1");
    for secure in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let gateway = gateway().with_http_limits(short_limits()).unwrap();
        let frontend = files.frontend();
        let server = tokio::spawn(async move {
            let shutdown = async {
                let _ = stopped.await;
            };
            if secure {
                gateway.serve_tls_until(listener, frontend, shutdown).await;
            } else {
                gateway.serve_until(listener, shutdown).await;
            }
        });
        let mut client = listener_client(addr, secure.then_some(&files), b"http/1.1").await;
        client
            .write_all(b"GET /_gateway/healthz HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();
        let mut headers = Vec::new();
        while !headers.ends_with(b"\r\n\r\n") {
            headers.push(client.read_u8().await.unwrap());
        }
        let mut body = [0; 3];
        client.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"ok\n");
        // Beyond ReadTimeout, but just inside IdleTimeout, start the next header.
        tokio::time::sleep(Duration::from_millis(500)).await;
        let started = tokio::time::Instant::now();
        client
            .write_all(b"GET /_gateway/healthz HTTP/1.1\r\nHost:")
            .await
            .unwrap();
        let mut byte = [0; 1];
        let premature =
            tokio::time::timeout(Duration::from_millis(200), client.read(&mut byte)).await;
        let closed = tokio::time::timeout(Duration::from_millis(350), client.read(&mut byte)).await;
        let elapsed = started.elapsed();
        drop(client);
        let _ = stop.send(());
        server.await.unwrap();
        assert!(
            premature.is_err(),
            "old idle deadline shortened the new read budget (TLS={secure})"
        );
        assert!(
            closed.is_ok(),
            "partial HTTP/1 headers escaped the read deadline"
        );
        assert!(elapsed >= short_limits().read);
    }
}

#[tokio::test]
async fn slow_h2_request_body_uses_total_read_budget_on_tls_and_loopback() {
    let files = TlsFixture::new("slow-h2");
    for secure in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let gateway = Gateway::new(
            Config {
                upstream: None,
                upstream_header_timeout: Duration::from_secs(5),
                trusted_proxies: TrustedProxies::default(),
                edge_limit: None,
            },
            RouteTable::proxy_all().with(ConsumeBody),
        )
        .unwrap()
        .with_http_limits(short_limits())
        .unwrap();
        let frontend = files.frontend();
        let server = tokio::spawn(async move {
            let shutdown = async {
                let _ = stopped.await;
            };
            if secure {
                gateway.serve_tls_until(listener, frontend, shutdown).await;
            } else {
                gateway.serve_until(listener, shutdown).await;
            }
        });
        let client = listener_client(addr, secure.then_some(&files), b"h2").await;
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(client))
                .await
                .unwrap();
        let driver = tokio::spawn(connection);
        let (mut input, body) =
            http_body_util::channel::Channel::<Bytes, setjoin_gateway::BoxError>::new(1);
        let started = tokio::time::Instant::now();
        input.send_data(Bytes::from_static(b"a")).await.unwrap();
        let request = tokio::spawn(async move {
            sender
                .send_request(Request::get("http://localhost/health").body(body).unwrap())
                .await
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        input.send_data(Bytes::from_static(b"b")).await.unwrap();
        let result = tokio::time::timeout(Duration::from_millis(450), request).await;
        let elapsed = started.elapsed();
        drop(input);
        driver.abort();
        let _ = driver.await;
        let _ = stop.send(());
        server.await.unwrap();
        assert!(
            matches!(result, Ok(Ok(Err(_)))),
            "slow h2 request escaped read budget (TLS={secure})"
        );
        assert!(elapsed >= short_limits().read);
    }
}

#[tokio::test]
async fn h2_peer_that_ignores_keepalive_ping_is_closed_before_idle_deadline() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let files = TlsFixture::new("h2-no-pong");
    for secure in [false, true] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let limits = setjoin_gateway::http_limits::HttpLimits {
            read: Duration::from_millis(100),
            write: Duration::from_secs(3),
            idle: Duration::from_secs(2),
            max_connections: 16,
        };
        let gateway = gateway().with_http_limits(limits).unwrap();
        let frontend = files.frontend();
        let server = tokio::spawn(async move {
            let shutdown = async {
                let _ = stopped.await;
            };
            if secure {
                gateway.serve_tls_until(listener, frontend, shutdown).await;
            } else {
                gateway.serve_until(listener, shutdown).await;
            }
        });
        let mut client = listener_client(addr, secure.then_some(&files), b"h2").await;
        let started = tokio::time::Instant::now();
        // RFC 9113 connection preface and an empty SETTINGS frame. Read every
        // server frame but deliberately withhold keepalive PING acknowledgements.
        client
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\0\0\0\x04\0\0\0\0\0")
            .await
            .unwrap();
        let mut frames = Vec::new();
        let closed =
            tokio::time::timeout(Duration::from_millis(1700), client.read_to_end(&mut frames))
                .await;
        let elapsed = started.elapsed();
        drop(client);
        let _ = stop.send(());
        server.await.unwrap();
        assert!(
            closed.is_ok(),
            "unresponsive h2 peer outlived PING timeout (TLS={secure})"
        );
        assert!(
            elapsed >= limits.idle / 2,
            "preface was rejected before the PING interval"
        );
    }
}

#[tokio::test]
async fn blocked_h2_response_retains_write_deadline_through_flow_control() {
    let files = TlsFixture::new("blocked-h2-write");
    for secure in [false, true] {
        for resume_early in [true, false] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let (stop, stopped) = tokio::sync::oneshot::channel();
            let limits = setjoin_gateway::http_limits::HttpLimits {
                read: Duration::from_secs(3),
                write: Duration::from_secs(3),
                idle: Duration::from_millis(300),
                max_connections: 16,
            };
            let gateway = Gateway::new(
                Config {
                    upstream: None,
                    upstream_header_timeout: Duration::from_secs(5),
                    trusted_proxies: TrustedProxies::default(),
                    edge_limit: None,
                },
                RouteTable::proxy_all().with(LargeResponse),
            )
            .unwrap()
            .with_http_limits(limits)
            .unwrap();
            let frontend = files.frontend();
            let server = tokio::spawn(async move {
                let shutdown = async {
                    let _ = stopped.await;
                };
                if secure {
                    gateway.serve_tls_until(listener, frontend, shutdown).await;
                } else {
                    gateway.serve_until(listener, shutdown).await;
                }
            });
            let client = listener_client(addr, secure.then_some(&files), b"h2").await;
            let (mut sender, connection) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(client))
                    .await
                    .unwrap();
            let driver = tokio::spawn(connection);
            let response = sender
                .send_request(
                    Request::get("http://localhost/health")
                        .body(Empty::<Bytes>::new())
                        .unwrap(),
                )
                .await
                .unwrap();
            tokio::time::sleep(if resume_early {
                limits.idle * 2
            } else {
                limits.write + Duration::from_millis(200)
            })
            .await;
            let body =
                tokio::time::timeout(Duration::from_secs(4), response.into_body().collect()).await;
            drop(sender);
            let _ = driver.await;
            let _ = stop.send(());
            server.await.unwrap();
            if resume_early {
                assert_eq!(
                    body.expect("response stalled")
                        .expect("flow-controlled response became idle")
                        .to_bytes()
                        .len(),
                    32 * 1024 * 1024
                );
            } else {
                assert!(
                    matches!(body, Ok(Err(_))),
                    "h2 flow control escaped write deadline (TLS={secure})"
                );
            }
        }
    }
}
