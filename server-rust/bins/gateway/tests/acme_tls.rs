//! TLS-ALPN renewal uses the application listener; existing h2 connections survive cache publication.
#[path = "../../../crates/acme/tests/support/pebble.rs"]
mod pebble;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{client::conn::http2, Request};
use hyper_util::rt::{TokioExecutor, TokioIo};
use setjoin_acme::{cache::DirCache, Challenge, Config as AcmeConfig, Manager, TickOutcome};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{pem::PemObject, CertificateDer, ServerName},
    },
    TlsConnector,
};
struct Work(PathBuf);
impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn client(blob: &[u8]) -> Arc<rustls::ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(blob) {
        roots.add(cert.unwrap()).unwrap();
    }
    let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(roots)
    .with_no_client_auth();
    cfg.alpn_protocols = vec![b"h2".to_vec()];
    Arc::new(cfg)
}
async fn tls(
    addr: std::net::SocketAddr,
    blob: &[u8],
) -> tokio_rustls::client::TlsStream<tokio::net::TcpStream> {
    TlsConnector::from(client(blob))
        .connect(
            ServerName::try_from("localhost").unwrap(),
            tokio::net::TcpStream::connect(addr).await.unwrap(),
        )
        .await
        .unwrap()
}
async fn health(sender: &mut http2::SendRequest<Empty<Bytes>>) {
    let r = sender
        .send_request(
            Request::get("https://localhost/_gateway/healthz")
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(r.status(), 200);
    assert_eq!(r.into_body().collect().await.unwrap().to_bytes(), "ok\n");
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_alpn_renewal_reloads_served_chain_without_dropping_h2() {
    let Some(_ca) = pebble::Pebble::start().await else {
        return;
    };
    let work = Work(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../test-results/gofree-tlsfront")
            .join(format!("renewal-{}", std::process::id())),
    );
    std::fs::create_dir_all(&work.0).unwrap();
    let out = std::process::Command::new("openssl")
        .current_dir(&work.0)
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-keyout",
            "key.pem",
            "-out",
            "cert.pem",
            "-days",
            "10",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-addext",
            "basicConstraints=critical,CA:FALSE",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let out = std::process::Command::new("openssl")
        .current_dir(&work.0)
        .args(["rsa", "-in", "key.pem", "-traditional", "-out", "rsa.pem"])
        .output()
        .unwrap();
    assert!(out.status.success());
    let mut seed = std::fs::read(work.0.join("rsa.pem")).unwrap();
    seed.extend(std::fs::read(work.0.join("cert.pem")).unwrap());
    let cache = DirCache::new(work.0.join("cache"));
    cache.put("localhost", &seed).unwrap();
    let frontend = setjoin_tls::Frontend::from_env(&|k| match k {
        "TLS_AUTOCERT_DOMAINS" => Some("localhost".into()),
        "TLS_AUTOCERT_CACHE_DIR" => Some(work.0.join("cache").display().to_string()),
        _ => None,
    })
    .unwrap()
    .unwrap();
    let manager = Manager::new_with_challenge(
        AcmeConfig {
            domains: vec!["localhost".into()],
            email: "ops@example.test".into(),
            cache_dir: work.0.join("cache"),
            key_file: None,
            ca_dir_url: Some(pebble::DIRECTORY.into()),
            ca_root: Some(pebble::ca_root()),
            backoff: Some(|_| Duration::from_millis(50)),
        },
        Challenge::TlsAlpn01(frontend.tls_alpn_store()),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("[::]:5071").await.unwrap();
    let addr = "127.0.0.1:5071".parse().unwrap();
    let gateway = Gateway::new(
        Config {
            upstream: None,
            upstream_header_timeout: Duration::from_secs(5),
            trusted_proxies: TrustedProxies::default(),
            edge_limit: None,
        },
        RouteTable::proxy_all(),
    )
    .unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let f = frontend.clone();
    let server = tokio::spawn(gateway.serve_tls_until(listener, f, async {
        let _ = stopped.await;
    }));
    let stream = tls(addr, &seed).await;
    let before = stream.get_ref().1.peer_certificates().unwrap()[0].clone();
    let (mut sender, connection) = http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
        .await
        .unwrap();
    let driver = tokio::spawn(connection);
    health(&mut sender).await;
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(60), manager.tick())
            .await
            .unwrap(),
        TickOutcome::Renewed
    );
    health(&mut sender).await;
    let renewed = cache.get("localhost").unwrap();
    assert_ne!(seed, renewed);
    assert_eq!(
        setjoin_acme::inspect::describe(&seed).spki_sha256,
        setjoin_acme::inspect::describe(&renewed).spki_sha256
    );
    let stream = tls(addr, &renewed).await;
    assert_ne!(stream.get_ref().1.peer_certificates().unwrap()[0], before);
    assert_eq!(
        stream.get_ref().1.peer_certificates().unwrap(),
        frontend.served_chain()
    );
    assert!(frontend.tls_alpn_store().get("localhost").is_none());
    drop(stream);
    drop(sender);
    driver.await.unwrap().unwrap();
    let _ = stop.send(());
    server.await.unwrap();
}
