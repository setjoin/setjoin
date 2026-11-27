//! #413: frozen-Go TLS/HTTP negotiations replayed against the native front door (pure Rust).
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{json, Value};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::net::TcpStream;
use tokio_rustls::rustls::{
    self,
    client::{ClientSessionMemoryCache, ClientSessionStore, Resumption},
    pki_types::{pem::PemObject, CertificateDer, ServerName},
    ClientConfig, HandshakeKind, NamedGroup, RootCertStore,
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}

struct Work(PathBuf);
impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[derive(Debug)]
struct CountingStore {
    inner: ClientSessionMemoryCache,
    tickets: AtomicUsize,
}

impl CountingStore {
    fn new() -> Self {
        Self {
            inner: ClientSessionMemoryCache::new(8),
            tickets: AtomicUsize::new(0),
        }
    }
    fn issued(&self) -> usize {
        self.tickets.load(Ordering::SeqCst)
    }
}

impl ClientSessionStore for CountingStore {
    fn set_kx_hint(&self, server_name: ServerName<'static>, group: NamedGroup) {
        self.inner.set_kx_hint(server_name, group);
    }
    fn kx_hint(&self, server_name: &ServerName<'_>) -> Option<NamedGroup> {
        self.inner.kx_hint(server_name)
    }
    fn set_tls12_session(
        &self,
        server_name: ServerName<'static>,
        value: rustls::client::Tls12ClientSessionValue,
    ) {
        self.tickets.fetch_add(1, Ordering::SeqCst);
        self.inner.set_tls12_session(server_name, value);
    }
    fn tls12_session(
        &self,
        server_name: &ServerName<'_>,
    ) -> Option<rustls::client::Tls12ClientSessionValue> {
        self.inner.tls12_session(server_name)
    }
    fn remove_tls12_session(&self, server_name: &ServerName<'static>) {
        self.inner.remove_tls12_session(server_name);
    }
    fn insert_tls13_ticket(
        &self,
        server_name: ServerName<'static>,
        value: rustls::client::Tls13ClientSessionValue,
    ) {
        self.tickets.fetch_add(1, Ordering::SeqCst);
        self.inner.insert_tls13_ticket(server_name, value);
    }
    fn take_tls13_ticket(
        &self,
        server_name: &ServerName<'static>,
    ) -> Option<rustls::client::Tls13ClientSessionValue> {
        self.inner.take_tls13_ticket(server_name)
    }
}

fn prepare(work: &Work, a: &Value) {
    std::fs::write(work.0.join("cert.pem"), a["certificate"].as_str().unwrap()).unwrap();
    std::fs::write(
        work.0.join("key.pem"),
        a["public_test_key"].as_str().unwrap(),
    )
    .unwrap();
    std::fs::write(work.0.join("roots.pem"), a["roots"].as_str().unwrap()).unwrap();
}

fn http_version_label(version: hyper::Version) -> &'static str {
    match version {
        hyper::Version::HTTP_10 => "HTTP/1.0",
        hyper::Version::HTTP_11 => "HTTP/1.1",
        hyper::Version::HTTP_2 => "HTTP/2.0",
        hyper::Version::HTTP_3 => "HTTP/3.0",
        _ => "HTTP/unknown",
    }
}

fn header_str(headers: &hyper::HeaderMap, name: &str) -> String {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned()
}

fn leaf_common_name(der: &[u8]) -> String {
    let (_, cert) = x509_parser::parse_x509_certificate(der).expect("parse leaf certificate");
    let cn = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|attr| attr.as_str().ok())
        .unwrap_or_default()
        .to_owned();
    cn
}

async fn probe(work: &Work, addr: SocketAddr, c: &Value) -> Value {
    let plain = c["plain"].as_bool().unwrap();
    let sni = c["sni"].as_str().unwrap();
    if plain {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
                .await
                .unwrap();
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = hyper::Request::builder()
            .method("GET")
            .uri(format!("http://{sni}/_gateway/healthz"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        let status = resp.status().as_u16();
        let http_version = http_version_label(resp.version());
        let content_type = header_str(resp.headers(), "content-type");
        let hsts = header_str(resp.headers(), "strict-transport-security");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        drop(sender);
        driver.abort();
        return json!({
            "resumed": false,
            "version": 0,
            "cipher": 0,
            "alpn": "",
            "subject": "",
            "chain": 0,
            "body": String::from_utf8(body.to_vec()).unwrap(),
            "status": status,
            "http_version": http_version,
            "content_type": content_type,
            "hsts": hsts,
            "tickets_issued": 0,
        });
    }

    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(work.0.join("roots.pem")).unwrap() {
        roots.add(cert.unwrap()).unwrap();
    }
    let version = c["version"].as_u64().unwrap() as u16;
    let versions: &[&rustls::SupportedProtocolVersion] = match version {
        0x303 => &[&rustls::version::TLS12],
        0x304 => &[&rustls::version::TLS13],
        _ => panic!("unexpected TLS version {version:#x}"),
    };
    let store = Arc::new(CountingStore::new());
    let mut cfg =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(versions)
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
    cfg.resumption = Resumption::store(store.clone());
    let alpn = c["alpn"].as_str().unwrap();
    if !alpn.is_empty() {
        cfg.alpn_protocols = alpn.split(',').map(|s| s.as_bytes().to_vec()).collect();
    }

    let tcp = TcpStream::connect(addr).await.unwrap();
    let server_name = ServerName::try_from(sni.to_owned()).unwrap();
    let tls = tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(server_name, tcp)
        .await
        .unwrap();

    let (resumed, negotiated_version, cipher, negotiated_alpn, chain, subject) = {
        let conn = tls.get_ref().1;
        let certs = conn.peer_certificates().unwrap_or_default();
        let subject = certs
            .first()
            .map(|der| leaf_common_name(der.as_ref()))
            .unwrap_or_default();
        (
            conn.handshake_kind() == Some(HandshakeKind::Resumed),
            u16::from(conn.protocol_version().unwrap()),
            u16::from(conn.negotiated_cipher_suite().unwrap().suite()),
            String::from_utf8_lossy(conn.alpn_protocol().unwrap_or_default()).into_owned(),
            certs.len(),
            subject,
        )
    };

    let (status, http_version, content_type, hsts, body) = if negotiated_alpn == "h2" {
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls))
                .await
                .unwrap();
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = hyper::Request::builder()
            .method("GET")
            .uri(format!("https://{sni}/_gateway/healthz"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        let status = resp.status().as_u16();
        let http_version = http_version_label(resp.version());
        let content_type = header_str(resp.headers(), "content-type");
        let hsts = header_str(resp.headers(), "strict-transport-security");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        drop(sender);
        driver.abort();
        (status, http_version, content_type, hsts, body)
    } else {
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
            .await
            .unwrap();
        let driver = tokio::spawn(async move {
            let _ = conn.await;
        });
        let req = hyper::Request::builder()
            .method("GET")
            .uri("/_gateway/healthz")
            .header("host", sni)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        let status = resp.status().as_u16();
        let http_version = http_version_label(resp.version());
        let content_type = header_str(resp.headers(), "content-type");
        let hsts = header_str(resp.headers(), "strict-transport-security");
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        drop(sender);
        driver.abort();
        (status, http_version, content_type, hsts, body)
    };

    json!({
        "resumed": resumed,
        "version": negotiated_version,
        "cipher": cipher,
        "alpn": negotiated_alpn,
        "subject": subject,
        "chain": chain,
        "body": String::from_utf8(body.to_vec()).unwrap(),
        "status": status,
        "http_version": http_version,
        "content_type": content_type,
        "hsts": hsts,
        "tickets_issued": store.issued(),
    })
}

async fn replay(work: &Work, a: &Value, c: &Value, aes: bool) -> Value {
    prepare(work, a);
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
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let frontend = setjoin_tls::Frontend::from_env_with_aes(
        &|key| match key {
            "TLS_CERT_FILE" => Some(work.0.join("cert.pem").display().to_string()),
            "TLS_KEY_FILE" => Some(work.0.join("key.pem").display().to_string()),
            _ => None,
        },
        aes,
    )
    .unwrap()
    .unwrap();
    let plain = c["plain"].as_bool().unwrap();
    let server = tokio::spawn(async move {
        let stop = async {
            let _ = stopped.await;
        };
        if plain {
            gateway.serve_until(listener, stop).await
        } else {
            gateway.serve_tls_until(listener, frontend, stop).await
        }
    });
    let observed = probe(work, addr, c).await;
    let _ = stop.send(());
    server.await.unwrap();
    observed
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_h2c_and_sni_match_recorded_go() {
    let work = Work(
        root()
            .join("test-results/gofree-tlsfront")
            .join(format!("http-oracle-{}", std::process::id())),
    );
    std::fs::create_dir_all(&work.0).unwrap();
    for aes in [true, false] {
        let name = if aes {
            "http-negotiation.json"
        } else {
            "http-negotiation-no-aes.json"
        };
        let path = root()
            .join("server-rust/tests/conformance/tlsfront")
            .join(name);
        let recorded: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let mut replayed = 0usize;
        for case in recorded["cases"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| c["cache"].as_str() == Some("none"))
        {
            let actual = replay(&work, &recorded["fixtures"], case, aes).await;
            assert_eq!(actual, case["observation"], "AES={aes}, {}", case["name"]);
            replayed += 1;
        }
        assert_eq!(replayed, 4, "expected 4 static-PEM/h2c cases for AES={aes}");
    }
}
