//! External TLS socket seam; assertions describe what a client negotiates and receives.
use rustls::pki_types::{CertificateDer, ServerName};
use setjoin_tls::Frontend;
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Files(PathBuf);
impl Files {
    fn new(case: &str) -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../../test-results/gofree-tlsfront")
            .join(format!("{case}-{}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn pair(&self, name: &str) -> CertificateDer<'static> {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![
            name.into(),
            "foreign.localhost".into(),
            "managed.localhost".into(),
        ])
        .unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, name);
        params.not_after = rcgen::date_time_ymd(2037, 1, 1);
        let cert = params.self_signed(&key).unwrap();
        std::fs::write(self.0.join("cert.pem"), cert.pem()).unwrap();
        std::fs::write(self.0.join("key.pem"), key.serialize_pem()).unwrap();
        cert.der().clone()
    }
    fn frontend(&self) -> Arc<Frontend> {
        Frontend::from_env(&|name| match name {
            "TLS_CERT_FILE" => Some(self.0.join("cert.pem").display().to_string()),
            "TLS_KEY_FILE" => Some(self.0.join("key.pem").display().to_string()),
            "TLS_AUTOCERT_DOMAINS" => std::fs::read_to_string(self.0.join("domains")).ok(),
            "TLS_AUTOCERT_CACHE_DIR" => Some(self.0.join("cache").display().to_string()),
            _ => None,
        })
        .unwrap()
        .unwrap()
    }
}
impl Drop for Files {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[tokio::test]
async fn static_certificate_negotiates_both_http_alpns() {
    let files = Files::new("static-alpn");
    let certificate = files.pair("localhost");
    let frontend = files.frontend();
    for alpn in [b"h2".as_slice(), b"http/1.1".as_slice()] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let frontend = frontend.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = frontend.accept(stream).await.unwrap();
            tls.write_all(b"ok\n").await.unwrap();
            tls.shutdown().await.unwrap();
        });
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate.clone()).unwrap();
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
                .connect(ServerName::try_from("localhost").unwrap(), stream)
                .await
                .unwrap();
            assert_eq!(tls.get_ref().1.alpn_protocol(), Some(alpn));
            assert_eq!(tls.get_ref().1.peer_certificates().unwrap()[0], certificate);
            let mut body = Vec::new();
            tls.read_to_end(&mut body).await.unwrap();
            assert_eq!(body, b"ok\n");
        })
        .await;
        server.await.unwrap();
        result.unwrap();
    }
}

fn managed_pair(name: &str, year: i32) -> (Vec<u8>, CertificateDer<'static>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![name.into()]).unwrap();
    params.not_after = rcgen::date_time_ymd(year, 1, 1);
    let cert = params.self_signed(&key).unwrap();
    (
        format!("{}{}", key.serialize_pem(), cert.pem()).into_bytes(),
        cert.der().clone(),
    )
}

async fn peer_certificate(
    frontend: Arc<Frontend>,
    roots: &[CertificateDer<'static>],
    sni: &str,
    send_sni: bool,
) -> CertificateDer<'static> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut tls = frontend.accept(stream).await.unwrap();
        tls.write_all(b"ok\n").await.unwrap();
        tls.shutdown().await.unwrap();
    });
    let mut store = rustls::RootCertStore::empty();
    for root in roots {
        store.add(root.clone()).unwrap();
    }
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_root_certificates(store)
    .with_no_client_auth();
    config.enable_sni = send_sni;
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let mut tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(ServerName::try_from(sni.to_owned()).unwrap(), stream)
        .await
        .unwrap();
    let certificate = tls.get_ref().1.peer_certificates().unwrap()[0].clone();
    let mut body = Vec::new();
    tls.read_to_end(&mut body).await.unwrap();
    server.await.unwrap();
    certificate
}

#[tokio::test]
async fn managed_sni_cache_is_reloaded_and_misses_fall_back_to_static() {
    let files = Files::new("managed-sni");
    let static_cert = files.pair("localhost");
    std::fs::write(files.0.join("domains"), "managed.localhost").unwrap();
    let cache = setjoin_acme::cache::DirCache::new(files.0.join("cache"));
    let (blob, managed) = managed_pair("managed.localhost", 2037);
    cache.put("managed.localhost", &blob).unwrap();
    let frontend = files.frontend();
    let roots = vec![static_cert.clone(), managed.clone()];
    assert_eq!(
        peer_certificate(frontend.clone(), &roots, "managed.localhost", true).await,
        managed
    );
    assert_eq!(
        peer_certificate(frontend.clone(), &roots, "foreign.localhost", true).await,
        static_cert
    );
    assert_eq!(
        peer_certificate(frontend.clone(), &roots, "localhost", false).await,
        static_cert
    );
    let (replacement_blob, replacement) = managed_pair("managed.localhost", 2036);
    cache.put("managed.localhost", &replacement_blob).unwrap();
    let roots = vec![static_cert.clone(), replacement.clone()];
    assert_eq!(
        peer_certificate(frontend.clone(), &roots, "managed.localhost", true).await,
        replacement
    );
    for blob in [
        b"corrupt blob".to_vec(),
        managed_pair("managed.localhost", 2020).0,
    ] {
        cache.put("managed.localhost", &blob).unwrap();
        assert_eq!(
            peer_certificate(frontend.clone(), &roots, "managed.localhost", true).await,
            static_cert
        );
    }
    assert!(
        !files.0.join("cache/account.key").exists(),
        "handshakes must never register or issue"
    );
}

#[tokio::test]
async fn autocert_literal_cache_is_the_second_source_and_enforces_hostname() {
    let files = Files::new("autocert-sni");
    let static_cert = files.pair("localhost");
    std::fs::write(files.0.join("domains"), "managed.localhost").unwrap();
    let cache = files.0.join("cache");
    std::fs::create_dir_all(&cache).unwrap();
    let (blob, autocert) = managed_pair("managed.localhost", 2037);
    std::fs::write(cache.join("managed.localhost-rsa"), &blob).unwrap();
    let frontend = files.frontend();
    let roots = vec![static_cert.clone(), autocert.clone()];
    assert_eq!(
        peer_certificate(frontend.clone(), &roots, "managed.localhost", true).await,
        autocert
    );
    let (wrong_name, _) = managed_pair("other.localhost", 2037);
    std::fs::write(cache.join("managed.localhost-rsa"), wrong_name).unwrap();
    assert_eq!(
        peer_certificate(frontend, &roots, "managed.localhost", true).await,
        static_cert
    );
}

#[tokio::test]
async fn session_ticket_survives_a_native_listener_restart() {
    let files = Files::new("ticket-restart");
    let cert = files.pair("localhost");
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert).unwrap();
    let config = Arc::new(
        rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth(),
    );
    let mut kinds = Vec::new();
    for _ in 0..2 {
        let frontend = files.frontend();
        frontend.set_ticket_keys([7; 32], None);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = frontend.accept(stream).await.unwrap();
            tls.write_all(b"ok\n").await.unwrap();
            tls.shutdown().await.unwrap();
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(config.clone())
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
            .unwrap();
        kinds.push(tls.get_ref().1.handshake_kind());
        let mut body = Vec::new();
        tls.read_to_end(&mut body).await.unwrap();
        server.await.unwrap();
    }
    assert_eq!(
        kinds,
        [
            Some(rustls::HandshakeKind::Full),
            Some(rustls::HandshakeKind::Resumed)
        ]
    );
}

#[tokio::test]
async fn tls_handshake_is_bounded_by_go_thirty_second_budget() {
    let files = Files::new("handshake-timeout");
    files.pair("localhost");
    let frontend = files.frontend();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (started, ready) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ = started.send(());
        frontend.accept(stream).await
    });
    let _client = tokio::net::TcpStream::connect(addr).await.unwrap();
    ready.await.unwrap();
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(29)).await;
    assert!(!server.is_finished(), "handshake ended before Go's budget");
    tokio::time::advance(Duration::from_secs(1)).await;
    let result = tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .expect("TLS handshake did not enforce its 30s timeout")
        .unwrap();
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
}

#[test]
fn go_tls_environment_names_select_the_configured_certificate() {
    let files = Files::new("go-env");
    let certificate = files.pair("localhost");
    let frontend = Frontend::from_env(&|name| match name {
        "TLS_CERT" => Some(files.0.join("cert.pem").display().to_string()),
        "TLS_KEY" => Some(files.0.join("key.pem").display().to_string()),
        _ => None,
    })
    .unwrap()
    .expect("Go's TLS_CERT/TLS_KEY must activate the native frontend");
    assert_eq!(frontend.served_chain(), vec![certificate]);
}
