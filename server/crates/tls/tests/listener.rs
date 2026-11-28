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

#[tokio::test]
async fn session_ticket_resumes_with_builtin_rustls_ticketer() {
    let files = Files::new("ticket-resume");
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
    let frontend = files.frontend();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        for _ in 0..2 {
            let (stream, _) = listener.accept().await.unwrap();
            let mut tls = frontend.accept(stream).await.unwrap();
            tls.write_all(b"ok\n").await.unwrap();
            tls.shutdown().await.unwrap();
        }
    });
    let mut kinds = Vec::new();
    for _ in 0..2 {
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut tls = tokio_rustls::TlsConnector::from(config.clone())
            .connect(ServerName::try_from("localhost").unwrap(), stream)
            .await
            .unwrap();
        kinds.push(tls.get_ref().1.handshake_kind());
        let mut body = Vec::new();
        tls.read_to_end(&mut body).await.unwrap();
    }
    server.await.unwrap();
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
