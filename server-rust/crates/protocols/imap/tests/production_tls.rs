//! Production TLS policy (#345): Go's `tlsutil` cipher/curve lists with TLS 1.2 as
//! the floor, certificate files loaded at start (implicit) or per upgrade
//! (STARTTLS, so a rotated pair is picked up).
use setjoin_imap::{production_tls, Server, ThreatPolicy, WebhookPolicy};
use std::{path::PathBuf, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tokio_rustls::rustls::{
    crypto::{ring, CryptoProvider},
    pki_types::{pem::PemObject, CertificateDer, ServerName},
    version::{TLS12, TLS13},
    ClientConfig, RootCertStore, SupportedCipherSuite,
};

const CERT: &str =
    include_str!("../../../../tests/conformance/directory-sync/ldap-fixture/server.pem");
const KEY: &str =
    include_str!("../../../../tests/conformance/directory-sync/ldap-fixture/server.p8");
const CA: &[u8] =
    include_bytes!("../../../../tests/conformance/directory-sync/ldap-fixture/ca.pem");

struct Dir(PathBuf);
impl Dir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("gofree-imap3-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn install(&self) -> (PathBuf, PathBuf) {
        let (cert, key) = (self.0.join("cert.pem"), self.0.join("key.pem"));
        std::fs::write(&cert, CERT).unwrap();
        std::fs::write(&key, KEY).unwrap();
        (cert, key)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn executor() -> setjoin_pg::ScopedExecutor {
    // Never connects: these tests stop at the greeting and the handshake.
    setjoin_pg::ScopedExecutor::from_dsn("postgres://nobody@127.0.0.1:9/none", 1).unwrap()
}

fn client(
    suites: Vec<SupportedCipherSuite>,
    versions: &[&'static tokio_rustls::rustls::SupportedProtocolVersion],
) -> tokio_rustls::TlsConnector {
    let mut provider: CryptoProvider = ring::default_provider();
    provider.cipher_suites = suites;
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(CA).unwrap())
        .unwrap();
    let config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(config))
}

fn suite(name: tokio_rustls::rustls::CipherSuite) -> SupportedCipherSuite {
    ring::default_provider()
        .cipher_suites
        .into_iter()
        .find(|s| s.suite() == name)
        .expect("ring suite")
}

async fn serve_implicit(
    cert: PathBuf,
    key: PathBuf,
) -> (std::net::SocketAddr, watch::Sender<bool>) {
    let server = Server::new(executor(), ThreatPolicy::Unwired, WebhookPolicy::Unwired)
        .with_tls_files(cert, key)
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    tokio::spawn(Arc::new(server).serve(listener, rx));
    (addr, stop)
}

async fn greeting(
    connector: tokio_rustls::TlsConnector,
    addr: std::net::SocketAddr,
) -> Result<String, std::io::Error> {
    let socket = TcpStream::connect(addr).await?;
    let mut tls = connector
        .connect(ServerName::try_from("localhost").unwrap(), socket)
        .await?;
    let mut buf = [0u8; 256];
    let n = tls.read(&mut buf).await?;
    Ok(String::from_utf8_lossy(&buf[..n]).to_string())
}

#[tokio::test]
async fn implicit_tls_follows_gos_cipher_and_version_policy() {
    use tokio_rustls::rustls::CipherSuite as S;
    let dir = Dir::new("policy");
    let (cert, key) = dir.install();
    let (addr, stop) = serve_implicit(cert, key).await;

    // TLS 1.3 and the four ECDHE-GCM TLS 1.2 suites work.
    let hello = greeting(
        client(ring::default_provider().cipher_suites, &[&TLS13]),
        addr,
    )
    .await
    .unwrap();
    assert!(hello.starts_with("* OK [CAPABILITY IMAP4rev2"), "{hello}");
    for name in [
        S::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        S::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    ] {
        let hello = greeting(client(vec![suite(name)], &[&TLS12]), addr)
            .await
            .unwrap();
        assert!(hello.starts_with("* OK"), "{name:?}: {hello}");
    }
    // ChaCha20 on TLS 1.2 is outside Go's list: no shared suite.
    let refused = greeting(
        client(
            vec![suite(S::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)],
            &[&TLS12],
        ),
        addr,
    )
    .await;
    assert!(refused.is_err(), "chacha20 on TLS 1.2 must be refused");
    stop.send(true).unwrap();
}

#[tokio::test]
async fn starttls_reloads_the_pair_for_every_upgrade() {
    let dir = Dir::new("reload");
    let (cert, key) = dir.install();
    let server = Server::new(executor(), ThreatPolicy::Unwired, WebhookPolicy::Unwired)
        .with_starttls_files(cert.clone(), key.clone())
        .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    tokio::spawn(Arc::new(server).serve(listener, rx));
    let connector = client(ring::default_provider().cipher_suites, &[&TLS13, &TLS12]);

    let upgrade = |connector: tokio_rustls::TlsConnector| async move {
        let mut socket = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 512];
        let _ = socket.read(&mut buf).await.unwrap(); // greeting
        socket.write_all(b"a1 STARTTLS\r\n").await.unwrap();
        let n = socket.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("a1 OK Begin TLS"));
        connector
            .connect(ServerName::try_from("localhost").unwrap(), socket)
            .await
            .map(|tls| tls.get_ref().1.peer_certificates().unwrap()[0].clone())
    };
    let leaf1 = upgrade(connector.clone()).await.unwrap();
    // Intentional availability improvement (#559, ReloadingPem): a corrupt PEM
    // write after startup retains the last-known-good certificate instead of
    // terminating new STARTTLS upgrades, while a valid atomic rotation serves
    // the new leaf without restarting the listener.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    std::fs::write(&cert, "not a certificate").unwrap();
    let leaf_during_corrupt = upgrade(connector.clone()).await.unwrap();
    assert_eq!(
        leaf_during_corrupt, leaf1,
        "corrupt PEM must retain last-known-good certificate"
    );

    // Atomic rotation to a fresh self-signed pair serves the new leaf on the
    // next STARTTLS upgrade (immediate recovery on new FileSig).
    let key2 = rcgen::KeyPair::generate().unwrap();
    let mut params2 = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    params2.not_after = rcgen::date_time_ymd(2037, 1, 1);
    let cert2 = params2.self_signed(&key2).unwrap();
    let tmp_cert = dir.0.join("cert.pem.new");
    let tmp_key = dir.0.join("key.pem.new");
    std::fs::write(&tmp_cert, cert2.pem()).unwrap();
    std::fs::write(&tmp_key, key2.serialize_pem()).unwrap();
    std::fs::rename(&tmp_key, &key).unwrap();
    std::fs::rename(&tmp_cert, &cert).unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
    let mut roots2 = RootCertStore::empty();
    roots2.add(cert2.der().clone()).unwrap();
    let cfg2 = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&TLS13, &TLS12])
        .unwrap()
        .with_root_certificates(roots2)
        .with_no_client_auth();
    let leaf2 = upgrade(tokio_rustls::TlsConnector::from(Arc::new(cfg2)))
        .await
        .unwrap();
    assert_eq!(leaf2, *cert2.der());
    assert_ne!(leaf2, leaf1);
    stop.send(true).unwrap();
}

#[tokio::test]
async fn implicit_imaps_hot_reloads_and_preserves_active_session() {
    let dir = Dir::new("imaps-hot-reload");
    let (cert, key) = dir.install();
    let (addr, stop) = serve_implicit(cert.clone(), key.clone()).await;

    // Open an active IMAPS session before rotating the certificate.
    let connector1 = client(ring::default_provider().cipher_suites, &[&TLS13, &TLS12]);
    let socket1 = TcpStream::connect(addr).await.unwrap();
    let mut active = connector1
        .connect(ServerName::try_from("localhost").unwrap(), socket1)
        .await
        .unwrap();
    let leaf1 = active.get_ref().1.peer_certificates().unwrap()[0].clone();
    let mut buf = [0u8; 512];
    let n = active.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("* OK"));

    // Rotate PEM atomically on disk.
    let key2 = rcgen::KeyPair::generate().unwrap();
    let mut params2 = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    params2.not_after = rcgen::date_time_ymd(2037, 1, 1);
    let cert2 = params2.self_signed(&key2).unwrap();
    let tmp_cert = dir.0.join("cert.pem.new");
    let tmp_key = dir.0.join("key.pem.new");
    std::fs::write(&tmp_cert, cert2.pem()).unwrap();
    std::fs::write(&tmp_key, key2.serialize_pem()).unwrap();
    std::fs::rename(&tmp_key, &key).unwrap();
    std::fs::rename(&tmp_cert, &cert).unwrap();

    // Wait past default 1s stat debounce window.
    tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

    // Active pre-rotation session continues working cleanly.
    active.write_all(b"a1 NOOP\r\n").await.unwrap();
    let n = active.read(&mut buf).await.unwrap();
    assert!(
        String::from_utf8_lossy(&buf[..n]).contains("a1 OK NOOP completed"),
        "active IMAPS session failed after cert rotation"
    );

    // New IMAPS handshake serves the rotated leaf certificate.
    let mut roots2 = RootCertStore::empty();
    roots2.add(cert2.der().clone()).unwrap();
    let cfg2 = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&TLS13, &TLS12])
        .unwrap()
        .with_root_certificates(roots2)
        .with_no_client_auth();
    let socket2 = TcpStream::connect(addr).await.unwrap();
    let mut tls2 = tokio_rustls::TlsConnector::from(Arc::new(cfg2))
        .connect(ServerName::try_from("localhost").unwrap(), socket2)
        .await
        .unwrap();
    let leaf2 = tls2.get_ref().1.peer_certificates().unwrap()[0].clone();
    assert_eq!(leaf2, *cert2.der());
    assert_ne!(leaf2, leaf1);
    let n = tls2.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("* OK"));

    stop.send(true).unwrap();
}

#[test]
fn a_bad_pair_is_refused_at_start_and_names_only_the_file() {
    let dir = Dir::new("bad");
    let (cert, key) = dir.install();
    std::fs::write(&key, "garbage").unwrap();
    let err = production_tls(&cert, &key).err().unwrap();
    assert!(err.contains("TLS key") && !err.contains("garbage"), "{err}");
    let missing = production_tls(&dir.0.join("none.pem"), &key).err().unwrap();
    assert!(missing.contains("TLS certificate"), "{missing}");
    assert!(
        Server::new(executor(), ThreatPolicy::Unwired, WebhookPolicy::Unwired)
            .with_tls_files(cert, key)
            .is_err()
    );
}
