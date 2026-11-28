//! Live PEM hot-reload tests for SMTPS (:465) and Submission STARTTLS (:587) (#559).
use setjoin_smtp::{Server, Submission};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
};
use tokio_rustls::rustls::{
    crypto::ring,
    pki_types::{CertificateDer, ServerName},
    version::{TLS12, TLS13},
    ClientConfig, RootCertStore,
};

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "setjoin-smtp-hot-reload-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn gen_pair(cn: &str) -> (String, String, CertificateDer<'static>) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.not_after = rcgen::date_time_ymd(2037, 1, 1);
    let cert = params.self_signed(&key).unwrap();
    (cert.pem(), key.serialize_pem(), cert.der().clone())
}

fn atomic_write(path: &Path, data: &str) {
    let tmp = path.with_extension("new");
    std::fs::write(&tmp, data).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

fn connector(root: CertificateDer<'static>) -> tokio_rustls::TlsConnector {
    let mut roots = RootCertStore::empty();
    roots.add(root).unwrap();
    let cfg = ClientConfig::builder_with_provider(Arc::new(ring::default_provider()))
        .with_protocol_versions(&[&TLS13, &TLS12])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
}

#[tokio::test]
async fn smtps_hot_reloads_and_preserves_active_session() {
    let dir = TempDir::new("smtps");
    let cert_path = dir.0.join("server.pem");
    let key_path = dir.0.join("server-key.pem");

    let (c1, k1, der1) = gen_pair("smtps1.localhost");
    std::fs::write(&cert_path, &c1).unwrap();
    std::fs::write(&key_path, &k1).unwrap();

    let server = Arc::new(
        Server::new()
            .with_tls_files(cert_path.clone(), key_path.clone())
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    tokio::spawn(server.serve(listener, rx));

    // 1. Open active SMTPS connection under cert 1.
    let mut active = connector(der1.clone())
        .connect(
            ServerName::try_from("localhost").unwrap(),
            TcpStream::connect(addr).await.unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(active.get_ref().1.peer_certificates().unwrap()[0], der1);
    let mut buf = [0u8; 256];
    let n = active.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("220 "));

    // 2. Atomically rotate PEM pair on disk.
    let (c2, k2, der2) = gen_pair("smtps2.localhost");
    atomic_write(&key_path, &k2);
    atomic_write(&cert_path, &c2);
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // 3. Active session survives rotation.
    active.write_all(b"NOOP\r\n").await.unwrap();
    let n = active.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("250 OK"));

    // 4. New SMTPS handshake serves cert 2.
    let mut conn2 = connector(der2.clone())
        .connect(
            ServerName::try_from("localhost").unwrap(),
            TcpStream::connect(addr).await.unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(conn2.get_ref().1.peer_certificates().unwrap()[0], der2);
    let n = conn2.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("220 "));

    stop.send(true).unwrap();
}

#[tokio::test]
async fn submission_starttls_hot_reloads_and_preserves_active_session() {
    let dir = TempDir::new("submission");
    let cert_path = dir.0.join("server.pem");
    let key_path = dir.0.join("server-key.pem");

    let (c1, k1, der1) = gen_pair("sub1.localhost");
    std::fs::write(&cert_path, &c1).unwrap();
    std::fs::write(&key_path, &k1).unwrap();

    // Never queries DB in this handshake-only test.
    let db =
        setjoin_pg::workers::WorkerDatabase::from_dsns("postgres://nobody@127.0.0.1:9/none", None)
            .unwrap();
    let submission = Arc::new(
        Submission::new(db)
            .with_starttls_files(cert_path.clone(), key_path.clone())
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    tokio::spawn(submission.serve(listener, rx));

    async fn starttls_upgrade(
        addr: std::net::SocketAddr,
        root: CertificateDer<'static>,
    ) -> tokio_rustls::client::TlsStream<TcpStream> {
        let mut sock = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 256];
        let n = sock.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("220 "));
        sock.write_all(b"STARTTLS\r\n").await.unwrap();
        let n = sock.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("220 Ready to start TLS"));
        connector(root)
            .connect(ServerName::try_from("localhost").unwrap(), sock)
            .await
            .unwrap()
    }

    // 1. Open active STARTTLS session under cert 1.
    let mut active = starttls_upgrade(addr, der1.clone()).await;
    assert_eq!(active.get_ref().1.peer_certificates().unwrap()[0], der1);

    // 2. Atomically rotate PEM pair on disk.
    let (c2, k2, der2) = gen_pair("sub2.localhost");
    atomic_write(&key_path, &k2);
    atomic_write(&cert_path, &c2);
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // 3. Active pre-rotation STARTTLS session still works.
    active.write_all(b"NOOP\r\n").await.unwrap();
    let mut buf = [0u8; 256];
    let n = active.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).starts_with("250 OK"));

    // 4. New STARTTLS upgrade serves cert 2.
    let conn2 = starttls_upgrade(addr, der2.clone()).await;
    assert_eq!(conn2.get_ref().1.peer_certificates().unwrap()[0], der2);

    stop.send(true).unwrap();
}
