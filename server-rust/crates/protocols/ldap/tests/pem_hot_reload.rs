//! Live LDAPS PEM hot-reload test (#559).
use setjoin_ldap::Server;
use setjoin_threat::{ConnectionMeta, ThreatAction, ThreatGate};
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

struct AllowAllGate;
impl ThreatGate for AllowAllGate {
    fn intercept<'a>(
        &'a self,
        _meta: &'a ConnectionMeta,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = (ThreatAction, Duration)> + Send + 'a>>
    {
        Box::pin(async { (ThreatAction::Allow, Duration::ZERO) })
    }
    fn record_result<'a>(
        &'a self,
        _meta: &'a ConnectionMeta,
        _success: bool,
        _user_id: i64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async {})
    }
    fn evaluate_post_auth<'a>(
        &'a self,
        _meta: &'a mut ConnectionMeta,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = (ThreatAction, String)> + Send + 'a>>
    {
        Box::pin(async { (ThreatAction::Allow, String::new()) })
    }
}

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "setjoin-ldap-hot-reload-{tag}-{}-{}",
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

/// Minimal BER-encoded LDAPv3 anonymous BindRequest (msgid=1, version=3, dn="", simple="").
const ANON_BIND_REQ: &[u8] = &[
    0x30, 0x0c, // SEQUENCE len 12
    0x02, 0x01, 0x01, // INTEGER msgid=1
    0x60, 0x07, // APPLICATION 0 (BindRequest) len 7
    0x02, 0x01, 0x03, // INTEGER version=3
    0x04, 0x00, // OCTET STRING dn=""
    0x80, 0x00, // CONTEXT 0 simple=""
];

#[tokio::test]
async fn ldaps_hot_reloads_and_preserves_active_connection() {
    let dir = TempDir::new("ldaps");
    let cert_path = dir.0.join("server.pem");
    let key_path = dir.0.join("server-key.pem");

    let (c1, k1, der1) = gen_pair("ldaps1.localhost");
    std::fs::write(&cert_path, &c1).unwrap();
    std::fs::write(&key_path, &k1).unwrap();

    let server = Arc::new(
        Server::default()
            .with_threat_gate(Arc::new(AllowAllGate))
            .with_tls_files(&cert_path, &key_path)
            .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let task = tokio::spawn(server.serve(listener, rx));

    // 1. Open active LDAPS connection under cert 1.
    let mut active = connector(der1.clone())
        .connect(
            ServerName::try_from("localhost").unwrap(),
            TcpStream::connect(addr).await.unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(active.get_ref().1.peer_certificates().unwrap()[0], der1);

    // 2. Rotate PEM pair atomically on disk.
    let (c2, k2, der2) = gen_pair("ldaps2.localhost");
    atomic_write(&key_path, &k2);
    atomic_write(&cert_path, &c2);
    tokio::time::sleep(Duration::from_millis(1100)).await;

    // 3. Active pre-rotation LDAPS connection still exchanges LDAP PDUs.
    active.write_all(ANON_BIND_REQ).await.unwrap();
    let mut resp = [0u8; 64];
    let n = active.read(&mut resp).await.unwrap();
    assert!(n > 0 && resp[0] == 0x30, "expected LDAP BindResponse BER");

    // 4. New LDAPS connection receives cert 2.
    let mut conn2 = connector(der2.clone())
        .connect(
            ServerName::try_from("localhost").unwrap(),
            TcpStream::connect(addr).await.unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(conn2.get_ref().1.peer_certificates().unwrap()[0], der2);
    conn2.write_all(ANON_BIND_REQ).await.unwrap();
    let n2 = conn2.read(&mut resp).await.unwrap();
    assert!(n2 > 0 && resp[0] == 0x30);

    stop.send(true).unwrap();
    task.await.unwrap().unwrap();
}
