//! Hot-reload, concurrency, symlink, and fault-tolerance tests for `ReloadingPem` (#559).
use rustls::{
    pki_types::{CertificateDer, ServerName},
    ClientConfig, RootCertStore, ServerConfig,
};
use setjoin_tls::{Frontend, ReloadingPem};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "setjoin-tls-hot-reload-{tag}-{}-{}",
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

fn gen_cert(
    cn: &str,
    existing_key: Option<&rcgen::KeyPair>,
) -> (String, String, CertificateDer<'static>, rcgen::KeyPair) {
    let key = match existing_key {
        Some(k) => rcgen::KeyPair::from_pem(&k.serialize_pem()).unwrap(),
        None => rcgen::KeyPair::generate().unwrap(),
    };
    let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.not_after = rcgen::date_time_ymd(2037, 1, 1);
    let cert = params.self_signed(&key).unwrap();
    (cert.pem(), key.serialize_pem(), cert.der().clone(), key)
}

fn atomic_write(path: &Path, data: &[u8]) {
    let tmp = path.with_extension(format!(
        "tmp.{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&tmp, data).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

fn client_connector(
    roots: &[CertificateDer<'static>],
    alpn: Option<&[u8]>,
) -> tokio_rustls::TlsConnector {
    let mut store = RootCertStore::empty();
    for root in roots {
        store.add(root.clone()).unwrap();
    }
    let mut cfg =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(store)
            .with_no_client_auth();
    if let Some(proto) = alpn {
        cfg.alpn_protocols = vec![proto.to_vec()];
    }
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
}

#[tokio::test]
async fn active_h2_connection_survives_dane_key_reuse_and_full_key_rotation() {
    let dir = TempDir::new("h2-rotate");
    let cert_path = dir.0.join("server.pem");
    let key_path = dir.0.join("server-key.pem");

    let (cert1_pem, key1_pem, cert1_der, key1) = gen_cert("gen1.localhost", None);
    std::fs::write(&cert_path, &cert1_pem).unwrap();
    std::fs::write(&key_path, &key1_pem).unwrap();

    let frontend = Frontend::from_env(&|k| match k {
        "TLS_CERT" => Some(cert_path.display().to_string()),
        "TLS_KEY" => Some(key_path.display().to_string()),
        _ => None,
    })
    .unwrap()
    .unwrap();
    assert_eq!(frontend.served_chain(), vec![cert1_der.clone()]);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let fe = frontend.clone();
    let accept_loop = tokio::spawn(async move {
        let mut tasks = Vec::new();
        for _ in 0..3 {
            let (stream, _) = listener.accept().await.unwrap();
            let fe = fe.clone();
            tasks.push(tokio::spawn(async move {
                let mut tls = fe.accept(stream).await.unwrap();
                let mut buf = [0u8; 4];
                tls.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"ping");
                tls.write_all(b"pong").await.unwrap();
                // Keep first stream alive for a second round-trip after rotations.
                if tls.read_exact(&mut buf).await.is_ok() {
                    assert_eq!(&buf, b"more");
                    tls.write_all(b"done").await.unwrap();
                }
                let _ = tls.shutdown().await;
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
    });

    // 1. Open active h2-negotiated connection under cert1.
    let c1 = client_connector(std::slice::from_ref(&cert1_der), Some(b"h2"));
    let mut active = c1
        .connect(
            ServerName::try_from("localhost").unwrap(),
            TcpStream::connect(addr).await.unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(active.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
    assert_eq!(
        active.get_ref().1.peer_certificates().unwrap()[0],
        cert1_der
    );
    active.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    active.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");

    // 2. DANE-EE key-reuse rotation (cert only, same private key).
    let (cert2_pem, _, cert2_der, _) = gen_cert("gen2-reuse.localhost", Some(&key1));
    atomic_write(&cert_path, cert2_pem.as_bytes());
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(frontend.served_chain(), vec![cert2_der.clone()]);

    let c2 = client_connector(std::slice::from_ref(&cert2_der), Some(b"h2"));
    let mut conn2 = c2
        .connect(
            ServerName::try_from("localhost").unwrap(),
            TcpStream::connect(addr).await.unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(conn2.get_ref().1.peer_certificates().unwrap()[0], cert2_der);
    conn2.write_all(b"ping").await.unwrap();
    conn2.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");
    drop(conn2);

    // 3. Full key rotation (both cert and key replaced atomically).
    let (cert3_pem, key3_pem, cert3_der, _) = gen_cert("gen3-newkey.localhost", None);
    atomic_write(&key_path, key3_pem.as_bytes());
    atomic_write(&cert_path, cert3_pem.as_bytes());
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(frontend.served_chain(), vec![cert3_der.clone()]);

    let c3 = client_connector(std::slice::from_ref(&cert3_der), Some(b"h2"));
    let mut conn3 = c3
        .connect(
            ServerName::try_from("localhost").unwrap(),
            TcpStream::connect(addr).await.unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(conn3.get_ref().1.peer_certificates().unwrap()[0], cert3_der);
    conn3.write_all(b"ping").await.unwrap();
    conn3.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");
    drop(conn3);

    // 4. Original pre-rotation h2 connection is still alive and passes traffic.
    active.write_all(b"more").await.unwrap();
    active.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"done");
    drop(active);

    accept_loop.await.unwrap();
}

#[tokio::test]
async fn concurrent_handshakes_corrupt_cooldown_and_immediate_recovery() {
    let dir = TempDir::new("concurrent");
    let cert_path = dir.0.join("server.pem");
    let key_path = dir.0.join("server-key.pem");

    let (cert1_pem, key1_pem, cert1_der, _) = gen_cert("c1.localhost", None);
    let (cert2_pem, key2_pem, cert2_der, _) = gen_cert("c2.localhost", None);
    std::fs::write(&cert_path, &cert1_pem).unwrap();
    std::fs::write(&key_path, &key1_pem).unwrap();

    // Zero stat debounce, long failure cooldown (60s) so we can prove cooldown
    // skips repeated disk reads on identical corrupt sig AND new FileSig
    // bypasses cooldown immediately.
    let resolver = Arc::new(
        ReloadingPem::load_with_intervals(
            &cert_path,
            &key_path,
            Duration::ZERO,
            Duration::from_secs(60),
        )
        .unwrap(),
    );

    // Write corrupt cert -> single reload attempt, last-known-good retained.
    atomic_write(&cert_path, b"corrupt-pem-payload");
    assert_eq!(resolver.served_chain(), vec![cert1_der.clone()]);
    let attempts_after_corrupt = resolver.reload_attempts();
    assert_eq!(attempts_after_corrupt, 1);

    // Repeated calls during failure cooldown MUST NOT re-read from disk.
    for _ in 0..20 {
        assert_eq!(resolver.served_chain(), vec![cert1_der.clone()]);
    }
    assert_eq!(
        resolver.reload_attempts(),
        attempts_after_corrupt,
        "failure cooldown must suppress redundant disk reads for unchanged corrupt sig"
    );

    // Mismatched pair (cert2 with key1): new FileSig triggers 1 attempt, fails
    // key match, retains cert1, then enters cooldown for that mismatched sig.
    atomic_write(&cert_path, cert2_pem.as_bytes());
    assert_eq!(resolver.served_chain(), vec![cert1_der.clone()]);
    let attempts_after_mismatch = resolver.reload_attempts();
    assert_eq!(attempts_after_mismatch, 2);
    assert_eq!(resolver.served_chain(), vec![cert1_der.clone()]);
    assert_eq!(resolver.reload_attempts(), attempts_after_mismatch);

    // Completing the 2-file rotation (atomic rename of key2) produces a new
    // FileSig -> MUST recover IMMEDIATELY despite 60s failure cooldown!
    atomic_write(&key_path, key2_pem.as_bytes());
    assert_eq!(resolver.served_chain(), vec![cert2_der.clone()]);
    assert_eq!(resolver.reload_attempts(), 3);

    // Now run concurrent TLS handshakes while rotating and injecting faults.
    let server_cfg = Arc::new(
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(resolver.clone()),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    let acceptor = tokio_rustls::TlsAcceptor::from(server_cfg);
    let server_task = tokio::spawn(async move {
        let mut conns = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = stop_rx.changed() => break,
                res = listener.accept() => {
                    let (sock, _) = res.unwrap();
                    let acc = acceptor.clone();
                    conns.spawn(async move {
                        let mut tls = acc.accept(sock).await.unwrap();
                        let _ = tls.write_all(b"ok").await;
                        let _ = tls.shutdown().await;
                    });
                }
            }
        }
        while conns.join_next().await.is_some() {}
    });

    let connector = client_connector(&[cert1_der.clone(), cert2_der.clone()], None);
    let mut clients = tokio::task::JoinSet::new();
    for _ in 0..24 {
        let conn = connector.clone();
        clients.spawn(async move {
            let sock = TcpStream::connect(addr).await.unwrap();
            let mut tls = conn
                .connect(ServerName::try_from("localhost").unwrap(), sock)
                .await
                .unwrap();
            let mut out = [0u8; 2];
            tls.read_exact(&mut out).await.unwrap();
            assert_eq!(&out, b"ok");
        });
    }

    // Mutate files concurrently while handshakes are in flight.
    atomic_write(&cert_path, b"garbage-mid-flight");
    atomic_write(&key_path, key1_pem.as_bytes());
    atomic_write(&cert_path, cert1_pem.as_bytes());
    atomic_write(&key_path, key2_pem.as_bytes());
    atomic_write(&cert_path, cert2_pem.as_bytes());

    while let Some(res) = clients.join_next().await {
        res.unwrap();
    }
    stop_tx.send(true).unwrap();
    server_task.await.unwrap();
    assert_eq!(resolver.served_chain(), vec![cert2_der]);
}

#[cfg(unix)]
#[test]
fn symlink_target_rotation_reloads_like_letsencrypt_live() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new("symlink");
    let archive = dir.0.join("archive");
    let live = dir.0.join("live");
    std::fs::create_dir_all(&archive).unwrap();
    std::fs::create_dir_all(&live).unwrap();

    let (cert1_pem, key1_pem, cert1_der, _) = gen_cert("sym1.localhost", None);
    let (cert2_pem, key2_pem, cert2_der, _) = gen_cert("sym2.localhost", None);

    let c1 = archive.join("fullchain1.pem");
    let k1 = archive.join("privkey1.pem");
    let c2 = archive.join("fullchain2.pem");
    let k2 = archive.join("privkey2.pem");
    std::fs::write(&c1, &cert1_pem).unwrap();
    std::fs::write(&k1, &key1_pem).unwrap();
    std::fs::write(&c2, &cert2_pem).unwrap();
    std::fs::write(&k2, &key2_pem).unwrap();

    let live_cert = live.join("fullchain.pem");
    let live_key = live.join("privkey.pem");
    symlink(&c1, &live_cert).unwrap();
    symlink(&k1, &live_key).unwrap();

    let resolver =
        ReloadingPem::load_with_intervals(&live_cert, &live_key, Duration::ZERO, Duration::ZERO)
            .unwrap();
    assert_eq!(resolver.served_chain(), vec![cert1_der]);

    // Atomically flip symlinks to generation 2 (exact certbot live/ behavior).
    let tmp_live_key = live.join(".privkey.pem.new");
    let tmp_live_cert = live.join(".fullchain.pem.new");
    symlink(&k2, &tmp_live_key).unwrap();
    symlink(&c2, &tmp_live_cert).unwrap();
    std::fs::rename(&tmp_live_key, &live_key).unwrap();
    std::fs::rename(&tmp_live_cert, &live_cert).unwrap();

    assert_eq!(resolver.served_chain(), vec![cert2_der]);
}

#[test]
fn rejects_oversized_and_mismatched_files_at_startup() {
    let dir = TempDir::new("bounds");
    let cert_path = dir.0.join("cert.pem");
    let key_path = dir.0.join("key.pem");

    let (cert1_pem, _, _, _) = gen_cert("a.localhost", None);
    let (_, key2_pem, _, _) = gen_cert("b.localhost", None);

    // Mismatched pair fails closed at startup.
    std::fs::write(&cert_path, &cert1_pem).unwrap();
    std::fs::write(&key_path, &key2_pem).unwrap();
    let err = ReloadingPem::load(&cert_path, &key_path).unwrap_err();
    assert!(err.contains("TLS certificate/key pair"), "{err}");

    // Oversized file (> 1 MiB) fails closed at startup.
    let big = vec![b'A'; (1 << 20) + 16];
    std::fs::write(&cert_path, &big).unwrap();
    let err = ReloadingPem::load(&cert_path, &key_path).unwrap_err();
    assert!(err.contains("exceeds"), "{err}");
}

#[tokio::test]
async fn frontend_direct_https_and_mtls_peer_certificate_survive_atomic_pem_swap() {
    use rustls::pki_types::{pem::PemObject, PrivateKeyDer};
    use setjoin_tls::PeerCertificate;

    let dir = TempDir::new("mtls-swap");
    let cert_path = dir.0.join("server.pem");
    let key_path = dir.0.join("server-key.pem");

    // 1. Server generation 1 & 2 (separate keys).
    let (cert1_pem, key1_pem, cert1_der, _) = gen_cert("mtls-srv-1.localhost", None);
    let (cert2_pem, key2_pem, cert2_der, _) = gen_cert("mtls-srv-2.localhost", None);
    std::fs::write(&cert_path, &cert1_pem).unwrap();
    std::fs::write(&key_path, &key1_pem).unwrap();

    // 2. Trusted client CA + leaf client cert, plus an untrusted client cert.
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Setjoin Test Client CA");
    ca_params.not_after = rcgen::date_time_ymd(2037, 1, 1);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    let client_key = rcgen::KeyPair::generate().unwrap();
    let mut client_params =
        rcgen::CertificateParams::new(vec!["alice@example.test".into()]).unwrap();
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "alice@example.test");
    client_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    client_params.not_after = rcgen::date_time_ymd(2037, 1, 1);
    let client_cert = client_params.signed_by(&client_key, &issuer).unwrap();
    let client_der = client_cert.der().clone();
    let client_key_pem = client_key.serialize_pem();

    let untrusted_key = rcgen::KeyPair::generate().unwrap();
    let mut untrusted_params =
        rcgen::CertificateParams::new(vec!["mallory@evil.test".into()]).unwrap();
    untrusted_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ClientAuth];
    untrusted_params.not_after = rcgen::date_time_ymd(2037, 1, 1);
    let untrusted_cert = untrusted_params.self_signed(&untrusted_key).unwrap();

    let mut client_roots = RootCertStore::empty();
    client_roots.add(ca_cert.der().clone()).unwrap();
    let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
        Arc::new(client_roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .allow_unauthenticated()
    .build()
    .unwrap();

    let frontend = Frontend::from_env_with_client_verifier(
        &|k| match k {
            "TLS_CERT_FILE" => Some(cert_path.display().to_string()),
            "TLS_KEY_FILE" => Some(key_path.display().to_string()),
            _ => None,
        },
        verifier,
    )
    .unwrap()
    .unwrap();
    assert_eq!(frontend.served_chain(), vec![cert1_der.clone()]);

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let fe = frontend.clone();
    let (peer_tx, mut peer_rx) = tokio::sync::mpsc::unbounded_channel::<Option<PeerCertificate>>();

    let server = tokio::spawn(async move {
        let mut tasks = Vec::new();
        for _ in 0..4 {
            let (stream, _) = listener.accept().await.unwrap();
            let fe = fe.clone();
            let peer_tx = peer_tx.clone();
            tasks.push(tokio::spawn(async move {
                match fe.accept(stream).await {
                    Ok(mut tls) => {
                        let peer = tls
                            .get_ref()
                            .1
                            .peer_certificates()
                            .and_then(|chain| chain.first())
                            .cloned()
                            .map(PeerCertificate);
                        let _ = peer_tx.send(peer);
                        let mut buf = [0u8; 4];
                        if tls.read_exact(&mut buf).await.is_ok() {
                            let _ = tls.write_all(b"pong").await;
                            if tls.read_exact(&mut buf).await.is_ok() {
                                let _ = tls.write_all(b"done").await;
                            }
                        }
                        let _ = tls.shutdown().await;
                    }
                    Err(_) => {
                        // Untrusted client cert handshake failure is expected.
                    }
                }
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
    });

    let mtls_connector = |server_root: CertificateDer<'static>,
                          c_cert: CertificateDer<'static>,
                          c_key_pem: &str| {
        let mut roots = RootCertStore::empty();
        roots.add(server_root).unwrap();
        let key = PrivateKeyDer::from_pem_slice(c_key_pem.as_bytes()).unwrap();
        let mut cfg =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_client_auth_cert(vec![c_cert], key)
                .unwrap();
        cfg.alpn_protocols = vec![b"h2".to_vec()];
        tokio_rustls::TlsConnector::from(Arc::new(cfg))
    };

    // Connection 1 (mTLS under server cert1, kept open across atomic swap).
    let mut active = mtls_connector(cert1_der.clone(), client_der.clone(), &client_key_pem)
        .connect(
            ServerName::try_from("localhost").unwrap(),
            TcpStream::connect(addr).await.unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        active.get_ref().1.peer_certificates().unwrap()[0],
        cert1_der
    );
    active.write_all(b"ping").await.unwrap();
    let mut buf = [0u8; 4];
    active.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");
    let peer1 = peer_rx
        .recv()
        .await
        .unwrap()
        .expect("mTLS PeerCertificate gen1");
    assert_eq!(peer1.0, client_der);

    // Atomic server PEM swap (cert2 + key2).
    atomic_write(&key_path, key2_pem.as_bytes());
    atomic_write(&cert_path, cert2_pem.as_bytes());
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(frontend.served_chain(), vec![cert2_der.clone()]);

    // Connection 2 (mTLS under rotated server cert2).
    let mut conn2 = mtls_connector(cert2_der.clone(), client_der.clone(), &client_key_pem)
        .connect(
            ServerName::try_from("localhost").unwrap(),
            TcpStream::connect(addr).await.unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(conn2.get_ref().1.peer_certificates().unwrap()[0], cert2_der);
    conn2.write_all(b"ping").await.unwrap();
    conn2.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");
    drop(conn2);
    let peer2 = peer_rx
        .recv()
        .await
        .unwrap()
        .expect("mTLS PeerCertificate gen2");
    assert_eq!(peer2.0, client_der);

    // Connection 3 (unauthenticated direct HTTPS without client cert still works).
    let mut conn3 = client_connector(std::slice::from_ref(&cert2_der), Some(b"http/1.1"))
        .connect(
            ServerName::try_from("localhost").unwrap(),
            TcpStream::connect(addr).await.unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(conn3.get_ref().1.peer_certificates().unwrap()[0], cert2_der);
    conn3.write_all(b"ping").await.unwrap();
    conn3.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"pong");
    drop(conn3);
    assert!(
        peer_rx.recv().await.unwrap().is_none(),
        "unauthenticated client must not populate PeerCertificate"
    );

    // Connection 4 (untrusted client cert rejected by verifier after swap).
    let untrusted_conn = mtls_connector(
        cert2_der.clone(),
        untrusted_cert.der().clone(),
        &untrusted_key.serialize_pem(),
    )
    .connect(
        ServerName::try_from("localhost").unwrap(),
        TcpStream::connect(addr).await.unwrap(),
    )
    .await;
    if let Ok(mut s) = untrusted_conn {
        // TLS 1.3 delivers client-auth alert post-handshake on first read/write.
        let _ = s.write_all(b"ping").await;
        assert!(
            s.read_exact(&mut buf).await.is_err(),
            "untrusted client certificate must be rejected"
        );
    }

    // Active pre-rotation mTLS connection still passes traffic cleanly.
    active.write_all(b"more").await.unwrap();
    active.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"done");
    drop(active);

    server.await.unwrap();
}
