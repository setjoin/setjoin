//! Frozen-Go TLS negotiation policy, including rejection alerts and cipher changes on resumption.
use rustls::{
    crypto::ring::{cipher_suite as cs, kx_group as kx},
    pki_types::{pem::PemObject, CertificateDer, ServerName},
    ClientConfig, SupportedCipherSuite,
};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
struct Work(PathBuf);
impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[derive(Clone)]
struct Case {
    name: &'static str,
    version: u16,
    ciphers: Vec<SupportedCipherSuite>,
    p384: bool,
    alpn: &'static str,
}
fn cases() -> Vec<Case> {
    let base = |name, version, ciphers| Case {
        name,
        version,
        ciphers,
        p384: false,
        alpn: "h2",
    };
    let mut cases = vec![
        base(
            "tls12-aes128",
            0x303,
            vec![cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
        ),
        base(
            "tls12-chacha-refused",
            0x303,
            vec![cs::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256],
        ),
        base(
            "tls12-server-order",
            0x303,
            vec![
                cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
                cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
            ],
        ),
        base(
            "tls13-server-order",
            0x304,
            vec![cs::TLS13_AES_256_GCM_SHA384, cs::TLS13_AES_128_GCM_SHA256],
        ),
        base(
            "tls13-client-chacha-preference",
            0x304,
            vec![
                cs::TLS13_CHACHA20_POLY1305_SHA256,
                cs::TLS13_AES_128_GCM_SHA256,
            ],
        ),
        base(
            "tls13-hardware-preference",
            0x304,
            vec![
                cs::TLS13_AES_128_GCM_SHA256,
                cs::TLS13_CHACHA20_POLY1305_SHA256,
            ],
        ),
    ];
    let mut p384 = base(
        "tls12-p384-refused",
        0x303,
        vec![cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256],
    );
    p384.p384 = true;
    cases.push(p384);
    let mut p384 = base(
        "tls13-p384-refused",
        0x304,
        vec![cs::TLS13_AES_128_GCM_SHA256],
    );
    p384.p384 = true;
    cases.push(p384);
    let mut alpn = base(
        "unmatched-alpn-refused",
        0x304,
        vec![cs::TLS13_AES_128_GCM_SHA256],
    );
    alpn.alpn = "smtp";
    cases.push(alpn);
    cases
}
#[derive(Debug)]
struct NoClientCert;
impl rustls::client::ResolvesClientCert for NoClientCert {
    fn resolve(
        &self,
        _: &[&[u8]],
        _: &[rustls::SignatureScheme],
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        None
    }
    fn has_certs(&self) -> bool {
        false
    }
}
fn config(
    c: &Case,
    verifier: Arc<dyn rustls::client::danger::ServerCertVerifier>,
    auth: Arc<NoClientCert>,
) -> ClientConfig {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.cipher_suites = c.ciphers.clone();
    provider.kx_groups = if c.p384 {
        vec![kx::SECP384R1]
    } else {
        vec![kx::X25519, kx::SECP256R1]
    };
    let versions = if c.version == 0x303 {
        &[&rustls::version::TLS12][..]
    } else {
        &[&rustls::version::TLS13][..]
    };
    let mut cfg = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(versions)
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_client_cert_resolver(auth);
    cfg.alpn_protocols = vec![c.alpn.as_bytes().to_vec()];
    cfg
}
async fn connect(address: &str, cfg: ClientConfig) -> Value {
    let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
    match tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
    {
        Err(e) => match e.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>()) {
            Some(rustls::Error::AlertReceived(alert)) => json!({"alert": u8::from(*alert)}),
            _ => panic!("unexpected TLS error: {e}"),
        },
        Ok(mut tls) => {
            let state = tls.get_ref().1;
            let value = json!({
                "cipher": format!("{:?}", state.negotiated_cipher_suite().unwrap().suite()),
                "version": format!("{:?}", state.protocol_version().unwrap()),
                "alpn": String::from_utf8_lossy(state.alpn_protocol().unwrap_or_default()),
                "resumed": state.handshake_kind() == Some(rustls::HandshakeKind::Resumed),
            });
            let mut body = vec![];
            tls.read_to_end(&mut body).await.unwrap();
            assert_eq!(body, b"ok\n");
            value
        }
    }
}
async fn native(
    files: &Work,
    _c: &Case,
    aes: bool,
) -> (
    String,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let front = setjoin_tls::Frontend::from_env_with_aes(
        &|key| match key {
            "TLS_CERT" => Some(files.0.join("cert.pem").display().to_string()),
            "TLS_KEY" => Some(files.0.join("key.pem").display().to_string()),
            _ => None,
        },
        aes,
    )
    .unwrap()
    .unwrap();
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = ln.local_addr().unwrap().to_string();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        tokio::pin!(stopped);
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut stopped => break,
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
                accepted = ln.accept() => {
                    let (stream, _) = accepted.unwrap();
                    let f = front.clone();
                    tasks.spawn(async move {
                        if let Ok(mut tls) = f.accept(stream).await {
                            let _ = tls.write_all(b"ok\n").await;
                            let _ = tls.shutdown().await;
                        }
                    });
                }
            }
        }
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    });
    (address, stop, task)
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn negotiations_and_resumption_match_go_policy() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap();
    let work = Work(
        root.join("test-results/gofree-tlsfront")
            .join(format!("policy-{}", std::process::id())),
    );
    std::fs::create_dir_all(work.0.join("cache")).unwrap();
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(root.join("server-rust/tests/conformance/tlsfront/tls13-resumed.json"))
            .unwrap(),
    )
    .unwrap();
    std::fs::write(
        work.0.join("cert.pem"),
        fixture["certificate_pem"].as_str().unwrap(),
    )
    .unwrap();
    std::fs::write(
        work.0.join("key.pem"),
        fixture["public_test_key_pem"].as_str().unwrap(),
    )
    .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_file(work.0.join("cert.pem")).unwrap())
        .unwrap();
    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(roots),
        Arc::new(rustls::crypto::ring::default_provider()),
    )
    .build()
    .unwrap();
    let auth = Arc::new(NoClientCert);
    let mut rows = vec![];
    for aes in [true, false] {
        for c in cases() {
            let (address, stop, task) = native(&work, &c, aes).await;
            let cfg = config(&c, verifier.clone(), auth.clone());
            let observed = vec![connect(&address, cfg).await];
            let _ = stop.send(());
            task.await.unwrap();
            rows.push(json!({"case": c.name, "aes": aes, "observation": observed}));
        }
    }
    let path = root.join("server-rust/tests/conformance/tlsfront/policy.json");
    let golden: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    // Filter out the two cases retired in Release N+1 (#560):
    // - `cold-certificate-alert`: required built-in ACME empty DirCache.
    // - `tls13-same-hash-cipher-resumption`: required the retired `state.rs`
    //   hack mutating pinned `rustls = "=0.23.46"` internal ServerSessionValue
    //   cipher bytes; standard `rustls` compares exact suite IDs on resumption
    //   (verified directly by `tls13_same_suite_resumes_and_cross_suite_falls_back_cleanly`).
    let expected: Vec<Value> = golden["rows"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| {
            !matches!(
                row["case"].as_str(),
                Some("cold-certificate-alert" | "tls13-same-hash-cipher-resumption")
            )
        })
        .cloned()
        .collect();
    assert_eq!(json!(expected), json!(rows));

    // Verify standard rustls in-process Ticketer behavior: same-suite TLS 1.3
    // resumes, while cross-suite (same HKDF hash) falls back cleanly to a full
    // handshake without alert.
    let probe = Case {
        name: "tls13-resumption",
        version: 0x304,
        ciphers: vec![cs::TLS13_AES_128_GCM_SHA256],
        p384: false,
        alpn: "h2",
    };
    let (address, stop, task) = native(&work, &probe, true).await;
    let first_cfg = config(&probe, verifier.clone(), auth.clone());
    let resume = first_cfg.resumption.clone();
    let first = connect(&address, first_cfg).await;
    assert_eq!(first["resumed"], false, "initial handshake: {first}");

    let mut same_cfg = config(&probe, verifier.clone(), auth.clone());
    same_cfg.resumption = resume.clone();
    let second = connect(&address, same_cfg).await;
    assert_eq!(second["resumed"], true, "same-suite resumption: {second}");
    assert_eq!(second["cipher"], "TLS13_AES_128_GCM_SHA256");

    let mut cross = probe.clone();
    cross.ciphers = vec![cs::TLS13_CHACHA20_POLY1305_SHA256];
    let mut cross_cfg = config(&cross, verifier.clone(), auth.clone());
    cross_cfg.resumption = resume;
    let third = connect(&address, cross_cfg).await;
    assert_eq!(
        third["resumed"], false,
        "standard rustls requires exact suite match for resumption: {third}"
    );
    assert_eq!(third["cipher"], "TLS13_CHACHA20_POLY1305_SHA256");

    let _ = stop.send(());
    task.await.unwrap();
}
