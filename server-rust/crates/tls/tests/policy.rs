//! Frozen-Go TLS negotiation policy, including rejection alerts and cipher changes on resumption.
#[path = "../../acme/tests/support/pebble.rs"]
mod pebble;
#[path = "../../../tests/conformance/tlsfront/peer.rs"]
mod peer;
use rustls::{
    crypto::ring::{cipher_suite as cs, kx_group as kx},
    pki_types::{pem::PemObject, CertificateDer, ServerName},
    ClientConfig, SupportedCipherSuite,
};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
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
    cold: bool,
    alpn: &'static str,
    switch: bool,
}
fn cases() -> Vec<Case> {
    let base = |name, version, ciphers| Case {
        name,
        version,
        ciphers,
        p384: false,
        cold: false,
        alpn: "h2",
        switch: false,
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
    let mut cold = base(
        "cold-certificate-alert",
        0x304,
        vec![cs::TLS13_AES_128_GCM_SHA256],
    );
    cold.cold = true;
    cases.push(cold);
    let mut switch = base(
        "tls13-same-hash-cipher-resumption",
        0x304,
        vec![cs::TLS13_AES_128_GCM_SHA256],
    );
    switch.switch = true;
    cases.push(switch);
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
            Some(rustls::Error::AlertReceived(alert)) => json!({"alert":u8::from(*alert)}),
            _ => panic!("unexpected TLS error: {e}"),
        },
        Ok(mut tls) => {
            let state = tls.get_ref().1;
            let value = json!({"cipher":format!("{:?}",state.negotiated_cipher_suite().unwrap().suite()),"version":format!("{:?}",state.protocol_version().unwrap()),"alpn":String::from_utf8_lossy(state.alpn_protocol().unwrap_or_default()),"resumed":state.handshake_kind()==Some(rustls::HandshakeKind::Resumed)});
            let mut body = vec![];
            tls.read_to_end(&mut body).await.unwrap();
            assert_eq!(body, b"ok\n");
            value
        }
    }
}
async fn native(
    files: &Work,
    c: &Case,
    aes: bool,
) -> (
    String,
    tokio::sync::oneshot::Sender<()>,
    tokio::task::JoinHandle<()>,
) {
    let front = setjoin_tls::Frontend::from_env_with_aes(
        &|key| match key {
            "TLS_CERT" if !c.cold => Some(files.0.join("cert.pem").display().to_string()),
            "TLS_KEY" if !c.cold => Some(files.0.join("key.pem").display().to_string()),
            "TLS_AUTOCERT_DOMAINS" if c.cold => Some("localhost".into()),
            "TLS_AUTOCERT_CACHE_DIR" => Some(files.0.join("cache").display().to_string()),
            _ => None,
        },
        aes,
    )
    .unwrap()
    .unwrap();
    front.set_ticket_keys([7; 32], None);
    let ln = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = ln.local_addr().unwrap().to_string();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        tokio::pin!(stopped);
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
             _=&mut stopped=>break,
             Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
             accepted=ln.accept()=>{let (stream,_)=accepted.unwrap();let f=front.clone();tasks.spawn(async move{if let Ok(mut tls)=f.accept(stream).await {let _=tls.write_all(b"ok\n").await;let _=tls.shutdown().await;}});}
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
    let recording = std::env::var_os("GOFREE_RECORD_TLS_POLICY").is_some();
    let _ca = if recording {
        Some(
            pebble::Pebble::start()
                .await
                .expect("recording needs Pebble"),
        )
    } else {
        None
    };
    let mut rows = vec![];
    for aes in [true, false] {
        for c in cases() {
            let mut server = None;
            let mut stop = None;
            let mut native_task = None;
            let address = if recording {
                let ready = work.0.join("ready");
                let _ = std::fs::remove_file(&ready);
                let mut cfg = json!({"Raw":true,"Listen":"127.0.0.1:0","Ready":ready,"Cert":work.0.join("cert.pem"),"Key":work.0.join("key.pem"),"DisableAES":!aes,"Keys":["BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc="]});
                if c.cold {
                    cfg["Cert"] = json!("");
                    cfg["Key"] = json!("");
                    cfg["Domains"] = json!(["localhost"]);
                    cfg["Cache"] = json!(work.0.join("cache"));
                    cfg["Directory"] = json!(pebble::DIRECTORY);
                    cfg["CA"] = json!(pebble::ca_root());
                }
                server = Some(peer::Server::spawn(&root, &cfg, &work.0.join("server.log")));
                let mut address = None;
                for _ in 0..100 {
                    if let Ok(s) = std::fs::read_to_string(&ready) {
                        address = Some(s);
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                address.unwrap_or_else(|| {
                    panic!(
                        "Go server: {}",
                        std::fs::read_to_string(work.0.join("server.log")).unwrap()
                    )
                })
            } else {
                let (a, s, t) = native(&work, &c, aes).await;
                stop = Some(s);
                native_task = Some(t);
                a
            };
            let cfg = config(&c, verifier.clone(), auth.clone());
            let resume = cfg.resumption.clone();
            let mut observed = vec![connect(&address, cfg).await];
            if c.switch {
                let mut next = c.clone();
                next.ciphers = vec![cs::TLS13_CHACHA20_POLY1305_SHA256];
                let mut cfg = config(&next, verifier.clone(), auth.clone());
                cfg.resumption = resume;
                observed.push(connect(&address, cfg).await);
            }
            drop(server);
            if let Some(stop) = stop {
                let _ = stop.send(());
            }
            if let Some(task) = native_task {
                task.await.unwrap();
            }
            rows.push(json!({"case":c.name,"aes":aes,"observation":observed}));
        }
    }
    let path = root.join("server-rust/tests/conformance/tlsfront/policy.json");
    if recording {
        assert!(!path.exists(), "immutable Go recording already exists");
        std::fs::write(path,serde_json::to_vec_pretty(&json!({"format":1,"go_source":std::env::var("GOFREE_GO_SOURCE").unwrap(),"rows":rows})).unwrap()).unwrap();
    } else {
        let golden: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        assert_eq!(golden["rows"], json!(rows));
    }
}
