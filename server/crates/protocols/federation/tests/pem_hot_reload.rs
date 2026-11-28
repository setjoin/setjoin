//! Live Federation mTLS PEM hot-reload test (#559):
//! verifies an active `PeerStream` survives atomic PEM rotation AND both new
//! inbound (server) and outbound (client) mTLS handshakes present the rotated
//! leaf certificate.
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};
use setjoin_federation::{
    db::{BoxFut, FedDb},
    flags::Flags,
    stream::{accept_stream, dial, AnchorLookup, Bounds, PeerEndpoint},
    trust::{Anchor, Identity},
    wire::{Frame, Hello, KIND_ACK},
};
use setjoin_pg::{Param, Row};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "setjoin-fed-hot-reload-{tag}-{}-{}",
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

struct AlwaysOn;
impl Flags for AlwaysOn {
    fn federation_enabled(&self) -> bool {
        true
    }
}

struct AllowPeerDb;
impl FedDb for AllowPeerDb {
    fn query<'a>(
        &'a self,
        _sql: &'a str,
        _params: &'a [Param<'a>],
    ) -> BoxFut<'a, Result<Vec<Row>, String>> {
        Box::pin(async { Ok(Vec::new()) })
    }
}

fn gen_ca(name: &str) -> (rcgen::Certificate, CertificateParams, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(DnType::CommonName, name);
    params.not_after = rcgen::date_time_ymd(2037, 1, 1);
    let cert = params.self_signed(&key).unwrap();
    (cert, params, key)
}

fn gen_leaf(
    ca_params: &CertificateParams,
    ca_key: &KeyPair,
    domain: &str,
    cn: &str,
) -> (String, String, Vec<u8>) {
    let issuer = Issuer::from_params(ca_params, ca_key);
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![domain.into()]).unwrap();
    params.distinguished_name.push(DnType::CommonName, cn);
    params.not_after = rcgen::date_time_ymd(2037, 1, 1);
    let cert = params.signed_by(&key, &issuer).unwrap();
    (cert.pem(), key.serialize_pem(), cert.der().to_vec())
}

fn atomic_write(path: &Path, data: &str) {
    let tmp = path.with_extension("new");
    std::fs::write(&tmp, data).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

#[tokio::test]
async fn federation_active_peer_stream_survives_and_new_inbound_outbound_mtls_rotate() {
    let dir = TempDir::new("mtls");
    let (ca_alpha, ca_alpha_params, ca_alpha_key) = gen_ca("Alpha Test CA");
    let (ca_beta, ca_beta_params, ca_beta_key) = gen_ca("Beta Test CA");

    let alpha_anchor = Anchor::from_pem(&ca_alpha.pem()).unwrap();
    let beta_anchor = Anchor::from_pem(&ca_beta.pem()).unwrap();

    let (alpha_c1, alpha_k1, alpha_der1) =
        gen_leaf(&ca_alpha_params, &ca_alpha_key, "alpha.test", "alpha-gen1");
    let (beta_c1, beta_k1, beta_der1) =
        gen_leaf(&ca_beta_params, &ca_beta_key, "beta.test", "beta-gen1");

    let alpha_cert_path = dir.0.join("alpha.crt");
    let alpha_key_path = dir.0.join("alpha.key");
    let beta_cert_path = dir.0.join("beta.crt");
    let beta_key_path = dir.0.join("beta.key");
    std::fs::write(&alpha_cert_path, &alpha_c1).unwrap();
    std::fs::write(&alpha_key_path, &alpha_k1).unwrap();
    std::fs::write(&beta_cert_path, &beta_c1).unwrap();
    std::fs::write(&beta_key_path, &beta_k1).unwrap();

    let alpha_id = Identity::load(
        alpha_cert_path.to_str().unwrap(),
        alpha_key_path.to_str().unwrap(),
    )
    .unwrap();
    let beta_id = Identity::load(
        beta_cert_path.to_str().unwrap(),
        beta_key_path.to_str().unwrap(),
    )
    .unwrap();
    assert_eq!(alpha_id.served_chain()[0].as_ref(), alpha_der1.as_slice());
    assert_eq!(beta_id.served_chain()[0].as_ref(), beta_der1.as_slice());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let beta_server_cfg = beta_id.server_config().unwrap();

    // 1. Establish active PeerStream (alpha dials beta).
    let ctx = CancellationToken::new();
    let accept_cfg = beta_server_cfg.clone();
    let lookup: AnchorLookup = Arc::new(move |domain: String| {
        let anchor = alpha_anchor.clone();
        Box::pin(async move {
            assert_eq!(domain, "alpha.test");
            Ok(Some(anchor))
        })
    });
    let first_accept = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let stream = accept_stream(
            tcp,
            accept_cfg,
            &lookup,
            &Hello::new("beta.test"),
            &AllowPeerDb,
            "dm",
            &Bounds::default(),
        )
        .await
        .unwrap();
        (listener, stream)
    });

    let endpoint = PeerEndpoint {
        domain: "beta.test".into(),
        target: "127.0.0.1".into(),
        port: addr.port(),
    };
    let active_client = dial(
        &ctx,
        &AlwaysOn,
        &endpoint,
        &alpha_id,
        beta_anchor.clone(),
        &Hello::new("alpha.test"),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    let (listener, active_server) = first_accept.await.unwrap();

    // 2. Atomically rotate BOTH alpha (outbound client) and beta (inbound server) PEM pairs.
    let (alpha_c2, alpha_k2, alpha_der2) =
        gen_leaf(&ca_alpha_params, &ca_alpha_key, "alpha.test", "alpha-gen2");
    let (beta_c2, beta_k2, beta_der2) =
        gen_leaf(&ca_beta_params, &ca_beta_key, "beta.test", "beta-gen2");
    atomic_write(&alpha_key_path, &alpha_k2);
    atomic_write(&alpha_cert_path, &alpha_c2);
    atomic_write(&beta_key_path, &beta_k2);
    atomic_write(&beta_cert_path, &beta_c2);
    tokio::time::sleep(Duration::from_millis(1100)).await;

    assert_eq!(alpha_id.served_chain()[0].as_ref(), alpha_der2.as_slice());
    assert_eq!(beta_id.served_chain()[0].as_ref(), beta_der2.as_slice());

    // 3. Pre-rotation PeerStream still exchanges frames cleanly.
    let ping = Frame::new(KIND_ACK, "s1", Some(br#"{"peerSeq":42}"#.to_vec()));
    active_client.write_frame(&ping).await.unwrap();
    let got = active_server.read_frame().await.unwrap();
    assert_eq!(got.kind, KIND_ACK);
    assert_eq!(got.stanza_id, "s1");

    // 4. Verify new mTLS handshake uses rotated server AND client leaf certs.
    let (server_peer_tx, server_peer_rx) = tokio::sync::oneshot::channel();
    let accept_cfg2 = beta_server_cfg.clone();
    let raw_accept = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let tls = tokio_rustls::TlsAcceptor::from(accept_cfg2)
            .accept(tcp)
            .await
            .unwrap();
        let client_leaf = tls.get_ref().1.peer_certificates().unwrap()[0].to_vec();
        let _ = server_peer_tx.send(client_leaf);
        tls
    });

    let client_cfg2 = alpha_id.client_config(beta_anchor, "beta.test").unwrap();
    let tcp2 = tokio::net::TcpStream::connect(addr).await.unwrap();
    let client_tls2 = tokio_rustls::TlsConnector::from(client_cfg2)
        .connect(
            rustls_pki_types::ServerName::try_from("beta.test").unwrap(),
            tcp2,
        )
        .await
        .unwrap();
    let observed_server_leaf = client_tls2.get_ref().1.peer_certificates().unwrap()[0].to_vec();
    let _server_tls2 = raw_accept.await.unwrap();
    let observed_client_leaf = server_peer_rx.await.unwrap();

    assert_eq!(
        observed_server_leaf, beta_der2,
        "inbound federation TLS must present rotated server leaf"
    );
    assert_eq!(
        observed_client_leaf, alpha_der2,
        "outbound federation mTLS must present rotated client leaf"
    );
}
