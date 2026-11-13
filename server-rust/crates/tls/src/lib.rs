//! Serving-only TLS plumbing for the Go-free front door (#413).
mod certificates;
mod policy;
mod state;
pub use policy::aes_gcm_hardware;
mod tickets;
use rustls::pki_types::pem::PemObject;
use std::{io, sync::Arc};
use tokio::net::TcpStream;

/// Leaf of this connection's TLS peer chain, carried in HTTP request extensions.
/// Forwarded headers never populate this transport metadata.
#[derive(Clone)]
pub struct PeerCertificate(pub rustls::pki_types::CertificateDer<'static>);

pub struct Frontend {
    config: Arc<rustls::ServerConfig>,
    chacha: Arc<rustls::ServerConfig>,
    aes_gcm: bool,
    alpn: setjoin_acme::TlsAlpnStore,
    certificates: Arc<certificates::Certificates>,
    tickets: Arc<tickets::Tickets>,
}

impl Frontend {
    /// Go's configured managed domains and static pair; serving never registers or issues.
    pub fn from_env(get: &dyn Fn(&str) -> Option<String>) -> Result<Option<Arc<Self>>, String> {
        Self::from_env_with_aes(get, aes_gcm_hardware())
    }

    /// Inject host capabilities for architecture qualification; this changes only
    /// cipher ordering, never the permitted protocol/cipher/curve set.
    pub fn from_env_with_aes(
        get: &dyn Fn(&str) -> Option<String>,
        aes_gcm: bool,
    ) -> Result<Option<Arc<Self>>, String> {
        Self::configured(get, aes_gcm, rustls::server::WebPkiClientVerifier::no_client_auth())
    }

    /// Install the gateway's audited optional client verifier. The gateway owns
    /// loading the configured CA pool; this transport never reads the database.
    pub fn from_env_with_client_verifier(
        get: &dyn Fn(&str) -> Option<String>,
        verifier: Arc<dyn rustls::server::danger::ClientCertVerifier>,
    ) -> Result<Option<Arc<Self>>, String> {
        Self::configured(get, aes_gcm_hardware(), verifier)
    }

    fn configured(
        get: &dyn Fn(&str) -> Option<String>,
        aes_gcm: bool,
        verifier: Arc<dyn rustls::server::danger::ClientCertVerifier>,
    ) -> Result<Option<Arc<Self>>, String> {
        let Some(certificates) = certificates::Certificates::from_env(get)? else {
            return Ok(None);
        };
        let tickets = Arc::new(tickets::Tickets::new()?);
        let build = |prefer_chacha| -> Result<Arc<rustls::ServerConfig>, String> {
            let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
                policy::provider(prefer_chacha),
            ))
            .with_safe_default_protocol_versions()
            .map_err(|e| e.to_string())?
            .with_client_cert_verifier(verifier.clone())
            .with_cert_resolver(certificates.clone());
            config.ignore_client_order = true;
            config.send_tls13_tickets = 1;
            config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            config.ticketer = tickets.for_name(None);
            Ok(Arc::new(config))
        };
        let config = build(false)?;
        let chacha = build(true)?;
        Ok(Some(Arc::new(Self {
            alpn: setjoin_acme::TlsAlpnStore::default(),
            tickets,
            certificates,
            config,
            chacha,
            aes_gcm,
        })))
    }

    /// The first usable configured SNI's served chain, exactly the source Go
    /// probes for certificate monitoring. No synthetic handshake triggers issuance.
    pub fn served_chain(&self) -> Vec<rustls::pki_types::CertificateDer<'static>> {
        if self.certificates.domains.is_empty() {
            return self
                .certificates
                .select("")
                .map(|pair| pair.cert.clone())
                .unwrap_or_default();
        }
        for name in &self.certificates.domains {
            if let Some(pair) = self.certificates.select(name) {
                return pair.cert.clone();
            }
        }
        Vec::new()
    }

    /// Publish the current and at most one previous persisted Go ticket key.
    pub fn set_ticket_keys(&self, current: [u8; 32], previous: Option<[u8; 32]>) {
        self.tickets.set(current, previous);
    }

    /// Shared only with the renewal worker; normal handshakes never issue or publish.
    pub fn tls_alpn_store(&self) -> setjoin_acme::TlsAlpnStore {
        self.alpn.clone()
    }

    pub async fn accept(
        &self,
        stream: TcpStream,
    ) -> io::Result<tokio_rustls::server::TlsStream<TcpStream>> {
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let mut hello =
                tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)
                    .await?;
            let client = hello.client_hello();
            if client
                .alpn()
                .is_some_and(|mut p| p.any(|p| p == b"acme-tls/1"))
            {
                if let Some(blob) = self.alpn.get(client.server_name().unwrap_or_default()) {
                    // The worker generated this pair together. WebPKI's application
                    // certificate parser deliberately rejects RFC 8737's unknown critical
                    // extension, so do not run its ordinary-certificate validation here.
                    use rustls::{
                        pki_types::{CertificateDer, PrivateKeyDer},
                        sign::{CertifiedKey, SingleCertAndKey},
                    };
                    let provider = rustls::crypto::ring::default_provider();
                    let certs = CertificateDer::pem_slice_iter(&blob)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(io::Error::other)?;
                    let key = provider
                        .key_provider
                        .load_private_key(
                            PrivateKeyDer::from_pem_slice(&blob).map_err(io::Error::other)?,
                        )
                        .map_err(io::Error::other)?;
                    let pair = CertifiedKey::new(certs, key);
                    let mut challenge =
                        rustls::ServerConfig::builder_with_provider(Arc::new(provider))
                            .with_safe_default_protocol_versions()
                            .map_err(io::Error::other)?
                            .with_no_client_auth()
                            .with_cert_resolver(Arc::new(SingleCertAndKey::from(pair)));
                    challenge.alpn_protocols = vec![b"acme-tls/1".to_vec()];
                    challenge.send_tls13_tickets = 0;
                    return hello.into_stream(Arc::new(challenge)).await;
                }
            }
            let client = hello.client_hello();
            let prefer_chacha =
                !self.aes_gcm || !policy::client_prefers_aes(client.cipher_suites());
            let mut config = if prefer_chacha {
                (*self.chacha).clone()
            } else {
                (*self.config).clone()
            };
            if let Some(pair) = self
                .certificates
                .select(client.server_name().unwrap_or_default())
            {
                // Select once per handshake, matching Go's GetCertificate/cache read.
                config.cert_resolver = Arc::new(rustls::sign::SingleCertAndKey::from(pair));
            } else {
                // Go's no-certificate result sends unrecognized_name. This is a
                // plaintext TLS fatal alert before any record keys exist.
                use tokio::io::AsyncWriteExt;
                hello.io.write_all(&[21, 3, 3, 0, 2, 2, 112]).await?;
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no TLS certificate for SNI",
                ));
            }
            let cipher = config
                .crypto_provider()
                .cipher_suites
                .iter()
                .find(|s| s.tls13().is_some() && client.cipher_suites().contains(&s.suite()))
                .map(|s| u16::from(s.suite()));
            config.ticketer = self.tickets.for_context(client.server_name(), cipher);
            hello.into_stream(Arc::new(config)).await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timeout"))?
    }
}
