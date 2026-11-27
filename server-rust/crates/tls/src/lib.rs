//! Slim pure-`rustls` TLS transport for Setjoin listeners (#413, #559, #560).
//!
//! Dedicated to atomic PEM hot-reloading ([`ReloadingPem`]), direct HTTPS
//! termination with optional mTLS [`PeerCertificate`] extraction ([`Frontend`]),
//! and rustls-native session resumption (built-in ring `Ticketer`).
mod certificates;
mod policy;
mod reloading_pem;

pub use policy::aes_gcm_hardware;
pub use reloading_pem::{ReloadingPem, DEFAULT_CHECK_INTERVAL, DEFAULT_FAILURE_COOLDOWN};

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
    certificates: Arc<certificates::Certificates>,
}

impl Frontend {
    /// Load static hot-reloading PEM pair from `TLS_CERT`/`TLS_KEY` (or
    /// `TLS_CERT_FILE`/`TLS_KEY_FILE`); returns `Ok(None)` when neither is set.
    pub fn from_env(get: &dyn Fn(&str) -> Option<String>) -> Result<Option<Arc<Self>>, String> {
        Self::from_env_with_aes(get, aes_gcm_hardware())
    }

    /// Inject host AES-GCM capability for architecture qualification; this
    /// changes only TLS 1.3 cipher ordering, never the permitted protocol/curve set.
    pub fn from_env_with_aes(
        get: &dyn Fn(&str) -> Option<String>,
        aes_gcm: bool,
    ) -> Result<Option<Arc<Self>>, String> {
        Self::configured(
            get,
            aes_gcm,
            rustls::server::WebPkiClientVerifier::no_client_auth(),
        )
    }

    /// Install the gateway's optional client certificate verifier for HTTP mTLS.
    /// The caller owns loading the CA pool; this transport never reads the database.
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
        let ticketer = rustls::crypto::ring::Ticketer::new().map_err(|e| e.to_string())?;
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
            config.ticketer = ticketer.clone();
            Ok(Arc::new(config))
        };
        let config = build(false)?;
        let chacha = build(true)?;
        Ok(Some(Arc::new(Self {
            certificates,
            config,
            chacha,
            aes_gcm,
        })))
    }

    /// Currently served certificate chain (live view through `ReloadingPem`),
    /// consumed by `CertMonitor`.
    pub fn served_chain(&self) -> Vec<rustls::pki_types::CertificateDer<'static>> {
        self.certificates.served_chain()
    }

    pub async fn accept(
        &self,
        stream: TcpStream,
    ) -> io::Result<tokio_rustls::server::TlsStream<TcpStream>> {
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let hello =
                tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)
                    .await?;
            let client = hello.client_hello();
            let prefer_chacha =
                !self.aes_gcm || !policy::client_prefers_aes(client.cipher_suites());
            let config = if prefer_chacha {
                self.chacha.clone()
            } else {
                self.config.clone()
            };
            hello.into_stream(config).await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timeout"))?
    }
}
