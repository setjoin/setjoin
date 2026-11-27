//! Serving-only certificate selection backed directly by [`crate::ReloadingPem`].
//!
//! Reads `TLS_CERT` / `TLS_KEY` (falling back to native `TLS_CERT_FILE` /
//! `TLS_KEY_FILE` aliases when neither primary variable is set). Edge-exported
//! PEM renewals take effect automatically on new handshakes and `CertMonitor`
//! checks without restarting `setjoind`.
use rustls::sign::CertifiedKey;
use std::sync::Arc;

#[derive(Debug)]
pub(crate) struct Certificates {
    pair: Arc<crate::ReloadingPem>,
}

impl Certificates {
    pub fn from_env(get: &dyn Fn(&str) -> Option<String>) -> Result<Option<Arc<Self>>, String> {
        let primary_cert = get("TLS_CERT");
        let primary_key = get("TLS_KEY");
        let (cert_file, key_file) = if primary_cert.is_some() || primary_key.is_some() {
            (primary_cert, primary_key)
        } else {
            (get("TLS_CERT_FILE"), get("TLS_KEY_FILE"))
        };
        let cert_file = cert_file.filter(|s| !s.is_empty());
        let key_file = key_file.filter(|s| !s.is_empty());
        match (cert_file, key_file) {
            (None, None) => Ok(None),
            (Some(cert), Some(key)) => {
                let pair = Arc::new(crate::ReloadingPem::load(cert, key)?);
                Ok(Some(Arc::new(Self { pair })))
            }
            _ => Err("TLS_CERT and TLS_KEY must both be set or both empty".into()),
        }
    }

    pub fn current(&self) -> Arc<CertifiedKey> {
        self.pair.current()
    }

    pub fn served_chain(&self) -> Vec<rustls::pki_types::CertificateDer<'static>> {
        self.pair.served_chain()
    }
}

impl rustls::server::ResolvesServerCert for Certificates {
    fn resolve(&self, _hello: rustls::server::ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.current())
    }
}
