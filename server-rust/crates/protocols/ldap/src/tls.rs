//! Production LDAPS TLS configuration (#559): Go's TLS 1.2/1.3 cipher/curve
//! policy backed by [`setjoin_tls::ReloadingPem`] for non-blocking PEM
//! hot-reload.
use std::{path::Path, sync::Arc};
use tokio_rustls::rustls::{
    crypto::{ring, CryptoProvider},
    version::{TLS12, TLS13},
    ServerConfig, SupportedCipherSuite,
};

fn allowed(suite: &SupportedCipherSuite) -> bool {
    use tokio_rustls::rustls::CipherSuite as S;
    matches!(
        suite.suite(),
        S::TLS13_AES_256_GCM_SHA384
            | S::TLS13_AES_128_GCM_SHA256
            | S::TLS13_CHACHA20_POLY1305_SHA256
            | S::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            | S::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            | S::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
            | S::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    )
}

fn provider() -> Arc<CryptoProvider> {
    let mut provider = ring::default_provider();
    provider.cipher_suites.retain(allowed);
    provider.kx_groups.retain(|g| {
        use tokio_rustls::rustls::NamedGroup as G;
        matches!(g.name(), G::X25519 | G::secp256r1)
    });
    Arc::new(provider)
}

/// Load a PEM certificate chain and private key with hot-reload support.
pub fn server_config(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>, String> {
    let resolver = Arc::new(setjoin_tls::ReloadingPem::load(cert, key)?);
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&TLS12, &TLS13])
        .map_err(|e| format!("TLS protocol versions: {e}"))?
        .with_no_client_auth()
        .with_cert_resolver(resolver);
    Ok(Arc::new(config))
}
