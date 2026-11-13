//! Production TLS configuration (#345): the policy of frozen Go's IMAP listeners,
//! `tlsutil.DefaultCipherSuites` / `DefaultCurves` with `MinVersion` TLS 1.2.
//! rustls (ring) supplies the primitives; this module only selects from them.
use std::{path::Path, sync::Arc};
use tokio_rustls::rustls::{
    crypto::{ring, CryptoProvider},
    pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    version::{TLS12, TLS13},
    ServerConfig, SupportedCipherSuite,
};

/// TLS 1.2 suites Go enables (ECDHE with AES-GCM); TLS 1.3 keeps the library's
/// own suites, as Go's `CipherSuites` field never applied to TLS 1.3.
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
    // `DefaultCurves`: X25519 and P-256 only.
    provider.kx_groups.retain(|g| {
        use tokio_rustls::rustls::NamedGroup as G;
        matches!(g.name(), G::X25519 | G::secp256r1)
    });
    Arc::new(provider)
}

/// Load one certificate chain and key into Go's TLS policy. Errors name the
/// failing file but never its content.
pub fn server_config(cert: &Path, key: &Path) -> Result<Arc<ServerConfig>, String> {
    let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert)
        .map_err(|e| format!("TLS certificate {}: {e}", cert.display()))?
        .collect::<Result<_, _>>()
        .map_err(|e| format!("TLS certificate {}: {e}", cert.display()))?;
    if chain.is_empty() {
        return Err(format!(
            "TLS certificate {}: no certificate",
            cert.display()
        ));
    }
    let key =
        PrivateKeyDer::from_pem_file(key).map_err(|e| format!("TLS key {}: {e}", key.display()))?;
    let config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&TLS12, &TLS13])
        .map_err(|e| format!("TLS protocol versions: {e}"))?
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|e| format!("TLS certificate/key pair: {e}"))?;
    Ok(Arc::new(config))
}
