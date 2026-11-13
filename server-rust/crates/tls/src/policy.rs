//! Frozen tlsutil's TLS 1.2 suite/curve floor and crypto/tls' TLS 1.3 ordering.
use rustls::{
    crypto::{
        ring::{cipher_suite as cs, kx_group as kx},
        CryptoProvider,
    },
    CipherSuite,
};
/// Go's AES-GCM hardware predicate for the three release architectures.
pub fn aes_gcm_hardware() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::is_x86_feature_detected!("aes") && std::is_x86_feature_detected!("pclmulqdq")
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes")
            && std::arch::is_aarch64_feature_detected!("pmull")
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}
pub(crate) fn provider(chacha: bool) -> CryptoProvider {
    let mut provider = rustls::crypto::ring::default_provider();
    provider.kx_groups = vec![kx::X25519, kx::SECP256R1];
    provider.cipher_suites = if chacha {
        vec![
            cs::TLS13_CHACHA20_POLY1305_SHA256,
            cs::TLS13_AES_128_GCM_SHA256,
            cs::TLS13_AES_256_GCM_SHA384,
        ]
    } else {
        vec![
            cs::TLS13_AES_128_GCM_SHA256,
            cs::TLS13_AES_256_GCM_SHA384,
            cs::TLS13_CHACHA20_POLY1305_SHA256,
        ]
    };
    provider.cipher_suites.extend([
        cs::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        cs::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        cs::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        cs::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    ]);
    provider
}
pub(crate) fn client_prefers_aes(ciphers: &[CipherSuite]) -> bool {
    use CipherSuite::*;
    for cipher in ciphers {
        match cipher {
            TLS13_AES_128_GCM_SHA256
            | TLS13_AES_256_GCM_SHA384
            | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => return true,
            TLS13_CHACHA20_POLY1305_SHA256
            | TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            | TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => return false,
            _ => {}
        }
    }
    false
}
