//! Mutual-certificate trust: the per-peer pinned anchor, the one verification
//! routine shared by both directions, and the rustls verifiers that carry it.
//!
//! The dialer knows the peer's anchor up front and verifies the server leaf
//! inside the handshake. The listener cannot know which peer is calling until
//! the hello frame arrives, so it accepts any client certificate at the TLS
//! layer (signatures are still verified) and validates the chain against the
//! allow-list anchor afterwards. Session resumption is disabled everywhere so
//! the anchor check can never be skipped.

use crate::error::FedError;
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use std::sync::Arc;
use tokio_rustls::rustls::{
    self,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{ring as ring_provider, CryptoProvider},
    server::danger::{ClientCertVerified, ClientCertVerifier},
    DigitallySignedStruct, DistinguishedName, SignatureScheme,
};
use webpki::{
    anchor_from_trusted_cert, EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeIdIter,
};
use x509_parser::prelude::*;

/// A peer's pinned trust root (a per-domain CA certificate, DER).
#[derive(Clone, Debug)]
pub struct Anchor {
    pub ca_der: Vec<u8>,
}

impl Anchor {
    /// Go: `pem.Decode` (first block of any type) then `x509.ParseCertificate`.
    pub fn from_pem(pem: &str) -> Result<Anchor, String> {
        let der = first_pem_block(pem).ok_or("no PEM block found")?;
        X509Certificate::from_der(&der)
            .map_err(|e| format!("x509: {e}"))
            .and_then(|(rest, _)| {
                if rest.is_empty() {
                    Ok(())
                } else {
                    Err("x509: trailing data after certificate".to_string())
                }
            })?;
        Ok(Anchor { ca_der: der })
    }
}

fn first_pem_block(pem: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let mut pos = 0;
    while let Some(off) = pem[pos..].find("-----BEGIN ") {
        let start = pos + off;
        let line_end = pem[start..].find('\n').map(|i| start + i + 1)?;
        let header = pem[start + 11..line_end].trim_end();
        if !header.ends_with("-----") {
            pos = start + 11;
            continue;
        }
        let end_marker = format!("-----END {}", &header[..header.len() - 5]);
        let end = pem[line_end..].find(&end_marker).map(|i| line_end + i)?;
        let mut body = String::new();
        for line in pem[line_end..end].lines() {
            if line.contains(':') {
                continue; // RFC 1421 header
            }
            body.extend(line.chars().filter(|c| !c.is_whitespace()));
        }
        if let Ok(d) = base64::engine::general_purpose::STANDARD.decode(body) {
            return Some(d);
        }
        pos = end;
    }
    None
}

/// Go's `x509.ExtKeyUsageAny`: any (or no) extended key usage is acceptable.
struct AnyUsage;
impl ExtendedKeyUsageValidator for AnyUsage {
    fn validate(&self, _iter: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        Ok(())
    }
}

fn dns_names(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for n in &san.value.general_names {
            if let GeneralName::DNSName(d) = n {
                out.push((*d).to_string());
            }
        }
    }
    out
}

/// The single anchor-validation routine: the presented chain must verify to
/// `anchor` and, when `expect_domain` is non-empty, the leaf's DNS SANs must
/// include it (exact match). Returns the leaf's DNS SANs.
pub fn verify_against_anchor(
    raw: &[&[u8]],
    anchor: &Anchor,
    expect_domain: &str,
) -> Result<Vec<String>, FedError> {
    if raw.is_empty() {
        return Err(FedError::Other(
            "federation: peer presented no certificate".into(),
        ));
    }
    let (_, leaf) = X509Certificate::from_der(raw[0])
        .map_err(|e| FedError::Other(format!("federation: parse presented certificate: {e}")))?;
    let mismatch = |why: String| {
        FedError::AnchorMismatch(format!(
            "federation: peer certificate does not chain to the pinned trust anchor: {why}"
        ))
    };
    // Go also validates the root's own validity window.
    let (_, ca) = X509Certificate::from_der(&anchor.ca_der)
        .map_err(|e| mismatch(format!("anchor unparseable: {e}")))?;
    if !ca.validity().is_valid() {
        return Err(mismatch(
            "x509: certificate has expired or is not yet valid".into(),
        ));
    }
    let ee_der = CertificateDer::from(raw[0]);
    let ee = EndEntityCert::try_from(&ee_der).map_err(|e| mismatch(format!("{e:?}")))?;
    let inter: Vec<CertificateDer<'_>> =
        raw[1..].iter().map(|r| CertificateDer::from(*r)).collect();
    let ca_der = CertificateDer::from(anchor.ca_der.as_slice());
    let ta = anchor_from_trusted_cert(&ca_der).map_err(|e| mismatch(format!("{e:?}")))?;
    let algs = ring_provider::default_provider()
        .signature_verification_algorithms
        .all;
    ee.verify_for_usage(
        algs,
        std::slice::from_ref(&ta),
        &inter,
        UnixTime::now(),
        AnyUsage,
        None,
        None,
    )
    .map_err(|e| mismatch(format!("{e:?}")))?;
    let names = dns_names(&leaf);
    if !expect_domain.is_empty() && !names.iter().any(|n| n == expect_domain) {
        return Err(FedError::DomainMismatch(format!(
            "federation: peer domain does not match the asserted/expected identity: leaf SAN does not include {expect_domain}"
        )));
    }
    Ok(names)
}

pub fn provider() -> Arc<CryptoProvider> {
    Arc::new(ring_provider::default_provider())
}

/// Dial side: verifies the server leaf against the peer's pinned anchor.
#[derive(Debug)]
pub struct AnchorServerVerifier {
    anchor: Anchor,
    expect_domain: String,
    provider: Arc<CryptoProvider>,
}

impl AnchorServerVerifier {
    pub fn new(anchor: Anchor, expect_domain: &str) -> Self {
        Self {
            anchor,
            expect_domain: expect_domain.to_string(),
            provider: provider(),
        }
    }
}

impl ServerCertVerifier for AnchorServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let mut raw: Vec<&[u8]> = vec![end_entity.as_ref()];
        raw.extend(intermediates.iter().map(|c| c.as_ref()));
        match verify_against_anchor(&raw, &self.anchor, &self.expect_domain) {
            Ok(_) => Ok(ServerCertVerified::assertion()),
            Err(e) => Err(rustls::Error::General(e.to_wire_tag())),
        }
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            m,
            c,
            d,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Listen side: any client certificate completes TLS (like Go's
/// `RequireAnyClientCert`); the handshake signature is still verified so the
/// caller really holds the key, and the anchor check runs after hello.
#[derive(Debug)]
pub struct AnyClientCert {
    provider: Arc<CryptoProvider>,
}
impl AnyClientCert {
    pub fn new() -> Self {
        Self {
            provider: provider(),
        }
    }
}
impl Default for AnyClientCert {
    fn default() -> Self {
        Self::new()
    }
}
impl ClientCertVerifier for AnyClientCert {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        _e: &CertificateDer<'_>,
        _i: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            m,
            c,
            d,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A leaf certificate chain and its private key (PEM files, like Go's
/// `tls.LoadX509KeyPair`).
#[derive(Clone)]
pub struct Identity {
    pub chain: Vec<CertificateDer<'static>>,
    pub key: Arc<rustls_pki_types::PrivateKeyDer<'static>>,
}

impl Identity {
    pub fn load(cert_path: &str, key_path: &str) -> Result<Identity, String> {
        use rustls_pki_types::{pem::PemObject, PrivateKeyDer};
        let chain: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(cert_path)
            .map_err(|e| format!("{cert_path}: {e}"))?
            .collect::<Result<_, _>>()
            .map_err(|e| format!("{cert_path}: {e}"))?;
        if chain.is_empty() {
            return Err(format!("{cert_path}: no certificate found"));
        }
        let key = PrivateKeyDer::from_pem_file(key_path).map_err(|e| format!("{key_path}: {e}"))?;
        Ok(Identity {
            chain,
            key: Arc::new(key),
        })
    }
    fn key(&self) -> rustls_pki_types::PrivateKeyDer<'static> {
        self.key.clone_key()
    }

    /// TLS 1.3 server configuration: any client certificate, no tickets.
    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>, String> {
        let mut cfg = rustls::ServerConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| e.to_string())?
            .with_client_cert_verifier(Arc::new(AnyClientCert::new()))
            .with_single_cert(self.chain.clone(), self.key())
            .map_err(|e| e.to_string())?;
        cfg.send_tls13_tickets = 0;
        cfg.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        Ok(Arc::new(cfg))
    }

    /// TLS 1.3 client configuration pinned to `anchor` for `expect_domain`.
    pub fn client_config(
        &self,
        anchor: Anchor,
        expect_domain: &str,
    ) -> Result<Arc<rustls::ClientConfig>, String> {
        let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| e.to_string())?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AnchorServerVerifier::new(
                anchor,
                expect_domain,
            )))
            .with_client_auth_cert(self.chain.clone(), self.key())
            .map_err(|e| e.to_string())?;
        cfg.resumption = rustls::client::Resumption::disabled();
        Ok(Arc::new(cfg))
    }
}
