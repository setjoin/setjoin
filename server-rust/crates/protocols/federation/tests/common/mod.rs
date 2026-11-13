//! Shared fixtures: fixture identities, a scripted TLS peer and database access.
#![allow(dead_code)]
use setjoin_federation::trust::{provider, Identity};
use std::{path::PathBuf, sync::Arc};
use tokio_rustls::rustls::{
    self,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, SignatureScheme,
};

pub fn oracle_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("oracle")
}

pub fn identity(name: &str) -> Identity {
    let d = oracle_dir().join("certs");
    Identity::load(
        d.join(format!("{name}.crt")).to_str().unwrap(),
        d.join(format!("{name}.key")).to_str().unwrap(),
    )
    .unwrap()
}

pub fn ca_pem(name: &str) -> String {
    std::fs::read_to_string(oracle_dir().join("certs").join(format!("ca-{name}.crt"))).unwrap()
}

/// Accepts any server certificate (the scripted peer only needs the wire).
#[derive(Debug)]
pub struct AcceptAny;
impl ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _e: &CertificateDer<'_>,
        _i: &[CertificateDer<'_>],
        _n: &ServerName<'_>,
        _o: &[u8],
        _t: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _m: &[u8],
        _c: &CertificateDer<'_>,
        _d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
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
            &provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

pub fn client_config(id: &Identity) -> Arc<rustls::ClientConfig> {
    let mut cfg = rustls::ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAny))
        .with_client_auth_cert(id.chain.clone(), id.key.clone_key())
        .unwrap();
    cfg.resumption = rustls::client::Resumption::disabled();
    Arc::new(cfg)
}

pub fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}
