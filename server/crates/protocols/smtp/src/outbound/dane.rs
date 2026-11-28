//! DANE certificate decisions made inside the TLS handshake (RFC 6698/7671/7672).
//!
//! Owner-approved security fixes 2026-11-05 (#500). Frozen Go validated PKIX
//! first and scanned TLSA records afterwards, so DANE-EE could never skip PKIX,
//! usage 0/2 matched *any* certificate the peer chose to present (no chain linkage),
//! and a TLS session was labelled DANE-validated whenever the feature was on, even
//! when no record had matched. Here a verifier decides before any application byte:
//! - usage 3 (DANE-EE): the leaf matches; PKIX, name and validity are skipped;
//! - usage 2 (DANE-TA): a *presented non-leaf* certificate matches and the leaf
//!   verifies (signatures, validity, server name) with that certificate as the only
//!   trust anchor;
//! - usage 0 (PKIX-TA): the ordinary PKIX verification passes AND the leaf also
//!   verifies with the matching presented or trusted CA as the only anchor, so the
//!   TLSA-pinned CA is in the validated chain;
//! - usage 1 (PKIX-EE): PKIX passes and the leaf matches.
//!
//! A session counts as DANE-validated only after one of these succeeded.
use super::transport::TlsaRecord;
use sha2::{Digest, Sha256, Sha512};
use std::sync::{Arc, Mutex};
use subtle::ConstantTimeEq;
use tokio_rustls::rustls::{
    client::{
        danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        WebPkiServerVerifier,
    },
    crypto::{ring, verify_tls12_signature, verify_tls13_signature, CryptoProvider},
    pki_types::{CertificateDer, ServerName, UnixTime},
    CertificateError, DigitallySignedStruct, Error, RootCertStore, SignatureScheme,
};

/// Trust anchors used for ordinary PKIX verification.
pub struct Trust {
    anchors: Vec<CertificateDer<'static>>,
    provider: Arc<CryptoProvider>,
    /// `None` when no anchor parsed: every PKIX verification then fails closed.
    pkix: Option<Arc<WebPkiServerVerifier>>,
}
impl Trust {
    pub fn new(anchors: Vec<CertificateDer<'static>>) -> Self {
        let provider = Arc::new(ring::default_provider());
        let mut roots = RootCertStore::empty();
        for certificate in &anchors {
            let _ = roots.add(certificate.clone());
        }
        let pkix = WebPkiServerVerifier::builder_with_provider(Arc::new(roots), provider.clone())
            .build()
            .ok();
        Self {
            anchors,
            provider,
            pkix,
        }
    }
    pub fn system() -> Self {
        Self::new(rustls_native_certs::load_native_certs().certs)
    }
    fn pkix(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        now: UnixTime,
    ) -> Result<(), Error> {
        match &self.pkix {
            Some(verifier) => verifier
                .verify_server_cert(end_entity, intermediates, name, &[], now)
                .map(|_| ()),
            None => Err(Error::InvalidCertificate(CertificateError::UnknownIssuer)),
        }
    }
}

/// The usable TLSA records of one authenticated answer.
pub struct Policy {
    records: Vec<TlsaRecord>,
}
impl Policy {
    pub fn new(records: Vec<TlsaRecord>) -> Self {
        Self {
            records: records
                .into_iter()
                .filter(|r| {
                    r.usage <= 3 && r.selector <= 1 && r.matching <= 2 && !r.association.is_empty()
                })
                .collect(),
        }
    }
    pub fn usable(&self) -> bool {
        !self.records.is_empty()
    }
}

fn associates(record: &TlsaRecord, certificate: &[u8]) -> bool {
    let Ok((_, parsed)) = x509_parser::parse_x509_certificate(certificate) else {
        return false;
    };
    let data = if record.selector == 0 {
        certificate
    } else {
        parsed.tbs_certificate.subject_pki.raw
    };
    let expected = match record.matching {
        0 => data.to_vec(),
        1 => Sha256::digest(data).to_vec(),
        _ => Sha512::digest(data).to_vec(),
    };
    bool::from(expected.as_slice().ct_eq(&record.association))
}

impl Trust {
    /// Verify `chain` (leaf first) against `policy`. `Ok(true)` means a TLSA
    /// record matched with the chain linkage its usage requires; `Ok(false)` means
    /// the policy has no usable record (plain PKIX applied); `Err` rejects.
    pub fn verify(
        &self,
        policy: Option<&Policy>,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        now: UnixTime,
    ) -> Result<bool, Error> {
        let pkix = || self.pkix(end_entity, intermediates, name, now);
        let Some(policy) = policy.filter(|p| p.usable()) else {
            pkix()?;
            return Ok(false);
        };
        let mismatch =
            || Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure);
        let mut pkix_result = None;
        for record in &policy.records {
            let linked = |candidate: &CertificateDer<'_>| -> bool {
                let mut roots = RootCertStore::empty();
                if roots.add(candidate.clone().into_owned()).is_err() {
                    return false;
                }
                WebPkiServerVerifier::builder_with_provider(Arc::new(roots), self.provider.clone())
                    .build()
                    .is_ok_and(|v| {
                        v.verify_server_cert(end_entity, intermediates, name, &[], now)
                            .is_ok()
                    })
            };
            let accepted = match record.usage {
                3 => {
                    if crate::mutants::on("dane-ee-requires-pkix") {
                        // Frozen Go: PKIX (including the name) always ran first.
                        pkix().is_ok() && associates(record, end_entity)
                    } else {
                        associates(record, end_entity)
                    }
                }
                1 => {
                    let ok = *pkix_result.get_or_insert_with(|| pkix().is_ok());
                    ok && associates(record, end_entity)
                }
                2 => {
                    if crate::mutants::on("dane-ca-without-linkage") {
                        // Frozen Go: any presented certificate (even the leaf) matched.
                        std::iter::once(end_entity)
                            .chain(intermediates)
                            .any(|c| associates(record, c))
                    } else {
                        intermediates
                            .iter()
                            .filter(|c| associates(record, c))
                            .any(linked)
                    }
                }
                _ => {
                    if crate::mutants::on("dane-ca-without-linkage") {
                        std::iter::once(end_entity)
                            .chain(intermediates)
                            .any(|c| associates(record, c))
                    } else {
                        let ok = *pkix_result.get_or_insert_with(|| pkix().is_ok());
                        ok && intermediates
                            .iter()
                            .chain(self.anchors.iter())
                            .filter(|c| associates(record, c))
                            .any(linked)
                    }
                }
            };
            if accepted {
                return Ok(true);
            }
        }
        Err(mismatch())
    }
}

/// What a handshake concluded about DANE, shared with the session.
#[derive(Default)]
pub struct Outcome {
    pub matched: bool,
    pub mismatch: bool,
    pub chain: Vec<CertificateDer<'static>>,
}
pub struct Verifier {
    pub trust: Arc<Trust>,
    pub policy: Option<Arc<Policy>>,
    pub outcome: Arc<Mutex<Outcome>>,
}
impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DaneVerifier")
    }
}
impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, Error> {
        let result = self.trust.verify(
            self.policy.as_deref(),
            end_entity,
            intermediates,
            server_name,
            now,
        );
        let mut outcome = self.outcome.lock().expect("dane outcome");
        match result {
            Ok(matched) => {
                outcome.matched = matched;
                outcome.chain = std::iter::once(end_entity)
                    .chain(intermediates)
                    .map(|c| c.clone().into_owned())
                    .collect();
                Ok(ServerCertVerified::assertion())
            }
            Err(error) => {
                outcome.mismatch = self.policy.as_ref().is_some_and(|p| p.usable())
                    && matches!(
                        error,
                        Error::InvalidCertificate(CertificateError::ApplicationVerificationFailure)
                    );
                Err(error)
            }
        }
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.trust.provider.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.trust.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.trust
            .provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}
