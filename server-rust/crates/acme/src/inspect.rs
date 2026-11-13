//! Read-only view of a cache blob (key PEM, then the certificate chain), used by the oracle and
//! by anything that needs a certificate's SANs or expiry without loading a TLS stack.
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

#[derive(Debug, PartialEq, Eq)]
pub struct BlobInfo {
    /// PEM label of the first private-key block (`RSA PRIVATE KEY`, `EC PRIVATE KEY`, `PRIVATE KEY`).
    pub key_label: Option<String>,
    /// SHA-256 of the leaf certificate's SubjectPublicKeyInfo (the DANE-EE (3 1 1) input).
    pub spki_sha256: Option<String>,
    pub chain_certificates: usize,
    pub dns_names: BTreeSet<String>,
    /// Seconds since the epoch of the leaf's NotAfter.
    pub not_after: Option<i64>,
    pub key_first: bool,
}

pub fn describe(blob: &[u8]) -> BlobInfo {
    let blocks = pem::parse_many(blob).unwrap_or_default();
    let key_label = blocks
        .iter()
        .find(|b| b.tag().ends_with("PRIVATE KEY"))
        .map(|b| b.tag().to_owned());
    let key_first = blocks
        .first()
        .is_some_and(|b| b.tag().ends_with("PRIVATE KEY"));
    let certs: Vec<_> = blocks.iter().filter(|b| b.tag() == "CERTIFICATE").collect();
    let mut info = BlobInfo {
        key_label,
        spki_sha256: None,
        chain_certificates: certs.len(),
        dns_names: BTreeSet::new(),
        not_after: None,
        key_first,
    };
    if let Some(Ok((_, leaf))) = certs
        .first()
        .map(|c| x509_parser::parse_x509_certificate(c.contents()))
    {
        info.not_after = Some(leaf.validity().not_after.timestamp());
        info.spki_sha256 = Some(
            Sha256::digest(leaf.public_key().raw)
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect(),
        );
        if let Ok(Some(san)) = leaf.subject_alternative_name() {
            for name in &san.value.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(d) = name {
                    info.dns_names.insert((*d).to_owned());
                }
            }
        }
    }
    info
}
