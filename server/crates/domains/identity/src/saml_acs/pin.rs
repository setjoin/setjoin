//! The IdP's pinned signing key, from the registration's certificate(s). Only the
//! public key is read (OpenSSL parses; ring verifies); `KeyInfo` in a message is
//! never consulted. RSA must be at least 2048 bits; ECDSA is P-256 or P-384.
use base64::{engine::general_purpose::STANDARD, Engine};
use openssl::{bn::BigNumContext, ec::PointConversionForm, nid::Nid, pkey::Id};

#[derive(Clone)]
pub enum PinnedKey {
    /// PKCS#1 RSAPublicKey DER.
    Rsa(Vec<u8>),
    /// Uncompressed X9.62 point.
    P256(Vec<u8>),
    P384(Vec<u8>),
}

/// Parse every certificate in the text (PEM blocks, or one bare base64 DER body).
/// A certificate that is unsupported or too weak contributes nothing, so a
/// registration without a usable key refuses every assertion.
pub fn parse(text: &str) -> Vec<PinnedKey> {
    let mut ders = Vec::new();
    let mut body = String::new();
    let mut inside = false;
    let mut saw_pem = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with("-----BEGIN") {
            saw_pem = true;
            inside = line.contains("CERTIFICATE") && !line.contains("TRUSTED");
            body.clear();
        } else if line.starts_with("-----END") {
            if inside {
                if let Ok(der) = STANDARD.decode(body.as_bytes()) {
                    ders.push(der);
                }
            }
            inside = false;
        } else if inside {
            body.push_str(line);
        }
    }
    if !saw_pem {
        let bare: String = text.split_whitespace().collect();
        if let Ok(der) = STANDARD.decode(bare.as_bytes()) {
            ders.push(der);
        }
    }
    ders.iter().filter_map(|der| from_der(der)).collect()
}

fn from_der(der: &[u8]) -> Option<PinnedKey> {
    let cert = openssl::x509::X509::from_der(der).ok()?;
    let key = cert.public_key().ok()?;
    match key.id() {
        Id::RSA => {
            let rsa = key.rsa().ok()?;
            if rsa.n().num_bits() < 2048 && !crate::mutants::on("saml-weak-rsa") {
                return None;
            }
            Some(PinnedKey::Rsa(rsa.public_key_to_der_pkcs1().ok()?))
        }
        Id::EC => {
            let ec = key.ec_key().ok()?;
            let group = ec.group();
            let mut ctx = BigNumContext::new().ok()?;
            let point = ec
                .public_key()
                .to_bytes(group, PointConversionForm::UNCOMPRESSED, &mut ctx)
                .ok()?;
            match group.curve_name()? {
                Nid::X9_62_PRIME256V1 => Some(PinnedKey::P256(point)),
                Nid::SECP384R1 => Some(PinnedKey::P384(point)),
                _ => None,
            }
        }
        _ => None,
    }
}
