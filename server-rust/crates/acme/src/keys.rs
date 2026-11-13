//! Key containers. Go writes the ACME account key as ECDSA P-256 `EC PRIVATE KEY` (SEC1) and
//! the certificate key lego-style (`RSA PRIVATE KEY` PKCS#1 for lego's RSA 2048).
//! New Rust certificate/challenge keys are P-256 (owner decision 2026-11-03).
//! Rust reads and reuses cached Go RSA keys so the DANE-EE SPKI hash survives renewal.
//!
use rcgen::{KeyPair, PublicKeyData, SignatureAlgorithm, SigningKey};
use ring::{
    rand::SystemRandom,
    signature::{RsaKeyPair, RSA_PKCS1_SHA256},
};

pub enum CertKey {
    Ec(KeyPair),
    Rsa(RsaSigner),
}

pub struct RsaSigner {
    pair: RsaKeyPair,
    pkcs1: Vec<u8>,
}

impl PublicKeyData for RsaSigner {
    fn der_bytes(&self) -> &[u8] {
        ring::signature::KeyPair::public_key(&self.pair).as_ref()
    }
    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &rcgen::PKCS_RSA_SHA256
    }
}

impl SigningKey for RsaSigner {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let mut out = vec![0; self.pair.public().modulus_len()];
        self.pair
            .sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), msg, &mut out)
            .map_err(|_| rcgen::Error::RingUnspecified)?;
        Ok(out)
    }
}

impl PublicKeyData for CertKey {
    fn der_bytes(&self) -> &[u8] {
        match self {
            Self::Ec(k) => k.der_bytes(),
            Self::Rsa(k) => k.der_bytes(),
        }
    }
    fn algorithm(&self) -> &'static SignatureAlgorithm {
        match self {
            Self::Ec(k) => k.algorithm(),
            Self::Rsa(k) => k.algorithm(),
        }
    }
}

impl SigningKey for CertKey {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        match self {
            Self::Ec(k) => SigningKey::sign(k, msg),
            Self::Rsa(k) => SigningKey::sign(k, msg),
        }
    }
}

impl CertKey {
    pub fn generate() -> Result<Self, String> {
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
            .map(Self::Ec)
            .map_err(|e| format!("generate certificate key: {e}"))
    }

    /// Wire CSR: lego puts the first configured identifier in CommonName and
    /// every configured identifier in SAN. The CA remains authority over the chain.
    pub fn request(&self, domains: &[String]) -> Result<Vec<u8>, String> {
        let first = domains
            .first()
            .ok_or("acme: CSR requires at least one domain")?;
        let mut params = rcgen::CertificateParams::new(domains.to_vec())
            .map_err(|e| format!("acme: csr params: {e}"))?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, first);
        let csr = params
            .serialize_request(self)
            .map_err(|e| format!("acme: csr: {e}"))?;
        Ok(csr.der().to_vec())
    }

    /// The private key as the PEM block that precedes the chain in a cache blob.
    pub fn to_pem(&self) -> String {
        match self {
            Self::Ec(k) => k.serialize_pem(),
            Self::Rsa(k) => encode_lf("RSA PRIVATE KEY", k.pkcs1.clone()),
        }
    }

    /// First private-key block of a cache blob (key PEM, then chain PEM).
    pub fn from_blob(blob: &[u8]) -> Option<Self> {
        for block in pem::parse_many(blob).ok()? {
            match block.tag() {
                "RSA PRIVATE KEY" => {
                    let pair = RsaKeyPair::from_der(block.contents()).ok()?;
                    return Some(Self::Rsa(RsaSigner {
                        pair,
                        pkcs1: block.contents().to_vec(),
                    }));
                }
                "EC PRIVATE KEY" => {
                    use p256::pkcs8::EncodePrivateKey;
                    let sk = p256::SecretKey::from_sec1_der(block.contents()).ok()?;
                    let der = sk.to_pkcs8_der().ok()?;
                    return KeyPair::try_from(der.as_bytes()).ok().map(Self::Ec);
                }
                "PRIVATE KEY" => return KeyPair::try_from(block.contents()).ok().map(Self::Ec),
                _ => {}
            }
        }
        None
    }
}

/// Go's `loadOrCreateAccountKey` container: SEC1 `EC PRIVATE KEY`; returns PKCS#8 DER too.
pub fn account_key_pem_to_pkcs8(pem_bytes: &[u8]) -> Result<Vec<u8>, String> {
    use p256::pkcs8::EncodePrivateKey;
    let block = pem::parse(pem_bytes).map_err(|_| "account key is not PEM".to_string())?;
    let sk = p256::SecretKey::from_sec1_der(block.contents())
        .map_err(|e| format!("parse account key: {e}"))?;
    Ok(sk
        .to_pkcs8_der()
        .map_err(|e| format!("parse account key: {e}"))?
        .as_bytes()
        .to_vec())
}

pub fn new_account_key_pem() -> Result<String, String> {
    use p256::pkcs8::DecodePrivateKey;
    let pair = KeyPair::generate().map_err(|e| format!("generate account key: {e}"))?;
    let sk = p256::SecretKey::from_pkcs8_der(&pair.serialize_der())
        .map_err(|e| format!("generate account key: {e}"))?;
    let sec1 = sk
        .to_sec1_der()
        .map_err(|e| format!("marshal account key: {e}"))?;
    Ok(encode_lf("EC PRIVATE KEY", sec1.to_vec()))
}

/// PEM with LF line endings, as Go's `pem.EncodeToMemory` writes.
fn encode_lf(tag: &str, der: Vec<u8>) -> String {
    pem::encode_config(
        &pem::Pem::new(tag, der),
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    )
}
