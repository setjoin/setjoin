//! Portable Exchange artifact envelope, frozen Go `shared/exchangeartifact`.
//! EK01 framing is protocol glue. AEADs, HKDF and randomness are audited crates.
use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use ring::{aead, hkdf, rand::SecureRandom};
use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    Standard,
    Smx,
    Hybrid,
}
impl Profile {
    pub fn parse(s: &str) -> Self {
        match s {
            "smx" => Self::Smx,
            "hybrid" => Self::Hybrid,
            _ => Self::Standard,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::Standard => "standard",
            Self::Smx => "smx",
            Self::Hybrid => "hybrid",
        }
    }
    fn key_len(self) -> usize {
        if self == Self::Smx {
            16
        } else {
            32
        }
    }
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Binding<'a> {
    pub installation_id: &'a str,
    pub tenant_id: i64,
    pub project_id: i64,
    pub kind: &'a str,
    pub plain_sha256: &'a str,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Envelope<'a> {
    schema_version: &'static str,
    profile: &'static str,
    binding: Binding<'a>,
    wrapped_dek: String,
    ciphertext: String,
}
/// The encoded object and exactly the metadata Go persists with it.
pub struct Sealed {
    pub bytes: Vec<u8>,
    pub ciphertext_size: i64,
    pub nonce: Vec<u8>,
    pub wrapped_dek: Vec<u8>,
    pub aad_sha256: String,
}
#[derive(Debug)]
pub struct SealError;
impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("artifact encryption failed")
    }
}
impl std::error::Error for SealError {}
struct Len(usize);
impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}
fn derive(secret: &[u8], salt: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>, SealError> {
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(secret);
    let okm = prk.expand(&[], Len(len)).map_err(|_| SealError)?;
    let mut key = Zeroizing::new(vec![0u8; len]);
    okm.fill(key.as_mut_slice()).map_err(|_| SealError)?;
    Ok(key)
}
fn raw_seal(profile: Profile, key: &[u8], plain: &[u8], aad: &[u8]) -> Result<Vec<u8>, SealError> {
    let mut nonce = [0u8; 12];
    ring::rand::SystemRandom::new()
        .fill(&mut nonce)
        .map_err(|_| SealError)?;
    let payload = if profile == Profile::Smx {
        use aes_gcm::aead::{Aead, KeyInit, Payload};
        type Sm4Gcm = aes_gcm::AesGcm<sm4::Sm4, aes_gcm::aead::consts::U12>;
        Sm4Gcm::new_from_slice(key)
            .map_err(|_| SealError)?
            .encrypt((&nonce).into(), Payload { msg: plain, aad })
            .map_err(|_| SealError)?
    } else {
        let key = aead::UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| SealError)?;
        let mut payload = plain.to_vec();
        aead::LessSafeKey::new(key)
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                &mut payload,
            )
            .map_err(|_| SealError)?;
        payload
    };
    let mut frame = Vec::with_capacity(25 + payload.len());
    frame.extend_from_slice(b"EK01");
    frame.push(if profile == Profile::Smx { 1 } else { 0 });
    frame.extend_from_slice(&(key.len() as u32).to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&12u16.to_be_bytes());
    frame.extend_from_slice(&nonce);
    frame.extend_from_slice(&payload);
    Ok(frame)
}
/// Go uses the purpose string as HKDF *salt*, with empty info, twice for the DEK.
pub fn seal(
    plain: &[u8],
    master: &[u8],
    profile: Profile,
    binding: Binding<'_>,
) -> Result<Sealed, SealError> {
    if binding.installation_id.is_empty()
        || binding.tenant_id < 1
        || binding.project_id < 1
        || binding.kind.is_empty()
        || format!("{:x}", Sha256::digest(plain)) != binding.plain_sha256
    {
        return Err(SealError);
    }
    let aad = super::go_escape(&serde_json::to_string(&binding).map_err(|_| SealError)?);
    let mut dek = Zeroizing::new(vec![0u8; profile.key_len()]);
    ring::rand::SystemRandom::new()
        .fill(dek.as_mut_slice())
        .map_err(|_| SealError)?;
    let ciphertext = raw_seal(profile, &dek, plain, aad.as_bytes())?;
    let wrapping = derive(
        master,
        b"exchange-assessment-artifact-dek/v1",
        profile.key_len(),
    )?;
    let column = derive(&wrapping, b"mailserver-db-encryption-v1", profile.key_len())?;
    let wrapped_dek = raw_seal(profile, &column, &dek, aad.as_bytes())?;
    let envelope = Envelope {
        schema_version: "setjoin.exchange.artifact-envelope/v1",
        profile: profile.name(),
        binding,
        wrapped_dek: STANDARD_NO_PAD.encode(&wrapped_dek),
        ciphertext: STANDARD_NO_PAD.encode(&ciphertext),
    };
    Ok(Sealed {
        bytes: super::go_escape(&serde_json::to_string(&envelope).map_err(|_| SealError)?)
            .into_bytes(),
        ciphertext_size: ciphertext.len() as i64,
        nonce: ciphertext[13..25].to_vec(),
        wrapped_dek,
        aad_sha256: format!("{:x}", Sha256::digest(aad.as_bytes())),
    })
}

/// Continuity Ed25519 signer; key bytes never enter a database or a response.
pub struct ReceiptSigner {
    key: ring::signature::Ed25519KeyPair,
    key_id: String,
}
pub struct ReceiptSubject<'a> {
    pub kind: &'a str,
    pub sha256: &'a str,
    pub installation: &'a str,
    pub tenant: i64,
    pub project: i64,
    pub disposition: &'a str,
}
pub struct SignedReceipt {
    pub bytes: String,
    pub signature: Vec<u8>,
    pub key_id: String,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ReceiptClaims<'a> {
    schema_version: &'static str,
    receipt_id: String,
    kind: &'a str,
    subject_sha256: &'a str,
    installation_id: &'a str,
    tenant_id: i64,
    project_id: i64,
    key_id: &'a str,
    issued_at: &'a str,
    disposition: &'a str,
}
#[derive(Serialize)]
struct Receipt<'a> {
    claims: ReceiptClaims<'a>,
    algorithm: &'static str,
    signature: String,
}
impl ReceiptSigner {
    pub fn from_pkcs8(der: &[u8], key_id: &str) -> Result<Self, SealError> {
        if key_id.is_empty()
            || key_id.len() > 64
            || !key_id.as_bytes()[0].is_ascii_alphanumeric()
            || !key_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        {
            return Err(SealError);
        }
        Ok(Self {
            key: ring::signature::Ed25519KeyPair::from_pkcs8_maybe_unchecked(der)
                .map_err(|_| SealError)?,
            key_id: key_id.into(),
        })
    }
    /// Caller supplies its UTC clock truncated to seconds, matching continuity service.
    pub fn sign(&self, s: ReceiptSubject<'_>, issued_at: &str) -> Result<SignedReceipt, SealError> {
        if s.kind.is_empty()
            || s.installation.is_empty()
            || s.tenant < 1
            || s.project < 1
            || s.disposition.is_empty()
            || s.sha256.len() != 64
            || !s
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
        {
            return Err(SealError);
        }
        let mut claims = ReceiptClaims {
            schema_version: "setjoin.exchange.receipt/v1",
            receipt_id: String::new(),
            kind: s.kind,
            subject_sha256: s.sha256,
            installation_id: s.installation,
            tenant_id: s.tenant,
            project_id: s.project,
            key_id: &self.key_id,
            issued_at,
            disposition: s.disposition,
        };
        let canonical = super::go_escape(&serde_json::to_string(&claims).map_err(|_| SealError)?);
        claims.receipt_id = format!("{:x}", Sha256::digest(canonical.as_bytes()));
        let canonical = super::go_escape(&serde_json::to_string(&claims).map_err(|_| SealError)?);
        let signature = self.key.sign(canonical.as_bytes()).as_ref().to_vec();
        let receipt = Receipt {
            claims,
            algorithm: "ed25519",
            signature: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&signature),
        };
        Ok(SignedReceipt {
            bytes: super::go_escape(&serde_json::to_string(&receipt).map_err(|_| SealError)?),
            signature,
            key_id: self.key_id.clone(),
        })
    }
}
