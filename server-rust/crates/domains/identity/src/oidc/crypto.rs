//! RFC7516 A256GCMKW/A256GCM framing. All crypto primitives are ring.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
use ring::{
    aead, hkdf, hmac,
    rand::{SecureRandom, SystemRandom},
};
use serde_json::json;

pub struct CodeCipher {
    key: [u8; 32],
    csrf: hmac::Key,
}
struct Len;
impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        32
    }
}
impl CodeCipher {
    pub fn new(secret: &[u8]) -> Result<Self, String> {
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"mailserver-oidc-cryptokey-v1");
        let prk = salt.extract(secret);
        let mut key = [0; 32];
        prk.expand(&[b""], Len)
            .map_err(|_| "OIDC HKDF expansion")?
            .fill(&mut key)
            .map_err(|_| "OIDC HKDF output")?;
        let mut csrf = [0; 32];
        prk.expand(&[b"op-complete-csrf-v1"], Len)
            .map_err(|_| "OIDC HKDF expansion")?
            .fill(&mut csrf)
            .map_err(|_| "OIDC HKDF output")?;
        Ok(Self {
            key,
            csrf: hmac::Key::new(hmac::HMAC_SHA256, &csrf),
        })
    }
    /// Synchroniser token for the state-changing authorization completion
    /// (#523): an HMAC over the caller-supplied session/request binding, so a
    /// page another origin cannot read is the only source of a valid token.
    pub fn csrf_token(&self, binding: &str) -> String {
        B64.encode(hmac::sign(&self.csrf, binding.as_bytes()).as_ref())
    }
    pub fn csrf_valid(&self, binding: &str, presented: &str) -> bool {
        B64.decode(presented)
            .ok()
            .is_some_and(|tag| hmac::verify(&self.csrf, binding.as_bytes(), &tag).is_ok())
    }
    pub fn encrypt(&self, plain: &str) -> Result<String, String> {
        let rng = SystemRandom::new();
        let mut cek = [0; 32];
        let mut wrap_iv = [0; 12];
        let mut iv = [0; 12];
        rng.fill(&mut cek).map_err(|_| "OIDC RNG")?;
        rng.fill(&mut wrap_iv).map_err(|_| "OIDC RNG")?;
        rng.fill(&mut iv).map_err(|_| "OIDC RNG")?;
        let seal = |key: &[u8],
                    nonce: [u8; 12],
                    aad: &[u8],
                    plain: &[u8]|
         -> Result<(Vec<u8>, aead::Tag), String> {
            let key = aead::LessSafeKey::new(
                aead::UnboundKey::new(&aead::AES_256_GCM, key).map_err(|_| "OIDC AES key")?,
            );
            let mut cipher = plain.to_vec();
            let tag = key
                .seal_in_place_separate_tag(
                    aead::Nonce::assume_unique_for_key(nonce),
                    aead::Aad::from(aad),
                    &mut cipher,
                )
                .map_err(|_| "OIDC AES sealing")?;
            Ok((cipher, tag))
        };
        let (wrapped, wrap_tag) = seal(&self.key, wrap_iv, b"", &cek)?;
        let protected=B64.encode(json!({"alg":"A256GCMKW","enc":"A256GCM","iv":B64.encode(wrap_iv),"kid":"authserver-enc-1","tag":B64.encode(wrap_tag.as_ref())}).to_string());
        let (cipher, tag) = seal(&cek, iv, protected.as_bytes(), plain.as_bytes())?;
        Ok(format!(
            "{protected}.{}.{}.{}.{}",
            B64.encode(wrapped),
            B64.encode(iv),
            B64.encode(cipher),
            B64.encode(tag.as_ref())
        ))
    }
    pub fn decrypt(&self, token: &str) -> Option<String> {
        let parts: Vec<_> = token.split('.').collect();
        if parts.len() == 5 {
            let h: serde_json::Value = serde_json::from_slice(&B64.decode(parts[0]).ok()?).ok()?;
            if h["alg"] != "A256GCMKW" || h["enc"] != "A256GCM" {
                return None;
            }
            let open =
                |key: &[u8], nonce: &str, cipher: &str, tag: &str, aad: &[u8]| -> Option<Vec<u8>> {
                    let nonce: [u8; 12] = B64.decode(nonce).ok()?.try_into().ok()?;
                    let mut bytes = B64.decode(cipher).ok()?;
                    bytes.extend(B64.decode(tag).ok()?);
                    let key = aead::LessSafeKey::new(
                        aead::UnboundKey::new(&aead::AES_256_GCM, key).ok()?,
                    );
                    Some(
                        key.open_in_place(
                            aead::Nonce::assume_unique_for_key(nonce),
                            aead::Aad::from(aad),
                            &mut bytes,
                        )
                        .ok()?
                        .to_vec(),
                    )
                };
            let cek = open(
                &self.key,
                h["iv"].as_str()?,
                parts[1],
                h["tag"].as_str()?,
                b"",
            )?;
            return String::from_utf8(open(
                &cek,
                parts[2],
                parts[3],
                parts[4],
                parts[0].as_bytes(),
            )?)
            .ok();
        }
        // Go's integrity-less CFB access-token fallback is no longer accepted
        // (owner-approved security fix 2026-11-05, #523): Go access tokens live
        // five minutes, so every legacy token is already dead, and CFB is
        // malleable (bit flips rewrite the subject).
        #[cfg(feature = "oracle-mutants")]
        if crate::mutants::on("oidc-cfb-legacy") {
            use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
            let bytes = B64.decode(token).ok()?;
            let (iv, cipher) = bytes.split_at_checked(16)?;
            let mut plain = cipher.to_vec();
            cfb_mode::Decryptor::<aes::Aes256>::new_from_slices(&self.key, iv)
                .ok()?
                .decrypt(&mut plain);
            return String::from_utf8(plain).ok();
        }
        None
    }
}
