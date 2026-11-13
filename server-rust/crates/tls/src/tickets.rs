//! crypto/tls' ticket envelope: random IV, AES-128-CTR, then HMAC-SHA256.
//! All primitives and constant-time authentication come from RustCrypto/ring.
use aes::cipher::{KeyIvInit, StreamCipher};
use ring::{
    hmac,
    rand::{SecureRandom, SystemRandom},
};
use sha2::{Digest, Sha512};
use std::{fmt, sync::RwLock};
use zeroize::Zeroizing;

pub(crate) struct Tickets {
    keys: RwLock<Vec<Zeroizing<[u8; 32]>>>,
}
impl fmt::Debug for Tickets {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Tickets { .. }")
    }
}
impl Tickets {
    pub fn new() -> Result<Self, String> {
        let mut key = [0; 32];
        SystemRandom::new()
            .fill(&mut key)
            .map_err(|_| "TLS ticket entropy unavailable")?;
        Ok(Self {
            keys: RwLock::new(vec![Zeroizing::new(key)]),
        })
    }
    pub fn set(&self, current: [u8; 32], previous: Option<[u8; 32]>) {
        let mut keys = vec![Zeroizing::new(current)];
        if let Some(previous) = previous {
            keys.push(Zeroizing::new(previous));
        }
        *self.keys.write().unwrap() = keys;
    }
    fn seal(&self, plaintext: &[u8]) -> Option<Vec<u8>> {
        let keys = self.keys.read().ok()?;
        // Go reserves hash[0..16] for its old public key name; these bytes
        // must never become encryption or authentication key material.
        let expanded = Zeroizing::new(<[u8; 64]>::from(Sha512::digest(&*keys[0])));
        let mut iv = [0; 16];
        SystemRandom::new().fill(&mut iv).ok()?;
        let mut out = iv.to_vec();
        out.extend_from_slice(plaintext);
        ctr::Ctr128BE::<aes::Aes128>::new_from_slices(&expanded[16..32], &iv)
            .ok()?
            .apply_keystream(&mut out[16..]);
        let mac = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, &expanded[32..48]), &out);
        out.extend_from_slice(mac.as_ref());
        Some(out)
    }
    pub fn open(&self, ciphertext: &[u8]) -> Option<Vec<u8>> {
        if !(48..=65535).contains(&ciphertext.len()) {
            return None;
        }
        let split = ciphertext.len() - 32;
        let (authenticated, tag) = ciphertext.split_at(split);
        for key in self.keys.read().ok()?.iter() {
            let expanded = Zeroizing::new(<[u8; 64]>::from(Sha512::digest(&**key)));
            if hmac::verify(
                &hmac::Key::new(hmac::HMAC_SHA256, &expanded[32..48]),
                authenticated,
                tag,
            )
            .is_err()
            {
                continue;
            }
            let mut plain = authenticated[16..].to_vec();
            ctr::Ctr128BE::<aes::Aes128>::new_from_slices(&expanded[16..32], &authenticated[..16])
                .ok()?
                .apply_keystream(&mut plain);
            return Some(plain);
        }
        None
    }
}
#[derive(Debug)]
struct BoundTickets {
    keys: std::sync::Arc<Tickets>,
    name: Option<String>,
    cipher: Option<u16>,
}
impl Tickets {
    pub fn for_name(
        self: &std::sync::Arc<Self>,
        name: Option<&str>,
    ) -> std::sync::Arc<dyn rustls::server::ProducesTickets> {
        self.for_context(name, None)
    }
    pub fn for_context(
        self: &std::sync::Arc<Self>,
        name: Option<&str>,
        cipher: Option<u16>,
    ) -> std::sync::Arc<dyn rustls::server::ProducesTickets> {
        std::sync::Arc::new(BoundTickets {
            keys: self.clone(),
            name: name.map(str::to_owned),
            cipher,
        })
    }
}
impl rustls::server::ProducesTickets for BoundTickets {
    fn enabled(&self) -> bool {
        true
    }
    fn lifetime(&self) -> u32 {
        7 * 24 * 3600
    }
    fn encrypt(&self, plain: &[u8]) -> Option<Vec<u8>> {
        self.keys
            .seal(&zeroize::Zeroizing::new(crate::state::for_go(plain)?))
    }
    fn decrypt(&self, cipher: &[u8]) -> Option<Vec<u8>> {
        crate::state::for_rustls(&self.keys.open(cipher)?, self.name.as_deref(), self.cipher)
    }
}
