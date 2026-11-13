use crate::GuardError;
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KdfParams {
    pub m_cost: u32,  // memory KiB (default 65536 = 64 MiB)
    pub t_cost: u32,  // iterations (default 3)
    pub p_cost: u32,  // parallelism (default 4)
    pub salt: String, // hex-encoded 16-byte salt
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams {
            m_cost: 65536,
            t_cost: 3,
            p_cost: 4,
            salt: generate_salt_hex(),
        }
    }
}

fn generate_salt_hex() -> String {
    use rand::Rng;
    let mut salt = [0u8; 16];
    rand::rng().fill_bytes(&mut salt);
    hex::encode(salt)
}

/// Derive a 32-byte per-store subkey from the vault root key using HKDF-SHA256.
///
/// `info` is the app_key bytes ('mail', 'drive', …); distinct infos → distinct subkeys.
/// The vault root key is the IKM; no salt (the root key already carries entropy).
/// ponytail: HKDF-SHA256 — upgrade to BLAKE3 if throughput of frequent re-derivations
///           ever becomes measurable (it won't for a single provision-per-open call).
pub fn derive_subkey(root: &[u8; 32], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, root);
    let mut out = [0u8; 32];
    hk.expand(info, &mut out)
        .expect("HKDF expand: 32 bytes always fits");
    out
}

/// Derive a 32-byte key from passphrase + stored params.
pub fn derive_key(passphrase: &str, params: &KdfParams) -> Result<[u8; 32], GuardError> {
    let salt = hex::decode(&params.salt).map_err(|e| GuardError::Crypto(e.to_string()))?;
    let argon2_params = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(32))
        .map_err(|e| GuardError::Crypto(e.to_string()))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key)
        .map_err(|e| GuardError::Crypto(e.to_string()))?;
    Ok(key)
}
