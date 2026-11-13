use crate::GuardError;
use aes_gcm::{aead::Aead, Aes256Gcm, KeyInit};
use hkdf::Hkdf;
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::Generate,
    pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey},
    PublicKey, SecretKey,
};
use sha2::Sha256;

/// Generate a new P-256 keypair. Returns (private_key_der, public_key_der).
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), GuardError> {
    let sk = SecretKey::generate();
    let pk = sk.public_key();
    let sk_der = sk
        .to_pkcs8_der()
        .map_err(|e| GuardError::Crypto(e.to_string()))?
        .as_bytes()
        .to_vec();
    let pk_der = pk
        .to_public_key_der()
        .map_err(|e| GuardError::Crypto(e.to_string()))?
        .as_bytes()
        .to_vec();
    Ok((sk_der, pk_der))
}

/// Decrypt an ECIES payload produced by the server.
///
/// Wire format: [65-byte uncompressed ephemeral pub key] | [12-byte nonce] | [ciphertext+tag]
pub fn decrypt_ecies(
    private_key_der: &[u8],
    encrypted_payload: &[u8],
) -> Result<Vec<u8>, GuardError> {
    if encrypted_payload.len() < 65 + 12 + 16 {
        return Err(GuardError::Crypto("payload too short".into()));
    }
    let (eph_pub_bytes, rest) = encrypted_payload.split_at(65);
    let (nonce_bytes, ct) = rest.split_at(12);

    // Parse private key
    let sk = SecretKey::from_pkcs8_der(private_key_der)
        .map_err(|e| GuardError::Crypto(e.to_string()))?;

    // Parse ephemeral public key (uncompressed point)
    let eph_pub =
        PublicKey::from_sec1_bytes(eph_pub_bytes).map_err(|e| GuardError::Crypto(e.to_string()))?;

    // ECDH shared secret
    let shared = p256::ecdh::diffie_hellman(sk.to_nonzero_scalar(), eph_pub.as_affine());

    // HKDF-SHA256 → 32-byte AES key
    let hk = Hkdf::<Sha256>::new(None, shared.raw_secret_bytes());
    let mut aes_key = [0u8; 32];
    hk.expand(b"push-challenge", &mut aes_key)
        .map_err(|e| GuardError::Crypto(e.to_string()))?;

    // AES-256-GCM decrypt
    let cipher =
        Aes256Gcm::new_from_slice(&aes_key).map_err(|e| GuardError::Crypto(e.to_string()))?;
    let nonce_arr: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| GuardError::Crypto("nonce length mismatch".into()))?;
    let nonce = aes_gcm::Nonce::from(nonce_arr);
    cipher
        .decrypt(&nonce, ct)
        .map_err(|_| GuardError::Crypto("decrypt failed".into()))
}

/// Sign the canonical push-approval bytes with the same persisted P-256 key
/// whose public point is registered for native push. The returned signature is
/// fixed-width IEEE P1363 (`r || s`, 64 bytes), avoiding DER ambiguity.
pub fn sign_push_approval(
    private_key_der: &[u8],
    canonical: &[u8],
) -> Result<[u8; 64], GuardError> {
    let secret = SecretKey::from_pkcs8_der(private_key_der)
        .map_err(|e| GuardError::Crypto(e.to_string()))?;
    let signing_key = SigningKey::from(secret);
    let signature: Signature = signing_key.sign(canonical);
    Ok(signature.to_bytes().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{
        aead::{Aead, Generate},
        Aes256Gcm, KeyInit, Nonce,
    };
    use p256::elliptic_curve::sec1::ToSec1Point;
    use p256::pkcs8::DecodePublicKey;
    use p256::SecretKey as TestSecretKey;
    use sha2::Sha256;

    fn encrypt_ecies_test(recipient_pub_der: &[u8], plaintext: &[u8]) -> Vec<u8> {
        let eph_sk = TestSecretKey::generate();
        let eph_pk = eph_sk.public_key();
        let eph_pub_bytes = eph_pk.to_sec1_point(false).as_bytes().to_vec();

        let recipient_pk = PublicKey::from_public_key_der(recipient_pub_der).unwrap();
        let shared =
            p256::ecdh::diffie_hellman(eph_sk.to_nonzero_scalar(), recipient_pk.as_affine());
        let hk = Hkdf::<Sha256>::new(None, shared.raw_secret_bytes());
        let mut aes_key = [0u8; 32];
        hk.expand(b"push-challenge", &mut aes_key).unwrap();

        let cipher = Aes256Gcm::new_from_slice(&aes_key).unwrap();
        let nonce = Nonce::generate();
        let ct = cipher.encrypt(&nonce, plaintext).unwrap();

        let mut out = eph_pub_bytes;
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    #[test]
    fn test_ecies_roundtrip() {
        let (sk_der, pk_der) = generate_keypair().unwrap();
        let plaintext = b"42"; // 2-digit challenge code
        let encrypted = encrypt_ecies_test(&pk_der, plaintext);
        let decrypted = decrypt_ecies(&sk_der, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
