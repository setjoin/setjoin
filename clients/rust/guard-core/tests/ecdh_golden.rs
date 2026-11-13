//! Cross-end golden vector for the ECDH push-challenge contract.
//!
//! This pins guard-core's `decrypt_ecies` to a ciphertext PRODUCED BY THE SERVER
//! (authserver's `EncryptECIES`, run with a fixed ephemeral key + nonce so the
//! bytes are reproducible). The IDENTICAL hex vector is asserted on the Go side in
//! `authserver/internal/authn/push_native_test.go` (TestECIESGoldenVector), so any
//! future change to either end's wire format / KDF / AEAD / point-encoding that
//! breaks interop FAILS this committed test instead of a user's push login.
//!
//! Contract (single source of truth): docs/standards/PUSH_ECIES_CONTRACT.md.
//!   - P-256 ECDH, HKDF-SHA256 (salt = empty, info = b"push-challenge"), AES-256-GCM.
//!   - Wire: [65-byte uncompressed SEC1 ephemeral pubkey][12-byte nonce][ct + 16-byte tag].
//!
//! DO NOT regenerate these constants to "make the test pass". If this fails, the
//! interop contract changed — fix the code or re-derive the vector on BOTH ends
//! deliberately (see the contract doc's "Changing the contract" section).
//!
//! Mirrors the RFC-6238 discipline of `tests/totp_vectors.rs`.

use guard_core::ecdh::decrypt_ecies;

/// Recipient (device) P-256 private key, PKCS#8 DER — what `decrypt_ecies` parses.
/// This is the private half of GOLDEN_RECIP_PUB_RAW65 in the Go test.
const GOLDEN_RECIP_PRIV_PKCS8_DER: &str = "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420ec1604f867dc08e17a4688f251adce508d6827bb72e952bf14666820febb08d5a144034200043ffa8457dbd2917d7ab2555efa3b1c1669079eef5933ecc4bd5fa6b1701787d3ee4d370c8e54b99ca7f14fdf08329eb19fc87d33e83108a3e9577d6709b8fc75";

/// Server-produced ECIES payload for the above recipient + plaintext "42",
/// with a FIXED ephemeral key and nonce (see push_native_test.go for the seed
/// material). Byte-for-byte identical to the Go side's GOLDEN_PAYLOAD.
const GOLDEN_PAYLOAD: &str = "0484d4083d3cce31d97122787043abdff18a900a421e471747e0aa0cad7ba4c00b78422c16286d6f57ddd9d2cbaa429ee04efce4ffb5d944a3571bb7c38f9670b1a4ff6b6dfd563c638179f6fa93db6bc2399d727d12c0f9c07916870c5a44";

/// Expected decrypted plaintext: a 2-digit number-match challenge code.
const GOLDEN_PLAINTEXT: &[u8] = b"42";

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

#[test]
fn ecies_cross_end_golden_vector() {
    let priv_der = unhex(GOLDEN_RECIP_PRIV_PKCS8_DER);
    let payload = unhex(GOLDEN_PAYLOAD);

    // Structural sanity: 65 (eph pub) + 12 (nonce) + 2 (ct) + 16 (tag) = 95.
    assert_eq!(payload.len(), 95, "golden payload length drifted");
    assert_eq!(
        payload[0], 0x04,
        "ephemeral point must be uncompressed (0x04)"
    );

    let decrypted =
        decrypt_ecies(&priv_der, &payload).expect("decrypt server-produced golden vector");
    assert_eq!(
        decrypted, GOLDEN_PLAINTEXT,
        "guard-core decrypt of the committed server ciphertext drifted — \
         the ECIES interop contract is broken (see docs/standards/PUSH_ECIES_CONTRACT.md)"
    );
}

/// Tampering with any byte of the AEAD-protected region (nonce or ct+tag) must
/// fail — proves the GCM tag is actually verified, not silently truncated.
#[test]
fn ecies_golden_vector_rejects_tamper() {
    let priv_der = unhex(GOLDEN_RECIP_PRIV_PKCS8_DER);
    let mut payload = unhex(GOLDEN_PAYLOAD);
    let last = payload.len() - 1;
    payload[last] ^= 0x01; // flip a bit in the GCM tag
    assert!(
        decrypt_ecies(&priv_der, &payload).is_err(),
        "tampered ciphertext must not decrypt"
    );
}
