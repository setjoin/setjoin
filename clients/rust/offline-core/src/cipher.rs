use crate::store::{apply_pragma_key, OfflineError};
use ghash::{
    universal_hash::{KeyInit as GhKeyInit, UniversalHash},
    GHash,
};
/// Cipher selection and SM4-GCM standalone seal/open.
///
/// `apply_cipher` dispatches on the `profile` string:
///   "standard" / "" → AES-256 via `store::apply_pragma_key` (SQLCipher default, always green)
///   "smx"           → SM4 page cipher via SQLCIPHER_CRYPTO_CUSTOM — gated behind
///                     `sm4-page-cipher` feature; the bundled-sqlcipher-vendored-openssl build
///                     compiles SQLCIPHER_CRYPTO_OPENSSL (a compile-time flag, not runtime-
///                     switchable), so this path requires a custom SQLCipher build.
///                     See A1 report concern.
///
/// SM4-GCM standalone seal/open — the at-rest page-cipher core.
///
/// AES-256 (the SQLCipher default, via bundled-sqlcipher-vendored-openssl)
/// is completely unaffected; this module is the SM4 interop gate only.
///
/// Wire: nonce is CALLER-SUPPLIED (12 bytes, 96-bit per GCM recommendation);
/// output = ciphertext || 16-byte GCM tag, nonce NOT prepended. Matches
/// gmsm `gcm.Seal(nil, nonce, pt, aad)` byte-for-byte — see
/// sm4_vectors.golden.json for the oracle vectors.
///
/// ponytail: AesGcm<Sm4, U12> requires InnerInit/InnerUser that sm4 0.6.x
/// (cipher 0.5.x) does not implement (coupled to AES hardware paths in
/// aes-gcm 0.11.x). Built as SM4-CTR + GHASH from RustCrypto primitives:
///   - sm4 0.6.0 (cipher 0.5.x, hybrid_array) for block encryption
///   - ghash 0.6.x (hybrid-array) for GHASH
///   - bridge: sm4_ecb extracts [u8; 16] via Array.0 field; the GHASH key
///     is reconstructed via `new_from_slice` — no unsafe, no copy
///     of sm4's hybrid_array/generic_array types across crate boundaries.
use rusqlite::Connection;
use sm4::cipher::{Array, BlockCipherEncrypt};
use sm4::Sm4;
use subtle::ConstantTimeEq;

/// Seal plaintext under SM4-GCM (NIST SP 800-38D, 96-bit IV path).
///
/// - `key`:       16-byte SM4 key
/// - `nonce`:     12-byte caller-supplied nonce (deterministic for the oracle gate)
/// - `plaintext`: message bytes (may be empty)
/// - `aad`:       additional authenticated data (may be empty)
///
/// Returns `ciphertext || 16-byte tag` — nonce is NOT prepended.
pub fn sm4_seal(key: &[u8], nonce: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, String> {
    if nonce.len() != 12 {
        return Err(format!(
            "sm4_seal: nonce must be 12 bytes, got {}",
            nonce.len()
        ));
    }
    let bc = Sm4::new_from_slice(key).map_err(|e| format!("sm4_seal key: {e}"))?;
    let mut ciphertext = plaintext.to_vec();
    gcm_ctr(&bc, nonce, &mut ciphertext);
    let tag = gcm_tag(&bc, nonce, aad, &ciphertext);
    ciphertext.extend_from_slice(&tag);
    Ok(ciphertext)
}

/// Open SM4-GCM ciphertext (NIST SP 800-38D).
///
/// - `key`:            16-byte SM4 key
/// - `nonce`:          12-byte nonce used during seal
/// - `ciphertext_tag`: ciphertext || 16-byte tag (as returned by sm4_seal)
/// - `aad`:            additional authenticated data (must match seal)
///
/// Returns plaintext on success; Err if the tag verification fails.
pub fn sm4_open(
    key: &[u8],
    nonce: &[u8],
    ciphertext_tag: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    if nonce.len() != 12 {
        return Err(format!(
            "sm4_open: nonce must be 12 bytes, got {}",
            nonce.len()
        ));
    }
    if ciphertext_tag.len() < 16 {
        return Err(format!(
            "sm4_open: ciphertext_tag too short ({})",
            ciphertext_tag.len()
        ));
    }
    let bc = Sm4::new_from_slice(key).map_err(|e| format!("sm4_open key: {e}"))?;
    let (ct, tag_bytes) = ciphertext_tag.split_at(ciphertext_tag.len() - 16);
    let expected = gcm_tag(&bc, nonce, aad, ct);
    // ponytail: constant-time compare — stdlib PartialEq short-circuits on first
    // differing byte (timing oracle for GCM tag forgery); subtle::ConstantTimeEq is
    // the vetted fix; subtle is already a transitive dep via ghash.
    if expected.ct_eq(tag_bytes).unwrap_u8() == 0 {
        return Err("sm4_open: authentication tag mismatch".into());
    }
    let mut plaintext = ct.to_vec();
    gcm_ctr(&bc, nonce, &mut plaintext);
    Ok(plaintext)
}

// ── Cipher selection ─────────────────────────────────────────────────────────

/// Dispatch the cipher for a freshly-opened connection based on `profile`.
///
/// - `"standard"` / `""` → AES-256 via existing `apply_pragma_key` (unaffected).
/// - `"smx"` → SM4 page cipher via SQLCIPHER_CRYPTO_CUSTOM; gated behind the
///   `sm4-page-cipher` feature (see Cargo.toml note on the build-feasibility risk).
///
/// Called by `lib.rs::open_cipher_init` immediately after `Connection::open`,
/// before any other SQL.
pub fn apply_cipher(conn: &Connection, profile: &str, key: &[u8; 32]) -> Result<(), OfflineError> {
    match profile {
        "standard" | "" => apply_pragma_key(conn, key),
        "smx" => {
            #[cfg(feature = "sm4-page-cipher")]
            {
                // ponytail: SQLCIPHER_CRYPTO_CUSTOM is a compile-time SQLCipher build flag;
                // bundled-sqlcipher-vendored-openssl uses SQLCIPHER_CRYPTO_OPENSSL instead.
                // SM4 page cipher here requires a custom SQLCipher build linked via a separate
                // `rusqlite` dependency without the bundled-openssl feature, plus a C shim
                // implementing the SQLCIPHER_CRYPTO_CUSTOM provider interface.
                // This is an A1 follow-up — do NOT fake a passing SM4-at-rest test.
                return Err(OfflineError::Crypto(
                    "SM4 page cipher: SQLCIPHER_CRYPTO_CUSTOM requires a custom SQLCipher \
                     build (not bundled-sqlcipher-vendored-openssl). Follow-up: \
                     link a SQLCIPHER_CRYPTO_CUSTOM-enabled SQLCipher build. \
                     SM4 standalone core (sm4_seal/sm4_open) is verified and ready."
                        .into(),
                ));
            }
            #[cfg(not(feature = "sm4-page-cipher"))]
            Err(OfflineError::Crypto(
                "SM4 page cipher not built — enable the sm4-page-cipher feature after \
                 confirming SQLCIPHER_CRYPTO_CUSTOM composes with your SQLCipher build \
                 (incompatible with bundled-sqlcipher-vendored-openssl)."
                    .into(),
            ))
        }
        p => Err(OfflineError::Crypto(format!("unknown cipher profile: {p}"))),
    }
}

// ── GCM internals ────────────────────────────────────────────────────────────

/// Encrypt one 16-byte block using SM4 (ECB, single block).
///
/// Bridges `hybrid_array::Array` (sm4/cipher 0.5.x) to `[u8; 16]`:
/// `Array(input)` constructs from `[u8; 16]` via its public `.0` tuple field;
/// `.0` extracts the inner `[u8; 16]` after encryption.
/// (`sm4::cipher::Array` re-exports `crypto_common`'s `hybrid_array::Array<T,U>`.)
fn sm4_ecb(bc: &Sm4, input: [u8; 16]) -> [u8; 16] {
    let mut block: Array<u8, _> = Array(input);
    bc.encrypt_block(&mut block);
    block.0
}

/// GCM counter-mode XOR for a 12-byte nonce (NIST SP 800-38D §6.2 GCTR).
///
/// ICB = inc32(J0) = nonce || 0x00000002 (J0 has counter=1; first plaintext
/// block uses J0+1 = nonce || 2). Only the last 32 bits are incremented
/// (big-endian, per GCM spec). Same operation for encryption and decryption.
fn gcm_ctr(bc: &Sm4, nonce: &[u8], buf: &mut [u8]) {
    let mut base = [0u8; 16];
    base[..12].copy_from_slice(nonce);
    // Counter = 2: J0 = nonce||1 is for E_J0 (tag); plaintext starts at nonce||2
    let mut counter: u32 = 2;
    for chunk in buf.chunks_mut(16) {
        base[12..].copy_from_slice(&counter.to_be_bytes());
        let ks = sm4_ecb(bc, base);
        for (b, k) in chunk.iter_mut().zip(ks.iter()) {
            *b ^= k;
        }
        counter = counter.wrapping_add(1);
    }
}

/// Compute the GCM authentication tag (NIST SP 800-38D §6.4, 96-bit nonce).
///
/// tag = GHASH_H(AAD, ciphertext) XOR SM4_K(J0)
/// where H = SM4_K(0^128) and J0 = nonce || 0x00000001.
///
/// Uses the ghash crate (generic_array 0.14.x). The [u8; 16] ↔ GenericArray
/// bridge: GenericArray::from_slice(&raw) returns &GenericArray<u8, U16>
/// (safe, always 16 bytes), dereferenced to copy.
fn gcm_tag(bc: &Sm4, nonce: &[u8], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    // H = SM4_K(0^128) — the GHASH polynomial evaluation key
    let h_raw = sm4_ecb(bc, [0u8; 16]);

    // E_J0 = SM4_K(J0) — for the final tag XOR
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 1; // counter = 0x00000001
    let e_j0 = sm4_ecb(bc, j0);

    // GHASH(H, AAD || ciphertext || length_block).
    // new_from_slice(&[u8]) avoids importing GenericArray from the deprecated 0.14.x API.
    // update_padded works for the length block (exactly 16 bytes = no padding needed).
    let mut mac = GHash::new_from_slice(&h_raw).expect("SM4 H block is always 16 bytes");
    mac.update_padded(aad);
    mac.update_padded(ciphertext);

    // Length block: [len(AAD) in bits as u64 BE || len(CT) in bits as u64 BE]
    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&((aad.len() as u64) * 8).to_be_bytes());
    len_block[8..].copy_from_slice(&((ciphertext.len() as u64) * 8).to_be_bytes());
    mac.update_padded(&len_block); // exactly 16 bytes → processed as a full block, no padding

    // finalize() → Tag = GenericArray<u8, U16>; deref-coerce to &[u8] for copy.
    let ghash_ga = mac.finalize();
    let mut ghash_out = [0u8; 16];
    ghash_out.copy_from_slice(&ghash_ga);

    // tag = GHASH XOR E_J0
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = ghash_out[i] ^ e_j0[i];
    }
    tag
}
