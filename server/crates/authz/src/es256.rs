//! ES256 (ECDSA P-256 / SHA-256, RFC 7518 §3.4) verification on `ring`.
//!
//! A [`VerifyingKey`] is a JWKS public key whose point was validated once,
//! when the JWKS was parsed (on the curve, coordinates reduced below the
//! field prime): an invalid JWK is skipped at parse time, as before, instead
//! of failing every token later. Verification takes the fixed 64-byte `r||s`
//! JWS signature; `ring` rejects `r` or `s` outside `[1, n-1]` and accepts
//! high-S signatures, as Go's `crypto/ecdsa` does.
//!
//! All inputs here are public (key, signature, signing input); nothing in
//! this module handles secret material.

use ring::agreement::{self, EphemeralPrivateKey, ECDH_P256};
use ring::rand::SystemRandom;
use ring::signature::{UnparsedPublicKey, ECDSA_P256_SHA256_FIXED};

/// Length of a JWS ES256 signature (`r || s`, 32 bytes each).
pub const SIGNATURE_LEN: usize = 64;

/// A validated P-256 public key, kept as its uncompressed SEC1 point.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifyingKey([u8; 65]);

impl std::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VerifyingKey(P-256)")
    }
}

impl VerifyingKey {
    /// The key at JWK affine coordinates `x` and `y` (32 bytes each), or
    /// `None` when they are not a valid P-256 public point.
    pub fn from_affine(x: &[u8], y: &[u8]) -> Option<Self> {
        if x.len() != 32 || y.len() != 32 {
            return None;
        }
        let mut point = [0u8; 65];
        point[0] = 0x04;
        point[1..33].copy_from_slice(x);
        point[33..].copy_from_slice(y);
        Self::from_sec1(&point)
    }

    /// The key from an uncompressed SEC1 point (`0x04 || x || y`).
    ///
    /// `ring` exposes its public-point validation (the same
    /// `parse_uncompressed_point` its ECDSA verifier runs) through ECDH peer
    /// keys, so an ephemeral agreement with the point is the parse-time
    /// check; the agreed value is discarded.
    pub fn from_sec1(point: &[u8]) -> Option<Self> {
        let point: [u8; 65] = point.try_into().ok()?;
        if point[0] != 0x04 {
            return None;
        }
        let ephemeral = EphemeralPrivateKey::generate(&ECDH_P256, &SystemRandom::new()).ok()?;
        let peer = agreement::UnparsedPublicKey::new(&ECDH_P256, &point);
        agreement::agree_ephemeral(ephemeral, &peer, |_| ()).ok()?;
        Some(Self(point))
    }

    /// The uncompressed SEC1 point (`0x04 || x || y`).
    pub fn sec1(&self) -> &[u8; 65] {
        &self.0
    }

    /// The affine `x` coordinate (32 bytes, big-endian).
    pub fn x(&self) -> &[u8] {
        &self.0[1..33]
    }

    /// The affine `y` coordinate (32 bytes, big-endian).
    pub fn y(&self) -> &[u8] {
        &self.0[33..]
    }

    /// Whether `signature` (64-byte `r || s`) is a valid ES256 signature
    /// of `message` under this key.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        signature.len() == SIGNATURE_LEN
            && UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, &self.0)
                .verify(message, signature)
                .is_ok()
    }
}
