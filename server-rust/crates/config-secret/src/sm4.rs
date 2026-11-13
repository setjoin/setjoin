//! SM4-GCM (NIST SP 800-38D, 96-bit nonce, 128-bit tag) over audited RustCrypto
//! crates: the `sm4` block cipher (GB/T 32907-2016) and `aes-gcm`'s generic
//! `AesGcm<Cipher, Nonce>` construction (CTR + GHASH, constant-time tag check). No
//! cipher or GHASH code lives here; the frozen Go (`gmsm`) recordings and the GB/T
//! block vector below pin the behaviour.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{aead::consts::U12, AesGcm};
use sm4::Sm4 as Sm4Block;

pub(crate) const TAG_LEN: usize = 16;
pub(crate) const NONCE_LEN: usize = 12;

type Sm4Gcm = AesGcm<Sm4Block, U12>;

pub(crate) struct Sm4(Sm4Gcm);

impl Sm4 {
    /// SM4 takes exactly a 16-byte key; anything else is rejected. The key schedule is
    /// zeroized on drop by the crates' `zeroize` feature.
    pub(crate) fn new(key: &[u8]) -> Option<Self> {
        if key.len() != 16 {
            return None;
        }
        Sm4Gcm::new_from_slice(key).ok().map(Self)
    }
}

/// Returns `ciphertext || tag`.
pub(crate) fn seal(cipher: &Sm4, nonce: &[u8; NONCE_LEN], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    cipher
        .0
        .encrypt(
            nonce.into(),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("SM4-GCM seal cannot fail for a 12-byte nonce")
}

/// Verifies the tag before any plaintext is produced.
pub(crate) fn open(
    cipher: &Sm4,
    nonce: &[u8; NONCE_LEN],
    sealed: &[u8],
    aad: &[u8],
) -> Option<Vec<u8>> {
    cipher
        .0
        .decrypt(nonce.into(), Payload { msg: sealed, aad })
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sm4::cipher::{generic_array::GenericArray, BlockEncrypt};

    // GB/T 32907-2016 appendix A.1: key = plaintext = 0123456789abcdeffedcba9876543210.
    #[test]
    fn standard_block_vector() {
        let key = [
            0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54,
            0x32, 0x10,
        ];
        let c = Sm4Block::new_from_slice(&key).unwrap();
        let mut block = GenericArray::clone_from_slice(&key);
        c.encrypt_block(&mut block);
        assert_eq!(
            block.as_slice(),
            [
                0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e,
                0x42, 0x46
            ]
        );
    }

    #[test]
    fn rejects_wrong_key_length() {
        assert!(Sm4::new(&[0u8; 15]).is_none());
        assert!(Sm4::new(&[0u8; 32]).is_none());
    }

    // The Go-recorded vectors cover byte-exact sealing; here the round trip and tamper
    // handling, including empty and block-boundary lengths.
    #[test]
    fn seal_open_round_trip_and_tamper() {
        let c = Sm4::new(&[7u8; 16]).unwrap();
        let nonce = [9u8; 12];
        for len in [0usize, 1, 15, 16, 17, 40] {
            let pt = vec![0xa5u8; len];
            let sealed = seal(&c, &nonce, &pt, b"aad");
            assert_eq!(open(&c, &nonce, &sealed, b"aad").unwrap(), pt);
            assert!(open(&c, &nonce, &sealed, b"other").is_none());
            let mut bad = sealed.clone();
            *bad.last_mut().unwrap() ^= 1;
            assert!(open(&c, &nonce, &bad, b"aad").is_none());
        }
        assert!(open(&c, &nonce, &[0u8; 15], b"").is_none());
    }
}
