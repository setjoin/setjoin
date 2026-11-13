/// SM4 gmsm interop gate — two arms:
///   (a) GM/T 0002-2012 block-cipher KAT: verifies the RustCrypto sm4 crate
///       produces the standard single-block output byte-for-byte.
///   (b) gmsm golden oracle: sm4_seal bytes MUST equal Go gmsm output;
///       sm4_open of those bytes MUST recover the original plaintext.
///
/// gmsm is the Go ORACLE only — NOT linked into Rust.
/// See shared/cryptokey/sm4_vectors.go for the Go oracle source.
use offline_core::cipher::{sm4_open, sm4_seal};
use serde::Deserialize;

fn from_hex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("golden hex must be valid")
}

// ── (a) GM/T 0002-2012 block-cipher KAT ──────────────────────────────────────

/// Verifies the RustCrypto sm4 block cipher against the GM/T 0002-2012
/// Appendix B test vector (single ECB block).
/// Key:       0123456789ABCDEFFEDCBA9876543210
/// Plaintext: 0123456789ABCDEFFEDCBA9876543210
/// Expected:  681EDF34D206965E86B3E94F536E4246
///
/// sm4 0.6.x uses cipher 0.5.x: BlockCipherEncrypt (was BlockEncrypt), Array (was GenericArray).
#[test]
fn gmt0002_sm4_kat() {
    use sm4::cipher::{Array, BlockCipherEncrypt, KeyInit};
    use sm4::Sm4;

    let key: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let pt: [u8; 16] = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ];
    let expected: [u8; 16] = [
        0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42,
        0x46,
    ];

    let cipher = Sm4::new_from_slice(&key).expect("16-byte key");
    let mut block: Array<u8, _> = Array(pt);
    cipher.encrypt_block(&mut block);
    assert_eq!(
        block.0, expected,
        "GM/T 0002 SM4 block KAT: got {:02x?}, want {:02x?}",
        block.0, expected,
    );
}

// ── (b) gmsm golden oracle: byte-for-byte match ───────────────────────────────

#[derive(Deserialize)]
struct GoldenVec {
    key: String,
    nonce: String,
    plaintext: String,
    aad: String,
    ciphertext_tag: String,
}

/// The gmsm Go oracle sealed these vectors deterministically.
/// Rust sm4_seal MUST produce the identical bytes (verify-crypto-with-oracle).
/// sm4_open of the golden bytes MUST recover the original plaintext.
#[test]
fn sm4_matches_gmsm_golden_both_directions() {
    let raw = include_str!("sm4_vectors.golden.json");
    let vs: Vec<GoldenVec> = serde_json::from_str(raw).expect("golden JSON must be valid");
    assert!(
        !vs.is_empty(),
        "no golden vectors — run: WRITE_GOLDEN=1 go test ./cryptokey/ -run TestEmitSM4Golden"
    );

    for (i, v) in vs.iter().enumerate() {
        let key = from_hex(&v.key);
        let nonce = from_hex(&v.nonce);
        let pt = from_hex(&v.plaintext);
        let aad = from_hex(&v.aad);
        let expected_ct = from_hex(&v.ciphertext_tag);

        // seal direction: Rust bytes must equal gmsm oracle exactly
        let got = sm4_seal(&key, &nonce, &pt, &aad)
            .unwrap_or_else(|e| panic!("vector {i}: sm4_seal failed: {e}"));
        assert_eq!(
            expected_ct, got,
            "vector {i}: seal bytes must match gmsm oracle\n  got:  {:02x?}\n  want: {:02x?}",
            got, expected_ct,
        );

        // open direction: Rust opens gmsm-sealed bytes → original plaintext
        let out = sm4_open(&key, &nonce, &expected_ct, &aad)
            .unwrap_or_else(|e| panic!("vector {i}: sm4_open failed: {e}"));
        assert_eq!(pt, out, "vector {i}: sm4_open must recover plaintext");
    }
}
