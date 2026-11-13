use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::{pkcs8::EncodePrivateKey, SecretKey};
use serde::Deserialize;

#[derive(Deserialize)]
struct Vector {
    canonical: String,
    signature_base64url: String,
}

#[test]
fn push_approval_cross_end_golden_vector() {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../docs/standards/PUSH_APPROVAL_V1_GOLDEN.json"
    ))
    .unwrap();
    let vector: Vector = serde_json::from_str(&raw).unwrap();
    let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let der = secret.to_pkcs8_der().unwrap();
    let signature =
        guard_core::ecdh::sign_push_approval(der.as_bytes(), vector.canonical.as_bytes()).unwrap();
    assert_eq!(
        URL_SAFE_NO_PAD.encode(signature),
        vector.signature_base64url
    );
}
