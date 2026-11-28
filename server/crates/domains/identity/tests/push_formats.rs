//! Device-facing cryptographic interoperability vectors, independent of HTTP.
#[test]
fn accepts_the_existing_cross_client_approval_vector_and_rejects_tampering() {
    let vector: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../docs/standards/PUSH_APPROVAL_V1_GOLDEN.json"
    ))
    .unwrap();
    let key = data_encoding::HEXLOWER_PERMISSIVE
        .decode(vector["public_key_hex"].as_str().unwrap().as_bytes())
        .unwrap();
    let canonical = vector["canonical"].as_str().unwrap().as_bytes();
    let signature = vector["signature_base64url"].as_str().unwrap();
    assert!(setjoin_identity::push::verify_approval(
        &key, canonical, signature
    ));
    assert!(!setjoin_identity::push::verify_approval(
        &key,
        b"tampered",
        signature
    ));
    assert!(!setjoin_identity::push::verify_approval(
        &key,
        canonical,
        &format!("{signature}=")
    ));
    assert!(!setjoin_identity::push::verify_approval(
        &key[..64],
        canonical,
        signature
    ));
}
