use guard_core::ecdh::generate_keypair;

#[test]
fn test_generate_keypair_returns_non_empty_der() {
    let (sk_der, pk_der) = generate_keypair().expect("generate_keypair");
    assert!(!sk_der.is_empty(), "private key DER must not be empty");
    assert!(!pk_der.is_empty(), "public key DER must not be empty");
    // P-256 private key DER is typically > 100 bytes
    assert!(
        sk_der.len() > 50,
        "private key DER too short: {}",
        sk_der.len()
    );
    // Public key DER (uncompressed) for P-256: 2+65+metadata = ~91 bytes
    assert!(
        pk_der.len() > 50,
        "public key DER too short: {}",
        pk_der.len()
    );
}
