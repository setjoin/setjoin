use guard_core::vault::kdf::{derive_key, KdfParams};

#[test]
fn test_derive_key_returns_32_bytes() {
    let params = KdfParams::default();
    let key = derive_key("test-passphrase", &params).expect("derive_key");
    assert_eq!(key.len(), 32, "derived key must be 32 bytes");
}

#[test]
fn test_kdf_params_default() {
    let params = KdfParams::default();
    assert_eq!(params.m_cost, 65536);
    assert_eq!(params.t_cost, 3);
    assert_eq!(params.p_cost, 4);
    assert!(!params.salt.is_empty(), "salt must be generated");
    // Salt is hex-encoded 16 bytes = 32 hex chars
    assert_eq!(
        params.salt.len(),
        32,
        "salt must be 32 hex chars (16 bytes)"
    );
}

#[test]
fn test_kdf_params_serialization() {
    let params = KdfParams::default();
    let json = serde_json::to_string(&params).expect("serialize");
    let deserialized: KdfParams = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(deserialized.m_cost, params.m_cost);
    assert_eq!(deserialized.t_cost, params.t_cost);
    assert_eq!(deserialized.p_cost, params.p_cost);
    assert_eq!(deserialized.salt, params.salt);
}
