use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use serde_json::Value;
use setjoin_release_format::{Manifest, Purpose, TrustStore, TrustedKey, VerifyOptions};

fn fixture() -> (Vec<u8>, TrustedKey, VerifyOptions) {
    let v: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/shared-vectors/goldens/release.json"
    ))
    .unwrap();
    let c = v["cases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "signed_manifest")
        .unwrap();
    (
        c["input"]["document"].as_str().unwrap().as_bytes().to_vec(),
        TrustedKey {
            id: c["input"]["key_id"].as_str().unwrap().into(),
            purpose: Purpose::Release,
            public_key: STANDARD_NO_PAD
                .decode(c["input"]["public_key_base64"].as_str().unwrap())
                .unwrap(),
            test_only: false,
            organization_artifact_set: Default::default(),
        },
        VerifyOptions {
            now: chrono::DateTime::parse_from_rfc3339(c["input"]["now"].as_str().unwrap())
                .unwrap()
                .into(),
            minimum_threshold: 1,
            ..Default::default()
        },
    )
}
#[test]
fn verification_refuses_wrong_scope_rollback_equivocation_and_signature_purpose() {
    let (bytes, key, valid) = fixture();
    let store = TrustStore::new(vec![key.clone()], false).unwrap();
    let verified = store.verify_manifest(&bytes, &valid).unwrap();
    let mut options = Vec::new();
    let mut o = valid.clone();
    o.channel = "enterprise".into();
    options.push(o);
    let mut o = valid.clone();
    o.platform = "windows".into();
    options.push(o);
    let mut o = valid.clone();
    o.architecture = "arm64".into();
    options.push(o);
    let mut o = valid.clone();
    o.current_version = "1.0.0".into();
    options.push(o);
    let mut o = valid.clone();
    o.last_metadata_version = 8;
    options.push(o);
    let mut o = valid.clone();
    o.last_metadata_version = 7;
    o.last_metadata_digest = "wrong".into();
    options.push(o);
    let mut o = valid.clone();
    o.now = chrono::DateTime::parse_from_rfc3339("2026-07-31T23:59:59Z")
        .unwrap()
        .into();
    options.push(o);
    for o in options {
        assert!(store.verify_manifest(&bytes, &o).is_err(), "{o:?}");
    }
    let mut same = valid.clone();
    same.last_metadata_version = 7;
    same.last_metadata_digest = verified.digest;
    assert!(store.verify_manifest(&bytes, &same).is_ok());
    for purpose in [
        Purpose::Entitlement,
        Purpose::Recovery,
        Purpose::AuditChain,
        Purpose::OfflineUpdate,
        Purpose::Organization,
    ] {
        let mut other = key.clone();
        other.purpose = purpose;
        assert!(TrustStore::new(vec![other], false)
            .unwrap()
            .verify_manifest(&bytes, &valid)
            .is_err());
    }
    assert!(TrustStore::new(vec![], false)
        .unwrap()
        .verify_manifest(&bytes, &valid)
        .is_err());
    let mut test_key = key.clone();
    test_key.test_only = true;
    assert!(TrustStore::new(vec![test_key.clone()], false).is_err());
    assert!(TrustStore::new(vec![test_key], true)
        .unwrap()
        .verify_manifest(&bytes, &valid)
        .is_ok());
    assert!(TrustStore::new(vec![key.clone(), key], false).is_err());
}

#[test]
fn malformed_inventory_migration_gates_and_registry_are_rejected_before_signing() {
    let (bytes, _, _) = fixture();
    let original: Value = serde_json::from_slice(&bytes).unwrap();
    let mut invalid = Vec::new();
    for (pointer, value) in [
        ("/schema_version", 2.into()),
        ("/schema_to", 179.into()),
        ("/artifacts/0/id", "../outside".into()),
        ("/artifacts/0/sha256", "A".repeat(64).into()),
        ("/artifacts/0/size", 0.into()),
        ("/artifacts/0/target", "core_mailserverd".into()),
        ("/migrations/0/transaction_required", false.into()),
        ("/migrations/0/class", "contract".into()),
        ("/migrations/0/sha256", "0".repeat(64).into()),
        (
            "/health_gates/preflight",
            serde_json::json!(["arbitrary command"]),
        ),
        ("/signing/threshold", 0.into()),
    ] {
        let mut m = original.clone();
        *m.pointer_mut(pointer).unwrap() = value;
        invalid.push(m);
    }
    let mut no_registry = original.clone();
    no_registry["schema_from"] = 183.into();
    no_registry["schema_to"] = 184.into();
    invalid.push(no_registry);
    for m in invalid {
        assert!(Manifest::parse(&serde_json::to_vec(&m).unwrap()).is_err());
    }
    let mut oversized = bytes;
    oversized.extend(vec![b' '; setjoin_release_format::MAX_DOCUMENT_BYTES]);
    assert!(Manifest::parse(&oversized).is_err());
}

#[test]
fn canonical_timestamps_reject_leap_seconds_like_go() {
    let (bytes, _, _) = fixture();
    let mut m: Value = serde_json::from_slice(&bytes).unwrap();
    m["published_at"] = "2026-07-31T23:59:60Z".into();
    assert!(Manifest::parse(&serde_json::to_vec(&m).unwrap()).is_err());
}
