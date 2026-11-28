use setjoin_conformance::shared_vectors::load_vectors;

#[test]
fn loads_cases_with_byte_exact_expected_values() {
    let data = br#"{"contract":"webhook","cases":[{"name":"known","input":{"body":"abc"},"output":{"signature":"00Ab"}}]}"#;
    let vectors = load_vectors(data, "webhook").unwrap();
    assert_eq!(vectors[0].name, "known");
    assert_eq!(vectors[0].input["body"], "abc");
    assert_eq!(vectors[0].output["signature"], "00Ab");
}

#[test]
fn rejects_empty_or_ambiguous_recordings() {
    assert!(load_vectors(br#"{"contract":"webhook","cases":[]}"#, "webhook").is_err());
    assert!(load_vectors(br#"{"contract":"webhook","cases":[{"name":"same","input":{},"output":{}},{"name":"same","input":{},"output":{}}]}"#, "webhook").is_err());
}

#[test]
fn all_go_recorded_contracts_load_for_family_tests() {
    for contract in [
        "pwhash",
        "cryptokey",
        "jwtutil",
        "reducererr",
        "clientip",
        "webhook",
        "release",
        "toggle",
        "configsecret",
    ] {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("shared-vectors/goldens")
            .join(format!("{contract}.json"));
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let cases = load_vectors(&bytes, contract).unwrap();
        assert!(
            cases.len() >= 3,
            "{contract} needs normal, edge and invalid cases"
        );
    }
}
