//! Public stored-format seam, replaying frozen Go vectors unchanged.
#[test]
fn go_recorded_password_formats() {
    let corpus: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/shared-vectors/goldens/pwhash.json"
    ))
    .unwrap();
    for case in corpus["cases"].as_array().unwrap() {
        assert_eq!(
            setjoin_authz::password::verify(
                case["input"]["hash"].as_str().unwrap(),
                case["input"]["password"].as_str().unwrap()
            ),
            case["output"]["password_valid"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}
#[test]
fn standard_upgrade_keeps_go_bcrypt_version() {
    let hash = "$2b$04$A5ox0PnnBJzfk5U44aU2f.rG2Qap1gfazGCHrnK/6M21ieIW2Ty8G";
    let upgraded = setjoin_authz::password::standard_upgrade(hash, "fixture-password").unwrap();
    assert!(
        upgraded.starts_with("$2a$10$"),
        "Go GenerateFromPassword uses 2a/10"
    );
}
