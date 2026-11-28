//! RFC 6238 SHA-1 vectors projected to frozen Go's six-digit profile.
#[test]
fn accepts_rfc6238_codes_only_within_the_go_time_window() {
    let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
    for (time, code) in [
        (59, "287082"),
        (1111111109, "081804"),
        (1111111111, "050471"),
        (1234567890, "005924"),
        (2000000000, "279037"),
        (20000000000, "353130"),
    ] {
        assert!(setjoin_identity::totp::validate(code, secret, time));
        assert!(!setjoin_identity::totp::validate(code, secret, time + 90));
    }
    assert!(!setjoin_identity::totp::validate("28708", secret, 59));
    assert!(!setjoin_identity::totp::validate(
        "287082",
        "invalid secret!",
        59
    ));
}

#[test]
fn replays_frozen_go_public_validator_vectors() {
    let doc: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/conformance/identity-mfa/totp-vectors.json"
    ))
    .unwrap();
    for case in doc["cases"].as_array().unwrap() {
        assert_eq!(
            setjoin_identity::totp::validate(
                case["code"].as_str().unwrap(),
                case["secret"].as_str().unwrap(),
                case["unix"].as_i64().unwrap()
            ),
            case["accepted"].as_bool().unwrap(),
            "{case}"
        );
    }
}

#[test]
fn replays_go_stored_secret_encoding_vectors() {
    let doc: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../tests/conformance/identity-mfa/totp-secret-vectors.json"
    ))
    .unwrap();
    for case in doc["cases"].as_array().unwrap() {
        assert_eq!(
            setjoin_identity::totp::code(
                case["secret"].as_str().unwrap(),
                case["unix"].as_i64().unwrap()
            )
            .as_deref(),
            case["code"].as_str(),
            "{case}"
        );
    }
}
