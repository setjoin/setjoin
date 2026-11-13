//! The public stored-credential verifier consumes bytes actually returned by Go.
use serde_json::Value;
fn hex(raw: &str) -> Vec<u8> {
    (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap())
        .collect()
}
#[test]
fn accepts_go_stored_cose_and_rejects_altered_signatures() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../../tests/conformance/identity-webauthn/vectors.json"
    ))
    .unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let key = hex(case["key"].as_str().unwrap());
        for name in ["success", "regression", "zero"] {
            let v = &case["assertions"][name];
            let message = hex(v["message"].as_str().unwrap());
            let mut signature = hex(v["signature"].as_str().unwrap());
            assert!(
                setjoin_identity::webauthn::verify_stored_signature(&key, &message, &signature),
                "Go algorithm{}",
                case["algorithm"]
            );
            signature[0] ^= 1;
            assert!(!setjoin_identity::webauthn::verify_stored_signature(
                &key, &message, &signature
            ));
        }
    }
    assert!(!setjoin_identity::webauthn::verify_stored_signature(
        &[0xa0],
        b"message",
        b"signature"
    ));
}
#[test]
fn opens_go_cookie_transport_and_rejects_tampering() {
    let keys: Value = serde_json::from_str(include_str!(
        "../../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/conformance/identity-webauthn/cookies.json"
    ))
    .unwrap();
    let codec =
        setjoin_identity::webauthn::CookieCipher::new(keys["secret"].as_str().unwrap().as_bytes());
    for v in fixture["cases"].as_array().unwrap() {
        let wire = v["cookie"].as_str().unwrap();
        assert_eq!(
            codec.open(wire).unwrap(),
            v["plaintext"].as_str().unwrap().as_bytes()
        );
        let mut altered = wire.as_bytes().to_vec();
        altered[0] = if altered[0] == b'A' { b'B' } else { b'A' };
        assert!(codec.open(std::str::from_utf8(&altered).unwrap()).is_none());
    }
}
#[test]
fn extended_rsa_and_go_auto_salt_verify() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/conformance/identity-webauthn/extra-vectors.json"
    ))
    .unwrap();
    for case in fixture["cases"].as_array().unwrap() {
        let key = hex(case["key"].as_str().unwrap());
        let v = &case["assertions"]["zero"];
        assert!(
            setjoin_identity::webauthn::verify_stored_signature(
                &key,
                &hex(v["message"].as_str().unwrap()),
                &hex(v["signature"].as_str().unwrap())
            ),
            "alg{}",
            case["algorithm"]
        );
    }
}

#[test]
fn rejects_login_signature_from_512_bit_rs256_credential() {
    use serde_cbor_2::Value as C;
    // Valid OpenSSL-generated RS256 signature; no private key is retained.
    // Go 1.26 crypto/rsa refuses this key because its modulus is below 1024 bits.
    let modulus = hex(concat!(
        "b317bfd48385eedc2a040aea05f67bb4c56aa3fb3533ff729fe1866612770a26a",
        "522563f58c8ed392f2c4d6f5853f13443f9188b7530104cad0738d8e15a1077"
    ));
    let key = serde_cbor_2::to_vec(&C::Map(
        [
            (C::Integer(1), C::Integer(3)),
            (C::Integer(3), C::Integer(-257)),
            (C::Integer(-1), C::Bytes(modulus)),
            (C::Integer(-2), C::Bytes(vec![1, 0, 1])),
        ]
        .into_iter()
        .collect(),
    ))
    .unwrap();
    let signature = hex(concat!(
        "14688e9cbddc8c2483a30f3173d84afe106ddbf3eed48fea7a900cb07534a5e811",
        "4183d3c5e238272df35f087ab1d31bb146095e3389cf7e2f9c5a97ffda1415"
    ));
    assert!(!setjoin_identity::webauthn::verify_stored_signature(
        &key,
        b"WebAuthn undersized RSA assertion regression",
        &signature,
    ));
}
