//! The frozen shared/jwtutil recordings are the oracle, including SM2's raw
//! SM3 prehash (NOT the usual SM2 ZA-prefixed message signature).
use serde_json::Value;
use setjoin_authz::legacy_jwt::LegacyKeys;

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn frozen_go_hs256_and_sm2_signature_vectors() {
    let doc: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/shared-vectors/goldens/jwtutil.json"
    ))
    .unwrap();
    for case in doc["cases"].as_array().unwrap() {
        let input = &case["input"];
        let token = input["token"].as_str().unwrap();
        let header: Value = {
            use base64::Engine;
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(token.split('.').next().unwrap())
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or(Value::Null)
        };
        if header["alg"] == "ES256" {
            continue;
        }
        let mut point = vec![4];
        point.extend(hex(input["sm2_public_x"].as_str().unwrap()));
        point.extend(hex(input["sm2_public_y"].as_str().unwrap()));
        let keys = LegacyKeys::new(
            input["secret"].as_str().unwrap().as_bytes(),
            &[input["kid"].as_str().unwrap()],
            Some(&point),
        )
        .unwrap();
        let valid = keys
            .validate(
                token,
                input["issuer"].as_str().unwrap(),
                input["audience"].as_str().unwrap(),
                1_800_000_000.0,
            )
            .is_some();
        assert_eq!(
            valid,
            case["output"]["valid"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}

#[tokio::test]
async fn shared_access_admission_verifies_hs256_without_jwks_io() {
    let secret = b"idlogin1-fixture-secret-at-least-32-bytes";
    let keys = setjoin_authz::jwks::Jwks::with_fetch(Box::new(|| {
        Box::pin(async { panic!("HS256 must not fetch a JWKS") })
    }))
    .with_legacy_keys(LegacyKeys::new(secret, &["authserver-hmac-1"], None).unwrap());
    let token = setjoin_authz::legacy_jwt::sign_hs256(
        secret,
        r#"{"uid":42,"email":"fixture@example.test","typ":"access","iat":1700000000,"exp":4102444800,"iss":"mailserver","aud":["mailserver-gateway"]}"#,
    );
    assert!(
        setjoin_authz::token::verify(&token, "mailserver", 1_800_000_000.0, &keys)
            .await
            .is_some()
    );
}

#[test]
fn postgres_key_recording_sm2_pem_and_rust_issuance() {
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let keys = LegacyKeys::from_pem(
        f["secret"].as_str().unwrap().as_bytes(),
        &["authserver-hmac-1"],
        Some(f["sm2_pem"].as_str().unwrap()),
    )
    .unwrap();
    assert!(keys
        .validate(
            f["tokens"]["SM2"].as_str().unwrap(),
            "mailserver",
            "mailserver-gateway",
            f["clock"].as_f64().unwrap()
        )
        .is_some());
    let signed=setjoin_authz::legacy_jwt::sign_sm2(f["sm2_pem"].as_str().unwrap(),r#"{"uid":42,"email":"fixture@example.test","typ":"access","exp":4102444800,"iss":"mailserver","aud":["mailserver-gateway"]}"#).unwrap();
    assert!(keys
        .validate(&signed, "mailserver", "mailserver-gateway", 1_800_000_000.0)
        .is_some());
    if let Ok(path) = std::env::var("GOFREE_RUST_SM2_TOKEN") {
        std::fs::write(path, signed).unwrap();
    }
}
