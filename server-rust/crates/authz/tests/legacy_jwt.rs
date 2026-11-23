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

const PUSH_CLAIMS: &str = r#"{"uid":42,"typ":"access","iat":1700000000,"exp":4102444800,"iss":"mailserver","aud":["mailserver-gateway"]}"#;

fn fixture_keys() -> Value {
    serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap()
}

fn hmac_with(key: &[u8], header: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let signed = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(PUSH_CLAIMS)
    );
    let tag = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key),
        signed.as_bytes(),
    );
    format!("{signed}.{}", URL_SAFE_NO_PAD.encode(tag.as_ref()))
}

fn sm2_with_header(pem: &str, header: &str) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use sm2::dsa::signature::hazmat::PrehashSigner;
    use sm2::pkcs8::DecodePrivateKey;
    use sm3::Digest;
    let key = if pem.contains("BEGIN EC PRIVATE KEY") {
        sm2::SecretKey::from_sec1_pem(pem).unwrap()
    } else {
        sm2::SecretKey::from_pkcs8_pem(pem).unwrap()
    };
    let signer = sm2::dsa::SigningKey::new("1234567812345678", &key).unwrap();
    let signed = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header),
        URL_SAFE_NO_PAD.encode(PUSH_CLAIMS)
    );
    let sig: sm2::dsa::Signature = signer
        .sign_prehash(&sm3::Sm3::digest(signed.as_bytes()))
        .unwrap();
    format!("{signed}.{}", URL_SAFE_NO_PAD.encode(sig.to_der().as_bytes()))
}

/// SEC1 private key d = 1 (public point = the SM2 generator G, the key the
/// frozen jwtutil vectors use): a valid SM2 key that is not the fixture's.
fn foreign_sm2_pem() -> String {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let mut der = vec![0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20];
    der.extend_from_slice(&[0u8; 31]);
    der.push(1);
    format!(
        "-----BEGIN EC PRIVATE KEY-----\n{}\n-----END EC PRIVATE KEY-----\n",
        STANDARD.encode(der)
    )
}

/// #356a F2/F4: the push seams trust this verifier for HS256/SM2 instead of
/// forwarding by header shape. Confusion and fail-closed cases.
#[test]
fn legacy_signature_layer_fails_closed_on_confusion_and_empty_keys() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let f = fixture_keys();
    let secret = f["secret"].as_str().unwrap().as_bytes();
    let pem = f["sm2_pem"].as_str().unwrap();
    let keys = LegacyKeys::from_pem(
        secret,
        &["authserver-hmac-1", "mailserver-drive-native-1"],
        Some(pem),
    )
    .unwrap();
    // Positive controls: Go's two HMAC kids and the SM2 kid.
    assert!(keys
        .verify_signature(&setjoin_authz::legacy_jwt::sign_hs256(secret, PUSH_CLAIMS))
        .is_some());
    assert!(keys
        .verify_signature(&hmac_with(secret, r#"{"alg":"HS256","kid":"mailserver-drive-native-1"}"#))
        .is_some());
    let sm2 = setjoin_authz::legacy_jwt::sign_sm2(pem, PUSH_CLAIMS).unwrap();
    assert!(keys.verify_signature(&sm2).is_some());
    // Kids outside the configured list.
    for kid in [
        "mailserver-hmac-1",
        "mailserver-mail-attachment-1",
        "authserver-sm2-1",
        "test-es256-1",
        "",
    ] {
        let token = hmac_with(secret, &format!(r#"{{"alg":"HS256","kid":"{kid}"}}"#));
        assert!(keys.verify_signature(&token).is_none(), "kid {kid:?}");
    }
    // Missing, non-string, lowercase and none algorithms; missing kid.
    for header in [
        r#"{"kid":"authserver-hmac-1"}"#,
        r#"{"alg":5,"kid":"authserver-hmac-1"}"#,
        r#"{"alg":"hs256","kid":"authserver-hmac-1"}"#,
        r#"{"alg":"HS256"}"#,
    ] {
        assert!(keys.verify_signature(&hmac_with(secret, header)).is_none(), "{header}");
    }
    let none = format!(
        "{}.{}.",
        URL_SAFE_NO_PAD.encode(r#"{"alg":"none","kid":"authserver-hmac-1"}"#),
        URL_SAFE_NO_PAD.encode(PUSH_CLAIMS)
    );
    assert!(keys.verify_signature(&none).is_none());
    // Duplicated alg member: last member wins, as Go's encoding/json does.
    assert!(keys
        .verify_signature(&hmac_with(secret, r#"{"alg":"ES256","alg":"HS256","kid":"authserver-hmac-1"}"#))
        .is_some());
    assert!(keys
        .verify_signature(&hmac_with(secret, r#"{"alg":"HS256","alg":"SM2","kid":"authserver-hmac-1"}"#))
        .is_none());
    // An HMAC tag presented as SM2; an SM2 signature under an HMAC kid.
    assert!(keys
        .verify_signature(&hmac_with(secret, r#"{"alg":"SM2","kid":"authserver-sm2-1"}"#))
        .is_none());
    assert!(keys
        .verify_signature(&sm2_with_header(pem, r#"{"alg":"SM2","kid":"authserver-hmac-1"}"#))
        .is_none());
    assert!(keys
        .verify_signature(&sm2_with_header(pem, r#"{"alg":"HS256","kid":"authserver-hmac-1"}"#))
        .is_none());
    // HMAC keyed with public key material is never accepted.
    let sm2_point: Vec<u8> = {
        let s = f["sm2_point"].as_str().unwrap();
        (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
    };
    let jwks: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/jmap/test-jwks.json"
    ))
    .unwrap();
    let mut es256_point = vec![4u8];
    for c in ["x", "y"] {
        es256_point.extend(URL_SAFE_NO_PAD.decode(jwks["keys"][0][c].as_str().unwrap()).unwrap());
    }
    for key in [&sm2_point, &es256_point] {
        for kid in ["authserver-hmac-1", "authserver-sm2-1", "test-es256-1"] {
            let token = hmac_with(key, &format!(r#"{{"alg":"HS256","kid":"{kid}"}}"#));
            assert!(keys.verify_signature(&token).is_none(), "{kid}");
        }
    }
    // An SM2 token from a different SM2 key is refused; the same token verifies
    // under that key's own material (proves the foreign key is well formed).
    let foreign = foreign_sm2_pem();
    let foreign_token = setjoin_authz::legacy_jwt::sign_sm2(&foreign, PUSH_CLAIMS).unwrap();
    assert!(keys.verify_signature(&foreign_token).is_none());
    let foreign_keys = LegacyKeys::from_pem(secret, &["authserver-hmac-1"], Some(&foreign)).unwrap();
    assert!(foreign_keys.verify_signature(&foreign_token).is_some());
    // Wrong secret and an extra segment.
    assert!(keys
        .verify_signature(&setjoin_authz::legacy_jwt::sign_hs256(
            b"another-secret-of-at-least-32-bytes!",
            PUSH_CLAIMS
        ))
        .is_none());
    let valid = setjoin_authz::legacy_jwt::sign_hs256(secret, PUSH_CLAIMS);
    assert!(keys.verify_signature(&format!("{valid}.x")).is_none());
    // SM2 without configured SM2 material (standard profile).
    let standard = LegacyKeys::new(secret, &["authserver-hmac-1"], None).unwrap();
    assert!(standard.verify_signature(&sm2).is_none());
    // An empty HMAC key never verifies, even a token signed with that empty key.
    let empty = LegacyKeys::new(b"", &["authserver-hmac-1"], None).unwrap();
    assert!(empty
        .verify_signature(&setjoin_authz::legacy_jwt::sign_hs256(b"", PUSH_CLAIMS))
        .is_none());
}

/// #356a F4: an ES256 header resolves only through the JWKS kid. (The HMAC tag
/// also fails the ES256 length check; the key-material cases above carry the
/// confusion proof.)
#[tokio::test]
async fn es256_header_never_falls_back_to_the_hmac_secret() {
    let secret = b"idlogin1-fixture-secret-at-least-32-bytes";
    let keys = setjoin_authz::jwks::Jwks::with_fetch(Box::new(|| {
        Box::pin(async { Ok(br#"{"keys":[]}"#.to_vec()) })
    }))
    .with_legacy_keys(LegacyKeys::new(secret, &["authserver-hmac-1"], None).unwrap());
    let token = hmac_with(secret, r#"{"alg":"ES256","kid":"authserver-hmac-1"}"#);
    assert!(
        setjoin_authz::token::verify(&token, "mailserver", 1_800_000_000.0, &keys)
            .await
            .is_none()
    );
}
