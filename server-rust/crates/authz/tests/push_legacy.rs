//! #356a: push-seam claim checks for natively verified HS256/SM2 tokens.
//! No database: a refused token fails before any read (`Invalid`); a token
//! whose claims pass reaches the guest lookup, which fails against an
//! unreachable pool (`GuestUnavailable`).
use serde_json::{json, Value};
use setjoin_authz::{
    jwks::Jwks,
    legacy_jwt::{sign_hs256, sign_sm2, LegacyKeys},
    push::{authenticate_detailed, PushAuthError},
};

const SECRET: &[u8] = b"push356a-test-secret-at-least-32-bytes";

fn pem() -> String {
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    f["sm2_pem"].as_str().unwrap().to_owned()
}

fn keys() -> Jwks {
    Jwks::with_fetch(Box::new(|| {
        Box::pin(async { Ok(br#"{"keys":[]}"#.to_vec()) })
    }))
    .with_legacy_keys(
        LegacyKeys::from_pem(
            SECRET,
            &["authserver-hmac-1", "mailserver-drive-native-1"],
            Some(&pem()),
        )
        .unwrap(),
    )
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn claims(extra: Value) -> Value {
    let now = now();
    let mut c = json!({"uid":42,"typ":"access","jti":"push356a","fam":"push356a","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+600});
    if let (Some(map), Some(more)) = (c.as_object_mut(), extra.as_object()) {
        map.extend(more.clone());
    }
    c
}

async fn admitted(token: &str, issuer: &str) -> bool {
    let exec = setjoin_pg::ScopedExecutor::from_dsn("postgres://push356a@127.0.0.1:1/push356a", 1)
        .unwrap();
    match authenticate_detailed(&exec, &keys(), issuer, token).await {
        Err(PushAuthError::GuestUnavailable) => true,
        Err(PushAuthError::Invalid) => false,
        Err(other) => panic!("unexpected refusal {other:?}"),
        Ok(_) => panic!("an unreachable guest lookup cannot admit"),
    }
}

#[tokio::test]
async fn claim_separation_for_hs256_and_sm2() {
    let base = claims(json!({}));
    assert!(admitted(&sign_hs256(SECRET, &base.to_string()), "mailserver").await);
    assert!(admitted(&sign_sm2(&pem(), &base.to_string()).unwrap(), "mailserver").await);
    let now = now();
    let mut missing_iat = base.clone();
    missing_iat.as_object_mut().unwrap().remove("iat");
    let refused = [
        ("wrong audience", claims(json!({"aud":["other-audience"]}))),
        ("wrong issuer", claims(json!({"iss":"other-issuer"}))),
        ("missing iat", missing_iat),
        ("mfa_pending", claims(json!({"typ":"mfa_pending"}))),
        ("refresh", claims(json!({"typ":"refresh"}))),
        ("force_pw_change", claims(json!({"typ":"force_pw_change"}))),
        ("password_reset", claims(json!({"typ":"password_reset"}))),
        ("nbf in the future", claims(json!({"nbf":now+300}))),
        ("expired", claims(json!({"exp":now-1}))),
        ("drive scope", claims(json!({"scp":"drive"}))),
        // F9: integer-only NumericDate for every algorithm (fail closed).
        (
            "fractional exp",
            claims(json!({"exp":(now + 600) as f64 + 0.5})),
        ),
        (
            "fractional iat",
            claims(json!({"iat":(now - 10) as f64 + 0.5})),
        ),
        ("string exp", claims(json!({"exp":(now + 600).to_string()}))),
    ];
    for (name, c) in refused {
        assert!(
            !admitted(&sign_hs256(SECRET, &c.to_string()), "mailserver").await,
            "HS256 {name}"
        );
        assert!(
            !admitted(&sign_sm2(&pem(), &c.to_string()).unwrap(), "mailserver").await,
            "SM2 {name}"
        );
    }
}

/// F10: an empty configured issuer refuses everything, even a token whose iss is empty.
#[tokio::test]
async fn empty_issuer_refuses_every_token() {
    let token = sign_hs256(SECRET, &claims(json!({"iss":""})).to_string());
    assert!(!admitted(&token, "").await);
    let token = sign_hs256(SECRET, &claims(json!({})).to_string());
    assert!(!admitted(&token, "").await);
}
