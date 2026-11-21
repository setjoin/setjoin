#![allow(dead_code)]

use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine as _};
use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

pub fn key(seed: u8) -> SigningKey {
    SigningKey::from_slice(&[seed; 32]).unwrap()
}

pub fn jwk_and_jkt(key: &SigningKey) -> (Value, String) {
    let point = key.verifying_key().to_sec1_point(false);
    let x = B64.encode(point.x().unwrap());
    let y = B64.encode(point.y().unwrap());
    let jwk = json!({"kty": "EC", "crv": "P-256", "x": x, "y": y});
    let jkt = setjoin_authz::dpop::thumbprint(&jwk).unwrap();
    (jwk, jkt)
}

pub fn proof_custom(
    key: &SigningKey,
    typ: &str,
    htm: &str,
    htu: &str,
    access: Option<&str>,
    jti: &str,
    iat: i64,
) -> (String, String) {
    let (jwk, jkt) = jwk_and_jkt(key);
    let h = B64.encode(json!({"typ": typ, "alg": "ES256", "jwk": jwk}).to_string());
    let mut payload = json!({
        "htm": htm,
        "htu": htu,
        "iat": iat,
        "jti": jti,
    });
    if let Some(a) = access {
        payload["ath"] = json!(B64.encode(Sha256::digest(a.as_bytes())));
    }
    let p = B64.encode(payload.to_string());
    let sig: Signature = key.sign(format!("{h}.{p}").as_bytes());
    (format!("{h}.{p}.{}", B64.encode(sig.to_bytes())), jkt)
}

pub fn proof(
    key: &SigningKey,
    htm: &str,
    htu: &str,
    access: Option<&str>,
    jti: &str,
) -> (String, String) {
    proof_custom(key, "dpop+jwt", htm, htu, access, jti, now())
}

pub fn bound_access_jwt(secret: &str, uid: i64, email: &str, jti: &str, jkt: &str) -> String {
    let n = now();
    let claims = json!({
        "uid": uid,
        "email": email,
        "typ": "access",
        "jti": jti,
        "cnf": {"jkt": jkt},
        "iss": "mailserver",
        "aud": ["mailserver-gateway"],
        "iat": n - 5,
        "nbf": n - 5,
        "exp": n + 600,
    });
    setjoin_authz::legacy_jwt::sign_hs256(secret.as_bytes(), &claims.to_string())
}

pub fn unbound_access_jwt(secret: &str, uid: i64, email: &str, jti: &str) -> String {
    let n = now();
    let claims = json!({
        "uid": uid,
        "email": email,
        "typ": "access",
        "jti": jti,
        "iss": "mailserver",
        "aud": ["mailserver-gateway"],
        "iat": n - 5,
        "nbf": n - 5,
        "exp": n + 600,
    });
    setjoin_authz::legacy_jwt::sign_hs256(secret.as_bytes(), &claims.to_string())
}

pub fn mfa_pending_jwt(secret: &str, uid: i64, email: &str, jti: &str) -> String {
    let n = now();
    let claims = json!({
        "uid": uid,
        "sub": uid.to_string(),
        "email": email,
        "typ": "mfa_pending",
        "jti": jti,
        "amr": ["pwd"],
        "iss": "mailserver",
        "aud": ["mailserver-gateway"],
        "iat": n - 5,
        "nbf": n - 5,
        "exp": n + 300,
    });
    setjoin_authz::legacy_jwt::sign_hs256(secret.as_bytes(), &claims.to_string())
}

pub fn cnf_jkt(jwt: &str) -> Option<String> {
    let payload = jwt.split('.').nth(1)?;
    let bytes = B64.decode(payload).ok()?;
    let v: Value = serde_json::from_slice(&bytes).ok()?;
    v["cnf"]["jkt"].as_str().map(str::to_owned)
}

pub fn assert_dpop_401(status: u16, www_auth: Option<&str>, body: &str) {
    assert_eq!(
        status, 401,
        "expected 401 dpop_admission, got {status}: {body}"
    );
    assert_eq!(
        www_auth,
        Some("Bearer realm=\"authserver\""),
        "missing WWW-Authenticate on dpop_admission 401: {body}"
    );
    let v: Value = serde_json::from_str(body).expect("json 401 body");
    assert_eq!(v["code"], "dpop_admission", "{v}");
    assert_eq!(v["detail"], "Unauthorized", "{v}");
}
