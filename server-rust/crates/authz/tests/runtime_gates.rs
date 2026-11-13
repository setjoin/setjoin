use serde_json::{json, Value};
use setjoin_authz::{
    jwks::Jwks,
    legacy_jwt::{sign_hs256, LegacyKeys},
    runtime::Proof,
};
fn keys() -> Jwks {
    Jwks::with_fetch(Box::new(|| {
        Box::pin(async { panic!("HS256 must not fetch JWKS") })
    }))
    .with_legacy_keys(
        LegacyKeys::new(
            b"authzgates-test-secret-32-bytes-long",
            &["authserver-hmac-1"],
            None,
        )
        .unwrap(),
    )
}
async fn proof(device: Value) -> Proof {
    let claims = json!({"uid":42,"typ":"access","iat":1700000000,"exp":4102444800i64,"iss":"mailserver","aud":["mailserver-gateway"],"device":device});
    let token = sign_hs256(b"authzgates-test-secret-32-bytes-long", &claims.to_string());
    Proof::verify(&token, "mailserver", 1_800_000_000.0, &keys(), false)
        .await
        .unwrap()
}
#[tokio::test]
async fn device_compliance_requires_a_claim_and_denies_wipe_or_quarantine() {
    for(device,expected)in[
  (Value::Null,Some(("device_compliance_unverifiable","Device compliance could not be verified from this token. Sign in again from your device."))),
  (json!({"trust_tier":"quarantined"}),Some(("Forbidden","Device is quarantined. Check compliance status in device settings."))),
  (json!({"trust_tier":"compliant","wipe_requested":true}),Some(("Forbidden","Device has been wiped. Contact your administrator."))),
  (json!({"trust_tier":"compliant"}),None),
 ]{assert_eq!(proof(device).await.compliance_denial(),expected);}
}

#[tokio::test]
async fn malformed_signed_device_claim_does_not_gain_runtime_admission() {
    let claims = json!({"uid":42,"typ":"access","iat":1700000000,"exp":4102444800i64,"iss":"mailserver","aud":["mailserver-gateway"],"device":{"trust_tier":"compliant","wipe_requested":"false"}});
    let token = sign_hs256(b"authzgates-test-secret-32-bytes-long", &claims.to_string());
    assert!(
        Proof::verify(&token, "mailserver", 1_800_000_000.0, &keys(), false)
            .await
            .is_none()
    );
    assert!(
        setjoin_authz::token::verify(&token, "mailserver", 1_800_000_000.0, &keys())
            .await
            .is_none()
    );
}

/// Owner-approved security fix 2026-11-05 (#499): the runtime verifier binds the
/// proof to the access token through `ath`. The frozen WebCrypto vector carried no
/// `ath` and was accepted by Go; it is now refused (divergence record: authzgates).
#[test]
fn dpop_proof_binds_access_token_uri_and_rejects_replay() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64, Engine};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    use sha2::{Digest, Sha256};
    let key = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let point = key.verifying_key().to_sec1_point(false);
    let jwk = json!({"kty":"EC","crv":"P-256","x":B64.encode(point.x().unwrap()),"y":B64.encode(point.y().unwrap())});
    let jkt = setjoin_authz::dpop::thumbprint(&jwk).unwrap();
    let make = |jti: &str, ath: Option<&str>| {
        let h = B64.encode(json!({"typ":"dpop+jwt","alg":"ES256","jwk":jwk}).to_string());
        let mut claims = json!({"htm":"POST","htu":"https://mail.example.com/jmap","iat":1751500000,"jti":jti});
        if let Some(ath) = ath {
            claims["ath"] = json!(B64.encode(Sha256::digest(ath.as_bytes())));
        }
        let p = B64.encode(claims.to_string());
        let sig: Signature = key.sign(format!("{h}.{p}").as_bytes());
        format!("{h}.{p}.{}", B64.encode(sig.to_bytes()))
    };
    let verify = |proof: &str, uri: &str, token: &str, cache: &setjoin_authz::dpop::ReplayCache| {
        setjoin_authz::dpop::verify(proof, "POST", uri, &jkt, 1751500000.0, cache, token)
    };
    let uri = "https://mail.example.com/jmap";
    let cache = setjoin_authz::dpop::ReplayCache::default();
    let bound = make("j1", Some("access-token-1"));
    assert!(verify(&bound, uri, "access-token-1", &cache));
    assert!(!verify(&bound, uri, "access-token-1", &cache), "replay");
    let fresh = setjoin_authz::dpop::ReplayCache::default();
    assert!(!verify(&make("j2", None), uri, "access-token-1", &fresh), "a proof without ath must be refused");
    assert!(!verify(&make("j3", Some("another-token")), uri, "access-token-1", &fresh), "ath of a different token");
    assert!(!verify(&make("j4", Some("access-token-1")), "https://mail.example.com/other", "access-token-1", &fresh), "uri binding");
}

#[test]
fn frozen_go_country_fixture_requires_cache_pin_but_accepts_operator_authority() {
    use setjoin_authz::geoip::CountryDb;
    let bytes = include_bytes!("../../../tests/conformance/authzgates/us.mmdb").to_vec();
    let db = CountryDb::from_bytes(bytes.clone(), false, "").unwrap();
    assert_eq!(db.country("203.0.113.5".parse().unwrap()), "US");
    assert!(CountryDb::from_bytes(bytes.clone(), true, "").is_err());
    assert!(CountryDb::from_bytes(bytes, false, &"00".repeat(32)).is_err());
}

/// Owner-approved security fix 2026-11-05 (#499): the replay cache keeps every entry
/// for the whole proof window; a full cache refuses new proofs instead of evicting
/// live ones, and entries expire only after the retention period.
#[test]
fn dpop_replay_cache_refuses_new_proofs_instead_of_evicting_live_ones() {
    let cache = setjoin_authz::dpop::ReplayCache::with_capacity(3);
    for (i, jti) in ["a", "b", "c"].iter().enumerate() {
        assert!(cache.add(jti, 1000.0 + i as f64));
    }
    assert!(!cache.add("d", 1010.0), "a full cache must refuse a new proof");
    assert!(!cache.add("a", 1011.0), "the oldest live proof must still be a replay");
    assert!(cache.add("d", 1400.0), "expired entries free room");
}
