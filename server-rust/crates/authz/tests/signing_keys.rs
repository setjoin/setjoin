use serde_json::Value;
use setjoin_authz::signing_keys::KeySet;
use setjoin_pg::ScopedExecutor;
fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[tokio::test]
async fn postgres_go_key_custody_and_tokens_survive_swap() {
    let dsn = std::env::var("TEST_DB_DSN").expect("TEST_DB_DSN required");
    let db = setjoin_conformance::harness::Db::for_case("IDLOGIN1-signing-keys").unwrap();
    let fixture_lock = db.connect().await.unwrap();
    fixture_lock
        .query_one(
            "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
            &[],
        )
        .await
        .unwrap();
    let f: Value = serde_json::from_str(
        &std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/conformance/identity-login/keys.json"
        ))
        .unwrap(),
    )
    .unwrap();
    let exec = ScopedExecutor::from_dsn(&dsn, 2).unwrap();
    // Install only this private DB's recorded key. This fixture is disposable.
    let kid = f["kid"].as_str().unwrap();
    let envelope = hex(f["envelope"].as_str().unwrap());
    exec.protocol_statement("DELETE FROM signing_keys", &[])
        .await
        .unwrap();
    exec.protocol_statement("INSERT INTO signing_keys(kid,alg,public_jwk,private_key_enc,status) VALUES($1,'ES256',$2::text::jsonb,$3,'active')",&[(&kid,setjoin_pg::Type::TEXT),(&f["jwks"]["keys"][0].to_string(),setjoin_pg::Type::TEXT),(&envelope,setjoin_pg::Type::BYTEA)]).await.unwrap();
    let keys = KeySet::load(
        &exec,
        f["secret"].as_str().unwrap().as_bytes(),
        setjoin_config_secret::CryptoProfile::Standard,
    )
    .await
    .unwrap();
    assert_eq!(keys.jwks(), f["jwks"]);
    let tok = f["tokens"]["ES256"].as_str().unwrap();
    assert!(keys
        .validate(tok, "mailserver", f["clock"].as_f64().unwrap())
        .is_some());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let claims = format!(
        r#"{{"uid":42,"email":"fixture@example.test","typ":"access","iat":{now},"exp":{},"iss":"mailserver","aud":["mailserver-gateway"]}}"#,
        now + 3600
    );
    let signed = keys.sign(&claims).unwrap();
    assert!(keys.validate(&signed, "mailserver", now as f64).is_some());
    if let Ok(path) = std::env::var("GOFREE_RUST_TOKENS") {
        std::fs::write(path,serde_json::json!({"ES256":signed,"HS256":setjoin_authz::legacy_jwt::sign_hs256(f["secret"].as_str().unwrap().as_bytes(),&claims)}).to_string()).unwrap();
    }
    assert!(KeySet::load(
        &exec,
        b"wrong-secret",
        setjoin_config_secret::CryptoProfile::Standard
    )
    .await
    .is_err());
}

#[tokio::test]
async fn concurrent_startup_keeps_retiring_go_keys_and_retired_keys_drop_out() {
    let dsn = std::env::var("TEST_DB_DSN").expect("TEST_DB_DSN required");
    let db = setjoin_conformance::harness::Db::for_case("IDLOGIN1-signing-keys").unwrap();
    let fixture_lock = db.connect().await.unwrap();
    fixture_lock
        .query_one(
            "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
            &[],
        )
        .await
        .unwrap();
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let exec = ScopedExecutor::from_dsn(&dsn, 4).unwrap();
    let secret = f["secret"].as_str().unwrap().as_bytes();
    let old = f["kid"].as_str().unwrap();
    let envelope = hex(f["envelope"].as_str().unwrap());
    exec.protocol_statement("DELETE FROM signing_keys", &[])
        .await
        .unwrap();
    exec.protocol_statement("INSERT INTO signing_keys(kid,alg,public_jwk,private_key_enc,status) VALUES($1,'ES256',$2::text::jsonb,$3,'active')",&[(&old,setjoin_pg::Type::TEXT),(&f["jwks"]["keys"][0].to_string(),setjoin_pg::Type::TEXT),(&envelope,setjoin_pg::Type::BYTEA)]).await.unwrap();

    exec.protocol_statement(
        "UPDATE signing_keys SET status='retiring' WHERE kid=$1",
        &[(&old, setjoin_pg::Type::TEXT)],
    )
    .await
    .unwrap();
    let (a, b) = tokio::join!(
        KeySet::load(
            &exec,
            secret,
            setjoin_config_secret::CryptoProfile::Standard
        ),
        KeySet::load(
            &exec,
            secret,
            setjoin_config_secret::CryptoProfile::Standard
        )
    );
    let a = a.unwrap();
    let b = b.unwrap();
    assert_eq!(a.active_kid(), b.active_kid());
    assert_ne!(a.active_kid(), old);
    assert!(a
        .validate(
            f["tokens"]["ES256"].as_str().unwrap(),
            "mailserver",
            f["clock"].as_f64().unwrap()
        )
        .is_some());
    exec.protocol_statement(
        "UPDATE signing_keys SET status='retired' WHERE kid=$1",
        &[(&old, setjoin_pg::Type::TEXT)],
    )
    .await
    .unwrap();
    let retired = KeySet::load(
        &exec,
        secret,
        setjoin_config_secret::CryptoProfile::Standard,
    )
    .await
    .unwrap();
    assert!(retired
        .validate(
            f["tokens"]["ES256"].as_str().unwrap(),
            "mailserver",
            f["clock"].as_f64().unwrap()
        )
        .is_none());
    assert!(!retired.jwks()["keys"]
        .as_array()
        .unwrap()
        .iter()
        .any(|k| k["kid"] == old));
    let generated = a.active_kid().to_owned();
    exec.protocol_statement(
        "DELETE FROM signing_keys WHERE kid=$1",
        &[(&generated, setjoin_pg::Type::TEXT)],
    )
    .await
    .unwrap();
    exec.protocol_statement(
        "UPDATE signing_keys SET status='active' WHERE kid=$1",
        &[(&old, setjoin_pg::Type::TEXT)],
    )
    .await
    .unwrap();
}
