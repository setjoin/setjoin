mod common;
use http_body_util::BodyExt;
use hyper::Request;
use serde_json::{json, Value};
use setjoin_auth::{body, AuthServer};

#[tokio::test]
async fn password_policy_defaults_match_go() {
    let dsn = std::env::var("TEST_DB_DSN").expect("TEST_DB_DSN required");
    let exec = setjoin_pg::ScopedExecutor::from_dsn(&dsn, 2).unwrap();
    let server = AuthServer::new(exec);
    let resp = server
        .handle(
            Request::get("/auth/password-policy")
                .body(body(""))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), 200);
    let b = resp.into_body().collect().await.unwrap().to_bytes();
    let value: Value = serde_json::from_slice(&b).unwrap();
    assert_eq!(
        value,
        json!({"maxBytes":72,"minLength":8,"requireDigit":true,"requireLowercase":true,"requireSpecial":true,"requireUppercase":true})
    );
}

#[tokio::test]
async fn jwks_publishes_the_existing_go_postgres_key() {
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let dsn = std::env::var("TEST_DB_DSN").unwrap();
    let db = setjoin_conformance::harness::Db::for_case("IDLOGIN1-JWKS").unwrap();
    let fixture_lock = db.connect().await.unwrap();
    fixture_lock
        .query_one(
            "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
            &[],
        )
        .await
        .unwrap();
    common::signing_key(&fixture_lock).await;
    let exec = setjoin_pg::ScopedExecutor::from_dsn(&dsn, 2).unwrap();
    let config = setjoin_auth::Config::for_secret(f["secret"].as_str().unwrap().to_owned());
    let server = AuthServer::load(exec, config).await.unwrap();
    let resp = server
        .handle(
            Request::get("/.well-known/jwks.json")
                .body(body(""))
                .unwrap(),
        )
        .await;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["cache-control"], "public, max-age=300");
    let b = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(serde_json::from_slice::<Value>(&b).unwrap(), f["jwks"]);
}

#[tokio::test]
async fn login_rejects_invalid_json_before_credential_lookup() {
    let dsn = std::env::var("TEST_DB_DSN").unwrap();
    let server = AuthServer::new(setjoin_pg::ScopedExecutor::from_dsn(&dsn, 2).unwrap());
    let (client, conn) = tokio_postgres::connect(&dsn, tokio_postgres::NoTls)
        .await
        .unwrap();
    let driver = tokio::spawn(conn);
    client
        .query_one(
            "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
            &[],
        )
        .await
        .unwrap();
    let old = client
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await
        .unwrap()
        .map(|r| r.get::<_, bool>(0));
    client.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await.unwrap();
    let server = server.with_threat_gate(&dsn).await.unwrap();
    let resp = server
        .handle(Request::post("/auth/login").body(body("{")).unwrap())
        .await;
    if let Some(v) = old {
        client
            .execute(
                "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.rate_limit'",
                &[&v],
            )
            .await
            .unwrap();
    } else {
        client
            .execute(
                "DELETE FROM feature_toggles WHERE key='feature.rate_limit'",
                &[],
            )
            .await
            .unwrap();
    }
    drop(client);
    driver.abort();
    assert_eq!(resp.status(), 400);
    let b = resp.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(&b[..],b"{\"type\":\"about:blank\",\"title\":\"Bad Request\",\"status\":400,\"detail\":\"invalid JSON\",\"instance\":\"/auth/login\"}\n");
}

#[tokio::test]
async fn password_login_issues_a_verifiable_pair_for_the_proven_user() {
    use setjoin_conformance::{fixture, harness::Db};
    let db = Db::for_case("IDLOGIN1-login").unwrap();
    let client = db.connect().await.unwrap();
    client
        .query_one(
            "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
            &[],
        )
        .await
        .unwrap();
    common::signing_key(&client).await;
    let old_rate = client
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await
        .unwrap()
        .map(|r| r.get::<_, bool>(0));
    client.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await.unwrap();
    let actor = fixture::account(&client, "idlogin1-actor").await.unwrap();
    client
        .execute(
            "UPDATE users SET password_hash=$1,mfa_exempt=true WHERE id=$2",
            &[&bcrypt::hash("Password1!", 4).unwrap(), &actor.user],
        )
        .await
        .unwrap();
    let email: String = client
        .query_one("SELECT email FROM users WHERE id=$1", &[&actor.user])
        .await
        .unwrap()
        .get(0);
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let exec = setjoin_pg::ScopedExecutor::from_dsn(&db.app.clone().unwrap_or(db.dsn.clone()), 2).unwrap();
    let server = AuthServer::load(
        exec,
        setjoin_auth::Config::for_secret(f["secret"].as_str().unwrap().to_owned()),
    )
    .await
    .unwrap()
    .with_threat_gate(&db.dsn)
    .await
    .unwrap();
    let resp = server
        .handle(
            Request::post("/auth/login")
                .body(body(
                    json!({"email":email,"password":"Password1!","uid":999999}).to_string(),
                ))
                .unwrap(),
        )
        .await;
    let status = resp.status();
    let b = resp.into_body().collect().await.unwrap().to_bytes();
    client
        .execute("DELETE FROM auth_event_log WHERE email=$1", &[&email])
        .await
        .unwrap();
    client
        .execute("DELETE FROM login_events WHERE user_id=$1", &[&actor.user])
        .await
        .unwrap();
    fixture::remove(&client, &actor).await.unwrap();
    if let Some(v) = old_rate {
        client
            .execute(
                "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.rate_limit'",
                &[&v],
            )
            .await
            .unwrap();
    } else {
        client
            .execute(
                "DELETE FROM feature_toggles WHERE key='feature.rate_limit'",
                &[],
            )
            .await
            .unwrap();
    }
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&b));
    let value: Value = serde_json::from_slice(&b).unwrap();
    let keys = setjoin_authz::legacy_jwt::LegacyKeys::new(
        f["secret"].as_str().unwrap().as_bytes(),
        &["authserver-hmac-1"],
        None,
    )
    .unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as f64;
    for (field, typ) in [("access_token", "access"), ("refresh_token", "refresh")] {
        let claims = keys
            .validate(
                value[field].as_str().unwrap(),
                "mailserver",
                "mailserver-gateway",
                now,
            )
            .unwrap();
        assert_eq!(claims["uid"], actor.user);
        assert_eq!(claims["email"], email);
        assert_eq!(claims["typ"], typ);
    }
}

#[tokio::test]
async fn login_audit_uses_the_socket_peer_for_untrusted_forwarding_headers() {
    use setjoin_conformance::{fixture, harness::Db};
    let db = Db::for_case("IDLOGIN1-source-IP").unwrap();
    let c = db.connect().await.unwrap();
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await
    .unwrap();
    common::signing_key(&c).await;
    let a = fixture::account(&c, "idlogin1-peer").await.unwrap();
    c.execute(
        "UPDATE users SET password_hash=$1,mfa_exempt=true WHERE id=$2",
        &[&bcrypt::hash("Password1!", 4).unwrap(), &a.user],
    )
    .await
    .unwrap();
    let email: String = c
        .query_one("SELECT email FROM users WHERE id=$1", &[&a.user])
        .await
        .unwrap()
        .get(0);
    let old = c
        .query_opt(
            "SELECT enabled FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await
        .unwrap()
        .map(|r| r.get::<_, bool>(0));
    c.execute("INSERT INTO feature_toggles(key,enabled) VALUES('feature.rate_limit',false) ON CONFLICT(key) DO UPDATE SET enabled=false",&[]).await.unwrap();
    let f: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let exec =
        setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).unwrap();
    let server = AuthServer::load(
        exec,
        setjoin_auth::Config::for_secret(f["secret"].as_str().unwrap().into()),
    )
    .await
    .unwrap()
    .with_threat_gate(&db.dsn)
    .await
    .unwrap();
    let mut req = Request::post("/auth/login")
        .header("host", "auth.idlogin1.test")
        .header("x-forwarded-for", "203.0.113.99")
        .body(body(
            json!({"email":email,"password":"Password1!"}).to_string(),
        ))
        .unwrap();
    // ConnectionMeta is provided by the transport, never decoded from headers.
    req.extensions_mut().insert(setjoin_auth::ConnectionMeta {
        peer: "198.51.100.8:54321".parse().unwrap(),
        tls: true,
    });
    let response = server.handle(req).await;
    let status = response.status();
    let ip: Option<String> = c
        .query_opt(
            "SELECT source_ip::text FROM login_events WHERE user_id=$1",
            &[&a.user],
        )
        .await
        .unwrap()
        .map(|r| r.get(0));
    c.execute("DELETE FROM auth_event_log WHERE email=$1", &[&email])
        .await
        .unwrap();
    c.execute("DELETE FROM login_events WHERE user_id=$1", &[&a.user])
        .await
        .unwrap();
    fixture::remove(&c, &a).await.unwrap();
    if let Some(v) = old {
        c.execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='feature.rate_limit'",
            &[&v],
        )
        .await
        .unwrap();
    } else {
        c.execute(
            "DELETE FROM feature_toggles WHERE key='feature.rate_limit'",
            &[],
        )
        .await
        .unwrap();
    }
    assert_eq!(status, 200);
    assert_eq!(ip.as_deref(), Some("198.51.100.8/32"));
}

#[tokio::test]
async fn configured_sm2_key_is_validated_before_the_auth_process_can_serve() {
    let dsn = std::env::var("TEST_DB_DSN").unwrap();
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let mut cfg = setjoin_auth::Config::for_secret(fixture["secret"].as_str().unwrap().into());
    cfg.profile = setjoin_config_secret::CryptoProfile::Hybrid;
    cfg.sm2_pem = Some("invalid PEM".into());
    let result =
        AuthServer::load(setjoin_pg::ScopedExecutor::from_dsn(&dsn, 2).unwrap(), cfg).await;
    assert!(
        result.is_err(),
        "malformed configured SM2 key reached serving state"
    );
}
