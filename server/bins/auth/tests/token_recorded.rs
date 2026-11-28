//! #333 front-door HTTP oracle. Frozen Go remains the expected wire authority.
mod common;
use http_body_util::BodyExt;
use hyper::Request;
use setjoin_auth::{body, AuthServer};
#[tokio::test]
async fn discovery_uses_the_request_host() {
    let dsn = std::env::var("TEST_DB_DSN").expect("TEST_DB_DSN required");
    let server = AuthServer::new(setjoin_pg::ScopedExecutor::from_dsn(&dsn, 2).unwrap());
    let r = server
        .handle(
            Request::get("/.well-known/setjoin")
                .header("host", "auth.idlogin3.test")
                .body(body(""))
                .unwrap(),
        )
        .await;
    assert_eq!(r.status(), 200);
    assert_eq!(r.into_body().collect().await.unwrap().to_bytes().as_ref(),b"{\"client_version\":\"https://auth.idlogin3.test/api/v1/version\",\"clients_base\":\"https://auth.idlogin3.test/clients\",\"jmap_session\":\"https://auth.idlogin3.test/jmap/session\",\"version\":\"2.5.0\"}\n");
}

// Frozen authserver installs the same startup + 30s revocation mirror on
// session and token routes (main.go's bearerAuth/requireAuth registrations).
// #332's logout-repeat recording also pins this positive-cache window.
#[tokio::test]
async fn token_and_session_routes_share_the_process_revocation_snapshot() {
    use serde_json::json;
    use setjoin_conformance::{fixture, harness::Db};
    let db = Db::for_case("IDLOGIN3-shared-session-cache").unwrap();
    let c = db.connect().await.unwrap();
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await
    .unwrap();
    common::signing_key(&c).await;
    let a = fixture::account(&c, "idlogin3-session-cache")
        .await
        .unwrap();
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let secret = f["secret"].as_str().unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let token = setjoin_authz::legacy_jwt::sign_hs256(
        secret.as_bytes(),
        &json!({"iss":"mailserver","aud":"mailserver-gateway","uid":a.user,
            "typ":"access","jti":"idlogin3-cache","iat":now,"exp":now+3600})
        .to_string(),
    );
    let load = || {
        let mut cfg = setjoin_auth::Config::for_secret(secret.into());
        cfg.dsn = db.dsn.clone();
        cfg.worker_dsn = Some(db.dsn.clone());
        AuthServer::load(
            setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2).unwrap(),
            cfg,
        )
    };
    let server = load().await.unwrap();
    c.execute("INSERT INTO session_revocations(user_id,scope,jti,reason,not_before,expires_at) VALUES($1,'jti','idlogin3-cache','fixture',now(),now()+interval '1 hour')",&[&a.user]).await.unwrap();
    let mut statuses = Vec::new();
    for path in ["/auth/session/token", "/terms/pending"] {
        statuses.push(
            server
                .handle(
                    Request::get(path)
                        .header("authorization", format!("Bearer {token}"))
                        .body(body(""))
                        .unwrap(),
                )
                .await
                .status()
                .as_u16(),
        );
    }
    drop(server);
    let server = load().await.unwrap();
    for path in ["/auth/session/token", "/terms/pending"] {
        statuses.push(
            server
                .handle(
                    Request::get(path)
                        .header("authorization", format!("Bearer {token}"))
                        .body(body(""))
                        .unwrap(),
                )
                .await
                .status()
                .as_u16(),
        );
    }
    drop(server);
    c.execute(
        "DELETE FROM session_revocations WHERE user_id=$1",
        &[&a.user],
    )
    .await
    .unwrap();
    fixture::remove(&c, &a).await.unwrap();
    assert_eq!(statuses, [200, 200, 401, 401]);
}
