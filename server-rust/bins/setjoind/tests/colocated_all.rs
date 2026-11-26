//! Suite 1: Unified `--subsystems=all` with `InProcessAuthAuthority` (#543).
//!
//! Proves:
//! - Zero `GATEWAY_RUST_AUTH_UPSTREAM` / `AUTHSERVER_URL` / `AUTHSERVER_JWKS_URL`.
//! - Auth does NOT bind a separate standalone TCP listener (and skips standalone
//!   non-loopback `LISTEN_ADDR` TLS refusal because `http` owns the listener).
//! - Real `POST /auth/login` -> ES256 JWT -> `GET /auth/me` + `GET /jmap/session`
//!   and `GET /.well-known/jwks.json` all work end-to-end in one process.
//! - Public listener blocks internal auth admin/SCIM routes (`/auth/scim/disable`
//!   returns 404; `/admin/reload` with `INTERNAL_API_KEY` does not hit auth reload).

mod common;

use std::process::Command;
use std::time::Duration;

use serde_json::Value;

const JWT_SECRET: &str = "setjoind-test-jwt-secret-at-least-32-bytes-long!!";
const INTERNAL_KEY: &str = "setjoind-internal-api-key-32-bytes-long!!";

#[tokio::test]
async fn unified_all_serves_in_process_auth_jmap_jwks_and_blocks_internal_routes() {
    let dsn = common::test_db_dsn();
    let email = "setjoind-unified@example.test";
    let password = "UnifiedPassword123!";
    common::seed_test_user(&dsn, email, password).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg_path = common::temp_config_file(tmp.path());
    let (notify_path, notify_sock) = common::bind_notify_socket(tmp.path());
    let http_addr = common::free_addr();

    let mut cmd = Command::new(common::setjoind_bin());
    cmd.env_clear()
        .arg("--subsystems=all")
        .env("DB_DSN", &dsn)
        .env("DB_DIRECT_DSN", &dsn)
        .env("CONFIG_PATH", &cfg_path)
        .env("NOTIFY_SOCKET", &notify_path)
        .env("GATEWAY_LISTEN", http_addr.to_string())
        // Non-loopback LISTEN_ADDR without TLS: unified mode MUST skip standalone
        // auth listener bind & TLS check because `http` owns the public listener.
        .env("LISTEN_ADDR", "0.0.0.0:1")
        .env("JWT_SECRET", JWT_SECRET)
        .env("JWT_SIGNING_ALG", "ES256")
        .env("DB_ENCRYPTION_KEY", "setjoind-test-db-enc-key-32-bytes!!")
        .env("INTERNAL_API_KEY", INTERNAL_KEY);

    let mut proc = common::OwnedChild::spawn(&mut cmd);
    common::wait_notify(&notify_sock, &mut proc, "READY=1", Duration::from_secs(20));

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http client");

    // 1. /.well-known/jwks.json served directly via InProcessAuthAuthority.
    let jwks_resp = client
        .get(format!("http://{http_addr}/.well-known/jwks.json"))
        .send()
        .await
        .expect("jwks request");
    assert_eq!(jwks_resp.status(), 200);
    let jwks: Value = jwks_resp.json().await.expect("jwks json");
    let keys = jwks["keys"].as_array().expect("jwks keys array");
    assert!(!keys.is_empty(), "expected at least one ES256 JWK: {jwks}");
    assert_eq!(keys[0]["alg"], "ES256");

    // 2. Real login via InProcessAuthAuthority (zero GATEWAY_RUST_AUTH_UPSTREAM).
    let login_resp = client
        .post(format!("http://{http_addr}/auth/login"))
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(serde_json::json!({ "email": email, "password": password }).to_string())
        .send()
        .await
        .expect("login request");
    let login_status = login_resp.status();
    let login_text = login_resp.text().await.expect("login text");
    assert_eq!(
        login_status, 200,
        "login should succeed in unified mode; body={login_text}"
    );
    let login_json: Value = serde_json::from_str(&login_text).expect("login json");
    let access_token = login_json["access_token"]
        .as_str()
        .expect("access_token in login reply");
    assert!(!access_token.is_empty());

    // 3. Authenticated /auth/me served via InProcessAuthAuthority.
    let me_resp = client
        .get(format!("http://{http_addr}/auth/me"))
        .header("authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .expect("/auth/me request");
    assert_eq!(me_resp.status(), 200);
    let me_json: Value = me_resp.json().await.expect("/auth/me json");
    assert_eq!(me_json["email"], email);

    // 4. Authenticated JMAP session (/.well-known/jmap) verified in-process via AuthKeySource.
    let jmap_resp = client
        .get(format!("http://{http_addr}/.well-known/jmap"))
        .header("authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .expect("/.well-known/jmap request");
    assert_eq!(
        jmap_resp.status(),
        200,
        "authenticated JMAP session should verify ES256 token via InProcessAuthAuthority"
    );
    let jmap_json: Value = jmap_resp.json().await.expect("jmap session json");
    assert_eq!(jmap_json["username"], email);

    // 5. Internal-only auth routes MUST be blocked on the public listener.
    let scim_disable = client
        .post(format!("http://{http_addr}/auth/scim/disable"))
        .header("authorization", format!("Bearer {INTERNAL_KEY}"))
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(r#"{"user_id":1}"#)
        .send()
        .await
        .expect("scim disable probe");
    assert_eq!(
        scim_disable.status(),
        404,
        "/auth/scim/disable must be 404 on the public unified listener"
    );

    let auth_reload = client
        .post(format!("http://{http_addr}/admin/reload"))
        .header("authorization", format!("Bearer {INTERNAL_KEY}"))
        .header("sec-fetch-site", "same-origin")
        .send()
        .await
        .expect("admin reload probe");
    assert_ne!(
        auth_reload.status(),
        200,
        "auth internal /admin/reload must not be reachable with INTERNAL_API_KEY on public listener"
    );

    proc.send_sigterm();
    common::wait_notify(
        &notify_sock,
        &mut proc,
        "STOPPING=1",
        Duration::from_secs(10),
    );
    let status = proc
        .wait_exit(Duration::from_secs(15))
        .expect("clean shutdown exit");
    assert!(status.success(), "expected exit 0, got {status}");
}
