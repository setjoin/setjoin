//! Suite 2: Split deployment (`--subsystems=http,protocols,workers` without
//! `JWT_SECRET` or `SM2_PRIVATE_KEY_FILE` talking to `--subsystems=auth` over
//! loopback via `RemoteAuthAuthority`) (#543).

use crate::common;

use std::collections::BTreeMap;
use std::process::Command;
use std::time::Duration;

use serde_json::Value;

use common::{TEST_DB_ENC_KEY, TEST_INTERNAL_KEY as INTERNAL_KEY, TEST_JWT_SECRET as JWT_SECRET};

#[tokio::test]
async fn split_edge_boots_without_private_keys_and_uses_remote_auth_authority() {
    let owner_dsn = common::test_db_dsn();
    let app_dsn = common::app_db_dsn();
    let worker_dsn = common::worker_db_dsn();
    let email = "setjoind-split@example.test";
    let password = "SplitPassword123!";
    common::seed_test_user(&owner_dsn, email, password).await;

    let tmp = tempfile::tempdir().expect("tempdir");
    let auth_cfg = common::temp_config_file(tmp.path());
    let (auth_notify_path, auth_notify_sock) =
        common::bind_notify_socket(&tmp.path().join("auth_run").tap_create());
    let (edge_notify_path, edge_notify_sock) =
        common::bind_notify_socket(&tmp.path().join("edge_run").tap_create());

    let auth_addr = common::free_addr();
    let edge_addr = common::free_addr();

    // 1. Start dedicated `--subsystems=auth` node holding private signing keys.
    let mut auth_cmd = Command::new(common::setjoind_bin());
    auth_cmd
        .env_clear()
        .arg("--subsystems=auth")
        .env("DB_DSN", &app_dsn)
        .env("DB_WORKER_DSN", &worker_dsn)
        .env("DB_OWNER_DSN", &owner_dsn)
        .env("DB_DIRECT_DSN", &app_dsn)
        .env("CONFIG_PATH", &auth_cfg)
        .env("NOTIFY_SOCKET", &auth_notify_path)
        .env("LISTEN_ADDR", auth_addr.to_string())
        .env("JWT_SECRET", JWT_SECRET)
        .env("JWT_SIGNING_ALG", "ES256")
        .env("DB_ENCRYPTION_KEY", TEST_DB_ENC_KEY)
        .env("INTERNAL_API_KEY", INTERNAL_KEY);
    let mut auth_proc = common::OwnedChild::spawn(&mut auth_cmd);
    common::wait_notify(
        &auth_notify_sock,
        &mut auth_proc,
        "READY=1",
        Duration::from_secs(20),
    );

    // 2. Start edge node `--subsystems=http,protocols,workers` with ZERO private
    // signing keys (no JWT_SECRET, no SM2_PRIVATE_KEY_FILE).
    let mut edge_cmd = Command::new(common::setjoind_bin());
    edge_cmd
        .env_clear()
        .arg("--subsystems=http,protocols,workers")
        .env("DB_DSN", &app_dsn)
        .env("DB_WORKER_DSN", &worker_dsn)
        .env("DB_OWNER_DSN", &owner_dsn)
        .env("DB_DIRECT_DSN", &app_dsn)
        .env("NOTIFY_SOCKET", &edge_notify_path)
        .env("GATEWAY_LISTEN", edge_addr.to_string())
        .env("GATEWAY_RUST_AUTH_UPSTREAM", format!("http://{auth_addr}"))
        .env("DB_ENCRYPTION_KEY", TEST_DB_ENC_KEY)
        .env("INTERNAL_API_KEY", INTERNAL_KEY);
    let mut edge_proc = common::OwnedChild::spawn(&mut edge_cmd);
    common::wait_notify(
        &edge_notify_sock,
        &mut edge_proc,
        "READY=1",
        Duration::from_secs(20),
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http client");

    // 3. Login through edge -> RemoteAuthAuthority -> standalone auth node.
    let login_resp = client
        .post(format!("http://{edge_addr}/auth/login"))
        .header("content-type", "application/json")
        .header("sec-fetch-site", "same-origin")
        .body(serde_json::json!({ "email": email, "password": password }).to_string())
        .send()
        .await
        .expect("edge login request");
    assert_eq!(login_resp.status(), 200);
    let login_json: Value = login_resp.json().await.expect("login json");
    let access_token = login_json["access_token"]
        .as_str()
        .expect("access_token from split auth");

    // 4. Edge node verifies ES256 token via RemoteAuthAuthority JWKS without JWT_SECRET.
    let jmap_resp = client
        .get(format!("http://{edge_addr}/.well-known/jmap"))
        .header("authorization", format!("Bearer {access_token}"))
        .send()
        .await
        .expect("edge /.well-known/jmap request");
    assert_eq!(
        jmap_resp.status(),
        200,
        "edge node without JWT_SECRET must verify ES256 token via RemoteAuthAuthority JWKS"
    );
    let jmap_json: Value = jmap_resp.json().await.expect("jmap session json");
    assert_eq!(jmap_json["username"], email);

    // 5. Public JWKS works through the edge node too.
    let jwks_resp = client
        .get(format!("http://{edge_addr}/.well-known/jwks.json"))
        .send()
        .await
        .expect("edge jwks request");
    assert_eq!(jwks_resp.status(), 200);
    let jwks: Value = jwks_resp.json().await.expect("jwks json");
    assert!(!jwks["keys"].as_array().expect("keys").is_empty());

    // Clean shutdown of both nodes.
    edge_proc.send_sigterm();
    auth_proc.send_sigterm();
    assert!(edge_proc
        .wait_exit(Duration::from_secs(15))
        .expect("edge exit")
        .success());
    assert!(auth_proc
        .wait_exit(Duration::from_secs(15))
        .expect("auth exit")
        .success());
}

#[test]
fn settings_validation_allows_edge_smx_without_private_keys_and_requires_them_on_auth() {
    let mut env = BTreeMap::new();
    env.insert("DB_DSN".into(), "postgres://mail@127.0.0.1/mail".into());
    env.insert("MINIO_ACCESS_KEY".into(), "minio".into());
    env.insert("MINIO_SECRET_KEY".into(), "miniosecret".into());
    env.insert("CRYPTO_ALGORITHM_PROFILE".into(), "smx".into());
    let settings = setjoin_gateway::configuration::Settings::parse("", &env).unwrap();

    let edge = setjoin_boot::Subsystems {
        http: true,
        auth: false,
        protocols: false,
        workers: true,
    };
    assert!(
        settings.validate_for(edge).is_ok(),
        "non-auth node must not require JWT_SECRET or SM2_PRIVATE_KEY_FILE"
    );

    let auth = setjoin_boot::Subsystems {
        http: false,
        auth: true,
        protocols: false,
        workers: false,
    };
    assert!(
        settings.validate_for(auth).is_err(),
        "auth node must refuse boot without JWT_SECRET / SM2_PRIVATE_KEY_FILE"
    );
}

trait DirExt {
    fn tap_create(self) -> Self;
}
impl DirExt for std::path::PathBuf {
    fn tap_create(self) -> Self {
        std::fs::create_dir_all(&self).expect("create subdir");
        self
    }
}
