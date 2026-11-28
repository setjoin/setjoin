use crate::common;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
struct Owned(Child);
impl Drop for Owned {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
#[tokio::test]
async fn auth_binary_serves_health_and_readiness_on_its_own_listener() {
    let db = setjoin_conformance::harness::Db::for_case("IDLOGIN1-startup").unwrap();
    let fixture_lock = db.connect().await.unwrap();
    fixture_lock
        .query_one(
            "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
            &[],
        )
        .await
        .unwrap();
    common::signing_key(&fixture_lock).await;

    // 1. Wave 1.9 (#547): setjoin-auth unconditionally refuses to start on
    //    superuser TEST_DB_DSN (exit 1 before binding any listener).
    let super_out = Command::new(env!("CARGO_BIN_EXE_setjoin-auth"))
        .arg0("gofree-idlogin1-auth-super-refuse")
        .env("DB_DSN", &db.dsn)
        .env("DB_WORKER_DSN", db.worker_dsn())
        .env("JWT_SECRET", "idlogin1-fixture-secret-at-least-32-bytes")
        .env("LISTEN_ADDR", "127.0.0.1:0")
        .env_remove("SETJOIN_CONFIG")
        .env("CRYPTO_ALGORITHM_PROFILE", "standard")
        .output()
        .unwrap();
    assert_eq!(
        super_out.status.code(),
        Some(1),
        "superuser DB_DSN must refuse boot: {}",
        String::from_utf8_lossy(&super_out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&super_out.stderr)
            .contains("native-RLS boot check FAILED — refusing to start"),
        "{}",
        String::from_utf8_lossy(&super_out.stderr)
    );

    // 2. Non-superuser BYPASSRLS role (DB_WORKER_DSN as DB_DSN) also refuses boot.
    if let Some(worker_dsn) = db.worker.as_deref() {
        let bypass_out = Command::new(env!("CARGO_BIN_EXE_setjoin-auth"))
            .arg0("gofree-idlogin1-auth-bypass-refuse")
            .env("DB_DSN", worker_dsn)
            .env("DB_WORKER_DSN", &db.dsn)
            .env("JWT_SECRET", "idlogin1-fixture-secret-at-least-32-bytes")
            .env("LISTEN_ADDR", "127.0.0.1:0")
            .env_remove("SETJOIN_CONFIG")
            .env("CRYPTO_ALGORITHM_PROFILE", "standard")
            .output()
            .unwrap();
        assert_eq!(
            bypass_out.status.code(),
            Some(1),
            "BYPASSRLS DB_DSN must refuse boot: {}",
            String::from_utf8_lossy(&bypass_out.stderr)
        );
    }

    // 3. Unset DB_WORKER_DSN (falls back to DB_DSN -> shared app/worker role) refuses boot.
    let shared_out = Command::new(env!("CARGO_BIN_EXE_setjoin-auth"))
        .arg0("gofree-idlogin1-auth-shared-worker-refuse")
        .env("DB_DSN", db.app_dsn())
        .env_remove("DB_WORKER_DSN")
        .env("JWT_SECRET", "idlogin1-fixture-secret-at-least-32-bytes")
        .env("LISTEN_ADDR", "127.0.0.1:0")
        .env_remove("SETJOIN_CONFIG")
        .env("CRYPTO_ALGORITHM_PROFILE", "standard")
        .output()
        .unwrap();
    assert_eq!(
        shared_out.status.code(),
        Some(1),
        "omitted DB_WORKER_DSN must refuse boot: {}",
        String::from_utf8_lossy(&shared_out.stderr)
    );

    // 4. Primary health & readiness proof: constrained DB_APP_DSN + distinct
    //    DB_WORKER_DSN boots cleanly and returns 200 {"status":"ok"}.
    let listener = setjoin_conformance::ports::std_listener();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let mut child = Owned(
        Command::new(env!("CARGO_BIN_EXE_setjoin-auth"))
            .arg0(format!(
                "{}-auth",
                std::env::var("GOFREE_RESOURCE_PREFIX")
                    .unwrap_or_else(|_| "gofree-idlogin1".into())
            ))
            .env("DB_DSN", db.app_dsn())
            .env("DB_DIRECT_DSN", db.app_dsn())
            .env("DB_WORKER_DSN", db.worker_dsn())
            .env("JWT_SECRET", "idlogin1-fixture-secret-at-least-32-bytes")
            .env("LISTEN_ADDR", addr.to_string())
            .env_remove("SETJOIN_CONFIG")
            .env("CRYPTO_ALGORITHM_PROFILE", "standard")
            // Go never reads this profile-inapplicable file.
            .env(
                "SM2_PRIVATE_KEY_FILE",
                "/gofree-idlogin1-nonexistent-standard-key",
            )
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let mut connected = false;
    for _ in 0..100 {
        if let Ok(mut stream) = tokio::net::TcpStream::connect(addr).await {
            stream
                .write_all(b"GET /health HTTP/1.1\r\nHost: auth.test\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));
            assert!(
                response.ends_with(br#"{"status":"ok"}"#),
                "expected ok on constrained DB_APP_DSN, got: {}",
                String::from_utf8_lossy(&response)
            );
            connected = true;
            break;
        }
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "auth process exited before readiness"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(connected, "auth process never bound its listener");
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /ready HTTP/1.1\r\nHost: auth.test\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));
}

#[test]
fn invalid_crypto_profile_is_rejected_before_serving() {
    let mut child = Owned(
        Command::new(env!("CARGO_BIN_EXE_setjoin-auth"))
            .arg0(format!(
                "{}-invalid-profile",
                std::env::var("GOFREE_RESOURCE_PREFIX")
                    .unwrap_or_else(|_| "gofree-idlogin1".into())
            ))
            .env("DB_DSN", std::env::var("TEST_DB_DSN").unwrap())
            .env("JWT_SECRET", "idlogin1-fixture-secret-at-least-32-bytes")
            .env("LISTEN_ADDR", "127.0.0.1:0")
            .env("CRYPTO_ALGORITHM_PROFILE", "typo")
            .env_remove("SETJOIN_CONFIG")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    for _ in 0..100 {
        if let Some(status) = child.0.try_wait().unwrap() {
            use std::io::Read;
            let mut stderr = String::new();
            child
                .0
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            assert!(!status.success());
            assert!(stderr.contains("CRYPTO_ALGORITHM_PROFILE"), "{stderr}");
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("invalid crypto profile reached the serving process");
}

#[test]
fn weak_database_encryption_key_is_rejected_before_listening() {
    let f: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-login/keys.json"
    ))
    .unwrap();
    let mut child = Owned(
        Command::new(env!("CARGO_BIN_EXE_setjoin-auth"))
            .arg0(format!(
                "{}-invalid-db-key",
                std::env::var("GOFREE_RESOURCE_PREFIX")
                    .unwrap_or_else(|_| "gofree-idlogin3".into())
            ))
            .env("DB_DSN", std::env::var("TEST_DB_DSN").unwrap())
            .env("JWT_SECRET", f["secret"].as_str().unwrap())
            .env("DB_ENCRYPTION_KEY", "weak")
            .env("LISTEN_ADDR", "127.0.0.1:0")
            .env("CRYPTO_ALGORITHM_PROFILE", "standard")
            .env_remove("SETJOIN_CONFIG")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    for _ in 0..250 {
        if let Some(status) = child.0.try_wait().unwrap() {
            use std::io::Read;
            let mut stderr = String::new();
            child
                .0
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .unwrap();
            assert!(!status.success());
            assert!(
                stderr.contains("DB_ENCRYPTION_KEY must be at least 32 characters or empty"),
                "{stderr}"
            );
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    panic!("weak configured encryption key was accepted");
}

#[tokio::test]
async fn auth_runtime_shared_tasks_start_without_go_workers_off() {
    let db = setjoin_conformance::harness::Db::for_case("AUTHRT-startup").unwrap();
    let c = db.connect().await.unwrap();
    c.query_one(
        "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
        &[],
    )
    .await
    .unwrap();
    common::signing_key(&c).await;
    let listener = setjoin_conformance::ports::std_listener();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    let mut child = Owned(
        Command::new(env!("CARGO_BIN_EXE_setjoin-auth"))
            .arg0("gofree-authrt-guard")
            .env("DB_DSN", db.app_dsn())
            .env("DB_DIRECT_DSN", db.app_dsn())
            .env("DB_WORKER_DSN", db.worker_dsn())
            .env("JWT_SECRET", "idlogin1-fixture-secret-at-least-32-bytes")
            .env("LISTEN_ADDR", addr.to_string())
            .env_remove("SETJOIN_CONFIG")
            .env("RUST_WORKERS_ON", "auth-runtime")
            .env("GO_WORKERS_OFF", "")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let mut connected = false;
    for _ in 0..100 {
        if let Ok(mut stream) = tokio::net::TcpStream::connect(addr).await {
            stream
                .write_all(b"GET /health HTTP/1.1\r\nHost: auth.test\r\nConnection: close\r\n\r\n")
                .await
                .unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert!(String::from_utf8_lossy(&response).starts_with("HTTP/1.1 200"));
            connected = true;
            break;
        }
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "auth-runtime exited without GO_WORKERS_OFF"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    assert!(
        connected,
        "auth-runtime did not bind its listener without GO_WORKERS_OFF"
    );
}

#[tokio::test]
async fn auth_runtime_refuses_a_missing_seeded_security_control() {
    let db = setjoin_conformance::harness::Db::for_case("AUTHRT-seed-tripwire").unwrap();
    let owner = db.connect().await.unwrap();
    owner
        .query_one(
            "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
            &[],
        )
        .await
        .unwrap();
    common::signing_key(&owner).await;
    let before: String = owner
        .query_one(
            "SELECT to_jsonb(t)::text FROM feature_toggles t WHERE key='feature.smime_verify'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    owner
        .execute(
            "DELETE FROM feature_toggles WHERE key='feature.smime_verify'",
            &[],
        )
        .await
        .unwrap();
    let mut child = Owned(
        Command::new(env!("CARGO_BIN_EXE_setjoin-auth"))
            .arg0("gofree-authrt-seed-guard")
            .env("DB_DSN", db.app_dsn())
            .env("DB_DIRECT_DSN", db.app_dsn())
            .env("DB_WORKER_DSN", db.worker_dsn())
            .env("JWT_SECRET", "idlogin1-fixture-secret-at-least-32-bytes")
            .env("LISTEN_ADDR", "127.0.0.1:0")
            .env("CRYPTO_ALGORITHM_PROFILE", "standard")
            .env_remove("SETJOIN_CONFIG")
            .env("RUST_WORKERS_ON", "")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let status = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await
        }
    })
    .await;
    if status.is_err() {
        let _ = child.0.kill();
        let _ = child.0.wait();
    }
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.0.stderr.take().unwrap(), &mut stderr).unwrap();
    owner.execute("INSERT INTO feature_toggles SELECT * FROM jsonb_populate_record(NULL::feature_toggles,$1::text::jsonb)",&[&before]).await.unwrap();
    assert!(
        status.is_ok_and(|s| !s.success()),
        "auth started with a missing seeded security control"
    );
    assert!(stderr.contains("feature.smime_verify"), "{stderr}");
}

#[tokio::test]
async fn auth_runtime_refuses_missing_toggle_registry_state() {
    let db = setjoin_conformance::harness::Db::for_case("AUTHRT-registry-tripwire").unwrap();
    let owner = db.connect().await.unwrap();
    owner
        .query_one(
            "SELECT pg_advisory_lock(hashtextextended('gofree-idlogin1-oracle',0))",
            &[],
        )
        .await
        .unwrap();
    common::signing_key(&owner).await;
    let before: String = owner
        .query_one(
            "SELECT to_jsonb(t)::text FROM feature_toggle_registry_state t WHERE singleton",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    owner
        .execute(
            "DELETE FROM feature_toggle_registry_state WHERE singleton",
            &[],
        )
        .await
        .unwrap();
    let mut child = Owned(
        Command::new(env!("CARGO_BIN_EXE_setjoin-auth"))
            .arg0("gofree-authrt-registry-guard")
            .env("DB_DSN", db.app_dsn())
            .env("DB_DIRECT_DSN", db.app_dsn())
            .env("DB_WORKER_DSN", db.worker_dsn())
            .env("JWT_SECRET", "idlogin1-fixture-secret-at-least-32-bytes")
            .env("LISTEN_ADDR", "127.0.0.1:0")
            .env("CRYPTO_ALGORITHM_PROFILE", "standard")
            .env_remove("SETJOIN_CONFIG")
            .env("RUST_WORKERS_ON", "")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap(),
    );
    let status = tokio::time::timeout(std::time::Duration::from_secs(3), async {
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await
        }
    })
    .await;
    if status.is_err() {
        let _ = child.0.kill();
        let _ = child.0.wait();
    }
    let mut stderr = String::new();
    std::io::Read::read_to_string(&mut child.0.stderr.take().unwrap(), &mut stderr).unwrap();
    owner.execute("INSERT INTO feature_toggle_registry_state SELECT * FROM jsonb_populate_record(NULL::feature_toggle_registry_state,$1::text::jsonb)",&[&before]).await.unwrap();
    assert!(
        status.is_ok_and(|s| !s.success()),
        "auth started with missing toggle registry state"
    );
    assert!(stderr.contains("registry state"), "{stderr}");
}
