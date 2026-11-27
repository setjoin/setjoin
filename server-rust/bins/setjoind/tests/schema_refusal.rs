//! Suite 4: Strict pre-bind schema-version mismatch refusal (`actual < expected`
//! and `actual > expected`) BEFORE binding any listener or sending `READY=1` (#543).

mod common;

use std::net::TcpStream;
use std::process::Command;
use std::time::Duration;

use tokio_postgres::NoTls;

fn dsn_with_search_path(base_dsn: &str, schema: &str) -> String {
    let sep = if base_dsn.contains('?') { '&' } else { '?' };
    format!("{base_dsn}{sep}options=-c%20search_path%3D{schema}")
}

#[tokio::test]
async fn schema_mismatch_behind_and_ahead_refuses_before_bind() {
    let owner_dsn = common::test_db_dsn();
    let app_dsn = common::app_db_dsn();
    let worker_dsn = common::worker_db_dsn();
    let (client, conn) = tokio_postgres::connect(&owner_dsn, NoTls)
        .await
        .expect("connect test DB");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let behind_schema = format!("schema_behind_{}", std::process::id());
    let ahead_schema = format!("schema_ahead_{}", std::process::id());

    client
        .batch_execute(&format!(
            "DROP SCHEMA IF EXISTS {behind_schema} CASCADE;
             CREATE SCHEMA {behind_schema};
             CREATE TABLE {behind_schema}.schema_migrations (version INT);
             INSERT INTO {behind_schema}.schema_migrations VALUES (1);
             GRANT USAGE ON SCHEMA {behind_schema} TO setjoin_app;
             GRANT SELECT ON {behind_schema}.schema_migrations TO setjoin_app;
             DROP SCHEMA IF EXISTS {ahead_schema} CASCADE;
             CREATE SCHEMA {ahead_schema};
             CREATE TABLE {ahead_schema}.schema_migrations (version INT);
             INSERT INTO {ahead_schema}.schema_migrations VALUES (999999);
             GRANT USAGE ON SCHEMA {ahead_schema} TO setjoin_app;
             GRANT SELECT ON {ahead_schema}.schema_migrations TO setjoin_app;"
        ))
        .await
        .expect("create temporary mismatch schemas");

    let result = std::panic::catch_unwind(|| {
        for (label, schema, expected_needle) in [
            ("behind", behind_schema.as_str(), "behind"),
            ("ahead", ahead_schema.as_str(), "ahead"),
        ] {
            let tmp = tempfile::tempdir().expect("tempdir");
            let cfg_path = common::temp_config_file(tmp.path());
            let (notify_path, notify_sock) = common::bind_notify_socket(tmp.path());
            let http_addr = common::free_addr();
            let scoped_app_dsn = dsn_with_search_path(&app_dsn, schema);
            let scoped_worker_dsn = dsn_with_search_path(&worker_dsn, schema);
            let scoped_owner_dsn = dsn_with_search_path(&owner_dsn, schema);

            let mut cmd = Command::new(common::setjoind_bin());
            cmd.env_clear()
                .arg("--subsystems=all")
                .env("DB_DSN", &scoped_app_dsn)
                .env("DB_WORKER_DSN", &scoped_worker_dsn)
                .env("DB_OWNER_DSN", &scoped_owner_dsn)
                .env("DB_DIRECT_DSN", &scoped_app_dsn)
                .env("CONFIG_PATH", &cfg_path)
                .env("NOTIFY_SOCKET", &notify_path)
                .env("GATEWAY_LISTEN", http_addr.to_string())
                .env(
                    "JWT_SECRET",
                    "setjoind-schema-refusal-jwt-secret-32-bytes!!",
                );

            let mut proc = common::OwnedChild::spawn(&mut cmd);
            let status = proc
                .wait_exit(Duration::from_secs(10))
                .unwrap_or_else(|| panic!("{label}: setjoind did not refuse before bind"));
            assert!(
                !status.success(),
                "{label}: expected non-zero exit on schema mismatch"
            );
            let stderr = proc.read_stderr();
            assert!(
                stderr.contains(expected_needle),
                "{label}: stderr missing {expected_needle:?}: {stderr}"
            );
            let events = common::drain_notify(&notify_sock);
            assert!(
                !events.iter().any(|e| e == "READY=1"),
                "{label}: READY=1 must never be sent on schema mismatch: {events:?}"
            );
            assert!(
                TcpStream::connect_timeout(&http_addr, Duration::from_millis(200)).is_err(),
                "{label}: listener must never bind on schema mismatch"
            );
        }
    });

    // Always clean up temporary schemas.
    let _ = client
        .batch_execute(&format!(
            "DROP SCHEMA IF EXISTS {behind_schema} CASCADE;
             DROP SCHEMA IF EXISTS {ahead_schema} CASCADE;"
        ))
        .await;

    if let Err(payload) = result {
        std::panic::resume_unwind(payload);
    }
}
