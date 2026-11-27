//! Suite 6: Shared `ListenHub` multiplexing across subsystems — proves ONE
//! single `DB_DIRECT_DSN` PostgreSQL backend serves all active subsystems in
//! `setjoind --subsystems=all`, and delivers `NOTIFY` events across channels (#543).

mod common;

use std::process::Command;
use std::time::Duration;

use tokio_postgres::NoTls;

use common::{TEST_DB_ENC_KEY, TEST_JWT_SECRET as JWT_SECRET};

fn dsn_with_app_name(base_dsn: &str, app_name: &str) -> String {
    let sep = if base_dsn.contains('?') { '&' } else { '?' };
    format!("{base_dsn}{sep}application_name={app_name}")
}

#[tokio::test]
async fn unified_all_uses_single_shared_db_direct_connection() {
    let owner_dsn = common::test_db_dsn();
    let app_dsn = common::app_db_dsn();
    let worker_dsn = common::worker_db_dsn();
    let app_name = format!("setjoind_hub_543b_{}", std::process::id());
    let direct_dsn = dsn_with_app_name(&app_dsn, &app_name);

    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg_path = common::temp_config_file(tmp.path());
    let (notify_path, notify_sock) = common::bind_notify_socket(tmp.path());
    let http_addr = common::free_addr();

    let mut cmd = Command::new(common::setjoind_bin());
    cmd.env_clear()
        .arg("--subsystems=all")
        .env("DB_DSN", &app_dsn)
        .env("DB_WORKER_DSN", &worker_dsn)
        .env("DB_OWNER_DSN", &owner_dsn)
        .env("DB_DIRECT_DSN", &direct_dsn)
        .env("CONFIG_PATH", &cfg_path)
        .env("NOTIFY_SOCKET", &notify_path)
        .env("GATEWAY_LISTEN", http_addr.to_string())
        .env("JWT_SECRET", JWT_SECRET)
        .env("JWT_SIGNING_ALG", "ES256")
        .env("DB_ENCRYPTION_KEY", TEST_DB_ENC_KEY)
        .env("RUST_WORKERS_ON", "session-denylist-refresh");

    let mut proc = common::OwnedChild::spawn(&mut cmd);
    common::wait_notify(&notify_sock, &mut proc, "READY=1", Duration::from_secs(20));

    // Trigger an HTTP request so Gateway's RuntimeAccess::initialize() & run()
    // have definitely subscribed to conditional_access, group_membership_changed,
    // and session_revoke on the shared ListenHub.
    common::wait_http_ready(http_addr, "/_gateway/healthz", Duration::from_secs(5)).await;
    tokio::time::sleep(Duration::from_millis(250)).await;

    let (client, conn) = tokio_postgres::connect(&owner_dsn, NoTls)
        .await
        .expect("connect observer PG");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    let count: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM pg_stat_activity WHERE application_name = $1",
            &[&app_name],
        )
        .await
        .expect("query pg_stat_activity")
        .get(0);
    assert_eq!(
        count, 1,
        "expected exactly ONE DB_DIRECT_DSN ListenHub connection across all active subsystems, found {count}"
    );

    // Emit NOTIFY across multiple distinct channels; connection count must remain 1.
    client
        .batch_execute(
            "NOTIFY config_changed, 'test';
             NOTIFY conditional_access, 'test';
             NOTIFY group_membership_changed, '1';
             NOTIFY timezone_changed, 'test';",
        )
        .await
        .expect("emit NOTIFY");
    tokio::time::sleep(Duration::from_millis(200)).await;

    let count_after: i64 = client
        .query_one(
            "SELECT count(*)::bigint FROM pg_stat_activity WHERE application_name = $1",
            &[&app_name],
        )
        .await
        .expect("query pg_stat_activity after notify")
        .get(0);
    assert_eq!(
        count_after, 1,
        "ListenHub connection count must remain 1 after multi-channel NOTIFY fan-out"
    );

    proc.send_sigterm();
    let status = proc
        .wait_exit(Duration::from_secs(15))
        .expect("clean shutdown");
    assert!(status.success(), "expected exit 0, got {status}");

    // Confirm the single direct connection closed cleanly on shutdown.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let remaining: i64 = client
            .query_one(
                "SELECT count(*)::bigint FROM pg_stat_activity WHERE application_name = $1",
                &[&app_name],
            )
            .await
            .expect("query pg_stat_activity after shutdown")
            .get(0);
        if remaining == 0 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "ListenHub connection leaked after shutdown: remaining={remaining}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}
