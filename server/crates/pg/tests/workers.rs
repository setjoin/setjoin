//! Integration tests for the worker runtime, against the disposable test DB.
use setjoin_pg::workers::{DirectListener, WorkerDatabase};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn worker_dsn() -> String {
    std::env::var("TEST_DB_DSN")
        .or_else(|_| std::env::var("DB_DSN"))
        .expect("worker tests require the disposable test database")
}

#[tokio::test]
async fn scheduler_singleton_uses_go_lock_and_releases_it_on_shutdown() {
    let _serial = SERIAL.lock().await;
    let db = WorkerDatabase::new(&worker_dsn()).unwrap();
    let first = db
        .try_cron_singleton()
        .await
        .unwrap()
        .expect("first scheduler");
    assert!(db.try_cron_singleton().await.unwrap().is_none());

    // This is the exact SQL/key used by Go's scheduler, on a separate backend.
    let (go, connection) = tokio_postgres::connect(&worker_dsn(), tokio_postgres::NoTls)
        .await
        .unwrap();
    let connection = tokio::spawn(connection);
    let acquired: bool = go
        .query_one(
            "SELECT pg_try_advisory_lock(hashtextextended($1, 0))",
            &[&"cron:scheduler-single-flight"],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!acquired, "a Go scheduler must not run beside Rust");
    first.release().await.unwrap();
    let next = db
        .try_cron_singleton()
        .await
        .unwrap()
        .expect("released lock");
    next.release().await.unwrap();
    drop(go);
    connection.await.unwrap().unwrap();
}

#[tokio::test]
async fn direct_listener_receives_committed_notifications() {
    let direct = std::env::var("DB_DIRECT_DSN").unwrap_or_else(|_| worker_dsn());
    let mut listener = DirectListener::connect(&direct, "gofree_t9_worker_test")
        .await
        .unwrap();
    let (sender, connection) = tokio_postgres::connect(&worker_dsn(), tokio_postgres::NoTls)
        .await
        .unwrap();
    let connection = tokio::spawn(connection);
    sender
        .query_one(
            "SELECT pg_notify($1, $2)",
            &[&"gofree_t9_worker_test", &"revocation"],
        )
        .await
        .unwrap();
    let notification = tokio::time::timeout(std::time::Duration::from_secs(3), listener.recv())
        .await
        .expect("notification timed out")
        .expect("listener disconnected");
    assert_eq!(notification.channel(), "gofree_t9_worker_test");
    assert_eq!(notification.payload(), "revocation");
    listener.close().await.unwrap();
    drop(sender);
    connection.await.unwrap().unwrap();
}

#[tokio::test]
async fn worker_credential_is_used_even_when_request_pool_is_unavailable() {
    let _serial = SERIAL.lock().await;
    let bad = "postgres://postgres:gofree@127.0.0.1:1/gofree_t9?connect_timeout=1";
    let db = WorkerDatabase::from_dsns(bad, Some(&worker_dsn())).unwrap();
    let lease = db
        .try_cron_singleton()
        .await
        .unwrap()
        .expect("worker connection");
    lease.release().await.unwrap();
    let no_worker = WorkerDatabase::from_dsns(&worker_dsn(), Some(bad)).unwrap();
    assert!(no_worker.try_cron_singleton().await.is_err());
}
