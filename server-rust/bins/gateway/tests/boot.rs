//! Boot is tested at its process boundary, on this ticket's disposable database.
use std::process::Stdio;
use tokio_postgres::NoTls;

fn dsn() -> Option<String> {
    let dsn = std::env::var("TEST_DB_DSN").ok();
    assert!(
        dsn.is_some() || std::env::var("REQUIRE_DB").as_deref() != Ok("1"),
        "TEST_DB_DSN is required"
    );
    dsn
}

#[tokio::test]
async fn unbaselined_database_refuses_boot_before_listening() {
    let Some(dsn) = dsn() else {
        eprintln!("BOOT-DB-SKIP (reason=no-dsn)");
        return;
    };
    let (client, connection) = tokio_postgres::connect(&dsn, NoTls).await.unwrap();
    let driver = tokio::spawn(connection);
    client
        .batch_execute("ALTER TABLE schema_migrations RENAME TO boot_saved_schema_migrations")
        .await
        .unwrap();
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"))
            .env_clear()
            .env("DB_DSN", &dsn)
            .env("GATEWAY_LISTEN", "127.0.0.1:0")
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await;
    client
        .batch_execute("ALTER TABLE boot_saved_schema_migrations RENAME TO schema_migrations")
        .await
        .unwrap();
    drop(client);
    driver.await.unwrap().unwrap();
    let output = output.expect("unbaselined gateway kept running").unwrap();
    assert_eq!(output.status.code(), Some(1));
    let log = String::from_utf8(output.stderr).unwrap();
    assert!(
        log.contains("database has no schema — refusing to start"),
        "{log}"
    );
}
