fn has_database() -> bool {
    if std::env::var("TEST_DB_DSN")
        .or_else(|_| std::env::var("DB_DSN"))
        .is_err()
    {
        assert_ne!(
            std::env::var("REQUIRE_DB").as_deref(),
            Ok("1"),
            "direct DB oracle requires TEST_DB_DSN"
        );
        use std::io::Write;
        std::io::stderr()
            .lock()
            .write_all(b"MAILCTL-DB-SKIP (reason=no-dsn)\n")
            .unwrap();
        return false;
    }
    true
}

fn oracle(mode: &str) {
    if !has_database() {
        return;
    }
    let status = std::process::Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/direct_db.py"))
        .arg(mode)
        .arg(env!("CARGO_BIN_EXE_mailctl"))
        .status()
        .expect("Python direct DB oracle must be available");
    assert!(status.success(), "mailctl direct DB parity failed");
}

#[test]
fn frozen_go_direct_database_process_oracle() {
    oracle("replay");
}

#[test]
fn direct_database_oracle_rejects_db_stdout_and_exit_mutants() {
    oracle("self-test");
}
