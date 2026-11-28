/// Per-file serial guard (#362). Both oracles take the host-wide
/// `/tmp/gofree-mctl4-backup.lock`; run in parallel, the preflight's 30 s
/// subprocess deadline expires while the minutes-long replay holds it.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

#[test]
fn backup_oracle_checks_restore_capacity_and_roundtrip_database_isolation() {
    let _serial = serial();
    let status = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/backup_preflight.py"
        ))
        .status()
        .expect("backup preflight oracle requires Python");
    assert!(status.success(), "backup oracle preflight checks failed");
}

#[test]
fn frozen_go_backup_process_oracle() {
    let _serial = serial();
    let status = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/backup_oracle.py"
        ))
        .arg("replay")
        .arg(env!("CARGO_BIN_EXE_mailctl"))
        .status()
        .expect("backup process oracle requires Python and PostgreSQL tools");
    assert!(status.success(), "backup process parity failed");
}
