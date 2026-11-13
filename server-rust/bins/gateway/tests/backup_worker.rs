/// Both oracles dump and restore the one database: libtest's threads must take turns.
static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
fn serial() -> std::sync::MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn recorded_go_backup_worker_through_gateway_process() {
    let _serial = serial();
    let status = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../mailctl/tests/backup_worker.py"
        ))
        .arg("replay")
        .arg(env!("CARGO_BIN_EXE_setjoin-gateway"))
        .status()
        .expect("backup worker oracle requires Python, PostgreSQL tools and OpenSSL");
    assert!(status.success(), "backup worker parity failed");
}

#[test]
fn backup_effects_require_go_worker_transfer() {
    let _serial = serial();
    use std::os::unix::fs::PermissionsExt;
    let key = std::env::temp_dir().join(format!("gofree-mctl4-worker-key-{}", std::process::id()));
    std::fs::write(&key, "00".repeat(32)).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"))
        .env_clear()
        .env("GATEWAY_LISTEN", "127.0.0.1:0")
        .env("GATEWAY_AUTH_UPSTREAM", "http://127.0.0.1:1")
        .env("BACKUP_SIGNING_KEY_FILE", &key)
        .env("BACKUP_PROVIDER", "s3")
        .env("BACKUP_BUCKET", "fixture")
        .output()
        .unwrap();
    std::fs::remove_file(key).unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("GO_WORKERS_OFF=backup-engine"));
}

#[test]
fn backup_keeps_go_parity_with_recovery_cleanup_enabled() {
    let _serial = serial();
    let status = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../mailctl/tests/backup_worker.py"
        ))
        .arg("replay")
        .arg(env!("CARGO_BIN_EXE_setjoin-gateway"))
        .env("MAILCTL_WORKER_CASE", "worker")
        .env("MAILCTL_WORKER_WITH_RECOVERY", "1")
        .status()
        .expect("combined worker oracle requires Python, PostgreSQL tools and OpenSSL");
    assert!(
        status.success(),
        "backup parity with recovery cleanup failed"
    );
}
