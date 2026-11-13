use std::process::Command;

#[test]
fn recovery_status_and_evidence_match_recorded_go() {
    let output = Command::new("python3")
        .arg(format!("{}/tests/recovery.py", env!("CARGO_MANIFEST_DIR")))
        .arg(env!("CARGO_BIN_EXE_setjoin-updater"))
        .output()
        .expect("Python recovery oracle");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn recovery_authorization_and_forced_previous_match_recorded_go() {
    let output = Command::new("python3")
        .env("REL3_RECOVERY_CASE", "activation")
        .arg(format!("{}/tests/recovery.py", env!("CARGO_MANIFEST_DIR")))
        .arg(env!("CARGO_BIN_EXE_setjoin-updater"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn recovery_usage_and_invalid_reason_exit_codes_match_go() {
    let output = Command::new("python3")
        .env("REL3_RECOVERY_CASE", "arguments")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/recovery.py"))
        .arg(env!("CARGO_BIN_EXE_setjoin-updater"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn recovery_evidence_reports_unavailable_units_like_go() {
    let output = Command::new("python3")
        .env("REL3_RECOVERY_CASE", "unavailable-units")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/recovery.py"))
        .arg(env!("CARGO_BIN_EXE_setjoin-updater"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
