#[test]
fn frozen_go_application_recovery_oracle() {
    let status = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/recovery_oracle.py"
        ))
        .arg("replay")
        .arg(env!("CARGO_BIN_EXE_mailctl"))
        .status()
        .expect("recovery oracle requires Python and PostgreSQL tools");
    assert!(
        status.success(),
        "application recovery process parity failed"
    );
}
