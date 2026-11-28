#[test]
fn frozen_go_process_oracle() {
    let status = std::process::Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/oracle.py"))
        .arg("replay")
        .arg(env!("CARGO_BIN_EXE_mailctl"))
        .status()
        .expect("Python process oracle must be available");
    assert!(status.success(), "mailctl process parity failed");
}

#[test]
fn process_oracle_rejects_request_stdout_and_exit_mutants() {
    let status = std::process::Command::new("python3")
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/oracle.py"))
        .arg("self-test")
        .arg(env!("CARGO_BIN_EXE_mailctl"))
        .status()
        .expect("Python oracle must be available");
    assert!(status.success(), "mailctl oracle mutant self-test failed");
}
