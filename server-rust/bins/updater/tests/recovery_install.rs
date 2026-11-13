use std::{path::Path, process::Command};

#[test]
fn authored_recovery_reconciles_previous_and_repeats_like_go() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap();
    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--name",
            "gofree-rel3-recovery",
            "--label",
            "org.setjoin.task=gofree-rel3",
        ])
        .arg("-v")
        .arg(format!("{}:/src:ro", root.display()))
        .arg("-v")
        .arg(format!(
            "{}:/updater:ro",
            env!("CARGO_BIN_EXE_setjoin-updater")
        ))
        .args([
            "-w",
            "/src",
            "-e",
            "REL_FIXTURE_DB=gofree_e2e_rel3",
            "-e",
            "REQUIRE_DB=1",
            "-e",
            "REL3_RECOVERY_CASE=authored",
            "setjoin-ci-linux-tc:local-amd64",
            "bash",
            "server-rust/bins/updater/tests/installer.sh",
            "/updater",
        ])
        .output()
        .expect("Docker CI image recovery fixture");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
