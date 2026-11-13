use std::{path::Path, process::Command};

#[test]
fn installer_update_rejections_crash_and_rollback_match_go() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap();
    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--name",
            "gofree-rel3-installer",
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
            "TEST_DB_DSN",
            "-e",
            "REQUIRE_DB",
            "setjoin-ci-linux-tc:local-amd64",
            "bash",
            "server-rust/bins/updater/tests/installer.sh",
            "/updater",
        ])
        .output()
        .expect("installer oracle requires Docker and CI image");
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
