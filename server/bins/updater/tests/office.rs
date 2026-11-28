use std::{path::Path, process::Command};
#[test]
fn unported_office_runner_receives_only_fixed_app_arguments() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .unwrap();
    let script = r#"set -eu
mkdir -p /usr/libexec
cat > /usr/libexec/setjoin-office-app-runner <<'SH'
#!/bin/sh
printf '%s\n' "$@"
SH
chmod 755 /usr/libexec/setjoin-office-app-runner
/updater run --once --office-app-only --office-app-execution --office-app-worker-dsn-file /private/app-dsn --office-app-manifest /private/manifest --office-app-state-dir /private/state
"#;
    let output = Command::new("docker")
        .args([
            "run",
            "--rm",
            "--name",
            "gofree-rel3-office",
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
        .args(["setjoin-ci-linux-tc:local-amd64", "bash", "-c", script])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let args = String::from_utf8(output.stdout).unwrap();
    assert_eq!(args,"--office-app-only\n--office-app-execution\n--office-app-worker-dsn-file\n/private/app-dsn\n--office-app-manifest\n/private/manifest\n--office-app-state-dir\n/private/state\n--executor-id\nsetjoin-updater\n--poll-interval\n15s\n--once\n");
}
