use serde_json::Value;
use std::{fs, process::Command};

#[test]
fn installer_refuses_active_go_journal_without_changing_executables() {
    let corpus: Value = serde_json::from_str(
        &fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/goldens/legacy-journals.json"
        ))
        .unwrap(),
    )
    .unwrap();
    for name in ["active", "recovery-required"] {
        let tmp = tempfile::tempdir().unwrap();
        let state = tmp.path().join("journal");
        fs::create_dir(&state).unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&state, fs::Permissions::from_mode(0o700)).unwrap();
        for (key, file) in [("events", "events.jsonl"), ("snapshot", "snapshot.json")] {
            if corpus["cases"][name][key] == "" {
                continue;
            }
            fs::write(
                state.join(file),
                corpus["cases"][name][key].as_str().unwrap(),
            )
            .unwrap();
            fs::set_permissions(state.join(file), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let installed = tmp.path().join("libexec");
        fs::create_dir(&installed).unwrap();
        fs::write(installed.join("setjoin-updater"), "old Go updater").unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_setjoin-updater"))
            .args(["install", "--state-dir"])
            .arg(&state)
            .arg("--binary")
            .arg(env!("CARGO_BIN_EXE_setjoin-updater"))
            .arg("--libexec-dir")
            .arg(&installed)
            .arg("--dsn-file")
            .arg(tmp.path().join("absent-credential"))
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("update is in progress"),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read(installed.join("setjoin-updater")).unwrap(),
            b"old Go updater"
        );
        assert!(!installed.join("setjoin-updater.prev").exists());
        assert!(state.join("events.jsonl").exists());
    }
}

#[test]
fn installer_refuses_a_live_executor_lock() {
    let tmp = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let lock = fs::File::create(tmp.path().join("executor.lock")).unwrap();
    lock.try_lock().unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_setjoin-updater"))
        .args(["install", "--state-dir"])
        .arg(tmp.path())
        .arg("--binary")
        .arg(env!("CARGO_BIN_EXE_setjoin-updater"))
        .arg("--libexec-dir")
        .arg(tmp.path().join("libexec"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("local execution lock"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn fresh_install_places_one_rust_updater_and_compatible_recovery_entrypoint() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source-updater");
    fs::copy(env!("CARGO_BIN_EXE_setjoin-updater"), &source).unwrap();
    let units = tmp.path().join("units");
    fs::create_dir(&units).unwrap();
    let source_unit = tmp.path().join("updater.service");
    fs::write(
        &source_unit,
        "[Service]\nExecStart=/usr/libexec/setjoin-updater run\n",
    )
    .unwrap();
    let tools = tmp.path().join("bin");
    fs::create_dir(&tools).unwrap();
    fs::write(tools.join("systemctl"), "#!/bin/sh\nexit 3\n").unwrap();
    fs::set_permissions(tools.join("systemctl"), fs::Permissions::from_mode(0o700)).unwrap();
    let installed = tmp.path().join("libexec");
    let output = Command::new(env!("CARGO_BIN_EXE_setjoin-updater"))
        .env("PATH", &tools)
        .args(["install", "--state-dir"])
        .arg(tmp.path().join("journal"))
        .arg("--binary")
        .arg(&source)
        .arg("--libexec-dir")
        .arg(&installed)
        .arg("--unit-source")
        .arg(&source_unit)
        .arg("--systemd-dir")
        .arg(&units)
        .arg("--dsn-file")
        .arg(tmp.path().join("absent-dsn"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read(installed.join("setjoin-updater")).unwrap(),
        fs::read(env!("CARGO_BIN_EXE_setjoin-updater")).unwrap()
    );
    assert_eq!(
        fs::read(units.join("setjoin-updater.service")).unwrap(),
        fs::read(source_unit).unwrap()
    );
    assert_eq!(
        fs::read(installed.join("setjoin-recovery")).unwrap(),
        b"#!/bin/sh\nexec /usr/libexec/setjoin-updater recover \"$@\"\n"
    );
    assert_eq!(
        fs::metadata(installed.join("setjoin-updater"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    // #506: the wrapper execs the fixed absolute path, never a `$0`-relative one.
    // A decoy `setjoin-updater` beside the wrapper must not run.
    let marker = tmp.path().join("decoy-ran");
    fs::write(
        installed.join("setjoin-updater"),
        format!("#!/bin/sh\ntouch {}\n", marker.display()),
    )
    .unwrap();
    let alias = Command::new(installed.join("setjoin-recovery"))
        .arg("status")
        .output()
        .unwrap();
    assert!(!marker.exists(), "wrapper executed a $0-relative updater");
    assert!(!alias.status.success());
    assert!(String::from_utf8_lossy(&alias.stderr).contains("/usr/libexec/setjoin-updater"));
}

#[test]
fn installer_rejects_invalid_unit_destination_before_replacing_any_binary() {
    let tmp = tempfile::tempdir().unwrap();
    let source = tmp.path().join("source-updater");
    fs::copy(env!("CARGO_BIN_EXE_setjoin-updater"), &source).unwrap();
    let unit = tmp.path().join("source.service");
    fs::write(
        &unit,
        "[Service]\nExecStart=/usr/libexec/setjoin-updater run\n",
    )
    .unwrap();
    let units = tmp.path().join("units");
    fs::create_dir(&units).unwrap();
    fs::create_dir(units.join("setjoin-updater.service")).unwrap();
    let libexec = tmp.path().join("libexec");
    let output = Command::new(env!("CARGO_BIN_EXE_setjoin-updater"))
        .args(["install", "--state-dir"])
        .arg(tmp.path().join("journal"))
        .arg("--binary")
        .arg(&source)
        .arg("--libexec-dir")
        .arg(&libexec)
        .arg("--unit-source")
        .arg(&unit)
        .arg("--systemd-dir")
        .arg(&units)
        .arg("--dsn-file")
        .arg(tmp.path().join("missing-dsn"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        !libexec.join("setjoin-updater").exists(),
        "failed installation left a partial executable swap"
    );
    assert!(!libexec.join("setjoin-recovery").exists());
    assert!(units.join("setjoin-updater.service").is_dir());
}

#[test]
fn swap_preflight_refuses_a_dangling_go_journal() {
    let tmp = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink("absent-snapshot", tmp.path().join("snapshot.json")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_setjoin-updater"))
        .args(["check-swap", "--state-dir"])
        .arg(tmp.path())
        .arg("--dsn-file")
        .arg(tmp.path().join("absent-dsn"))
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "a dangling journal was treated as an empty first install"
    );
}
