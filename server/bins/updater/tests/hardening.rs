//! #505/#506 owner-approved security fixes (2026-11-05) at the executable seam.
use std::{
    fs,
    os::unix::{fs::MetadataExt, fs::PermissionsExt, process::CommandExt},
    process::Command,
};

fn adopt(install: &std::path::Path, tmp: &std::path::Path, umask: Option<u32>) -> std::process::Output {
    let config = tmp.join("config.env");
    fs::write(&config, "SECRET=fixture\n").unwrap();
    fs::set_permissions(&config, fs::Permissions::from_mode(0o600)).unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_setjoin-updater"));
    cmd.args(["adopt-current-layout", "--install-root"])
        .arg(install)
        .arg("--config-file")
        .arg(&config)
        .arg("--quarantine-dir")
        .arg(tmp.join("q"));
    if let Some(mask) = umask {
        unsafe {
            cmd.pre_exec(move || {
                libc::umask(mask as libc::mode_t);
                Ok(())
            })
        };
    }
    cmd.output().unwrap()
}

#[test]
fn secure_dir_refuses_a_directory_not_owned_by_root() {
    assert_eq!(unsafe { libc::geteuid() }, 0, "hardening tests run as root");
    let tmp = tempfile::tempdir().unwrap();
    let install = tmp.path().join("install");
    fs::create_dir(&install).unwrap();
    fs::set_permissions(&install, fs::Permissions::from_mode(0o755)).unwrap();
    std::os::unix::fs::chown(&install, Some(65534), Some(65534)).unwrap();
    let out = adopt(&install, tmp.path(), None);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "adopted under a non-root-owned directory");
    assert!(err.contains("owner must be root"), "non-root-owned directory accepted: {err}");
    assert_eq!(fs::read_dir(&install).unwrap().count(), 0);
}

#[test]
fn new_directories_get_their_exact_mode_whatever_the_umask() {
    for mask in [0o000, 0o077] {
        let tmp = tempfile::tempdir().unwrap();
        fs::set_permissions(tmp.path(), fs::Permissions::from_mode(0o755)).unwrap();
        let install = tmp.path().join("deep/install");
        // adoption stops at missing artifacts, after secure_dir created the root.
        let out = adopt(&install, tmp.path(), Some(mask));
        assert!(!out.status.success());
        let meta = fs::metadata(&install).unwrap();
        assert_eq!(meta.mode() & 0o7777, 0o755, "umask {mask:o}");
        assert_eq!(fs::metadata(install.parent().unwrap()).unwrap().mode() & 0o7777, 0o755);
    }
}

#[test]
fn verify_test_flags_exist_only_in_non_release_builds() {
    let out = Command::new(env!("CARGO_BIN_EXE_setjoin-updater"))
        .args(["verify", "--manifest", "/nonexistent", "--trust-roots", "/nonexistent", "--allow-test-roots"])
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr);
    if cfg!(debug_assertions) {
        // Accepted as a flag; fails later on the missing file, not on the flag.
        assert!(!err.contains("unknown flags"), "{err}");
    } else {
        assert!(err.contains("unknown flags"), "{err}");
    }
}
