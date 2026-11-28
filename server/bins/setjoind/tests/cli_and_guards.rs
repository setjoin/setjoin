//! Suite 8: Subsystem CLI / env / `argv[0]` parsing, fail-closed invalid or
//! conflicting flags (exit 2), retired `GATEWAY_ROUTE_INVENTORY` refusal, and
//! expand–contract binary guards (#543).

mod common;

use std::os::unix::fs::symlink;
use std::process::Command;

use setjoin_boot::Subsystems;
use setjoind::{default_subsystems_for_argv0, parse_cli, CliAction, EXIT_USAGE};

#[test]
fn version_flags_succeed_with_setjoind_prefix() {
    for flag in ["--version", "-V"] {
        let out = Command::new(common::setjoind_bin())
            .env_clear()
            .arg(flag)
            .output()
            .expect("run setjoind --version");
        assert!(out.status.success(), "{flag} failed: {out:?}");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(
            stdout.starts_with("setjoind "),
            "{flag} stdout mismatch: {stdout:?}"
        );
    }
}

#[test]
fn invalid_duplicate_and_conflicting_flags_fail_closed_with_exit_2() {
    let cases: &[(&[&str], Option<&str>, &str)] = &[
        (
            &["--subsystems=http", "--subsystems=auth"],
            None,
            "duplicate",
        ),
        (
            &["--subsystems=http", "--subsystems", "http"],
            None,
            "duplicate",
        ),
        (&["--subsystems"], None, "requires a value"),
        (&["--subsystems="], None, "empty"),
        (&["--subsystems=bogus"], None, "unknown subsystem"),
        (&["--subsystems=all,http"], None, "cannot be combined"),
        (&["--subsystems=http,"], None, "empty"),
        (&["--unknown-flag"], None, "unknown argument"),
        (
            &["--version", "--subsystems=all"],
            None,
            "cannot be combined",
        ),
        (&[], Some("invalid_name"), "unknown subsystem"),
    ];

    for (args, env_val, needle) in cases {
        let mut cmd = Command::new(common::setjoind_bin());
        cmd.env_clear().args(*args);
        if let Some(val) = env_val {
            cmd.env("SETJOIND_SUBSYSTEMS", val);
        }
        let out = cmd.output().expect("spawn setjoind for invalid flag");
        assert_eq!(
            out.status.code(),
            Some(i32::from(EXIT_USAGE)),
            "args={args:?} env={env_val:?} expected exit 2, got {:?}\nstderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains(needle),
            "args={args:?} env={env_val:?} stderr missing {needle:?}: {stderr}"
        );
    }
}

#[test]
fn gateway_route_inventory_is_retired_and_refused_fail_closed() {
    let out = Command::new(common::setjoind_bin())
        .env_clear()
        .arg("--subsystems=http")
        .env("GATEWAY_ROUTE_INVENTORY", "/tmp/does-not-matter.json")
        .output()
        .expect("spawn setjoind with GATEWAY_ROUTE_INVENTORY");
    assert!(
        !out.status.success(),
        "setjoind must reject GATEWAY_ROUTE_INVENTORY"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("GATEWAY_ROUTE_INVENTORY") && stderr.contains("retired"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn argv0_symlink_and_env_precedence_match_contract() {
    assert_eq!(
        default_subsystems_for_argv0("/usr/bin/setjoind"),
        Subsystems::ALL
    );
    assert_eq!(
        default_subsystems_for_argv0("/usr/bin/setjoin-server"),
        Subsystems {
            http: true,
            auth: false,
            protocols: true,
            workers: true,
        }
    );
    assert_eq!(
        default_subsystems_for_argv0("/usr/bin/setjoin-gateway"),
        Subsystems {
            http: true,
            auth: false,
            protocols: true,
            workers: true,
        }
    );
    assert_eq!(
        default_subsystems_for_argv0("/usr/bin/setjoin-auth"),
        Subsystems {
            http: false,
            auth: true,
            protocols: false,
            workers: false,
        }
    );

    // SETJOIND_SUBSYSTEMS overrides argv[0]; CLI flag overrides both.
    assert_eq!(
        parse_cli(["setjoin-auth"], Some("workers")).unwrap(),
        CliAction::Run(Subsystems {
            http: false,
            auth: false,
            protocols: false,
            workers: true,
        })
    );
    assert_eq!(
        parse_cli(["setjoin-auth", "--subsystems=http"], Some("workers")).unwrap(),
        CliAction::Run(Subsystems {
            http: true,
            auth: false,
            protocols: false,
            workers: false,
        })
    );

    // Real symlink execution with argv[0] = setjoin-auth (fails on missing DB_DSN
    // from auth config instead of binding HTTP, proving argv[0] selected `auth`).
    let tmp = tempfile::tempdir().expect("tempdir");
    let link = tmp.path().join("setjoin-auth");
    symlink(common::setjoind_bin(), &link).expect("create setjoin-auth symlink");
    let out = Command::new(&link)
        .env_clear()
        .output()
        .expect("exec setjoin-auth symlink");
    assert!(
        !out.status.success(),
        "setjoin-auth symlink without DB_DSN must refuse to start"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("DB_DSN"),
        "expected auth DB_DSN refusal via argv[0]=setjoin-auth, got: {stderr}"
    );
}
