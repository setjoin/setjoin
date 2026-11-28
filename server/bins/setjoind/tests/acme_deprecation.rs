//! Subprocess verification of Release N+1 fail-closed built-in ACME retirement (#560).
use std::process::Command;

#[test]
fn setjoind_refuses_startup_on_retired_acme_env_without_leaking_secrets() {
    let exe = env!("CARGO_BIN_EXE_setjoind");
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = tmp.path().join("config.yaml");
    std::fs::write(&cfg, "server:\n  hostname: mail.example.test\n").unwrap();

    // Legacy TLS_AUTOCERT_* / TLS_DNS_* variables must refuse startup fail-closed
    // BEFORE boot/DB/bind (even for --subsystems=auth or --subsystems=all)
    // with an actionable Release N+1 error and zero secret leakage.
    for subsystems in ["http", "auth", "all"] {
        let out = Command::new(exe)
            .env_clear()
            .arg(format!("--subsystems={subsystems}"))
            .env("CONFIG_PATH", &cfg)
            .env("TLS_AUTOCERT_DOMAINS", "mail.example.test")
            .env("TLS_DNS_PROVIDER", "cloudflare")
            .env(
                "TLS_DNS_CONFIG",
                r#"{"CF_API_TOKEN":"sentinel-secret-do-not-log-560"}"#,
            )
            .env("TLS_DNS_API_TOKEN", "sentinel-api-token-560")
            .env("TLS_DNS_TSIG_SECRET", "sentinel-tsig-secret-560")
            .output()
            .expect("spawn setjoind");

        assert!(
            !out.status.success(),
            "setjoind --subsystems={subsystems} must fail closed on retired ACME variables"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("built-in ACME") && stderr.contains("retired in Release N+1 (#560)"),
            "expected Release N+1 retirement error on stderr ({subsystems}), got:\n{stderr}"
        );
        assert!(
            stderr.contains("TLS_AUTOCERT_DOMAINS")
                && stderr.contains("TLS_DNS_PROVIDER")
                && stderr.contains("TLS_DNS_CONFIG")
                && stderr.contains("TLS_DNS_API_TOKEN")
                && stderr.contains("TLS_DNS_TSIG_SECRET"),
            "expected trigger names in stderr ({subsystems}), got:\n{stderr}"
        );
        assert!(
            stderr.contains("docs/guides/EDGE_TLS_ACME_MIGRATION.md")
                && stderr.contains("TLS_CERT_FILE")
                && stderr.contains("TLS_KEY_FILE"),
            "expected migration guide and TLS_CERT_FILE/TLS_KEY_FILE reference in stderr ({subsystems}), got:\n{stderr}"
        );
        for secret in [
            "sentinel-secret-do-not-log-560",
            "sentinel-api-token-560",
            "sentinel-tsig-secret-560",
        ] {
            assert!(
                !stderr.contains(secret),
                "secret value `{secret}` leaked to stderr:\n{stderr}"
            );
        }
    }
}

#[cfg(unix)]
#[test]
fn setjoind_refuses_non_unicode_legacy_dns_secret_without_panicking() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    let exe = env!("CARGO_BIN_EXE_setjoind");
    let mut raw = b"raw-tsig-secret-".to_vec();
    raw.extend_from_slice(&[0xff, 0xfe, 0x80]);
    let out = Command::new(exe)
        .env_clear()
        .arg("--subsystems=all")
        .env("TLS_DNS_TSIG_SECRET", OsString::from_vec(raw))
        .output()
        .expect("spawn setjoind");

    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("TLS_DNS_TSIG_SECRET") && stderr.contains("retired in Release N+1 (#560)"),
        "expected clean retirement error on non-Unicode secret, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("panicked") && !stderr.contains("raw-tsig-secret"),
        "must neither panic nor leak non-Unicode secret:\n{stderr}"
    );
}

#[test]
fn setjoind_refuses_startup_on_acme_prefixed_env_vars() {
    let exe = env!("CARGO_BIN_EXE_setjoind");
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = tmp.path().join("config.yaml");
    std::fs::write(&cfg, "server:\n  hostname: mail.example.test\n").unwrap();

    for (key, value) in [
        ("ACME_DOMAINS", "mail.example.test"),
        ("ACME_EMAIL", "ops@example.test"),
        ("ACME_CHALLENGE", "http-01"),
        ("ACME_CACHE_DIR", "/var/cache/acme"),
        ("ACME_DNS_PROVIDER", "cloudflare"),
        ("RUST_WORKERS_ON", "acme-renewal"),
    ] {
        let out = Command::new(exe)
            .env_clear()
            .arg("--subsystems=http")
            .env("CONFIG_PATH", &cfg)
            .env(key, value)
            .output()
            .expect("spawn setjoind");

        assert!(
            !out.status.success(),
            "setjoind must fail closed on {key}={value}"
        );
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("retired in Release N+1 (#560)")
                && stderr.contains("docs/guides/EDGE_TLS_ACME_MIGRATION.md"),
            "missing retirement guidance for {key}, got:\n{stderr}"
        );
    }
}

#[test]
fn setjoind_is_silent_on_static_pem_configuration() {
    let exe = env!("CARGO_BIN_EXE_setjoind");
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = tmp.path().join("config.yaml");
    std::fs::write(&cfg, "server:\n  hostname: mail.example.test\n").unwrap();

    // Fails fast at tls_runtime::guard_activation (no https descriptor),
    // proving the ACME retirement guard passes cleanly for static PEM envs.
    let out = Command::new(exe)
        .env_clear()
        .arg("--subsystems=http")
        .env("CONFIG_PATH", &cfg)
        .env("RUST_WORKERS_ON", "http-tls")
        .env("TLS_CERT", "/etc/mail/tls/server.pem")
        .env("TLS_KEY", "/etc/mail/tls/server-key.pem")
        .env("TLS_AUTOCERT_CACHE_DIR", "/var/cache/mailserver/autocert")
        .output()
        .expect("spawn setjoind");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("built-in ACME"),
        "static PEM must not trigger ACME retirement error:\n{stderr}"
    );
    assert!(
        stderr.contains("http-tls requires the socket-activated descriptor named `https`"),
        "expected execution to reach tls_runtime::guard_activation, got:\n{stderr}"
    );
}
