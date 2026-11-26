//! Subprocess verification of Release N built-in ACME deprecation warning (#559).
use std::process::Command;

#[test]
fn setjoind_emits_acme_deprecation_warning_without_leaking_secrets() {
    let exe = env!("CARGO_BIN_EXE_setjoind");
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = tmp.path().join("config.yaml");
    std::fs::write(&cfg, "server:\n  hostname: mail.example.test\n").unwrap();

    // Run with ACME triggers and RUST_WORKERS_ON=http-tls (without an activated
    // https descriptor) so run_with_options executes its early deprecation
    // warning before failing fast at tls_runtime::guard_activation (no DB needed).
    let out = Command::new(exe)
        .env_clear()
        .arg("--subsystems=http")
        .env("CONFIG_PATH", &cfg)
        .env("RUST_WORKERS_ON", "http-tls")
        .env("TLS_AUTOCERT_DOMAINS", "mail.example.test")
        .env("TLS_DNS_PROVIDER", "cloudflare")
        .env(
            "TLS_DNS_CONFIG",
            r#"{"CF_API_TOKEN":"sentinel-secret-do-not-log-559"}"#,
        )
        .output()
        .expect("spawn setjoind");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("DEPRECATION WARNING: built-in ACME"),
        "expected deprecation warning on stderr, got:\n{stderr}"
    );
    assert!(
        stderr.contains("TLS_AUTOCERT_DOMAINS")
            && stderr.contains("TLS_DNS_PROVIDER")
            && stderr.contains("TLS_DNS_CONFIG"),
        "expected trigger names in stderr, got:\n{stderr}"
    );
    assert!(
        stderr.contains("docs/guides/EDGE_TLS_ACME_MIGRATION.md") && stderr.contains("#560"),
        "expected migration guide and #560 reference in stderr, got:\n{stderr}"
    );
    assert!(
        !stderr.contains("sentinel-secret-do-not-log-559"),
        "TLS_DNS_CONFIG secret value leaked to stderr:\n{stderr}"
    );
}

#[test]
fn setjoind_is_silent_on_static_pem_configuration() {
    let exe = env!("CARGO_BIN_EXE_setjoind");
    let tmp = tempfile::tempdir().expect("tempdir");
    let cfg = tmp.path().join("config.yaml");
    std::fs::write(&cfg, "server:\n  hostname: mail.example.test\n").unwrap();

    let out = Command::new(exe)
        .env_clear()
        .arg("--subsystems=http")
        .env("CONFIG_PATH", &cfg)
        .env("RUST_WORKERS_ON", "http-tls")
        .env("TLS_CERT", "/etc/mail/tls/server.pem")
        .env("TLS_KEY", "/etc/mail/tls/server-key.pem")
        .output()
        .expect("spawn setjoind");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("DEPRECATION WARNING: built-in ACME"),
        "static PEM must not trigger ACME deprecation warning:\n{stderr}"
    );
}
