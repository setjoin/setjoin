//! Startup-bound deployment and on-disk key compatibility seams.
use std::os::unix::process::CommandExt;
use std::{path::PathBuf, process::Command};
struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "gofree-idfed1-keys-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
#[test]
fn provider_configuration_is_startup_bound_and_validated() {
    if std::env::var_os("IDFED1_CONFIG_PROBE").is_some() {
        let cfg = setjoin_auth::Config::from_env();
        let valid = std::env::var("IDFED1_EXPECT_VALID").unwrap() == "true";
        if valid {
            let cfg = cfg.unwrap();
            assert!(cfg.oidc_enabled);
            assert_eq!(cfg.oidc_hostname, "auth.idfed1.test");
            assert_eq!(cfg.oidc_private_key, "/owned/private.pem");
            assert_eq!(cfg.oidc_public_key, "/owned/public.pem");
        } else {
            assert!(cfg.is_err());
        }
        return;
    }
    for (origins, valid) in [
        ("https://spa.idfed1.test", true),
        (
            "http://localhost:3000,http://127.0.0.1:3000,http://[::1]:3000",
            true,
        ),
        ("https://spa.idfed1.test///", true),
        ("http://remote.idfed1.test", false),
        ("https://spa.idfed1.test/path", false),
        ("https://user@spa.idfed1.test", false),
        ("https://*.idfed1.test", false),
        ("http://127.1", false),
        ("http://2130706433", false),
    ] {
        let out = Command::new(std::env::current_exe().unwrap())
            .arg0("gofree-idfed1-config-probe")
            .args([
                "--exact",
                "provider_configuration_is_startup_bound_and_validated",
                "--nocapture",
            ])
            .env("CRYPTO_ALGORITHM_PROFILE", "standard")
            .env("IDFED1_CONFIG_PROBE", "1")
            .env("IDFED1_EXPECT_VALID", valid.to_string())
            .env_remove("SETJOIN_CONFIG")
            .env("JWT_SECRET", "idfed1-configuration-fixture-32-bytes")
            .env("DB_DSN", std::env::var("TEST_DB_DSN").unwrap())
            .env("LISTEN_ADDR", "127.0.0.1:0")
            .env("HOSTNAME", "auth.idfed1.test")
            .env("OIDC_PROVIDER_ENABLED", "TRUE")
            .env("OIDC_PROVIDER_PRIVATE_KEY_FILE", "/owned/private.pem")
            .env("OIDC_PROVIDER_PUBLIC_KEY_FILE", "/owned/public.pem")
            .env("OIDC_PROVIDER_ALLOWED_ORIGINS", origins)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "origin {origins}: {}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
#[test]
fn existing_go_keys_survive_reload_and_new_keys_use_the_same_disk_profile() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = Scratch::new();
    let private = scratch.0.join("private.pem");
    let public = scratch.0.join("public.pem");
    std::fs::write(
        &private,
        include_str!("../../../tests/conformance/identity-oidc/op-private.pem"),
    )
    .unwrap();
    let load = || {
        setjoin_identity::oidc::SigningKey::load(
            private.to_str().unwrap(),
            public.to_str().unwrap(),
        )
    };
    let key = load().unwrap();
    let before = std::fs::read(&private).unwrap();
    let jwks = key.jwks();
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/identity-oidc/goldens/keys-success.json"
    ))
    .unwrap();
    assert_eq!(
        jwks,
        fixture["observation"]["response"]["body"].as_str().unwrap()
    );
    assert_eq!(load().unwrap().jwks(), jwks);
    assert_eq!(std::fs::read(&private).unwrap(), before);
    assert_eq!(
        std::fs::metadata(&private).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        std::fs::metadata(&public).unwrap().permissions().mode() & 0o777,
        0o644
    );
    std::fs::remove_file(&private).unwrap();
    let generated = load().unwrap();
    assert_ne!(generated.jwks(), jwks);
    let bytes = std::fs::read(&private).unwrap();
    assert!(std::str::from_utf8(&bytes)
        .unwrap()
        .starts_with("-----BEGIN PRIVATE KEY-----"));
    assert_eq!(load().unwrap().jwks(), generated.jwks());
    assert_eq!(std::fs::read(&private).unwrap(), bytes);
    std::fs::write(&private, "not a private key").unwrap();
    assert!(load().is_err());
    assert!(setjoin_identity::oidc::SigningKey::load(
        private.to_str().unwrap(),
        private.to_str().unwrap()
    )
    .is_err());
}

/// Owner-approved security fix 2026-11-05 (#523): frozen Go tolerated RSA-1024
/// and e=3 signing keys. The Rust provider fails closed at startup with an
/// operator rotate message and never signs, rotates, or publishes them.
#[test]
fn weak_pre_existing_go_keys_fail_closed_at_startup_with_a_rotate_message() {
    let corpus = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/identity-oidc");
    let fixture: serde_json::Value =
        serde_json::from_slice(&std::fs::read(corpus.join("legacy-key-goldens.json")).unwrap())
            .unwrap();
    let scratch = Scratch::new();
    for name in fixture["profiles"].as_object().unwrap().keys() {
        let private = scratch.0.join(format!("{name}.pem"));
        let public = scratch.0.join(format!("{name}-public.pem"));
        std::fs::copy(corpus.join(format!("{name}.pem")), &private).unwrap();
        let before = std::fs::read(&private).unwrap();
        let error = setjoin_identity::oidc::SigningKey::load(
            private.to_str().unwrap(),
            public.to_str().unwrap(),
        )
        .err()
        .unwrap_or_else(|| panic!("{name}: a weak key was accepted"));
        assert!(error.contains("Rotate it"), "{name}: {error}");
        assert!(error.contains("2048"), "{name}: {error}");
        assert_eq!(std::fs::read(&private).unwrap(), before, "{name}: silently rotated");
        assert!(!public.exists(), "{name}: weak public key published");
    }
}
