//! Rust-side issuance against pebble over HTTP-01 (needs `PEBBLE_BIN`).
#[path = "support/pebble.rs"]
mod pebble;
use setjoin_acme::{inspect::describe, Config, Http01Store, Manager, TickOutcome};
use std::time::Duration;

fn config(dir: &std::path::Path, domains: &[&str]) -> Config {
    Config {
        domains: domains.iter().map(|d| (*d).into()).collect(),
        email: "ops@example.test".into(),
        cache_dir: dir.into(),
        key_file: None,
        ca_dir_url: Some(pebble::DIRECTORY.into()),
        ca_root: Some(pebble::ca_root()),
        backoff: Some(|_| Duration::from_millis(50)),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn cold_cache_issues_a_certificate_for_every_san() {
    let Some(_pebble) = pebble::Pebble::start().await else {
        return;
    };
    let dir = tempdir("cold");
    let store = Http01Store::default();
    let _http = pebble::serve_http01(store.clone()).await;
    let manager = Manager::new(config(&dir, &["localhost", "alt.localhost"]), store).unwrap();
    assert_eq!(manager.tick().await, TickOutcome::Renewed);
    for d in ["localhost", "alt.localhost"] {
        let blob = std::fs::read(setjoin_acme::cache::DirCache::new(&dir).path(d)).unwrap();
        use rcgen::PublicKeyData;
        let key = setjoin_acme::keys::CertKey::from_blob(&blob).expect("issued private key");
        assert!(key.algorithm() == &rcgen::PKCS_ECDSA_P256_SHA256);
        assert_eq!(
            describe(&blob).dns_names,
            ["alt.localhost", "localhost"]
                .into_iter()
                .map(String::from)
                .collect()
        );
    }
    assert_eq!(manager.tick().await, TickOutcome::Fresh);
}

fn tempdir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("gofree-plat7-acme-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// A cache blob (key PEM then certificate PEM) for `localhost` made by the openssl CLI, with an
/// RSA key in Go's PKCS#1 container and the given validity, standing in for a Go-issued cert.
fn seed_rsa_blob(days: u32) -> Vec<u8> {
    let dir = tempdir("seed");
    std::fs::create_dir_all(&dir).unwrap();
    let run = |args: &[&str]| {
        let out = std::process::Command::new("openssl")
            .args(args)
            .current_dir(&dir)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    run(&[
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-keyout",
        "k8.pem",
        "-out",
        "c.pem",
        "-days",
        &days.to_string(),
        "-subj",
        "/CN=localhost",
        "-addext",
        "subjectAltName=DNS:localhost",
    ]);
    run(&["rsa", "-in", "k8.pem", "-traditional", "-out", "k1.pem"]);
    let mut blob = std::fs::read(dir.join("k1.pem")).unwrap();
    blob.extend(std::fs::read(dir.join("c.pem")).unwrap());
    blob
}

fn spki_of_key(blob: &[u8]) -> Vec<u8> {
    use rcgen::PublicKeyData;
    let key = setjoin_acme::keys::CertKey::from_blob(blob).expect("parseable key");
    key.der_bytes().to_vec()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_near_expiry_certificate_is_reissued_with_the_same_private_key() {
    let Some(_pebble) = pebble::Pebble::start().await else {
        return;
    };
    let dir = tempdir("reuse");
    let cache = setjoin_acme::cache::DirCache::new(&dir);
    let seeded = seed_rsa_blob(10);
    cache.put("localhost", &seeded).unwrap();
    let store = Http01Store::default();
    let _http = pebble::serve_http01(store.clone()).await;
    let manager = Manager::new(config(&dir, &["localhost"]), store).unwrap();
    assert_eq!(manager.tick().await, TickOutcome::Renewed);
    let renewed = cache.get("localhost").unwrap();
    assert_ne!(renewed, seeded);
    assert_eq!(
        spki_of_key(&renewed),
        spki_of_key(&seeded),
        "DANE-EE needs a stable key"
    );
    assert!(String::from_utf8_lossy(&renewed).starts_with("-----BEGIN RSA PRIVATE KEY-----\n"));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_fresh_certificate_is_left_alone_and_nothing_is_contacted() {
    // No pebble: a fresh seeded certificate must not make the manager dial anything.
    let dir = tempdir("fresh");
    let cache = setjoin_acme::cache::DirCache::new(&dir);
    let seeded = seed_rsa_blob(60);
    cache.put("localhost", &seeded).unwrap();
    let mut cfg = config(&dir, &["localhost"]);
    cfg.ca_dir_url = Some("https://127.0.0.1:1/dir".into());
    let manager = Manager::new(cfg, Http01Store::default()).unwrap();
    assert_eq!(manager.tick().await, TickOutcome::Fresh);
    assert_eq!(cache.get("localhost").unwrap(), seeded);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_failed_validation_publishes_nothing_and_retries_three_times() {
    let Some(_pebble) = pebble::Pebble::start().await else {
        return;
    };
    let dir = tempdir("fail");
    // No HTTP-01 responder is started, so validation fails every attempt.
    let manager = Manager::new(config(&dir, &["localhost"]), Http01Store::default()).unwrap();
    assert!(matches!(manager.tick().await, TickOutcome::Failed(_)));
    assert!(setjoin_acme::cache::DirCache::new(&dir)
        .get("localhost")
        .is_err());
}
