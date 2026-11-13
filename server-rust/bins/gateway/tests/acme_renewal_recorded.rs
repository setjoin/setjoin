//! #305: seed-plus-one-tick oracle for the `acme-renewal` worker. Frozen Go's real
//! `LegoManager.renewIfNeeded` (overlay `tests/conformance/acme/acme_tick_test.go.txt`) runs one
//! tick over a seeded certificate cache against a pebble ACME server over HTTP-01; the Rust
//! manager's tick must leave the same cache (file layout, modes, SANs, chain length, key reuse,
//! account key) and make the same number of unanswered validation requests.
//!
//! Record: `GOFREE_RECORD_ACME=all|case,case` + `GOFREE_GO_SOURCE` + `PEBBLE_BIN` (a delete of the
//! golden is not needed; recording replaces it). Replay needs Go neither nor, for the failure-free
//! cases, anything but pebble: `PEBBLE_BIN` is required (a missing binary fails under REQUIRE_DB).
mod drain_oracle;
#[path = "../../../crates/acme/tests/support/pebble.rs"]
mod pebble;
use drain_oracle::{repo_root, BoxError, GoTick};
use serde_json::{json, Value};
use setjoin_acme::{cache::DirCache, inspect::describe, Challenge, Config, Http01Store, Manager};
use std::{os::unix::fs::PermissionsExt, path::Path, time::Duration};

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
const DOMAINS: &[&str] = &["localhost", "alt.localhost"];

#[derive(Clone, Copy)]
enum Seed {
    None,
    /// Certificate for `domain` expiring in `days`, RSA key in Go's PKCS#1 container.
    Rsa(&'static str, u32),
    Garbage(&'static str),
}

struct Case {
    name: &'static str,
    challenge: &'static str,
    seeds: &'static [Seed],
    /// Whether the validation endpoint answers (false: every validation fails).
    serve: bool,
}

const CASES: &[Case] = &[
    Case {
        name: "acme-tls-alpn-cold-cache",
        challenge: "tls-alpn-01",
        seeds: &[Seed::None],
        serve: true,
    },
    Case {
        name: "acme-tls-alpn-near-expiry-reuses-key",
        challenge: "tls-alpn-01",
        seeds: &[Seed::Rsa("localhost", 10)],
        serve: true,
    },
    Case {
        challenge: "http-01",
        name: "acme-cold-cache-two-sans",
        seeds: &[Seed::None],
        serve: true,
    },
    Case {
        challenge: "http-01",
        name: "acme-near-expiry-reuses-the-private-key",
        seeds: &[Seed::Rsa("localhost", 10)],
        serve: true,
    },
    Case {
        challenge: "http-01",
        name: "acme-fresh-certificates-are-untouched",
        seeds: &[Seed::Rsa("localhost", 60), Seed::Rsa("alt.localhost", 60)],
        serve: true,
    },
    Case {
        challenge: "http-01",
        name: "acme-one-stale-domain-reissues-all",
        seeds: &[Seed::Rsa("localhost", 60), Seed::Rsa("alt.localhost", 10)],
        serve: true,
    },
    Case {
        challenge: "http-01",
        name: "acme-corrupt-cache-is-reissued",
        seeds: &[Seed::Garbage("localhost")],
        serve: true,
    },
    Case {
        challenge: "http-01",
        name: "acme-validation-failure-publishes-nothing",
        seeds: &[Seed::None],
        serve: false,
    },
];

fn openssl(dir: &Path, args: &[&str]) {
    let out = std::process::Command::new("openssl")
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Key PEM (PKCS#1, as lego writes RSA keys) then certificate PEM, from the openssl CLI.
fn rsa_blob(scratch: &Path, domain: &str, days: u32) -> Vec<u8> {
    std::fs::create_dir_all(scratch).unwrap();
    openssl(
        scratch,
        &[
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
            &format!("/CN={domain}"),
            "-addext",
            &format!("subjectAltName=DNS:{domain}"),
        ],
    );
    openssl(
        scratch,
        &["rsa", "-in", "k8.pem", "-traditional", "-out", "k1.pem"],
    );
    let mut blob = std::fs::read(scratch.join("k1.pem")).unwrap();
    blob.extend(std::fs::read(scratch.join("c.pem")).unwrap());
    blob
}

/// Seed one cache directory identically for both implementations; returns the seeded blobs.
fn seed(dir: &Path, seeds: &[Seed], scratch: &Path) -> Vec<(String, Vec<u8>)> {
    let cache = DirCache::new(dir);
    let mut out = Vec::new();
    for s in seeds {
        let (domain, blob) = match *s {
            Seed::None => continue,
            Seed::Rsa(d, days) => (d, rsa_blob(&scratch.join(d), d, days)),
            Seed::Garbage(d) => (d, b"not a certificate\n".to_vec()),
        };
        cache.put(domain, &blob).unwrap();
        out.push((domain.to_owned(), blob));
    }
    out
}

fn observe(dir: &Path, seeded: &[(String, Vec<u8>)], misses: u64, strict_key: bool) -> Value {
    let cache = DirCache::new(dir);
    let first_seeded_key = DOMAINS
        .iter()
        .filter_map(|d| seeded.iter().find(|(s, _)| s == d))
        .find_map(|(_, blob)| {
            describe(blob)
                .spki_sha256
                .filter(|_| describe(blob).key_label.is_some())
        });
    let mode = |p: &Path| {
        format!(
            "{:o}",
            std::fs::metadata(p).unwrap().permissions().mode() & 0o777
        )
    };
    let mut files = Vec::new();
    let mut certs = serde_json::Map::new();
    for d in DOMAINS {
        let path = cache.path(d);
        let Ok(blob) = std::fs::read(&path) else {
            continue;
        };
        let before = seeded.iter().find(|(s, _)| s == d).map(|(_, b)| b);
        files.push(json!({"domain": d, "mode": mode(&path), "changed": before != Some(&blob)}));
        let info = describe(&blob);
        let days = info.not_after.map(|t| (t - now()) as f64 / 86400.0);
        let reused = info.spki_sha256.is_some() && info.spki_sha256 == first_seeded_key;
        let mut observation = json!({
            "sans": info.dns_names,
            "chain_certificates": info.chain_certificates,
            "key_first": info.key_first,
            // Keep #305's historical projection; #413 TLS cases also check new keys.
            "key_label": if reused || strict_key { json!(info.key_label) } else { Value::Null },
            "key_reused": reused,
            "valid_days_nearest_10": days.map(|d| ((d / 10.0).round() * 10.0) as i64),
        });
        if strict_key {
            use tokio_rustls::rustls::pki_types::{pem::PemObject, CertificateDer};
            let der = CertificateDer::from_pem_slice(&blob).unwrap();
            let (_, cert) = x509_parser::parse_x509_certificate(&der).unwrap();
            observation["subject"] = json!(cert.subject().to_string());
        }
        certs.insert((*d).into(), observation);
    }
    let account = dir.join("account.key");
    let account_pem = std::fs::read_to_string(&account).unwrap_or_default();
    let names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    json!({
        "dir_mode": mode(dir),
        "files": files,
        "other_entries": names.iter().filter(|n| *n != "account.key" && !DOMAINS.iter().any(|d| cache.path(d).file_name().unwrap().to_string_lossy() == **n)).count(),
        "temp_files": names.iter().filter(|n| n.starts_with(".acme-")).count(),
        "account_key": {
            "present": account.exists(),
            "mode": account.exists().then(|| mode(&account)),
            "label_line": account_pem.lines().next(),
            "cr_free": !account_pem.contains('\r'),
        },
        "certs": certs,
        "challenge_misses": misses,
    })
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn work(name: &str) -> std::path::PathBuf {
    repo_root()
        .unwrap()
        .join("test-results/gofree-plat7-acme")
        .join(name)
}

fn golden_path(case: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/acme/goldens")
        .join(format!("{case}.json"))
}

async fn run_go(case: &Case) -> Result<Value, BoxError> {
    let root = work(case.name);
    let _ = std::fs::remove_dir_all(&root);
    let cache = root.join("go-cache");
    let scratch = root.join("seed-go");
    let seeded = seed(&cache, case.seeds, &scratch);
    let _pebble = pebble::Pebble::start()
        .await
        .ok_or("pebble is required to record")?;
    let out = root.join("go-out.json");
    // Go runs in a container with the host network, as the other drain/tick oracles do.
    if std::env::var_os("GOFREE_ORACLE_CONTAINER_PREFIX").is_none() {
        std::env::set_var("GOFREE_ORACLE_CONTAINER_PREFIX", "gofree-plat7-acme");
    }
    let rel = |p: &Path| {
        format!(
            "/src/test-results/gofree-plat7-acme/{}",
            p.strip_prefix(work("")).unwrap().display()
        )
    };
    let tick =
        GoTick {
            package: "internal/acme",
            overlay: "../acme/acme_tick_test.go.txt",
            test: "TestGoFreeAcmeTick",
            file: "gofree_acme_tick_test.go",
            env: vec![
            (
                "GOFREE_ACME_CASE".into(),
                json!({
                    "domains": DOMAINS,
                    "challenge": case.challenge,
                    "email": "ops@example.test",
                    "cache_dir": rel(&cache),
                    "directory": pebble::DIRECTORY,
                    "ca": "/src/server-rust/tests/conformance/acme/pebble/certs/pebble.minica.pem",
                    "out": rel(&out),
                })
                .to_string(),
            ),
            ("GOFREE_ACME_SERVE".into(), if case.serve { "1" } else { "0" }.into()),
        ],
            docker: vec![],
        };
    tokio::task::spawn_blocking(move || tick.run()).await??;
    let misses = serde_json::from_slice::<Value>(&std::fs::read(&out)?)?["challenge_misses"]
        .as_u64()
        .unwrap();
    Ok(observe(
        &cache,
        &seeded,
        misses,
        case.challenge == "tls-alpn-01",
    ))
}

async fn run_rust(case: &Case) -> Result<Option<Value>, BoxError> {
    let root = work(&format!("{}-rust", case.name));
    let _ = std::fs::remove_dir_all(&root);
    let cache = root.join("cache");
    let seeded = seed(&cache, case.seeds, &root.join("seed"));
    let Some(_pebble) = pebble::Pebble::start().await else {
        return Ok(None);
    };
    let store = Http01Store::default();
    let responder = if case.challenge == "http-01" {
        Some(pebble::serve_http01_with(store.clone(), case.serve).await)
    } else {
        None
    };
    struct Task(tokio::task::JoinHandle<()>);
    impl Drop for Task {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let mut alpn_task = None;
    let challenge = if case.challenge == "tls-alpn-01" {
        let frontend = setjoin_tls::Frontend::from_env(&|k| match k {
            "TLS_AUTOCERT_DOMAINS" => Some(DOMAINS.join(",")),
            "TLS_AUTOCERT_CACHE_DIR" => Some(cache.display().to_string()),
            _ => None,
        })?
        .unwrap();
        let challenge = Challenge::TlsAlpn01(frontend.tls_alpn_store());
        let listener = tokio::net::TcpListener::bind("[::]:5071").await?;
        alpn_task = Some(Task(tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let f = frontend.clone();
                tokio::spawn(async move {
                    let _ = f.accept(stream).await;
                });
            }
        })));
        challenge
    } else {
        Challenge::Http01(store)
    };
    let manager = Manager::new_with_challenge(
        Config {
            domains: DOMAINS.iter().map(|d| (*d).into()).collect(),
            email: "ops@example.test".into(),
            cache_dir: cache.clone(),
            key_file: None,
            ca_dir_url: Some(pebble::DIRECTORY.into()),
            ca_root: Some(pebble::ca_root()),
            backoff: Some(|_| Duration::from_millis(50)),
        },
        challenge,
    )?;
    manager.tick().await;
    // New keys deliberately differ from Go (owner decision 2026-11-03).
    // Check the actual key even in #305's older key-label-masked HTTP goldens.
    if !seeded.iter().any(|(_, blob)| setjoin_acme::keys::CertKey::from_blob(blob).is_some()) {
        use rcgen::PublicKeyData;
        for domain in DOMAINS {
            if let Ok(blob) = DirCache::new(&cache).get(domain) {
                let key = setjoin_acme::keys::CertKey::from_blob(&blob).expect("issued private key");
                assert!(key.algorithm() == &rcgen::PKCS_ECDSA_P256_SHA256);
            }
        }
    }
    let misses = responder
        .as_ref()
        .map_or(0, |r| r.misses.load(std::sync::atomic::Ordering::SeqCst));
    drop(alpn_task);
    Ok(Some(observe(
        &cache,
        &seeded,
        misses,
        case.challenge == "tls-alpn-01",
    )))
}

#[tokio::test(flavor = "multi_thread")]
async fn acme_renewal_seed_plus_one_tick() -> Result<(), BoxError> {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let record = std::env::var("GOFREE_RECORD_ACME").ok();
    for case in CASES {
        let recording = record
            .as_deref()
            .is_some_and(|f| f == "all" || f.split(',').any(|t| t == case.name));
        if recording {
            let observation = run_go(case).await?;
            let path = golden_path(case.name);
            let _ = std::fs::remove_file(&path);
            setjoin_conformance::golden::record(
                &path,
                &json!({"format":1,"case":case.name,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}),
            )?;
            continue;
        }
        let Some(actual) = run_rust(case).await? else {
            return Ok(());
        };
        let golden: Value = serde_json::from_slice(&std::fs::read(golden_path(case.name))?)?;
        let divergences: Value = serde_json::from_str(include_str!(
            "../../../tests/conformance/acme/divergences.json"
        ))?;
        setjoin_conformance::golden::compare_reviewed(
            "acme-renewal", case.name, &golden["observation"], &actual, &divergences,
        )?;
        println!(
            "GOLDEN-REPLAY: acme-renewal {} :: seed-plus-one-tick",
            case.name
        );
    }
    Ok(())
}
