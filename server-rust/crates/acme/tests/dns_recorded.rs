//! #413 DNS-01 providers: real managed tick against local in-process DNS and API peripherals.
#[path = "support/dns_fake.rs"]
mod dns_fake;
#[path = "support/pebble.rs"]
mod pebble;
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn repo_root() -> Result<PathBuf, BoxError> {
    Ok(Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()?)
}

struct Work(PathBuf);
impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn fake(work: &Work, unsigned: bool) -> dns_fake::DnsFake {
    dns_fake::DnsFake::start(work.0.join("journal.json"), unsigned, None).await
}

async fn fake_with_publish_gate(work: &Work, unsigned: bool) -> dns_fake::DnsFake {
    dns_fake::DnsFake::start(
        work.0.join("journal.json"),
        unsigned,
        Some(dns_fake::PublishGate {
            started: work.0.join("publish-started"),
            release: work.0.join("publish-release"),
        }),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_finishes_dns_publication_and_cleanup_before_returning() -> Result<(), BoxError> {
    let root = repo_root()?;
    let work = Work(
        root.join("test-results/gofree-tlsfront")
            .join(format!("dns-cancel-{}", std::process::id())),
    );
    std::fs::create_dir_all(&work.0)?;
    let api = fake_with_publish_gate(&work, false).await;
    let _ca = pebble::Pebble::start().await.expect("Pebble required");
    let provider = setjoin_acme::dns::Provider::with_endpoints(
        "cloudflare",
        &config("cloudflare", &api.dns_addr).to_string(),
        &[api.dns_addr.clone()],
        setjoin_acme::dns::Endpoints {
            cloudflare: Some(format!("{}/client/v4", api.http_url)),
            route53: None,
        },
    )?;
    let manager = setjoin_acme::Manager::new_with_challenge(
        setjoin_acme::Config {
            domains: vec!["*.example.test".into()],
            email: "ops@example.test".into(),
            cache_dir: work.0.join("cache"),
            key_file: None,
            ca_dir_url: Some(pebble::DIRECTORY.into()),
            ca_root: Some(pebble::ca_root()),
            backoff: Some(|_| Duration::from_millis(50)),
        },
        setjoin_acme::Challenge::Dns01(provider),
    )?;
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        manager
            .run(async {
                let _ = stopped.await;
            })
            .await
    });
    tokio::time::timeout(Duration::from_secs(15), async {
        while !work.0.join("publish-started").exists() {
            assert!(
                !task.is_finished(),
                "renewal stopped before DNS publication"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await?;
    stop.send(()).unwrap();
    // The response has not arrived, so the record ID is still unavailable.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let waited_for_publication = !task.is_finished();
    std::fs::write(work.0.join("publish-release"), "release")?;
    tokio::time::timeout(Duration::from_secs(10), task).await??;
    assert!(
        waited_for_publication,
        "worker exited with a published DNS record still outstanding"
    );
    let golden: Value = serde_json::from_slice(&std::fs::read(
        root.join("server-rust/tests/conformance/tlsfront/dns-cloudflare.json"),
    )?)?;
    assert_eq!(
        observation(&work),
        json!({
            "events": &golden["observation"]["events"].as_array().unwrap()[..3],
            "published": false,
        }),
        "shutdown must clean the one started attempt, without retry or cache publication"
    );
    Ok(())
}

fn config(provider: &str, dns_addr: &str) -> Value {
    match provider {
        "cloudflare" => json!({"CF_API_TOKEN": "public-test-token"}),
        "route53" => {
            json!({"AWS_ACCESS_KEY_ID": "public-access", "AWS_SECRET_ACCESS_KEY": "public-secret"})
        }
        _ => {
            json!({"RFC2136_NAMESERVER": dns_addr, "RFC2136_TSIG_KEY": "fixture-key.", "RFC2136_TSIG_SECRET": "cHVibGljLXRlc3Qta2V5"})
        }
    }
}

fn observation(work: &Work) -> Value {
    let journal: Value = serde_json::from_slice(
        &std::fs::read(work.0.join("journal.json")).expect("no successful provider IO"),
    )
    .unwrap();
    let cache = setjoin_acme::cache::DirCache::new(work.0.join("cache"));
    json!({"events": journal, "published": cache.get("*.example.test").is_ok()})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns01_provider_ticks_match_frozen_go() -> Result<(), BoxError> {
    let root = repo_root()?;
    for provider in [
        "cloudflare",
        "route53",
        "rfc2136",
        "route53-env",
        "rfc2136-sha1",
        "rfc2136-sha224",
        "rfc2136-sha384",
        "rfc2136-sha512",
        "rfc2136-unsigned",
    ] {
        if std::env::var("GOFREE_DNS_CASES")
            .ok()
            .is_some_and(|f| !f.split(',').any(|s| s == provider))
        {
            continue;
        }
        let work = Work(
            root.join("test-results/gofree-tlsfront")
                .join(format!("dns-{provider}-{}", std::process::id())),
        );
        std::fs::create_dir_all(&work.0)?;
        let api = fake(&work, provider.ends_with("unsigned")).await;
        let _ca = pebble::Pebble::start().await.expect("Pebble required");
        let kind = if provider.starts_with("rfc2136") {
            "rfc2136"
        } else if provider == "route53-env" {
            "route53"
        } else {
            provider
        };
        let _env = (provider == "route53-env").then(Env::fixture_aws);
        let mut credentials = config(kind, &api.dns_addr);
        if provider == "route53-env" {
            credentials = json!({});
        }
        if let Some(algorithm) = provider.strip_prefix("rfc2136-sha") {
            credentials["RFC2136_TSIG_ALGORITHM"] = json!(format!("hmac-sha{algorithm}"));
        }
        if provider.ends_with("unsigned") {
            credentials
                .as_object_mut()
                .unwrap()
                .remove("RFC2136_TSIG_KEY");
            credentials
                .as_object_mut()
                .unwrap()
                .remove("RFC2136_TSIG_SECRET");
        }
        let credentials = credentials.to_string();
        let golden = root.join(format!(
            "server-rust/tests/conformance/tlsfront/dns-{provider}.json"
        ));
        let native = setjoin_acme::dns::Provider::with_endpoints(
            kind,
            &credentials,
            &[api.dns_addr.clone()],
            setjoin_acme::dns::Endpoints {
                cloudflare: Some(format!("{}/client/v4", api.http_url)),
                route53: Some(api.http_url.clone()),
            },
        )?;
        let manager = setjoin_acme::Manager::new_with_challenge(
            setjoin_acme::Config {
                domains: vec!["*.example.test".into()],
                email: "ops@example.test".into(),
                cache_dir: work.0.join("cache"),
                key_file: None,
                ca_dir_url: Some(pebble::DIRECTORY.into()),
                ca_root: Some(pebble::ca_root()),
                backoff: Some(|_| Duration::from_millis(50)),
            },
            setjoin_acme::Challenge::Dns01(native),
        )?;
        assert!(matches!(
            manager.tick().await,
            setjoin_acme::TickOutcome::Failed(_)
        ));
        let recorded: Value = serde_json::from_slice(&std::fs::read(&golden)?)?;
        assert_eq!(recorded["observation"], observation(&work), "{provider}");
        println!("GOLDEN-REPLAY: DNS-01 {provider} :: seed-plus-one-tick");
    }
    Ok(())
}

struct Env(Vec<(&'static str, Option<std::ffi::OsString>)>);
impl Env {
    fn fixture_aws() -> Self {
        let mut old = Vec::new();
        for (name, value) in [
            ("AWS_ACCESS_KEY_ID", "public-access"),
            ("AWS_SECRET_ACCESS_KEY", "public-secret"),
            ("AWS_SESSION_TOKEN", ""),
        ] {
            old.push((name, std::env::var_os(name)));
            std::env::set_var(name, value);
        }
        Self(old)
    }
}
impl Drop for Env {
    fn drop(&mut self) {
        for (name, value) in &self.0 {
            match value {
                Some(v) => std::env::set_var(name, v),
                None => std::env::remove_var(name),
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_apis_reject_wrong_provider_credentials() -> Result<(), BoxError> {
    let root = repo_root()?;
    for provider in ["cloudflare", "route53", "rfc2136"] {
        let work = Work(
            root.join("test-results/gofree-tlsfront")
                .join(format!("mutant-{provider}-{}", std::process::id())),
        );
        std::fs::create_dir_all(&work.0)?;
        let api = fake(&work, false).await;
        let mut c = config(provider, &api.dns_addr);
        let field = match provider {
            "cloudflare" => "CF_API_TOKEN",
            "route53" => "AWS_SECRET_ACCESS_KEY",
            _ => "RFC2136_TSIG_SECRET",
        };
        c[field] = json!("d3Jvbmcta2V5");
        let native = setjoin_acme::dns::Provider::with_endpoints(
            provider,
            &c.to_string(),
            &[api.dns_addr.clone()],
            setjoin_acme::dns::Endpoints {
                cloudflare: Some(format!("{}/client/v4", api.http_url)),
                route53: Some(api.http_url.clone()),
            },
        )?;
        use base64::Engine;
        assert!(native
            .present(&setjoin_acme::dns::RecordSpec {
                name: "_acme-challenge.example.test.".into(),
                value: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1; 32])
            })
            .await
            .is_err());
        assert!(
            !work.0.join("journal.json").exists(),
            "bad credentials caused a provider mutation"
        );
    }
    Ok(())
}

/// Exercise every provider, TSIG hash, AWS env auth, multi-domain cleanup, and publish gate
/// directly against `dns_fake::DnsFake` (no Pebble process needed) and assert exact parity
/// with the immutable frozen-Go recordings' event sequences.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns_fake_provider_roundtrips_match_golden_events() -> Result<(), BoxError> {
    use base64::Engine;
    let root = repo_root()?;
    let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 32]);

    for provider in [
        "cloudflare",
        "route53",
        "rfc2136",
        "route53-env",
        "rfc2136-sha1",
        "rfc2136-sha224",
        "rfc2136-sha384",
        "rfc2136-sha512",
        "rfc2136-unsigned",
    ] {
        let work = Work(
            root.join("test-results/gofree-tlsfront")
                .join(format!("fake-roundtrip-{provider}-{}", std::process::id())),
        );
        std::fs::create_dir_all(&work.0)?;
        let api = fake(&work, provider.ends_with("unsigned")).await;
        let kind = if provider.starts_with("rfc2136") {
            "rfc2136"
        } else if provider == "route53-env" {
            "route53"
        } else {
            provider
        };
        let _env = (provider == "route53-env").then(Env::fixture_aws);
        let mut credentials = config(kind, &api.dns_addr);
        if provider == "route53-env" {
            credentials = json!({});
        }
        if let Some(algorithm) = provider.strip_prefix("rfc2136-sha") {
            credentials["RFC2136_TSIG_ALGORITHM"] = json!(format!("hmac-sha{algorithm}"));
        }
        if provider.ends_with("unsigned") {
            credentials
                .as_object_mut()
                .unwrap()
                .remove("RFC2136_TSIG_KEY");
            credentials
                .as_object_mut()
                .unwrap()
                .remove("RFC2136_TSIG_SECRET");
        }
        let native = setjoin_acme::dns::Provider::with_endpoints(
            kind,
            &credentials.to_string(),
            &[api.dns_addr.clone()],
            setjoin_acme::dns::Endpoints {
                cloudflare: Some(format!("{}/client/v4", api.http_url)),
                route53: Some(api.http_url.clone()),
            },
        )?;
        // Three present + cleanup rounds match one Go tick (3 attempts per round).
        for _ in 0..3 {
            let spec = native.record("*.example.test", challenge.clone()).await?;
            native.present(&spec).await?;
            native.clean_up(&spec).await?;
        }
        let golden: Value = serde_json::from_slice(&std::fs::read(root.join(format!(
            "server-rust/tests/conformance/tlsfront/dns-{provider}.json"
        )))?)?;
        assert_eq!(golden["observation"], observation(&work), "{provider}");
    }

    // Multi-domain present + cleanup across all 3 providers (tests alt record-id and Route53 DELETE).
    for provider in ["cloudflare", "route53", "rfc2136"] {
        let work = Work(
            root.join("test-results/gofree-tlsfront")
                .join(format!("fake-multi-{provider}-{}", std::process::id())),
        );
        std::fs::create_dir_all(&work.0)?;
        let api = fake(&work, false).await;
        let native = setjoin_acme::dns::Provider::with_endpoints(
            provider,
            &config(provider, &api.dns_addr).to_string(),
            &[api.dns_addr.clone()],
            setjoin_acme::dns::Endpoints {
                cloudflare: Some(format!("{}/client/v4", api.http_url)),
                route53: Some(api.http_url.clone()),
            },
        )?;
        for _ in 0..3 {
            let s1 = native.record("*.example.test", challenge.clone()).await?;
            let s2 = native.record("alt.example.test", challenge.clone()).await?;
            if provider == "rfc2136" {
                native.present(&s1).await?;
                native.clean_up(&s1).await?;
                native.present(&s2).await?;
                native.clean_up(&s2).await?;
            } else {
                native.present(&s1).await?;
                native.present(&s2).await?;
                native.clean_up(&s1).await?;
                native.clean_up(&s2).await?;
            }
        }
        let golden: Value = serde_json::from_slice(&std::fs::read(root.join(format!(
            "server-rust/tests/conformance/tlsfront/dns-{provider}-multi-zone.json"
        )))?)?;
        assert_eq!(
            normalize_multi(provider, golden["observation"].clone()),
            normalize_multi(provider, observation(&work)),
            "{provider}-multi"
        );
    }

    // Verify Cloudflare publish gate holds until release, then cleanup succeeds.
    {
        let work = Work(
            root.join("test-results/gofree-tlsfront")
                .join(format!("fake-gate-{}", std::process::id())),
        );
        std::fs::create_dir_all(&work.0)?;
        let api = fake_with_publish_gate(&work, false).await;
        let native = setjoin_acme::dns::Provider::with_endpoints(
            "cloudflare",
            &config("cloudflare", &api.dns_addr).to_string(),
            &[api.dns_addr.clone()],
            setjoin_acme::dns::Endpoints {
                cloudflare: Some(format!("{}/client/v4", api.http_url)),
                route53: None,
            },
        )?;
        let spec = native.record("*.example.test", challenge).await?;
        let p = native.clone();
        let s = spec.clone();
        let present_task = tokio::spawn(async move { p.present(&s).await });
        tokio::time::timeout(Duration::from_secs(5), async {
            while !work.0.join("publish-started").exists() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(!present_task.is_finished(), "publish gate did not hold");
        std::fs::write(work.0.join("publish-release"), "release")?;
        tokio::time::timeout(Duration::from_secs(5), present_task).await???;
        native.clean_up(&spec).await?;
        let golden: Value = serde_json::from_slice(&std::fs::read(
            root.join("server-rust/tests/conformance/tlsfront/dns-cloudflare.json"),
        )?)?;
        assert_eq!(
            observation(&work),
            json!({
                "events": &golden["observation"]["events"].as_array().unwrap()[..3],
                "published": false,
            })
        );
    }

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn route53_default_endpoints_match_frozen_sdk() -> Result<(), BoxError> {
    let root = repo_root()?;
    let path = root.join("server-rust/tests/conformance/tlsfront/route53-endpoints.json");
    let golden: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    for row in golden["rows"].as_array().unwrap() {
        let (endpoint, signing) =
            setjoin_acme::dns::route53_default_target(row["region"].as_str().unwrap());
        assert_eq!(endpoint, row["endpoint"], "{}", row["region"]);
        assert_eq!(signing, row["signing_region"], "{}", row["region"]);
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns01_multi_domain_ticks_match_frozen_go() -> Result<(), BoxError> {
    let root = repo_root()?;
    for provider in ["cloudflare", "route53", "rfc2136"] {
        let work = Work(
            root.join("test-results/gofree-tlsfront")
                .join(format!("dns-multi-{provider}-{}", std::process::id())),
        );
        std::fs::create_dir_all(&work.0)?;
        let api = fake(&work, false).await;
        let _ca = pebble::Pebble::start().await.expect("Pebble required");
        let credentials = config(provider, &api.dns_addr).to_string();
        let domains = vec!["*.example.test".to_owned(), "alt.example.test".to_owned()];
        let golden = root.join(format!(
            "server-rust/tests/conformance/tlsfront/dns-{provider}-multi-zone.json"
        ));
        let native = setjoin_acme::dns::Provider::with_endpoints(
            provider,
            &credentials,
            &[api.dns_addr.clone()],
            setjoin_acme::dns::Endpoints {
                cloudflare: Some(format!("{}/client/v4", api.http_url)),
                route53: Some(api.http_url.clone()),
            },
        )?;
        let manager = setjoin_acme::Manager::new_with_challenge(
            setjoin_acme::Config {
                domains,
                email: "ops@example.test".into(),
                cache_dir: work.0.join("cache"),
                key_file: None,
                ca_dir_url: Some(pebble::DIRECTORY.into()),
                ca_root: Some(pebble::ca_root()),
                backoff: Some(|_| Duration::from_millis(50)),
            },
            setjoin_acme::Challenge::Dns01(native),
        )?;
        assert!(matches!(
            manager.tick().await,
            setjoin_acme::TickOutcome::Failed(_)
        ));
        let recorded: Value = serde_json::from_slice(&std::fs::read(&golden)?)?;
        assert_eq!(
            normalize_multi(provider, recorded["observation"].clone()),
            normalize_multi(provider, observation(&work)),
            "{provider}"
        );
    }
    Ok(())
}

// Pebble randomizes authorization order. Preserve every call/body and ordering
// within an authorization; canonicalize only independent names within a phase.
fn normalize_multi(provider: &str, mut observation: Value) -> Value {
    let events = observation["events"].as_array().unwrap();
    let mut normalized = Vec::new();
    let sort = |rows: &mut [Value]| rows.sort_by_key(Value::to_string);
    if provider == "cloudflare" {
        assert_eq!(
            events.len(),
            13,
            "three rounds must process both authorizations"
        );
        assert_eq!(events[0]["op"], "zone");
        normalized.push(events[0].clone());
        for round in events[1..].chunks_exact(4) {
            assert!(round[..2].iter().all(|r| r["op"] == "present"));
            assert!(round[2..].iter().all(|r| r["op"] == "cleanup"));
            let mut prepare = round[..2].to_vec();
            let mut cleanup = round[2..].to_vec();
            sort(&mut prepare);
            sort(&mut cleanup);
            normalized.extend(prepare);
            normalized.extend(cleanup);
        }
    } else {
        let width = if provider == "route53" { 12 } else { 6 };
        assert_eq!(
            events.len(),
            width * 3,
            "three rounds must process both authorizations"
        );
        for round in events.chunks_exact(width) {
            let mut calls = Vec::new();
            for sequence in round.chunks_exact(3) {
                if provider == "route53" {
                    assert_eq!(sequence[0]["op"], "zones");
                    assert_eq!(sequence[1]["op"], "records");
                    assert_eq!(sequence[1]["name"], sequence[2]["name"]);
                } else {
                    assert_eq!(
                        sequence
                            .iter()
                            .map(|r| r["op"].as_u64().unwrap())
                            .collect::<Vec<_>>(),
                        [255, 1, 254]
                    );
                    assert!(sequence.iter().all(|r| r["name"] == sequence[0]["name"]));
                }
                calls.push(json!(sequence));
            }
            // Route53 has two prepares then two cleanups; RFC2136 requires
            // complete Present/CleanUp sequences for one name before the next.
            for phase in calls.chunks_mut(2) {
                sort(phase);
            }
            normalized.extend(
                calls
                    .into_iter()
                    .flat_map(|r| r.as_array().unwrap().clone()),
            );
        }
    }
    observation["events"] = json!(normalized);
    observation
}
