//! #413 DNS-01 providers: real managed tick against local DNS and API peripherals.
#[path = "support/pebble.rs"]
mod pebble;
#[path = "../../../tests/conformance/tlsfront/peer.rs"]
mod peer;
#[path = "../../../tests/conformance/tlsfront/tick.rs"]
mod tick;
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
struct Work(PathBuf);
impl Drop for Work {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
async fn fake(root: &Path, work: &Work, unsigned: bool) -> (peer::Server, Value) {
    fake_with_publish_gate(root, work, unsigned, false).await
}
async fn fake_with_publish_gate(
    root: &Path,
    work: &Work,
    unsigned: bool,
    gated: bool,
) -> (peer::Server, Value) {
    let ready = work.0.join("ready.json");
    let mut config = json!({"Mode":"dns-api","DNS":{"Ready":ready,"Journal":work.0.join("journal.json"),"AllowUnsigned":unsigned}});
    if gated {
        config["DNS"]["PublishStarted"] = json!(work.0.join("publish-started"));
        config["DNS"]["PublishRelease"] = json!(work.0.join("publish-release"));
    }
    // The peer is a docker container: on a loaded host its start can take far longer than 5 s.
    let server = peer::Server::spawn(root, &config, &work.0.join("fake.log"));
    for _ in 0..1200 {
        // The Go fake writes the file with os.WriteFile, which creates it empty before the bytes
        // land, so the file existing is not the file being complete. Ready means it parses; an
        // unparsable file that stays so is reported below with the fake's log.
        if let Ok(v) = std::fs::read(&ready)
            .map_err(|e| e.to_string())
            .and_then(|b| serde_json::from_slice::<Value>(&b).map_err(|e| e.to_string()))
        {
            return (server, v);
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!(
        "DNS fake did not start: {}",
        std::fs::read_to_string(work.0.join("fake.log")).unwrap()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_finishes_dns_publication_and_cleanup_before_returning(
) -> Result<(), tick::BoxError> {
    let root = tick::repo_root()?;
    let work = Work(
        root.join("test-results/gofree-tlsfront")
            .join(format!("dns-cancel-{}", std::process::id())),
    );
    std::fs::create_dir_all(&work.0)?;
    let (_api, ready) = fake_with_publish_gate(&root, &work, false, true).await;
    let _ca = pebble::Pebble::start().await.expect("Pebble required");
    let provider = setjoin_acme::dns::Provider::with_endpoints(
        "cloudflare",
        &config("cloudflare", &ready).to_string(),
        &[ready["dns"].as_str().unwrap().into()],
        setjoin_acme::dns::Endpoints {
            cloudflare: Some(format!("{}/client/v4", ready["http"].as_str().unwrap())),
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
fn config(provider: &str, ready: &Value) -> Value {
    match provider {
        "cloudflare" => json!({"CF_API_TOKEN":"public-test-token"}),
        "route53" => {
            json!({"AWS_ACCESS_KEY_ID":"public-access","AWS_SECRET_ACCESS_KEY":"public-secret"})
        }
        _ => {
            json!({"RFC2136_NAMESERVER":ready["dns"],"RFC2136_TSIG_KEY":"fixture-key.","RFC2136_TSIG_SECRET":"cHVibGljLXRlc3Qta2V5"})
        }
    }
}
fn observation(work: &Work) -> Value {
    let journal: Value = serde_json::from_slice(
        &std::fs::read(work.0.join("journal.json")).expect("no successful provider IO"),
    )
    .unwrap();
    let cache = setjoin_acme::cache::DirCache::new(work.0.join("cache"));
    json!({"events":journal,"published":cache.get("*.example.test").is_ok()})
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dns01_provider_ticks_match_frozen_go() -> Result<(), tick::BoxError> {
    let root = tick::repo_root()?;
    let record = std::env::var("GOFREE_RECORD_DNS").ok();
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
        let (_api, ready) = fake(&root, &work, provider.ends_with("unsigned")).await;
        let _ca = pebble::Pebble::start().await.expect("Pebble required");
        let kind = if provider.starts_with("rfc2136") {
            "rfc2136"
        } else if provider == "route53-env" {
            "route53"
        } else {
            provider
        };
        let _env = (provider == "route53-env").then(|| Env::fixture_aws());
        let mut credentials = config(kind, &ready);
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
        let recording = record
            .as_deref()
            .is_some_and(|s| s == "all" || s == provider);
        let golden = root.join(format!(
            "server-rust/tests/conformance/tlsfront/dns-{provider}.json"
        ));
        if recording {
            assert!(!golden.exists(), "immutable recording already exists");
            let cfg = json!({"Provider":kind,"UseEnv":provider=="route53-env","Config":credentials,"Cache":format!("/src/{}/cache",work.0.strip_prefix(&root)?.display()),"Directory":pebble::DIRECTORY,"CA":"/src/server-rust/tests/conformance/acme/pebble/certs/pebble.minica.pem","API":ready["http"],"Resolver":ready["dns"]});
            tokio::task::spawn_blocking(move || tick::dns_tick(cfg)).await??;
            std::fs::write(
                &golden,
                serde_json::to_vec_pretty(
                    &json!({"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation(&work)}),
                )?,
            )?;
        } else {
            let native = setjoin_acme::dns::Provider::with_endpoints(
                kind,
                &credentials,
                &[ready["dns"].as_str().unwrap().into()],
                setjoin_acme::dns::Endpoints {
                    cloudflare: Some(format!("{}/client/v4", ready["http"].as_str().unwrap())),
                    route53: Some(ready["http"].as_str().unwrap().into()),
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
async fn dns_apis_reject_wrong_provider_credentials() -> Result<(), tick::BoxError> {
    let root = tick::repo_root()?;
    for provider in ["cloudflare", "route53", "rfc2136"] {
        let work = Work(
            root.join("test-results/gofree-tlsfront")
                .join(format!("mutant-{provider}-{}", std::process::id())),
        );
        std::fs::create_dir_all(&work.0)?;
        let (_api, ready) = fake(&root, &work, false).await;
        let mut c = config(provider, &ready);
        let field = match provider {
            "cloudflare" => "CF_API_TOKEN",
            "route53" => "AWS_SECRET_ACCESS_KEY",
            _ => "RFC2136_TSIG_SECRET",
        };
        c[field] = json!("d3Jvbmcta2V5");
        let native = setjoin_acme::dns::Provider::with_endpoints(
            provider,
            &c.to_string(),
            &[ready["dns"].as_str().unwrap().into()],
            setjoin_acme::dns::Endpoints {
                cloudflare: Some(format!("{}/client/v4", ready["http"].as_str().unwrap())),
                route53: Some(ready["http"].as_str().unwrap().into()),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn route53_default_endpoints_match_frozen_sdk() -> Result<(), tick::BoxError> {
    let root = tick::repo_root()?;
    let path = root.join("server-rust/tests/conformance/tlsfront/route53-endpoints.json");
    if std::env::var_os("GOFREE_RECORD_DNS_ENDPOINTS").is_some() {
        assert!(!path.exists(), "immutable endpoint recording exists");
        let out = root.join("test-results/gofree-tlsfront/route53-endpoints-go.json");
        let cfg =
            json!({"EndpointsOut":"/src/test-results/gofree-tlsfront/route53-endpoints-go.json"});
        tokio::task::spawn_blocking(move || tick::dns_tick(cfg)).await??;
        let rows: Value = serde_json::from_slice(&std::fs::read(out)?)?;
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(
                &json!({"format":1,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"rows":rows}),
            )?,
        )?;
        return Ok(());
    }
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
async fn dns01_multi_domain_ticks_match_frozen_go() -> Result<(), tick::BoxError> {
    let root = tick::repo_root()?;
    let recording = std::env::var_os("GOFREE_RECORD_DNS_MULTI").is_some();
    for provider in ["cloudflare", "route53", "rfc2136"] {
        let work = Work(
            root.join("test-results/gofree-tlsfront")
                .join(format!("dns-multi-{provider}-{}", std::process::id())),
        );
        std::fs::create_dir_all(&work.0)?;
        let (_api, ready) = fake(&root, &work, false).await;
        let _ca = pebble::Pebble::start().await.expect("Pebble required");
        let credentials = config(provider, &ready).to_string();
        let domains = vec!["*.example.test".to_owned(), "alt.example.test".to_owned()];
        let golden = root.join(format!(
            "server-rust/tests/conformance/tlsfront/dns-{provider}-multi-zone.json"
        ));
        if recording {
            assert!(!golden.exists(), "immutable recording already exists");
            let cfg = json!({"Provider":provider,"Domains":domains,"Config":credentials,"Cache":format!("/src/{}/cache",work.0.strip_prefix(&root)?.display()),"Directory":pebble::DIRECTORY,"CA":"/src/server-rust/tests/conformance/acme/pebble/certs/pebble.minica.pem","API":ready["http"],"Resolver":ready["dns"]});
            tokio::task::spawn_blocking(move || tick::dns_tick(cfg)).await??;
            std::fs::write(
                &golden,
                serde_json::to_vec_pretty(
                    &json!({"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation(&work)}),
                )?,
            )?;
        } else {
            let native = setjoin_acme::dns::Provider::with_endpoints(
                provider,
                &credentials,
                &[ready["dns"].as_str().unwrap().into()],
                setjoin_acme::dns::Endpoints {
                    cloudflare: Some(format!("{}/client/v4", ready["http"].as_str().unwrap())),
                    route53: Some(ready["http"].as_str().unwrap().into()),
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
