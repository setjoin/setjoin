//! #413: frozen-Go TLS/HTTP negotiations replayed against the native front door.
#[path = "../../../crates/acme/tests/support/pebble.rs"]
mod pebble;
#[path = "../../../tests/conformance/tlsfront/peer.rs"]
mod peer;
use serde_json::{json, Value};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../..")
        .canonicalize()
        .unwrap()
}
struct Work(PathBuf);
impl Drop for Work {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
fn pair(cn: &str, names: &[&str], year: i32) -> (String, String) {
    let key = rcgen::KeyPair::generate().unwrap();
    let mut p =
        rcgen::CertificateParams::new(names.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>())
            .unwrap();
    p.distinguished_name.push(rcgen::DnType::CommonName, cn);
    p.not_after = rcgen::date_time_ymd(year, 1, 1);
    let cert = p.self_signed(&key).unwrap();
    (cert.pem(), key.serialize_pem())
}
fn assets() -> Value {
    let (cert, key) = pair(
        "static.localhost",
        &[
            "localhost",
            "foreign.localhost",
            "managed.localhost",
            "127.0.0.1",
            "one.example.test",
            "a.b.example.test",
        ],
        2037,
    );
    let (managed, mkey) = pair("managed.localhost", &["managed.localhost"], 2037);
    let (auto, akey) = pair("autocert.localhost", &["managed.localhost"], 2037);
    let (expired, ekey) = pair("managed.localhost", &["managed.localhost"], 2020);
    let (wrong, wkey) = pair("wrong.localhost", &["wrong.localhost"], 2037);
    let (wildcard, wildkey) = pair("*.example.test", &["*.example.test"], 2037);
    json!({"certificate":cert,"public_test_key":key,"managed_blob":format!("{mkey}{managed}"),"autocert_blob":format!("{akey}{auto}"),"expired_blob":format!("{ekey}{expired}"),"wrong_blob":format!("{wkey}{wrong}"),"wildcard_blob":format!("{wildkey}{wildcard}"),"roots":format!("{cert}{managed}{auto}{wildcard}")})
}
fn case(name: &str, sni: &str, alpn: &str, version: u16, cache: &str) -> Value {
    json!({"name":name,"sni":sni,"alpn":alpn,"version":version,"plain":false,"cache":cache})
}
fn cases() -> Vec<Value> {
    let mut plain = case("h2c-prior-knowledge", "localhost", "h2", 0, "none");
    plain["plain"] = json!(true);
    vec![
        case("tls13-h2", "localhost", "h2", 0x304, "none"),
        case("tls13-http11", "localhost", "http/1.1", 0x304, "none"),
        case("tls12-http11", "localhost", "http/1.1", 0x303, "none"),
        plain,
        case("managed-sni", "managed.localhost", "h2", 0x304, "managed"),
        case(
            "normalized-sni",
            "MANAGED.localhost.",
            "http/1.1",
            0x304,
            "managed",
        ),
        case(
            "foreign-sni-fallback",
            "foreign.localhost",
            "h2",
            0x304,
            "managed",
        ),
        case(
            "empty-sni-fallback",
            "127.0.0.1",
            "http/1.1",
            0x304,
            "managed",
        ),
        case(
            "cold-cache-fallback",
            "managed.localhost",
            "h2",
            0x304,
            "cold",
        ),
        case(
            "expired-cache-fallback",
            "managed.localhost",
            "h2",
            0x304,
            "expired",
        ),
        case(
            "corrupt-cache-fallback",
            "managed.localhost",
            "h2",
            0x304,
            "corrupt",
        ),
        case(
            "autocert-literal-cache",
            "managed.localhost",
            "h2",
            0x304,
            "autocert",
        ),
        case(
            "autocert-wrong-host-fallback",
            "managed.localhost",
            "h2",
            0x304,
            "wrong",
        ),
        case(
            "managed-precedes-autocert",
            "managed.localhost",
            "h2",
            0x304,
            "both",
        ),
        case(
            "wildcard-one-label",
            "one.example.test",
            "h2",
            0x304,
            "wildcard",
        ),
        case(
            "wildcard-deeper-fallback",
            "a.b.example.test",
            "h2",
            0x304,
            "wildcard",
        ),
    ]
}
fn prepare(work: &Work, a: &Value, c: &Value) -> Vec<String> {
    std::fs::write(work.0.join("cert.pem"), a["certificate"].as_str().unwrap()).unwrap();
    std::fs::write(
        work.0.join("key.pem"),
        a["public_test_key"].as_str().unwrap(),
    )
    .unwrap();
    std::fs::write(work.0.join("roots.pem"), a["roots"].as_str().unwrap()).unwrap();
    let cache_dir = work.0.join("cache");
    if cache_dir.exists() {
        std::fs::remove_dir_all(&cache_dir).unwrap();
    }
    std::fs::create_dir_all(&cache_dir).unwrap();
    let kind = c["cache"].as_str().unwrap();
    if kind == "none" {
        return vec![];
    }
    let domains = if kind == "wildcard" {
        vec!["*.example.test".into()]
    } else {
        vec!["managed.localhost".into()]
    };
    let cache = setjoin_acme::cache::DirCache::new(&cache_dir);
    match kind {
        "managed" | "both" => cache
            .put(
                "managed.localhost",
                a["managed_blob"].as_str().unwrap().as_bytes(),
            )
            .unwrap(),
        "expired" => cache
            .put(
                "managed.localhost",
                a["expired_blob"].as_str().unwrap().as_bytes(),
            )
            .unwrap(),
        "corrupt" => cache.put("managed.localhost", b"corrupt").unwrap(),
        "wildcard" => cache
            .put(
                "*.example.test",
                a["wildcard_blob"].as_str().unwrap().as_bytes(),
            )
            .unwrap(),
        _ => {}
    }
    if matches!(kind, "autocert" | "both" | "wrong") {
        std::fs::write(
            cache_dir.join("managed.localhost-rsa"),
            a[if kind == "wrong" {
                "wrong_blob"
            } else {
                "autocert_blob"
            }]
            .as_str()
            .unwrap(),
        )
        .unwrap();
    }
    domains
}
fn config(work: &Work, c: &Value) -> Value {
    json!({"Cert":work.0.join("cert.pem"),"Key":work.0.join("key.pem"),"Roots":work.0.join("roots.pem"),"Raw":false,"Plain":c["plain"],"SNI":c["sni"],"ALPN":c["alpn"],"Version":c["version"],"Out":work.0.join("out.json")})
}
async fn record(work: &Work, a: &Value, c: &Value, aes: bool) -> Value {
    let domains = prepare(work, a, c);
    let _ = std::fs::remove_file(work.0.join("ready"));
    let mut cfg = config(work, c);
    cfg["Mode"] = json!("server");
    cfg["DisableAES"] = json!(!aes);
    cfg["Listen"] = json!("127.0.0.1:0");
    cfg["Ready"] = json!(work.0.join("ready"));
    cfg["Cache"] = json!(work.0.join("cache"));
    cfg["Domains"] = json!(domains);
    cfg["Directory"] = json!(pebble::DIRECTORY);
    cfg["CA"] = json!(pebble::ca_root());
    if c["cache"] == "wildcard" {
        cfg["Challenge"] = json!("dns-01");
    }
    let mut server = peer::Server::spawn(&root(), &cfg, &work.0.join("server.log"));
    let mut address = None;
    for _ in 0..500 {
        if let Ok(addr) = std::fs::read_to_string(work.0.join("ready")) {
            address = Some(addr);
            break;
        }
        assert!(
            server.try_wait().unwrap().is_none(),
            "Go exited: {}",
            std::fs::read_to_string(work.0.join("server.log")).unwrap()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let mut cfg = config(work, c);
    cfg["Mode"] = json!("probe");
    cfg["Listen"] = json!(address.expect("Go not ready"));
    let output = peer::run(&root(), &cfg);
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&std::fs::read(work.0.join("out.json")).unwrap()).unwrap()
}
async fn replay(work: &Work, a: &Value, c: &Value, aes: bool) -> Value {
    let domains = prepare(work, a, c);
    let gateway = Gateway::new(
        Config {
            upstream: None,
            upstream_header_timeout: Duration::from_secs(5),
            trusted_proxies: TrustedProxies::default(),
            edge_limit: None,
        },
        RouteTable::proxy_all(),
    )
    .unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let frontend = setjoin_tls::Frontend::from_env_with_aes(
        &|key| match key {
            "TLS_CERT_FILE" => Some(work.0.join("cert.pem").display().to_string()),
            "TLS_KEY_FILE" => Some(work.0.join("key.pem").display().to_string()),
            "TLS_AUTOCERT_DOMAINS" => Some(domains.join(",")),
            "TLS_AUTOCERT_CACHE_DIR" => Some(work.0.join("cache").display().to_string()),
            _ => None,
        },
        aes,
    )
    .unwrap()
    .unwrap();
    let plain = c["plain"].as_bool().unwrap();
    let server = tokio::spawn(async move {
        let stop = async {
            let _ = stopped.await;
        };
        if plain {
            gateway.serve_until(listener, stop).await
        } else {
            gateway.serve_tls_until(listener, frontend, stop).await
        }
    });
    let mut cfg = config(work, c);
    cfg["Mode"] = json!("probe");
    cfg["Listen"] = json!(addr.to_string());
    let output = tokio::task::spawn_blocking(move || peer::run(&root(), &cfg))
        .await
        .unwrap();
    let _ = stop.send(());
    server.await.unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&std::fs::read(work.0.join("out.json")).unwrap()).unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_h2c_and_sni_match_recorded_go() {
    let work = Work(
        root()
            .join("test-results/gofree-tlsfront")
            .join(format!("http-oracle-{}", std::process::id())),
    );
    std::fs::create_dir_all(&work.0).unwrap();
    for aes in [true, false] {
        let name = if aes {
            "http-negotiation.json"
        } else {
            "http-negotiation-no-aes.json"
        };
        let path = root()
            .join("server-rust/tests/conformance/tlsfront")
            .join(name);
        let target = std::env::var("GOFREE_RECORD_TLSFRONT_HTTP").ok();
        if target.as_deref() == Some(if aes { "1" } else { "no-aes" }) {
            let _pebble = pebble::Pebble::start()
                .await
                .expect("recording requires test ACME server");
            let assets = assets();
            let mut cases = cases();
            for case in &mut cases {
                case["observation"] = record(&work, &assets, case, aes).await;
            }
            let source = std::process::Command::new("git")
                .args(["rev-parse", "HEAD"])
                .output()
                .unwrap();
            use std::io::Write;
            let mut out = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            out.write_all(&serde_json::to_vec_pretty(&json!({"format":1,"go_source":String::from_utf8(source.stdout).unwrap().trim(),"aes":aes,"fixtures":assets,"cases":cases})).unwrap()).unwrap();
        }
        let recorded: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        for case in recorded["cases"].as_array().unwrap() {
            let actual = replay(&work, &recorded["fixtures"], case, aes).await;
            assert_eq!(actual, case["observation"], "AES={aes}, {}", case["name"]);
        }
    }
}
