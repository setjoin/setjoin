//! #354: unauthenticated requests never reach Go on any ON local-rust gateway route.
//!
//! Every inventory route is probed with six credential variants against the native executable
//! (GATEWAY_UPSTREAM unset). A request that bumps `setjoin_gateway_proxied_to_go_total` is a Go hop;
//! the set of hops must equal `known-go-hops.json`, which only ratchets down.
use crate::common::boot::Child;
use crate::common::boot::CommandBootExt;
mod common;
use common::BoxError;
use common::{body_bytes, full, send};
use hyper::Request;
use serde_json::json;
use setjoin_conformance::harness::Db;
use setjoin_gateway::RouteTable;
use std::process::{Command, Stdio};
use std::time::Duration;

use serde_json::json;
use setjoin_conformance::harness::Db;
use std::process::{Command, Stdio};

const SECRET: &str = "blobs1-test-jwt-secret-for-recording";
struct Process {
    child: Child,
    address: std::net::SocketAddr,
    log: std::path::PathBuf,
}
impl Drop for Process {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            unsafe {
                libc::kill(self.child.id() as i32, libc::SIGTERM);
            }
            for _ in 0..50 {
                if self.child.try_wait().ok().flatten().is_some() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            if self.child.try_wait().ok().flatten().is_none() {
                let _ = self.child.kill();
            }
        }
        let _ = self.child.wait();
        if !std::thread::panicking() {
            let _ = std::fs::remove_file(&self.log);
        }
    }
}
impl Process {
    async fn start(db: &Db) -> Result<Self, BoxError> {
        Self::start_with(db, &[]).await
    }
    async fn start_with(db: &Db, extra: &[(&str, String)]) -> Result<Self, BoxError> {
        use std::os::unix::process::CommandExt;
        let listener = setjoin_conformance::ports::listener().await;
        let address = listener.local_addr()?;
        drop(listener);
        let jwks = common::fake_upstream(|_| async {
            hyper::Response::builder()
                .header("content-type", "application/json")
                .body(full(
                    include_bytes!("../../../tests/conformance/jmap/test-jwks.json").as_slice(),
                ))
                .unwrap()
        })
        .await;
        let log =
            std::env::temp_dir().join(format!("gofree-authzdeny-gateway-{}.log", address.port()));
        let output = std::fs::File::create(&log)?;
        if let Ok(ledger) = std::env::var("GOFREE_RESOURCE_LEDGER") {
            use std::io::Write;
            writeln!(
                std::fs::OpenOptions::new().append(true).open(ledger)?,
                "Plan owned gofree-authzdeny-gateway at {address}; log {}; own DB only",
                log.display()
            )?;
        }
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
        cmd.arg0("gofree-authzdeny-gateway").env_clear();
        for (key, value) in [
            ("GATEWAY_LISTEN", address.to_string()),
            ("GATEWAY_AUTH_UPSTREAM", "http://127.0.0.1:1".into()),
            ("DB_DSN", db.app.as_deref().unwrap_or(&db.dsn).into()),
            ("DB_WORKER_DSN", db.dsn.clone()),
            ("DB_OWNER_DSN", db.dsn.clone()),
            ("DB_DIRECT_DSN", db.direct.clone()),
            ("DB_ENCRYPTION_KEY", "22".repeat(32)),
            (
                "AUTHSERVER_JWKS_URL",
                format!("http://{jwks}/.well-known/jwks.json"),
            ),
            ("JWT_SECRET", SECRET.into()),
            ("CORE_RATE_LIMIT", "100000".into()),
            ("S3_ENDPOINT", "http://127.0.0.1:1".into()),
            ("S3_ACCESS_KEY", "test-access".into()),
            ("S3_SECRET_KEY", "test-secret".into()),
            ("S3_BUCKET", "mailblobs".into()),
            ("S3_SECURE", "false".into()),
            ("ADMIN_RATE_LIMIT", "100000".into()),
        ] {
            cmd.env(key, value);
        }
        for (key, value) in extra {
            cmd.env(key, value);
        }
        let child = cmd
            .stdout(Stdio::from(output.try_clone()?))
            .stderr(Stdio::from(output))
            .spawn_boot()?;
        let mut process = Self {
            child,
            address,
            log,
        };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        loop {
            if let Some(status) = process.child.try_wait()? {
                return Err(format!(
                    "gateway exited {status}: {}",
                    std::fs::read_to_string(&process.log)?
                )
                .into());
            }
            if tokio::net::TcpStream::connect(address).await.is_ok() {
                return Ok(process);
            }
            if tokio::time::Instant::now() > deadline {
                return Err("gateway startup timed out".into());
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }
}

const VARIANTS: &[&str] = &[
    "none",
    "bearer-garbage",
    "cookie",
    "expired",
    "basic",
    "negotiate",
];
/// Variants 1-4 are recorded against frozen Go; Basic and Negotiate are native-only.
const RECORDED_VARIANTS: usize = 4;
const OWNERS: &[&str] = &["#355", "#356", "#357"];

fn concrete(path: &str) -> String {
    let mut out = String::new();
    let mut rest = path;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let close = open + rest[open..].find('}').expect("unterminated placeholder");
        let name = rest[open + 1..close].to_lowercase();
        out.push_str(&if name == "sha256" {
            "0".repeat(64)
        } else if name.contains("id") {
            "1".to_string()
        } else {
            "a".to_string()
        });
        rest = &rest[close + 1..];
    }
    out.push_str(rest);
    if path.ends_with('/') {
        out.push('x');
    }
    out
}

/// `(method, inventory path, concrete path)` for every ON local-rust gateway route.
fn routes() -> Vec<(String, String, String)> {
    let inventory: serde_json::Value =
        serde_json::from_str(include_str!("../route-inventory.json")).unwrap();
    let mut out = Vec::new();
    for row in inventory["routes"].as_array().unwrap() {
        if row["listener"] == "gateway" && row["state"] == "ON" && row["upstream"] == "local-rust" {
            let method = match row["method"].as_str().unwrap() {
                "*" => "GET",
                m => m,
            };
            let path = row["path"].as_str().unwrap();
            out.push((method.to_string(), path.to_string(), concrete(path)));
        }
    }
    out
}

fn expired_token() -> String {
    setjoin_authz::legacy_jwt::sign_hs256(SECRET.as_bytes(),
        &json!({"uid":1,"typ":"access","iss":"mailserver","aud":["mailserver-gateway"],"iat":1,"exp":2}).to_string())
}

async fn probe(
    address: std::net::SocketAddr,
    variant: &str,
    method: &str,
    uri: &str,
    expired: &str,
) -> hyper::Response<hyper::body::Incoming> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "mail.test")
        .header("x-request-id", "authzdeny-oracle");
    builder = match variant {
        "none" => builder,
        "bearer-garbage" => builder.header("authorization", "Bearer a.b.c"),
        "cookie" => builder.header("cookie", "access_token=x"),
        "expired" => builder.header("authorization", format!("Bearer {expired}")),
        "basic" => builder.header("authorization", "Basic Zm9vOmJhcg=="),
        "negotiate" => builder.header("authorization", "Negotiate YII="),
        other => panic!("unknown variant {other}"),
    };
    if method != "GET" {
        builder = builder.header("content-type", "application/json");
    }
    let body = if method == "GET" { "" } else { "{}" };
    send(address, builder.body(full(body)).unwrap()).await
}

async fn observe(response: hyper::Response<hyper::body::Incoming>) -> serde_json::Value {
    let status = response.status().as_u16();
    let headers: serde_json::Map<String, serde_json::Value> = response
        .headers()
        .iter()
        .filter(|(k, _)| {
            !matches!(
                k.as_str(),
                "date" | "content-length" | "transfer-encoding" | "connection"
            )
        })
        .map(|(k, v)| (k.to_string(), json!(v.to_str().unwrap())))
        .collect();
    let bytes = body_bytes(response).await;
    json!({"status":status,"headers":headers,"body":String::from_utf8_lossy(&bytes)})
}

async fn go_hops(address: std::net::SocketAddr) -> Result<u64, BoxError> {
    let metrics = send(
        address,
        Request::builder()
            .uri("/_gateway/metrics")
            .body(full(""))
            .unwrap(),
    )
    .await;
    let text = String::from_utf8(body_bytes(metrics).await.to_vec())?;
    text.lines()
        .find_map(|l| l.strip_prefix("setjoin_gateway_proxied_to_go_total "))
        .ok_or("proxied_to_go_total missing from metrics")?
        .trim()
        .parse()
        .map_err(Into::into)
}

fn corpus_path(name: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/authz-deny")
        .join(name)
}

fn check_known_hops(observed: &std::collections::BTreeSet<(String, String, String)>) {
    let known: serde_json::Value =
        serde_json::from_slice(&std::fs::read(corpus_path("known-go-hops.json")).unwrap()).unwrap();
    let mut expected = std::collections::BTreeMap::new();
    for row in known["hops"].as_array().unwrap() {
        let key = (
            row["variant"].as_str().unwrap().to_string(),
            row["method"].as_str().unwrap().to_string(),
            row["path"].as_str().unwrap().to_string(),
        );
        let owner = row["owner"].as_str().unwrap();
        assert!(OWNERS.contains(&owner), "bad owner {owner} for {key:?}");
        if key.0 == "basic" || key.0 == "negotiate" {
            assert_eq!(
                owner, "#355",
                "alternative credentials belong to #355: {key:?}"
            );
        }
        assert!(
            VARIANTS.contains(&key.0.as_str()),
            "unknown variant {key:?}"
        );
        assert!(
            expected.insert(key.clone(), owner).is_none(),
            "duplicate row {key:?}"
        );
    }
    let new: Vec<_> = observed
        .iter()
        .filter(|k| !expected.contains_key(*k))
        .collect();
    let fixed: Vec<_> = expected.keys().filter(|k| !observed.contains(*k)).collect();
    let rows = |set: &[&(String, String, String)]| {
        set.iter()
            .map(|(v, m, p)| json!({"variant":v,"method":m,"path":p,"owner":"TBD"}).to_string())
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert!(
        new.is_empty(),
        "{} new unauthenticated Go hops (add with an owner only if justified):\n{}",
        new.len(),
        rows(&new)
    );
    assert!(
        fixed.is_empty(),
        "{} known hops no longer hop; remove them from known-go-hops.json:\n{}",
        fixed.len(),
        rows(&fixed)
    );
}

#[tokio::test]
async fn unauthenticated_requests_never_reach_go_except_known_hops() -> Result<(), BoxError> {
    let db = Db::for_case("authzdeny-unauth").expect("assigned DB required");
    let record = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
    let s3 = common::fake_upstream(|_| async { hyper::Response::new(full("")) }).await;
    let go = common::go_oracle::start_named(&db, s3, None, "gofree-authzdeny-oracle").await?;
    let native = if record {
        None
    } else {
        Some(Process::start(&db).await?)
    };
    // Recording traverses the Rust front door configured as a transparent transport.
    let address = if let Some(go) = &go {
        common::gateway(go.address, "", RouteTable::proxy_all()).await
    } else {
        native.as_ref().unwrap().address
    };
    let path = corpus_path("unauthenticated.json");
    let frozen: Option<serde_json::Value> = if record || !path.exists() {
        None
    } else {
        Some(serde_json::from_slice::<serde_json::Value>(&std::fs::read(&path)?)?["cases"].clone())
    };
    if !record && frozen.is_none() {
        eprintln!(
            "no frozen-Go corpus {}: skipping byte comparison until recorded",
            path.display()
        );
    }
    let expired = expired_token();
    let mut observed_hops = std::collections::BTreeSet::new();
    let mut recorded = serde_json::Map::new();
    let mut mismatches = Vec::new();
    for (method, inventory_path, uri) in routes() {
        for (index, variant) in VARIANTS.iter().enumerate() {
            if record {
                if index < RECORDED_VARIANTS {
                    let value =
                        observe(probe(address, variant, &method, &uri, &expired).await).await;
                    recorded.insert(format!("{variant} {method} {inventory_path}"), value);
                }
                continue;
            }
            let before = go_hops(address).await?;
            let value = observe(probe(address, variant, &method, &uri, &expired).await).await;
            if go_hops(address).await? > before {
                observed_hops.insert((variant.to_string(), method.clone(), inventory_path.clone()));
            }
            let key = format!("{variant} {method} {inventory_path}");
            if let Some(expected) = frozen.as_ref().and_then(|f| f.get(&key)) {
                // Public-route answers depend on fixtures: bytes are compared only where Go said 401.
                if expected["status"] == 401 && value != *expected {
                    mismatches.push(format!("{key}: actual {value}; expected {expected}"));
                }
            }
        }
    }
    if record {
        assert!(!path.exists(), "immutable corpus already exists");
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(
            path,
            serde_json::to_vec_pretty(
                &json!({"go_source":std::env::var("GOFREE_GO_SOURCE")?,"cases":recorded}),
            )?,
        )?;
    } else {
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
        check_known_hops(&observed_hops);
    }
    Ok(())
}
