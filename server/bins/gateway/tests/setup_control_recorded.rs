//! #305: recorded Go sessions of the unix setup control socket. Frozen Go (a real mailserverd
//! process, `GO_WORKERS_OFF` as the other oracles) answers each request on its control socket
//! against a fake S3 and the disposable database; the Rust control server must answer the same
//! status, headers, body, restore-job rows, restored configuration and primary-store objects.
//!
//! Record: `GOFREE_RECORD_CONTROL=all|case,case` + `GOFREE_RECORD_GO_BINARY` + `GOFREE_GO_SOURCE`.
//! Replay needs no Go. The socket's mode (0600), its directory (0750) and the absolute-path,
//! non-socket and already-active refusals are asserted in `socket_hardening` (no Go needed).
mod common;
use common::{go_oracle, BoxError};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::setup_control::{bind, serve, Control};
use setjoin_pg::workers::WorkerDatabase;
use std::{
    collections::BTreeMap,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

static SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());
const TOKEN: &str = "plat7-setup-token";

/// In-memory path-style S3 for the primary bucket (`mailblobs`) and the backup bucket (`backup-bk`).
#[derive(Clone, Default)]
struct Objects(Arc<Mutex<BTreeMap<String, Vec<u8>>>>);

async fn fake_s3(objects: Objects) -> std::net::SocketAddr {
    common::fake_upstream(move |request| {
        let objects = objects.clone();
        async move {
            use http_body_util::BodyExt;
            let (parts, body) = request.into_parts();
            let bytes = body.collect().await.map(|b| b.to_bytes()).unwrap_or_default();
            let path = parts.uri.path().to_owned();
            let query = parts.uri.query().unwrap_or("");
            let reply = |status: u16, body: Vec<u8>, head: bool, headers: &[(&str, String)]| {
                let mut b = hyper::Response::builder().status(status);
                for (k, v) in headers {
                    b = b.header(*k, v);
                }
                b = b.header("content-length", body.len());
                b.body(common::full(if head { Vec::new() } else { body })).unwrap()
            };
            if parts.method == hyper::Method::GET && query.starts_with("location") {
                return reply(200, b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><LocationConstraint xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">us-east-1</LocationConstraint>".to_vec(), false, &[]);
            }
            let missing = || reply(404, b"<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>NoSuchKey</Code><Message>missing</Message></Error>".to_vec(), parts.method == hyper::Method::HEAD, &[]);
            match parts.method.as_str() {
                "GET" | "HEAD" => match objects.0.lock().unwrap().get(&path).cloned() {
                    Some(data) => reply(200, data, parts.method == hyper::Method::HEAD, &[("etag", "\"fake\"".into()), ("last-modified", "Mon, 02 Nov 2026 00:00:00 GMT".into())]),
                    None => missing(),
                },
                "PUT" => {
                    let streaming = parts.headers.get("x-amz-content-sha256").is_some_and(|v| v == "STREAMING-AWS4-HMAC-SHA256-PAYLOAD");
                    let data = if streaming { dechunk(&bytes) } else { bytes.to_vec() };
                    objects.0.lock().unwrap().insert(path, data);
                    reply(200, Vec::new(), false, &[("etag", "\"fake\"".into())])
                }
                _ => reply(405, Vec::new(), false, &[]),
            }
        }
    })
    .await
}

fn dechunk(mut framed: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(end) = framed.windows(2).position(|w| w == b"\r\n") {
        let header = String::from_utf8_lossy(&framed[..end]).into_owned();
        let size = usize::from_str_radix(header.split(';').next().unwrap_or("0"), 16).unwrap_or(0);
        framed = &framed[end + 2..];
        if size == 0 || framed.len() < size {
            break;
        }
        out.extend_from_slice(&framed[..size]);
        framed = framed.get(size + 2..).unwrap_or_default();
    }
    out
}

/// The S3 client's own error text, and where it surfaces (open or first read), differ between
/// implementations; keep the operation and the object.
fn scrub(text: &str) -> String {
    for object in ["config.json", "backup-manifest.json"] {
        for marker in [format!("download {object}: "), format!("read {object}: ")] {
            if let Some(at) = text.find(&marker) {
                return format!("{}<{object} s3 error>", &text[..at]);
            }
        }
    }
    for marker in ["backup head: ", "backup get: ", "primary put/read close: "] {
        if let Some(at) = text.find(marker) {
            return format!("{}{marker}<s3 error>", &text[..at]);
        }
    }
    text.to_owned()
}

fn scrub_value(v: &mut Value) {
    match v {
        Value::String(s) => *s = scrub(s),
        Value::Array(items) => items.iter_mut().for_each(scrub_value),
        Value::Object(map) => map.values_mut().for_each(scrub_value),
        _ => {}
    }
}

fn sha(data: &[u8]) -> String {
    setjoin_backup::digest(data)
}

const BLOB_A: &[u8] = b"plat7 blob a";
const BLOB_B: &[u8] = b"plat7 blob b";

/// Backup bucket contents: a legacy (unsigned) manifest, config.json and two blobs.
fn backup_fixture(objects: &Objects, corrupt_b: bool) {
    let config = json!({
        "feature.gofree_plat7_safe": {"value": "true", "encrypted": false},
        "ad_gofree_plat7": {"value": "\"x\"", "encrypted": false},
        "gofree_plat7_unknown": {"value": "1", "encrypted": false},
        "gofree_plat7_secret": {"value": "\"s\"", "encrypted": true}
    })
    .to_string();
    let hashes = [sha(BLOB_A), sha(BLOB_B)];
    let manifest = json!({
        "schema_version": 0, "timestamp": "20261102T000000Z", "config_size_bytes": config.len(),
        "config_sha256": sha(config.as_bytes()),
        "blob_manifest": {"timestamp":"20261102T000000Z","type":"full","hashes":hashes,"count":2,"total_size":24},
        "blob_count": 2, "blob_total_size_bytes": 24
    });
    let mut o = objects.0.lock().unwrap();
    o.clear();
    o.insert(
        "/backup-bk/backup-manifest.json".into(),
        manifest.to_string().into_bytes(),
    );
    o.insert("/backup-bk/config.json".into(), config.into_bytes());
    o.insert(format!("/backup-bk/blobs/{}", hashes[0]), BLOB_A.to_vec());
    o.insert(
        format!("/backup-bk/blobs/{}", hashes[1]),
        if corrupt_b {
            b"tampered!!!!".to_vec()
        } else {
            BLOB_B.to_vec()
        },
    );
}

fn request_body(extra: Value) -> String {
    let mut base = json!({"provider":"s3","endpoint":"","region":"us-east-1","bucket":"backup-bk","access_key":"ak","secret_key":"sk","type":"full"});
    for (k, v) in extra.as_object().cloned().unwrap_or_default() {
        if v.is_null() {
            base.as_object_mut().unwrap().remove(&k);
        } else {
            base[k] = v;
        }
    }
    base.to_string()
}

struct Case {
    name: &'static str,
    method: &'static str,
    path: &'static str,
    token: Option<&'static str>,
    body: fn(&str) -> String,
    /// 0 none, 1 backup fixture, 2 fixture with a tampered blob.
    backup: u8,
    users: bool,
    running_job: bool,
    primary_has_a: bool,
}

fn good(endpoint: &str) -> String {
    request_body(json!({"endpoint": endpoint}))
}

macro_rules! case {
    ($name:expr, $path:expr, $token:expr, $body:expr) => {
        Case {
            name: $name,
            method: "POST",
            path: $path,
            token: $token,
            body: $body,
            backup: 1,
            users: false,
            running_job: false,
            primary_has_a: false,
        }
    };
}

fn cases() -> Vec<Case> {
    vec![
        case!("control-no-token", "/setup/preflight", None, good),
        case!("control-wrong-token", "/setup/restore", Some("nope"), good),
        Case {
            method: "GET",
            ..case!(
                "control-method-not-allowed",
                "/setup/preflight",
                Some(TOKEN),
                good
            )
        },
        case!("control-unknown-path", "/setup/status", Some(TOKEN), good),
        case!(
            "control-invalid-json",
            "/setup/preflight",
            Some(TOKEN),
            |_| "{not json".into()
        ),
        case!(
            "control-trailing-json",
            "/setup/preflight",
            Some(TOKEN),
            |e| format!("{} {{}}", good(e))
        ),
        case!(
            "control-wrong-field-type",
            "/setup/preflight",
            Some(TOKEN),
            |e| request_body(json!({"endpoint": e, "bucket": 7}))
        ),
        case!(
            "control-missing-secret",
            "/setup/restore",
            Some(TOKEN),
            |e| request_body(json!({"endpoint": e, "secret_key": Value::Null}))
        ),
        case!("control-bad-type", "/setup/restore", Some(TOKEN), |e| {
            request_body(json!({"endpoint": e, "type": "everything"}))
        }),
        case!(
            "control-case-insensitive-keys",
            "/setup/preflight",
            Some(TOKEN),
            |e| good(e).replace("\"bucket\"", "\"BUCKET\"")
        ),
        Case {
            users: true,
            ..case!(
                "control-setup-completed-preflight",
                "/setup/preflight",
                Some(TOKEN),
                good
            )
        },
        Case {
            users: true,
            ..case!(
                "control-setup-completed-restore",
                "/setup/restore",
                Some(TOKEN),
                good
            )
        },
        case!(
            "control-preflight-ok",
            "/setup/preflight",
            Some(TOKEN),
            good
        ),
        Case {
            backup: 0,
            ..case!(
                "control-preflight-no-manifest",
                "/setup/preflight",
                Some(TOKEN),
                good
            )
        },
        case!(
            "control-preflight-insecure-endpoint",
            "/setup/preflight",
            Some(TOKEN),
            |_| request_body(json!({"endpoint": "http://backup.example.com"}))
        ),
        case!(
            "control-restore-config",
            "/setup/restore",
            Some(TOKEN),
            |e| request_body(json!({"endpoint": e, "type": "config"}))
        ),
        case!("control-restore-full", "/setup/restore", Some(TOKEN), good),
        Case {
            primary_has_a: true,
            ..case!(
                "control-restore-blobs-skips-present",
                "/setup/restore",
                Some(TOKEN),
                |e| request_body(json!({"endpoint": e, "type": "blobs"}))
            )
        },
        Case {
            backup: 2,
            ..case!(
                "control-restore-blobs-corrupt-source",
                "/setup/restore",
                Some(TOKEN),
                |e| request_body(json!({"endpoint": e, "type": "blobs"}))
            )
        },
        case!(
            "control-restore-explicit-hashes",
            "/setup/restore",
            Some(TOKEN),
            |e| request_body(
                json!({"endpoint": e, "type": "blobs", "hashes": [sha(BLOB_A), "../../etc/passwd"]})
            )
        ),
        Case {
            backup: 0,
            ..case!(
                "control-restore-config-no-manifest",
                "/setup/restore",
                Some(TOKEN),
                |e| request_body(json!({"endpoint": e, "type": "config"}))
            )
        },
        Case {
            running_job: true,
            ..case!(
                "control-restore-in-progress",
                "/setup/restore",
                Some(TOKEN),
                good
            )
        },
    ]
}

async fn clean(owner: &tokio_postgres::Client) -> Result<(), BoxError> {
    owner.batch_execute(
        "DELETE FROM restore_jobs; DELETE FROM restore_config_quarantine WHERE config_key LIKE '%gofree_plat7%'; DELETE FROM system_config WHERE key LIKE '%gofree_plat7%'",
    ).await?;
    Ok(())
}

async fn http(
    socket: &Path,
    method: &str,
    path: &str,
    token: Option<&str>,
    body: &str,
) -> Result<(u16, BTreeMap<String, String>, Vec<u8>), BoxError> {
    let mut stream = tokio::net::UnixStream::connect(socket).await?;
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: control\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    if let Some(t) = token {
        head += &format!("X-Setup-Token: {t}\r\n");
    }
    stream
        .write_all(format!("{head}\r\n{body}").as_bytes())
        .await?;
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("no response head")?;
    let text = String::from_utf8_lossy(&raw[..split]).into_owned();
    let mut lines = text.lines();
    let status: u16 = lines
        .next()
        .unwrap()
        .split_whitespace()
        .nth(1)
        .unwrap()
        .parse()?;
    let headers: BTreeMap<String, String> = lines
        .filter_map(|l| l.split_once(": "))
        .map(|(k, v)| (k.to_lowercase(), v.to_owned()))
        .collect();
    let mut body = raw[split + 4..].to_vec();
    if headers
        .get("transfer-encoding")
        .is_some_and(|v| v == "chunked")
    {
        body = dechunk(&body);
    }
    Ok((status, headers, body))
}

async fn observe(
    owner: &tokio_postgres::Client,
    objects: &Objects,
    response: (u16, BTreeMap<String, String>, Vec<u8>),
) -> Result<Value, BoxError> {
    let (status, headers, body) = response;
    let mut kept = serde_json::Map::new();
    for name in [
        "content-type",
        "cache-control",
        "allow",
        "x-content-type-options",
    ] {
        if let Some(v) = headers.get(name) {
            kept.insert(name.into(), json!(v));
        }
    }
    let text = String::from_utf8_lossy(&body).into_owned();
    let mut parsed = serde_json::from_str::<Value>(&text).unwrap_or(Value::Null);
    // The job id is a serial; its value is run-specific.
    if parsed.get("restore_job_id").is_some() {
        parsed["restore_job_id"] = json!("<id>");
    }
    scrub_value(&mut parsed);
    let jobs: Vec<Value> = owner.query("SELECT status, restore_type, error_log::text FROM restore_jobs ORDER BY id", &[]).await?
        .iter().map(|r| {
            let mut log = r.get::<_, Option<String>>(2).and_then(|t| serde_json::from_str::<Value>(&t).ok()).unwrap_or(Value::Null);
            scrub_value(&mut log);
            json!({"status": r.get::<_, String>(0), "type": r.get::<_, Option<String>>(1), "error_log": log})
        }).collect();
    let config: Vec<Value> = owner.query("SELECT key, value::text, encrypted FROM system_config WHERE key LIKE '%gofree_plat7%' ORDER BY key", &[]).await?
        .iter().map(|r| json!({"key": r.get::<_, String>(0), "value": r.get::<_, String>(1), "encrypted": r.get::<_, bool>(2)})).collect();
    let quarantine: Vec<Value> = owner.query("SELECT config_key, disposition, source_verified FROM restore_config_quarantine WHERE config_key LIKE '%gofree_plat7%' ORDER BY config_key", &[]).await?
        .iter().map(|r| json!({"key": r.get::<_, String>(0), "disposition": r.get::<_, String>(1), "verified": r.get::<_, bool>(2)})).collect();
    let primary: Vec<String> = objects
        .0
        .lock()
        .unwrap()
        .keys()
        .filter(|k| k.starts_with("/mailblobs/"))
        .cloned()
        .collect();
    Ok(json!({
        "request": {"method": "", "path": ""},
        "response": {"status": status, "headers": kept, "body": if parsed.is_null() { json!(text) } else { parsed }},
        "effects": {"restore_jobs": jobs, "config": config, "quarantine": quarantine, "primary_objects": primary},
        "audit": [], "notify": [],
    }))
}

async fn arrange(
    owner: &tokio_postgres::Client,
    objects: &Objects,
    case: &Case,
) -> Result<Option<fixture::Account>, BoxError> {
    clean(owner).await?;
    objects.0.lock().unwrap().clear();
    if case.backup > 0 {
        backup_fixture(objects, case.backup == 2);
    }
    if case.primary_has_a {
        objects
            .0
            .lock()
            .unwrap()
            .insert(format!("/mailblobs/blobs/{}", sha(BLOB_A)), BLOB_A.to_vec());
    }
    if case.running_job {
        owner.execute("INSERT INTO restore_jobs (status, restore_type, started_at) VALUES ('running','full',now())", &[]).await?;
    }
    Ok(if case.users {
        Some(fixture::account(owner, "plat7-control").await?)
    } else {
        None
    })
}

async fn finish(
    owner: &tokio_postgres::Client,
    account: Option<fixture::Account>,
) -> Result<(), BoxError> {
    clean(owner).await?;
    if let Some(a) = account {
        common::remove_blob_account(owner, &a).await?;
    }
    Ok(())
}

fn golden_path(case: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/platform/control")
        .join(format!("{case}.json"))
}

fn recording_filter() -> Option<String> {
    std::env::var("GOFREE_RECORD_CONTROL").ok()
}

fn listed(name: &str) -> bool {
    recording_filter().is_some_and(|f| f == "all" || f.split(',').any(|t| t == name))
}

async fn go_socket(
    db: &Db,
    s3: std::net::SocketAddr,
    token: &str,
) -> Result<Option<(go_oracle::GoOracle, PathBuf)>, BoxError> {
    let Some(binary) = std::env::var_os("GOFREE_RECORD_GO_BINARY") else {
        return Ok(None);
    };
    let parent = std::fs::canonicalize(binary)?
        .parent()
        .unwrap()
        .to_path_buf();
    let dir = format!("gofree-plat7-ctl-{}", std::process::id());
    let host = parent.join(&dir).join("control.sock");
    let oracle = go_oracle::start_unscoped_with_env(
        db,
        s3,
        "gofree-plat7-ctl",
        &[
            (
                "SETJOIN_CONTROL_SOCKET",
                format!("/evidence/{dir}/control.sock"),
            ),
            ("SETJOIN_SETUP_TOKEN", token.into()),
        ],
    )
    .await?;
    Ok(oracle.map(|o| (o, host)))
}

fn record(case: &str, method: &str, path: &str, mut observation: Value) -> Result<(), BoxError> {
    observation["request"] = json!({"method": method, "path": path});
    let p = golden_path(case);
    let _ = std::fs::remove_file(&p);
    golden::record(
        &p,
        &json!({"format":1,"route": format!("{method} {path}"),"case":case,"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}),
    )?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn control_socket_matches_recorded_go() -> Result<(), BoxError> {
    let _serial = SERIAL
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let Some(db) = Db::for_case("setup-control") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let objects = Objects::default();
    let s3 = fake_s3(objects.clone()).await;
    let endpoint = format!("http://{s3}");
    let recording = recording_filter().is_some();

    // Recording: Go answers on its control socket.
    let go = if recording {
        go_socket(&db, s3, TOKEN).await?
    } else {
        None
    };
    // Replay (and the Rust half of any run): the Rust server on a private socket.
    let dir = std::env::temp_dir().join(format!("gofree-plat7-rust-ctl-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let socket = dir.join("control.sock");
    std::env::set_var("S3_ENDPOINT", s3.to_string());
    let control = Arc::new(Control {
        db: WorkerDatabase::new(&db.dsn)?,
        primary: Some(setjoin_gateway::setup_control::primary_from_env(&|n| {
            std::env::var(n).ok()
        })?),
        token: TOKEN.into(),
    });
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve(bind(&socket)?, socket.clone(), control, async move {
        let _ = stopped.await;
    }));
    let mut failures = Vec::new();
    for case in cases() {
        let account = arrange(&owner, &objects, &case).await?;
        let body = (case.body)(&endpoint);
        if listed(case.name) {
            let (_, go_socket) = go
                .as_ref()
                .ok_or("recording needs GOFREE_RECORD_GO_BINARY")?;
            let response = http(go_socket, case.method, case.path, case.token, &body).await?;
            let observation = observe(&owner, &objects, response).await?;
            record(case.name, case.method, case.path, observation)?;
        } else if !recording {
            let response = http(&socket, case.method, case.path, case.token, &body).await?;
            let actual = observe(&owner, &objects, response).await?;
            let golden: Value = serde_json::from_slice(&std::fs::read(golden_path(case.name))?)?;
            let mut expected = golden["observation"].clone();
            expected["request"] = json!({"method": "", "path": ""});
            match golden::compare(&expected, &actual) {
                Ok(()) => println!(
                    "GOLDEN-REPLAY: {} {} :: {}",
                    case.method, case.path, case.name
                ),
                Err(e) => failures.push(format!("{}: {e}", case.name)),
            }
        }
        finish(&owner, account).await?;
    }
    let _ = stop.send(());
    let _ = server.await;
    drop(go);
    let _ = std::fs::remove_dir_all(&dir);
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    Ok(())
}

#[tokio::test]
async fn socket_hardening() -> Result<(), BoxError> {
    let dir = std::env::temp_dir().join(format!("gofree-plat7-harden-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777))?;
    let socket = dir.join("control.sock");
    let listener = bind(&socket)?;
    assert_eq!(
        std::fs::metadata(&socket)?.permissions().mode() & 0o777,
        0o600,
        "socket mode"
    );
    assert_eq!(
        std::fs::metadata(&dir)?.permissions().mode() & 0o777,
        0o750,
        "a loose directory is tightened"
    );
    assert_eq!(
        bind(&socket).err().as_deref(),
        Some("setup control socket is already active")
    );
    drop(listener);
    // A stale socket file (nobody listening) is replaced.
    drop(bind(&socket)?);
    let plain = dir.join("plain");
    std::fs::write(&plain, b"x")?;
    assert_eq!(
        bind(&plain).err().as_deref(),
        Some("setup control path exists and is not a socket")
    );
    assert_eq!(
        bind(Path::new("relative.sock")).err().as_deref(),
        Some("setup control socket must be an absolute path")
    );
    let _ = std::fs::remove_dir_all(&dir);
    println!("GOLDEN-REPLAY: control socket :: hardening");
    Ok(())
}

/// Go's `setupTokenGate` with no configured token fails closed with a 503 on every call (the Go
/// process of the oracle always has a token, so this case is asserted against the source contract).
#[tokio::test]
async fn an_unconfigured_token_fails_closed() -> Result<(), BoxError> {
    let dir = std::env::temp_dir().join(format!("gofree-plat7-notoken-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let socket = dir.join("control.sock");
    let control = Arc::new(Control {
        db: WorkerDatabase::new("postgres://nobody@127.0.0.1:1/none")?,
        primary: None,
        token: String::new(),
    });
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(serve(bind(&socket)?, socket.clone(), control, async move {
        let _ = stopped.await;
    }));
    for token in [None, Some("anything")] {
        let (status, headers, body) = http(&socket, "POST", "/setup/restore", token, "{}").await?;
        assert_eq!(status, 503);
        assert_eq!(
            headers.get("content-type").map(String::as_str),
            Some("application/problem+json")
        );
        assert!(String::from_utf8_lossy(&body).contains("setup token not configured"));
    }
    let _ = stop.send(());
    let _ = server.await;
    let _ = std::fs::remove_dir_all(&dir);
    println!("GOLDEN-REPLAY: control socket :: unconfigured-token");
    Ok(())
}
