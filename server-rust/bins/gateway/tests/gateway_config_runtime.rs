//! The executable must resolve YAML without any Go upstream.
use crate::common::boot::CommandBootExt;
use crate::common::boot::Child;
mod common;
use common::BoxError;
use hyper::{Request, Response};
use setjoin_conformance::harness::Db;
use std::{
    os::unix::process::CommandExt,
    path::PathBuf,
    process::{Command, Stdio},
};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Process {
    child: Child,
    dir: PathBuf,
}
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        self.child.wait().expect("reap owned gateway");
        std::fs::remove_dir_all(&self.dir).expect("remove owned configuration");
    }
}
async fn start(db: &Db, yaml: &str) -> Result<(Process, std::net::SocketAddr), BoxError> {
    start_configured(db, yaml, &[]).await
}
async fn start_configured(
    db: &Db,
    yaml: &str,
    extra: &[(&str, String)],
) -> Result<(Process, std::net::SocketAddr), BoxError> {
    let keys = common::fake_upstream(|_| async {
        Response::new(common::full(
            include_bytes!("../../../tests/conformance/jmap/test-jwks.json").as_slice(),
        ))
    })
    .await;
    let listener = setjoin_conformance::ports::listener().await;
    let address = listener.local_addr()?;
    drop(listener);
    let dir = std::env::temp_dir().join(format!(
        "gofree-gwconfig-{}-{}",
        std::process::id(),
        address.port()
    ));
    std::fs::create_dir(&dir)?;
    let file = dir.join("config.yaml");
    // Fixture paths are selected by this operator-owned configuration only.
    std::fs::write(&file, yaml)?;
    let mut command = Command::new(env!("CARGO_BIN_EXE_setjoin-gateway"));
    command
        .arg0("gofree-gwconfig-gateway")
        .env_clear()
        .env("GATEWAY_LISTEN", address.to_string())
        .env("GATEWAY_AUTH_UPSTREAM", "http://127.0.0.1:1")
        .env("SETJOIN_CONFIG", &file)
        .env("DB_DSN", db.app.as_deref().unwrap_or(&db.dsn))
        .env("DB_WORKER_DSN", &db.dsn)
        .env("DB_DIRECT_DSN", &db.direct)
        .env("JWT_SECRET", "blobs1-test-jwt-secret-for-recording")
        .env("DB_ENCRYPTION_KEY", "22".repeat(32))
        .env("S3_ACCESS_KEY", "test-access")
        .env("S3_SECRET_KEY", "test-secret")
        .env("IMAP_ADDR", "127.0.0.1:0")
        .env("SMTP_SUBMISSION_ADDR", "127.0.0.1:0")
        .env(
            "AUTHSERVER_JWKS_URL",
            format!("http://{keys}/.well-known/jwks.json"),
        )
        .env("SETJOIN_AUTHZ_PRECHECK_TIMEOUT_MS", "15000")
        .env("SETJOIN_PG_DEADLINE_MS", "30000")
        .env("CORE_RATE_LIMIT", "100000")
        .env("ADMIN_RATE_LIMIT", "100000")
        .stdout(Stdio::null())
        .stderr(std::fs::File::create(dir.join("stderr.log"))?);
    for (key, value) in extra {
        command.env(key, value);
    }
    let child = command.spawn_boot()?;
    let mut process = Process { child, dir };
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        if let Some(status) = process.child.try_wait()? {
            return Err(format!(
                "gateway exited at startup: {status}: {}",
                std::fs::read_to_string(process.dir.join("stderr.log"))?
            )
            .into());
        }
        if tokio::net::TcpStream::connect(address).await.is_ok() {
            break;
        }
        if tokio::time::Instant::now() > deadline {
            return Err("gateway failed to listen".into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    Ok((process, address))
}
async fn no_go(address: std::net::SocketAddr) -> Result<(), BoxError> {
    let response = common::send(
        address,
        Request::get("/_gateway/metrics").body(common::full(""))?,
    )
    .await;
    let text = String::from_utf8(common::body_bytes(response).await.to_vec())?;
    assert!(
        text.lines()
            .any(|l| l == "setjoin_gateway_proxied_to_go_total 0"),
        "{text}"
    );
    Ok(())
}
#[tokio::test]
async fn yaml_download_asset_is_native_without_go() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("gwconfig-download").expect("required disposable database");
    let (_process, address) = start(&db, "network:\n  mode: airgap\n").await?;
    let response = common::send(
        address,
        Request::get("/downloads/asset/SetJoin_latest_linux-x86_64.deb").body(common::full(""))?,
    )
    .await;
    assert_eq!(response.status(), 302);
    assert_eq!(
        response.headers()["location"],
        "/updates/SetJoin_latest_linux-x86_64.deb"
    );
    common::body_bytes(response).await;
    no_go(address).await
}

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

struct Workspace(PathBuf);
impl Drop for Workspace {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).expect("remove owned oracle workspace");
    }
}
fn workspace() -> Result<Workspace, BoxError> {
    let parent = std::env::var_os("GOFREE_RECORD_GO_BINARY")
        .map(|p| PathBuf::from(p).parent().unwrap().to_owned())
        .unwrap_or_else(std::env::temp_dir);
    let path = parent.join(format!("gofree-gwconfig-fixture-{}", std::process::id()));
    std::fs::create_dir(&path)?;
    Ok(Workspace(path))
}
fn website(path: &std::path::Path) -> Result<(), BoxError> {
    std::fs::create_dir_all(path.join("_app"))?;
    let mut assets = vec![];
    for (name, body) in [
        ("index.html", "<html>GWCONFIG</html>\n"),
        ("_app/version.json", "{\"version\":\"gwconfig-v1\"}\n"),
    ] {
        std::fs::write(path.join(name), body)?;
        assets.push(json!({"path":format!("/{name}"),"identityBytes":body.len(),"identitySha256":format!("{:x}",Sha256::digest(body.as_bytes())),"representations":{}}));
    }
    std::fs::write(
        path.join("static-representations.v1.json"),
        serde_json::to_vec(&json!({"schemaVersion":1,"buildId":"gwconfig-v1","assets":assets}))?,
    )?;
    for relative in [
        "index.html",
        "_app/version.json",
        "static-representations.v1.json",
    ] {
        std::fs::File::open(path.join(relative))?.set_times(
            std::fs::FileTimes::new().set_modified(
                std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
            ),
        )?;
    }
    Ok(())
}
async fn observation(
    address: std::net::SocketAddr,
    path: &str,
    domain: &str,
    token: Option<&str>,
) -> Result<Value, BoxError> {
    let mut request = Request::get(path)
        .header("host", domain)
        .header("x-request-id", "gwconfig-oracle");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = common::send(address, request.body(common::full(""))?).await;
    let status = response.status().as_u16();
    let mut headers = serde_json::Map::new();
    for (name, value) in response.headers() {
        if !matches!(
            name.as_str(),
            "date" | "content-length" | "transfer-encoding"
        ) {
            headers.insert(
                name.to_string(),
                value.to_str()?.replace(domain, "gwconfig.test").into(),
            );
        }
    }
    let body = String::from_utf8(common::body_bytes(response).await.to_vec())?
        .replace(domain, "gwconfig.test");
    Ok(json!({"status":status,"headers":headers,"body":body}))
}
#[tokio::test]
async fn yaml_f7_conditions_replay_frozen_go_with_zero_proxies() -> Result<(), BoxError> {
    f7_case(true).await
}
async fn f7_case(scim: bool) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("gwconfig-f7").expect("required disposable database");
    let owner = db.connect().await?;
    let actor = setjoin_conformance::fixture::account(&owner, "gwconfig").await?;
    let domain: String = owner
        .query_one("SELECT name FROM domains WHERE id=$1", &[&actor.domain])
        .await?
        .get(0);
    let work = workspace()?;
    let website_path = work.0.join("website");
    website(&website_path)?;
    // These are global operator settings, saved and restored around the oracle.
    let saved: Vec<_> = owner
        .query(
            "SELECT key,value::text,encrypted,description FROM system_config WHERE key=ANY($1)",
            &[&vec![
                "ad_sync_domain",
                "ad_sync_ldap_host",
                "ldap_sync_enabled",
                "ldap_sync_host",
            ]],
        )
        .await?;
    owner.batch_execute("DELETE FROM system_config WHERE key IN ('ad_sync_domain','ad_sync_ldap_host','ldap_sync_enabled','ldap_sync_host'); INSERT INTO system_config(key,value) VALUES ('ad_sync_domain','\"gwconfig.test\"'),('ad_sync_ldap_host','\"127.0.0.1\"'),('ldap_sync_enabled','\"true\"'),('ldap_sync_host','\"127.0.0.1\"')").await?;
    let yaml = |website: &str| {
        format!("network:\n  mode: airgap\nscim:\n  enabled: {scim}\nad:\n  sync_enabled: true\nimap:\n  tls_addr: \"\"\ncrypto:\n  algorithm_profile: hybrid\nwebsite:\n  dir: {website}\n")
    };
    let record = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
    let mut native = None;
    let mut oracle = None;
    let address = if record {
        let file = work.0.join("config.yaml");
        let rel = work.0.file_name().unwrap().to_str().unwrap();
        std::fs::write(&file, yaml(&format!("/evidence/{rel}/website")))?;
        let s3=common::fake_upstream(|_|async {Response::new(common::full("<ListMultipartUploadsResult><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>"))}).await;
        oracle = common::go_oracle::start_unscoped_with_env(
            &db,
            s3,
            "gofree-gwconfig",
            &[("SETJOIN_CONFIG", format!("/evidence/{rel}/config.yaml"))],
        )
        .await?;
        common::gateway(
            oracle.as_ref().unwrap().address,
            "",
            setjoin_gateway::RouteTable::proxy_all(),
        )
        .await
    } else {
        let (process, address) = start(&db, &yaml(website_path.to_str().unwrap())).await?;
        native = Some(process);
        address
    };
    let token = common::recovery_token_with(actor.user, json!({"perms":["users.read"]}));
    let mut observations = serde_json::Map::new();
    for (name, path, auth) in [
        ("scim-by-file", "/scim/v2/ServiceProviderConfig", None),
        (
            "ad-runtime-enable",
            "/api/admin/ad/health",
            Some(token.as_str()),
        ),
        (
            "ldap-runtime-enable",
            "/api/admin/ldap/health",
            Some(token.as_str()),
        ),
        ("well-known", "/.well-known/setjoin", None),
        (
            "autoconfig",
            "/.well-known/autoconfig/mail/config-v1.1.xml",
            None,
        ),
        (
            "downloads-asset",
            "/downloads/asset/SetJoin_latest_linux-x86_64.deb",
            None,
        ),
        ("favicon", "/favicon.ico", None),
    ] {
        observations.insert(
            name.into(),
            observation(address, path, &domain, auth).await?,
        );
    }
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(if scim {
        "../../tests/conformance/gateway-config/f7.json"
    } else {
        "../../tests/conformance/gateway-config/f7-disabled-scim.json"
    });
    let result = if record {
        setjoin_conformance::golden::record(
            &path,
            &json!({"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observations}),
        )
        .map_err(|e| e.to_string())
    } else {
        no_go(address).await?;
        let golden: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        setjoin_conformance::golden::compare(&golden["observation"], &observations.into())
    };
    drop(native);
    drop(oracle);
    owner.batch_execute("DELETE FROM system_config WHERE key IN ('ad_sync_domain','ad_sync_ldap_host','ldap_sync_enabled','ldap_sync_host')").await?;
    for row in saved {
        let key: String = row.get(0);
        let value: String = row.get(1);
        let encrypted: bool = row.get(2);
        let description: Option<String> = row.get(3);
        owner
            .execute(
                "INSERT INTO system_config(key,value,encrypted,description) VALUES($1,$2::text::jsonb,$3,$4)",
                &[&key, &value, &encrypted, &description],
            )
            .await?;
    }
    setjoin_conformance::fixture::remove(&owner, &actor).await?;
    result.map_err(Into::into)
}

async fn reload_request(
    address: std::net::SocketAddr,
    method: &str,
    path: &str,
    token: &str,
) -> Result<Value, BoxError> {
    let response = common::send(
        address,
        Request::builder()
            .method(method)
            .uri(path)
            .header("host", "mail.test")
            .header("x-request-id", "gwconfig-oracle")
            .header("x-forwarded-for", "198.51.100.7")
            .header("authorization", format!("Bearer {token}"))
            .body(common::full("ignored malformed JSON"))?,
    )
    .await;
    let status = response.status().as_u16();
    let mut headers = serde_json::Map::new();
    for (name, value) in response.headers() {
        if !matches!(
            name.as_str(),
            "date" | "content-length" | "transfer-encoding"
        ) {
            headers.insert(name.to_string(), value.to_str()?.into());
        }
    }
    let body = String::from_utf8(common::body_bytes(response).await.to_vec())?;
    Ok(json!({"status":status,"headers":headers,"body":body}))
}
#[tokio::test]
async fn reload_http_matches_go_and_refreshes_proxies_without_rebuilding_handlers(
) -> Result<(), BoxError> {
    reload_http_case("sequence").await
}
async fn reload_http_case(receipt: &str) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("gwconfig-reload").expect("required disposable database");
    let owner = db.connect().await?;
    let actor = setjoin_conformance::fixture::account(&owner, "gwconfig-reload").await?;
    let saved = owner
        .query_opt(
            "SELECT value::text,encrypted,description FROM system_config WHERE key='trusted_proxy_ips'",
            &[],
        )
        .await?;
    owner.batch_execute("INSERT INTO system_config(key,value) VALUES('trusted_proxy_ips','[\"127.0.0.1\"]') ON CONFLICT(key) DO UPDATE SET value=excluded.value,encrypted=false").await?;
    let before: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let work = workspace()?;
    let record = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
    let yaml = "network:\n  mode: airgap\nscim:\n  enabled: true\n";
    let mut native = None;
    let mut oracle = None;
    let (address, file) = if record {
        let file = work.0.join("config.yaml");
        std::fs::write(&file, yaml)?;
        let rel = work.0.file_name().unwrap().to_str().unwrap();
        let s3=common::fake_upstream(|_|async {Response::new(common::full("<ListMultipartUploadsResult><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>"))}).await;
        oracle = common::go_oracle::start_unscoped_with_env(
            &db,
            s3,
            "gofree-gwconfig",
            &[("SETJOIN_CONFIG", format!("/evidence/{rel}/config.yaml"))],
        )
        .await?;
        // Preserve the forwarded identity at this recording front door, as in production.
        (
            common::gateway(
                oracle.as_ref().unwrap().address,
                "127.0.0.1",
                setjoin_gateway::RouteTable::proxy_all(),
            )
            .await,
            file,
        )
    } else {
        let (process, address) = start(&db, yaml).await?;
        let file = process.dir.join("config.yaml");
        native = Some(process);
        (address, file)
    };
    let allowed = common::recovery_token_with(actor.user, json!({"perms":["system.config"]}));
    let denied = common::recovery_token(actor.user);
    let scoped = common::recovery_token_with(
        actor.user,
        json!({"perms":["system.config"],"domain":actor.domain}),
    );
    let mut observations = serde_json::Map::new();
    observations.insert(
        "before".into(),
        reload_request(address, "GET", "/.well-known/setjoin", &allowed).await?,
    );
    observations.insert(
        "denied".into(),
        reload_request(address, "POST", "/api/admin/reload", &denied).await?,
    );
    observations.insert(
        "cross-tenant".into(),
        reload_request(address, "POST", "/api/admin/reload", &scoped).await?,
    );
    std::fs::write(
        &file,
        "network:\n  mode: china\ncrypto:\n  algorithm_profile: hybrid\nscim:\n  enabled: false\n",
    )?;
    owner
        .batch_execute(
            "UPDATE system_config SET value='[\"192.0.2.1\"]' WHERE key='trusted_proxy_ips'",
        )
        .await?;
    observations.insert(
        "success".into(),
        reload_request(address, "POST", "/api/admin/reload", &allowed).await?,
    );
    observations.insert(
        "repeat".into(),
        reload_request(address, "POST", "/api/admin/reload", &allowed).await?,
    );
    observations.insert(
        "after".into(),
        reload_request(address, "GET", "/.well-known/setjoin", &allowed).await?,
    );
    // Go keeps boot route registration, even when the newly loaded file disables SCIM.
    observations.insert(
        "scim-after".into(),
        reload_request(address, "GET", "/scim/v2/Users", "opaque-invalid").await?,
    );
    owner
        .batch_execute(
            "UPDATE system_config SET value='[\"127.0.0.1\"]' WHERE key='trusted_proxy_ips'",
        )
        .await?;
    std::fs::write(&file, "smime:\n  encrypt_algorithm: typo\n")?;
    observations.insert(
        "invalid-input".into(),
        reload_request(address, "POST", "/api/admin/reload", &allowed).await?,
    );
    observations.insert(
        "after-failure".into(),
        reload_request(address, "GET", "/.well-known/setjoin", &allowed).await?,
    );
    let audit_rows=owner.query("SELECT id,(to_jsonb(a)-ARRAY['id','occurred_at','checksum','prev_checksum'])::text FROM admin_audit_log a WHERE id>$1 ORDER BY id",&[&before]).await?;
    let audit_ids: Vec<i64> = audit_rows.iter().map(|r| r.get(0)).collect();
    let audits: Vec<Value> = audit_rows
        .iter()
        .map(|r| {
            serde_json::from_str(
                &r.get::<_, String>(1)
                    .replace(&format!("domain={}", actor.domain), "domain=<actor>"),
            )
        })
        .collect::<Result<_, _>>()?;
    observations.insert("audit".into(), audits.into());
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/conformance/gateway-config/reload-http.json");
    let result = if record {
        setjoin_conformance::golden::record(
            &path,
            &json!({"go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observations}),
        )
        .map_err(|e| e.to_string())
    } else {
        no_go(address).await?;
        let golden: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        setjoin_conformance::golden::compare(&golden["observation"], &observations.into())
    };
    drop(native);
    drop(oracle);
    owner
        .batch_execute("DELETE FROM system_config WHERE key='trusted_proxy_ips'")
        .await?;
    if let Some(row) = saved {
        let value: String = row.get(0);
        let encrypted: bool = row.get(1);
        let description: Option<String> = row.get(2);
        owner.execute("INSERT INTO system_config(key,value,encrypted,description) VALUES('trusted_proxy_ips',$1::text::jsonb,$2,$3)",&[&value,&encrypted,&description]).await?;
    }
    if !audit_ids.is_empty() {
        owner
            .batch_execute("BEGIN; SET LOCAL session_replication_role=replica")
            .await?;
        owner
            .execute(
                "DELETE FROM admin_audit_log WHERE id=ANY($1)",
                &[&audit_ids],
            )
            .await?;
        owner.batch_execute("COMMIT").await?;
    }
    setjoin_conformance::fixture::remove(&owner, &actor).await?;
    if result.is_ok() && !record {
        // The recorded case is one wire sequence; each test names the golden case it stands for.
        println!("GOLDEN-REPLAY: POST /admin/reload :: {receipt}");
    }
    result.map_err(Into::into)
}

async fn proxy_status(
    address: std::net::SocketAddr,
    ip: &str,
    token: Option<&str>,
) -> Result<u16, BoxError> {
    let mut request = Request::builder()
        .method(if token.is_some() { "POST" } else { "GET" })
        .uri(if token.is_some() {
            "/api/admin/reload"
        } else {
            "/.well-known/setjoin"
        })
        .header("host", "mail.test")
        .header("x-forwarded-for", ip)
        .header("x-request-id", "gwconfig-proxy");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = common::send(address, request.body(common::full(""))?).await;
    let status = response.status().as_u16();
    common::body_bytes(response).await;
    Ok(status)
}
async fn signal_and_wait(
    native: &mut Option<Process>,
    oracle: &Option<common::go_oracle::GoOracle>,
    expected: &str,
) -> Result<(), BoxError> {
    let logs = || -> Result<String, BoxError> {
        match oracle {
            Some(o) => o.logs(),
            None => Ok(std::fs::read_to_string(
                native.as_ref().unwrap().dir.join("stderr.log"),
            )?),
        }
    };
    let before = logs()?.matches(expected).count();
    if let Some(oracle) = oracle {
        oracle.reload_signal()?;
    } else {
        let pid = native.as_ref().unwrap().child.id();
        // This PID belongs to this RAII child; never signal by a global process name.
        if unsafe { libc::kill(pid as i32, libc::SIGHUP) } != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        let text = match oracle {
            Some(o) => o.logs()?,
            None => {
                let process = native.as_mut().unwrap();
                if let Some(status) = process.child.try_wait()? {
                    return Err(format!("gateway exited after SIGHUP: {status}").into());
                }
                std::fs::read_to_string(process.dir.join("stderr.log"))?
            }
        };
        if text.matches(expected).count() > before {
            break;
        }
        if tokio::time::Instant::now() > deadline {
            return Err(format!("signal did not produce {expected}: {text}").into());
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    Ok(())
}
async fn proxy_reload_case(signal: bool) -> Result<(), BoxError> {
    proxy_reload_input(signal, "v2", "[\"192.0.2.1\"]").await
}
async fn proxy_reload_input(signal: bool, case: &str, trust: &str) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("gwconfig-proxy-refresh").expect("required disposable database");
    let owner = db.connect().await?;
    let actor = setjoin_conformance::fixture::account(&owner, "gwconfig-proxy").await?;
    let saved = owner
        .query_opt(
            "SELECT value::text,encrypted,description FROM system_config WHERE key='trusted_proxy_ips'",
            &[],
        )
        .await?;
    owner.batch_execute("INSERT INTO system_config(key,value) VALUES('trusted_proxy_ips','[\"127.0.0.1\"]') ON CONFLICT(key) DO UPDATE SET value=excluded.value,encrypted=false").await?;
    let ips = vec![
        "127.0.0.1",
        "198.51.100.61",
        "198.51.100.62",
        "198.51.100.63",
        "198.51.100.64",
    ];
    let counters = owner
        .query(
            "SELECT to_jsonb(r)::text FROM rate_limit_counters r WHERE key=ANY($1)",
            &[&ips],
        )
        .await?
        .into_iter()
        .map(|r| serde_json::from_str::<Value>(&r.get::<_, String>(0)))
        .collect::<Result<Vec<_>, _>>()?;
    owner
        .execute("DELETE FROM rate_limit_counters WHERE key=ANY($1)", &[&ips])
        .await?;
    // A rate window must not turn over during this bounded oracle.
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs()
        % 60;
    if seconds > 50 {
        tokio::time::sleep(std::time::Duration::from_secs(61 - seconds)).await;
    }
    let work = workspace()?;
    let record = std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some();
    let yaml = "network:\n  mode: airgap\n";
    let mut native = None;
    let mut oracle = None;
    let (address, file) = if record {
        let file = work.0.join("config.yaml");
        std::fs::write(&file, yaml)?;
        let rel = work.0.file_name().unwrap().to_str().unwrap();
        let s3=common::fake_upstream(|_|async {Response::new(common::full("<ListMultipartUploadsResult><IsTruncated>false</IsTruncated></ListMultipartUploadsResult>"))}).await;
        oracle = common::go_oracle::start_unscoped_with_env(
            &db,
            s3,
            "gofree-gwconfig",
            &[
                ("SETJOIN_CONFIG", format!("/evidence/{rel}/config.yaml")),
                ("CORE_RATE_LIMIT", "2".into()),
            ],
        )
        .await?;
        (
            common::gateway(
                oracle.as_ref().unwrap().address,
                "127.0.0.1",
                setjoin_gateway::RouteTable::proxy_all(),
            )
            .await,
            file,
        )
    } else {
        let (process, address) =
            start_configured(&db, yaml, &[("CORE_RATE_LIMIT", "2".into())]).await?;
        let file = process.dir.join("config.yaml");
        native = Some(process);
        (address, file)
    };
    // Saturate the socket-peer bucket in both processes. Startup readiness may
    // already have spent a credit; two more calls deterministically fill it.
    for _ in 0..2 {
        let response = common::send(
            address,
            Request::get("/.well-known/setjoin").body(common::full(""))?,
        )
        .await;
        common::body_bytes(response).await;
    }
    let token = common::recovery_token_with(actor.user, json!({"perms":["system.config"]}));
    let mut statuses = vec![];
    for _ in 0..3 {
        statuses.push(proxy_status(address, ips[1], None).await?);
    }
    owner
        .execute(
            "UPDATE system_config SET value=$1::text::jsonb WHERE key='trusted_proxy_ips'",
            &[&trust],
        )
        .await?;
    std::fs::write(&file, "smime:\n  encrypt_algorithm: typo\n")?;
    if signal {
        signal_and_wait(&mut native, &oracle, "config reload failed").await?;
    } else {
        statuses.push(proxy_status(address, ips[2], Some(&token)).await?);
    }
    statuses.push(proxy_status(address, ips[3], None).await?);
    std::fs::write(&file, yaml)?;
    if signal {
        signal_and_wait(&mut native, &oracle, "config reloaded successfully").await?;
    } else {
        statuses.push(proxy_status(address, ips[2], Some(&token)).await?);
    }
    statuses.push(proxy_status(address, ips[1], None).await?);
    statuses.push(proxy_status(address, ips[4], None).await?);
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../tests/conformance/gateway-config/proxy-{}-{}.json",
        if signal { "sighup" } else { "http" },
        case
    ));
    let result = if record {
        setjoin_conformance::golden::record(
            &path,
            &json!({"go_source":std::env::var("GOFREE_GO_SOURCE")?,"statuses":statuses}),
        )
        .map_err(|e| e.to_string())
    } else {
        no_go(address).await?;
        let golden: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        setjoin_conformance::golden::compare(&golden["statuses"], &json!(statuses))
    };
    drop(native);
    drop(oracle);
    owner
        .batch_execute("DELETE FROM system_config WHERE key='trusted_proxy_ips'")
        .await?;
    if let Some(row) = saved {
        let value: String = row.get(0);
        let encrypted: bool = row.get(1);
        let description: Option<String> = row.get(2);
        owner.execute("INSERT INTO system_config(key,value,encrypted,description) VALUES('trusted_proxy_ips',$1::text::jsonb,$2,$3)",&[&value,&encrypted,&description]).await?;
    }
    owner
        .execute("DELETE FROM rate_limit_counters WHERE key=ANY($1)", &[&ips])
        .await?;
    let rows = serde_json::to_string(&counters)?;
    owner.execute("INSERT INTO rate_limit_counters SELECT * FROM jsonb_populate_recordset(NULL::rate_limit_counters,$1::text::jsonb)",&[&rows]).await?;
    setjoin_conformance::fixture::remove(&owner, &actor).await?;
    result.map_err(Into::into)
}
#[tokio::test]
async fn http_reload_refreshes_client_ip_budget_after_success_only() -> Result<(), BoxError> {
    proxy_reload_case(false).await
}
#[tokio::test]
async fn sighup_refreshes_client_ip_budget_after_success_only() -> Result<(), BoxError> {
    proxy_reload_case(true).await
}

#[tokio::test]
async fn double_underscore_environment_controls_startup_registration() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("gwconfig-alias").expect("required disposable database");
    let (_process, address) = start_configured(
        &db,
        "",
        &[
            ("SCIM__ENABLED", "true".into()),
            ("NETWORK__MODE", "airgap".into()),
        ],
    )
    .await?;
    let response = common::send(
        address,
        Request::get("/scim/v2/Users").body(common::full(""))?,
    )
    .await;
    assert_eq!(response.status(), 401);
    common::body_bytes(response).await;
    no_go(address).await
}

#[tokio::test]
async fn bare_reload_uses_go_api_alias_without_reaching_auth_listener() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("gwconfig-reload-alias").expect("required disposable database");
    let (_process, address) = start(&db, "network:\n  mode: airgap\n").await?;
    let response = common::send(
        address,
        Request::post("/admin/reload?x=1").body(common::full("opaque"))?,
    )
    .await;
    assert_eq!(response.status(), 308);
    assert_eq!(response.headers()["location"], "/api/admin/reload?x=1");
    common::body_bytes(response).await;
    no_go(address).await
}

macro_rules! replay_reload {
    ($name:ident, $case:literal) => {
        #[tokio::test]
        async fn $name() -> Result<(), BoxError> {
            reload_http_case($case).await
        }
    };
}
replay_reload!(reload_success_recording, "success");
replay_reload!(reload_scoped_recording, "cross-tenant");
replay_reload!(reload_invalid_recording, "invalid-input");
replay_reload!(reload_denied_recording, "denied");
replay_reload!(reload_repeat_recording, "repeat");

#[tokio::test]
async fn reload_status_mutant_is_rejected() -> Result<(), BoxError> {
    use setjoin_gateway::{
        Body, BoxFuture, Config, Gateway, Intercept, RequestContext, RouteTable, TrustedProxies,
    };
    use std::sync::Arc;
    struct Changed<T>(T);
    impl<T: Intercept + 'static> Intercept for Changed<T> {
        fn matches(&self, r: &Request<Body>) -> bool {
            self.0.matches(r)
        }
        fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
            let response = self.0.handle(r, c);
            Box::pin(async move {
                let mut response = response.await;
                *response.status_mut() = hyper::StatusCode::BAD_GATEWAY;
                response
            })
        }
    }
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("gwconfig-status-mutant").expect("required disposable database");
    let owner = db.connect().await?;
    let actor = setjoin_conformance::fixture::account(&owner, "gwconfig-mutant").await?;
    let environment = std::collections::BTreeMap::from([
        (
            "DB_DSN".into(),
            db.app.clone().unwrap_or_else(|| db.dsn.clone()),
        ),
        (
            "JWT_SECRET".into(),
            "blobs1-test-jwt-secret-for-recording".into(),
        ),
        ("S3_ACCESS_KEY".into(), "test-access".into()),
        ("S3_SECRET_KEY".into(), "test-secret".into()),
        ("IMAP_ADDR".into(), "127.0.0.1:0".into()),
        ("SMTP_SUBMISSION_ADDR".into(), "127.0.0.1:0".into()),
    ]);
    let settings = setjoin_gateway::configuration::Settings::parse("", &environment)?;
    let runtime = Arc::new(setjoin_gateway::configuration::Runtime::new(
        environment,
        settings,
    )?);
    let exec = common::patient_exec(db.app.as_deref().unwrap_or(&db.dsn), 2)?;
    let token = common::recovery_token_with(actor.user, json!({"perms":["system.config"]}));
    let golden: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/gateway-config/reload-success.json"
    ))?;
    let expected = json!({"status":golden["observation"]["response"]["status"],"body":golden["observation"]["response"]["body"]});
    for changed in [false, true] {
        let route = setjoin_gateway::platform::PlatformRoute::new(
            exec.clone(),
            Arc::new(common::recovery_keys()),
            "mailserver".into(),
        )
        .with_configuration(runtime.clone());
        let routes = if changed {
            RouteTable::proxy_all().with(Changed(route))
        } else {
            RouteTable::proxy_all().with(route)
        };
        let gateway = Gateway::new(
            Config {
                upstream: None,
                trusted_proxies: TrustedProxies::default(),
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit: None,
            },
            routes,
        )?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(gateway.serve_until(listener, async {
            let _ = stopped.await;
        }));
        let response = reload_request(address, "POST", "/api/admin/reload", &token).await?;
        let observed = json!({"status":response["status"],"body":response["body"]});
        no_go(address).await?;
        let _ = stop.send(());
        task.await?;
        let comparison = setjoin_conformance::golden::compare(&expected, &observed);
        if changed {
            assert!(comparison.is_err(), "status mutant survived");
        } else {
            comparison?;
        }
    }
    setjoin_conformance::fixture::remove(&owner, &actor).await?;
    println!("MUTANT-REJECTED: POST /admin/reload :: changed-status");
    Ok(())
}

#[tokio::test]
async fn proxy_list_whitespace_is_not_an_ip() -> Result<(), BoxError> {
    proxy_reload_input(false, "whitespace", "[\" 127.0.0.1 \"]").await
}
#[tokio::test]
async fn proxy_list_member_cannot_contain_a_second_ip() -> Result<(), BoxError> {
    proxy_reload_input(false, "embedded-comma", "[\"127.0.0.1,192.0.2.1\"]").await
}
#[tokio::test]
async fn proxy_list_ipv4_mapped_cidr_matches_go() -> Result<(), BoxError> {
    proxy_reload_input(false, "mapped-cidr", "[\"::ffff:127.0.0.1/128\"]").await
}

#[tokio::test]
async fn yaml_startup_refuses_the_same_invalid_algorithm_as_go_reload() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("gwconfig-invalid-startup").expect("required disposable database");
    let go: Value = serde_json::from_str(include_str!(
        "../../../tests/conformance/gateway-config/reload-invalid-input.json"
    ))?;
    let body: Value =
        serde_json::from_str(go["observation"]["response"]["body"].as_str().unwrap())?;
    let expected = body["error"]
        .as_str()
        .unwrap()
        .strip_prefix("config reload failed: ")
        .unwrap();
    match start(&db, "smime:\n  encrypt_algorithm: typo\n").await {
        Ok((_process, _)) => Err("invalid Go configuration opened a listener".into()),
        Err(error) => {
            assert!(error.to_string().contains(expected), "{error}");
            Ok(())
        }
    }
}

#[tokio::test]
async fn disabled_scim_uses_the_configured_root_fallback() -> Result<(), BoxError> {
    f7_case(false).await
}

#[tokio::test]
async fn legacy_jwt_configuration_serves_config_without_a_jwks_url() -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let db = Db::for_case("gwconfig-legacy-only").expect("required disposable database");
    let owner = db.connect().await?;
    let actor = setjoin_conformance::fixture::account(&owner, "gwconfig-legacy").await?;
    let (process, address) = start_configured(
        &db,
        "network:\n  mode: airgap\n",
        &[("AUTHSERVER_JWKS_URL", "".into())],
    )
    .await?;
    let result = async {
        let public = common::send(address, Request::get("/.well-known/setjoin").body(common::full(""))?).await;
        let status = public.status().as_u16();
        common::body_bytes(public).await;
        if status != 200 { return Err::<(), BoxError>(format!("Go's optional JWKS setting prevented public config: {status}").into()); }
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
        let claims = json!({"uid":actor.user,"email":"x@test","typ":"access","jti":"gwconfig-legacy","fam":"gwconfig-legacy","iss":"mailserver","aud":["mailserver-gateway"],"iat":now-10,"exp":now+600,"perms":["system.config"]});
        let token = setjoin_authz::legacy_jwt::sign_hs256(b"blobs1-test-jwt-secret-for-recording", &claims.to_string());
        let response = reload_request(address, "POST", "/api/admin/reload", &token).await?;
        let go: Value = serde_json::from_str(include_str!("../../../tests/conformance/gateway-config/reload-success.json"))?;
        setjoin_conformance::golden::compare(&go["observation"]["response"], &response)?;
        no_go(address).await
    }.await;
    drop(process);
    setjoin_conformance::fixture::remove(&owner, &actor).await?;
    result
}
