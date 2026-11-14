//! Frozen-Go recorder and replayer for root-mux answers (#357, #378).
//!
//! Recording (`GOFREE_RECORD_GO_BINARY` set): the gateway forwards every request to
//! the covered mailserverd (`with_enabled(false)`); the answer is written exclusively.
//! Replay: no Go process and no upstream; the case's route table answers and
//! `setjoin_gateway_proxied_to_go_total` must stay 0. With `website`, both sides serve
//! the deterministic operator build from `catchall_oracle/assets.rs`.
use super::BoxError;
use futures_util::FutureExt;
use hyper::Request;
use serde_json::{json, Value};
use setjoin_conformance::{golden, harness::Db};
use setjoin_gateway::{Config, Gateway, RouteTable, TrustedProxies};
use std::path::PathBuf;
use std::sync::Arc;

#[path = "../catchall_oracle/assets.rs"]
mod assets;

pub type Website = Option<Arc<setjoin_static::website::Website>>;

pub struct MuxCase {
    pub name: &'static str,
    pub method: &'static str,
    pub uri: &'static str,
    /// Send a valid first-party member token for a fixture account.
    pub bearer: bool,
    /// Serve the operator webmail build (Go's `WEBSITE_DIR`).
    pub website: bool,
}

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub async fn run(
    corpus: &str,
    case: &MuxCase,
    extra_env: &[(&str, String)],
    table: &dyn Fn(setjoin_pg::ScopedExecutor, Website) -> RouteTable,
) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    let Some(db) = Db::for_case(case.name) else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let account = if case.bearer {
        Some(setjoin_conformance::fixture::account(&owner, "mux-oracle").await?)
    } else {
        None
    };
    let user = account.as_ref().map(|a| a.user);
    let result = std::panic::AssertUnwindSafe(observe(corpus, case, extra_env, table, &db, user))
        .catch_unwind()
        .await;
    if let Some(account) = account {
        setjoin_conformance::fixture::remove(&owner, &account).await?;
    }
    match result {
        Ok(result) => result,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

async fn observe(
    corpus: &str,
    case: &MuxCase,
    extra_env: &[(&str, String)],
    table: &dyn Fn(setjoin_pg::ScopedExecutor, Website) -> RouteTable,
    db: &Db,
    user: Option<i64>,
) -> Result<(), BoxError> {
    let site = if case.website {
        Some(assets::website(case.name)?)
    } else {
        None
    };
    let mut env: Vec<(&str, String)> = extra_env.to_vec();
    if let Some(site) = &site {
        let dir = site
            .0
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or("website dir")?;
        env.push(("WEBSITE_DIR", format!("/evidence/{dir}")));
    }
    let s3 = super::fake_upstream(|_| async { hyper::Response::new(super::full("")) }).await;
    let go = super::go_oracle::start_named_with_env(db, s3, "gofree-mux-oracle", &env).await?;
    let exec = setjoin_pg::ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 2)
        .map_err(|e| e.0)?;
    let website: Website = match &site {
        Some(site) => Some(Arc::new(setjoin_static::website::Website::load(&site.0)?)),
        None => None,
    };
    let gateway = Gateway::new(
        Config {
            upstream: go
                .as_ref()
                .map(|g| format!("http://{}", g.address).parse())
                .transpose()?,
            trusted_proxies: TrustedProxies::parse("")?,
            upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
            edge_limit: None,
        },
        if go.is_some() {
            RouteTable::proxy_all()
        } else {
            table(exec, website)
        },
    )?;
    let gateway = if go.is_some() {
        gateway.with_enabled(false)
    } else {
        gateway
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server = tokio::spawn(gateway.serve(listener));
    let mut request = Request::builder()
        .method(case.method)
        .uri(case.uri)
        .header("host", "mail.test")
        .header("x-request-id", "mux-oracle");
    if let Some(user) = user {
        request = request.header(
            "authorization",
            format!("Bearer {}", super::recovery_token(user)),
        );
    }
    let response = super::send(addr, request.body(super::full(""))?).await;
    let status = response.status().as_u16();
    let mut headers = serde_json::Map::new();
    for (name, value) in response.headers() {
        if !matches!(
            name.as_str(),
            "date" | "transfer-encoding" | "content-length"
        ) {
            headers.insert(name.to_string(), json!(value.to_str()?));
        }
    }
    let body = super::body_bytes(response).await;
    if go.is_none() {
        let metrics = super::send(
            addr,
            Request::get("/_gateway/metrics").body(super::full(""))?,
        )
        .await;
        let metrics = String::from_utf8(super::body_bytes(metrics).await.to_vec())?;
        if !metrics
            .lines()
            .any(|l| l == "setjoin_gateway_proxied_to_go_total 0")
        {
            server.abort();
            return Err(format!("{}: Go hop: {metrics}", case.name).into());
        }
    }
    server.abort();
    drop(go);
    let observation = json!({
        "request": {"method": case.method, "path": case.uri, "bearer": case.bearer, "website": case.website},
        "response": {"status": status, "headers": headers, "body": String::from_utf8_lossy(&body)},
        "effects": [], "audit": [], "notify": []
    });
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../../tests/conformance/{corpus}/{}.json",
        case.name
    ));
    if std::env::var_os("GOFREE_RECORD_GO_BINARY").is_some() {
        std::fs::create_dir_all(path.parent().ok_or("corpus path")?)?;
        golden::record(
            &path,
            &json!({"format":1,"route":format!("{} {}", case.method, case.uri),"case":case.name,
                    "go_source":std::env::var("GOFREE_GO_SOURCE")?,"observation":observation}),
        )?;
    } else {
        let expected: Value = serde_json::from_slice(&std::fs::read(&path)?)?;
        golden::compare(&expected["observation"], &observation)?;
        println!("GOLDEN-REPLAY: {corpus} :: {}", case.name);
    }
    drop(site);
    Ok(())
}
