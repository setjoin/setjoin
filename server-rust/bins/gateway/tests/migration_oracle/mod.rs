//! F05 slice `migration` frozen-Go oracle: HTTP wire, committed rows and audit.
//! Record mode runs the covered Go binary behind the front door; replay serves the
//! same requests from Rust with no Go upstream. Every case builds and removes its own
//! fixtures (two accounts, three jobs, the three `system_config` profiles); `SERIAL`
//! keeps cases from overlapping.
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{golden, harness::Db};
use setjoin_gateway::{
    migration::MigrationRoute, Body, BoxFuture, Config, Gateway, Intercept, RequestContext,
    RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

pub mod expected;
mod plan;
pub use plan::{plan, Fx};

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Probe {
    inner: MigrationRoute<setjoin_gateway::jmap::jwks::Jwks>,
    changed_status: bool,
}
impl Intercept for Probe {
    fn matches(&self, r: &Request<Body>) -> bool {
        self.inner.matches(r)
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        self.inner.admits_member(h, s)
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let future = self.inner.handle(r, c);
        let changed = self.changed_status;
        Box::pin(async move {
            let mut response = future.await;
            if changed {
                *response.status_mut() = hyper::StatusCode::IM_A_TEAPOT;
            }
            response
        })
    }
}

pub fn admin_token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let source = common::recovery_token(user);
    let fields: Vec<&str> = source.split('.').collect();
    let mut claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(fields[1]).unwrap()).unwrap();
    claims["admin"] = json!(true);
    claims["perms"] = json!(["forged.permission"]);
    claims["auth_time"] = json!(claims["iat"].clone());
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let signature: p256::ecdsa::Signature = key.sign(format!("{}.{payload}", fields[0]).as_bytes());
    format!(
        "{}.{payload}.{}",
        fields[0],
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
}

fn timestamp_like(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() >= 19
        && b[4] == b'-'
        && b[7] == b'-'
        && (b[10] == b'T' || b[10] == b' ')
        && b[13] == b':'
}

/// Replace run-specific identities: numeric ids by the key that names them (as numbers
/// or strings) and timestamps.
fn mask(v: &mut Value, ids: &[(&str, i64, String)]) {
    match v {
        Value::Object(map) => {
            for (k, x) in map.iter_mut() {
                let named = |n: i64| {
                    ids.iter()
                        .find(|(key, id, _)| key == k && *id == n)
                        .map(|(_, _, name)| name.clone())
                };
                if let Some(name) = x.as_i64().and_then(named) {
                    *x = json!(name);
                } else if let Some(name) = x
                    .as_str()
                    .and_then(|s| s.parse::<i64>().ok())
                    .and_then(named)
                {
                    *x = json!(name);
                } else {
                    mask(x, ids);
                }
            }
        }
        Value::Array(xs) => xs.iter_mut().for_each(|x| mask(x, ids)),
        Value::String(s) if timestamp_like(s) => *s = "<timestamp>".into(),
        _ => {}
    }
}

/// Ids inside request paths and prose (a problem `instance`, an audit target).
fn mask_paths(text: &str, fx: &Fx) -> String {
    let mut out = text.to_owned();
    for (id, name) in [
        (fx.j1, "<job-completed>"),
        (fx.j2, "<job-failed>"),
        (fx.j3, "<job-cancelled>"),
    ] {
        out = out.replace(&format!("/jobs/{id}"), &format!("/jobs/{name}"));
    }
    out = out.replace(&format!("domain={})", fx.a.domain), "domain=<domain-a>)");
    out
}

/// The OAuth state is 32 random bytes of hex.
fn mask_state(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        let run = b[i..]
            .iter()
            .take_while(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
            .count();
        if run >= 64 && (i == 0 || !b[i - 1].is_ascii_alphanumeric()) {
            out.push_str("<state>");
            i += run;
        } else {
            let ch = text[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

async fn rows(c: &tokio_postgres::Client, sql: &str) -> Result<Vec<Value>, BoxError> {
    c.query(sql, &[])
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
        .collect()
}

/// Everything the routes of this slice may touch, keyed by names (no ids).
async fn snapshot(c: &tokio_postgres::Client, fx: &Fx, since: &str) -> Result<Value, BoxError> {
    let users = format!("({},{})", fx.a.user, fx.b.user);
    let mut config = vec![];
    for row in c
        .query("SELECT key, value::text, encrypted, updated_at >= $1::text::timestamptz FROM system_config WHERE key=ANY($2) ORDER BY key", &[&since, &plan::KEYS.map(String::from).to_vec()])
        .await?
    {
        let (key, value, encrypted, touched): (String, String, bool, bool) = (row.get(0), row.get(1), row.get(2), row.get(3));
        let mut v: Value = serde_json::from_str(&value)?;
        let mut opened = Value::Null;
        // A stored profile is sealed under a random nonce: compare what it holds.
        if v.get("_enc").is_some() {
            if let setjoin_mailboxes::migration::Unsealed::Plain(plain) = setjoin_mailboxes::migration::unseal(&value, &plan::root()) {
                opened = plain;
                v = json!("<sealed>");
            }
        }
        config.push(json!({"key":key,"encrypted":encrypted,"value":v,"opened":opened,"touched":touched}));
    }
    Ok(json!({
        "jobs": rows(c, &format!("SELECT jsonb_build_object('id',id,'user_id',user_id,'source',source_type,'status',status,'strategy',conflict_strategy,'progress',progress,'error_log',error_log,'started',started_at IS NOT NULL,'completed',completed_at IS NOT NULL,'mailbox',target_mailbox_id,'has_config',source_config_enc IS NOT NULL)::text FROM migration_jobs WHERE user_id IN {users} ORDER BY created_at")).await?,
        "config": config,
        "consent": rows(c, &format!("SELECT jsonb_build_object('actor_user_id',actor_user_id,'cloud',cloud,'consumed',consumed_at IS NOT NULL,'token_length',length(state_token),'live',expires_at>now(),'stale',state_token IN ('stale-token-1','other-token-1'))::text FROM m365_consent_states WHERE actor_user_id IN {users} ORDER BY actor_user_id, state_token IN ('stale-token-1','other-token-1') DESC")).await?,
    }))
}

pub async fn run(action: &str, kind: &str) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run_inner(action, kind).await
}

async fn run_inner(action: &str, kind: &str) -> Result<(), BoxError> {
    let mutant = kind.ends_with("-status-mutant");
    let label = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let Some(db) = Db::for_case("migration-http") else {
        return Ok(());
    };
    let learn = std::env::var_os("GOFREE_ORACLE_LEARN").is_some();
    let owner = db.connect().await?;
    let fx = Fx::build(&owner, label, action).await?;
    let seeded = fx.seed(&owner, action, label).await;
    let p = plan(action, label, &fx);
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F05'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    let result = async {
        seeded?;
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        let go = common::go_oracle::start_named(&db, s3, None, "gofree-mbox2-http").await?;
        let recording = go.is_some();
        let patient = std::time::Duration::from_secs(30);
        let timeouts = setjoin_pg::Timeouts { pool_wait: patient, create: patient, statement: patient };
        let exec = ScopedExecutor::from_dsn_with(db.app.as_deref().unwrap_or(&db.dsn), 4, timeouts)
            .map_err(|e| e.0)?
            .with_audit_keys("22".repeat(32), String::new());
        let adapter = Probe {
            inner: MigrationRoute {
                exec,
                keys: Arc::new(common::recovery_keys()),
                issuer: "mailserver".into(),
                encryption_key: plan::root(),
                public_host: "mail.test".into(),
                runner: None,
            },
            changed_status: mutant,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F05" && r["slice"] == "migration" {
                r["state"] = json!(if recording { "OFF" } else { "ON" });
                r["upstream"] = json!(if recording { "go-mail" } else { "local-rust" });
                r["oracle_commands"] = json!([""]);
            }
        }
        let gateway = Gateway::new(
            Config {
                upstream: go.as_ref().map(|g| format!("http://{}", g.address).parse()).transpose()?,
                trusted_proxies: TrustedProxies::parse("")?,
                upstream_header_timeout: setjoin_gateway::proxy::DEFAULT_HEADER_TIMEOUT,
                edge_limit: None,
            },
            RouteTable::proxy_all().with(adapter),
        )?
        .with_inventory(&inventory.to_string())?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let server = tokio::spawn(gateway.serve(listener));
        let send = |sent: &plan::Plan| {
            let uri = format!("/api{}{}", sent.path, sent.query);
            let token = admin_token(fx.a.user);
            let method = if sent.head { "HEAD" } else { sent.method };
            let body = sent.body.clone();
            async move {
                let request = Request::builder()
                    .method(method)
                    .uri(uri)
                    .header("host", "mail.test")
                    .header("origin", "http://mail.test")
                    .header("content-type", "application/json")
                    .header("x-request-id", "gofree-mbox2-oracle")
                    .header("authorization", format!("Bearer {token}"));
                Ok::<_, BoxError>(common::send(address, request.body(common::full(body))?).await)
            }
        };
        if p.repeat {
            let first = send(&p).await?;
            let status = first.status().as_u16();
            let data = common::body_bytes(first).await;
            if recording && !(200..300).contains(&status) {
                return Err(format!("initial {action}: {status} {data:?}").into());
            }
        }
        let since: String = owner.query_one("SELECT clock_timestamp()::text", &[]).await?.get(0);
        let before = snapshot(&owner, &fx, &since).await?;
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
        let mut config = db.listen("config_changed").await?;
        let response = send(&p).await?;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| mask_state(v.to_str().unwrap())).collect::<Vec<_>>()));
        }
        let bytes = common::body_bytes(response).await;
        let raw = String::from_utf8(bytes.to_vec())?;
        if recording && learn {
            eprintln!("LEARN {action}/{label} {status} {}", raw.chars().take(200).collect::<String>().replace('\n', " "));
            return Ok(());
        }
        let after = snapshot(&owner, &fx, &since).await?;
        let wanted = expected::status(action, label);
        if recording && status != wanted {
            return Err(format!("Go {action}/{label}: expected {wanted}, got {status}: {raw}").into());
        }
        let ids = fx.ids();
        let mut audit: Vec<Value> = owner
            .query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&last])
            .await?
            .iter()
            .map(|r| serde_json::from_str(&r.get::<_, String>(0)))
            .collect::<Result<_, _>>()?;
        for row in &mut audit {
            if row["id"].as_i64().is_none_or(|n| n <= 0) {
                return Err("invalid audit id".into());
            }
            row["id"] = json!("<audit>");
            for key in ["checksum", "prev_checksum"] {
                if row[key].as_str().is_some_and(|s| !s.is_empty()) {
                    row[key] = json!("<checksum>");
                }
            }
            let text = mask_paths(&fx.names(&row.to_string()), &fx);
            *row = serde_json::from_str(&text)?;
            mask(row, &ids);
        }
        let mut notify = vec![];
        for event in config.drain(&owner).await? {
            notify.push(json!({"channel":"config_changed","payload":serde_json::from_str::<Value>(&event)?}));
        }
        let text = mask_json_text(&mask_state(&mask_paths(&fx.names(&raw), &fx)), &ids);
        if let Some(date) = headers.get_mut("date") {
            *date = json!(["<timestamp>"]);
        }
        if let Some(length) = headers.get_mut("content-length") {
            if p.head {
                // A HEAD answer carries the length a GET would, which varies with the ids.
                *length = json!(["<get-length>"]);
            } else {
                if *length != json!([raw.len().to_string()]) {
                    return Err("bad wire length".into());
                }
                *length = json!([text.len().to_string()]);
            }
        }
        let (before, after) = (mask_all(before, &ids, &fx), mask_all(after, &ids, &fx));
        let effects = json!([{"table":"migration_jobs+system_config+m365_consent_states","before":before,"after":after}]);
        let mut request = json!({"method":p.method,"path":p.pattern,"external_path":format!("/api{}",p.pattern)});
        if !p.query.is_empty() {
            request["query"] = json!(fx.names(&p.query).replace(&fx.a.user.to_string(), "<admin>").replace(&fx.b.user.to_string(), "<other>"));
        }
        if p.head {
            request["head"] = json!(true);
        }
        if !p.recorded_body.is_empty() {
            request["body"] = json!(p.recorded_body);
        }
        let observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":notify});
        if !recording {
            let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F05\"} 0") {
                return Err(format!("F05 replay forwarded to Go: {metrics}").into());
            }
        }
        server.abort();
        let name = format!("{action}-{label}");
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/migration/goldens");
        std::fs::create_dir_all(&dir)?;
        let file = dir.join(format!("{name}.json"));
        let row_file = dir.join(format!("{name}-row-effects.json"));
        let route_name = format!("{} {}", p.method, p.pattern);
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            record(&file, &json!({"format":1,"route":route_name,"case":label,"go_source":source,"observation":observation}))?;
            record(&row_file, &json!({"format":1,"route":route_name,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;
        } else {
            let expected: Value = common::golden_doc(&file, "observation", &observation);
            let compared = golden::compare(&expected["observation"], &observation);
            if mutant {
                let error = compared.err().ok_or("planted status mutant survived")?;
                if !error.contains("/response/status") {
                    return Err(format!("mutant failed outside response status: {error}").into());
                }
                eprintln!("MUTANT-REJECTED: {route_name} :: changed-status");
                return Ok(());
            }
            compared?;
            let expected: Value = common::golden_doc(&row_file, "effects", &observation["effects"]);
            golden::compare(&expected["effects"], &observation["effects"])?;
            eprintln!("GOLDEN-REPLAY: {route_name} :: {label}");
        }
        Ok::<_, BoxError>(())
    }
    .await;
    // Cleanup runs on every path and touches only this case's rows.
    owner
        .execute("DELETE FROM rust_operation_receipts WHERE family='F05' AND operation_id::text<>ALL($1)", &[&receipts])
        .await?;
    fx.remove(&owner).await?;
    owner
        .batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;"))
        .await?;
    result
}

/// JSON text whose key order and spacing are the contract: replace `"key":<id>` values.
fn mask_json_text(text: &str, ids: &[(&'static str, i64, String)]) -> String {
    let mut out = text.to_owned();
    for (key, id, name) in ids {
        let id = id.to_string();
        for sep in [":", ": "] {
            out = out.replace(
                &format!("\"{key}\"{sep}{id},"),
                &format!("\"{key}\"{sep}\"{name}\","),
            );
            out = out.replace(
                &format!("\"{key}\"{sep}{id}}}"),
                &format!("\"{key}\"{sep}\"{name}\"}}"),
            );
        }
    }
    // Timestamps inside string values.
    let mut result = String::new();
    let mut i = 0;
    while i < out.len() {
        let rest = &out[i..];
        if rest.starts_with('"')
            && rest.len() > 20
            && rest.is_char_boundary(20)
            && timestamp_like(&rest[1..20])
        {
            if let Some(close) = rest[1..].find('"') {
                result.push_str("\"<timestamp>\"");
                i += close + 2;
                continue;
            }
        }
        let ch = rest.chars().next().unwrap();
        result.push(ch);
        i += ch.len_utf8();
    }
    result
}

fn mask_all(mut v: Value, ids: &[(&'static str, i64, String)], fx: &Fx) -> Value {
    let text = mask_paths(&fx.names(&v.to_string()), fx);
    v = serde_json::from_str(&text).expect("json");
    mask(&mut v, ids);
    v
}

/// Verification mode compares immutable Go observations instead of rewriting them.
fn record(path: &std::path::Path, value: &Value) -> Result<(), BoxError> {
    if std::env::var_os("GOFREE_VERIFY_GO").is_some() {
        let expected: Value = serde_json::from_slice(&std::fs::read(path)?)?;
        golden::compare(&expected, value)?;
        Ok(())
    } else {
        golden::record(path, value).map_err(Into::into)
    }
}
