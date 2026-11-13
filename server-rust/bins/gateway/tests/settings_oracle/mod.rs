//! F19 User mail settings and profile frozen-Go oracle, shared by every slice's test target.
//!
//! Record mode runs the covered Go binary behind the front door; replay serves the same
//! requests from Rust with no Go upstream. Each case builds two accounts (the actor's and
//! another tenant's), takes `SERIAL` for its whole run and removes only what it made. A slice
//! module (`a.rs`, ...) owns `route`, `seed`, `request`, `wanted`, `snapshot` and
//! `plant_foreign` for its actions; this file owns masking, observation, goldens, planted
//! mutants and cleanup. Every F19 route needs only a verified token, so there is no persona.
pub mod a;
pub mod b;
pub mod c;
pub mod p;
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    user_settings::UserSettingsRoute, Body, BoxFuture, Config, Gateway, Intercept, RequestContext,
    RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Probe {
    inner: UserSettingsRoute<setjoin_gateway::jmap::jwks::Jwks>,
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

fn timestamp_at(b: &[u8], i: usize) -> bool {
    let digits = |from: usize, n: usize| {
        b.get(from..from + n)
            .is_some_and(|s| s.iter().all(u8::is_ascii_digit))
    };
    digits(i, 4)
        && b.get(i + 4) == Some(&b'-')
        && digits(i + 5, 2)
        && b.get(i + 7) == Some(&b'-')
        && digits(i + 8, 2)
        && matches!(b.get(i + 10), Some(b'T' | b' '))
        && digits(i + 11, 2)
        && b.get(i + 13) == Some(&b':')
        && digits(i + 14, 2)
        && b.get(i + 16) == Some(&b':')
        && digits(i + 17, 2)
}

/// Masks run-time timestamps in text (seeded `2026-10-0x` times stay readable).
pub fn mask_timestamps(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::new();
    let mut i = 0;
    while i < b.len() {
        if timestamp_at(b, i) && !text[i..].starts_with("2026-10-0") {
            let mut end = i + 19;
            if b.get(end) == Some(&b'.') {
                end += 1;
                while b.get(end).is_some_and(u8::is_ascii_digit) {
                    end += 1;
                }
            }
            if b.get(end) == Some(&b'Z') {
                end += 1;
            } else if matches!(b.get(end), Some(b'+' | b'-')) && b.get(end + 3) == Some(&b':') {
                end += 6;
            }
            out.push_str("<timestamp>");
            i = end;
        } else {
            let ch = text[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// Replaces `"key":value` (a bare integer) by the symbolic label, for run-specific ids.
pub fn mask_ids(text: &str, names: &[(&str, i64, String)]) -> String {
    let mut out = text.to_owned();
    for (key, value, label) in names {
        for sep in [":", ": "] {
            let tag = format!("\"{key}\"{sep}{value}");
            let mut at = 0;
            while let Some(found) = out[at..].find(&tag) {
                let start = at + found;
                let end = start + tag.len();
                if out.as_bytes().get(end).is_some_and(u8::is_ascii_digit) {
                    at = end;
                    continue;
                }
                let replacement = format!("\"{key}\"{sep}\"{label}\"");
                out.replace_range(start..end, &replacement);
                at = start + replacement.len();
            }
        }
    }
    out
}

/// Masks `/{id}/` and trailing `/{id}` path segments of ids named under key `id`.
pub fn mask_path_ids(text: &str, names: &[(&str, i64, String)]) -> String {
    let mut out = text.to_owned();
    for (key, value, label) in names.iter().filter(|n| n.0 == "id") {
        let _ = key;
        out = out.replace(&format!("/+{value}"), &format!("/+{label}"));
        out = out.replace(&format!("/{value}/"), &format!("/{label}/"));
        out = out.replace(&format!("/{value}\""), &format!("/{label}\""));
        if out.ends_with(&format!("/{value}")) && !out.ends_with(&format!("/+{label}")) {
            out.truncate(out.len() - value.to_string().len());
            out.push_str(label);
        }
    }
    out
}

/// Everything a slice needs to name run-specific rows.
pub struct Seed {
    /// `(json key, id, label)`: ids are masked wherever they appear under that key.
    pub names: Vec<(&'static str, i64, String)>,
    pub vars: std::collections::BTreeMap<&'static str, i64>,
    /// Users a slice added to the actor's domain; removed before the accounts.
    pub extra_users: Vec<i64>,
    /// Statements restoring global rows the seed changed (run in cleanup).
    pub undo: Vec<String>,
    /// Literal text replaced in recordings (run-specific ids inside messages).
    pub text_masks: Vec<(String, String)>,
}

pub struct Req {
    pub path: String,
    pub query: String,
    pub body: String,
    /// The body as recorded (long bodies are summarised).
    pub recorded_body: String,
}

pub async fn rows(c: &tokio_postgres::Client, sql: &str) -> Result<Vec<Value>, BoxError> {
    c.query(sql, &[])
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
        .collect()
}

pub async fn run(
    slice: &str,
    action: &str,
    kind: &str,
    fault: Option<&str>,
) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run_inner(slice, action, kind, fault).await
}

async fn run_inner(
    slice: &str,
    action: &str,
    kind: &str,
    fault: Option<&str>,
) -> Result<(), BoxError> {
    let mutant = kind.ends_with("-status-mutant");
    let label = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let Some(db) = Db::for_case("settings1-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "settings1-actor").await?;
    let b = fixture::account(&owner, "settings1-other").await?;
    let domain_of = |id: i64| {
        let owner = &owner;
        async move {
            Ok::<String, BoxError>(
                owner
                    .query_one("SELECT name FROM domains WHERE id=$1", &[&id])
                    .await?
                    .get(0),
            )
        }
    };
    let domain_names = [
        (domain_of(a.domain).await?, "host-a.test"),
        (domain_of(b.domain).await?, "host-b.test"),
    ];
    let names = |text: &str| {
        let mut out = text.to_owned();
        for (domain, name) in &domain_names {
            out = out.replace(domain.as_str(), name);
        }
        out
    };
    let (method, pattern) = a_route(slice, action);
    let seed = match slice {
        "settings-a" => a::seed(&owner, &a, &b, action, label).await?,
        "settings-b" => b::seed(&owner, &a, &b, action, label).await?,
        "settings-c" => c::seed(&owner, &a, &b, action, label).await?,
        "profile" => p::seed(&owner, &a, &b, action, label).await?,
        _ => panic!("unknown slice {slice}"),
    };
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F19'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    // Faults run real mutated database objects against the unchanged expectation.
    let schema = format!("gofree_settings1_fault_{}", a.user);
    let mut undo: Vec<String> = vec![];
    match fault {
        Some("double-bump") => {
            // A second write behind the handler's single one.
            owner.batch_execute(&format!("CREATE SCHEMA {schema};CREATE FUNCTION {schema}.fault() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF pg_trigger_depth() = 1 THEN UPDATE users SET view_prefs = COALESCE(view_prefs,'{{}}'::jsonb) || '{{\"bump\":1}}'::jsonb WHERE id=NEW.id; END IF; RETURN NEW; END $fault$;CREATE TRIGGER {schema} AFTER UPDATE OF view_prefs ON users FOR EACH ROW EXECUTE FUNCTION {schema}.fault();")).await?;
            undo.push(format!("DROP TRIGGER {schema} ON users"));
        }
        Some("no-audit") => {
            // The audit insert is silently swallowed behind the reducer's own statement.
            owner.batch_execute(&format!("CREATE SCHEMA {schema};CREATE FUNCTION {schema}.fault() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN RETURN NULL; END $fault$;CREATE TRIGGER {schema} BEFORE INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION {schema}.fault();")).await?;
            undo.push(format!("DROP TRIGGER {schema} ON admin_audit_log"));
        }
        Some("no-notify") => {
            // The reducers are SECURITY DEFINER with a pinned search_path, so the publisher
            // itself is swapped for a no-op and put back afterwards.
            owner.batch_execute("ALTER FUNCTION public.app_notify(text,text) RENAME TO app_notify_settings3_orig; CREATE FUNCTION public.app_notify(text,text) RETURNS void LANGUAGE sql AS 'SELECT NULL::void'").await?;
            undo.push("DROP FUNCTION public.app_notify(text,text); ALTER FUNCTION public.app_notify_settings3_orig(text,text) RENAME TO app_notify".into());
        }
        Some("no-tenant-filter") => {
            assert_eq!(
                slice, "settings-a",
                "the family mutants are defined by settings-a"
            );
            a::plant_foreign(&owner, &b, &seed).await?;
        }
        _ => {}
    }
    let result = async {
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        let go = common::go_oracle::start_named(&db, s3, None, "gofree-settings1-http").await?;
        let recording = go.is_some();
        // The adapter and Go must both be given time on a loaded shared host.
        let patient = std::time::Duration::from_secs(30);
        let timeouts = || setjoin_pg::Timeouts { pool_wait: patient, create: patient, statement: patient };
        let exec = ScopedExecutor::from_dsn_with(db.app.as_deref().unwrap_or(&db.dsn), 4, timeouts())
            .map_err(|e| e.0)?
            .with_audit_keys("22".repeat(32), String::new());
        let adapter = Probe {
            inner: UserSettingsRoute::new(exec, Arc::new(common::recovery_keys()), "mailserver".into()),
            changed_status: mutant,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F19" && r["slice"] == slice {
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
        let req = match slice {
            "settings-a" => a::request(action, label, &seed),
            "settings-c" => c::request(action, label, &seed),
            "profile" => p::request(action, label, &seed),
            _ => b::request(action, label, &seed),
        };
        let token = match slice {
            "settings-b" => b::token(action, label, a.user),
            "settings-c" => c::token(action, label, a.user),
            _ => common::recovery_token(a.user),
        };
        let send = |body: String| {
            let uri = format!("/api{}{}", req.path, req.query);
            let token = token.clone();
            async move {
                let request = Request::builder().method(method).uri(uri).header("host", "mail.test").header("origin", "http://mail.test").header("content-type", "application/json").header("x-request-id", "gofree-settings1-oracle").header("authorization", format!("Bearer {token}"));
                Ok::<_, BoxError>(common::send(address, request.body(common::full(body))?).await)
            }
        };
        if label == "repeat" {
            let first = send(req.body.clone()).await?;
            let status = first.status().as_u16();
            let data = common::body_bytes(first).await;
            // Go cannot complete sync-put under the app role (BZ100), so its repeat starts from that 409.
            let initial_ok = (200..300).contains(&status) || (slice == "settings-b" && action == "sync-put" && status == 409);
            if recording && !initial_ok {
                return Err(format!("initial {action}: {status} {data:?}").into());
            }
        }
        let snapshot = |slice: &str| {
            let (owner, a, b, seed) = (&owner, &a, &b, &seed);
            let slice = slice.to_owned();
            async move {
                match slice.as_str() {
                    "settings-a" => a::snapshot(owner, a, b, seed).await,
                    "settings-c" => c::snapshot(owner, a, b, seed).await,
                    "profile" => p::snapshot(owner, a, b, seed).await,
                    _ => b::snapshot(owner, a, b, seed).await,
                }
            }
        };
        if slice == "profile" {
            p::reapply(&owner, &a, &b, action, label, &seed).await?;
        }
        let before = snapshot(slice).await?;
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
        let mut alerts = db.listen("admin:alert").await?;
        let mut revoked = db.listen("session_revoke").await?;
        let chans = [format!("tag:{}", a.mailbox), format!("tag:{}", b.mailbox)];
        let mut tags_a = db.listen(&chans[0]).await?;
        let mut tags_b = db.listen(&chans[1]).await?;
        let response = send(req.body.clone()).await?;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        let after = snapshot(slice).await?;
        let users: Vec<(&'static str, i64, String)> = vec![
            ("user_id", a.user, "<actor>".into()),
            ("user_id", b.user, "<other>".into()),
            ("target_id", a.user, "<actor>".into()),
            ("target_id", b.user, "<other>".into()),
            ("actor", a.user, "<actor>".into()),
        ];
        let all_names: Vec<(&str, i64, String)> = seed.names.iter().cloned().chain(users.iter().cloned()).collect();
        let tidy = |text: &str| {
            let mut text = names(text);
            for (from, to) in &seed.text_masks {
                text = text.replace(from.as_str(), to);
            }
            mask_timestamps(&mask_ids(&mask_path_ids(&text, &all_names), &all_names))
        };
        let mut audit: Vec<Value> = owner.query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&last]).await?.iter().map(|r| serde_json::from_str(&r.get::<_, String>(0))).collect::<Result<_, _>>()?;
        for row in &mut audit {
            if row["id"].as_i64().is_none_or(|n| n <= 0) { return Err("invalid audit id".into()); }
            row["id"] = json!("<audit>");
            for key in ["checksum", "prev_checksum"] {
                if row[key].as_str().is_some_and(|s| !s.is_empty()) { row[key] = json!("<checksum>"); }
            }
            *row = serde_json::from_str(&tidy(&row.to_string()))?;
        }
        let mut notify = vec![];
        for event in alerts.drain(&owner).await? {
            let payload: Value = serde_json::from_str(&event)?;
            notify.push(json!({"channel":"admin:alert","payload":serde_json::from_str::<Value>(&tidy(&payload.to_string()))?}));
        }
        for event in revoked.drain(&owner).await? {
            let payload: Value = serde_json::from_str(&event)?;
            notify.push(json!({"channel":"session_revoke","payload":serde_json::from_str::<Value>(&tidy(&payload.to_string()))?}));
        }
        for (events, channel) in [(tags_a.drain(&owner).await?, "tag:<mailbox-actor>"), (tags_b.drain(&owner).await?, "tag:<mailbox-other>")] {
            for event in events {
                let payload: Value = serde_json::from_str(&event)?;
                notify.push(json!({"channel":channel,"payload":serde_json::from_str::<Value>(&tidy(&payload.to_string()))?}));
            }
        }
        let wanted = match slice {
            "settings-a" => a::wanted(action, label),
            "settings-c" => c::wanted(action, label),
            "profile" => p::wanted(action, label),
            _ => b::wanted(action, label),
        };
        if let Some(wanted) = wanted {
            if recording && status != wanted {
                return Err(format!("Go {action}/{label}: expected {wanted}, got {status}: {raw}").into());
            }
        }
        if let Some(date) = headers.get_mut("date") { *date = json!(["<timestamp>"]); }
        let text = tidy(&raw);
        if let Some(length) = headers.get_mut("content-length") {
            *length = json!([text.len().to_string()]);
        }
        let (before, after) = (serde_json::from_str::<Value>(&tidy(&before.to_string()))?, serde_json::from_str::<Value>(&tidy(&after.to_string()))?);
        let effects = json!([{"table":"user_settings","before":before,"after":after}]);
        let mut request = json!({"method":method,"path":pattern,"external_path":tidy(&format!("/api{}",req.path))});
        if !req.recorded_body.is_empty() { request["body"] = json!(names(&req.recorded_body)); }
        if !req.query.is_empty() { request["query"] = json!(req.query); }
        let observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":notify});
        if !recording {
            let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F19\"} 0") {
                return Err(format!("F19 replay forwarded to Go: {metrics}").into());
            }
        }
        server.abort();
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/user-settings/goldens");
        std::fs::create_dir_all(&dir)?;
        let stem = format!("{slice}-{action}-{label}");
        let file = dir.join(format!("{stem}.json"));
        let row_file = dir.join(format!("{stem}-row-effects.json"));
        let route_name = format!("{method} {pattern}");
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            record(&file, &json!({"format":1,"route":route_name,"case":label,"go_source":source,"observation":observation}))?;
            record(&row_file, &json!({"format":1,"route":route_name,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;
        } else {
            let expected: Value = serde_json::from_slice(&std::fs::read(&file)?)?;
            let compared = golden::compare(&expected["observation"], &observation);
            if mutant {
                let error = compared.err().ok_or("planted status mutant survived")?;
                if !error.contains("/response/status") { return Err(format!("mutant failed outside response status: {error}").into()); }
                eprintln!("MUTANT-REJECTED: {route_name} :: changed-status");
                return Ok(());
            }
            if let Some(fault) = fault {
                eprintln!("FAULT-OBSERVED {fault}: {status} {}", observation["response"]["body"]);
                compared.err().ok_or("planted family fault survived")?;
                eprintln!("MUTANT-REJECTED: {route_name} :: {fault}");
                return Ok(());
            }
            compared?;
            let expected: Value = serde_json::from_slice(&std::fs::read(row_file)?)?;
            golden::compare(&expected["effects"], &observation["effects"])?;
            eprintln!("GOLDEN-REPLAY: {route_name} :: {label}");
        }
        Ok::<_, BoxError>(())
    }
    .await;
    // Cleanup runs on every path and touches only this case's rows.
    for statement in &undo {
        owner.batch_execute(statement).await?;
    }
    if matches!(fault, Some("double-bump" | "no-audit")) {
        owner
            .batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
            .await?;
    }
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F19' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    for statement in &seed.undo {
        owner.batch_execute(statement).await?;
    }
    {
        owner
            .execute(
                "DELETE FROM approval_delegations WHERE delegate_user_id = ANY($1)",
                &[&seed.extra_users],
            )
            .await?;
        owner
            .execute("DELETE FROM users WHERE id = ANY($1)", &[&seed.extra_users])
            .await?;
    }
    for account in [&a, &b] {
        common::remove_blob_account(&owner, account).await?;
    }
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;")).await?;
    result
}

/// `(method, inventory pattern)` of an action in a slice.
fn a_route(slice: &str, action: &str) -> (&'static str, &'static str) {
    match slice {
        "settings-a" => a::route(action),
        "settings-b" => b::route(action),
        "settings-c" => c::route(action),
        "profile" => p::route(action),
        _ => panic!("unknown slice {slice}"),
    }
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
