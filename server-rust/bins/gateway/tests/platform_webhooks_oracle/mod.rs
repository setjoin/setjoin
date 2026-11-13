//! F08 slice `webhooks` frozen-Go oracle (#302): `/admin/webhooks*`.
//!
//! Record mode runs the covered Go binary behind the front door; replay serves the same
//! requests from Rust with no Go upstream. Each case builds its own admin persona (governed
//! role group + assignment) and its own subscriptions (urls `https://plat4-*`, explicit
//! creation times so list order and `time.Time` rendering are pinned), takes `SERIAL`,
//! and removes what it made. Signing secrets are checked independently: the harness opens
//! every stored envelope with the shared codec and classifies it (`<returned>`, a seed
//! label, `<other>`), so Go-sealed rows are opened by Rust and Rust-sealed rows by the
//! same open routine Go's output already passed through in record mode.
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_config_secret::{open_column, seal_column, CryptoProfile};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    platform_webhooks::PlatformWebhooksRoute, Body, BoxFuture, Config, Gateway, Intercept,
    RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use setjoin_platform::webhook_secret::SecretCodec;
use std::sync::Arc;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
/// The master secret the recorded Go process runs with (`JWT_SECRET`).
const MASTER: &[u8] = b"blobs1-test-jwt-secret-for-recording";
const OLD: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const PREV: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct Probe {
    inner: PlatformWebhooksRoute<setjoin_gateway::jmap::jwks::Jwks>,
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

fn timestamp_like(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() >= 19 && b[4] == b'-' && b[7] == b'-' && (b[10] == b'T' || b[10] == b' ') && b[13] == b':'
}

/// Run-time timestamps differ per run; the fixed seed times (`2026-10-01...`) are kept.
fn mask_times(value: &mut Value) {
    match value {
        Value::Object(map) => map.values_mut().for_each(mask_times),
        Value::Array(items) => items.iter_mut().for_each(mask_times),
        Value::String(text) if timestamp_like(text) && !text.starts_with("2026-10-01") => {
            *text = "<timestamp>".into();
        }
        _ => {}
    }
}

/// `(method, inventory pattern)` for an action.
fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "list" => ("GET", "/admin/webhooks"),
        "create" => ("POST", "/admin/webhooks"),
        "delete" => ("DELETE", "/admin/webhooks/{id}"),
        "rotate" => ("POST", "/admin/webhooks/{id}/rotate-secret"),
        "deliveries" => ("GET", "/admin/webhooks/{id}/deliveries"),
        "events" => ("GET", "/admin/webhooks/events"),
        _ => panic!("unknown webhooks action {action}"),
    }
}

/// The permissions that satisfy an action's gate.
fn granted(action: &str) -> Vec<&'static str> {
    match action {
        "create" | "delete" | "rotate" => vec!["system.config"],
        _ => vec!["backup.read"],
    }
}

fn hex_ok(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

struct Seed {
    label: &'static str,
    id: i64,
}

#[allow(clippy::too_many_arguments, clippy::type_complexity)]
async fn subscription(
    owner: &tokio_postgres::Client,
    label: &'static str,
    user: Option<i64>,
    minute: u32,
    scope: &str,
    active: bool,
    types: &str,
    cells: (Option<&str>, Option<(&str, Option<&str>)>, Option<&str>),
) -> Result<Seed, BoxError> {
    // cells: (legacy plaintext, (sealed secret, key id), legacy prev plaintext)
    let (legacy, sealed, prev_legacy) = cells;
    let (enc, key): (Option<Vec<u8>>, Option<String>) = match sealed {
        Some((secret, key)) => (
            Some(seal_column(secret.as_bytes(), MASTER, CryptoProfile::Standard)?),
            key.map(str::to_owned),
        ),
        None => (None, None),
    };
    let created = if minute == 59 {
        "2026-10-01T10:59:00.123456Z".to_string()
    } else {
        format!("2026-10-01T10:{minute:02}:00Z")
    };
    let id: i64 = owner
        .query_one(
            "INSERT INTO webhook_subscriptions(user_id,url,secret,prev_secret,secret_enc,secret_key_id,event_types,scope,is_active,created_at,updated_at) \
             VALUES($1,$2,$3,$4,$5,$6,$7::text::jsonb,$8,$9,$10::text::timestamptz,$10::text::timestamptz) RETURNING id",
            &[&user, &format!("https://plat4-{label}.example/hook?x=<&>"), &legacy, &prev_legacy, &enc, &key, &types, &scope, &active, &created],
        )
        .await?
        .get(0);
    Ok(Seed { label, id })
}

/// Text with run-specific numbers replaced by labels (`"id":12,` becomes `"id":"<sub-a>",`).
fn label_ids(text: &str, field: &str, ids: &[(i64, String)]) -> String {
    let mut out = text.to_owned();
    for (id, label) in ids {
        for end in [",", "}", "]"] {
            out = out.replace(
                &format!("\"{field}\":{id}{end}"),
                &format!("\"{field}\":\"{label}\"{end}"),
            );
        }
    }
    out
}

fn classify(opened: Option<String>, returned: &Option<String>) -> Value {
    match opened {
        None => json!("<unopenable>"),
        Some(text) if returned.as_deref() == Some(text.as_str()) => json!("<returned>"),
        Some(text) if text == OLD => json!("<seed:old>"),
        Some(text) if text == PREV => json!("<seed:prev>"),
        Some(_) => json!("<other>"),
    }
}

async fn snapshot(
    owner: &tokio_postgres::Client,
    users: &[(i64, &str)],
    returned: &Option<String>,
) -> Result<Value, BoxError> {
    let rows = owner
        .query(
            "SELECT id,user_id,url,secret,prev_secret,secret_enc,secret_key_id,prev_secret_enc,prev_secret_key_id,event_types::text,scope,is_active,\
             (SELECT count(*) FROM webhook_deliveries d WHERE d.subscription_id=s.id) FROM webhook_subscriptions s WHERE url LIKE 'https://plat4-%' ORDER BY url,id",
            &[],
        )
        .await?;
    let mut out = Vec::new();
    for row in &rows {
        let (secret, prev): (Option<String>, Option<String>) = (row.get(3), row.get(4));
        let envelopes: [(Option<Vec<u8>>, Option<String>); 2] =
            [(row.get(5), row.get(6)), (row.get(7), row.get(8))];
        let open = |cell: &(Option<Vec<u8>>, Option<String>)| -> Value {
            match cell {
                (None, key) => json!({"cell":"null","key":key}),
                (Some(bytes), key) => {
                    let opened = open_column(bytes, MASTER).ok().map(|b| String::from_utf8_lossy(&b).into_owned());
                    json!({"cell":"sealed","key":key,"opens_to":classify(opened,returned)})
                }
            }
        };
        let user: Option<i64> = row.get(1);
        out.push(json!({
            "url": row.get::<_, String>(2),
            "user": user.map(|u| users.iter().find(|(i, _)| *i == u).map_or("<unknown>".to_string(), |(_, n)| n.to_string())),
            "legacy_secret": secret.map(|s| classify(Some(s), returned)),
            "legacy_prev_secret": prev.map(|s| classify(Some(s), returned)),
            "secret_enc": open(&envelopes[0]),
            "prev_secret_enc": open(&envelopes[1]),
            "event_types": row.get::<_, String>(9),
            "scope": row.get::<_, String>(10),
            "is_active": row.get::<_, bool>(11),
            "deliveries": row.get::<_, i64>(12),
        }));
    }
    Ok(json!(out))
}

pub async fn run(action: &str, kind: &str) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run_inner(action, kind).await
}

async fn run_inner(action: &str, kind: &str) -> Result<(), BoxError> {
    let mutant = kind.ends_with("-status-mutant");
    let label = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let Some(db) = Db::for_case("plat4-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "plat4-admin").await?;
    let b = fixture::account(&owner, "plat4-other").await?;
    let domain_of = |id: i64| {
        let owner = &owner;
        async move {
            Ok::<String, BoxError>(owner.query_one("SELECT name FROM domains WHERE id=$1", &[&id]).await?.get(0))
        }
    };
    let domain_names = [(domain_of(a.domain).await?, "host-a.test"), (domain_of(b.domain).await?, "host-b.test")];
    let names = |text: &str| {
        let mut out = text.to_owned();
        for (domain, name) in &domain_names {
            out = out.replace(domain.as_str(), name);
        }
        out
    };
    let (permissions, scope): (Vec<&str>, Option<i64>) = match label {
        "denied" => (vec!["users.read"], None),
        "scoped" => (granted(action), Some(b.domain)),
        _ => (granted(action), None),
    };
    let role = format!("plat4-role-{}", a.user);
    owner
        .execute("INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,$3)", &[&role, &permissions, &scope])
        .await?;
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,eligible) SELECT $1,id,$1,false FROM admin_role_groups WHERE name=$2",
            &[&a.user, &role],
        )
        .await?;
    // The list route returns every subscription: start from a known-empty table.
    owner.execute("DELETE FROM webhook_subscriptions", &[]).await?;
    let all = r#"["user.created","user.updated"]"#;
    let mut seeds: Vec<Seed> = Vec::new();
    let mut deliveries: Vec<(i64, String)> = Vec::new();
    let me = Some(a.user);
    let other = Some(b.user);
    match (action, label) {
        ("list", "success" | "ignored-query" | "scoped") => {
            seeds.push(subscription(&owner, "a", me, 1, "self", true, all, (None, Some((OLD, Some("v1"))), None)).await?);
            seeds.push(subscription(&owner, "b", None, 2, "organization", false, r#"["mail.received"]"#, (Some(OLD), None, None)).await?);
            seeds.push(subscription(&owner, "c", other, 59, "self", true, r#"[]"#, (None, None, None)).await?);
            seeds.push(subscription(&owner, "d", me, 30, "organization", true, r#"["user.deleted","auth.login"]"#, (None, Some((OLD, Some("v1"))), None)).await?);
        }
        ("list", "odd-types") => {
            seeds.push(subscription(&owner, "a", me, 1, "self", true, r#"[1,"user.created",null,{"x":1}]"#, (None, None, None)).await?);
            seeds.push(subscription(&owner, "b", me, 2, "self", true, r#"{"not":"a list"}"#, (None, None, None)).await?);
            seeds.push(subscription(&owner, "c", me, 3, "self", true, r#"null"#, (None, None, None)).await?);
            seeds.push(subscription(&owner, "d", me, 4, "self", true, r#""text""#, (None, None, None)).await?);
        }
        ("deliveries", l) if l != "empty" && l != "denied" => {
            seeds.push(subscription(&owner, "a", if l == "other-owner" { other } else { me }, 1, "self", true, all, (None, Some((OLD, Some("v1"))), None)).await?);
            seeds.push(subscription(&owner, "b", me, 2, "self", true, all, (None, Some((OLD, Some("v1"))), None)).await?);
            let sub = seeds[0].id;
            for (n, (event, code, latency, attempt, status, error, minute)) in [
                ("evt_one", Some(200i32), Some(12i32), 1i32, "success", Some(""), 10u32),
                ("evt_two", Some(503), Some(1500), 2, "failed", Some("upstream <busy> & slow"), 11),
                ("evt_three", None, None, 0, "pending", None, 12),
                ("evt_four", Some(0), Some(0), 3, "exhausted", Some("circuit breaker open"), 13),
            ]
            .into_iter()
            .enumerate()
            {
                let id: i64 = owner
                    .query_one(
                        "INSERT INTO webhook_deliveries(subscription_id,event_id,event_type,request_body,response_code,latency_ms,attempt,status,error_message,created_at) \
                         VALUES($1,$2,'user.created','{}'::jsonb,$3,$4,$5,$6,$7,$8::text::timestamptz) RETURNING id",
                        &[&sub, &event, &code, &latency, &attempt, &status, &error, &format!("2026-10-01T10:{minute:02}:00Z")],
                    )
                    .await?
                    .get(0);
                deliveries.push((id, format!("<delivery-{}>", n + 1)));
            }
            // A delivery of another subscription never shows.
            owner
                .execute(
                    "INSERT INTO webhook_deliveries(subscription_id,event_id,event_type,request_body,attempt,status) VALUES($1,'evt_alien','user.created','{}'::jsonb,1,'success')",
                    &[&seeds[1].id],
                )
                .await?;
        }
        ("deliveries", "empty") => {
            seeds.push(subscription(&owner, "a", me, 1, "self", true, all, (None, None, None)).await?);
        }
        ("delete", "success" | "repeat") => {
            seeds.push(subscription(&owner, "a", me, 1, "self", true, all, (None, Some((OLD, Some("v1"))), None)).await?);
            seeds.push(subscription(&owner, "b", me, 2, "organization", true, all, (None, Some((OLD, Some("v1"))), None)).await?);
            owner
                .execute("INSERT INTO webhook_deliveries(subscription_id,event_id,event_type,request_body,attempt,status) VALUES($1,'evt_cascade','user.created','{}'::jsonb,1,'success')", &[&seeds[0].id])
                .await?;
        }
        ("delete", "other-owner") => {
            seeds.push(subscription(&owner, "a", other, 1, "organization", true, all, (None, Some((OLD, Some("v1"))), None)).await?);
            seeds.push(subscription(&owner, "b", me, 2, "self", true, all, (None, Some((OLD, Some("v1"))), None)).await?);
        }
        ("delete", _) => {
            seeds.push(subscription(&owner, "a", me, 1, "self", true, all, (None, Some((OLD, Some("v1"))), None)).await?);
        }
        ("rotate", "success" | "repeat" | "scoped" | "denied") => {
            seeds.push(subscription(&owner, "a", me, 1, "self", true, all, (None, Some((OLD, Some("v1"))), None)).await?);
            seeds.push(subscription(&owner, "b", me, 2, "self", true, all, (None, Some((PREV, Some("v1"))), None)).await?);
        }
        ("rotate", "legacy") => {
            seeds.push(subscription(&owner, "a", me, 1, "self", true, all, (Some(OLD), None, Some(PREV))).await?);
        }
        ("rotate", "malformed") => {
            seeds.push(subscription(&owner, "a", me, 1, "self", true, all, (None, None, None)).await?);
        }
        ("rotate", "unknown-key") => {
            seeds.push(subscription(&owner, "a", me, 1, "self", true, all, (None, Some((OLD, Some("v2"))), None)).await?);
        }
        ("rotate", "no-key-id") => {
            seeds.push(subscription(&owner, "a", me, 1, "self", true, all, (None, Some((OLD, None)), None)).await?);
        }
        ("rotate", "other-owner") => {
            seeds.push(subscription(&owner, "a", other, 1, "organization", true, all, (None, Some((OLD, Some("v1"))), None)).await?);
        }
        ("rotate", "missing" | "bad-id") => {
            seeds.push(subscription(&owner, "a", me, 1, "self", true, all, (None, Some((OLD, Some("v1"))), None)).await?);
        }
        _ => {}
    }
    let audit_start: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
    let receipts = owner
        .query("SELECT operation_id::text FROM rust_operation_receipts WHERE family='F08'", &[])
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    let users: Vec<(i64, &str)> = vec![(a.user, "<admin>"), (b.user, "<other>")];
    let seed_ids: Vec<(i64, String)> = seeds.iter().map(|s| (s.id, format!("<sub-{}>", s.label))).collect();
    let result = async {
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        let go = common::go_oracle::start_named(&db, s3, None, "gofree-plat4-http").await?;
        let recording = go.is_some();
        let patient = std::time::Duration::from_secs(30);
        let exec = ScopedExecutor::from_dsn_with(
            db.app.as_deref().unwrap_or(&db.dsn),
            4,
            setjoin_pg::Timeouts { pool_wait: patient, create: patient, statement: patient },
        )
        .map_err(|e| e.0)?
        .with_audit_keys("22".repeat(32), String::new());
        let adapter = Probe {
            inner: PlatformWebhooksRoute {
                exec,
                keys: Arc::new(common::recovery_keys()),
                issuer: "mailserver".into(),
                codec: SecretCodec::new(MASTER, CryptoProfile::Standard),
            },
            changed_status: mutant,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F08" && r["slice"] == "webhooks" {
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
        let (method, pattern) = route(action);
        let query = if label == "ignored-query" { "?limit=-1&q=%00&x=%zz" } else { "" };
        let types25: Vec<&str> = setjoin_platform::webhooks::CATALOG.iter().map(|c| c.0).collect();
        let good = r#"{"url":"https://plat4-new.example/hook","eventTypes":["user.created","mail.sent"],"scope":"organization"}"#;
        let same = |text: &str| (text.to_string(), text.to_string());
        let (body, recorded_body) = match (action, label) {
            ("create", "default") => same(r#"{"url":"https://plat4-new.example/hook","eventTypes":["user.created"]}"#),
            ("create", "bad-json") => same(r#"{"url":"#),
            ("create", "empty-body") => same(""),
            ("create", "missing-url") => same(r#"{"eventTypes":["user.created"]}"#),
            ("create", "empty-url") => same(r#"{"url":"","eventTypes":["user.created"]}"#),
            ("create", "missing-types") => same(r#"{"url":"https://plat4-new.example/hook"}"#),
            ("create", "null-types") => same(r#"{"url":"https://plat4-new.example/hook","eventTypes":null}"#),
            ("create", "empty-types") => same(r#"{"url":"https://plat4-new.example/hook","eventTypes":[]}"#),
            ("create", "bad-scope") => same(r#"{"url":"https://plat4-new.example/hook","eventTypes":["user.created"],"scope":"everyone"}"#),
            ("create", "unknown-event") => same(r#"{"url":"https://plat4-new.example/hook","eventTypes":["user.created","nope.event"]}"#),
            ("create", "duplicate-event") => same(r#"{"url":"https://plat4-new.example/hook","eventTypes":["user.created","mail.sent","user.created"]}"#),
            ("create", "too-many") => {
                let mut list = types25.clone();
                list.push("user.created");
                same(&json!({"url":"https://plat4-new.example/hook","eventTypes":list}).to_string())
            }
            ("create", "all-types") => same(&json!({"url":"https://plat4-new.example/hook","eventTypes":types25,"scope":"self"}).to_string()),
            ("create", "folded") => same(r#"{"URL":"https://plat4-new.example/hook","EVENTTYPES":["user.created"],"Scope":"organization","extra":[1,2]}"#),
            ("create", "trailing-data") => same(r#"{"url":"https://plat4-new.example/hook","eventTypes":["user.created"]} trailing"#),
            ("create", "wrong-type") => same(r#"{"url":5,"eventTypes":["user.created"]}"#),
            ("create", "null-element") => same(r#"{"url":"https://plat4-new.example/hook","eventTypes":[null]}"#),
            ("create", "markup-url") => same(r#"{"url":"https://plat4-new.example/h?a=<b>&c= ","eventTypes":["user.created"]}"#),
            ("create", _) => same(good),
            _ => (String::new(), String::new()),
        };
        let first = |n: usize| seeds.get(n).map(|s| s.id);
        let concrete_id: String = match (action, label) {
            (_, "bad-id") => "abc".into(),
            (_, "missing") => "999999999".into(),
            ("deliveries", "empty") => first(0).unwrap().to_string(),
            ("list" | "create" | "events", _) => String::new(),
            _ => first(0).map_or("0".into(), |n| n.to_string()),
        };
        let recorded_id: String = match concrete_id.as_str() {
            id if first(0).is_some_and(|n| n.to_string() == id) => "<sub-a>".into(),
            id => id.to_owned(),
        };
        let build = |id: &str| pattern.replace("{id}", id);
        let (concrete, external) = (build(&concrete_id), build(&recorded_id));
        let send = |body: String| {
            let uri = format!("/api{concrete}{query}");
            let token = crate::platform_oracle::admin_token(a.user);
            async move {
                let request = Request::builder().method(method).uri(uri).header("host", "mail.test").header("origin", "http://mail.test").header("content-type", "application/json").header("x-request-id", "gofree-plat4-oracle").header("authorization", format!("Bearer {token}"));
                Ok::<_, BoxError>(common::send(address, request.body(common::full(body))?).await)
            }
        };
        let mut returned: Option<String> = None;
        if label == "repeat" {
            let first_call = send(body.clone()).await?;
            let status = first_call.status().as_u16();
            let data = String::from_utf8(common::body_bytes(first_call).await.to_vec())?;
            if recording && !(200..300).contains(&status) {
                return Err(format!("initial {action}: {status} {data:?}").into());
            }
            if let Ok(doc) = serde_json::from_str::<Value>(&data) {
                returned = doc["secret"].as_str().map(str::to_owned);
            }
        }
        let before = snapshot(&owner, &users, &returned).await?;
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
        let response = send(body.clone()).await?;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        if let Ok(doc) = serde_json::from_str::<Value>(&raw) {
            if let Some(secret) = doc["secret"].as_str() {
                if !hex_ok(secret) {
                    return Err(format!("secret shape: {secret}").into());
                }
                returned = Some(secret.to_owned());
            }
        }
        // The new row's id, when the route created one.
        let mut ids = seed_ids.clone();
        let mut text = names(&raw);
        if action == "create" && status == 201 {
            let doc: Value = serde_json::from_str(&text)?;
            let new = doc["id"].as_i64().filter(|n| *n > 0).ok_or("created id")?;
            ids.push((new, "<new>".into()));
        }
        text = label_ids(&text, "id", &ids);
        text = label_ids(&text, "id", &deliveries);
        text = label_ids(&text, "userId", &[(a.user, "<admin>".into()), (b.user, "<other>".into())]);
        if let Some(secret) = &returned {
            text = text.replace(secret.as_str(), "<secret>");
        }
        let after = snapshot(&owner, &users, &returned).await?;
        let mut audit: Vec<Value> = owner.query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&last]).await?.iter().map(|r| serde_json::from_str(&r.get::<_, String>(0))).collect::<Result<_, _>>()?;
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
            for key in ["actor_id", "user_id"] {
                if let Some(n) = row[key].as_i64() {
                    if let Some((_, name)) = users.iter().find(|(i, _)| *i == n) {
                        row[key] = json!(name);
                    }
                }
            }
            let mut text = names(&row.to_string());
            for (id, label) in &ids {
                text = text.replace(&format!("/webhooks/{id}"), &format!("/webhooks/{label}"));
            }
            *row = serde_json::from_str(&text)?;
            mask_times(row);
        }
        let wanted = match (action, label) {
            (_, "denied") => 403,
            ("create", "success" | "default" | "repeat" | "folded" | "trailing-data" | "all-types" | "markup-url" | "scoped") => 201,
            ("create", _) => 400,
            ("delete", "success" | "scoped") => 204,
            ("delete", _) => 404,
            ("rotate", "success" | "repeat" | "legacy" | "malformed" | "scoped") => 200,
            ("rotate", "unknown-key" | "no-key-id") => 500,
            ("rotate", _) => 404,
            _ => 200,
        };
        if recording && status != wanted {
            return Err(format!("Go {action}/{label}: expected {wanted}, got {status}: {raw}").into());
        }
        if let Some(date) = headers.get_mut("date") {
            *date = json!(["<timestamp>"]);
        }
        if let Some(length) = headers.get_mut("content-length") {
            *length = json!([text.len().to_string()]);
        }
        let effects = json!([{"table":"webhook_subscriptions","before":before,"after":after}]);
        let mut request = json!({"method":method,"path":pattern,"external_path":format!("/api{external}")});
        if !recorded_body.is_empty() {
            request["body"] = json!(names(&recorded_body));
        }
        if !query.is_empty() {
            request["query"] = json!(query);
        }
        let observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":[]});
        if !recording {
            let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F08\"} 0") {
                return Err(format!("F08 replay forwarded to Go: {metrics}").into());
            }
        }
        server.abort();
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/platform/goldens");
        std::fs::create_dir_all(&dir)?;
        let stem = format!("webhooks-{action}-{label}");
        let file = dir.join(format!("{stem}.json"));
        let row_file = dir.join(format!("{stem}-row-effects.json"));
        let route_name = format!("{method} {pattern}");
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            record(&file, &json!({"format":1,"route":route_name,"case":label,"go_source":source,"observation":observation}))?;
            if matches!(action, "create" | "delete" | "rotate") {
                record(&row_file, &json!({"format":1,"route":route_name,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;
            }
        } else {
            let expected: Value = serde_json::from_slice(&std::fs::read(&file)?)?;
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
            if matches!(action, "create" | "delete" | "rotate") {
                let expected: Value = serde_json::from_slice(&std::fs::read(row_file)?)?;
                golden::compare(&expected["effects"], &observation["effects"])?;
            }
            eprintln!("GOLDEN-REPLAY: {route_name} :: {label}");
        }
        Ok::<_, BoxError>(())
    }
    .await;
    owner.execute("DELETE FROM webhook_subscriptions WHERE url LIKE 'https://plat4-%'", &[]).await?;
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F08' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    owner.execute("DELETE FROM admin_role_assignments WHERE user_id=$1", &[&a.user]).await?;
    owner.execute("DELETE FROM admin_role_groups WHERE name=$1", &[&role]).await?;
    for account in [&a, &b] {
        common::remove_blob_account(&owner, account).await?;
    }
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;")).await?;
    result
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
