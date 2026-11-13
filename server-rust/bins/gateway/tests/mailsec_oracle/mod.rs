//! F06 Mail security frozen-Go oracle, shared by every slice's test target.
//!
//! Record mode runs the covered Go binary behind the front door; replay serves the same
//! requests from Rust with no Go upstream. Each case builds two accounts (the actor's and
//! another tenant's), a governed admin role when the route is an admin route, takes `SERIAL`
//! for its whole run (the admin audit window is global) and removes only what it made. A
//! slice module (`quarantine.rs`, ...) owns `route`, `granted`, `seed`, `request`, `wanted`
//! and `snapshot` for its actions; this file owns persona, masking, observation, goldens,
//! planted mutants and cleanup.
pub mod certificates;
pub mod dlp;
pub mod dmarc;
pub mod quarantine;
pub mod queue;
pub mod smime;
pub mod spam;
pub mod threat;
pub mod tls;
pub mod trace;
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    mail_security::MailSecurityRoute, Body, BoxFuture, Config, Gateway, Intercept, RequestContext,
    RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Probe {
    inner: MailSecurityRoute<setjoin_gateway::jmap::jwks::Jwks>,
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

/// A token Go and Rust both treat as an admin whose real permissions are the governed
/// grants (the signed `forged.permission` claim must never matter).
pub fn admin_token(user: i64) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::{signature::Signer, SigningKey};
    let source = common::recovery_token(user);
    let fields = source.split('.').collect::<Vec<_>>();
    let mut claims: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(fields[1]).unwrap()).unwrap();
    claims["admin"] = json!(true);
    claims["perms"] = json!(["forged.permission"]);
    let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
    let key = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let signature: p256::ecdsa::Signature = key.sign(format!("{}.{payload}", fields[0]).as_bytes());
    format!(
        "{}.{payload}.{}",
        fields[0],
        URL_SAFE_NO_PAD.encode(signature.to_bytes())
    )
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
        out = out.replace(&format!("/{value}/"), &format!("/{label}/"));
        out = out.replace(&format!("/{value}\""), &format!("/{label}\""));
        out = out.replace(&format!("/+{value}/"), &format!("/+{label}/"));
        out = out.replace(&format!("/+{value}\""), &format!("/+{label}\""));
        if out.ends_with(&format!("/+{value}")) {
            out.truncate(out.len() - value.to_string().len());
            out.push_str(label);
        }
        if out.ends_with(&format!("/{value}")) {
            out.truncate(out.len() - value.to_string().len());
            out.push_str(label);
        }
    }
    out
}

/// Masks the bare integer after `"days_left":` (it counts down with the calendar).
pub fn mask_days(text: &str) -> String {
    let tag = "\"days_left\":";
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = rest.find(tag) {
        let end = at + tag.len();
        out.push_str(&rest[..end]);
        let digits = rest[end..]
            .chars()
            .take_while(|c| c.is_ascii_digit() || *c == '-')
            .count();
        if digits > 0 {
            out.push_str("\"<days>\"");
        }
        rest = &rest[end + digits..];
    }
    out + rest
}

/// Masks a quoted value for a key (`"previewToken":"…"`).
pub fn mask_strings(text: &str, keys: &[&str]) -> String {
    let mut out = text.to_owned();
    for key in keys {
        for sep in [":", ": "] {
            let tag = format!("\"{key}\"{sep}\"");
            let mut at = 0;
            while let Some(found) = out[at..].find(&tag) {
                let start = at + found + tag.len();
                let Some(len) = out[start..].find('"') else {
                    break;
                };
                out.replace_range(start..start + len, "<value>");
                at = start + 7;
            }
        }
    }
    out
}

/// Everything a slice needs to name run-specific rows.
pub struct Seed {
    /// Rows a slice moved aside (global tables) and puts back in `teardown`.
    pub stash: Vec<String>,
    /// `(json key, id, label)`: ids are masked wherever they appear under that key.
    pub names: Vec<(&'static str, i64, String)>,
    pub vars: std::collections::BTreeMap<&'static str, i64>,
}

pub struct Req {
    pub path: String,
    pub query: String,
    /// The query as recorded when the real one holds run-specific ids (else `query`).
    pub recorded_query: String,
    /// Extra request headers (lower-case names).
    pub headers: Vec<(String, String)>,
    pub body: String,
    /// The body as recorded (long bodies are summarised).
    pub recorded_body: String,
}

fn route(slice: &str, action: &str) -> (&'static str, &'static str) {
    match slice {
        "quarantine" => quarantine::route(action),
        "queue" => queue::route(action),
        "smime" => smime::route(action),
        "dmarc" => dmarc::route(action),
        "tls" => tls::route(action),
        "trace" => trace::route(action),
        "dlp" => dlp::route(action),
        "threat" => threat::route(action),
        "spam" => spam::route(action),
        _ => panic!("unknown slice {slice}"),
    }
}
fn granted(slice: &str, action: &str) -> Vec<&'static str> {
    match slice {
        "quarantine" => quarantine::granted(action),
        "queue" => queue::granted(action),
        "smime" => smime::granted(action),
        "dmarc" => dmarc::granted(action),
        "tls" => tls::granted(action),
        "trace" => trace::granted(action),
        "dlp" => dlp::granted(action),
        "threat" => threat::granted(action),
        "spam" => spam::granted(action),
        _ => panic!("unknown slice {slice}"),
    }
}
fn wanted(slice: &str, action: &str, label: &str) -> Option<u16> {
    match slice {
        "quarantine" => quarantine::wanted(action, label),
        "queue" => queue::wanted(action, label),
        "smime" => smime::wanted(action, label),
        "dmarc" => dmarc::wanted(action, label),
        "tls" => tls::wanted(action, label),
        "trace" => trace::wanted(action, label),
        "dlp" => dlp::wanted(action, label),
        "threat" => threat::wanted(action, label),
        "spam" => spam::wanted(action, label),
        _ => panic!("unknown slice {slice}"),
    }
}
fn request(slice: &str, action: &str, label: &str, seed: &Seed) -> Req {
    match slice {
        "quarantine" => quarantine::request(action, label, seed),
        "queue" => queue::request(action, label, seed),
        "smime" => smime::request(action, label, seed),
        "dmarc" => dmarc::request(action, label, seed),
        "tls" => tls::request(action, label, seed),
        "trace" => trace::request(action, label, seed),
        "dlp" => dlp::request(action, label, seed),
        "threat" => threat::request(action, label, seed),
        "spam" => spam::request(action, label, seed),
        _ => panic!("unknown slice {slice}"),
    }
}
async fn snapshot(
    slice: &str,
    owner: &tokio_postgres::Client,
    a: &fixture::Account,
    b: &fixture::Account,
    seed: &Seed,
) -> Result<Value, BoxError> {
    match slice {
        "quarantine" => quarantine::snapshot(owner, a, b, seed).await,
        "queue" => queue::snapshot(owner, a, b, seed).await,
        "smime" => smime::snapshot(owner, a, b, seed).await,
        "dmarc" => dmarc::snapshot(owner, a, b, seed).await,
        "tls" => tls::snapshot(owner, a, b, seed).await,
        "trace" => trace::snapshot(owner, a, b, seed).await,
        "dlp" => dlp::snapshot(owner, a, b, seed).await,
        "threat" => threat::snapshot(owner, a, b, seed).await,
        "spam" => spam::snapshot(owner, a, b, seed).await,
        _ => panic!("unknown slice {slice}"),
    }
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
    let Some(db) = Db::for_case("mailsec1-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "mailsec1-actor").await?;
    let b = fixture::account(&owner, "mailsec1-other").await?;
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
        if slice == "tls" {
            out = out.replace(&tls::dir(&a).display().to_string(), "<tlsdir>");
        }
        if slice == "smime" {
            out = smime::mask_text(&out);
        }
        if slice == "dlp" {
            out = out.replace(&format!("domain={}", b.domain), "domain=<scope-domain>");
        }
        out
    };
    let (method, pattern) = route(slice, action);
    let admin = pattern.starts_with("/admin/");
    // Persona: the governed role the caller holds (admin routes only).
    let role = format!("mailsec1-role-{}", a.user);
    if admin {
        let (permissions, scope): (Vec<&str>, Option<i64>) = match label {
            "denied" => (vec!["users.read"], None),
            "scoped" | "unreachable" => (granted(slice, action), Some(b.domain)),
            l if slice == "smime" && smime::is_scoped(l) => (granted(slice, action), Some(b.domain)),
            _ => (granted(slice, action), None),
        };
        owner
            .execute(
                "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,$3)",
                &[&role, &permissions, &scope],
            )
            .await?;
        owner
            .execute(
                "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,eligible) SELECT $1,id,$1,false FROM admin_role_groups WHERE name=$2",
                &[&a.user, &role],
            )
            .await?;
    }
    let seed = match slice {
        "quarantine" => quarantine::seed(&owner, &a, &b, action, label).await?,
        "queue" => queue::seed(&owner, &a, &b, action, label).await?,
        "smime" => smime::seed(&owner, &a, &b, action, label).await?,
        "dmarc" => dmarc::seed(&owner, &a, &b, action, label).await?,
        "tls" => tls::seed(&owner, &a, &b, action, label).await?,
        "trace" => trace::seed(&owner, &a, &b, action, label).await?,
        "dlp" => dlp::seed(&owner, &a, &b, action, label).await?,
        "threat" => threat::seed(&owner, &a, &b, action, label).await?,
        "spam" => spam::seed(&owner, &a, &b, action, label).await?,
        _ => panic!("unknown slice {slice}"),
    };
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F06'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    // Faults run real mutated database objects against the unchanged expectation.
    let schema = format!("gofree_mailsec1_fault_{}", a.user);
    let mut undo: Vec<String> = vec![];
    match fault {
        Some("no-audit") => {
            owner.batch_execute(&format!("CREATE SCHEMA {schema};CREATE FUNCTION {schema}.fault() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN RETURN NULL; END $fault$;CREATE TRIGGER {schema} BEFORE INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION {schema}.fault();")).await?;
            undo.push(format!("DROP TRIGGER {schema} ON admin_audit_log"));
        }
        Some("no-notify") => {
            // The push goes through app_notify; make it a no-op, restore the real body after.
            let def: String = owner
                .query_one(
                    "SELECT pg_get_functiondef('app_notify(text,text)'::regprocedure)",
                    &[],
                )
                .await?
                .get(0);
            owner
                .batch_execute("CREATE OR REPLACE FUNCTION app_notify(p_channel text, p_payload text) RETURNS void LANGUAGE sql AS $fault$ SELECT $fault$")
                .await?;
            undo.push(def);
        }
        Some("double-bump") => {
            owner.batch_execute(&format!("CREATE SCHEMA {schema};CREATE FUNCTION {schema}.fault() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN UPDATE mailboxes SET jmap_email_state=jmap_email_state+1 WHERE id=NEW.mailbox_id; RETURN NEW; END $fault$;CREATE TRIGGER {schema} AFTER UPDATE OF released_at ON quarantined_messages FOR EACH ROW EXECUTE FUNCTION {schema}.fault();")).await?;
            undo.push(format!("DROP TRIGGER {schema} ON quarantined_messages"));
        }
        Some("no-policy-notify") => {
            // The policy reducer's config_changed notification: rewrite it without one.
            let def: String = owner
                .query_one("SELECT pg_get_functiondef('rust_mailsec_tls_policy_set(jsonb,jsonb,jsonb)'::regprocedure)", &[])
                .await?
                .get(0);
            owner
                .batch_execute("CREATE OR REPLACE FUNCTION rust_mailsec_tls_policy_set(p_enforce jsonb, p_skip jsonb, p_mode jsonb) RETURNS boolean LANGUAGE sql AS $fault$ SELECT true $fault$")
                .await?;
            undo.push(def);
        }
        Some("no-smime-notify") => {
            // Both reducers send the notification last: rewrite them without it.
            for signature in ["rust_mailsec_smime_anchor_import(text,jsonb,bigint,bigint)", "rust_mailsec_smime_anchor_delete(bigint,bigint)"] {
                let def: String = owner
                    .query_one(&format!("SELECT pg_get_functiondef('{signature}'::regprocedure)"), &[])
                    .await?
                    .get(0);
                owner.batch_execute(&def.replace("PERFORM pg_notify('smime_trust_changed', '1');", "")).await?;
                undo.push(def);
            }
        }
        Some("no-delete-scope") => {
            let def: String = owner
                .query_one("SELECT pg_get_functiondef('rust_mailsec_smime_anchor_delete(bigint,bigint)'::regprocedure)", &[])
                .await?
                .get(0);
            owner.batch_execute(&def.replace(" AND (p_domain = 0 OR domain_id = p_domain)", "")).await?;
            undo.push(def);
        }
        Some("no-tenant-filter") => {
            quarantine::plant_foreign(&owner, &b, &seed).await?;
        }
        _ => {}
    }
    let result = async {
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        // Go's report resolves the message through the request pool with no tenant GUC, so it
        // answers 404 for every message once that pool is the RLS-bound app role (a frozen-Go
        // bug, logged in the ticket); the pre-flip owner pool is the behaviour to record.
        let go = if slice == "spam" && action == "report" {
            common::go_oracle::start_named_unscoped(&db, s3, None, "gofree-mailsec1-http").await?
        } else if slice == "tls" {
            common::go_oracle::start_named_with_env(&db, s3, "gofree-mailsec1-http", &tls::go_env(&a)).await?
        } else {
            common::go_oracle::start_named(&db, s3, None, "gofree-mailsec1-http").await?
        };
        let recording = go.is_some();
        let token = if admin { admin_token(a.user) } else { common::recovery_token(a.user) };
        let standin = if slice == "trace" { trace::jmap_standin(label, &a, &seed, &token).await? } else { None };
        if slice == "queue" {
            queue::after_start(&owner, &seed).await?;
        }
        if slice == "trace" {
            trace::after_start(&owner, &a).await?;
        }
        // The adapter and Go must both be given time on a loaded shared host.
        let patient = std::time::Duration::from_secs(30);
        let timeouts = || setjoin_pg::Timeouts { pool_wait: patient, create: patient, statement: patient };
        let exec = ScopedExecutor::from_dsn_with(db.app.as_deref().unwrap_or(&db.dsn), 4, timeouts())
            .map_err(|e| e.0)?
            .with_audit_keys("22".repeat(32), String::new());
        let worker = ScopedExecutor::from_dsn_with(&db.dsn, 4, timeouts())
            .map_err(|e| e.0)?
            .with_audit_keys("22".repeat(32), String::new());
        let mut route = MailSecurityRoute::new(exec, worker, Arc::new(common::recovery_keys()), "mailserver".into());
        if slice == "tls" {
            // Go's certificate directory is the case's mount.
            route = route.with_import_dir(Some(format!("{}/imported", tls::dir(&a).display())));
        }
        if slice == "trace" {
            // Go's identity names with HOSTNAME=mail.test: mailserver and the host itself.
            route = route.with_trace(setjoin_gateway::mail_security_trace::TraceConfig::new(Some(setjoin_mail_security::received::Identity::from_config("mail.test", "mail.test"))));
        }
        let adapter = Probe { inner: route, changed_status: mutant };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F06" && r["slice"] == slice {
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
        let req = request(slice, action, label, &seed);
        let send = |body: String| {
            let uri = format!("/api{}{}", req.path, req.query);
            let token = token.clone();
            let headers = req.headers.clone();
            async move {
                let own_type = headers.iter().any(|(name, _)| name == "content-type");
                let mut request = Request::builder().method(method).uri(uri).header("host", "mail.test").header("origin", "http://mail.test").header("x-request-id", "gofree-mailsec1-oracle").header("authorization", format!("Bearer {token}"));
                if !own_type {
                    request = request.header("content-type", "application/json");
                }
                for (name, value) in &headers {
                    request = request.header(name.as_str(), value.as_str());
                }
                Ok::<_, BoxError>(common::send(address, request.body(common::full(body))?).await)
            }
        };
        if label == "repeat" || label.ends_with("-repeat") {
            let first = send(req.body.clone()).await?;
            let status = first.status().as_u16();
            let data = common::body_bytes(first).await;
            if recording && !(200..300).contains(&status) {
                return Err(format!("initial {action}: {status} {data:?}").into());
            }
        }
        let before = snapshot(slice, &owner, &a, &b, &seed).await?;
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
        let mut alerts = db.listen("admin:alert").await?;
        let chans = [format!("tag:{}", a.mailbox), format!("tag:{}", b.mailbox)];
        let mut tags_a = db.listen(&chans[0]).await?;
        let mut tags_b = db.listen(&chans[1]).await?;
        let mut trainer = db.listen("spam_train").await?;
        let mut control = db.listen("sender_control").await?;
        let mut config_changes = db.listen("config_changed").await?;
        let mut trust_changes = db.listen("smime_trust_changed").await?;
        let response = send(req.body.clone()).await?;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        let after = snapshot(slice, &owner, &a, &b, &seed).await?;
        let users: Vec<(&'static str, i64, String)> = vec![
            ("user_id", a.user, "<actor>".into()),
            ("actor_id", a.user, "<actor>".into()),
            ("granted_by", a.user, "<actor>".into()),
            ("user_id", b.user, "<other>".into()),
        ];
        let strings = ["previewToken", "preview_token", "trained_at"];
        let all_names: Vec<(&str, i64, String)> = seed.names.iter().cloned().chain(users.iter().cloned()).collect();
        let days: Vec<String> = if slice == "dmarc" {
            owner.query("SELECT to_char(now()::date - k, 'YYYY-MM-DD') FROM generate_series(0, 45) k ORDER BY k", &[]).await?.iter().map(|r| r.get(0)).collect()
        } else {
            vec![]
        };
        let scoped_domain = (format!("domain={})", b.domain), "domain=<other-domain>)");
        let base = |text: &str| mask_days(&mask_timestamps(&mask_strings(&mask_ids(&mask_path_ids(&names(text), &all_names), &all_names), &strings)));
        let tidy = |text: &str| if slice == "dmarc" { dmarc::mask_text(text, &scoped_domain, &days, base) } else if slice == "threat" { threat::mask_text(&base(text), &b.domain.to_string()) } else { base(text) };
        let tidy = |text: &str| if slice == "trace" { trace::mask_text(&tidy(text), &a, &b, &seed) } else { tidy(text) };
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
        for (events, channel) in [(tags_a.drain(&owner).await?, "tag:<mailbox-actor>"), (tags_b.drain(&owner).await?, "tag:<mailbox-other>")] {
            for event in events {
                let payload: Value = serde_json::from_str(&event)?;
                notify.push(json!({"channel":channel,"payload":serde_json::from_str::<Value>(&tidy(&payload.to_string()))?}));
            }
        }
        // Go upserts a config batch in map order, so the per-key notifications arrive in a
        // random order: compare them as a set.
        let mut changes = vec![];
        for event in config_changes.drain(&owner).await? {
            let payload: Value = serde_json::from_str(&event)?;
            changes.push(json!({"channel":"config_changed","payload":serde_json::from_str::<Value>(&tidy(&payload.to_string()))?}));
        }
        changes.sort_by_key(|c| c.to_string());
        notify.extend(changes);
        for event in trust_changes.drain(&owner).await? {
            notify.push(json!({"channel":"smime_trust_changed","payload":event}));
        }
        for event in control.drain(&owner).await? {
            let payload: Value = serde_json::from_str(&event)?;
            notify.push(json!({"channel":"sender_control","payload":serde_json::from_str::<Value>(&tidy(&payload.to_string()))?}));
        }
        // Go hands a spam report to its in-process trainer queue; Rust has no such queue and
        // emits the `spam_train` notification the message_tags trigger uses. The divergence
        // is recorded (divergences.json); here the notification must be exactly that.
        let trained = trainer.drain(&owner).await?;
        if slice == "spam" && action == "report" {
            let wants = !recording && matches!(label, "success" | "with-note" | "repeat");
            if trained.len() != usize::from(wants) {
                return Err(format!("spam report notifications: {trained:?}").into());
            }
            if let Some(event) = trained.first() {
                let payload: Value = serde_json::from_str(event)?;
                if payload["user_id"] != json!(a.user) || payload["is_spam"] != json!(true) || payload["message_id"].as_i64() != seed.vars.get("ma").copied() {
                    return Err(format!("spam_train payload: {payload}").into());
                }
            }
        } else if !trained.is_empty() {
            return Err(format!("unexpected spam_train notifications: {trained:?}").into());
        }
        if let Some(wanted) = wanted(slice, action, label) {
            if recording && status != wanted {
                return Err(format!("Go {action}/{label}: expected {wanted}, got {status}: {raw}").into());
            }
        }
        if let Some(date) = headers.get_mut("date") { *date = json!(["<timestamp>"]); }
        if slice == "threat" {
            if let Some(list) = headers.get_mut("content-disposition") {
                *list = json!(list.as_array().into_iter().flatten().filter_map(|v| v.as_str()).map(|v| threat::mask_text(v, "")).collect::<Vec<_>>());
            }
        }
        let text = tidy(&raw);
        if let Some(length) = headers.get_mut("content-length") {
            *length = json!([text.len().to_string()]);
        }
        let (before, after) = (serde_json::from_str::<Value>(&tidy(&before.to_string()))?, serde_json::from_str::<Value>(&tidy(&after.to_string()))?);
        let effects = json!([{"table":slice,"before":before,"after":after}]);
        let mut request = json!({"method":method,"path":pattern,"external_path":tidy(&format!("/api{}",req.path))});
        if !req.recorded_body.is_empty() { request["body"] = json!(names(&req.recorded_body)); }
        let shown_query = if req.recorded_query.is_empty() { &req.query } else { &req.recorded_query };
        if !shown_query.is_empty() { request["query"] = json!(shown_query); }
        let observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":notify});
        if !recording {
            let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F06\"} 0") {
                return Err(format!("F06 replay forwarded to Go: {metrics}").into());
            }
        }
        server.abort();
        if let Some(standin) = &standin { standin.abort(); }
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/mail-security/goldens");
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
            let expected: Value = common::golden_doc(&file, "observation", &observation);
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
            let expected: Value = common::golden_doc(&row_file, "effects", &observation["effects"]);
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
    if matches!(fault, Some("no-audit" | "double-bump")) {
        owner
            .batch_execute(&format!("DROP SCHEMA IF EXISTS {schema} CASCADE"))
            .await?;
    }
    if slice == "queue" {
        queue::teardown(&owner, &seed).await?;
    }
    if slice == "dmarc" {
        dmarc::teardown(&owner, action, &seed).await?;
    }
    if slice == "spam" {
        spam::teardown(&owner, action, label, &seed).await?;
    }
    if slice == "tls" {
        tls::teardown(&owner, &a, &seed).await?;
    }
    if slice == "trace" {
        trace::teardown(&owner, &a, &seed).await?;
    }
    if slice == "smime" {
        smime::teardown(&owner, &seed).await?;
    }
    if slice == "dlp" {
        dlp::teardown(&owner, &seed).await?;
    }
    if slice == "threat" {
        threat::teardown(&owner, &seed).await?;
    }
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F06' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    if admin {
        owner
            .execute(
                "DELETE FROM admin_role_assignments WHERE user_id=$1",
                &[&a.user],
            )
            .await?;
        owner
            .execute("DELETE FROM admin_role_groups WHERE name=$1", &[&role])
            .await?;
    }
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
