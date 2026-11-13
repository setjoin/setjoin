//! F08 Platform frozen-Go oracle (shared by every Platform slice's test target).
//!
//! Record mode runs the covered Go binary behind the front door; replay serves the same
//! requests from Rust with no Go upstream. Each case builds its own admin persona
//! (governed role group + assignment), takes `SERIAL` for its whole run (the global
//! `backup_runs` and admin audit window are shared state) and removes only what it made.
//! A case table maps `(action, label)` to a request; `route` names the inventory key.
pub mod updates;
pub mod airgap;
pub mod deploy;
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    platform::PlatformRoute, Body, BoxFuture, Config, Gateway, Intercept, RequestContext,
    RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

pub mod alerts;
pub mod apps;
pub mod branding;
pub mod dns;
pub mod domains;
pub mod federation;
pub mod monitor;
pub mod terms;
mod b;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Probe {
    inner: PlatformRoute<setjoin_gateway::jmap::jwks::Jwks>,
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

fn timestamp_like(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() >= 19
        && b[4] == b'-'
        && b[7] == b'-'
        && (b[10] == b'T' || b[10] == b' ')
        && b[13] == b':'
}

fn uuid_at(b: &[u8]) -> bool {
    b.len() >= 36
        && b[..36].iter().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *c == b'-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}
fn is_uuid(s: &str) -> bool {
    s.len() == 36 && uuid_at(s.as_bytes())
}
/// Every UUID in a rendered text becomes `<uuid>`.
pub fn mask_uuids(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < b.len() {
        if uuid_at(&b[i..]) {
            out.push_str("<uuid>");
            i += 36;
        } else {
            let ch = text[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// Mask run-specific identities (by key) and run-time timestamps.
fn mask(v: &mut Value, users: &[(i64, &str)]) {
    match v {
        Value::Object(map) => {
            for (k, x) in map.iter_mut() {
                if let Some(n) = x.as_i64() {
                    if matches!(
                        k.as_str(),
                        "user_id" | "actor_id" | "actor" | "granted_by" | "updated_by" | "opened_by" | "approved_by" | "closed_by" | "affected_user_id" | "uploading_user_id" | "fork_consented_by"
                    ) {
                        if let Some((_, name)) = users.iter().find(|(i, _)| *i == n) {
                            *x = json!(name);
                        }
                    }
                } else {
                    mask(x, users);
                }
            }
        }
        Value::Array(xs) => xs.iter_mut().for_each(|x| mask(x, users)),
        Value::String(s) => {
            if timestamp_like(s) && !s.starts_with("2026-10-0") {
                *s = "<timestamp>".into();
            } else if is_uuid(s) && !matches!(s.as_str(),
                "aaaaaaaa-0000-4000-8000-000000000001" | "bbbbbbbb-0000-4000-8000-000000000002") {
                // Authored recovery-set/proof fixture inputs remain observable;
                // only generated UUIDs are run-specific normalization targets.
                *s = "<uuid>".into();
            }
        }
        _ => {}
    }
}
fn masked(
    mut v: Value,
    users: &[(i64, &str)],
    names: &dyn Fn(&str) -> String,
) -> Result<Value, BoxError> {
    v = serde_json::from_str(&names(&v.to_string()))?;
    mask(&mut v, users);
    Ok(v)
}

/// Schema-load values that differ on every fresh database: the grant-authority
/// timestamps, the deployment identity and the AD password row's encrypted flag. Pinned on both sides of a comparison so a
/// freshly loaded database replays the goldens recorded on an older load.
fn pin_load_values(body: &str) -> String {
    // Go flips the AD password row to encrypted once it has run against a database; a
    // freshly loaded schema carries the seed's `false`.
    let mut out = body.replace(
        "\"encrypted\":true,\"key\":\"ad_sync_password_enc\"",
        "\"encrypted\":false,\"key\":\"ad_sync_password_enc\"",
    );
    for (marker, width) in [
        ("\"authorized_at\":\"", 20usize),
        ("\"key\":\"identity.deployment_id\",\"value\":\"", 36),
    ] {
        let mut from = 0;
        while let Some(i) = out[from..].find(marker) {
            let start = from + i + marker.len();
            if out.len() < start + width || !out.is_char_boundary(start + width) {
                break;
            }
            out.replace_range(start..start + width, &"0".repeat(width));
            from = start + width;
        }
    }
    out
}

const SEEDS: &[(i64, &str, &str)] = &[
    (9001, "completed", "2026-10-01T10:00:00Z"),
    (9002, "failed", "2026-10-01T11:00:00Z"),
    (9003, "pending", "2026-10-01T12:00:00Z"),
];

async fn rows(c: &tokio_postgres::Client, sql: &str) -> Result<Vec<Value>, BoxError> {
    c.query(sql, &[])
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
        .collect()
}
async fn snapshot(c: &tokio_postgres::Client) -> Result<Value, BoxError> {
    // New runs get a run-specific id; the position in `created_at` order names them.
    Ok(json!(rows(c, "SELECT jsonb_build_object('id',CASE WHEN id>=9000 AND id<9100 THEN id::text ELSE '<run>' END,'status',status,'blob_count',blob_count,'created',CASE WHEN created_at<'2026-10-02' THEN to_char(created_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') ELSE '<now>' END)::text FROM backup_runs ORDER BY created_at, id").await?))
}

const WRITABLE: [&str; 18] = [
    "identity_source",
    "deleted_items_purge_days",
    "spam_purge_days",
    "smtp_retry_max",
    "greylist_duration",
    "max_message_bytes",
    "dkim_selector",
    "vacation_default_subject",
    "password_min_length",
    "password_require_uppercase",
    "password_require_lowercase",
    "password_require_digit",
    "password_require_special",
    "mfa_enforcement_mode",
    "worm_retention_days",
    "worm_mode",
    "worm_legal_hold_enabled",
    "apps_caps_strict",
];

fn group(action: &str) -> &'static str {
    if action.starts_with("config") {
        "config"
    } else {
        "system"
    }
}

/// The `system_config` rows this suite owns or may touch.
async fn config_snapshot(c: &tokio_postgres::Client) -> Result<Value, BoxError> {
    Ok(json!(rows(c, "SELECT jsonb_build_object('key',key,'value',value,'encrypted',encrypted,'description',description)::text FROM system_config WHERE key LIKE 'plat1.%' OR key = ANY(ARRAY['identity_source','deleted_items_purge_days','spam_purge_days','smtp_retry_max','greylist_duration','max_message_bytes','dkim_selector','vacation_default_subject','password_min_length','password_require_uppercase','password_require_lowercase','password_require_digit','password_require_special','mfa_enforcement_mode','worm_retention_days','worm_mode','worm_legal_hold_enabled','apps_caps_strict','assist.api_key']) ORDER BY key").await?))
}

/// `(method, inventory pattern, concrete path)` for an action.
fn route(action: &str) -> (&'static str, &'static str) {
    if let Some(found) = b::route(action) {
        return found;
    }
    match action {
        "version" => ("GET", "/admin/system/version"),
        "schema-version" => ("GET", "/admin/system/schema-version"),
        "status" => ("GET", "/admin/system/status"),
        "health" => ("GET", "/admin/system/health"),
        "backup-list" => ("GET", "/admin/system/backup/list"),
        "backup-enqueue" => ("POST", "/admin/system/backup"),
        "backup-download" => ("GET", "/admin/system/backup/download"),
        "backup-delete" => ("DELETE", "/admin/system/backup"),
        "config-list" => ("GET", "/admin/system/config"),
        "config-get" => ("GET", "/admin/system/config/{key}"),
        "config-set" => ("PUT", "/admin/system/config/{key}"),
        "config-export" => ("GET", "/admin/system/config/export"),
        "config-import" => ("POST", "/admin/system/config/import"),
        _ => panic!("unknown F08 action {action}"),
    }
}

/// The permissions that satisfy an action's gate.
fn granted(action: &str) -> Vec<&'static str> {
    if b::handles(action) {
        return b::granted(action);
    }
    match action {
        "backup-enqueue" | "backup-delete" => vec!["backup.write"],
        "config-set" | "config-import" => vec!["system.config"],
        _ => vec!["backup.read"],
    }
}

pub async fn run(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run_inner(action, kind, fault).await
}

async fn run_inner(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let mutant = kind.ends_with("-status-mutant");
    let label = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let Some(db) = Db::for_case("plat1-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "plat1-admin").await?;
    let b = fixture::account(&owner, "plat1-other").await?;
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
    // Persona: the governed role the caller holds.
    let (permissions, scope): (Vec<&str>, Option<i64>) = match label {
        "denied" if b::handles(action) => (b::denied(action), None),
        "denied" => (vec!["users.read"], None),
        "scoped" => (granted(action), Some(b.domain)),
        _ => (granted(action), None),
    };
    let role = format!("plat1-role-{}", a.user);
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
    let is_config = action.starts_with("config");
    let touched: Vec<String> = WRITABLE
        .iter()
        .map(|k| k.to_string())
        .chain(["assist.api_key".to_string()])
        .collect();
    let originals: Vec<(String, String, bool, Option<String>)> = owner
        .query("SELECT key, value::text, encrypted, description FROM system_config WHERE key = ANY($1)", &[&touched])
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1), r.get(2), r.get(3)))
        .collect();
    if is_config {
        owner
            .execute("DELETE FROM system_config WHERE key LIKE 'plat1.%'", &[])
            .await?;
        for (key, value, encrypted, description) in [
            (
                "plat1.string",
                "\"hello <b> & \\u2028 \\b é\"",
                false,
                "a string",
            ),
            ("plat1.number", "1.50", false, ""),
            ("plat1.big", "12345678901234567890", false, ""),
            ("plat1.huge", "1e25", false, ""),
            ("plat1.small", "0.0000001", false, ""),
            (
                "plat1.nested",
                "{\"b\":[1,2,{\"z\":null,\"a\":\"<&>\"}],\"a\":true}",
                false,
                "nested <desc>",
            ),
            ("plat1.null", "null", false, ""),
            ("plat1.flag_enc", "\"cipher\"", false, ""),
            ("plat1.secret", "\"cipher2\"", true, ""),
        ] {
            owner
                .execute("INSERT INTO system_config(key,value,encrypted,description) VALUES($1,$2::text::jsonb,$3,NULLIF($4,''))", &[&key, &value, &encrypted, &description])
                .await?;
        }
        if action == "config-set" && label == "overwrite" {
            owner
                .execute("DELETE FROM system_config WHERE key='spam_purge_days'", &[])
                .await?;
            owner.execute("INSERT INTO system_config(key,value,encrypted) VALUES('spam_purge_days','7'::jsonb,true)", &[]).await?;
        }
        if matches!(action, "config-set" | "config-import") && label != "overwrite" {
            owner
                .execute("DELETE FROM system_config WHERE key = ANY($1)", &[&touched])
                .await?;
        }
    }
    owner.execute("DELETE FROM backup_runs", &[]).await?;
    if matches!(
        (action, label),
        ("backup-list", "success" | "ignored-query" | "scoped") | ("backup-enqueue", "repeat")
    ) {
        for (id, status, created) in SEEDS {
            owner
                .execute(
                    "INSERT INTO backup_runs(id,status,created_at,blob_count,blob_total_size,config_size,manifest_timestamp,blobs_copied,blobs_skipped,started_at,completed_at) OVERRIDING SYSTEM VALUE VALUES($1::bigint,$2::text,$3::text::timestamptz,($1::bigint)::int,$1::bigint*10,NULL,CASE WHEN $2::text='completed' THEN '20261001T100000Z' END,1,2,$3::text::timestamptz,CASE WHEN $2::text='completed' THEN $3::text::timestamptz END)",
                    &[id, status, created],
                )
                .await?;
        }
    }
    let pending_migration = (action, label) == ("schema-version", "pending");
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F08'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    // Faults run real mutated database objects against the unchanged expectation.
    let schema = format!("gofree_plat1_fault_{}", a.user);
    let mut undo: Vec<String> = vec![];
    match fault {
        Some("no-audit") => {
            owner.batch_execute(&format!("CREATE SCHEMA {schema};CREATE FUNCTION {schema}.fault() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN RETURN NULL; END $fault$;CREATE TRIGGER {schema} BEFORE INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION {schema}.fault();")).await?;
            undo.push(format!("DROP TRIGGER {schema} ON admin_audit_log"));
        }
        Some("no-notify") => {
            owner
                .batch_execute("ALTER TABLE backup_runs DISABLE TRIGGER trg_backup_runs_insert")
                .await?;
            undo.push("ALTER TABLE backup_runs ENABLE TRIGGER trg_backup_runs_insert".into());
        }
        Some("double-bump") => {
            owner.batch_execute(&format!("CREATE SCHEMA {schema};CREATE FUNCTION {schema}.fault() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF pg_trigger_depth() = 1 THEN INSERT INTO backup_runs(status) VALUES('pending'); END IF; RETURN NEW; END $fault$;CREATE TRIGGER {schema} AFTER INSERT ON backup_runs FOR EACH ROW EXECUTE FUNCTION {schema}.fault();")).await?;
            undo.push(format!("DROP TRIGGER {schema} ON backup_runs"));
        }
        Some("no-tenant-filter") => {
            owner
                .execute("INSERT INTO backup_runs(id,status,created_at) OVERRIDING SYSTEM VALUE VALUES(9099,'pending','2026-10-01T13:00:00Z')", &[])
                .await?;
        }
        _ => {}
    }
    if b::handles(action) {
        b::seed(
            &owner,
            &a,
            action,
            label,
            b::Phase::Before,
            false,
            &mut undo,
        )
        .await?;
    }
    let users: Vec<(i64, &str)> = vec![(a.user, "<admin>"), (b.user, "<other>")];
    let result = async {
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        let go = common::go_oracle::start_named(&db, s3, None, "gofree-plat1-http").await?;
        let recording = go.is_some();
        // The adapter and Go must both be given time on a loaded shared host.
        let patient = std::time::Duration::from_secs(30);
        let exec = ScopedExecutor::from_dsn_with(
            db.app.as_deref().unwrap_or(&db.dsn),
            4,
            setjoin_pg::Timeouts { pool_wait: patient, create: patient, statement: patient },
        )
        .map_err(|e| e.0)?
        .with_audit_keys("22".repeat(32), String::new());
        let adapter = Probe {
            inner: PlatformRoute::new(exec, Arc::new(common::recovery_keys()), "mailserver".into())
                // The recorded Go process runs with DNSSEC_ENABLED=false.
                .with_overrides(setjoin_platform::features::Overrides { dnssec: false, ..Default::default() }),
            changed_status: mutant,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F08" && r["slice"] == "system-features" {
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
        let query = match (action, label) {
            ("config-list", "success") => "?prefix=plat1.".to_string(),
            ("config-list", "like") => "?prefix=plat1.s%25".to_string(),
            ("config-list", "none") => "?prefix=zzz.nothing.".to_string(),
            (_, "ignored-query") => "?limit=-1&q=%00&x=%zz".to_string(),
            _ => String::new(),
        };
        let wire = b::handles(action).then(|| b::wire(action, label));
        let query = wire.as_ref().map_or(query.as_str(), |w| w.query.as_str());
        let (body, recorded_body) = match (action, label) {
            _ if wire.is_some() => {
                let w = wire.as_ref().unwrap();
                (w.body.clone(), w.recorded_body.clone())
            }
            ("backup-enqueue", "bad-body") => ("{\"garbage\":".to_string(), "{\"garbage\":".to_string()),
            ("config-import", l) => {
                let same = |text: &str| (text.to_string(), text.to_string());
                let item = "{\"key\":\"deleted_items_purge_days\",\"value\":\"1\"}";
                match l {
                    "bad-json" => same("[{\"key\":"),
                    "not-array" => same("{\"a\":1}"),
                    "empty-body" => same(""),
                    "bare-item" => same("[5]"),
                    "missing-comma" => same("[{\"key\":\"worm_mode\",\"value\":\"1\"}{\"key\":\"b\"}]"),
                    "trailing-comma" => same("[{\"key\":\"\"},]"),
                    "unterminated" => same("[{\"key\":\"deleted_items_purge_days\",\"value\":\"2\"}"),
                    "disallowed" => same("[{\"key\":\"deleted_items_purge_days\",\"value\":\"1\"},{\"key\":\"plat1.string\",\"value\":\"2\"}]"),
                    "too-many" => (format!("[{}]", vec![item; 513].join(",")), "[<513 items of {\"key\":\"deleted_items_purge_days\",\"value\":\"1\"}>]".to_string()),
                    "oversize" => (format!("[{{\"key\":\"deleted_items_purge_days\",\"value\":\"1\",\"description\":\"{}\"}}]", "x".repeat(4 << 20)), "[{\"key\":\"deleted_items_purge_days\",\"value\":\"1\",\"description\":\"<4 MiB of x>\"}]".to_string()),
                    "folded" => same("[{\"key\":\"worm_mode\",\"key\":\"worm_mode\",\"value\":\"1\",\"value\":\"2\"}]"),
                    "null-only" => same("[null]"),
                    "empty-array" => same("[]"),
                    "trailing-data" => same("[] garbage"),
                    "description-null" => same("[{\"key\":\"spam_purge_days\",\"value\":\"7\",\"description\":null}]"),
                    _ => same("[{\"key\":\"deleted_items_purge_days\",\"value\":\"30\",\"description\":\"d1\"},{\"key\":\"spam_purge_days\",\"value\":\"\\\"abc\\\"\"},{\"key\":\"\",\"value\":\"x\"},null,{\"key\":\"smtp_retry_max\",\"value\":\"[ENCRYPTED]\"},{\"key\":\"greylist_duration\",\"value\":5},{\"key\":\"dkim_selector\",\"value\":\"not json\"},{\"key\":\"worm_mode\",\"value\":\"1\",\"description\":5}]"),
                }
            }
            ("config-set", l) => {
                let same = |text: &str| (text.to_string(), text.to_string());
                match l {
                    "bad-json" => same("{\"value\":"),
                    "array-body" => same("[1]"),
                    "bad-bool" => same("{\"value\":\"maybe\"}"),
                    "no-bool" => same("{\"value\":5}"),
                    "no-value" => same("{}"),
                    "null-value" => same("{\"value\":null,\"encrypted\":null}"),
                    "encrypted" => same("{\"value\":\"x\",\"encrypted\":true}"),
                    "bool-upper" => same("{\"value\":\"TRUE\"}"),
                    "bool-json" => same("{\"value\":false}"),
                    "folded" => same("{\"VALUE\":{\"b\":2,\"a\":[1,2]},\"Encrypted\":false,\"x\":1} trailing"),
                    "oversize" => (format!("{{\"value\":\"{}\"}}", "x".repeat(1 << 20)), "{\"value\":\"<1 MiB of x>\"}".to_string()),
                    "typed-encrypted" => same("{\"value\":1,\"encrypted\":\"yes\"}"),
                    _ => same("{\"value\":30}"),
                }
            }
            _ => (String::new(), String::new()),
        };
        let key = match (action, label) {
            _ if wire.is_some() => wire.as_ref().unwrap().key.as_str(),
            ("config-get", "success") => "plat1.nested",
            ("config-get", "string") => "plat1.string",
            ("config-get", "number") => "plat1.big",
            ("config-get", "secret") => "plat1.secret",
            ("config-get", "suffix") => "plat1.flag_enc",
            ("config-get", "named") => "assist.api_key",
            ("config-get", "null") => "plat1.null",
            ("config-get", "missing") => "plat1.absent",
            ("config-get", _) => "plat1.string",
            ("config-set", "not-writable") => "plat1.string",
            ("config-set", "bool-upper" | "bool-json" | "bad-bool" | "no-bool") => "apps_caps_strict",
            ("config-set", "overwrite") => "spam_purge_days",
            ("config-set", _) => "deleted_items_purge_days",
            _ => "",
        };
        let concrete = pattern.replace("{key}", key).replace("{slug}", key);
        let extra: Vec<(String, String)> = wire.as_ref().map(|w| w.headers.clone()).unwrap_or_default();
        let send = |body: String| {
            let uri = format!("/api{concrete}{query}");
            let token = admin_token(a.user);
            let extra = extra.clone();
            async move {
                let request = Request::builder().method(method).uri(uri).header("host", "mail.test").header("origin", "http://mail.test").header("content-type", "application/json").header("x-request-id", "gofree-plat1-oracle").header("authorization", format!("Bearer {token}"));
                let request = extra.iter().fold(request, |r, (k, v)| r.header(k.as_str(), v.as_str()));
                Ok::<_, BoxError>(common::send(address, request.body(common::full(body))?).await)
            }
        };
        if label == "repeat" {
            let first = send(body.clone()).await?;
            let status = first.status().as_u16();
            let data = common::body_bytes(first).await;
            if recording && !(200..300).contains(&status) && !(b::handles(action) && status == b::wanted(action, label)) {
                return Err(format!("initial {action}: {status} {data:?}").into());
            }
        }
        if pending_migration {
            // After Go's start-up guard has passed: one migration is now pending.
            owner
                .execute("DELETE FROM schema_migrations WHERE version=(SELECT max(version) FROM schema_migrations)", &[])
                .await?;
        }
        // Seeded after Go's start-up, which encrypts a plaintext named secret.
        if label == "named" {
            owner.execute("DELETE FROM system_config WHERE key='assist.api_key'", &[]).await?;
            owner.execute("INSERT INTO system_config(key,value) VALUES('assist.api_key','\"sk-test\"'::jsonb)", &[]).await?;
        }
        if b::handles(action) {
            b::seed(&owner, &a, action, label, b::Phase::After, recording, &mut undo).await?;
        }
        let before_b = if b::handles(action) { Some(b::effects(&owner, &a, action).await?) } else { None };
        let before = if before_b.is_some() { Value::Null } else if is_config { config_snapshot(&owner).await? } else { snapshot(&owner).await? };
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
        let mut alerts = db.listen("admin:alert").await?;
        let mut backups = db.listen("backup_run").await?;
        let mut changes = db.listen("config_changed").await?;
        let mut extras = vec![];
        if b::handles(action) {
            for channel in b::channels(action).iter().filter(|c| !matches!(**c, "admin:alert" | "backup_run" | "config_changed")) {
                extras.push((channel.to_string(), db.listen(channel).await?));
            }
        }
        let response = send(body.clone()).await?;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        let after_b = if b::handles(action) { Some(b::effects(&owner, &a, action).await?) } else { None };
        let after = if after_b.is_some() { Value::Null } else if is_config { config_snapshot(&owner).await? } else { snapshot(&owner).await? };
        let mut audit: Vec<Value> = owner.query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&last]).await?.iter().map(|r| serde_json::from_str(&r.get::<_, String>(0))).collect::<Result<_, _>>()?;
        for row in &mut audit {
            if row["id"].as_i64().is_none_or(|n| n <= 0) { return Err("invalid audit id".into()); }
            row["id"] = json!("<audit>");
            for key in ["checksum", "prev_checksum"] {
                if row[key].as_str().is_some_and(|s| !s.is_empty()) { row[key] = json!("<checksum>"); }
            }
            *row = masked(row.clone(), &users, &names)?;
        }
        let mut notify = vec![];
        for event in alerts.drain(&owner).await? {
            let payload: Value = serde_json::from_str(&event)?;
            notify.push(json!({"channel":"admin:alert","payload":masked(payload, &users, &names)?}));
        }
        for event in backups.drain(&owner).await? {
            let known = SEEDS.iter().any(|(id, _, _)| id.to_string() == event);
            notify.push(json!({"channel":"backup_run","payload":if known { event } else { "<run>".to_string() }}));
        }
        for event in changes.drain(&owner).await? {
            let payload: Value = serde_json::from_str(&event)?;
            notify.push(json!({"channel":"config_changed","payload":payload}));
        }
        for (channel, listener) in &mut extras {
            for event in listener.drain(&owner).await? {
                let payload = serde_json::from_str::<Value>(&event).unwrap_or(json!(event));
                notify.push(json!({"channel":channel.as_str(),"payload":masked(payload, &users, &names)?}));
            }
        }
        let wanted = if b::handles(action) { b::wanted(action, label) } else { match (action, label) {
            (_, "denied") => 403,
            ("backup-enqueue", _) => 202,
            ("config-get", "missing") => 404,
            ("config-set", "not-writable") => 403,
            ("config-set", "bad-json" | "bad-bool" | "no-bool" | "oversize" | "array-body") => 400,
            ("config-import", "denied") => 403,
            ("config-import", "disallowed") => 403,
            ("config-import", "too-many" | "oversize") => 413,
            ("config-import", "bad-json" | "not-array" | "empty-body" | "bare-item" | "missing-comma" | "trailing-comma" | "unterminated") => 400,
            ("config-import", _) => 200,
            ("config-set", "no-value") => 500,
            ("config-set", "typed-encrypted") => 400,
            ("config-set", _) => 204,
            ("backup-download" | "backup-delete", _) => 501,
            _ => 200,
        } };
        if recording && status != wanted {
            return Err(format!("Go {action}/{label}: expected {wanted}, got {status}: {raw}").into());
        }
        // Process facts and run ids differ per process and run; their shape must not.
        let mut text = names(&raw);
        if b::handles(action) {
            text = b::normalize(&a, action, &text);
        }
        if matches!(action, "status" | "health") && status == 200 {
            let mut doc: Value = serde_json::from_str(&text)?;
            let shape_ok = doc["pid"].as_u64().is_some_and(|n| n > 0)
                && doc["uptime_sec"].as_u64().is_some()
                && doc["goroutines"].as_u64().is_some_and(|n| n > 0)
                && doc["memory_mb"].as_u64().is_some()
                && doc["started_at"].as_str().is_some_and(timestamp_like)
                && doc["started_at"].as_str().is_some_and(|t| t.ends_with('Z'));
            if !shape_ok { return Err(format!("status shape: {text}").into()); }
            for key in ["pid", "uptime_sec", "goroutines", "memory_mb"] { doc[key] = json!("<n>"); }
            doc["started_at"] = json!("<timestamp>");
            text = serde_json::to_string(&doc)? + "\n";
        }
        if action == "backup-enqueue" && status == 202 {
            let doc: Value = serde_json::from_str(&text)?;
            if doc["run_id"].as_i64().is_none_or(|n| n <= 0) { return Err("run id".into()); }
            text = "{\"run_id\":\"<run>\",\"status\":\"enqueued\"}\n".into();
        }
        text = pin_load_values(&text);
        if let Some(date) = headers.get_mut("date") { *date = json!(["<timestamp>"]); }
        if let Some(length) = headers.get_mut("content-length") {
            *length = json!([text.len().to_string()]);
        }
        let effects = if let (Some(before_b), Some(after_b)) = (before_b, after_b) {
            let mut list = vec![];
            for ((table, before), (_, after)) in before_b.into_iter().zip(after_b) {
                list.push(json!({"table":table,"before":masked(before, &users, &names)?,"after":masked(after, &users, &names)?}));
            }
            json!(list)
        } else {
            let (before, after) = (masked(before, &users, &names)?, masked(after, &users, &names)?);
            json!([{"table":if is_config {"system_config"} else {"backup_runs"},"before":before,"after":after}])
        };
        let mut request = json!({"method":method,"path":pattern,"external_path":format!("/api{concrete}")});
        if !recorded_body.is_empty() { request["body"] = json!(names(&recorded_body)); }
        if !query.is_empty() { request["query"] = json!(query); }
        let observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":notify});
        if !recording {
            let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F08\"} 0") {
                return Err(format!("F08 replay forwarded to Go: {metrics}").into());
            }
        }
        server.abort();
        let name = format!("{action}-{label}");
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/platform/goldens");
        std::fs::create_dir_all(&dir)?;
        // Config actions already carry their group in the name (`config-list`).
        let stem = if group(action) == "config" { name.clone() } else { format!("system-{name}") };
        let file = dir.join(format!("{stem}.json"));
        let row_file = dir.join(format!("{stem}-row-effects.json"));
        let route_name = format!("{method} {pattern}");
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            record(&file, &json!({"format":1,"route":route_name,"case":label,"go_source":source,"observation":observation}))?;
            record(&row_file, &json!({"format":1,"route":route_name,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;
        } else {
            let mut expected: Value = serde_json::from_slice(&std::fs::read(&file)?)?;
            if let Some(body) = expected["observation"]["response"]["body"].as_str() {
                let body = if matches!(action, "sod-get" | "sod-set") {
                    b::sod_canonical(body)
                } else if action == "schema-version" && body.contains("\"up_to_date\"") {
                    schema_version_expected(body)
                } else {
                    body.to_owned()
                };
                expected["observation"]["response"]["body"] = json!(pin_load_values(&body));
                if action == "schema-version" && body.contains("\"up_to_date\"") {
                    if let Some(length) = expected["observation"]["response"]["headers"].get_mut("content-length") {
                        *length = json!([body.len().to_string()]);
                    }
                }
            }
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
    if matches!(fault, Some("no-audit" | "double-bump")) {
        owner
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
    }
    if pending_migration {
        let version = setjoin_gateway_schema_last();
        owner
            .execute(
                "INSERT INTO schema_migrations(version) VALUES($1) ON CONFLICT DO NOTHING",
                &[&version],
            )
            .await?;
    }
    if is_config {
        owner
            .execute(
                "DELETE FROM system_config WHERE key LIKE 'plat1.%' OR key = ANY($1)",
                &[&touched],
            )
            .await?;
        for (key, value, encrypted, description) in &originals {
            owner
                .execute("INSERT INTO system_config(key,value,encrypted,description) VALUES($1,$2::text::jsonb,$3,$4)", &[key, value, encrypted, description])
                .await?;
        }
    }
    owner.execute("DELETE FROM backup_runs", &[]).await?;
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F08' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE user_id=$1",
            &[&a.user],
        )
        .await?;
    owner
        .execute("DELETE FROM admin_role_groups WHERE name=$1", &[&role])
        .await?;
    for account in [&a, &b] {
        common::remove_blob_account(&owner, account).await?;
    }
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;")).await?;
    result
}

/// The recorded schema-version body names Go's migration set at recording time (V276). The
/// repository's set has advanced while the recording stays immutable, so the recorded shape
/// (key order, `pending` empty or naming exactly the one deleted migration, `up_to_date`) is
/// re-derived from this repository's migrations; the wire body is still compared byte for byte.
fn schema_version_expected(recorded: &str) -> String {
    let migrations = setjoin_schema::MIGRATIONS;
    let (last, name) = migrations.last().map(|m| (m.0, m.1)).expect("embedded migrations");
    let pending = recorded.contains("\"up_to_date\":false");
    let current = if pending { migrations[migrations.len() - 2].0 } else { last };
    let listed = if pending { serde_json::to_string(name).unwrap() } else { String::new() };
    let tail = &recorded[recorded.trim_end().len()..];
    format!("{{\"current\":{current},\"expected\":{last},\"pending\":[{listed}],\"up_to_date\":{}}}{tail}", !pending)
}

fn setjoin_gateway_schema_last() -> i32 {
    setjoin_schema::MIGRATIONS.last().map_or(0, |m| m.0)
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

pub mod jobs_storage;
