//! F01 slice `sod` frozen-Go oracle: HTTP wire, committed rows and audit for the
//! just-in-time activation and activation-policy routes. Record mode runs the
//! covered Go binary behind the front door; replay serves the same requests from
//! Rust with no Go upstream.
//!
//! Parallel safety: every case shares the global `rbac.jit` toggle, the
//! `jit.default_*` configuration rows, the admin audit window and the F01 receipts,
//! so each case holds `SERIAL` for its whole run (taken in `run`, not re-entrant).
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    admin_sod::AdminSodRoute, Body, BoxFuture, Config, Gateway, Intercept, RequestContext,
    RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Probe {
    inner: AdminSodRoute<setjoin_gateway::jmap::jwks::Jwks>,
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

fn admin_token(user: i64) -> String {
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

fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "my-roles" => ("GET", "/admin/me/roles"),
        "activate" => ("POST", "/admin/me/roles/{id}/activate"),
        "deactivate" => ("POST", "/admin/me/roles/{id}/deactivate"),
        "policy-get" => ("GET", "/admin/roles/{id}/activation-policy"),
        "policy-put" => ("PUT", "/admin/roles/{id}/activation-policy"),
        _ => panic!("unknown F01 sod action {action}"),
    }
}

// Fixed ids keep the goldens free of run-specific numbers.
const ALPHA: i64 = 940001; // a: eligible, active window, policy 45/justified, approval flags set
const BETA: i64 = 940002; // a: direct (not eligible)
const GAMMA: i64 = 940003; // a: eligible, expired assignment
const DELTA: i64 = 940004; // b only
const JIT: i64 = 940005; // a: eligible, policy 60/no justification
const JUST: i64 = 940006; // a: eligible, policy 120/justification required
const CAP: i64 = 940007; // a: eligible, expires in 7 minutes (cap label only)
const BARE: i64 = 940008; // a: eligible, no policy
const NOPOL: i64 = 940009; // nobody, no policy
const PERM: i64 = 940010; // a: the governing role (roles.manage or other)
const ROLES: [i64; 10] = [ALPHA, BETA, GAMMA, DELTA, JIT, JUST, CAP, BARE, NOPOL, PERM];
const MISSING: i64 = 99999999;

fn timestamp_like(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() >= 19
        && b[4] == b'-'
        && b[7] == b'-'
        && (b[10] == b'T' || b[10] == b' ')
        && b[13] == b':'
}

/// Mask run-specific identities by the key that names them.
fn mask(v: &mut Value, users: &[(i64, &str)]) {
    match v {
        Value::Object(map) => {
            for (k, x) in map.iter_mut() {
                if let Some(n) = x.as_i64() {
                    let user = matches!(
                        k.as_str(),
                        "user_id"
                            | "actor_id"
                            | "actor"
                            | "granted_by"
                            | "created_by"
                            | "requester_user_id"
                            | "approver_ref"
                    );
                    if user {
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
            if timestamp_like(s) && !s.starts_with("2026-10-01") && !s.starts_with("2031-") {
                *s = "<timestamp>".into();
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

/// A timestamp column as text: far-future and historic fixtures verbatim, a window
/// relative to now in whole minutes (an elapsed second never changes the ceiling).
fn when(column: &str) -> String {
    format!(
        "CASE WHEN {c} IS NULL THEN NULL WHEN {c} > '2030-01-01' OR {c} < '2026-10-02' THEN to_char({c} AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') ELSE 'in '||ceil(extract(epoch from {c}-now())/60)||' min' END",
        c = column
    )
}

async fn rows(c: &tokio_postgres::Client, sql: &str) -> Result<Vec<Value>, BoxError> {
    c.query(sql, &[])
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
        .collect()
}
async fn snapshot(c: &tokio_postgres::Client) -> Result<Value, BoxError> {
    let ids = "(940001,940002,940003,940004,940005,940006,940007,940008,940009,940010)";
    Ok(json!({
        "assignments": rows(c, &format!("SELECT jsonb_build_object('role',role_group_id,'user_id',user_id,'eligible',eligible,'activated_until',{},'expires_at',{},'granted_by',granted_by)::text FROM admin_role_assignments WHERE role_group_id IN {ids} ORDER BY role_group_id,user_id", when("activated_until"), when("expires_at"))).await?,
        "policies": rows(c, &format!("SELECT to_jsonb(p)::text FROM admin_role_activation_policy p WHERE role_group_id IN {ids} ORDER BY role_group_id")).await?,
        "approval_requests": rows(c, "SELECT jsonb_build_object('type',consumer_type,'requester_user_id',requester_user_id,'status',status,'subject',subject,'payload',payload,'approver_kind',approver_kind,'approver_ref',approver_ref)::text FROM approval_requests WHERE consumer_type='rbac.jit_activation' ORDER BY id").await?,
    }))
}

pub async fn run(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run_inner(action, kind, fault).await
}

async fn run_inner(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let mutant = kind.ends_with("-status-mutant");
    let label = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let Some(db) = Db::for_case("admin5-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "admin5-admin").await?;
    let b = fixture::account(&owner, "admin5-other").await?;
    let t = fixture::account(&owner, "admin5-third").await?;
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
        (domain_of(t.domain).await?, "host-t.test"),
    ];
    let names = |text: &str| {
        let mut out = text.to_owned();
        for (domain, name) in &domain_names {
            out = out.replace(domain.as_str(), name);
        }
        out
    };
    // The governing role: roles.manage, narrowed to the other domain, or something else.
    let (permissions, scope): (Vec<&str>, Option<i64>) = match (action, label) {
        (_, "denied") => (vec!["users.read"], None),
        ("policy-get" | "policy-put", "foreign") => (vec!["roles.manage"], Some(b.domain)),
        _ => (vec!["roles.manage"], None),
    };
    let originals: Vec<(String, Value)> = owner
        .query(
            "SELECT key, value::text FROM system_config WHERE key LIKE 'jit.default_%' ORDER BY key",
            &[],
        )
        .await?
        .iter()
        .map(|r| (r.get(0), serde_json::from_str(&r.get::<_, String>(1)).unwrap()))
        .collect();
    let jit_toggle: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='rbac.jit'",
            &[],
        )
        .await?
        .get(0);
    let approval_toggle: bool = owner
        .query_one(
            "SELECT enabled FROM feature_toggles WHERE key='approval.rbac'",
            &[],
        )
        .await?
        .get(0);
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='rbac.jit'",
            &[&(label != "toggle-off")],
        )
        .await?;
    if label == "approval" {
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=true WHERE key='approval.rbac'",
                &[],
            )
            .await?;
    }
    match label {
        "configured" => {
            owner.execute("UPDATE system_config SET value='90'::jsonb WHERE key='jit.default_max_minutes'", &[]).await?;
            owner.execute("UPDATE system_config SET value='true'::jsonb WHERE key='jit.default_require_justification'", &[]).await?;
        }
        "configured-array" => {
            owner.execute("UPDATE system_config SET value='[90]'::jsonb WHERE key='jit.default_max_minutes'", &[]).await?;
            owner.execute("UPDATE system_config SET value='[true]'::jsonb WHERE key='jit.default_require_justification'", &[]).await?;
        }
        _ => {}
    }
    for (id, name, perms) in [
        (ALPHA, "admin5-alpha", vec!["users.read"]),
        (BETA, "admin5-beta", vec!["users.read"]),
        (GAMMA, "admin5-gamma", vec!["users.read"]),
        (DELTA, "admin5-delta", vec!["users.read"]),
        (JIT, "admin5-jit", vec!["users.read"]),
        (JUST, "admin5-just", vec!["users.read"]),
        (CAP, "admin5-cap", vec!["users.read"]),
        (BARE, "admin5-bare", vec!["users.read"]),
        (NOPOL, "admin5-nopol", vec!["users.read"]),
        (PERM, "admin5-perm", permissions.clone()),
    ] {
        let domain_scope = if id == PERM { scope } else { None };
        owner
            .execute(
                "INSERT INTO admin_role_groups(id,name,permissions,domain_scope) OVERRIDING SYSTEM VALUE VALUES($1,$2,$3,$4)",
                &[&id, &name, &perms, &domain_scope],
            )
            .await?;
    }
    // (role, user, eligible, activated_until, expires_at)
    let mut grants: Vec<(i64, i64, bool, Option<&str>, Option<&str>)> = vec![
        (PERM, a.user, false, None, None),
        (
            ALPHA,
            a.user,
            true,
            Some("2031-01-01T00:00:00.5Z"),
            Some("2031-06-01T00:00:00Z"),
        ),
        (BETA, a.user, false, None, None),
        (GAMMA, a.user, true, None, Some("2026-10-01T00:00:00Z")),
        (DELTA, b.user, true, None, None),
        (JIT, a.user, true, None, None),
        (JUST, a.user, true, None, None),
        (BARE, a.user, true, None, None),
    ];
    if label == "cap" {
        grants.push((CAP, a.user, true, None, None));
    }
    for (role, user, eligible, until, expires) in &grants {
        owner
            .execute(
                "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by,eligible,activated_until,expires_at) VALUES($1,$2,$1,$3,$4::text::timestamptz,$5::text::timestamptz)",
                &[user, role, eligible, until, expires],
            )
            .await?;
    }
    if label == "cap" {
        owner
            .execute("UPDATE admin_role_assignments SET expires_at=now()+interval '7 minutes' WHERE role_group_id=$1", &[&CAP])
            .await?;
    }
    // Policies; alpha also carries approval settings that a PUT must leave alone.
    for (role, minutes, justified) in [(ALPHA, 45i32, true), (JIT, 60, false), (JUST, 120, true)] {
        owner
            .execute(
                "INSERT INTO admin_role_activation_policy(role_group_id,max_duration_minutes,require_justification) VALUES($1,$2,$3)",
                &[&role, &minutes, &justified],
            )
            .await?;
    }
    owner
        .execute(
            "UPDATE admin_role_activation_policy SET require_approval=true, approver_spec=jsonb_build_object('kind','named','user_id',$2::bigint) WHERE role_group_id=$1",
            &[&ALPHA, &b.user],
        )
        .await?;
    let policy_row_for_approval = label == "approval";
    if policy_row_for_approval {
        // The parked-approval path: JIT's policy now requires approval from a named approver.
        owner
            .execute(
                "UPDATE admin_role_activation_policy SET require_approval=true, approver_spec=jsonb_build_object('kind','named','user_id',$2::bigint) WHERE role_group_id=$1",
                &[&JIT, &b.user],
            )
            .await?;
    }
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let approval_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM approval_requests", &[])
        .await
        .map(|r| r.get(0))
        .unwrap_or(0);
    let receipts = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F01'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    // Faults run real mutated database objects against the unchanged expectation.
    let schema = format!("gofree_admin5_fault_{}", a.user);
    let mut trigger = None;
    if fault == Some("no-audit") {
        owner.batch_execute(&format!("CREATE SCHEMA {schema};CREATE FUNCTION {schema}.fault() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF NEW.user_id={} THEN RETURN NULL; END IF; RETURN NEW; END $fault$;CREATE TRIGGER {schema} BEFORE INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION {schema}.fault();", a.user)).await?;
        trigger = Some("admin_audit_log");
    }
    let users: Vec<(i64, &str)> = vec![
        (a.user, "<admin>"),
        (b.user, "<other>"),
        (t.user, "<third>"),
    ];
    let result = async {
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        let go = common::go_oracle::start_named(&db, s3, None, "gofree-admin5-http").await?;
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
            inner: AdminSodRoute { exec, keys: Arc::new(common::recovery_keys()), issuer: "mailserver".into() },
            changed_status: mutant,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F01" && r["slice"] == "sod" {
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
        let role_part = match (action, label) {
            ("my-roles", _) => String::new(),
            (_, "bad-id") => "bad".to_string(),
            (_, "unknown-role" | "missing" | "missing-role") => MISSING.to_string(),
            ("activate", "foreign" | "success" | "repeat" | "cold-start" | "clamp" | "bad-json" | "zero" | "negative" | "required" | "typed" | "fractional" | "null-body" | "huge" | "folded" | "padded" | "oversize" | "toggle-off" | "approval") => JIT.to_string(),
            ("activate", "not-eligible") => BETA.to_string(),
            ("activate", "cap") => CAP.to_string(),
            ("activate", "fallback-clamp" | "configured" | "configured-array") => BARE.to_string(),
            ("activate", _) => JUST.to_string(),
            ("deactivate", "direct") => BETA.to_string(),
            ("deactivate", _) => ALPHA.to_string(),
            ("policy-get", "fallback" | "configured" | "configured-array") => NOPOL.to_string(),
            ("policy-get", _) => ALPHA.to_string(),
            ("policy-put", "success" | "repeat") => NOPOL.to_string(),
            ("policy-put", _) => ALPHA.to_string(),
            _ => String::new(),
        };
        let path = pattern.replace("{id}", &role_part);
        // `(sent, recorded)`: the recorded form never contains run-specific numbers.
        let same = |text: &str| (text.to_string(), text.to_string());
        let (body, recorded_body) = match (action, label) {
            ("activate", l) => match l {
                "bad-json" => same("{\"durationMinutes\":"),
                "zero" => same("{\"durationMinutes\":0}"),
                "negative" => same("{\"durationMinutes\":-5}"),
                "required" => same("{}"),
                "typed" => same("{\"durationMinutes\":\"5\"}"),
                "fractional" => same("{\"durationMinutes\":1.5}"),
                "null-body" => same("null"),
                "huge" => same("{\"durationMinutes\":3000000000}"),
                "folded" => same("{\"DURATIONMINUTES\":15,\"Justification\":null,\"other\":[1]} trailing"),
                "padded" => (format!("{{\"durationMinutes\":15}}{}", " ".repeat(5000)), "{\"durationMinutes\":15}<5000 spaces>".to_string()),
                "oversize" => (format!("{{\"durationMinutes\":15,\"justification\":\"{}\"}}", "x".repeat(5000)), "{\"durationMinutes\":15,\"justification\":\"<5000 x>\"}".to_string()),
                "justification-required" => same("{\"durationMinutes\":30}"),
                "blank-justification" => same("{\"durationMinutes\":30,\"justification\":\"   \"}"),
                "empty-justification" => same("{\"durationMinutes\":30,\"justification\":\"\"}"),
                "justified" => same("{\"durationMinutes\":30,\"justification\":\"ticket <42> & co\"}"),
                "clamp" => same("{\"durationMinutes\":600,\"justification\":\"long\"}"),
                "cap" => same("{\"durationMinutes\":60}"),
                "fallback-clamp" | "configured" | "configured-array" => same("{\"durationMinutes\":100000,\"justification\":\"why\"}"),
                _ => same("{\"durationMinutes\":30,\"justification\":\"on call\"}"),
            },
            ("policy-put", l) => match l {
                "invalid" => same("{\"maxDurationMinutes\":"),
                "zero" => same("{\"maxDurationMinutes\":0,\"requireJustification\":true}"),
                "negative" => same("{\"maxDurationMinutes\":-1}"),
                "required" => same("{}"),
                "typed" => same("{\"maxDurationMinutes\":\"5\"}"),
                "huge" => same("{\"maxDurationMinutes\":3000000000}"),
                "folded" => same("{\"MAXDURATIONMINUTES\":25,\"requirejustification\":true} trailing"),
                "justified" => same("{\"maxDurationMinutes\":90,\"requireJustification\":true}"),
                _ => same("{\"maxDurationMinutes\":90,\"requireJustification\":false}"),
            },
            _ => (String::new(), String::new()),
        };
        // Self-service callers: the third account has no assignments; a cold-start token is not admin.
        let caller = if label == "foreign" && !action.starts_with("policy") { t.user } else { a.user };
        let non_admin = matches!(label, "cold-start");
        let query = if action == "my-roles" && label == "ignored-query" { "?limit=-1&q=%00" } else { "" };
        let send = |body: String| {
            let uri = format!("/api{path}{query}");
            let token = if non_admin { common::recovery_token(caller) } else { admin_token(caller) };
            async move {
                let request = Request::builder().method(method).uri(uri).header("host", "mail.test").header("origin", "http://mail.test").header("content-type", "application/json").header("x-request-id", "gofree-admin5-oracle").header("authorization", format!("Bearer {token}"));
                Ok::<_, BoxError>(common::send(address, request.body(common::full(body))?).await)
            }
        };
        if label == "repeat" {
            let first = send(body.clone()).await?;
            let status = first.status().as_u16();
            let data = common::body_bytes(first).await;
            if recording && status != 200 {
                return Err(format!("initial {action}: {status} {data:?}").into());
            }
        }
        let before = snapshot(&owner).await?;
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
        let mut alerts = db.listen("admin:alert").await?;
        let response = send(body.clone()).await?;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        let after = snapshot(&owner).await?;
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
        let wanted = match (action, label) {
            (_, "denied") => 403,
            ("activate", "huge") | ("policy-put", "huge" | "missing-role") => 500,
            ("activate", "approval") => 500,
            ("activate", "foreign" | "not-eligible" | "unknown-role" | "toggle-off" | "justification-required" | "blank-justification" | "empty-justification" | "bad-json" | "zero" | "negative" | "required" | "typed" | "fractional" | "null-body" | "oversize" | "bad-id") => 400,
            ("policy-put", "invalid" | "zero" | "negative" | "required" | "typed" | "bad-id") => 400,
            ("policy-get" | "deactivate", "bad-id") => 400,
            _ => 200,
        };
        if recording && status != wanted {
            return Err(format!("Go {action}/{label}: expected {wanted}, got {status}: {raw}").into());
        }
        // The activation instant is "now plus the window"; the committed minutes are in the effects.
        let mut text = names(&raw);
        if action == "activate" {
            if let Some(start) = text.find("\"activatedUntil\":\"") {
                let from = start + "\"activatedUntil\":\"".len();
                if let Some(len) = text[from..].find('"') {
                    text.replace_range(from..from + len, "<timestamp>");
                }
            }
        }
        if let Some(date) = headers.get_mut("date") { *date = json!(["<timestamp>"]); }
        if let Some(length) = headers.get_mut("content-length") {
            if length[0] != raw.len().to_string() { return Err("bad wire length".into()); }
            *length = json!([text.len().to_string()]);
        }
        let (before, after) = (masked(before, &users, &names)?, masked(after, &users, &names)?);
        let effects = json!([{"table":"admin_role_assignments","before":before,"after":after}]);
        let mut request = json!({"method":method,"path":pattern,"external_path":format!("/api{pattern}")});
        if !recorded_body.is_empty() { request["body"] = json!(names(&recorded_body)); }
        if non_admin { request["token"] = json!("non-admin"); }
        let observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":notify});
        let _ = approval_start;
        if !recording {
            let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F01\"} 0") {
                return Err(format!("F01 replay forwarded to Go: {metrics}").into());
            }
        }
        server.abort();
        let name = format!("{action}-{label}");
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/admin-identity/goldens");
        std::fs::create_dir_all(&dir)?;
        let file = dir.join(format!("sod-{name}.json"));
        let row_file = dir.join(format!("sod-{name}-row-effects.json"));
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
    if let Some(table) = trigger {
        owner
            .batch_execute(&format!("DROP TRIGGER {schema} ON {table}"))
            .await?;
    }
    if fault.is_some() {
        owner
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
    }
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='rbac.jit'",
            &[&jit_toggle],
        )
        .await?;
    owner
        .execute(
            "UPDATE feature_toggles SET enabled=$1 WHERE key='approval.rbac'",
            &[&approval_toggle],
        )
        .await?;
    for (key, value) in &originals {
        owner
            .execute(
                "UPDATE system_config SET value=$2::text::jsonb WHERE key=$1",
                &[key, &value.to_string()],
            )
            .await?;
    }
    owner
        .execute(
            "DELETE FROM approval_requests WHERE consumer_type='rbac.jit_activation' AND id>$1",
            &[&approval_start],
        )
        .await
        .ok();
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F01' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    let ids: Vec<i64> = ROLES.to_vec();
    owner.execute("UPDATE admin_role_assignments SET expires_at=now()-interval '1 hour' WHERE role_group_id=ANY($1)", &[&ids]).await?;
    owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE role_group_id=ANY($1)",
            &[&ids],
        )
        .await?;
    owner
        .execute(
            "DELETE FROM admin_role_activation_policy WHERE role_group_id=ANY($1)",
            &[&ids],
        )
        .await?;
    owner
        .execute("DELETE FROM admin_role_groups WHERE id=ANY($1)", &[&ids])
        .await?;
    for account in [&a, &b, &t] {
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
