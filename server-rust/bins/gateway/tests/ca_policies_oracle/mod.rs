//! F03 slice `policies` frozen-Go oracle: HTTP wire, committed rows, audit and notifications.
//! Record mode runs the covered Go binary behind the front door; replay mode serves the same
//! requests from Rust with no Go upstream.
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    conditional_access::ConditionalAccessRoute, Body, BoxFuture, Config, Gateway, Intercept,
    RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

struct Probe {
    inner: ConditionalAccessRoute<setjoin_gateway::jmap::jwks::Jwks>,
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
        "list" => ("GET", "/admin/conditional-access/policies"),
        "create" => ("POST", "/admin/conditional-access/policies"),
        "update" => ("PUT", "/admin/conditional-access/policies/{id}"),
        "delete" => ("DELETE", "/admin/conditional-access/policies/{id}"),
        "restore" => ("POST", "/admin/conditional-access/policies/{id}/restore"),
        "promote" => ("POST", "/admin/conditional-access/policies/{id}/promote"),
        "restore-from-audit" => (
            "POST",
            "/admin/conditional-access/policies/restore-from-audit",
        ),
        "reorder" => ("POST", "/admin/conditional-access/policies/reorder"),
        _ => panic!("unknown F03 policies action {action}"),
    }
}

// Fixed ids keep the goldens free of run-specific numbers.
const ALPHA: i64 = 940001; // off, global, allow
const BETA: i64 = 940002; // report_only, user scope, block (has would-block sign-ins)
const GAMMA: i64 = 940003; // tombstone, off
const DELTA: i64 = 940004; // on, allow, priority 9404
const EPSILON: i64 = 940005; // tombstone, on, priority 9404 (restore clashes with DELTA)
const ZETA: i64 = 940006; // report_only, global block, no exclusions (promote locks out)
const ETA: i64 = 940007; // report_only, user scope, block, no sign-ins
const MISSING: i64 = 99999999;
const SOURCE: i64 = 940100; // policy snapshotted in the audit fixture row

fn timestamp_like(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() >= 19
        && b[4] == b'-'
        && b[7] == b'-'
        && (b[10] == b'T' || b[10] == b' ')
        && b[13] == b':'
}

/// Mask run-specific identities by the key that names them.
fn mask(v: &mut Value, users: &[(i64, &str)], new_policies: &[i64]) {
    match v {
        Value::Object(map) => {
            for (k, x) in map.iter_mut() {
                if let Some(n) = x.as_i64() {
                    let user = matches!(k.as_str(), "user_id" | "actor_id" | "actor");
                    let policy = matches!(k.as_str(), "id" | "target_id" | "policy_id")
                        && new_policies.contains(&n);
                    if user {
                        if let Some((_, name)) = users.iter().find(|(i, _)| *i == n) {
                            *x = json!(name);
                        }
                    } else if policy {
                        *x = json!("<new-policy>");
                    }
                } else {
                    mask(x, users, new_policies);
                }
            }
        }
        Value::Array(xs) => xs.iter_mut().for_each(|x| mask(x, users, new_policies)),
        Value::String(s) => {
            if timestamp_like(s) && !s.starts_with("2026-10-01") {
                *s = "<timestamp>".into();
            }
        }
        _ => {}
    }
}
fn masked(
    mut v: Value,
    users: &[(i64, &str)],
    new_policies: &[i64],
    names: &dyn Fn(&str) -> String,
) -> Result<Value, BoxError> {
    v = serde_json::from_str(&names(&v.to_string()))?;
    mask(&mut v, users, new_policies);
    Ok(v)
}

/// Quoted timestamp strings that are not fixture times become `<timestamp>`; a response body
/// is otherwise kept byte for byte.
fn scrub_timestamps(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find('"') {
        out.push_str(&rest[..=start]);
        rest = &rest[start + 1..];
        let mut end = 0;
        let bytes = rest.as_bytes();
        while end < bytes.len() {
            if bytes[end] == b'\\' {
                end += 2;
                continue;
            }
            if bytes[end] == b'"' {
                break;
            }
            end += 1;
        }
        let end = end.min(bytes.len());
        let inner = &rest[..end];
        if timestamp_like(inner) && !inner.starts_with("2026-10-01") {
            out.push_str("<timestamp>");
        } else {
            out.push_str(inner);
        }
        if end < rest.len() {
            out.push('"');
            rest = &rest[end + 1..];
        } else {
            rest = "";
        }
    }
    out.push_str(rest);
    out
}

async fn rows(c: &tokio_postgres::Client, sql: &str) -> Result<Vec<Value>, BoxError> {
    c.query(sql, &[])
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
        .collect()
}
async fn snapshot(c: &tokio_postgres::Client) -> Result<Value, BoxError> {
    Ok(json!({
        "policies": rows(c, "SELECT (to_jsonb(p) - 'enabled')::text FROM conditional_access_policies p ORDER BY priority, name, id").await?,
    }))
}

/// Cases share fixed fixture keys and global windows (audit id, receipts), so they run one at a time.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

pub async fn run(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run_inner(action, kind, fault).await
}

fn wanted(action: &str, label: &str) -> u16 {
    match (action, label) {
        (_, "denied") => 403,
        ("list", _) => 200,
        (
            "create",
            "success" | "foreign" | "repeat" | "priority" | "session" | "folded" | "default-state",
        ) => 201,
        ("create", "lockout") => 409,
        ("create", "dup-on" | "big-priority" | "null-docs") => 500,
        ("create", _) => 400,
        ("update", "success" | "foreign" | "repeat" | "session" | "folded") => 200,
        ("update", "missing") => 404,
        ("update", "lockout") => 409,
        ("update", "big-priority") => 500,
        ("update", _) => 400,
        ("delete" | "restore", "success" | "foreign" | "repeat") => 204,
        ("restore", "conflict") => 409,
        ("delete" | "restore", "missing") => 404,
        ("delete" | "restore", _) => 400,
        ("promote", "preview-blocked" | "lockout") => 409,
        ("promote", "missing-confirm") => 404,
        ("promote", "invalid" | "bad-json" | "empty-body") => 400,
        ("promote", _) => 200,
        ("restore-from-audit", "missing-audit") => 404,
        ("restore-from-audit", "invalid" | "required" | "bad-type") => 400,
        ("restore-from-audit", _) => 200,
        ("reorder", "success" | "foreign" | "repeat" | "missing-ids" | "null-element") => 204,
        ("reorder", _) => 400,
        _ => 200,
    }
}

async fn run_inner(action: &str, kind: &str, fault: Option<&str>) -> Result<(), BoxError> {
    let mutant = kind.ends_with("-status-mutant");
    let label = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let Some(db) = Db::for_case("ca1-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    let a = fixture::account(&owner, "ca1-admin").await?;
    let b = fixture::account(&owner, "ca1-other").await?;
    let t = fixture::account(&owner, "ca1-target").await?;
    let email_of = |id: i64| {
        let owner = &owner;
        async move {
            Ok::<String, BoxError>(
                owner
                    .query_one("SELECT email FROM users WHERE id=$1", &[&id])
                    .await?
                    .get(0),
            )
        }
    };
    let emails = [
        (email_of(a.user).await?, "admin@host-a.test"),
        (email_of(b.user).await?, "other@host-b.test"),
        (email_of(t.user).await?, "target@host-t.test"),
    ];
    let names = |text: &str| {
        let mut out = text.to_owned();
        for (email, name) in &emails {
            out = out.replace(email.as_str(), name);
        }
        out
    };
    // Grant shapes: global admin, scoped to the other domain, or no permission.
    let (permissions, scope): (Vec<&str>, Option<i64>) = match label {
        "denied" => (vec!["users.read"], None),
        "foreign" => (
            vec!["access.policy_read", "access.policy_write"],
            Some(b.domain),
        ),
        _ => (vec!["access.policy_read", "access.policy_write"], None),
    };
    let role: i64 = owner
        .query_one(
            "INSERT INTO admin_role_groups(name,permissions,domain_scope) VALUES($1,$2,$3) RETURNING id",
            &[&format!("ca1-{}", a.user), &permissions, &scope],
        )
        .await?
        .get(0);
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&a.user, &role],
        )
        .await?;
    // The seeded policies are set aside so lists and priorities are fixture-only.
    let aside: Vec<String> = owner
        .query(
            "SELECT to_jsonb(p)::text FROM conditional_access_policies p ORDER BY id",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get(0))
        .collect();
    owner
        .execute("DELETE FROM conditional_access_policies", &[])
        .await?;
    let insert = "INSERT INTO conditional_access_policies(id,priority,name,description,enabled,state,scope_type,scope_target,conditions,actions,exclude_users,exclude_groups,created_at,updated_at,deleted_at) VALUES($1,$2,$3,$4,false,$5,$6,$7,$8::text::jsonb,$9::text::jsonb,'[]','[]','2026-10-01T12:00:00Z'::text::timestamptz,'2026-10-01T12:00:00.5Z'::text::timestamptz,$10::text::timestamptz)";
    let none: Option<String> = None;
    let tomb = Some("2026-10-01T12:30:00Z".to_string());
    for (
        id,
        priority,
        name,
        description,
        state,
        scope_type,
        scope_target,
        conditions,
        actions,
        deleted,
    ) in [
        (
            ALPHA,
            9401i32,
            "ca1-alpha",
            "Alpha <policy> & co",
            "off",
            "global",
            "",
            r#"{"client_type":"imap"}"#,
            r#"{"action":"allow"}"#,
            &none,
        ),
        (
            BETA,
            9402,
            "ca1-beta",
            "",
            "report_only",
            "user",
            "9",
            r#"{"ip_reputation":"critical"}"#,
            r#"{"action":"block"}"#,
            &none,
        ),
        (
            GAMMA,
            9403,
            "ca1-gamma",
            "Gone",
            "off",
            "global",
            "",
            "{}",
            r#"{"action":"allow"}"#,
            &tomb,
        ),
        (
            DELTA,
            9404,
            "ca1-delta",
            "",
            "on",
            "global",
            "",
            "{}",
            r#"{"action":"allow"}"#,
            &none,
        ),
        (
            EPSILON,
            9404,
            "ca1-epsilon",
            "",
            "on",
            "global",
            "",
            "{}",
            r#"{"action":"allow"}"#,
            &tomb,
        ),
        (
            ZETA,
            9406,
            "ca1-zeta",
            "",
            "report_only",
            "global",
            "",
            "{}",
            r#"{"action":"block"}"#,
            &none,
        ),
        (
            ETA,
            9407,
            "ca1-eta",
            "",
            "report_only",
            "user",
            "9",
            "{}",
            r#"{"action":"block"}"#,
            &none,
        ),
    ] {
        owner
            .execute(
                insert,
                &[
                    &id,
                    &priority,
                    &name,
                    &description,
                    &state,
                    &scope_type,
                    &scope_target,
                    &conditions,
                    &actions,
                    deleted,
                ],
            )
            .await?;
    }
    // Would-block sign-ins for BETA: the acting admin and the target user.
    for (user, would) in [(a.user, "block"), (t.user, "block"), (a.user, "step_up")] {
        owner
            .execute(
                "INSERT INTO ca_signin_log(user_id,matched_policy_id,decision,would_decision,report_only) VALUES($1,$2,'allow',$3,true)",
                &[&user, &BETA, &would],
            )
            .await?;
    }
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    // A hard-deleted policy's audit snapshot, for restore-from-audit.
    owner
        .execute(
            "SELECT audit_write($1,'ca_policy_delete','conditional_access_policy',$2,$3::text::jsonb,NULL,NULL,NULL,'core')",
            &[
                &a.user,
                &SOURCE,
                &json!({"id":SOURCE,"priority":9498,"name":"ca1-audited","description":"from <audit>","state":"off","scope_type":"global","scope_target":"","conditions":{"client_type":"web"},"actions":{"action":"allow"},"exclude_users":[],"exclude_groups":[],"created_from_template":""}).to_string(),
            ],
        )
        .await?;
    let source_audit: i64 = owner
        .query_one(
            "SELECT max(id) FROM admin_audit_log WHERE id>$1",
            &[&audit_start],
        )
        .await?
        .get(0);
    let receipts = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F03'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    // Faults run real mutated database objects against the unchanged expectation.
    let schema = format!("gofree_ca1_fault_{}", a.user);
    let mut notify_def: Option<String> = None;
    match fault {
        Some("no-audit") => {
            owner.batch_execute(&format!("CREATE SCHEMA {schema};CREATE FUNCTION {schema}.fault() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF NEW.user_id={} AND NEW.action LIKE 'ca_policy_%' THEN RETURN NULL; END IF; RETURN NEW; END $fault$;CREATE TRIGGER {schema} BEFORE INSERT ON admin_audit_log FOR EACH ROW EXECUTE FUNCTION {schema}.fault();", a.user)).await?;
        }
        Some("no-tenant-filter") => {
            // Observational: an unfiltered read would surface this extra live policy.
            owner.execute("INSERT INTO conditional_access_policies(id,priority,name,enabled,state,created_at,updated_at) VALUES(940090,9490,'ca1-foreign',false,'off','2026-10-01T12:00:00Z','2026-10-01T12:00:00Z')", &[]).await?;
        }
        Some("no-notify") => {
            notify_def = Some(
                owner
                    .query_one(
                        "SELECT pg_get_functiondef('ca_notify_policy_change(text)'::regprocedure)",
                        &[],
                    )
                    .await?
                    .get(0),
            );
            owner.batch_execute("CREATE OR REPLACE FUNCTION ca_notify_policy_change(p_reason text) RETURNS void LANGUAGE sql AS 'SELECT'").await?;
        }
        Some("double-bump") => {
            owner.batch_execute(&format!("CREATE SCHEMA {schema};CREATE FUNCTION {schema}.fault() RETURNS trigger LANGUAGE plpgsql AS $fault$ BEGIN IF pg_trigger_depth()=1 THEN UPDATE conditional_access_policies SET description=description||'!' WHERE id=NEW.id; END IF; RETURN NULL; END $fault$;CREATE TRIGGER {schema} AFTER INSERT OR UPDATE ON conditional_access_policies FOR EACH ROW EXECUTE FUNCTION {schema}.fault();")).await?;
        }
        _ => {}
    }
    let users: Vec<(i64, &str)> = vec![
        (t.user, "<target>"),
        (a.user, "<admin>"),
        (b.user, "<other>"),
    ];
    let result = async {
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        let go = common::go_oracle::start_named(&db, s3, None, "gofree-ca1-http").await?;
        let recording = go.is_some();
        let exec = ScopedExecutor::from_dsn(db.app.as_deref().unwrap_or(&db.dsn), 4)
            .map_err(|e| e.0)?
            .with_audit_keys("22".repeat(32), String::new());
        let adapter = Probe {
            inner: ConditionalAccessRoute { exec, worker: None, keys: Arc::new(common::recovery_keys()), issuer: "mailserver".into() },
            changed_status: mutant,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F03" && r["slice"] == "policies" {
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
        // The policy a case targets (path id); `{id}` routes only.
        let target: String = match (action, label) {
            (_, "invalid") if action != "restore-from-audit" && action != "create" && action != "reorder" && action != "list" => "bad".into(),
            (_, "missing" | "missing-confirm") => MISSING.to_string(),
            ("update", _) => ALPHA.to_string(),
            ("delete", _) => ALPHA.to_string(),
            ("restore", "conflict") => EPSILON.to_string(),
            ("restore", "repeat") => ALPHA.to_string(),
            ("restore", _) => GAMMA.to_string(),
            ("promote", "preview-clean") => ETA.to_string(),
            ("promote", "lockout") => ZETA.to_string(),
            ("promote", "already-on") => DELTA.to_string(),
            ("promote", _) => BETA.to_string(),
            _ => ALPHA.to_string(),
        };
        let mut path = pattern.replace("{id}", &target);
        if action == "list" {
            match label {
                "deleted" => path.push_str("?include_deleted=1"),
                "invalid" => path.push_str("?include_deleted=yes"),
                "zero" => path.push_str("?include_deleted=0"),
                _ => {}
            }
        }
        let same = |text: &str| (text.to_string(), text.to_string());
        let audit_text = source_audit.to_string();
        let (body, recorded_body): (String, String) = match (action, label) {
            ("create" | "update", l) => match l {
                "invalid" | "bad-json" => same("{\"name\":"),
                "empty" | "empty-name" => same(if action == "update" { "{}" } else { "{\"name\":\"\"}" }),
                "bad-key" => same("{\"name\":\"ca1-x\",\"conditions\":{\"auth_strength\":\"x\"}}"),
                "bad-enum" => same("{\"name\":\"ca1-x\",\"conditions\":{\"client_type\":\"browser\"}}"),
                "bad-int" => same("{\"name\":\"ca1-x\",\"conditions\":{\"user_group\":1.5}}"),
                "bad-time" => same("{\"name\":\"ca1-x\",\"conditions\":{\"time_of_day\":{\"start\":\"9am\",\"end\":\"10:00\"}}}"),
                "bad-grant" => same("{\"name\":\"ca1-x\",\"actions\":{\"action\":\"nope\"}}"),
                "bad-conditions" => same("{\"name\":\"ca1-x\",\"conditions\":[]}"),
                "bad-actions" => same("{\"name\":\"ca1-x\",\"actions\":\"x\"}"),
                "bad-priority" => same("{\"name\":\"ca1-x\",\"priority\":\"high\"}"),
                "big-priority" => same("{\"name\":\"ca1-x\",\"priority\":99999999999}"),
                "lockout" => same("{\"name\":\"ca1-lock\",\"state\":\"on\",\"scope_type\":\"global\",\"actions\":{\"action\":\"block\"}}"),
                "session" => same("{\"name\":\"ca1-session\",\"session_control\":{\"cae\":\"enabled\"}}"),
                "bad-session" => same("{\"name\":\"ca1-session\",\"session_control\":{\"bogus\":1}}"),
                "bad-scope" => same("{\"name\":\"ca1-x\",\"scope_type\":\"bogus\"}"),
                "bad-state" => same("{\"name\":\"ca1-x\",\"state\":\"bogus\"}"),
                "dup-on" => same("{\"name\":\"ca1-dup\",\"state\":\"on\",\"priority\":9404}"),
                "null-docs" => same("{\"name\":\"ca1-null\",\"conditions\":null,\"actions\":null}"),
                "folded" => same("{\"NAME\":\"ca1-folded\",\"Description\":null,\"STATE\":\"off\",\"Conditions\":{\"client_type\":\"web\"}} trailing"),
                "default-state" => same("{\"name\":\"ca1-default\"}"),
                "priority" => same("{\"name\":\"ca1-prio\",\"priority\":9500,\"state\":\"report_only\"}"),
                _ => same("{\"name\":\"ca1-new\",\"description\":\"made <here> & now\",\"state\":\"report_only\",\"scope_type\":\"global\",\"conditions\":{\"client_type\":\"web\"},\"actions\":{\"operator\":\"all\",\"grants\":[{\"type\":\"allow\"}]},\"exclude_users\":[],\"exclude_groups\":[]}"),
            },
            ("promote", l) => match l {
                "bad-json" => same("{"),
                "empty-body" => same(""),
                "success" | "repeat" | "lockout" | "already-on" | "missing-confirm" | "foreign" => same("{\"confirm\":true}"),
                "folded" => same("{\"CONFIRM\":true} trailing"),
                _ => same("{}"),
            },
            ("restore-from-audit", l) => match l {
                "invalid" => same("{\"audit_id\":"),
                "required" => same("{}"),
                "bad-type" => same("{\"audit_id\":\"x\"}"),
                "missing-audit" => same("{\"audit_id\":99999999}"),
                "folded" => (format!("{{\"AUDIT_ID\":{audit_text}}} trailing"), "{\"AUDIT_ID\":\"<source-audit>\"} trailing".to_string()),
                _ => (format!("{{\"audit_id\":{audit_text}}}"), "{\"audit_id\":\"<source-audit>\"}".to_string()),
            },
            ("reorder", l) => match l {
                "invalid" => same("{}"),
                "bad-element" => same("[\"x\"]"),
                "empty" => same("[]"),
                "null" => same("null"),
                "missing-ids" => same("[99999999]"),
                "null-element" => same(&format!("[null,{ALPHA}]")),
                _ => same(&format!("[{DELTA},{ALPHA},{BETA}]")),
            },
            _ => (String::new(), String::new()),
        };
        let send = |body: String| {
            let uri = format!("/api{path}");
            let token = admin_token(a.user);
            async move {
                let request = Request::builder().method(method).uri(uri).header("host", "mail.test").header("origin", "http://mail.test").header("content-type", "application/json").header("x-request-id", "gofree-ca1-oracle").header("authorization", format!("Bearer {token}"));
                Ok::<_, BoxError>(common::send(address, request.body(common::full(body))?).await)
            }
        };
        if label == "repeat" {
            let first = send(body.clone()).await?;
            let status = first.status().as_u16();
            let data = common::body_bytes(first).await;
            if recording && !matches!(status, 200 | 201 | 204) {
                return Err(format!("initial {action}: {status} {data:?}").into());
            }
        }
        let before = snapshot(&owner).await?;
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
        let mut changes = db.listen("conditional_access").await?;
        let response = send(body.clone()).await?;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        let after = snapshot(&owner).await?;
        let new_policies: Vec<i64> = owner.query("SELECT id FROM conditional_access_policies WHERE id NOT BETWEEN 940001 AND 940099", &[]).await?.iter().map(|r| r.get(0)).collect();
        let mut audit: Vec<Value> = owner.query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&last]).await?.iter().map(|r| serde_json::from_str(&r.get::<_, String>(0))).collect::<Result<_, _>>()?;
        let source_text = format!("audit_log id {source_audit}");
        let audit_names = |text: &str| names(text).replace(&source_text, "audit_log id <source-audit>");
        for row in &mut audit {
            if row["id"].as_i64().is_none_or(|n| n <= 0) { return Err("invalid audit id".into()); }
            row["id"] = json!("<audit>");
            for key in ["checksum", "prev_checksum"] {
                if row[key].as_str().is_some_and(|s| !s.is_empty()) { row[key] = json!("<checksum>"); }
            }
            *row = masked(row.clone(), &users, &new_policies, &audit_names)?;
        }
        let mut notify = vec![];
        for event in changes.drain(&owner).await? {
            let payload: Value = serde_json::from_str(&event)?;
            notify.push(json!({"channel":"conditional_access","payload":masked(payload, &users, &new_policies, &names)?}));
        }
        let expected = wanted(action, label);
        if recording && status != expected {
            return Err(format!("Go {action}/{label}: expected {expected}, got {status}: {raw}").into());
        }
        // Normalize identities and times that differ per run; fixtures are otherwise deterministic.
        let mut text = scrub_timestamps(&names(&raw));
        for n in &new_policies {
            text = text.replace(&format!("\"id\": {n},"), "\"id\": \"<new-policy>\",").replace(&format!("{{\"id\":{n}}}"), "{\"id\":\"<new-policy>\"}");
        }
        for (id, name) in &users {
            let name = name.trim_matches(['<', '>']);
            for end in [",", "}"] {
                text = text.replace(&format!("\"id\":{id}{end}"), &format!("\"id\":\"{name}\"{end}"));
            }
        }
        if let Some(date) = headers.get_mut("date") { *date = json!(["<timestamp>"]); }
        if let Some(length) = headers.get_mut("content-length") {
            if length[0] != raw.len().to_string() { return Err("bad wire length".into()); }
            *length = json!([text.len().to_string()]);
        }
        let (before, after) = (masked(before, &users, &new_policies, &names)?, masked(after, &users, &new_policies, &names)?);
        let effects = json!([{"table":"conditional_access_policies","before":before,"after":after}]);
        let mut request = json!({"method":method,"path":pattern,"external_path":format!("/api{pattern}")});
        if !recorded_body.is_empty() { request["body"] = json!(names(&recorded_body)); }
        let observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":notify});
        if !recording {
            let metrics = common::send(address, Request::get("/_gateway/metrics").body(common::full(""))?).await;
            let metrics = String::from_utf8(common::body_bytes(metrics).await.to_vec())?;
            if !metrics.lines().any(|l| l == "setjoin_gateway_proxied_to_go_by_family_total{family=\"F03\"} 0") {
                return Err(format!("F03 replay forwarded to Go: {metrics}").into());
            }
        }
        server.abort();
        let name = format!("{action}-{label}");
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/conformance/conditional-access/goldens");
        std::fs::create_dir_all(&dir)?;
        let file = dir.join(format!("policies-{name}.json"));
        let row_file = dir.join(format!("policies-{name}-row-effects.json"));
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
    if fault == Some("no-audit") {
        owner
            .batch_execute(&format!("DROP TRIGGER {schema} ON admin_audit_log"))
            .await?;
    }
    if fault == Some("double-bump") {
        owner
            .batch_execute(&format!(
                "DROP TRIGGER {schema} ON conditional_access_policies"
            ))
            .await?;
    }
    if matches!(fault, Some("no-audit" | "double-bump")) {
        owner
            .batch_execute(&format!("DROP SCHEMA {schema} CASCADE"))
            .await?;
    }
    if let Some(definition) = notify_def {
        owner.batch_execute(&definition).await?;
    }
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F03' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    owner
        .execute("DELETE FROM conditional_access_policies", &[])
        .await?;
    for row in &aside {
        owner
            .execute(
                "INSERT INTO conditional_access_policies SELECT * FROM jsonb_populate_record(null::conditional_access_policies, $1::text::jsonb)",
                &[row],
            )
            .await?;
    }
    owner.execute("UPDATE admin_role_assignments SET expires_at=now()-interval '1 hour' WHERE role_group_id=$1", &[&role]).await?;
    owner
        .execute(
            "DELETE FROM admin_role_assignments WHERE role_group_id=$1",
            &[&role],
        )
        .await?;
    owner
        .execute("DELETE FROM admin_role_groups WHERE id=$1", &[&role])
        .await?;
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM ca_signin_log WHERE matched_policy_id={BETA}; COMMIT;")).await?;
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
