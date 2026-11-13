//! F01 slice `idv2-upgrade`: frozen-Go oracle for the identity v2 upgrade, doctor and
//! diagnostics routes. Record mode runs the covered Go binary behind the front door;
//! replay serves the same requests from Rust with no Go upstream. An observation is the
//! wire, the identity rows the route may change (before and after), the audit rows and
//! the notifications.
//!
//! Parallel safety: cases share the fixed `admin9-*` sources, the F01 receipts, the
//! identity feature toggles and the admin audit window, so each holds `SERIAL`.
use crate::common::{self, BoxError};
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_conformance::{fixture, golden, harness::Db};
use setjoin_gateway::{
    admin_identity_v2_upgrade::AdminIdentityV2UpgradeRoute, Body, BoxFuture, Config, Gateway,
    Intercept, RequestContext, RouteTable, TrustedProxies,
};
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct Probe {
    inner: AdminIdentityV2UpgradeRoute<setjoin_gateway::jmap::jwks::Jwks>,
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

fn secret_env(name: &str) -> Option<String> {
    (name == "DB_ENCRYPTION_KEY").then(|| "22".repeat(32))
}

const PERM: i64 = 960001;
const ALPHA: &str = "admin9-alpha";
const OIDC: &str = "admin9-oidc";
const J_DONE: &str = "96100000-0000-4000-8000-000000000001";
const J_QUEUED: &str = "96100000-0000-4000-8000-000000000002";
const J_OTHER: &str = "96100000-0000-4000-8000-000000000003";
const J_BACKFILL: &str = "96100000-0000-4000-8000-000000000004";
const J_EXPIRED: &str = "96100000-0000-4000-8000-000000000005";
const J_PAST: &str = "96100000-0000-4000-8000-000000000006";
const J_MISSING: &str = "96100000-0000-4000-8000-0000000000ff";
const IDEM: &str = "96300000-0000-4000-8000-000000000001";
const IDEM_OTHER: &str = "96300000-0000-4000-8000-000000000002";
const REASON: &str = "admin9 reason <&>";
const MISSING_TRANSITION: &str = "96400000-0000-4000-8000-000000000001";

/// Actions whose routes can change rows (they carry row-effect goldens and a repeat case).
pub fn mutator(action: &str) -> bool {
    matches!(
        action,
        "backfill" | "canary" | "rollback" | "diag-create" | "diag-download" | "diag-delete"
    )
}

pub fn route(action: &str) -> (&'static str, &'static str) {
    match action {
        "status" => ("GET", "/admin/identity/v2/upgrade/status"),
        "preflight" => ("POST", "/admin/identity/v2/upgrade/preflight"),
        "backfill" => ("POST", "/admin/identity/v2/upgrade/backfill"),
        "shadow" => ("GET", "/admin/identity/v2/upgrade/shadow"),
        "canary" => ("POST", "/admin/identity/v2/upgrade/canary"),
        "rollback" => ("POST", "/admin/identity/v2/upgrade/rollback"),
        "retirement" => ("GET", "/admin/identity/v2/upgrade/retirement-check"),
        "doctor" => ("GET", "/admin/identity/v2/doctor"),
        "diag-create" => ("POST", "/admin/identity/v2/diagnostics"),
        "diag-status" => ("GET", "/admin/identity/v2/diagnostics/{id}"),
        "diag-download" => ("GET", "/admin/identity/v2/diagnostics/{id}/download"),
        "diag-delete" => ("DELETE", "/admin/identity/v2/diagnostics/{id}"),
        other => panic!("unknown idv2-upgrade action {other}"),
    }
}

fn is_diag(action: &str) -> bool {
    action.starts_with("diag-")
}

/// Permissions of the governing role for a case.
fn permissions(action: &str, label: &str) -> Vec<&'static str> {
    match label {
        "denied" => return vec!["users.read"],
        "only-upgrade" => return vec!["system.upgrade"],
        "only-identity" => return vec!["identity.write"],
        "backfill-job" => return vec!["audit.export", "system.upgrade", "identity.write"],
        _ => {}
    }
    if is_diag(action) {
        vec!["audit.export"]
    } else if action == "doctor" {
        vec!["identity.write"]
    } else {
        vec!["system.upgrade", "identity.write"]
    }
}

pub struct Plan {
    pub method: &'static str,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub shown_body: String,
    pub repeat: bool,
    pub wanted: u16,
}

fn timestamp_like(s: &str) -> bool {
    let b = s.as_bytes();
    s.len() >= 19
        && b[4] == b'-'
        && b[7] == b'-'
        && (b[10] == b'T' || b[10] == b' ')
        && b[13] == b':'
}

/// Every uuid that is not a fixture id (those are `96xxxxxx-0000-4000-8000-...`) is
/// issued per run.
fn mask_uuids(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < b.len() {
        let window = text.get(i..i + 36);
        let uuid = window.is_some_and(|w| {
            w.bytes().enumerate().all(|(k, c)| {
                if [8, 13, 18, 23].contains(&k) {
                    c == b'-'
                } else {
                    c.is_ascii_hexdigit()
                }
            })
        });
        if uuid {
            let w = window.unwrap();
            let fixture = w.starts_with("96") && w[8..].starts_with("-0000-4000-8000-");
            out.push_str(if fixture { w } else { "<uuid>" });
            i += 36;
        } else {
            let ch = text[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

/// Bare JSON numbers (reducer counts over the whole database) become `"<n>"`; strings
/// are left alone.
fn mask_numbers(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let (mut in_string, mut escaped) = (false, false);
    let mut previous = ' ';
    while let Some(ch) = chars.next() {
        if in_string {
            out.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            previous = ch;
            continue;
        }
        if ch == '"' {
            in_string = true;
            out.push(ch);
        } else if (ch.is_ascii_digit() || ch == '-')
            && matches!(previous, ':' | '[' | ',' | ' ')
            && (ch != '-' || chars.peek().is_some_and(char::is_ascii_digit))
        {
            while chars
                .peek()
                .is_some_and(|c| c.is_ascii_digit() || matches!(c, '.' | 'e' | 'E' | '+' | '-'))
            {
                chars.next();
            }
            out.push_str("\"<n>\"");
        } else {
            out.push(ch);
        }
        previous = ch;
    }
    out
}

/// Instants taken from `now()` differ per run; the fixtures use 2026-10-0x and 2031.
fn scrub_instants(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < b.len() {
        let looks = i + 19 <= b.len()
            && b[i..i + 4].iter().all(u8::is_ascii_digit)
            && b[i + 4] == b'-'
            && b[i + 7] == b'-'
            && b[i + 10] == b'T'
            && b[i + 13] == b':'
            && b[i + 16] == b':'
            && text.is_char_boundary(i);
        if looks {
            let mut end = i + 19;
            while end < b.len()
                && (b[end].is_ascii_digit() || matches!(b[end], b'.' | b'Z' | b'+' | b'-' | b':'))
            {
                end += 1;
            }
            let stamp = &text[i..end];
            if stamp.starts_with("2026-10-0") || stamp.starts_with("2031-") {
                out.push_str(stamp);
            } else {
                out.push_str("<timestamp>");
            }
            i = end;
        } else {
            let ch = text[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    out
}

fn mask(v: &mut Value, users: &[(i64, &str)]) {
    match v {
        Value::Object(map) => {
            for (k, x) in map.iter_mut() {
                if let Some(n) = x.as_i64() {
                    let user = matches!(
                        k.as_str(),
                        "user_id" | "actor_id" | "actor" | "actor_user_id" | "updated_by"
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
            if timestamp_like(s) {
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
    v = serde_json::from_str(&mask_uuids(&names(&v.to_string())))?;
    mask(&mut v, users);
    Ok(v)
}

async fn clean(owner: &tokio_postgres::Client) -> Result<(), BoxError> {
    owner
        .batch_execute(
            "BEGIN; SET LOCAL session_replication_role=replica; \
             DELETE FROM identity_jobs WHERE actor_user_id IN (SELECT id FROM users WHERE email LIKE 'admin9-%'); \
             DELETE FROM identity_read_cohort WHERE source_id IN (SELECT id FROM identity_sources WHERE source_key LIKE 'admin9-%'); \
             DELETE FROM identity_link_events WHERE actor_user_id IN (SELECT id FROM users WHERE email LIKE 'admin9-%') \
                OR source_id IN (SELECT id FROM identity_sources WHERE source_key LIKE 'admin9-%'); \
             DELETE FROM identity_sources WHERE source_key LIKE 'admin9-%'; \
             DELETE FROM backup_runs WHERE error_log='[\"admin9\"]'::jsonb; \
             UPDATE audit_policy SET reason_required_areas = array_remove(array_remove(reason_required_areas,'identity'),'audit') WHERE id=1; \
             DELETE FROM admin_role_assignments WHERE role_group_id=960001; DELETE FROM admin_role_groups WHERE id=960001; COMMIT;",
        )
        .await?;
    Ok(())
}

async fn rows(c: &tokio_postgres::Client, sql: &str) -> Result<Vec<Value>, BoxError> {
    c.query(sql, &[])
        .await?
        .iter()
        .map(|r| serde_json::from_str(&r.get::<_, String>(0)).map_err(Into::into))
        .collect()
}

/// Every row a route of the slice can change.
async fn snapshot(c: &tokio_postgres::Client) -> Result<Value, BoxError> {
    Ok(json!({
        "toggles": rows(c, "SELECT jsonb_build_object('key',key,'enabled',enabled)::text FROM feature_toggles WHERE key IN ('feature.identity_model_v2','feature.identity_normalized_reads','feature.identity_transitions') ORDER BY key").await?,
        "sources": rows(c, "SELECT jsonb_build_object('key',source_key,'state',state,'read_mode',read_mode,'generation',generation,'updated_by',updated_by)::text FROM identity_sources WHERE source_key LIKE 'admin9-%' ORDER BY source_key").await?,
        "cohort": rows(c, "SELECT jsonb_build_object('source',s.source_key,'users',count(*))::text FROM identity_read_cohort r JOIN identity_sources s ON s.id=r.source_id WHERE s.source_key LIKE 'admin9-%' GROUP BY s.source_key ORDER BY s.source_key").await?,
        "events": rows(c, "SELECT jsonb_build_object('action',e.action,'reason',e.reason,'actor_user_id',e.actor_user_id,'source',(SELECT source_key FROM identity_sources s WHERE s.id=e.source_id),'metadata',e.metadata)::text FROM identity_link_events e WHERE e.actor_user_id IN (SELECT id FROM users WHERE email LIKE 'admin9-%') ORDER BY e.id").await?,
        "jobs": rows(c, "SELECT jsonb_build_object('id',j.id,'kind',j.kind,'state',j.state,'actor_user_id',j.actor_user_id,'source',(SELECT source_key FROM identity_sources s WHERE s.id=j.source_id),'has_transition',j.transition_id IS NOT NULL,'request',j.request,'reason',j.reason,'has_artifact',j.artifact IS NOT NULL,'cancel_requested',j.cancel_requested,'next_action',j.next_action,'terminal',j.completed_at IS NOT NULL)::text FROM identity_jobs j WHERE j.actor_user_id IN (SELECT id FROM users WHERE email LIKE 'admin9-%') ORDER BY j.created_at, j.id").await?,
    }))
}

pub async fn run(action: &str, kind: &str) -> Result<(), BoxError> {
    let _serial = SERIAL.lock().await;
    run_inner(action, kind).await
}

/// The fixtures shared by every case: three accounts, the governing role, two sources
/// and the job rows.
/// Users in the database when the Go responses were recorded (see the padding in `run_inner`).
const RECORDED_PEOPLE: i64 = 6;

struct World {
    a: fixture::Account,
    b: fixture::Account,
    t: fixture::Account,
}

async fn fixtures(
    owner: &tokio_postgres::Client,
    action: &str,
    label: &str,
    w: &World,
) -> Result<(), BoxError> {
    let scope: Option<i64> = (label == "scoped").then_some(w.b.domain);
    let perms = permissions(action, label);
    owner
        .execute(
            "INSERT INTO admin_role_groups(id,name,permissions,domain_scope) OVERRIDING SYSTEM VALUE VALUES($1,'admin9-perm',$2,$3)",
            &[&PERM, &perms, &scope],
        )
        .await?;
    owner
        .execute(
            "INSERT INTO admin_role_assignments(user_id,role_group_id,granted_by) VALUES($1,$2,$1)",
            &[&w.a.user, &PERM],
        )
        .await?;
    for (key, name, kind, read_mode, generation) in [
        (ALPHA, "Admin9 Alpha", "ldap", "shadow", 3i64),
        (OIDC, "Admin9 OIDC", "oidc", "canary", 2),
    ] {
        owner
            .execute(
                "INSERT INTO identity_sources(source_key,display_name,kind,capabilities,state,generation,mapping_version,read_mode) \
                 VALUES($1,$2,$3,'{\"authenticate\": true, \"provision_lifecycle\": false, \"stable_immutable_subject\": true}'::jsonb,'active',$4,2,$5)",
                &[&key, &name, &kind, &generation, &read_mode],
            )
            .await?;
    }
    let alpha: i64 = owner
        .query_one(
            "SELECT id FROM identity_sources WHERE source_key=$1",
            &[&ALPHA],
        )
        .await?
        .get(0);
    let (a, b) = (w.a.user, w.b.user);
    for (n, (id, kind, state, actor, source, artifact, expires)) in [
        (
            J_DONE,
            "diagnostics",
            "completed",
            a,
            Some(alpha),
            true,
            "2031-01-05T00:00:00Z",
        ),
        (
            J_QUEUED,
            "diagnostics",
            "queued",
            a,
            Some(alpha),
            false,
            "2031-01-05T00:00:00Z",
        ),
        (
            J_OTHER,
            "diagnostics",
            "completed",
            b,
            Some(alpha),
            true,
            "2031-01-05T00:00:00Z",
        ),
        (
            J_BACKFILL,
            "upgrade_backfill",
            "completed",
            a,
            None,
            false,
            "2031-01-05T00:00:00Z",
        ),
        (
            J_EXPIRED,
            "diagnostics",
            "expired",
            a,
            Some(alpha),
            false,
            "2031-01-05T00:00:00Z",
        ),
        (
            J_PAST,
            "diagnostics",
            "completed",
            a,
            Some(alpha),
            true,
            "2026-10-03T00:00:00Z",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let large = label == "large-artifact";
        owner
            .execute(
                "INSERT INTO identity_jobs(id,kind,state,actor_user_id,source_id,snapshot_id,idempotency_key,request_digest,request,progress,next_action,reason,cancel_requested,created_at,updated_at,completed_at,expires_at,artifact,artifact_sha256,artifact_manifest) \
                 VALUES($1::text::uuid,$2,$3,$4,$5,$1::text::uuid,('96200000-0000-4000-8000-00000000000'||$6::text)::uuid,decode(repeat('0e',32),'hex'),'{\"sinceSeconds\": 60}'::jsonb,'{\"failed\": 0, \"processed\": 7}'::jsonb,'wait','seeded',false,\
                 CASE WHEN $7 LIKE '2031%' THEN '2031-01-01T00:00:00Z' ELSE '2026-10-01T00:00:00Z' END::timestamptz,CASE WHEN $7 LIKE '2031%' THEN '2031-01-01T00:00:00Z' ELSE '2026-10-01T00:00:00Z' END::timestamptz,CASE WHEN $3='queued' THEN NULL WHEN $7 LIKE '2031%' THEN '2031-01-02T00:00:00.5Z'::timestamptz ELSE '2026-10-02T00:00:00.5Z'::timestamptz END,$7::text::timestamptz,\
                 CASE WHEN $8 THEN convert_to(CASE WHEN $9 THEN repeat('admin9-bundle-',300) ELSE 'PK-admin9-bundle' END,'UTF8') END,\
                 CASE WHEN $8 THEN decode(repeat('0e',32),'hex') END,CASE WHEN $8 THEN '{\"manifestVersion\": \"7\"}'::jsonb END)",
                &[&id, &kind, &state, &actor, &source, &((n + 1).to_string()), &expires, &artifact, &large],
            )
            .await?;
    }
    Ok(())
}

fn plan(action: &str, label: &str, checksum: &str) -> Plan {
    let (method, pattern) = route(action);
    let json_headers = || -> Vec<(String, String)> {
        vec![
            ("content-type".into(), "application/json".into()),
            ("x-audit-reason".into(), REASON.into()),
        ]
    };
    let mut headers = if method == "GET" {
        vec![]
    } else {
        json_headers()
    };
    let mut query = String::new();
    let mut wanted: u16 = match action {
        "backfill" | "diag-create" if label != "plan" => 202,
        "diag-delete" => 204,
        _ => 200,
    };
    let mut repeat = false;
    let mut target = String::new();
    // Request body by action.
    let mut body = match action {
        "backfill" => match label {
            "plan" => json!({"action": "plan"}),
            _ => {
                json!({"action": "start", "preflightChecksum": checksum, "reason": REASON, "idempotencyKey": IDEM})
            }
        },
        "canary" => {
            json!({"sourceKey": OIDC, "expectedGeneration": "2", "enabled": false, "userIds": [], "reason": REASON})
        }
        "rollback" => json!({"readPath": "legacy", "reason": REASON}),
        "diag-create" => {
            json!({"sourceKey": ALPHA, "sinceSeconds": 300, "reason": REASON, "idempotencyKey": IDEM})
        }
        "diag-delete" => json!({"reason": REASON}),
        _ => Value::Null,
    };
    if action == "backfill" && label != "plan" {
        headers.push(("idempotency-key".into(), IDEM.into()));
    }
    if action == "diag-create" {
        headers.push(("idempotency-key".into(), IDEM.into()));
    }
    let set = |body: &mut Value, key: &str, value: Value| {
        if let Value::Object(map) = body {
            map.insert(key.to_owned(), value);
        }
    };
    let mut raw_body: Option<String> = None;
    let mut status = |w: u16| wanted = w;
    // Path / query targets.
    match action {
        "shadow" => {
            query = match label {
                "missing-source" => "?sourceKey=admin9-nothing".into(),
                "bad-key" => "?sourceKey=-bad".into(),
                "no-key" => String::new(),
                "oidc" => format!("?sourceKey={OIDC}"),
                "padded" => format!("?sourceKey=%20{ALPHA}%20"),
                _ => format!("?sourceKey={ALPHA}"),
            }
        }
        "doctor" => {
            query = match label {
                "with-source" => format!("?source={ALPHA}"),
                "missing-source" => "?source=admin9-nothing".into(),
                "bad-source" => "?source=-bad".into(),
                "padded" => format!("?source=%20{ALPHA}%20"),
                _ => String::new(),
            }
        }
        "diag-status" | "diag-download" | "diag-delete" => {
            target = match (action, label) {
                (_, "bad-id") => "bad".into(),
                (_, "nil-id") => "00000000-0000-0000-0000-000000000000".into(),
                (_, "missing") => J_MISSING.into(),
                (_, "other-actor") => J_OTHER.into(),
                (_, "running" | "not-ready") => J_QUEUED.into(),
                (_, "kind-denied" | "backfill-job") => J_BACKFILL.into(),
                (_, "expired") => J_EXPIRED.into(),
                (_, "past-expiry") => J_PAST.into(),
                (_, "uppercase") => J_DONE.to_uppercase(),
                _ => J_DONE.into(),
            }
        }
        _ => {}
    }
    // Per-action cases.
    match (action, label) {
        ("canary", "stale") => set(&mut body, "expectedGeneration", json!("9")),
        ("canary", "bad-generation") => set(&mut body, "expectedGeneration", json!("0")),
        ("canary", "text-generation") => set(&mut body, "expectedGeneration", json!("x")),
        ("canary", "missing-source") => set(&mut body, "sourceKey", json!("admin9-nothing")),
        ("canary", "bad-source-key") => set(&mut body, "sourceKey", json!("-bad")),
        ("canary", "if-match-ok") => headers.push(("if-match".into(), "\"2\"".into())),
        ("canary", "if-match-list") => headers.push(("if-match".into(), "\"7\", \"2\"".into())),
        ("canary", "if-match-bad") => {
            headers.push(("if-match".into(), "\"7\"".into()));
            status(412)
        }
        ("canary", "enable-ldap") => {
            set(&mut body, "sourceKey", json!(ALPHA));
            set(&mut body, "expectedGeneration", json!("3"));
            set(&mut body, "enabled", json!(true));
            set(&mut body, "userIds", json!(["1"]));
        }
        ("canary", "enable-unready") => {
            set(&mut body, "enabled", json!(true));
            set(&mut body, "userIds", json!(["1"]));
        }
        ("canary", "enable-no-users") => set(&mut body, "enabled", json!(true)),
        ("canary", "too-many-users") => {
            set(&mut body, "userIds", json!((1..=501).map(|n| n.to_string()).collect::<Vec<_>>()))
        }
        ("canary", "bad-user-id") => set(&mut body, "userIds", json!(["0"])),
        ("canary", "text-user-id") => set(&mut body, "userIds", json!(["x"])),
        ("canary", "null-user-id") => set(&mut body, "userIds", json!([null])),
        ("canary", "typed-user-id") => set(&mut body, "userIds", json!([5])),
        ("canary", "duplicate-users") => set(&mut body, "userIds", json!(["5", "5"])),
        ("canary", "typed-enabled") => set(&mut body, "enabled", json!("yes")),
        ("rollback", "bad-read-path") => set(&mut body, "readPath", json!("normalized")),
        ("rollback", "no-read-path") => body = json!({"reason": REASON}),
        ("diag-create", "transition") => {
            body = json!({"transitionId": MISSING_TRANSITION, "sinceSeconds": 300, "reason": REASON, "idempotencyKey": IDEM})
        }
        ("diag-create", "bad-transition-id") => {
            body = json!({"transitionId": "bad", "sinceSeconds": 300, "reason": REASON, "idempotencyKey": IDEM})
        }
        ("diag-create", "nil-transition-id") => {
            body = json!({"transitionId": "00000000-0000-0000-0000-000000000000", "sinceSeconds": 300, "reason": REASON, "idempotencyKey": IDEM})
        }
        ("diag-create", "both-scopes") => set(&mut body, "transitionId", json!(MISSING_TRANSITION)),
        ("diag-create", "no-scope") => body = json!({"sinceSeconds": 300, "reason": REASON, "idempotencyKey": IDEM}),
        ("diag-create", "missing-source") => set(&mut body, "sourceKey", json!("admin9-nothing")),
        ("diag-create", "bad-source-key") => set(&mut body, "sourceKey", json!("-bad")),
        ("diag-create", "zero-since") => set(&mut body, "sinceSeconds", json!(0)),
        ("diag-create", "long-since") => set(&mut body, "sinceSeconds", json!(86401)),
        ("diag-create", "max-since") => set(&mut body, "sinceSeconds", json!(86400)),
        ("diag-create", "float-since") => raw_body = Some(format!("{{\"sourceKey\":\"{ALPHA}\",\"sinceSeconds\":1.5,\"reason\":\"{REASON}\",\"idempotencyKey\":\"{IDEM}\"}}")),
        ("diag-create", "string-since") => set(&mut body, "sinceSeconds", json!("300")),
        ("diag-create", "idem-reuse") => {}
        ("diag-create", "header-key-only") => {
            set(&mut body, "idempotencyKey", json!(""));
        }
        ("diag-create", "body-key-only") => {
            headers.retain(|(k, _)| k != "idempotency-key");
        }
        ("diag-create", "no-key") => {
            headers.retain(|(k, _)| k != "idempotency-key");
            set(&mut body, "idempotencyKey", json!(""));
        }
        ("backfill", "bad-action") => set(&mut body, "action", json!("run")),
        ("backfill", "bad-checksum") => set(&mut body, "preflightChecksum", json!("ABC")),
        ("backfill", "no-checksum") => set(&mut body, "preflightChecksum", json!("")),
        ("backfill", "stale") => set(&mut body, "preflightChecksum", json!("0".repeat(64))),
        ("backfill", "header-key-only") => set(&mut body, "idempotencyKey", json!("")),
        ("backfill", "body-key-only") => headers.retain(|(k, _)| k != "idempotency-key"),
        ("backfill", "no-key") => {
            headers.retain(|(k, _)| k != "idempotency-key");
            set(&mut body, "idempotencyKey", json!(""));
        }
        _ => {}
    }
    // Generic label effects.
    let (mut shown, mut text) = (None::<String>, None::<String>);
    match label {
        "repeat" => repeat = true,
        "denied" | "only-upgrade" | "only-identity" | "scoped" => status(403),
        "etag-match" => headers.push(("if-none-match".into(), "*".into())),
        "bad-json" => text = Some("{\"reason\":".into()),
        "unknown-field" => {
            if let Value::Object(map) = &mut body {
                map.insert("extra".into(), json!(1));
            }
        }
        "typed" => set(&mut body, "reason", json!(5)),
        "trailing" => text = Some(format!("{} {{}}", body)),
        "null-body" => text = Some("null".into()),
        "oversize" => {
            text = Some(format!("{{\"reason\":\"{}\"}}", "x".repeat(70000)));
            shown = Some("{\"reason\":\"<70000 x>\"}".into());
            status(413)
        }
        "reason-mismatch" => {
            headers.retain(|(k, _)| k != "x-audit-reason");
            headers.push(("x-audit-reason".into(), "another reason".into()));
        }
        "reason-required" => headers.retain(|(k, _)| k != "x-audit-reason"),
        "no-reason-header" => headers.retain(|(k, _)| k != "x-audit-reason"),
        "key-mismatch" => {
            headers.retain(|(k, _)| k != "idempotency-key");
            headers.push(("idempotency-key".into(), IDEM_OTHER.into()));
        }
        "bad-key" if action != "shadow" => {
            headers.retain(|(k, _)| k != "idempotency-key");
            headers.push(("idempotency-key".into(), "not-a-uuid".into()));
            set(&mut body, "idempotencyKey", json!("not-a-uuid"));
        }
        _ => {}
    }
    let _ = &mut status;
    let wire = text.clone().or(raw_body).unwrap_or_else(|| {
        if body.is_null() {
            String::new()
        } else {
            body.to_string()
        }
    });
    let shown_body = shown.unwrap_or_else(|| {
        let mut s = wire.clone();
        s = s.replace(checksum, "<checksum>");
        s
    });
    let path = pattern.replace("{id}", &target);
    // Expected statuses where a label is a refusal.
    let expect: Option<u16> = match (action, label) {
        (
            _,
            "bad-json" | "unknown-field" | "typed" | "trailing" | "reason-mismatch" | "bad-key",
        ) => Some(400),
        (_, "reason-required" | "no-reason-header" | "null-body") => Some(400),
        ("backfill", "bad-action" | "bad-checksum" | "no-checksum" | "key-mismatch" | "no-key") => {
            Some(400)
        }
        ("backfill", "stale" | "blocked") => Some(409),
        ("canary", "stale" | "missing-source" | "enable-unready" | "enable-ldap" | "repeat") => {
            Some(409)
        }
        (
            "canary",
            "bad-generation" | "text-generation" | "bad-source-key" | "enable-no-users"
            | "too-many-users" | "bad-user-id" | "text-user-id" | "null-user-id" | "typed-user-id"
            | "duplicate-users" | "typed-enabled" | "key-mismatch",
        ) => Some(400),
        ("rollback", "bad-read-path" | "no-read-path") => Some(400),
        ("shadow", "missing-source" | "no-key") => Some(400),
        ("doctor", "missing-source" | "bad-source") => Some(400),
        ("diag-create", "transition") => Some(409),
        ("diag-create", "idem-reuse") => Some(409),
        (
            "diag-create",
            "missing-source" | "bad-transition-id" | "nil-transition-id" | "both-scopes"
            | "no-scope" | "bad-source-key" | "zero-since" | "long-since" | "float-since"
            | "string-since" | "no-key" | "key-mismatch",
        ) => Some(400),
        ("diag-status" | "diag-download" | "diag-delete", "bad-id" | "nil-id") => Some(400),
        ("diag-status", "missing" | "other-actor") => Some(404),
        ("diag-download", "missing" | "other-actor") => Some(404),
        ("diag-status", "kind-denied") => Some(403),
        ("diag-download", "not-ready") => Some(409),
        ("diag-download", "expired" | "past-expiry") => Some(410),
        (_, "etag-match") => Some(304),
        _ => None,
    };
    let wanted = match (action, label, expect) {
        (_, "oversize", _) => 413,
        (_, "denied" | "only-upgrade" | "only-identity" | "scoped", _) => 403,
        (_, _, Some(w)) => w,
        _ => wanted,
    };
    Plan {
        method,
        path,
        query,
        headers,
        body: wire,
        shown_body,
        repeat,
        wanted,
    }
}

async fn run_inner(action: &str, kind: &str) -> Result<(), BoxError> {
    let mutant = kind.ends_with("-status-mutant");
    let label = kind.strip_suffix("-status-mutant").unwrap_or(kind);
    let Some(db) = Db::for_case("admin9-http") else {
        return Ok(());
    };
    let owner = db.connect().await?;
    clean(&owner).await?;
    let w = World {
        a: fixture::account(&owner, "admin9-admin").await?,
        b: fixture::account(&owner, "admin9-other").await?,
        t: fixture::account(&owner, "admin9-third").await?,
    };
    let (a, b, t) = (&w.a, &w.b, &w.t);
    // The preflight report's sha256 digests whole-database facts, `people` among them, and
    // the recorded Go responses were taken with six users in the database (these three plus
    // three others). Pad to that population so the digest is a function of the fixture, not
    // of whatever an earlier suite left behind or cleaned up (#421). The pads have primary
    // mailboxes, so no other preflight fact moves; the case removes them on every path.
    let mut pads = Vec::new();
    if matches!(action, "preflight" | "backfill") {
        let present: i64 = owner.query_one("SELECT count(*) FROM users", &[]).await?.get(0);
        for n in present..RECORDED_PEOPLE {
            pads.push(fixture::account(&owner, &format!("pad9-{n}")).await?);
        }
    }
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
    let users: Vec<(i64, &str)> = vec![
        (a.user, "<admin>"),
        (b.user, "<other>"),
        (t.user, "<third>"),
    ];
    fixtures(&owner, action, label, &w).await?;
    let saved_toggles: Vec<(String, bool)> = owner
        .query("SELECT key,enabled FROM feature_toggles WHERE key IN ('feature.identity_model_v2','feature.identity_normalized_reads','feature.identity_transitions')", &[])
        .await?
        .iter()
        .map(|r| (r.get(0), r.get(1)))
        .collect();
    // Rollback only has an effect when something is switched on.
    owner.batch_execute("UPDATE feature_toggles SET enabled=true WHERE key IN ('feature.identity_model_v2','feature.identity_normalized_reads')").await?;
    let audit_start: i64 = owner
        .query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[])
        .await?
        .get(0);
    let receipts = owner
        .query(
            "SELECT operation_id::text FROM rust_operation_receipts WHERE family='F01'",
            &[],
        )
        .await?
        .iter()
        .map(|r| r.get::<_, String>(0))
        .collect::<Vec<_>>();
    let result = async {
        // Per-case database setup.
        match (action, label) {
            (_, "reason-required") => {
                let area = if is_diag(action) { "audit" } else { "identity" };
                owner.batch_execute(&format!("UPDATE audit_policy SET reason_required_areas = reason_required_areas || ARRAY['{area}']::text[] WHERE id=1 AND NOT ('{area}'=ANY(reason_required_areas))")).await?;
            }
            ("backfill", "success" | "repeat" | "header-key-only" | "body-key-only" | "key-mismatch-ok") => {
                owner.batch_execute("INSERT INTO backup_runs(status,error_log,started_at,completed_at) VALUES('completed','[\"admin9\"]'::jsonb,now()-interval '2 minutes',now()-interval '1 minute')").await?;
            }
            ("diag-create", "idem-reuse") => {
                owner.batch_execute(&format!("INSERT INTO identity_jobs(kind,state,actor_user_id,source_id,idempotency_key,request_digest,request,reason) SELECT 'diagnostics','queued',{},id,'{IDEM}'::uuid,decode(repeat('0f',32),'hex'),'{{}}'::jsonb,'earlier' FROM identity_sources WHERE source_key='admin9-alpha'", a.user)).await?;
            }
            _ => {}
        }
        let s3 = common::fake_upstream(|_| async { Response::new(common::full("")) }).await;
        let go = common::go_oracle::start_named(&db, s3, None, "gofree-admin9-http").await?;
        let recording = go.is_some();
        let patient = std::time::Duration::from_secs(30);
        let timeouts = || setjoin_pg::Timeouts { pool_wait: patient, create: patient, statement: patient };
        let exec = ScopedExecutor::from_dsn_with(db.app.as_deref().unwrap_or(&db.dsn), 4, timeouts())
            .map_err(|e| e.0)?
            .with_audit_keys("22".repeat(32), String::new());
        let worker = ScopedExecutor::from_dsn_with(&db.dsn, 4, timeouts())
            .map_err(|e| e.0)?
            .with_audit_keys("22".repeat(32), String::new());
        let adapter = Probe {
            inner: AdminIdentityV2UpgradeRoute {
                exec,
                worker,
                keys: Arc::new(common::recovery_keys()),
                issuer: "mailserver".into(),
                secrets: setjoin_gateway::admin_identity_v2::SourceSecrets::new(secret_env),
                runtime: setjoin_admin_identity::idv2_upgrade::Runtime {
                    expected_schema: setjoin_schema::MIGRATIONS.last().map_or(0, |m| m.0),
                    worker_dsn: true,
                    owner_dsn: true,
                    direct_dsn: true,
                    authserver: true,
                },
            },
            changed_status: mutant,
        };
        let mut inventory: Value = serde_json::from_str(include_str!("../../route-inventory.json"))?;
        for r in inventory["routes"].as_array_mut().ok_or("routes")? {
            if r["family"] == "F01" && r["slice"] == "idv2-upgrade" {
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
        let send_raw = |method: &'static str, uri: String, headers: Vec<(String, String)>, body: String| {
            let token = admin_token(a.user);
            async move {
                let mut request = Request::builder().method(method).uri(uri).header("host", "mail.test").header("origin", "http://mail.test").header("x-request-id", "gofree-admin9-oracle").header("authorization", format!("Bearer {token}"));
                for (k, v) in headers { request = request.header(k, v); }
                Ok::<_, BoxError>(common::send(address, request.body(common::full(body))?).await)
            }
        };
        // A backfill start carries the checksum of the preflight report that is current.
        let mut checksum = "<checksum>".to_owned();
        if action == "backfill" && !matches!(label, "plan" | "stale") {
            let report = send_raw("POST", "/api/admin/identity/v2/upgrade/preflight".into(), vec![], String::new()).await?;
            let text = String::from_utf8(common::body_bytes(report).await.to_vec())?;
            let value: Value = serde_json::from_str(&text)?;
            // A refused preflight (denied, scoped) leaves nothing to echo.
            checksum = value["sha256"].as_str().map_or_else(|| "0".repeat(64), str::to_owned);
        }
        let p = plan(action, label, &checksum);
        let (_, pattern) = route(action);
        let uri = format!("/api{}{}", p.path, p.query);
        let before = snapshot(&owner).await?;
        let mut notify_listener = db.listen("config_changed").await?;
        let last: i64 = owner.query_one("SELECT COALESCE(max(id),0) FROM admin_audit_log", &[]).await?.get(0);
        let (mut first_status, mut first_text) = (None, None);
        if p.repeat {
            let first = send_raw(p.method, uri.clone(), p.headers.clone(), p.body.clone()).await?;
            first_status = Some(first.status().as_u16());
            first_text = Some(String::from_utf8_lossy(&common::body_bytes(first).await).into_owned());
        }
        let response = send_raw(p.method, uri.clone(), p.headers.clone(), p.body.clone()).await?;
        let status = response.status().as_u16();
        let mut headers = serde_json::Map::new();
        for name in response.headers().keys() {
            headers.insert(name.to_string(), json!(response.headers().get_all(name).iter().map(|v| v.to_str().unwrap().to_owned()).collect::<Vec<_>>()));
        }
        let raw = String::from_utf8(common::body_bytes(response).await.to_vec())?;
        if recording && status != p.wanted {
            return Err(format!("Go {action}/{label}: expected {}, got {status}: {raw}", p.wanted).into());
        }
        let after = snapshot(&owner).await?;
        let notify_raw = notify_listener.drain(&owner).await?;
        let mut audit: Vec<Value> = owner.query("SELECT to_jsonb(a)::text FROM admin_audit_log a WHERE id>$1 ORDER BY id", &[&last]).await?.iter().map(|r| serde_json::from_str(&r.get::<_, String>(0))).collect::<Result<_, _>>()?;
        for row in &mut audit {
            if row["id"].as_i64().is_none_or(|n| n <= 0) { return Err("invalid audit id".into()); }
            row["id"] = json!("<audit>");
            for key in ["checksum", "prev_checksum"] {
                if row[key].as_str().is_some_and(|s| !s.is_empty()) { row[key] = json!("<checksum>"); }
            }
            let shown = masked(row.clone(), &users, &names)?;
            *row = serde_json::from_str(&shown.to_string().replace(&format!("domain={}", b.domain), "domain=<scope>"))?;
            // The source row id is sequence-issued.
            if let Some(source) = row.pointer_mut("/after_state/sourceId") {
                if source.is_number() { *source = json!("<source-id>"); }
            }
        }
        let mut notify = Vec::new();
        for event in notify_raw {
            let payload: Value = serde_json::from_str(&event)?;
            notify.push(json!({"channel":"config_changed","payload":masked(payload, &users, &names)?}));
        }
        // Volatile text: whole-database counts, generation instants, run-issued ids.
        let volatile = |raw: &str| -> String {
            let mut text = scrub_instants(&mask_uuids(&names(raw))).replace(&checksum, "<checksum>");
            if matches!(action, "status" | "preflight" | "doctor" | "backfill" | "rollback") && status == 200 {
                text = mask_numbers(&text);
                for marker in ["\"sha256\":\""] {
                    while let Some(at) = text.find(marker) {
                        let from = at + marker.len();
                        let Some(len) = text[from..].find('"') else { break };
                        if len == 64 { text.replace_range(from..from + len, "<sha256>"); } else { break }
                    }
                }
            }
            text
        };
        let text = if action == "diag-download" && status == 200 {
            names(&raw)
        } else {
            volatile(&raw)
        };
        // Masking hides the digest from the golden comparison, so check it here against the raw
        // (unmasked) report it travels in: a stale or copied digest fails, it is not just hidden.
        if matches!(action, "preflight" | "backfill") && status == 200 {
            digest_is_current(&owner, &raw).await?;
            // A self-consistent but out-of-date report still hashes to its own digest, so also take
            // a fresh preflight in the same database state (read-only; its audit row is cleaned
            // with the case's window) and require the same report: only `generatedAt` may differ.
            let fresh = send_raw("POST", "/api/admin/identity/v2/upgrade/preflight".into(), vec![], String::new()).await?;
            let fresh = String::from_utf8(common::body_bytes(fresh).await.to_vec())?;
            report_matches_fresh(&raw, &fresh)?;
            facts_match_database(&owner, &raw).await?;
        }
        let wire_etag = headers.get("etag").cloned();
        if let Some(date) = headers.get_mut("date") { *date = json!(["<timestamp>"]); }
        if let Some(tag) = headers.get_mut("etag") {
            if tag[0].as_str().is_some_and(|t| t.len() == 66) { *tag = json!(["<etag>"]); }
        }
        let _ = wire_etag;
        for key in ["location", "content-disposition"] {
            if let Some(value) = headers.get_mut(key) {
                *value = json!(value.as_array().unwrap().iter().map(|v| mask_uuids(v.as_str().unwrap())).collect::<Vec<_>>());
            }
        }
        if let Some(length) = headers.get_mut("content-length") {
            if length[0] != raw.len().to_string() { return Err("bad wire length".into()); }
            *length = json!([text.len().to_string()]);
        }
        let (before, after) = (masked(before, &users, &names)?, masked(after, &users, &names)?);
        // The backfill job request records the checksum of the preflight report.
        let (before, after): (Value, Value) = (
            serde_json::from_str(&before.to_string().replace(&checksum, "<checksum>"))?,
            serde_json::from_str(&after.to_string().replace(&checksum, "<checksum>"))?,
        );
        let effects = json!([{"table":"identity","before":before,"after":after}]);
        let mut request = json!({"method":p.method,"path":pattern,"external_path":format!("/api{pattern}")});
        if !p.query.is_empty() { request["query"] = json!(p.query); }
        let shown_headers: Vec<&str> = p.headers.iter().map(|(k, _)| k.as_str()).collect();
        if !shown_headers.is_empty() { request["headers"] = json!(shown_headers); }
        if !p.shown_body.is_empty() { request["body"] = json!(names(&p.shown_body)); }
        let mut observation = json!({"request":request,"response":{"status":status,"headers":headers,"body":text},"effects":effects,"audit":audit,"notify":notify});
        if let (Some(s), Some(t)) = (first_status, first_text) {
            observation["first"] = json!({"status": s, "body": volatile(&t)});
        }
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
        let file = dir.join(format!("idv2u-{name}.json"));
        let row_file = dir.join(format!("idv2u-{name}-row-effects.json"));
        let route_name = format!("{} {pattern}", p.method);
        if recording {
            let source = std::env::var("GOFREE_GO_SOURCE")?;
            record(&file, &json!({"format":1,"route":route_name,"case":label,"go_source":source,"observation":observation}))?;
            if mutator(action) {
                record(&row_file, &json!({"format":1,"route":route_name,"case":format!("{label}-row-effects"),"go_source":source,"effects":observation["effects"]}))?;
            }
        } else {
            let mut expected: Value = serde_json::from_slice(&std::fs::read(&file)?)?;
            if action == "rollback" {
                // One UPDATE flips three feature toggles; the per-row notifications follow heap
                // order, which Go leaves unspecified and earlier suites' updates reshuffle. The
                // same notifications must arrive, in either order.
                for value in [&mut expected["observation"], &mut observation] {
                    if let Some(list) = value["notify"].as_array_mut() {
                        list.sort_by_key(|n| n.to_string());
                    }
                }
            }
            // The preflight digest covers the database schema version (a `schema_binary_compatible`
            // fact), which has advanced past the recording's V276 while the recording stays
            // immutable. The wire digest must still be a SHA-256 hex string; both sides are
            // masked for the comparison, every other byte is compared as recorded.
            if matches!(action, "preflight" | "backfill") && status == 200 {
                let digest = regex::Regex::new(r#""sha256":\s*"([0-9a-f]{64})""#)?;
                let body = observation["response"]["body"].as_str().unwrap_or_default().to_owned();
                if !digest.is_match(&body) { return Err("preflight report has no sha256 digest".into()); }
                for value in [&mut expected["observation"], &mut observation] {
                    if let Some(body) = value["response"]["body"].as_str() {
                        value["response"]["body"] = json!(digest.replace_all(body, "\"sha256\": \"<sha256>\"").into_owned());
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
            compared?;
            if mutator(action) {
                let expected: Value = serde_json::from_slice(&std::fs::read(row_file)?)?;
                golden::compare(&expected["effects"], &observation["effects"])?;
            }
            eprintln!("GOLDEN-REPLAY: {route_name} :: {label}");
        }
        Ok::<_, BoxError>(())
    }
    .await;
    // Cleanup runs on every path and touches only this case's rows.
    for (key, enabled) in &saved_toggles {
        owner
            .execute(
                "UPDATE feature_toggles SET enabled=$2 WHERE key=$1",
                &[key, enabled],
            )
            .await?;
    }
    clean(&owner).await?;
    owner.execute("DELETE FROM rust_operation_receipts WHERE family='F01' AND operation_id::text<>ALL($1)", &[&receipts]).await?;
    for account in [a, b, t].into_iter().chain(pads.iter()) {
        common::remove_blob_account(&owner, account).await?;
    }
    owner.batch_execute(&format!("BEGIN; SET LOCAL session_replication_role=replica; DELETE FROM admin_audit_log WHERE id>{audit_start}; COMMIT;")).await?;
    result
}

/// The report as the reducer hashes it: everything but `generatedAt`.
fn report_core(body: &str) -> Result<Value, BoxError> {
    let mut report: Value = serde_json::from_str(body)?;
    report.as_object_mut().ok_or("preflight report is not an object")?.remove("generatedAt");
    Ok(report)
}

/// `reported` must equal a `fresh` report taken in the same database state (same digest too),
/// so a stale report that is merely self-consistent is rejected.
pub fn report_matches_fresh(reported: &str, fresh: &str) -> Result<(), BoxError> {
    let (reported, fresh) = (report_core(reported)?, report_core(fresh)?);
    if reported != fresh {
        return Err(format!("stale preflight report: differs from a fresh one: {}", golden::compare(&fresh, &reported).err().unwrap_or_default()).into());
    }
    Ok(())
}

/// Facts of the report that the database answers on its own, independent of the endpoint under
/// test: a self-consistent report (right digest, equal to a repeat of the same wrong answer) with
/// a wrong head count or wrong feature flags is rejected.
pub async fn facts_match_database(owner: &tokio_postgres::Client, body: &str) -> Result<(), BoxError> {
    let report: Value = serde_json::from_str(body)?;
    let people: i64 = owner.query_one("SELECT count(*) FROM users", &[]).await?.get(0);
    if report["estimates"]["people"].as_i64() != Some(people) {
        return Err(format!("stale preflight report: estimates.people {} but the database has {people} users", report["estimates"]["people"]).into());
    }
    for (name, key) in [("identityModelV2", "feature.identity_model_v2"), ("normalizedReads", "feature.identity_normalized_reads"), ("transitions", "feature.identity_transitions")] {
        let enabled: bool = owner.query_opt("SELECT enabled FROM feature_toggles WHERE key=$1", &[&key]).await?.is_some_and(|r| r.get(0));
        if report["featureFlags"][name].as_bool() != Some(enabled) {
            return Err(format!("stale preflight report: featureFlags.{name} {} but the toggle is {enabled}", report["featureFlags"][name]).into());
        }
    }
    Ok(())
}

/// The report digest is `sha256((report - generatedAt)::text)` computed by
/// `identity_upgrade_preflight` over the jsonb text form. Recompute it in the database from the
/// wire body (minus `sha256` and `generatedAt`) and require it to equal the wire digest, so a
/// digest that does not describe its own report (stale, copied, or left unmasked-but-wrong) is
/// rejected even though the golden comparison masks the value.
pub async fn digest_is_current(owner: &tokio_postgres::Client, body: &str) -> Result<(), BoxError> {
    let report: Value = serde_json::from_str(body)?;
    let wire = report["sha256"]
        .as_str()
        .filter(|d| d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or("preflight report has no sha256 digest")?
        .to_owned();
    let expected: String = owner
        .query_one(
            "SELECT encode(digest(convert_to(($1::text::jsonb - 'sha256' - 'generatedAt')::text,'UTF8'),'sha256'),'hex')",
            &[&body],
        )
        .await?
        .get(0);
    if wire != expected {
        return Err(format!("stale preflight digest: wire {wire}, report hashes to {expected}").into());
    }
    Ok(())
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
