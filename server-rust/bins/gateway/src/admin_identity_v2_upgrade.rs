//! F01 slice `idv2-upgrade` HTTP adapter: the identity v2 upgrade, doctor and
//! diagnostics routes. Each route keeps Go's gate order (audited live permission
//! gates, `RequireReason`, the handler's own decode and source-wide gates), strict
//! request bodies and bare problem documents. Every statement is one existing reducer
//! on the worker executor, as Go's `workerPool` calls it. See the crate DOX.
use crate::admin_identity_v2::{
    bare, body_refusal, header_text, raw_json, raw_json_as, read_body, reason_matches, refusal,
    rejection, segment, unknown_outcome, SourceSecrets, LIVE, UNSCOPED,
};
use crate::{Body, BoxFuture, Intercept, RequestContext};
use base64::Engine as _;
use hyper::{Method, Request, Response};
use serde_json::Value;
use setjoin_admin_identity::idv2 as db;
use setjoin_admin_identity::idv2_ops as ops;
use setjoin_admin_identity::idv2_upgrade as up;
use setjoin_admin_identity::idv2_writes as wr;
use setjoin_authz::token::KeySource;
use setjoin_pg::{CommandOutcome, ScopedExecutor, StatementFailure};
use std::sync::Arc;

pub struct AdminIdentityV2UpgradeRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub worker: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    pub secrets: SourceSecrets,
    pub runtime: up::Runtime,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Status,
    Preflight,
    Backfill,
    Shadow,
    Canary,
    Rollback,
    Retirement,
    Doctor,
    DiagCreate,
    DiagStatus,
    DiagDownload,
    DiagDelete,
}

const BASE: &str = "/api/admin/identity/v2";

const TABLE: [(&str, Action); 6] = [
    ("/api/admin/identity/v2/upgrade/status", Action::Status),
    ("/api/admin/identity/v2/upgrade/shadow", Action::Shadow),
    (
        "/api/admin/identity/v2/upgrade/retirement-check",
        Action::Retirement,
    ),
    ("/api/admin/identity/v2/doctor", Action::Doctor),
    (
        "/api/admin/identity/v2/diagnostics/{id}",
        Action::DiagStatus,
    ),
    (
        "/api/admin/identity/v2/diagnostics/{id}/download",
        Action::DiagDownload,
    ),
];

const WRITES: [(&str, Action); 5] = [
    (
        "/api/admin/identity/v2/upgrade/preflight",
        Action::Preflight,
    ),
    ("/api/admin/identity/v2/upgrade/backfill", Action::Backfill),
    ("/api/admin/identity/v2/upgrade/canary", Action::Canary),
    ("/api/admin/identity/v2/upgrade/rollback", Action::Rollback),
    ("/api/admin/identity/v2/diagnostics", Action::DiagCreate),
];

const DELETES: [(&str, Action); 1] = [(
    "/api/admin/identity/v2/diagnostics/{id}",
    Action::DiagDelete,
)];

fn action(method: &Method, path: &str) -> Option<Action> {
    let table: &[(&str, Action)] = match *method {
        Method::GET | Method::HEAD => &TABLE,
        Method::POST => &WRITES,
        Method::DELETE => &DELETES,
        _ => return None,
    };
    table
        .iter()
        .filter(|(pattern, _)| crate::inventory::path_score(pattern, path).is_some())
        .max_by_key(|(pattern, _)| crate::inventory::path_score(pattern, path))
        .map(|(_, action)| *action)
}

/// The audited permission gates Go chains in front of the handler, in order.
fn gates(what: Action) -> &'static [&'static str] {
    match what {
        Action::Status
        | Action::Preflight
        | Action::Backfill
        | Action::Shadow
        | Action::Canary
        | Action::Rollback
        | Action::Retirement => &["system.upgrade", "identity.write"],
        Action::Doctor => &["identity.write"],
        Action::DiagCreate | Action::DiagStatus | Action::DiagDownload | Action::DiagDelete => {
            &["audit.export"]
        }
    }
}

/// `RequireReason(perm)` where Go wraps the route: the permission it names.
fn reason_perm(what: Action) -> Option<&'static str> {
    match what {
        Action::Canary | Action::Rollback => Some("identity.write"),
        Action::DiagCreate | Action::DiagDelete => Some("audit.export"),
        _ => None,
    }
}

/// A reducer statement that failed: its classified refusal, or Go's 500 for the route.
fn failed(
    e: &StatementFailure,
    fallback: &str,
    path: &str,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    match ops::classify(e) {
        Some(r) => refusal(r, path, c, id),
        None => bare(500, fallback, c, id),
    }
}

/// An error Go answers with a fixed 500 (it does not classify these).
fn flat(e: &StatementFailure, fallback: &str, c: &RequestContext, id: &str) -> Response<Body> {
    let _ = e;
    bare(500, fallback, c, id)
}

/// `json.Unmarshal` of the member `name` as a string field of a decoded struct.
fn string_of(raw: &Value) -> Option<String> {
    match raw {
        Value::Null => Some(String::new()),
        Value::String(s) => Some(s.clone()),
        _ => None,
    }
}

/// Go's `identityIfMatch`: empty passes, else the strong ETag must be listed.
fn if_match(r: &Request<Body>, version: &str) -> bool {
    let header = header_text(r, "if-match");
    let header = header.trim_matches(|c: char| c.is_ascii_whitespace() || c == '\u{a0}');
    if header.is_empty() {
        return true;
    }
    let etag = format!("\"{version}\"");
    header
        .split(',')
        .map(|c| c.trim())
        .any(|c| c == "*" || c == etag)
}

/// Go's `validIdentityDigest`.
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn nonzero_uuid(text: &str) -> Option<String> {
    db::parse_uuid(text).filter(|u| u != "00000000-0000-0000-0000-000000000000")
}

/// `result.<name>` (a string member), the way Go decodes a reducer's JSON object.
fn member_text(raw: &str, name: &str) -> Option<String> {
    let v: Value = serde_json::from_str(raw).ok()?;
    let object = v.as_object()?;
    let member = object.get(name).or_else(|| {
        object
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v)
    });
    match member {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

impl<K: KeySource + 'static> Intercept for AdminIdentityV2UpgradeRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, r: &Request<Body>) -> bool {
        action(r.method(), r.uri().path()).is_some()
    }
    fn admits_member(&self, headers: hyper::HeaderMap, scheme: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            setjoin_authz::authorize_request(&exec, &keys, &issuer, &headers, scheme)
                .await
                .is_some()
        })
    }
    fn handle(&self, mut r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let (exec, worker, keys, issuer) = (
            self.exec.clone(),
            self.worker.clone(),
            self.keys.clone(),
            self.issuer.clone(),
        );
        let (secrets, runtime) = (self.secrets.clone(), self.runtime.clone());
        Box::pin(async move {
            let Some(what) = action(r.method(), r.uri().path()) else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let Some(auth) = setjoin_authz::authorize_request(
                &exec,
                &keys,
                &issuer,
                r.headers(),
                c.identity.proto,
            )
            .await
            else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let Some(operation) = crate::jmap::random() else {
                return bare(503, "service unavailable", &c, "");
            };
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation);
            let actor = auth.context();
            let path = r.uri().path().to_owned();
            let go_path = path.strip_prefix("/api").unwrap_or(&path).to_owned();
            let go_path = crate::guests_input::go_utf8(&crate::inventory::unescape(&go_path));
            let query = r.uri().query().unwrap_or("").to_owned();
            // `r.URL.Query()` is read before the gate by the shadow handler's key check
            // only; every route resolves its query lazily below.
            let Ok(authority) = setjoin_admin_identity::authority(&exec, actor).await else {
                return c.upstream.forward(r, &c.identity).await;
            };
            // Go's audited route guards (`RequirePermAudited`), one per permission.
            for perm in gates(what) {
                if !authority.allows_any(&[perm]) {
                    let _ = setjoin_admin_identity::console_denied(
                        &exec, actor, &go_path, perm, operation,
                    )
                    .await;
                    return bare(403, "Forbidden", &c, &id);
                }
                if authority.refused_for_scope(&[perm]) {
                    let detail = format!(
                        "{perm} (domain-scoped principal; org-wide-only surface, domain={})",
                        authority.domain_scope()
                    );
                    let _ = setjoin_admin_identity::console_denied(
                        &exec, actor, &go_path, &detail, operation,
                    )
                    .await;
                    return bare(403, "Forbidden", &c, &id);
                }
            }
            if let Some(perm) = reason_perm(what) {
                let area = perm.split('.').next().unwrap_or("");
                if up::reason_required(&exec, area).await
                    && r.headers()
                        .get("x-audit-reason")
                        .is_none_or(|v| v.as_bytes().is_empty())
                {
                    let ip = c.identity.client_ip.to_string();
                    up::missing_reason(&exec, actor, &ip, perm, operation).await;
                    return bare(400, "reason_required", &c, &id);
                }
            }
            // `requireUnscopedIdentityAdmin(perms...)`: every permission live and global,
            // then no domain scope.
            let unscoped = |perms: &[&str]| -> Option<&'static str> {
                if !perms.iter().all(|p| authority.global_any(&[p])) {
                    Some(LIVE)
                } else if authority.domain_scope() != 0 {
                    Some(UNSCOPED)
                } else {
                    None
                }
            };
            let upgrade = ["identity.write", "system.upgrade"];
            let user = actor.user_id();
            let secrets_ok = || async { secrets.codec(&worker).await.is_some() };
            match what {
                Action::Status | Action::Preflight | Action::Retirement => {
                    if let Some(detail) = unscoped(&upgrade) {
                        return bare(403, detail, &c, &id);
                    }
                    let (result, fallback) = match what {
                        Action::Status => {
                            (up::status(&worker).await, "identity upgrade status failed")
                        }
                        Action::Preflight => {
                            let ok = secrets_ok().await;
                            (
                                up::preflight(&worker, &runtime, ok).await,
                                "identity upgrade preflight failed",
                            )
                        }
                        _ => (
                            up::retirement_check(&worker).await,
                            "identity retirement check failed",
                        ),
                    };
                    match result {
                        Ok(raw) => raw_json(raw, r.headers().get("if-none-match"), &c, &id),
                        Err(e) => flat(&e, fallback, &c, &id),
                    }
                }
                Action::Shadow => {
                    let pairs = db::query_first(&query);
                    let key = pairs
                        .get("sourceKey")
                        .map(|k| k.trim().to_owned())
                        .unwrap_or_default();
                    if !db::valid_source_key(&key) {
                        return bare(
                            400,
                            "identity shadow check requires a valid sourceKey",
                            &c,
                            &id,
                        );
                    }
                    if let Some(detail) = unscoped(&upgrade) {
                        return bare(403, detail, &c, &id);
                    }
                    match up::shadow(&worker, &key).await {
                        Ok(raw) => raw_json(raw, r.headers().get("if-none-match"), &c, &id),
                        Err(e) => failed(&e, "identity shadow check failed", &go_path, &c, &id),
                    }
                }
                Action::Doctor => {
                    if let Some(detail) = unscoped(&["identity.write"]) {
                        return bare(403, detail, &c, &id);
                    }
                    let pairs = db::query_first(&query);
                    let key = pairs
                        .get("source")
                        .map(|k| k.trim().to_owned())
                        .unwrap_or_default();
                    if !key.is_empty() && !db::valid_source_key(&key) {
                        return bare(400, "invalid identity source key", &c, &id);
                    }
                    let ok = secrets_ok().await;
                    let source = (!key.is_empty()).then_some(key.as_str());
                    match up::doctor(&worker, &runtime, ok, source).await {
                        Ok(raw) => raw_json(raw, r.headers().get("if-none-match"), &c, &id),
                        Err(e) => failed(&e, "identity doctor failed", &go_path, &c, &id),
                    }
                }
                Action::Backfill => {
                    let Some(bytes) = read_body(&mut r).await else {
                        return bare(400, "invalid identity backfill request", &c, &id);
                    };
                    let members = match wr::strict_object(
                        &bytes,
                        &["action", "preflightChecksum", "reason", "idempotencyKey"],
                    ) {
                        Ok(m) => m,
                        Err(e) => {
                            return body_refusal(e, "invalid identity backfill request", &c, &id)
                        }
                    };
                    let (Ok(act), Ok(checksum), Ok(reason), Ok(key_text)) = (
                        wr::text(&members, "action"),
                        wr::text(&members, "preflightChecksum"),
                        wr::text(&members, "reason"),
                        wr::text(&members, "idempotencyKey"),
                    ) else {
                        return bare(400, "invalid identity backfill request", &c, &id);
                    };
                    if act == "plan" {
                        if let Some(detail) = unscoped(&upgrade) {
                            return bare(403, detail, &c, &id);
                        }
                        let ok = secrets_ok().await;
                        return match up::preflight(&worker, &runtime, ok).await {
                            Ok(raw) => raw_json(raw, r.headers().get("if-none-match"), &c, &id),
                            Err(e) => flat(&e, "identity backfill plan failed", &c, &id),
                        };
                    }
                    if act != "start" {
                        return bare(
                            400,
                            "identity backfill action must be plan or start",
                            &c,
                            &id,
                        );
                    }
                    if let Err((status, detail)) = reason_matches(&r, &reason) {
                        return bare(status, detail, &c, &id);
                    }
                    let header_key = header_text(&r, "idempotency-key");
                    let header_key = header_key.trim();
                    if !header_key.is_empty() && !key_text.is_empty() && header_key != key_text {
                        return bare(
                            400,
                            "Idempotency-Key must match body idempotencyKey",
                            &c,
                            &id,
                        );
                    }
                    let key_text = if header_key.is_empty() {
                        key_text
                    } else {
                        header_key.to_owned()
                    };
                    let (Some(key), true) = (nonzero_uuid(&key_text), valid_digest(&checksum))
                    else {
                        return bare(
                            400,
                            "identity backfill start requires checksum and idempotency UUID",
                            &c,
                            &id,
                        );
                    };
                    if let Some(detail) = unscoped(&upgrade) {
                        return bare(403, detail, &c, &id);
                    }
                    let ok = secrets_ok().await;
                    let raw = match up::backfill_start(
                        &worker, actor, &checksum, &key, &reason, &runtime, ok, operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(raw) => raw.unwrap_or_default(),
                        CommandOutcome::RolledBack(e) => {
                            return rejection(
                                &e,
                                "identity backfill start failed",
                                &go_path,
                                &c,
                                &id,
                            )
                        }
                        CommandOutcome::Unknown { operation } => {
                            return unknown_outcome(operation, &c, &id)
                        }
                    };
                    let Some(job) = member_text(&raw, "jobId") else {
                        return bare(
                            500,
                            "identity backfill returned an invalid response",
                            &c,
                            &id,
                        );
                    };
                    accepted(raw, &format!("{BASE}/jobs/{job}"), &r, &c, &id)
                }
                Action::Canary => {
                    let Some(bytes) = read_body(&mut r).await else {
                        return bare(400, "invalid identity canary request", &c, &id);
                    };
                    let members = match wr::strict_object(
                        &bytes,
                        &[
                            "sourceKey",
                            "expectedGeneration",
                            "enabled",
                            "userIds",
                            "reason",
                        ],
                    ) {
                        Ok(m) => m,
                        Err(e) => {
                            return body_refusal(e, "invalid identity canary request", &c, &id)
                        }
                    };
                    let decode = || -> Option<(String, String, bool, Vec<String>, String)> {
                        let enabled = match members.get("enabled") {
                            None => false,
                            Some(raw) => match serde_json::from_str::<Value>(raw.get()).ok()? {
                                Value::Null => false,
                                Value::Bool(b) => b,
                                _ => return None,
                            },
                        };
                        let users = match members.get("userIds") {
                            None => Vec::new(),
                            Some(raw) => match serde_json::from_str::<Value>(raw.get()).ok()? {
                                Value::Null => Vec::new(),
                                Value::Array(items) => {
                                    items.iter().map(string_of).collect::<Option<Vec<_>>>()?
                                }
                                _ => return None,
                            },
                        };
                        Some((
                            wr::text(&members, "sourceKey").ok()?,
                            wr::text(&members, "expectedGeneration").ok()?,
                            enabled,
                            users,
                            wr::text(&members, "reason").ok()?,
                        ))
                    };
                    let Some((source, generation_text, enabled, user_texts, reason)) = decode()
                    else {
                        return bare(400, "invalid identity canary request", &c, &id);
                    };
                    if let Err((status, detail)) = reason_matches(&r, &reason) {
                        return bare(status, detail, &c, &id);
                    }
                    let generation = generation_text.parse::<i64>().ok().filter(|g| *g > 0);
                    let (Some(generation), true) = (generation, db::valid_source_key(&source))
                    else {
                        return bare(400, "invalid identity canary request", &c, &id);
                    };
                    if !if_match(&r, &generation_text) {
                        return bare(
                            412,
                            "identity resource version does not match If-Match",
                            &c,
                            &id,
                        );
                    }
                    if user_texts.len() > 500 {
                        return bare(400, "identity canary cohort exceeds 500 users", &c, &id);
                    }
                    let mut users: Vec<i64> = Vec::with_capacity(user_texts.len());
                    for text in &user_texts {
                        let Some(n) = text.parse::<i64>().ok().filter(|n| *n > 0) else {
                            return bare(400, "invalid identity canary user id", &c, &id);
                        };
                        if users.contains(&n) {
                            return bare(400, "identity canary user ids must be unique", &c, &id);
                        }
                        users.push(n);
                    }
                    if enabled && users.is_empty() {
                        return bare(400, "invalid identity canary request", &c, &id);
                    }
                    if let Some(detail) = unscoped(&upgrade) {
                        return bare(403, detail, &c, &id);
                    }
                    let raw = match up::canary(
                        &worker, actor, &source, generation, enabled, &users, &reason, operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(raw) => raw.unwrap_or_default(),
                        CommandOutcome::RolledBack(e) => {
                            return rejection(&e, "identity canary failed", &go_path, &c, &id)
                        }
                        CommandOutcome::Unknown { operation } => {
                            return unknown_outcome(operation, &c, &id)
                        }
                    };
                    let Some(next) = member_text(&raw, "generation") else {
                        return bare(500, "identity canary returned an invalid response", &c, &id);
                    };
                    raw_json_as(
                        raw,
                        200,
                        Some(next),
                        r.headers().get("if-none-match"),
                        &c,
                        &id,
                    )
                }
                Action::Rollback => {
                    let Some(bytes) = read_body(&mut r).await else {
                        return bare(400, "invalid identity rollback request", &c, &id);
                    };
                    let members = match wr::strict_object(&bytes, &["readPath", "reason"]) {
                        Ok(m) => m,
                        Err(e) => {
                            return body_refusal(e, "invalid identity rollback request", &c, &id)
                        }
                    };
                    let (Ok(read_path), Ok(reason)) =
                        (wr::text(&members, "readPath"), wr::text(&members, "reason"))
                    else {
                        return bare(400, "invalid identity rollback request", &c, &id);
                    };
                    if let Err((status, detail)) = reason_matches(&r, &reason) {
                        return bare(status, detail, &c, &id);
                    }
                    if read_path != "legacy" {
                        return bare(400, "identity rollback readPath must be legacy", &c, &id);
                    }
                    if let Some(detail) = unscoped(&upgrade) {
                        return bare(403, detail, &c, &id);
                    }
                    match up::rollback(&worker, actor, &reason, operation).await {
                        CommandOutcome::Committed(raw) => raw_json(
                            raw.unwrap_or_default(),
                            r.headers().get("if-none-match"),
                            &c,
                            &id,
                        ),
                        CommandOutcome::RolledBack(e) => {
                            rejection(&e, "identity rollback failed", &go_path, &c, &id)
                        }
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::DiagCreate => {
                    let Some(bytes) = read_body(&mut r).await else {
                        return bare(400, "invalid identity diagnostic request", &c, &id);
                    };
                    let members = match wr::strict_object(
                        &bytes,
                        &[
                            "sourceKey",
                            "transitionId",
                            "sinceSeconds",
                            "reason",
                            "idempotencyKey",
                        ],
                    ) {
                        Ok(m) => m,
                        Err(e) => {
                            return body_refusal(e, "invalid identity diagnostic request", &c, &id)
                        }
                    };
                    let since = match members.get("sinceSeconds") {
                        None => Some(0i64),
                        Some(raw) if raw.get() == "null" => Some(0),
                        Some(raw) => raw.get().parse::<i64>().ok(),
                    };
                    let (Ok(source), Ok(transition_text), Ok(reason), Ok(key_text), Some(since)) = (
                        wr::text(&members, "sourceKey"),
                        wr::text(&members, "transitionId"),
                        wr::text(&members, "reason"),
                        wr::text(&members, "idempotencyKey"),
                        since,
                    ) else {
                        return bare(400, "invalid identity diagnostic request", &c, &id);
                    };
                    if let Err((status, detail)) = reason_matches(&r, &reason) {
                        return bare(status, detail, &c, &id);
                    }
                    let header_key = header_text(&r, "idempotency-key");
                    let header_key = header_key.trim();
                    if !header_key.is_empty() && !key_text.is_empty() && header_key != key_text {
                        return bare(
                            400,
                            "Idempotency-Key must match body idempotencyKey",
                            &c,
                            &id,
                        );
                    }
                    let key_text = if header_key.is_empty() {
                        key_text
                    } else {
                        header_key.to_owned()
                    };
                    let key = nonzero_uuid(&key_text);
                    let mut transition: Option<String> = None;
                    if !transition_text.is_empty() {
                        match nonzero_uuid(&transition_text) {
                            Some(t) => transition = Some(t),
                            None => return bare(400, "invalid identity transition id", &c, &id),
                        }
                    }
                    let Some(key) = key.filter(|_| {
                        source.is_empty() != transition.is_none()
                            && (source.is_empty() || db::valid_source_key(&source))
                            && (1..=86400).contains(&since)
                    }) else {
                        return bare(
                            400,
                            "diagnostics requires one source or transition and a 1..86400 second range",
                            &c,
                            &id,
                        );
                    };
                    if let Some(detail) = unscoped(&["audit.export"]) {
                        return bare(403, detail, &c, &id);
                    }
                    let request = format!("{{\"sinceSeconds\":{since}}}");
                    let source = (!source.is_empty()).then_some(source.as_str());
                    let raw = match up::diagnostic_create(
                        &worker,
                        actor,
                        &key,
                        source,
                        transition.as_deref(),
                        &request,
                        &reason,
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(raw) => raw.unwrap_or_default(),
                        CommandOutcome::RolledBack(e) => {
                            return rejection(
                                &e,
                                "identity diagnostic creation failed",
                                &go_path,
                                &c,
                                &id,
                            )
                        }
                        CommandOutcome::Unknown { operation } => {
                            return unknown_outcome(operation, &c, &id)
                        }
                    };
                    let Some(job) = member_text(&raw, "jobId") else {
                        return bare(
                            500,
                            "identity diagnostic creation returned an invalid response",
                            &c,
                            &id,
                        );
                    };
                    accepted(raw, &format!("{BASE}/diagnostics/{job}"), &r, &c, &id)
                }
                Action::DiagStatus => {
                    // Go's `IdentityJob`: any of the three job permissions, unscoped.
                    if authority.domain_scope() != 0 {
                        return bare(403, UNSCOPED, &c, &id);
                    }
                    if !authority.global_any(&["audit.export", "identity.write", "system.upgrade"])
                    {
                        return bare(403, LIVE, &c, &id);
                    }
                    let Some(job) = nonzero_uuid(&segment(&path, 6)) else {
                        return bare(400, "invalid identity job id", &c, &id);
                    };
                    let raw = match ops::job(&worker, user, &job).await {
                        Ok(raw) => raw,
                        Err(_) => return bare(500, "identity job read failed", &c, &id),
                    };
                    if raw.is_empty() || raw == "null" {
                        return bare(404, "identity job not found", &c, &id);
                    }
                    let Some((kind, terminal)) = job_state(&raw) else {
                        return bare(500, "identity job returned an invalid response", &c, &id);
                    };
                    let held = match kind.as_str() {
                        "diagnostics" => authority.global_any(&["audit.export"]),
                        "upgrade_backfill" | "cohort_preview" => {
                            authority.global_any(&["system.upgrade"])
                                && authority.global_any(&["identity.write"])
                        }
                        _ => false,
                    };
                    if !held {
                        return bare(403, "identity job permission is no longer held", &c, &id);
                    }
                    let mut response = raw_json(raw, r.headers().get("if-none-match"), &c, &id);
                    if !terminal {
                        response
                            .headers_mut()
                            .insert("retry-after", hyper::header::HeaderValue::from_static("2"));
                    }
                    response
                }
                Action::DiagDownload => {
                    if let Some(detail) = unscoped(&["audit.export"]) {
                        return bare(403, detail, &c, &id);
                    }
                    let Some(job) = nonzero_uuid(&segment(&path, 6)) else {
                        return bare(400, "invalid identity job id", &c, &id);
                    };
                    let raw = match ops::job(&worker, user, &job).await {
                        Ok(raw) => raw,
                        Err(_) => return bare(500, "identity diagnostic status failed", &c, &id),
                    };
                    if raw.is_empty() || raw == "null" {
                        return bare(404, "identity diagnostic bundle not found", &c, &id);
                    }
                    let fields = serde_json::from_str::<Value>(&raw).ok().and_then(|v| {
                        let object = v.as_object()?.clone();
                        let field = |name: &str| -> Option<String> {
                            let member = object.get(name).or_else(|| {
                                object
                                    .iter()
                                    .find(|(k, _)| k.eq_ignore_ascii_case(name))
                                    .map(|(_, v)| v)
                            });
                            member.map_or(Some(String::new()), string_of)
                        };
                        Some((field("kind")?, field("state")?, field("expiresAt")?))
                    });
                    let Some((_kind, state, expires)) = fields.filter(|f| f.0 == "diagnostics")
                    else {
                        return bare(500, "identity diagnostic status is invalid", &c, &id);
                    };
                    let Ok(expires) = chrono::DateTime::parse_from_rfc3339(&expires) else {
                        return bare(500, "identity diagnostic expiry is invalid", &c, &id);
                    };
                    if state == "expired" || expires <= chrono::Utc::now() {
                        return bare(410, "identity diagnostic bundle has expired", &c, &id);
                    }
                    if state != "completed" {
                        return bare(409, "identity diagnostic bundle is not ready", &c, &id);
                    }
                    let bundle = match up::diagnostic_download(&worker, actor, &job, operation)
                        .await
                    {
                        CommandOutcome::Committed(Some(bundle)) => bundle,
                        CommandOutcome::Committed(None) => {
                            return bare(404, "identity diagnostic bundle not found", &c, &id)
                        }
                        CommandOutcome::RolledBack(setjoin_pg::Rejection::Statement(e))
                        | CommandOutcome::RolledBack(setjoin_pg::Rejection::Body(e)) => {
                            return match ops::classify(&e) {
                                Some(refusal_) => refusal(refusal_, &go_path, &c, &id),
                                None => bare(404, "identity diagnostic bundle not found", &c, &id),
                            }
                        }
                        CommandOutcome::RolledBack(_) => {
                            return bare(404, "identity diagnostic bundle not found", &c, &id)
                        }
                        CommandOutcome::Unknown { operation } => {
                            return unknown_outcome(operation, &c, &id)
                        }
                    };
                    let chunked = bundle.artifact.len() > 2048;
                    let mut response =
                        crate::jmap::reply::response(String::new(), c.identity.proto, id.clone());
                    {
                        use http_body_util::BodyExt;
                        *response.body_mut() =
                            http_body_util::Full::new(hyper::body::Bytes::from(bundle.artifact))
                                .map_err(|n| match n {})
                                .boxed();
                    }
                    let headers = response.headers_mut();
                    let put = |h: &mut hyper::HeaderMap, k: &'static str, v: String| {
                        h.insert(k, v.parse().expect("header"));
                    };
                    put(headers, "content-type", "application/zip".into());
                    put(
                        headers,
                        "content-disposition",
                        format!("attachment; filename=\"setjoin-identity-diagnostic-{job}.zip\""),
                    );
                    put(
                        headers,
                        "x-setjoin-manifest-version",
                        bundle.manifest_version,
                    );
                    put(
                        headers,
                        "digest",
                        format!(
                            "sha-256={}",
                            base64::engine::general_purpose::STANDARD.encode(bundle.digest)
                        ),
                    );
                    if chunked {
                        put(headers, "transfer-encoding", "chunked".into());
                    }
                    response
                }
                Action::DiagDelete => {
                    let Some(bytes) = read_body(&mut r).await else {
                        return bare(400, "invalid diagnostic deletion request", &c, &id);
                    };
                    let members = match wr::strict_object(&bytes, &["reason"]) {
                        Ok(m) => m,
                        Err(e) => {
                            return body_refusal(e, "invalid diagnostic deletion request", &c, &id)
                        }
                    };
                    let Ok(reason) = wr::text(&members, "reason") else {
                        return bare(400, "invalid diagnostic deletion request", &c, &id);
                    };
                    if let Err((status, detail)) = reason_matches(&r, &reason) {
                        return bare(status, detail, &c, &id);
                    }
                    if let Some(detail) = unscoped(&["audit.export"]) {
                        return bare(403, detail, &c, &id);
                    }
                    let Some(job) = nonzero_uuid(&segment(&path, 6)) else {
                        return bare(400, "invalid identity job id", &c, &id);
                    };
                    match up::diagnostic_delete(&worker, actor, &job, &reason, operation).await {
                        CommandOutcome::Committed(_) => {
                            let mut response = crate::jmap::reply::response(
                                String::new(),
                                c.identity.proto,
                                id.clone(),
                            );
                            *response.status_mut() = hyper::StatusCode::NO_CONTENT;
                            response.headers_mut().remove("content-type");
                            response
                        }
                        CommandOutcome::RolledBack(e) => {
                            rejection(&e, "identity diagnostic deletion failed", &go_path, &c, &id)
                        }
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
            }
        })
    }
}

/// A 202 with the job's `Location` and `Retry-After: 2` (also on a 304).
fn accepted(
    raw: String,
    location: &str,
    r: &Request<Body>,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    let mut response = raw_json_as(raw, 202, None, r.headers().get("if-none-match"), c, id);
    let headers = response.headers_mut();
    headers.insert("location", location.parse().expect("location"));
    headers.insert("retry-after", hyper::header::HeaderValue::from_static("2"));
    response
}

/// `kind` and `terminal` of a job document as Go decodes `struct{Kind string; Terminal bool}`.
fn job_state(raw: &str) -> Option<(String, bool)> {
    let v: Value = serde_json::from_str(raw).ok()?;
    let object = v.as_object()?;
    let field = |name: &str| {
        object.get(name).or_else(|| {
            object
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v)
        })
    };
    let kind = match field("kind") {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(k)) => k.clone(),
        Some(_) => return None,
    };
    let terminal = match field("terminal") {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return None,
    };
    Some((kind, terminal))
}
