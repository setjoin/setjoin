//! F01 slice `idv2-sources` HTTP adapter, read half: the identity v2 list and detail
//! routes (sources, people, conflicts, events). Each route keeps Go's gate order
//! (live permission, audited bare 403), list option checks, ETag handling and bare
//! problem documents. Reads run on the worker executor, as Go's `workerPool` does.
//! See the crate DOX for the contract.
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use setjoin_admin_identity::idv2 as db;
use setjoin_admin_identity::idv2_ops as ops;
use setjoin_admin_identity::idv2_source as src;
use setjoin_admin_identity::idv2_writes as wr;
use setjoin_authz::token::KeySource;
use setjoin_pg::CommandOutcome;
use setjoin_pg::ScopedExecutor;
use sha2::{Digest as _, Sha256};
use std::sync::Arc;

mod transitions;

pub struct AdminIdentityV2Route<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub worker: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    pub secrets: SourceSecrets,
}

/// Go's identity connector secret codec, built once from the process configuration
/// and the `identity.deployment_id` row (Go builds it at startup).
type EnvLookup = Arc<dyn Fn(&str) -> Option<String> + Send + Sync>;

/// Go's `sourceProbe` (#400): the directory transport probe a dry run of an AD
/// or LDAP source makes. `Err(true)` is a rejected bind password, `Err(false)`
/// any other failure.
pub trait SourceProbe: Send + Sync {
    fn probe<'a>(
        &'a self,
        config: &'a setjoin_admin_identity::idv2_source::RuntimeConfig,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), bool>> + Send + 'a>>;
}

#[derive(Clone)]
pub struct SourceSecrets {
    env: EnvLookup,
    codec: Arc<tokio::sync::OnceCell<Arc<setjoin_config_secret::ConfigSecretCodec>>>,
    /// Without a probe a dry run of an AD or LDAP source with its secrets set is Go's.
    probe: Option<Arc<dyn SourceProbe>>,
}
impl SourceSecrets {
    pub fn new(env: impl Fn(&str) -> Option<String> + Send + Sync + 'static) -> Self {
        Self {
            env: Arc::new(env),
            codec: Arc::new(tokio::sync::OnceCell::new()),
            probe: None,
        }
    }
    pub fn with_probe(mut self, probe: Arc<dyn SourceProbe>) -> Self {
        self.probe = Some(probe);
        self
    }
    pub fn from_process_env() -> Self {
        Self::new(|name| std::env::var(name).ok())
    }
    pub(crate) async fn codec(
        &self,
        worker: &ScopedExecutor,
    ) -> Option<Arc<setjoin_config_secret::ConfigSecretCodec>> {
        self.codec
            .get_or_try_init(|| async {
                let rows = worker
                    .read(
                        "SELECT value #>> '{}' FROM system_config WHERE key = 'identity.deployment_id'",
                        &[],
                    )
                    .await
                    .map_err(|_| ())?;
                let deployment: String = rows
                    .first()
                    .and_then(|r| r.try_get::<_, Option<String>>(0).ok().flatten())
                    .ok_or(())?;
                let keyring = setjoin_config_secret::keyring_from_lookup(&deployment, |n| (self.env)(n))
                    .map_err(|_| ())?;
                setjoin_config_secret::ConfigSecretCodec::new(keyring)
                    .map(Arc::new)
                    .map_err(|_| ())
            })
            .await
            .ok()
            .cloned()
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Sources,
    People,
    Person,
    Conflicts,
    Conflict,
    Events,
    GroupMappings,
    Inventory,
    InventoryExport,
    Job,
    JobResults,
    SourceDetail,
    Lifecycle(&'static str),
    JobCancel,
    Decision,
    Plan,
    Apply,
    Secret(bool),
    DryRun,
    MappingsPut,
    Transition(transitions::Kind),
}

const TABLE: [(&str, Action); 16] = [
    ("/api/admin/identity/v2/sources", Action::Sources),
    ("/api/admin/identity/v2/people", Action::People),
    ("/api/admin/identity/v2/people/{id}", Action::Person),
    ("/api/admin/identity/v2/conflicts", Action::Conflicts),
    ("/api/admin/identity/v2/conflicts/{id}", Action::Conflict),
    ("/api/admin/identity/v2/events", Action::Events),
    ("/api/admin/identity/group-mappings", Action::GroupMappings),
    ("/api/admin/identity/inventory", Action::Inventory),
    (
        "/api/admin/identity/v2/inventory/export",
        Action::InventoryExport,
    ),
    ("/api/admin/identity/v2/jobs/{id}", Action::Job),
    (
        "/api/admin/identity/v2/jobs/{id}/results",
        Action::JobResults,
    ),
    (
        "/api/admin/identity/v2/sources/{sourceKey}",
        Action::SourceDetail,
    ),
    (
        "/api/admin/identity/v2/sources/{sourceKey}/export",
        Action::SourceDetail,
    ),
    (
        "/api/admin/identity/v2/transitions",
        Action::Transition(transitions::Kind::List),
    ),
    (
        "/api/admin/identity/v2/transitions/{id}",
        Action::Transition(transitions::Kind::Read),
    ),
    (
        "/api/admin/identity/v2/transitions/{id}/report",
        Action::Transition(transitions::Kind::Report),
    ),
];

const WRITES: [(&str, Action); 21] = [
    ("/api/admin/identity/v2/sources", Action::Apply),
    ("/api/admin/identity/v2/sources/plan", Action::Plan),
    (
        "/api/admin/identity/v2/sources/{sourceKey}/dry-run",
        Action::DryRun,
    ),
    (
        "/api/admin/identity/v2/sources/{sourceKey}/secrets/{name}/rotate",
        Action::Secret(true),
    ),
    (
        "/api/admin/identity/v2/sources/{sourceKey}/pause",
        Action::Lifecycle("pause"),
    ),
    (
        "/api/admin/identity/v2/sources/{sourceKey}/resume",
        Action::Lifecycle("resume"),
    ),
    (
        "/api/admin/identity/v2/sources/{sourceKey}/retire",
        Action::Lifecycle("retire"),
    ),
    (
        "/api/admin/identity/v2/sources/{sourceKey}/activate",
        Action::Lifecycle("activate"),
    ),
    ("/api/admin/identity/v2/jobs/{id}/cancel", Action::JobCancel),
    (
        "/api/admin/identity/v2/conflicts/{id}/decision",
        Action::Decision,
    ),
    (
        "/api/admin/identity/v2/transitions/preview",
        Action::Transition(transitions::Kind::Preview),
    ),
    (
        "/api/admin/identity/v2/transitions/{id}/request",
        Action::Transition(transitions::Kind::Command(transitions::Op::Request)),
    ),
    (
        "/api/admin/identity/v2/transitions/{id}/approve",
        Action::Transition(transitions::Kind::Command(transitions::Op::Approve)),
    ),
    (
        "/api/admin/identity/v2/transitions/{id}/deny",
        Action::Transition(transitions::Kind::Command(transitions::Op::Deny)),
    ),
    (
        "/api/admin/identity/v2/transitions/{id}/execute",
        Action::Transition(transitions::Kind::Command(transitions::Op::Execute)),
    ),
    (
        "/api/admin/identity/v2/transitions/{id}/cancel",
        Action::Transition(transitions::Kind::Command(transitions::Op::Cancel)),
    ),
    (
        "/api/admin/identity/v2/transitions/{id}/rollback",
        Action::Transition(transitions::Kind::Command(transitions::Op::Rollback)),
    ),
    (
        "/api/admin/identity/v2/transitions/{id}/rollback-preview",
        Action::Transition(transitions::Kind::Command(transitions::Op::RollbackPreview)),
    ),
    (
        "/api/admin/identity/v2/transitions/{id}/effects/{effectId}/retry",
        Action::Transition(transitions::Kind::Command(transitions::Op::Retry)),
    ),
    (
        "/api/admin/identity/v2/transitions/{id}/step-up/challenge",
        Action::Transition(transitions::Kind::Command(transitions::Op::ChallengeIssue)),
    ),
    (
        "/api/admin/identity/v2/transitions/{id}/step-up/complete",
        Action::Transition(transitions::Kind::Command(
            transitions::Op::ChallengeComplete,
        )),
    ),
];

const PUTS: [(&str, Action); 3] = [
    (
        "/api/admin/identity/group-mappings/{type}/{id}",
        Action::MappingsPut,
    ),
    ("/api/admin/identity/v2/sources/{sourceKey}", Action::Apply),
    (
        "/api/admin/identity/v2/sources/{sourceKey}/secrets/{name}",
        Action::Secret(false),
    ),
];

fn action(method: &Method, path: &str) -> Option<Action> {
    let table: &[(&str, Action)] = match *method {
        Method::GET | Method::HEAD => &TABLE,
        Method::POST => &WRITES,
        Method::PUT => &PUTS,
        _ => return None,
    };
    table
        .iter()
        .filter(|(pattern, _)| crate::inventory::path_score(pattern, path).is_some())
        .max_by_key(|(pattern, _)| crate::inventory::path_score(pattern, path))
        .map(|(_, action)| *action)
}

/// Go's `r.PathValue`: the percent-decoded segment at `index` of the full path.
pub(crate) fn segment(path: &str, index: usize) -> String {
    crate::guests_input::go_utf8(&crate::inventory::unescape(
        path.split('/').nth(index).unwrap_or(""),
    ))
}

impl<K: KeySource + 'static> Intercept for AdminIdentityV2Route<K> {
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
        let secrets = self.secrets.clone();
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
            let Ok(authority) = setjoin_admin_identity::authority(&exec, actor).await else {
                return c.upstream.forward(r, &c.identity).await;
            };
            // Go's audited route guard: `RequirePermAudited` (users.read, audit.read),
            // `RequireAnyPermAudited` (the Auth console set) or
            // `RequireAnyPermissionSetAudited` (the job access sets).
            let required: &[&str] = match what {
                Action::Events => &["audit.read"],
                Action::InventoryExport | Action::Transition(transitions::Kind::Report) => {
                    &["audit.export"]
                }
                Action::GroupMappings | Action::Inventory => &setjoin_admin_identity::AUTH_CONSOLE,
                Action::Job | Action::JobResults | Action::JobCancel => {
                    &["audit.export", "system.upgrade", "identity.write"]
                }
                Action::Lifecycle(_)
                | Action::Decision
                | Action::Plan
                | Action::Apply
                | Action::Secret(_)
                | Action::MappingsPut
                | Action::DryRun
                | Action::Transition(transitions::Kind::Preview | transitions::Kind::Command(_)) => {
                    &["identity.write"]
                }
                _ => &["users.read"],
            };
            let passed = match what {
                Action::Job | Action::JobResults | Action::JobCancel => {
                    authority.allows_any(&["audit.export"])
                        || (authority.allows_any(&["system.upgrade"])
                            && authority.allows_any(&["identity.write"]))
                }
                _ => authority.allows_any(required),
            };
            if !passed {
                let detail = match what {
                    Action::Job | Action::JobResults | Action::JobCancel => {
                        "audit.export|system.upgrade&identity.write".to_owned()
                    }
                    _ => required.join("|"),
                };
                let _ = setjoin_admin_identity::console_denied(
                    &exec, actor, &go_path, &detail, operation,
                )
                .await;
                return bare(403, "Forbidden", &c, &id);
            }
            if authority.refused_for_scope(required) {
                let detail = format!(
                    "{} (domain-scoped principal; org-wide-only surface, domain={})",
                    required.join("|"),
                    authority.domain_scope()
                );
                let _ = setjoin_admin_identity::console_denied(
                    &exec, actor, &go_path, &detail, operation,
                )
                .await;
                return bare(403, "Forbidden", &c, &id);
            }
            // The handlers' own source-wide gates (`requireUnscopedIdentityAdmin`: every
            // permission, then scope; `requireAnyUnscopedIdentityAdmin`: scope, then one).
            let handler_gate: Option<&str> = match what {
                Action::GroupMappings | Action::Inventory => {
                    if authority.domain_scope() != 0 {
                        Some(UNSCOPED)
                    } else if !authority.global_any(&setjoin_admin_identity::AUTH_CONSOLE) {
                        Some(LIVE)
                    } else {
                        None
                    }
                }
                Action::Job | Action::JobResults | Action::JobCancel => {
                    if authority.domain_scope() != 0 {
                        Some(UNSCOPED)
                    } else if !authority.global_any(&[
                        "audit.export",
                        "identity.write",
                        "system.upgrade",
                    ]) {
                        Some(LIVE)
                    } else {
                        None
                    }
                }
                Action::InventoryExport
                | Action::SourceDetail
                | Action::Transition(transitions::Kind::Report) => {
                    let one = if what == Action::InventoryExport
                        || what == Action::Transition(transitions::Kind::Report)
                    {
                        "audit.export"
                    } else {
                        "users.read"
                    };
                    if !authority.global_any(&[one]) {
                        Some(LIVE)
                    } else if authority.domain_scope() != 0 {
                        Some(UNSCOPED)
                    } else {
                        None
                    }
                }
                _ => None,
            };
            if let Some(detail) = handler_gate {
                return bare(403, detail, &c, &id);
            }
            // Go's `RequireReason(identity.write)` in front of the source, decision and
            // diagnostic writes.
            let ip = c.identity.client_ip.to_string();
            if matches!(
                what,
                Action::Lifecycle(_)
                    | Action::Decision
                    | Action::Apply
                    | Action::Secret(_)
                    | Action::MappingsPut
                    | Action::DryRun
                    | Action::Transition(transitions::Kind::Preview)
                    | Action::Transition(transitions::Kind::Command(
                        transitions::Op::Request
                            | transitions::Op::Approve
                            | transitions::Op::Deny
                            | transitions::Op::Execute
                            | transitions::Op::Rollback
                            | transitions::Op::Cancel
                            | transitions::Op::RollbackPreview
                            | transitions::Op::Retry
                    ))
            ) && wr::reason_required(&exec).await
                && r.headers()
                    .get("x-audit-reason")
                    .is_none_or(|v| v.as_bytes().is_empty())
            {
                wr::missing_reason(&exec, actor, &ip, operation).await;
                return bare(400, "reason_required", &c, &id);
            }
            let scope = authority.domain_scope();
            let user = actor.user_id();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let refuse = |e: db::Refusal| refusal(e, &go_path, &c, &id);
            let query = r.uri().query().unwrap_or("").to_owned();
            if let Action::Transition(kind) = what {
                let call = transitions::Call {
                    worker: &worker,
                    auth: &auth,
                    actor,
                    scope,
                    operation,
                    path: &path,
                    go_path: &go_path,
                    query: &query,
                    now,
                    id: &id,
                    c: &c,
                };
                return transitions::serve(kind, r, &call).await;
            }
            // Responses that are not an ETagged list or detail document.
            match what {
                Action::GroupMappings => {
                    let body = ops::group_mappings(&exec).await;
                    return json_reply(body, &c, &id);
                }
                Action::Inventory => {
                    return match ops::inventory(&worker).await {
                        Ok(body) => json_reply(body, &c, &id),
                        Err(e) => refuse(e),
                    };
                }
                Action::InventoryExport => {
                    let raw = match ops::inventory_export(&worker).await {
                        Ok(raw) => raw,
                        Err(e) => return refuse(e),
                    };
                    let sum = Sha256::digest(raw.as_bytes());
                    use base64::Engine as _;
                    let digest = format!(
                        "sha-256={}",
                        base64::engine::general_purpose::STANDARD.encode(sum)
                    );
                    let mut response = raw_json(raw, r.headers().get("if-none-match"), &c, &id);
                    let headers = response.headers_mut();
                    headers.insert(
                        "content-disposition",
                        "attachment; filename=\"setjoin-identity-inventory.json\""
                            .parse()
                            .expect("header"),
                    );
                    headers.insert("digest", digest.parse().expect("header"));
                    return response;
                }
                Action::Job | Action::JobResults => {
                    let Some(job) = db::parse_uuid(&segment(&path, 6))
                        .filter(|u| u != "00000000-0000-0000-0000-000000000000")
                    else {
                        return bare(400, "invalid identity job id", &c, &id);
                    };
                    let held = |kind: &str| match kind {
                        "diagnostics" => authority.global_any(&["audit.export"]),
                        "upgrade_backfill" | "cohort_preview" => {
                            authority.global_any(&["system.upgrade"])
                                && authority.global_any(&["identity.write"])
                        }
                        _ => false,
                    };
                    let raw = match ops::job(&worker, user, &job).await {
                        Ok(raw) => raw,
                        Err(mut e) => {
                            if what == Action::JobResults {
                                e.detail = "identity job permission check failed".into();
                            }
                            return refuse(e);
                        }
                    };
                    if raw.is_empty() || raw == "null" {
                        return bare(404, "identity job not found", &c, &id);
                    }
                    let state: Option<(String, bool)> =
                        serde_json::from_str::<serde_json::Value>(&raw)
                            .ok()
                            .and_then(|v| {
                                let object = v.as_object()?;
                                let field = |name: &str| {
                                    object.get(name).or_else(|| {
                                        object
                                            .iter()
                                            .find(|(k, _)| k.to_ascii_lowercase() == name)
                                            .map(|(_, v)| v)
                                    })
                                };
                                let kind = match field("kind") {
                                    None | Some(serde_json::Value::Null) => String::new(),
                                    Some(serde_json::Value::String(k)) => k.clone(),
                                    Some(_) => return None,
                                };
                                let terminal = match field("terminal") {
                                    None | Some(serde_json::Value::Null) => false,
                                    Some(serde_json::Value::Bool(b)) => *b,
                                    Some(_) => return None,
                                };
                                Some((kind, terminal))
                            });
                    if what == Action::Job {
                        let Some((kind, terminal)) = state else {
                            return bare(500, "identity job returned an invalid response", &c, &id);
                        };
                        if !held(&kind) {
                            return bare(403, "identity job permission is no longer held", &c, &id);
                        }
                        let mut response = raw_json(raw, r.headers().get("if-none-match"), &c, &id);
                        if !terminal {
                            response.headers_mut().insert(
                                "retry-after",
                                hyper::header::HeaderValue::from_static("2"),
                            );
                        }
                        return response;
                    }
                    if !state.as_ref().is_some_and(|(kind, _)| held(kind)) {
                        return bare(403, "identity job permission is no longer held", &c, &id);
                    }
                    let mut after = 0i64;
                    let mut limit = 100i32;
                    let pairs = db::query_first(&query);
                    if let Some(value) = pairs.get("after").filter(|v| !v.is_empty()) {
                        match value.parse::<i64>() {
                            Ok(n) if n >= 0 => after = n,
                            _ => return bare(400, "invalid identity job result cursor", &c, &id),
                        }
                    }
                    if let Some(value) = pairs.get("limit").filter(|v| !v.is_empty()) {
                        match value.parse::<i64>() {
                            Ok(n) if (1..=500).contains(&n) => limit = n as i32,
                            _ => {
                                return bare(
                                    400,
                                    "identity job result limit must be between 1 and 500",
                                    &c,
                                    &id,
                                )
                            }
                        }
                    }
                    return match ops::job_results(&worker, user, &job, after, limit).await {
                        Ok(raw) if raw.is_empty() || raw == "null" => {
                            bare(404, "identity job not found", &c, &id)
                        }
                        Ok(raw) => raw_json(raw, r.headers().get("if-none-match"), &c, &id),
                        Err(e) => refuse(e),
                    };
                }
                Action::SourceDetail => {
                    let key = segment(&path, 6);
                    if !db::valid_source_key(&key) {
                        return bare(400, "invalid identity source key", &c, &id);
                    }
                    let row = match ops::load_source(&worker, &key).await {
                        Ok(Some(row)) => row,
                        Ok(None) => return bare(404, "identity source not found", &c, &id),
                        Err(_) => return bare(500, "identity source lookup failed", &c, &id),
                    };
                    let stored = match secrets.codec(&worker).await {
                        Some(codec) => ops::decode_stored(&codec, &key, &row.envelope),
                        None => None,
                    };
                    let Some(stored) = stored else {
                        return bare(
                            500,
                            "identity source stored document cannot be decrypted",
                            &c,
                            &id,
                        );
                    };
                    let body = ops::source_detail_body(&key, &row, &stored);
                    return raw_json(body, r.headers().get("if-none-match"), &c, &id);
                }
                Action::Lifecycle(name) => {
                    let Some(bytes) = read_body(&mut r).await else {
                        return bare(400, "invalid identity source lifecycle request", &c, &id);
                    };
                    let members = match wr::strict_object(
                        &bytes,
                        &["expectedGeneration", "idempotencyKey", "reason"],
                    ) {
                        Ok(m) => m,
                        Err(e) => {
                            return body_refusal(
                                e,
                                "invalid identity source lifecycle request",
                                &c,
                                &id,
                            )
                        }
                    };
                    let (Ok(expected_text), Ok(key_text), Ok(reason)) = (
                        wr::text(&members, "expectedGeneration"),
                        wr::text(&members, "idempotencyKey"),
                        wr::text(&members, "reason"),
                    ) else {
                        return bare(400, "invalid identity source lifecycle request", &c, &id);
                    };
                    let expected = match expected_generation(&r, &expected_text) {
                        Ok(n) => n,
                        Err((status, detail)) => return bare(status, detail, &c, &id),
                    };
                    let idempotency = match mutation_key(&r, &key_text) {
                        Ok(k) => k,
                        Err((status, detail)) => return bare(status, detail, &c, &id),
                    };
                    if let Err((status, detail)) = reason_matches(&r, &reason) {
                        return bare(status, detail, &c, &id);
                    }
                    // `requireUnscopedIdentityAdmin()`: identity.write, then scope.
                    if !authority.global_any(&["identity.write"]) {
                        return bare(403, LIVE, &c, &id);
                    }
                    if authority.domain_scope() != 0 {
                        return bare(403, UNSCOPED, &c, &id);
                    }
                    let key = segment(&path, 6);
                    if !db::valid_source_key(&key) {
                        return bare(400, "invalid identity source key", &c, &id);
                    }
                    let outcome = wr::lifecycle(
                        &worker,
                        actor,
                        &key,
                        name,
                        expected,
                        &idempotency,
                        &reason,
                        operation,
                    )
                    .await;
                    let raw = match outcome {
                        CommandOutcome::Committed(raw) => raw.unwrap_or_default(),
                        CommandOutcome::RolledBack(e) => {
                            return rejection(
                                &e,
                                "identity source lifecycle failed",
                                &go_path,
                                &c,
                                &id,
                            )
                        }
                        CommandOutcome::Unknown { operation } => {
                            return unknown_outcome(operation, &c, &id)
                        }
                    };
                    let generation = serde_json::from_str::<serde_json::Value>(&raw)
                        .ok()
                        .and_then(|v| {
                            let object = v.as_object()?;
                            let member = object.get("generation").or_else(|| {
                                object
                                    .iter()
                                    .find(|(k, _)| k.eq_ignore_ascii_case("generation"))
                                    .map(|(_, v)| v)
                            });
                            match member {
                                Some(serde_json::Value::String(g)) if !g.is_empty() => {
                                    Some(g.clone())
                                }
                                _ => None,
                            }
                        });
                    let Some(generation) = generation else {
                        return bare(
                            500,
                            "identity source lifecycle returned invalid result",
                            &c,
                            &id,
                        );
                    };
                    let mut response = raw_json_as(
                        raw,
                        202,
                        Some(generation),
                        r.headers().get("if-none-match"),
                        &c,
                        &id,
                    );
                    response.headers_mut().insert(
                        "location",
                        format!("/api/admin/identity/v2/sources/{key}")
                            .parse()
                            .expect("location"),
                    );
                    return response;
                }
                Action::MappingsPut => {
                    // `requireUnscopedIdentityAdmin()` opens the handler.
                    if let Some(refused) = unscoped_all_identity(&authority) {
                        return bare(403, refused, &c, &id);
                    }
                    let (provider_type, provider_id) = (segment(&path, 5), segment(&path, 6));
                    // `http.MaxBytesReader(1 MiB)` then a first-value decode: any failure is
                    // "invalid JSON".
                    let bytes = {
                        use http_body_util::BodyExt;
                        let mut bytes = Vec::new();
                        let mut over = false;
                        while let Some(frame) = r.body_mut().frame().await {
                            let Ok(frame) = frame else {
                                over = true;
                                break;
                            };
                            if let Ok(data) = frame.into_data() {
                                bytes.extend_from_slice(&data);
                                if bytes.len() > 1 << 20 {
                                    over = true;
                                    break;
                                }
                            }
                        }
                        (!over).then(|| crate::guests_input::go_json_bytes(&bytes))
                    };
                    let Some(list) = bytes.and_then(|b| wr::decode_group_mappings(&b)) else {
                        return bare(400, "invalid JSON", &c, &id);
                    };
                    if let Err(detail) = wr::validate_group_mappings(&list) {
                        return bare(400, &detail, &c, &id);
                    }
                    let rendered = wr::render_group_mappings(&list);
                    return match wr::group_mappings_put(
                        &exec,
                        actor,
                        &provider_type,
                        &provider_id,
                        &rendered,
                        authority.permissions(),
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(v) if v.status == 204 => {
                            let mut response = crate::jmap::reply::response(
                                String::new(),
                                c.identity.proto,
                                id.clone(),
                            );
                            *response.status_mut() = hyper::StatusCode::NO_CONTENT;
                            response.headers_mut().remove("content-type");
                            response
                        }
                        CommandOutcome::Committed(v) => bare(v.status, &v.detail, &c, &id),
                        CommandOutcome::RolledBack(_) => bare(500, "update failed", &c, &id),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    };
                }
                Action::Plan => {
                    let Some(bytes) = read_body(&mut r).await else {
                        return bare(400, "invalid identity source document", &c, &id);
                    };
                    let text = match wr::single_value(&bytes) {
                        Ok(text) => text.to_owned(),
                        Err(e) => {
                            return body_refusal(e, "invalid identity source document", &c, &id)
                        }
                    };
                    let document = match src::validate(&text) {
                        src::Validation::Valid(d) => d,
                        src::Validation::Refuse(detail) => return bare(400, &detail, &c, &id),
                        src::Validation::Forward => return forward_body(r, bytes, &c).await,
                    };
                    if let Some(refused) = unscoped_all_identity(&authority) {
                        return bare(403, refused, &c, &id);
                    }
                    let row = match ops::load_source(&worker, &document.key).await {
                        Ok(row) => row,
                        Err(_) => return bare(500, "identity source plan failed", &c, &id),
                    };
                    let mut changed = true;
                    let mut operations = "[\"create_draft\"]".to_owned();
                    let mut current = String::new();
                    if let Some(row) = &row {
                        let stored = match secrets.codec(&worker).await {
                            Some(codec) => ops::decode_stored(&codec, &document.key, &row.envelope),
                            None => None,
                        };
                        let Some(stored) = stored else {
                            return bare(
                                500,
                                "identity source stored document cannot be decrypted",
                                &c,
                                &id,
                            );
                        };
                        changed = stored.raw != document.canonical;
                        operations = if changed {
                            "[\"update_draft_config\",\"increment_generation\"]".into()
                        } else {
                            "[]".into()
                        };
                        current = format!(",\"currentGeneration\":\"{}\"", row.generation);
                    }
                    let body = setjoin_admin_identity::go_escape(&format!(
                        "{{\"sourceKey\":{},\"create\":{},\"changed\":{changed}{current},\"desired\":{},\"operations\":{operations}}}",
                        serde_json::to_string(&document.key).expect("string"),
                        row.is_none(),
                        document.canonical
                    ));
                    return raw_json(body, r.headers().get("if-none-match"), &c, &id);
                }
                Action::Apply => {
                    const BAD: &str = "invalid identity source apply request";
                    let Some(bytes) = read_body(&mut r).await else {
                        return bare(400, BAD, &c, &id);
                    };
                    let members = match wr::strict_object(
                        &bytes,
                        &["document", "reason", "idempotencyKey"],
                    ) {
                        Ok(m) => m,
                        Err(e) => return body_refusal(e, BAD, &c, &id),
                    };
                    let (Ok(reason), Ok(key_text)) = (
                        wr::text(&members, "reason"),
                        wr::text(&members, "idempotencyKey"),
                    ) else {
                        return bare(400, BAD, &c, &id);
                    };
                    let raw_document = members
                        .get("document")
                        .map(|d| d.get().to_owned())
                        .unwrap_or_default();
                    let document = match src::validate(&raw_document) {
                        src::Validation::Valid(d) => d,
                        src::Validation::Refuse(detail) => return bare(400, &detail, &c, &id),
                        src::Validation::Forward => return forward_body(r, bytes, &c).await,
                    };
                    let path_key = if r.method() == Method::PUT {
                        segment(&path, 6)
                    } else {
                        String::new()
                    };
                    if !path_key.is_empty() && path_key != document.key {
                        return bare(
                            400,
                            "path sourceKey must match document metadata.sourceKey",
                            &c,
                            &id,
                        );
                    }
                    let idempotency = match mutation_key(&r, &key_text) {
                        Ok(k) => k,
                        Err((status, detail)) => return bare(status, detail, &c, &id),
                    };
                    if let Err((status, detail)) = reason_matches(&r, &reason) {
                        return bare(status, detail, &c, &id);
                    }
                    if let Some(refused) = unscoped_all_identity(&authority) {
                        return bare(403, refused, &c, &id);
                    }
                    let mut expected: Option<i64> = None;
                    let mut kept: std::collections::BTreeMap<String, String> = Default::default();
                    let mut status = 201;
                    match ops::load_source(&worker, &document.key).await {
                        Ok(Some(row)) => {
                            match expected_generation(&r, &row.generation.to_string()) {
                                Ok(n) => expected = Some(n),
                                Err((status, detail)) => return bare(status, detail, &c, &id),
                            }
                            let stored = match secrets.codec(&worker).await {
                                Some(codec) => {
                                    ops::decode_stored(&codec, &document.key, &row.envelope)
                                }
                                None => None,
                            };
                            let Some(stored) = stored else {
                                return bare(
                                    500,
                                    "identity source stored document cannot be decrypted",
                                    &c,
                                    &id,
                                );
                            };
                            kept = stored.secrets;
                            status = 200;
                        }
                        Ok(None) => {
                            if !header_text(&r, "if-match").trim().is_empty() {
                                return bare(
                                    412,
                                    "new identity source must not send If-Match",
                                    &c,
                                    &id,
                                );
                            }
                        }
                        Err(_) => return bare(500, "identity source lookup failed", &c, &id),
                    }
                    let sealed = match secrets.codec(&worker).await {
                        Some(codec) => codec
                            .encrypt(
                                &format!("identity_source.{}", document.key),
                                src::stored_plaintext(&document.canonical, &kept).as_bytes(),
                            )
                            .ok()
                            .map(|envelope| (envelope, i64::from(codec.active_version()))),
                        None => None,
                    };
                    let Some((envelope, key_version)) = sealed else {
                        return bare(503, "identity source encryption is unavailable", &c, &id);
                    };
                    let input = src::Apply {
                        document: &document,
                        envelope: &envelope,
                        key_version,
                        expected,
                        idempotency: &idempotency,
                        reason: &reason,
                    };
                    return finish_generation(
                        src::apply(&worker, actor, &input, operation).await,
                        status,
                        "identity source apply failed",
                        "identity source apply returned invalid result",
                        &r,
                        &go_path,
                        &c,
                        &id,
                    );
                }
                Action::Secret(rotate) => {
                    if let Some(refused) = unscoped_all_identity(&authority) {
                        return bare(403, refused, &c, &id);
                    }
                    let content_type = header_text(&r, "content-type");
                    if !is_octet_stream(&content_type) {
                        return bare(
                            415,
                            "identity source secrets require application/octet-stream",
                            &c,
                            &id,
                        );
                    }
                    let (key, name) = (segment(&path, 6), segment(&path, 8));
                    if !db::valid_source_key(&key) || !src::bounded(&name, 64) {
                        return bare(400, "invalid identity source secret path", &c, &id);
                    }
                    let row = match ops::load_source(&worker, &key).await {
                        Ok(Some(row)) => row,
                        Ok(None) => return bare(404, "identity source not found", &c, &id),
                        Err(_) => return bare(500, "identity source lookup failed", &c, &id),
                    };
                    if !ops::secret_catalog(&row.kind).contains(&name.as_str()) {
                        return bare(
                            400,
                            "secret name is not valid for this source kind",
                            &c,
                            &id,
                        );
                    }
                    let expected = match expected_generation(&r, &row.generation.to_string()) {
                        Ok(n) => n,
                        Err((status, detail)) => return bare(status, detail, &c, &id),
                    };
                    let idempotency =
                        match db::parse_uuid(header_text(&r, "idempotency-key").trim())
                            .filter(|u| u != "00000000-0000-0000-0000-000000000000")
                        {
                            Some(k) => k,
                            None => return bare(400, "invalid Idempotency-Key", &c, &id),
                        };
                    let reason = header_text(&r, "x-identity-reason");
                    if let Err((status, detail)) = reason_matches(&r, &reason) {
                        return bare(status, detail, &c, &id);
                    }
                    let secret = match read_secret(&mut r).await {
                        Ok(bytes) => bytes,
                        Err(SecretError::TooLarge) => {
                            return bare(413, "identity source secret exceeds 65536 bytes", &c, &id)
                        }
                        Err(SecretError::Unreadable) => {
                            return bare(400, "identity source secret could not be read", &c, &id)
                        }
                    };
                    if secret.is_empty() {
                        return bare(400, "identity source secret must be non-empty", &c, &id);
                    }
                    let codec = secrets.codec(&worker).await;
                    let stored = match &codec {
                        Some(codec) => ops::decode_stored(codec, &key, &row.envelope),
                        None => None,
                    };
                    let Some(mut stored) = stored else {
                        return bare(
                            500,
                            "identity source stored document cannot be decrypted",
                            &c,
                            &id,
                        );
                    };
                    if rotate && stored.secrets.get(&name).is_none_or(|v| v.is_empty()) {
                        return bare(
                            409,
                            "cannot rotate an identity source secret that is not configured",
                            &c,
                            &id,
                        );
                    }
                    {
                        use base64::Engine as _;
                        stored.secrets.insert(
                            name.clone(),
                            base64::engine::general_purpose::STANDARD.encode(&secret),
                        );
                    }
                    let document = if stored.raw.is_empty() {
                        "null".to_owned()
                    } else {
                        stored.raw.clone()
                    };
                    let sealed = codec.as_ref().and_then(|codec| {
                        codec
                            .encrypt(
                                &format!("identity_source.{key}"),
                                src::stored_plaintext(&document, &stored.secrets).as_bytes(),
                            )
                            .ok()
                            .map(|envelope| (envelope, i64::from(codec.active_version())))
                    });
                    let Some((envelope, key_version)) = sealed else {
                        return bare(503, "identity source encryption is unavailable", &c, &id);
                    };
                    return finish_generation(
                        src::set_secret(
                            &worker,
                            actor,
                            &key,
                            &name,
                            &envelope,
                            key_version,
                            expected,
                            rotate,
                            &idempotency,
                            &reason,
                            operation,
                        )
                        .await,
                        202,
                        "identity source secret update failed",
                        "identity source secret update returned invalid result",
                        &r,
                        &go_path,
                        &c,
                        &id,
                    );
                }
                Action::DryRun => {
                    if let Some(refused) = unscoped_all_identity(&authority) {
                        return bare(403, refused, &c, &id);
                    }
                    const BAD: &str = "invalid identity source dry-run request";
                    let Some(bytes) = read_body(&mut r).await else {
                        return bare(400, BAD, &c, &id);
                    };
                    let members = match wr::strict_object(
                        &bytes,
                        &["expectedGeneration", "idempotencyKey", "reason"],
                    ) {
                        Ok(m) => m,
                        Err(e) => return body_refusal(e, BAD, &c, &id),
                    };
                    let (Ok(expected_text), Ok(key_text), Ok(reason)) = (
                        wr::text(&members, "expectedGeneration"),
                        wr::text(&members, "idempotencyKey"),
                        wr::text(&members, "reason"),
                    ) else {
                        return bare(400, BAD, &c, &id);
                    };
                    let expected = match expected_generation(&r, &expected_text) {
                        Ok(n) => n,
                        Err((status, detail)) => return bare(status, detail, &c, &id),
                    };
                    let idempotency = match mutation_key(&r, &key_text) {
                        Ok(k) => k,
                        Err((status, detail)) => return bare(status, detail, &c, &id),
                    };
                    if let Err((status, detail)) = reason_matches(&r, &reason) {
                        return bare(status, detail, &c, &id);
                    }
                    let key = segment(&path, 6);
                    let row = match ops::load_source(&worker, &key).await {
                        Ok(Some(row)) => row,
                        Ok(None) => return bare(404, "identity source not found", &c, &id),
                        Err(_) => return bare(500, "identity source lookup failed", &c, &id),
                    };
                    if expected != row.generation {
                        return bare(412, "identity source generation is stale", &c, &id);
                    }
                    let stored = match secrets.codec(&worker).await {
                        Some(codec) => ops::decode_stored(&codec, &key, &row.envelope),
                        None => None,
                    };
                    let Some(stored) = stored else {
                        return bare(
                            500,
                            "identity source stored document cannot be decrypted",
                            &c,
                            &id,
                        );
                    };
                    if !matches!(src::validate(&stored.raw), src::Validation::Valid(_)) {
                        return bare(409, "stored identity source document is invalid", &c, &id);
                    }
                    let mut posture: Vec<(&str, bool)> = ops::secret_catalog(&row.kind)
                        .iter()
                        .map(|n| (*n, stored.secrets.get(*n).is_some_and(|v| !v.is_empty())))
                        .collect();
                    posture.sort_unstable();
                    let secret_json = format!(
                        "{{{}}}",
                        posture
                            .iter()
                            .map(|(n, v)| format!("\"{n}\":{v}"))
                            .collect::<Vec<_>>()
                            .join(",")
                    );
                    let needs = matches!(row.kind.as_str(), "ad" | "ldap" | "scim" | "oidc");
                    let mut blockers: Vec<String> = posture
                        .iter()
                        .filter(|(_, configured)| !configured && needs)
                        .map(|(n, _)| format!("secret_missing:{n}"))
                        .collect();
                    let mut transport = "not_required";
                    if blockers.is_empty() && matches!(row.kind.as_str(), "ad" | "ldap") {
                        // The directory transport probe (Go `h.sourceProbe`); without
                        // one wired the whole request is Go's.
                        let Some(probe) = secrets.probe.clone() else {
                            return forward_body(r, bytes, &c).await;
                        };
                        let codec = secrets.codec(&worker).await;
                        match src::decode_runtime(codec.as_deref(), &key, &row.kind, &row.envelope)
                        {
                            Err(_) => {
                                blockers.push("runtime_configuration_invalid".into());
                                transport = "failed";
                            }
                            Ok(config) => match probe.probe(&config).await {
                                Ok(()) => transport = "reachable",
                                Err(true) => {
                                    blockers.push("credential_rejected".into());
                                    transport = "reachable";
                                }
                                Err(false) => {
                                    blockers.push("directory_probe_failed".into());
                                    transport = "failed";
                                }
                            },
                        }
                    }
                    if !blockers.is_empty() {
                        let list = blockers
                            .iter()
                            .map(|b| serde_json::to_string(b).expect("string"))
                            .collect::<Vec<_>>()
                            .join(",");
                        let body = format!(
                            "{{\"blockers\":[{list}],\"personWrites\":0,\"secretConfigured\":{secret_json},\"sourceKey\":{},\"transport\":\"{transport}\",\"valid\":false}}",
                            serde_json::to_string(&key).expect("string")
                        );
                        return raw_json(
                            setjoin_admin_identity::go_escape(&body),
                            r.headers().get("if-none-match"),
                            &c,
                            &id,
                        );
                    }
                    let outcome = wr::lifecycle(
                        &worker,
                        actor,
                        &key,
                        "validate",
                        expected,
                        &idempotency,
                        &reason,
                        operation,
                    )
                    .await;
                    let outcome = match outcome {
                        CommandOutcome::Committed(Some(raw)) => {
                            // `json.Unmarshal` into a map, the extras added, then `json.Marshal`.
                            let extras = format!(
                                "{{\"valid\":true,\"transport\":\"{transport}\",\"personWrites\":0,\"blockers\":[],\"secretConfigured\":{secret_json}}}"
                            );
                            let merged = match (
                                serde_json::from_str::<serde_json::Value>(&raw),
                                serde_json::from_str::<serde_json::Value>(&extras),
                            ) {
                                (
                                    Ok(serde_json::Value::Object(mut base)),
                                    Ok(serde_json::Value::Object(extra)),
                                ) => {
                                    base.extend(extra);
                                    Some(serde_json::Value::Object(base).to_string())
                                }
                                _ => None,
                            };
                            CommandOutcome::Committed(Some(merged.unwrap_or(raw)))
                        }
                        other => other,
                    };
                    return with_location(
                        finish_generation(
                            outcome,
                            202,
                            "identity source lifecycle failed",
                            "identity source lifecycle returned invalid result",
                            &r,
                            &go_path,
                            &c,
                            &id,
                        ),
                        &key,
                    );
                }
                Action::JobCancel => {
                    let Some(job) = db::parse_uuid(&segment(&path, 6))
                        .filter(|u| u != "00000000-0000-0000-0000-000000000000")
                    else {
                        return bare(400, "invalid identity job id", &c, &id);
                    };
                    let mut held: Vec<String> = Vec::new();
                    if authority.global_any(&["audit.export"]) {
                        held.push("diagnostics".into());
                    }
                    if authority.global_any(&["system.upgrade"])
                        && authority.global_any(&["identity.write"])
                    {
                        held.push("upgrade_backfill".into());
                        held.push("cohort_preview".into());
                    }
                    return match wr::job_cancel(&worker, actor, &job, &held, operation).await {
                        CommandOutcome::Committed(v) => match v.status {
                            404 => bare(404, "identity job not found", &c, &id),
                            403 => bare(403, "identity job permission is no longer held", &c, &id),
                            _ => match v.body.filter(|b| !b.is_empty() && b != "null") {
                                None => bare(404, "identity job not found", &c, &id),
                                Some(raw) => raw_json_as(
                                    raw,
                                    202,
                                    None,
                                    r.headers().get("if-none-match"),
                                    &c,
                                    &id,
                                ),
                            },
                        },
                        CommandOutcome::RolledBack(e) => {
                            rejection(&e, "identity job cancel failed", &go_path, &c, &id)
                        }
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    };
                }
                Action::Decision => {
                    let Some(conflict) = db::parse_uuid(&segment(&path, 6))
                        .filter(|u| u != "00000000-0000-0000-0000-000000000000")
                    else {
                        return bare(400, "invalid conflict id", &c, &id);
                    };
                    let Some(bytes) = read_body(&mut r).await else {
                        return bare(400, "invalid identity conflict decision", &c, &id);
                    };
                    let members = match wr::strict_object(
                        &bytes,
                        &[
                            "decision",
                            "personId",
                            "expectedGeneration",
                            "reason",
                            "idempotencyKey",
                        ],
                    ) {
                        Ok(m) => m,
                        Err(e) => {
                            return body_refusal(e, "invalid identity conflict decision", &c, &id)
                        }
                    };
                    let (
                        Ok(decision),
                        Ok(person_text),
                        Ok(expected_text),
                        Ok(reason),
                        Ok(key_text),
                    ) = (
                        wr::text(&members, "decision"),
                        wr::text(&members, "personId"),
                        wr::text(&members, "expectedGeneration"),
                        wr::text(&members, "reason"),
                        wr::text(&members, "idempotencyKey"),
                    )
                    else {
                        return bare(400, "invalid identity conflict decision", &c, &id);
                    };
                    let decision_ok = decision == decision.trim()
                        && matches!(decision.as_str(), "link" | "create" | "reject" | "defer");
                    if !wr::valid_reason(&reason) || !decision_ok {
                        return bare(400, "invalid identity conflict decision", &c, &id);
                    }
                    if header_text(&r, "x-audit-reason") != reason {
                        return bare(
                            400,
                            "body reason must exactly match X-Audit-Reason",
                            &c,
                            &id,
                        );
                    }
                    let idempotency = match mutation_key(&r, &key_text) {
                        Ok(k) => k,
                        Err((status, detail)) => return bare(status, detail, &c, &id),
                    };
                    let generation = match expected_generation(&r, &expected_text) {
                        Ok(n) => n,
                        Err((status, detail)) => return bare(status, detail, &c, &id),
                    };
                    let mut person: Option<i64> = None;
                    if !person_text.is_empty() {
                        match person_text.parse::<i64>() {
                            Ok(n) if n > 0 => person = Some(n),
                            _ => return bare(400, "invalid personId", &c, &id),
                        }
                    }
                    if (decision == "link") != person.is_some() {
                        return bare(400, "personId is required only for link decisions", &c, &id);
                    }
                    let refusal_detail = if !authority.global_any(&["identity.write"]) {
                        LIVE
                    } else if authority.domain_scope() != 0 {
                        UNSCOPED
                    } else {
                        ""
                    };
                    let input = wr::DecideInput {
                        conflict: &conflict,
                        generation,
                        decision: &decision,
                        person,
                        reason: &reason,
                        idempotency: &idempotency,
                        unscoped_refusal: refusal_detail,
                    };
                    return match wr::conflict_decide(&worker, actor, &input, operation).await {
                        CommandOutcome::Committed(v) => match v.status {
                            404 => bare(404, "identity conflict not found", &c, &id),
                            403 => bare(403, &v.body.unwrap_or_default(), &c, &id),
                            _ => raw_json_as(
                                v.body.unwrap_or_default(),
                                200,
                                Some(expected_text),
                                r.headers().get("if-none-match"),
                                &c,
                                &id,
                            ),
                        },
                        CommandOutcome::RolledBack(e) => {
                            rejection(&e, "identity conflict decision failed", &go_path, &c, &id)
                        }
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    };
                }
                _ => {}
            }
            let body = match what {
                Action::Sources | Action::People | Action::Conflicts | Action::Events => {
                    let spec = match what {
                        Action::Sources => &db::SOURCES,
                        Action::People => &db::PEOPLE,
                        Action::Conflicts => &db::CONFLICTS,
                        _ => &db::EVENTS,
                    };
                    let opts = match db::parse_list(&query, spec, user, scope, now) {
                        Ok(opts) => opts,
                        Err(e) => return refuse(e),
                    };
                    let page = match what {
                        Action::Sources => db::sources(&worker, user, scope, &opts, now).await,
                        Action::People => db::people(&worker, user, &opts, now).await,
                        Action::Conflicts => db::conflicts(&worker, user, scope, &opts, now).await,
                        _ => db::events(&worker, user, scope, &opts, now).await,
                    };
                    match page {
                        Ok(body) => body,
                        Err(e) => return refuse(e),
                    }
                }
                Action::Person => {
                    // Go's `strconv.ParseInt(.., 10, 64)` and `id <= 0`.
                    let Some(person) = segment(&path, 6).parse::<i64>().ok().filter(|n| *n > 0)
                    else {
                        return bare(400, "invalid person id", &c, &id);
                    };
                    match db::person(&worker, user, person).await {
                        Ok(Some(raw)) if raw != "null" && !raw.is_empty() => raw,
                        Ok(_) => return bare(404, "identity person not found", &c, &id),
                        Err(e) => return refuse(e),
                    }
                }
                Action::GroupMappings
                | Action::Inventory
                | Action::InventoryExport
                | Action::Job
                | Action::JobResults
                | Action::SourceDetail
                | Action::Lifecycle(_)
                | Action::JobCancel
                | Action::Decision
                | Action::Plan
                | Action::Apply
                | Action::Secret(_)
                | Action::MappingsPut
                | Action::DryRun
                | Action::Transition(_) => unreachable!("answered above"),
                Action::Conflict => {
                    let Some(conflict) = db::parse_uuid(&segment(&path, 6))
                        .filter(|u| u != "00000000-0000-0000-0000-000000000000")
                    else {
                        return bare(400, "invalid conflict id", &c, &id);
                    };
                    match db::conflict(&worker, user, &conflict).await {
                        Ok(Some(raw)) => raw,
                        Ok(None) => return bare(404, "identity conflict not found", &c, &id),
                        Err(e) => return refuse(e),
                    }
                }
            };
            // Lists are `json.Marshal` output (HTML-escaped); person and conflict detail
            // write the database's jsonb text unchanged.
            let body = if matches!(what, Action::Person | Action::Conflict) {
                body
            } else {
                setjoin_admin_identity::go_escape(&body)
            };
            raw_json(body, r.headers().get("if-none-match"), &c, &id)
        })
    }
}

/// `httputil.WriteJSON`: the encoder's trailing newline, no ETag; one write, so a body
/// over net/http's 2 KiB buffer is chunked.
pub(crate) fn json_reply(body: String, c: &RequestContext, id: &str) -> Response<Body> {
    let chunked = body.len() > 2048;
    let mut response = crate::jmap::reply::response(body, c.identity.proto, id.to_owned());
    if chunked {
        response.headers_mut().insert(
            "transfer-encoding",
            hyper::header::HeaderValue::from_static("chunked"),
        );
    }
    response
}

/// A refusal as Go writes it: a bare problem, or `reducererr.WriteClassified`'s full one.
pub(crate) fn refusal(e: db::Refusal, path: &str, c: &RequestContext, id: &str) -> Response<Body> {
    let Some((code, remediation)) = e.reducer else {
        return bare(e.status, &e.detail, c, id);
    };
    let quote = |t: &str| serde_json::to_string(t).expect("string");
    let body = format!(
        "{{\"type\":\"https://setjoin.com/problems/reducer/{}\",\"title\":{},\"status\":{},\"detail\":{},\"instance\":{},\"remediation\":{},\"code\":{},\"retryable\":false}}",
        code.to_ascii_lowercase(),
        quote(title(e.status)),
        e.status,
        quote(&e.detail),
        quote(path),
        quote(&remediation),
        quote(&code)
    );
    let mut r = crate::jmap::reply::response(
        setjoin_admin_identity::go_escape(&body) + "\n",
        c.identity.proto,
        id.to_owned(),
    );
    *r.status_mut() = hyper::StatusCode::from_u16(e.status).expect("status");
    let headers = r.headers_mut();
    headers.insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/problem+json"),
    );
    headers.insert(
        "content-language",
        hyper::header::HeaderValue::from_static("en"),
    );
    r
}

/// Go's `requireUnscopedIdentityAdmin()` for `identity.write`: the refusal detail, if any.
fn unscoped_all_identity(authority: &setjoin_admin_identity::Authority) -> Option<&'static str> {
    if !authority.global_any(&["identity.write"]) {
        Some(LIVE)
    } else if authority.domain_scope() != 0 {
        Some(UNSCOPED)
    } else {
        None
    }
}

/// Re-send a request whose body was already read to Go (an outcome that is not modelled).
pub(crate) async fn forward_body(
    r: Request<Body>,
    bytes: Vec<u8>,
    c: &RequestContext,
) -> Response<Body> {
    use http_body_util::BodyExt;
    let (parts, _) = r.into_parts();
    let body: Body = http_body_util::Full::new(hyper::body::Bytes::from(bytes))
        .map_err(|never| match never {})
        .boxed();
    c.upstream
        .forward(Request::from_parts(parts, body), &c.identity)
        .await
}

/// A reducer's committed result that must carry a `generation`: the route's success
/// status with the generation as ETag, or the reducer's classified refusal / Go's 500.
#[allow(clippy::too_many_arguments)]
fn finish_generation(
    outcome: CommandOutcome<Option<String>, setjoin_pg::StatementFailure>,
    status: u16,
    failed: &str,
    invalid: &str,
    r: &Request<Body>,
    go_path: &str,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    let raw = match outcome {
        CommandOutcome::Committed(raw) => raw.unwrap_or_default(),
        CommandOutcome::RolledBack(e) => return rejection(&e, failed, go_path, c, id),
        CommandOutcome::Unknown { operation } => return unknown_outcome(operation, c, id),
    };
    let generation = serde_json::from_str::<serde_json::Value>(&raw)
        .ok()
        .and_then(|v| {
            let object = v.as_object()?;
            let member = object.get("generation").or_else(|| {
                object
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case("generation"))
                    .map(|(_, v)| v)
            });
            match member {
                Some(serde_json::Value::String(g)) if !g.is_empty() => Some(g.clone()),
                _ => None,
            }
        });
    let Some(generation) = generation else {
        return bare(500, invalid, c, id);
    };
    raw_json_as(
        raw,
        status,
        Some(generation),
        r.headers().get("if-none-match"),
        c,
        id,
    )
}

/// The dry-run's `Location` header on its 202 / 304.
fn with_location(mut response: Response<Body>, key: &str) -> Response<Body> {
    if response.status() == hyper::StatusCode::ACCEPTED
        || response.status() == hyper::StatusCode::NOT_MODIFIED
    {
        response.headers_mut().insert(
            "location",
            format!("/api/admin/identity/v2/sources/{key}")
                .parse()
                .expect("location"),
        );
    }
    response
}

/// `mime.ParseMediaType(...) == "application/octet-stream"`.
fn is_octet_stream(value: &str) -> bool {
    let mut parts = value.split(';');
    let media = parts.next().unwrap_or("").trim().to_ascii_lowercase();
    media == "application/octet-stream" && parts.all(|p| p.trim().is_empty() || p.contains('='))
}

enum SecretError {
    TooLarge,
    Unreadable,
}

/// `io.ReadAll(http.MaxBytesReader(.., 64 KiB))`.
async fn read_secret(r: &mut Request<Body>) -> Result<Vec<u8>, SecretError> {
    use http_body_util::BodyExt;
    let mut bytes = Vec::new();
    while let Some(frame) = r.body_mut().frame().await {
        let frame = frame.map_err(|_| SecretError::Unreadable)?;
        if let Ok(data) = frame.into_data() {
            if bytes.len() + data.len() > 64 << 10 {
                return Err(SecretError::TooLarge);
            }
            bytes.extend_from_slice(&data);
        }
    }
    Ok(bytes)
}

pub(crate) const LIVE: &str =
    "source-wide identity operations require a live unscoped permission grant";
pub(crate) const UNSCOPED: &str = "source-wide identity operations require unscoped authority";

/// The request body up to one byte past Go's 64 KiB cap, UTF-8 repaired as `encoding/json` reads it.
pub(crate) async fn read_body(r: &mut Request<Body>) -> Option<Vec<u8>> {
    use http_body_util::BodyExt;
    let mut bytes = Vec::new();
    while let Some(frame) = r.body_mut().frame().await {
        let frame = frame.ok()?;
        if let Ok(data) = frame.into_data() {
            bytes.extend_from_slice(&data);
            if bytes.len() > wr::BODY_MAX {
                bytes.truncate(wr::BODY_MAX + 1);
                break;
            }
        }
    }
    Some(crate::guests_input::go_json_bytes(&bytes))
}

pub(crate) fn header_text(r: &Request<Body>, name: &str) -> String {
    r.headers()
        .get(name)
        .map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned())
        .unwrap_or_default()
}

pub(crate) fn body_refusal(
    e: wr::BodyError,
    detail: &str,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    match e {
        wr::BodyError::TooLarge => bare(413, "identity request body exceeds 65536 bytes", c, id),
        wr::BodyError::Invalid => bare(400, detail, c, id),
    }
}

/// Go's `identityExpectedGeneration`.
fn expected_generation(r: &Request<Body>, body: &str) -> Result<i64, (u16, &'static str)> {
    let Some(value) = body.parse::<i64>().ok().filter(|n| *n > 0) else {
        return Err((400, "invalid expectedGeneration"));
    };
    if header_text(r, "if-match").trim() != format!("\"{body}\"") {
        return Err((412, "If-Match must be the strong current generation ETag"));
    }
    Ok(value)
}

/// Go's `identityMutationHeaders`: the canonical idempotency UUID.
fn mutation_key(r: &Request<Body>, body: &str) -> Result<String, (u16, &'static str)> {
    let header = header_text(r, "idempotency-key");
    let header = header.trim();
    if body.is_empty() || header.is_empty() || body != header {
        return Err((
            400,
            "body idempotencyKey must exactly match Idempotency-Key",
        ));
    }
    match db::parse_uuid(body).filter(|u| u != "00000000-0000-0000-0000-000000000000") {
        Some(key) => Ok(key),
        None => Err((400, "invalid Idempotency-Key")),
    }
}

/// Go's `identityReasonMatches`.
pub(crate) fn reason_matches(r: &Request<Body>, body: &str) -> Result<(), (u16, &'static str)> {
    let header = header_text(r, "x-audit-reason");
    if !wr::valid_reason(body) || !wr::valid_reason(&header) || body != header {
        return Err((400, "body reason must exactly match X-Audit-Reason"));
    }
    Ok(())
}

/// A rolled back command: a known reducer refusal, or Go's 500 for the route.
pub(crate) fn rejection(
    e: &setjoin_pg::Rejection<setjoin_pg::StatementFailure>,
    fallback: &str,
    path: &str,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    let (setjoin_pg::Rejection::Statement(f) | setjoin_pg::Rejection::Body(f)) = e else {
        return bare(500, fallback, c, id);
    };
    match ops::classify(f) {
        Some(refusal_) => refusal(refusal_, path, c, id),
        None => bare(500, fallback, c, id),
    }
}

pub(crate) fn unknown_outcome(
    operation: setjoin_contracts::ids::OperationId,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    let mut response = bare(503, "operation outcome unknown", c, id);
    response.headers_mut().insert(
        "x-operation-id",
        setjoin_pg::operation_hex(operation)
            .parse()
            .expect("operation"),
    );
    response
}

/// Go's `writeIdentityRawJSON`: strong ETag over the body, 304 on a match, no newline.
pub(crate) fn raw_json(
    body: String,
    if_none_match: Option<&hyper::header::HeaderValue>,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    raw_json_as(body, 200, None, if_none_match, c, id)
}

/// `writeIdentityRawJSON(status, raw, version)`: the ETag is `version` when given,
/// else the body's SHA-256; a matching `If-None-Match` answers 304 whatever the status.
pub(crate) fn raw_json_as(
    body: String,
    status: u16,
    version: Option<String>,
    if_none_match: Option<&hyper::header::HeaderValue>,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    let version = version.unwrap_or_else(|| {
        Sha256::digest(body.as_bytes())
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    });
    let etag = format!("\"{version}\"");
    let matched = if_none_match
        .and_then(|v| v.to_str().ok())
        .is_some_and(|header| {
            header
                .split(',')
                .map(|candidate| candidate.trim_matches(|c: char| c.is_ascii_whitespace()))
                .any(|candidate| candidate == "*" || candidate == etag)
        });
    // net/http buffers 2 KiB of a handler's output; a larger single write is flushed
    // before the handler returns and is sent chunked.
    let chunked = !matched && body.len() > 2048;
    let mut response = crate::jmap::reply::response(
        if matched { String::new() } else { body },
        c.identity.proto,
        id.to_owned(),
    );
    response
        .headers_mut()
        .insert("etag", etag.parse().expect("etag"));
    if chunked {
        response.headers_mut().insert(
            "transfer-encoding",
            hyper::header::HeaderValue::from_static("chunked"),
        );
    }
    if matched {
        *response.status_mut() = hyper::StatusCode::NOT_MODIFIED;
        response.headers_mut().remove("content-type");
    } else {
        *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
    }
    response
}

fn title(status: u16) -> &'static str {
    crate::problem::title(status)
}

/// Go's `WriteProblemStatus`: a minimal problem, empty instance, no language.
pub(crate) fn bare(status: u16, detail: &str, c: &RequestContext, id: &str) -> Response<Body> {
    let quote = |t: &str| serde_json::to_string(t).expect("string");
    let body = format!(
        "{{\"type\":\"about:blank\",\"title\":{},\"status\":{status},\"detail\":{},\"instance\":\"\"}}",
        quote(title(status)),
        quote(detail)
    );
    let mut r = crate::jmap::reply::response(
        setjoin_admin_identity::go_escape(&body) + "\n",
        c.identity.proto,
        id.to_owned(),
    );
    *r.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
    r.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/problem+json"),
    );
    r
}
