//! F03 Conditional access HTTP adapter. The two-slice map and each slice's contract live in the
//! `setjoin-conditional-access` DOX. Every route is gated like Go's `requireCAPolicyRead|Write`
//! (`RequirePermAudited`) from the live governed grants: a refusal writes Go's durable
//! `console.denied` audit row and answers the bare 403. A failed authority read or a missing
//! token forwards the untouched request to Go, as every family adapter does, so Go keeps
//! answering 401 and any state it alone can judge. Errors are Go's bare `WriteError`.
use crate::admin_identity_input::query;
use crate::mailboxes::{bare, unknown_outcome};
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use serde::de::{MapAccess, Visitor};
use serde_json::value::RawValue;
use setjoin_authz::token::KeySource;
use setjoin_conditional_access::policies as db;
use setjoin_conditional_access::policy;
use setjoin_pg::{CommandOutcome, ScopedExecutor};
use std::fmt;
use std::sync::Arc;

pub struct ConditionalAccessRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    /// The worker credential (`DB_WORKER_DSN`) for the reads and writes Go makes on its worker
    /// pool (session log, user risk); the request credential when unset.
    pub worker: Option<ScopedExecutor>,
    pub keys: Arc<K>,
    pub issuer: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Action {
    PolicyList,
    PolicyCreate,
    PolicyUpdate,
    PolicyDelete,
    PolicyRestore,
    PolicyPromote,
    PolicyRestoreFromAudit,
    PolicyReorder,
    More(crate::conditional_access_more::More),
}

/// Method/pattern table; the first column is the method predicate. The `remaining` slice
/// appends rows.
pub(crate) fn action(method: &Method, path: &str) -> Option<Action> {
    let reads = matches!(*method, Method::GET | Method::HEAD);
    let post = *method == Method::POST;
    let table: [(bool, &str, Action); 8] = [
        (
            reads,
            "/api/admin/conditional-access/policies",
            Action::PolicyList,
        ),
        (
            post,
            "/api/admin/conditional-access/policies",
            Action::PolicyCreate,
        ),
        (
            *method == Method::PUT,
            "/api/admin/conditional-access/policies/{id}",
            Action::PolicyUpdate,
        ),
        (
            *method == Method::DELETE,
            "/api/admin/conditional-access/policies/{id}",
            Action::PolicyDelete,
        ),
        (
            post,
            "/api/admin/conditional-access/policies/{id}/restore",
            Action::PolicyRestore,
        ),
        (
            post,
            "/api/admin/conditional-access/policies/{id}/promote",
            Action::PolicyPromote,
        ),
        (
            post,
            "/api/admin/conditional-access/policies/restore-from-audit",
            Action::PolicyRestoreFromAudit,
        ),
        (
            post,
            "/api/admin/conditional-access/policies/reorder",
            Action::PolicyReorder,
        ),
    ];
    table
        .iter()
        .filter(|(ok, pattern, _)| *ok && crate::inventory::path_score(pattern, path).is_some())
        .max_by_key(|(_, pattern, _)| crate::inventory::path_score(pattern, path))
        .map(|(_, _, action)| *action)
        .or_else(|| crate::conditional_access_more::action(method, path).map(Action::More))
}

/// Go's `requireCAPolicyRead` / `requireCAPolicyWrite`.
fn gate(what: Action) -> &'static [&'static str] {
    match what {
        Action::PolicyList => &setjoin_conditional_access::POLICY_READ,
        Action::More(more) if more.reads() => &setjoin_conditional_access::POLICY_READ,
        _ => &setjoin_conditional_access::POLICY_WRITE,
    }
}

fn segment_path(path: &str) -> String {
    crate::mail_security::segment_path(path)
}
fn segment(path: &str, index: usize) -> String {
    crate::mail_security::segment(path, index)
}

/// Go's `caPolicyCreate` decoded by `json.NewDecoder(...).Decode`: keys match
/// case-insensitively (the last duplicate wins), `null` leaves a plain field at its zero
/// value, a `json.RawMessage` keeps its literal text (`null` included), unknown keys are
/// ignored and any wrongly typed value is a decode error.
#[derive(Default)]
struct PolicyBody {
    priority: Option<i64>,
    name: String,
    description: String,
    state: String,
    scope_type: String,
    scope_target: String,
    conditions: Option<Box<RawValue>>,
    actions: Option<Box<RawValue>>,
    exclude_users: Option<Box<RawValue>>,
    exclude_groups: Option<Box<RawValue>>,
    session_control: Option<Box<RawValue>>,
}

impl<'de> serde::Deserialize<'de> for PolicyBody {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = PolicyBody;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<PolicyBody, E> {
                Ok(PolicyBody::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<PolicyBody, M::Error> {
                let mut body = PolicyBody::default();
                while let Some(key) = map.next_key::<String>()? {
                    macro_rules! text {
                        ($field:ident) => {
                            if let Some(value) = map.next_value::<Option<String>>()? {
                                body.$field = value;
                            }
                        };
                    }
                    match crate::guests_input::fold(&key).as_str() {
                        "priority" => {
                            if let Some(value) = map.next_value::<Option<i64>>()? {
                                body.priority = Some(value);
                            }
                        }
                        "name" => text!(name),
                        "description" => text!(description),
                        "state" => text!(state),
                        "scope_type" => text!(scope_type),
                        "scope_target" => text!(scope_target),
                        "conditions" => body.conditions = Some(map.next_value()?),
                        "actions" => body.actions = Some(map.next_value()?),
                        "exclude_users" => body.exclude_users = Some(map.next_value()?),
                        "exclude_groups" => body.exclude_groups = Some(map.next_value()?),
                        "session_control" => body.session_control = Some(map.next_value()?),
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                Ok(body)
            }
        }
        decoder.deserialize_any(Fields)
    }
}

fn raw_text(raw: &Option<Box<RawValue>>) -> Option<&str> {
    raw.as_deref().map(RawValue::get)
}

/// `{"audit_id": n}`; a missing or null key is zero.
#[derive(Default)]
struct AuditBody {
    audit_id: i64,
}
impl<'de> serde::Deserialize<'de> for AuditBody {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = AuditBody;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<AuditBody, E> {
                Ok(AuditBody::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<AuditBody, M::Error> {
                let mut body = AuditBody::default();
                while let Some(key) = map.next_key::<String>()? {
                    if crate::guests_input::fold(&key) == "audit_id" {
                        if let Some(value) = map.next_value::<Option<i64>>()? {
                            body.audit_id = value;
                        }
                    } else {
                        let _: serde::de::IgnoredAny = map.next_value()?;
                    }
                }
                Ok(body)
            }
        }
        decoder.deserialize_any(Fields)
    }
}

/// `{"confirm": bool}`; a missing or null key is false.
#[derive(Default)]
struct ConfirmBody {
    confirm: bool,
}
impl<'de> serde::Deserialize<'de> for ConfirmBody {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = ConfirmBody;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<ConfirmBody, E> {
                Ok(ConfirmBody::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<ConfirmBody, M::Error> {
                let mut body = ConfirmBody::default();
                while let Some(key) = map.next_key::<String>()? {
                    if crate::guests_input::fold(&key) == "confirm" {
                        if let Some(value) = map.next_value::<Option<bool>>()? {
                            body.confirm = value;
                        }
                    } else {
                        let _: serde::de::IgnoredAny = map.next_value()?;
                    }
                }
                Ok(body)
            }
        }
        decoder.deserialize_any(Fields)
    }
}

/// `[]int64`: `null` is empty, a `null` element is zero, a non-array is a decode error.
struct Ids(Vec<i64>);
impl<'de> serde::Deserialize<'de> for Ids {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        let list = Option::<Vec<Option<i64>>>::deserialize(decoder)?;
        Ok(Ids(list
            .unwrap_or_default()
            .into_iter()
            .map(|id| id.unwrap_or(0))
            .collect()))
    }
}

impl<K: KeySource + 'static> Intercept for ConditionalAccessRoute<K> {
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
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        let worker = self.worker.clone();
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
            let required = gate(what);
            let Ok(authority) = setjoin_conditional_access::authority(&exec, actor).await else {
                return c.upstream.forward(r, &c.identity).await;
            };
            if !authority.allows_any(required) {
                let _ = setjoin_conditional_access::console_denied(
                    &exec,
                    actor,
                    &segment_path(r.uri().path()),
                    &required.join("|"),
                    operation,
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
                let _ = setjoin_conditional_access::console_denied(
                    &exec,
                    actor,
                    &segment_path(r.uri().path()),
                    &detail,
                    operation,
                )
                .await;
                return bare(403, "Forbidden", &c, &id);
            }
            let head = r.method() == Method::HEAD;
            let reply = |body: String, status: u16| {
                // net/http buffers 2 KiB of a handler's output; a larger single write
                // is flushed before the handler returns and sent chunked.
                let chunked = body.len() > 2048 && !head;
                let mut response = crate::jmap::reply::response(body, c.identity.proto, id.clone());
                *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
                if chunked {
                    response.headers_mut().insert(
                        "transfer-encoding",
                        hyper::header::HeaderValue::from_static("chunked"),
                    );
                }
                response
            };
            let no_content = || {
                let mut response =
                    crate::jmap::reply::response(String::new(), c.identity.proto, id.clone());
                *response.status_mut() = hyper::StatusCode::NO_CONTENT;
                response.headers_mut().remove("content-type");
                response
            };
            let failed = |p: db::Projected| bare(p.status, &p.detail, &c, &id);
            let refused = |e: &setjoin_pg::Rejection<setjoin_pg::StatementFailure>| {
                failed(db::project_rejection(e))
            };
            let path = r.uri().path().to_owned();
            let ip = c.identity.client_ip.to_string();
            let user = actor.user_id();
            // Go's `strconv.ParseInt(r.PathValue("id"), 10, 64)`.
            let policy_id = || segment(&path, 5).parse::<i64>().ok();
            match what {
                Action::More(more) => {
                    let worker = worker.as_ref().unwrap_or(&exec);
                    let x = crate::conditional_access_more::Ctx {
                        exec: &exec,
                        worker,
                        actor,
                        c: &c,
                        id: &id,
                        operation,
                        ip: &ip,
                        path: &path,
                        head,
                    };
                    crate::conditional_access_more::serve(more, &mut r, &x).await
                }
                Action::PolicyList => {
                    let include = query(r.uri(), "include_deleted").as_deref() == Some("1");
                    match db::list(&exec, actor, include).await {
                        Ok(body) => reply(body, 200),
                        Err(_) => bare(500, "database error", &c, &id),
                    }
                }
                Action::PolicyCreate | Action::PolicyUpdate => {
                    let update = what == Action::PolicyUpdate;
                    let target = if update {
                        let Some(target) = policy_id() else {
                            return bare(400, "invalid policy ID", &c, &id);
                        };
                        Some(target)
                    } else {
                        None
                    };
                    let Ok(body) =
                        crate::admin_identity_input::first::<PolicyBody>(&mut r, 1 << 20).await
                    else {
                        return bare(400, "invalid JSON", &c, &id);
                    };
                    if body.name.is_empty() {
                        return bare(400, "name is required", &c, &id);
                    }
                    // F6: the policy document shape is validated before the reducer.
                    let parse = |raw: &Option<Box<RawValue>>| match raw {
                        Some(raw) if !raw.get().is_empty() => policy::parse_object(raw.get()),
                        _ => Ok(None),
                    };
                    let Ok(conditions) = parse(&body.conditions) else {
                        return bare(400, "conditions: invalid JSON object", &c, &id);
                    };
                    let Ok(actions) = parse(&body.actions) else {
                        return bare(400, "actions: invalid JSON object", &c, &id);
                    };
                    if let Err(e) = policy::validate_document(conditions.as_ref(), actions.as_ref())
                    {
                        return bare(400, &e.to_string(), &c, &id);
                    }
                    let request = db::Policy {
                        name: &body.name,
                        description: &body.description,
                        state: &body.state,
                        scope_type: &body.scope_type,
                        scope_target: &body.scope_target,
                        priority: body.priority,
                        conditions: raw_text(&body.conditions),
                        actions: raw_text(&body.actions),
                        exclude_users: raw_text(&body.exclude_users),
                        exclude_groups: raw_text(&body.exclude_groups),
                        session_control: raw_text(&body.session_control),
                    };
                    // Owner-approved security fix 2026-11-05 (#467): the stored policy and the
                    // scope being written must both be in the caller's reach.
                    let scope_type = if body.scope_type.is_empty() {
                        "global"
                    } else {
                        body.scope_type.as_str()
                    };
                    match db::gate(
                        &exec,
                        actor,
                        target,
                        None,
                        Some((scope_type, body.scope_target.as_str())),
                        false,
                    )
                    .await
                    {
                        Ok(db::Gate::Allowed) => {}
                        Ok(db::Gate::NotFound) => return failed(db::not_found()),
                        Ok(db::Gate::Forbidden) => {
                            return bare(403, "policy scope is outside your administrative scope", &c, &id)
                        }
                        Err(_) => return bare(500, "database error", &c, &id),
                    }
                    // Owner decision 2026-11-06: a domain-limited admin's policy cannot take
                    // effect before an org-wide policy.
                    match db::priority_allowed(&exec, actor, body.priority, None).await {
                        Ok(true) => {}
                        Ok(false) => {
                            return bare(
                                403,
                                "priority must come after every organization-wide policy",
                                &c,
                                &id,
                            )
                        }
                        Err(_) => return bare(500, "database error", &c, &id),
                    }
                    match db::save(&exec, actor, &ip, target, &request, operation).await {
                        CommandOutcome::Committed(out) => {
                            reply(out, if update { 200 } else { 201 })
                        }
                        CommandOutcome::RolledBack(e) => refused(&e),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::PolicyDelete | Action::PolicyRestore => {
                    let Some(target) = policy_id() else {
                        return bare(400, "invalid policy ID", &c, &id);
                    };
                    match db::gate(&exec, actor, Some(target), None, None, false).await {
                        Ok(db::Gate::Allowed) => {}
                        Ok(_) => return failed(db::not_found()),
                        Err(_) => return bare(500, "database error", &c, &id),
                    }
                    let outcome = if what == Action::PolicyDelete {
                        db::soft_delete(&exec, actor, target, operation).await
                    } else {
                        db::restore(&exec, actor, target, operation).await
                    };
                    match outcome {
                        CommandOutcome::Committed(()) => no_content(),
                        CommandOutcome::RolledBack(e) => refused(&e),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::PolicyRestoreFromAudit => {
                    let Ok(body) =
                        crate::admin_identity_input::first::<AuditBody>(&mut r, 1 << 16).await
                    else {
                        return bare(400, "invalid JSON", &c, &id);
                    };
                    if body.audit_id == 0 {
                        return bare(400, "audit_id is required", &c, &id);
                    }
                    match db::gate(&exec, actor, None, Some(body.audit_id), None, false).await {
                        Ok(db::Gate::Allowed) => {}
                        Ok(_) => return failed(db::not_found()),
                        Err(_) => return bare(500, "database error", &c, &id),
                    }
                    match db::priority_allowed(&exec, actor, None, Some(body.audit_id)).await {
                        Ok(true) => {}
                        Ok(false) => {
                            return bare(
                                403,
                                "priority must come after every organization-wide policy",
                                &c,
                                &id,
                            )
                        }
                        Err(_) => return bare(500, "database error", &c, &id),
                    }
                    match db::restore_from_audit(&exec, actor, body.audit_id, operation).await {
                        CommandOutcome::Committed(new) => reply(
                            setjoin_conditional_access::done(format!("{{\"id\":{new}}}")),
                            200,
                        ),
                        CommandOutcome::RolledBack(e) => refused(&e),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::PolicyReorder => {
                    let Ok(ids) = crate::admin_identity_input::first::<Ids>(&mut r, 1 << 20).await
                    else {
                        return bare(400, "invalid JSON: expected array of policy IDs", &c, &id);
                    };
                    if ids.0.is_empty() {
                        return bare(400, "at least one policy ID required", &c, &id);
                    }
                    for policy in &ids.0 {
                        match db::gate(&exec, actor, Some(*policy), None, None, false).await {
                            Ok(db::Gate::Allowed) => {}
                            Ok(_) => return failed(db::not_found()),
                            Err(_) => return bare(500, "database error", &c, &id),
                        }
                    }
                    match db::reorder(&exec, actor, &ip, &ids.0, operation).await {
                        CommandOutcome::Committed(()) => no_content(),
                        CommandOutcome::RolledBack(e) => refused(&e),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::PolicyPromote => {
                    let Some(target) = policy_id() else {
                        return bare(400, "invalid policy ID", &c, &id);
                    };
                    let Ok(body) =
                        crate::admin_identity_input::first::<ConfirmBody>(&mut r, 1 << 16).await
                    else {
                        return bare(400, "invalid JSON", &c, &id);
                    };
                    match db::gate(&exec, actor, Some(target), None, None, false).await {
                        Ok(db::Gate::Allowed) => {}
                        Ok(_) => return failed(db::not_found()),
                        Err(_) => return bare(500, "database error", &c, &id),
                    }
                    // Step 1: the 7d impact summary, read before any decision.
                    let summary = match db::impact(&exec, actor, target, None).await {
                        Ok(text) => text,
                        Err(e) => return failed(db::project(&e)),
                    };
                    let Some((would_block, admins, window)) = db::parse_summary(&summary) else {
                        return bare(500, "impact read failed", &c, &id);
                    };
                    if !body.confirm {
                        // Preview only: a read, never a mutation.
                        if would_block > 0 {
                            let list = match db::impact(&exec, actor, target, Some("blocked_users")).await
                            {
                                Ok(text) => text,
                                Err(e) => return failed(db::project(&e)),
                            };
                            let Some(mut preview) = db::parse_list(&list) else {
                                return bare(500, "impact read failed", &c, &id);
                            };
                            preview.would_block_users = would_block;
                            preview.would_block_admins = admins;
                            preview.window = window;
                            preview.self_locked_out = preview.blocked.iter().any(|u| u.0 == user)
                                || preview.admins.iter().any(|u| u.0 == user);
                            return reply(preview.render(), 409);
                        }
                        return reply(db::Preview::zeroed(window).render(), 200);
                    }
                    match db::promote(&exec, actor, target, operation).await {
                        CommandOutcome::Committed(out) => reply(out, 200),
                        CommandOutcome::RolledBack(e) => refused(&e),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
            }
        })
    }
}
