//! F01 slice `org-policies` HTTP adapter: departments, email-address policies and the
//! distribution-group picker. Gates are Go's per-route middleware: `requireMailPerm`
//! (reads), `requireUsersCreate` (department writes), `requireIdentityWrite` (policy
//! writes) and `requireScopeSetsManage` (picker). Go audits none of the writes and
//! applies no required-reason policy here. See the crate DOX for the contract.
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use serde::de::{MapAccess, Visitor};
use setjoin_admin_identity::org_policies::{self as db, DepartmentPatch, PolicyInput};
use setjoin_authz::token::KeySource;
use setjoin_pg::{CommandOutcome, Rejection, ScopedExecutor};
use std::fmt;
use std::sync::Arc;

pub struct AdminOrgPoliciesRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    DeptList,
    DeptTree,
    DeptCreate,
    DeptUpdate,
    DeptDelete,
    DeptAssign,
    PolicyList,
    PolicyCreate,
    PolicyUpdate,
    PolicyDelete,
    PolicyReorder,
    PolicyPreview,
    PolicyMatchCount,
    PolicyApply,
    PolicyApplyStatus,
    Groups,
}

fn action(method: &Method, path: &str) -> Option<Action> {
    let reads = matches!(*method, Method::GET | Method::HEAD);
    let post = *method == Method::POST;
    let put = *method == Method::PUT;
    let delete = *method == Method::DELETE;
    let table: [(bool, &str, Action); 16] = [
        (reads, "/api/admin/departments", Action::DeptList),
        (reads, "/api/admin/departments/tree", Action::DeptTree),
        (post, "/api/admin/departments", Action::DeptCreate),
        (put, "/api/admin/departments/{id}", Action::DeptUpdate),
        (delete, "/api/admin/departments/{id}", Action::DeptDelete),
        (
            post,
            "/api/admin/departments/assign-user",
            Action::DeptAssign,
        ),
        (
            reads,
            "/api/admin/email-address-policies-list",
            Action::PolicyList,
        ),
        (
            post,
            "/api/admin/email-address-policies",
            Action::PolicyCreate,
        ),
        (
            put,
            "/api/admin/email-address-policies/{id}",
            Action::PolicyUpdate,
        ),
        (
            delete,
            "/api/admin/email-address-policies/{id}",
            Action::PolicyDelete,
        ),
        (
            post,
            "/api/admin/email-address-policies/reorder",
            Action::PolicyReorder,
        ),
        (
            post,
            "/api/admin/email-address-policies/{id}/preview",
            Action::PolicyPreview,
        ),
        (
            post,
            "/api/admin/email-address-policies/match-count",
            Action::PolicyMatchCount,
        ),
        (
            post,
            "/api/admin/email-address-policies/apply",
            Action::PolicyApply,
        ),
        (
            reads,
            "/api/admin/email-address-policies/apply/{jobId}",
            Action::PolicyApplyStatus,
        ),
        (reads, "/api/admin/distribution-groups", Action::Groups),
    ];
    table
        .iter()
        .filter(|(ok, pattern, _)| *ok && crate::inventory::path_score(pattern, path).is_some())
        .max_by_key(|(_, pattern, _)| crate::inventory::path_score(pattern, path))
        .map(|(_, _, action)| *action)
}

/// The permissions of Go's per-route middleware (any-of).
fn required(what: Action) -> &'static [&'static str] {
    match what {
        Action::DeptList
        | Action::DeptTree
        | Action::PolicyList
        | Action::PolicyPreview
        | Action::PolicyMatchCount
        | Action::PolicyApplyStatus => &db::MAIL_CONSOLE,
        Action::DeptCreate | Action::DeptUpdate | Action::DeptDelete | Action::DeptAssign => {
            &setjoin_admin_identity::USERS_CREATE
        }
        Action::PolicyCreate
        | Action::PolicyUpdate
        | Action::PolicyDelete
        | Action::PolicyReorder
        | Action::PolicyApply => &db::IDENTITY_WRITE,
        Action::Groups => &setjoin_admin_identity::scope_sets::SCOPE_SETS_MANAGE,
    }
}

/// Go's `r.PathValue`: the percent-decoded segment at `index` of the full path.
fn segment(path: &str, index: usize) -> String {
    crate::guests_input::go_utf8(&crate::inventory::unescape(
        path.split('/').nth(index).unwrap_or(""),
    ))
}

/// Go `json.NewDecoder(r.Body).Decode(&struct)`: case-folded keys, null keeps
/// the zero value, unknown keys ignored.
macro_rules! body {
    ($name:ident { $($field:ident : $ty:ty = $key:literal),+ $(,)? }) => {
        #[derive(Default)]
        struct $name { $($field: $ty),+ }
        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
                struct Fields;
                impl<'de> Visitor<'de> for Fields {
                    type Value = $name;
                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str("a JSON object")
                    }
                    fn visit_unit<E: serde::de::Error>(self) -> Result<$name, E> {
                        Ok($name::default())
                    }
                    fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<$name, M::Error> {
                        let mut body = $name::default();
                        while let Some(key) = map.next_key::<String>()? {
                            match crate::guests_input::fold(&key).as_str() {
                                $($key => {
                                    if let Some(value) = map.next_value::<Option<$ty>>()? {
                                        body.$field = value;
                                    }
                                })+
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
    };
}
body!(DeptCreate {
    name: String = "name",
    parent_id: Option<i64> = "parentid",
    ldap_ou: String = "ldapou"
});
body!(DeptUpdate {
    name: String = "name",
    parent_id: Option<i64> = "parentid",
    ldap_ou: String = "ldapou",
    sort_order: Option<i64> = "sortorder"
});
body!(Assign {
    user_id: i64 = "userid",
    department_id: Option<i64> = "departmentid"
});
// Go decodes a JSON null array element as the zero value.
body!(Policy {
    priority: Option<i64> = "priority",
    name: String = "name",
    enabled: Option<bool> = "enabled",
    overwrite: Option<bool> = "overwritedirectoryaddress",
    departments: Vec<Option<String>> = "conddepartment",
    domains: Vec<Option<i64>> = "conddomainids",
    mailbox_types: Vec<Option<String>> = "condmailboxtype",
    ad_ous: Vec<Option<String>> = "condadou",
    primary: String = "primarytemplate",
    additional: Vec<Option<String>> = "additionaltemplates",
    duplicate: Option<String> = "duplicateresolution"
});
body!(Reorder {
    order: Vec<Option<i64>> = "order"
});
body!(Preview {
    policy: i64 = "policyid",
    user: i64 = "userid",
    mailbox: i64 = "mailboxid"
});
body!(Conditions {
    departments: Vec<Option<String>> = "conddepartment",
    domains: Vec<Option<i64>> = "conddomainids",
    mailbox_types: Vec<Option<String>> = "condmailboxtype",
    ad_ous: Vec<Option<String>> = "condadou"
});
body!(Apply {
    policy: Option<i64> = "policyid"
});

/// Go's `nullableStrings`: an empty slice is SQL NULL.
fn texts(values: &[Option<String>]) -> Option<Vec<String>> {
    (!values.is_empty()).then(|| {
        values
            .iter()
            .map(|v| v.clone().unwrap_or_default())
            .collect()
    })
}
/// Go's `nullableInt64s`.
fn numbers(values: &[Option<i64>]) -> Option<Vec<i64>> {
    (!values.is_empty()).then(|| values.iter().map(|v| v.unwrap_or_default()).collect())
}
/// Go's `nilIfEmpty`.
fn present(text: &str) -> Option<&str> {
    (!text.is_empty()).then_some(text)
}

async fn json_body<T: serde::de::DeserializeOwned>(
    r: &mut Request<Body>,
    cap: usize,
) -> Result<T, ()> {
    crate::admin_identity_input::first(r, cap).await
}

impl<K: KeySource + 'static> Intercept for AdminOrgPoliciesRoute<K> {
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
            let Ok(authority) = setjoin_admin_identity::authority(&exec, actor).await else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let path = r.uri().path().to_owned();
            let go_path = segment_path(&path);
            let wanted = required(what);
            if !authority.allows_any(wanted) {
                let _ = setjoin_admin_identity::console_denied(
                    &exec,
                    actor,
                    &go_path,
                    &wanted.join("|"),
                    operation,
                )
                .await;
                return bare(403, "Forbidden", &c, &id);
            }
            // Owner-approved security fix 2026-11-05 (#510): email-address policy writes are
            // organization-wide; a domain-scoped identity.write holder is refused.
            if matches!(
                what,
                Action::PolicyCreate
                    | Action::PolicyUpdate
                    | Action::PolicyDelete
                    | Action::PolicyReorder
                    | Action::PolicyApply
            ) && !db::org_wide(&exec, actor).await
            {
                let _ = setjoin_admin_identity::console_denied(
                    &exec,
                    actor,
                    &go_path,
                    "identity.write (organization-wide grant required)",
                    operation,
                )
                .await;
                return bare(403, "Forbidden", &c, &id);
            }
            // Go's `DomainScopeFromContext`: the actor's own domain scope, nil when global.
            let grant_domain = Some(authority.domain_scope()).filter(|d| *d > 0);
            let head = r.method() == Method::HEAD;
            let reply = |body: String| {
                // net/http buffers 2 KiB of a handler's output; a larger single
                // write is flushed before the handler returns and sent chunked.
                let chunked = body.len() > 2048 && !head;
                let mut response = crate::jmap::reply::response(body, c.identity.proto, id.clone());
                if chunked {
                    response.headers_mut().insert(
                        "transfer-encoding",
                        hyper::header::HeaderValue::from_static("chunked"),
                    );
                }
                response
            };
            let with_status = |status: u16, body: String| {
                let mut response = reply(body);
                *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
                response
            };
            let full = |status: u16, detail: &str| problem(status, detail, &go_path, &c, &id);
            let plain = |status: u16, detail: &str| bare(status, detail, &c, &id);
            let database = || full(500, "database error");
            let unknown = |operation| {
                let mut response = bare(503, "operation outcome unknown", &c, &id);
                response.headers_mut().insert(
                    "x-operation-id",
                    setjoin_pg::operation_hex(operation)
                        .parse()
                        .expect("operation"),
                );
                response
            };
            let status_only = |status: u16| {
                let mut response =
                    crate::jmap::reply::response(String::new(), c.identity.proto, id.clone());
                *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
                response.headers_mut().remove("content-type");
                response
            };
            // A refusal decided by a reducer, or the database failing.
            let failed = |e: &Rejection<setjoin_pg::StatementFailure>| match db::problem_of(e) {
                Some(p) if p.status == 409 => conflict(&p.detail, &go_path, &c, &id),
                Some(p) => full(p.status, &p.detail),
                None => database(),
            };
            // Department handlers: `id, _ := strconv.ParseInt`, then `id <= 0`.
            let dept_id = || crate::admin_identity_input::atoi(&segment(&path, 4));
            match what {
                Action::DeptList => match db::departments(&exec).await {
                    Ok(body) => reply(body),
                    Err(_) => database(),
                },
                Action::DeptTree => match db::department_tree(&exec).await {
                    Ok(body) => reply(body),
                    Err(_) => database(),
                },
                Action::Groups => match db::distribution_groups(&exec).await {
                    Ok(body) => reply(body),
                    Err(_) => database(),
                },
                Action::DeptCreate => {
                    let Ok(body) = json_body::<DeptCreate>(&mut r, 1 << 30).await else {
                        return full(400, "invalid JSON");
                    };
                    let name = body.name.trim().to_owned();
                    let mut ldap_ou = body.ldap_ou.trim().to_owned();
                    if name.is_empty() {
                        return full(400, "name required");
                    }
                    if let Some(reason) =
                        setjoin_admin_identity::roles::resource_name_problem(&name)
                    {
                        return full(400, reason);
                    }
                    if ldap_ou.is_empty() {
                        ldap_ou = name.clone();
                    }
                    match db::department_create(
                        &exec,
                        actor,
                        &name,
                        body.parent_id,
                        &ldap_ou,
                        grant_domain,
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(new) => reply(format!("{{\"id\":{new}}}\n")),
                        CommandOutcome::RolledBack(e) => failed(&e),
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::DeptUpdate => {
                    let department = dept_id();
                    if department <= 0 {
                        return full(400, "invalid id");
                    }
                    let Ok(body) = json_body::<DeptUpdate>(&mut r, 1 << 30).await else {
                        return full(400, "invalid JSON");
                    };
                    let patch = DepartmentPatch {
                        name: &body.name,
                        parent: body.parent_id,
                        ldap_ou: &body.ldap_ou,
                        sort: body.sort_order,
                    };
                    match db::department_update(
                        &exec,
                        actor,
                        department,
                        &patch,
                        grant_domain,
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(500) => database(),
                        CommandOutcome::Committed(_) => status_only(204),
                        CommandOutcome::RolledBack(e) => failed(&e),
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::DeptDelete => {
                    let department = dept_id();
                    if department <= 0 {
                        return full(400, "invalid id");
                    }
                    match db::department_delete(&exec, actor, department, grant_domain, operation)
                        .await
                    {
                        CommandOutcome::Committed(()) => status_only(204),
                        CommandOutcome::RolledBack(e) => failed(&e),
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::DeptAssign => {
                    let Ok(body) = json_body::<Assign>(&mut r, 1 << 30).await else {
                        return full(400, "invalid JSON");
                    };
                    if body.user_id <= 0 {
                        return full(400, "userId required");
                    }
                    match db::department_assign_user(
                        &exec,
                        actor,
                        body.user_id,
                        body.department_id.filter(|d| *d > 0),
                        grant_domain,
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(()) => status_only(204),
                        CommandOutcome::RolledBack(e) => failed(&e),
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::PolicyList => match db::policies(&exec).await {
                    Ok(body) => reply(body),
                    Err(_) => plain(500, "database error"),
                },
                Action::PolicyCreate => {
                    let Ok(body) = json_body::<Policy>(&mut r, 1 << 20).await else {
                        return plain(400, "invalid JSON");
                    };
                    if body.name.is_empty() {
                        return plain(400, "name is required");
                    }
                    if let Some(reason) = db::template_problem(&body.primary) {
                        return plain(400, &format!("primaryTemplate: {reason}"));
                    }
                    let input = PolicyInput {
                        priority: body.priority,
                        name: Some(&body.name),
                        enabled: body.enabled,
                        overwrite: body.overwrite,
                        departments: texts(&body.departments),
                        domains: numbers(&body.domains),
                        mailbox_types: texts(&body.mailbox_types),
                        ad_ous: texts(&body.ad_ous),
                        primary: Some(&body.primary),
                        additional: texts(&body.additional),
                        duplicate: body.duplicate.as_deref(),
                    };
                    match db::policy_create(&exec, actor, &input, operation).await {
                        CommandOutcome::Committed(row) => with_status(201, row),
                        CommandOutcome::RolledBack(e) => {
                            if db::sqlstate(&e).as_deref() == Some("23505") {
                                plain(
                                    409,
                                    "a policy with this priority already exists (unique enabled-priority)",
                                )
                            } else {
                                plain(500, "failed to create policy")
                            }
                        }
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::PolicyUpdate => {
                    let Ok(policy) = segment(&path, 4).parse::<i64>() else {
                        return plain(400, "invalid policy ID");
                    };
                    let Ok(body) = json_body::<Policy>(&mut r, 1 << 20).await else {
                        return plain(400, "invalid JSON");
                    };
                    if !body.primary.is_empty() {
                        if let Some(reason) = db::template_problem(&body.primary) {
                            return plain(400, &format!("primaryTemplate: {reason}"));
                        }
                    }
                    let input = PolicyInput {
                        priority: body.priority,
                        name: present(&body.name),
                        enabled: body.enabled,
                        overwrite: body.overwrite,
                        departments: texts(&body.departments),
                        domains: numbers(&body.domains),
                        mailbox_types: texts(&body.mailbox_types),
                        ad_ous: texts(&body.ad_ous),
                        primary: present(&body.primary),
                        additional: texts(&body.additional),
                        duplicate: body.duplicate.as_deref(),
                    };
                    match db::policy_update(&exec, actor, policy, &input, operation).await {
                        CommandOutcome::Committed(Some(row)) => with_status(200, row),
                        CommandOutcome::Committed(None) => plain(404, "policy not found"),
                        CommandOutcome::RolledBack(e) => match db::sqlstate(&e).as_deref() {
                            Some("23505") => plain(409, "priority already in use"),
                            _ => plain(500, "update failed"),
                        },
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::PolicyDelete => {
                    let Ok(policy) = segment(&path, 4).parse::<i64>() else {
                        return plain(400, "invalid policy ID");
                    };
                    match db::policy_delete(&exec, actor, policy, operation).await {
                        CommandOutcome::Committed(true) => status_only(204),
                        CommandOutcome::Committed(false) => plain(404, "policy not found"),
                        CommandOutcome::RolledBack(_) => plain(500, "delete failed"),
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::PolicyReorder => {
                    let Ok(body) = json_body::<Reorder>(&mut r, 1 << 20).await else {
                        return plain(400, "invalid JSON: expected {\"order\":[ids]}");
                    };
                    if body.order.is_empty() {
                        return plain(400, "at least one policy ID required");
                    }
                    let order: Vec<i64> =
                        body.order.iter().map(|v| v.unwrap_or_default()).collect();
                    match db::policy_reorder(&exec, actor, &order, operation).await {
                        CommandOutcome::Committed(()) => status_only(204),
                        CommandOutcome::RolledBack(_) => plain(500, "reorder update failed"),
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::PolicyPreview => {
                    let Ok(body) = json_body::<Preview>(&mut r, 1 << 20).await else {
                        return plain(400, "invalid JSON");
                    };
                    match db::preview(&exec, body.policy, body.user, body.mailbox).await {
                        Ok(text) => reply(text),
                        Err(_) => plain(500, "preview failed"),
                    }
                }
                Action::PolicyMatchCount => {
                    let Ok(body) = json_body::<Conditions>(&mut r, 1 << 20).await else {
                        return plain(400, "invalid JSON");
                    };
                    match db::match_count(
                        &exec,
                        &texts(&body.departments),
                        &numbers(&body.domains),
                        &texts(&body.mailbox_types),
                        &texts(&body.ad_ous),
                    )
                    .await
                    {
                        Ok(text) => reply(text),
                        Err(_) => plain(500, "match-count failed"),
                    }
                }
                Action::PolicyApply => {
                    let Ok(body) = json_body::<Apply>(&mut r, 1 << 20).await else {
                        return plain(400, "invalid JSON");
                    };
                    match db::policy_apply(&exec, actor, body.policy, operation).await {
                        CommandOutcome::Committed(job) => {
                            with_status(202, format!("{{\"jobId\":{job}}}\n"))
                        }
                        CommandOutcome::RolledBack(_) => plain(500, "failed to enqueue apply job"),
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::PolicyApplyStatus => {
                    let Ok(job) = segment(&path, 5).parse::<i64>() else {
                        return plain(400, "invalid job ID");
                    };
                    match db::apply_status(&exec, job).await {
                        Some(text) => reply(text),
                        None => plain(404, "job not found"),
                    }
                }
            }
        })
    }
}

/// Go sees the `/api`-stripped request path, decoded.
fn segment_path(path: &str) -> String {
    crate::guests_input::go_utf8(&crate::inventory::unescape(
        path.strip_prefix("/api").unwrap_or(path),
    ))
}

fn render(
    status: u16,
    body: String,
    language: bool,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    let code = hyper::StatusCode::from_u16(status).expect("status");
    let mut r = crate::jmap::reply::response(body, c.identity.proto, id.to_owned());
    *r.status_mut() = code;
    r.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/problem+json"),
    );
    if language {
        r.headers_mut().insert(
            "content-language",
            hyper::header::HeaderValue::from_static("en"),
        );
    }
    r
}

/// Go's `WriteProblemStatus`: a minimal problem, empty instance, no language.
fn bare(status: u16, detail: &str, c: &RequestContext, id: &str) -> Response<Body> {
    render(
        status,
        crate::problem::Problem::new(status, detail).body(),
        false,
        c,
        id,
    )
}
/// Go's `WriteProblem` with a bare status and detail.
fn problem(status: u16, detail: &str, path: &str, c: &RequestContext, id: &str) -> Response<Body> {
    let body = crate::problem::Problem::new(status, detail)
        .instance(path)
        .body();
    render(status, body, true, c, id)
}
/// Go's `NewConflictProblem`.
fn conflict(detail: &str, path: &str, c: &RequestContext, id: &str) -> Response<Body> {
    let body = crate::problem::Problem::new(409, detail)
        .kind("https://setjoin.com/errors/conflict")
        .instance(path)
        .body();
    render(409, body, true, c, id)
}
