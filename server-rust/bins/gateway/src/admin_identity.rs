//! F01 slice `users` HTTP adapter: the database-backed user reads, alias,
//! quota and app-access writes. User lifecycle (create, update, delete,
//! password, import), secure-account, sign-ins and app-password revocation stay
//! with Go: see the crate DOX for the slice map. The `roles` slice (role groups,
//! memberships, permission catalog, effective permissions) lives in `roles.rs`.
mod roles;
use crate::admin_identity_input as input;
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_pg::{CommandOutcome, Rejection, ScopedExecutor};
use std::sync::Arc;

pub struct AdminIdentityRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    List,
    Get,
    Aliases,
    AddAlias,
    RemoveAlias,
    Quota,
    SetQuota,
    AppPasswords,
    AppAccess,
    SetAppAccess,
    Sessions,
    Roles,
    CreateRole,
    Role,
    UpdateRole,
    DeleteRole,
    AssignMember,
    RemoveMember,
    BulkAssign,
    BulkRevoke,
    EffectivePermissions,
    Permissions,
}

fn action(method: &Method, path: &str) -> Option<Action> {
    let reads = matches!(*method, Method::GET | Method::HEAD);
    let table: [(bool, &str, Action); 22] = [
        (reads, "/api/admin/users", Action::List),
        (reads, "/api/admin/users/{id}", Action::Get),
        (reads, "/api/admin/users/{id}/aliases", Action::Aliases),
        (
            *method == Method::POST,
            "/api/admin/users/{id}/aliases",
            Action::AddAlias,
        ),
        (
            *method == Method::DELETE,
            "/api/admin/users/{id}/aliases/{aliasId}",
            Action::RemoveAlias,
        ),
        (reads, "/api/admin/users/{id}/quota", Action::Quota),
        (
            *method == Method::PUT,
            "/api/admin/users/{id}/quota",
            Action::SetQuota,
        ),
        (
            reads,
            "/api/admin/users/{id}/app-passwords",
            Action::AppPasswords,
        ),
        (reads, "/api/admin/users/{id}/app-access", Action::AppAccess),
        (
            *method == Method::PUT,
            "/api/admin/users/{id}/app-access/{app}",
            Action::SetAppAccess,
        ),
        (reads, "/api/admin/users/{id}/sessions", Action::Sessions),
        (reads, "/api/admin/roles", Action::Roles),
        (
            *method == Method::POST,
            "/api/admin/roles",
            Action::CreateRole,
        ),
        (reads, "/api/admin/roles/{id}", Action::Role),
        (
            *method == Method::PUT,
            "/api/admin/roles/{id}",
            Action::UpdateRole,
        ),
        (
            *method == Method::DELETE,
            "/api/admin/roles/{id}",
            Action::DeleteRole,
        ),
        (
            *method == Method::POST,
            "/api/admin/roles/{id}/members",
            Action::AssignMember,
        ),
        (
            *method == Method::DELETE,
            "/api/admin/roles/{id}/members/{userId}",
            Action::RemoveMember,
        ),
        (
            *method == Method::POST,
            "/api/admin/roles/{id}/members:bulk",
            Action::BulkAssign,
        ),
        (
            *method == Method::DELETE,
            "/api/admin/roles/{id}/members:bulk",
            Action::BulkRevoke,
        ),
        (
            reads,
            "/api/admin/users/{id}/effective-permissions",
            Action::EffectivePermissions,
        ),
        (reads, "/api/admin/permissions", Action::Permissions),
    ];
    table
        .iter()
        .filter(|(ok, pattern, _)| *ok && crate::inventory::path_score(pattern, path).is_some())
        .max_by_key(|(_, pattern, _)| crate::inventory::path_score(pattern, path))
        .map(|(_, _, action)| *action)
}

/// Go's `r.PathValue`: the percent-decoded segment at `index` of the full path.
fn segment(path: &str, index: usize) -> String {
    crate::guests_input::go_utf8(&crate::inventory::unescape(
        path.split('/').nth(index).unwrap_or(""),
    ))
}

impl<K: KeySource + 'static> Intercept for AdminIdentityRoute<K> {
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
            let required: &[&str] = match what {
                Action::AddAlias
                | Action::RemoveAlias
                | Action::SetQuota
                | Action::SetAppAccess => &setjoin_admin_identity::USERS_CREATE,
                Action::Sessions => &setjoin_admin_identity::SIGN_IN,
                Action::Roles
                | Action::CreateRole
                | Action::Role
                | Action::UpdateRole
                | Action::DeleteRole
                | Action::AssignMember
                | Action::RemoveMember
                | Action::BulkAssign
                | Action::BulkRevoke
                | Action::EffectivePermissions
                | Action::Permissions => &setjoin_admin_identity::roles::ROLES_MANAGE,
                _ => &setjoin_admin_identity::AUTH_CONSOLE,
            };
            if !authority.allows_any(required) {
                let _ = setjoin_admin_identity::console_denied(
                    &exec,
                    actor,
                    &go_path,
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
                let _ = setjoin_admin_identity::console_denied(
                    &exec, actor, &go_path, &detail, operation,
                )
                .await;
                return bare(403, "Forbidden", &c, &id);
            }
            if roles::is_write(what)
                && setjoin_admin_identity::roles::reason_required(&exec).await
                && r.headers()
                    .get("x-audit-reason")
                    .is_none_or(|v| v.as_bytes().is_empty())
            {
                setjoin_admin_identity::roles::missing_reason(
                    &exec,
                    actor,
                    &c.identity.client_ip.to_string(),
                    operation,
                )
                .await;
                return bare(400, "reason_required", &c, &id);
            }
            if matches!(
                what,
                Action::Roles
                    | Action::CreateRole
                    | Action::Role
                    | Action::UpdateRole
                    | Action::DeleteRole
                    | Action::AssignMember
                    | Action::RemoveMember
                    | Action::BulkAssign
                    | Action::BulkRevoke
                    | Action::EffectivePermissions
                    | Action::Permissions
            ) {
                return roles::serve(
                    &exec, what, r, actor, &authority, &c, &id, &path, &go_path, operation,
                )
                .await;
            }
            let scope = authority.domain_scope();
            let reply =
                |body: String| crate::jmap::reply::response(body, c.identity.proto, id.clone());
            let full = |status: u16, detail: &str| problem(status, detail, &go_path, &c, &id);
            let db = || full(500, "database error");
            let internal = || internal_problem(&go_path, &c, &id);
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
            let target = |index: usize| segment(&path, index).parse::<i64>().ok();
            match what {
                Action::List => {
                    let q = input::query(r.uri(), "q").unwrap_or_default();
                    let mut limit = input::query(r.uri(), "limit")
                        .map(|v| input::atoi(&v))
                        .unwrap_or(0);
                    if limit <= 0 || limit > 100 {
                        limit = 50;
                    }
                    let offset = input::query(r.uri(), "offset")
                        .map(|v| input::atoi(&v))
                        .unwrap_or(0)
                        .clamp(0, 1_000_000);
                    match setjoin_admin_identity::users(
                        &exec,
                        actor.user_id(),
                        scope,
                        &q,
                        limit,
                        offset,
                    )
                    .await
                    {
                        Ok(body) => reply(body),
                        Err(_) => db(),
                    }
                }
                Action::Get => {
                    let Some(user) = target(4) else {
                        return full(400, "invalid user id");
                    };
                    match setjoin_admin_identity::user(&exec, scope, user).await {
                        Ok(Some(body)) => reply(body),
                        Ok(None) => full(404, "user not found"),
                        Err(_) => db(),
                    }
                }
                Action::Aliases | Action::Quota | Action::AddAlias | Action::SetQuota => {
                    // `id, _ := strconv.ParseInt(...)`: any failure is 0, and ids <= 0 are refused.
                    let user = target(4).unwrap_or(0);
                    if user <= 0 {
                        return full(400, "invalid user id");
                    }
                    match what {
                        Action::Aliases => {
                            match setjoin_admin_identity::aliases(&exec, scope, user).await {
                                Ok(body) => reply(body),
                                Err(_) => db(),
                            }
                        }
                        Action::Quota => {
                            match setjoin_admin_identity::quota(&exec, scope, user).await {
                                Some(body) => reply(body),
                                None => full(404, "mailbox not found"),
                            }
                        }
                        Action::AddAlias => {
                            let Ok(body) = input::first::<input::Alias>(&mut r, 1 << 20).await
                            else {
                                return full(400, "invalid JSON");
                            };
                            if body.email.is_empty() {
                                return full(400, "email required");
                            }
                            let Some((mailbox, _)) =
                                setjoin_admin_identity::primary_mailbox(&exec, scope, user).await
                            else {
                                return full(404, "primary mailbox not found");
                            };
                            let email = match input::address(&body.email) {
                                Ok(email) => email,
                                Err(detail) => return full(400, detail),
                            };
                            // Owner-approved security fix 2026-11-05 (#373): a domain-scoped
                            // admin binds only addresses in the mailbox's own domain.
                            if !setjoin_admin_identity::alias_domain_allowed(
                                &exec, scope, mailbox, &email,
                            )
                            .await
                            {
                                return full(
                                    403,
                                    "alias address is outside the mailbox's domain",
                                );
                            }
                            match setjoin_admin_identity::add_alias(
                                &exec, actor, scope, user, mailbox, &email, operation,
                            )
                            .await
                            {
                                CommandOutcome::Committed(Some(alias)) => {
                                    let mut response = reply(format!("{{\"id\":{alias}}}\n"));
                                    *response.status_mut() = hyper::StatusCode::CREATED;
                                    response
                                }
                                CommandOutcome::Committed(None) => db(),
                                CommandOutcome::RolledBack(error) => {
                                    if code(&error) == Some("23505") {
                                        full(409, "alias already exists")
                                    } else {
                                        db()
                                    }
                                }
                                CommandOutcome::Unknown { operation } => unknown(operation),
                            }
                        }
                        _ => {
                            let Ok(body) = input::first::<input::Quota>(&mut r, 1 << 20).await
                            else {
                                return full(400, "invalid JSON");
                            };
                            let bytes = body.quota_bytes.filter(|n| *n > 0);
                            let day = body.sending_quota_day.filter(|n| *n > 0);
                            if bytes.is_none() && day.is_none() {
                                return full(400, "no fields to update");
                            }
                            match setjoin_admin_identity::set_quota(
                                &exec, actor, scope, user, bytes, day, operation,
                            )
                            .await
                            {
                                CommandOutcome::Committed(0) => full(404, "mailbox not found"),
                                CommandOutcome::Committed(_) => no_content(&c, &id),
                                CommandOutcome::RolledBack(_) => db(),
                                CommandOutcome::Unknown { operation } => unknown(operation),
                            }
                        }
                    }
                }
                Action::RemoveAlias => {
                    let user = target(4).unwrap_or(0);
                    let alias = target(6).unwrap_or(0);
                    if user <= 0 || alias <= 0 {
                        return full(400, "invalid id");
                    }
                    match setjoin_admin_identity::remove_alias(
                        &exec, actor, scope, user, alias, operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(_) => no_content(&c, &id),
                        CommandOutcome::RolledBack(_) => db(),
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::AppPasswords => {
                    let Some(user) = target(4) else {
                        return bare(400, "invalid user id", &c, &id);
                    };
                    match setjoin_admin_identity::app_passwords(&exec, scope, user).await {
                        Ok(body) => reply(body),
                        Err(_) => bare(500, "database error", &c, &id),
                    }
                }
                Action::AppAccess => {
                    let Some(user) = target(4) else {
                        return typed(
                            400,
                            "validation-failed",
                            "Bad Request",
                            "invalid user id",
                            &go_path,
                            &c,
                            &id,
                        );
                    };
                    match setjoin_admin_identity::app_access(&exec, scope, user).await {
                        Ok(body) => reply(body),
                        Err(_) => internal(),
                    }
                }
                Action::SetAppAccess => {
                    let Some(user) = target(4) else {
                        return typed(
                            400,
                            "validation-failed",
                            "Validation Failed",
                            "invalid user id",
                            &go_path,
                            &c,
                            &id,
                        );
                    };
                    let app = segment(&path, 6);
                    if !setjoin_admin_identity::APPS.contains(&app.as_str()) {
                        let mut response = typed(
                            422,
                            "validation-failed",
                            "Validation Failed",
                            "unknown app; must be one of mail, calendar, contacts, tasks, chat, drive, meet",
                            &go_path,
                            &c,
                            &id,
                        );
                        // Go's NewValidationProblem adds the field list after instance.
                        let body = format!(
                            "{{\"type\":\"https://setjoin.com/errors/validation-failed\",\"title\":\"Validation Failed\",\"status\":422,\"detail\":\"unknown app; must be one of mail, calendar, contacts, tasks, chat, drive, meet\",\"instance\":{},\"invalid-params\":[{{\"field\":\"app\",\"message\":\"unknown app\"}}]}}\n",
                            serde_json::to_string(&go_path).expect("path")
                        );
                        use http_body_util::BodyExt;
                        *response.body_mut() = http_body_util::Full::new(bytes::Bytes::from(body))
                            .map_err(|n| match n {})
                            .boxed();
                        return response;
                    }
                    let Ok(body) = input::first::<input::Entitlement>(&mut r, usize::MAX).await
                    else {
                        return typed(
                            400,
                            "validation-failed",
                            "Bad Request",
                            "request body must be JSON with an 'enabled' boolean",
                            &go_path,
                            &c,
                            &id,
                        );
                    };
                    match setjoin_admin_identity::set_app_access(
                        &exec,
                        actor,
                        scope,
                        user,
                        &app,
                        body.enabled,
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(0) => typed(
                            404,
                            "not-found",
                            "Not Found",
                            "user not found",
                            &go_path,
                            &c,
                            &id,
                        ),
                        CommandOutcome::Committed(_) => no_content(&c, &id),
                        CommandOutcome::RolledBack(error) => match code(&error) {
                            Some("BZ033") => reducer(
                                404,
                                "BZ033",
                                "notFound",
                                "Refresh the target identifier and retry only if the resource still exists.",
                                &go_path,
                                &c,
                                &id,
                            ),
                            Some("BZ226") => reducer(
                                409,
                                "BZ226",
                                "conflict",
                                "Refresh current state, resolve the conflict, and retry.",
                                &go_path,
                                &c,
                                &id,
                            ),
                            _ => internal(),
                        },
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::Sessions => {
                    let Some(user) = target(4) else {
                        return bare(400, "bad id", &c, &id);
                    };
                    match setjoin_admin_identity::sessions(&exec, scope, user).await {
                        Ok(Some(body)) => reply(body),
                        Ok(None) => bare(404, "not found", &c, &id),
                        Err(_) => bare(500, "database error", &c, &id),
                    }
                }
                _ => unreachable!("roles actions return above"),
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

fn code(error: &Rejection<setjoin_pg::StatementFailure>) -> Option<&str> {
    match error {
        Rejection::Statement(e) | Rejection::Body(e) => e.sqlstate.as_deref(),
        _ => None,
    }
}

fn render(
    status: u16,
    body: String,
    language: bool,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    let code = hyper::StatusCode::from_u16(status).expect("status");
    let mut r = crate::jmap::reply::response(
        setjoin_admin_identity::go_escape(&body) + "\n",
        c.identity.proto,
        id.to_owned(),
    );
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
fn title(status: u16) -> &'static str {
    crate::problem::title(status)
}
fn quote(text: &str) -> String {
    serde_json::to_string(text).expect("string")
}

/// Go's `WriteProblemStatus`/`WriteError`: a minimal problem, empty instance, no language.
fn bare(status: u16, detail: &str, c: &RequestContext, id: &str) -> Response<Body> {
    render(
        status,
        format!(
            "{{\"type\":\"about:blank\",\"title\":{},\"status\":{status},\"detail\":{},\"instance\":\"\"}}",
            quote(title(status)),
            quote(detail)
        ),
        false,
        c,
        id,
    )
}
/// Go's `WriteProblem` with a bare status and detail.
fn problem(status: u16, detail: &str, path: &str, c: &RequestContext, id: &str) -> Response<Body> {
    render(
        status,
        format!(
            "{{\"type\":\"about:blank\",\"title\":{},\"status\":{status},\"detail\":{},\"instance\":{}}}",
            quote(title(status)),
            quote(detail),
            quote(path)
        ),
        true,
        c,
        id,
    )
}
/// Go's `WriteProblem` with one of the `https://setjoin.com/errors/*` types.
fn typed(
    status: u16,
    slug: &str,
    heading: &str,
    detail: &str,
    path: &str,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    render(
        status,
        format!(
            "{{\"type\":\"https://setjoin.com/errors/{slug}\",\"title\":{},\"status\":{status},\"detail\":{},\"instance\":{}}}",
            quote(heading),
            quote(detail),
            quote(path)
        ),
        true,
        c,
        id,
    )
}
fn internal_problem(path: &str, c: &RequestContext, id: &str) -> Response<Body> {
    typed(
        500,
        "internal-error",
        "Internal Server Error",
        "An unexpected error occurred. Please try again.",
        path,
        c,
        id,
    )
}
/// Go's `reducererr.WriteClassified` for a known reducer code.
fn reducer(
    status: u16,
    code: &str,
    detail: &str,
    remediation: &str,
    path: &str,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    render(
        status,
        format!(
            "{{\"type\":\"https://setjoin.com/problems/reducer/{}\",\"title\":{},\"status\":{status},\"detail\":{},\"instance\":{},\"remediation\":{},\"code\":{},\"retryable\":false}}",
            code.to_ascii_lowercase(),
            quote(title(status)),
            quote(detail),
            quote(path),
            quote(remediation),
            quote(code)
        ),
        true,
        c,
        id,
    )
}
fn no_content(c: &RequestContext, id: &str) -> Response<Body> {
    let mut r = crate::jmap::reply::response(String::new(), c.identity.proto, id.to_owned());
    *r.status_mut() = hyper::StatusCode::NO_CONTENT;
    r.headers_mut().remove("content-type");
    r
}
