//! F01 slice `roles` HTTP adapter: decoding, Go's validation order and the
//! problem shapes. Database work lives in `setjoin_admin_identity::roles`.
use super::*;
use setjoin_admin_identity::roles::{self as db, Problem};
use setjoin_admin_identity::Authority;
use setjoin_authz::AuthContext;

pub(super) fn is_write(what: Action) -> bool {
    matches!(
        what,
        Action::CreateRole
            | Action::UpdateRole
            | Action::DeleteRole
            | Action::AssignMember
            | Action::RemoveMember
            | Action::BulkAssign
            | Action::BulkRevoke
    )
}

fn problem_for(p: u16, detail: &str) -> Option<Problem> {
    Some(Problem {
        status: p,
        detail: detail.to_owned(),
    })
}

/// Go's `permissions.IsValid` loop, then Rule A (grant-only-what-you-hold).
fn grant_problem(authority: &Authority, wanted: &[String], rule_a: &str) -> Option<Problem> {
    if let Some(unknown) = wanted.iter().find(|p| !db::is_known(p)) {
        return problem_for(400, &format!("unknown permission: {unknown}"));
    }
    wanted
        .iter()
        .find(|p| !authority.holds(p))
        .and_then(|p| problem_for(403, &format!("{rule_a}{p}")))
}

/// Go's scope-type validation shared by assign and bulk assign.
fn scope_problem(scope_type: &Option<String>, scope_id: Option<i64>) -> Option<Problem> {
    match scope_type.as_deref() {
        Some(t @ ("ou" | "set")) => scope_id
            .is_none()
            .then(|| format!("scopeId is required when scopeType is '{t}'"))
            .and_then(|d| problem_for(400, &d)),
        Some("group" | "user") => problem_for(400, "group/user scope is retired; use a scope-set"),
        Some(_) => problem_for(400, "invalid scopeType"),
        None => scope_id
            .is_some()
            .then(|| problem_for(400, "scopeId requires scopeType"))
            .flatten(),
    }
}

fn shown_problem(p: &Problem, go_path: &str, c: &RequestContext, id: &str) -> Response<Body> {
    if p.status == 409 {
        typed(409, "conflict", "Conflict", &p.detail, go_path, c, id)
    } else {
        problem(p.status, &p.detail, go_path, c, id)
    }
}

/// A rolled-back command: Go's problem, a protection denial, or a 500.
#[allow(clippy::too_many_arguments)]
async fn failed(
    exec: &ScopedExecutor,
    actor: &AuthContext,
    error: &Rejection<setjoin_pg::StatementFailure>,
    target: Option<i64>,
    ip: &str,
    operation: [u8; 16],
    go_path: &str,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    if let Some(p) = db::problem_of(error) {
        return shown_problem(&p, go_path, c, id);
    }
    let database = || problem(500, "database error", go_path, c, id);
    let (Rejection::Statement(e) | Rejection::Body(e)) = error else {
        return database();
    };
    let remediation =
        "Complete the required authorization, approval, or recovery step before retrying.";
    let (status, class, remediation) = match e.sqlstate.as_deref() {
        Some("BZ064") => (
            409,
            "BZ064",
            "Refresh current state, resolve the conflict, and retry.",
        ),
        Some("BZ065") => (403, "BZ065", remediation),
        Some("BZ066") => (403, "BZ066", remediation),
        _ => return database(),
    };
    if let Some(target) = target {
        db::protection_denied(exec, actor, target, class, ip, operation).await;
    }
    reducer(status, class, &e.message, remediation, go_path, c, id)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn serve(
    exec: &ScopedExecutor,
    what: Action,
    mut r: Request<Body>,
    actor: &AuthContext,
    authority: &Authority,
    c: &RequestContext,
    id: &str,
    path: &str,
    go_path: &str,
    operation: [u8; 16],
) -> Response<Body> {
    let scope = authority.domain_scope();
    let ip = c.identity.client_ip.to_string();
    let head = r.method() == hyper::Method::HEAD;
    let reply = |body: String| {
        // net/http buffers 2 KiB of a handler's output; a larger single write
        // is flushed before the handler returns and is sent chunked.
        let chunked = body.len() > 2048 && !head;
        let mut response = crate::jmap::reply::response(body, c.identity.proto, id.to_owned());
        if chunked {
            response.headers_mut().insert(
                "transfer-encoding",
                hyper::header::HeaderValue::from_static("chunked"),
            );
        }
        response
    };
    let full = |status: u16, detail: &str| problem(status, detail, go_path, c, id);
    let db_failed = || full(500, "database error");
    let created = |key: &str, value: i64, status: u16| {
        let mut response = reply(format!("{{\"{key}\":{value}}}\n"));
        *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
        response
    };
    let unknown = |operation| {
        let mut response = bare(503, "operation outcome unknown", c, id);
        response.headers_mut().insert(
            "x-operation-id",
            setjoin_pg::operation_hex(operation)
                .parse()
                .expect("operation"),
        );
        response
    };
    let shown = |p: &Problem| shown_problem(p, go_path, c, id);
    let role_id = |index: usize| segment(path, index).parse::<i64>().ok();
    match what {
        Action::Roles => match db::roles(exec, scope).await {
            Ok(body) => reply(body),
            Err(_) => db_failed(),
        },
        Action::Permissions => match db::catalog(exec).await {
            Ok(body) => reply(body),
            Err(_) => db_failed(),
        },
        Action::Role => {
            let Some(role) = role_id(4) else {
                return full(400, "invalid role id");
            };
            match db::role(exec, actor.user_id(), scope, role).await {
                Ok(Some(body)) => reply(body),
                Ok(None) => full(404, "role not found"),
                Err(_) => db_failed(),
            }
        }
        Action::EffectivePermissions => {
            let Some(user) = role_id(4) else {
                return full(400, "invalid user id");
            };
            match db::effective_permissions(exec, scope, user).await {
                Ok(Some(body)) => reply(body),
                Ok(None) => full(404, "user not found"),
                Err(_) => db_failed(),
            }
        }
        Action::CreateRole => {
            let Ok(body) = input::first::<input::RoleCreate>(&mut r, 1 << 20).await else {
                return full(400, "invalid JSON");
            };
            if body.name.is_empty() {
                return full(400, "role name is required");
            }
            if let Some(reason) = db::resource_name_problem(&body.name) {
                return full(400, reason);
            }
            let wanted = input::strings(body.permissions);
            if wanted.is_empty() {
                return full(400, "at least one permission is required");
            }
            if let Some(p) = grant_problem(
                authority,
                &wanted,
                "cannot grant a permission you do not hold: ",
            ) {
                return shown(&p);
            }
            if scope > 0 && body.domain_scope != Some(scope) {
                return full(
                    403,
                    "scoped admin cannot create a role outside their domain",
                );
            }
            let new = db::NewRole {
                name: &body.name,
                description: &body.description,
                permissions: &wanted,
                domain_scope: body.domain_scope,
            };
            match db::create_role(exec, actor, &new, &ip, operation).await {
                CommandOutcome::Committed(role) => created("id", role, 201),
                CommandOutcome::RolledBack(e) => {
                    failed(exec, actor, &e, None, &ip, operation, go_path, c, id).await
                }
                CommandOutcome::Unknown { operation } => unknown(operation),
            }
        }
        Action::UpdateRole | Action::DeleteRole => {
            let Some(role) = role_id(4) else {
                return full(400, "invalid role id");
            };
            let outcome = if what == Action::DeleteRole {
                db::delete_role(exec, actor, scope, role, &ip, operation).await
            } else {
                let patch = match input::first::<input::RoleUpdate>(&mut r, 1 << 20).await {
                    Err(()) => db::RolePatch {
                        name: None,
                        description: None,
                        permissions: None,
                        domain_scope: None,
                        sod_class: None,
                        problem: problem_for(400, "invalid JSON"),
                    },
                    Ok(body) => {
                        let wanted = input::strings(body.permissions);
                        let problem = body
                            .name
                            .as_ref()
                            .and_then(|n| {
                                if n.is_empty() {
                                    problem_for(400, "role name must not be empty")
                                } else {
                                    db::resource_name_problem(n)
                                        .and_then(|reason| problem_for(400, reason))
                                }
                            })
                            .or_else(|| {
                                (!wanted.is_empty())
                                    .then(|| {
                                        grant_problem(
                                            authority,
                                            &wanted,
                                            "cannot grant a permission you do not hold: ",
                                        )
                                    })
                                    .flatten()
                            })
                            .or_else(|| {
                                (scope > 0 && body.domain_scope.is_some_and(|d| d != scope))
                                    .then(|| {
                                        problem_for(
                                            403,
                                            "scoped admin cannot move a role outside their domain",
                                        )
                                    })
                                    .flatten()
                            });
                        db::RolePatch {
                            name: body.name,
                            description: body.description,
                            permissions: (!wanted.is_empty()).then_some(wanted),
                            domain_scope: body.domain_scope,
                            sod_class: body.sod_class,
                            problem,
                        }
                    }
                };
                db::update_role(exec, actor, scope, role, &patch, &ip, operation).await
            };
            match outcome {
                CommandOutcome::Committed(_) => no_content(c, id),
                CommandOutcome::RolledBack(e) => {
                    failed(exec, actor, &e, None, &ip, operation, go_path, c, id).await
                }
                CommandOutcome::Unknown { operation } => unknown(operation),
            }
        }
        Action::AssignMember => {
            let Some(role) = role_id(4) else {
                return full(400, "invalid role id");
            };
            let assignment = input::first::<input::RoleAssign>(&mut r, 1 << 20)
                .await
                .ok();
            let mut a = db::Assignment {
                user: 0,
                domain_override: None,
                expires_at: None,
                expires_bad: false,
                scope_type: None,
                scope_id: None,
                eligible: None,
                problem: None,
            };
            match assignment {
                None => a.problem = problem_for(400, "invalid JSON"),
                Some(body) => {
                    a.user = body.user_id;
                    a.domain_override = body.domain_override;
                    a.eligible = body.eligible;
                    a.problem = if body.user_id <= 0 {
                        problem_for(400, "userId is required")
                    } else {
                        scope_problem(&body.scope_type, body.scope_id)
                    };
                    a.scope_type = body.scope_type;
                    a.scope_id = body.scope_id;
                    if let Some(raw) = body.expires_at.filter(|raw| !raw.is_empty()) {
                        match input::rfc3339(&raw) {
                            Some(at) => a.expires_at = Some(input::timestamptz(at)),
                            None => a.expires_bad = true,
                        }
                    }
                }
            }
            match db::assign_member(exec, actor, authority, role, &a, &ip, operation).await {
                CommandOutcome::Committed(reply) => {
                    created("id", reply.id.unwrap_or_default(), 201)
                }
                CommandOutcome::RolledBack(e) => {
                    failed(
                        exec,
                        actor,
                        &e,
                        Some(a.user),
                        &ip,
                        operation,
                        go_path,
                        c,
                        id,
                    )
                    .await
                }
                CommandOutcome::Unknown { operation } => unknown(operation),
            }
        }
        Action::RemoveMember => {
            let (role, user) = (role_id(4), role_id(6));
            let (Some(role), Some(user)) = (role, user) else {
                return full(400, "invalid role id or user id");
            };
            match db::remove_member(exec, actor, scope, role, user, &ip, operation).await {
                CommandOutcome::Committed(_) => no_content(c, id),
                CommandOutcome::RolledBack(e) => {
                    failed(exec, actor, &e, Some(user), &ip, operation, go_path, c, id).await
                }
                CommandOutcome::Unknown { operation } => unknown(operation),
            }
        }
        Action::BulkAssign | Action::BulkRevoke => {
            let assign = what == Action::BulkAssign;
            let Some(role) = role_id(4) else {
                return full(400, "invalid role id");
            };
            let held = match db::role_permissions(exec, role).await {
                Ok(Some(held)) => held,
                Ok(None) => return full(404, "role not found"),
                Err(_) => return db_failed(),
            };
            if let Some(missing) = held.iter().find(|p| !authority.holds(p)) {
                return full(
                    403,
                    &format!(
                        "cannot assign a role granting a permission you do not hold: {missing}"
                    ),
                );
            }
            let Ok(body) = input::first::<input::RoleBulk>(&mut r, 1 << 20).await else {
                return full(400, "invalid JSON");
            };
            if assign {
                if let Some(p) = scope_problem(&body.scope_type, body.scope_id) {
                    return shown(&p);
                }
            }
            let mut users: Vec<i64> = Vec::new();
            for user in body.user_ids.into_iter().map(Option::unwrap_or_default) {
                if !users.contains(&user) {
                    users.push(user);
                }
            }
            if users.is_empty() || users.len() > 1000 {
                return full(400, "userIds must have 1\u{2013}1000 entries");
            }
            let mut expires_at = None;
            if assign {
                if let Some(raw) = body.expires_at.as_deref() {
                    let Some(at) = input::rfc3339(raw) else {
                        return full(400, "expiresAt must be RFC3339");
                    };
                    if at < chrono::Utc::now() {
                        return full(400, "expiresAt must be in the future");
                    }
                    expires_at = Some(input::timestamptz(at));
                }
            }
            let job = db::BulkJob {
                op: if assign { "assign" } else { "revoke" },
                role,
                users: &users,
                expires_at,
                scope_type: if assign { body.scope_type } else { None },
                scope_id: if assign { body.scope_id } else { None },
                eligible: assign && body.eligible.unwrap_or(false),
            };
            match db::enqueue_bulk(exec, actor, &job, operation).await {
                CommandOutcome::Committed(job) => created("jobId", job, 202),
                CommandOutcome::RolledBack(e) => {
                    failed(exec, actor, &e, None, &ip, operation, go_path, c, id).await
                }
                CommandOutcome::Unknown { operation } => unknown(operation),
            }
        }
        _ => unreachable!("not a roles action"),
    }
}
