//! F01 slice `sod` HTTP adapter: just-in-time role activation (`/admin/me/roles*`,
//! authenticated users only; the actor is always the verified token's user) and the
//! role activation policy (`/admin/roles/{id}/activation-policy`, gated by live
//! `roles.manage`). Activation calls Go's own reducers; the policy write is one
//! statement. See the crate DOX for the contract.
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use serde::de::{MapAccess, Visitor};
use setjoin_admin_identity::sod as db;
use setjoin_authz::token::KeySource;
use setjoin_pg::{CommandOutcome, Rejection, ScopedExecutor};
use std::fmt;
use std::sync::Arc;

pub struct AdminSodRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    MyRoles,
    Activate,
    Deactivate,
    Policy,
    PutPolicy,
}

fn action(method: &Method, path: &str) -> Option<Action> {
    let reads = matches!(*method, Method::GET | Method::HEAD);
    let post = *method == Method::POST;
    let table: [(bool, &str, Action); 5] = [
        (reads, "/api/admin/me/roles", Action::MyRoles),
        (post, "/api/admin/me/roles/{id}/activate", Action::Activate),
        (
            post,
            "/api/admin/me/roles/{id}/deactivate",
            Action::Deactivate,
        ),
        (
            reads,
            "/api/admin/roles/{id}/activation-policy",
            Action::Policy,
        ),
        (
            *method == Method::PUT,
            "/api/admin/roles/{id}/activation-policy",
            Action::PutPolicy,
        ),
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
body!(ActivateBody {
    duration_minutes: i64 = "durationminutes",
    justification: Option<String> = "justification"
});
body!(PolicyBody {
    max_duration_minutes: i64 = "maxdurationminutes",
    require_justification: bool = "requirejustification"
});

/// Go's `http.MaxBytesReader(w, r.Body, 4096)` plus `Decode`: only the first JSON
/// value is read, and it fails when it does not end within the first 4096 bytes.
async fn json_body<T: serde::de::DeserializeOwned>(r: &mut Request<Body>) -> Result<T, ()> {
    use http_body_util::BodyExt;
    const CAP: usize = 4096;
    let mut bytes = Vec::new();
    while bytes.len() < CAP {
        let Some(frame) = r.body_mut().frame().await else {
            break;
        };
        if let Ok(data) = frame.map_err(|_| ())?.into_data() {
            bytes.extend_from_slice(&data[..data.len().min(CAP - bytes.len())]);
        }
    }
    let fixed = crate::guests_input::go_json_bytes(&bytes);
    match serde_json::Deserializer::from_slice(&fixed)
        .into_iter::<T>()
        .next()
    {
        Some(Ok(value)) => Ok(value),
        _ => Err(()),
    }
}

impl<K: KeySource + 'static> Intercept for AdminSodRoute<K> {
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
            let path = r.uri().path().to_owned();
            let go_path = segment_path(&path);
            // Policy routes need live `roles.manage` (Go's `requireRolesManage`);
            // the self-service routes are open to any authenticated user.
            if matches!(what, Action::Policy | Action::PutPolicy) {
                let Ok(authority) = setjoin_admin_identity::authority(&exec, actor).await else {
                    return c.upstream.forward(r, &c.identity).await;
                };
                let required: &[&str] = &db::ROLES_MANAGE;
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
            }
            let reply =
                |body: String| crate::jmap::reply::response(body, c.identity.proto, id.clone());
            let full = |status: u16, detail: &str| problem(status, detail, &go_path, &c, &id);
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
            // Go's `httputil.ParseIDPath` on the `{id}` segment.
            let Some(role) = (match what {
                Action::MyRoles => Some(0),
                Action::Activate | Action::Deactivate => segment(&path, 5).parse::<i64>().ok(),
                Action::Policy | Action::PutPolicy => segment(&path, 4).parse::<i64>().ok(),
            }) else {
                return full(400, "invalid role id");
            };
            match what {
                Action::MyRoles => match db::my_roles(&exec, actor.user_id()).await {
                    Ok(body) => reply(body),
                    Err(_) => database(),
                },
                Action::Activate => {
                    let Ok(body) = json_body::<ActivateBody>(&mut r).await else {
                        return full(400, "invalid JSON");
                    };
                    if body.duration_minutes <= 0 {
                        return full(400, "durationMinutes must be positive");
                    }
                    // pgx refuses an int4 parameter out of range before any SQL runs.
                    let Ok(minutes) = i32::try_from(body.duration_minutes) else {
                        return database();
                    };
                    let justification = body.justification.filter(|j| !j.is_empty());
                    match db::activate(
                        &exec,
                        actor,
                        role,
                        minutes,
                        justification.as_deref(),
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(until) => {
                            // D6 cold start: the token predates the eligible assignment.
                            let refresh = if actor.signed_admin() {
                                ""
                            } else {
                                ",\"tokenRefreshRequired\":true"
                            };
                            reply(format!("{{\"activatedUntil\":\"{until}\"{refresh}}}\n"))
                        }
                        CommandOutcome::RolledBack(e) => {
                            let (Rejection::Statement(f) | Rejection::Body(f)) = &e else {
                                return database();
                            };
                            match f.sqlstate.as_deref() {
                                Some(code @ ("BZ104" | "BZ105")) => reducer(
                                    400,
                                    code,
                                    &f.message,
                                    "Correct the request fields and retry.",
                                    &go_path,
                                    &c,
                                    &id,
                                ),
                                _ => database(),
                            }
                        }
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::Deactivate => match db::deactivate(&exec, actor, role, operation).await {
                    CommandOutcome::Committed(()) => reply("{}\n".into()),
                    CommandOutcome::RolledBack(_) => database(),
                    CommandOutcome::Unknown { operation } => unknown(operation),
                },
                Action::Policy => {
                    // Owner-approved security fix 2026-11-05 (#393): role ownership.
                    if !db::role_in_scope(&exec, actor, role).await {
                        return full(404, "role not found");
                    }
                    match db::policy(&exec, role).await {
                        Ok(body) => reply(body),
                        Err(_) => database(),
                    }
                }
                Action::PutPolicy => {
                    if !db::role_in_scope(&exec, actor, role).await {
                        return full(404, "role not found");
                    }
                    let Ok(body) = json_body::<PolicyBody>(&mut r).await else {
                        return full(400, "invalid JSON");
                    };
                    if body.max_duration_minutes <= 0 {
                        return full(400, "maxDurationMinutes must be positive");
                    }
                    let Ok(minutes) = i32::try_from(body.max_duration_minutes) else {
                        return database();
                    };
                    match db::put_policy(
                        &exec,
                        actor,
                        role,
                        minutes,
                        body.require_justification,
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(text) => reply(text),
                        CommandOutcome::RolledBack(_) => database(),
                        CommandOutcome::Unknown { operation } => unknown(operation),
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

/// Go's `WriteProblemStatus`: a minimal problem, empty instance, no language.
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
