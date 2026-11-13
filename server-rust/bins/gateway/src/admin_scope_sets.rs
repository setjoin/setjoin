//! F01 slice `scope-sets` HTTP adapter: named admin scope containers and their
//! members. Every route is gated by `scope_sets.manage` (Go's
//! `requireScopeSetsManage`), writes additionally by Go's `RequireReason`.
//! Each write is one reducer call; see the crate DOX for the contract.
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use serde::de::{MapAccess, Visitor};
use setjoin_admin_identity::scope_sets as db;
use setjoin_authz::token::KeySource;
use setjoin_pg::{CommandOutcome, Rejection, ScopedExecutor};
use std::fmt;
use std::sync::Arc;

pub struct AdminScopeSetsRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    List,
    Create,
    Get,
    Update,
    Delete,
    AddMember,
    RemoveMember,
}

fn action(method: &Method, path: &str) -> Option<Action> {
    let reads = matches!(*method, Method::GET | Method::HEAD);
    let table: [(bool, &str, Action); 7] = [
        (reads, "/api/admin/scope-sets", Action::List),
        (
            *method == Method::POST,
            "/api/admin/scope-sets",
            Action::Create,
        ),
        (reads, "/api/admin/scope-sets/{id}", Action::Get),
        (
            *method == Method::PUT,
            "/api/admin/scope-sets/{id}",
            Action::Update,
        ),
        (
            *method == Method::DELETE,
            "/api/admin/scope-sets/{id}",
            Action::Delete,
        ),
        (
            *method == Method::POST,
            "/api/admin/scope-sets/{id}/members",
            Action::AddMember,
        ),
        (
            *method == Method::DELETE,
            "/api/admin/scope-sets/{id}/members/{memberType}/{memberId}",
            Action::RemoveMember,
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
body!(CreateBody {
    name: String = "name",
    domain_id: Option<i64> = "domainid",
    description: String = "description"
});
body!(UpdateBody {
    name: Option<String> = "name",
    description: Option<String> = "description"
});
body!(MemberBody {
    member_type: String = "membertype",
    member_id: i64 = "memberid"
});

async fn json_body<T: serde::de::DeserializeOwned>(r: &mut Request<Body>) -> Result<T, ()> {
    crate::admin_identity_input::first(r, 1 << 20).await
}

impl<K: KeySource + 'static> Intercept for AdminScopeSetsRoute<K> {
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
            let required: &[&str] = &db::SCOPE_SETS_MANAGE;
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
            let ip = c.identity.client_ip.to_string();
            if !matches!(what, Action::List | Action::Get)
                && db::reason_required(&exec).await
                && r.headers()
                    .get("x-audit-reason")
                    .is_none_or(|v| v.as_bytes().is_empty())
            {
                db::missing_reason(&exec, actor, &ip, operation).await;
                return bare(400, "reason_required", &c, &id);
            }
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
            let status_only = |status: u16| {
                let mut response =
                    crate::jmap::reply::response(String::new(), c.identity.proto, id.clone());
                *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
                response.headers_mut().remove("content-type");
                response
            };
            let number = |index: usize| segment(&path, index).parse::<i64>().ok();
            // A refusal decided by a reducer, or the database failing.
            let failed = |e: &Rejection<setjoin_pg::StatementFailure>| match db::problem_of(e) {
                Some(p) if p.status == 409 => conflict(&p.detail, &go_path, &c, &id),
                Some(p) => full(p.status, &p.detail),
                None => database(),
            };
            let code = |e: &Rejection<setjoin_pg::StatementFailure>| match e {
                Rejection::Statement(e) | Rejection::Body(e) => e.sqlstate.clone(),
                _ => None,
            };
            match what {
                Action::List => match db::list(&exec, actor).await {
                    Ok(body) => reply(body),
                    Err(_) => database(),
                },
                Action::Get => {
                    let Some(set) = number(4) else {
                        return full(400, "invalid scope set id");
                    };
                    match db::get(&exec, actor, set).await {
                        Ok(Some(body)) => reply(body),
                        Ok(None) => full(404, "scope set not found"),
                        Err(_) => database(),
                    }
                }
                Action::Create => {
                    let Ok(body) = json_body::<CreateBody>(&mut r).await else {
                        return full(400, "invalid JSON");
                    };
                    if body.name.is_empty() {
                        return full(400, "name is required");
                    }
                    match db::create(
                        &exec,
                        actor,
                                        &body.name,
                        body.domain_id,
                        &body.description,
                        &ip,
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(set) => {
                            let mut response = reply(format!("{{\"id\":{set}}}\n"));
                            *response.status_mut() = hyper::StatusCode::CREATED;
                            response
                        }
                        CommandOutcome::RolledBack(e) => {
                            if code(&e).as_deref() == Some("23505") {
                                conflict(
                                    &format!(
                                        "a set named {} already exists in this domain",
                                        db::go_quote(&body.name)
                                    ),
                                    &go_path,
                                    &c,
                                    &id,
                                )
                            } else {
                                failed(&e)
                            }
                        }
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::Update => {
                    let Some(set) = number(4) else {
                        return full(400, "invalid scope set id");
                    };
                    let Ok(body) = json_body::<UpdateBody>(&mut r).await else {
                        return full(400, "invalid JSON");
                    };
                    match db::update(
                        &exec,
                        actor,
                                        set,
                        body.name.as_deref(),
                        body.description.as_deref(),
                        &ip,
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(()) => status_only(204),
                        CommandOutcome::RolledBack(e) => {
                            if code(&e).as_deref() == Some("23505") {
                                conflict(
                                    "a set with that name already exists in this domain",
                                    &go_path,
                                    &c,
                                    &id,
                                )
                            } else {
                                failed(&e)
                            }
                        }
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::Delete => {
                    let Some(set) = number(4) else {
                        return full(400, "invalid scope set id");
                    };
                    match db::delete(&exec, actor, set, &ip, operation).await {
                        CommandOutcome::Committed(()) => status_only(204),
                        CommandOutcome::RolledBack(e) => failed(&e),
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::AddMember => {
                    let Some(set) = number(4) else {
                        return full(400, "invalid scope set id");
                    };
                    let Ok(body) = json_body::<MemberBody>(&mut r).await else {
                        return full(400, "invalid JSON");
                    };
                    if body.member_type.is_empty() || body.member_id == 0 {
                        return full(400, "memberType and memberId are required");
                    }
                    match db::add_member(
                        &exec,
                        actor,
                                        set,
                        &body.member_type,
                        body.member_id,
                        &ip,
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(status) => status_only(status),
                        CommandOutcome::RolledBack(e) => failed(&e),
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::RemoveMember => {
                    let Some(set) = number(4) else {
                        return full(400, "invalid scope set id");
                    };
                    let member_type = segment(&path, 6);
                    if !matches!(member_type.as_str(), "ou" | "user" | "group") {
                        return full(400, "invalid memberType");
                    }
                    let Some(member) = number(7) else {
                        return full(400, "invalid member id");
                    };
                    match db::remove_member(&exec, actor, set, &member_type, member, &ip, operation)
                        .await
                    {
                        CommandOutcome::Committed(()) => status_only(204),
                        CommandOutcome::RolledBack(e) => failed(&e),
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
/// Go's `NewConflictProblem`.
fn conflict(detail: &str, path: &str, c: &RequestContext, id: &str) -> Response<Body> {
    render(
        409,
        format!(
            "{{\"type\":\"https://setjoin.com/errors/conflict\",\"title\":\"Conflict\",\"status\":409,\"detail\":{},\"instance\":{}}}",
            quote(detail),
            quote(path)
        ),
        true,
        c,
        id,
    )
}
