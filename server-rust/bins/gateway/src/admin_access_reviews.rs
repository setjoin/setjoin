//! F01 slice `access-reviews` HTTP adapter: recertification campaigns. Every
//! route is gated by `roles.manage` (Go's `requireRolesManage`, audited bare 403).
//! Each write is one call of Go's own `access_review_*` reducer; see the crate DOX.
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use serde::de::{MapAccess, Visitor};
use setjoin_admin_identity::access_reviews as db;
use setjoin_authz::token::KeySource;
use setjoin_pg::{CommandOutcome, Rejection, ScopedExecutor};
use std::fmt;
use std::sync::Arc;

pub struct AdminAccessReviewsRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    List,
    Start,
    Get,
    Decide,
    DecideBulk,
    Close,
}

fn action(method: &Method, path: &str) -> Option<Action> {
    let reads = matches!(*method, Method::GET | Method::HEAD);
    let table: [(bool, &str, Action); 6] = [
        (reads, "/api/admin/access-reviews", Action::List),
        (
            *method == Method::POST,
            "/api/admin/access-reviews",
            Action::Start,
        ),
        (reads, "/api/admin/access-reviews/{id}", Action::Get),
        (
            *method == Method::PUT,
            "/api/admin/access-reviews/{id}/items/{itemId}",
            Action::Decide,
        ),
        (
            *method == Method::PUT,
            "/api/admin/access-reviews/{id}/items",
            Action::DecideBulk,
        ),
        (
            *method == Method::POST,
            "/api/admin/access-reviews/{id}/close",
            Action::Close,
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
body!(StartBody {
    name: String = "name"
});
body!(DecideBody {
    decision: String = "decision",
    note: Option<String> = "note"
});
// A JSON null element decodes to Go's zero value.
body!(BulkBody {
    item_ids: Vec<Option<i64>> = "itemids",
    decision: String = "decision"
});

fn valid_decision(decision: &str) -> bool {
    matches!(decision, "keep" | "revoke")
}

async fn json_body<T: serde::de::DeserializeOwned>(
    r: &mut Request<Body>,
    cap: usize,
) -> Result<T, ()> {
    crate::admin_identity_input::first(r, cap).await
}

impl<K: KeySource + 'static> Intercept for AdminAccessReviewsRoute<K> {
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
            let domain_scope = authority.domain_scope();
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
            let failed = |e: &Rejection<setjoin_pg::StatementFailure>| match db::reducer_of(e) {
                Some(p) => reducer(&p, &go_path, &c, &id),
                None => database(),
            };
            match what {
                Action::List => match db::list(&exec, domain_scope).await {
                    Ok(body) => reply(body),
                    Err(_) => database(),
                },
                Action::Get => {
                    let Some(campaign) = number(4) else {
                        return full(400, "invalid id");
                    };
                    match db::get(&exec, actor.user_id(), domain_scope, campaign).await {
                        Ok(Some(body)) => reply(body),
                        Ok(None) => full(404, "no such campaign"),
                        Err(_) => database(),
                    }
                }
                Action::Start => {
                    let body = json_body::<StartBody>(&mut r, 1 << 16).await;
                    let Some(name) = body.ok().map(|b| b.name).filter(|n| !n.is_empty()) else {
                        return full(400, "name required");
                    };
                    match db::start(&exec, actor, &name, domain_scope, operation).await {
                        CommandOutcome::Committed(campaign) => {
                            let mut response = reply(format!("{{\"id\":{campaign}}}\n"));
                            *response.status_mut() = hyper::StatusCode::CREATED;
                            response
                        }
                        CommandOutcome::RolledBack(e) => failed(&e),
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::Decide => {
                    let Some(campaign) = number(4) else {
                        return full(400, "invalid id");
                    };
                    let Some(item) = number(6) else {
                        return full(400, "invalid id");
                    };
                    let body = json_body::<DecideBody>(&mut r, 1 << 16).await;
                    let Some(body) = body.ok().filter(|b| valid_decision(&b.decision)) else {
                        return full(400, "decision must be keep or revoke");
                    };
                    match db::decide(
                        &exec,
                        actor,
                        campaign,
                        item,
                        &body.decision,
                        body.note.as_deref(),
                        domain_scope,
                        operation,
                    )
                    .await
                    {
                        CommandOutcome::Committed(()) => status_only(204),
                        CommandOutcome::RolledBack(e) => failed(&e),
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::DecideBulk => {
                    let Some(campaign) = number(4) else {
                        return full(400, "invalid id");
                    };
                    let body = json_body::<BulkBody>(&mut r, 1 << 20).await;
                    let Some(body) = body
                        .ok()
                        .filter(|b| valid_decision(&b.decision) && !b.item_ids.is_empty())
                    else {
                        return full(400, "itemIds + keep/revoke required");
                    };
                    let items: Vec<i64> = body.item_ids.iter().map(|i| i.unwrap_or(0)).collect();
                    match db::decide_bulk(
                        &exec,
                        actor,
                        campaign,
                        &items,
                        &body.decision,
                        domain_scope,
                        operation,
                    )
                    .await
                    {
                        // The reducer's jsonb text is written as is, without a newline.
                        CommandOutcome::Committed(result) => reply(result),
                        CommandOutcome::RolledBack(e) => failed(&e),
                        CommandOutcome::Unknown { operation } => unknown(operation),
                    }
                }
                Action::Close => {
                    let Some(campaign) = number(4) else {
                        return full(400, "invalid id");
                    };
                    let ip = c.identity.client_ip.to_string();
                    match db::close(&exec, actor, campaign, &ip, domain_scope, operation).await {
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
/// Go's `reducererr.WriteClassified` for a known reducer code: the reducer
/// message is the detail, the class supplies the remediation, never retryable.
fn reducer(p: &db::Reducer, path: &str, c: &RequestContext, id: &str) -> Response<Body> {
    render(
        p.status,
        format!(
            "{{\"type\":\"https://setjoin.com/problems/reducer/{}\",\"title\":{},\"status\":{},\"detail\":{},\"instance\":{},\"remediation\":{},\"code\":{},\"retryable\":false}}",
            p.code.to_ascii_lowercase(),
            quote(title(p.status)),
            p.status,
            quote(&p.detail),
            quote(path),
            quote(p.remediation),
            quote(&p.code)
        ),
        true,
        c,
        id,
    )
}
