//! F08 slice `webhooks` HTTP adapter (#302): `/admin/webhooks*`, Go's
//! `admin.WebhooksHandler` (contract in the `setjoin-platform` DOX). Gates mirror Go's
//! `requireSystemPerm` (reads) and `requireSystemConfig` (create, delete, rotate); a
//! refusal writes Go's durable `console.denied` row and answers the bare 403. Ownership
//! of delete and rotate comes only from the verified token.
use crate::mailboxes::{bare, unknown_outcome};
use crate::platform::{json_body, segment, segment_path};
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use serde::de::{MapAccess, Visitor};
use setjoin_authz::token::KeySource;
use setjoin_pg::{CommandOutcome, ScopedExecutor};
use setjoin_platform::{
    webhook_secret::SecretCodec,
    webhooks::{self as db, Failure, Outcome},
};
use std::sync::Arc;

pub struct PlatformWebhooksRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    pub codec: SecretCodec,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Action {
    List,
    Create,
    Delete,
    Rotate,
    Deliveries,
    Events,
}

pub(crate) fn action(method: &Method, path: &str) -> Option<Action> {
    let reads = matches!(*method, Method::GET | Method::HEAD);
    let (post, delete) = (*method == Method::POST, *method == Method::DELETE);
    let table: [(bool, &str, Action); 6] = [
        (reads, "/api/admin/webhooks", Action::List),
        (post, "/api/admin/webhooks", Action::Create),
        (delete, "/api/admin/webhooks/{id}", Action::Delete),
        (
            post,
            "/api/admin/webhooks/{id}/rotate-secret",
            Action::Rotate,
        ),
        (
            reads,
            "/api/admin/webhooks/{id}/deliveries",
            Action::Deliveries,
        ),
        (reads, "/api/admin/webhooks/events", Action::Events),
    ];
    table
        .iter()
        .filter(|(ok, pattern, _)| *ok && crate::inventory::path_score(pattern, path).is_some())
        .max_by_key(|(_, pattern, _)| crate::inventory::path_score(pattern, path))
        .map(|(_, _, action)| *action)
}

fn gate(what: Action) -> &'static [&'static str] {
    match what {
        Action::Create | Action::Delete | Action::Rotate => &setjoin_platform::SYSTEM_CONFIG,
        _ => &setjoin_platform::SYSTEM_CONSOLE,
    }
}

/// Go's `struct{URL string; EventTypes []string; Scope string}` decoded by
/// `json.Decoder.Decode`: case-folded keys, `null` leaves the zero value, unknown keys
/// ignored, the last duplicate wins, only the first JSON value is read.
#[derive(Default)]
struct CreateBody {
    url: String,
    event_types: Vec<String>,
    scope: String,
}
impl<'de> serde::Deserialize<'de> for CreateBody {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        impl<'de> Visitor<'de> for Fields {
            type Value = CreateBody;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<CreateBody, E> {
                Ok(CreateBody::default())
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<CreateBody, M::Error> {
                let mut body = CreateBody::default();
                while let Some(key) = map.next_key::<String>()? {
                    match crate::guests_input::fold(&key).as_str() {
                        "url" => {
                            if let Some(text) = map.next_value::<Option<String>>()? {
                                body.url = text;
                            }
                        }
                        "eventtypes" => {
                            if let Some(list) = map.next_value::<Option<Vec<Option<String>>>>()? {
                                body.event_types =
                                    list.into_iter().map(Option::unwrap_or_default).collect();
                            }
                        }
                        "scope" => {
                            if let Some(text) = map.next_value::<Option<String>>()? {
                                body.scope = text;
                            }
                        }
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

impl<K: KeySource + 'static> Intercept for PlatformWebhooksRoute<K> {
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
        let codec = self.codec.clone();
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
            let Ok(authority) = setjoin_platform::authority(&exec, actor).await else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let go_path = segment_path(r.uri().path());
            let required = gate(what);
            if !authority.allows_any(required) {
                let _ = setjoin_platform::console_denied(
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
                let _ =
                    setjoin_platform::console_denied(&exec, actor, &go_path, &detail, operation)
                        .await;
                return bare(403, "Forbidden", &c, &id);
            }
            let head = r.method() == Method::HEAD;
            let reply = |body: String, status: u16| {
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
            // Go's `strconv.ParseInt(r.PathValue("id"), 10, 64)` with the error ignored.
            let path = r.uri().path().to_owned();
            let target = || segment(&path, 4).parse::<i64>().unwrap_or(0);
            let failed = |failure: Failure| match failure {
                Failure::Detail(text) | Failure::Stored(text) => bare(500, text, &c, &id),
                Failure::NotFound => bare(404, "not found", &c, &id),
                Failure::Database => bare(500, "database error", &c, &id),
            };
            match what {
                Action::Events => reply(db::event_catalog(), 200),
                Action::List => match db::list(&exec).await {
                    Ok(body) => reply(body, 200),
                    Err(_) => bare(500, "database error", &c, &id),
                },
                Action::Deliveries => match db::deliveries(&exec, target()).await {
                    Ok(body) => reply(body, 200),
                    Err(_) => bare(500, "query failed", &c, &id),
                },
                Action::Create => {
                    let invalid = || bare(400, "url and eventTypes required", &c, &id);
                    let Ok(mut body) = json_body::<CreateBody>(&mut r, 16 << 20).await else {
                        return invalid();
                    };
                    if body.url.is_empty() || body.event_types.is_empty() {
                        return invalid();
                    }
                    if body.scope.is_empty() {
                        body.scope = "self".into();
                    }
                    if let Err(detail) =
                        db::create_refusal(&body.url, &body.event_types, &body.scope)
                    {
                        return bare(400, detail, &c, &id);
                    }
                    match db::create(
                        &exec,
                        actor,
                        &codec,
                        &body.url,
                        &body.event_types,
                        &body.scope,
                        operation,
                    )
                    .await
                    {
                        Outcome::Done(text) => reply(text, 201),
                        Outcome::Failed(Failure::Database) => bare(500, "create failed", &c, &id),
                        Outcome::Failed(other) => failed(other),
                        Outcome::Unknown(operation) => unknown_outcome(operation, &c, &id),
                    }
                }
                Action::Delete => match db::delete(&exec, actor, target(), operation).await {
                    CommandOutcome::Committed(true) => {
                        let mut response = reply(String::new(), 204);
                        response.headers_mut().remove("content-type");
                        response
                    }
                    CommandOutcome::Committed(false) => bare(404, "not found", &c, &id),
                    CommandOutcome::RolledBack(_) => bare(500, "database error", &c, &id),
                    CommandOutcome::Unknown { operation } => unknown_outcome(operation, &c, &id),
                },
                Action::Rotate => {
                    match db::rotate(&exec, actor, &codec, target(), operation).await {
                        Outcome::Done(text) => reply(text, 200),
                        Outcome::Failed(failure) => failed(failure),
                        Outcome::Unknown(operation) => unknown_outcome(operation, &c, &id),
                    }
                }
            }
        })
    }
}
