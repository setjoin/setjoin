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
    sql as platform_sql,
    webhook_secret::SecretCodec,
    webhooks::{self as db, Failure},
};
use std::sync::Arc;

pub struct PlatformWebhooksRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub worker: Option<ScopedExecutor>,
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
    fn requires_session(&self, _req: &Request<Body>) -> bool {
        true
    }
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
        let codec = self.codec.clone();
        Box::pin(async move {
            let what = action(r.method(), r.uri().path()).expect("matched route");
            let verdict =
                crate::deny::admit(&exec, &keys, &issuer, &r, crate::deny::Scope::Member).await;
            let auth = match verdict {
                Ok(auth) => auth,
                Err(refusal) => return crate::deny::answer(refusal, r, &c).await,
            };
            let Some(operation) = crate::jmap::random() else {
                return bare(503, "service unavailable", &c, "");
            };
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation);
            let worker_exec = worker.as_ref().unwrap_or(&exec);
            let Some(factory) =
                crate::policy_composition::tx_factory_from_executors(&exec, Some(worker_exec))
            else {
                return bare(503, "service unavailable", &c, &id);
            };
            let ip = c.identity.client_ip.to_string();
            let Ok(user_principal) = factory.mint_user_from_authorized(&auth, &ip).await else {
                return bare(500, "database error", &c, &id);
            };
            let actor = auth.context();
            let go_path = segment_path(r.uri().path());
            let required = gate(what);
            let admin_opt = if actor.signed_admin() {
                factory.mint_admin_from_authorized(&auth, &ip).await.ok()
            } else {
                None
            };
            let Some(admin_principal) = admin_opt.filter(|a| a.allows_any(required)) else {
                let _ = setjoin_platform::console_denied(
                    &factory,
                    &user_principal,
                    &go_path,
                    &required.join("|"),
                    operation,
                )
                .await;
                return bare(403, "Forbidden", &c, &id);
            };
            if admin_principal.refused_for_scope(required) {
                let detail = format!(
                    "{} (domain-scoped principal; org-wide-only surface, domain={})",
                    required.join("|"),
                    admin_principal.enforced_domain_scope().unwrap_or(0)
                );
                let _ = setjoin_platform::console_denied(
                    &factory,
                    &user_principal,
                    &go_path,
                    &detail,
                    operation,
                )
                .await;
                return bare(403, "Forbidden", &c, &id);
            }
            let Ok(admin) = admin_principal.require_any_permission(required) else {
                let _ = setjoin_platform::console_denied(
                    &factory,
                    &user_principal,
                    &go_path,
                    &required.join("|"),
                    operation,
                )
                .await;
                return bare(403, "Forbidden", &c, &id);
            };
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
                Action::List => match db::list(&factory, &admin).await {
                    Ok(body) => reply(body, 200),
                    Err(_) => bare(500, "database error", &c, &id),
                },
                Action::Deliveries => match db::deliveries(&factory, &admin, target()).await {
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
                    let prepared = match db::prepare_create(&codec, &body.event_types) {
                        Ok(p) => p,
                        Err(other) => return failed(other),
                    };
                    let owner = user_principal.user().get();
                    match crate::mailboxes::worker_write_contract_family(
                        worker_exec,
                        &admin,
                        setjoin_platform::FAMILY,
                        "webhook_create",
                        &platform_sql::WEBHOOKS_CREATE,
                        &[
                            &owner,
                            &body.url,
                            &prepared.sealed,
                            &prepared.key_id,
                            &prepared.types_json,
                            &body.scope,
                        ],
                        operation,
                        db::parse_created_id,
                    )
                    .await
                    {
                        CommandOutcome::Committed(created_id) => reply(
                            db::format_created(
                                created_id,
                                &body.scope,
                                &prepared.secret,
                                &body.url,
                            ),
                            201,
                        ),
                        CommandOutcome::RolledBack(_) => bare(500, "create failed", &c, &id),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::Delete => {
                    let owner = user_principal.user().get();
                    let sub_id = target();
                    match crate::mailboxes::worker_write_contract_family(
                        worker_exec,
                        &admin,
                        setjoin_platform::FAMILY,
                        "webhook_delete",
                        &platform_sql::WEBHOOKS_DELETE,
                        &[&sub_id, &owner],
                        operation,
                        |rows| Ok(!rows.is_empty()),
                    )
                    .await
                    {
                        CommandOutcome::Committed(true) => {
                            let mut response = reply(String::new(), 204);
                            response.headers_mut().remove("content-type");
                            response
                        }
                        CommandOutcome::Committed(false) => bare(404, "not found", &c, &id),
                        CommandOutcome::RolledBack(_) => bare(500, "database error", &c, &id),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::Rotate => {
                    let (secret, sealed_new) = match db::prepare_rotate_new(&codec) {
                        Ok(pair) => pair,
                        Err(failure) => return failed(failure),
                    };
                    let owner = user_principal.user().get();
                    let sub_id = target();
                    let key_id = codec.active_key_id().to_owned();
                    for attempt in 0u16..5 {
                        let current = match db::rotate_read(&factory, &admin, sub_id, owner).await {
                            Ok(Some(row)) => row,
                            Ok(None) => return failed(Failure::NotFound),
                            Err(failure) => return failed(failure),
                        };
                        let sealed_prev = match db::prepare_rotate_prev(&codec, &current) {
                            Ok(prev) => prev,
                            Err(failure) => return failed(failure),
                        };
                        let mut op = operation;
                        op[14..16].copy_from_slice(&attempt.to_be_bytes());
                        match crate::mailboxes::worker_write_contract_family(
                            worker_exec,
                            &admin,
                            setjoin_platform::FAMILY,
                            "webhook_rotate_secret",
                            &platform_sql::WEBHOOKS_ROTATE_UPDATE,
                            &[
                                &sub_id,
                                &owner,
                                &sealed_prev,
                                &key_id,
                                &sealed_new,
                                &current.legacy,
                                &current.stored,
                                &current.key,
                            ],
                            op,
                            |rows| Ok(!rows.is_empty()),
                        )
                        .await
                        {
                            CommandOutcome::Committed(true) => {
                                return reply(db::format_rotated(&secret), 200);
                            }
                            CommandOutcome::Committed(false) => continue,
                            CommandOutcome::RolledBack(_) => return failed(Failure::Database),
                            CommandOutcome::Unknown { operation } => {
                                return unknown_outcome(operation, &c, &id);
                            }
                        }
                    }
                    failed(Failure::Database)
                }
            }
        })
    }
}
