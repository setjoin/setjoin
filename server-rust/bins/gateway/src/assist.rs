//! F20 Assist (#271): `POST /assist/complete` and `POST /assist/stream`, plus
//! the Go-shaped problem and provider helpers `POST /chat/messages/{id}/translate`
//! shares. Mounted by Go at `/api` (`/assist/*` is not a pinned prefix).
//!
//! Authentication is the shared request chain; an unauthenticated or
//! unverifiable caller is handled by shared admission. Provider secrets use
//! the foundation config-secret codec; decrypt failures fail closed.
use crate::{Body, BoxFuture, Intercept, RequestContext};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_pg::{ScopedExecutor, Type};
use setjoin_static::assist as logic;
use setjoin_static::wellknown::go_json_string;
use std::sync::Arc;

pub struct AssistRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
}

/// `toggle.FeatureFlags.IsEnabled` for a default-OFF key; `None` when the
/// read failed (the caller then defers to Go).
pub(crate) async fn feature_on(exec: &ScopedExecutor, key: &str) -> Option<bool> {
    let rows = exec
        .read(
            "SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key=$1),false)",
            &[(&key, Type::TEXT)],
        )
        .await
        .ok()?;
    Some(rows[0].get::<_, bool>(0))
}

/// `httputil.WriteProblem` with a typed problem: Go's field order, the
/// request's `Accept-Language` tag and `no-store`.
pub(crate) fn typed_problem(
    status: u16,
    slug: &str,
    title: &str,
    detail: &str,
    instance: &str,
    language: &str,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let mut response = crate::chat::problem(status, detail, instance, c, id);
    let kind = format!("https://setjoin.com/errors/{slug}");
    let body = crate::problem::Problem::new(status, detail)
        .kind(&kind).title(title).instance(instance).body();
    *response.body_mut() = Full::new(Bytes::from(body)).map_err(|n| match n {}).boxed();
    if let Ok(value) = language.parse() {
        response.headers_mut().insert("content-language", value);
    }
    response
}

pub(crate) fn bad_gateway(
    instance: &str,
    language: &str,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    typed_problem(
        502,
        "internal-error",
        "Bad Gateway",
        "The AI assist provider returned an error. Please try again.",
        instance,
        language,
        c,
        id,
    )
}

/// The request with its already-read body restored, for a whole-request
/// forward to Go.
pub(crate) fn restore(mut r: Request<Body>, bytes: Vec<u8>) -> Request<Body> {
    *r.body_mut() = Full::new(Bytes::from(bytes))
        .map_err(|n| match n {})
        .boxed();
    r
}

fn text_of(fields: &crate::chat::Fields, key: &str) -> Result<String, ()> {
    crate::chat_channels::text_field(fields, key)
}

/// The envelope Go decodes with `json.Decoder` into `sharedassist.Request`.
fn decode(bytes: &[u8]) -> Result<logic::Request, ()> {
    let fields = crate::chat_channels::decode_fields(bytes)?;
    let mut messages = Vec::new();
    for (key, raw) in &fields.0 {
        if !key.eq_ignore_ascii_case("messages") {
            continue;
        }
        // Go resets a slice on every occurrence; `null` leaves it empty.
        messages.clear();
        if raw.get() == "null" {
            continue;
        }
        let items: Vec<Box<serde_json::value::RawValue>> =
            serde_json::from_str(raw.get()).map_err(|_| ())?;
        for item in items {
            if item.get() == "null" {
                messages.push(logic::Message::default());
                continue;
            }
            let m = crate::chat_channels::decode_fields(item.get().as_bytes())?;
            messages.push(logic::Message {
                role: text_of(&m, "ROLE")?,
                content: text_of(&m, "CONTENT")?,
            });
        }
    }
    Ok(logic::Request {
        messages,
        context: text_of(&fields, "CONTEXT")?,
        locale: text_of(&fields, "LOCALE")?,
    })
}

impl<K: KeySource + 'static> Intercept for AssistRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, r: &Request<Body>) -> bool {
        *r.method() == Method::POST
            && ["/api/assist/complete", "/api/assist/stream"]
                .iter()
                .any(|p| crate::inventory::path_score(p, r.uri().path()).is_some())
    }

    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            setjoin_authz::authorize_request(&exec, &keys, &issuer, &h, s)
                .await
                .is_some()
        })
    }

    fn handle(&self, mut r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        let language = crate::chat_channels::problem_language(r.headers());
        Box::pin(async move {
            let mut nonce = [0; 16];
            if getrandom::getrandom(&mut nonce).is_err() {
                return c.upstream.forward(r, &c.identity).await;
            }
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), nonce);
            // Go's StripPrefix("/api") compares the raw spelling.
            if r.uri().path().split('/').nth(1).is_some_and(|p| p != "api") {
                let mut response = crate::jmap::reply::response(
                    "404 page not found\n".into(),
                    c.identity.proto,
                    id,
                );
                *response.status_mut() = hyper::StatusCode::NOT_FOUND;
                response.headers_mut().insert(
                    "content-type",
                    hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
                );
                return response;
            }
            let decoded = crate::chat::go_utf8(&crate::inventory::unescape(r.uri().path()));
            let instance = decoded.strip_prefix("/api").unwrap_or(&decoded).to_owned();
            if setjoin_authz::authorize_request(
                &exec,
                &*keys,
                &issuer,
                r.headers(),
                c.identity.proto,
            )
            .await
            .is_none()
            {
                return c.upstream.forward(r, &c.identity).await;
            }
            if instance == "/assist/stream" {
                return typed_problem(
                    501,
                    "not-implemented",
                    "Not Implemented",
                    "Streaming is not yet available. Use POST /assist/complete instead.",
                    &instance,
                    &language,
                    &c,
                    id,
                );
            }
            match feature_on(&exec, "feature.assist").await {
                Some(true) => {}
                Some(false) => {
                    return typed_problem(
                        403,
                        "forbidden",
                        "Forbidden",
                        "AI assist is not enabled for your account.",
                        &instance,
                        &language,
                        &c,
                        id,
                    )
                }
                None => return c.upstream.forward(r, &c.identity).await,
            }
            let invalid = |c: &RequestContext, id: String, detail: &str| {
                typed_problem(
                    422,
                    "validation-failed",
                    "Validation Failed",
                    detail,
                    &instance,
                    &language,
                    c,
                    id,
                )
            };
            let Ok(bytes) = crate::chat_channels::read_body(&mut r).await else {
                return invalid(&c, id, "Invalid JSON in request body.");
            };
            let request = match decode(&bytes) {
                Ok(request) => request,
                Err(()) => return invalid(&c, id, "Invalid JSON in request body."),
            };
            if let Err(why) = logic::validate(&request) {
                return invalid(&c, id, why.detail());
            }
            let config = match logic::load_config(&exec).await {
                Ok(config) => config,
                Err(logic::ConfigError::NotConfigured) => {
                    return typed_problem(
                        503,
                        "service-unavailable",
                        "Service Unavailable",
                        "AI assist is not configured. An administrator must set assist.provider_url and assist.model.",
                        &instance,
                        &language,
                        &c,
                        id,
                    )
                }
                Err(logic::ConfigError::Unavailable) => {
                    return typed_problem(
                        503,
                        "service-unavailable",
                        "Service Unavailable",
                        "AI assist is temporarily unavailable.",
                        &instance,
                        &language,
                        &c,
                        id,
                    )
                }
            };
            match logic::complete(&config, &request).await {
                Ok(content) => {
                    let body = format!("{{\"content\":{}}}\n", go_json_string(&content));
                    crate::jmap::reply::response(body, c.identity.proto, id)
                }
                Err(logic::UpstreamError) => bad_gateway(&instance, &language, &c, id),
            }
        })
    }
}
