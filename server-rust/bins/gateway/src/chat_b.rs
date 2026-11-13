//! F12 Part B's inventory-gated HTTP adapter.
use crate::{Body, BoxFuture, Intercept, RequestContext};
use http_body_util::BodyExt;
use hyper::{Method, Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_contracts::han;
use setjoin_pg::{ScopedExecutor, Type};
use std::sync::Arc;

pub struct ChatBRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    pub store: Option<Arc<crate::recovery_worker::S3Store>>,
}
impl<K: KeySource + 'static> Intercept for ChatBRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, r: &Request<Body>) -> bool {
        if matches!(*r.method(), Method::GET | Method::HEAD)
            && crate::inventory::path_score("/api/chat/unfurl/image/{sha256}", r.uri().path())
                .is_some()
        {
            return true;
        }

        if matches!(*r.method(), Method::GET | Method::HEAD)
            && crate::inventory::path_score("/api/chat/polls/{id}/results", r.uri().path())
                .is_some()
        {
            return true;
        }

        if r.method() == Method::POST
            && crate::inventory::path_score("/api/chat/polls/{id}/close", r.uri().path()).is_some()
        {
            return true;
        }

        if r.method() == Method::POST
            && crate::inventory::path_score("/api/chat/polls/{id}/vote", r.uri().path()).is_some()
        {
            return true;
        }

        if r.method() == Method::DELETE
            && crate::inventory::path_score("/api/chat/scheduled/{actionId}", r.uri().path())
                .is_some()
        {
            return true;
        }

        if matches!(*r.method(), Method::GET | Method::HEAD)
            && crate::inventory::path_score("/api/chat/scheduled", r.uri().path()).is_some()
        {
            return true;
        }

        if r.method() == Method::POST
            && [
                "/api/chat/messages/{id}/reactions",
                "/api/chat/messages/{id}/pin",
                "/api/chat/messages/{id}/translate",
            ]
            .iter()
            .any(|p| crate::inventory::path_score(p, r.uri().path()).is_some())
        {
            return true;
        }

        (matches!(*r.method(), Method::GET | Method::HEAD)
            && (crate::inventory::path_score("/api/chat/search", r.uri().path()).is_some()
                || crate::inventory::path_score("/api/chat/my-threads", r.uri().path()).is_some()
                || crate::inventory::path_score("/api/chat/saves", r.uri().path()).is_some()
                || crate::inventory::path_score("/api/chat/messages/{id}/thread", r.uri().path())
                    .is_some()))
            || (r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/messages/{id}/save", r.uri().path())
                    .is_some())
            || (matches!(*r.method(), Method::PATCH | Method::DELETE)
                && crate::inventory::path_score("/api/chat/messages/{id}", r.uri().path())
                    .is_some())
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            setjoin_authz::authorize_user_request(&exec, &keys, &issuer, &h, s)
                .await
                .is_some()
        })
    }
    fn handle(&self, mut r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        let store = self.store.clone();
        let language = crate::chat_channels::problem_language(r.headers());
        let work = async move {
            let mut nonce = [0; 16];
            if getrandom::getrandom(&mut nonce).is_err() {
                return c.upstream.forward(r, &c.identity).await;
            }
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), nonce);
            // Go StripPrefix checks the raw API mount spelling too.
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

            let Some(auth) = setjoin_authz::authorize_user_request(
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
            let feature=exec.read("SELECT coalesce((SELECT enabled FROM feature_toggles WHERE key='feature.chat'),false)",&[]).await;
            match feature {
                Ok(rows) if rows[0].get::<_, bool>(0) => {}
                Ok(_) => return opaque_not_found(&c, id),
                Err(_) => return c.upstream.forward(r, &c.identity).await,
            }
            let user = auth.context().user_id();
            if !exec
                .read(
                    "SELECT check_user_app_entitlement($1,'chat')",
                    &[(&user, Type::INT8)],
                )
                .await
                .is_ok_and(|rows| rows[0].get::<_, bool>(0))
            {
                setjoin_chat::members::app_blocked(
                    &exec,
                    auth.context(),
                    &c.identity.client_ip.to_string(),
                    nonce,
                )
                .await;
                let mut response = crate::chat::problem(
                    403,
                    "Access to this application is not permitted for your account.",
                    &instance,
                    &c,
                    id,
                );
                let body = crate::chat::go_problem_json(
                    "https://setjoin.com/errors/forbidden",
                    "Forbidden",
                    403,
                    "Access to this application is not permitted for your account.",
                    &instance,
                    None,
                );
                *response.body_mut() = http_body_util::Full::new(bytes::Bytes::from(body))
                    .map_err(|never| match never {})
                    .boxed();
                return response;
            }

            if r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/messages/{id}/translate", r.uri().path())
                    .is_some()
            {
                let language = crate::chat_channels::problem_language(r.headers());
                return crate::translate::serve(
                    &exec,
                    &auth,
                    r,
                    instance.as_str(),
                    &language,
                    &c,
                    id,
                    nonce,
                )
                .await;
            }
            if r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/messages/{id}/reactions", r.uri().path())
                    .is_some()
            {
                let path = instance.as_str();
                let Some(message) =
                    message_id(r.uri().path(), "reactions").and_then(|s| s.parse::<i64>().ok())
                else {
                    return super::chat::problem(400, "invalid id", &path, &c, id);
                };
                let bytes = match crate::chat_channels::read_body(&mut r).await {
                    Ok(b) => b,
                    Err(_) => return super::chat::problem(400, "invalid JSON", &path, &c, id),
                };
                let emoji = match text_field(&bytes, "emoji") {
                    Ok(s) => s,
                    Err(_) => return super::chat::problem(400, "invalid JSON", &path, &c, id),
                };
                return match setjoin_chat::members::reaction(
                    &exec,
                    auth.context(),
                    message,
                    &emoji,
                    nonce,
                )
                .await
                {
                    setjoin_pg::CommandOutcome::Committed(present) => crate::jmap::reply::response(
                        serde_json::json!({"present":present}).to_string() + "\n",
                        c.identity.proto,
                        id,
                    ),
                    setjoin_pg::CommandOutcome::RolledBack(ref error) => {
                        rejection(error, &path, &c, id)
                    }
                    setjoin_pg::CommandOutcome::Unknown { operation } => {
                        super::chat::unknown(operation, &path, &c, id)
                    }
                };
            }
            if r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/messages/{id}/pin", r.uri().path())
                    .is_some()
            {
                let path = instance.as_str();
                let Some(message) =
                    message_id(r.uri().path(), "pin").and_then(|s| s.parse::<i64>().ok())
                else {
                    return super::chat::problem(400, "invalid message id", path, &c, id);
                };
                return match setjoin_chat::members::pin(&exec, auth.context(), message, nonce).await
                {
                    setjoin_pg::CommandOutcome::Committed(pinned) => crate::jmap::reply::response(
                        serde_json::json!({"pinned":pinned}).to_string() + "\n",
                        c.identity.proto,
                        id,
                    ),
                    setjoin_pg::CommandOutcome::RolledBack(ref error) => {
                        rejection(error, path, &c, id)
                    }
                    setjoin_pg::CommandOutcome::Unknown { operation } => {
                        super::chat::unknown(operation, path, &c, id)
                    }
                };
            }
            if crate::inventory::path_score("/api/chat/scheduled", r.uri().path()).is_some() {
                let path = instance.as_str();
                return match setjoin_chat::members::scheduled(&exec, auth.context()).await {
                    Ok(value) => read_reply(&value, instance.as_str(), &c, id),
                    Err(ref e) => failure(e, path, &c, id),
                };
            }
            if r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/polls/{id}/vote", r.uri().path())
                    .is_some()
            {
                let path = instance.as_str();
                let Some(poll) = r.uri().path().split('/').nth(4).and_then(|s| {
                    String::from_utf8(crate::inventory::unescape(s))
                        .ok()?
                        .parse::<i64>()
                        .ok()
                }) else {
                    return super::chat::problem(400, "invalid id", &path, &c, id);
                };
                let option = async {
                    let bytes = crate::chat_channels::read_body(&mut r)
                        .await
                        .map_err(|_| ())?;
                    let fields = crate::chat_channels::decode_fields(&bytes)?;
                    option_id(&fields)
                }
                .await;
                let Ok(option) = option else {
                    return super::chat::problem(400, "invalid JSON", &path, &c, id);
                };
                return match setjoin_chat::members::vote(&exec, auth.context(), poll, option, nonce)
                    .await
                {
                    setjoin_pg::CommandOutcome::Committed(_) => no_content(&c, id),
                    setjoin_pg::CommandOutcome::RolledBack(ref error) => {
                        rejection(error, &path, &c, id)
                    }
                    setjoin_pg::CommandOutcome::Unknown { operation } => {
                        super::chat::unknown(operation, &path, &c, id)
                    }
                };
            }
            if r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/polls/{id}/close", r.uri().path())
                    .is_some()
            {
                let path = instance.as_str();
                let Some(poll) = r.uri().path().split('/').nth(4).and_then(|s| {
                    String::from_utf8(crate::inventory::unescape(s))
                        .ok()?
                        .parse::<i64>()
                        .ok()
                }) else {
                    return super::chat::problem(400, "invalid poll id", path, &c, id);
                };
                return match setjoin_chat::members::close(&exec, auth.context(), poll, nonce).await
                {
                    setjoin_pg::CommandOutcome::Committed(_) => no_content(&c, id),
                    setjoin_pg::CommandOutcome::RolledBack(ref error) => {
                        rejection(error, path, &c, id)
                    }
                    setjoin_pg::CommandOutcome::Unknown { operation } => {
                        super::chat::unknown(operation, path, &c, id)
                    }
                };
            }
            if crate::inventory::path_score("/api/chat/polls/{id}/results", r.uri().path())
                .is_some()
            {
                let path = instance.as_str();
                let Some(poll) = r.uri().path().split('/').nth(4).and_then(|s| {
                    String::from_utf8(crate::inventory::unescape(s))
                        .ok()?
                        .parse::<i64>()
                        .ok()
                }) else {
                    return super::chat::problem(400, "invalid poll id", path, &c, id);
                };
                return match setjoin_chat::members::results(&exec, auth.context(), poll).await {
                    Ok(value) => read_reply(&value, instance.as_str(), &c, id),
                    Err(ref error) => failure(error, path, &c, id),
                };
            }
            if crate::inventory::path_score("/api/chat/unfurl/image/{sha256}", r.uri().path())
                .is_some()
            {
                let raw = r
                    .uri()
                    .path()
                    .split('/')
                    .nth(5)
                    .map(crate::inventory::unescape)
                    .unwrap_or_default();
                let Some(store) = store else {
                    return opaque_not_found(&c, id);
                };
                if raw.len() != 64
                    || !raw
                        .iter()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
                {
                    return opaque_not_found(&c, id);
                }
                let hash = String::from_utf8(raw).expect("ASCII hash");
                let content_type =
                    match setjoin_chat::members::image_type(&exec, auth.context(), &hash).await {
                        Ok(Some(t)) => t,
                        _ => return opaque_not_found(&c, id),
                    };
                // Go's MinIO GetObject defers network errors until io.Copy;
                // once this ownership/metadata preflight passes those errors
                // leave an empty 200 with the same untrusted-blob headers.
                let bytes = store.unfurl_image(&hash).await.unwrap_or_default();
                let mut response =
                    crate::jmap::reply::response(String::new(), c.identity.proto, id);
                response.headers_mut().remove("content-type");
                if !content_type.is_empty() {
                    if let Ok(value) = content_type.parse() {
                        response.headers_mut().insert("content-type", value);
                    }
                }
                response.headers_mut().insert(
                    "content-security-policy",
                    hyper::header::HeaderValue::from_static("default-src 'none'; sandbox"),
                );
                // net/http buffers at most 2 KiB before switching this
                // io.Copy response to chunked transfer coding. HEAD omits it.
                if r.method() != Method::HEAD && bytes.len() > 2048 {
                    response.headers_mut().insert(
                        "transfer-encoding",
                        hyper::header::HeaderValue::from_static("chunked"),
                    );
                }
                *response.body_mut() = if r.method() == Method::HEAD && bytes.len() > 2048 {
                    // Go flushes this copy before handler completion, so HEAD
                    // advertises neither a synthesized length nor chunking.
                    let stream = futures_util::stream::once(async move {
                        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(hyper::body::Frame::data(
                            bytes::Bytes::from(bytes),
                        ))
                    });
                    http_body_util::StreamBody::new(stream).boxed()
                } else {
                    http_body_util::Full::new(bytes::Bytes::from(bytes))
                        .map_err(|never| match never {})
                        .boxed()
                };
                return response;
            }
            if r.method() == Method::DELETE
                && crate::inventory::path_score("/api/chat/scheduled/{actionId}", r.uri().path())
                    .is_some()
            {
                let path = instance.as_str();
                let raw = r
                    .uri()
                    .path()
                    .split('/')
                    .nth(4)
                    .map(crate::inventory::unescape)
                    .unwrap_or_default();
                let Some(action) = uuid(&raw) else {
                    return super::chat::problem(400, "invalid actionId", path, &c, id);
                };
                return match setjoin_chat::members::cancel(&exec, auth.context(), &action, nonce)
                    .await
                {
                    setjoin_pg::CommandOutcome::Committed(_) => no_content(&c, id),
                    setjoin_pg::CommandOutcome::RolledBack(ref error) => {
                        rejection(error, path, &c, id)
                    }
                    setjoin_pg::CommandOutcome::Unknown { operation } => {
                        super::chat::unknown(operation, path, &c, id)
                    }
                };
            }
            if r.method() == Method::DELETE {
                let path = instance.as_str();
                let message = message_id(r.uri().path(), "").and_then(|s| s.parse::<i64>().ok());
                let Some(message) = message else {
                    return super::chat::problem(400, "invalid message id", path, &c, id);
                };
                return match setjoin_chat::members::delete(&exec, auth.context(), message, nonce)
                    .await
                {
                    setjoin_pg::CommandOutcome::Committed(seq) => crate::jmap::reply::response(
                        serde_json::json!({"seq":seq}).to_string() + "\n",
                        c.identity.proto,
                        id,
                    ),
                    setjoin_pg::CommandOutcome::RolledBack(ref error) => {
                        rejection(error, path, &c, id)
                    }
                    setjoin_pg::CommandOutcome::Unknown { operation } => {
                        super::chat::unknown(operation, path, &c, id)
                    }
                };
            }
            if r.method() == Method::PATCH {
                let path = instance.as_str();
                let message = message_id(r.uri().path(), "").and_then(|s| s.parse::<i64>().ok());
                let Some(message) = message else {
                    return super::chat::problem(400, "invalid id", &path, &c, id);
                };
                let mut bytes = Vec::new();
                while let Some(frame) = r.body_mut().frame().await {
                    let Ok(frame) = frame else {
                        return super::chat::problem(400, "invalid JSON", &path, &c, id);
                    };
                    if let Some(data) = frame.data_ref() {
                        if bytes.len() + data.len() > 1 << 20 {
                            return super::chat::problem(400, "invalid JSON", &path, &c, id);
                        }
                        bytes.extend_from_slice(data);
                    }
                }
                let body = text_field(&bytes, "body");
                let Ok(body) = body else {
                    return super::chat::problem(400, "invalid JSON", &path, &c, id);
                };
                return match setjoin_chat::members::edit(
                    &exec,
                    auth.context(),
                    message,
                    &body,
                    nonce,
                )
                .await
                {
                    setjoin_pg::CommandOutcome::Committed(seq) => crate::jmap::reply::response(
                        serde_json::json!({"seq":seq}).to_string() + "\n",
                        c.identity.proto,
                        id,
                    ),
                    setjoin_pg::CommandOutcome::RolledBack(ref error) => {
                        rejection(error, &path, &c, id)
                    }
                    setjoin_pg::CommandOutcome::Unknown { operation } => {
                        super::chat::unknown(operation, &path, &c, id)
                    }
                };
            }
            if r.method() == Method::POST {
                let path = instance.as_str();
                let message =
                    message_id(r.uri().path(), "save").and_then(|s| s.parse::<i64>().ok());
                let Some(message) = message else {
                    return super::chat::problem(400, "invalid message id", path, &c, id);
                };
                return match setjoin_chat::members::save(&exec, auth.context(), message, nonce)
                    .await
                {
                    setjoin_pg::CommandOutcome::Committed(saved) => crate::jmap::reply::response(
                        serde_json::json!({"saved":saved}).to_string() + "\n",
                        c.identity.proto,
                        id,
                    ),
                    setjoin_pg::CommandOutcome::RolledBack(ref error) => {
                        rejection(error, path, &c, id)
                    }
                    setjoin_pg::CommandOutcome::Unknown { operation } => {
                        super::chat::unknown(operation, path, &c, id)
                    }
                };
            }
            if crate::inventory::path_score("/api/chat/search", r.uri().path()).is_some() {
                let path = instance.as_str();
                let query = super::chat::query_bytes(&r, "q").unwrap_or_default();
                if query.is_empty() {
                    return super::chat::problem(400, "q is required", path, &c, id);
                }
                let Ok(query) = String::from_utf8(query) else {
                    return super::chat::problem(500, "request failed", path, &c, id);
                };
                let mut filters = Vec::new();
                for name in ["in", "from", "before"] {
                    let value = super::chat::query(&r, name)
                        .filter(|s| !s.is_empty())
                        .map(|s| s.parse::<i64>())
                        .transpose();
                    let Ok(value) = value else {
                        return super::chat::problem(400, &format!("invalid {name}"), path, &c, id);
                    };
                    filters.push(value);
                }
                let has = super::chat::query_bytes(&r, "has")
                    .filter(|s| !s.is_empty())
                    .map(String::from_utf8)
                    .transpose();
                let Ok(has) = has else {
                    return super::chat::problem(500, "request failed", path, &c, id);
                };
                let search = setjoin_chat::members::Search {
                    query: &query,
                    channel: filters[0],
                    author: filters[1],
                    before: filters[2],
                    has,
                    han: query.chars().any(han::contains),
                };
                return match setjoin_chat::members::search(&exec, auth.context(), search).await {
                    Ok(value) => read_reply(&value, instance.as_str(), &c, id),
                    Err(ref error) => failure(error, path, &c, id),
                };
            }
            if crate::inventory::path_score("/api/chat/my-threads", r.uri().path()).is_some() {
                let path = instance.as_str();
                let limit = super::chat::query(&r, "limit")
                    .filter(|s| !s.is_empty())
                    .map(|s| s.parse::<i64>())
                    .transpose();
                let Ok(limit) = limit else {
                    return super::chat::problem(400, "invalid limit", path, &c, id);
                };
                return match setjoin_chat::members::my_threads(&exec, auth.context(), limit).await {
                    Ok(value) => read_reply(&value, instance.as_str(), &c, id),
                    Err(ref error) => failure(error, path, &c, id),
                };
            }
            if let Some(message) = message_id(r.uri().path(), "thread") {
                let path = instance.as_str();
                let Ok(message) = message.parse::<i64>() else {
                    return super::chat::problem(400, "invalid message id", path, &c, id);
                };
                return match setjoin_chat::members::thread(&exec, auth.context(), message).await {
                    Ok(value) => read_reply(&value, instance.as_str(), &c, id),
                    Err(ref error) => failure(error, path, &c, id),
                };
            }
            match setjoin_chat::members::saves(&exec, auth.context()).await {
                Ok(value) => read_reply(&value, instance.as_str(), &c, id),
                Err(ref error) => failure(error, &instance, &c, id),
            }
        };
        Box::pin(async move {
            let mut response = work.await;
            if response.headers().contains_key("content-language") {
                response.headers_mut().insert(
                    "content-language",
                    language.parse().expect("validated language tag"),
                );
            }
            response
        })
    }
}

fn message_id(path: &str, suffix: &str) -> Option<String> {
    let p: Vec<_> = path.split('/').collect();
    if p.len() != (if suffix.is_empty() { 5 } else { 6 })
        || crate::inventory::unescape(p[1]) != b"api"
        || crate::inventory::unescape(p[2]) != b"chat"
        || crate::inventory::unescape(p[3]) != b"messages"
        || (!suffix.is_empty() && crate::inventory::unescape(p[5]) != suffix.as_bytes())
    {
        return None;
    }
    Some(String::from_utf8_lossy(&crate::inventory::unescape(p[4])).into_owned())
}

fn failure(
    error: &setjoin_pg::StatementFailure,
    path: &str,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    crate::chat_channels::failure(error, path, c, id, "en")
}
fn rejection(
    error: &setjoin_pg::Rejection<setjoin_pg::StatementFailure>,
    path: &str,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    match error {
        setjoin_pg::Rejection::Statement(e) | setjoin_pg::Rejection::Body(e) => {
            failure(e, path, c, id)
        }
        _ => super::chat::problem(500, "request failed", path, c, id),
    }
}

fn text_field(bytes: &[u8], name: &str) -> Result<String, ()> {
    let fields = crate::chat_channels::decode_fields(bytes)?;
    crate::chat_channels::text_field(&fields, &name.to_ascii_uppercase())
}

fn no_content(c: &RequestContext, id: String) -> Response<Body> {
    let mut response = crate::jmap::reply::response(String::new(), c.identity.proto, id);
    *response.status_mut() = hyper::StatusCode::NO_CONTENT;
    response.headers_mut().remove("content-type");
    response
}
fn uuid(raw: &[u8]) -> Option<String> {
    let s = match raw.len() {
        45 if raw[..9].eq_ignore_ascii_case(b"urn:uuid:") => &raw[9..],
        38 => &raw[1..37],
        32 | 36 => raw,
        _ => return None,
    };
    let mut hex = Vec::new();
    for (i, b) in s.iter().copied().enumerate() {
        if s.len() == 36 && [8, 13, 18, 23].contains(&i) {
            if b != b'-' {
                return None;
            }
        } else if b.is_ascii_hexdigit() {
            hex.push(b.to_ascii_lowercase())
        } else {
            return None;
        }
    }
    if hex.len() != 32 {
        return None;
    }
    let text = String::from_utf8(hex).ok()?;
    Some(format!(
        "{}-{}-{}-{}-{}",
        &text[..8],
        &text[8..12],
        &text[12..16],
        &text[16..20],
        &text[20..]
    ))
}

fn opaque_not_found(c: &RequestContext, id: String) -> Response<Body> {
    let mut response = crate::chat::problem(404, "not found", "", c, id);
    response.headers_mut().remove("content-language");
    response
}

fn read_reply(raw: &str, path: &str, c: &RequestContext, id: String) -> Response<Body> {
    match crate::jmap::reply::go_compact(raw) {
        Some(value) => crate::jmap::reply::response(value + "\n", c.identity.proto, id),
        None => crate::chat::problem(500, "request failed", path, c, id),
    }
}

fn option_id(fields: &crate::chat::Fields) -> Result<i64, ()> {
    // A null leaves Go's scalar int64 unchanged, including after duplicates.
    // Pointer-valued fields use the separate optional-field decoder.
    let mut value = 0;
    for (key, raw) in &fields.0 {
        if key.eq_ignore_ascii_case("optionId") && raw.get() != "null" {
            value = serde_json::from_str(raw.get()).map_err(|_| ())?;
        }
    }
    Ok(value)
}
