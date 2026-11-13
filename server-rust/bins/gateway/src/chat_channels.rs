//! F12 user routes, shared by the executable and recorded HTTP replay (#267).
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use setjoin_authz::token::KeySource;
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

pub struct ChannelRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    pub federation_local_domain: String,
    pub unfurl: Option<Arc<crate::chat_unfurl::Unfurl>>,
    pub federation_typing: Option<Arc<crate::federation_typing::Typing>>,
}
impl<K: KeySource + 'static> Intercept for ChannelRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, r: &Request<Body>) -> bool {
        matches!(*r.method(), Method::GET | Method::HEAD)
            && [
                "/api/chat/channels/browse",
                "/api/chat/conversations",
                "/api/chat/channels/{id}/members",
                "/api/chat/channels/{id}/members/search",
                "/api/chat/channels/{id}/pins",
                "/api/chat/channels/{id}/readers",
                "/api/chat/channels/{id}/messages",
                "/api/chat/channels/{id}/messages/since",
                "/api/chat/channels/{id}/federation",
            ]
            .iter()
            .any(|path| crate::inventory::path_score(path, r.uri().path()).is_some())
            || (r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/channels", r.uri().path()).is_some())
            || (r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/channels/{id}/join", r.uri().path())
                    .is_some())
            || (r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/channels/{id}/typing", r.uri().path())
                    .is_some())
            || (r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/channels/{id}/read", r.uri().path())
                    .is_some())
            || (r.method() == Method::PUT
                && crate::inventory::path_score("/api/chat/channels/{id}/notif", r.uri().path())
                    .is_some())
            || (r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/channels/{id}/members", r.uri().path())
                    .is_some())
            || (r.method() == Method::PATCH
                && crate::inventory::path_score("/api/chat/channels/{id}", r.uri().path())
                    .is_some())
            || (r.method() == Method::DELETE
                && crate::inventory::path_score(
                    "/api/chat/channels/{id}/members/{userId}",
                    r.uri().path(),
                )
                .is_some())
            || (r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/dm", r.uri().path()).is_some())
            || (r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/dm/federated", r.uri().path()).is_some())
            || (r.method() == Method::POST
                && crate::inventory::path_score(
                    "/api/chat/channels/{id}/federation",
                    r.uri().path(),
                )
                .is_some())
            || (r.method() == Method::POST
                && crate::inventory::path_score(
                    "/api/chat/channels/{id}/federation/invite",
                    r.uri().path(),
                )
                .is_some())
            || (r.method() == Method::POST
                && crate::inventory::path_score(
                    "/api/chat/channels/{id}/federation/remove",
                    r.uri().path(),
                )
                .is_some())
            || (r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/channels/{id}/space", r.uri().path())
                    .is_some())
            || (r.method() == Method::POST
                && crate::inventory::path_score(
                    "/api/chat/channels/{id}/members/guest-preview",
                    r.uri().path(),
                )
                .is_some())
            || (r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/channels/{id}/messages", r.uri().path())
                    .is_some())
            || (r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/channels/{id}/polls", r.uri().path())
                    .is_some())
            || (r.method() == Method::POST
                && crate::inventory::path_score(
                    "/api/chat/channels/{id}/messages/schedule",
                    r.uri().path(),
                )
                .is_some())
    }
    fn admits_member(&self, h: hyper::HeaderMap, scheme: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            setjoin_authz::authorize_user_request(&exec, &keys, &issuer, &h, scheme)
                .await
                .is_some()
        })
    }
    fn handle(&self, mut r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        let local_domain = self.federation_local_domain.clone();
        let federation_typing = self.federation_typing.clone();
        let unfurl = self.unfurl.clone();
        Box::pin(async move {
            let language = problem_language(r.headers());
            let id = crate::jmap::reply::request_id(
                r.headers().get("x-request-id"),
                crate::jmap::random().unwrap_or([0; 16]),
            );
            // Go's StripPrefix rejects an encoded spelling of the API mount.
            if r.uri()
                .path()
                .split('/')
                .nth(1)
                .is_some_and(|segment| segment != "api")
            {
                let mut reply = crate::jmap::reply::response(
                    "404 page not found\n".into(),
                    c.identity.proto,
                    id,
                );
                *reply.status_mut() = hyper::StatusCode::NOT_FOUND;
                reply.headers_mut().insert(
                    "content-type",
                    hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
                );
                return reply;
            }
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
            match setjoin_chat::channels::enabled(&exec).await {
                Ok(true) => {}
                Ok(false) => {
                    let mut reply = problem(404, "not found", "", &c, id, &language);
                    reply.headers_mut().remove("content-language");
                    return reply;
                }
                Err(_) => return c.upstream.forward(r, &c.identity).await,
            }
            let conversation =
                crate::inventory::path_score("/api/chat/conversations", r.uri().path()).is_some();
            let decoded =
                String::from_utf8_lossy(&crate::inventory::unescape(r.uri().path())).into_owned();
            let path = decoded.strip_prefix("/api").unwrap_or(&decoded).to_owned();
            if r.method() == Method::POST
                && crate::inventory::path_score(
                    "/api/chat/channels/{id}/messages/schedule",
                    r.uri().path(),
                )
                .is_some()
            {
                let channel = match r.uri().path().split('/').nth(4).and_then(|s| {
                    String::from_utf8_lossy(&crate::inventory::unescape(s))
                        .parse::<i64>()
                        .ok()
                }) {
                    Some(v) => v,
                    None => return problem(400, "invalid channel id", &path, &c, id, &language),
                };
                let bytes = match read_body(&mut r).await {
                    Ok(v) => v,
                    Err(_) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let fields = match decode_fields(&bytes) {
                    Ok(v) => v,
                    Err(()) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let (body, parent, mentions, broadcast, fire) = match (
                    text_field(&fields, "BODY"),
                    optional_field::<i64>(&fields, "PARENTID"),
                    ids_field(&fields, "MENTIONS"),
                    optional_field::<String>(&fields, "BROADCAST"),
                    optional_field::<String>(&fields, "FIREAT"),
                ) {
                    (Ok(b), Ok(p), Ok(m), Ok(t), Ok(f)) => (b, p, m.unwrap_or_default(), t, f),
                    _ => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                if fire
                    .as_ref()
                    .is_some_and(|s| chrono::DateTime::parse_from_rfc3339(s).is_err())
                {
                    return problem(400, "invalid JSON", &path, &c, id, &language);
                }
                let Some(operation) = crate::jmap::random() else {
                    return problem(500, "request failed", &path, &c, id, &language);
                };
                return json_response(
                    setjoin_chat::channels::schedule(
                        &exec,
                        auth.context(),
                        channel,
                        body,
                        parent,
                        mentions,
                        broadcast,
                        fire,
                        operation,
                    )
                    .await,
                    201,
                    &path,
                    &c,
                    id,
                    &language,
                );
            }
            if r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/channels/{id}/polls", r.uri().path())
                    .is_some()
            {
                let channel = match r.uri().path().split('/').nth(4).and_then(|s| {
                    String::from_utf8_lossy(&crate::inventory::unescape(s))
                        .parse::<i64>()
                        .ok()
                }) {
                    Some(v) => v,
                    None => return problem(400, "invalid channel id", &path, &c, id, &language),
                };
                let bytes = match read_body(&mut r).await {
                    Ok(v) => v,
                    Err(_) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let fields = match decode_fields(&bytes) {
                    Ok(v) => v,
                    Err(()) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let (question, options, multi, closes) = match (
                    text_field(&fields, "QUESTION"),
                    strings_field(&fields, "OPTIONS"),
                    bool_field(&fields, "MULTI"),
                    optional_field::<String>(&fields, "CLOSESAT"),
                ) {
                    (Ok(q), Ok(o), Ok(m), Ok(t)) => (q, o, m, t),
                    _ => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let Some(operation) = crate::jmap::random() else {
                    return problem(500, "request failed", &path, &c, id, &language);
                };
                return json_response(
                    setjoin_chat::channels::poll(
                        &exec,
                        auth.context(),
                        channel,
                        question,
                        options,
                        multi,
                        closes,
                        operation,
                    )
                    .await,
                    201,
                    &path,
                    &c,
                    id,
                    &language,
                );
            }
            if r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/channels/{id}/messages", r.uri().path())
                    .is_some()
            {
                let channel = match r.uri().path().split('/').nth(4).and_then(|s| {
                    String::from_utf8_lossy(&crate::inventory::unescape(s))
                        .parse::<i64>()
                        .ok()
                }) {
                    Some(v) => v,
                    None => return problem(400, "invalid channel id", &path, &c, id, &language),
                };
                let bytes = match read_body(&mut r).await {
                    Ok(v) => v,
                    Err(ReadError::TooLarge) => return too_large(&path, &c, id, &language),
                    Err(_) => return invalid_json(&path, &c, id, &language),
                };
                let fields = match decode_fields(&bytes) {
                    Ok(v) => v,
                    Err(()) => return invalid_json(&path, &c, id, &language),
                };
                let body = match text_field(&fields, "BODY") {
                    Ok(v) => v,
                    Err(()) => return invalid_json(&path, &c, id, &language),
                };
                let (parent, mentions, broadcast, msg_type) = match (
                    optional_field::<i64>(&fields, "PARENTID"),
                    ids_field(&fields, "MENTIONS"),
                    optional_field::<String>(&fields, "BROADCAST"),
                    optional_field::<String>(&fields, "MSGTYPE"),
                ) {
                    (Ok(p), Ok(m), Ok(b), Ok(t)) => (p, m.unwrap_or_default(), b, t),
                    _ => return invalid_json(&path, &c, id, &language),
                };
                let attachments = raw_field(&bytes, "ATTACHMENTS")
                    .filter(|v| *v != b"null")
                    .unwrap_or(b"[]");
                let array = match serde_json::from_str::<Vec<Box<serde_json::value::RawValue>>>(
                    &crate::chat::go_json_text(attachments),
                ) {
                    Ok(v) => v,
                    Err(_) => return problem(400, "invalid attachments", &path, &c, id, &language),
                };
                if !array.is_empty() {
                    match setjoin_chat::channels::drive_enabled(&exec).await {
                        Ok(true) => {}
                        Ok(false) => {
                            let mut reply = problem(404, "not found", "", &c, id, &language);
                            reply.headers_mut().remove("content-language");
                            return reply;
                        }
                        Err(_) => return problem(500, "request failed", &path, &c, id, &language),
                    }
                }
                let msg_type = msg_type
                    .filter(|v| !v.is_empty())
                    .unwrap_or_else(|| "text".into());
                if !matches!(msg_type.as_str(), "text" | "voice" | "question") {
                    return problem(400, "invalid msgType", &path, &c, id, &language);
                }
                let attachments = match std::str::from_utf8(attachments) {
                    Ok(v) => v.to_owned(),
                    Err(_) => return problem(500, "request failed", &path, &c, id, &language),
                };
                let payload = match raw_field(&bytes, "PAYLOAD")
                    .filter(|v| *v != b"null")
                    .map(std::str::from_utf8)
                    .transpose()
                {
                    Ok(v) => v.map(str::to_owned),
                    Err(_) => return problem(500, "request failed", &path, &c, id, &language),
                };
                let Some(operation) = crate::jmap::random() else {
                    return problem(500, "request failed", &path, &c, id, &language);
                };
                let unfurl_body = unfurl.as_ref().map(|_| body.clone());
                let outcome = setjoin_chat::channels::send(
                    &exec,
                    auth.context(),
                    channel,
                    body,
                    parent,
                    mentions,
                    broadcast,
                    attachments,
                    msg_type,
                    payload,
                    operation,
                )
                .await;
                if let (Some(unfurl), Some(body), setjoin_pg::CommandOutcome::Committed(sent)) =
                    (&unfurl, &unfurl_body, &outcome)
                {
                    unfurl.trigger(auth.context(), sent, body);
                }
                return json_response(outcome, 201, &path, &c, id, &language);
            }
            if r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/channels/{id}/join", r.uri().path())
                    .is_some()
            {
                let channel = match r.uri().path().split('/').nth(4).and_then(|s| {
                    String::from_utf8_lossy(&crate::inventory::unescape(s))
                        .parse::<i64>()
                        .ok()
                }) {
                    Some(v) => v,
                    None => return problem(400, "invalid channel id", &path, &c, id, &language),
                };
                let Some(operation) = crate::jmap::random() else {
                    return problem(500, "request failed", &path, &c, id, &language);
                };
                return void_response(
                    setjoin_chat::channels::join(&exec, auth.context(), channel, operation).await,
                    &path,
                    &c,
                    id,
                    &language,
                );
            }
            if r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/channels/{id}/typing", r.uri().path())
                    .is_some()
            {
                let channel = match r.uri().path().split('/').nth(4).and_then(|s| {
                    String::from_utf8_lossy(&crate::inventory::unescape(s))
                        .parse::<i64>()
                        .ok()
                }) {
                    Some(v) => v,
                    None => return problem(400, "invalid channel id", &path, &c, id, &language),
                };
                let debounced = federation_typing.as_ref().is_some_and(|typing|typing.debounced(channel));
                let Some(operation) = crate::jmap::random() else {
                    return problem(500, "request failed", &path, &c, id, &language);
                };
                let outcome = setjoin_chat::channels::typing(&exec, auth.context(), channel, operation).await;
                if matches!(&outcome,setjoin_pg::CommandOutcome::Committed(())) && !debounced {
                    if let Some(typing)=federation_typing {
                        typing.send(exec.clone(),auth.context().clone(),channel);
                    }
                }
                return void_response(outcome, &path, &c, id, &language);
            }
            if r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/channels/{id}/read", r.uri().path())
                    .is_some()
            {
                let channel = match r.uri().path().split('/').nth(4).and_then(|s| {
                    String::from_utf8_lossy(&crate::inventory::unescape(s))
                        .parse::<i64>()
                        .ok()
                }) {
                    Some(v) => v,
                    None => return problem(400, "invalid id", &path, &c, id, &language),
                };
                let bytes = match read_body(&mut r).await {
                    Ok(v) => v,
                    Err(_) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let fields = match decode_fields(&bytes) {
                    Ok(v) => v,
                    Err(()) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let value = match number_field(&fields, "SEQ") {
                    Ok(v) => v,
                    Err(()) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let Some(operation) = crate::jmap::random() else {
                    return problem(500, "request failed", &path, &c, id, &language);
                };
                return void_response(
                    setjoin_chat::channels::mark_read(
                        &exec,
                        auth.context(),
                        channel,
                        value,
                        operation,
                    )
                    .await,
                    &path,
                    &c,
                    id,
                    &language,
                );
            }
            if r.method() == Method::PUT
                && crate::inventory::path_score("/api/chat/channels/{id}/notif", r.uri().path())
                    .is_some()
            {
                let channel = match r.uri().path().split('/').nth(4).and_then(|s| {
                    String::from_utf8_lossy(&crate::inventory::unescape(s))
                        .parse::<i64>()
                        .ok()
                }) {
                    Some(v) => v,
                    None => return problem(400, "invalid id", &path, &c, id, &language),
                };
                let bytes = match read_body(&mut r).await {
                    Ok(v) => v,
                    Err(_) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let fields = match decode_fields(&bytes) {
                    Ok(v) => v,
                    Err(()) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let value = match text_field(&fields, "LEVEL") {
                    Ok(v) => v,
                    Err(()) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let Some(operation) = crate::jmap::random() else {
                    return problem(500, "request failed", &path, &c, id, &language);
                };
                return void_response(
                    setjoin_chat::channels::notif(&exec, auth.context(), channel, value, operation)
                        .await,
                    &path,
                    &c,
                    id,
                    &language,
                );
            }
            if r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/channels/{id}/members", r.uri().path())
                    .is_some()
            {
                let channel = match r.uri().path().split('/').nth(4).and_then(|s| {
                    String::from_utf8_lossy(&crate::inventory::unescape(s))
                        .parse::<i64>()
                        .ok()
                }) {
                    Some(v) => v,
                    None => return problem(400, "invalid id", &path, &c, id, &language),
                };
                let bytes = match read_body(&mut r).await {
                    Ok(v) => v,
                    Err(_) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let fields = match decode_fields(&bytes) {
                    Ok(v) => v,
                    Err(()) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let value = match number_field(&fields, "USERID") {
                    Ok(v) => v,
                    Err(()) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let Some(operation) = crate::jmap::random() else {
                    return problem(500, "request failed", &path, &c, id, &language);
                };
                return void_response(
                    setjoin_chat::channels::add_member(
                        &exec,
                        auth.context(),
                        channel,
                        value,
                        operation,
                    )
                    .await,
                    &path,
                    &c,
                    id,
                    &language,
                );
            }
            if r.method() == Method::PATCH
                && crate::inventory::path_score("/api/chat/channels/{id}", r.uri().path()).is_some()
            {
                let channel = match r.uri().path().split('/').nth(4).and_then(|s| {
                    String::from_utf8_lossy(&crate::inventory::unescape(s))
                        .parse::<i64>()
                        .ok()
                }) {
                    Some(v) => v,
                    None => return problem(400, "invalid id", &path, &c, id, &language),
                };
                let bytes = match read_body(&mut r).await {
                    Ok(v) => v,
                    Err(_) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let fields = match decode_fields(&bytes) {
                    Ok(v) => v,
                    Err(()) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let patch = match (
                    optional_field(&fields, "NAME"),
                    optional_field(&fields, "TOPIC"),
                    optional_field(&fields, "ARCHIVED"),
                    optional_field(&fields, "POSTPERMISSION"),
                    optional_field(&fields, "BROADCASTPERMISSION"),
                ) {
                    (
                        Ok(name),
                        Ok(topic),
                        Ok(archived),
                        Ok(post_permission),
                        Ok(broadcast_permission),
                    ) => setjoin_chat::channels::ChannelPatch {
                        name,
                        topic,
                        archived,
                        post_permission,
                        broadcast_permission,
                    },
                    _ => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let Some(operation) = crate::jmap::random() else {
                    return problem(500, "request failed", &path, &c, id, &language);
                };
                return void_response(
                    setjoin_chat::channels::update(
                        &exec,
                        auth.context(),
                        channel,
                        patch,
                        operation,
                    )
                    .await,
                    &path,
                    &c,
                    id,
                    &language,
                );
            }
            if r.method() == Method::DELETE
                && crate::inventory::path_score(
                    "/api/chat/channels/{id}/members/{userId}",
                    r.uri().path(),
                )
                .is_some()
            {
                let channel = match r.uri().path().split('/').nth(4).and_then(|s| {
                    String::from_utf8_lossy(&crate::inventory::unescape(s))
                        .parse::<i64>()
                        .ok()
                }) {
                    Some(v) => v,
                    None => return problem(400, "invalid channel id", &path, &c, id, &language),
                };
                let target = match r.uri().path().split('/').nth(6).and_then(|s| {
                    String::from_utf8_lossy(&crate::inventory::unescape(s))
                        .parse::<i64>()
                        .ok()
                }) {
                    Some(v) => v,
                    None => return problem(400, "invalid user id", &path, &c, id, &language),
                };
                let Some(operation) = crate::jmap::random() else {
                    return problem(500, "request failed", &path, &c, id, &language);
                };
                return void_response(
                    setjoin_chat::channels::remove_member(
                        &exec,
                        auth.context(),
                        channel,
                        target,
                        operation,
                    )
                    .await,
                    &path,
                    &c,
                    id,
                    &language,
                );
            }
            if matches!(*r.method(), Method::GET | Method::HEAD)
                && crate::inventory::path_score(
                    "/api/chat/channels/{id}/federation",
                    r.uri().path(),
                )
                .is_some()
            {
                match setjoin_chat::channels::federation_enabled(&exec).await {
                    Ok(true) => {}
                    Ok(false) => {
                        let mut reply = problem(404, "not found", "", &c, id, &language);
                        reply.headers_mut().remove("content-language");
                        return reply;
                    }
                    Err(_) => return c.upstream.forward(r, &c.identity).await,
                }
                let channel = match r.uri().path().split('/').nth(4).and_then(|s| {
                    String::from_utf8_lossy(&crate::inventory::unescape(s))
                        .parse::<i64>()
                        .ok()
                }) {
                    Some(v) => v,
                    None => return problem(400, "invalid channel id", &path, &c, id, &language),
                };
                return match setjoin_chat::channels::federation_roster(
                    &exec,
                    auth.context(),
                    channel,
                )
                .await
                {
                    Ok(raw) => match crate::jmap::reply::go_compact(&raw) {
                        Some(body) => {
                            crate::jmap::reply::response(body + "\n", c.identity.proto, id)
                        }
                        None => problem(500, "request failed", &path, &c, id, &language),
                    },
                    Err(error) => failure(&error, &path, &c, id, &language),
                };
            }
            if r.method() == Method::POST
                && crate::inventory::path_score(
                    "/api/chat/channels/{id}/federation/remove",
                    r.uri().path(),
                )
                .is_some()
            {
                match setjoin_chat::channels::federation_enabled(&exec).await {
                    Ok(true) => {}
                    Ok(false) => {
                        let mut reply = problem(404, "not found", "", &c, id, &language);
                        reply.headers_mut().remove("content-language");
                        return reply;
                    }
                    Err(_) => return c.upstream.forward(r, &c.identity).await,
                }
                let channel = match r.uri().path().split('/').nth(4).and_then(|s| {
                    String::from_utf8_lossy(&crate::inventory::unescape(s))
                        .parse::<i64>()
                        .ok()
                }) {
                    Some(v) => v,
                    None => return problem(400, "invalid id", &path, &c, id, &language),
                };
                let bytes = match read_body(&mut r).await {
                    Ok(v) => v,
                    Err(_) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let fields = match decode_fields(&bytes) {
                    Ok(v) => v,
                    Err(()) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let domain = match text_field(&fields, "MEMBERDOMAIN") {
                    Ok(v) => v,
                    Err(()) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let Some(operation) = crate::jmap::random() else {
                    return problem(500, "request failed", &path, &c, id, &language);
                };
                return void_response(
                    setjoin_chat::channels::federation_remove(
                        &exec,
                        auth.context(),
                        channel,
                        domain,
                        operation,
                    )
                    .await,
                    &path,
                    &c,
                    id,
                    &language,
                );
            }
            if r.method() == Method::POST
                && crate::inventory::path_score(
                    "/api/chat/channels/{id}/federation/invite",
                    r.uri().path(),
                )
                .is_some()
            {
                match setjoin_chat::channels::federation_enabled(&exec).await {
                    Ok(true) => {}
                    Ok(false) => {
                        let mut reply = problem(404, "not found", "", &c, id, &language);
                        reply.headers_mut().remove("content-language");
                        return reply;
                    }
                    Err(_) => return c.upstream.forward(r, &c.identity).await,
                }
                let channel = match r.uri().path().split('/').nth(4).and_then(|s| {
                    String::from_utf8_lossy(&crate::inventory::unescape(s))
                        .parse::<i64>()
                        .ok()
                }) {
                    Some(v) => v,
                    None => return problem(400, "invalid id", &path, &c, id, &language),
                };
                let bytes = match read_body(&mut r).await {
                    Ok(v) => v,
                    Err(_) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let fields = match decode_fields(&bytes) {
                    Ok(v) => v,
                    Err(()) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let (domain, contact) = match (
                    text_field(&fields, "MEMBERDOMAIN"),
                    text_field(&fields, "CONTACTADDR"),
                ) {
                    (Ok(d), Ok(c)) => (d, c),
                    _ => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let Some(operation) = crate::jmap::random() else {
                    return problem(500, "request failed", &path, &c, id, &language);
                };
                return void_response(
                    setjoin_chat::channels::federation_invite(
                        &exec,
                        auth.context(),
                        channel,
                        domain,
                        contact,
                        operation,
                    )
                    .await,
                    &path,
                    &c,
                    id,
                    &language,
                );
            }
            if r.method() == Method::POST
                && crate::inventory::path_score(
                    "/api/chat/channels/{id}/federation",
                    r.uri().path(),
                )
                .is_some()
            {
                match setjoin_chat::channels::federation_enabled(&exec).await {
                    Ok(true) if !local_domain.is_empty() => {}
                    Ok(_) => {
                        let mut reply = problem(404, "not found", "", &c, id, &language);
                        reply.headers_mut().remove("content-language");
                        return reply;
                    }
                    Err(_) => return c.upstream.forward(r, &c.identity).await,
                }
                let channel = match r.uri().path().split('/').nth(4).and_then(|s| {
                    String::from_utf8_lossy(&crate::inventory::unescape(s))
                        .parse::<i64>()
                        .ok()
                }) {
                    Some(v) => v,
                    None => return problem(400, "invalid channel id", &path, &c, id, &language),
                };
                let Some(operation) = crate::jmap::random() else {
                    return problem(500, "request failed", &path, &c, id, &language);
                };
                return json_response(
                    setjoin_chat::channels::federation_bind(
                        &exec,
                        auth.context(),
                        channel,
                        local_domain,
                        operation,
                    )
                    .await,
                    200,
                    &path,
                    &c,
                    id,
                    &language,
                );
            }
            if r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/dm/federated", r.uri().path()).is_some()
            {
                match setjoin_chat::channels::federation_enabled(&exec).await {
                    Ok(true) => {}
                    Ok(false) => {
                        let mut reply = problem(404, "not found", "", &c, id, &language);
                        reply.headers_mut().remove("content-language");
                        return reply;
                    }
                    Err(_) => return c.upstream.forward(r, &c.identity).await,
                }
                let bytes = match read_body(&mut r).await {
                    Ok(v) => v,
                    Err(_) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let fields = match decode_fields(&bytes) {
                    Ok(v) => v,
                    Err(()) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let remote = match text_field(&fields, "REMOTEADDR") {
                    Ok(v) => v,
                    Err(()) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                if remote.trim().is_empty() {
                    return problem(400, "remoteAddr is required", &path, &c, id, &language);
                }
                let Some(operation) = crate::jmap::random() else {
                    return problem(500, "request failed", &path, &c, id, &language);
                };
                return scalar_response(
                    setjoin_chat::channels::federated_dm(&exec, auth.context(), remote, operation)
                        .await,
                    "channelId",
                    200,
                    &path,
                    &c,
                    id,
                    &language,
                );
            }
            if r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/dm", r.uri().path()).is_some()
            {
                let bytes = match read_body(&mut r).await {
                    Ok(v) => v,
                    Err(_) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let fields = match decode_fields(&bytes) {
                    Ok(v) => v,
                    Err(()) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let others = match ids_field(&fields, "USERIDS") {
                    Ok(v) => v,
                    Err(()) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let Some(operation) = crate::jmap::random() else {
                    return problem(500, "request failed", &path, &c, id, &language);
                };
                return scalar_response(
                    setjoin_chat::channels::dm(&exec, auth.context(), others, operation).await,
                    "channelId",
                    200,
                    &path,
                    &c,
                    id,
                    &language,
                );
            }
            if r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/channels/{id}/space", r.uri().path())
                    .is_some()
            {
                match setjoin_chat::channels::drive_enabled(&exec).await {
                    Ok(true) => {}
                    Ok(false) => {
                        let mut response = problem(404, "not found", "", &c, id, &language);
                        response.headers_mut().remove("content-language");
                        return response;
                    }
                    Err(_) => return c.upstream.forward(r, &c.identity).await,
                }
                let channel = match r.uri().path().split('/').nth(4).and_then(|s| {
                    String::from_utf8_lossy(&crate::inventory::unescape(s))
                        .parse::<i64>()
                        .ok()
                }) {
                    Some(v) => v,
                    None => return problem(400, "invalid channel id", &path, &c, id, &language),
                };
                let Some(operation) = crate::jmap::random() else {
                    return problem(500, "request failed", &path, &c, id, &language);
                };
                return scalar_response(
                    setjoin_chat::channels::space(&exec, auth.context(), channel, operation).await,
                    "spaceId",
                    200,
                    &path,
                    &c,
                    id,
                    &language,
                );
            }
            if r.method() == Method::POST
                && crate::inventory::path_score(
                    "/api/chat/channels/{id}/members/guest-preview",
                    r.uri().path(),
                )
                .is_some()
            {
                let channel = match r.uri().path().split('/').nth(4).and_then(|s| {
                    String::from_utf8_lossy(&crate::inventory::unescape(s))
                        .parse::<i64>()
                        .ok()
                }) {
                    Some(v) => v,
                    None => return problem(400, "invalid channel id", &path, &c, id, &language),
                };
                let bytes = match read_body(&mut r).await {
                    Ok(v) => v,
                    Err(_) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let fields = match decode_fields(&bytes) {
                    Ok(v) => v,
                    Err(()) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                if fields.0.iter().any(|(k, _)| fold(k) != "EMAIL") {
                    return problem(400, "invalid JSON", &path, &c, id, &language);
                }
                let email = match text_field(&fields, "EMAIL") {
                    Ok(v) => v,
                    Err(()) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                if email.trim().is_empty() {
                    let mut response = problem(400, "email is required", &path, &c, id, &language);
                    let raw = crate::problem::Problem::new(400, "email is required")
                        .kind("https://setjoin.com/problems/chat/invalid-arguments")
                        .instance(&path)
                        .body();
                    crate::problem::set_body(&mut response, raw);
                    return response;
                }
                return match setjoin_chat::channels::preview(&exec, auth.context(), channel, &email)
                    .await
                {
                    Ok(raw) => crate::jmap::reply::response(
                        crate::jmap::reply::go_compact(&raw).expect("reducer JSON") + "\n",
                        c.identity.proto,
                        id,
                    ),
                    Err(error) => failure(&error, &path, &c, id, &language),
                };
            }
            if r.method() == Method::POST
                && crate::inventory::path_score("/api/chat/channels", r.uri().path()).is_some()
            {
                let bytes = match read_body(&mut r).await {
                    Ok(v) => v,
                    Err(_) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let fields = match decode_fields(&bytes) {
                    Ok(v) => v,
                    Err(()) => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let (name, topic, visibility) = match (
                    text_field(&fields, "NAME"),
                    text_field(&fields, "TOPIC"),
                    text_field(&fields, "VISIBILITY"),
                ) {
                    (Ok(a), Ok(b), Ok(d)) => (a, b, d),
                    _ => return problem(400, "invalid JSON", &path, &c, id, &language),
                };
                let Some(operation) = crate::jmap::random() else {
                    return problem(500, "request failed", &path, &c, id, &language);
                };
                let result = setjoin_chat::channels::create(
                    &exec,
                    auth.context(),
                    &name,
                    if topic.is_empty() { None } else { Some(topic) },
                    if visibility.is_empty() {
                        "public"
                    } else {
                        &visibility
                    },
                    operation,
                )
                .await;
                return match result {
                    setjoin_pg::CommandOutcome::Committed(channel) => {
                        let mut response = crate::jmap::reply::response(
                            format!("{{\"channelId\":{channel}}}\n"),
                            c.identity.proto,
                            id,
                        );
                        *response.status_mut() = hyper::StatusCode::CREATED;
                        response
                    }
                    setjoin_pg::CommandOutcome::Unknown { operation, .. } => {
                        unknown(operation, &path, &c, id, &language)
                    }
                    setjoin_pg::CommandOutcome::RolledBack(error) => {
                        rejected(&error, &path, &c, id, &language)
                    }
                };
            }
            let roster =
                crate::inventory::path_score("/api/chat/channels/{id}/members", r.uri().path())
                    .is_some();
            let search = crate::inventory::path_score(
                "/api/chat/channels/{id}/members/search",
                r.uri().path(),
            )
            .is_some();
            let pins = crate::inventory::path_score("/api/chat/channels/{id}/pins", r.uri().path())
                .is_some();
            let readers =
                crate::inventory::path_score("/api/chat/channels/{id}/readers", r.uri().path())
                    .is_some();
            let messages =
                crate::inventory::path_score("/api/chat/channels/{id}/messages", r.uri().path())
                    .is_some();
            let since = crate::inventory::path_score(
                "/api/chat/channels/{id}/messages/since",
                r.uri().path(),
            )
            .is_some();
            let channel = if roster || search || pins || readers || messages || since {
                match r.uri().path().split('/').nth(4).and_then(|s| {
                    String::from_utf8_lossy(&crate::inventory::unescape(s))
                        .parse::<i64>()
                        .ok()
                }) {
                    Some(v) => v,
                    None => return problem(400, "invalid channel id", &path, &c, id, &language),
                }
            } else {
                0
            };
            let drive = if conversation {
                match setjoin_chat::channels::drive_enabled(&exec).await {
                    Ok(v) => v,
                    Err(_) => return c.upstream.forward(r, &c.identity).await,
                }
            } else {
                false
            };
            let query = crate::chat::query(&r, "q").unwrap_or_default();
            let (mut before, mut limit, mut around) = (None, None, None);
            if messages {
                for (key, target) in [
                    ("beforeSeq", &mut before),
                    ("limit", &mut limit),
                    ("aroundSeq", &mut around),
                ] {
                    *target = match optional_int(&r, key) {
                        Ok(v) => v,
                        Err(()) => {
                            return problem(
                                400,
                                &format!("invalid {key}"),
                                &path,
                                &c,
                                id,
                                &language,
                            )
                        }
                    };
                }
            }
            let seq = if since {
                match optional_int(&r, "seq") {
                    Ok(v) => v,
                    Err(()) => return problem(400, "invalid seq", &path, &c, id, &language),
                }
            } else {
                None
            };
            let mut cursor = None;
            let result = if since {
                setjoin_chat::channels::since(&exec, auth.context(), channel, seq)
                    .await
                    .map(|(body, seq)| {
                        cursor = Some(seq);
                        body
                    })
            } else if messages {
                setjoin_chat::channels::messages(
                    &exec,
                    auth.context(),
                    channel,
                    before,
                    limit,
                    around,
                )
                .await
            } else if readers {
                setjoin_chat::channels::readers(&exec, auth.context(), channel).await
            } else if pins {
                setjoin_chat::channels::pins(&exec, auth.context(), channel).await
            } else if search {
                setjoin_chat::channels::mention_search(&exec, auth.context(), channel, &query).await
            } else if roster {
                setjoin_chat::channels::roster(&exec, auth.context(), channel).await
            } else if conversation {
                setjoin_chat::channels::conversations(&exec, auth.context()).await
            } else {
                setjoin_chat::channels::browse(&exec, auth.context()).await
            };
            match result {
                Ok(raw) => {
                    let raw = if conversation {
                        format!("{{\"attachmentsEnabled\":{},\"conversations\":{raw}}}",drive && !auth.context().is_guest())
                    } else {
                        raw
                    };
                    match crate::jmap::reply::go_compact(&raw) {
                        Some(body) => {
                            let mut response =
                                crate::jmap::reply::response(body + "\n", c.identity.proto, id);
                            if let Some(cursor) = cursor {
                                response.headers_mut().insert(
                                    "x-setjoin-chat-cursor",
                                    cursor.to_string().parse().expect("integer cursor"),
                                );
                            }
                            response
                        }
                        None => problem(500, "request failed", &path, &c, id, &language),
                    }
                }
                Err(error) => failure(&error, &path, &c, id, &language),
            }
        })
    }
}

pub(crate) fn failure(
    error: &setjoin_pg::StatementFailure,
    path: &str,
    c: &RequestContext,
    id: String,
    language: &str,
) -> Response<Body> {
    let Some(code) = error.sqlstate.as_deref() else {
        return problem(500, "request failed", path, c, id, language);
    };
    // Frozen Go's Chat slug table and shared class fallback. Nested Drive
    // errors retain the generic surface; only Chat codes expose Chat slugs.
    let (status, slug, detail) = match code {
        "BZ160" | "BZ172" => (400, Some("invalid-arguments"), "invalidArguments"),
        "BZ161" | "BZ163" | "BZ164" | "BZ166" | "BZ167" | "BZ171" | "BZ173" | "BZ175" | "BZ176"
        | "BZ194" | "BZ204" | "BZ211" | "BZ213" | "BZ215" | "BZ216" | "BZ219" | "BZ220" => {
            (403, Some("forbidden"), "forbidden")
        }
        "BZ140" => (403, None, "forbidden"),
        "BZ169" | "BZ170" => (404, Some("not-found"), "notFound"),
        "BZ139" => (404, None, "notFound"),
        "BZ205" => (409, Some("conflict"), "conflict"),
        "BZ193" => (409, Some("immutable"), "conflict"),
        "BZ192" | "BZ198" => (409, Some("state-mismatch"), "conflict"),
        "BZ142" | "BZ143" | "BZ145" | "BZ146" | "BZ147" | "BZ149" | "BZ150" => {
            (409, None, "conflict")
        }
        "BZ162" | "BZ165" | "BZ168" | "BZ177" | "BZ178" | "BZ179" | "BZ191" | "BZ195" | "BZ197"
        | "BZ206" | "BZ209" | "BZ210" | "BZ212" => {
            (422, Some("invalid-arguments"), "unprocessable")
        }
        "BZ141" | "BZ144" => (422, None, "unprocessable"),
        "BZ196" => (507, Some("sending-quota-exceeded"), "overQuota"),
        "BZ148" => (507, None, "overQuota"),
        _ => return problem(500, "request failed", path, c, id, language),
    };
    let mut response = problem(status, detail, path, c, id, language);
    if let Some(slug) = slug {
        let body = crate::chat::go_problem_json(
            &format!("https://setjoin.com/problems/chat/{slug}"),
            crate::problem::title(status),
            status,
            detail,
            path,
            Some(code),
        );
        use http_body_util::BodyExt;
        *response.body_mut() = http_body_util::Full::new(bytes::Bytes::from(body))
            .map_err(|never| match never {})
            .boxed();
    }
    response
}

fn optional_int(r: &Request<Body>, key: &str) -> Result<Option<i64>, ()> {
    crate::chat::query(r, key)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<i64>().map_err(|_| ()))
        .transpose()
}

pub(crate) fn problem(
    status: u16,
    detail: &str,
    path: &str,
    c: &RequestContext,
    id: String,
    language: &str,
) -> Response<Body> {
    let mut response = crate::chat::problem(status, detail, path, c, id);
    response.headers_mut().insert(
        "content-language",
        language.parse().expect("validated language tag"),
    );
    response
}
pub(crate) fn problem_language(headers: &hyper::HeaderMap) -> String {
    let valid = || -> Option<&str> {
        let raw = std::str::from_utf8(headers.get("accept-language")?.as_bytes()).ok()?;
        let tag = raw.split([',', ';']).next()?.trim();
        let mut parts = tag.split('-');
        let first = parts.next()?;
        if first.is_empty() || first.len() > 8 || !first.bytes().all(|b| b.is_ascii_alphabetic()) {
            return None;
        }
        if !parts.all(|part| {
            !part.is_empty() && part.len() <= 8 && part.bytes().all(|b| b.is_ascii_alphanumeric())
        }) {
            return None;
        }
        Some(tag)
    };
    valid().unwrap_or("en").into()
}

pub(crate) enum ReadError {
    Transport,
    TooLarge,
}
pub(crate) async fn read_body(r: &mut Request<Body>) -> Result<Vec<u8>, ReadError> {
    use http_body_util::BodyExt;
    let mut out = Vec::new();
    while let Some(frame) = r.body_mut().frame().await {
        let frame = frame.map_err(|_| ReadError::Transport)?;
        if let Some(bytes) = frame.data_ref() {
            if out.len() + bytes.len() > 1 << 20 {
                return Err(ReadError::TooLarge);
            }
            out.extend_from_slice(bytes);
        }
    }
    Ok(out)
}
pub(crate) fn decode_fields(bytes: &[u8]) -> Result<crate::chat::Fields, ()> {
    use serde::Deserialize;
    let text = crate::chat::go_json_text(bytes);
    let mut d = serde_json::Deserializer::from_str(&text);
    let fields = crate::chat::Fields::deserialize(&mut d).map_err(|_| ())?;
    d.end().map_err(|_| ())?;
    Ok(fields)
}
pub(crate) fn fold(key: &str) -> String {
    key.chars()
        .map(|c| match c {
            '\u{017f}' => 'S',
            '\u{212a}' => 'K',
            c => c.to_ascii_uppercase(),
        })
        .collect()
}
pub(crate) fn text_field(fields: &crate::chat::Fields, key: &str) -> Result<String, ()> {
    let mut value = String::new();
    for (k, v) in &fields.0 {
        if fold(k) == key && v.get() != "null" {
            value = serde_json::from_str(v.get()).map_err(|_| ())?;
        }
    }
    Ok(value)
}
fn rejected(
    error: &setjoin_pg::Rejection<setjoin_pg::StatementFailure>,
    path: &str,
    c: &RequestContext,
    id: String,
    language: &str,
) -> Response<Body> {
    match error {
        setjoin_pg::Rejection::Body(e) | setjoin_pg::Rejection::Statement(e) => {
            failure(e, path, c, id, language)
        }
        _ => problem(500, "request failed", path, c, id, language),
    }
}
fn unknown(
    operation: setjoin_contracts::ids::OperationId,
    path: &str,
    c: &RequestContext,
    id: String,
    language: &str,
) -> Response<Body> {
    let mut response = problem(503, "chat command outcome unknown", path, c, id, language);
    response.headers_mut().insert(
        "x-operation-id",
        setjoin_pg::operation_hex(operation)
            .parse()
            .expect("opaque operation ID"),
    );
    response
}

fn void_response(
    result: setjoin_pg::CommandOutcome<(), setjoin_pg::StatementFailure>,
    path: &str,
    c: &RequestContext,
    id: String,
    language: &str,
) -> Response<Body> {
    match result {
        setjoin_pg::CommandOutcome::Committed(()) => {
            let mut response = crate::jmap::reply::response(String::new(), c.identity.proto, id);
            *response.status_mut() = hyper::StatusCode::NO_CONTENT;
            response.headers_mut().remove("content-type");
            response
        }
        setjoin_pg::CommandOutcome::Unknown { operation, .. } => {
            unknown(operation, path, c, id, language)
        }
        setjoin_pg::CommandOutcome::RolledBack(error) => rejected(&error, path, c, id, language),
    }
}

pub(crate) fn number_field(fields: &crate::chat::Fields, key: &str) -> Result<i64, ()> {
    let mut value = 0;
    for (k, v) in &fields.0 {
        if fold(k) == key && v.get() != "null" {
            value = serde_json::from_str(v.get()).map_err(|_| ())?;
        }
    }
    Ok(value)
}

pub(crate) fn optional_field<T: serde::de::DeserializeOwned>(
    fields: &crate::chat::Fields,
    key: &str,
) -> Result<Option<T>, ()> {
    let mut value = None;
    for (k, v) in &fields.0 {
        if fold(k) == key {
            value = serde_json::from_str(v.get()).map_err(|_| ())?;
        }
    }
    Ok(value)
}

fn ids_field(fields: &crate::chat::Fields, key: &str) -> Result<Option<Vec<i64>>, ()> {
    let mut value = None;
    for (k, v) in &fields.0 {
        if fold(k) == key {
            value = serde_json::from_str::<Option<Vec<Option<i64>>>>(v.get())
                .map_err(|_| ())?
                .map(|v| v.into_iter().map(|n| n.unwrap_or_default()).collect());
        }
    }
    Ok(value)
}
fn scalar_response(
    result: setjoin_pg::CommandOutcome<i64, setjoin_pg::StatementFailure>,
    key: &str,
    status: u16,
    path: &str,
    c: &RequestContext,
    id: String,
    language: &str,
) -> Response<Body> {
    match result {
        setjoin_pg::CommandOutcome::Committed(value) => {
            let mut response = crate::jmap::reply::response(
                format!("{{\"{key}\":{value}}}\n"),
                c.identity.proto,
                id,
            );
            *response.status_mut() = hyper::StatusCode::from_u16(status).expect("static status");
            response
        }
        setjoin_pg::CommandOutcome::Unknown { operation, .. } => {
            unknown(operation, path, c, id, language)
        }
        setjoin_pg::CommandOutcome::RolledBack(error) => rejected(&error, path, c, id, language),
    }
}

// The struct decoder applies Go's replacement rules to typed strings. RawMessage
// fields instead retain their original bytes (including escapes) for PostgreSQL.
// Syntax was already checked by decode_fields; this only locates top-level values.
fn raw_field<'a>(input: &'a [u8], key: &str) -> Option<&'a [u8]> {
    fn whitespace(input: &[u8], p: &mut usize) {
        while input.get(*p).is_some_and(u8::is_ascii_whitespace) {
            *p += 1;
        }
    }
    fn string_end(input: &[u8], start: usize) -> Option<usize> {
        let mut escaped = false;
        for (i, b) in input.iter().enumerate().skip(start + 1) {
            if escaped {
                escaped = false;
            } else if *b == b'\\' {
                escaped = true;
            } else if *b == b'"' {
                return Some(i + 1);
            }
        }
        None
    }
    let mut p = 0;
    whitespace(input, &mut p);
    if input.get(p) != Some(&b'{') {
        return None;
    }
    p += 1;
    let mut found = None;
    loop {
        whitespace(input, &mut p);
        if input.get(p) == Some(&b'}') {
            break;
        }
        if input.get(p) != Some(&b'"') {
            return None;
        }
        let start = p;
        p = string_end(input, start)?;
        let name: String =
            serde_json::from_str(&crate::chat::go_json_text(&input[start..p])).ok()?;
        whitespace(input, &mut p);
        if input.get(p) != Some(&b':') {
            return None;
        }
        p += 1;
        whitespace(input, &mut p);
        let start = p;
        let (mut depth, mut quoted, mut escaped) = (0usize, false, false);
        while let Some(&byte) = input.get(p) {
            if quoted {
                if escaped {
                    escaped = false;
                } else if byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    quoted = false;
                }
            } else {
                match byte {
                    b'"' => quoted = true,
                    b'[' | b'{' => depth += 1,
                    b']' | b'}' => {
                        if depth == 0 {
                            break;
                        }
                        depth -= 1;
                    }
                    b',' if depth == 0 => break,
                    _ => {}
                }
            }
            p += 1;
        }
        let mut end = p;
        while end > start && input[end - 1].is_ascii_whitespace() {
            end -= 1;
        }
        if fold(&name) == key {
            found = Some(&input[start..end]);
        }
        match input.get(p) {
            Some(b',') => p += 1,
            Some(b'}') => break,
            _ => return None,
        }
    }
    found
}

fn json_response(
    result: setjoin_pg::CommandOutcome<String, setjoin_pg::StatementFailure>,
    status: u16,
    path: &str,
    c: &RequestContext,
    id: String,
    language: &str,
) -> Response<Body> {
    match result {
        setjoin_pg::CommandOutcome::Committed(value) => {
            let Some(body) = crate::jmap::reply::go_compact(&value) else {
                return problem(500, "request failed", path, c, id, language);
            };
            let mut response = crate::jmap::reply::response(body + "\n", c.identity.proto, id);
            *response.status_mut() = hyper::StatusCode::from_u16(status).expect("static status");
            response
        }
        setjoin_pg::CommandOutcome::Unknown { operation, .. } => {
            unknown(operation, path, c, id, language)
        }
        setjoin_pg::CommandOutcome::RolledBack(error) => rejected(&error, path, c, id, language),
    }
}

pub(crate) fn strings_field(
    fields: &crate::chat::Fields,
    key: &str,
) -> Result<Option<Vec<String>>, ()> {
    let mut value = None;
    for (k, v) in &fields.0 {
        if fold(k) == key {
            value = serde_json::from_str::<Option<Vec<Option<String>>>>(v.get())
                .map_err(|_| ())?
                .map(|v| v.into_iter().map(|s| s.unwrap_or_default()).collect());
        }
    }
    Ok(value)
}
pub(crate) fn bool_field(fields: &crate::chat::Fields, key: &str) -> Result<bool, ()> {
    let mut value = false;
    for (k, v) in &fields.0 {
        if fold(k) == key && v.get() != "null" {
            value = serde_json::from_str(v.get()).map_err(|_| ())?;
        }
    }
    Ok(value)
}

pub(crate) fn invalid_json(
    path: &str,
    c: &RequestContext,
    id: String,
    language: &str,
) -> Response<Body> {
    let mut response = problem(400, "invalid JSON body", path, c, id, language);
    let raw = crate::problem::Problem::new(400, "invalid JSON body")
        .kind("https://setjoin.com/errors/invalid-json")
        .instance(path)
        .body();
    crate::problem::set_body(&mut response, raw);
    response
}

pub(crate) fn too_large(
    path: &str,
    c: &RequestContext,
    id: String,
    language: &str,
) -> Response<Body> {
    let mut response = problem(
        413,
        "request body exceeds the allowed size",
        path,
        c,
        id,
        language,
    );
    let raw = crate::problem::Problem::new(413, "request body exceeds the allowed size")
        .kind("https://setjoin.com/errors/too-large")
        .instance(path)
        .body();
    crate::problem::set_body(&mut response, raw);
    response
}
