//! F14 registration, shared by the executable and recorded HTTP replay.
mod acl;
mod b;
mod content;
use crate::{Body, BoxFuture, Intercept, RequestContext};
use http_body_util::BodyExt;
use hyper::{Request, Response};
use serde_json::{json, Value};
use setjoin_authz::token::KeySource;
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;
pub struct DriveRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub worker: ScopedExecutor,
    pub store: Option<Arc<crate::recovery_worker::S3Store>>,
    pub keys: Arc<K>,
    pub issuer: String,
}
impl<K: KeySource + 'static> Intercept for DriveRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, r: &Request<Body>) -> bool {
        b::matches(r)
            || acl::matches(r)
            || (matches!(r.method().as_str(), "GET" | "HEAD")
                && crate::inventory::path_score("/api/me/sharing", r.uri().path()).is_some())
            || (r.method() == hyper::Method::POST
                && crate::inventory::path_score("/api/me/sharing/delegates", r.uri().path())
                    .is_some())
            || (r.method() == hyper::Method::DELETE
                && crate::inventory::path_score(
                    "/api/me/sharing/delegates/{userId}",
                    r.uri().path(),
                )
                .is_some())
            || (r.method() == hyper::Method::PUT
                && crate::inventory::path_score("/api/me/sharing/default", r.uri().path())
                    .is_some())
            || (r.method() == hyper::Method::DELETE
                && crate::inventory::path_score("/api/me/sharing/default/{id}", r.uri().path())
                    .is_some())
            || (matches!(r.method().as_str(), "GET" | "HEAD" | "POST")
                && crate::inventory::path_score("/api/admin/sharing/defaults", r.uri().path())
                    .is_some())
            || (r.method() == hyper::Method::DELETE
                && crate::inventory::path_score("/api/admin/sharing/defaults/{id}", r.uri().path())
                    .is_some())
            || (matches!(r.method().as_str(), "GET" | "HEAD")
                && crate::inventory::path_score("/api/admin/sharing/users/{id}", r.uri().path())
                    .is_some())
            || (matches!(r.method().as_str(), "GET" | "HEAD")
                && crate::inventory::path_score("/api/admin/sharing/audit", r.uri().path())
                    .is_some())
    }
    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            setjoin_authz::authorize_drive_user_request(&exec, &keys, &issuer, &h, s,"/api/drive/")
                .await
                .is_some()
        })
    }
    fn handle(&self, mut r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let (exec, worker, keys, issuer) = (
            self.exec.clone(),
            self.worker.clone(),
            self.keys.clone(),
            self.issuer.clone(),
        );
        let language = locale(r.headers());
        let store = self.store.clone();
        Box::pin(async move {
            if b::matches(&r) {
                let mut response = b::handle(r, c, exec, worker, keys, issuer, store).await;
                if response.headers().contains_key("content-language") {
                    response.headers_mut().insert(
                        "content-language",
                        language.parse().expect("validated locale"),
                    );
                }
                return response;
            }
            if acl::matches(&r) {
                let mut response = acl::handle(r, c, exec, keys, issuer).await;
                if response.headers().contains_key("content-language") {
                    response.headers_mut().insert(
                        "content-language",
                        language.parse().expect("validated locale"),
                    );
                }
                return response;
            }
            let mut response = async move {
                let Some(auth) = setjoin_authz::authorize_drive_user_request(
                    &exec,
                    &keys,
                    &issuer,
                    r.headers(),
                    c.identity.proto,
                    r.uri().path(),
                )
                .await
                else {
                    return c.upstream.forward(r, &c.identity).await;
                };
                let mut random = [0; 16];
                if getrandom::getrandom(&mut random).is_err() {
                    return c.upstream.forward(r, &c.identity).await;
                }
                let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), random);
                if crate::inventory::path_score("/api/admin/sharing/audit", r.uri().path())
                    .is_some()
                {
                    let path = "/admin/sharing/audit";
                    let scope = match setjoin_drive::authority(&worker, auth.context(), false).await
                    {
                        Ok(Some(a)) => a,
                        Ok(None) => {
                            setjoin_drive::denied(&worker, auth.context(), path, false, random)
                                .await;
                            return problem(403, "Forbidden", None, &c, id);
                        }
                        Err(_) => return c.upstream.forward(r, &c.identity).await,
                    };
                    let value = |key: &str| query(&r, key);
                    let user = value("user_id").and_then(|s| s.parse::<i64>().ok());
                    let limit = value("limit")
                        .and_then(|s| s.parse::<i64>().ok())
                        .filter(|v| *v > 0 && *v <= 500)
                        .unwrap_or(50);
                    let offset = value("offset")
                        .map(|s| go_atoi(&s))
                        .unwrap_or(0)
                        .clamp(0, 1_000_000);
                    return match setjoin_drive::audit(&worker, &scope, user, limit, offset).await {
                        Ok(v) => {
                            crate::jmap::reply::response(v.to_string() + "\n", c.identity.proto, id)
                        }
                        Err(_) => problem(500, "database error", Some(path), &c, id),
                    };
                }
                if crate::inventory::path_score("/api/admin/sharing/users/{id}", r.uri().path())
                    .is_some()
                {
                    let path = String::from_utf8_lossy(&crate::inventory::unescape(r.uri().path()))
                        .strip_prefix("/api")
                        .unwrap()
                        .to_owned();
                    let scope = match setjoin_drive::authority(&worker, auth.context(), false).await
                    {
                        Ok(Some(a)) => a,
                        Ok(None) => {
                            setjoin_drive::denied(&worker, auth.context(), &path, false, random)
                                .await;
                            return problem(403, "Forbidden", None, &c, id);
                        }
                        Err(_) => return c.upstream.forward(r, &c.identity).await,
                    };
                    let value = String::from_utf8_lossy(&crate::inventory::unescape(
                        r.uri().path().rsplit('/').next().unwrap_or(""),
                    ))
                    .into_owned();
                    let Ok(target) = value.parse::<i64>() else {
                        return problem(400, "invalid user id", Some(&path), &c, id);
                    };
                    return match setjoin_drive::oversight(&worker, &scope, target).await {
                        Ok(Some(v)) => {
                            crate::jmap::reply::response(v.to_string() + "\n", c.identity.proto, id)
                        }
                        Ok(None) => problem(404, "user not found", Some(&path), &c, id),
                        Err(_) => problem(500, "database error", Some(&path), &c, id),
                    };
                }
                if r.method() == hyper::Method::DELETE
                    && crate::inventory::path_score(
                        "/api/admin/sharing/defaults/{id}",
                        r.uri().path(),
                    )
                    .is_some()
                {
                    let path = String::from_utf8_lossy(&crate::inventory::unescape(r.uri().path()))
                        .strip_prefix("/api")
                        .unwrap()
                        .to_owned();
                    let scope = match setjoin_drive::authority(&worker, auth.context(), true).await
                    {
                        Ok(Some(a)) => a,
                        Ok(None) => {
                            setjoin_drive::denied(&worker, auth.context(), &path, true, random)
                                .await;
                            return problem(403, "Forbidden", None, &c, id);
                        }
                        Err(_) => return c.upstream.forward(r, &c.identity).await,
                    };
                    if setjoin_drive::reason_required(&exec).await
                        && r.headers()
                            .get("x-audit-reason")
                            .is_none_or(|v| v.as_bytes().is_empty())
                    {
                        setjoin_drive::missing_reason(
                            &exec,
                            auth.context(),
                            &c.identity.client_ip.to_string(),
                            random,
                        )
                        .await;
                        return problem(400, "reason_required", None, &c, id);
                    }
                    let value = String::from_utf8_lossy(&crate::inventory::unescape(
                        r.uri().path().rsplit('/').next().unwrap_or(""),
                    ))
                    .into_owned();
                    let Ok(target) = value.parse::<i64>() else {
                        return problem(400, "invalid id", Some(&path), &c, id);
                    };
                    return match setjoin_drive::delete_default(&worker, &scope, target, random)
                        .await
                    {
                        setjoin_pg::CommandOutcome::Committed(_) => empty(204, &c, id),
                        setjoin_pg::CommandOutcome::RolledBack(ref e) => {
                            rejected(e, Some(&path), &c, id)
                        }
                        setjoin_pg::CommandOutcome::Unknown { operation } => {
                            unknown(operation, &c, id)
                        }
                    };
                }
                if crate::inventory::path_score("/api/admin/sharing/defaults", r.uri().path())
                    .is_some()
                {
                    let path = "/admin/sharing/defaults";
                    let manage = r.method() == hyper::Method::POST;
                    let scope = match setjoin_drive::authority(&worker, auth.context(), manage)
                        .await
                    {
                        Ok(Some(a)) => a,
                        Ok(None) => {
                            setjoin_drive::denied(&worker, auth.context(), path, manage, random)
                                .await;
                            return problem(403, "Forbidden", None, &c, id);
                        }
                        Err(_) => return c.upstream.forward(r, &c.identity).await,
                    };
                    if manage {
                        if setjoin_drive::reason_required(&exec).await
                            && r.headers()
                                .get("x-audit-reason")
                                .is_none_or(|v| v.as_bytes().is_empty())
                        {
                            setjoin_drive::missing_reason(
                                &exec,
                                auth.context(),
                                &c.identity.client_ip.to_string(),
                                random,
                            )
                            .await;
                            return problem(400, "reason_required", None, &c, id);
                        }
                        let bytes = match r.body_mut().collect().await {
                            Ok(b) => b.to_bytes(),
                            Err(_) => return problem(400, "invalid JSON", Some(path), &c, id),
                        };
                        // Go's MaxBytesReader bounds the decoder's reads, not
                        // the full request: a complete first value can precede
                        // an arbitrarily large ignored trailer.
                        let body: Value = match decode_body(
                            &bytes[..bytes.len().min(1 << 20)],
                            &[
                                ("ownerScope", false),
                                ("ownerRef", true),
                                ("audience", false),
                                ("audienceRef", true),
                                ("level", false),
                            ],
                        ) {
                            Ok(v) => v,
                            Err(_) => return problem(400, "invalid JSON", Some(path), &c, id),
                        };
                        let result = setjoin_drive::create_default(
                            &worker,
                            &scope,
                            body["ownerScope"].as_str().unwrap_or(""),
                            body["ownerRef"].as_i64().unwrap_or(0),
                            body["audience"].as_str().unwrap_or(""),
                            body["audienceRef"].as_i64().unwrap_or(0),
                            body["level"].as_str().unwrap_or(""),
                            random,
                        )
                        .await;
                        return match result {
                            setjoin_pg::CommandOutcome::Committed(v) => {
                                crate::jmap::reply::response(
                                    v.to_string() + "\n",
                                    c.identity.proto,
                                    id,
                                )
                            }
                            setjoin_pg::CommandOutcome::RolledBack(ref e) => {
                                rejected(e, Some(path), &c, id)
                            }
                            setjoin_pg::CommandOutcome::Unknown { operation } => {
                                unknown(operation, &c, id)
                            }
                        };
                    }
                    return match setjoin_drive::list_defaults(&worker, &scope).await {
                        Ok(v) => {
                            crate::jmap::reply::response(v.to_string() + "\n", c.identity.proto, id)
                        }
                        Err(_) => problem(500, "database error", Some(path), &c, id),
                    };
                }
                if r.method() == hyper::Method::PUT {
                    let bytes = match r.body_mut().collect().await {
                        Ok(b) => b.to_bytes(),
                        Err(_) => return problem(400, "invalid JSON", None, &c, id),
                    };
                    let body: Value = match decode_body(
                        &bytes,
                        &[("audience", false), ("audienceRef", true), ("level", false)],
                    ) {
                        Ok(v) => v,
                        Err(_) => return problem(400, "invalid JSON", None, &c, id),
                    };
                    let audience = body["audience"].as_str().unwrap_or("");
                    let mut audience_ref = body["audienceRef"].as_i64().unwrap_or(0);
                    let level = body["level"].as_str().unwrap_or("");
                    if audience == "everyone" && audience_ref == 0 {
                        audience_ref =
                            match setjoin_drive::actor_domain(&worker, auth.context()).await {
                                Ok(Some(domain)) => domain,
                                _ => return problem(500, "database error", None, &c, id),
                            };
                    }
                    return match setjoin_drive::set_default(
                        &worker,
                        auth.context(),
                        audience,
                        audience_ref,
                        level,
                        random,
                    )
                    .await
                    {
                        setjoin_pg::CommandOutcome::Committed(v) => {
                            crate::jmap::reply::response(v.to_string() + "\n", c.identity.proto, id)
                        }
                        setjoin_pg::CommandOutcome::RolledBack(ref e) => rejected(e, None, &c, id),
                        setjoin_pg::CommandOutcome::Unknown { operation } => {
                            unknown(operation, &c, id)
                        }
                    };
                }
                if r.method() == hyper::Method::DELETE {
                    let value = String::from_utf8_lossy(&crate::inventory::unescape(
                        r.uri().path().rsplit('/').next().unwrap_or(""),
                    ))
                    .into_owned();
                    let is_default = crate::inventory::path_score(
                        "/api/me/sharing/default/{id}",
                        r.uri().path(),
                    )
                    .is_some();
                    let Ok(grantee) = value.parse::<i64>() else {
                        return problem(
                            400,
                            if is_default {
                                "invalid id"
                            } else {
                                "invalid user id"
                            },
                            None,
                            &c,
                            id,
                        );
                    };
                    if !is_default {
                        match setjoin_drive::primary_mailbox(&worker, auth.context()).await {
                            Ok(Some(mailbox)) if mailbox == auth.context().mailbox_id() => (),
                            Ok(Some(_)) => return c.upstream.forward(r, &c.identity).await,
                            _ => return problem(500, "mailbox not found", None, &c, id),
                        }
                    }
                    let outcome = if is_default {
                        setjoin_drive::clear_default(&worker, auth.context(), grantee, random).await
                    } else {
                        setjoin_drive::revoke(&worker, auth.context(), grantee, random).await
                    };
                    return match outcome {
                        setjoin_pg::CommandOutcome::Committed(_) => empty(204, &c, id),
                        setjoin_pg::CommandOutcome::RolledBack(ref e) => rejected(e, None, &c, id),
                        setjoin_pg::CommandOutcome::Unknown { operation } => {
                            unknown(operation, &c, id)
                        }
                    };
                }
                if r.method() == hyper::Method::POST {
                    let bytes = match r.body_mut().collect().await {
                        Ok(b) => b.to_bytes(),
                        Err(_) => {
                            return problem(
                                400,
                                "granteeEmail and permission are required",
                                None,
                                &c,
                                id,
                            )
                        }
                    };
                    let body: Value = match decode_body(
                        &bytes,
                        &[("granteeEmail", false), ("permission", false)],
                    ) {
                        Ok(v) => v,
                        Err(_) => {
                            return problem(
                                400,
                                "granteeEmail and permission are required",
                                None,
                                &c,
                                id,
                            )
                        }
                    };
                    let email = body["granteeEmail"].as_str().unwrap_or("");
                    let permission = body["permission"].as_str().unwrap_or("");
                    if email.is_empty() {
                        return problem(
                            400,
                            "granteeEmail and permission are required",
                            None,
                            &c,
                            id,
                        );
                    }
                    match setjoin_drive::primary_mailbox(&worker, auth.context()).await {
                        Ok(Some(mailbox)) if mailbox == auth.context().mailbox_id() => (),
                        Ok(Some(_)) => {
                            *r.body_mut() = http_body_util::Full::new(bytes)
                                .map_err(|e| match e {})
                                .boxed();
                            return c.upstream.forward(r, &c.identity).await;
                        }
                        _ => return problem(500, "mailbox not found", None, &c, id),
                    }
                    return match setjoin_drive::grant(
                        &worker,
                        auth.context(),
                        email,
                        permission,
                        random,
                    )
                    .await
                    {
                        setjoin_pg::CommandOutcome::Committed(_) => empty(201, &c, id),
                        setjoin_pg::CommandOutcome::RolledBack(ref e) => rejected(e, None, &c, id),
                        setjoin_pg::CommandOutcome::Unknown { operation } => {
                            unknown(operation, &c, id)
                        }
                    };
                }
                match setjoin_drive::overview(&worker, auth.context()).await {
                    Ok(v) => {
                        crate::jmap::reply::response(v.to_string() + "\n", c.identity.proto, id)
                    }
                    Err(_) => problem(500, "database error", None, &c, id),
                }
            }
            .await;
            if response.headers().contains_key("content-language") {
                response.headers_mut().insert(
                    "content-language",
                    language.parse().expect("validated locale"),
                );
            }
            response
        })
    }
}
fn empty(status: u16, c: &RequestContext, id: String) -> Response<Body> {
    let mut r = crate::jmap::reply::response(String::new(), c.identity.proto, id);
    *r.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
    r.headers_mut().remove("content-type");
    r
}
fn problem(
    status: u16,
    detail: &str,
    path: Option<&str>,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let status = hyper::StatusCode::from_u16(status).unwrap();
    let text = crate::problem::Problem::new(status.as_u16(), detail)
        .instance(path.unwrap_or(""))
        .body();
    let mut r = crate::jmap::reply::response(text, c.identity.proto, id);
    *r.status_mut() = status;
    r.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/problem+json"),
    );
    if path.is_some() {
        r.headers_mut().insert(
            "content-language",
            hyper::header::HeaderValue::from_static("en"),
        );
    }
    r
}
fn rejected(
    e: &setjoin_pg::Rejection<setjoin_pg::StatementFailure>,
    path: Option<&str>,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let f = match e {
        setjoin_pg::Rejection::Statement(f) | setjoin_pg::Rejection::Body(f) => Some(f),
        _ => None,
    };
    let (status, detail) = match f.and_then(|f| f.sqlstate.as_deref()) {
        Some("BZ114") => (404, "notFound"),
        Some("BZ115" | "BZ117") => (400, f.unwrap().message.as_str()),
        Some("BZ116") => (403, f.unwrap().message.as_str()),
        _ => (500, "request failed"),
    };
    let mut r = problem(status, detail, path, c, id);
    if let (Some(path), Some(f)) = (path, f) {
        if let Some(code) = f
            .sqlstate
            .as_deref()
            .filter(|v| matches!(*v, "BZ114" | "BZ115" | "BZ116" | "BZ117"))
        {
            let remediation=match code{"BZ114"=>"Refresh the target identifier and retry only if the resource still exists.","BZ116"=>"Complete the required authorization, approval, or recovery step before retrying.",_=>"Correct the request fields and retry."};
            let kind = format!(
                "https://setjoin.com/problems/reducer/{}",
                code.to_lowercase()
            );
            let raw = crate::problem::Problem::new(status, detail)
                .kind(&kind)
                .instance(path)
                .remediation(remediation)
                .code(code)
                .retryable(false)
                .body();
            crate::problem::set_body(&mut r, raw);
        }
    }
    r
}
fn unknown(
    operation: setjoin_contracts::ids::OperationId,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let hex = setjoin_pg::command::operation_hex(operation);
    let mut r = problem(503, "commit outcome unknown", None, c, id);
    r.headers_mut()
        .insert("x-operation-id", hex.parse().expect("operation hex"));
    r
}

struct Fields(Vec<(String, Box<serde_json::value::RawValue>)>);
impl<'de> serde::Deserialize<'de> for Fields {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct Object;
        impl<'de> serde::de::Visitor<'de> for Object {
            type Value = Fields;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an object or null")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Fields, E> {
                Ok(Fields(Vec::new()))
            }
            fn visit_map<M: serde::de::MapAccess<'de>>(
                self,
                mut map: M,
            ) -> Result<Fields, M::Error> {
                let mut fields = Vec::new();
                while let Some(k) = map.next_key::<String>()? {
                    fields.push((k, map.next_value()?));
                }
                Ok(Fields(fields))
            }
        }
        d.deserialize_any(Object)
    }
}
fn decode_body(bytes: &[u8], known: &[(&str, bool)]) -> Result<Value, ()> {
    use serde::Deserialize;
    let text = go_json_text(bytes);
    let mut decoder = serde_json::Deserializer::from_str(&text);
    let fields = Fields::deserialize(&mut decoder).map_err(|_| ())?;
    let fold = |s: &str| {
        s.chars()
            .map(|c| match c {
                'ſ' => 'S',
                'K' => 'K',
                c => c.to_ascii_uppercase(),
            })
            .collect::<String>()
    };
    let mut out = serde_json::Map::new();
    for (key, raw) in fields.0 {
        if let Some((name, integer)) = known.iter().find(|(name, _)| fold(name) == fold(&key)) {
            if raw.get() == "null" {
                continue;
            }
            let value = if *integer {
                json!(serde_json::from_str::<i64>(raw.get()).map_err(|_| ())?)
            } else {
                json!(serde_json::from_str::<String>(raw.get()).map_err(|_| ())?)
            };
            out.insert((*name).into(), value);
        }
    }
    Ok(Value::Object(out))
}

fn go_json_text(input: &[u8]) -> String {
    let text = go_utf8(input);
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let (mut i, mut quoted) = (0, false);
    let unit = |at: usize| -> Option<u16> {
        if bytes.get(at..at + 2)? != b"\\u" {
            return None;
        }
        let hex = bytes.get(at + 2..at + 6)?;
        let mut n = 0u16;
        for b in hex {
            n = (n << 4) | (*b as char).to_digit(16)? as u16;
        }
        Some(n)
    };
    while i < bytes.len() {
        if quoted && bytes[i] == b'\\' {
            if let Some(n) = unit(i) {
                if (0xd800..=0xdbff).contains(&n)
                    && unit(i + 6).is_some_and(|m| (0xdc00..=0xdfff).contains(&m))
                {
                    out.extend_from_slice(&bytes[i..i + 12]);
                    i += 12;
                    continue;
                }
                if (0xd800..=0xdfff).contains(&n) {
                    out.extend_from_slice(b"\\ufffd");
                    i += 6;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
            if i < bytes.len() {
                out.push(bytes[i]);
                i += 1;
            }
            continue;
        }
        if bytes[i] == b'"' {
            quoted = !quoted;
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8(out).expect("UTF-8 preserving JSON escape replacement")
}

fn go_utf8(mut input: &[u8]) -> String {
    let mut out = String::with_capacity(input.len());
    loop {
        match std::str::from_utf8(input) {
            Ok(valid) => {
                out.push_str(valid);
                return out;
            }
            Err(error) => {
                let prefix = error.valid_up_to();
                out.push_str(
                    std::str::from_utf8(&input[..prefix]).expect("validated UTF-8 prefix"),
                );
                out.push('\u{fffd}');
                input = &input[prefix + 1..];
            }
        }
    }
}

fn locale(headers: &hyper::HeaderMap) -> String {
    let raw = headers
        .get("accept-language")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split([',', ';'])
        .next()
        .unwrap_or("")
        .trim();
    let mut parts = raw.split('-');
    let first = parts.next().unwrap_or("");
    if first.is_empty()
        || first.len() > 8
        || !first.bytes().all(|b| b.is_ascii_alphabetic())
        || !parts
            .all(|p| !p.is_empty() && p.len() <= 8 && p.bytes().all(|b| b.is_ascii_alphanumeric()))
    {
        "en".into()
    } else {
        raw.into()
    }
}

fn go_atoi(value: &str) -> i64 {
    if let Ok(n) = value.parse() {
        return n;
    }
    let (negative, digits) = if let Some(s) = value.strip_prefix('-') {
        (true, s)
    } else {
        (false, value.strip_prefix('+').unwrap_or(value))
    };
    if !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()) {
        if negative {
            i64::MIN
        } else {
            i64::MAX
        }
    } else {
        0
    }
}

fn query(r: &Request<Body>, key: &str) -> Option<String> {
    for pair in r.uri().query().unwrap_or("").split('&') {
        if pair.contains(';') {
            continue;
        }
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let (Some(k), Some(v)) = (decode_query(k), decode_query(v)) else {
            continue;
        };
        if k == key {
            return Some(v);
        }
    }
    None
}
fn decode_query(value: &str) -> Option<String> {
    let mut out = Vec::new();
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => {
                let hi = (*bytes.get(i + 1)? as char).to_digit(16)?;
                let lo = (*bytes.get(i + 2)? as char).to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
                i += 2
            }
            b => out.push(b),
        }
        i += 1;
    }
    Some(go_utf8(&out))
}

#[path = "drive_core.rs"]
pub mod core;
