//! F12 gateway registration shared by executable and HTTP replay.
use crate::{Body, BoxFuture, Intercept, RequestContext};
use http_body_util::BodyExt;
use hyper::{Method, Request, Response, StatusCode};
use serde::Deserialize;
use setjoin_authz::token::KeySource;
use setjoin_pg::ScopedExecutor;
use std::sync::Arc;

pub struct ChatRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub worker: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
}
impl<K: KeySource + 'static> Intercept for ChatRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, r: &Request<Body>) -> bool {
        if matches!(*r.method(), Method::GET | Method::HEAD)
            && (crate::inventory::path_score("/api/admin/chat-channels", r.uri().path()).is_some()
                || channel(r.uri().path(), "audit").is_some()
                || channel(r.uri().path(), "audit/verify").is_some())
        {
            return true;
        }
        (r.method() == Method::POST
            && (channel(r.uri().path(), "hold").is_some()
                || channel(r.uri().path(), "classification").is_some()))
            || (r.method() == Method::PUT && channel(r.uri().path(), "retention").is_some())
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
        let worker = self.worker.clone();
        Box::pin(async move {
            let is_list =
                crate::inventory::path_score("/api/admin/chat-channels", r.uri().path()).is_some();
            let is_audit = channel(r.uri().path(), "audit").is_some();
            let is_verify = channel(r.uri().path(), "audit/verify").is_some();
            let action = if is_list {
                "list"
            } else if is_verify {
                "audit/verify"
            } else if is_audit {
                "audit"
            } else if r.method() == Method::PUT {
                "retention"
            } else if channel(r.uri().path(), "classification").is_some() {
                "classification"
            } else {
                "hold"
            };
            let id = if is_list {
                Ok(0)
            } else {
                channel(r.uri().path(), action).unwrap().parse::<i64>()
            };
            let mut nonce = [0; 16];
            if getrandom::getrandom(&mut nonce).is_err() {
                return c.upstream.forward(r, &c.identity).await;
            }
            let request_id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), nonce);
            let encoded_mount = r
                .uri()
                .path()
                .split('/')
                .nth(1)
                .is_some_and(|s| s != "api" && crate::inventory::unescape(s) == b"api");
            // Go's StripPrefix checks RawPath as well as decoded Path.
            if encoded_mount
                || (!is_list && channel(r.uri().path(), action).is_some_and(|id| id.contains('/')))
            {
                let mut response = crate::jmap::reply::response(
                    "404 page not found\n".into(),
                    c.identity.proto,
                    request_id,
                );
                *response.status_mut() = StatusCode::NOT_FOUND;
                response.headers_mut().insert(
                    "content-type",
                    hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
                );
                return response;
            }
            let decoded_path = go_utf8(&crate::inventory::unescape(r.uri().path()));
            let path = decoded_path
                .strip_prefix("/api")
                .unwrap_or(&decoded_path)
                .to_owned();
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
            let scope = match setjoin_chat::authority(
                &exec,
                auth.context(),
                !(is_list || is_audit || is_verify),
            )
            .await
            {
                Ok(Some(s)) => s,
                Ok(None) => {
                    let mut operation = [0; 16];
                    if getrandom::getrandom(&mut operation).is_ok() {
                        setjoin_chat::denied(
                            &exec,
                            auth.context(),
                            &path,
                            !(is_list || is_audit || is_verify),
                            operation,
                        )
                        .await;
                    }
                    let mut response = problem(403, "Forbidden", "", &c, request_id);
                    response.headers_mut().remove("content-language");
                    return response;
                }
                Err(_) => return c.upstream.forward(r, &c.identity).await,
            };
            match setjoin_chat::enabled(&exec).await {
                Ok(true) => {}
                Ok(false) => {
                    let mut response = problem(404, "not found", "", &c, request_id);
                    response.headers_mut().remove("content-language");
                    return response;
                }
                Err(_) => return c.upstream.forward(r, &c.identity).await,
            }
            if is_list {
                let user = match query(&r, "userId")
                    .filter(|s| !s.is_empty())
                    .map(|s| s.parse::<i64>())
                    .transpose()
                {
                    Ok(v) => v,
                    Err(_) => return problem(400, "invalid userId", &path, &c, request_id),
                };
                let (limit, offset) = page(&r, 50, 500);
                // Go passes raw query bytes to pgx. Invalid UTF-8 text fails
                // PostgreSQL encoding rather than becoming a different search.
                let search = match query_bytes(&r, "q")
                    .filter(|v| !v.is_empty())
                    .map(String::from_utf8)
                    .transpose()
                {
                    Ok(v) => v,
                    Err(_) => return problem(500, "database error", &path, &c, request_id),
                };
                let rows =
                    match setjoin_chat::list(&worker, &scope, user, search, limit, offset).await {
                        Ok(v) => v,
                        Err(_) => return problem(500, "database error", &path, &c, request_id),
                    };
                let mut operation = [0; 16];
                if getrandom::getrandom(&mut operation).is_ok() {
                    setjoin_chat::audit_read(
                        &exec,
                        &scope,
                        "chat_channel_admin_list",
                        None,
                        &c.identity.client_ip.to_string(),
                        operation,
                    )
                    .await;
                }
                return crate::jmap::reply::response(
                    rows.to_string() + "\n",
                    c.identity.proto,
                    request_id,
                );
            }
            let Ok(id) = id else {
                return problem(400, "invalid channel id", &path, &c, request_id);
            };
            if is_verify {
                let mut value = match setjoin_chat::verify(&worker, &scope, id).await {
                    Ok(v) => v,
                    Err(_) => return problem(500, "database error", &path, &c, request_id),
                };
                value["verifiedAt"] = chrono::Local::now()
                    .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                    .into();
                return crate::jmap::reply::response(
                    value.to_string() + "\n",
                    c.identity.proto,
                    request_id,
                );
            }
            if is_audit {
                let before = match query(&r, "beforeId")
                    .filter(|s| !s.is_empty())
                    .map(|s| s.parse::<i64>())
                    .transpose()
                {
                    Ok(v) => v,
                    Err(_) => return problem(400, "invalid beforeId", &path, &c, request_id),
                };
                let (limit, _) = page(&r, 100, 1000);
                let rows = match setjoin_chat::audit(&worker, &scope, id, before, limit).await {
                    Ok(v) => v,
                    Err(_) => return problem(500, "database error", &path, &c, request_id),
                };
                let mut operation = [0; 16];
                if getrandom::getrandom(&mut operation).is_ok() {
                    setjoin_chat::audit_read(
                        &exec,
                        &scope,
                        "chat_channel_audit_read",
                        Some(id),
                        &c.identity.client_ip.to_string(),
                        operation,
                    )
                    .await;
                }
                if query(&r, "format").as_deref() == Some("csv") {
                    let summary = setjoin_chat::chain_summary(&worker, &scope, id).await;
                    return csv_response(id, &rows, summary, &c, request_id);
                }
                return crate::jmap::reply::response(
                    rows.to_string() + "\n",
                    c.identity.proto,
                    request_id,
                );
            }
            let mut bytes = Vec::new();
            while let Some(frame) = r.body_mut().frame().await {
                let Ok(frame) = frame else {
                    return problem(400, "invalid JSON", &path, &c, request_id);
                };
                if let Some(data) = frame.data_ref() {
                    if bytes.len() + data.len() > 1 << 20 {
                        return problem(400, "invalid JSON", &path, &c, request_id);
                    };
                    bytes.extend_from_slice(data);
                }
            }
            let body = match decode_mutation(action, &bytes) {
                Ok(b) => b,
                Err(_) => return problem(400, "invalid JSON", &path, &c, request_id),
            };
            let mut operation = [0; 16];
            if getrandom::getrandom(&mut operation).is_err() {
                return problem(500, "database error", &path, &c, request_id);
            }
            if action == "classification" {
                if body.classification != "gxp" {
                    return problem(
                        400,
                        "classification must be gxp (the only reducer-valid transition)",
                        &path,
                        &c,
                        request_id,
                    );
                }
                if body.retention_days.unwrap_or(0) <= 0 {
                    return problem(
                        400,
                        "retentionDays must be a positive integer",
                        &path,
                        &c,
                        request_id,
                    );
                }
                if !matches!(body.worm_mode.as_str(), "governance" | "compliance") {
                    return problem(
                        400,
                        "wormMode must be governance or compliance",
                        &path,
                        &c,
                        request_id,
                    );
                }
                let days = match i32::try_from(body.retention_days.unwrap_or(0)) {
                    Ok(v) => v,
                    Err(_) => return problem(500, "database error", &path, &c, request_id),
                };
                match setjoin_chat::classification_knobs(
                    &worker,
                    &scope,
                    id,
                    days,
                    &body.worm_mode,
                    operation,
                )
                .await
                {
                    setjoin_pg::CommandOutcome::Committed(()) => {}
                    setjoin_pg::CommandOutcome::Unknown { operation } => {
                        return unknown(operation, &path, &c, request_id)
                    }
                    _ => return problem(500, "database error", &path, &c, request_id),
                }
                if getrandom::getrandom(&mut operation).is_err() {
                    return problem(500, "database error", &path, &c, request_id);
                }
            }
            let days = match body.retention_days.map(i32::try_from).transpose() {
                Ok(v) => v,
                Err(_) => return problem(500, "database error", &path, &c, request_id),
            };
            let outcome = if action == "classification" {
                setjoin_chat::classification(&exec, &scope, id, &body.classification, operation)
                    .await
            } else if action == "retention" {
                setjoin_chat::retention(&exec, &scope, id, days, operation).await
            } else {
                setjoin_chat::hold(&exec, &scope, id, body.on, body.reason, operation).await
            };
            match outcome {
                setjoin_pg::CommandOutcome::Committed(()) => {
                    let mut response =
                        crate::jmap::reply::response(String::new(), c.identity.proto, request_id);
                    *response.status_mut() = StatusCode::NO_CONTENT;
                    response.headers_mut().remove("content-type");
                    response
                }
                setjoin_pg::CommandOutcome::RolledBack(ref e) => {
                    eprintln!("chat rejected: {}", e.log_summary());
                    rejected(e, &path, &c, request_id)
                }
                setjoin_pg::CommandOutcome::Unknown { operation } => {
                    unknown(operation, &path, &c, request_id)
                }
            }
        })
    }
}
fn channel(path: &str, action: &str) -> Option<String> {
    let mut parts: Vec<_> = path.split('/').collect();
    if parts
        .get(1)
        .is_some_and(|s| crate::inventory::unescape(s) == b"api")
    {
        parts.remove(1);
    }
    if parts.len() < 5
        || crate::inventory::unescape(parts[1]) != b"admin"
        || crate::inventory::unescape(parts[2]) != b"chat-channels"
    {
        return None;
    }
    let suffix: Vec<_> = action.split('/').collect();
    if suffix.len() != parts.len() - 4
        || suffix
            .iter()
            .zip(&parts[4..])
            .any(|(a, b)| crate::inventory::unescape(a) != crate::inventory::unescape(b))
    {
        return None;
    }
    Some(String::from_utf8_lossy(&crate::inventory::unescape(parts[3])).into_owned())
}

/// `httputil.Problem` as Go's `json.Encoder` writes it (see [`crate::problem`]).
pub(crate) fn go_problem_json(
    type_: &str,
    title: &str,
    status: u16,
    detail: &str,
    instance: &str,
    code: Option<&str>,
) -> String {
    let mut problem = crate::problem::Problem::new(status, detail)
        .kind(type_)
        .title(title)
        .instance(instance);
    if let Some(code) = code {
        problem = problem.code(code);
    }
    problem.body()
}

pub(crate) fn problem(
    status: u16,
    detail: &str,
    path: &str,
    c: &RequestContext,
    request_id: String,
) -> Response<Body> {
    let status = StatusCode::from_u16(status).unwrap();
    let raw = go_problem_json(
        "about:blank",
        crate::problem::title(status.as_u16()),
        status.as_u16(),
        detail,
        path,
        None,
    );
    let mut response = crate::jmap::reply::response(raw, c.identity.proto, request_id);
    *response.status_mut() = status;
    response.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/problem+json"),
    );
    response.headers_mut().insert(
        "content-language",
        hyper::header::HeaderValue::from_static("en"),
    );
    response
}

fn rejected(
    e: &setjoin_pg::Rejection<setjoin_pg::StatementFailure>,
    path: &str,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let code = match e {
        setjoin_pg::Rejection::Statement(e) | setjoin_pg::Rejection::Body(e) => {
            e.sqlstate.as_deref()
        }
        _ => None,
    };
    if !matches!(code, Some("BZ192" | "BZ195" | "BZ210")) {
        return problem(500, "database error", path, c, id);
    }
    let code = code.expect("classified code");
    let (status, detail, remediation) = if code == "BZ192" {
        (
            409,
            "conflict",
            "Refresh current state, resolve the conflict, and retry.",
        )
    } else {
        (
            422,
            "unprocessable",
            "Correct the requested operation using the documented runbook and retry.",
        )
    };
    let mut response = problem(status, detail, path, c, id);
    let kind = format!(
        "https://setjoin.com/problems/reducer/{}",
        code.to_ascii_lowercase()
    );
    let text = crate::problem::Problem::new(status, detail)
        .kind(&kind)
        .instance(path)
        .remediation(remediation)
        .code(code)
        .retryable(false)
        .body();
    crate::problem::set_body(&mut response, text);
    response
}

pub(crate) fn query(r: &Request<Body>, key: &str) -> Option<String> {
    query_bytes(r, key).map(|v| go_utf8(&v))
}
pub(super) fn query_bytes(r: &Request<Body>, key: &str) -> Option<Vec<u8>> {
    r.uri()
        .query()?
        .split('&')
        .filter(|p| !p.contains(';'))
        .filter_map(|p| {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            Some((form(k)?, form(v)?))
        })
        .find(|(k, _)| k == key.as_bytes())
        .map(|(_, v)| v)
}
fn form(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => out.push(b' '),
            b'%' => {
                if i + 2 >= bytes.len() {
                    return None;
                }
                let a = (bytes[i + 1] as char).to_digit(16)?;
                let b = (bytes[i + 2] as char).to_digit(16)?;
                out.push((a * 16 + b) as u8);
                i += 2
            }
            b => out.push(b),
        }
        i += 1
    }
    Some(out)
}
fn page(r: &Request<Body>, default: i64, max: i64) -> (i64, i64) {
    let limit = query(r, "limit")
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|v| *v > 0 && *v <= max)
        .unwrap_or(default);
    let offset = query(r, "offset")
        .map(|v| go_atoi(&v))
        .unwrap_or(0)
        .clamp(0, 1_000_000);
    (limit, offset)
}

fn csv_response(
    channel: i64,
    rows: &serde_json::Value,
    summary: Result<setjoin_chat::ChainSummary, setjoin_pg::StatementFailure>,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    use setjoin_contracts::csv::{escape_formula, record};
    let now = chrono::Local::now();
    let mut body = match summary {
        Ok(s) => record(&[
            "# chain verification".into(),
            format!("valid={}", s.valid),
            format!("checked={}", s.checked),
            format!("keyVersion={}", s.key_version),
            format!(
                "verifiedAt={}",
                now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
            ),
        ]),
        Err(_) => record(&[
            "# verification".into(),
            "error computing chain validity".into(),
        ]),
    };
    body.push_str(&record(
        &[
            "ID",
            "Occurred At",
            "User ID",
            "IP",
            "Action",
            "Target Type",
            "Target ID",
            "Notes",
        ]
        .map(str::to_owned),
    ));
    for row in rows.as_array().expect("audit rows") {
        let cells = [
            "id",
            "occurredAt",
            "userId",
            "ip",
            "action",
            "targetType",
            "targetId",
            "notes",
        ]
        .map(|key| match &row[key] {
            serde_json::Value::Null => String::new(),
            serde_json::Value::String(s) => s.clone(),
            v => v.to_string(),
        })
        .map(|s| escape_formula(&s));
        body.push_str(&record(&cells));
    }
    let mut response = crate::jmap::reply::response(body, c.identity.proto, id);
    response.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("text/csv"),
    );
    response.headers_mut().insert(
        "content-disposition",
        format!(
            "attachment; filename=chat-audit-{channel}-{}.csv",
            now.format("%Y%m%d")
        )
        .parse()
        .expect("CSV filename"),
    );
    response
}

#[derive(Default)]
struct MutationBody {
    on: bool,
    reason: Option<String>,
    retention_days: Option<i64>,
    classification: String,
    worm_mode: String,
}
pub(crate) struct Fields(pub(crate) Vec<(String, Box<serde_json::value::RawValue>)>);
impl<'de> Deserialize<'de> for Fields {
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
fn decode_mutation(action: &str, bytes: &[u8]) -> Result<MutationBody, ()> {
    let text = go_json_text(bytes);
    let mut decoder = serde_json::Deserializer::from_str(&text);
    let fields = Fields::deserialize(&mut decoder).map_err(|_| ())?;
    decoder.end().map_err(|_| ())?;
    let mut out = MutationBody::default();
    for (key, raw) in fields.0 {
        let key = key
            .chars()
            .map(|c| match c {
                '\u{017f}' => 'S',
                '\u{212a}' => 'K',
                c => c.to_ascii_uppercase(),
            })
            .collect::<String>();
        if !matches!(
            (action, key.as_str()),
            ("hold", "ON" | "REASON")
                | ("retention", "RETENTIONDAYS")
                | (
                    "classification",
                    "CLASSIFICATION" | "RETENTIONDAYS" | "WORMMODE"
                )
        ) {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(raw.get()).map_err(|_| ())?;
        match (action, key.as_str()) {
            ("hold", "ON") => {
                if !value.is_null() {
                    out.on = value.as_bool().ok_or(())?
                }
            }
            ("hold", "REASON") => {
                out.reason = if value.is_null() {
                    None
                } else {
                    Some(value.as_str().ok_or(())?.into())
                }
            }
            ("retention" | "classification", "RETENTIONDAYS") => {
                if value.is_null() {
                    if action == "retention" {
                        out.retention_days = None;
                    }
                } else {
                    out.retention_days = Some(value.as_i64().ok_or(())?);
                }
            }
            ("classification", "CLASSIFICATION") => {
                if !value.is_null() {
                    out.classification = value.as_str().ok_or(())?.into()
                }
            }
            ("classification", "WORMMODE") => {
                if !value.is_null() {
                    out.worm_mode = value.as_str().ok_or(())?.into()
                }
            }
            _ => {}
        }
    }
    Ok(out)
}

// encoding/json replaces malformed UTF-8 and unpaired UTF-16 escapes inside
// strings. Preserve paired escapes and escaped backslashes before Serde parses.
pub(crate) fn go_json_text(input: &[u8]) -> String {
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

pub(super) fn unknown(
    operation: setjoin_contracts::ids::OperationId,
    path: &str,
    c: &RequestContext,
    id: String,
) -> Response<Body> {
    let mut response = problem(503, "chat command outcome unknown", path, c, id);
    response.headers_mut().insert(
        "x-operation-id",
        setjoin_pg::operation_hex(operation)
            .parse()
            .expect("opaque operation ID"),
    );
    response
}

// ParseLimitOffset deliberately ignores strconv.Atoi's error. Range failures
// retain the saturated integer before Go applies its pagination ceiling.
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

// Go consumes one invalid UTF-8 byte per replacement rune; Rust's standard
// lossy conversion can collapse a malformed multi-byte prefix into one rune.
pub(crate) fn go_utf8(mut input: &[u8]) -> String {
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
