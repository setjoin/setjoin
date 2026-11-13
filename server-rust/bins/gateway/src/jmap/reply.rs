//! The bytes and headers Go writes for the `Email/set` the route serves.
//!
//! Body: `httputil.WriteJSON` of `jmap.Response` — `json.Encoder` output with
//! a trailing newline, `sessionState` before `methodResponses`, no
//! `createdIds`. The `Email/set` arguments are Go's re-marshalled map of the
//! reducer's JSONB, so keys are sorted (`accountId`, `newState`,
//! `notUpdated`, `oldState`, `updated`) and `updated` is the reducer's array
//! of numeric ids. Every interpolated value is a decimal or a client id the
//! classifier restricted to `[A-Za-z0-9._:-]`, so no JSON escaping arises.
//!
//! Headers: those Go's HTTP listener chain sets on this response
//! (`RequestID`, `CacheControl`, `SecurityHeaders`, `WriteJSON`); `HSTS` is
//! only on Go's TLS listener, which the gateway never fronts.

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{HeaderMap, HeaderValue};
use hyper::{Response, StatusCode};

use crate::Body;

/// What the command did, in the reducer's terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome<'a> {
    /// The message was updated (changed or already in that state).
    Updated { old_state: i64, new_state: i64 },
    /// No such message in the caller's mailbox.
    NotFound { state: i64 },
    /// The reducer's per-item error for the message (committed, no state
    /// change): `set_error` is its `notUpdated` entry as JSONB text, which
    /// Go passes through as a `json.RawMessage`.
    NotUpdated { state: i64, set_error: &'a str },
    /// Known not committed: Go's `mapReducerErr` default arm.
    Failed,
    /// Commit outcome unknown: never success; carries the operation id.
    Unknown { operation: [u8; 16] },
}

pub fn body(
    session_state: &str,
    mailbox: i64,
    message: i64,
    client_id: &str,
    outcome: Outcome<'_>,
) -> String {
    let (name, args) = match outcome {
        Outcome::Updated {
            old_state,
            new_state,
        } => (
            "Email/set",
            format!(
                r#"{{"accountId":"{mailbox}","newState":"{new_state}","notUpdated":{{}},"oldState":"{old_state}","updated":[{message}]}}"#
            ),
        ),
        Outcome::NotFound { state } => (
            "Email/set",
            format!(
                r#"{{"accountId":"{mailbox}","newState":"{state}","notUpdated":{{"{message}":{{"type":"notFound"}}}},"oldState":"{state}","updated":[]}}"#
            ),
        ),
        Outcome::NotUpdated { state, set_error } => match go_compact(set_error) {
            Some(entry) => (
                "Email/set",
                format!(
                    r#"{{"accountId":"{mailbox}","newState":"{state}","notUpdated":{{"{message}":{entry}}},"oldState":"{state}","updated":[]}}"#
                ),
            ),
            // Not JSON (never from a JSONB column): no partial answer.
            None => ("error", server_fail("database error")),
        },
        Outcome::Failed => ("error", server_fail("database error")),
        Outcome::Unknown { operation } => {
            let hex = hex(&operation);
            (
                "error",
                server_fail(&format!("commit outcome unknown; look up operation {hex}")),
            )
        }
    };
    format!(
        r#"{{"sessionState":"{session_state}","methodResponses":[["{name}",{args},"{client_id}"]]}}"#
    ) + "\n"
}

/// What Go's `json.Encoder` writes for a `json.RawMessage`: the text
/// compacted (whitespace outside strings removed, nothing reordered or
/// re-escaped) with `<`, `>`, `&`, U+2028 and U+2029 inside strings written
/// as `\u003c`, `\u003e`, `\u0026`, `\u2028`, `\u2029`. `None` when `raw`
/// is not JSON.
pub fn go_compact(raw: &str) -> Option<String> {
    // Go compacts RawMessage lexically; valid PostgreSQL numeric values may
    // exceed every machine-number range. Validate without materializing them.
    serde_json::from_str::<&serde_json::value::RawValue>(raw).ok()?;
    let (mut out, mut in_str, mut esc) = (String::with_capacity(raw.len()), false, false);
    for ch in raw.chars() {
        if !in_str {
            if ch == '"' {
                in_str = true;
                out.push(ch);
            } else if !ch.is_ascii_whitespace() {
                out.push(ch);
            }
            continue;
        }
        if esc {
            esc = false;
            out.push(ch);
            continue;
        }
        match ch {
            '\\' => {
                esc = true;
                out.push(ch);
            }
            '"' => {
                in_str = false;
                out.push(ch);
            }
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            _ => out.push(ch),
        }
    }
    Some(out)
}

/// Go's `json.Marshal` of a `map[string]json.RawMessage`: keys sorted bytewise
/// and escaped as Go escapes strings, each raw value compacted.
pub fn marshal_sorted(
    object: &std::collections::BTreeMap<String, Box<serde_json::value::RawValue>>,
) -> Option<String> {
    let mut out = String::from("{");
    for (i, (key, value)) in object.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&go_compact(&serde_json::to_string(key).ok()?)?);
        out.push(':');
        out.push_str(&go_compact(value.get())?);
    }
    out.push('}');
    Some(out)
}

/// Lower-case hex of an operation id (the form clients and logs see).
pub fn hex(operation: &[u8; 16]) -> String {
    operation.iter().map(|b| format!("{b:02x}")).collect()
}

/// Go's answer to a method that returned a reducer-backed object: the
/// response envelope around the reducer JSONB compacted as `json.RawMessage`.
/// `None` when `raw` is not JSON (the caller forwards).
pub fn method_response(
    session_state: &str,
    name: &str,
    raw: &str,
    client_id: &str,
) -> Option<String> {
    let args = go_compact(raw)?;
    Some(
        format!(
            r#"{{"sessionState":"{session_state}","methodResponses":[["{name}",{args},"{client_id}"]]}}"#
        ) + "\n",
    )
}

/// Go's method-level error (`jmap.Error`): an RFC 7807 object whose `status`
/// is `errorStatus(type)`, inside HTTP 200. `detail` is plain ASCII here.
pub fn method_error(
    session_state: &str,
    error_type: &str,
    status: u16,
    detail: &str,
    client_id: &str,
) -> String {
    let problem = crate::problem::jmap(status, error_type, detail);
    format!(
        r#"{{"sessionState":"{session_state}","methodResponses":[["error",{problem},"{client_id}"]]}}"#
    ) + "\n"
}

/// Go's method error for a deterministic reducer failure
/// ([`setjoin_jmap::Failure`]); `None` for `Forward`.
pub fn failure_error(
    session_state: &str,
    failure: setjoin_jmap::Failure,
    client_id: &str,
) -> Option<String> {
    use setjoin_jmap::Failure;
    let (kind, status, detail) = match failure {
        Failure::AccountNotFound => (
            "accountNotFound",
            400,
            "accountId does not match an existing account",
        ),
        Failure::CannotCalculateChanges => (
            "cannotCalculateChanges",
            400,
            "client must resync (sinceState too old)",
        ),
        Failure::Forbidden => ("forbidden", 500, "access denied"),
        Failure::ServerFail => ("serverFail", 500, "database error"),
        Failure::Forward => return None,
    };
    Some(method_error(session_state, kind, status, detail, client_id))
}

fn server_fail(detail: &str) -> String {
    format!(
        r#"{{"type":"urn:ietf:params:jmap:error:serverFail","status":500,"detail":"{detail}"}}"#
    )
}

/// Go's `connect-src` drops `http:` when the client used TLS.
pub fn response(body: String, scheme: &str, request_id: String) -> Response<Body> {
    // net/http buffers up to 2 KiB before choosing Content-Length. Larger
    // JSON replies flush as chunked HTTP/1.1 (observable in recorded headers).
    let body = if body.len() > 2048 {
        http_body_util::StreamBody::new(futures_util::stream::iter([Ok::<_, crate::BoxError>(
            hyper::body::Frame::data(Bytes::from(body)),
        )]))
        .boxed()
    } else {
        Full::new(Bytes::from(body)).map_err(|n| match n {}).boxed()
    };
    let mut resp = Response::new(body);
    *resp.status_mut() = StatusCode::OK;
    headers(resp.headers_mut(), scheme, request_id);
    resp
}

fn headers(h: &mut HeaderMap, scheme: &str, request_id: String) {
    security_headers(h, scheme);
    h.insert("cache-control", HeaderValue::from_static("no-store"));
    h.insert("content-type", HeaderValue::from_static("application/json"));
    if let Ok(v) = HeaderValue::from_str(&request_id) {
        h.insert("x-request-id", v);
    }
}

/// Headers from Go's SecurityHeaders middleware, inside the core limiter.
pub(crate) fn security_headers(h: &mut HeaderMap, scheme: &str) {
    let connect = if scheme == "https" {
        "'self' wss: https:"
    } else {
        "'self' wss: https: http:"
    };
    let csp = format!(
        "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; \
         style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; font-src 'self'; \
         connect-src {connect}; media-src 'self' blob: http://127.0.0.1:*; object-src 'self' blob:; \
         base-uri 'self'; form-action 'self'; frame-src 'self'; frame-ancestors 'none';"
    );
    let fixed = [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "strict-origin-when-cross-origin"),
        ("cross-origin-opener-policy", "same-origin"),
        (
            "permissions-policy",
            "camera=(self), microphone=(self), autoplay=(self), geolocation=(), payment=(), \
             usb=(), magnetometer=(), gyroscope=(), accelerometer=()",
        ),
    ];
    for (k, v) in fixed {
        h.insert(k, HeaderValue::from_static(v));
    }
    // Built from static ASCII only, so this never fails; no panic path.
    if let Ok(v) = HeaderValue::from_str(&csp) {
        h.insert("content-security-policy", v);
    }
}

/// Go's `RequestID`: echo a valid inbound `X-Request-ID` (≤ 64 bytes, no
/// control characters or whitespace), else a fresh UUIDv4.
pub fn request_id(inbound: Option<&HeaderValue>, random: [u8; 16]) -> String {
    if let Some(v) = inbound.map(HeaderValue::as_bytes) {
        if !v.is_empty() && v.len() <= 64 && v.iter().all(|b| *b > 32 && *b != 127) {
            if let Ok(s) = std::str::from_utf8(v) {
                return s.to_owned();
            }
        }
    }
    let mut b = random;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h: Vec<String> = b.iter().map(|x| format!("{x:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        h[0..4].concat(),
        h[4..6].concat(),
        h[6..8].concat(),
        h[8..10].concat(),
        h[10..16].concat()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Review item 6: the expected bytes are REAL Go output, captured from
    /// mailserverd's `emailSet` on the real stack (rp07 review-fix kit,
    /// `capture.sh`: account 1, HS256 token, same request bodies the webmail
    /// sends) and committed under `tests/golden/`. The inputs are the values
    /// that capture ran with.
    #[test]
    fn bodies_equal_captured_go_output() {
        const S0: &str = "69-0-0-69-0-0-0-1793295569";
        const S1: &str = "70-0-0-69-0-0-0-1793295569";
        let cases = [
            (
                body(
                    S0,
                    1,
                    11,
                    "0",
                    Outcome::Updated {
                        old_state: 69,
                        new_state: 70,
                    },
                ),
                include_str!("../../tests/golden/go-set-updated.json"),
            ),
            (
                body(
                    S1,
                    1,
                    11,
                    "0",
                    Outcome::Updated {
                        old_state: 70,
                        new_state: 70,
                    },
                ),
                include_str!("../../tests/golden/go-set-unchanged.json"),
            ),
            (
                body(S1, 1, 999_999_999, "0", Outcome::NotFound { state: 70 }),
                include_str!("../../tests/golden/go-set-notfound.json"),
            ),
            (
                // The reducer's notUpdated entry, as PostgreSQL prints the JSONB.
                body(
                    S1,
                    1,
                    13,
                    "0",
                    Outcome::NotUpdated {
                        state: 70,
                        set_error: r#"{"type": "invalidArguments", "description": "Update failed"}"#,
                    },
                ),
                include_str!("../../tests/golden/go-set-invalid.json"),
            ),
            (
                body(S1, 1, 12, "0", Outcome::Failed),
                include_str!("../../tests/golden/go-set-fail.json"),
            ),
        ];
        for (rust, go) in cases {
            assert_eq!(rust, go);
        }
    }

    /// Go's `json.Encoder` compacts a `json.RawMessage` and HTML-escapes it
    /// (`<`, `>`, `&`, U+2028, U+2029 → `\u003c` …); escapes already in the
    /// text and key order are kept.
    #[test]
    fn raw_entries_are_compacted_as_go_compacts_them() {
        assert_eq!(
            go_compact(r#"{"type": "x", "description": "a <b> & \"c\"   d"}"#).as_deref(),
            Some(r#"{"type":"x","description":"a \u003cb\u003e \u0026 \"c\"   d"}"#)
        );
        assert_eq!(
            go_compact("{\"d\": \"line\u{2028}sep\"}").as_deref(),
            Some(r#"{"d":"line\u2028sep"}"#)
        );
        assert_eq!(go_compact("{not json"), None);
    }

    #[test]
    fn request_ids_follow_go() {
        assert_eq!(
            request_id(Some(&HeaderValue::from_static("abc-1")), [0; 16]),
            "abc-1"
        );
        assert_eq!(
            request_id(Some(&HeaderValue::from_static("has space")), [0xff; 16]),
            "ffffffff-ffff-4fff-bfff-ffffffffffff"
        );
    }
}
