//! The loopback-only, bearer-authenticated control HTTP surface the gateway's
//! `CaptionsController` drives (Go `bot.Server`), with `net/http` ServeMux
//! behaviour reproduced where a client can observe it.

use crate::gojson;
use crate::registry::RoomRegistry;
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::body::Incoming;
use hyper::header::{HeaderValue, ALLOW, AUTHORIZATION, CONTENT_TYPE, LOCATION};
use hyper::{Method, Request, Response, StatusCode};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use subtle::ConstantTimeEq;

/// Bounds every decoded body (`maxControlBodyBytes` in Go's main).
pub const MAX_CONTROL_BODY_BYTES: usize = 8 << 10;
const READ_TIMEOUT: Duration = Duration::from_secs(10);

pub struct Server {
    rooms: Arc<RoomRegistry>,
    token: String,
}

type Resp = Response<BoxBody<Bytes, std::convert::Infallible>>;

fn full(bytes: Bytes) -> BoxBody<Bytes, std::convert::Infallible> {
    Full::new(bytes).boxed()
}

impl Server {
    pub fn new(rooms: Arc<RoomRegistry>, token: String) -> Self {
        Self { rooms, token }
    }

    pub async fn handle(&self, req: Request<Incoming>) -> Resp {
        let (parts, body) = req.into_parts();
        let (method, raw_path, query) = (
            parts.method,
            parts.uri.path().to_owned(),
            parts.uri.query().map(str::to_owned),
        );
        let auth = parts
            .headers
            .get(AUTHORIZATION)
            .map(|v| v.as_bytes().to_vec());
        self.route(
            &method,
            &raw_path,
            query.as_deref(),
            auth.as_deref(),
            async move { read_limited(body).await },
        )
        .await
    }

    /// Transport-free dispatch: ServeMux semantics, then `requireAuth`, then the handler.
    pub async fn route<F>(
        &self,
        method: &Method,
        raw_path: &str,
        query: Option<&str>,
        auth: Option<&[u8]>,
        body: F,
    ) -> Resp
    where
        F: std::future::Future<Output = Option<Vec<u8>>>,
    {
        let cleaned = clean_path(raw_path);
        if cleaned != raw_path {
            return redirect(method, &cleaned, query);
        }
        let Some(path) = unescape_path(raw_path) else {
            return bad_request_close();
        };
        let (allowed, handler): (&[Method], Handler) = match path.as_str() {
            "/start" => (&[Method::POST], Handler::Start),
            "/stop" => (&[Method::POST], Handler::Stop),
            "/status" => (&[Method::GET, Method::HEAD], Handler::Status),
            "/healthz" => (&[Method::GET, Method::HEAD], Handler::Healthz),
            _ => return text(StatusCode::NOT_FOUND, "404 page not found\n"),
        };
        if !allowed.contains(method) {
            let allow = allowed
                .iter()
                .map(Method::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            let mut resp = text(StatusCode::METHOD_NOT_ALLOWED, "Method Not Allowed\n");
            resp.headers_mut()
                .insert(ALLOW, HeaderValue::from_str(&allow).expect("static"));
            return resp;
        }
        if !matches!(handler, Handler::Healthz) && !self.authorized(auth) {
            return json(
                StatusCode::UNAUTHORIZED,
                "{\"error\":\"unauthorized\"}\n".into(),
            );
        }
        match handler {
            Handler::Healthz => Response::new(full(Bytes::new())),
            Handler::Status => {
                let rooms: Vec<String> = self
                    .rooms
                    .rooms()
                    .iter()
                    .map(|r| gojson::encode_string(r))
                    .collect();
                json(
                    StatusCode::OK,
                    format!("{{\"rooms\":[{}]}}\n", rooms.join(",")),
                )
            }
            Handler::Start => {
                let fields = decode(body.await, &["room", "token"]);
                let Some((room, token)) =
                    fields.and_then(|mut f| Some((f.remove(0)?, f.remove(0)?)))
                else {
                    return json(
                        StatusCode::BAD_REQUEST,
                        "{\"error\":\"bad_request\"}\n".into(),
                    );
                };
                if room.is_empty() || token.is_empty() {
                    return json(
                        StatusCode::BAD_REQUEST,
                        "{\"error\":\"bad_request\"}\n".into(),
                    );
                }
                if !self.rooms.start(&room, &token) {
                    return json(StatusCode::CONFLICT, "{\"error\":\"busy\"}\n".into());
                }
                json(StatusCode::OK, "{}\n".into())
            }
            Handler::Stop => {
                let room = decode(body.await, &["room"])
                    .and_then(|mut f| f.remove(0))
                    .filter(|r| !r.is_empty());
                let Some(room) = room else {
                    return json(
                        StatusCode::BAD_REQUEST,
                        "{\"error\":\"bad_request\"}\n".into(),
                    );
                };
                // Idempotent (F17): a room that was never started or already ended is a no-op.
                self.rooms.stop(&room);
                json(StatusCode::OK, "{}\n".into())
            }
        }
    }

    /// `strings.TrimPrefix(header, "Bearer ")` then a constant-time compare (ring).
    fn authorized(&self, header: Option<&[u8]>) -> bool {
        let header = header.unwrap_or_default();
        let got = header.strip_prefix(b"Bearer ").unwrap_or(header);
        !got.is_empty() && bool::from(got.ct_eq(self.token.as_bytes()))
    }
}

#[derive(Clone, Copy)]
enum Handler {
    Start,
    Stop,
    Status,
    Healthz,
}

fn decode(body: Option<Vec<u8>>, fields: &[&str]) -> Option<Vec<Option<String>>> {
    gojson::decode_string_fields(&body?, fields).ok()
}

/// Read at most `MAX_CONTROL_BODY_BYTES` of the body within the read timeout;
/// `None` is an unreadable body (Go's decoder then fails the same way).
async fn read_limited(mut body: Incoming) -> Option<Vec<u8>> {
    let read = async {
        let mut out: Vec<u8> = Vec::new();
        while out.len() < MAX_CONTROL_BODY_BYTES {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        out.extend_from_slice(&data);
                    }
                }
                Some(Err(_)) => return None,
                None => break,
            }
        }
        // Go's decoder only ever sees the first limit bytes.
        out.truncate(MAX_CONTROL_BODY_BYTES);
        Some(out)
    };
    tokio::time::timeout(READ_TIMEOUT, read)
        .await
        .ok()
        .flatten()
}

fn json(status: StatusCode, body: String) -> Resp {
    let mut resp = Response::new(full(Bytes::from(body)));
    *resp.status_mut() = status;
    resp.headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    resp
}

fn text(status: StatusCode, body: &'static str) -> Resp {
    let mut resp = Response::new(full(Bytes::from_static(body.as_bytes())));
    *resp.status_mut() = status;
    let headers = resp.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    resp
}

/// The server's own malformed-request answer (not a handler's): close-delimited, no length.
fn bad_request_close() -> Resp {
    let body = futures_util::stream::once(async {
        Ok::<_, std::convert::Infallible>(hyper::body::Frame::data(Bytes::from_static(
            b"400 Bad Request",
        )))
    });
    let mut resp = Response::new(StreamBody::new(body).boxed());
    *resp.status_mut() = StatusCode::BAD_REQUEST;
    let headers = resp.headers_mut();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(hyper::header::CONNECTION, HeaderValue::from_static("close"));
    resp
}

/// `http.Redirect` as ServeMux uses it for a non-canonical path (307).
fn redirect(method: &Method, cleaned: &str, query: Option<&str>) -> Resp {
    let mut location = escape_path(cleaned);
    if let Some(q) = query {
        location.push('?');
        location.push_str(q);
    }
    let get = method == Method::GET;
    let body = if get {
        Bytes::from(format!(
            "<a href=\"{}\">Temporary Redirect</a>.\n\n",
            html_escape(&location)
        ))
    } else {
        Bytes::new()
    };
    let mut resp = Response::new(full(body));
    *resp.status_mut() = StatusCode::TEMPORARY_REDIRECT;
    resp.headers_mut().insert(
        LOCATION,
        HeaderValue::from_str(&location).unwrap_or(HeaderValue::from_static("/")),
    );
    if get || method == Method::HEAD {
        resp.headers_mut().insert(
            CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
    }
    resp
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('\'', "&#39;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
}

/// `net/http.cleanPath`: `path.Clean` keeping a trailing slash.
pub fn clean_path(p: &str) -> String {
    if p.is_empty() {
        return "/".into();
    }
    let p = if p.starts_with('/') {
        p.to_owned()
    } else {
        format!("/{p}")
    };
    let mut stack: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            s => stack.push(s),
        }
    }
    let mut np = format!("/{}", stack.join("/"));
    if p.ends_with('/') && np != "/" {
        if p.len() == np.len() + 1 && p.starts_with(&np) {
            np = p;
        } else {
            np.push('/');
        }
    }
    np
}

fn unescape_path(p: &str) -> Option<String> {
    let bytes = p.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// `url.URL.EscapedPath` for a decoded path (RFC 3986 path characters kept).
fn escape_path(p: &str) -> String {
    let mut out = String::new();
    for b in p.bytes() {
        match b {
            b'A'..=b'Z'
            | b'a'..=b'z'
            | b'0'..=b'9'
            | b'-'
            | b'_'
            | b'.'
            | b'~'
            | b'/'
            | b':'
            | b'@'
            | b'&'
            | b'='
            | b'+'
            | b'$'
            | b','
            | b';'
            | b'!'
            | b'*'
            | b'\''
            | b'('
            | b')'
            | b'%' => out.push(b as char),
            b => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Refuse any listen address that is not explicitly loopback (`bot.ValidateLoopback`).
pub fn validate_loopback(addr: &str) -> Result<(), String> {
    let (host, _port) =
        split_host_port(addr).map_err(|e| format!("invalid listen address {addr:?}: {e}"))?;
    if host.is_empty() {
        return Err(format!("listen address {addr:?} has no host \u{2014} binds all interfaces, refused (loopback-only)"));
    }
    if host == "localhost" {
        return Ok(());
    }
    let ip: IpAddr = parse_ip(&host).ok_or_else(|| {
        format!("listen address {addr:?}: host {host:?} is not an IP or \"localhost\"")
    })?;
    let loopback = match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    };
    if !loopback {
        return Err(format!("listen address {addr:?} refused \u{2014} must bind loopback only (127.0.0.1/::1/localhost), got host {host:?}"));
    }
    Ok(())
}

/// Go's `net.ParseIP` accepts exactly what `IpAddr` parses, minus IPv6 zones.
fn parse_ip(host: &str) -> Option<IpAddr> {
    host.parse().ok()
}

/// `net.SplitHostPort` with Go's error texts (`address <addr>: <why>`).
fn split_host_port(hostport: &str) -> Result<(String, String), String> {
    let err = |why: &str| format!("address {hostport}: {why}");
    let bytes = hostport.as_bytes();
    let i = hostport
        .rfind(':')
        .ok_or_else(|| err("missing port in address"))?;
    let (host, mut j, mut k) = if bytes[0] == b'[' {
        let end = hostport
            .find(']')
            .ok_or_else(|| err("missing ']' in address"))?;
        if end + 1 == hostport.len() {
            return Err(err("missing port in address"));
        } else if end + 1 != i {
            return Err(err(if bytes[end + 1] == b':' {
                "too many colons in address"
            } else {
                "missing port in address"
            }));
        }
        (&hostport[1..end], 1, end + 1)
    } else {
        let host = &hostport[..i];
        if host.contains(':') {
            return Err(err("too many colons in address"));
        }
        (host, 0, 0)
    };
    j = j.min(hostport.len());
    k = k.min(hostport.len());
    if hostport[j..].contains('[') {
        return Err(err("unexpected '[' in address"));
    }
    if hostport[k..].contains(']') {
        return Err(err("unexpected ']' in address"));
    }
    Ok((host.to_owned(), hostport[i + 1..].to_owned()))
}

/// `bot.ValidateToken`.
pub fn validate_token(token: &str) -> Result<(), String> {
    if token.is_empty() {
        return Err("ASR_TOKEN is required \u{2014} loopback TCP carries no peer identity, refusing to serve an unauthenticated captions control API".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_path_matches_go() {
        for (input, want) in [
            ("", "/"),
            ("/", "/"),
            ("/status", "/status"),
            ("//status", "/status"),
            ("/a/../status", "/status"),
            ("/./status", "/status"),
            ("/status/", "/status/"),
            ("/status//", "/status/"),
            ("/a/b/..", "/a"),
            ("/a/b/../", "/a/"),
            ("/../..", "/"),
        ] {
            assert_eq!(clean_path(input), want, "{input:?}");
        }
    }

    #[test]
    fn loopback_validation_mirrors_go() {
        for ok in [
            "127.0.0.1:7890",
            "[::1]:7890",
            "localhost:1",
            "127.5.5.5:9",
            "[::ffff:127.0.0.1]:9",
        ] {
            assert!(validate_loopback(ok).is_ok(), "{ok}");
        }
        for bad in [
            ":7890",
            "0.0.0.0:7890",
            "[::]:7890",
            "10.0.0.1:7890",
            "example.com:80",
            "127.0.0.1",
            "[fe80::1%eth0]:1",
        ] {
            assert!(validate_loopback(bad).is_err(), "{bad}");
        }
        assert_eq!(
            validate_loopback("0.0.0.0:7890").unwrap_err(),
            "listen address \"0.0.0.0:7890\" refused \u{2014} must bind loopback only (127.0.0.1/::1/localhost), got host \"0.0.0.0\""
        );
        assert_eq!(
            validate_loopback("127.0.0.1").unwrap_err(),
            "invalid listen address \"127.0.0.1\": address 127.0.0.1: missing port in address"
        );
    }

    #[test]
    fn empty_token_is_refused() {
        assert!(validate_token("").is_err());
        assert!(validate_token("x").is_ok());
    }
}
