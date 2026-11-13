//! F13 `/rtc` and `/rtc/`: the reverse proxy to the LiveKit SFU's signal port
//! (#410). Frozen Go registers `httputil.ReverseProxy` with a `Rewrite` on
//! both patterns when LiveKit is configured, outside `requireAuth` (LiveKit
//! validates its own access token on the signal WebSocket), pointed at the
//! fixed loopback address `127.0.0.1:7880`. This module reproduces that proxy:
//!
//! - `Rewrite`: scheme/host fixed, the single `/rtc` mount prefix stripped from
//!   the decoded path (re-escaped like `url.URL.EscapedPath`), `Forwarded` and
//!   `X-Forwarded-*` replaced by `SetXForwarded`.
//! - `ReverseProxy`: hop-by-hop headers dropped, an upgrade re-added, no `User-Agent` invented, `Accept-Encoding: gzip` added by
//!   Go's transport (and the gzip answer transparently decoded) when the
//!   client sent neither `Accept-Encoding` nor `Range`.
//! - Failures: a dial or protocol error answers an empty 502.
//! - A `101` is tunnelled; either side ending closes both.
//!
//! Go's global middleware wraps the answer (`SecurityHeaders`, the single
//! `Cache-Control` authority, `X-Request-ID`) and its `ServeMux` redirects an
//! unclean path with `307` before any handler runs. Go's guest belt only sees a
//! request carrying a JWT credential: such a request is proxied natively only
//! when the verified-member precheck admits it, otherwise it stays with Go.
//! Without LiveKit configuration Go registers no `/rtc` handler and the SPA
//! fallback answers, so the request goes to Go.
use crate::{Body, BoxFuture, Intercept, RequestContext};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{HeaderMap, HeaderName, HeaderValue, CONNECTION, UPGRADE};
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::client::legacy::{connect::HttpConnector, Client};
use hyper_util::rt::{TokioExecutor, TokioIo};
use setjoin_authz::token::KeySource;
use setjoin_pg::ScopedExecutor;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// Go's hard-coded SFU signal address.
pub const SFU_SIGNAL: &str = "127.0.0.1:7880";

const HOP_BY_HOP: [&str; 8] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
];

pub struct RtcRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    configured: bool,
    upstream: SocketAddr,
    client: Client<HttpConnector, Body>,
}

impl<K: KeySource + 'static> RtcRoute<K> {
    /// `configured` is Go's `meetCfg.Configured()`; `upstream` is
    /// [`SFU_SIGNAL`] in production.
    pub fn new(
        exec: ScopedExecutor,
        keys: Arc<K>,
        issuer: String,
        configured: bool,
        upstream: SocketAddr,
    ) -> Self {
        let mut connector = HttpConnector::new();
        // net/http's DefaultTransport dial timeout.
        connector.set_connect_timeout(Some(Duration::from_secs(30)));
        connector.set_nodelay(true);
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .build(connector);
        Self {
            exec,
            keys,
            issuer,
            configured,
            upstream,
            client,
        }
    }
}

fn is_rtc(path: &str) -> bool {
    path == "/rtc" || path.starts_with("/rtc/")
}

fn carries_jwt(headers: &HeaderMap) -> bool {
    if headers
        .get(hyper::header::AUTHORIZATION)
        .is_some_and(|v| v.as_bytes().starts_with(b"Bearer "))
    {
        return true;
    }
    headers
        .get_all(hyper::header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .any(|pair| {
            pair.trim()
                .split_once('=')
                .is_some_and(|(n, v)| n == "access_token" && !v.is_empty())
        })
}

impl<K: KeySource + 'static> Intercept for RtcRoute<K> {
    fn matches(&self, req: &Request<Body>) -> bool {
        is_rtc(req.uri().path())
    }

    fn handle(&self, req: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        let (configured, upstream, client) = (self.configured, self.upstream, self.client.clone());
        Box::pin(async move {
            if !configured {
                return c.upstream.forward(req, &c.identity).await;
            }
            if carries_jwt(req.headers())
                && setjoin_authz::authorize_user_request(
                    &exec,
                    &keys,
                    &issuer,
                    req.headers(),
                    c.identity.proto,
                )
                .await
                .is_none()
            {
                return c.upstream.forward(req, &c.identity).await;
            }
            let id = crate::jmap::reply::request_id(
                req.headers().get("x-request-id"),
                crate::jmap::random().unwrap_or([0; 16]),
            );
            serve(req, &c, id, upstream, &client).await
        })
    }
}

/// Go's middleware envelope: `SecurityHeaders`, `Cache-Control: no-store` (the
/// policy table's default for this path) and `X-Request-ID`.
fn envelope(c: &RequestContext, id: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    crate::jmap::reply::security_headers(&mut h, c.identity.proto);
    h.insert("cache-control", HeaderValue::from_static("no-store"));
    if let Ok(v) = HeaderValue::from_str(id) {
        h.insert("x-request-id", v);
    }
    h
}

fn empty(status: StatusCode, mut headers: HeaderMap) -> Response<Body> {
    let mut resp = Response::new(Full::new(Bytes::new()).map_err(|n| match n {}).boxed());
    *resp.status_mut() = status;
    std::mem::swap(resp.headers_mut(), &mut headers);
    resp
}

async fn serve(
    mut req: Request<Body>,
    c: &RequestContext,
    id: String,
    upstream: SocketAddr,
    client: &Client<HttpConnector, Body>,
) -> Response<Body> {
    let headers = envelope(c, &id);
    let raw_path = req.uri().path().to_owned();
    let Some(decoded) = unescape(&raw_path) else {
        // Go rejects a malformed escape while parsing the request line.
        return empty(StatusCode::BAD_REQUEST, HeaderMap::new());
    };
    let cleaned = clean_path(&decoded);
    if cleaned != decoded && req.method() != Method::CONNECT {
        return redirect(req.method(), &cleaned, req.uri().query(), headers);
    }
    let out_path = match decoded.strip_prefix("/rtc") {
        Some("") | None => "/".to_owned(),
        Some(rest) => rest.to_owned(),
    };
    let mut target = escape_path(&out_path);
    if let Some(q) = req.uri().query() {
        target.push('?');
        target.push_str(q);
    }
    let uri: Uri = match format!("http://{upstream}{target}").parse() {
        Ok(u) => u,
        Err(_) => return empty(StatusCode::BAD_GATEWAY, headers),
    };

    let upgrade = upgrade_type(req.headers());
    let client_upgrade = upgrade.as_ref().map(|_| hyper::upgrade::on(&mut req));
    let host = req.headers().get(hyper::header::HOST).cloned();
    let method = req.method().clone();
    let (mut parts, body) = req.into_parts();
    let h = &mut parts.headers;
    // Rewrite: client forwarding headers are replaced by SetXForwarded.
    for name in [
        "forwarded",
        "x-forwarded-for",
        "x-forwarded-host",
        "x-forwarded-proto",
    ] {
        h.remove(name);
    }
    if let Ok(v) = HeaderValue::from_str(&c.identity.client_ip.to_string()) {
        h.insert("x-forwarded-for", v);
    }
    if let Some(host) = host {
        h.insert("x-forwarded-host", host);
    }
    h.insert(
        "x-forwarded-proto",
        HeaderValue::from_static(c.identity.proto),
    );
    // The front door drops `Te` before Go sees it, so `Te: trailers` is never
    // re-added upstream (the recorded oracle runs behind the same gateway).
    strip_hop_by_hop(h);
    if let Some(proto) = &upgrade {
        h.insert(CONNECTION, HeaderValue::from_static("Upgrade"));
        h.insert(UPGRADE, proto.clone());
    }
    h.remove(hyper::header::HOST);
    // net/http's Transport asks for gzip itself and decodes the answer.
    let own_gzip =
        !h.contains_key("accept-encoding") && !h.contains_key("range") && method != Method::HEAD;
    if own_gzip {
        h.insert("accept-encoding", HeaderValue::from_static("gzip"));
    }
    parts.uri = uri;
    parts.version = hyper::Version::HTTP_11;
    parts.extensions = Default::default();

    let mut resp = match client.request(Request::from_parts(parts, body)).await {
        Ok(resp) => resp,
        Err(_) => return empty(StatusCode::BAD_GATEWAY, headers),
    };

    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        let answered = upgrade_type(resp.headers());
        let (Some(wanted), Some(got), Some(client_upgrade)) =
            (upgrade.as_ref(), answered, client_upgrade)
        else {
            return empty(StatusCode::BAD_GATEWAY, headers);
        };
        if !wanted.as_bytes().eq_ignore_ascii_case(got.as_bytes()) {
            return empty(StatusCode::BAD_GATEWAY, headers);
        }
        let upstream_upgrade = hyper::upgrade::on(&mut resp);
        tokio::spawn(async move {
            let (Ok(client), Ok(server)) = (client_upgrade.await, upstream_upgrade.await) else {
                return;
            };
            tunnel(TokioIo::new(client), TokioIo::new(server)).await;
        });
        let (parts, _) = resp.into_parts();
        // Go hijacks the connection: its Cache-Control stamp (first write) never
        // happens. The front door re-emits the pair in lower case.
        let mut out = headers;
        out.remove("cache-control");
        for (k, v) in &parts.headers {
            if k == CONNECTION {
                continue;
            }
            out.append(k.clone(), v.clone());
        }
        out.insert(CONNECTION, HeaderValue::from_static("upgrade"));
        return empty(StatusCode::SWITCHING_PROTOCOLS, out);
    }

    let (mut parts, body) = resp.into_parts();
    let gunzip = own_gzip
        && parts
            .headers
            .get("content-encoding")
            .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"gzip"));
    strip_hop_by_hop(&mut parts.headers);
    let mut out = headers;
    for (k, v) in &parts.headers {
        if k == "cache-control" || (gunzip && (k == "content-encoding" || k == "content-length")) {
            continue;
        }
        out.append(k.clone(), v.clone());
    }
    let body: Body = if gunzip {
        match body.collect().await {
            Ok(all) => {
                use std::io::Read;
                let mut decoded = Vec::new();
                let _ = flate2::read::GzDecoder::new(&all.to_bytes()[..]).read_to_end(&mut decoded);
                Full::new(Bytes::from(decoded))
                    .map_err(|n| match n {})
                    .boxed()
            }
            Err(_) => return empty(StatusCode::BAD_GATEWAY, out),
        }
    } else {
        body.map_err(Into::into).boxed()
    };
    let mut resp = Response::new(body);
    *resp.status_mut() = parts.status;
    *resp.headers_mut() = out;
    resp
}

/// Copies both ways; the first side to finish closes both, as Go's
/// `handleUpgradeResponse` does.
async fn tunnel<A, B>(a: A, b: B)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{copy, split, AsyncWriteExt};
    let ((mut ar, mut aw), (mut br, mut bw)) = (split(a), split(b));
    tokio::select! {
        _ = copy(&mut ar, &mut bw) => {}
        _ = copy(&mut br, &mut aw) => {}
    }
    let _ = aw.shutdown().await;
    let _ = bw.shutdown().await;
}

fn upgrade_type(headers: &HeaderMap) -> Option<HeaderValue> {
    let wants = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .any(|t| t.trim().eq_ignore_ascii_case("upgrade"));
    wants.then(|| headers.get(UPGRADE).cloned()).flatten()
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|t| HeaderName::from_bytes(t.trim().as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
    headers.remove(UPGRADE);
}

/// `http.Redirect` as `ServeMux` uses it for a non-canonical path.
fn redirect(
    method: &Method,
    cleaned: &str,
    query: Option<&str>,
    mut headers: HeaderMap,
) -> Response<Body> {
    let mut location = escape_path(cleaned);
    if let Some(q) = query {
        location.push('?');
        location.push_str(q);
    }
    let get = method == Method::GET;
    let body = if get {
        let escaped = location
            .replace('&', "&amp;")
            .replace('\'', "&#39;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
            .replace('"', "&#34;");
        Bytes::from(format!("<a href=\"{escaped}\">Temporary Redirect</a>.\n\n"))
    } else {
        Bytes::new()
    };
    if let Ok(v) = HeaderValue::from_str(&location) {
        headers.insert(hyper::header::LOCATION, v);
    }
    if get || method == Method::HEAD {
        headers.insert(
            hyper::header::CONTENT_TYPE,
            HeaderValue::from_static("text/html; charset=utf-8"),
        );
    }
    let mut resp = Response::new(Full::new(body).map_err(|n| match n {}).boxed());
    *resp.status_mut() = StatusCode::TEMPORARY_REDIRECT;
    *resp.headers_mut() = headers;
    resp
}

/// `net/http.cleanPath`: `path.Clean` keeping a trailing slash.
fn clean_path(p: &str) -> String {
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
        np.push('/');
    }
    np
}

/// `url.PathUnescape` over the request path: `None` on a malformed escape.
fn unescape(p: &str) -> Option<String> {
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

/// `url.URL.EscapedPath` of a decoded path with no `RawPath`.
fn escape_path(p: &str) -> String {
    if p == "*" {
        return "*".into();
    }
    let mut out = String::with_capacity(p.len());
    for b in p.bytes() {
        let keep = b.is_ascii_alphanumeric()
            || matches!(
                b,
                b'-' | b'_'
                    | b'.'
                    | b'~'
                    | b'$'
                    | b'&'
                    | b'+'
                    | b','
                    | b'/'
                    | b':'
                    | b';'
                    | b'='
                    | b'@'
            );
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mount_prefix_and_escaping_follow_go() {
        assert_eq!(escape_path("/a b/é?x"), "/a%20b/%C3%A9%3Fx");
        assert_eq!(escape_path("/v1/!*'()"), "/v1/%21%2A%27%28%29");
        assert_eq!(clean_path("/rtc//x/./y/../z/"), "/rtc/x/z/");
        assert_eq!(clean_path("/rtc/.."), "/");
        assert_eq!(unescape("/rtc/a%2Fb").as_deref(), Some("/rtc/a/b"));
        assert_eq!(unescape("/rtc/%zz"), None);
    }
}
