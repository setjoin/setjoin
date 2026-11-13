//! Reverse proxy to the Go upstream.
//!
//! End-to-end request and response parts (method, path, query, `Host`,
//! headers, body, status) pass through unchanged; bodies stream in both
//! directions without buffering. Hop-by-hop headers (RFC 9110 §7.6.1) are
//! dropped, as Go's `httputil.ReverseProxy` does, and the client identity
//! headers are replaced per [`crate::forwarded`]. A `Connection: upgrade`
//! request (WebSocket `GET /jmap/ws`) keeps its `Upgrade` header and, on a
//! `101` from Go, both connections are joined into a byte tunnel.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{HeaderMap, HeaderName, HeaderValue, CONNECTION, UPGRADE};
use hyper::{Request, Response, StatusCode, Uri, Version};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo};

use crate::forwarded::{self, ClientIdentity};
use crate::Body;

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

/// Go's own `WriteTimeout` on its plain HTTP listeners: no Go response can
/// take longer to start, so waiting past it only holds the client.
pub const DEFAULT_HEADER_TIMEOUT: Duration = Duration::from_secs(120);

/// Handle to the Go upstream; cheap to clone.
#[derive(Clone)]
pub struct Upstream {
    base: Option<Uri>,
    client: Client<HttpConnector, Body>,
    header_timeout: Duration,
    go_counter: Option<(std::sync::Arc<crate::metrics::GoProxies>, usize)>,
}

impl Upstream {
    /// `base` must be an absolute `http://host:port` URI with no path.
    pub fn new(base: Uri) -> Result<Self, String> {
        if base.scheme_str() != Some("http") || base.authority().is_none() {
            return Err(format!("upstream must be http://host:port, got {base}"));
        }
        if !matches!(base.path(), "" | "/") || base.query().is_some() {
            return Err(format!(
                "upstream must not carry a path or query, got {base}"
            ));
        }
        Ok(Self::with_base(Some(base)))
    }

    /// Disable proxying: a declined or unclaimed request gets a 502.
    pub fn disabled() -> Self {
        Self::with_base(None)
    }

    fn with_base(base: Option<Uri>) -> Self {
        let mut connector = HttpConnector::new();
        connector.set_connect_timeout(Some(Duration::from_secs(10)));
        connector.set_nodelay(true);
        // The upstream is a fixed internal address: no environment proxy.
        let client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(90))
            .build(connector);
        Self {
            base,
            client,
            header_timeout: DEFAULT_HEADER_TIMEOUT,
            go_counter: None,
        }
    }

    /// Bound on waiting for Go's response headers (then `504`).
    pub fn with_header_timeout(mut self, timeout: Duration) -> Self {
        self.header_timeout = timeout;
        self
    }

    /// Attach this request's Go attribution; clones share the HTTP pool.
    pub(crate) fn with_go_counter(
        mut self,
        counters: std::sync::Arc<crate::metrics::GoProxies>,
        family: usize,
    ) -> Self {
        self.go_counter = Some((counters, family));
        self
    }

    /// Application-frame handoff for an unported JMAP command batch. The
    /// destination is deployment configuration, never a client-provided URL.
    pub(crate) fn unported_push_target(&self) -> Option<(Uri, Duration)> {
        if let Some((counters, family)) = &self.go_counter {
            counters.increment(*family);
        }
        Some((self.base.clone()?, self.header_timeout))
    }

    /// Forwards `req` to Go and returns Go's response (502 if Go is
    /// unreachable). Never partially answers a request itself.
    pub async fn forward(&self, mut req: Request<Body>, id: &ClientIdentity) -> Response<Body> {
        if let Some((counters, family)) = &self.go_counter {
            counters.increment(*family);
        }
        let Some(base) = &self.base else {
            return status(StatusCode::BAD_GATEWAY, "bad gateway\n");
        };
        let upgrade = upgrade_protocol(req.headers());
        let client_upgrade = upgrade.as_ref().map(|_| hyper::upgrade::on(&mut req));

        let (mut parts, body) = req.into_parts();
        strip_hop_by_hop(&mut parts.headers);
        forwarded::apply(&mut parts.headers, id);
        if let Some(proto) = &upgrade {
            parts
                .headers
                .insert(CONNECTION, HeaderValue::from_static("upgrade"));
            parts.headers.insert(UPGRADE, proto.clone());
        }
        let path = parts.uri.path_and_query().map_or("/", |p| p.as_str());
        parts.uri = match format!("{}{}", base.to_string().trim_end_matches('/'), path).parse() {
            Ok(uri) => uri,
            Err(_) => return status(StatusCode::BAD_REQUEST, "bad request target\n"),
        };
        parts.version = Version::HTTP_11;
        parts.extensions = Default::default();

        let pending = self.client.request(Request::from_parts(parts, body));
        let mut resp = match tokio::time::timeout(self.header_timeout, pending).await {
            Ok(Ok(resp)) => resp,
            Err(_) => {
                eprintln!(
                    "setjoin-gateway: upstream sent no response headers within {:?}",
                    self.header_timeout
                );
                return status(StatusCode::GATEWAY_TIMEOUT, "gateway timeout\n");
            }
            Ok(Err(err)) => {
                eprintln!("setjoin-gateway: upstream request failed: {err}");
                return status(StatusCode::BAD_GATEWAY, "bad gateway\n");
            }
        };

        let switching = resp.status() == StatusCode::SWITCHING_PROTOCOLS;
        let resp_upgrade = resp.headers().get(UPGRADE).cloned();
        strip_hop_by_hop(resp.headers_mut());
        if switching {
            let (Some(client_upgrade), Some(proto)) = (client_upgrade, resp_upgrade) else {
                // A 101 we did not ask for cannot be tunnelled safely.
                return status(StatusCode::BAD_GATEWAY, "bad gateway\n");
            };
            let upstream_upgrade = hyper::upgrade::on(&mut resp);
            tokio::spawn(async move {
                let (Ok(client), Ok(upstream)) = (client_upgrade.await, upstream_upgrade.await)
                else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(
                    &mut TokioIo::new(client),
                    &mut TokioIo::new(upstream),
                )
                .await;
            });
            resp.headers_mut()
                .insert(CONNECTION, HeaderValue::from_static("upgrade"));
            resp.headers_mut().insert(UPGRADE, proto);
        }
        resp.map(|b| committed_body(b.map_err(Into::into).boxed()))
    }
}

pub(crate) fn committed_body(body: Body) -> Body {
    CommitHeaders {
        body,
        yielded: false,
    }
    .boxed()
}

// A ready body error must not discard a head already committed by Go.
// Yield once so Hyper flushes that head before polling a failed byte stream.
struct CommitHeaders {
    body: Body,
    yielded: bool,
}
impl hyper::body::Body for CommitHeaders {
    type Data = bytes::Bytes;
    type Error = crate::BoxError;
    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if !this.yielded {
            this.yielded = true;
            cx.waker().wake_by_ref();
            return std::task::Poll::Pending;
        }
        std::pin::Pin::new(&mut this.body).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.body.size_hint()
    }
}

/// The requested upgrade protocol, when `Connection` names `upgrade`.
fn upgrade_protocol(headers: &HeaderMap) -> Option<HeaderValue> {
    let wants = connection_tokens(headers).any(|t| t.eq_ignore_ascii_case("upgrade"));
    wants.then(|| headers.get(UPGRADE).cloned()).flatten()
}

fn connection_tokens(headers: &HeaderMap) -> impl Iterator<Item = &str> {
    headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|t| !t.is_empty())
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let named: Vec<HeaderName> = connection_tokens(headers)
        .filter_map(|t| HeaderName::from_bytes(t.as_bytes()).ok())
        .collect();
    for name in named {
        headers.remove(name);
    }
    for name in HOP_BY_HOP {
        headers.remove(name);
    }
    headers.remove(UPGRADE);
}

pub(crate) fn status(code: StatusCode, msg: &'static str) -> Response<Body> {
    let mut resp = Response::new(
        Full::new(Bytes::from_static(msg.as_bytes()))
            .map_err(|n| match n {})
            .boxed(),
    );
    *resp.status_mut() = code;
    resp.headers_mut().insert(
        "content-type",
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}
