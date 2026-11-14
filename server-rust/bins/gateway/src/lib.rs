//! `setjoin-gateway` — the Rust front door (#220, ARCH-027).
//!
//! The reviewed [`inventory`] selects local Rust, Rust auth, Go mail or Go
//! auth. Local adapters live in [`RouteTable`] and may decline a whole
//! request to Go. The default-ON front door also serves liveness
//! (`GET`/`HEAD` [`HEALTH_PATH`]) and Go proxy counters ([`metrics::PATH`]).
//! Its kill switch bypasses all dispatch to Go mailserver.
//!
//! Listeners accept HTTP/1.1 and prior-knowledge h2c, plus native TLS 1.2/1.3
//! on an owned HTTPS descriptor. ALPN selects h2 or HTTP/1.1. Upgrades and
//! streaming responses remain supported within Go's listener deadlines;
//! upgraded sessions retain their application-owned lifetime.

pub mod acme;
mod admission;
mod guest_allowlist;
pub mod activation;
pub mod attachment;
pub mod blobs;
mod blob_content;
pub mod catchall;
pub mod oidc_namespace;
pub mod cert_monitor;
pub mod chat;
pub mod chat_b;
pub mod chat_unfurl;
pub mod chat_workers;
pub mod cron_catalog;
pub mod notify_drain;
pub mod push_drain;
pub mod secevents;
pub mod setup_control;

pub mod assist;
pub mod blob_cleanup;
pub mod chat_channels;
pub mod dmarc_report;
pub mod drive;
pub mod drive_workers;
pub mod f15;
pub mod f16;
pub mod forwarded;
pub mod http_limits;
pub mod imap_runtime;
pub mod smtp_runtime;
pub mod inventory;
pub mod jmap;
pub mod mdm_notify;
pub mod meet;
pub mod meet_livekit;
pub mod meet_worker;
pub mod metrics;
pub mod office;
pub mod office_provider;
pub mod offline;
pub mod problem;
pub mod proxy;
pub mod recovery;
pub mod recovery_begin;
pub mod recovery_finalize;
pub mod recovery_worker;
pub mod routes;
pub mod rtc;
pub mod served_stats;
pub mod surface;
pub mod ticket_keys;
pub mod tls_runtime;
pub mod translate;
pub mod workers;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, Uri};
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use tokio::net::TcpListener;

pub use forwarded::{ClientIdentity, TrustedProxies};
pub use proxy::Upstream;
pub use routes::{BoxFuture, Intercept, RequestContext, RouteTable};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
/// Body type on both sides of the gateway: streams, never buffers.
pub type Body = BoxBody<Bytes, BoxError>;

/// Gateway-local liveness path; outside every Go route prefix.
pub const HEALTH_PATH: &str = "/_gateway/healthz";

/// Go gives active HTTP requests 30 seconds to finish on shutdown.
const HTTP_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Config {
    /// Go mailserver base, `http://host:port`, or none for an offline replay.
    pub upstream: Option<Uri>,
    /// How long Go may take to send response headers before the client
    /// gets `504` ([`proxy::DEFAULT_HEADER_TIMEOUT`] by default). Bodies
    /// (SSE, downloads) are not bounded once headers arrived.
    pub upstream_header_timeout: Duration,
    /// Peers whose forwarded headers are trusted (default: nobody).
    pub trusted_proxies: TrustedProxies,
    /// Go's per-IP core budget (`CORE_RATE_LIMIT`), shared by Rust and Go.
    /// The executable configures it whenever the front door is enabled;
    /// the kill switch bypasses it. Tests may omit or gate the limiter.
    pub edge_limit: Option<jmap::limit::EdgeLimit>,
}

struct Shared {
    enabled: bool,
    upstream: Upstream,
    auth_upstream: Option<Upstream>,
    rust_auth_upstream: Option<Upstream>,
    inventory: inventory::Inventory,
    go_proxies: Arc<metrics::GoProxies>,
    upstream_header_timeout: Duration,
    trusted: Arc<std::sync::RwLock<TrustedProxies>>,
    routes: RouteTable,
    edge_limit: Option<jmap::limit::EdgeLimit>,
    http_limits: http_limits::HttpLimits,
    connections: Arc<tokio::sync::Semaphore>,
}

#[derive(Clone)]
pub struct Gateway {
    shared: Arc<Shared>,
}

impl Gateway {
    pub fn new(config: Config, routes: RouteTable) -> Result<Self, String> {
        let upstream = match config.upstream {
            Some(uri) => Upstream::new(uri)?,
            None => Upstream::disabled(),
        }
        .with_header_timeout(config.upstream_header_timeout);
        Ok(Self {
            shared: Arc::new(Shared {
                enabled: true,
                upstream,
                auth_upstream: None,
                rust_auth_upstream: None,
                inventory: inventory::Inventory::parse(inventory::BUNDLED)?,
                go_proxies: Arc::new(metrics::GoProxies::default()),
                upstream_header_timeout: config.upstream_header_timeout,
                trusted: Arc::new(std::sync::RwLock::new(config.trusted_proxies)),
                routes,
                edge_limit: config.edge_limit,
                http_limits: http_limits::HttpLimits::default(),
                connections: Arc::new(tokio::sync::Semaphore::new(
                    http_limits::HttpLimits::default().max_connections,
                )),
            }),
        })
    }

    /// Listener resource policy, shared by TLS and loopback HTTP.
    pub fn with_http_limits(mut self, limits: http_limits::HttpLimits) -> Result<Self, String> {
        limits.validate()?;
        let shared = Arc::get_mut(&mut self.shared).expect("new gateway is unshared");
        shared.http_limits = limits;
        shared.connections = Arc::new(tokio::sync::Semaphore::new(limits.max_connections));
        Ok(self)
    }

    /// Share the process-local trusted-proxy snapshot with config reload.
    pub fn with_configuration(mut self, config: &configuration::Runtime) -> Self {
        Arc::get_mut(&mut self.shared).expect("new gateway is unshared").trusted = config.trusted.clone();
        self
    }

    /// Configure a direct authserver upstream for `/auth/` requests.
    pub fn with_auth_upstream(mut self, uri: Uri) -> Result<Self, String> {
        let shared = Arc::get_mut(&mut self.shared).expect("new gateway is unshared");
        shared.auth_upstream =
            Some(Upstream::new(uri)?.with_header_timeout(shared.upstream_header_timeout));
        Ok(self)
    }

    /// Separate Rust identity process; selected only by ON inventory entries.
    pub fn with_rust_auth_upstream(mut self, uri: Uri) -> Result<Self, String> {
        let shared = Arc::get_mut(&mut self.shared).expect("new gateway is unshared");
        shared.rust_auth_upstream =
            Some(Upstream::new(uri)?.with_header_timeout(shared.upstream_header_timeout));
        Ok(self)
    }

    /// Load reviewed transfer decisions (also used by recording/rehearsal tools).
    pub fn with_inventory(mut self, json: &str) -> Result<Self, String> {
        Arc::get_mut(&mut self.shared)
            .expect("new gateway is unshared")
            .inventory = inventory::Inventory::parse(json)?;
        Ok(self)
    }

    /// Kill switch: bypass all Rust dispatch, probes and edge limiting.
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        Arc::get_mut(&mut self.shared)
            .expect("new gateway is unshared")
            .enabled = enabled;
        self
    }

    /// Serves until the process ends.
    pub async fn serve(self, listener: TcpListener) {
        self.serve_until(listener, std::future::pending()).await
    }

    /// Stops accepting on shutdown and drains active HTTP connections for 30 seconds.
    pub async fn serve_until(self, listener: TcpListener, shutdown: impl Future<Output = ()>) {
        self.serve_connections(listener, None, shutdown).await
    }

    /// Terminate TLS on an owned listener; ALPN selects the HTTP engine.
    pub async fn serve_tls_until(
        self,
        listener: TcpListener,
        tls: Arc<setjoin_tls::Frontend>,
        shutdown: impl Future<Output = ()>,
    ) {
        self.serve_connections(listener, Some(tls), shutdown).await
    }

    async fn serve_connections(
        self,
        listener: TcpListener,
        tls: Option<Arc<setjoin_tls::Frontend>>,
        shutdown: impl Future<Output = ()>,
    ) {
        tokio::pin!(shutdown);
        if let Some(runtime) = &self.shared.routes.runtime {
            runtime.initialize().await;
        }
        let (draining, _) = tokio::sync::watch::channel(false);
        let mut runtime_task = RuntimeTask(self.shared.routes.runtime.clone().map(|runtime| {
            let stop = draining.subscribe();
            tokio::spawn(async move { runtime.run(stop).await; })
        }));
        let mut connections = tokio::task::JoinSet::new();
        loop {
            let accepted = tokio::select! {
                () = &mut shutdown => break,
                Some(_) = connections.join_next(), if !connections.is_empty() => continue,
                accepted = listener.accept() => accepted,
            };
            let (stream, peer) = match accepted {
                Ok(conn) => conn,
                Err(err) => {
                    // EMFILE and friends: back off instead of spinning.
                    eprintln!("setjoin-gateway: accept failed: {err}");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            };
            let _ = stream.set_nodelay(true);
            // Shed immediately: handshakes also consume capacity, and neither
            // listener may wait for a permit while its accept queue fills.
            let Ok(permit) = self.shared.connections.clone().try_acquire_owned() else {
                drop(stream);
                continue;
            };
            let shared = self.shared.clone();
            let mut drain = draining.subscribe();
            let tls = tls.clone();
            connections.spawn(async move {
                let _active = served_stats::Connection::open();
                match tls {
                    Some(frontend) => {
                        let accepted = tokio::select! {
                            biased;
                            _ = drain.changed() => return,
                            accepted = frontend.accept(stream) => accepted,
                        };
                        let Ok(stream) = accepted else { return };
                        if stream.get_ref().1.alpn_protocol() == Some(b"acme-tls/1") { return; }
                        let h2 = stream.get_ref().1.alpn_protocol() == Some(b"h2");
                        let leaf = stream.get_ref().1.peer_certificates()
                            .and_then(|chain| chain.first()).cloned()
                            .map(setjoin_tls::PeerCertificate);
                        serve_http_connection(shared, peer, stream, drain, Some(h2), leaf, permit).await;
                    }
                    None => serve_http_connection(shared, peer, stream, drain, None, None, permit).await,
                }
            });
        }
        drop(listener);
        self.shared.routes.shutdown();
        let _ = draining.send(true);
        if let Some(mut task) = runtime_task.0.take() {
            if tokio::time::timeout(Duration::from_secs(5), &mut task).await.is_err() {
                task.abort();
                let _ = task.await;
            }
        }
        if tokio::time::timeout(HTTP_DRAIN_TIMEOUT, async {
            while connections.join_next().await.is_some() {}
        })
        .await
        .is_err()
        {
            connections.abort_all();
            while connections.join_next().await.is_some() {}
        }
    }
}

async fn serve_http_connection<S>(
    shared: Arc<Shared>,
    peer: SocketAddr,
    stream: S,
    mut drain: tokio::sync::watch::Receiver<bool>,
    tls_http2: Option<bool>,
    peer_certificate: Option<setjoin_tls::PeerCertificate>,
    permit: tokio::sync::OwnedSemaphorePermit,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let limits = shared.http_limits;
    let activity = http_limits::Activity::new(limits);
    let cancel = tokio_util::sync::CancellationToken::new();
    let _cancel = cancel.clone().drop_guard();
    let service_activity = activity.clone();
    let svc = service_fn(move |req: Request<Incoming>| {
        let shared = shared.clone();
        use hyper::body::Body as _;
        let (active, reading) = service_activity.start(req.body().is_end_stream());
        let mut req = req.map(|body| {
            http_limits::RequestBody::new(body.map_err(Into::into).boxed(), reading).boxed()
        });
        if let Some(leaf) = &peer_certificate {
            req.extensions_mut().insert(leaf.clone());
        }
        let cancel = cancel.clone();
        async move {
            let started = std::time::Instant::now();
            let mut response = tokio::select! {
                response = handle(&shared, peer, req, tls_http2.is_some()) => response,
                _ = cancel.cancelled() => return Err::<Response<Body>, std::io::Error>(std::io::Error::new(std::io::ErrorKind::TimedOut, "HTTP connection deadline")),
            };
            if tls_http2.is_some() {
                response
                    .headers_mut()
                    .entry(hyper::header::STRICT_TRANSPORT_SECURITY)
                    .or_insert(hyper::header::HeaderValue::from_static(
                        "max-age=63072000; includeSubDomains; preload",
                    ));
            }
            served_stats::record(started.elapsed(), response.status().as_u16());
            Ok::<_, std::io::Error>(
                response.map(|body| http_limits::ResponseBody::new(body, active).boxed()),
            )
        }
    });
    let mut builder = auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(None);
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(limits.idle / 2)
        .keep_alive_timeout(limits.read);
    let builder = match tls_http2 {
        Some(true) => builder.http2_only(),
        Some(false) => builder.http1_only(),
        None => builder,
    };
    let connection = builder.serve_connection_with_upgrades(
        TokioIo::new(http_limits::HttpIo::new(
            stream,
            activity.clone(),
            tls_http2,
            permit,
        )),
        svc,
    );
    tokio::pin!(connection);
    tokio::select! {
        _ = &mut connection => {}
        _ = activity.expired() => {}
        _ = drain.changed() => {
            connection.as_mut().graceful_shutdown();
            let _ = connection.await;
        }
    }
}

async fn handle(
    shared: &Shared,
    peer: SocketAddr,
    mut req: Request<Body>,
    secure: bool,
) -> Response<Body> {
    // HTTP/2 carries Host in :authority. Preserve it before a proxy rewrites
    // the target URI, just as net/http exposes it through Request.Host.
    // HTTP/1 keeps its original Host-header absence: its frozen SSE cookie
    // recording rejects that absolute-form request through the Go proxy.
    if req.version() == hyper::Version::HTTP_2 && !req.headers().contains_key(hyper::header::HOST) {
        if let Some(authority) = req
            .uri()
            .authority()
            .and_then(|a| hyper::header::HeaderValue::from_str(a.as_str()).ok())
        {
            req.headers_mut().insert(hyper::header::HOST, authority);
        }
    }
    let mut identity = forwarded::resolve(peer.ip(), req.headers(), &shared.trusted.read().expect("trusted proxy snapshot"));
    // shared/clientip: the actual TLS socket is authoritative even for a
    // trusted proxy claiming that the original scheme was plaintext.
    if secure {
        identity.proto = "https";
    }
    let route = shared.inventory.find(req.method(), req.uri().path());
    let auth_path = req.uri().path().starts_with("/auth/");
    // Direct authserver recordings retain its per-route CSRF ordering/headers.
    // Gateway traffic, including both auth upstreams, has mailserver's outer CSRF.
    let auth_listener = shared.inventory.auth_only();
    let auth_target = route.map_or(auth_path, |r| {
        matches!(r.target, inventory::Target::RustAuth | inventory::Target::GoAuth)
    });
    let family = shared
        .inventory
        .proxy_family(req.method(), req.uri().path(), route)
        .unwrap_or(if auth_path { 21 } else { 0 });
    let go_mail = shared
        .upstream
        .clone()
        .with_go_counter(shared.go_proxies.clone(), family);
    if !shared.enabled {
        return go_mail.forward(req, &identity).await;
    }
    if req.uri().path() == HEALTH_PATH {
        return match *req.method() {
            Method::GET | Method::HEAD => proxy::status(StatusCode::OK, "ok\n"),
            _ => proxy::status(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n"),
        };
    }
    if req.uri().path() == metrics::PATH {
        return match *req.method() {
            Method::GET | Method::HEAD => shared.go_proxies.response(req.method() == Method::HEAD),
            _ => proxy::status(StatusCode::METHOD_NOT_ALLOWED, "method not allowed\n"),
        };
    }
    // Owner-approved security fix 2026-11-05 (#491): the global CSRF gate runs
    // before the over-budget branch. An over-budget request that is not answered
    // here used to skip it entirely (and the later gate only runs without an edge
    // limiter), so a cross-site mutation reached the routes unchecked.
    if shared.edge_limit.is_some()
        && !auth_listener
        && !setjoin_contracts::mutants::on("csrf-after-over-budget")
    {
        if let Some(response) = csrf_denial(&req, &identity) {
            return response;
        }
    }
    if let Some(limit) = &shared.edge_limit {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        // Go's coreLimit answers every over-budget request with its own 429 (#357).
        if !limit.limiter.allow(identity.client_ip, now) {
            return jmap::limit::rate_limited(req.headers().get("x-request-id"));
        } else {
            // Go mailserver's global CSRF gate runs before route-specific buckets.
            // Rejections are final before any route bucket or authentication.
            if !auth_listener && setjoin_contracts::mutants::on("csrf-after-over-budget") {
                if let Some(response)=csrf_denial(&req,&identity){return response;}
            }
            // ServeMux canonicalization precedes buildRootDispatch's belt.
            if shared.routes.catchall && shared.inventory.root_on() {
                let ctx=RequestContext{identity:identity.clone(),upstream:go_mail.clone()};
                if let Some(response)=catchall::root_redirect(&req,&ctx){return response;}
            }
            let path=req.uri().path();
            let concrete=route.is_some_and(|r|r.path!="/" && r.path!="/api/");
            let legacy=!matches!(*req.method(),Method::GET|Method::HEAD) &&
                (shared.inventory.go_match(req.method(),path,None).is_some() ||
                 shared.inventory.go_match(req.method(),&format!("{path}/"),None).is_some());
            // Auth proxy entries are gated too; ordinary SPA GETs are not.
            if path.starts_with("/api/") || auth_path || concrete || legacy {
                if let Some(admission) = &shared.routes.admission {
                    if let Some(response) = admission.check(req.headers().clone(), req.method().clone(),
                        req.uri().path().to_owned(), identity.clone(), false).await {
                        return response;
                    }
                }
            }
            // SCIM registration is pinned at startup after the YAML/env merge,
            // as Go does. A disabled registration falls through to the root mux
            // (404 without a website, the SPA with one).
            if limit.scim_disabled(req.method(), req.uri().path())
                && route.is_some_and(|r| r.target == inventory::Target::LocalRust)
            {
                if let Some(fallback) = shared.routes.mux_fallback() {
                    return fallback
                        .handle(req, RequestContext { identity, upstream: go_mail })
                        .await;
                }
                return surface::unregistered(&req, identity.proto);
            }
            // Go's guest belt precedes the route limit and may deliberately
            // answer 404. A local adapter may prove membership through its
            // verified precheck; unresolved callers remain with Go.
            if limit.has_route_limit(req.method(), req.uri().path())
                && !route.is_some_and(|r| r.target == inventory::Target::RustAuth)
                && shared.routes.admission.is_none()
                && may_carry_guest_token(req.headers())
            {
                let admitted = if route.is_some_and(|r| r.target == inventory::Target::LocalRust) {
                    match shared.routes.find(&req) {
                        Some(adapter) => {
                            adapter
                                .admits_member(req.headers().clone(), identity.proto)
                                .await
                        }
                        None => false,
                    }
                } else {
                    false
                };
                if !admitted {
                    // D-357a-1: without the deployment verifier (no DB_DSN, or a custom
                    // embedding) Go's guest belt cannot run here; fail closed with
                    // guestgate's lookup-failure answer (middleware.go:75).
                    return admission::problem(req.headers(), &identity, 503, "service unavailable");
                }
            }
            if !limit.allow_route(req.method(), req.uri().path(), identity.client_ip, now) {
                return jmap::limit::route_rate_limited(
                    req.headers().get("x-request-id"),
                    identity.proto,
                );
            }
        }
    }
    if !auth_listener
        && shared.edge_limit.is_none()
        && (auth_target || shared.routes.find(&req).is_some())
    {
        if let Some(response) = csrf_denial(&req, &identity) {
            return response;
        }
    }
    if shared.routes.catchall && shared.inventory.root_on() {
        let ctx = RequestContext {
            identity: identity.clone(),
            upstream: go_mail.clone(),
        };
        if let Some(reply) = catchall::root_redirect(&req, &ctx) {
            return reply;
        }
    }
    // #357/#378: an `/auth/*` spelling no inventory row claims is answered by frozen
    // Go's pinned-API root mux (slash redirect, else SPA/404), never by Go auth. This
    // runs after CSRF, both budgets and admission, exactly as Go's root dispatch does.
    if route.is_none() && auth_path && shared.inventory.root_on() {
        if let Some(fallback) = shared.routes.mux_fallback() {
            if let Some(reply) = unmatched::slash_redirect(&shared.inventory, &req, identity.proto) {
                return reply;
            }
            return fallback
                .handle(req, RequestContext { identity, upstream: go_mail })
                .await;
        }
    }
    let target = route.map_or(
        if auth_path {
            inventory::Target::GoAuth
        } else {
            inventory::Target::GoMail
        },
        |r| r.target,
    );
    // Qualified auth routes reach setjoin-auth. That process owns the
    // credential-route threat admission and forwards only shapes awaiting #420.
    match target {
        inventory::Target::GoAuth => {
            return match &shared.auth_upstream {
                Some(upstream) => {
                    upstream
                        .clone()
                        .with_go_counter(shared.go_proxies.clone(), family)
                        .forward(req, &identity)
                        .await
                }
                None => proxy::status(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Go auth upstream unavailable\n",
                ),
            }
        }
        inventory::Target::RustAuth => {
            return match &shared.rust_auth_upstream {
                Some(upstream) => upstream.forward(req, &identity).await,
                None => proxy::status(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Rust auth upstream unavailable\n",
                ),
            }
        }
        inventory::Target::GoMail => return go_mail.forward(req, &identity).await,
        inventory::Target::LocalRust => {}
    }
    // The wildcard subtree rows (F22 `/` and `/api/`; F12 `/chat/`, F14 `/drive/`, F13
    // `/meet` and `/meet/`) belong to the catch-all alone: a request only they claim (a bare
    // SPA path, or a route rolled back to Go whose inventory row keeps its registration
    // path) must not reach a concrete adapter that merely matches it (#421, #472).
    let adapter = if route.is_some_and(inventory::Inventory::is_subtree_row) {
        shared.routes.find_catchall(&req)
    } else {
        shared.routes.find(&req)
    };
    if let Some(runtime) = shared.routes.runtime.as_ref().filter(|_| {
        adapter.is_some() && route.is_some_and(|r| r.path != "/" && r.path != "/api/")
    }) {
        let ctx = RequestContext { identity: identity.clone(), upstream: go_mail.clone() };
        if let Some(response) = runtime.check(&mut req, &ctx).await {
            return response;
        }
    }
    match adapter {
        Some(route) => {
            // RequireAuth follows the route bucket; the guest belt precedes it.
            if route.requires_session(&req) {
                if let Some(admission) = &shared.routes.admission {
                    if let Some(response) = admission.check(req.headers().clone(), req.method().clone(),
                        req.uri().path().to_owned(), identity.clone(), true).await {
                        return response;
                    }
                }
            }
            let ctx = RequestContext {
                identity,
                upstream: go_mail,
            };
            route.handle(req, ctx).await
        }
        None => go_mail.forward(req, &identity).await,
    }
}

fn csrf_denial(req:&Request<Body>,identity:&ClientIdentity)->Option<Response<Body>>{
    if matches!(*req.method(),Method::GET|Method::HEAD|Method::OPTIONS)
        || jmap::csrf::allows(req.headers(),identity.proto){return None;}
    let id=jmap::reply::request_id(req.headers().get("x-request-id"),jmap::random().unwrap_or([0;16]));
    let mut response=jmap::reply::response(problem::middleware(403,"csrf_failed","CSRF validation failed"),identity.proto,id);
    *response.status_mut()=StatusCode::FORBIDDEN;
    response.headers_mut().insert("content-type","application/problem+json".parse().unwrap());
    Some(response)
}

fn may_carry_guest_token(headers: &hyper::HeaderMap) -> bool {
    if headers
        .get(hyper::header::AUTHORIZATION)
        .is_some_and(|value| value.as_bytes().starts_with(b"Bearer "))
    {
        return true;
    }
    headers.get_all(hyper::header::COOKIE).iter().any(|value| {
        value.to_str().map_or(true, |cookies| {
            cookies.split(';').any(|cookie| {
                cookie
                    .trim()
                    .split_once('=')
                    .is_some_and(|(name, value)| name == "access_token" && !value.is_empty())
            })
        })
    })
}

pub mod approvals;

mod approval_pages;

pub mod guests;

pub mod admin_identity;

mod admin_identity_input;

pub mod admin_access_reviews;

pub mod admin_org_policies;
pub mod admin_scope_sets;

pub mod admin_identity_v2;
pub mod admin_identity_v2_upgrade;
pub mod admin_sod;
pub mod blob_retention;
pub mod health_alerts;
pub mod platform;
mod platform_input;
pub mod platform_jobs;
pub mod platform_storage;
pub mod platform_terms;
pub mod platform_updates;
mod platform_recovery_admin;
mod platform_airgap;
mod platform_deploy;
mod platform_upgrades;
pub mod platform_webhooks;
pub mod webhook;

pub mod booking_mail;
pub mod booking_worker;
pub mod calendar;
pub mod caldav;
pub mod carddav;
pub mod contacts;
pub mod contacts_csv;
pub mod contacts_vcard;
mod go_time;
mod unmatched;
pub mod ics;
mod ssrf;
pub mod subscription_sync;

mod admin_users_csv;
pub mod admin_users_lifecycle;
pub mod conditional_access;
mod conditional_access_more;
pub mod devices;
pub mod directory_sync;
pub mod link_protect;
pub mod link_protect_pages;
pub mod mail_security;
pub mod mail_security_dlp;
pub mod mail_security_input;
pub mod mail_security_smime;
pub mod mail_security_spam;
pub mod mail_security_threat;
pub mod mail_security_tls;
pub mod mail_security_trace;
pub mod mail_workers;
pub mod mailbox_io;
pub mod mailboxes;
pub mod migration;
pub mod migration_runner;
pub mod smime_trust;
pub mod tls_rpt;
pub mod user_risk_worker;
pub mod user_settings;

pub mod scim;

mod directory_sync_input;

mod guests_input;

pub mod admin_job_workers;
mod guest_mail;
pub mod guest_worker;

pub mod chat_compliance;
pub mod compliance;
pub mod retention_audit;

mod compliance_export;
pub mod exchange;
pub mod exchange_deletion;

mod chat_compliance_export;

pub mod federation_typing;
pub mod rules;

pub mod drive_native;
pub mod smtp_events;
pub mod smtp_outbound;

pub mod runtime_access;

// Abort on cancellation as well as normal shutdown (test/front-door owners may
// drop serve_until). Direct listener drivers then drop with the runtime future.
struct RuntimeTask(Option<tokio::task::JoinHandle<()>>);
impl Drop for RuntimeTask {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() { task.abort(); }
    }
}

/// Layered operator configuration and native reload.
pub mod configuration;

pub mod telemetry;

pub mod discovery;
pub mod spam_trainer;

pub mod identity_self_service;
mod identity_smime;
mod identity_migration;
