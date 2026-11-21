//! F22 public surface (#271): OpenAPI documents, downloads, health, metrics,
//! discovery documents, cert hint, favicon and the telemetry kill-switch path.
//!
//! Every response carries the headers Go's listener chain sets (security
//! headers, the `Cache-Control` policy table, `X-Request-Id`). A request this
//! adapter cannot answer exactly as Go does is forwarded whole. Discovery,
//! configured sidecar probes, device-proof telemetry and full-spec permission
//! denials (including their audits) are native (#406, #417, #457).
use crate::{Body, BoxFuture, Intercept, RequestContext};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode};
use setjoin_authz::token::KeySource;
use setjoin_pg::ScopedExecutor;
use setjoin_static::{downloads, health::HealthGate, metrics, openapi, wellknown};
use std::sync::Arc;

/// Process configuration Go reads from its environment/koanf layers. The
/// executable resolves Go's YAML/environment layers before constructing the
/// startup snapshot. Reload does not rebuild these handlers, as in Go.
#[derive(Clone)]
pub struct SurfaceConfig {
    pub network_mode: String,
    pub website_dir: bool,
    pub setjoin: wellknown::SetJoinConfig,
    pub imap_tls: bool,
    pub metrics: metrics::MetricsAuth,
    pub probes_configured: bool,
}

impl SurfaceConfig {
    pub fn from_settings(settings: &crate::configuration::Settings) -> Self {
        let mut config = Self::from_env();
        config.network_mode = settings.string("network.mode");
        config.website_dir = !settings.string("website.dir").is_empty();
        config.imap_tls = !settings.string("imap.tls_addr").is_empty();
        config.setjoin.crypto_profile = settings.string("crypto.algorithm_profile");
        config
    }

    pub fn from_env() -> Self {
        let env = |k: &str| std::env::var(k).unwrap_or_default();
        Self {
            network_mode: env("NETWORK_MODE"),
            website_dir: !env("WEBSITE_DIR").is_empty(),
            setjoin: wellknown::SetJoinConfig {
                crypto_profile: match env("CRYPTO_ALGORITHM_PROFILE") {
                    p if p.is_empty() => "standard".into(),
                    p => p,
                },
                // Go declares these fields but never decodes them from any layer.
                login_field: String::new(),
                login_domain_hint: String::new(),
            },
            // Go's default `imap.tls_addr` is ":993"; a present, empty variable disables it.
            imap_tls: std::env::var("IMAP_TLS_ADDR").map_or(true, |v| !v.is_empty()),
            metrics: metrics::MetricsAuth::from_values(
                &env("METRICS_TOKEN"),
                &env("METRICS_ALLOW_UNAUTHENTICATED"),
            ),
            // `meetCfg.Configured()` and the ASR bot gate the live probes.
            probes_configured: !env("LIVEKIT_API_KEY").is_empty()
                || !env("LIVEKIT_URL").is_empty()
                || !env("ASR_URL").is_empty(),
        }
    }
}

pub struct SurfaceRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    pub keys: Arc<K>,
    pub issuer: String,
    pub config: Arc<SurfaceConfig>,
    pub health: Arc<HealthGate>,
    /// Trusted transport seam; main uses the native system resolver.
    pub discovery: Option<Arc<crate::discovery::Discovery>>,
    /// Go registrations absent at startup fall through to this same root mux.
    pub fallback: Option<Arc<crate::catchall::CatchallRoute>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Yaml,
    Json,
    Docs,
    RedocJs,
    Logo,
    Font,
    FullYaml,
    FullJson,
    Downloads,
    Platform,
    Asset,
    Favicon,
    Health,
    Ready,
    Metrics,
    SetJoin,
    Autoconfig,
    Caldav,
    Carddav,
    CertHint,
    Discover,
    Telemetry,
}

const GET_ROUTES: [(&str, Kind); 22] = [
    ("/api/openapi.yaml", Kind::Yaml),
    ("/api/openapi.json", Kind::Json),
    ("/api/docs", Kind::Docs),
    ("/api/redoc.standalone.js", Kind::RedocJs),
    ("/api/logo.svg", Kind::Logo),
    ("/api/fonts/ibm-plex-sans-400.woff2", Kind::Font),
    ("/api/fonts/ibm-plex-sans-500.woff2", Kind::Font),
    ("/api/openapi.full.yaml", Kind::FullYaml),
    ("/api/openapi.full.json", Kind::FullJson),
    ("/downloads", Kind::Downloads),
    ("/downloads/asset/{asset}", Kind::Asset),
    ("/downloads/{platform}", Kind::Platform),
    ("/favicon.ico", Kind::Favicon),
    ("/health", Kind::Health),
    ("/ready", Kind::Ready),
    ("/metrics", Kind::Metrics),
    ("/.well-known/setjoin", Kind::SetJoin),
    (
        "/.well-known/autoconfig/mail/config-v1.1.xml",
        Kind::Autoconfig,
    ),
    ("/.well-known/caldav", Kind::Caldav),
    ("/.well-known/carddav", Kind::Carddav),
    ("/api/cert-hint", Kind::CertHint),
    ("/api/discover", Kind::Discover),
];

fn classify(method: &Method, path: &str) -> Option<Kind> {
    if *method == Method::POST {
        return crate::inventory::path_score("/api/telemetry", path).map(|_| Kind::Telemetry);
    }
    if !matches!(*method, Method::GET | Method::HEAD) {
        return None;
    }
    // Go's ServeMux redirects a path that is not in clean form; leave those
    // to Go.
    // `ServeMux` cleans the escaped path, so `%2e` and `%2f` are ordinary bytes.
    if go_clean(path) != path {
        return None;
    }
    GET_ROUTES
        .iter()
        .find(|(pattern, _)| crate::inventory::path_score(pattern, path).is_some())
        .map(|(_, kind)| *kind)
}

/// Go's `path.Clean`, keeping a trailing slash (`ServeMux.cleanPath`).
fn go_clean(p: &str) -> String {
    if p.is_empty() {
        return "/".into();
    }
    let mut out: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            s => out.push(s),
        }
    }
    let mut clean = format!("/{}", out.join("/"));
    if p.ends_with('/') && !clean.ends_with('/') {
        clean.push('/');
    }
    clean
}

/// What a Go `Cache-Control` policy row says for a 2xx GET/HEAD of `kind`.
fn cache_policy(kind: Kind, path: &str) -> &'static str {
    match kind {
        Kind::Favicon => "public, max-age=604800, immutable",
        Kind::Font => "public, max-age=31536000, immutable",
        Kind::Autoconfig => "public, max-age=86400",
        Kind::SetJoin => "public, max-age=3600",
        Kind::Downloads => "public, max-age=3600",
        Kind::Yaml | Kind::Json => "public, max-age=300",
        Kind::RedocJs | Kind::Logo => "public, max-age=86400",
        _ => {
            let _ = path;
            "no-store"
        }
    }
}

struct Reply<'a> {
    status: u16,
    content_type: Option<&'a str>,
    cache: &'a str,
    headers: Vec<(&'static str, String)>,
    body: Bytes,
}

impl<'a> Reply<'a> {
    fn new(
        status: u16,
        content_type: Option<&'a str>,
        cache: &'a str,
        body: impl Into<Bytes>,
    ) -> Self {
        Self {
            status,
            content_type,
            cache,
            headers: Vec::new(),
            body: body.into(),
        }
    }
    fn header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }
    fn build(self, c: &RequestContext, id: String) -> Response<Body> {
        let mut response = crate::jmap::reply::response(String::new(), c.identity.proto, id);
        *response.status_mut() = StatusCode::from_u16(self.status).expect("static status");
        let headers = response.headers_mut();
        // Go stamps the table value on 2xx only; every other status is no-store.
        let cache = if (200..300).contains(&self.status) {
            self.cache
        } else {
            "no-store"
        };
        headers.insert("cache-control", cache.parse().expect("static header"));
        match self.content_type {
            Some(ct) => headers.insert("content-type", ct.parse().expect("static header")),
            None => headers.remove("content-type"),
        };
        for (name, value) in self.headers {
            if let Ok(value) = value.parse() {
                headers.insert(name, value);
            }
        }
        *response.body_mut() = Full::new(self.body).map_err(|n| match n {}).boxed();
        response
    }
}

/// `http.Error`.
fn text_error(status: u16, message: &str) -> Reply<'static> {
    Reply::new(
        status,
        Some("text/plain; charset=utf-8"),
        "no-store",
        format!("{message}\n"),
    )
}

fn problem_status(status: u16, title: &str, detail: &str) -> Reply<'static> {
    // `WriteProblemStatus`: no request path, so `instance` is empty.
    let body = crate::problem::Problem::new(status, detail)
        .title(title)
        .body();
    Reply::new(status, Some("application/problem+json"), "no-store", body)
}

fn json(status: u16, body: impl Into<Bytes>, cache: &'static str) -> Reply<'static> {
    Reply::new(status, Some("application/json"), cache, body)
}

fn hex_escape_non_ascii(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b >= 0x80 {
            out.push_str(&format!("%{b:02x}"));
        } else {
            out.push(b as char);
        }
    }
    out
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&#34;")
        .replace('\'', "&#39;")
}

/// `http.Redirect`: `None` when the target has bytes a header cannot carry
/// (the request then goes to Go).
fn redirect(location: &str, code: u16, method: &Method) -> Option<Reply<'static>> {
    let mut url = location.to_owned();
    let relative = !url.contains("://") && !url.starts_with("//");
    if relative && url.starts_with('/') {
        let (path, query) = match url.find('?') {
            Some(i) => (url[..i].to_owned(), url[i..].to_owned()),
            None => (url.clone(), String::new()),
        };
        // `url.Parse` fails on a malformed escape; Go then leaves it as is.
        let bytes = path.as_bytes();
        let escapes_ok = bytes.iter().enumerate().all(|(i, b)| {
            *b != b'%'
                || (i + 2 < bytes.len()
                    && bytes[i + 1].is_ascii_hexdigit()
                    && bytes[i + 2].is_ascii_hexdigit())
        });
        if escapes_ok {
            let trailing = path.ends_with('/');
            let mut cleaned = go_clean(&path);
            if trailing && !cleaned.ends_with('/') {
                cleaned.push('/');
            }
            url = cleaned + &query;
        }
    }
    if url.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return None;
    }
    let status_text = if code == 301 {
        "Moved Permanently"
    } else {
        "Found"
    };
    let mut reply = Reply::new(
        code,
        Some("text/html; charset=utf-8"),
        "no-store",
        Bytes::new(),
    )
    .header("location", hex_escape_non_ascii(&url));
    if *method == Method::GET {
        reply.body = format!("<a href=\"{}\">{status_text}</a>.\n\n", html_escape(&url)).into();
    }
    Some(reply)
}

impl<K: KeySource + 'static> SurfaceRoute<K> {
    async fn reply(
        &self,
        kind: Kind,
        r: &Request<Body>,
        proto: &'static str,
    ) -> Option<Reply<'static>> {
        let path = r.uri().path();
        let decoded = || String::from_utf8_lossy(&crate::inventory::unescape(path)).into_owned();
        let segment = |index: usize| -> Option<String> {
            let raw = path.split('/').nth(index)?;
            Some(String::from_utf8_lossy(&crate::inventory::unescape(raw)).into_owned())
        };
        let cfg = &self.config;
        let get = *r.method() == Method::GET;
        Some(match kind {
            Kind::Yaml => Reply::new(
                200,
                Some("application/yaml; charset=utf-8"),
                cache_policy(kind, path),
                openapi::PUBLIC_YAML,
            ),
            Kind::Json => Reply::new(
                200,
                Some("application/json; charset=utf-8"),
                cache_policy(kind, path),
                openapi::PUBLIC_JSON,
            ),
            Kind::Docs => Reply::new(
                200,
                Some("text/html; charset=utf-8"),
                "no-store",
                openapi::DOCS_HTML,
            ),
            Kind::RedocJs => Reply::new(
                200,
                Some("application/javascript; charset=utf-8"),
                cache_policy(kind, path),
                openapi::REDOC_JS,
            ),
            Kind::Logo => Reply::new(
                200,
                Some("image/svg+xml"),
                cache_policy(kind, path),
                openapi::LOGO_SVG,
            ),
            Kind::Font => Reply::new(
                200,
                Some("font/woff2"),
                cache_policy(kind, path),
                openapi::font(&decoded()),
            ),
            Kind::FullYaml | Kind::FullJson => {
                let auth = setjoin_authz::authorize_console_request(
                    &self.exec,
                    &*self.keys,
                    &self.issuer,
                    r.headers(),
                    proto,
                )
                .await?;
                let actor = auth.context();
                let allowed = match tokio::time::timeout(
                    setjoin_authz::precheck_timeout(),
                    actor.has_permission(&self.exec, "system.config"),
                )
                .await
                {
                    Ok(Ok(value)) => value,
                    // Frozen Go chain.go:482 retained signed permissions on a live
                    // authority read error; owner-approved security fix 2026-11-05
                    // (#484): the failed lookup drops them and the request is denied.
                    _ => {
                        setjoin_contracts::mutants::on("authority-lookup-keeps-signed-grants")
                            && actor
                                .signed_permissions()
                                .iter()
                                .any(|p| p == "system.config")
                    }
                };
                if !allowed {
                    let actor_id = setjoin_contracts::ids::ActorId::new(actor.user_id()).ok()?;
                    let target = decoded();
                    let before=serde_json::json!({"actor":actor.email(),"target":target,"missingPermission":"system.config"}).to_string();
                    let _ = self
                        .exec
                        .audit_console_denied(actor_id, &before, &target)
                        .await;
                    return Some(problem_status(403, "Forbidden", "Forbidden"));
                }
                if kind == Kind::FullYaml {
                    Reply::new(
                        200,
                        Some("application/yaml; charset=utf-8"),
                        "no-store",
                        openapi::FULL_YAML,
                    )
                } else {
                    Reply::new(
                        200,
                        Some("application/json; charset=utf-8"),
                        "no-store",
                        openapi::FULL_JSON,
                    )
                }
            }
            // The page and the platform redirect refuse every method but GET
            // inside the handler, so a HEAD gets Go's 405.
            Kind::Downloads if !get => text_error(405, "method not allowed"),
            Kind::Downloads => Reply::new(
                200,
                Some("application/json"),
                cache_policy(kind, path),
                downloads::page(),
            ),
            Kind::Platform if !get => text_error(405, "method not allowed"),
            Kind::Platform => {
                let slug: String = segment(2)?;
                match downloads::platform_target(&slug) {
                    Some(target) => redirect(&target, 302, r.method())?,
                    None => text_error(404, "unknown platform"),
                }
            }
            Kind::Asset => {
                let asset: String = segment(3)?;
                if asset.is_empty() {
                    text_error(400, "asset is required")
                } else if !downloads::asset_is_valid(&asset) {
                    text_error(400, "invalid asset name")
                } else {
                    redirect(
                        &downloads::mirror_url(&cfg.network_mode, &asset),
                        302,
                        r.method(),
                    )?
                }
            }
            Kind::Favicon => {
                if !cfg.website_dir {
                    return Some(text_error(404, "404 page not found"));
                }
                Reply::new(
                    200,
                    Some("image/svg+xml"),
                    cache_policy(kind, path),
                    "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 32 32\"><text y=\"28\" font-size=\"28\">\u{1F4E7}</text></svg>",
                )
            }
            Kind::Health => match self.health.public(&self.exec).await {
                setjoin_static::health::Outcome::Json { status, overall } => json(
                    status,
                    format!("{{\"status\":\"{overall}\"}}\n"),
                    "no-store",
                ),
                setjoin_static::health::Outcome::Internal => text_error(500, "internal error"),
                setjoin_static::health::Outcome::Defer => return None,
            },
            Kind::Ready => {
                if setjoin_static::health::ready(&self.exec).await {
                    json(200, "{\"status\":\"ok\"}\n", "no-store")
                } else {
                    text_error(503, "database unreachable")
                }
            }
            Kind::Metrics => {
                let authorization = r
                    .headers()
                    .get(hyper::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok());
                // A non-UTF-8 Authorization value never matches the token.
                if !cfg.metrics.admits(authorization) {
                    Reply::new(401, None, "no-store", Bytes::new())
                } else {
                    let identity = metrics::collect_identity(&self.exec).await;
                    Reply::new(
                        200,
                        Some("text/plain; version=0.0.4"),
                        "no-store",
                        metrics::render(&crate::served_stats::snapshot(), &identity),
                    )
                }
            }
            Kind::SetJoin => json(
                200,
                wellknown::setjoin_document(&cfg.setjoin),
                cache_policy(kind, path),
            )
            .header("access-control-allow-origin", "*"),
            Kind::Autoconfig => {
                let host = r
                    .headers()
                    .get(hyper::header::HOST)
                    .and_then(|v| v.to_str().ok())
                    .or_else(|| r.uri().authority().map(|a| a.as_str()))
                    .unwrap_or_default();
                let domain = wellknown::autoconfig_domain(host);
                if wellknown::local_domain_exists(&self.exec, &domain).await {
                    Reply::new(
                        200,
                        Some("application/xml"),
                        cache_policy(kind, path),
                        wellknown::autoconfig_xml(&domain, cfg.imap_tls),
                    )
                } else {
                    text_error(404, "404 page not found")
                }
            }
            Kind::Caldav | Kind::Carddav => {
                let target = if kind == Kind::Caldav {
                    "/caldav/"
                } else {
                    "/carddav/"
                };
                redirect(target, 301, r.method())?
            }
            Kind::CertHint => json(200, "{\"cert_status\":\"none\"}\n", "no-store")
                .header("x-cert-status", "none"),
            Kind::Discover => match crate::chat::query(r, "domain").filter(|d| !d.is_empty()) {
                Some(domain) => match match &self.discovery {
                    Some(discovery) => discovery.get(&domain).await,
                    None => crate::discovery::system_get(&domain).await,
                } {
                    Some(body) => json(200, body, "no-store"),
                    None => problem_status(
                        404,
                        "Not Found",
                        &format!("no server found for domain {domain}"),
                    ),
                },
                None => problem_status(400, "Bad Request", "domain parameter required"),
            },
            Kind::Telemetry => unreachable!("telemetry consumes its body before reply"),
        })
    }
}

impl<K: KeySource + 'static> Intercept for SurfaceRoute<K> {
    fn requires_session(&self, r: &Request<Body>) -> bool {
        matches!(
            classify(r.method(), r.uri().path()),
            Some(Kind::FullYaml | Kind::FullJson)
        )
    }
    fn matches(&self, r: &Request<Body>) -> bool {
        classify(r.method(), r.uri().path()).is_some()
    }

    fn admits_member(&self, h: hyper::HeaderMap, s: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            setjoin_authz::authorize_request(&exec, &keys, &issuer, &h, s)
                .await
                .is_some()
        })
    }

    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let Some(kind) = classify(r.method(), r.uri().path()) else {
            // `matches` already declined: never reached through the route table (#357).
            let reply = unregistered(&r, c.identity.proto);
            return Box::pin(async move { reply });
        };
        let this = Self {
            exec: self.exec.clone(),
            keys: self.keys.clone(),
            issuer: self.issuer.clone(),
            config: self.config.clone(),
            health: self.health.clone(),
            discovery: self.discovery.clone(),
            fallback: self.fallback.clone(),
        };
        Box::pin(async move {
            // The nonce only seeds a fallback request ID; Go's middleware never fails here.
            let nonce = crate::jmap::random().unwrap_or([0; 16]);
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), nonce);
            if kind == Kind::Telemetry {
                return crate::telemetry::serve(&this.exec, r, &c, id).await;
            }
            if matches!(kind, Kind::Caldav | Kind::Carddav) {
                let key = if kind == Kind::Caldav {
                    "feature.caldav"
                } else {
                    "feature.carddav"
                };
                if crate::assist::feature_on(&this.exec, key).await != Some(true) {
                    return match this.fallback {
                        Some(fallback) => fallback.handle(r, c).await,
                        None => unregistered(&r, c.identity.proto),
                    };
                }
            }
            match this.reply(kind, &r, c.identity.proto).await {
                Some(reply) => reply.build(&c, id),
                None => c.upstream.forward(r, &c.identity).await,
            }
        })
    }
}

/// Go's root mux NotFound when a config-controlled registration is absent.
pub(crate) fn unregistered(r: &Request<Body>, proto: &'static str) -> Response<Body> {
    let id = crate::jmap::reply::request_id(
        r.headers().get("x-request-id"),
        crate::jmap::random().unwrap_or([0; 16]),
    );
    let mut response = crate::jmap::reply::response("404 page not found\n".into(), proto, id);
    *response.status_mut() = StatusCode::NOT_FOUND;
    response
        .headers_mut()
        .insert("content-type", "text/plain; charset=utf-8".parse().unwrap());
    response
}
