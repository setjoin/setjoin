//! F08 Platform HTTP adapter for the `terms-remaining` slice (#303). A separate intercept
//! from `platform.rs` (`system-features`) and `platform_updates.rs` so every slice owns
//! disjoint arms. Gates mirror Go's `RequirePermAudited`: a refusal writes Go's durable
//! `console.denied` row and answers the bare 403; a failed authority read or a missing
//! token forwards the untouched request to Go.
use crate::mailboxes::{bare, unknown_outcome};
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hyper::{Method, Request, Response};
use serde::de::{MapAccess, Visitor};
use setjoin_authz::token::KeySource;
use setjoin_pg::{CommandOutcome, ScopedExecutor};
use setjoin_platform::terms::{self, Document, Done};
use std::sync::Arc;

mod alerts;
mod apps;
mod branding;
mod dns;
mod domains;
mod federation;
mod monitor;

/// What a group handler needs once the gate has admitted the request.
pub(crate) struct Env<'a> {
    pub exec: &'a ScopedExecutor,
    pub worker: &'a ScopedExecutor,
    /// `FEDERATION_LOCAL_DOMAIN`, lower-cased and trimmed; empty when unset.
    pub local_domain: &'a str,
    pub resolver: &'a setjoin_platform::dns::Resolver,
    pub store: Option<&'a Arc<crate::recovery_worker::S3Store>>,
    pub actor: &'a setjoin_authz::AuthContext,
    pub authority: &'a setjoin_platform::Authority,
    pub c: &'a RequestContext,
    pub id: &'a str,
    pub operation: [u8; 16],
    pub go_path: &'a str,
    pub raw_path: String,
    pub language: String,
    pub head: bool,
}
impl Env<'_> {
    /// A Go `WriteJSON` body: net/http buffers 2 KiB of a handler's output; a larger
    /// single write is flushed before the handler returns and sent chunked.
    pub fn reply(&self, body: String, status: u16) -> Response<Body> {
        let chunked = body.len() > 2048 && !self.head;
        let mut response =
            crate::jmap::reply::response(body, self.c.identity.proto, self.id.to_owned());
        *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
        if chunked {
            response.headers_mut().insert(
                "transfer-encoding",
                hyper::header::HeaderValue::from_static("chunked"),
            );
        }
        response
    }
    pub fn no_content(&self) -> Response<Body> {
        let mut response = self.reply(String::new(), 204);
        response.headers_mut().remove("content-type");
        response
    }
    /// Go's `httputil.WriteProblem` with a bare status and detail.
    pub fn problem(&self, status: u16, detail: &str) -> Response<Body> {
        crate::chat_channels::problem(
            status,
            detail,
            self.go_path,
            self.c,
            self.id.to_owned(),
            &self.language,
        )
    }
    /// Go's `WriteProblemStatus`: a minimal problem, empty instance, no language.
    pub fn bare(&self, status: u16, detail: &str) -> Response<Body> {
        bare(status, detail, self.c, self.id)
    }
    pub fn database(&self) -> Response<Body> {
        self.problem(500, "database error")
    }
    pub fn unknown(&self, operation: setjoin_contracts::ids::OperationId) -> Response<Body> {
        unknown_outcome(operation, self.c, self.id)
    }
}

pub struct PlatformTermsRoute<K: KeySource + 'static> {
    pub exec: ScopedExecutor,
    /// The cross-tenant credential for the organization-wide counters (`DB_WORKER_DSN`);
    /// the request pool serves when none is installed.
    pub worker: Option<ScopedExecutor>,
    pub local_domain: String,
    pub resolver: setjoin_platform::dns::Resolver,
    /// Object storage for the brand logo.
    pub store: Option<Arc<crate::recovery_worker::S3Store>>,
    pub keys: Arc<K>,
    pub issuer: String,
}

impl<K: KeySource + 'static> PlatformTermsRoute<K> {
    pub fn new(exec: ScopedExecutor, keys: Arc<K>, issuer: String) -> Self {
        Self {
            exec,
            worker: None,
            resolver: setjoin_platform::dns::Resolver::System,
            store: None,
            local_domain: std::env::var("FEDERATION_LOCAL_DOMAIN")
                .unwrap_or_default()
                .trim()
                .to_lowercase(),
            keys,
            issuer,
        }
    }
    /// A fixed name server for DNS verification (tests); production reads `resolv.conf`.
    pub fn with_resolver(mut self, resolver: setjoin_platform::dns::Resolver) -> Self {
        self.resolver = resolver;
        self
    }
    pub fn with_store(mut self, store: Arc<crate::recovery_worker::S3Store>) -> Self {
        self.store = Some(store);
        self
    }
    pub fn with_worker(mut self, worker: ScopedExecutor) -> Self {
        self.worker = Some(worker);
        self
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Action {
    List,
    Create,
    Update,
    Delete,
    DomainList,
    DomainGet,
    DomainCreate,
    DomainUpdate,
    DomainDelete,
    AlertList,
    AlertAck,
    AlertUnsuppress,
    AlertConfigGet,
    AlertConfigSet,
    MonitorLive,
    ReportsSummary,
    AppList,
    AppRequest,
    AppRecover,
    PeerList,
    PeerUpsert,
    PeerDelete,
    DnsRecords,
    DnsVerify,
    BrandingGet,
    BrandingSet,
}

/// Method/pattern table; the first column is the method predicate.
pub(crate) fn action(method: &Method, path: &str) -> Option<Action> {
    let reads = matches!(*method, Method::GET | Method::HEAD);
    let table: [(bool, &str, Action); 26] = [
        (reads, "/api/admin/branding", Action::BrandingGet),
        (
            *method == Method::POST,
            "/api/admin/branding",
            Action::BrandingSet,
        ),
        (reads, "/api/admin/dns/records", Action::DnsRecords),
        (reads, "/api/admin/dns/verify", Action::DnsVerify),
        (reads, "/api/admin/federation/peers", Action::PeerList),
        (
            *method == Method::POST,
            "/api/admin/federation/peers",
            Action::PeerUpsert,
        ),
        (
            *method == Method::DELETE,
            "/api/admin/federation/peers/{domain}",
            Action::PeerDelete,
        ),
        (reads, "/api/admin/apps", Action::AppList),
        (
            *method == Method::POST,
            "/api/admin/apps/{appId}/operations",
            Action::AppRequest,
        ),
        (
            *method == Method::POST,
            "/api/admin/apps/{appId}/operations/{operationId}/recover",
            Action::AppRecover,
        ),
        (reads, "/api/admin/monitor/live", Action::MonitorLive),
        (reads, "/api/admin/reports/summary", Action::ReportsSummary),
        (reads, "/api/admin/alerts", Action::AlertList),
        (
            *method == Method::POST,
            "/api/admin/alerts/ack",
            Action::AlertAck,
        ),
        (
            *method == Method::POST,
            "/api/admin/alerts/unsuppress",
            Action::AlertUnsuppress,
        ),
        (reads, "/api/admin/alerts/config", Action::AlertConfigGet),
        (
            *method == Method::PUT,
            "/api/admin/alerts/config",
            Action::AlertConfigSet,
        ),
        (reads, "/api/admin/domains", Action::DomainList),
        (reads, "/api/admin/domains/{id}", Action::DomainGet),
        (
            *method == Method::POST,
            "/api/admin/domains",
            Action::DomainCreate,
        ),
        (
            *method == Method::PUT,
            "/api/admin/domains/{id}",
            Action::DomainUpdate,
        ),
        (
            *method == Method::DELETE,
            "/api/admin/domains/{id}",
            Action::DomainDelete,
        ),
        (reads, "/api/admin/terms-of-use", Action::List),
        (
            *method == Method::POST,
            "/api/admin/terms-of-use",
            Action::Create,
        ),
        (
            *method == Method::PUT,
            "/api/admin/terms-of-use/{id}",
            Action::Update,
        ),
        (
            *method == Method::DELETE,
            "/api/admin/terms-of-use/{id}",
            Action::Delete,
        ),
    ];
    table
        .iter()
        .filter(|(ok, pattern, _)| *ok && crate::inventory::path_score(pattern, path).is_some())
        .max_by_key(|(_, pattern, _)| crate::inventory::path_score(pattern, path))
        .map(|(_, _, action)| *action)
}

fn is_domain(what: Action) -> bool {
    matches!(
        what,
        Action::DomainList
            | Action::DomainGet
            | Action::DomainCreate
            | Action::DomainUpdate
            | Action::DomainDelete
    )
}

/// Go sees the `/api`-stripped request path, decoded.
fn segment_path(path: &str) -> String {
    crate::guests_input::go_utf8(&crate::inventory::unescape(
        path.strip_prefix("/api").unwrap_or(path),
    ))
}

/// The permission a route's Go middleware requires.
fn gate(what: Action) -> &'static [&'static str] {
    match what {
        Action::List => &setjoin_platform::ACCESS_POLICY_READ,
        Action::Create | Action::Update | Action::Delete => &setjoin_platform::ACCESS_POLICY_WRITE,
        Action::DomainList
        | Action::DomainGet
        | Action::MonitorLive
        | Action::DnsRecords
        | Action::DnsVerify
        | Action::BrandingGet
        | Action::ReportsSummary => &setjoin_platform::MAIL_CONSOLE,
        Action::DomainCreate | Action::DomainUpdate | Action::DomainDelete => {
            &setjoin_platform::DOMAINS_WRITE
        }
        Action::AlertList | Action::AlertConfigGet => &setjoin_platform::LOGS_CONSOLE,
        Action::AlertAck | Action::AlertUnsuppress | Action::AlertConfigSet => {
            &setjoin_platform::SECURITY_WRITE
        }
        Action::BrandingSet => &setjoin_platform::MAIL_PIPELINE,
        Action::PeerList | Action::PeerUpsert | Action::PeerDelete => {
            &setjoin_platform::FEDERATION_MANAGE
        }
        Action::AppList => &setjoin_platform::APPS_VIEW,
        Action::AppRequest | Action::AppRecover => &setjoin_platform::APPS_MANAGE,
    }
}

/// Go's `r.PathValue` at `index` of the full path, as `strconv.ParseInt(.., 10, 64)`.
pub(crate) fn path_id(path: &str, index: usize) -> Option<i64> {
    let text = crate::guests_input::go_utf8(&crate::inventory::unescape(
        path.split('/').nth(index).unwrap_or(""),
    ));
    let digits = text.strip_prefix(['+', '-']).unwrap_or(&text);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<i64>().ok()
}

impl<K: KeySource + 'static> Intercept for PlatformTermsRoute<K> {
    fn requires_session(&self, _req: &Request<Body>) -> bool { true }
    fn matches(&self, r: &Request<Body>) -> bool {
        action(r.method(), r.uri().path()).is_some()
    }
    fn admits_member(&self, headers: hyper::HeaderMap, scheme: &'static str) -> BoxFuture<bool> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        Box::pin(async move {
            setjoin_authz::authorize_request(&exec, &keys, &issuer, &headers, scheme)
                .await
                .is_some()
        })
    }
    fn handle(&self, mut r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let (exec, keys, issuer) = (self.exec.clone(), self.keys.clone(), self.issuer.clone());
        let worker = self.worker.clone().unwrap_or_else(|| exec.clone());
        let local_domain = self.local_domain.clone();
        let resolver = self.resolver.clone();
        let store = self.store.clone();
        Box::pin(async move {
            let Some(what) = action(r.method(), r.uri().path()) else {
                return c.upstream.forward(r, &c.identity).await;
            };
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
            let Some(operation) = crate::jmap::random() else {
                return bare(503, "service unavailable", &c, "");
            };
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation);
            let actor = auth.context();
            let Ok(authority) = setjoin_platform::authority(&exec, actor).await else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let go_path = segment_path(r.uri().path());
            let required = gate(what);
            if !authority.allows_any(required) {
                let _ = setjoin_platform::console_denied(
                    &exec,
                    actor,
                    &go_path,
                    &required.join("|"),
                    operation,
                )
                .await;
                return bare(403, "Forbidden", &c, &id);
            }
            if authority.refused_for_scope(required) {
                let detail = format!(
                    "{} (domain-scoped principal; org-wide-only surface, domain={})",
                    required.join("|"),
                    authority.domain_scope()
                );
                let _ =
                    setjoin_platform::console_denied(&exec, actor, &go_path, &detail, operation)
                        .await;
                return bare(403, "Forbidden", &c, &id);
            }
            let head = r.method() == Method::HEAD;
            let env = Env {
                exec: &exec,
                worker: &worker,
                local_domain: &local_domain,
                resolver: &resolver,
                store: store.as_ref(),
                actor,
                authority: &authority,
                c: &c,
                id: &id,
                operation,
                go_path: &go_path,
                raw_path: r.uri().path().to_owned(),
                language: crate::chat_channels::problem_language(r.headers()),
                head,
            };
            match what {
                Action::AlertList
                | Action::AlertAck
                | Action::AlertUnsuppress
                | Action::AlertConfigGet
                | Action::AlertConfigSet => return alerts::run(what, r, &env).await,
                Action::MonitorLive | Action::ReportsSummary => {
                    return monitor::run(what, r, &env).await
                }
                Action::AppList | Action::AppRequest | Action::AppRecover => {
                    return apps::run(what, r, &env).await
                }
                Action::PeerList | Action::PeerUpsert | Action::PeerDelete => {
                    return federation::run(what, r, &env).await
                }
                Action::DnsRecords | Action::DnsVerify => return dns::run(what, r, &env).await,
                Action::BrandingGet | Action::BrandingSet => {
                    return branding::run(what, r, &env).await
                }
                _ if is_domain(what) => return domains::run(what, r, &env).await,
                _ => {}
            }
            let reply = |body: String, status: u16| {
                // net/http buffers 2 KiB of a handler's output; a larger single write
                // is flushed before the handler returns and sent chunked.
                let chunked = body.len() > 2048 && !head;
                let mut response = crate::jmap::reply::response(body, c.identity.proto, id.clone());
                *response.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
                if chunked {
                    response.headers_mut().insert(
                        "transfer-encoding",
                        hyper::header::HeaderValue::from_static("chunked"),
                    );
                }
                response
            };
            let no_content = || {
                let mut response = reply(String::new(), 204);
                response.headers_mut().remove("content-type");
                response
            };
            let ip = c.identity.client_ip.to_string();
            match what {
                Action::DomainList
                | Action::DomainGet
                | Action::DomainCreate
                | Action::DomainUpdate
                | Action::DomainDelete
                | Action::AlertList
                | Action::AlertAck
                | Action::AlertUnsuppress
                | Action::AlertConfigGet
                | Action::AlertConfigSet
                | Action::MonitorLive
                | Action::ReportsSummary
                | Action::AppList
                | Action::AppRequest
                | Action::AppRecover
                | Action::PeerList
                | Action::PeerUpsert
                | Action::PeerDelete
                | Action::DnsRecords
                | Action::DnsVerify
                | Action::BrandingGet
                | Action::BrandingSet => unreachable!("handled by the group above"),
                Action::List => {
                    let limit = terms::limit(
                        crate::admin_identity_input::query(r.uri(), "limit").as_deref(),
                    );
                    match terms::list(&exec, limit).await {
                        Ok(body) => reply(body, 200),
                        Err(_) => bare(500, "database error", &c, &id),
                    }
                }
                Action::Create => {
                    let Ok(body) = json_body::<TouBody>(&mut r, 1 << 20).await else {
                        return bare(400, "invalid JSON", &c, &id);
                    };
                    let doc = body.0;
                    if !doc.valid() {
                        return bare(400, "name, body_md, and version >= 1 are required", &c, &id);
                    }
                    match terms::create(&exec, actor, &doc, &ip, operation).await {
                        CommandOutcome::Committed(Done::Created(new)) => {
                            reply(setjoin_platform::done(format!("{{\"id\":{new}}}")), 201)
                        }
                        CommandOutcome::Committed(_) | CommandOutcome::RolledBack(_) => {
                            bare(500, "request failed", &c, &id)
                        }
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::Update => {
                    let Some(target) = path_id(r.uri().path(), 4) else {
                        return bare(400, "invalid ToU ID", &c, &id);
                    };
                    let Ok(body) = json_body::<TouBody>(&mut r, 1 << 20).await else {
                        return bare(400, "invalid JSON", &c, &id);
                    };
                    let doc = body.0;
                    if !doc.valid() {
                        return bare(400, "name, body_md, and version >= 1 are required", &c, &id);
                    }
                    match terms::update(&exec, actor, target, &doc, &ip, operation).await {
                        CommandOutcome::Committed(Done::Updated) => no_content(),
                        CommandOutcome::Committed(Done::NotFound) => {
                            bare(404, "terms_of_use not found", &c, &id)
                        }
                        CommandOutcome::Committed(_) | CommandOutcome::RolledBack(_) => {
                            bare(500, "request failed", &c, &id)
                        }
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
                Action::Delete => {
                    let Some(target) = path_id(r.uri().path(), 4) else {
                        return bare(400, "invalid ToU ID", &c, &id);
                    };
                    match terms::delete(&exec, actor, target, &ip, operation).await {
                        CommandOutcome::Committed(Done::Updated) => no_content(),
                        CommandOutcome::Committed(Done::NotFound) => {
                            bare(404, "terms_of_use not found", &c, &id)
                        }
                        CommandOutcome::Committed(_) => bare(500, "request failed", &c, &id),
                        // Go answers 500 with the reducer detail for a failed DELETE.
                        CommandOutcome::RolledBack(_) => bare(500, "request failed", &c, &id),
                        CommandOutcome::Unknown { operation } => {
                            unknown_outcome(operation, &c, &id)
                        }
                    }
                }
            }
        })
    }
}

/// Go's `touRequest` decoded with `json.Decoder.Decode`: case-folded keys, `null` keeps
/// the previous value (zero), unknown keys are ignored, a wrongly typed field fails the
/// decode, an integer field takes only a JSON integer, and only the first value is read.
struct TouBody(Document);
impl<'de> serde::Deserialize<'de> for TouBody {
    fn deserialize<D: serde::Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct Fields;
        fn zero() -> Document {
            Document {
                name: String::new(),
                version: 0,
                body_md: String::new(),
                lang: String::new(),
                require_scroll: false,
                enabled: false,
            }
        }
        impl<'de> Visitor<'de> for Fields {
            type Value = TouBody;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a JSON object")
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<TouBody, E> {
                Ok(TouBody(zero()))
            }
            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<TouBody, M::Error> {
                let mut doc = zero();
                while let Some(key) = map.next_key::<String>()? {
                    match crate::guests_input::fold(&key).as_str() {
                        "name" => {
                            if let Some(v) = map.next_value::<Option<String>>()? {
                                doc.name = v;
                            }
                        }
                        "body_md" => {
                            if let Some(v) = map.next_value::<Option<String>>()? {
                                doc.body_md = v;
                            }
                        }
                        "lang" => {
                            if let Some(v) = map.next_value::<Option<String>>()? {
                                doc.lang = v;
                            }
                        }
                        "version" => {
                            if let Some(n) = map.next_value::<Option<serde_json::Number>>()? {
                                doc.version = n
                                    .as_i64()
                                    .ok_or_else(|| serde::de::Error::custom("not an integer"))?;
                            }
                        }
                        "require_scroll" => {
                            if let Some(v) = map.next_value::<Option<bool>>()? {
                                doc.require_scroll = v;
                            }
                        }
                        "enabled" => {
                            if let Some(v) = map.next_value::<Option<bool>>()? {
                                doc.enabled = v;
                            }
                        }
                        _ => {
                            let _: serde::de::IgnoredAny = map.next_value()?;
                        }
                    }
                }
                Ok(TouBody(doc))
            }
        }
        decoder.deserialize_any(Fields)
    }
}

/// Go's `http.MaxBytesReader(w, r.Body, cap)` plus `Decode`: only the first JSON value is
/// read, and it fails when it does not end within the first `cap` bytes.
pub(crate) async fn json_body<T: serde::de::DeserializeOwned>(
    r: &mut Request<Body>,
    cap: usize,
) -> Result<T, ()> {
    use http_body_util::BodyExt;
    let mut bytes = Vec::new();
    while bytes.len() < cap {
        let Some(frame) = r.body_mut().frame().await else {
            break;
        };
        if let Ok(data) = frame.map_err(|_| ())?.into_data() {
            bytes.extend_from_slice(&data[..data.len().min(cap - bytes.len())]);
        }
    }
    let fixed = crate::guests_input::go_json_bytes(&bytes);
    match serde_json::Deserializer::from_slice(&fixed)
        .into_iter::<T>()
        .next()
    {
        Some(Ok(value)) => Ok(value),
        _ => Err(()),
    }
}
