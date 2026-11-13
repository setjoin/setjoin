//! F06 slice `dlp`: the unauthenticated link-protect click, `GET /link-protect?token=...`.
//!
//! Mirrors frozen Go's `linkprotect.LinkProtectHandler`: verify the HMAC-signed token (current
//! key, then the retiring key while the rotation window is open), run the scanner pipeline
//! (Safe Browsing when `SAFEBROWSING_API_KEY` is set, then the Spamhaus DBL over DNS), let the
//! `link_protect_check_and_audit` reducer decide and audit in one transaction, and answer a 302
//! (safe, or confirmed unknown), the block page (malicious) or the warn page (unknown, or the
//! audit failed: fail closed). Authority is the signed token alone: the mailbox and message come
//! from its claims, never from the query string.
use crate::{Body, BoxFuture, Intercept, RequestContext};
use hmac::{Hmac, Mac};
use hyper::{Method, Request, Response};
use setjoin_pg::ScopedExecutor;
use sha2::Sha256;
use std::sync::Arc;

type Hs256 = Hmac<Sha256>;

/// Go's `TokenKeys`, held as the DERIVED HMAC keys: the current secret at `version` and the
/// retiring secret at `version-1`. A process that only handles link tokens (the SMTP gateway)
/// receives these keys pre-derived and never sees the master `JWT_SECRET`.
#[derive(Clone, Default)]
pub struct TokenKeys {
    current: Vec<u8>,
    previous: Vec<u8>,
    pub version: i64,
}

impl TokenKeys {
    pub fn new(secret: &[u8], previous: &[u8], version: i64) -> Self {
        let version = version.max(1);
        Self {
            current: Self::derive(secret, version),
            // Go `previousTokenKey`: no previous generation at version 1 or when drained.
            previous: if previous.is_empty() || version <= 1 {
                Vec::new()
            } else {
                Self::derive(previous, version - 1)
            },
            version,
        }
    }
    /// Keys derived elsewhere (the deploy renderer): used as-is, byte for byte.
    pub fn from_derived(current: &[u8], previous: &[u8], version: i64) -> Self {
        Self {
            current: current.to_vec(),
            previous: previous.to_vec(),
            version: version.max(1),
        }
    }
    /// The derived current key (empty = unconfigured: nothing verifies).
    pub fn current_key(&self) -> &[u8] {
        &self.current
    }
    /// `tokenKeyN`: HMAC(secret, "link-protect-v<version>: link-protect token hmac key").
    pub fn derive(secret: &[u8], version: i64) -> Vec<u8> {
        let mut mac = Hs256::new_from_slice(secret).expect("hmac accepts any key length");
        mac.update(format!("link-protect-v{version}: link-protect token hmac key").as_bytes());
        mac.finalize().into_bytes().to_vec()
    }
    /// Keys from the process environment: the master-secret form (`JWT_SECRET`, as Go) when set,
    /// else the pre-derived `SMTP_LINK_PROTECT_*` keys the SMTP unit receives, else unconfigured.
    pub fn from_env() -> Self {
        let env = |name: &str| std::env::var(name).ok();
        if env("JWT_SECRET").is_some_and(|s| !s.is_empty()) {
            let version = env("JWT_LINK_PROTECT_TOKEN_VERSION")
                .and_then(|v| v.trim().parse::<i64>().ok())
                .unwrap_or(0);
            return Self::new(
                env("JWT_SECRET").unwrap_or_default().as_bytes(),
                env("JWT_LINK_PROTECT_TOKEN_PREVIOUS_SECRET")
                    .unwrap_or_default()
                    .as_bytes(),
                version,
            );
        }
        match Self::from_derived_env(&env) {
            Ok(Some(keys)) => keys,
            _ => Self::default(),
        }
    }
    /// `SMTP_LINK_PROTECT_KEY` / `_KEY_PREVIOUS` (64 hex digits each) and
    /// `SMTP_LINK_PROTECT_VERSION`; `None` when no current key is set.
    pub fn from_derived_env(get: &dyn Fn(&str) -> Option<String>) -> Result<Option<Self>, String> {
        let Some(current) = get("SMTP_LINK_PROTECT_KEY").filter(|v| !v.is_empty()) else {
            return Ok(None);
        };
        let hex = |name: &str, value: &str| -> Result<Vec<u8>, String> {
            let bytes = value.as_bytes();
            if bytes.len() != 64 || !bytes.iter().all(u8::is_ascii_hexdigit) {
                return Err(format!(
                    "{name} must be 64 hex digits (a derived HMAC-SHA256 key)"
                ));
            }
            Ok(bytes
                .chunks(2)
                .map(|p| {
                    u8::from_str_radix(std::str::from_utf8(p).expect("ascii"), 16).expect("hex")
                })
                .collect())
        };
        let version = match get("SMTP_LINK_PROTECT_VERSION").filter(|v| !v.is_empty()) {
            Some(v) => v
                .trim()
                .parse::<i64>()
                .map_err(|_| "SMTP_LINK_PROTECT_VERSION: not a number".to_owned())?,
            None => 1,
        };
        if version < 1 {
            return Err("SMTP_LINK_PROTECT_VERSION must be >= 1".into());
        }
        let current = hex("SMTP_LINK_PROTECT_KEY", &current)?;
        let previous = match get("SMTP_LINK_PROTECT_KEY_PREVIOUS").filter(|v| !v.is_empty()) {
            Some(p) if version <= 1 => {
                let _ = p;
                return Err("SMTP_LINK_PROTECT_KEY_PREVIOUS is set but SMTP_LINK_PROTECT_VERSION=1 has no previous generation".into());
            }
            Some(p) => hex("SMTP_LINK_PROTECT_KEY_PREVIOUS", &p)?,
            None => Vec::new(),
        };
        Ok(Some(Self::from_derived(&current, &previous, version)))
    }
}

/// The signed claims (`TokenClaims`): `u` URL, `m` Message-ID header, `b` mailbox, `e` expiry.
#[derive(Default, Debug)]
pub struct Claims {
    pub url: String,
    pub message_id: String,
    pub mailbox: i64,
    pub expires: i64,
}

/// Go's base64 decoders skip `\r` and `\n`.
fn b64url(text: &str) -> Option<Vec<u8>> {
    use base64::{
        alphabet::URL_SAFE,
        engine::{general_purpose::GeneralPurpose, DecodePaddingMode, GeneralPurposeConfig},
        Engine,
    };
    let engine = GeneralPurpose::new(
        &URL_SAFE,
        GeneralPurposeConfig::new()
            .with_decode_allow_trailing_bits(true)
            .with_decode_padding_mode(DecodePaddingMode::RequireCanonical),
    );
    let cleaned: String = text.chars().filter(|c| *c != '\r' && *c != '\n').collect();
    engine.decode(cleaned).ok()
}

fn verify_with(token: &str, key: &[u8], now: i64) -> Option<Claims> {
    let (payload_b64, sig_b64) = token.split_once('.')?;
    let sig = b64url(sig_b64)?;
    let mut mac = Hs256::new_from_slice(key).ok()?;
    mac.update(payload_b64.as_bytes());
    mac.verify_slice(&sig).ok()?;
    let payload = b64url(payload_b64)?;
    let fixed = crate::guests_input::go_json_bytes(&payload);
    let raw: crate::mail_security_input::LinkClaims = serde_json::from_slice(&fixed).ok()?;
    if now > raw.expires {
        return None;
    }
    Some(Claims {
        url: raw.url,
        message_id: raw.message_id,
        mailbox: raw.mailbox,
        expires: raw.expires,
    })
}

/// `VerifyTokenN`.
pub fn verify_token(token: &str, keys: &TokenKeys, now: i64) -> Option<Claims> {
    if keys.current.is_empty() {
        return None;
    }
    if let Some(claims) = verify_with(token, &keys.current, now) {
        return Some(claims);
    }
    if keys.previous.is_empty() {
        return None;
    }
    verify_with(token, &keys.previous, now)
}

// ---- Go net/url authority parsing (the scan target) ----

pub use setjoin_authz::go_url::{go_url_parse, parse_url_host, GoUrl};

/// `extractURLDomain`: a bare domain is tolerated by prepending a scheme.
pub fn extract_domain(raw: &str) -> Result<String, ()> {
    if raw.is_empty() {
        return Err(());
    }
    if raw.contains("://") {
        parse_url_host(raw)
    } else {
        parse_url_host(&format!("http://{raw}"))
    }
}

// ---- scanners ----

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Verdict {
    Safe,
    Malicious,
    Unknown,
}

impl Verdict {
    pub fn text(self) -> &'static str {
        match self {
            Verdict::Safe => "safe",
            Verdict::Malicious => "malicious",
            Verdict::Unknown => "unknown",
        }
    }
}

/// Why a DNS lookup produced no addresses.
pub enum DnsFailure {
    /// NXDOMAIN or an empty answer: Go's `DNSError.IsNotFound`.
    NotFound,
    Other(String),
}

pub trait Dns: Send + Sync + 'static {
    fn lookup(&self, name: String) -> BoxFuture<Result<Vec<String>, DnsFailure>>;
}

fn classify(error: &hickory_resolver::net::NetError) -> DnsFailure {
    use hickory_resolver::net::{DnsError, NetError};
    match error {
        NetError::Dns(DnsError::NoRecordsFound(_)) => DnsFailure::NotFound,
        other => DnsFailure::Other(other.to_string()),
    }
}

async fn resolve(
    resolver: hickory_resolver::TokioResolver,
    name: String,
) -> Result<Vec<String>, DnsFailure> {
    match resolver.lookup_ip(name).await {
        Ok(found) => Ok(found.iter().map(|ip| ip.to_string()).collect()),
        Err(error) => Err(classify(&error)),
    }
}

/// The host's resolver configuration (`/etc/resolv.conf`), read per lookup like Go's.
pub struct SystemDns;
impl Dns for SystemDns {
    fn lookup(&self, name: String) -> BoxFuture<Result<Vec<String>, DnsFailure>> {
        Box::pin(async move {
            let resolver = hickory_resolver::TokioResolver::builder_tokio()
                .and_then(|b| b.build())
                .map_err(|e| DnsFailure::Other(e.to_string()))?;
            resolve(resolver, name).await
        })
    }
}

/// One fixed UDP name server (tests, and a fixed-resolver deployment).
pub struct FixedDns(pub std::net::SocketAddr);
impl Dns for FixedDns {
    fn lookup(&self, name: String) -> BoxFuture<Result<Vec<String>, DnsFailure>> {
        let addr = self.0;
        Box::pin(async move {
            use hickory_resolver::config::{NameServerConfig, ResolverConfig};
            use hickory_resolver::net::runtime::TokioRuntimeProvider;
            let mut server = NameServerConfig::udp(addr.ip());
            for connection in &mut server.connections {
                connection.port = addr.port();
            }
            let mut builder = hickory_resolver::Resolver::builder_with_config(
                ResolverConfig::from_name_servers(vec![server]),
                TokioRuntimeProvider::default(),
            );
            builder.options_mut().attempts = 1;
            builder.options_mut().timeout = std::time::Duration::from_secs(2);
            let resolver = builder
                .build()
                .map_err(|e| DnsFailure::Other(e.to_string()))?;
            resolve(resolver, name).await
        })
    }
}

/// Go's `isDomainName`: the resolver refuses any other name without asking a server and
/// reports it as not found.
pub fn is_domain_name(name: &str) -> bool {
    if name == "." {
        return true;
    }
    let b = name.as_bytes();
    if b.is_empty() || b.len() > 254 || (b.len() == 254 && b[253] != b'.') {
        return false;
    }
    let (mut last, mut non_numeric, mut part) = (b'.', false, 0usize);
    for &c in b {
        match c {
            b'a'..=b'z' | b'A'..=b'Z' | b'_' => {
                non_numeric = true;
                part += 1;
            }
            b'0'..=b'9' => part += 1,
            b'-' => {
                if last == b'.' {
                    return false;
                }
                part += 1;
                non_numeric = true;
            }
            b'.' => {
                if last == b'.' || last == b'-' || part > 63 || part == 0 {
                    return false;
                }
                part = 0;
            }
            _ => return false,
        }
        last = c;
    }
    !(last == b'-' || part > 63) && non_numeric
}

/// `SpamhausDBLScanner.Check`.
async fn spamhaus(dns: &dyn Dns, url: &str) -> Result<Verdict, String> {
    let domain = extract_domain(url).map_err(|()| "cannot extract domain from URL".to_owned())?;
    let name = format!("{domain}.dbl.spamhaus.org");
    if !is_domain_name(&name) {
        return Ok(Verdict::Safe);
    }
    match dns.lookup(name).await {
        Ok(addrs) => Ok(if addrs.iter().any(|a| a.starts_with("127.0.1.")) {
            Verdict::Malicious
        } else {
            Verdict::Safe
        }),
        Err(DnsFailure::NotFound) => Ok(Verdict::Safe),
        Err(DnsFailure::Other(e)) => Err(e),
    }
}

/// `SafeBrowsingScanner.Check`: a fixed endpoint, 3 s per check.
async fn safe_browsing(endpoint: &str, key: &str, url: &str) -> Result<Verdict, String> {
    let body = format!(
        "{{\"client\":{{\"clientId\":\"mailserver\",\"clientVersion\":\"1.0.0\"}},\"threatInfo\":{{\"threatTypes\":[\"MALWARE\",\"SOCIAL_ENGINEERING\",\"UNWANTED_SOFTWARE\",\"POTENTIALLY_HARMFUL_APPLICATION\"],\"platformTypes\":[\"ANY_PLATFORM\"],\"threatEntryTypes\":[\"URL\"],\"threatEntries\":[{{\"url\":{}}}]}}}}",
        crate::problem::go_string(url)
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .map_err(|e| e.to_string())?;
    let response = client
        .post(format!("{endpoint}/v5/threatMatches:find?key={key}"))
        .header("content-type", "application/json")
        .body(body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if response.status() != reqwest::StatusCode::OK {
        return Err(format!("HTTP {}", response.status().as_u16()));
    }
    let bytes = response.bytes().await.map_err(|e| e.to_string())?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    let found = match value.get("matches") {
        Some(serde_json::Value::Array(items)) => !items.is_empty(),
        Some(serde_json::Value::Null) | None => false,
        Some(_) => return Err("decode response".into()),
    };
    Ok(if found {
        Verdict::Malicious
    } else {
        Verdict::Safe
    })
}

/// The scanner configuration of one gateway.
#[derive(Clone)]
pub struct Scanners {
    pub safe_browsing_key: String,
    pub safe_browsing_endpoint: String,
    pub dns: Arc<dyn Dns>,
}

/// `ScanPipeline`: the verdict, the per-scanner results (sorted by name) and `allErrors`.
async fn scan(scanners: &Scanners, url: &str) -> (Verdict, Vec<(&'static str, Verdict)>, bool) {
    let mut results: Vec<(&'static str, Verdict)> = vec![];
    let mut has_unknown = false;
    let mut all_errors = true;
    let mut count = 0;
    for name in ["safebrowsing", "spamhaus"] {
        let verdict = match name {
            "safebrowsing" if !scanners.safe_browsing_key.is_empty() => Some(
                safe_browsing(
                    &scanners.safe_browsing_endpoint,
                    &scanners.safe_browsing_key,
                    url,
                )
                .await,
            ),
            "spamhaus" => Some(spamhaus(scanners.dns.as_ref(), url).await),
            _ => None,
        };
        let Some(verdict) = verdict else { continue };
        count += 1;
        match verdict {
            Err(_) => {
                results.push((name, Verdict::Unknown));
                has_unknown = true;
            }
            Ok(v) => {
                all_errors = false;
                results.push((name, v));
                if v == Verdict::Malicious {
                    results.sort_by_key(|r| r.0);
                    return (Verdict::Malicious, results, false);
                }
                if v == Verdict::Unknown {
                    has_unknown = true;
                }
            }
        }
    }
    results.sort_by_key(|r| r.0);
    let verdict = if count == 0 {
        Verdict::Safe
    } else if all_errors || has_unknown {
        Verdict::Unknown
    } else {
        Verdict::Safe
    };
    (verdict, results, count > 0 && all_errors)
}

// ---- the route ----

pub struct LinkProtectRoute {
    pub worker: ScopedExecutor,
    pub keys: TokenKeys,
    pub scanners: Scanners,
    /// A `SETJOIN_CONFIG` file may hold the secrets: Go answers every click.
    pub forward: bool,
}

pub const SAFE_BROWSING_ENDPOINT: &str = "https://safebrowsing.googleapis.com";

impl LinkProtectRoute {
    /// Go's `cfg.JWTSecret`, `LinkProtectTokenKeys()` and `SafeBrowsingAPIKey` from the environment.
    /// With a `SETJOIN_CONFIG` file and any of those unset in the environment the file might set
    /// them, so the route forwards to Go.
    pub fn from_env(worker: ScopedExecutor) -> Self {
        let env = |name: &str| std::env::var(name).unwrap_or_default();
        let config_file = std::env::var("SETJOIN_CONFIG").is_ok_and(|v| !v.is_empty());
        let missing = ["JWT_SECRET", "SAFEBROWSING_API_KEY"]
            .iter()
            .any(|n| std::env::var(n).is_err());
        Self {
            worker,
            keys: TokenKeys::from_env(),
            scanners: Scanners {
                safe_browsing_key: env("SAFEBROWSING_API_KEY"),
                safe_browsing_endpoint: SAFE_BROWSING_ENDPOINT.into(),
                dns: Arc::new(SystemDns),
            },
            forward: config_file && missing,
        }
    }
    pub fn with_dns(mut self, dns: Arc<dyn Dns>) -> Self {
        self.scanners.dns = dns;
        self
    }
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// `http.Error`: text/plain, nosniff, the message and a newline.
fn text_error(status: u16, message: &str, c: &RequestContext, id: &str) -> Response<Body> {
    let mut r =
        crate::jmap::reply::response(format!("{message}\n"), c.identity.proto, id.to_owned());
    *r.status_mut() = hyper::StatusCode::from_u16(status).expect("status");
    r.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    r
}

/// A 200 page written by the handler: the type is sniffed from the content, and a body past
/// net/http's 2 KiB buffer is flushed before the handler returns and sent chunked.
fn page(body: String, head: bool, c: &RequestContext, id: &str) -> Response<Body> {
    let chunked = body.len() > 2048 && !head;
    let mut r = crate::jmap::reply::response(body, c.identity.proto, id.to_owned());
    r.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    if chunked {
        r.headers_mut().insert(
            "transfer-encoding",
            hyper::header::HeaderValue::from_static("chunked"),
        );
    }
    r
}

fn hex_escape_non_ascii(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        if b < 0x80 {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02x}"));
        }
    }
    out
}

/// Go's `path.Clean`.
fn path_clean(p: &str) -> String {
    if p.is_empty() {
        return ".".into();
    }
    let rooted = p.starts_with('/');
    let mut stack: Vec<&str> = vec![];
    for part in p.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if stack.last().is_some_and(|l| *l != "..") {
                    stack.pop();
                } else if !rooted {
                    stack.push("..");
                }
            }
            other => stack.push(other),
        }
    }
    let joined = stack.join("/");
    match (rooted, joined.is_empty()) {
        (true, true) => "/".into(),
        (true, false) => format!("/{joined}"),
        (false, true) => ".".into(),
        (false, false) => joined,
    }
}

/// `http.Redirect(w, r, url, 302)` for a GET or HEAD request.
fn redirect(
    url: &str,
    head: bool,
    confirmed: bool,
    c: &RequestContext,
    id: &str,
) -> Response<Body> {
    let mut target = url.to_owned();
    if let Ok(parsed) = go_url_parse(url) {
        if parsed.scheme.is_empty() && parsed.host.is_empty() {
            if target.is_empty() || !target.starts_with('/') {
                // The request path is /link-protect: its directory is "/".
                target = format!("/{target}");
            }
            let (path, query) = match target.find('?') {
                Some(i) => (target[..i].to_owned(), target[i..].to_owned()),
                None => (target.clone(), String::new()),
            };
            let trailing = path.ends_with('/');
            let mut cleaned = path_clean(&path);
            if trailing && !cleaned.ends_with('/') {
                cleaned.push('/');
            }
            target = cleaned + &query;
        }
    }
    let body = if head {
        String::new()
    } else {
        format!(
            "<a href=\"{}\">Found</a>.\n\n",
            target
                .replace('&', "&amp;")
                .replace('<', "&lt;")
                .replace('>', "&gt;")
                .replace('"', "&#34;")
                .replace('\'', "&#39;")
        )
    };
    let mut r = crate::jmap::reply::response(body, c.identity.proto, id.to_owned());
    *r.status_mut() = hyper::StatusCode::FOUND;
    if confirmed {
        r.headers_mut().insert(
            "x-linkprotect-confirmed",
            hyper::header::HeaderValue::from_static("1"),
        );
    }
    if let Ok(location) = hyper::header::HeaderValue::from_str(&hex_escape_non_ascii(&target)) {
        r.headers_mut().insert("location", location);
    }
    r.headers_mut().insert(
        "content-type",
        hyper::header::HeaderValue::from_static("text/html; charset=utf-8"),
    );
    r
}

fn warn_page(url: &str, token: &str) -> String {
    crate::link_protect_pages::WARN
        .replace("{URL}", &escape_html(url))
        .replace("{TOKEN}", token)
}

impl Intercept for LinkProtectRoute {
    fn matches(&self, r: &Request<Body>) -> bool {
        matches!(*r.method(), Method::GET | Method::HEAD) && r.uri().path() == "/link-protect"
    }
    fn handle(&self, r: Request<Body>, c: RequestContext) -> BoxFuture<Response<Body>> {
        let (worker, keys, scanners, forward) = (
            self.worker.clone(),
            self.keys.clone(),
            self.scanners.clone(),
            self.forward,
        );
        Box::pin(async move {
            if forward {
                return c.upstream.forward(r, &c.identity).await;
            }
            let Some(operation) = crate::jmap::random() else {
                return text_error(503, "service unavailable", &c, "");
            };
            let id = crate::jmap::reply::request_id(r.headers().get("x-request-id"), operation);
            let head = *r.method() == Method::HEAD;
            let query = |name: &str| crate::admin_identity_input::query(r.uri(), name);
            let token = query("token").unwrap_or_default();
            if token.is_empty() {
                return text_error(400, "link_protect: missing token", &c, &id);
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| d.as_secs() as i64);
            let Some(claims) = verify_token(&token, &keys, now) else {
                return text_error(400, "link_protect: invalid or expired token", &c, &id);
            };
            let Ok(strict) = setjoin_mail_security::dlp::strict_mode(&worker).await else {
                return c.upstream.forward(r, &c.identity).await;
            };
            let (base, results, all_errors) = scan(&scanners, &claims.url).await;
            let scanner_json = format!(
                "{{{}}}",
                results
                    .iter()
                    .map(|(name, v)| format!("\"{name}\":\"{}\"", v.text()))
                    .collect::<Vec<_>>()
                    .join(",")
            );
            let ip = c.identity.client_ip.to_string();
            let decided = setjoin_mail_security::dlp::click_audit(
                &worker,
                claims.mailbox,
                &claims.url,
                &claims.message_id,
                base.text(),
                &scanner_json,
                all_errors,
                strict,
                &ip,
                operation,
            )
            .await;
            use setjoin_mail_security::dlp::Click;
            let verdict = match decided {
                Click::Verdict(v) => v,
                Click::Unscoped => return c.upstream.forward(r, &c.identity).await,
                // FAIL CLOSED: no durable audit row means no redirect.
                Click::Failed => return page(warn_page(&claims.url, &token), head, &c, &id),
            };
            match verdict.as_str() {
                "safe" => redirect(&claims.url, head, false, &c, &id),
                "malicious" => page(
                    crate::link_protect_pages::BLOCK.replace("{URL}", &escape_html(&claims.url)),
                    head,
                    &c,
                    &id,
                ),
                _ => {
                    if query("confirm").as_deref() == Some("1") {
                        redirect(&claims.url, head, true, &c, &id)
                    } else {
                        page(warn_page(&claims.url, &token), head, &c, &id)
                    }
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sign(url: &str, secret: &[u8], version: i64, expires: i64) -> String {
        use base64::{engine::general_purpose::URL_SAFE, Engine};
        let payload = format!("{{\"u\":{url:?},\"m\":\"<m@x>\",\"b\":7,\"e\":{expires}}}");
        let b64 = URL_SAFE.encode(payload);
        let mut mac = Hs256::new_from_slice(&TokenKeys::derive(secret, version)).unwrap();
        mac.update(b64.as_bytes());
        format!("{b64}.{}", URL_SAFE.encode(mac.finalize().into_bytes()))
    }

    #[test]
    fn token_verifies_current_then_retiring_key_and_rejects_the_rest() {
        let keys = TokenKeys::new(b"new", b"old", 2);
        let now = 1_000;
        let current = sign("https://a.test/", b"new", 2, 2_000);
        assert_eq!(verify_token(&current, &keys, now).unwrap().mailbox, 7);
        let retiring = sign("https://a.test/", b"old", 1, 2_000);
        assert!(verify_token(&retiring, &keys, now).is_some());
        // The retiring key stops verifying once drained, and a version-2 label is not version 1.
        assert!(verify_token(&retiring, &TokenKeys::new(b"new", b"", 2), now).is_none());
        assert!(verify_token(&sign("u", b"old", 2, 2_000), &keys, now).is_none());
        assert!(verify_token(&sign("u", b"new", 2, 999), &keys, now).is_none());
        assert!(verify_token("nodot", &keys, now).is_none());
        let (payload, _) = current.split_once('.').unwrap();
        assert!(verify_token(&format!("{payload}.AAAA"), &keys, now).is_none());
    }

    #[test]
    fn predrived_keys_are_byte_equal_to_master_derivation_both_ways() {
        let (master, old) = (
            b"master-secret-0123456789abcdef0123".as_slice(),
            b"old-master-secret".as_slice(),
        );
        // The SMTP crate signs with its own derivation: it must equal Go's tokenKeyN.
        for version in [1, 2, 7] {
            assert_eq!(
                setjoin_smtp::inbound::derive_link_key(master, version),
                TokenKeys::derive(master, version)
            );
        }
        let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
        let env = |version: &str, prev: bool| {
            let pairs = vec![
                (
                    "SMTP_LINK_PROTECT_KEY".to_owned(),
                    hex(&TokenKeys::derive(master, 2)),
                ),
                (
                    "SMTP_LINK_PROTECT_KEY_PREVIOUS".to_owned(),
                    if prev {
                        hex(&TokenKeys::derive(old, 1))
                    } else {
                        String::new()
                    },
                ),
                ("SMTP_LINK_PROTECT_VERSION".to_owned(), version.to_owned()),
            ];
            move |n: &str| pairs.iter().find(|p| p.0 == n).map(|p| p.1.clone())
        };
        let derived = TokenKeys::from_derived_env(&env("2", true))
            .unwrap()
            .unwrap();
        let from_master = TokenKeys::new(master, old, 2);
        let now = 1_000;
        // master-signed tokens verify under the pre-derived keys, current and retiring.
        assert!(verify_token(&sign("https://a.test/", master, 2, 2_000), &derived, now).is_some());
        assert!(verify_token(&sign("https://a.test/", old, 1, 2_000), &derived, now).is_some());
        assert!(verify_token(&sign("u", old, 2, 2_000), &derived, now).is_none());
        // tokens signed with the pre-derived key (the SMTP signer) verify under the master form.
        use base64::Engine as _;
        let payload = "{\"u\":\"https://b.test/\",\"m\":\"<m@x>\",\"b\":7,\"e\":2000}";
        let b64 = base64::engine::general_purpose::URL_SAFE.encode(payload);
        let sig = ring::hmac::sign(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, derived.current_key()),
            b64.as_bytes(),
        );
        let token = format!(
            "{b64}.{}",
            base64::engine::general_purpose::URL_SAFE.encode(sig)
        );
        assert_eq!(
            verify_token(&token, &from_master, now).unwrap().url,
            "https://b.test/"
        );
        // drained previous: retiring tokens rejected; malformed or inconsistent settings refused.
        let drained = TokenKeys::from_derived_env(&env("2", false))
            .unwrap()
            .unwrap();
        assert!(verify_token(&sign("u", old, 1, 2_000), &drained, now).is_none());
        assert!(TokenKeys::from_derived_env(&env("1", true)).is_err());
        assert!(TokenKeys::from_derived_env(
            &|n: &str| (n == "SMTP_LINK_PROTECT_KEY").then(|| "abc".into())
        )
        .is_err());
        assert!(TokenKeys::from_derived_env(&|_: &str| None)
            .unwrap()
            .is_none());
        assert!(verify_token(&sign("u", master, 1, 2_000), &TokenKeys::default(), now).is_none());
    }

    #[test]
    fn spamhaus_scan_target_is_the_authority_not_the_userinfo() {
        for (url, host) in [
            ("http://internal.test:80@evil.example/", "evil.example"),
            ("HTTPS://EVIL.Example:8443/Case", "evil.example"),
            ("http://[::1]:8080/p", "::1"),
            ("ok.example/path?x=1", "ok.example"),
            ("https://ok.example", "ok.example"),
            // No "://": the bare-domain rule prepends a scheme, so "mailto:a" is userinfo.
            ("mailto:a@evil.example", "evil.example"),
        ] {
            assert_eq!(extract_domain(url).as_deref(), Ok(host), "{url}");
        }
        for url in [
            "",
            "http://[bad/",
            "http://a b/",
            "http://a:x/",
            "https://ok.example/%zz",
            "/only/a/path",
        ] {
            assert!(extract_domain(url).is_err(), "{url}");
        }
    }

    #[test]
    fn invalid_dns_names_are_not_found_without_a_query() {
        assert!(is_domain_name("evil.example.dbl.spamhaus.org"));
        assert!(is_domain_name("a_b.c-d.example."));
        for bad in [
            "..dbl.spamhaus.org",
            "::1.dbl.spamhaus.org",
            "-a.example",
            "a-.example",
            "a b.example",
            "é.example",
            "",
        ] {
            assert!(!is_domain_name(bad), "{bad}");
        }
        assert!(!is_domain_name(&format!("{}.example", "a".repeat(64))));
    }

    #[test]
    fn relative_redirect_is_cleaned_like_net_http() {
        assert_eq!(path_clean("/ok.example/path"), "/ok.example/path");
        assert_eq!(path_clean("/../up/../x/"), "/x");
        assert_eq!(path_clean(""), ".");
    }

    async fn serve_once(status: &'static str, body: &'static str) -> String {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0u8; 4096];
            let n = stream.read(&mut buffer).await.unwrap();
            let request = String::from_utf8_lossy(&buffer[..n]).into_owned();
            assert!(request.starts_with("POST /v5/threatMatches:find?key=k HTTP/1.1"));
            assert!(request.contains("\"url\":\"https://x.test/\""));
            let reply = format!(
                "HTTP/1.1 {status}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(reply.as_bytes()).await.unwrap();
        });
        format!("http://{address}")
    }

    #[tokio::test]
    async fn safe_browsing_maps_matches_and_failures() {
        let url = "https://x.test/";
        let malicious = serve_once("200 OK", "{\"matches\":[{\"threatType\":\"MALWARE\"}]}").await;
        assert_eq!(
            safe_browsing(&malicious, "k", url).await,
            Ok(Verdict::Malicious)
        );
        let clean = serve_once("200 OK", "{}").await;
        assert_eq!(safe_browsing(&clean, "k", url).await, Ok(Verdict::Safe));
        let null = serve_once("200 OK", "{\"matches\":null}").await;
        assert_eq!(safe_browsing(&null, "k", url).await, Ok(Verdict::Safe));
        let denied = serve_once("403 Forbidden", "{}").await;
        assert!(safe_browsing(&denied, "k", url).await.is_err());
        let garbage = serve_once("200 OK", "not json").await;
        assert!(safe_browsing(&garbage, "k", url).await.is_err());
    }

    struct Fixed(Result<Vec<String>, bool>);
    impl Dns for Fixed {
        fn lookup(&self, _: String) -> BoxFuture<Result<Vec<String>, DnsFailure>> {
            let answer = match &self.0 {
                Ok(a) => Ok(a.clone()),
                Err(true) => Err(DnsFailure::NotFound),
                Err(false) => Err(DnsFailure::Other("down".into())),
            };
            Box::pin(async move { answer })
        }
    }

    #[tokio::test]
    async fn pipeline_follows_the_scanner_contract() {
        let with = |dns: Fixed, key: &str, endpoint: String| Scanners {
            safe_browsing_key: key.into(),
            safe_browsing_endpoint: endpoint,
            dns: Arc::new(dns),
        };
        let url = "https://x.test/";
        // Listed in the DBL: malicious; unlisted: safe; outside 127.0.1.x: safe.
        let (v, r, e) = scan(
            &with(Fixed(Ok(vec!["127.0.1.2".into()])), "", String::new()),
            url,
        )
        .await;
        assert_eq!(
            (v, e, r),
            (
                Verdict::Malicious,
                false,
                vec![("spamhaus", Verdict::Malicious)]
            )
        );
        assert_eq!(
            scan(&with(Fixed(Err(true)), "", String::new()), url)
                .await
                .0,
            Verdict::Safe
        );
        assert_eq!(
            scan(
                &with(Fixed(Ok(vec!["127.0.2.2".into()])), "", String::new()),
                url
            )
            .await
            .0,
            Verdict::Safe
        );
        // A DNS outage alone is unknown with allErrors (passthrough), never a block.
        let (v, _, e) = scan(&with(Fixed(Err(false)), "", String::new()), url).await;
        assert_eq!((v, e), (Verdict::Unknown, true));
        // Safe Browsing malicious short-circuits Spamhaus; a Safe Browsing outage plus a clean
        // DBL is unknown without allErrors.
        let hit = serve_once("200 OK", "{\"matches\":[{}]}").await;
        let (v, r, _) = scan(&with(Fixed(Err(true)), "k", hit), url).await;
        assert_eq!(
            (v, r),
            (
                Verdict::Malicious,
                vec![("safebrowsing", Verdict::Malicious)]
            )
        );
        let down = serve_once("500 Internal Server Error", "").await;
        let (v, r, e) = scan(&with(Fixed(Err(true)), "k", down), url).await;
        assert_eq!(
            (v, e, r),
            (
                Verdict::Unknown,
                false,
                vec![
                    ("safebrowsing", Verdict::Unknown),
                    ("spamhaus", Verdict::Safe)
                ]
            )
        );
    }
}
