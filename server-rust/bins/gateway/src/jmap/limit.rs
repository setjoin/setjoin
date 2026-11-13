//! The coarse per-client-IP budget Go puts in front of every route
//! (`coreLimit`, `CORE_RATE_LIMIT`, default 600 per minute, fixed windows
//! aligned to the epoch minute, keyed by the trusted-proxy-resolved client
//! IP), held at the front door (review item 3).
//!
//! Bound: the enabled gateway counts **every**
//! request it receives (proxied or served by Rust; not its own health
//! probe) in one in-memory window per client IP. A request over the
//! budget is answered with Go's own `429` ([`rate_limited`], REAL Go
//! bytes). [`EdgeLimit::for_front_door`] owns the enabled front door
//! budget independently of retired pilot flags because direct auth also bypasses
//! mailserver's limiter. Go only sees admitted requests, so a client gets at most
//! `CORE_RATE_LIMIT` requests per window across both processes, not one
//! budget per process. Like frozen Go's observed behavior, the gateway starts
//! cold: Go attempts to load `rate_limit_counters` but its current timestamp
//! scan into an integer skips the rows. Rust does not yet mirror Go's periodic
//! counter writes.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Mutex, OnceLock, PoisonError};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::HeaderValue;
use hyper::{Response, StatusCode};

use crate::routes::BoxFuture;
use crate::Body;

/// An availability predicate for custom embeddings. The executable always
/// owns the enabled front door budget, independently of command flags.
pub type RustServing = std::sync::Arc<dyn Fn() -> BoxFuture<bool> + Send + Sync>;

/// The front-door core budget plus an injected availability predicate.
pub struct EdgeLimit {
    pub limiter: Limiter,
    pub rust_serving: RustServing,
    booking_write: Limiter,
    admin: Limiter,
    auth: Limiter,
    booking_read: Limiter,
    meet_read: Limiter,
    meet_write: Limiter,
    setup: Limiter,
    recovery: Limiter,
    telemetry: Limiter,
    link_protect: Limiter,
    scim: Limiter,
    scim_enabled: bool,
}

impl EdgeLimit {
    pub fn new(limiter: Limiter, rust_serving: RustServing) -> Self {
        Self {
            limiter,
            rust_serving,
            booking_write: Limiter::new(5, 15 * 60),
            admin: Limiter::new(60, 60),
            auth: Limiter::new(20, 15 * 60),
            booking_read: Limiter::new(60, 60),
            meet_read: Limiter::new(120, 60),
            meet_write: Limiter::new(20, 15 * 60),
            setup: Limiter::new(60, 60),
            recovery: Limiter::new(2400, 60),
            telemetry: Limiter::new(30, 60),
            link_protect: Limiter::new(60, 60),
            scim: Limiter::new(120, 60),
            scim_enabled: false,
        }
    }

    /// The enabled front door accounts for every request, even without a
    /// configured local adapter: direct auth traffic also bypasses Go's core limiter.
    pub fn for_front_door(limiter: Limiter) -> Self {
        Self::new(limiter, std::sync::Arc::new(|| Box::pin(async { true }))).with_environment()
    }

    fn with_environment(mut self) -> Self {
        let limit = std::env::var("BOOKING_WRITE_RATE_LIMIT")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .map_or(5, |n| n.max(0) as u64);
        self.booking_write = Limiter::new(limit, 15 * 60);
        let limit = std::env::var("ADMIN_RATE_LIMIT")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .map_or(60, |n| n.max(0) as u64);
        self.admin = Limiter::new(limit, 60);
        let limit = std::env::var("AUTH_RATE_LIMIT")
            .ok()
            .and_then(|v| v.parse::<i64>().ok())
            .map_or(20, |n| n.max(0) as u64);
        self.auth = Limiter::new(limit, 15 * 60);
        self.booking_read = env_limiter("BOOKING_READ_RATE_LIMIT", 60, 60);
        self.meet_read = env_limiter("MEET_GUEST_READ_RATE_LIMIT", 120, 60);
        self.meet_write = env_limiter("MEET_GUEST_WRITE_RATE_LIMIT", 20, 15 * 60);
        self.setup = env_limiter("SETUP_RATE_LIMIT", 60, 60);
        self.recovery = env_limiter("RECOVERY_UPLOAD_RATE_LIMIT", 2400, 60);
        self.telemetry = env_limiter("TELEMETRY_RATE_LIMIT", 30, 60);
        self.link_protect = env_limiter("LINK_PROTECT_RATE_LIMIT", 60, 60);
        self.scim = env_limiter("SCIM_RATE_LIMIT", 120, 60);
        self.scim_enabled = matches!(
            std::env::var("SCIM_ENABLED").as_deref(),
            Ok("1" | "t" | "T" | "true" | "TRUE" | "True")
        );
        self
    }

    pub(crate) fn allow_route(
        &self,
        method: &hyper::Method,
        path: &str,
        ip: IpAddr,
        now: u64,
    ) -> bool {
        if self.scim_enabled && scim_route(method, path) {
            return self.scim.allow(ip, now);
        }
        match route_bucket(method, path) {
            Some("bookingWriteLimit") => self.booking_write.allow(ip, now),
            Some("adminLimit") => self.admin.allow(ip, now),
            Some("authLimit") => self.auth.allow(ip, now),
            Some("bookingReadLimit") => self.booking_read.allow(ip, now),
            Some("meetGuestReadLimit") => self.meet_read.allow(ip, now),
            Some("meetGuestWriteLimit") => {
                let path = path.strip_prefix("/api").unwrap_or(path);
                let slug = path.split('/').nth(3).unwrap_or_default();
                let mut key = ip.to_string().into_bytes();
                key.push(b'|');
                key.extend(crate::inventory::unescape(slug));
                self.meet_write.allow_key(&key, now)
            }
            Some("setupLimit") => self.setup.allow(ip, now),
            Some("recoveryLimit") => self.recovery.allow(ip, now),
            Some("telemetryLimit") => self.telemetry.allow(ip, now),
            Some("linkProtectLimit") => self.link_protect.allow(ip, now),
            _ => true,
        }
    }

    pub(crate) fn has_route_limit(&self, method: &hyper::Method, path: &str) -> bool {
        (self.scim_enabled && scim_route(method, path)) || has_route_limit(method, path)
    }

    pub(crate) fn scim_disabled(&self, method: &hyper::Method, path: &str) -> bool {
        !self.scim_enabled && scim_route(method, path)
    }

    /// Whether the gateway answers this over-budget request itself:
    /// bounded by [`setjoin_authz::precheck_timeout`] (1 s unless the env override widens it); slow or failed = forward.
    pub async fn answer_over_budget(&self) -> bool {
        tokio::time::timeout(setjoin_authz::precheck_timeout(), (self.rust_serving)())
            .await
            .unwrap_or(false)
    }
}

fn env_limiter(name: &str, default: u64, window_secs: u64) -> Limiter {
    let limit = std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<i64>().ok())
        .map_or(default, |n| n.max(0) as u64);
    Limiter::new(limit, window_secs)
}

/// SCIM registrations are outside mailserverd's main middleware golden.
fn scim_route(method: &hyper::Method, path: &str) -> bool {
    static RULES: OnceLock<Vec<(String, String)>> = OnceLock::new();
    let rules = RULES.get_or_init(|| {
        let inventory: serde_json::Value = serde_json::from_str(crate::inventory::BUNDLED)
            .expect("bundled inventory is validated at gateway startup");
        inventory["routes"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|row| {
                row["sources"].as_array().is_some_and(|sources| {
                    sources
                        .iter()
                        .any(|source| source == "mailserver/internal/scim/server.go")
                })
            })
            .filter_map(|row| Some((row["method"].as_str()?.into(), row["path"].as_str()?.into())))
            .collect()
    });
    let path = if path.starts_with("/api/") {
        &path[4..]
    } else {
        path
    };
    rules.iter().any(|(m, pattern)| {
        (m == method.as_str() || (method == hyper::Method::HEAD && m == "GET"))
            && crate::inventory::path_score(pattern, path).is_some()
    })
}

/// Select the middleware of the actual Go ServeMux match, including routes
/// without a limiter (which can override a less-specific limited subtree).
fn route_bucket(method: &hyper::Method, path: &str) -> Option<&'static str> {
    const ROUTES: &str =
        include_str!("../../../../../mailserver/cmd/mailserverd/testdata/route_inventory.golden");
    type Rule = (&'static str, &'static str, &'static str);
    static RULES: OnceLock<Vec<Rule>> = OnceLock::new();
    let rules = RULES.get_or_init(|| {
        ROUTES
            .lines()
            .filter(|line| !line.starts_with('#'))
            .filter_map(|line| {
                let (pattern, chain) = line.split_once('\t')?;
                let (method, path) = pattern.split_once(' ').unwrap_or(("*", pattern));
                Some((method, path, chain.split(" > ").next()?))
            })
            .collect()
    });
    let select = |path: &str| {
        rules
            .iter()
            .filter_map(|(route_method, pattern, bucket)| {
                let method_score = if *route_method == method.as_str() {
                    2
                } else if method == hyper::Method::HEAD && *route_method == "GET" {
                    1
                } else if *route_method == "*" {
                    0
                } else {
                    return None;
                };
                let mut score = crate::inventory::path_score(pattern, path)?;
                score.push(method_score);
                Some((score, *bucket))
            })
            .max_by(|a, b| a.0.cmp(&b.0))
            .map(|(_, bucket)| bucket)
    };

    if path.starts_with("/api/") {
        // Literal /api routes take precedence; all other API handlers receive
        // a path with the mount prefix stripped by mailserver's root mux.
        return select(path).or_else(|| select(&path[4..]));
    }
    const PINNED: &str = include_str!("../../../../../scripts/api-pinned-prefixes.txt");
    let pinned = PINNED.lines().filter_map(|line| {
        let prefix = line.split('#').next()?.trim();
        (!prefix.is_empty()).then_some(prefix)
    });
    // isPinnedPath in Go reads URL.Path (decoded), while ServeMux matches
    // escaped segments. Decode only for the root pin check; select must keep
    // segment boundaries so an escaped slash cannot create a different route.
    let decoded = crate::inventory::unescape(path);
    if pinned.into_iter().any(|prefix| {
        decoded == prefix.as_bytes()
            || decoded
                .strip_prefix(prefix.as_bytes())
                .is_some_and(|rest| rest.starts_with(b"/"))
    }) {
        select(path)
    } else {
        // Unpinned bare paths are redirects or SPA fallbacks, not API calls.
        None
    }
}

pub(crate) fn has_route_limit(method: &hyper::Method, path: &str) -> bool {
    matches!(
        route_bucket(method, path),
        Some(
            "bookingWriteLimit"
                | "bookingReadLimit"
                | "adminLimit"
                | "authLimit"
                | "meetGuestReadLimit"
                | "meetGuestWriteLimit"
                | "setupLimit"
                | "recoveryLimit"
                | "telemetryLimit"
                | "linkProtectLimit"
        )
    )
}

/// What Go's `coreLimit` writes (`httputil.WriteProblemStatus(w, 429,
/// "rate limit exceeded")` under `CacheControl` and `RequestID`), captured
/// from mailserverd on the real stack; the same for every path.
pub const RATE_LIMITED_BODY: &str = "{\"type\":\"about:blank\",\"title\":\"Too Many Requests\",\"status\":429,\"detail\":\"rate limit exceeded\",\"instance\":\"\"}\n";

/// Go's `429` for a spent budget: `Cache-Control: no-store`,
/// `Content-Type: application/problem+json`, `X-Request-Id` (Go's rule).
pub fn rate_limited(inbound_request_id: Option<&HeaderValue>) -> Response<Body> {
    let mut resp = Response::new(
        Full::new(Bytes::from_static(RATE_LIMITED_BODY.as_bytes()))
            .map_err(|n| match n {})
            .boxed(),
    );
    *resp.status_mut() = StatusCode::TOO_MANY_REQUESTS;
    let h = resp.headers_mut();
    h.insert("cache-control", HeaderValue::from_static("no-store"));
    h.insert(
        "content-type",
        HeaderValue::from_static("application/problem+json"),
    );
    if let Some(random) = super::random() {
        if let Ok(v) = HeaderValue::from_str(&super::reply::request_id(inbound_request_id, random))
        {
            h.insert("x-request-id", v);
        }
    }
    resp
}

/// A route-specific 429 is inside Go's security-header middleware.
pub fn route_rate_limited(
    inbound_request_id: Option<&HeaderValue>,
    scheme: &str,
) -> Response<Body> {
    let mut resp = rate_limited(inbound_request_id);
    super::reply::security_headers(resp.headers_mut(), scheme);
    resp
}

pub struct Limiter {
    limit: u64,
    window_secs: u64,
    counts: Mutex<HashMap<Vec<u8>, (u64, u64)>>,
}

impl Limiter {
    pub fn new(limit: u64, window_secs: u64) -> Self {
        Self {
            limit,
            window_secs: window_secs.max(1),
            counts: Mutex::new(HashMap::new()),
        }
    }

    /// Counts one request at `now_unix`; `false` once the budget is spent.
    pub fn allow(&self, ip: IpAddr, now_unix: u64) -> bool {
        self.allow_key(ip.to_string().as_bytes(), now_unix)
    }

    fn allow_key(&self, key: &[u8], now_unix: u64) -> bool {
        let window = now_unix - now_unix % self.window_secs;
        let mut counts = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        if counts.len() > 100_000 {
            counts.retain(|_, (start, _)| *start == window);
        }
        let entry = counts.entry(key.to_vec()).or_insert((window, 0));
        if entry.0 != window {
            *entry = (window, 0);
        }
        if entry.1 >= self.limit {
            return false;
        }
        entry.1 += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_budget_is_per_ip_per_window() {
        let l = Limiter::new(2, 60);
        let a: IpAddr = "192.0.2.1".parse().unwrap();
        let b: IpAddr = "192.0.2.2".parse().unwrap();
        assert!(l.allow(a, 120) && l.allow(a, 150));
        assert!(!l.allow(a, 179));
        assert!(l.allow(b, 179));
        assert!(l.allow(a, 180), "a new window resets the count");
    }

    /// A panic elsewhere while the lock is held must not turn every later
    /// request into a panic (review item 2): the counts stay usable.
    #[test]
    fn a_poisoned_lock_keeps_counting() {
        let l = std::sync::Arc::new(Limiter::new(1, 60));
        let held = l.clone();
        let _ = std::thread::spawn(move || {
            let _guard = held.counts.lock();
            panic!("poison the limiter");
        })
        .join();
        assert!(l.counts.is_poisoned());
        let a: IpAddr = "192.0.2.9".parse().unwrap();
        assert!(l.allow(a, 60));
        assert!(!l.allow(a, 61));
    }
}
