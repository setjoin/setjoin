//! The authserver's first-party JWKS, cached the way Go's gateway caches it
//! (`mailserver/internal/auth/jwks.go`, ARCH-005): only the configured URL is
//! ever fetched; a hit inside the 5-minute TTL is served from memory; an
//! unknown kid or an expired cache triggers a refresh at most once per 30 s;
//! a failed refresh keeps serving the previous keys (serve-stale); with no
//! keys at all every lookup misses (fail closed — the route forwards to Go).
//!
//! Admitted keys: `kid` set, `use` absent or `sig`, `alg` absent or `ES256`,
//! `kty` `EC` on `P-256`, public only (no `d`). A document with none fails.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::{Request, StatusCode, Uri};
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use serde_json::Value;

use super::token::{KeySource, VerifyingKey};

pub const CACHE_TTL: Duration = Duration::from_secs(5 * 60);
pub const REFRESH_MIN_INTERVAL: Duration = Duration::from_secs(30);
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DOCUMENT: usize = 1 << 20;

type Fetch = Box<
    dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send>>
        + Send
        + Sync,
>;

#[derive(Default)]
struct Cache {
    keys: HashMap<String, VerifyingKey>,
    fetched_at: Option<Instant>,
    last_attempt: Option<Instant>,
}

pub struct Jwks {
    legacy: Option<crate::legacy_jwt::LegacyKeys>,
    fetch: Fetch,
    cache: Mutex<Cache>,
    /// Single flight: a lookup that needs a fetch holds this while fetching,
    /// so concurrent lookups wait for that fetch instead of seeing the
    /// refresh rate limit with an empty cache and failing.
    refresh: tokio::sync::Mutex<()>,
}

impl Jwks {
    /// A client for exactly one `http://` JWKS URL. No network I/O here.
    pub fn new(url: Uri) -> Result<Self, String> {
        if url.scheme_str() != Some("http") || url.authority().is_none() {
            return Err(format!(
                "JWKS URL must be http://host[:port]/path, got {url}"
            ));
        }
        let client: Client<HttpConnector, Empty<Bytes>> =
            Client::builder(TokioExecutor::new()).build(HttpConnector::new());
        Ok(Self::with_fetch(Box::new(move || {
            let (client, url) = (client.clone(), url.clone());
            Box::pin(async move {
                let req = Request::get(url)
                    .header("accept", "application/json")
                    .body(Empty::new())
                    .map_err(|e| e.to_string())?;
                let resp = tokio::time::timeout(FETCH_TIMEOUT, client.request(req))
                    .await
                    .map_err(|_| "jwks fetch timed out".to_string())?
                    .map_err(|e| e.to_string())?;
                if resp.status() != StatusCode::OK {
                    return Err(format!("jwks fetch: status {}", resp.status()));
                }
                let body = tokio::time::timeout(
                    FETCH_TIMEOUT,
                    Limited::new(resp.into_body(), MAX_DOCUMENT).collect(),
                )
                .await
                .map_err(|_| "jwks read timed out".to_string())?
                .map_err(|e| e.to_string())?;
                Ok(body.to_bytes().to_vec())
            })
        })))
    }

    /// Test seam: any document source.
    pub fn with_fetch(fetch: Fetch) -> Self {
        Self {
            legacy: None,
            fetch,
            cache: Mutex::new(Cache::default()),
            refresh: tokio::sync::Mutex::new(()),
        }
    }

    /// Attach deployment-owned legacy verification material (never JWKS input).
    pub fn with_legacy_keys(mut self, keys: crate::legacy_jwt::LegacyKeys) -> Self {
        self.legacy = Some(keys);
        self
    }

    fn fresh_key(&self, kid: &str, now: Instant) -> Option<VerifyingKey> {
        let c = self.cache();
        let fresh = c
            .fetched_at
            .is_some_and(|t| now.saturating_duration_since(t) < CACHE_TTL);
        c.keys.get(kid).copied().filter(|_| fresh)
    }

    /// The cache; a lock poisoned by an unrelated panic is still used (the
    /// cache holds only whole values, never a half-written state).
    fn cache(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache.lock().unwrap_or_else(PoisonError::into_inner)
    }

    async fn lookup(&self, kid: &str, now: Instant) -> Option<VerifyingKey> {
        if kid.is_empty() {
            return None;
        }
        if let Some(key) = self.fresh_key(kid, now) {
            return Some(key);
        }
        let _flight = self.refresh.lock().await;
        {
            // Re-checked under the flight: a fetch that finished while this
            // lookup waited has filled the cache.
            let mut c = self.cache();
            let fresh = c
                .fetched_at
                .is_some_and(|t| now.duration_since(t) < CACHE_TTL);
            if let (Some(key), true) = (c.keys.get(kid), fresh) {
                return Some(*key);
            }
            if c.last_attempt
                .is_some_and(|t| now.duration_since(t) < REFRESH_MIN_INTERVAL)
            {
                return c.keys.get(kid).copied();
            }
            c.last_attempt = Some(now);
        }
        if let Ok(keys) = (self.fetch)().await.and_then(|raw| parse(&raw)) {
            let mut c = self.cache();
            c.keys = keys;
            c.fetched_at = Some(now);
        }
        self.cache().keys.get(kid).copied()
    }
}

impl KeySource for Jwks {
    fn legacy_keys(&self) -> Option<&crate::legacy_jwt::LegacyKeys> {
        self.legacy.as_ref()
    }
    async fn key(&self, kid: &str) -> Option<VerifyingKey> {
        self.lookup(kid, Instant::now()).await
    }
}

/// Parses a JWKS document into its admissible ES256 verification keys.
pub fn parse(raw: &[u8]) -> Result<HashMap<String, VerifyingKey>, String> {
    let doc: Value = serde_json::from_slice(raw).map_err(|e| format!("jwks: {e}"))?;
    let keys = doc
        .get("keys")
        .and_then(Value::as_array)
        .ok_or("jwks: no keys array")?;
    let mut out = HashMap::new();
    for k in keys {
        let field = |name: &str| k.get(name).and_then(Value::as_str).unwrap_or("");
        let kid = field("kid");
        if kid.is_empty()
            || !matches!(field("use"), "" | "sig")
            || !matches!(field("alg"), "" | "ES256")
            || field("kty") != "EC"
            || field("crv") != "P-256"
            || k.get("d").is_some()
        {
            continue;
        }
        let coord = |name: &str| {
            URL_SAFE_NO_PAD
                .decode(field(name))
                .ok()
                .filter(|b| b.len() == 32)
        };
        let (Some(x), Some(y)) = (coord("x"), coord("y")) else {
            continue;
        };
        if let Some(key) = VerifyingKey::from_affine(&x, &y) {
            out.insert(kid.to_owned(), key);
        }
    }
    if out.is_empty() {
        return Err("jwks: document contains no usable EC signing keys".into());
    }
    Ok(out)
}

/// The public JWK of `key` (tests and fixtures).
pub fn jwk(kid: &str, key: &VerifyingKey) -> Value {
    serde_json::json!({
        "kty": "EC", "crv": "P-256", "use": "sig", "alg": "ES256", "kid": kid,
        "x": URL_SAFE_NO_PAD.encode(key.x()),
        "y": URL_SAFE_NO_PAD.encode(key.y()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::tests::{public_key, signing_key};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    fn counting(doc: Arc<Mutex<Result<Vec<u8>, String>>>, calls: Arc<AtomicUsize>) -> Jwks {
        Jwks::with_fetch(Box::new(move || {
            calls.fetch_add(1, Ordering::SeqCst);
            let r = doc.lock().unwrap().clone();
            Box::pin(async move { r })
        }))
    }

    fn doc(keys: &[Value]) -> Vec<u8> {
        serde_json::json!({ "keys": keys }).to_string().into_bytes()
    }

    #[tokio::test]
    async fn keys_are_cached_refreshed_rate_limited_and_served_stale() {
        let k1 = public_key(&signing_key(1));
        let k2 = public_key(&signing_key(2));
        let source = Arc::new(Mutex::new(Ok(doc(&[jwk("k1", &k1)]))));
        let calls = Arc::new(AtomicUsize::new(0));
        let jwks = counting(source.clone(), calls.clone());
        let t0 = Instant::now();

        assert_eq!(jwks.lookup("k1", t0).await, Some(k1));
        assert_eq!(
            jwks.lookup("k1", t0 + Duration::from_secs(60)).await,
            Some(k1)
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            1,
            "a hit inside the TTL is cached"
        );

        // A new kid is published: the unknown-kid refresh is rate limited.
        *source.lock().unwrap() = Ok(doc(&[jwk("k1", &k1), jwk("k2", &k2)]));
        assert_eq!(jwks.lookup("k2", t0 + Duration::from_secs(10)).await, None);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            jwks.lookup("k2", t0 + Duration::from_secs(31)).await,
            Some(k2)
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        // authserver down after the TTL: the stale keys keep verifying.
        *source.lock().unwrap() = Err("down".into());
        let late = t0 + CACHE_TTL + Duration::from_secs(60);
        assert_eq!(jwks.lookup("k1", late).await, Some(k1));
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn no_keys_means_every_lookup_misses() {
        let jwks = counting(
            Arc::new(Mutex::new(Err("unreachable".into()))),
            Arc::new(AtomicUsize::new(0)),
        );
        assert_eq!(jwks.lookup("k1", Instant::now()).await, None);
    }

    /// Found by the RP07 review-fix recovery re-run: right after a gateway
    /// restart, concurrent first requests raced the cold cache — one fetched,
    /// the others saw the refresh rate limit, found no key and forwarded to
    /// Go (a client-visible `401` where Go cannot verify ES256). Concurrent
    /// lookups now wait for the in-flight fetch: one fetch, every lookup
    /// gets the key.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_cold_lookups_share_one_fetch() {
        let k1 = public_key(&signing_key(1));
        let calls = Arc::new(AtomicUsize::new(0));
        let counter = calls.clone();
        let body = doc(&[jwk("k1", &k1)]);
        let jwks = Arc::new(Jwks::with_fetch(Box::new(move || {
            counter.fetch_add(1, Ordering::SeqCst);
            let body = body.clone();
            Box::pin(async move {
                tokio::time::sleep(Duration::from_millis(100)).await;
                Ok(body)
            })
        })));
        let now = Instant::now();
        let lookups: Vec<_> = (0..4)
            .map(|_| {
                let jwks = jwks.clone();
                tokio::spawn(async move { jwks.lookup("k1", now).await })
            })
            .collect();
        for l in lookups {
            assert_eq!(l.await.unwrap(), Some(k1));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    /// A poisoned cache lock (a panic while it was held) must not panic
    /// every later token lookup (review item 2).
    #[tokio::test]
    async fn a_poisoned_cache_still_serves_keys() {
        let k1 = public_key(&signing_key(1));
        let jwks = Arc::new(counting(
            Arc::new(Mutex::new(Ok(doc(&[jwk("k1", &k1)])))),
            Arc::new(AtomicUsize::new(0)),
        ));
        let held = jwks.clone();
        let _ = std::thread::spawn(move || {
            let _guard = held.cache.lock();
            panic!("poison the cache");
        })
        .join();
        assert!(jwks.cache.is_poisoned());
        assert_eq!(jwks.lookup("k1", Instant::now()).await, Some(k1));
    }

    #[test]
    fn only_public_es256_signing_keys_are_admitted() {
        let k = public_key(&signing_key(1));
        let mut private = jwk("priv", &k);
        private["d"] = "AAAA".into();
        let mut enc = jwk("enc", &k);
        enc["use"] = "enc".into();
        let mut rs = jwk("rs", &k);
        rs["alg"] = "RS256".into();
        let mut p384 = jwk("p384", &k);
        p384["crv"] = "P-384".into();
        let mut no_kid = jwk("", &k);
        no_kid["kid"] = "".into();
        let keys = parse(&doc(&[jwk("ok", &k), private, enc, rs, p384, no_kid])).unwrap();
        assert_eq!(keys.keys().collect::<Vec<_>>(), vec!["ok"]);
        assert!(parse(&doc(&[])).is_err());
    }

    /// A JWK whose coordinates are not a P-256 point is never a verifier:
    /// off the curve, or a coordinate not reduced below the field prime.
    #[test]
    fn only_points_on_the_curve_are_admitted() {
        let k = public_key(&signing_key(1));
        let good = jwk("ok", &k);
        let coord = |v: &Value| URL_SAFE_NO_PAD.decode(v.as_str().unwrap()).unwrap();
        let mut off = jwk("off", &k);
        let mut y = coord(&good["y"]);
        y[31] ^= 1;
        off["y"] = URL_SAFE_NO_PAD.encode(&y).into();
        // x = p, the field prime: not a canonical coordinate.
        let p: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ];
        let mut unreduced = jwk("unreduced", &k);
        unreduced["x"] = URL_SAFE_NO_PAD.encode(p).into();
        let mut zero = jwk("zero", &k);
        zero["x"] = URL_SAFE_NO_PAD.encode([0u8; 32]).into();
        zero["y"] = URL_SAFE_NO_PAD.encode([0u8; 32]).into();
        let mut short = jwk("short", &k);
        short["x"] = URL_SAFE_NO_PAD.encode(&coord(&good["x"])[1..]).into();
        let invalid = [off, unreduced, zero, short];
        let keys = parse(&doc(&[&[good][..], &invalid[..]].concat())).unwrap();
        assert_eq!(keys.keys().collect::<Vec<_>>(), vec!["ok"]);
        assert_eq!(keys["ok"], k);
        assert!(parse(&doc(&invalid)).is_err(), "no usable key left");
    }
}
