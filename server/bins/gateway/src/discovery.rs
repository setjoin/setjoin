//! Frozen discovery: SRV, then MX, a public-only HTTPS fetch, and a bounded
//! success cache. The renderer and Go JSON decoder share the gateway foundation.
use hickory_resolver::{proto::rr::RData, TokioResolver};
use hyper::StatusCode;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use serde::Deserialize;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant},
};

struct PublicDns {
    resolver: TokioResolver,
    peer: Option<(String, SocketAddr)>,
}
impl Resolve for PublicDns {
    fn resolve(&self, name: Name) -> Resolving {
        let (resolver, peer) = (self.resolver.clone(), self.peer.clone());
        Box::pin(async move {
            let addresses: Vec<_> = resolver
                .lookup_ip(name.as_str())
                .await?
                .iter()
                .filter(|ip| !crate::ssrf::blocked(*ip))
                .map(|ip| SocketAddr::new(ip, 0))
                .collect();
            if addresses.is_empty() {
                return Err("discovery: destination is not public".into());
            }
            // Recording-only transport mapping, after the real public-IP policy.
            let addresses = match peer.filter(|(host, _)| host == name.as_str()) {
                Some((_, address)) => vec![address],
                None => addresses,
            };
            Ok(Box::new(addresses.into_iter()) as Addrs)
        })
    }
}
struct Cached {
    until: Instant,
    body: String,
}
pub struct Discovery {
    resolver: TokioResolver,
    client: reqwest::Client,
    cache: Mutex<HashMap<String, Cached>>,
}
impl Discovery {
    fn new(
        resolver: TokioResolver,
        peer: Option<(String, SocketAddr)>,
        ca: Option<&[u8]>,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut builder = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(10))
            .pool_max_idle_per_host(0)
            .dns_resolver(Arc::new(PublicDns {
                resolver: resolver.clone(),
                peer,
            }));
        if let Some(ca) = ca {
            builder = builder.add_root_certificate(reqwest::Certificate::from_pem(ca)?);
        }
        Ok(Self {
            resolver,
            client: builder.build()?,
            cache: Mutex::new(HashMap::new()),
        })
    }
    pub fn system() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut builder = TokioResolver::builder_tokio()?;
        builder.options_mut().cache_size = 0;
        builder.options_mut().ip_strategy = hickory_resolver::config::LookupIpStrategy::Ipv4AndIpv6;
        Self::new(builder.build()?, None, None)
    }
    /// Controlled DNS/TLS receiver. Main never supplies a physical mapping.
    /// Each logical address still passes the same public-IP policy first.
    pub fn for_tests(
        resolver: TokioResolver,
        host: &str,
        address: SocketAddr,
        ca: &[u8],
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Self::new(resolver, Some((host.into(), address)), Some(ca))
    }
    pub async fn get(&self, domain: &str) -> Option<String> {
        {
            let mut cache = self.cache.lock().expect("discovery cache");
            if let Some(entry) = cache.get(domain) {
                if entry.until > Instant::now() {
                    return Some(entry.body.clone());
                }
            }
            cache.remove(domain);
        }
        let result = self.lookup(domain).await?;
        let now = Instant::now();
        let mut cache = self.cache.lock().expect("discovery cache");
        if !cache.contains_key(domain) && cache.len() >= 1024 {
            cache.retain(|_, entry| entry.until > now);
            if cache.len() >= 1024 {
                if let Some(key) = cache
                    .iter()
                    .min_by_key(|(_, entry)| entry.until)
                    .map(|(key, _)| key.clone())
                {
                    cache.remove(&key);
                }
            }
        }
        cache.insert(
            domain.into(),
            Cached {
                until: now + Duration::from_secs(300),
                body: result.clone(),
            },
        );
        Some(result)
    }
    async fn lookup(&self, domain: &str) -> Option<String> {
        if let Ok(found) = self
            .resolver
            .srv_lookup(format!("_jmap._tcp.{domain}"))
            .await
        {
            let mut records: Vec<_> = found
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::SRV(s) => Some(s.clone()),
                    _ => None,
                })
                .collect();
            records.sort_by_key(|s| (s.priority, s.weight));
            let mut at = 0;
            while at < records.len() {
                let end = records[at..]
                    .iter()
                    .position(|r| r.priority != records[at].priority)
                    .map_or(records.len(), |n| at + n);
                for first in at..end {
                    let sum: u64 = records[first..end]
                        .iter()
                        .map(|r| u64::from(r.weight))
                        .sum();
                    if sum > 0 {
                        let choice = rand::random_range(0..sum);
                        let mut cumulative = 0;
                        let selected = records[first..end]
                            .iter()
                            .position(|r| {
                                cumulative += u64::from(r.weight);
                                cumulative > choice
                            })
                            .unwrap();
                        records.swap(first, first + selected);
                    }
                }
                at = end;
            }
            for record in records {
                let target = record.target.to_utf8();
                let origin = format!("https://{}:{}", target.trim_end_matches('.'), record.port);
                if let Some(body) = self.fetch(&origin, "srv").await {
                    return Some(body);
                }
            }
        }
        if let Ok(found) = self.resolver.mx_lookup(domain).await {
            let mut records: Vec<_> = found
                .answers()
                .iter()
                .filter_map(|r| match &r.data {
                    RData::MX(s) => Some(s.clone()),
                    _ => None,
                })
                .collect();
            use rand::seq::SliceRandom;
            records.shuffle(&mut rand::rng());
            records.sort_by_key(|r| r.preference);
            for record in records {
                let target = record.exchange.to_utf8();
                let origin = format!("https://{}:443", target.trim_end_matches('.'));
                if let Some(body) = self.fetch(&origin, "mx").await {
                    return Some(body);
                }
            }
        }
        None
    }
    async fn fetch(&self, origin: &str, via: &str) -> Option<String> {
        let url = reqwest::Url::parse(origin).ok()?;
        if url.scheme() != "https" {
            return None;
        }
        let host = url.host_str()?;
        // Literal hosts bypass reqwest's DNS resolver. Check the parsed URL too,
        // including WHATWG IPv4 normalization (hex/octal/numeric aliases).
        if host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(crate::ssrf::blocked)
        {
            return None;
        }
        let authority = format!("{host}:{}", url.port_or_known_default()?);
        let mut response = self
            .client
            .get(format!("{origin}/.well-known/setjoin"))
            .header("host", authority)
            .send()
            .await
            .ok()?;
        if response.status() != StatusCode::OK {
            return None;
        }
        let mut raw = Vec::new();
        while raw.len() < 65536 {
            let Some(chunk) = response.chunk().await.ok()? else {
                break;
            };
            let take = (65536 - raw.len()).min(chunk.len());
            raw.extend_from_slice(&chunk[..take]);
        }
        let text = crate::chat::go_json_text(&raw);
        let fields =
            crate::chat::Fields::deserialize(&mut serde_json::Deserializer::from_str(&text))
                .ok()?;
        let login = crate::chat_channels::text_field(&fields, "LOGIN_FIELD").ok()?;
        let hint = crate::chat_channels::text_field(&fields, "LOGIN_DOMAIN_HINT").ok()?;
        let mut features: Vec<Option<String>> = Vec::new();
        for (key, value) in &fields.0 {
            if crate::chat_channels::fold(key) == "FEATURES" {
                features = if value.get() == "null" {
                    vec![]
                } else {
                    serde_json::from_str(value.get()).ok()?
                };
            }
        }
        if !features.iter().any(|f| f.as_deref() == Some("jmap")) {
            return None;
        }
        let quote = setjoin_static::wellknown::go_json_string;
        let optional = if hint.is_empty() {
            String::new()
        } else {
            format!(",\"login_domain_hint\":{}", quote(&hint))
        };
        Some(format!(
            "{{\"url\":{},\"login_field\":{}{optional},\"discovered_via\":{}}}\n",
            quote(origin),
            quote(&login),
            quote(via)
        ))
    }
}
static SYSTEM: OnceLock<Arc<Discovery>> = OnceLock::new();
pub async fn system_get(domain: &str) -> Option<String> {
    let discovery = if let Some(d) = SYSTEM.get() {
        d.clone()
    } else {
        let d = Arc::new(Discovery::system().ok()?);
        let _ = SYSTEM.set(d.clone());
        SYSTEM.get().cloned().unwrap_or(d)
    };
    discovery.get(domain).await
}
