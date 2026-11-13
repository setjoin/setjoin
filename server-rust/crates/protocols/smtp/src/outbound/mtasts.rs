//! Go's process-local MTA-STS cache, loaded from its persistent policy table.
use crate::mail_auth::{Dns, DnsType};
use setjoin_pg::{workers::WorkerDatabase, Type};
use std::sync::Arc;

/// HTTP boundary: 200-only, no redirects, 10 seconds and at most 65536 bytes.
/// Production callers supply the shared SSRF-guarded client.
pub trait PolicyFetch: Send + Sync {
    fn get<'a>(
        &'a self,
        url: &'a str,
    ) -> futures_util::future::BoxFuture<'a, Result<Vec<u8>, String>>;
}
use std::collections::HashMap;
use tokio::sync::Mutex;

#[derive(Clone)]
pub(super) struct Policy {
    pub mode: String,
    version: String,
    mx: Vec<String>,
    max_age: i64,
    fetched: i128,
}
impl Policy {
    pub fn matches(&self, host: &str) -> bool {
        let trim = |s: &str| s.strip_suffix('.').unwrap_or(s).to_owned();
        let host = trim(&trim(host));
        // Go's method is exact, case-insensitive comparison; no wildcard expansion.
        self.mx
            .iter()
            .any(|allowed| trim(&trim(allowed)).eq_ignore_ascii_case(&host))
    }
    fn from_body(body: &[u8], fetched: i128) -> Option<Self> {
        let mut policy = Self {
            mode: String::new(),
            version: String::new(),
            mx: vec![],
            max_age: 86400,
            fetched,
        };
        for line in setjoin_mime::go_lossy(body).split('\n') {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let value = value.trim();
            match key.trim().to_ascii_lowercase().as_str() {
                "version" => policy.version = value.into(),
                "mode" => policy.mode = value.into(),
                "mx" => policy.mx.push(value.into()),
                "max_age" => {
                    let mut end = 0;
                    for (i, b) in value.bytes().enumerate() {
                        if b.is_ascii_digit() || (i == 0 && (b == b'+' || b == b'-')) {
                            end = i + 1
                        } else {
                            break;
                        }
                    }
                    if let Ok(n) = value[..end].parse::<i64>() {
                        policy.max_age = n
                    };
                    if policy.max_age <= 0 {
                        policy.max_age = 86400
                    }
                }
                _ => {}
            }
        }
        (policy.version == "STSv1" && !policy.mode.is_empty() && !policy.mx.is_empty())
            .then_some(policy)
    }
    fn valid(&self) -> bool {
        let now = i128::from(chrono::Utc::now().timestamp_nanos_opt().unwrap());
        now - self.fetched < i128::from(self.max_age.wrapping_mul(1_000_000_000))
    }
    fn from_json(raw: &str, fetched: i128) -> Option<Self> {
        let value: serde_json::Value = serde_json::from_str(raw).ok()?;
        // json.Unmarshal(null, &struct) is a zero struct in Go.
        if !value.is_null() && !value.is_object() {
            return None;
        }
        let mut policy = Self {
            version: String::new(),
            mode: String::new(),
            mx: vec![],
            max_age: 0,
            fetched,
        };
        // The stored source is jsonb::text: equal-length case aliases appear
        // in byte order. Go consumes every field, keeps scalar values on null,
        // clears slices on null and rejects the row after ANY typed error.
        for (key, value) in value.as_object().into_iter().flatten() {
            match key.to_ascii_lowercase().as_str() {
                "version" if !value.is_null() => policy.version = value.as_str()?.into(),
                "mode" if !value.is_null() => policy.mode = value.as_str()?.into(),
                "maxage" if !value.is_null() => policy.max_age = value.as_i64()?,
                "cachedat" if !value.is_null() => {
                    chrono::DateTime::parse_from_rfc3339(value.as_str()?).ok()?;
                }
                "mx" => {
                    policy.mx = if value.is_null() {
                        vec![]
                    } else {
                        value
                            .as_array()?
                            .iter()
                            .map(|v| {
                                if v.is_null() {
                                    Some(String::new())
                                } else {
                                    v.as_str().map(str::to_owned)
                                }
                            })
                            .collect::<Option<Vec<_>>>()?
                    }
                }
                _ => {}
            }
        }
        Some(policy)
    }
}
pub(super) struct MtaSts {
    db: WorkerDatabase,
    network: Option<(Arc<dyn Dns>, Arc<dyn PolicyFetch>)>,
    cache: Mutex<Option<HashMap<String, Policy>>>,
}
impl MtaSts {
    pub fn new(db: WorkerDatabase) -> Self {
        Self {
            db,
            network: None,
            cache: Mutex::new(None),
        }
    }
    pub fn with_network(mut self, dns: Arc<dyn Dns>, fetch: Arc<dyn PolicyFetch>) -> Self {
        self.network = Some((dns, fetch));
        self
    }
    pub async fn initialize(&self) {
        let mut cache = self.cache.lock().await;
        if cache.is_none() {
            let mut loaded = HashMap::new();
            if let Ok(connection) = self.db.connect_session().await {
                if let Ok(rows)=connection.query("SELECT domain,policy_json::text,to_char(fetched_at AT TIME ZONE 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') FROM mta_sts_policies",&[]).await {
                    for row in rows {
                        let (Ok(domain),Ok(raw),Ok(fetched))=(row.try_get::<_,String>(0),row.try_get::<_,String>(1),row.try_get::<_,String>(2)) else {continue};
                        let Some(fetched)=chrono::DateTime::parse_from_rfc3339(&fetched).ok().and_then(|t|t.timestamp_nanos_opt()).map(i128::from) else{continue};
                        if let Some(policy)=Policy::from_json(&raw,fetched).filter(Policy::valid) {loaded.insert(domain,policy);}
                    }
                }
            }
            *cache = Some(loaded);
        }
    }
    pub async fn lookup(&self, domain: &str) -> Option<Policy> {
        self.initialize().await;
        let cache = self.cache.lock().await;
        if let Some(policy) = cache
            .as_ref()
            .unwrap()
            .get(domain)
            .filter(|p| p.valid())
            .cloned()
        {
            return Some(policy);
        }
        drop(cache);
        let (dns, fetch) = self.network.as_ref()?;
        let txt = dns
            .lookup(DnsType::Txt, &format!("_mta-sts.{domain}"))
            .await
            .ok()?;
        let mut id = String::new();
        for record in txt {
            for part in record.split(';') {
                if let Some(value) = part.trim().strip_prefix("id=") {
                    id = value.trim().into()
                }
            }
        }
        if id.is_empty() {
            return None;
        }
        let body = fetch
            .get(&format!("https://mta-sts.{domain}/.well-known/mta-sts.txt"))
            .await
            .ok()?;
        let at = chrono::Utc::now();
        let policy = Policy::from_body(
            &body[..body.len().min(65536)],
            i128::from(at.timestamp_nanos_opt()?),
        )?;
        if policy.mode == "none" {
            return None;
        }
        self.cache
            .lock()
            .await
            .as_mut()
            .unwrap()
            .insert(domain.into(), policy.clone());
        let timestamp = at.to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true);
        let raw=serde_json::json!({"Version":policy.version,"Mode":policy.mode,"MX":policy.mx,"MaxAge":policy.max_age,"CachedAt":timestamp}).to_string();
        if let Ok(connection) = self.db.connect_session().await {
            let _=connection.query("INSERT INTO mta_sts_policies(domain,policy_json,fetched_at) VALUES($1,$2::jsonb,$3::timestamptz) ON CONFLICT(domain) DO UPDATE SET policy_json=$2::jsonb,fetched_at=$3::timestamptz",&[(&domain,Type::TEXT),(&raw,Type::TEXT),(&timestamp,Type::TEXT)]).await;
        }
        Some(policy)
    }
}
