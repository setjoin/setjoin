//! Process-local config publication and trusted-proxy reload. Go keeps its own
//! copy until deletion: this task performs no shared writes or outbound I/O.
use super::Settings;
use crate::TrustedProxies;
use setjoin_pg::ScopedExecutor;
use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

pub struct Runtime {
    environment: BTreeMap<String, String>,
    current: RwLock<Settings>,
    pub(crate) trusted: Arc<RwLock<TrustedProxies>>,
}
impl Runtime {
    pub fn new(environment: BTreeMap<String, String>, settings: Settings) -> Result<Self, String> {
        let trusted = TrustedProxies::parse(
            environment
                .get("GATEWAY_TRUSTED_PROXIES")
                .map_or("127.0.0.1,::1", String::as_str),
        )?;
        Ok(Self {
            environment,
            current: RwLock::new(settings),
            trusted: Arc::new(RwLock::new(trusted)),
        })
    }
    /// Read the original operator layers without publishing a reload (deploy S3 handoff).
    pub fn source_settings(&self) -> Result<Settings, String> { Settings::load(&self.environment) }
    pub fn startup_settings(&self) -> Settings {
        self.current.read().expect("config snapshot").clone()
    }
    /// Go stores the newly validated pointer, then refreshes the proxy cache.
    /// Boot handlers retain their original snapshot; no environment is mutated.
    pub async fn reload(&self, exec: Option<&ScopedExecutor>) -> Result<(), String> {
        let next = Settings::load(&self.environment)?;
        next.validate()?;
        *self.current.write().expect("config snapshot") = next;
        self.refresh_proxies(exec).await;
        Ok(())
    }
    /// Global operator-owned infrastructure configuration; uses the request
    /// credential, never the direct LISTEN connection or a user-data query.
    pub async fn refresh_proxies(&self, exec: Option<&ScopedExecutor>) {
        let Some(exec) = exec else { return };
        let Ok(rows) = exec
            .read(
                "SELECT value::text FROM system_config WHERE key='trusted_proxy_ips'",
                &[],
            )
            .await
        else {
            return;
        };
        let Some(row) = rows.first() else { return };
        let Ok(raw) = row.try_get::<_, String>(0) else {
            return;
        };
        let Ok(ips) = serde_json::from_str::<Vec<String>>(&raw) else {
            return;
        };
        if ips.is_empty() {
            return;
        }
        // Go discards malformed individual entries, but publishes even an
        // all-invalid, non-empty list. Missing/empty/malformed arrays keep old trust.
        let valid = ips
            .iter()
            .filter(|ip| {
                // Each JSON member is one net.ParseIP/net.ParseCIDR input.
                // The environment-list parser intentionally trims/splits, but
                // Go's database loader does neither for an individual member.
                ip.as_str() == ip.trim()
                    && !ip.contains(',')
                    && ip.split_once('/').is_none_or(|(_, bits)| {
                        !bits.is_empty() && bits.bytes().all(|b| b.is_ascii_digit())
                    })
                    && TrustedProxies::parse(ip).is_ok()
            })
            .cloned()
            .collect::<Vec<_>>()
            .join(",");
        *self.trusted.write().expect("trusted proxy snapshot") =
            TrustedProxies::parse(&valid).expect("validated proxy entries");
    }
}
