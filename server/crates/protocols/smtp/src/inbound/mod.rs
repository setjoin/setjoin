//! Enabled inbound adapters. SMTP intake and reducers remain the public seams.
mod clamav;
pub(crate) mod imip;
mod links;
mod phish;
mod sandbox;
pub(crate) mod scoring;
mod smime;
pub use links::{derive_key as derive_link_key, Config as LinkConfig};
pub use sandbox::Config as SandboxConfig;
use std::{sync::Arc, time::Duration};

#[derive(Clone)]
pub struct Config {
    pub anti_phish: bool,
    pub clamav_addr: Option<String>,
    pub sandbox: Option<SandboxConfig>,
    pub links: Option<LinkConfig>,
    pub trust_cache: Arc<setjoin_certificates::trust::TrustCache>,
    pub internal_domains: Vec<String>,
    pub protected_domains: Vec<String>,
    pub name_threshold: f64,
    pub user_cache_ttl: Duration,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            anti_phish: false,
            clamav_addr: None,
            sandbox: None,
            links: None,
            trust_cache: Arc::new(setjoin_certificates::trust::TrustCache::new()),
            internal_domains: Vec::new(),
            protected_domains: Vec::new(),
            name_threshold: 0.85,
            user_cache_ttl: Duration::from_secs(300),
        }
    }
}
pub(crate) struct Pipeline {
    pub config: Config,
    pub clamav: Option<Arc<clamav::ClamAv>>,
    pub sandbox: Option<sandbox::Cape>,
    detectors: std::sync::OnceLock<[bool; 2]>,
    names: tokio::sync::Mutex<Option<(std::time::Instant, Vec<String>)>>,
}
impl Pipeline {
    pub async fn initialize(&self, flags: Option<&dyn crate::submission::Flags>) {
        if let Some(clamd) = &self.clamav {
            clamd.ping().await;
        }
        if let Some(cape) = &self.sandbox {
            cape.health().await;
        }
        self.detectors.get_or_init(|| {
            [
                flags.is_some_and(|f| f.enabled("feature.antiphish_display_name")),
                flags.is_some_and(|f| f.enabled("feature.antiphish_lookalike")),
            ]
        });
    }
    pub fn new(mut config: Config) -> Arc<Self> {
        if config.user_cache_ttl.is_zero() {
            config.user_cache_ttl = Duration::from_secs(300);
        }
        Arc::new(Self {
            clamav: config.clamav_addr.clone().map(clamav::ClamAv::new),
            sandbox: config.sandbox.clone().map(sandbox::Cape::new),
            config,
            detectors: std::sync::OnceLock::new(),
            names: tokio::sync::Mutex::new(None),
        })
    }
}
pub(crate) use phish::{inject, Verdict};
pub(crate) use sandbox::risky;
