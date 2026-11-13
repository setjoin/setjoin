use crate::{
    cache::{write_atomic, DirCache},
    keys::{account_key_pem_to_pkcs8, new_account_key_pem, CertKey},
};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewOrder, RetryPolicy,
};
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime},
};

/// Where ACME servers fetch HTTP-01 responses (RFC 8555 section 8.3).
pub const HTTP01_PREFIX: &str = "/.well-known/acme-challenge/";
/// Lego production directory, Go's default when `CADirURL` is unset.
pub const LETS_ENCRYPT_PRODUCTION: &str = "https://acme-v02.api.letsencrypt.org/directory";
const RENEW_BEFORE: Duration = Duration::from_secs(30 * 24 * 3600);
const CHECK_INTERVAL: Duration = Duration::from_secs(12 * 3600);
const MAX_ATTEMPTS: usize = 3;

/// In-process HTTP-01 responder: `token -> key authorization`, answered by the :80 listener.
#[derive(Clone, Default)]
pub struct Http01Store(Arc<Mutex<HashMap<String, String>>>);

impl Http01Store {
    pub fn present(&self, token: &str, key_authorization: &str) {
        self.0
            .lock()
            .unwrap()
            .insert(token.into(), key_authorization.into());
    }
    pub fn clean_up(&self, token: &str) {
        self.0.lock().unwrap().remove(token);
    }
    /// The key authorization for a request path, if it is a pending challenge. Other paths and
    /// unknown tokens return `None` so the caller keeps serving them.
    pub fn answer(&self, path: &str) -> Option<String> {
        let token = path.strip_prefix(HTTP01_PREFIX)?;
        self.0.lock().unwrap().get(token).cloned()
    }
}

#[derive(Clone)]
pub struct Config {
    pub domains: Vec<String>,
    pub email: String,
    pub cache_dir: PathBuf,
    /// Persisted account key (`TLS_AUTOCERT_KEY_FILE`); default `<cache_dir>/account.key`.
    pub key_file: Option<PathBuf>,
    pub ca_dir_url: Option<String>,
    /// Extra trusted root (PEM) for a private test CA such as pebble.
    pub ca_root: Option<PathBuf>,
    /// Pause between failed attempts of one round (default: 30 s doubling to 1 h, 20 % jitter).
    pub backoff: Option<fn(usize) -> Duration>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum TickOutcome {
    /// Every configured certificate is present and outside the renew-before window.
    Fresh,
    Renewed,
    Failed(String),
}

#[derive(Clone)]
pub enum Challenge {
    Http01(Http01Store),
    TlsAlpn01(crate::TlsAlpnStore),
    Dns01(crate::dns::Provider),
}
impl Challenge {
    fn kind(&self) -> ChallengeType {
        match self {
            Self::Http01(_) => ChallengeType::Http01,
            Self::TlsAlpn01(_) => ChallengeType::TlsAlpn01,
            Self::Dns01(_) => ChallengeType::Dns01,
        }
    }
    fn name(&self) -> &'static str {
        match self {
            Self::Http01(_) => "http-01",
            Self::TlsAlpn01(_) => "tls-alpn-01",
            Self::Dns01(_) => "dns-01",
        }
    }
}

pub struct Manager {
    config: Config,
    cache: DirCache,
    challenge: Challenge,
    account_key_path: PathBuf,
    /// Serialises registration and issuance; one round at a time (Go's `mu` + single flight).
    round: tokio::sync::Mutex<Option<Account>>,
    /// A provider may have applied a request before returning its record ID.
    /// Graceful shutdown must drain its response and cleanup, even if the tick is cancelled.
    dns_tasks: tokio::sync::Mutex<tokio::task::JoinSet<()>>,
    now: fn() -> SystemTime,
}

/// Go's `normalizeSNI`: lowercase, trim, drop one trailing dot.
pub fn normalize(name: &str) -> String {
    let lowered = name.trim().to_lowercase();
    lowered.strip_suffix('.').unwrap_or(&lowered).to_owned()
}

impl Manager {
    /// Go's `NewLegoManager` for the http-01 challenge. Account key is loaded or created now.
    pub fn new(config: Config, store: Http01Store) -> Result<Self, String> {
        Self::new_with_challenge(config, Challenge::Http01(store))
    }

    pub fn new_with_challenge(config: Config, challenge: Challenge) -> Result<Self, String> {
        if config.domains.is_empty() {
            return Err("acme/dns01: at least one domain is required".into());
        }
        if config.cache_dir.as_os_str().is_empty() {
            return Err("acme/dns01: cache dir is required".into());
        }
        if config.email.is_empty() {
            return Err("acme/dns01: email is required".into());
        }
        for d in &config.domains {
            if normalize(d).starts_with("*.") && !matches!(challenge, Challenge::Dns01(_)) {
                return Err(format!(
                    "acme/dns01: wildcard domain {d:?} requires the dns-01 challenge (configured: {})", challenge.name()
                ));
            }
        }
        let account_key_path = config
            .key_file
            .clone()
            .unwrap_or_else(|| config.cache_dir.join("account.key"));
        load_or_create_account_key(&account_key_path)?;
        Ok(Self {
            cache: DirCache::new(config.cache_dir.clone()),
            config,
            challenge,
            account_key_path,
            round: tokio::sync::Mutex::new(None),
            dns_tasks: tokio::sync::Mutex::new(tokio::task::JoinSet::new()),
            now: SystemTime::now,
        })
    }

    /// Initial pass, then a check every 12 h until `stop` resolves.
    pub async fn run(&self, stop: impl std::future::Future<Output = ()>) {
        async {
            tokio::pin!(stop);
            let mut ticks = tokio::time::interval_at(
                tokio::time::Instant::now() + CHECK_INTERVAL,
                CHECK_INTERVAL,
            );
            ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            tokio::select! {biased; () = &mut stop => return, o = self.tick() => log(&o)}
            loop {
                tokio::select! {biased; () = &mut stop => return, _ = ticks.tick() => {}}
                tokio::select! {biased; () = &mut stop => return, o = self.tick() => log(&o)}
            }
        }
        .await;
        let mut tasks = self.dns_tasks.lock().await;
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                eprintln!("acme: DNS cleanup task failed: {error}");
            }
        }
    }

    /// One managed round (Go's `renewIfNeeded`): issue the multi-SAN certificate for every
    /// configured domain when any is missing, unparsable or inside the renew-before window.
    pub async fn tick(&self) -> TickOutcome {
        if self.first_stale().is_none() {
            return TickOutcome::Fresh;
        }
        let mut guard = self.round.lock().await;
        if self.first_stale().is_none() {
            return TickOutcome::Fresh;
        }
        let mut last = String::new();
        for attempt in 0..self.max_attempts() {
            match self.obtain(&mut guard).await {
                Ok(()) => return TickOutcome::Renewed,
                Err(e) => {
                    eprintln!(
                        "acme: certificate obtain attempt {} failed: {e}",
                        attempt + 1
                    );
                    last = e;
                }
            }
            tokio::time::sleep(self.backoff(attempt)).await;
        }
        TickOutcome::Failed(last)
    }

    fn max_attempts(&self) -> usize {
        MAX_ATTEMPTS
    }

    fn backoff(&self, attempt: usize) -> Duration {
        self.config
            .backoff
            .map_or_else(|| default_backoff(attempt), |f| f(attempt))
    }

    fn first_stale(&self) -> Option<&String> {
        self.config.domains.iter().find(|d| self.needs_renewal(d))
    }

    /// Missing, unparsable or expiring within 30 days.
    fn needs_renewal(&self, domain: &str) -> bool {
        let Ok(blob) = self.cache.get(&normalize(domain)) else {
            return true;
        };
        match not_after(&blob) {
            Some(end) => (self.now)() + RENEW_BEFORE > end,
            None => true,
        }
    }

    async fn obtain(&self, account: &mut Option<Account>) -> Result<(), String> {
        let acct = match account {
            Some(a) => a.clone(),
            None => {
                let a = self.register().await?;
                *account = Some(a.clone());
                a
            }
        };
        let identifiers: Vec<Identifier> = self
            .config
            .domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();
        let mut order = acct
            .new_order(&NewOrder::new(&identifiers))
            .await
            .map_err(|e| format!("acme: new order: {e}"))?;
        // Guards remain live through polling, and withdraw responses on every exit/cancellation.
        let mut pending = Pending {
            http: None,
            alpn: Vec::new(),
        };
        self.validate(&mut order, &mut pending).await?;
        drop(pending);
        let key = self.reuse_key().map_or_else(CertKey::generate, Ok)?;
        let csr = key.request(&self.config.domains)?;
        order
            .finalize_csr(&csr)
            .await
            .map_err(|e| format!("acme: finalize: {e}"))?;
        let chain = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(|e| format!("acme: certificate: {e}"))?;
        // Key PEM first, then the chain, as Go's `append(res.PrivateKey, res.Certificate...)`.
        let blob = format!("{}{}", key.to_pem(), chain);
        let mut errors = Vec::new();
        for d in &self.config.domains {
            if let Err(e) = self.cache.put(&normalize(d), blob.as_bytes()) {
                errors.push(format!("cache put {:?}: {e}", normalize(d)));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors.join("; "))
        }
    }

    async fn validate(
        &self,
        order: &mut instant_acme::Order,
        pending: &mut Pending,
    ) -> Result<(), String> {
        let mut dns_records = Vec::new();
        let mut authorizations = order.authorizations();
        while let Some(result) = authorizations.next().await {
            let mut authz = result.map_err(|e| format!("acme: authorization: {e}"))?;
            match authz.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                other => return Err(format!("acme: authorization is {other:?}")),
            }
            let mut challenge = authz.challenge(self.challenge.kind()).ok_or_else(|| {
                format!(
                    "acme: server offered no {} challenge",
                    self.challenge.name()
                )
            })?;
            match &self.challenge {
                Challenge::Http01(store) => {
                    let token = challenge.token.clone();
                    store.present(&token, challenge.key_authorization().as_str());
                    pending
                        .http
                        .get_or_insert_with(|| (store.clone(), Vec::new()))
                        .1
                        .push(token);
                }
                Challenge::TlsAlpn01(store) => {
                    pending.alpn.push(store.present(
                        &challenge.identifier().to_string(),
                        challenge.key_authorization().as_str(),
                    )?);
                }
                Challenge::Dns01(provider) => {
                    let record = provider
                        .record(
                            &challenge.identifier().to_string(),
                            challenge.key_authorization().dns_value(),
                        )
                        .await?;
                    dns_records.push(record);
                    continue;
                }
            }
            challenge
                .set_ready()
                .await
                .map_err(|e| format!("acme: challenge: {e}"))?;
        }
        if let Challenge::Dns01(provider) = &self.challenge {
            if !dns_records.is_empty() {
                return self.solve_dns(provider.clone(), dns_records).await;
            }
        }
        order
            .poll_ready(&RetryPolicy::default())
            .await
            .map_err(|e| format!("acme: order not ready: {e}"))?;
        Ok(())
    }

    async fn solve_dns(
        &self,
        provider: crate::dns::Provider,
        records: Vec<crate::dns::RecordSpec>,
    ) -> Result<(), String> {
        let (done, completed) = tokio::sync::oneshot::channel();
        {
            let mut tasks = self.dns_tasks.lock().await;
            while tasks.try_join_next().is_some() {}
            tasks.spawn(async move {
                let mut error = None;
                for record in &records {
                    if let Err(e) = provider.present(record).await {
                        error.get_or_insert(e);
                    }
                    if provider.sequential() {
                        if let Err(e) = provider.clean_up(record).await {
                            eprintln!("acme: DNS cleanup failed: {e}");
                        }
                    }
                }
                // Lego's parallel providers prepare every name, then clean every
                // name, even if a different authorization's preparation failed.
                if !provider.sequential() {
                    for record in &records {
                        if let Err(e) = provider.clean_up(record).await {
                            eprintln!("acme: DNS cleanup failed: {e}");
                        }
                    }
                }
                let _ = done.send(error.map_or(Ok(()), Err));
            });
        }
        completed
            .await
            .map_err(|e| format!("acme: DNS task: {e}"))??;
        // Frozen Go's explicit partial configs have PropagationTimeout=0.
        Err("acme: DNS propagation: time limit exceeded".into())
    }

    async fn register(&self) -> Result<Account, String> {
        let pem = std::fs::read(&self.account_key_path)
            .map_err(|e| format!("acme: read account key: {e}"))?;
        let pkcs8 = account_key_pem_to_pkcs8(&pem)?;
        let key = instant_acme::Key::from_pkcs8_der(pkcs8.clone().into())
            .map_err(|e| format!("acme: account key: {e}"))?;
        let builder = Account::builder_with_http(Box::new(crate::client::Transport::new(
            self.config.ca_root.as_deref(),
        )?));
        let directory = self
            .config
            .ca_dir_url
            .clone()
            .unwrap_or_else(|| LETS_ENCRYPT_PRODUCTION.into());
        let (account, _) = builder
            .create_from_key((key, rustls_pki_types_pkcs8(pkcs8)), directory)
            .await
            .map_err(|e| format!("acme/dns01: register: {e}"))?;
        let contact = format!("mailto:{}", self.config.email);
        account
            .update_contacts(&[contact.as_str()])
            .await
            .map_err(|e| format!("acme/dns01: register: {e}"))?;
        Ok(account)
    }

    /// Private key of the first parseable cached certificate (Go's `existingCertKey`).
    fn reuse_key(&self) -> Option<CertKey> {
        self.config
            .domains
            .iter()
            .filter_map(|d| self.cache.get(&normalize(d)).ok())
            .find_map(|blob| CertKey::from_blob(&blob))
    }
}

fn rustls_pki_types_pkcs8(der: Vec<u8>) -> rustls_pki_types::PrivateKeyDer<'static> {
    rustls_pki_types::PrivateKeyDer::Pkcs8(der.into())
}

fn log(outcome: &TickOutcome) {
    match outcome {
        TickOutcome::Fresh => {}
        TickOutcome::Renewed => eprintln!("acme: certificate obtained via managed loop"),
        TickOutcome::Failed(e) => {
            eprintln!("acme: managed certificate renewal failed; will retry next check: {e}")
        }
    }
}

/// 30 s doubling to a 1 h cap, up to 20 % downward jitter (Go's `defaultBackoff`).
fn default_backoff(attempt: usize) -> Duration {
    let mut d = Duration::from_secs(30);
    for _ in 0..attempt {
        if d < Duration::from_secs(3600) {
            d *= 2;
        }
    }
    d = d.min(Duration::from_secs(3600));
    let mut bytes = [0u8; 8];
    if ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut bytes).is_err() {
        return d;
    }
    let span = d.as_nanos() as u64 / 5 + 1;
    d - Duration::from_nanos(u64::from_le_bytes(bytes) % span)
}

/// NotAfter of the leaf (first certificate) of a key+chain blob.
pub fn not_after(blob: &[u8]) -> Option<SystemTime> {
    let secs = u64::try_from(crate::inspect::describe(blob).not_after?).ok()?;
    Some(SystemTime::UNIX_EPOCH + Duration::from_secs(secs))
}

fn load_or_create_account_key(path: &std::path::Path) -> Result<(), String> {
    match std::fs::read(path) {
        Ok(data) => account_key_pem_to_pkcs8(&data)
            .map(|_| ())
            .map_err(|e| format!("acme/dns01: {} {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let pem = new_account_key_pem()?;
            write_atomic(path, pem.as_bytes(), 0o600)
                .map_err(|e| format!("acme/dns01: persist account key {}: {e}", path.display()))
        }
        Err(e) => Err(format!(
            "acme/dns01: read account key {}: {e}",
            path.display()
        )),
    }
}

struct Pending {
    http: Option<(Http01Store, Vec<String>)>,
    alpn: Vec<crate::PendingAlpn>,
}
impl Drop for Pending {
    fn drop(&mut self) {
        if let Some((store, tokens)) = &self.http {
            for token in tokens {
                store.clean_up(token);
            }
        }
    }
}
