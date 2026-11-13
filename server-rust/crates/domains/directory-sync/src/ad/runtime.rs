//! AD worker state (`admin.ADHandler.ReloadConfig`, `ad.SyncWorker`) and the
//! `ad-sync` loop.
//!
//! Like the LDAP runtime nothing is cached: `reload` is Go's `ReloadConfig` run
//! on demand (per request and per tick). Whether AD sync is on is Go's resolved
//! `feature.ad_sync`, which `main.go` always pins to the environment value
//! `AD_SYNC_ENABLED` (the database toggle is never consulted), so the runtime
//! carries that boolean from the process environment.
use super::client::{AdClient, AdUser, SrvResolver, SystemResolver};
use super::log_warn;
use crate::ldap::engine::{Res, SyncResult};
use crate::ldap::new_uuid;
use crate::ldap::normalized::{sync_with, Connector, Object};
use crate::ldap::runtime::{atoi_lenient, load_env_codec, read_prefixed};
use setjoin_config_secret::ConfigSecretCodec;
use setjoin_pg::workers::WorkerDatabase;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

pub const SOURCE_KEY: &str = "legacy:ad";

/// `AD_SYNC_*` settings Go builds its startup worker from (`NewADHandler`).
#[derive(Clone, Debug, Default)]
pub struct EnvConfig {
    pub domain: String,
    pub bind_dn: String,
    pub password_enc: String,
    pub ldap_host: String,
    pub interval_min: i64,
}

impl EnvConfig {
    pub fn from_env() -> Self {
        let get = |k: &str| std::env::var(k).unwrap_or_default();
        let interval = atoi_lenient(&get("AD_SYNC_INTERVAL_MIN"));
        Self {
            domain: get("AD_SYNC_DOMAIN"),
            bind_dn: get("AD_SYNC_BIND_DN"),
            password_enc: get("AD_SYNC_PASSWORD_ENC"),
            ldap_host: get("AD_SYNC_LDAP_HOST"),
            interval_min: if interval == 0 { 15 } else { interval },
        }
    }
}

/// Go `strconv.ParseBool` for the `AD_SYNC_ENABLED` value.
pub fn enabled_from_env() -> bool {
    matches!(
        std::env::var("AD_SYNC_ENABLED").as_deref(),
        Ok("1" | "t" | "T" | "true" | "TRUE" | "True")
    )
}

/// The built worker: one configured directory (`ad.SyncWorker`).
#[derive(Clone)]
pub struct AdWorker {
    pub client: AdClient,
    pub db: WorkerDatabase,
    pub interval_min: i64,
    /// Lease owner for the pipeline; stable for the worker's life.
    pub instance: String,
    /// The identity source this worker feeds: `legacy:ad`, or a catalog key.
    pub source_key: String,
}

pub struct Loaded {
    pub worker: AdWorker,
}

pub struct AdRuntime {
    pub db: WorkerDatabase,
    codec: tokio::sync::OnceCell<Option<Arc<ConfigSecretCodec>>>,
    from_env: bool,
    enabled: bool,
    env: EnvConfig,
    resolver: Arc<dyn SrvResolver>,
    /// Wakes the periodic loop (config saved, toggle observed).
    pub wake: Notify,
    /// Completed loop iterations (a cycle ran or was skipped); tests poll it.
    pub cycles: std::sync::atomic::AtomicU64,
}

impl AdRuntime {
    /// Secrets keyed from the process environment, the system resolver, and the
    /// startup settings from `AD_SYNC_*`.
    pub fn from_env(db: WorkerDatabase) -> Self {
        Self {
            db,
            codec: tokio::sync::OnceCell::new(),
            from_env: true,
            enabled: enabled_from_env(),
            env: EnvConfig::from_env(),
            resolver: Arc::new(SystemResolver),
            wake: Notify::new(),
            cycles: Default::default(),
        }
    }

    pub fn with_parts(
        db: WorkerDatabase,
        codec: Option<Arc<ConfigSecretCodec>>,
        enabled: bool,
        env: EnvConfig,
        resolver: Arc<dyn SrvResolver>,
    ) -> Self {
        let cell = tokio::sync::OnceCell::new();
        let _ = cell.set(codec);
        Self {
            db,
            codec: cell,
            from_env: false,
            enabled,
            env,
            resolver,
            wake: Notify::new(),
            cycles: Default::default(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub async fn codec(&self) -> Option<Arc<ConfigSecretCodec>> {
        self.codec
            .get_or_init(|| async {
                if !self.from_env {
                    return None;
                }
                load_env_codec(&self.db).await
            })
            .await
            .clone()
    }

    /// Go `ReloadConfig`: `Ok(None)` is "no worker".
    pub async fn reload(&self) -> Res<Option<Loaded>> {
        if !self.enabled {
            return Ok(None);
        }
        let codec = self.codec().await;
        // `LIKE 'ad_sync_%'`: the underscores are wildcards, as in Go (#377).
        let (domain, bind_dn, password, host, interval) =
            match read_prefixed(&self.db, &codec, "ad_sync_%").await? {
                None => {
                    // Go keeps the worker `NewADHandler` built from the environment.
                    let e = &self.env;
                    if e.domain.is_empty() {
                        return Ok(None);
                    }
                    (
                        e.domain.clone(),
                        e.bind_dn.clone(),
                        e.password_enc.clone(),
                        e.ldap_host.clone(),
                        e.interval_min,
                    )
                }
                Some(values) => {
                    let get = |k: &str| values.get(k).cloned().unwrap_or_default();
                    let domain = get("ad_sync_domain");
                    if domain.is_empty() {
                        return Ok(None);
                    }
                    let mut interval = atoi_lenient(&get("ad_sync_interval_min"));
                    if interval <= 0 {
                        interval = 15;
                    }
                    (
                        domain,
                        get("ad_sync_bind_dn"),
                        get("ad_sync_password_enc"),
                        get("ad_sync_ldap_host"),
                        interval,
                    )
                }
            };
        let client =
            AdClient::new(&domain, &bind_dn, &password, &host, self.resolver.as_ref()).await?;
        Ok(Some(Loaded {
            worker: AdWorker {
                client,
                db: self.db.clone(),
                interval_min: interval,
                instance: new_uuid(),
                source_key: SOURCE_KEY.to_owned(),
            },
        }))
    }

    /// The periodic loop (`SyncWorker.Run` under the `ad-sync` controller): an
    /// immediate cycle, then one per configured interval; a saved configuration
    /// or toggle event restarts it. An absent worker only waits.
    pub async fn run_until(&self, shutdown: impl std::future::Future<Output = ()>) {
        tokio::pin!(shutdown);
        loop {
            let wait = match self.reload().await {
                Ok(Some(Loaded { worker })) => {
                    if let Err(e) = worker.sync().await {
                        log_warn(&format!("AD sync cycle failed: {e}"));
                    }
                    Duration::from_secs(worker.interval_min.max(1) as u64 * 60)
                }
                Ok(None) => Duration::from_secs(60),
                Err(e) => {
                    log_warn(&format!("stored AD config could not be activated: {e}"));
                    Duration::from_secs(60)
                }
            };
            self.cycles
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::select! {
                _ = &mut shutdown => return,
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(wait) => {}
            }
        }
    }
}

impl AdWorker {
    /// Go `SyncNow`: one cycle through the identity-source pipeline.
    pub async fn sync(&self) -> Res<SyncResult> {
        sync_with(
            &AdConnector(self),
            &self.db,
            &self.instance,
            &self.source_key,
        )
        .await
    }

    /// Go `DryRun`: bind and read the whole user set, zero database writes.
    pub async fn dry_run(&self) -> Res<i64> {
        let (users, _) = self.read(0).await?;
        Ok(users.len() as i64)
    }

    async fn read(&self, cursor: i64) -> Res<(Vec<AdUser>, i64)> {
        let (mut ldap, endpoint) = self.client.connect().await.map_err(|e| e.to_string())?;
        endpoint.bind(&mut ldap).await.map_err(|e| e.to_string())?;
        let found = self
            .client
            .search_users(&mut ldap, cursor)
            .await
            .map_err(|e| e.to_string());
        let _ = ldap.unbind().await;
        found
    }
}

/// `ad.normalizedConnector`: usn cursor, no preflight, duplicates not rejected.
pub struct AdConnector<'a>(pub &'a AdWorker);

impl Connector for AdConnector<'_> {
    fn label(&self) -> &'static str {
        "AD"
    }
    fn forbid_duplicates(&self) -> bool {
        false
    }
    fn decode_cursor(&self, committed: &str) -> Res<String> {
        if committed.is_empty() {
            return Ok("0".into());
        }
        let value: serde_json::Value =
            serde_json::from_str(committed).map_err(|e| e.to_string())?;
        // Go decodes into `struct{USN string}`: a non-string `usn` is an error.
        let object = value
            .as_object()
            .ok_or("json: cannot unmarshal into Go value of type struct")?;
        match object.iter().find(|(k, _)| k.eq_ignore_ascii_case("usn")) {
            None => Ok("0".into()),
            Some((_, serde_json::Value::Null)) => Ok("0".into()),
            Some((_, serde_json::Value::String(text))) if text.is_empty() => Ok("0".into()),
            Some((_, serde_json::Value::String(text))) => text
                .parse::<i64>()
                .map(|n| n.to_string())
                .map_err(|e| format!("decode AD committed uSNChanged: {e}")),
            Some(_) => Err("json: cannot unmarshal into Go struct field of type string".into()),
        }
    }
    fn encode_cursor(&self, state: &str) -> String {
        serde_json::json!({"usn": state}).to_string()
    }
    async fn fetch(&self, before: &str) -> Res<(Vec<Object>, String)> {
        let cursor: i64 = before
            .parse()
            .map_err(|_| "AD cursor is invalid".to_owned())?;
        let (users, max_usn) = self.0.read(cursor).await?;
        let after = max_usn.max(cursor);
        let objects = users
            .iter()
            .map(|u| Object {
                subject: u.object_guid.clone(),
                relation_key: crate::ldap::client::normalize_dn(&u.dn),
                manager_relation_key: crate::ldap::client::normalize_dn(&u.manager_dn),
                manager_subject: u.manager_subject.clone(),
                email: u.email.clone(),
                display_name: u.display_name.clone(),
                first_name: u.first_name.clone(),
                last_name: u.last_name.clone(),
                job_title: u.title.clone(),
                phone: u.phone.clone(),
                department: u.department.clone(),
                upn: u.upn.clone(),
                disabled: u.disabled,
                tombstone: false,
                cursor_value: u.usn_changed.to_string(),
            })
            .collect();
        Ok((objects, after.to_string()))
    }
}
