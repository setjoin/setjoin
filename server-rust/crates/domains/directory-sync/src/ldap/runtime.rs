//! Worker state and configuration (`admin.LDAPHandler.ReloadConfig`, the
//! `ldapsync.SyncWorker.Run` loop and `identitysource.Controller`).
//!
//! The configured worker is derived from `system_config` on demand, so a write
//! that Go still handles is seen by the next request or tick; `reload` is Go's
//! `ReloadConfig` and fails the same way (the worker is then absent).
use super::engine::{admit_filter, Res, Worker};
use super::{log_warn, new_uuid, LdapClient};
use serde_json::Value;
use setjoin_config_secret::{is_config_secret_envelope, ConfigSecretCodec};
use setjoin_pg::workers::WorkerDatabase;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;

pub const SOURCE_KEY: &str = "legacy:ldap";

/// Go `isSecretConfigKey` for the LDAP prefix (`_enc` suffix and the named keys).
pub fn is_secret_key(key: &str) -> bool {
    key.ends_with("_enc") || key == "assist.api_key"
}

/// `strconv.ParseBool`.
pub fn parse_bool(raw: &str) -> Option<bool> {
    match raw {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

/// `strconv.Atoi` with the error ignored: a syntax error is 0, a range error saturates.
pub(crate) fn atoi_lenient(raw: &str) -> i64 {
    let digits = raw.strip_prefix(['+', '-']).unwrap_or(raw);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return 0;
    }
    match raw.parse::<i64>() {
        Ok(n) => n,
        Err(_) if raw.starts_with('-') => i64::MIN,
        Err(_) => i64::MAX,
    }
}

/// The identity-connector secret codec keyed from the process environment and
/// `identity.deployment_id` (Go builds it at startup; Rust on first use).
pub async fn load_env_codec(db: &WorkerDatabase) -> Option<Arc<ConfigSecretCodec>> {
    let conn = db.connect().await.ok()?;
    let rows = conn
        .query(
            "SELECT value #>> '{}' FROM system_config WHERE key = 'identity.deployment_id'",
            &[],
        )
        .await
        .ok()?;
    let deployment: String = rows.first()?.get::<_, Option<String>>(0)?;
    let keyring = setjoin_config_secret::keyring_from_env(&deployment)
        .map_err(|e| log_warn(&format!("identity connector secret keyring: {e}")))
        .ok()?;
    ConfigSecretCodec::new(keyring)
        .map_err(|e| log_warn(&format!("identity connector secret codec: {e}")))
        .ok()
        .map(Arc::new)
}

/// Go `GetDecryptedByPrefix` as a string map: every JSON-string value of the
/// keys matching `pattern` (a `LIKE` pattern, `_` is a wildcard exactly as in
/// Go), secrets opened with `codec`. `None` means no rows at all.
pub(crate) async fn read_prefixed(
    db: &WorkerDatabase,
    codec: &Option<Arc<ConfigSecretCodec>>,
    pattern: &str,
) -> Res<Option<std::collections::HashMap<String, String>>> {
    let conn = db.connect().await.map_err(|e| e.to_string())?;
    let rows = conn
        .query(
            "SELECT key, value::text, encrypted FROM system_config WHERE key LIKE $1 ORDER BY key",
            &[(&pattern, setjoin_pg::Type::TEXT)],
        )
        .await?;
    if rows.is_empty() {
        return Ok(None);
    }
    let mut cfg = std::collections::HashMap::<String, String>::new();
    for row in &rows {
        let (key, value, encrypted): (String, String, bool) = (row.get(0), row.get(1), row.get(2));
        let value = if encrypted || is_secret_key(&key) {
            let codec = codec
                .as_ref()
                .ok_or_else(|| format!("decrypt config secret {key:?}: codec is not configured"))?;
            if !is_config_secret_envelope(value.as_bytes()) {
                return Err(format!(
                    "decrypt config secret {key:?}: legacy plaintext requires startup migration"
                ));
            }
            String::from_utf8(
                codec
                    .decrypt(&key, value.as_bytes())
                    .map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?
        } else {
            value
        };
        if let Ok(Value::String(text)) = serde_json::from_str::<Value>(&value) {
            cfg.insert(key, text);
        }
    }
    Ok(Some(cfg))
}

pub struct Loaded {
    pub worker: Worker,
    pub enabled: bool,
}

pub struct LdapRuntime {
    pub db: WorkerDatabase,
    codec: tokio::sync::OnceCell<Option<Arc<ConfigSecretCodec>>>,
    from_env: bool,
    /// Wakes the periodic loop (config saved, manual restart).
    pub wake: Notify,
    /// Completed loop iterations (a cycle ran or was skipped); tests poll it.
    pub cycles: std::sync::atomic::AtomicU64,
}

impl LdapRuntime {
    /// Secrets keyed from the process environment and `identity.deployment_id`,
    /// resolved on first use (Go builds the codec at startup).
    pub fn from_env(db: WorkerDatabase) -> Self {
        Self {
            db,
            codec: tokio::sync::OnceCell::new(),
            from_env: true,
            wake: Notify::new(),
            cycles: Default::default(),
        }
    }

    pub fn with_codec(db: WorkerDatabase, codec: Option<Arc<ConfigSecretCodec>>) -> Self {
        let cell = tokio::sync::OnceCell::new();
        let _ = cell.set(codec);
        Self {
            db,
            codec: cell,
            from_env: false,
            wake: Notify::new(),
            cycles: Default::default(),
        }
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

    /// Go `ReloadConfig`: `Ok(None)` is "no worker" (no rows or no host).
    pub async fn reload(&self) -> Res<Option<Loaded>> {
        let codec = self.codec().await;
        let Some(cfg) = read_prefixed(&self.db, &codec, "ldap_sync_%").await? else {
            return Ok(None);
        };
        let get = |k: &str| cfg.get(k).cloned().unwrap_or_default();
        let enabled = match get("ldap_sync_enabled").as_str() {
            "" => false,
            raw => parse_bool(raw).ok_or("LDAP sync enabled flag is invalid")?,
        };
        let host = get("ldap_sync_host");
        if host.is_empty() {
            return Ok(None);
        }
        let mut port = atoi_lenient(&get("ldap_sync_port"));
        if port <= 0 {
            port = 636;
        }
        let mut interval = atoi_lenient(&get("ldap_sync_interval_min"));
        if interval <= 0 {
            interval = 15;
        }
        let use_tls = match get("ldap_sync_tls").as_str() {
            "" => true,
            raw => parse_bool(raw).ok_or("LDAP sync TLS mode is invalid")?,
        };
        let mut client = LdapClient::new(
            &host,
            port,
            use_tls,
            &get("ldap_sync_bind_dn"),
            &get("ldap_sync_password_enc"),
            &get("ldap_sync_base_dn"),
        );
        client.set_subject_attribute(&get("ldap_sync_subject_attribute"))?;
        let filter = get("ldap_sync_user_filter");
        admit_filter(&filter)?;
        let normalized = !client.subject_attribute().is_empty();
        Ok(Some(Loaded {
            enabled,
            worker: Worker {
                client,
                db: self.db.clone(),
                interval_min: interval,
                filter,
                source_key: normalized.then(|| SOURCE_KEY.to_owned()),
                instance: new_uuid(),
                enabled,
            },
        }))
    }

    /// The periodic loop (`SyncWorker.Run` under the `ldap-sync` controller):
    /// an immediate cycle, then one per configured interval; a saved
    /// configuration restarts it. A disabled or absent worker only waits.
    pub async fn run_until(&self, shutdown: impl std::future::Future<Output = ()>) {
        tokio::pin!(shutdown);
        loop {
            let wait = match self.reload().await {
                Ok(Some(Loaded {
                    worker,
                    enabled: true,
                })) => {
                    match worker.sync().await {
                        Ok(_) => {}
                        Err(e) => log_warn(&format!("LDAP sync cycle failed: {e}")),
                    }
                    Duration::from_secs(worker.interval_min.max(1) as u64 * 60)
                }
                Ok(_) => Duration::from_secs(60),
                Err(e) => {
                    log_warn(&format!("stored LDAP config could not be activated: {e}"));
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
