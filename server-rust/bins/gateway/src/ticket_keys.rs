//! Persisted ticket generations consumed by the native TLS listener (#413).
use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use setjoin_config_secret::ConfigSecretCodec;
use setjoin_pg::ticket_keys::TicketKeyStore;
use std::{future::Future, io, sync::Arc, time::Duration};

/// `system_config` key of the persisted generations.
pub const CONFIG_KEY: &str = "tls_session_ticket_keys";

/// Build the system_config secret codec from the deployment's configured key
/// material, or `None` when it is unavailable (the keys then stay in memory).
pub async fn codec(
    store: &TicketKeyStore,
    get: &dyn Fn(&str) -> Option<String>,
) -> Option<Arc<ConfigSecretCodec>> {
    let deployment = match store.deployment_id().await {
        Ok(Some(id)) if !id.trim().is_empty() => id,
        _ => {
            eprintln!("ticket keys: no identity.deployment_id; keys stay in memory only");
            return None;
        }
    };
    let built = setjoin_config_secret::keyring_from_lookup(&deployment, get)
        .and_then(ConfigSecretCodec::new);
    match built {
        Ok(codec) => Some(Arc::new(codec)),
        Err(error) => {
            eprintln!("ticket keys: {error}; keys stay in memory only");
            None
        }
    }
}

type Error = Box<dyn std::error::Error + Send + Sync>;

/// The live listener adapter. All supplied fresh keys must come
/// from a cryptographically secure random source; do not log their contents.
pub struct TicketKeys {
    current: [u8; 32],
    previous: [u8; 32],
}

impl TicketKeys {
    /// Open a stored generation pair. Owner-approved security fix 2026-11-05
    /// (#503): only the sealed envelope is accepted; a legacy plaintext row (as
    /// frozen Go persisted it despite its `encrypted` marker) is never trusted.
    fn open(stored: &str, codec: &ConfigSecretCodec) -> Option<Self> {
        if setjoin_contracts::mutants::on("ticket-keys-plaintext") {
            return Self::parse(stored);
        }
        let plain = codec.decrypt(CONFIG_KEY, stored.as_bytes()).ok()?;
        Self::parse(std::str::from_utf8(&plain).ok()?)
    }
    /// Seal the generation pair for `system_config`; plaintext only for the
    /// restored-bug mutant.
    fn seal(&self, codec: Option<&ConfigSecretCodec>) -> Option<String> {
        let plain = json!({ "current": STANDARD.encode(self.current), "previous": STANDARD.encode(self.previous) }).to_string();
        if setjoin_contracts::mutants::on("ticket-keys-plaintext") {
            return Some(plain);
        }
        String::from_utf8(codec?.encrypt(CONFIG_KEY, plain.as_bytes()).ok()?).ok()
    }
    fn parse(stored: &str) -> Option<Self> {
        let parsed = serde_json::from_str::<Value>(stored).ok()?;
        // encoding/json rejects non-string, non-null values for either Go
        // string field before parseStoredKeys can accept the current key.
        if parsed
            .get("previous")
            .is_some_and(|value| !value.is_string() && !value.is_null())
        {
            return None;
        }
        let decode = |name: &str| {
            parsed
                .get(name)?
                .as_str()
                .and_then(|s| STANDARD.decode(s).ok())
                .and_then(|b| b.try_into().ok())
        };
        Some(Self {
            current: decode("current")?,
            previous: decode("previous").unwrap_or([0; 32]),
        })
    }

    /// Load and apply at startup, then rotate after each interval. The consumer
    /// applies keys to the actual TLS listener through `tls_runtime`. Entropy
    /// must be secure; its failure is fatal to the listener runtime.
    pub async fn run<R, C, S>(
        store: TicketKeyStore,
        interval: Duration,
        codec: Option<Arc<ConfigSecretCodec>>,
        mut random: R,
        mut consume: C,
        shutdown: S,
    ) -> Result<(), Error>
    where
        R: FnMut() -> io::Result<[u8; 32]>,
        C: FnMut([u8; 32], Option<[u8; 32]>),
        S: Future<Output = ()>,
    {
        if interval.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero ticket rotation interval",
            )
            .into());
        }
        tokio::pin!(shutdown);
        let stored = tokio::select! { _ = &mut shutdown => return Ok(()), value = store.load() => value.ok().flatten() };
        // Without key material nothing stored can be opened or trusted. Owner-approved
        // security fix 2026-11-05 (#503): a legacy plaintext row (frozen Go's) is deleted
        // so old keys do not linger; a sealed row is kept for when the codec is back.
        if codec.is_none() && !setjoin_contracts::mutants::on("ticket-legacy-row-kept") {
            if let Some(row) = stored.as_deref() {
                if !setjoin_config_secret::is_config_secret_envelope(row.as_bytes()) {
                    if let Err(err) = store.delete().await {
                        eprintln!("ticket keys: could not remove legacy plaintext row: {err}");
                    }
                }
            }
        }
        let opened = match (stored.as_deref(), codec.as_deref()) {
            (Some(stored), Some(codec)) => Self::open(stored, codec),
            _ => None,
        };
        // Fresh keys replace an absent, legacy-plaintext or unreadable row at once,
        // so unsealed material never lingers until the first rotation.
        let replace = opened.is_none() && codec.is_some();
        let mut keys = match opened {
            Some(keys) => keys,
            None => Self {
                current: random()?,
                previous: [0; 32],
            },
        };
        consume(
            keys.current,
            (keys.previous != [0; 32]).then_some(keys.previous),
        );
        if replace {
            if let Some(value) = keys.seal(codec.as_deref()) {
                match store.save_until(&value, &mut shutdown).await {
                    Ok(true) => return Ok(()),
                    Ok(false) => {}
                    Err(err) => eprintln!("ticket key persistence failed: {err}"),
                }
            }
        }
        let mut timer = tokio::time::interval_at(tokio::time::Instant::now() + interval, interval);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! { _ = &mut shutdown => return Ok(()), _ = timer.tick() => {} }
            keys.previous = keys.current;
            keys.current = random()?;
            consume(
                keys.current,
                (keys.previous != [0; 32]).then_some(keys.previous),
            );
            let Some(value) = keys.seal(codec.as_deref()) else {
                continue;
            };
            match store.save_until(&value, &mut shutdown).await {
                Ok(true) => return Ok(()),
                Ok(false) => {}
                Err(err) => eprintln!("ticket key persistence failed: {err}"),
            }
        }
    }
}

/// Generate a key from the operating system CSPRNG on Setjoin's Linux targets.
pub fn secure_ticket_key() -> io::Result<[u8; 32]> {
    let mut key = [0; 32];
    getrandom::getrandom(&mut key).map_err(|err| io::Error::other(err.to_string()))?;
    Ok(key)
}
