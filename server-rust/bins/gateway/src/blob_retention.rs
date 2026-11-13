//! The `WORM_MODE` PUT retention adapter (#301, pairs with #419): Go's
//! `RetentionPolicyRegistry.ApplyAll` after a blob PUT, and the process-local retry ledger
//! its cleanup tick drains.
//!
//! Go arms S3 Object Lock retention (`PutObjectRetention`, mode from `WORM_MODE`, retain-until
//! `now + WORM_RETENTION_DAYS` calendar days) on the canonical key after a successful upload.
//! A failure is logged and non-fatal: the PUT still answers 201 and the key joins a bounded
//! in-memory ledger (1024, an arbitrary entry evicted when full) that the `blob-cleanup`
//! tick retries. Go refuses to start with an invalid `WORM_MODE`/`WORM_RETENTION_DAYS`, so an
//! invalid configuration is "not served here" and PUT stays with Go.
use crate::recovery_worker::ObjectStore;
use std::{collections::HashSet, sync::Mutex};

/// Go's `DefaultWORMRetentionDays` (7 years).
pub const DEFAULT_DAYS: i64 = 2557;
/// Go's `maxRetryLedger`.
const MAX_LEDGER: usize = 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Worm {
    pub mode: String,
    pub days: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Config {
    /// `WORM_MODE` empty: retention disabled (Go's nil registry).
    Off,
    On(Worm),
    /// Go's `ValidateWORMConfig` would refuse to start.
    Invalid,
}

/// Go's `WORM_MODE` / `WORM_RETENTION_DAYS` as `ValidateWORMConfig` reads them.
pub fn parse(mode: Option<&str>, days: Option<&str>) -> Config {
    let mode = mode.unwrap_or("");
    let days = match days {
        None => Some(DEFAULT_DAYS),
        Some(text) => text.trim().parse::<i64>().ok(),
    };
    // Go's `InitWORM` returns before validating when `WORM_MODE` is empty.
    if mode.is_empty() {
        return Config::Off;
    }
    match (mode, days) {
        ("compliance" | "governance", Some(n)) if n >= 1 => Config::On(Worm {
            mode: mode.to_owned(),
            days: n,
        }),
        _ => Config::Invalid,
    }
}

pub fn config() -> Config {
    parse(
        std::env::var("WORM_MODE").ok().as_deref(),
        std::env::var("WORM_RETENTION_DAYS").ok().as_deref(),
    )
}

/// `time.Now().AddDate(0, 0, days)` rendered as `encoding/xml` renders a `time.Time`.
pub fn retain_until(now: chrono::DateTime<chrono::Utc>, days: i64) -> String {
    crate::admin_job_workers::go_rfc3339_nano(now + chrono::Duration::days(days))
}

static LEDGER: std::sync::LazyLock<Mutex<HashSet<String>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashSet::new()));

/// Go's `noteRetentionRetry`.
pub fn note_retry(key: &str) {
    let mut ledger = LEDGER.lock().unwrap();
    if ledger.len() >= MAX_LEDGER {
        if let Some(evict) = ledger.iter().next().cloned() {
            ledger.remove(&evict);
        }
    }
    ledger.insert(key.to_owned());
}

pub fn pending() -> Vec<String> {
    LEDGER.lock().unwrap().iter().cloned().collect()
}

/// Go's `ApplyAll` for the one WORM policy.
pub async fn apply<S: ObjectStore>(store: &S, worm: &Worm, key: &str) -> Result<(), String> {
    let until = retain_until(chrono::Utc::now(), worm.days);
    store.retain_object(key, &worm.mode, &until).await
}

/// Go's `retryFailedRetention`: drained by the cleanup tick, nothing when WORM is off.
pub async fn retry_failed<S: ObjectStore>(store: &S) {
    let Config::On(worm) = config() else {
        return;
    };
    for key in pending() {
        if let Err(e) = apply(store, &worm, &key).await {
            eprintln!("blob retention retry: apply still failing key={key}: {e}");
            continue;
        }
        LEDGER.lock().unwrap().remove(&key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_follows_go_validation() {
        assert_eq!(parse(None, None), Config::Off);
        assert_eq!(parse(Some(""), Some("2557")), Config::Off);
        assert_eq!(parse(Some(""), Some("30")), Config::Off);
        assert_eq!(
            parse(Some("governance"), None),
            Config::On(Worm {
                mode: "governance".into(),
                days: 2557
            })
        );
        assert_eq!(parse(Some("compliance"), Some("0")), Config::Invalid);
        assert_eq!(parse(Some("legal"), Some("30")), Config::Invalid);
        assert_eq!(parse(Some("compliance"), Some("x")), Config::Invalid);
    }
}
