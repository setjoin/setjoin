//! The `WORM_MODE` PUT retention adapter (#301, upgraded to durable `WorkQueue`
//! in Wave 2.2 #549).
//!
//! Arms S3 Object Lock retention (`PutObjectRetention`, mode from `WORM_MODE`,
//! retain-until `now + WORM_RETENTION_DAYS` calendar days) on the canonical key.
//! All process-local in-memory retry ledgers are retired: durable-first enqueue
//! on `"blob.worm_arm"` happens BEFORE `store.promote`, and retries/DLQ live
//! exclusively in PostgreSQL `work_items` / `work_dead_letters`.

use crate::recovery_worker::{ObjectStore, RetentionError};
use serde::{Deserialize, Serialize};

/// Go's `DefaultWORMRetentionDays` (7 years).
pub const DEFAULT_DAYS: i64 = 2557;
/// Durable WorkQueue kind for S3 Object Lock retention arming.
pub const WORK_KIND_WORM_ARM: &str = "blob.worm_arm";
/// Durable WorkQueue kind for post-row-delete S3 object reap retries.
pub const WORK_KIND_REAP_RETRY: &str = "blob.s3_reap_retry";
/// Per-kind concurrency cap for `blob.worm_arm`.
pub const WORM_MAX_CONCURRENCY: i32 = 8;
/// Max retry attempts before moving a failing `blob.worm_arm` job to DLQ.
pub const WORM_MAX_ATTEMPTS: i32 = 20;

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

/// Durable JSON payload stored on `work_items` for `kind = "blob.worm_arm"`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WormArmPayload {
    pub sha256: String,
    pub object_key: String,
    pub mode: String,
    pub retain_days: i64,
    pub retain_until: String,
    pub version_id: Option<String>,
}

/// Canonical idempotency key for `blob.worm_arm`.
pub fn worm_idempotency_key(sha256: &str, retain_until: &str) -> String {
    format!("{WORK_KIND_WORM_ARM}:{sha256}:{retain_until}")
}

/// Canonical idempotency key for `blob.s3_reap_retry`.
pub fn reap_idempotency_key(sha256: &str) -> String {
    format!("blob_reap:{sha256}")
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

/// Apply WORM retention using an explicit pre-computed `retain_until` timestamp.
pub async fn apply_until<S: ObjectStore>(
    store: &S,
    mode: &str,
    key: &str,
    until: &str,
) -> Result<(), RetentionError> {
    store.retain_object(key, mode, until).await
}

/// Apply WORM retention for `now + worm.days`.
pub async fn apply<S: ObjectStore>(
    store: &S,
    worm: &Worm,
    key: &str,
) -> Result<(), RetentionError> {
    let until = retain_until(chrono::Utc::now(), worm.days);
    apply_until(store, &worm.mode, key, &until).await
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
