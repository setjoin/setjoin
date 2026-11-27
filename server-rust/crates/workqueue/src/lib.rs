//! Durable PostgreSQL `WorkQueue` (`FOR UPDATE SKIP LOCKED`), dead-letter
//! inspection/replay, and content-free wakeup bells (Wave 2.1, #548).
//!
//! # Feature isolation
//!
//! - Default features (`[]`): domain-safe only (`enqueue_app_in_mailbox_tx`,
//!   `enqueue_app_in_user_tx`, `collect_stats`, backoff/truncation helpers).
//!   Zero `WorkerPool` or `WorkerTx` types are exposed or compiled.
//! - `worker` feature: enables `setjoin-pg/worker-pool` and the `WorkQueue`
//!   claim / heartbeat / settle / reclaim / consumer API. Strictly restricted
//!   to composition roots (`setjoin-gateway`, `setjoind`) by
//!   `scripts/check-rust-family-isolation.py`.
//! - `operator` feature: enables `OperatorConnection`-based DLQ helpers for
//!   `setjoin-mailctl`.
#![forbid(unsafe_code)]

use std::fmt;
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use setjoin_pg::{MailboxTx, ReadWrite, Row, ScopedExecutor, StatementFailure, Type, UserTx};

#[cfg(feature = "operator")]
pub mod operator;
#[cfg(feature = "worker")]
pub mod schedule;
#[cfg(feature = "worker")]
pub mod worker;

#[cfg(feature = "worker")]
pub use schedule::{ScheduleCredential, ScheduleOutcome, ScheduleRow, ScheduleSpec, ScheduleStore};
#[cfg(feature = "worker")]
pub use worker::{
    ClaimSpec, KindCap, ScheduledActionOutcome, WorkConsumerConfig, WorkQueue,
    WorkScheduledActionConsumer,
};

/// Maximum UTF-8 byte length persisted in `work_items.last_error` and
/// `work_dead_letters.last_error` (matching the V286 `CHECK` constraint).
pub const MAX_ERROR_BYTES: usize = 4096;

/// Content-free wakeup bus channel for durable work queue notifications.
pub const WORK_WAKEUP_CHANNEL: &str = "work";

/// Content-free wakeup bus channel for client/session sync notifications.
pub const SYNC_WAKEUP_CHANNEL: &str = "sync";

/// UTF-8 character-boundary-safe byte truncation.
///
/// Returns the longest valid UTF-8 prefix of `input` whose byte length is
/// `<= max_bytes`. Never panics on multibyte characters.
pub fn truncate_utf8_bytes(input: &str, max_bytes: usize) -> &str {
    if input.len() <= max_bytes {
        return input;
    }
    let mut end = max_bytes;
    while end > 0 && !input.is_char_boundary(end) {
        end -= 1;
    }
    &input[..end]
}

/// Receipt returned by `work_enqueue` / `work_enqueue_app`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnqueueReceipt {
    pub id: i64,
    pub coalesced: bool,
}

/// Scalar queue counts from `public.work_queue_stats()` (zero tenant data).
#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
pub struct WorkQueueStats {
    pub pending: i64,
    pub leased: i64,
    pub dead_letters: i64,
    pub oldest_due_age_secs: f64,
}

/// Domain-safe enqueue request routed through `public.work_enqueue_app(...)`.
#[derive(Clone, Debug, PartialEq)]
pub struct AppEnqueueRequest {
    pub kind: String,
    pub payload: serde_json::Value,
    pub idempotency_key: Option<String>,
    pub delay_secs: f64,
}

impl AppEnqueueRequest {
    pub fn new(kind: impl Into<String>, payload: serde_json::Value) -> Self {
        Self {
            kind: kind.into(),
            payload,
            idempotency_key: None,
            delay_secs: 0.0,
        }
    }

    pub fn with_idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = Some(key.into());
        self
    }

    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay_secs = delay.as_secs_f64();
        self
    }
}

/// Worker-only enqueue request routed through `public.work_enqueue(...)`.
#[derive(Clone, Debug, PartialEq)]
pub struct WorkRequest {
    pub kind: String,
    pub payload: serde_json::Value,
    pub idempotency_key: Option<String>,
    pub delay_secs: f64,
    pub priority: i16,
    pub max_attempts: i32,
}

impl WorkRequest {
    pub fn new(kind: impl Into<String>, payload: serde_json::Value) -> Self {
        Self {
            kind: kind.into(),
            payload,
            idempotency_key: None,
            delay_secs: 0.0,
            priority: 0,
            max_attempts: 5,
        }
    }

    pub fn with_idempotency_key(mut self, key: impl Into<String>) -> Self {
        self.idempotency_key = Some(key.into());
        self
    }

    pub fn with_delay(mut self, delay: Duration) -> Self {
        self.delay_secs = delay.as_secs_f64();
        self
    }

    pub fn with_priority(mut self, priority: i16) -> Self {
        self.priority = priority;
        self
    }

    pub fn with_max_attempts(mut self, max_attempts: i32) -> Self {
        self.max_attempts = max_attempts;
        self
    }
}

/// A leased work item returned by `work_queue_claim`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkItem {
    pub id: i64,
    pub kind: String,
    pub payload: serde_json::Value,
    pub idempotency_key: Option<String>,
    pub priority: i16,
    pub attempts: i32,
    pub max_attempts: i32,
    pub claim_generation: i32,
    pub locked_by: Option<String>,
    pub last_error: Option<String>,
    pub created_at: String,
}

/// A dead-lettered work item from `public.work_dead_letters`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadLetter {
    pub id: i64,
    pub work_item_id: i64,
    pub kind: String,
    pub payload: serde_json::Value,
    pub idempotency_key: Option<String>,
    pub priority: i16,
    pub attempts: i32,
    pub max_attempts: i32,
    pub last_error: String,
    pub failed_by: Option<String>,
    pub enqueued_at: String,
    pub dead_lettered_at: String,
    pub replayed_at: Option<String>,
    pub replayed_work_item_id: Option<i64>,
}

/// Outcome of failing a leased work item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailOutcome {
    Retried,
    DeadLettered { dead_letter_id: i64 },
    LeaseLost,
}

/// Counts returned by `work_queue_reclaim_expired`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ReclaimCounts {
    pub reclaimed: i32,
    pub dead_lettered: i32,
}

/// Errors returned by `WorkQueue` operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WorkQueueError {
    Statement(StatementFailure),
    InvalidArgument(String),
    Protocol(&'static str),
    LeaseLost { id: i64, claim_generation: i32 },
}

impl fmt::Display for WorkQueueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Statement(e) => write!(f, "workqueue db error: {e:?}"),
            Self::InvalidArgument(msg) => write!(f, "workqueue invalid argument: {msg}"),
            Self::Protocol(msg) => write!(f, "workqueue protocol error: {msg}"),
            Self::LeaseLost {
                id,
                claim_generation,
            } => write!(
                f,
                "workqueue lease lost for item {id} (claim_generation={claim_generation})"
            ),
        }
    }
}

impl std::error::Error for WorkQueueError {}

impl From<StatementFailure> for WorkQueueError {
    fn from(err: StatementFailure) -> Self {
        Self::Statement(err)
    }
}

/// Exponential backoff policy with cryptographic uniform jitter in `[0.5 * d, 1.0 * d]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BackoffPolicy {
    pub base: Duration,
    pub max: Duration,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        Self {
            base: Duration::from_secs(30),
            max: Duration::from_secs(3600),
        }
    }
}

impl BackoffPolicy {
    pub const fn new(base: Duration, max: Duration) -> Self {
        Self { base, max }
    }

    /// Compute the unjittered capped exponential delay for 1-based `attempt`.
    pub fn uncapped_base_delay(&self, attempt: i32) -> Duration {
        let shift = attempt.saturating_sub(1).clamp(0, 20) as u32;
        let factor = 1u32.checked_shl(shift).unwrap_or(u32::MAX);
        self.base.saturating_mul(factor).min(self.max)
    }

    /// Compute a jittered delay uniformly distributed in `[0.5 * d, 1.0 * d]`
    /// using `ring::rand::SystemRandom`, capped at `self.max`.
    pub fn jittered_delay(&self, attempt: i32) -> Duration {
        let ceiling = self.uncapped_base_delay(attempt);
        let max_nanos = ceiling.as_nanos().min(u64::MAX as u128) as u64;
        if max_nanos <= 1 {
            return ceiling;
        }
        let half = max_nanos / 2;
        let span = max_nanos - half;
        let mut bytes = [0u8; 8];
        let sample = match SystemRandom::new().fill(&mut bytes) {
            Ok(()) => u64::from_le_bytes(bytes),
            Err(_) => span,
        };
        let offset = sample % (span.saturating_add(1).max(1));
        Duration::from_nanos((half + offset).min(max_nanos))
    }
}

pub(crate) fn sanitize_delay_secs(delay_secs: f64) -> Result<f64, WorkQueueError> {
    if !delay_secs.is_finite() {
        return Err(WorkQueueError::InvalidArgument(
            "delay_secs must be finite".into(),
        ));
    }
    Ok(delay_secs.max(0.0))
}

const APP_ENQUEUE_SQL: &str = "SELECT work_item_id, coalesced \
     FROM public.work_enqueue_app($1, $2::text::jsonb, $3, now() + make_interval(secs => $4))";

/// Enqueue an allowlisted app work item inside a verified `MailboxTx<ReadWrite>`.
///
/// The SQL reducer stamps `actor_user_id` / `actor_mailbox_id` from session GUCs
/// (R2), prefixes `idempotency_key` with the actor scope, and clamps priority /
/// max_attempts / delay.
pub async fn enqueue_app_in_mailbox_tx(
    tx: &mut MailboxTx<ReadWrite>,
    req: &AppEnqueueRequest,
) -> Result<EnqueueReceipt, WorkQueueError> {
    let payload_text = serde_json::to_string(&req.payload)
        .map_err(|_| WorkQueueError::Protocol("invalid work payload JSON"))?;
    let delay = sanitize_delay_secs(req.delay_secs)?;
    let rows = tx
        .query(
            APP_ENQUEUE_SQL,
            &[
                (&req.kind, Type::TEXT),
                (&payload_text, Type::TEXT),
                (&req.idempotency_key, Type::TEXT),
                (&delay, Type::FLOAT8),
            ],
        )
        .await?;
    parse_enqueue_receipt(&rows)
}

/// Enqueue an allowlisted app work item inside a verified `UserTx<ReadWrite>`.
pub async fn enqueue_app_in_user_tx(
    tx: &mut UserTx<ReadWrite>,
    req: &AppEnqueueRequest,
) -> Result<EnqueueReceipt, WorkQueueError> {
    let payload_text = serde_json::to_string(&req.payload)
        .map_err(|_| WorkQueueError::Protocol("invalid work payload JSON"))?;
    let delay = sanitize_delay_secs(req.delay_secs)?;
    let rows = tx
        .query(
            APP_ENQUEUE_SQL,
            &[
                (&req.kind, Type::TEXT),
                (&payload_text, Type::TEXT),
                (&req.idempotency_key, Type::TEXT),
                (&delay, Type::FLOAT8),
            ],
        )
        .await?;
    parse_enqueue_receipt(&rows)
}

/// Collect scalar queue counts via `public.work_queue_stats()`.
pub async fn collect_stats(exec: &ScopedExecutor) -> Result<WorkQueueStats, WorkQueueError> {
    let rows = exec
        .read(
            "SELECT pending, leased, dead_letters, oldest_due_age_secs FROM public.work_queue_stats()",
            &[],
        )
        .await?;
    parse_stats_row(&rows)
}

pub(crate) fn parse_enqueue_receipt(rows: &[Row]) -> Result<EnqueueReceipt, WorkQueueError> {
    let row = rows
        .first()
        .ok_or(WorkQueueError::Protocol("work_enqueue returned no rows"))?;
    let id: i64 = row
        .try_get(0)
        .map_err(|_| WorkQueueError::Protocol("invalid work_item_id column"))?;
    let coalesced: bool = row
        .try_get(1)
        .map_err(|_| WorkQueueError::Protocol("invalid coalesced column"))?;
    Ok(EnqueueReceipt { id, coalesced })
}

pub(crate) fn parse_stats_row(rows: &[Row]) -> Result<WorkQueueStats, WorkQueueError> {
    let row = rows.first().ok_or(WorkQueueError::Protocol(
        "work_queue_stats returned no rows",
    ))?;
    Ok(WorkQueueStats {
        pending: row.try_get(0).unwrap_or(0),
        leased: row.try_get(1).unwrap_or(0),
        dead_letters: row.try_get(2).unwrap_or(0),
        oldest_due_age_secs: row.try_get(3).unwrap_or(0.0),
    })
}

#[cfg(feature = "operator")]
pub(crate) fn parse_dead_letter_row(row: &Row) -> Result<DeadLetter, String> {
    let payload_str: String = row.try_get(3).map_err(|e| format!("payload: {e}"))?;
    let payload: serde_json::Value =
        serde_json::from_str(&payload_str).map_err(|e| format!("parse payload json: {e}"))?;
    Ok(DeadLetter {
        id: row.try_get(0).map_err(|e| format!("id: {e}"))?,
        work_item_id: row.try_get(1).map_err(|e| format!("work_item_id: {e}"))?,
        kind: row.try_get(2).map_err(|e| format!("kind: {e}"))?,
        payload,
        idempotency_key: row
            .try_get(4)
            .map_err(|e| format!("idempotency_key: {e}"))?,
        priority: row.try_get(5).map_err(|e| format!("priority: {e}"))?,
        attempts: row.try_get(6).map_err(|e| format!("attempts: {e}"))?,
        max_attempts: row.try_get(7).map_err(|e| format!("max_attempts: {e}"))?,
        last_error: row.try_get(8).map_err(|e| format!("last_error: {e}"))?,
        failed_by: row.try_get(9).map_err(|e| format!("failed_by: {e}"))?,
        enqueued_at: row.try_get(10).map_err(|e| format!("enqueued_at: {e}"))?,
        dead_lettered_at: row
            .try_get(11)
            .map_err(|e| format!("dead_lettered_at: {e}"))?,
        replayed_at: row.try_get(12).map_err(|e| format!("replayed_at: {e}"))?,
        replayed_work_item_id: row
            .try_get(13)
            .map_err(|e| format!("replayed_work_item_id: {e}"))?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_utf8_bytes_never_splits_multibyte_chars() {
        assert_eq!(truncate_utf8_bytes("hello", 10), "hello");
        assert_eq!(truncate_utf8_bytes("hello", 5), "hello");
        assert_eq!(truncate_utf8_bytes("hello", 3), "hel");
        // Each emoji is 4 UTF-8 bytes; truncating at 5, 6, 7 bytes must keep 1 emoji (4 bytes).
        let emojis = "🔥🚀🎉";
        assert_eq!(emojis.len(), 12);
        assert_eq!(truncate_utf8_bytes(emojis, 0), "");
        assert_eq!(truncate_utf8_bytes(emojis, 3), "");
        assert_eq!(truncate_utf8_bytes(emojis, 4), "🔥");
        assert_eq!(truncate_utf8_bytes(emojis, 5), "🔥");
        assert_eq!(truncate_utf8_bytes(emojis, 7), "🔥");
        assert_eq!(truncate_utf8_bytes(emojis, 8), "🔥🚀");
        // 3-byte CJK chars crossing 4096-byte boundary.
        let cjk = "测".repeat(2000);
        let truncated = truncate_utf8_bytes(&cjk, MAX_ERROR_BYTES);
        assert!(truncated.len() <= MAX_ERROR_BYTES);
        assert_eq!(truncated.len(), 4095);
    }

    #[test]
    fn backoff_policy_bounds_and_jitter_range() {
        let policy = BackoffPolicy::new(Duration::from_secs(10), Duration::from_secs(120));
        assert_eq!(policy.uncapped_base_delay(1), Duration::from_secs(10));
        assert_eq!(policy.uncapped_base_delay(2), Duration::from_secs(20));
        assert_eq!(policy.uncapped_base_delay(3), Duration::from_secs(40));
        assert_eq!(policy.uncapped_base_delay(10), Duration::from_secs(120));
        for attempt in 1..=8 {
            let ceiling = policy.uncapped_base_delay(attempt);
            let floor = ceiling / 2;
            for _ in 0..32 {
                let d = policy.jittered_delay(attempt);
                assert!(d >= floor, "delay {d:?} below floor {floor:?}");
                assert!(d <= ceiling, "delay {d:?} above ceiling {ceiling:?}");
            }
        }
    }
}
