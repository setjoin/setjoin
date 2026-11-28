//! Wave 2.3/2.4 (#550/#551): Mark-and-Sweep S3 Blob GC Worker, abandoned
//! `tmp/blob-upload/*` staging sweep, and lock-safe `orphaned_message_blobs` cleaner.
//!
//! Operates in three modes controlled by `BLOB_GC_MODE=off|shadow|live` (env override)
//! or worker-only `public.blob_gc_config.mode` (`live` after V293):
//! - `off`: operator emergency kill-switch (halts live sweeping immediately without
//!   invoking any retired legacy `ref_count` cleanup).
//! - `shadow`: runs Phase 1 Mark ONLY (zero S3 deletes, zero `DELETE FROM blobs`).
//! - `live`: runs Phase 1 Mark, Phase 2 Two-Transaction Sweep (Tx 2A `blob_gc_claim_purging`,
//!   then Tx 2B on a dedicated `WorkerDatabase::connect_session()` session with
//!   `SET LOCAL idle_in_transaction_session_timeout = '8s'`, per-`sha256` advisory lock,
//!   split Statement 1 `FOR UPDATE OF s, b` + Statement 2 fresh `READ COMMITTED` snapshot
//!   check of `blob_has_live_reference` / `blob_is_held_or_retained`, version-aware
//!   `delete_blob_checked`, concurrency = 1, wall-clock tick budget, circuit breaker,
//!   and graceful S3 403 Object Lock reversion), lock-safe `orphaned_message_blobs`
//!   reaping, and abandoned `tmp/blob-upload/*` (>24h) cleanup.

use crate::blob_retention::{
    BLOB_STAGING_PREFIX, WORK_KIND_PROMOTE_RECOVER, WORK_KIND_PROMOTE_VERIFY,
};
use crate::recovery_worker::{BlobDeleteOutcome, ObjectStore, S3Store};
use serde::Deserialize;
use setjoin_pg::{
    workers::{WorkerConnection, WorkerDatabase},
    Type,
};
use std::{
    collections::HashSet,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;

/// Default timeout for a single S3 DELETE future inside Tx 2B (PLAN-550/551).
pub const DEFAULT_S3_DELETE_TIMEOUT: Duration = Duration::from_secs(5);
/// Bounded HTTP/TCP request timeout so client TCP abort fires strictly before
/// PG's 5s wait / 8s `idle_in_transaction_session_timeout`.
pub const DEFAULT_S3_HTTP_TIMEOUT: Duration = Duration::from_secs(4);
/// Default consecutive transient S3 error threshold that trips the sweep circuit breaker.
pub const DEFAULT_MAX_CONSECUTIVE_ERRORS: usize = 5;
/// Default wall-clock budget for a single supervised GC tick (fits inside 300s schedule timeout).
pub const DEFAULT_TICK_BUDGET: Duration = Duration::from_secs(180);
/// Default age threshold before unreferenced `tmp/blob-upload/*` objects are swept (24h).
pub const DEFAULT_STAGING_TTL: Duration = Duration::from_secs(24 * 3600);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GcMode {
    Off,
    Shadow,
    Live,
}

impl GcMode {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "off" => Some(Self::Off),
            "shadow" => Some(Self::Shadow),
            "live" => Some(Self::Live),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Shadow => "shadow",
            Self::Live => "live",
        }
    }
}

/// Returns `Ok(Some(mode))` when `BLOB_GC_MODE` is explicitly set and valid,
/// `Ok(None)` when unset/empty, or `Err(bad_value)` when set to an invalid value.
pub fn env_mode() -> Result<Option<GcMode>, String> {
    match std::env::var("BLOB_GC_MODE") {
        Ok(val) if !val.trim().is_empty() => GcMode::parse(&val)
            .map(Some)
            .ok_or_else(|| format!("invalid BLOB_GC_MODE={val:?}; expected off|shadow|live")),
        _ => Ok(None),
    }
}

/// Returns true iff `key` is a bare lowercase 64-hex SHA-256 object key (canonical `blobs` key).
pub fn is_bare_sha256(key: &str) -> bool {
    key.len() == 64
        && key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Strict classifier for S3 Object Lock / WORM retention 403 rejections (delegates
/// to `recovery_worker::is_strict_object_lock_error_msg`; kept public for tests).
pub fn is_s3_object_lock_403(err: &str) -> bool {
    crate::recovery_worker::is_strict_object_lock_error_msg(err)
}

/// Process-wide Prometheus counters for Mark-and-Sweep S3 Blob GC.
#[derive(Default)]
pub struct BlobGcMetrics {
    pub shadow_runs_total: AtomicU64,
    pub shadow_only_in_mark_and_sweep_total: AtomicU64,
    pub shadow_only_in_refcount_zero_total: AtomicU64,
    pub mark_eligible_total: AtomicU64,
    pub mark_reactivated_total: AtomicU64,
    pub sweep_purged_total: AtomicU64,
    pub sweep_aborted_reactivated_total: AtomicU64,
    pub sweep_s3_errors_total: AtomicU64,
    pub sweep_worm_lock_403_total: AtomicU64,
    pub sweep_worm_invalid_refusals_total: AtomicU64,
    pub sweep_circuit_breaker_trips_total: AtomicU64,
    pub staging_swept_total: AtomicU64,
    pub orphaned_raw_reaped_total: AtomicU64,
    pub extracted_text_swept_total: AtomicU64,
}

impl BlobGcMetrics {
    pub fn render_prometheus(&self) -> String {
        let rows: &[(&str, &str, u64)] = &[
            (
                "setjoin_blob_gc_shadow_runs_total",
                "Total shadow-mode mark-only runs executed by Mark-and-Sweep blob GC.",
                self.shadow_runs_total.load(Ordering::Relaxed),
            ),
            (
                "setjoin_blob_gc_shadow_only_in_mark_and_sweep_total",
                "Historical pre-V293 ref_count shadow discrepancy counter (always 0 post-V293).",
                self.shadow_only_in_mark_and_sweep_total
                    .load(Ordering::Relaxed),
            ),
            (
                "setjoin_blob_gc_shadow_only_in_refcount_zero_total",
                "Historical pre-V293 ref_count shadow discrepancy counter (always 0 post-V293).",
                self.shadow_only_in_refcount_zero_total
                    .load(Ordering::Relaxed),
            ),
            (
                "setjoin_blob_gc_mark_eligible_total",
                "Blobs transitioned to reclaim_eligible by Phase 1 Mark.",
                self.mark_eligible_total.load(Ordering::Relaxed),
            ),
            (
                "setjoin_blob_gc_mark_reactivated_total",
                "Blobs reactivated from reclaim_eligible back to active.",
                self.mark_reactivated_total.load(Ordering::Relaxed),
            ),
            (
                "setjoin_blob_gc_sweep_purged_total",
                "Blobs permanently deleted from S3 and public.blobs in Tx 2B.",
                self.sweep_purged_total.load(Ordering::Relaxed),
            ),
            (
                "setjoin_blob_gc_sweep_aborted_reactivated_total",
                "Tx 2B sweeps aborted with zero S3 deletes because the blob was reactivated.",
                self.sweep_aborted_reactivated_total.load(Ordering::Relaxed),
            ),
            (
                "setjoin_blob_gc_sweep_s3_errors_total",
                "Transient S3 errors or timeouts during Tx 2B (row left purging for retry).",
                self.sweep_s3_errors_total.load(Ordering::Relaxed),
            ),
            (
                "setjoin_blob_gc_sweep_worm_lock_403_total",
                "S3 403 Object Lock rejections handled cleanly by reverting to active.",
                self.sweep_worm_lock_403_total.load(Ordering::Relaxed),
            ),
            (
                "setjoin_blob_gc_sweep_worm_invalid_refusals_total",
                "GC ticks refused fail-closed due to invalid WORM_MODE configuration.",
                self.sweep_worm_invalid_refusals_total
                    .load(Ordering::Relaxed),
            ),
            (
                "setjoin_blob_gc_sweep_circuit_breaker_trips_total",
                "Sweep batches halted early by consecutive S3 error circuit breaker.",
                self.sweep_circuit_breaker_trips_total
                    .load(Ordering::Relaxed),
            ),
            (
                "setjoin_blob_gc_staging_swept_total",
                "Abandoned tmp/blob-upload/* objects permanently swept after 24h.",
                self.staging_swept_total.load(Ordering::Relaxed),
            ),
            (
                "setjoin_blob_gc_orphaned_raw_reaped_total",
                "Orphaned raw message blobs permanently reaped under advisory lock.",
                self.orphaned_raw_reaped_total.load(Ordering::Relaxed),
            ),
            (
                "setjoin_blob_gc_extracted_text_swept_total",
                "Orphaned search_extracted_text cache rows swept by Mark-and-Sweep GC.",
                self.extracted_text_swept_total.load(Ordering::Relaxed),
            ),
        ];
        let mut out = String::new();
        for (name, help, value) in rows {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
            ));
        }
        out
    }
}

pub static METRICS: BlobGcMetrics = BlobGcMetrics {
    shadow_runs_total: AtomicU64::new(0),
    shadow_only_in_mark_and_sweep_total: AtomicU64::new(0),
    shadow_only_in_refcount_zero_total: AtomicU64::new(0),
    mark_eligible_total: AtomicU64::new(0),
    mark_reactivated_total: AtomicU64::new(0),
    sweep_purged_total: AtomicU64::new(0),
    sweep_aborted_reactivated_total: AtomicU64::new(0),
    sweep_s3_errors_total: AtomicU64::new(0),
    sweep_worm_lock_403_total: AtomicU64::new(0),
    sweep_worm_invalid_refusals_total: AtomicU64::new(0),
    sweep_circuit_breaker_trips_total: AtomicU64::new(0),
    staging_swept_total: AtomicU64::new(0),
    orphaned_raw_reaped_total: AtomicU64::new(0),
    extracted_text_swept_total: AtomicU64::new(0),
};

#[derive(Clone, Debug)]
struct EffectiveConfig {
    mode: GcMode,
    grace_minutes: i32,
    cooldown_minutes: i32,
    batch_size: i32,
}

/// Reads effective GC mode (`BLOB_GC_MODE` env override > `public.blob_gc_config.mode` > `live`).
/// Fails closed to `Err` on invalid `BLOB_GC_MODE`.
pub async fn effective_mode(conn: &WorkerConnection) -> Result<GcMode, String> {
    if let Some(m) = env_mode()? {
        return Ok(m);
    }
    let rows = conn
        .query("SELECT mode FROM public.blob_gc_config WHERE id = 1", &[])
        .await
        .map_err(|e| format!("blob_gc_config read failed: {e}"))?;
    let Some(row) = rows.first() else {
        return Ok(GcMode::Off);
    };
    let raw: String = row
        .try_get(0)
        .map_err(|e| format!("blob_gc_config.mode decode failed: {e}"))?;
    GcMode::parse(&raw).ok_or_else(|| format!("invalid blob_gc_config.mode={raw:?}"))
}

enum PrepOutcome {
    Proceed,
    AbortedOpenTx,
    AbortedCommitted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PurgeOutcome {
    Purged,
    AbortedReactivated,
    WormLocked403,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickSummary {
    pub mode: Option<GcMode>,
    pub marked_eligible: u64,
    pub reactivated: u64,
    pub only_in_mark_and_sweep: u64,
    pub only_in_refcount_zero: u64,
    pub purged: u64,
    pub aborted_reactivated: u64,
    pub worm_locked_403: u64,
    pub s3_errors: u64,
    pub staging_swept: u64,
    pub orphaned_raw_reaped: u64,
    pub extracted_text_swept: u64,
    pub circuit_breaker_tripped: bool,
    pub budget_exhausted: bool,
}

#[derive(Deserialize)]
struct MarkResult {
    marked_eligible: u64,
    reactivated: u64,
}

pub struct BlobGcWorker<S = S3Store> {
    db: WorkerDatabase,
    store: Arc<S>,
    mode_override: Option<GcMode>,
    worm_override: Option<crate::blob_retention::Config>,
    grace_minutes_override: Option<i32>,
    cooldown_minutes_override: Option<i32>,
    batch_size_override: Option<i32>,
    audit_hmac_key_override: Option<String>,
    s3_delete_timeout: Duration,
    max_consecutive_errors: usize,
    tick_budget: Duration,
    staging_ttl: Duration,
    cancel: Option<CancellationToken>,
}

impl<S: ObjectStore> BlobGcWorker<S> {
    pub fn new(db: WorkerDatabase, store: Arc<S>) -> Self {
        Self {
            db,
            store,
            mode_override: None,
            worm_override: None,
            grace_minutes_override: None,
            cooldown_minutes_override: None,
            batch_size_override: None,
            audit_hmac_key_override: None,
            s3_delete_timeout: DEFAULT_S3_DELETE_TIMEOUT,
            max_consecutive_errors: DEFAULT_MAX_CONSECUTIVE_ERRORS,
            tick_budget: DEFAULT_TICK_BUDGET,
            staging_ttl: DEFAULT_STAGING_TTL,
            cancel: None,
        }
    }

    pub fn with_mode(mut self, mode: GcMode) -> Self {
        self.mode_override = Some(mode);
        self
    }

    pub fn with_worm_config(mut self, config: crate::blob_retention::Config) -> Self {
        self.worm_override = Some(config);
        self
    }

    pub fn with_grace_minutes(mut self, minutes: i32) -> Self {
        self.grace_minutes_override = Some(minutes);
        self
    }

    pub fn with_cooldown_minutes(mut self, minutes: i32) -> Self {
        self.cooldown_minutes_override = Some(minutes);
        self
    }

    pub fn with_batch_size(mut self, batch_size: i32) -> Self {
        self.batch_size_override = Some(batch_size);
        self
    }

    pub fn with_audit_hmac_key(mut self, key: String) -> Self {
        self.audit_hmac_key_override = Some(key);
        self
    }

    pub fn with_s3_delete_timeout(mut self, timeout: Duration) -> Self {
        self.s3_delete_timeout = timeout;
        self
    }

    pub fn with_max_consecutive_errors(mut self, max: usize) -> Self {
        self.max_consecutive_errors = max.max(1);
        self
    }

    pub fn with_tick_budget(mut self, budget: Duration) -> Self {
        self.tick_budget = budget;
        self
    }

    pub fn with_staging_ttl(mut self, ttl: Duration) -> Self {
        self.staging_ttl = ttl;
        self
    }

    pub fn with_cancel(mut self, cancel: CancellationToken) -> Self {
        self.cancel = Some(cancel);
        self
    }

    fn should_stop(&self, started: Instant) -> bool {
        started.elapsed() >= self.tick_budget
            || self.cancel.as_ref().is_some_and(|c| c.is_cancelled())
    }

    /// Ensures `app.audit_hmac_key` is populated inside the active transaction for
    /// Audit V3 cutover (`V232__audit_chain_cutover.sql`) whenever the session does
    /// not already carry it via `WorkerDatabase::with_audit_keys`.
    async fn apply_audit_hmac_local(&self, conn: &WorkerConnection) -> Result<(), String> {
        let existing_rows = conn
            .query(
                "SELECT COALESCE(current_setting('app.audit_hmac_key', true), '')",
                &[],
            )
            .await
            .map_err(|e| format!("audit_hmac_key check failed: {e}"))?;
        let existing: String = existing_rows
            .first()
            .ok_or("audit_hmac_key check returned no row")?
            .try_get(0)
            .map_err(|e| format!("audit_hmac_key decode failed: {e}"))?;
        if !existing.is_empty() {
            return Ok(());
        }
        let key = self
            .audit_hmac_key_override
            .clone()
            .or_else(|| std::env::var("AUDIT_HMAC_KEY").ok())
            .unwrap_or_default();
        if !key.is_empty() {
            conn.query(
                "SELECT set_config('app.audit_hmac_key', $1, true)",
                &[(&key, Type::TEXT)],
            )
            .await
            .map_err(|e| format!("set_config(app.audit_hmac_key) failed: {e}"))?;
        }
        Ok(())
    }

    pub async fn worker_bypasses_rls(&self, conn: &WorkerConnection) -> Result<bool, String> {
        let rows = conn
            .query(
                "SELECT rolbypassrls OR rolsuper FROM pg_roles WHERE rolname = current_user",
                &[],
            )
            .await
            .map_err(|e| e.to_string())?;
        match rows.first() {
            Some(r) => r
                .try_get::<_, bool>(0)
                .map_err(|e| format!("BYPASSRLS check decode failed: {e}")),
            None => Ok(false),
        }
    }

    fn resolve_worm_days(&self) -> Result<i32, String> {
        let cfg = self
            .worm_override
            .clone()
            .unwrap_or_else(crate::blob_retention::config);
        match cfg {
            crate::blob_retention::Config::Off => Ok(0),
            crate::blob_retention::Config::On(w) => i32::try_from(w.days)
                .ok()
                .filter(|d| *d >= 1)
                .ok_or_else(|| {
                    METRICS
                        .sweep_worm_invalid_refusals_total
                        .fetch_add(1, Ordering::Relaxed);
                    "WORM_RETENTION_DAYS out of range; refusing blob GC sweep (fail-closed)".into()
                }),
            crate::blob_retention::Config::Invalid => {
                METRICS
                    .sweep_worm_invalid_refusals_total
                    .fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "blob-gc: REFUSING sweep: invalid WORM_MODE/WORM_RETENTION_DAYS configuration (fail-closed)"
                );
                Err("invalid WORM_MODE configuration; refusing blob GC sweep (fail-closed)".into())
            }
        }
    }

    async fn resolve_config(
        &self,
        conn: &WorkerConnection,
        forced_mode: Option<GcMode>,
    ) -> Result<EffectiveConfig, String> {
        let rows = conn
            .query(
                "SELECT mode, grace_minutes, sweep_cooldown_minutes, batch_size \
                 FROM public.blob_gc_config WHERE id = 1",
                &[],
            )
            .await
            .map_err(|e| format!("blob_gc_config query failed: {e}"))?;

        let (db_mode, db_grace, db_cooldown, db_batch) = match rows.first() {
            Some(r) => {
                let raw: String = r
                    .try_get(0)
                    .map_err(|e| format!("blob_gc_config.mode decode failed: {e}"))?;
                let parsed = GcMode::parse(&raw)
                    .ok_or_else(|| format!("invalid blob_gc_config.mode={raw:?}"))?;
                let grace: i32 = r
                    .try_get(1)
                    .map_err(|e| format!("blob_gc_config.grace_minutes decode failed: {e}"))?;
                let cooldown: i32 = r.try_get(2).map_err(|e| {
                    format!("blob_gc_config.sweep_cooldown_minutes decode failed: {e}")
                })?;
                let batch: i32 = r
                    .try_get(3)
                    .map_err(|e| format!("blob_gc_config.batch_size decode failed: {e}"))?;
                (parsed, grace, cooldown, batch)
            }
            None => (GcMode::Off, 1440, 1440, 500),
        };

        let mode = match forced_mode.or(self.mode_override) {
            Some(m) => m,
            None => env_mode()?.unwrap_or(db_mode),
        };

        Ok(EffectiveConfig {
            mode,
            grace_minutes: self.grace_minutes_override.unwrap_or(db_grace).max(1440),
            cooldown_minutes: self.cooldown_minutes_override.unwrap_or(db_cooldown).max(0),
            batch_size: self
                .batch_size_override
                .unwrap_or(db_batch)
                .clamp(1, 10_000),
        })
    }

    /// Executes one Mark-and-Sweep GC tick respecting `off | shadow | live` mode
    /// and all fail-closed safety gates.
    pub async fn tick(&self) -> Result<TickSummary, String> {
        self.tick_inner(None).await
    }

    /// Executes one Mark-and-Sweep GC tick using a caller-sampled `GcMode`.
    pub async fn tick_with_mode(&self, mode: GcMode) -> Result<TickSummary, String> {
        self.tick_inner(Some(mode)).await
    }

    async fn tick_inner(&self, forced_mode: Option<GcMode>) -> Result<TickSummary, String> {
        let started = Instant::now();
        let conn = self.db.connect_session().await.map_err(|e| e.to_string())?;
        if !self.worker_bypasses_rls(&conn).await? {
            return Err(
                "blob-gc: worker credential lacks BYPASSRLS; refusing to run (fail-closed)".into(),
            );
        }

        let cfg = self.resolve_config(&conn, forced_mode).await?;
        match cfg.mode {
            GcMode::Off => Ok(TickSummary {
                mode: Some(GcMode::Off),
                ..TickSummary::default()
            }),
            GcMode::Shadow => {
                // Post-V293 shadow mode executes Phase 1 Mark only (zero S3/DB deletes).
                let worm_days = self.resolve_worm_days()?;
                self.run_shadow_mark_only(&conn, &cfg, worm_days).await
            }
            GcMode::Live => {
                // Fail closed before any Mark or Sweep if WORM_MODE is misconfigured.
                let worm_days = self.resolve_worm_days()?;
                self.run_live(&conn, &cfg, worm_days, started).await
            }
        }
    }

    async fn run_shadow_mark_only(
        &self,
        conn: &WorkerConnection,
        cfg: &EffectiveConfig,
        worm_days: i32,
    ) -> Result<TickSummary, String> {
        let mark_rows = conn
            .query(
                "SELECT public.blob_gc_mark($1, $2, $3)::text",
                &[
                    (&cfg.grace_minutes, Type::INT4),
                    (&worm_days, Type::INT4),
                    (&cfg.batch_size, Type::INT4),
                ],
            )
            .await?;
        let mark_raw: String = mark_rows
            .first()
            .ok_or("blob_gc_mark returned no row")?
            .try_get(0)
            .map_err(|e| format!("blob_gc_mark decode failed: {e}"))?;
        let mark: MarkResult =
            serde_json::from_str(&mark_raw).map_err(|e| format!("invalid mark JSON: {e}"))?;

        METRICS.shadow_runs_total.fetch_add(1, Ordering::Relaxed);
        METRICS
            .mark_eligible_total
            .fetch_add(mark.marked_eligible, Ordering::Relaxed);
        METRICS
            .mark_reactivated_total
            .fetch_add(mark.reactivated, Ordering::Relaxed);

        Ok(TickSummary {
            mode: Some(GcMode::Shadow),
            marked_eligible: mark.marked_eligible,
            reactivated: mark.reactivated,
            ..TickSummary::default()
        })
    }

    async fn run_live(
        &self,
        conn: &WorkerConnection,
        cfg: &EffectiveConfig,
        worm_days: i32,
        started: Instant,
    ) -> Result<TickSummary, String> {
        let mut summary = TickSummary {
            mode: Some(GcMode::Live),
            ..TickSummary::default()
        };

        // Phase 1: Mark
        let mark_rows = conn
            .query(
                "SELECT public.blob_gc_mark($1, $2, $3)::text",
                &[
                    (&cfg.grace_minutes, Type::INT4),
                    (&worm_days, Type::INT4),
                    (&cfg.batch_size, Type::INT4),
                ],
            )
            .await?;
        let mark_raw: String = mark_rows
            .first()
            .ok_or("blob_gc_mark returned no row")?
            .try_get(0)
            .map_err(|e| format!("blob_gc_mark decode failed: {e}"))?;
        let mark: MarkResult =
            serde_json::from_str(&mark_raw).map_err(|e| format!("invalid mark JSON: {e}"))?;
        summary.marked_eligible = mark.marked_eligible;
        summary.reactivated = mark.reactivated;
        METRICS
            .mark_eligible_total
            .fetch_add(mark.marked_eligible, Ordering::Relaxed);
        METRICS
            .mark_reactivated_total
            .fetch_add(mark.reactivated, Ordering::Relaxed);

        let batch_limit = i64::from(cfg.batch_size);

        // Resume any durable `purging` rows left behind by prior crashed/timed-out Tx 2B.
        let mut queue: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        let resume_rows = conn
            .query(
                "SELECT blob_sha256 FROM public.blob_gc_state \
                  WHERE gc_state = 'purging' \
                  ORDER BY purging_at ASC, blob_sha256 ASC \
                  LIMIT $1",
                &[(&batch_limit, Type::INT8)],
            )
            .await?;
        for row in resume_rows {
            let sha: String = row
                .try_get(0)
                .map_err(|e| format!("purging queue blob_sha256 decode failed: {e}"))?;
            if seen.insert(sha.clone()) {
                queue.push(sha);
            }
        }

        // Phase 2 Tx 2A: claim eligible blobs past cooldown into `purging`.
        let remaining = (cfg.batch_size as usize).saturating_sub(queue.len());
        if remaining > 0 && !self.should_stop(started) {
            let rem_i64 = remaining as i64;
            let cand_rows = conn
                .query(
                    "SELECT blob_sha256 FROM public.blob_gc_state \
                      WHERE gc_state = 'reclaim_eligible' \
                        AND reclaim_eligible_at <= now() - make_interval(mins => $1) \
                      ORDER BY reclaim_eligible_at ASC, blob_sha256 ASC \
                      LIMIT $2",
                    &[(&cfg.cooldown_minutes, Type::INT4), (&rem_i64, Type::INT8)],
                )
                .await?;
            for row in cand_rows {
                if self.should_stop(started) {
                    summary.budget_exhausted = true;
                    break;
                }
                let sha: String = row
                    .try_get(0)
                    .map_err(|e| format!("reclaim_eligible blob_sha256 decode failed: {e}"))?;
                if seen.contains(&sha) {
                    continue;
                }
                let claimed = self
                    .claim_purging(
                        conn,
                        &sha,
                        cfg.grace_minutes,
                        cfg.cooldown_minutes,
                        worm_days,
                    )
                    .await?;
                if claimed == "purging" && seen.insert(sha.clone()) {
                    queue.push(sha);
                }
            }
        }

        // Phase 2 Tx 2B: sequential (concurrency = 1) dedicated connection per purge
        // with circuit breaker and wall-clock tick budget checked ONLY between items
        // (never aborting an in-flight S3 DELETE mid-flight).
        let mut consecutive_errors: usize = 0;
        for sha in queue {
            if self.should_stop(started) {
                summary.budget_exhausted = true;
                break;
            }
            if consecutive_errors >= self.max_consecutive_errors {
                summary.circuit_breaker_tripped = true;
                METRICS
                    .sweep_circuit_breaker_trips_total
                    .fetch_add(1, Ordering::Relaxed);
                eprintln!(
                    "blob-gc: sweep circuit breaker tripped after {consecutive_errors} consecutive S3 errors"
                );
                break;
            }
            match self.purge_one(&sha, worm_days).await {
                Ok(PurgeOutcome::Purged) => {
                    consecutive_errors = 0;
                    summary.purged += 1;
                }
                Ok(PurgeOutcome::AbortedReactivated) => {
                    consecutive_errors = 0;
                    summary.aborted_reactivated += 1;
                }
                Ok(PurgeOutcome::WormLocked403) => {
                    consecutive_errors = 0;
                    summary.worm_locked_403 += 1;
                }
                Err(err) => {
                    consecutive_errors += 1;
                    summary.s3_errors += 1;
                    eprintln!("blob-gc: Tx 2B transient failure sha256={sha}: {err}");
                }
            }
        }

        // Phase 3: lock-safe orphaned_message_blobs cleanup (prefixed keys + legacy bare 64-hex).
        if !self.should_stop(started) && !summary.circuit_breaker_tripped {
            summary.orphaned_raw_reaped = self
                .sweep_orphaned_message_blobs(conn, worm_days, started)
                .await;
        }

        // Phase 4: abandoned tmp/blob-upload/* staging sweep (>24h with no active promote item).
        if !self.should_stop(started) && !summary.circuit_breaker_tripped {
            summary.staging_swept = self.sweep_abandoned_staging(conn, started).await;
        }

        // Phase 5: sweep orphaned content-addressed search_extracted_text cache rows (#557).
        if !self.should_stop(started) && !summary.circuit_breaker_tripped {
            summary.extracted_text_swept = self
                .sweep_orphaned_extracted_text(conn, cfg.grace_minutes, cfg.batch_size)
                .await;
        }

        Ok(summary)
    }

    /// Reclaims orphaned `public.search_extracted_text` cache rows older than
    /// `grace_minutes` whose underlying blob / Drive file version is no longer
    /// live-referenced (`V298` `search_extracted_text_gc_sweep`).
    pub async fn sweep_orphaned_extracted_text(
        &self,
        conn: &WorkerConnection,
        grace_minutes: i32,
        batch_size: i32,
    ) -> u64 {
        let rows = match conn
            .query(
                "SELECT public.search_extracted_text_gc_sweep($1, $2)",
                &[(&grace_minutes, Type::INT4), (&batch_size, Type::INT4)],
            )
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                eprintln!("blob-gc: search_extracted_text_gc_sweep failed: {e}");
                return 0;
            }
        };
        let swept = rows
            .first()
            .and_then(|r| r.try_get::<_, i32>(0).ok())
            .unwrap_or(0)
            .max(0) as u64;
        if swept > 0 {
            METRICS
                .extracted_text_swept_total
                .fetch_add(swept, Ordering::Relaxed);
        }
        swept
    }

    /// Reaps `orphaned_message_blobs` safely under `pg_advisory_xact_lock` (#551):
    /// - Inline RFC 5322 text: dequeued directly.
    /// - Bare 64-hex keys (legacy pre-cutover rows): if present in `public.blobs`,
    ///   dequeued for Mark-and-Sweep ownership; if absent from `public.blobs` and
    ///   zero live references / holds, deleted via `delete_blob_checked` under
    ///   the advisory lock and dequeued.
    /// - Prefixed keys (`inbound/*`, `blobs/*`, `dmarc/*`): acquires per-key
    ///   advisory lock inside a short dedicated transaction, verifies absence
    ///   across all 5 `raw_ref` tables, deletes via `delete_blob_checked`, and dequeues.
    pub async fn sweep_orphaned_message_blobs(
        &self,
        conn: &WorkerConnection,
        worm_days: i32,
        started: Instant,
    ) -> u64 {
        let rows = match conn
            .query("SELECT raw_ref FROM public.orphaned_message_blobs", &[])
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                eprintln!("blob-gc: orphaned_message_blobs scan failed: {e}");
                return 0;
            }
        };
        let refs: Vec<String> = rows
            .iter()
            .filter_map(|r| r.try_get::<_, String>(0).ok())
            .collect();
        let http_timeout = self.s3_delete_timeout.min(DEFAULT_S3_HTTP_TIMEOUT);
        let mut reaped = 0u64;

        for raw_ref in refs {
            if self.should_stop(started) {
                break;
            }
            if crate::blob_cleanup::is_inline_message(&raw_ref) {
                let _ = conn
                    .execute(
                        "DELETE FROM public.orphaned_message_blobs WHERE raw_ref = $1",
                        &[(&raw_ref, Type::TEXT)],
                    )
                    .await;
                continue;
            }
            let Ok(tx_conn) = self.db.connect_session().await else {
                continue;
            };
            if tx_conn
                .batch("BEGIN ISOLATION LEVEL READ COMMITTED")
                .await
                .is_err()
            {
                continue;
            }
            if tx_conn
                .batch("SET LOCAL idle_in_transaction_session_timeout = '8s'; SET LOCAL lock_timeout = '3s'")
                .await
                .is_err()
                || tx_conn
                    .query(
                        "SELECT pg_catalog.pg_advisory_xact_lock(public.blob_gc_lock_key($1))",
                        &[(&raw_ref, Type::TEXT)],
                    )
                    .await
                    .is_err()
            {
                let _ = tx_conn.batch("ROLLBACK").await;
                continue;
            }

            let should_delete_s3 = if is_bare_sha256(&raw_ref) {
                let in_blobs = tx_conn
                    .query(
                        "SELECT EXISTS(SELECT 1 FROM public.blobs WHERE sha256 = $1)",
                        &[(&raw_ref, Type::TEXT)],
                    )
                    .await
                    .ok()
                    .and_then(|r| r.first().and_then(|row| row.try_get::<_, bool>(0).ok()));
                match in_blobs {
                    Some(true) => false, // Mark-and-Sweep owns canonical blobs row; dequeue.
                    Some(false) => {
                        let live_or_held = tx_conn
                            .query(
                                "SELECT public.blob_has_live_reference($1) \
                                     OR public.blob_is_held_or_retained($1, $2)",
                                &[(&raw_ref, Type::TEXT), (&worm_days, Type::INT4)],
                            )
                            .await
                            .ok()
                            .and_then(|r| r.first().and_then(|row| row.try_get::<_, bool>(0).ok()));
                        match live_or_held {
                            Some(false) => true,
                            Some(true) => false,
                            None => {
                                let _ = tx_conn.batch("ROLLBACK").await;
                                continue;
                            }
                        }
                    }
                    None => {
                        let _ = tx_conn.batch("ROLLBACK").await;
                        continue;
                    }
                }
            } else {
                let check_sql =
                    "SELECT NOT EXISTS (SELECT 1 FROM public.messages WHERE raw_ref = $1) \
                    AND NOT EXISTS (SELECT 1 FROM public.outbound_queue WHERE raw_ref = $1) \
                    AND NOT EXISTS (SELECT 1 FROM public.outbound_queue_hot WHERE raw_ref = $1) \
                    AND NOT EXISTS (SELECT 1 FROM public.journal_queue WHERE raw_ref = $1) \
                    AND NOT EXISTS (SELECT 1 FROM public.held_inbound_messages WHERE raw_ref = $1)";
                match tx_conn.query(check_sql, &[(&raw_ref, Type::TEXT)]).await {
                    Ok(r) => match r.first().and_then(|row| row.try_get::<_, bool>(0).ok()) {
                        Some(still_orphaned) => still_orphaned,
                        None => {
                            let _ = tx_conn.batch("ROLLBACK").await;
                            continue;
                        }
                    },
                    Err(_) => {
                        let _ = tx_conn.batch("ROLLBACK").await;
                        continue;
                    }
                }
            };

            if should_delete_s3 {
                match tokio::time::timeout(
                    self.s3_delete_timeout,
                    self.store.delete_blob_checked(&raw_ref, http_timeout),
                )
                .await
                {
                    Ok(Ok(BlobDeleteOutcome::Deleted)) => {
                        reaped += 1;
                        METRICS
                            .orphaned_raw_reaped_total
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(Ok(BlobDeleteOutcome::WormLocked403 { detail, .. })) => {
                        eprintln!(
                            "blob-gc: orphaned raw_ref={raw_ref} blocked by Object Lock 403: {detail}"
                        );
                        let _ = tx_conn.batch("ROLLBACK").await;
                        continue;
                    }
                    Ok(Err(e)) => {
                        eprintln!("blob-gc: orphaned raw_ref={raw_ref} S3 delete failed: {e}");
                        let _ = tx_conn.batch("ROLLBACK").await;
                        continue;
                    }
                    Err(_) => {
                        eprintln!("blob-gc: orphaned raw_ref={raw_ref} S3 delete timed out");
                        let _ = tx_conn.batch("ROLLBACK").await;
                        continue;
                    }
                }
            }

            if tx_conn
                .execute(
                    "DELETE FROM public.orphaned_message_blobs WHERE raw_ref = $1",
                    &[(&raw_ref, Type::TEXT)],
                )
                .await
                .is_ok()
            {
                let _ = tx_conn.batch("COMMIT").await;
            } else {
                let _ = tx_conn.batch("ROLLBACK").await;
            }
        }
        reaped
    }

    /// Sweeps abandoned `tmp/blob-upload/*` objects older than `staging_ttl` (24h)
    /// that have no pending/leased `blob.promote_recover` or `blob.promote_verify` item (#551).
    pub async fn sweep_abandoned_staging(&self, conn: &WorkerConnection, started: Instant) -> u64 {
        let entries = match self
            .store
            .list_prefix_with_modified(BLOB_STAGING_PREFIX)
            .await
        {
            Ok(entries) => entries,
            Err(e) => {
                eprintln!("blob-gc: list {BLOB_STAGING_PREFIX} failed: {e}");
                return 0;
            }
        };
        let cutoff = chrono::Utc::now().timestamp() - (self.staging_ttl.as_secs() as i64);
        let http_timeout = self.s3_delete_timeout.min(DEFAULT_S3_HTTP_TIMEOUT);
        let mut swept = 0u64;

        for (key, modified_unix) in entries {
            if self.should_stop(started) {
                break;
            }
            if !key.starts_with(BLOB_STAGING_PREFIX) || modified_unix <= 0 || modified_unix > cutoff
            {
                continue;
            }
            let has_active_intent = conn
                .query(
                    "SELECT EXISTS ( \
                        SELECT 1 FROM public.work_items \
                         WHERE kind IN ($1, $2) \
                           AND status IN ('pending', 'leased') \
                           AND payload->>'staging_key' = $3 \
                    )",
                    &[
                        (&WORK_KIND_PROMOTE_RECOVER, Type::TEXT),
                        (&WORK_KIND_PROMOTE_VERIFY, Type::TEXT),
                        (&key, Type::TEXT),
                    ],
                )
                .await
                .ok()
                .and_then(|r| r.first().and_then(|row| row.try_get::<_, bool>(0).ok()))
                .unwrap_or(true);
            if has_active_intent {
                continue;
            }
            if let Ok(Ok(BlobDeleteOutcome::Deleted)) = tokio::time::timeout(
                self.s3_delete_timeout,
                self.store.delete_blob_checked(&key, http_timeout),
            )
            .await
            {
                swept += 1;
                METRICS.staging_swept_total.fetch_add(1, Ordering::Relaxed);
            }
        }
        swept
    }

    /// Tx 2A: atomic claim from `reclaim_eligible` -> `purging`.
    pub async fn claim_purging(
        &self,
        conn: &WorkerConnection,
        sha: &str,
        grace_minutes: i32,
        cooldown_minutes: i32,
        worm_days: i32,
    ) -> Result<String, String> {
        let rows = conn
            .query(
                "SELECT public.blob_gc_claim_purging($1, $2, $3, $4)",
                &[
                    (&sha, Type::TEXT),
                    (&grace_minutes, Type::INT4),
                    (&cooldown_minutes, Type::INT4),
                    (&worm_days, Type::INT4),
                ],
            )
            .await?;
        match rows.first() {
            Some(r) => r
                .try_get::<_, String>(0)
                .map_err(|e| format!("blob_gc_claim_purging decode failed: {e}")),
            None => Ok("skipped".into()),
        }
    }

    /// Tx 2B: executes on a **dedicated `WorkerDatabase::connect_session()` session**
    /// with `SET LOCAL idle_in_transaction_session_timeout = '8s'`, per-`sha256`
    /// advisory lock, **split Statement 1 (`FOR UPDATE OF s, b`) + Statement 2
    /// (fresh `READ COMMITTED` snapshot of `blob_has_live_reference` /
    /// `blob_is_held_or_retained`)**, version-aware bounded S3 DELETE, and
    /// `DELETE FROM public.blobs` (#550/#551).
    pub async fn purge_one(&self, sha: &str, worm_days: i32) -> Result<PurgeOutcome, String> {
        let conn = self.db.connect_session().await.map_err(|e| e.to_string())?;
        conn.batch("BEGIN ISOLATION LEVEL READ COMMITTED").await?;

        let prep: Result<PrepOutcome, String> = async {
            conn.batch("SET LOCAL idle_in_transaction_session_timeout = '8s'; SET LOCAL lock_timeout = '3s'")
                .await?;
            // Statement 1a: per-sha256 transaction advisory lock.
            conn.query(
                "SELECT pg_catalog.pg_advisory_xact_lock(public.blob_gc_lock_key($1))",
                &[(&sha, Type::TEXT)],
            )
            .await?;
            // Statement 1b: acquire exclusive FOR UPDATE locks on BOTH blob_gc_state
            // and blobs FIRST so any concurrent FK-holding attachment transaction
            // finishes committing before Statement 2 takes its snapshot (Codex #5 fix).
            let state_rows = conn
                .query(
                    "SELECT s.gc_state \
                       FROM public.blob_gc_state s \
                       JOIN public.blobs b ON b.sha256 = s.blob_sha256 \
                      WHERE s.blob_sha256 = $1 \
                        FOR UPDATE OF s, b",
                    &[(&sha, Type::TEXT)],
                )
                .await?;
            let Some(state_row) = state_rows.first() else {
                return Ok(PrepOutcome::AbortedOpenTx);
            };
            let state: String = state_row
                .try_get(0)
                .map_err(|e| format!("Tx 2B gc_state decode failed: {e}"))?;
            if state != "purging" {
                return Ok(PrepOutcome::AbortedOpenTx);
            }
            // Statement 2: FRESH READ COMMITTED snapshot strictly AFTER acquiring
            // FOR UPDATE OF s, b, guaranteeing visibility of every committed FK root.
            let check_rows = conn
                .query(
                    "SELECT public.blob_has_live_reference($1), \
                            public.blob_is_held_or_retained($1, $2)",
                    &[(&sha, Type::TEXT), (&worm_days, Type::INT4)],
                )
                .await?;
            let Some(check_row) = check_rows.first() else {
                return Ok(PrepOutcome::AbortedOpenTx);
            };
            let has_live: bool = check_row
                .try_get(0)
                .map_err(|e| format!("Tx 2B has_live decode failed: {e}"))?;
            let is_held: bool = check_row
                .try_get(1)
                .map_err(|e| format!("Tx 2B is_held decode failed: {e}"))?;
            if has_live || is_held {
                conn.execute(
                    "UPDATE public.blob_gc_state \
                        SET gc_state = 'active', \
                            reclaim_eligible_at = NULL, \
                            purging_at = NULL \
                      WHERE blob_sha256 = $1",
                    &[(&sha, Type::TEXT)],
                )
                .await?;
                conn.batch("COMMIT").await?;
                return Ok(PrepOutcome::AbortedCommitted);
            }
            Ok(PrepOutcome::Proceed)
        }
        .await;

        match prep {
            Err(err) => {
                let _ = conn.batch("ROLLBACK").await;
                return Err(err);
            }
            Ok(PrepOutcome::AbortedOpenTx) => {
                let _ = conn.batch("ROLLBACK").await;
                METRICS
                    .sweep_aborted_reactivated_total
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(PurgeOutcome::AbortedReactivated);
            }
            Ok(PrepOutcome::AbortedCommitted) => {
                METRICS
                    .sweep_aborted_reactivated_total
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(PurgeOutcome::AbortedReactivated);
            }
            Ok(PrepOutcome::Proceed) => {}
        }

        // Still inside Tx 2B holding the per-sha256 advisory lock and FOR UPDATE row locks.
        // Bound the underlying HTTP socket timeout to <= 4s so client TCP abort fires
        // strictly before the 5s Tokio bound and PG's 8s idle_in_transaction_session_timeout.
        let http_timeout = self.s3_delete_timeout.min(DEFAULT_S3_HTTP_TIMEOUT);
        let remove_res = tokio::time::timeout(
            self.s3_delete_timeout,
            self.store.delete_blob_checked(sha, http_timeout),
        )
        .await;
        match remove_res {
            Ok(Ok(BlobDeleteOutcome::Deleted)) => {
                if let Err(err) = conn
                    .execute(
                        "DELETE FROM public.blobs WHERE sha256 = $1",
                        &[(&sha, Type::TEXT)],
                    )
                    .await
                {
                    let _ = conn.batch("ROLLBACK").await;
                    return Err(format!("DELETE FROM blobs failed after S3 delete: {err}"));
                }
                if let Err(err) = conn.batch("COMMIT").await {
                    let _ = conn.batch("ROLLBACK").await;
                    return Err(format!("Tx 2B COMMIT failed: {err}"));
                }
                METRICS.sweep_purged_total.fetch_add(1, Ordering::Relaxed);
                Ok(PurgeOutcome::Purged)
            }
            Ok(Ok(BlobDeleteOutcome::WormLocked403 {
                detail,
                retain_until,
            })) => {
                let lock_days = worm_days.max(1);
                let reason = format!("s3_object_lock_403: {detail}");
                let record_conn = if conn.batch("ROLLBACK").await.is_ok() {
                    conn
                } else {
                    drop(conn);
                    self.db
                        .connect_session()
                        .await
                        .map_err(|e| format!("403 WORM lock reconnect failed: {e}"))?
                };
                record_conn
                    .batch("BEGIN")
                    .await
                    .map_err(|e| format!("403 WORM lock BEGIN failed: {e}"))?;
                let rec_res: Result<(), String> = async {
                    self.apply_audit_hmac_local(&record_conn).await?;
                    if let Some(until) = retain_until.as_deref() {
                        record_conn
                            .query(
                                "SELECT public.blob_gc_record_worm_lock(\
                                     $1, $2::text::timestamptz, $3)",
                                &[
                                    (&sha, Type::TEXT),
                                    (&until, Type::TEXT),
                                    (&reason, Type::TEXT),
                                ],
                            )
                            .await
                            .map_err(|e| format!("blob_gc_record_worm_lock failed: {e}"))?;
                    } else {
                        record_conn
                            .query(
                                "SELECT public.blob_gc_record_worm_lock(\
                                     $1, now() + make_interval(days => $2), $3)",
                                &[
                                    (&sha, Type::TEXT),
                                    (&lock_days, Type::INT4),
                                    (&reason, Type::TEXT),
                                ],
                            )
                            .await
                            .map_err(|e| format!("blob_gc_record_worm_lock failed: {e}"))?;
                    }
                    Ok(())
                }
                .await;
                if let Err(rec_err) = rec_res {
                    let _ = record_conn.batch("ROLLBACK").await;
                    return Err(rec_err);
                }
                if let Err(commit_err) = record_conn.batch("COMMIT").await {
                    let _ = record_conn.batch("ROLLBACK").await;
                    return Err(format!(
                        "blob_gc_record_worm_lock COMMIT failed: {commit_err}"
                    ));
                }
                METRICS
                    .sweep_worm_lock_403_total
                    .fetch_add(1, Ordering::Relaxed);
                Ok(PurgeOutcome::WormLocked403)
            }
            Ok(Err(err)) => {
                let _ = conn.batch("ROLLBACK").await;
                METRICS
                    .sweep_s3_errors_total
                    .fetch_add(1, Ordering::Relaxed);
                Err(format!("S3 delete error (left purging for retry): {err}"))
            }
            Err(_) => {
                let _ = conn.batch("ROLLBACK").await;
                METRICS
                    .sweep_s3_errors_total
                    .fetch_add(1, Ordering::Relaxed);
                Err(format!(
                    "S3 delete timed out after {:?} (left purging for retry)",
                    self.s3_delete_timeout
                ))
            }
        }
    }
}
