//! Wave 2.3 (#550): Shadow-Reconciled Mark-and-Sweep S3 Blob GC Worker.
//!
//! Operates in three modes controlled by `BLOB_GC_MODE=off|shadow|live` (env override)
//! or worker-only `public.blob_gc_config.mode` (default `off`):
//! - `off`: completely inert (no DB writes, no S3 calls).
//! - `shadow`: runs Phase 1 Mark + `blob_gc_shadow_reconcile` ONLY (zero S3 deletes,
//!   zero `DELETE FROM blobs`), recording discrepancies between Mark-and-Sweep
//!   and legacy `ref_count = 0` plus Prometheus counters and admin alert.
//! - `live`: runs Phase 1 Mark and Phase 2 Two-Transaction Sweep (Tx 2A `blob_gc_claim_purging`,
//!   then Tx 2B on a dedicated `WorkerDatabase::connect()` session with
//!   `SET LOCAL idle_in_transaction_session_timeout = '8s'`, per-`sha256`
//!   advisory lock, 5s bounded S3 DELETE, concurrency = 1, circuit breaker,
//!   and graceful S3 403 Object Lock reversion).
//!
//! Fail-closed invariants:
//! - Refuses to run unless the worker role has `rolbypassrls OR rolsuper`.
//! - Refuses to run mark or sweep if `WORM_MODE` / `WORM_RETENTION_DAYS` is invalid
//!   (`blob_retention::Config::Invalid`) — never silently defaults `p_worm_days = 0`.
//! - Invalid `BLOB_GC_MODE` env values fail closed without sweeping.

use crate::recovery_worker::{ObjectStore, S3Store};
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
    time::Duration,
};

/// Default timeout for a single S3 DELETE future inside Tx 2B (PLAN-550 §2.4).
pub const DEFAULT_S3_DELETE_TIMEOUT: Duration = Duration::from_secs(5);
/// Bounded HTTP/TCP request timeout for `S3Store::remove_with_timeout` so client
/// TCP abort fires strictly before PG's 5s wait / 8s `idle_in_transaction_session_timeout`.
pub const DEFAULT_S3_HTTP_TIMEOUT: Duration = Duration::from_secs(4);
/// Default consecutive transient S3 error threshold that trips the sweep circuit breaker.
pub const DEFAULT_MAX_CONSECUTIVE_ERRORS: usize = 5;

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

/// Heuristic classifier for S3 Object Lock / WORM retention 403 rejections.
pub fn is_s3_object_lock_403(err: &str) -> bool {
    let lower = err.to_ascii_lowercase();
    lower.contains("http 403")
        || lower.contains("403 forbidden")
        || lower.contains("accessdenied")
        || lower.contains("access denied")
        || lower.contains("object lock")
        || lower.contains("objectlock")
        || lower.contains("retainuntil")
        || lower.contains("worm")
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
}

impl BlobGcMetrics {
    pub fn render_prometheus(&self) -> String {
        let rows: &[(&str, &str, u64)] = &[
            (
                "setjoin_blob_gc_shadow_runs_total",
                "Total shadow reconciliation runs executed by Mark-and-Sweep blob GC.",
                self.shadow_runs_total.load(Ordering::Relaxed),
            ),
            (
                "setjoin_blob_gc_shadow_only_in_mark_and_sweep_total",
                "Blobs eligible in Mark-and-Sweep but not ref_count=0 (ref_count drift).",
                self.shadow_only_in_mark_and_sweep_total
                    .load(Ordering::Relaxed),
            ),
            (
                "setjoin_blob_gc_shadow_only_in_refcount_zero_total",
                "Blobs at ref_count=0 past grace that Mark-and-Sweep protected as live/held.",
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
};

#[derive(Clone, Debug)]
struct EffectiveConfig {
    mode: GcMode,
    grace_minutes: i32,
    cooldown_minutes: i32,
    batch_size: i32,
}

/// Reads effective GC mode (`BLOB_GC_MODE` env override > `public.blob_gc_config.mode` > `off`).
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
    pub circuit_breaker_tripped: bool,
}

#[derive(Deserialize)]
struct MarkResult {
    marked_eligible: u64,
    reactivated: u64,
}

#[derive(Deserialize)]
struct ShadowResult {
    run_id: i64,
    marked_eligible: u64,
    reactivated: u64,
    only_in_mark_and_sweep: u64,
    only_in_refcount_zero: u64,
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

    /// Executes one Mark-and-Sweep GC tick using a caller-sampled `GcMode` so a
    /// coordinator (e.g. `BlobCleanup::tick`) never mixes legacy and live modes
    /// across a mid-tick mode flip.
    pub async fn tick_with_mode(&self, mode: GcMode) -> Result<TickSummary, String> {
        self.tick_inner(Some(mode)).await
    }

    async fn tick_inner(&self, forced_mode: Option<GcMode>) -> Result<TickSummary, String> {
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
                // Fail closed before any Mark or Shadow run if WORM_MODE is misconfigured.
                let worm_days = self.resolve_worm_days()?;
                self.run_shadow(&conn, &cfg, worm_days).await
            }
            GcMode::Live => {
                // Fail closed before any Mark or Sweep if WORM_MODE is misconfigured.
                let worm_days = self.resolve_worm_days()?;
                self.run_live(&conn, &cfg, worm_days).await
            }
        }
    }

    async fn run_shadow(
        &self,
        conn: &WorkerConnection,
        cfg: &EffectiveConfig,
        worm_days: i32,
    ) -> Result<TickSummary, String> {
        conn.batch("BEGIN").await?;
        let tx_res: Result<String, String> = async {
            self.apply_audit_hmac_local(conn).await?;
            let rows = conn
                .query(
                    "SELECT public.blob_gc_shadow_reconcile($1, $2, $3)::text",
                    &[
                        (&cfg.grace_minutes, Type::INT4),
                        (&worm_days, Type::INT4),
                        (&cfg.batch_size, Type::INT4),
                    ],
                )
                .await?;
            rows.first()
                .ok_or_else(|| "blob_gc_shadow_reconcile returned no row".to_owned())?
                .try_get(0)
                .map_err(|e| format!("blob_gc_shadow_reconcile decode failed: {e}"))
        }
        .await;
        let raw = match tx_res {
            Ok(v) => {
                if let Err(err) = conn.batch("COMMIT").await {
                    let _ = conn.batch("ROLLBACK").await;
                    return Err(format!("shadow reconcile COMMIT failed: {err}"));
                }
                v
            }
            Err(err) => {
                let _ = conn.batch("ROLLBACK").await;
                return Err(err);
            }
        };
        let res: ShadowResult = serde_json::from_str(&raw)
            .map_err(|e| format!("invalid shadow reconcile JSON: {e}"))?;

        METRICS.shadow_runs_total.fetch_add(1, Ordering::Relaxed);
        METRICS
            .mark_eligible_total
            .fetch_add(res.marked_eligible, Ordering::Relaxed);
        METRICS
            .mark_reactivated_total
            .fetch_add(res.reactivated, Ordering::Relaxed);
        METRICS
            .shadow_only_in_mark_and_sweep_total
            .fetch_add(res.only_in_mark_and_sweep, Ordering::Relaxed);
        METRICS
            .shadow_only_in_refcount_zero_total
            .fetch_add(res.only_in_refcount_zero, Ordering::Relaxed);

        if res.only_in_mark_and_sweep > 0 || res.only_in_refcount_zero > 0 {
            eprintln!(
                "blob-gc shadow ALERT: run_id={} only_in_mark_and_sweep={} only_in_refcount_zero={}",
                res.run_id, res.only_in_mark_and_sweep, res.only_in_refcount_zero
            );
        }

        Ok(TickSummary {
            mode: Some(GcMode::Shadow),
            marked_eligible: res.marked_eligible,
            reactivated: res.reactivated,
            only_in_mark_and_sweep: res.only_in_mark_and_sweep,
            only_in_refcount_zero: res.only_in_refcount_zero,
            ..TickSummary::default()
        })
    }

    async fn run_live(
        &self,
        conn: &WorkerConnection,
        cfg: &EffectiveConfig,
        worm_days: i32,
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
        if remaining > 0 {
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
        // with circuit breaker on consecutive transient S3 errors/timeouts.
        let mut consecutive_errors: usize = 0;
        for sha in queue {
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

        Ok(summary)
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
    /// (keeping shared pools unstarved) with `SET LOCAL idle_in_transaction_session_timeout = '8s'`,
    /// per-`sha256` transaction advisory lock, `FOR UPDATE` re-verification that
    /// `gc_state = 'purging'`, bounded S3 DELETE (`<= 4s` HTTP timeout, `5s` total bound),
    /// and `DELETE FROM public.blobs`.
    pub async fn purge_one(&self, sha: &str, worm_days: i32) -> Result<PurgeOutcome, String> {
        let conn = self.db.connect_session().await.map_err(|e| e.to_string())?;
        conn.batch("BEGIN").await?;

        let prep: Result<PrepOutcome, String> = async {
            conn.batch("SET LOCAL idle_in_transaction_session_timeout = '8s'")
                .await?;
            conn.query(
                "SELECT pg_catalog.pg_advisory_xact_lock(public.blob_gc_lock_key($1))",
                &[(&sha, Type::TEXT)],
            )
            .await?;
            let rows = conn
                .query(
                    "SELECT s.gc_state, \
                            public.blob_has_live_reference($1), \
                            public.blob_is_held_or_retained($1, $2) \
                       FROM public.blob_gc_state s \
                       JOIN public.blobs b ON b.sha256 = s.blob_sha256 \
                      WHERE s.blob_sha256 = $1 \
                        FOR UPDATE OF s, b",
                    &[(&sha, Type::TEXT), (&worm_days, Type::INT4)],
                )
                .await?;
            let Some(row) = rows.first() else {
                return Ok(PrepOutcome::AbortedOpenTx);
            };
            let state: String = row
                .try_get(0)
                .map_err(|e| format!("Tx 2B gc_state decode failed: {e}"))?;
            let has_live: bool = row
                .try_get(1)
                .map_err(|e| format!("Tx 2B has_live decode failed: {e}"))?;
            let is_held: bool = row
                .try_get(2)
                .map_err(|e| format!("Tx 2B is_held decode failed: {e}"))?;
            if state != "purging" {
                return Ok(PrepOutcome::AbortedOpenTx);
            }
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
            self.store.remove_with_timeout(sha, http_timeout),
        )
        .await;
        match remove_res {
            Ok(Ok(())) => {
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
            Ok(Err(err)) if is_s3_object_lock_403(&err) => {
                let lock_days = worm_days.max(1);
                let reason = format!("s3_object_lock_403: {err}");
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
