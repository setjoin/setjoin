//! Distributed `SKIP LOCKED` periodic schedule runner (Wave 2.2, #549).
//!
//! Replaces session-level advisory locks (`CronScheduler`) with `public.worker_schedules`
//! leases, `clock_timestamp()` UTC due calculation, fenced heartbeats (`lease_secs / 3`),
//! bounded `WorkerPool::begin_read_write_bounded(timeout)` execution with in-tx schedule
//! lock verification + atomic `worker_schedule_complete`, and `<1s` graceful shutdown
//! lease release.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, Datelike, Duration as ChronoDuration, Timelike, Utc};
use setjoin_pg::Type;
use setjoin_workqueue::{
    ScheduleCredential, ScheduleOutcome, ScheduleRow, ScheduleSpec, ScheduleStore,
};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::cron_catalog::Credential;
use crate::supervisor::TaskCtx;

/// Default lease duration (seconds) for claimed schedule rows.
pub const DEFAULT_LEASE_SECS: i32 = 30;
/// Default max schedules claimed per tick per node.
pub const DEFAULT_CLAIM_LIMIT: i32 = 4;
/// Default scheduler poll interval.
pub const DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Async callback for custom Rust periodic tasks supervised via `worker_schedules`.
pub type ScheduleCallback = Arc<
    dyn Fn(
            TaskCtx,
            ScheduleRow,
            CancellationToken,
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send>>
        + Send
        + Sync,
>;

/// Execution handler for a registered periodic task.
#[derive(Clone)]
pub enum ScheduleHandler {
    /// Fixed SQL statement from `cron_catalog::CATALOG` executed inside
    /// `WorkerPool::begin_read_write_bounded(timeout)` with in-tx fencing and
    /// atomic `worker_schedule_complete` (for worker-credential tasks).
    Sql {
        sql: &'static str,
        credential: ScheduleCredential,
    },
    /// Custom Rust callback. `safe_to_release` controls whether an aborted
    /// in-flight run should release its schedule lease immediately on SIGTERM.
    Callback {
        handler: ScheduleCallback,
        safe_to_release: bool,
    },
}

/// Complete task registration entry for [`ScheduleRunner`].
#[derive(Clone)]
pub struct ScheduledTask {
    pub spec: ScheduleSpec,
    pub handler: ScheduleHandler,
}

/// Configuration for [`ScheduleRunner`].
#[derive(Clone, Debug)]
pub struct ScheduleRunnerConfig {
    pub lease_secs: i32,
    pub claim_limit: i32,
    pub poll_interval: Duration,
    pub schedule_tz: String,
    pub max_concurrent: usize,
}

impl Default for ScheduleRunnerConfig {
    fn default() -> Self {
        Self {
            lease_secs: DEFAULT_LEASE_SECS,
            claim_limit: DEFAULT_CLAIM_LIMIT,
            poll_interval: DEFAULT_POLL_INTERVAL,
            schedule_tz: "UTC".to_owned(),
            max_concurrent: 8,
        }
    }
}

/// Build the full 30-task cron catalog for [`ScheduleRunner`] (excluding
/// `dispatch-scheduled-actions`, which runs via the Wave 2.1 `WorkQueue` promoter).
pub fn catalog_tasks(schedule_tz: &str) -> Vec<ScheduledTask> {
    crate::cron_catalog::supervised_tasks()
        .into_iter()
        .filter_map(|(name, sql, cred)| {
            let (spec_str, timeout_secs) = crate::workers::go_task_spec(name)?;
            let credential = match cred {
                Credential::Worker => ScheduleCredential::Worker,
                Credential::Owner => ScheduleCredential::Owner,
            };
            Some(ScheduledTask {
                spec: ScheduleSpec {
                    task_name: name.to_owned(),
                    schedule_spec: spec_str,
                    timeout_secs: timeout_secs.clamp(1, 600) as i32,
                    schedule_tz: schedule_tz.to_owned(),
                    credential,
                },
                handler: ScheduleHandler::Sql { sql, credential },
            })
        })
        .collect()
}

/// Wave 2+ native supervised maintenance tasks outside the frozen Go 31-task
/// `cron_catalog::CATALOG` (`#552` `scope_revocations` + `#553` `chat_changes`
/// retention; `prune-changes-journal` remains owned by `cron_catalog::CATALOG`).
pub fn wave2_maintenance_tasks(schedule_tz: &str) -> Vec<ScheduledTask> {
    vec![
        ScheduledTask {
            spec: ScheduleSpec {
                task_name: "prune-scope-revocations".to_owned(),
                schedule_spec: "35 4 * * *".to_owned(),
                timeout_secs: 60,
                schedule_tz: schedule_tz.to_owned(),
                credential: ScheduleCredential::Worker,
            },
            handler: ScheduleHandler::Sql {
                sql: "SELECT public.prune_scope_revocations(90)",
                credential: ScheduleCredential::Worker,
            },
        },
        ScheduledTask {
            spec: ScheduleSpec {
                task_name: "prune-chat-changes".to_owned(),
                schedule_spec: "40 4 * * *".to_owned(),
                timeout_secs: 60,
                schedule_tz: schedule_tz.to_owned(),
                credential: ScheduleCredential::Worker,
            },
            handler: ScheduleHandler::Sql {
                sql: "SELECT public.prune_chat_changes(30, COALESCE((SELECT (value #>> '{}')::int FROM public.system_config WHERE key = 'offline_journal_high_water'), 50000))",
                credential: ScheduleCredential::Worker,
            },
        },
    ]
}

/// Parse a schedule spec (`@every <N>s|m|h` or 5-field UTC cron `m h dom mon dow`)
/// and compute the next strictly-future UTC instant after `now_utc`.
pub fn next_due_utc(spec: &str, now_utc: DateTime<Utc>) -> Result<DateTime<Utc>, String> {
    let trimmed = spec.trim();
    if let Some(rest) = trimmed.strip_prefix("@every ") {
        let rest = rest.trim();
        let secs = if let Some(s) = rest.strip_suffix('s') {
            s.trim()
                .parse::<i64>()
                .map_err(|_| format!("invalid @every seconds in {spec:?}"))?
        } else if let Some(m) = rest.strip_suffix('m') {
            m.trim()
                .parse::<i64>()
                .map_err(|_| format!("invalid @every minutes in {spec:?}"))?
                .checked_mul(60)
                .ok_or_else(|| format!("@every overflow in {spec:?}"))?
        } else if let Some(h) = rest.strip_suffix('h') {
            h.trim()
                .parse::<i64>()
                .map_err(|_| format!("invalid @every hours in {spec:?}"))?
                .checked_mul(3600)
                .ok_or_else(|| format!("@every overflow in {spec:?}"))?
        } else {
            return Err(format!("unsupported @every unit in {spec:?}"));
        };
        if secs <= 0 {
            return Err(format!("@every duration must be positive in {spec:?}"));
        }
        return Ok(now_utc + ChronoDuration::seconds(secs));
    }

    let parts: Vec<&str> = trimmed.split_whitespace().collect();
    if parts.len() != 5 {
        return Err(format!("invalid 5-field cron spec {spec:?}"));
    }
    let parse_field = |raw: &str, min: u32, max: u32| -> Result<Option<u32>, String> {
        if raw == "*" {
            return Ok(None);
        }
        let val = raw
            .parse::<u32>()
            .map_err(|_| format!("invalid cron field {raw:?} in {spec:?}"))?;
        if val < min || val > max {
            return Err(format!("cron field {raw:?} out of range {min}..={max}"));
        }
        Ok(Some(val))
    };
    let fields = [
        parse_field(parts[0], 0, 59)?,
        parse_field(parts[1], 0, 23)?,
        parse_field(parts[2], 1, 31)?,
        parse_field(parts[3], 1, 12)?,
        parse_field(parts[4], 0, 6)?,
    ];

    // Advance to the next whole minute strictly after `now_utc`.
    let base = now_utc
        .with_second(0)
        .and_then(|t| t.with_nanosecond(0))
        .unwrap_or(now_utc);
    let mut candidate = base + ChronoDuration::minutes(1);
    // Bounded search (up to 366 days of minutes = 527,040 steps).
    for _ in 0..(366 * 24 * 60) {
        let values = [
            candidate.minute(),
            candidate.hour(),
            candidate.day(),
            candidate.month(),
            candidate.weekday().num_days_from_sunday(),
        ];
        if fields
            .iter()
            .zip(values)
            .all(|(f, v)| f.is_none_or(|n| n == v))
        {
            return Ok(candidate);
        }
        candidate += ChronoDuration::minutes(1);
    }
    Err(format!(
        "cron spec {spec:?} has no matching slot within 366 days"
    ))
}

/// Distributed `SKIP LOCKED` periodic task runner.
pub struct ScheduleRunner {
    tasks: HashMap<String, ScheduledTask>,
    config: ScheduleRunnerConfig,
}

impl ScheduleRunner {
    pub fn new(tasks: Vec<ScheduledTask>, config: ScheduleRunnerConfig) -> Self {
        let map = tasks
            .into_iter()
            .map(|t| (t.spec.task_name.clone(), t))
            .collect();
        Self { tasks: map, config }
    }

    /// Register all configured tasks in `public.worker_schedules` (fail-closed
    /// on cross-node `schedule_tz` drift).
    pub async fn register_all(&self, store: &ScheduleStore) -> Result<(), String> {
        let mut names: Vec<&String> = self.tasks.keys().collect();
        names.sort();
        for name in names {
            if let Some(task) = self.tasks.get(name) {
                store
                    .register(&task.spec)
                    .await
                    .map_err(|e| format!("register schedule {name}: {e}"))?;
            }
        }
        Ok(())
    }

    /// Claimable task names for this node (skips `Owner`-credential tasks when
    /// `owner_pool` is absent on worker-only nodes).
    pub fn claimable_names(&self, has_owner_pool: bool) -> Vec<String> {
        let mut names: Vec<String> = self
            .tasks
            .values()
            .filter(|t| has_owner_pool || t.spec.credential != ScheduleCredential::Owner)
            .map(|t| t.spec.task_name.clone())
            .collect();
        names.sort();
        names
    }

    /// Execute one claim-and-run cycle (returns count of claimed tasks).
    pub async fn tick_once(&self, ctx: &TaskCtx) -> Result<usize, String> {
        if ctx.cancel.is_cancelled() {
            return Ok(0);
        }
        let names = self.claimable_names(ctx.owner_pool.is_some());
        if names.is_empty() {
            return Ok(0);
        }
        let claimed = ctx
            .schedule_store
            .claim(
                &names,
                &ctx.node_id,
                self.config.lease_secs,
                self.config.claim_limit,
            )
            .await
            .map_err(|e| format!("worker_schedule_claim failed: {e}"))?;
        let count = claimed.len();
        let mut set = JoinSet::new();
        for row in claimed {
            if let Some(task) = self.tasks.get(&row.task_name).cloned() {
                let ctx_clone = ctx.clone();
                let lease_secs = self.config.lease_secs;
                set.spawn(async move {
                    run_claimed_task(ctx_clone, task, row, lease_secs).await;
                });
            }
        }
        while set.join_next().await.is_some() {}
        Ok(count)
    }

    /// Run continuously until `ctx.cancel` fires, draining in-flight tasks cleanly
    /// within the supervisor shutdown window.
    pub async fn run(self, ctx: TaskCtx) -> Result<(), String> {
        self.register_all(&ctx.schedule_store).await?;
        let names = self.claimable_names(ctx.owner_pool.is_some());
        if names.is_empty() {
            ctx.cancel.cancelled().await;
            return Ok(());
        }

        let mut in_flight: JoinSet<()> = JoinSet::new();
        let mut ticker = tokio::time::interval(self.config.poll_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            while let Some(res) = in_flight.try_join_next() {
                let _ = res;
            }
            tokio::select! {
                biased;
                _ = ctx.cancel.cancelled() => break,
                Some(_) = in_flight.join_next(), if !in_flight.is_empty() => continue,
                _ = ticker.tick() => {
                    if ctx.cancel.is_cancelled() {
                        break;
                    }
                    let available = self.config.max_concurrent.saturating_sub(in_flight.len());
                    if available == 0 {
                        continue;
                    }
                    let limit = self.config.claim_limit.min(available as i32).max(1);
                    match ctx
                        .schedule_store
                        .claim(&names, &ctx.node_id, self.config.lease_secs, limit)
                        .await
                    {
                        Ok(rows) => {
                            for row in rows {
                                if let Some(task) = self.tasks.get(&row.task_name).cloned() {
                                    let ctx_clone = ctx.clone();
                                    let lease_secs = self.config.lease_secs;
                                    in_flight.spawn(async move {
                                        run_claimed_task(ctx_clone, task, row, lease_secs).await;
                                    });
                                }
                            }
                        }
                        Err(err) => {
                            eprintln!("worker_schedules claim error: {err}");
                        }
                    }
                }
            }
        }

        // Cooperative drain of already-claimed tasks; if supervisor triggers
        // abort_inflight at T0+25s, abort remaining tasks so supervisor's safe
        // lease release can hand them off immediately.
        tokio::select! {
            biased;
            _ = async {
                while in_flight.join_next().await.is_some() {}
            } => {}
            _ = ctx.abort_inflight.cancelled() => {
                in_flight.abort_all();
                while in_flight.join_next().await.is_some() {}
            }
        }
        Ok(())
    }
}

struct HeartbeatGuard {
    stop: CancellationToken,
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl HeartbeatGuard {
    fn spawn(
        store: ScheduleStore,
        name: String,
        token: i64,
        owner: String,
        lease_secs: i32,
        local_cancel: CancellationToken,
        abort_inflight: CancellationToken,
    ) -> Self {
        let hb_interval = Duration::from_millis(((lease_secs.max(1) as u64) * 1000 / 3).max(100));
        let stop = CancellationToken::new();
        let hb_stop = stop.clone();
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(hb_interval);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                tokio::select! {
                    biased;
                    _ = hb_stop.cancelled() => return,
                    _ = abort_inflight.cancelled() => return,
                    _ = interval.tick() => {
                        match store.heartbeat(&name, token, &owner, lease_secs).await {
                            Ok(true) => {}
                            Ok(false) => {
                                local_cancel.cancel();
                                return;
                            }
                            Err(err) => {
                                eprintln!("worker_schedules heartbeat error task={name}: {err}");
                            }
                        }
                    }
                }
            }
        });
        Self {
            stop,
            handle: Some(handle),
        }
    }

    async fn stop(mut self) {
        self.stop.cancel();
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for HeartbeatGuard {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

enum AtomicSqlOutcome {
    Completed,
    LeaseLost,
    AdvisoryBusy,
}

async fn run_claimed_task(ctx: TaskCtx, task: ScheduledTask, row: ScheduleRow, lease_secs: i32) {
    let started = Instant::now();
    let timeout = Duration::from_secs(row.timeout_secs.clamp(1, 600) as u64);
    let local_cancel = CancellationToken::new();

    // Track safe-to-release schedule lease for SQL tasks and safe callbacks.
    let safe_release = match &task.handler {
        ScheduleHandler::Sql { .. } => true,
        ScheduleHandler::Callback {
            safe_to_release, ..
        } => *safe_to_release,
    };
    let lease_guard = safe_release.then(|| {
        ctx.safe_leases
            .track_schedule(row.task_name.clone(), row.fencing_token)
    });

    // Spawn heartbeat loop every lease_secs / 3 (minimum 100ms for short test leases),
    // wrapped in a Drop guard so aborting this task never leaks an orphan heartbeat.
    let hb_guard = HeartbeatGuard::spawn(
        ctx.schedule_store.clone(),
        row.task_name.clone(),
        row.fencing_token,
        ctx.node_id.clone(),
        lease_secs,
        local_cancel.clone(),
        ctx.abort_inflight.clone(),
    );

    let finish_via_complete = match &task.handler {
        ScheduleHandler::Sql {
            sql,
            credential: ScheduleCredential::Worker,
        } => {
            // Execute worker-credential SQL statement inside bounded WorkerTx
            // with non-blocking lease check, Release N advisory lock, and
            // atomic fenced completion at tx end (never holding FOR UPDATE
            // across long SQL so heartbeats renew freely!).
            let exec_res = tokio::select! {
                biased;
                _ = local_cancel.cancelled() => Err((ScheduleOutcome::Cancelled, "lease lost during execution".to_owned())),
                _ = ctx.abort_inflight.cancelled() => {
                    hb_guard.stop().await;
                    // Keep lease_guard armed for supervisor shutdown release.
                    return;
                }
                res = tokio::time::timeout(timeout, run_worker_sql_atomic(&ctx, &row, sql, started)) => {
                    match res {
                        Ok(Ok(outcome)) => Ok(outcome),
                        Ok(Err(msg)) => Err((ScheduleOutcome::Error, msg)),
                        Err(_) => Err((ScheduleOutcome::Timeout, format!("timed out after {}s", row.timeout_secs))),
                    }
                }
            };
            match exec_res {
                Ok(AtomicSqlOutcome::Completed) | Ok(AtomicSqlOutcome::LeaseLost) => {
                    hb_guard.stop().await;
                    if let Some(guard) = lease_guard {
                        guard.disarm();
                    }
                    return;
                }
                Ok(AtomicSqlOutcome::AdvisoryBusy) => {
                    hb_guard.stop().await;
                    let _ = ctx
                        .schedule_store
                        .release(&row.task_name, row.fencing_token, &ctx.node_id)
                        .await;
                    if let Some(guard) = lease_guard {
                        guard.disarm();
                    }
                    return;
                }
                Err(pair) => pair,
            }
        }
        ScheduleHandler::Sql {
            sql,
            credential: ScheduleCredential::Owner,
        } => {
            let Some(owner_pool) = &ctx.owner_pool else {
                hb_guard.stop().await;
                let _ = ctx
                    .schedule_store
                    .release(&row.task_name, row.fencing_token, &ctx.node_id)
                    .await;
                if let Some(guard) = lease_guard {
                    guard.disarm();
                }
                return;
            };
            let exec_res = tokio::select! {
                biased;
                _ = local_cancel.cancelled() => Err((ScheduleOutcome::Cancelled, "lease lost during execution".to_owned())),
                _ = ctx.abort_inflight.cancelled() => {
                    hb_guard.stop().await;
                    return;
                }
                res = tokio::time::timeout(timeout, async {
                    let mut tx = owner_pool
                        .begin_read_write_bounded(timeout)
                        .await
                        .map_err(|e| e.message)?;
                    let adv = match tx
                        .query(
                            "SELECT pg_catalog.pg_try_advisory_xact_lock(\
                                 pg_catalog.hashtextextended('cron-task:' || $1, 0)\
                             )",
                            &[(&row.task_name, Type::TEXT)],
                        )
                        .await
                    {
                        Ok(rows) => rows
                            .first()
                            .and_then(|r| r.try_get::<_, bool>(0).ok())
                            .unwrap_or(false),
                        Err(err) => {
                            let _ = tx.rollback().await;
                            return Err(err.message);
                        }
                    };
                    if !adv {
                        let _ = tx.rollback().await;
                        return Ok(AtomicSqlOutcome::AdvisoryBusy);
                    }
                    // Verify schedule lease is still fenced to this node BEFORE executing DDL.
                    match ctx
                        .schedule_store
                        .heartbeat(&row.task_name, row.fencing_token, &ctx.node_id, lease_secs)
                        .await
                    {
                        Ok(true) => {}
                        _ => {
                            let _ = tx.rollback().await;
                            return Ok(AtomicSqlOutcome::LeaseLost);
                        }
                    }
                    if let Err(err) = tx.execute(sql, &[]).await {
                        let _ = tx.rollback().await;
                        return Err(err.message);
                    }
                    // Re-verify schedule lease is still fenced to this node BEFORE committing DDL.
                    match ctx
                        .schedule_store
                        .heartbeat(&row.task_name, row.fencing_token, &ctx.node_id, lease_secs)
                        .await
                    {
                        Ok(true) => {}
                        _ => {
                            let _ = tx.rollback().await;
                            return Ok(AtomicSqlOutcome::LeaseLost);
                        }
                    }
                    tx.commit().await.map_err(|e| e.message)?;
                    Ok(AtomicSqlOutcome::Completed)
                }) => {
                    match res {
                        Ok(Ok(outcome)) => Ok(outcome),
                        Ok(Err(msg)) => Err((ScheduleOutcome::Error, msg)),
                        Err(_) => Err((ScheduleOutcome::Timeout, format!("timed out after {}s", row.timeout_secs))),
                    }
                }
            };
            match exec_res {
                Ok(AtomicSqlOutcome::Completed) => (ScheduleOutcome::Ok, String::new()),
                Ok(AtomicSqlOutcome::LeaseLost) => {
                    hb_guard.stop().await;
                    if let Some(guard) = lease_guard {
                        guard.disarm();
                    }
                    return;
                }
                Ok(AtomicSqlOutcome::AdvisoryBusy) => {
                    hb_guard.stop().await;
                    let _ = ctx
                        .schedule_store
                        .release(&row.task_name, row.fencing_token, &ctx.node_id)
                        .await;
                    if let Some(guard) = lease_guard {
                        guard.disarm();
                    }
                    return;
                }
                Err(pair) => pair,
            }
        }
        ScheduleHandler::Callback { handler, .. } => {
            let fut = handler(ctx.clone(), row.clone(), local_cancel.clone());
            let exec_res = tokio::select! {
                biased;
                _ = local_cancel.cancelled() => Err((ScheduleOutcome::Cancelled, "lease lost during execution".to_owned())),
                _ = ctx.abort_inflight.cancelled() => {
                    hb_guard.stop().await;
                    return;
                }
                res = tokio::time::timeout(timeout, fut) => {
                    match res {
                        Ok(Ok(())) => Ok(()),
                        Ok(Err(msg)) => Err((ScheduleOutcome::Error, msg)),
                        Err(_) => Err((ScheduleOutcome::Timeout, format!("timed out after {}s", row.timeout_secs))),
                    }
                }
            };
            match exec_res {
                Ok(()) => (ScheduleOutcome::Ok, String::new()),
                Err(pair) => pair,
            }
        }
    };

    hb_guard.stop().await;

    let (outcome, err_msg) = finish_via_complete;
    let duration_ms = started.elapsed().as_millis().min(i32::MAX as u128) as i32;
    let next_due = compute_next_due_rfc3339(&ctx.schedule_store, &row.schedule_spec).await;
    let err_opt = (!err_msg.is_empty()).then_some(err_msg.as_str());
    let _ = ctx
        .schedule_store
        .complete(
            &row.task_name,
            row.fencing_token,
            &ctx.node_id,
            outcome,
            duration_ms,
            err_opt,
            &next_due,
        )
        .await;
    if let Some(guard) = lease_guard {
        guard.disarm();
    }
}

async fn run_worker_sql_atomic(
    ctx: &TaskCtx,
    row: &ScheduleRow,
    sql: &str,
    started: Instant,
) -> Result<AtomicSqlOutcome, String> {
    let timeout = Duration::from_secs(row.timeout_secs.clamp(1, 600) as u64);
    let mut tx = ctx
        .pool
        .begin_read_write_bounded(timeout)
        .await
        .map_err(|e| e.message)?;

    // Non-locking fail-fast lease check: does NOT take FOR UPDATE on
    // `worker_schedules` so concurrent heartbeats update `lease_expires_at`
    // freely during long-running SQL; fenced atomicity is enforced by
    // `ScheduleStore::complete_tx` at transaction end.
    let verified = match tx
        .query(
            "SELECT to_char(clock_timestamp() AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') \
             FROM public.worker_schedules \
             WHERE task_name = $1 AND fencing_token = $2 AND lease_owner = $3",
            &[
                (&row.task_name, Type::TEXT),
                (&row.fencing_token, Type::INT8),
                (&ctx.node_id, Type::TEXT),
            ],
        )
        .await
    {
        Ok(rows) => rows,
        Err(err) => {
            let _ = tx.rollback().await;
            return Err(err.message);
        }
    };
    let Some(vrow) = verified.first() else {
        let _ = tx.rollback().await;
        return Ok(AtomicSqlOutcome::LeaseLost);
    };
    let db_now_str: String = vrow.try_get(0).unwrap_or_default();

    // Release N mixed-version compatibility: hold the legacy per-task advisory
    // xact lock for the duration of SQL execution so an older replica cannot
    // overlap with this worker run.
    let adv_ok = match tx
        .query(
            "SELECT pg_catalog.pg_try_advisory_xact_lock(\
                 pg_catalog.hashtextextended('cron-task:' || $1, 0)\
             )",
            &[(&row.task_name, Type::TEXT)],
        )
        .await
    {
        Ok(rows) => rows
            .first()
            .and_then(|r| r.try_get::<_, bool>(0).ok())
            .unwrap_or(false),
        Err(err) => {
            let _ = tx.rollback().await;
            return Err(err.message);
        }
    };
    if !adv_ok {
        let _ = tx.rollback().await;
        return Ok(AtomicSqlOutcome::AdvisoryBusy);
    }

    if let Err(err) = tx.execute(sql, &[]).await {
        let _ = tx.rollback().await;
        return Err(err.message);
    }

    let now_utc = DateTime::parse_from_rfc3339(&db_now_str)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now());
    let next_due = next_due_utc(&row.schedule_spec, now_utc)
        .unwrap_or_else(|_| now_utc + ChronoDuration::seconds(60))
        .to_rfc3339();
    let duration_ms = started.elapsed().as_millis().min(i32::MAX as u128) as i32;

    let completed = match ScheduleStore::complete_tx(
        &mut tx,
        &row.task_name,
        row.fencing_token,
        &ctx.node_id,
        ScheduleOutcome::Ok,
        duration_ms,
        None,
        &next_due,
    )
    .await
    {
        Ok(ok) => ok,
        Err(err) => {
            let _ = tx.rollback().await;
            return Err(err.message);
        }
    };

    if completed {
        tx.commit().await.map_err(|e| e.message)?;
        Ok(AtomicSqlOutcome::Completed)
    } else {
        let _ = tx.rollback().await;
        Ok(AtomicSqlOutcome::LeaseLost)
    }
}

async fn compute_next_due_rfc3339(store: &ScheduleStore, spec: &str) -> String {
    let now_utc = store
        .db_now_utc()
        .await
        .ok()
        .and_then(|s| DateTime::parse_from_rfc3339(&s).ok())
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(Utc::now);
    next_due_utc(spec, now_utc)
        .unwrap_or_else(|_| now_utc + ChronoDuration::seconds(60))
        .to_rfc3339()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn parses_every_and_cron_specs_from_catalog() {
        let now = Utc.with_ymd_and_hms(2026, 10, 25, 2, 0, 0).unwrap();
        assert_eq!(
            next_due_utc("@every 2s", now).unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 25, 2, 0, 2).unwrap()
        );
        assert_eq!(
            next_due_utc("@every 5m", now).unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 25, 2, 5, 0).unwrap()
        );
        assert_eq!(
            next_due_utc("5 2 * * *", now).unwrap(),
            Utc.with_ymd_and_hms(2026, 10, 25, 2, 5, 0).unwrap()
        );
        assert_eq!(
            next_due_utc("0 0 25 * *", now).unwrap(),
            Utc.with_ymd_and_hms(2026, 11, 25, 0, 0, 0).unwrap()
        );
        let tasks = catalog_tasks("UTC");
        assert_eq!(
            tasks.len(),
            31,
            "all 31 non-dispatch catalog tasks registered"
        );
        for task in &tasks {
            assert!(
                next_due_utc(&task.spec.schedule_spec, now).is_ok(),
                "failed to parse schedule for {}: {}",
                task.spec.task_name,
                task.spec.schedule_spec
            );
        }
        // Only create-monthly-partitions requires Credential::Owner.
        let owner_tasks: Vec<&str> = tasks
            .iter()
            .filter(|t| t.spec.credential == ScheduleCredential::Owner)
            .map(|t| t.spec.task_name.as_str())
            .collect();
        assert_eq!(owner_tasks, vec!["create-monthly-partitions"]);

        let wave2 = wave2_maintenance_tasks("UTC");
        let wave2_names: Vec<&str> = wave2.iter().map(|t| t.spec.task_name.as_str()).collect();
        assert_eq!(
            wave2_names,
            vec!["prune-scope-revocations", "prune-chat-changes"]
        );
        let catalog_names: std::collections::HashSet<&str> =
            tasks.iter().map(|t| t.spec.task_name.as_str()).collect();
        for task in &wave2 {
            assert!(
                !catalog_names.contains(task.spec.task_name.as_str()),
                "wave2_maintenance_tasks must be disjoint from catalog_tasks: {}",
                task.spec.task_name
            );
            assert_eq!(task.spec.credential, ScheduleCredential::Worker);
            assert!(
                next_due_utc(&task.spec.schedule_spec, now).is_ok(),
                "failed to parse schedule for {}: {}",
                task.spec.task_name,
                task.spec.schedule_spec
            );
        }
    }
}
