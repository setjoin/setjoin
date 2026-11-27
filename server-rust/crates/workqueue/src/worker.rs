//! Privileged worker execution API for `setjoin-workqueue` (`feature = "worker"`).

use std::time::Duration;

use setjoin_pg::{ListenEvent, ListenHub, Row, StatementFailure, Type, WorkerPool, WorkerTx};
use tokio_util::sync::CancellationToken;

use crate::{
    parse_enqueue_receipt, parse_stats_row, truncate_utf8_bytes, BackoffPolicy, EnqueueReceipt,
    FailOutcome, ReclaimCounts, WorkItem, WorkQueueError, WorkQueueStats, WorkRequest,
    MAX_ERROR_BYTES, WORK_WAKEUP_CHANNEL,
};

/// Claim parameters for [`WorkQueue::claim`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClaimSpec {
    pub worker_id: String,
    pub kinds: Vec<String>,
    pub batch: i32,
    pub lease_secs: i32,
    pub max_concurrency: Option<i32>,
}

impl ClaimSpec {
    pub fn new(worker_id: impl Into<String>, kinds: Vec<String>) -> Self {
        Self {
            worker_id: worker_id.into(),
            kinds,
            batch: 10,
            lease_secs: 60,
            max_concurrency: None,
        }
    }

    pub fn with_batch(mut self, batch: i32) -> Self {
        self.batch = batch.max(1);
        self
    }

    pub fn with_lease_secs(mut self, lease_secs: i32) -> Self {
        self.lease_secs = lease_secs.max(1);
        self
    }

    pub fn with_max_concurrency(mut self, cap: i32) -> Self {
        self.max_concurrency = Some(cap.max(0));
        self
    }
}

/// Per-kind concurrency cap for heterogeneous [`WorkQueue::claim_with_caps`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KindCap {
    pub kind: String,
    pub max_concurrency: Option<i32>,
}

/// Outcome of executing a `scheduled_action.*` work item in one transaction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScheduledActionOutcome {
    Completed { note: String },
    Retried { note: String },
    DeadLettered { dead_letter_id: i64, note: String },
    LeaseLost,
}

const WORK_ENQUEUE_SQL: &str = "SELECT work_item_id, coalesced \
     FROM public.work_enqueue($1, $2::text::jsonb, $3, now() + make_interval(secs => $4), $5, $6)";

const CLAIM_SQL: &str = "SELECT id, kind, payload::text, idempotency_key, priority, \
     attempts, max_attempts, claim_generation, locked_by, last_error, \
     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"') \
     FROM public.work_queue_claim($1, $2, $3, $4, $5)";

const HEARTBEAT_SQL: &str = "SELECT public.work_queue_heartbeat($1, $2, $3, $4)";
const COMPLETE_SQL: &str = "SELECT public.work_queue_complete($1, $2, $3)";
const RELEASE_SQL: &str = "SELECT public.work_release($1, $2, $3)";
const CANCEL_PENDING_SQL: &str = "SELECT public.work_cancel_pending($1)";
const EXPEDITE_SQL: &str = "SELECT public.work_expedite($1)";
const FAIL_SQL: &str = "SELECT outcome, dead_letter_id \
     FROM public.work_queue_fail($1, $2, $3, $4, $5, $6)";
const RECLAIM_SQL: &str = "SELECT reclaimed, dead_lettered \
     FROM public.work_queue_reclaim_expired($1)";
const PROMOTE_SCHEDULED_SQL: &str = "SELECT public.promote_due_scheduled_actions($1)";
const EXECUTE_SCHEDULED_SQL: &str = "SELECT outcome, note \
     FROM public.execute_scheduled_action_work($1::text::uuid, $2, $3, $4, $5)";

/// Durable `FOR UPDATE SKIP LOCKED` work queue backed by `WorkerPool` (`BYPASSRLS`).
#[derive(Clone)]
pub struct WorkQueue {
    pool: WorkerPool,
}

impl WorkQueue {
    pub fn new(pool: WorkerPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &WorkerPool {
        &self.pool
    }

    /// Enqueue a work item in its own worker transaction.
    pub async fn enqueue(&self, req: &WorkRequest) -> Result<EnqueueReceipt, WorkQueueError> {
        let mut tx = self.pool.begin_read_write().await?;
        let receipt = Self::enqueue_tx(&mut tx, req).await?;
        tx.commit().await?;
        Ok(receipt)
    }

    /// Enqueue a work item inside an existing [`WorkerTx`].
    pub async fn enqueue_tx(
        tx: &mut WorkerTx,
        req: &WorkRequest,
    ) -> Result<EnqueueReceipt, WorkQueueError> {
        let payload_text = serde_json::to_string(&req.payload)
            .map_err(|_| WorkQueueError::Protocol("invalid work payload JSON"))?;
        let delay = crate::sanitize_delay_secs(req.delay_secs)?;
        let rows = tx
            .query(
                WORK_ENQUEUE_SQL,
                &[
                    (&req.kind, Type::TEXT),
                    (&payload_text, Type::TEXT),
                    (&req.idempotency_key, Type::TEXT),
                    (&delay, Type::FLOAT8),
                    (&req.priority, Type::INT2),
                    (&req.max_attempts, Type::INT4),
                ],
            )
            .await?;
        parse_enqueue_receipt(&rows)
    }

    /// Claim up to `spec.batch` due pending work items via `work_queue_claim`.
    pub async fn claim(&self, spec: &ClaimSpec) -> Result<Vec<WorkItem>, WorkQueueError> {
        if spec.worker_id.trim().is_empty() {
            return Err(WorkQueueError::InvalidArgument(
                "worker_id must not be empty".into(),
            ));
        }
        let mut tx = self.pool.begin_read_write().await?;
        let kinds_param: Option<Vec<String>> = if spec.kinds.is_empty() {
            None
        } else {
            Some(spec.kinds.clone())
        };
        let batch = spec.batch.max(1);
        let lease_secs = spec.lease_secs.max(1);
        let rows = tx
            .query(
                CLAIM_SQL,
                &[
                    (&spec.worker_id, Type::TEXT),
                    (&kinds_param, Type::TEXT_ARRAY),
                    (&batch, Type::INT4),
                    (&lease_secs, Type::INT4),
                    (&spec.max_concurrency, Type::INT4),
                ],
            )
            .await?;
        tx.commit().await?;
        rows.iter()
            .map(parse_work_item_row)
            .collect::<Result<Vec<_>, _>>()
    }

    /// Claim due items with heterogeneous per-kind concurrency caps.
    ///
    /// Acquires 64-bit collision-free advisory locks in strict ascending
    /// lexicographical order (`hashtextextended('workqueue:cap:' || $1, 0)`)
    /// and computes non-negative headroom (`GREATEST(cap - COALESCE(active, 0), 0)`)
    /// before `LATERAL (... LIMIT headroom FOR UPDATE SKIP LOCKED)` so a lowered
    /// cap where `active > cap` never triggers PG `2201W`.
    pub async fn claim_with_caps(
        &self,
        worker_id: &str,
        caps: &[KindCap],
        batch: i32,
        lease_secs: i32,
    ) -> Result<Vec<WorkItem>, WorkQueueError> {
        if worker_id.trim().is_empty() {
            return Err(WorkQueueError::InvalidArgument(
                "worker_id must not be empty".into(),
            ));
        }
        if caps.is_empty() {
            return Ok(Vec::new());
        }
        let mut sorted: Vec<KindCap> = caps.to_vec();
        sorted.sort_by(|a, b| a.kind.cmp(&b.kind));
        sorted.dedup_by(|a, b| a.kind == b.kind);

        let mut tx = self.pool.begin_read_write().await?;

        // Lock capped kinds in strict ascending lexicographical order via 64-bit hashtextextended.
        for cap in &sorted {
            if cap.max_concurrency.is_some() {
                tx.query(
                    "SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('workqueue:cap:' || $1, 0))",
                    &[(&cap.kind, Type::TEXT)],
                )
                .await?;
            }
        }

        let mut remaining = batch.max(1);
        let lease_secs = lease_secs.max(1);
        let mut out = Vec::new();
        for cap in &sorted {
            if remaining <= 0 {
                break;
            }
            let kinds = vec![cap.kind.clone()];
            let rows = tx
                .query(
                    CLAIM_SQL,
                    &[
                        (&worker_id, Type::TEXT),
                        (&Some(kinds), Type::TEXT_ARRAY),
                        (&remaining, Type::INT4),
                        (&lease_secs, Type::INT4),
                        (&cap.max_concurrency, Type::INT4),
                    ],
                )
                .await?;
            for row in &rows {
                out.push(parse_work_item_row(row)?);
                remaining -= 1;
            }
        }

        tx.commit().await?;
        Ok(out)
    }

    /// Extend an active lease iff `(id, claim_generation, locked_by)` match AND
    /// `lease_expires_at > now()`. Returns `Ok(false)` if the lease has lapsed.
    pub async fn heartbeat(
        &self,
        id: i64,
        claim_generation: i32,
        worker_id: &str,
        lease_secs: i32,
    ) -> Result<bool, WorkQueueError> {
        let mut tx = self.pool.begin_read_write().await?;
        let lease_secs = lease_secs.max(1);
        let rows = tx
            .query(
                HEARTBEAT_SQL,
                &[
                    (&id, Type::INT8),
                    (&claim_generation, Type::INT4),
                    (&worker_id, Type::TEXT),
                    (&lease_secs, Type::INT4),
                ],
            )
            .await?;
        tx.commit().await?;
        Ok(rows
            .first()
            .and_then(|r| r.try_get::<_, bool>(0).ok())
            .unwrap_or(false))
    }

    /// Complete a leased item in its own transaction (fenced by `claim_generation`).
    pub async fn complete(
        &self,
        id: i64,
        claim_generation: i32,
        worker_id: &str,
    ) -> Result<bool, WorkQueueError> {
        let mut tx = self.pool.begin_read_write().await?;
        let ok = Self::complete_tx(&mut tx, id, claim_generation, worker_id).await?;
        tx.commit().await?;
        Ok(ok)
    }

    /// Complete a leased item inside the caller's [`WorkerTx`] (atomic with handler effects).
    pub async fn complete_tx(
        tx: &mut WorkerTx,
        id: i64,
        claim_generation: i32,
        worker_id: &str,
    ) -> Result<bool, StatementFailure> {
        let rows = tx
            .query(
                COMPLETE_SQL,
                &[
                    (&id, Type::INT8),
                    (&claim_generation, Type::INT4),
                    (&worker_id, Type::TEXT),
                ],
            )
            .await?;
        Ok(rows
            .first()
            .and_then(|r| r.try_get::<_, bool>(0).ok())
            .unwrap_or(false))
    }

    /// Gracefully release a safe-to-retry leased item on shutdown via
    /// `public.work_release` (resets `status = 'pending'`, decrements
    /// `attempts = GREATEST(attempts - 1, 0)`, and rings the `'work'` bell).
    pub async fn release(
        &self,
        id: i64,
        claim_generation: i32,
        worker_id: &str,
    ) -> Result<bool, WorkQueueError> {
        let mut tx = self.pool.begin_read_write().await?;
        let rows = match tx
            .query(
                RELEASE_SQL,
                &[
                    (&id, Type::INT8),
                    (&claim_generation, Type::INT4),
                    (&worker_id, Type::TEXT),
                ],
            )
            .await
        {
            Ok(rows) => rows,
            Err(err) => {
                let _ = tx.rollback().await;
                return Err(err.into());
            }
        };
        tx.commit().await?;
        Ok(rows
            .first()
            .and_then(|r| r.try_get::<_, bool>(0).ok())
            .unwrap_or(false))
    }

    /// Cancel a deferred `'pending'` work item (e.g. inline WORM retention succeeded).
    pub async fn cancel_pending(&self, id: i64) -> Result<bool, WorkQueueError> {
        let mut tx = self.pool.begin_read_write().await?;
        let rows = match tx.query(CANCEL_PENDING_SQL, &[(&id, Type::INT8)]).await {
            Ok(rows) => rows,
            Err(err) => {
                let _ = tx.rollback().await;
                return Err(err.into());
            }
        };
        tx.commit().await?;
        Ok(rows
            .first()
            .and_then(|r| r.try_get::<_, bool>(0).ok())
            .unwrap_or(false))
    }

    /// Expedite a deferred `'pending'` work item to run immediately and ring `'work'`.
    pub async fn expedite(&self, id: i64) -> Result<bool, WorkQueueError> {
        let mut tx = self.pool.begin_read_write().await?;
        let rows = match tx.query(EXPEDITE_SQL, &[(&id, Type::INT8)]).await {
            Ok(rows) => rows,
            Err(err) => {
                let _ = tx.rollback().await;
                return Err(err.into());
            }
        };
        tx.commit().await?;
        Ok(rows
            .first()
            .and_then(|r| r.try_get::<_, bool>(0).ok())
            .unwrap_or(false))
    }

    /// Settle a transient failure with explicit retry delay (or dead-letter if
    /// `attempts >= max_attempts`). Truncates `error` to `<= 4096` UTF-8 bytes.
    pub async fn fail_transient(
        &self,
        id: i64,
        claim_generation: i32,
        worker_id: &str,
        error: &str,
        retry_after: Duration,
    ) -> Result<FailOutcome, WorkQueueError> {
        let mut tx = self.pool.begin_read_write().await?;
        let outcome =
            Self::fail_transient_tx(&mut tx, id, claim_generation, worker_id, error, retry_after)
                .await?;
        tx.commit().await?;
        Ok(outcome)
    }

    /// Same-transaction transient failure settlement.
    pub async fn fail_transient_tx(
        tx: &mut WorkerTx,
        id: i64,
        claim_generation: i32,
        worker_id: &str,
        error: &str,
        retry_after: Duration,
    ) -> Result<FailOutcome, WorkQueueError> {
        let truncated = truncate_utf8_bytes(error, MAX_ERROR_BYTES);
        let delay = Some(retry_after.as_secs_f64().max(0.0));
        let permanent = false;
        let rows = tx
            .query(
                FAIL_SQL,
                &[
                    (&id, Type::INT8),
                    (&claim_generation, Type::INT4),
                    (&worker_id, Type::TEXT),
                    (&truncated, Type::TEXT),
                    (&delay, Type::FLOAT8),
                    (&permanent, Type::BOOL),
                ],
            )
            .await?;
        parse_fail_outcome(&rows)
    }

    /// Permanently dead-letter a leased item. Truncates `error` to `<= 4096` UTF-8 bytes.
    pub async fn dead_letter(
        &self,
        id: i64,
        claim_generation: i32,
        worker_id: &str,
        error: &str,
    ) -> Result<FailOutcome, WorkQueueError> {
        let mut tx = self.pool.begin_read_write().await?;
        let outcome = Self::dead_letter_tx(&mut tx, id, claim_generation, worker_id, error).await?;
        tx.commit().await?;
        Ok(outcome)
    }

    /// Same-transaction permanent dead-letter settlement.
    pub async fn dead_letter_tx(
        tx: &mut WorkerTx,
        id: i64,
        claim_generation: i32,
        worker_id: &str,
        error: &str,
    ) -> Result<FailOutcome, WorkQueueError> {
        let truncated = truncate_utf8_bytes(error, MAX_ERROR_BYTES);
        let delay: Option<f64> = None;
        let permanent = true;
        let rows = tx
            .query(
                FAIL_SQL,
                &[
                    (&id, Type::INT8),
                    (&claim_generation, Type::INT4),
                    (&worker_id, Type::TEXT),
                    (&truncated, Type::TEXT),
                    (&delay, Type::FLOAT8),
                    (&permanent, Type::BOOL),
                ],
            )
            .await?;
        parse_fail_outcome(&rows)
    }

    /// Reclaim expired leases: poison pills (`attempts >= max_attempts`) go
    /// straight to `work_dead_letters`, remaining items return to `pending`.
    pub async fn reclaim_expired(&self, batch: i32) -> Result<ReclaimCounts, WorkQueueError> {
        let mut tx = self.pool.begin_read_write().await?;
        let batch = batch.max(1);
        let rows = tx.query(RECLAIM_SQL, &[(&batch, Type::INT4)]).await?;
        tx.commit().await?;
        let row = rows
            .first()
            .ok_or(WorkQueueError::Protocol("reclaim returned no rows"))?;
        Ok(ReclaimCounts {
            reclaimed: row.try_get(0).unwrap_or(0),
            dead_lettered: row.try_get(1).unwrap_or(0),
        })
    }

    /// Promote due `'pending'` `scheduled_actions` to `'enqueued'` work items.
    pub async fn promote_due_scheduled_actions(&self, batch: i32) -> Result<i32, WorkQueueError> {
        let mut tx = self.pool.begin_read_write().await?;
        let batch = batch.max(1);
        let rows = tx
            .query(PROMOTE_SCHEDULED_SQL, &[(&batch, Type::INT4)])
            .await?;
        tx.commit().await?;
        Ok(rows
            .first()
            .and_then(|r| r.try_get::<_, i32>(0).ok())
            .unwrap_or(0))
    }

    /// Execute one `scheduled_action.*` work item AND settle its `work_items`
    /// row inside the **same** `WorkerTx` so a crash after handler commit cannot
    /// double-execute.
    pub async fn execute_scheduled_action_and_settle(
        &self,
        item: &WorkItem,
        worker_id: &str,
        backoff: &BackoffPolicy,
    ) -> Result<ScheduledActionOutcome, WorkQueueError> {
        let Some(action_id) = item
            .payload
            .get("scheduled_action_id")
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
        else {
            let outcome = self
                .dead_letter(
                    item.id,
                    item.claim_generation,
                    worker_id,
                    "missing scheduled_action_id in payload",
                )
                .await?;
            return Ok(match outcome {
                FailOutcome::DeadLettered { dead_letter_id } => {
                    ScheduledActionOutcome::DeadLettered {
                        dead_letter_id,
                        note: "missing scheduled_action_id in payload".into(),
                    }
                }
                _ => ScheduledActionOutcome::LeaseLost,
            });
        };

        let mut tx = self.pool.begin_read_write().await?;
        let live = tx
            .query(
                "SELECT 1 FROM public.work_items \
                 WHERE id = $1 \
                   AND status = 'leased' \
                   AND locked_by = $2 \
                   AND claim_generation = $3 \
                   AND lease_expires_at > clock_timestamp() \
                 FOR UPDATE",
                &[
                    (&item.id, Type::INT8),
                    (&worker_id, Type::TEXT),
                    (&item.claim_generation, Type::INT4),
                ],
            )
            .await?;
        if live.is_empty() {
            tx.rollback().await?;
            return Ok(ScheduledActionOutcome::LeaseLost);
        }

        let allow_replay = false;
        let rows = tx
            .query(
                EXECUTE_SCHEDULED_SQL,
                &[
                    (&action_id, Type::TEXT),
                    (&worker_id, Type::TEXT),
                    (&item.attempts, Type::INT4),
                    (&item.max_attempts, Type::INT4),
                    (&allow_replay, Type::BOOL),
                ],
            )
            .await?;
        let row = rows.first().ok_or(WorkQueueError::Protocol(
            "execute_scheduled_action_work returned no rows",
        ))?;
        let outcome: String = row.try_get(0).map_err(|_| {
            WorkQueueError::Protocol("invalid execute_scheduled_action_work outcome column")
        })?;
        let note: String = row.try_get(1).unwrap_or_default();

        let result = match outcome.as_str() {
            "complete" => {
                if Self::complete_tx(&mut tx, item.id, item.claim_generation, worker_id).await? {
                    tx.commit().await?;
                    ScheduledActionOutcome::Completed { note }
                } else {
                    tx.rollback().await?;
                    ScheduledActionOutcome::LeaseLost
                }
            }
            "permanent_fail" => {
                match Self::dead_letter_tx(
                    &mut tx,
                    item.id,
                    item.claim_generation,
                    worker_id,
                    &note,
                )
                .await?
                {
                    FailOutcome::DeadLettered { dead_letter_id } => {
                        tx.commit().await?;
                        ScheduledActionOutcome::DeadLettered {
                            dead_letter_id,
                            note,
                        }
                    }
                    FailOutcome::LeaseLost => {
                        tx.rollback().await?;
                        ScheduledActionOutcome::LeaseLost
                    }
                    FailOutcome::Retried => {
                        tx.commit().await?;
                        ScheduledActionOutcome::Retried { note }
                    }
                }
            }
            _ => {
                let delay = backoff.jittered_delay(item.attempts);
                match Self::fail_transient_tx(
                    &mut tx,
                    item.id,
                    item.claim_generation,
                    worker_id,
                    &note,
                    delay,
                )
                .await?
                {
                    FailOutcome::Retried => {
                        tx.commit().await?;
                        ScheduledActionOutcome::Retried { note }
                    }
                    FailOutcome::DeadLettered { dead_letter_id } => {
                        tx.commit().await?;
                        ScheduledActionOutcome::DeadLettered {
                            dead_letter_id,
                            note,
                        }
                    }
                    FailOutcome::LeaseLost => {
                        tx.rollback().await?;
                        ScheduledActionOutcome::LeaseLost
                    }
                }
            }
        };
        Ok(result)
    }

    /// Scalar stats via `public.work_queue_stats()`.
    pub async fn stats(&self) -> Result<WorkQueueStats, WorkQueueError> {
        let mut tx = self.pool.begin_repeatable_read_only().await?;
        let rows = tx
            .query(
                "SELECT pending, leased, dead_letters, oldest_due_age_secs FROM public.work_queue_stats()",
                &[],
            )
            .await?;
        tx.commit().await?;
        parse_stats_row(&rows)
    }
}

/// Configuration for the durable scheduled-action WorkQueue consumer loop.
#[derive(Clone, Debug)]
pub struct WorkConsumerConfig {
    pub worker_id: String,
    pub batch: i32,
    pub lease_secs: i32,
    pub poll_interval: Duration,
    pub reclaim_interval: Duration,
    pub backoff: BackoffPolicy,
}

impl Default for WorkConsumerConfig {
    fn default() -> Self {
        Self {
            worker_id: format!("workq-{}", std::process::id()),
            batch: 25,
            lease_secs: 60,
            poll_interval: Duration::from_secs(1),
            reclaim_interval: Duration::from_secs(15),
            backoff: BackoffPolicy::default(),
        }
    }
}

const SCHEDULED_ACTION_KINDS: &[&str] = &[
    "scheduled_action.send",
    "scheduled_action.snooze",
    "scheduled_action.remind",
    "scheduled_action.dsn",
    "scheduled_action.rules_retro",
    "scheduled_action.chat_send",
];

/// Background WorkQueue promoter + consumer for `scheduled_action.*` items.
pub struct WorkScheduledActionConsumer {
    queue: WorkQueue,
    config: WorkConsumerConfig,
    listen_hub: Option<ListenHub>,
}

impl WorkScheduledActionConsumer {
    pub fn new(
        queue: WorkQueue,
        config: WorkConsumerConfig,
        listen_hub: Option<ListenHub>,
    ) -> Self {
        Self {
            queue,
            config,
            listen_hub,
        }
    }

    /// Run one promote + claim-and-execute pass (up to `self.config.batch` items).
    pub async fn drain_once(&self) -> Result<usize, WorkQueueError> {
        self.drain_once_until(&CancellationToken::new()).await
    }

    /// Run one promote + 1-by-1 claim-and-execute pass, checking `shutdown`
    /// before claiming each item so unstarted items are never left leased across
    /// shutdown and no multi-item batch can silently expire before execution.
    async fn drain_once_until(
        &self,
        shutdown: &CancellationToken,
    ) -> Result<usize, WorkQueueError> {
        if shutdown.is_cancelled() {
            return Ok(0);
        }
        let max_items = self.config.batch.max(1) as usize;
        let _ = self
            .queue
            .promote_due_scheduled_actions(self.config.batch)
            .await?;
        let kinds: Vec<String> = SCHEDULED_ACTION_KINDS
            .iter()
            .map(|k| (*k).to_owned())
            .collect();
        let spec = ClaimSpec::new(self.config.worker_id.clone(), kinds)
            .with_batch(1)
            .with_lease_secs(self.config.lease_secs);

        let mut executed = 0usize;
        while executed < max_items {
            if shutdown.is_cancelled() {
                break;
            }
            let items = self.queue.claim(&spec).await?;
            let Some(item) = items.into_iter().next() else {
                break;
            };
            let _ = self
                .queue
                .execute_scheduled_action_and_settle(
                    &item,
                    &self.config.worker_id,
                    &self.config.backoff,
                )
                .await;
            executed += 1;
        }
        Ok(executed)
    }

    /// Run until `shutdown` is cancelled, waking immediately on `ListenHub`
    /// `"work"` notifications / reconnect resyncs and falling back to polling.
    pub async fn run_until(self, shutdown: CancellationToken) {
        let mut sub = match &self.listen_hub {
            Some(hub) => hub.subscribe(WORK_WAKEUP_CHANNEL).await.ok(),
            None => None,
        };
        let mut poll = tokio::time::interval(self.config.poll_interval);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut reclaim = tokio::time::interval(self.config.reclaim_interval);
        reclaim.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;
                _ = shutdown.cancelled() => return,
                _ = reclaim.tick() => {
                    let _ = self.queue.reclaim_expired(self.config.batch).await;
                }
                ev = async {
                    match sub.as_mut() {
                        Some(s) => s.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match ev {
                        Some(ListenEvent::Notification(_)) | Some(ListenEvent::ResyncRequired { .. }) => {
                            let _ = self.drain_once_until(&shutdown).await;
                        }
                        None => {
                            sub = None;
                        }
                    }
                }
                _ = poll.tick() => {
                    let _ = self.drain_once_until(&shutdown).await;
                }
            }
        }
    }
}

fn parse_work_item_row(row: &Row) -> Result<WorkItem, WorkQueueError> {
    let payload_str: String = row
        .try_get(2)
        .map_err(|_| WorkQueueError::Protocol("invalid payload column"))?;
    let payload: serde_json::Value = serde_json::from_str(&payload_str)
        .map_err(|_| WorkQueueError::Protocol("invalid payload json"))?;
    Ok(WorkItem {
        id: row
            .try_get(0)
            .map_err(|_| WorkQueueError::Protocol("invalid id column"))?,
        kind: row
            .try_get(1)
            .map_err(|_| WorkQueueError::Protocol("invalid kind column"))?,
        payload,
        idempotency_key: row.try_get(3).unwrap_or(None),
        priority: row.try_get(4).unwrap_or(0),
        attempts: row.try_get(5).unwrap_or(0),
        max_attempts: row.try_get(6).unwrap_or(5),
        claim_generation: row.try_get(7).unwrap_or(0),
        locked_by: row.try_get(8).unwrap_or(None),
        last_error: row.try_get(9).unwrap_or(None),
        created_at: row.try_get(10).unwrap_or_default(),
    })
}

fn parse_fail_outcome(rows: &[Row]) -> Result<FailOutcome, WorkQueueError> {
    let row = rows
        .first()
        .ok_or(WorkQueueError::Protocol("work_queue_fail returned no rows"))?;
    let outcome: String = row
        .try_get(0)
        .map_err(|_| WorkQueueError::Protocol("invalid fail outcome column"))?;
    let dead_letter_id: Option<i64> = row.try_get(1).unwrap_or(None);
    Ok(match outcome.as_str() {
        "retried" => FailOutcome::Retried,
        "dead_lettered" => FailOutcome::DeadLettered {
            dead_letter_id: dead_letter_id.unwrap_or(0),
        },
        _ => FailOutcome::LeaseLost,
    })
}
