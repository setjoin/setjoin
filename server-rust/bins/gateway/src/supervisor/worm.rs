//! Durable S3 WORM Object Lock arming (`blob.worm_arm`), legacy S3 reap-retry
//! drain (`blob.s3_reap_retry`), and durable staging promote recovery / post-purging
//! verification (`blob.promote_recover`, `blob.promote_verify`) consumers on
//! `WorkQueue` (Wave 2.2 #549, Wave 2.4 #551).

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use setjoin_pg::{ListenEvent, Type};
use setjoin_workqueue::{
    BackoffPolicy, ClaimSpec, WorkItem, WorkQueue, WorkQueueError, WORK_WAKEUP_CHANNEL,
};

use crate::blob_gc::{is_bare_sha256, DEFAULT_S3_HTTP_TIMEOUT};
use crate::blob_retention::{
    self, BlobPromotePayload, WormArmPayload, BLOB_STAGING_PREFIX, WORK_KIND_PROMOTE_RECOVER,
    WORK_KIND_PROMOTE_VERIFY, WORK_KIND_REAP_RETRY, WORK_KIND_WORM_ARM, WORM_MAX_CONCURRENCY,
};
use crate::recovery_worker::{BlobDeleteOutcome, ObjectStore, RetentionError};
use crate::supervisor::TaskCtx;

/// Backoff policy for `blob.worm_arm`: 5s base -> 1h cap with uniform jitter.
pub fn worm_backoff_policy() -> BackoffPolicy {
    BackoffPolicy::new(Duration::from_secs(5), Duration::from_secs(3600))
}

/// Backoff policy for `blob.s3_reap_retry` and `blob.promote_*`: 5s base -> 1h cap.
pub fn reap_backoff_policy() -> BackoffPolicy {
    BackoffPolicy::new(Duration::from_secs(5), Duration::from_secs(3600))
}

/// Drop-guarded per-item WorkQueue lease heartbeat (prevents lease expiry
/// during slow S3 retry storms and never leaks a background task on cancel).
struct WorkHeartbeatGuard {
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl WorkHeartbeatGuard {
    fn spawn(
        queue: WorkQueue,
        item_id: i64,
        claim_generation: i32,
        worker_id: String,
        lease_secs: i32,
    ) -> Self {
        let interval_dur = Duration::from_secs(((lease_secs.max(3) as u64) / 3).max(1));
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(interval_dur);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;
            loop {
                interval.tick().await;
                match queue
                    .heartbeat(item_id, claim_generation, &worker_id, lease_secs)
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => return,
                    Err(_) => {}
                }
            }
        });
        Self {
            handle: Some(handle),
        }
    }
}

impl Drop for WorkHeartbeatGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// Atomically records `worm_locked_until` in `blob_gc_state` and completes the
/// `blob.worm_arm` WorkQueue item inside a single `WorkerTx` (#551).
async fn record_worm_and_complete(
    queue: &WorkQueue,
    sha256: &str,
    until_rfc3339: &str,
    item_id: i64,
    claim_generation: i32,
    worker_id: &str,
) -> Result<(), WorkQueueError> {
    let mut tx = queue.pool().begin_read_write().await?;
    if is_bare_sha256(sha256) {
        let reason = "worm_arm_worker";
        if let Err(err) = tx
            .query(
                "SELECT public.blob_gc_record_worm_lock($1, $2::text::timestamptz, $3)",
                &[
                    (&sha256, Type::TEXT),
                    (&until_rfc3339, Type::TEXT),
                    (&reason, Type::TEXT),
                ],
            )
            .await
        {
            let _ = tx.rollback().await;
            return Err(err.into());
        }
    }
    if let Err(err) = tx
        .query(
            "SELECT public.work_queue_complete($1, $2, $3)",
            &[
                (&item_id, Type::INT8),
                (&claim_generation, Type::INT4),
                (&worker_id, Type::TEXT),
            ],
        )
        .await
    {
        let _ = tx.rollback().await;
        return Err(err.into());
    }
    tx.commit().await?;
    Ok(())
}

/// Durable consumer for `blob.worm_arm` work items.
pub struct WormArmConsumer<S: ObjectStore> {
    store: Arc<S>,
    backoff: BackoffPolicy,
    lease_secs: i32,
    batch: i32,
    poll_interval: Duration,
}

impl<S: ObjectStore + 'static> WormArmConsumer<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            backoff: worm_backoff_policy(),
            lease_secs: 90,
            batch: 1,
            poll_interval: Duration::from_secs(2),
        }
    }

    pub fn with_backoff(mut self, backoff: BackoffPolicy) -> Self {
        self.backoff = backoff;
        self
    }

    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Refresh the `setjoin_worm_arm_dead_letters` Prometheus gauge from
    /// `public.work_dead_letters`. Preserves the previous gauge value on DB error.
    pub async fn refresh_dead_letter_metric(queue: &WorkQueue) {
        let Ok(mut tx) = queue.pool().begin_repeatable_read_only().await else {
            return;
        };
        let rows = match tx
            .query(
                "SELECT count(*)::bigint FROM public.work_dead_letters \
                 WHERE kind = $1 AND replayed_at IS NULL",
                &[(&WORK_KIND_WORM_ARM, Type::TEXT)],
            )
            .await
        {
            Ok(rows) => rows,
            Err(_) => {
                let _ = tx.rollback().await;
                return;
            }
        };
        if tx.commit().await.is_ok() {
            if let Some(count) = rows.first().and_then(|r| r.try_get::<_, i64>(0).ok()) {
                crate::metrics::WORM_ARM_DEAD_LETTERS.store(count.max(0) as u64, Ordering::Relaxed);
            }
        }
    }

    /// Claim and settle one batch of `blob.worm_arm` items.
    pub async fn drain_once(
        &self,
        queue: &WorkQueue,
        worker_id: &str,
        override_retry_delay: Option<Duration>,
    ) -> Result<usize, WorkQueueError> {
        let spec = ClaimSpec::new(worker_id.to_owned(), vec![WORK_KIND_WORM_ARM.to_owned()])
            .with_batch(self.batch)
            .with_lease_secs(self.lease_secs)
            .with_max_concurrency(WORM_MAX_CONCURRENCY);
        let items = queue.claim(&spec).await?;
        let count = items.len();
        for item in items {
            self.handle_item(queue, worker_id, &item, override_retry_delay)
                .await?;
        }
        Self::refresh_dead_letter_metric(queue).await;
        Ok(count)
    }

    async fn handle_item(
        &self,
        queue: &WorkQueue,
        worker_id: &str,
        item: &WorkItem,
        override_retry_delay: Option<Duration>,
    ) -> Result<(), WorkQueueError> {
        let retry_delay =
            override_retry_delay.unwrap_or_else(|| self.backoff.jittered_delay(item.attempts));

        let payload: WormArmPayload = match serde_json::from_value(item.payload.clone()) {
            Ok(p) => p,
            Err(err) => {
                let _ = queue
                    .dead_letter(
                        item.id,
                        item.claim_generation,
                        worker_id,
                        &format!("invalid blob.worm_arm payload: {err}"),
                    )
                    .await?;
                return Ok(());
            }
        };

        let live_worm = match blob_retention::config() {
            blob_retention::Config::Off => {
                let _ = queue
                    .complete(item.id, item.claim_generation, worker_id)
                    .await?;
                return Ok(());
            }
            blob_retention::Config::Invalid => {
                let _ = queue
                    .fail_transient(
                        item.id,
                        item.claim_generation,
                        worker_id,
                        "WORM_MODE configuration is invalid; refusing to drop retention item",
                        retry_delay,
                    )
                    .await?;
                return Ok(());
            }
            blob_retention::Config::On(worm) => worm,
        };

        // Keep lease alive while S3 retries run (Drop-guarded so cancellation never leaks).
        let _hb_guard = WorkHeartbeatGuard::spawn(
            queue.clone(),
            item.id,
            item.claim_generation,
            worker_id.to_owned(),
            self.lease_secs,
        );

        // Never shorten an existing lock: effective_until = max(payload.retain_until, now + retain_days).
        let now_plus_days = Utc::now() + chrono::Duration::days(live_worm.days);
        let payload_dt = DateTime::parse_from_rfc3339(&payload.retain_until)
            .ok()
            .map(|dt| dt.with_timezone(&Utc));
        let effective_dt = payload_dt
            .map(|dt| dt.max(now_plus_days))
            .unwrap_or(now_plus_days);
        let effective_until = crate::admin_job_workers::go_rfc3339_nano(effective_dt);

        match self
            .store
            .retain_object(&payload.object_key, &payload.mode, &effective_until)
            .await
        {
            Ok(()) => {
                record_worm_and_complete(
                    queue,
                    &payload.sha256,
                    &effective_until,
                    item.id,
                    item.claim_generation,
                    worker_id,
                )
                .await?;
            }
            Err(RetentionError::NotFound) => {
                let exists = blob_row_exists(queue, &payload.sha256).await?;
                if !exists {
                    let _ = queue
                        .complete(item.id, item.claim_generation, worker_id)
                        .await?;
                } else {
                    let _ = queue
                        .fail_transient(
                            item.id,
                            item.claim_generation,
                            worker_id,
                            &format!(
                                "integrity incident: S3 404 for live blobs row sha256={}",
                                payload.sha256
                            ),
                            retry_delay,
                        )
                        .await?;
                }
            }
            Err(RetentionError::Forbidden(msg)) => {
                // If WORM_RETENTION_DAYS was raised after upload, enforce the extended
                // `effective_dt`; otherwise accept an existing lock that already covers
                // the upload-time horizon (`payload_dt`, avoiding 30s retry-drift loops
                // on already-locked objects per #549's worker_supervisor contract).
                let required_dt = if live_worm.days > payload.retain_days {
                    effective_dt
                } else {
                    payload_dt.unwrap_or(effective_dt)
                };
                let observed_sufficient =
                    match self.store.object_retention(&payload.object_key).await {
                        Ok(Some(existing)) => {
                            let existing_dt = DateTime::parse_from_rfc3339(&existing.retain_until)
                                .ok()
                                .map(|dt| dt.with_timezone(&Utc));
                            if existing.mode.eq_ignore_ascii_case(&payload.mode)
                                && existing_dt.is_some_and(|dt| dt >= required_dt)
                            {
                                let recorded_dt = existing_dt
                                    .map(|dt| dt.max(required_dt))
                                    .unwrap_or(required_dt);
                                Some(crate::admin_job_workers::go_rfc3339_nano(recorded_dt))
                            } else {
                                None
                            }
                        }
                        _ => None,
                    };
                if let Some(observed_until) = observed_sufficient {
                    record_worm_and_complete(
                        queue,
                        &payload.sha256,
                        &observed_until,
                        item.id,
                        item.claim_generation,
                        worker_id,
                    )
                    .await?;
                } else {
                    let _ = queue
                        .fail_transient(
                            item.id,
                            item.claim_generation,
                            worker_id,
                            &format!("S3 PutObjectRetention 403: {msg}"),
                            retry_delay,
                        )
                        .await?;
                }
            }
            Err(RetentionError::Transient(status, msg)) => {
                let _ = queue
                    .fail_transient(
                        item.id,
                        item.claim_generation,
                        worker_id,
                        &format!("S3 PutObjectRetention transient ({status}): {msg}"),
                        retry_delay,
                    )
                    .await?;
            }
            Err(RetentionError::Invalid(msg)) => {
                let _ = queue
                    .dead_letter(
                        item.id,
                        item.claim_generation,
                        worker_id,
                        &format!("S3 PutObjectRetention invalid: {msg}"),
                    )
                    .await?;
            }
        }
        Ok(())
    }

    /// Run supervised until `ctx.cancel` fires.
    pub async fn run(self, ctx: TaskCtx) -> Result<(), String> {
        let mut sub = match &ctx.listen_hub {
            Some(hub) => hub.subscribe(WORK_WAKEUP_CHANNEL).await.ok(),
            None => None,
        };
        let mut poll = tokio::time::interval(self.poll_interval);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;
                _ = ctx.cancel.cancelled() => return Ok(()),
                ev = async {
                    match sub.as_mut() {
                        Some(s) => s.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match ev {
                        Some(ListenEvent::Notification(_)) | Some(ListenEvent::ResyncRequired { .. }) => {
                            let _ = self.drain_once(&ctx.work_queue, &ctx.node_id, None).await;
                        }
                        None => { sub = None; }
                    }
                }
                _ = poll.tick() => {
                    let _ = self.drain_once(&ctx.work_queue, &ctx.node_id, None).await;
                }
            }
        }
    }
}

/// Minimal supervised drain-only consumer for residual pre-cutover `blob.s3_reap_retry`
/// items (#551). No new `blob.s3_reap_retry` items are enqueued post-V289; this consumer
/// drains any pre-cutover items safely under `pg_advisory_xact_lock` + version-aware
/// `delete_blob_checked` so pre-cutover objects never leak.
pub struct BlobReapRetryConsumer<S: ObjectStore> {
    store: Arc<S>,
    backoff: BackoffPolicy,
    lease_secs: i32,
    batch: i32,
    poll_interval: Duration,
}

impl<S: ObjectStore + 'static> BlobReapRetryConsumer<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            backoff: reap_backoff_policy(),
            lease_secs: 60,
            batch: 32,
            poll_interval: Duration::from_secs(5),
        }
    }

    /// Drain one batch of due residual `blob.s3_reap_retry` items.
    pub async fn drain_once(
        &self,
        queue: &WorkQueue,
        worker_id: &str,
        override_retry_delay: Option<Duration>,
    ) -> Result<usize, WorkQueueError> {
        let spec = ClaimSpec::new(worker_id.to_owned(), vec![WORK_KIND_REAP_RETRY.to_owned()])
            .with_batch(self.batch)
            .with_lease_secs(self.lease_secs);
        let items = queue.claim(&spec).await?;
        let count = items.len();
        for item in items {
            let retry_delay =
                override_retry_delay.unwrap_or_else(|| self.backoff.jittered_delay(item.attempts));
            let Some(sha) = item
                .payload
                .get("sha256")
                .and_then(serde_json::Value::as_str)
            else {
                let _ = queue
                    .dead_letter(
                        item.id,
                        item.claim_generation,
                        worker_id,
                        "missing sha256 in blob.s3_reap_retry payload",
                    )
                    .await?;
                continue;
            };
            // Serialize under per-sha256 advisory lock with explicit READ COMMITTED
            // isolation and bounded lock_timeout so a concurrent re-upload cannot race
            // with residual S3 object deletion and a stuck lock never stalls the worker.
            let db_err = |msg: String| {
                WorkQueueError::Statement(setjoin_pg::StatementFailure {
                    sqlstate: None,
                    hint: None,
                    message: msg,
                })
            };
            let db = queue.pool().worker_database().map_err(db_err)?;
            let tx_conn = db
                .connect_session()
                .await
                .map_err(|e| db_err(e.to_string()))?;
            let exists_res: Result<bool, String> = async {
                tx_conn.batch("BEGIN ISOLATION LEVEL READ COMMITTED").await?;
                tx_conn
                    .batch("SET LOCAL idle_in_transaction_session_timeout = '8s'; SET LOCAL lock_timeout = '3s'")
                    .await?;
                tx_conn
                    .query(
                        "SELECT pg_catalog.pg_advisory_xact_lock(public.blob_gc_lock_key($1))",
                        &[(&sha, Type::TEXT)],
                    )
                    .await?;
                let rows = tx_conn
                    .query(
                        "SELECT EXISTS(SELECT 1 FROM public.blobs WHERE sha256 = $1)",
                        &[(&sha, Type::TEXT)],
                    )
                    .await?;
                Ok(rows
                    .first()
                    .and_then(|r| r.try_get::<_, bool>(0).ok())
                    .unwrap_or(true))
            }
            .await;
            let exists = match exists_res {
                Ok(v) => v,
                Err(err) => {
                    let _ = tx_conn.batch("ROLLBACK").await;
                    let _ = queue
                        .fail_transient(
                            item.id,
                            item.claim_generation,
                            worker_id,
                            &err,
                            retry_delay,
                        )
                        .await?;
                    continue;
                }
            };
            if exists {
                // Re-uploaded: Mark-and-Sweep GC owns this live blob row now.
                let _ = tx_conn.batch("ROLLBACK").await;
                let _ = queue
                    .complete(item.id, item.claim_generation, worker_id)
                    .await?;
                continue;
            }
            match tokio::time::timeout(
                Duration::from_secs(5),
                self.store.delete_blob_checked(sha, DEFAULT_S3_HTTP_TIMEOUT),
            )
            .await
            {
                Ok(Ok(BlobDeleteOutcome::Deleted)) => {
                    if let Err(err) = tx_conn
                        .query(
                            "SELECT public.work_queue_complete($1, $2, $3)",
                            &[
                                (&item.id, Type::INT8),
                                (&item.claim_generation, Type::INT4),
                                (&worker_id, Type::TEXT),
                            ],
                        )
                        .await
                    {
                        let _ = tx_conn.batch("ROLLBACK").await;
                        return Err(db_err(err));
                    }
                    tx_conn.batch("COMMIT").await.map_err(db_err)?;
                }
                Ok(Ok(BlobDeleteOutcome::WormLocked403 { detail, .. })) => {
                    let _ = tx_conn.batch("ROLLBACK").await;
                    let _ = queue
                        .fail_transient(
                            item.id,
                            item.claim_generation,
                            worker_id,
                            &format!("residual blob.s3_reap_retry blocked by WORM 403: {detail}"),
                            retry_delay,
                        )
                        .await?;
                }
                Ok(Err(err)) => {
                    let _ = tx_conn.batch("ROLLBACK").await;
                    eprintln!("blob cleanup retry: minio remove still failing sha256={sha}: {err}");
                    let _ = queue
                        .fail_transient(
                            item.id,
                            item.claim_generation,
                            worker_id,
                            &err,
                            retry_delay,
                        )
                        .await?;
                }
                Err(_) => {
                    let _ = tx_conn.batch("ROLLBACK").await;
                    let _ = queue
                        .fail_transient(
                            item.id,
                            item.claim_generation,
                            worker_id,
                            "residual blob.s3_reap_retry S3 delete timed out",
                            retry_delay,
                        )
                        .await?;
                }
            }
        }
        Ok(count)
    }

    pub async fn run(self, ctx: TaskCtx) -> Result<(), String> {
        let mut sub = match &ctx.listen_hub {
            Some(hub) => hub.subscribe(WORK_WAKEUP_CHANNEL).await.ok(),
            None => None,
        };
        let mut poll = tokio::time::interval(self.poll_interval);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;
                _ = ctx.cancel.cancelled() => return Ok(()),
                ev = async {
                    match sub.as_mut() {
                        Some(s) => s.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match ev {
                        Some(ListenEvent::Notification(_)) | Some(ListenEvent::ResyncRequired { .. }) => {
                            let _ = self.drain_once(&ctx.work_queue, &ctx.node_id, None).await;
                        }
                        None => { sub = None; }
                    }
                }
                _ = poll.tick() => {
                    let _ = self.drain_once(&ctx.work_queue, &ctx.node_id, None).await;
                }
            }
        }
    }
}

/// Durable supervised consumer for `blob.promote_recover` (crash between
/// `blob_upload_account` commit and `store.promote`) and `blob.promote_verify`
/// (delayed verification after reactivating a `'purging'` blob on unversioned
/// backends) (#551).
pub struct BlobPromoteConsumer<S: ObjectStore> {
    store: Arc<S>,
    backoff: BackoffPolicy,
    lease_secs: i32,
    batch: i32,
    poll_interval: Duration,
}

impl<S: ObjectStore + 'static> BlobPromoteConsumer<S> {
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            backoff: reap_backoff_policy(),
            lease_secs: 60,
            batch: 16,
            poll_interval: Duration::from_secs(2),
        }
    }

    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Claim and settle one batch of `blob.promote_recover` and `blob.promote_verify` items.
    pub async fn drain_once(
        &self,
        queue: &WorkQueue,
        worker_id: &str,
        override_retry_delay: Option<Duration>,
    ) -> Result<usize, WorkQueueError> {
        let spec = ClaimSpec::new(
            worker_id.to_owned(),
            vec![
                WORK_KIND_PROMOTE_RECOVER.to_owned(),
                WORK_KIND_PROMOTE_VERIFY.to_owned(),
            ],
        )
        .with_batch(self.batch)
        .with_lease_secs(self.lease_secs);
        let items = queue.claim(&spec).await?;
        let count = items.len();
        for item in items {
            self.handle_item(queue, worker_id, &item, override_retry_delay)
                .await?;
        }
        Ok(count)
    }

    async fn handle_item(
        &self,
        queue: &WorkQueue,
        worker_id: &str,
        item: &WorkItem,
        override_retry_delay: Option<Duration>,
    ) -> Result<(), WorkQueueError> {
        let retry_delay =
            override_retry_delay.unwrap_or_else(|| self.backoff.jittered_delay(item.attempts));
        let payload: BlobPromotePayload = match serde_json::from_value(item.payload.clone()) {
            Ok(p) => p,
            Err(err) => {
                let _ = queue
                    .dead_letter(
                        item.id,
                        item.claim_generation,
                        worker_id,
                        &format!("invalid {} payload: {err}", item.kind),
                    )
                    .await?;
                return Ok(());
            }
        };
        if !is_bare_sha256(&payload.sha256) || !payload.staging_key.starts_with(BLOB_STAGING_PREFIX)
        {
            let _ = queue
                .dead_letter(
                    item.id,
                    item.claim_generation,
                    worker_id,
                    "invalid sha256 or staging_key prefix in blob.promote payload",
                )
                .await?;
            return Ok(());
        }

        let _hb_guard = WorkHeartbeatGuard::spawn(
            queue.clone(),
            item.id,
            item.claim_generation,
            worker_id.to_owned(),
            self.lease_secs,
        );

        // Verify the blobs row still exists and is NOT currently 'purging'.
        let active_blob = blob_is_active_not_purging(queue, &payload.sha256).await?;
        if !active_blob {
            let _ = self
                .store
                .delete_blob_checked(&payload.staging_key, DEFAULT_S3_HTTP_TIMEOUT)
                .await;
            let _ = queue
                .complete(item.id, item.claim_generation, worker_id)
                .await?;
            return Ok(());
        }

        // Check canonical key first (for both recover & verify): if canonical object
        // is missing (crash before promote OR delayed unversioned S3 DELETE wiped it),
        // promote from staging_key -> sha256 outside PG tx.
        match self.store.object_exists(&payload.sha256).await {
            Ok(true) => {}
            Ok(false) => {
                if let Err(err) = self
                    .store
                    .promote_object(&payload.staging_key, &payload.sha256)
                    .await
                {
                    let _ = queue
                        .fail_transient(
                            item.id,
                            item.claim_generation,
                            worker_id,
                            &format!(
                                "{} promote {} -> {} failed: {err}",
                                item.kind, payload.staging_key, payload.sha256
                            ),
                            retry_delay,
                        )
                        .await?;
                    return Ok(());
                }
            }
            Err(err) => {
                let _ = queue
                    .fail_transient(
                        item.id,
                        item.claim_generation,
                        worker_id,
                        &format!("{} HEAD {} failed: {err}", item.kind, payload.sha256),
                        retry_delay,
                    )
                    .await?;
                return Ok(());
            }
        }

        // Complete work item, then permanently delete all versions of staging_key.
        // Only delete staging_key when no sibling pending/leased promote item still
        // references the exact same staging_key (e.g. blob.promote_verify waiting 60s).
        let _ = queue
            .complete(item.id, item.claim_generation, worker_id)
            .await?;
        let still_referenced_by_sibling =
            staging_key_still_needed(queue, &payload.staging_key).await?;
        if !still_referenced_by_sibling {
            let _ = self
                .store
                .delete_blob_checked(&payload.staging_key, DEFAULT_S3_HTTP_TIMEOUT)
                .await;
        }
        Ok(())
    }

    pub async fn run(self, ctx: TaskCtx) -> Result<(), String> {
        let mut sub = match &ctx.listen_hub {
            Some(hub) => hub.subscribe(WORK_WAKEUP_CHANNEL).await.ok(),
            None => None,
        };
        let mut poll = tokio::time::interval(self.poll_interval);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                biased;
                _ = ctx.cancel.cancelled() => return Ok(()),
                ev = async {
                    match sub.as_mut() {
                        Some(s) => s.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match ev {
                        Some(ListenEvent::Notification(_)) | Some(ListenEvent::ResyncRequired { .. }) => {
                            let _ = self.drain_once(&ctx.work_queue, &ctx.node_id, None).await;
                        }
                        None => { sub = None; }
                    }
                }
                _ = poll.tick() => {
                    let _ = self.drain_once(&ctx.work_queue, &ctx.node_id, None).await;
                }
            }
        }
    }
}

async fn blob_row_exists(queue: &WorkQueue, sha256: &str) -> Result<bool, WorkQueueError> {
    let mut tx = queue.pool().begin_repeatable_read_only().await?;
    let rows = match tx
        .query(
            "SELECT EXISTS(SELECT 1 FROM public.blobs WHERE sha256 = $1) \
                 OR EXISTS( \
                     SELECT 1 FROM public.work_items \
                      WHERE kind IN ($2, $3) \
                        AND status IN ('pending', 'leased') \
                        AND payload->>'sha256' = $1 \
                 )",
            &[
                (&sha256, Type::TEXT),
                (&WORK_KIND_PROMOTE_RECOVER, Type::TEXT),
                (&WORK_KIND_PROMOTE_VERIFY, Type::TEXT),
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

async fn blob_is_active_not_purging(
    queue: &WorkQueue,
    sha256: &str,
) -> Result<bool, WorkQueueError> {
    let mut tx = queue.pool().begin_repeatable_read_only().await?;
    let rows = match tx
        .query(
            "SELECT EXISTS( \
                SELECT 1 \
                  FROM public.blobs b \
                  LEFT JOIN public.blob_gc_state s ON s.blob_sha256 = b.sha256 \
                 WHERE b.sha256 = $1 \
                   AND COALESCE(s.gc_state, 'active') <> 'purging' \
            )",
            &[(&sha256, Type::TEXT)],
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

async fn staging_key_still_needed(
    queue: &WorkQueue,
    staging_key: &str,
) -> Result<bool, WorkQueueError> {
    let mut tx = queue.pool().begin_repeatable_read_only().await?;
    let rows = match tx
        .query(
            "SELECT EXISTS( \
                SELECT 1 FROM public.work_items \
                 WHERE kind IN ($1, $2) \
                   AND status IN ('pending', 'leased') \
                   AND payload->>'staging_key' = $3 \
            )",
            &[
                (&WORK_KIND_PROMOTE_RECOVER, Type::TEXT),
                (&WORK_KIND_PROMOTE_VERIFY, Type::TEXT),
                (&staging_key, Type::TEXT),
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
        .unwrap_or(true))
}
