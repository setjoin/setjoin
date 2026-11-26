//! Durable S3 WORM Object Lock arming (`blob.worm_arm`) & S3 reap-retry
//! (`blob.s3_reap_retry`) consumers on `WorkQueue` (Wave 2.2, #549).

use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use setjoin_pg::{ListenEvent, Type};
use setjoin_workqueue::{
    BackoffPolicy, ClaimSpec, WorkItem, WorkQueue, WorkQueueError, WORK_WAKEUP_CHANNEL,
};

use crate::blob_retention::{
    self, WormArmPayload, WORK_KIND_REAP_RETRY, WORK_KIND_WORM_ARM, WORM_MAX_CONCURRENCY,
};
use crate::recovery_worker::{ObjectStore, RetentionError};
use crate::supervisor::TaskCtx;

/// Backoff policy for `blob.worm_arm`: 5s base -> 1h cap with uniform jitter.
pub fn worm_backoff_policy() -> BackoffPolicy {
    BackoffPolicy::new(Duration::from_secs(5), Duration::from_secs(3600))
}

/// Backoff policy for `blob.s3_reap_retry`: 5s base -> 1h cap with uniform jitter.
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
                // WORM disabled live: complete cleanly as skipped.
                let _ = queue
                    .complete(item.id, item.claim_generation, worker_id)
                    .await?;
                return Ok(());
            }
            blob_retention::Config::Invalid => {
                // Fail-closed: NEVER drop retention work while config is invalid.
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
                let _ = queue
                    .complete(item.id, item.claim_generation, worker_id)
                    .await?;
            }
            Err(RetentionError::NotFound) => {
                // Distinguish benign crash-before-promote / GC from a missing live blob.
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
                // Inspect GetObjectRetention: compare against the original
                // payload.retain_until (not advancing `now + days`), so an
                // object already locked at upload time completes cleanly on a
                // later 403 retry instead of looping to DLQ.
                let required_dt = payload_dt.unwrap_or(effective_dt);
                let already_sufficient =
                    match self.store.object_retention(&payload.object_key).await {
                        Ok(Some(existing)) => {
                            existing.mode.eq_ignore_ascii_case(&payload.mode)
                                && DateTime::parse_from_rfc3339(&existing.retain_until)
                                    .map(|dt| dt.with_timezone(&Utc) >= required_dt)
                                    .unwrap_or(false)
                        }
                        _ => false,
                    };
                if already_sufficient {
                    let _ = queue
                        .complete(item.id, item.claim_generation, worker_id)
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

/// Durable consumer for `blob.s3_reap_retry` work items (replaces `BlobCleanup::reap_retries`).
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

    /// Drain one batch of due `blob.s3_reap_retry` items.
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
            if blob_row_exists(queue, sha).await? {
                // Re-uploaded: object is live again; ref_count owns it now.
                let _ = queue
                    .complete(item.id, item.claim_generation, worker_id)
                    .await?;
                continue;
            }
            match self.store.remove(sha).await {
                Ok(()) => {
                    let _ = queue
                        .complete(item.id, item.claim_generation, worker_id)
                        .await?;
                }
                Err(err) => {
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

async fn blob_row_exists(queue: &WorkQueue, sha256: &str) -> Result<bool, WorkQueueError> {
    let mut tx = queue.pool().begin_repeatable_read_only().await?;
    let rows = match tx
        .query(
            "SELECT EXISTS(SELECT 1 FROM public.blobs WHERE sha256 = $1)",
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
