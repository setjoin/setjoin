//! Legacy ad-hoc job table drain-then-retire adapters on `WorkQueue` (Wave 2.2, #549).
//!
//! Routes execution triggers for `bulk_role_jobs` (`admin.bulk_role_apply`),
//! `eap_apply_jobs` (`admin.eap_apply`), and `guest_notification_intents`
//! (`guest.digest_notify`) onto the durable `WorkQueue`, while preserving the
//! status/progress tables and draining pre-upgrade `'queued'` / `sent_at IS NULL`
//! rows cleanly via `FOR UPDATE SKIP LOCKED`.

use std::sync::Arc;
use std::time::Duration;

use setjoin_pg::{ListenEvent, Type};
use setjoin_workqueue::{
    BackoffPolicy, ClaimSpec, EnqueueReceipt, WorkQueue, WorkQueueError, WorkRequest,
    WORK_WAKEUP_CHANNEL,
};

use crate::admin_job_workers::{BulkRoleJobs, EapJobs};
use crate::push_drain::PushIntentDrain;
use crate::supervisor::TaskCtx;

pub const WORK_KIND_BULK_ROLE_APPLY: &str = "admin.bulk_role_apply";
pub const WORK_KIND_EAP_APPLY: &str = "admin.eap_apply";
pub const WORK_KIND_GUEST_DIGEST: &str = "guest.digest_notify";

/// Enqueue a durable `admin.bulk_role_apply` trigger for a `bulk_role_jobs` row.
pub async fn enqueue_bulk_role_apply(
    queue: &WorkQueue,
    job_id: i64,
) -> Result<EnqueueReceipt, WorkQueueError> {
    let req = WorkRequest::new(
        WORK_KIND_BULK_ROLE_APPLY,
        serde_json::json!({ "job_id": job_id }),
    )
    .with_idempotency_key(format!("{WORK_KIND_BULK_ROLE_APPLY}:{job_id}"))
    .with_max_attempts(5);
    queue.enqueue(&req).await
}

/// Enqueue a durable `admin.eap_apply` trigger for an `eap_apply_jobs` row.
pub async fn enqueue_eap_apply(
    queue: &WorkQueue,
    job_id: i64,
) -> Result<EnqueueReceipt, WorkQueueError> {
    let req = WorkRequest::new(WORK_KIND_EAP_APPLY, serde_json::json!({ "job_id": job_id }))
        .with_idempotency_key(format!("{WORK_KIND_EAP_APPLY}:{job_id}"))
        .with_max_attempts(5);
    queue.enqueue(&req).await
}

/// Enqueue a coalesced `guest.digest_notify` trigger for `user_id`.
pub async fn enqueue_guest_digest(
    queue: &WorkQueue,
    user_id: i64,
) -> Result<EnqueueReceipt, WorkQueueError> {
    let req = WorkRequest::new(
        WORK_KIND_GUEST_DIGEST,
        serde_json::json!({ "user_id": user_id }),
    )
    .with_idempotency_key(format!("guest.digest:{user_id}"))
    .with_max_attempts(5);
    queue.enqueue(&req).await
}

/// Durable `WorkQueue` consumer + `SKIP LOCKED` legacy pre-upgrade drainer for
/// `bulk_role_jobs`, `eap_apply_jobs`, and `guest_notification_intents`.
pub struct LegacyJobDrainConsumer {
    pub bulk: Option<Arc<BulkRoleJobs>>,
    pub eap: Option<Arc<EapJobs>>,
    pub push_drain: Option<Arc<PushIntentDrain>>,
    pub backoff: BackoffPolicy,
    pub lease_secs: i32,
    pub poll_interval: Duration,
}

impl LegacyJobDrainConsumer {
    pub fn new(
        bulk: Option<Arc<BulkRoleJobs>>,
        eap: Option<Arc<EapJobs>>,
        push_drain: Option<Arc<PushIntentDrain>>,
    ) -> Self {
        Self {
            bulk,
            eap,
            push_drain,
            backoff: BackoffPolicy::new(Duration::from_secs(5), Duration::from_secs(300)),
            lease_secs: 60,
            poll_interval: Duration::from_secs(3),
        }
    }

    /// Execute one WorkQueue claim-and-settle pass + legacy `SKIP LOCKED` sweep.
    pub async fn drain_once(
        &self,
        queue: &WorkQueue,
        worker_id: &str,
    ) -> Result<usize, WorkQueueError> {
        let mut kinds = Vec::new();
        if self.bulk.is_some() {
            kinds.push(WORK_KIND_BULK_ROLE_APPLY.to_owned());
        }
        if self.eap.is_some() {
            kinds.push(WORK_KIND_EAP_APPLY.to_owned());
        }
        if self.push_drain.is_some() {
            kinds.push(WORK_KIND_GUEST_DIGEST.to_owned());
        }

        let mut handled = 0usize;
        if !kinds.is_empty() {
            let spec = ClaimSpec::new(worker_id.to_owned(), kinds)
                .with_batch(16)
                .with_lease_secs(self.lease_secs);
            let items = queue.claim(&spec).await?;
            for item in items {
                handled += 1;
                match item.kind.as_str() {
                    WORK_KIND_BULK_ROLE_APPLY => {
                        let Some(bulk) = &self.bulk else {
                            let _ = queue
                                .release(item.id, item.claim_generation, worker_id)
                                .await;
                            continue;
                        };
                        let Some(job_id) = item
                            .payload
                            .get("job_id")
                            .and_then(serde_json::Value::as_i64)
                        else {
                            let _ = queue
                                .dead_letter(
                                    item.id,
                                    item.claim_generation,
                                    worker_id,
                                    "missing job_id in admin.bulk_role_apply payload",
                                )
                                .await;
                            continue;
                        };
                        match bulk.process_job_by_id(job_id).await {
                            Ok(_) => {
                                let _ = queue
                                    .complete(item.id, item.claim_generation, worker_id)
                                    .await;
                            }
                            Err(err) => {
                                if is_job_terminal(queue, "public.bulk_role_jobs", job_id).await {
                                    // Status table already recorded terminal 'error' / 'done'.
                                    let _ = queue
                                        .complete(item.id, item.claim_generation, worker_id)
                                        .await;
                                } else {
                                    // Transient DB/connect/timeout error: keep queued and retry.
                                    let delay = self.backoff.jittered_delay(item.attempts);
                                    let _ = queue
                                        .fail_transient(
                                            item.id,
                                            item.claim_generation,
                                            worker_id,
                                            &err,
                                            delay,
                                        )
                                        .await;
                                }
                            }
                        }
                    }
                    WORK_KIND_EAP_APPLY => {
                        let Some(eap) = &self.eap else {
                            let _ = queue
                                .release(item.id, item.claim_generation, worker_id)
                                .await;
                            continue;
                        };
                        let Some(job_id) = item
                            .payload
                            .get("job_id")
                            .and_then(serde_json::Value::as_i64)
                        else {
                            let _ = queue
                                .dead_letter(
                                    item.id,
                                    item.claim_generation,
                                    worker_id,
                                    "missing job_id in admin.eap_apply payload",
                                )
                                .await;
                            continue;
                        };
                        match eap.process_job_by_id(job_id).await {
                            Ok(_) => {
                                let _ = queue
                                    .complete(item.id, item.claim_generation, worker_id)
                                    .await;
                            }
                            Err(err) => {
                                if is_job_terminal(queue, "public.eap_apply_jobs", job_id).await {
                                    // Status table already recorded terminal 'error' / 'done'.
                                    let _ = queue
                                        .complete(item.id, item.claim_generation, worker_id)
                                        .await;
                                } else {
                                    // Transient DB/connect/timeout error: retry via WorkQueue.
                                    let delay = self.backoff.jittered_delay(item.attempts);
                                    let _ = queue
                                        .fail_transient(
                                            item.id,
                                            item.claim_generation,
                                            worker_id,
                                            &err,
                                            delay,
                                        )
                                        .await;
                                }
                            }
                        }
                    }
                    WORK_KIND_GUEST_DIGEST => {
                        let Some(push) = &self.push_drain else {
                            let _ = queue
                                .release(item.id, item.claim_generation, worker_id)
                                .await;
                            continue;
                        };
                        let Some(user_id) = item
                            .payload
                            .get("user_id")
                            .and_then(serde_json::Value::as_i64)
                        else {
                            let _ = queue
                                .dead_letter(
                                    item.id,
                                    item.claim_generation,
                                    worker_id,
                                    "missing user_id in guest.digest_notify payload",
                                )
                                .await;
                            continue;
                        };
                        match push.drain_guest_for(user_id).await {
                            Ok(drained_any) => {
                                if let Err(err) = settle_guest_digest_tx(
                                    queue,
                                    item.id,
                                    item.claim_generation,
                                    worker_id,
                                    user_id,
                                    drained_any,
                                )
                                .await
                                {
                                    let delay = self.backoff.jittered_delay(item.attempts);
                                    let _ = queue
                                        .fail_transient(
                                            item.id,
                                            item.claim_generation,
                                            worker_id,
                                            &err,
                                            delay,
                                        )
                                        .await;
                                }
                            }
                            Err(err) => {
                                let delay = self.backoff.jittered_delay(item.attempts);
                                let _ = queue
                                    .fail_transient(
                                        item.id,
                                        item.claim_generation,
                                        worker_id,
                                        &err,
                                        delay,
                                    )
                                    .await;
                            }
                        }
                    }
                    _ => {
                        let _ = queue
                            .release(item.id, item.claim_generation, worker_id)
                            .await;
                    }
                }
            }
        }

        // Legacy drain-then-retire leg: sweep pre-upgrade 'queued' rows via SKIP LOCKED
        // and keep mail/chat push intent draining + guest reaping active when supervised.
        if let Some(bulk) = &self.bulk {
            let _ = bulk.tick().await;
        }
        if let Some(eap) = &self.eap {
            let _ = eap.tick().await;
        }
        if let Some(push) = &self.push_drain {
            push.tick().await;
        }

        Ok(handled)
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
                            let _ = self.drain_once(&ctx.work_queue, &ctx.node_id).await;
                        }
                        None => { sub = None; }
                    }
                }
                _ = poll.tick() => {
                    let _ = self.drain_once(&ctx.work_queue, &ctx.node_id).await;
                }
            }
        }
    }
}

async fn is_job_terminal(queue: &WorkQueue, table: &'static str, job_id: i64) -> bool {
    let Ok(mut tx) = queue.pool().begin_repeatable_read_only().await else {
        return false;
    };
    let sql = format!("SELECT status FROM {table} WHERE id = $1");
    let rows = match tx.query(&sql, &[(&job_id, Type::INT8)]).await {
        Ok(rows) => rows,
        Err(_) => {
            let _ = tx.rollback().await;
            return false;
        }
    };
    let _ = tx.commit().await;
    match rows.first().and_then(|r| r.try_get::<_, String>(0).ok()) {
        // Missing row or terminal status -> complete the WorkQueue trigger.
        None => true,
        Some(status) => matches!(status.as_str(), "done" | "error"),
    }
}

/// Atomically settle a `guest.digest_notify` work item under the same
/// per-guest advisory xact lock used by `guest_notification_intent_enqueue`.
///
/// Any concurrent producer either commits before we acquire the lock (so
/// `has_pending` sees its row and re-enqueues after completion) or waits until
/// we commit (so our leased item is already gone and its `work_enqueue` creates
/// a fresh item). Never swallows DB errors as `false`.
async fn settle_guest_digest_tx(
    queue: &WorkQueue,
    item_id: i64,
    claim_generation: i32,
    worker_id: &str,
    user_id: i64,
    drained_any: bool,
) -> Result<(), String> {
    let mut tx = queue
        .pool()
        .begin_read_write()
        .await
        .map_err(|e| format!("guest digest settle begin tx: {}", e.message))?;

    if let Err(err) = tx
        .query(
            "SELECT pg_catalog.pg_advisory_xact_lock(\
                 pg_catalog.hashtextextended('guest-digest:' || ($1::bigint)::text, 0)\
             )",
            &[(&user_id, Type::INT8)],
        )
        .await
    {
        let _ = tx.rollback().await;
        return Err(format!("guest digest advisory lock: {}", err.message));
    }

    let has_pending = match tx
        .query(
            "SELECT EXISTS (\
                 SELECT 1 FROM public.guest_notification_intents \
                 WHERE user_id = $1 AND sent_at IS NULL\
             )",
            &[(&user_id, Type::INT8)],
        )
        .await
    {
        Ok(rows) => match rows.first() {
            Some(row) => match row.try_get::<_, bool>(0) {
                Ok(v) => v,
                Err(err) => {
                    let _ = tx.rollback().await;
                    return Err(format!("guest digest pending check decode: {err}"));
                }
            },
            None => {
                let _ = tx.rollback().await;
                return Err("guest digest pending check returned no rows".to_owned());
            }
        },
        Err(err) => {
            let _ = tx.rollback().await;
            return Err(format!("guest digest pending check: {}", err.message));
        }
    };

    if drained_any {
        if let Err(err) =
            WorkQueue::complete_tx(&mut tx, item_id, claim_generation, worker_id).await
        {
            let _ = tx.rollback().await;
            return Err(format!("guest digest complete_tx: {}", err.message));
        }
        if has_pending {
            let payload = serde_json::json!({ "user_id": user_id }).to_string();
            let idem = format!("guest.digest:{user_id}");
            let priority = 0_i16;
            let max_attempts = 5_i32;
            if let Err(err) = tx
                .query(
                    "SELECT work_item_id, coalesced \
                     FROM public.work_enqueue($1, $2::text::jsonb, $3, now(), $4, $5)",
                    &[
                        (&WORK_KIND_GUEST_DIGEST, Type::TEXT),
                        (&payload, Type::TEXT),
                        (&idem, Type::TEXT),
                        (&priority, Type::INT2),
                        (&max_attempts, Type::INT4),
                    ],
                )
                .await
            {
                let _ = tx.rollback().await;
                return Err(format!("guest digest re-enqueue: {}", err.message));
            }
        }
    } else if has_pending {
        let msg = "guest digest deferred (active, throttled, or locked)";
        let delay = Some(10.0_f64);
        let permanent = false;
        if let Err(err) = tx
            .query(
                "SELECT outcome, dead_letter_id \
                 FROM public.work_queue_fail($1, $2, $3, $4, $5, $6)",
                &[
                    (&item_id, Type::INT8),
                    (&claim_generation, Type::INT4),
                    (&worker_id, Type::TEXT),
                    (&msg, Type::TEXT),
                    (&delay, Type::FLOAT8),
                    (&permanent, Type::BOOL),
                ],
            )
            .await
        {
            let _ = tx.rollback().await;
            return Err(format!(
                "guest digest defer fail_transient: {}",
                err.message
            ));
        }
    } else if let Err(err) =
        WorkQueue::complete_tx(&mut tx, item_id, claim_generation, worker_id).await
    {
        let _ = tx.rollback().await;
        return Err(format!("guest digest complete empty tx: {}", err.message));
    }

    tx.commit()
        .await
        .map_err(|e| format!("guest digest settle commit: {}", e.message))
}
