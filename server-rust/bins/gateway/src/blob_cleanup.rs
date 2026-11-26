//! The `blob-cleanup` worker (#411, upgraded to durable `WorkQueue` retries in
//! Wave 2.2 #549): drain `blob_cleanup_queue` and `orphaned_message_blobs` with
//! object-store deletes, routing post-row-delete S3 removal failures durably
//! onto `WorkQueue` kind `"blob.s3_reap_retry"` (zero process-local retry
//! ledgers; WORM arming retries live exclusively on `"blob.worm_arm"`).
//!
//! Boot-time `BYPASSRLS` privilege verification is owned fail-closed by
//! `WorkerSupervisor::boot` before `READY=1`.
use crate::blob_retention::{reap_idempotency_key, WORK_KIND_REAP_RETRY};
use crate::recovery_worker::{ObjectStore, S3Store};
use setjoin_pg::{
    workers::{WorkerConnection, WorkerDatabase},
    Type,
};
use std::{future::Future, sync::Arc, time::Duration};

pub const NAME: &str = "blob-cleanup";
/// Go's ticker (first tick after one interval).
pub const INTERVAL: Duration = Duration::from_secs(300);

/// Go's `blob.IsInlineMessage`: inline RFC 5322 text, never an object key.
pub fn is_inline_message(raw_ref: &str) -> bool {
    raw_ref.contains(['\r', '\n'])
}

pub struct BlobCleanup<S = S3Store> {
    db: WorkerDatabase,
    store: Arc<S>,
}

impl<S: ObjectStore> BlobCleanup<S> {
    pub fn new(db: WorkerDatabase, store: Arc<S>) -> Self {
        Self { db, store }
    }

    pub async fn run_until(self, stop: impl Future<Output = ()> + Send) {
        let mut ticks = tokio::time::interval_at(tokio::time::Instant::now() + INTERVAL, INTERVAL);
        ticks.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tokio::pin!(stop);
        loop {
            tokio::select! {biased; _ = &mut stop => return, _ = ticks.tick() => {}}
            tokio::select! {biased; _ = &mut stop => return, _ = self.tick() => {}}
        }
    }

    /// One maintenance pass: cleanup queue, orphaned message blobs, and durable
    /// `blob.s3_reap_retry` WorkQueue retries.
    /// When `BLOB_GC_MODE=live` (or `blob_gc_config.mode='live'`), Mark-and-Sweep GC owns
    /// canonical `blobs` and bare 64-hex keys: legacy `process_cleanup_queue` and
    /// `retry_failed_reaps` are disabled, and `process_orphaned_blobs` fences bare 64-hex
    /// keys while continuing to reap prefixed keys (`inbound/*`, `blobs/*`, `dmarc/*`)
    /// with the full cross-table check (#550).
    pub async fn tick(&self) {
        let conn = match self.db.connect().await {
            Ok(c) => c,
            Err(e) => {
                eprintln!("blob cleanup: worker connection failed: {e}");
                return;
            }
        };
        let gc_mode = match crate::blob_gc::effective_mode(&conn).await {
            Ok(m) => m,
            Err(e) => {
                eprintln!("blob cleanup: invalid BLOB_GC_MODE config (failing closed): {e}");
                return;
            }
        };
        match gc_mode {
            crate::blob_gc::GcMode::Off => {
                self.process_cleanup_queue(&conn).await;
                self.process_orphaned_blobs(&conn, false).await;
                self.retry_failed_reaps(&conn).await;
                drop(conn);
            }
            crate::blob_gc::GcMode::Shadow => {
                drop(conn);
                let gc = crate::blob_gc::BlobGcWorker::new(self.db.clone(), self.store.clone());
                if let Err(e) = gc.tick_with_mode(crate::blob_gc::GcMode::Shadow).await {
                    eprintln!("blob-gc shadow tick failed: {e}");
                }
                match self.db.connect().await {
                    Ok(legacy_conn) => {
                        self.process_cleanup_queue(&legacy_conn).await;
                        self.process_orphaned_blobs(&legacy_conn, false).await;
                        self.retry_failed_reaps(&legacy_conn).await;
                    }
                    Err(e) => eprintln!("blob cleanup: legacy reconnect failed after shadow: {e}"),
                }
            }
            crate::blob_gc::GcMode::Live => {
                self.process_orphaned_blobs(&conn, true).await;
                drop(conn);
                let gc = crate::blob_gc::BlobGcWorker::new(self.db.clone(), self.store.clone());
                if let Err(e) = gc.tick_with_mode(crate::blob_gc::GcMode::Live).await {
                    eprintln!("blob-gc live tick failed: {e}");
                }
            }
        }
    }

    async fn enqueue_reap_retry(&self, conn: &WorkerConnection, sha: &str) {
        let payload = serde_json::json!({ "sha256": sha }).to_string();
        let idem = reap_idempotency_key(sha);
        let priority = 0_i16;
        let max_attempts = 20_i32;
        if let Err(err) = conn
            .query(
                "SELECT work_item_id, coalesced \
                 FROM public.work_enqueue($1, $2::text::jsonb, $3, now(), $4, $5)",
                &[
                    (&WORK_KIND_REAP_RETRY, Type::TEXT),
                    (&payload, Type::TEXT),
                    (&idem, Type::TEXT),
                    (&priority, Type::INT2),
                    (&max_attempts, Type::INT4),
                ],
            )
            .await
        {
            eprintln!("blob cleanup: durable reap retry enqueue failed sha256={sha}: {err}");
        }
    }

    /// Due, apparently unreferenced blobs: a snapshot only, so the delete
    /// re-checks `ref_count = 0` atomically before touching any bytes.
    async fn process_cleanup_queue(&self, conn: &WorkerConnection) {
        let rows = match conn
            .query(
                "SELECT q.blob_sha256 FROM blob_cleanup_queue q
		 JOIN blobs b ON b.sha256 = q.blob_sha256
		 WHERE q.scheduled_at + make_interval(mins => q.delay_minutes) < now()
		   AND b.ref_count = 0",
                &[],
            )
            .await
        {
            Ok(rows) => rows,
            Err(_) => return, // Go returns no candidates on a query error, silently
        };
        let candidates: Vec<String> = rows
            .iter()
            .filter_map(|r| r.try_get::<_, String>(0).ok())
            .collect();
        for sha in candidates {
            self.reap_candidate(conn, &sha).await;
        }
    }

    /// `DELETE ... WHERE ref_count = 0` + durable-first `blob.s3_reap_retry`
    /// enqueue commit in the same transaction so a crash between DB delete and
    /// S3 removal can never lose the reap intent. When immediate S3 removal
    /// succeeds, the deferred work item is cancelled; when it fails, the item
    /// is expedited to `run_at = now()`.
    async fn reap_candidate(&self, conn: &WorkerConnection, sha: &str) {
        if let Err(e) = conn.batch("BEGIN").await {
            eprintln!("blob cleanup: begin tx failed sha256={sha}: {e}");
            return;
        }
        let deleted = match conn
            .execute(
                "DELETE FROM blobs WHERE sha256 = $1 AND ref_count = 0",
                &[(&sha, Type::TEXT)],
            )
            .await
        {
            Ok(n) => n,
            Err(e) => {
                let _ = conn.batch("ROLLBACK").await;
                eprintln!("blob cleanup: row delete failed sha256={sha}: {e}");
                return;
            }
        };
        if deleted == 0 {
            let _ = conn.batch("ROLLBACK").await;
            return; // attached since the scan: still referenced
        }
        let payload = serde_json::json!({ "sha256": sha }).to_string();
        // Non-coalescing (NULL idempotency key): each committed blob row delete
        // owns its own guaranteed `work_item_id`, so it can never coalesce onto
        // an older already-leased retry that saw the re-uploaded row and is
        // about to complete.
        let idem: Option<&str> = None;
        let delay_secs = 30.0_f64;
        let priority = 0_i16;
        let max_attempts = 20_i32;
        let work_item_id = match conn
            .query(
                "SELECT work_item_id, coalesced \
                 FROM public.work_enqueue($1, $2::text::jsonb, $3, now() + make_interval(secs => $4), $5, $6)",
                &[
                    (&WORK_KIND_REAP_RETRY, Type::TEXT),
                    (&payload, Type::TEXT),
                    (&idem, Type::TEXT),
                    (&delay_secs, Type::FLOAT8),
                    (&priority, Type::INT2),
                    (&max_attempts, Type::INT4),
                ],
            )
            .await
        {
            Ok(rows) => rows.first().and_then(|r| r.try_get::<_, i64>(0).ok()),
            Err(err) => {
                let _ = conn.batch("ROLLBACK").await;
                eprintln!("blob cleanup: durable reap retry enqueue failed sha256={sha}: {err}");
                return;
            }
        };
        if let Err(e) = conn.batch("COMMIT").await {
            let _ = conn.batch("ROLLBACK").await;
            eprintln!("blob cleanup: commit failed sha256={sha}: {e}");
            return;
        }

        match self.store.remove(sha).await {
            Ok(()) => {
                if let Some(id) = work_item_id {
                    let _ = conn
                        .query(
                            "SELECT public.work_cancel_pending($1)",
                            &[(&id, Type::INT8)],
                        )
                        .await;
                }
            }
            Err(e) => {
                eprintln!("blob cleanup: minio remove failed sha256={sha}: {e}");
                if let Some(id) = work_item_id {
                    let _ = conn
                        .query("SELECT public.work_expedite($1)", &[(&id, Type::INT8)])
                        .await;
                } else {
                    self.enqueue_reap_retry(conn, sha).await;
                }
            }
        }
    }

    /// The sibling queue for message raw bodies. `raw_ref` is an exact object
    /// key (never assumed to be a sha); inline message text is only dequeued.
    /// When `fence_bare_sha256` is true (`BLOB_GC_MODE=live`), bare 64-hex keys
    /// are handed to Mark-and-Sweep GC (never deleted here), while prefixed keys
    /// (`inbound/*`, `blobs/*`, `dmarc/*`) continue to be reaped after checking
    /// all 5 raw_ref tables (`messages`, `outbound_queue`, `outbound_queue_hot`,
    /// `journal_queue`, `held_inbound_messages`).
    async fn process_orphaned_blobs(&self, conn: &WorkerConnection, fence_bare_sha256: bool) {
        let rows = match conn
            .query("SELECT raw_ref FROM orphaned_message_blobs", &[])
            .await
        {
            Ok(rows) => rows,
            Err(_) => return,
        };
        let refs: Vec<String> = rows
            .iter()
            .filter_map(|r| r.try_get::<_, String>(0).ok())
            .collect();
        for raw_ref in refs {
            if fence_bare_sha256 && crate::blob_gc::is_bare_sha256(&raw_ref) {
                // Fenced off for Mark-and-Sweep GC (#550): never perform lock-free
                // deletion of bare 64-hex canonical keys here.
                continue;
            }
            if !is_inline_message(&raw_ref) {
                let check_sql = if fence_bare_sha256 {
                    "SELECT NOT EXISTS (SELECT 1 FROM messages WHERE raw_ref = $1) \
                        AND NOT EXISTS (SELECT 1 FROM outbound_queue WHERE raw_ref = $1) \
                        AND NOT EXISTS (SELECT 1 FROM outbound_queue_hot WHERE raw_ref = $1) \
                        AND NOT EXISTS (SELECT 1 FROM journal_queue WHERE raw_ref = $1) \
                        AND NOT EXISTS (SELECT 1 FROM held_inbound_messages WHERE raw_ref = $1)"
                } else {
                    "SELECT NOT EXISTS (SELECT 1 FROM messages WHERE raw_ref = $1)"
                };
                let still_orphaned = match conn.query(check_sql, &[(&raw_ref, Type::TEXT)]).await {
                    Ok(rows) => rows
                        .first()
                        .and_then(|r| r.try_get::<_, bool>(0).ok())
                        .unwrap_or(false),
                    Err(_) => continue, // stays queued; retried next tick
                };
                if still_orphaned {
                    if let Err(e) = self.store.remove(&raw_ref).await {
                        eprintln!("orphaned blob cleanup: remove failed raw_ref={raw_ref}: {e}");
                        continue;
                    }
                }
                // else: a new message re-created this key, nothing to delete.
            }
            if let Err(e) = conn
                .execute(
                    "DELETE FROM orphaned_message_blobs WHERE raw_ref = $1",
                    &[(&raw_ref, Type::TEXT)],
                )
                .await
            {
                eprintln!("orphaned blob cleanup: dequeue failed raw_ref={raw_ref}: {e}");
            }
        }
    }

    /// Drain one durable `WorkQueue` pass for `blob.s3_reap_retry` items whose
    /// row delete already committed.
    async fn retry_failed_reaps(&self, conn: &WorkerConnection) {
        let worker_id = NAME;
        let kinds = vec![WORK_KIND_REAP_RETRY.to_owned()];
        let batch = 64_i32;
        let lease_secs = 60_i32;
        let cap: Option<i32> = None;
        let rows = match conn
            .query(
                "SELECT id, claim_generation, payload::text \
                 FROM public.work_queue_claim($1, $2, $3, $4, $5)",
                &[
                    (&worker_id, Type::TEXT),
                    (&kinds, Type::TEXT_ARRAY),
                    (&batch, Type::INT4),
                    (&lease_secs, Type::INT4),
                    (&cap, Type::INT4),
                ],
            )
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                eprintln!("blob cleanup retry: claim failed: {e}");
                return;
            }
        };
        for row in rows {
            let Ok(id) = row.try_get::<_, i64>(0) else {
                continue;
            };
            let Ok(gen) = row.try_get::<_, i32>(1) else {
                continue;
            };
            let payload_str = row.try_get::<_, String>(2).unwrap_or_default();
            let sha = serde_json::from_str::<serde_json::Value>(&payload_str)
                .ok()
                .and_then(|v| {
                    v.get("sha256")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                });
            let Some(sha) = sha else {
                let err = "missing sha256 in blob.s3_reap_retry payload";
                let delay: Option<f64> = None;
                let permanent = true;
                let _ = conn
                    .query(
                        "SELECT outcome, dead_letter_id FROM public.work_queue_fail($1, $2, $3, $4, $5, $6)",
                        &[
                            (&id, Type::INT8),
                            (&gen, Type::INT4),
                            (&worker_id, Type::TEXT),
                            (&err, Type::TEXT),
                            (&delay, Type::FLOAT8),
                            (&permanent, Type::BOOL),
                        ],
                    )
                    .await;
                continue;
            };

            let gone = match conn
                .query(
                    "SELECT NOT EXISTS (SELECT 1 FROM blobs WHERE sha256 = $1)",
                    &[(&sha, Type::TEXT)],
                )
                .await
            {
                Ok(rows) => rows
                    .first()
                    .and_then(|r| r.try_get::<_, bool>(0).ok())
                    .unwrap_or(false),
                Err(e) => {
                    eprintln!("blob cleanup retry: existence re-check failed sha256={sha}: {e}");
                    let delay = Some(0.0_f64);
                    let permanent = false;
                    let _ = conn
                        .query(
                            "SELECT outcome, dead_letter_id FROM public.work_queue_fail($1, $2, $3, $4, $5, $6)",
                            &[
                                (&id, Type::INT8),
                                (&gen, Type::INT4),
                                (&worker_id, Type::TEXT),
                                (&e, Type::TEXT),
                                (&delay, Type::FLOAT8),
                                (&permanent, Type::BOOL),
                            ],
                        )
                        .await;
                    continue;
                }
            };

            if !gone {
                // Re-uploaded: the object is live again; ref_count owns it now.
                let _ = conn
                    .query(
                        "SELECT public.work_queue_complete($1, $2, $3)",
                        &[
                            (&id, Type::INT8),
                            (&gen, Type::INT4),
                            (&worker_id, Type::TEXT),
                        ],
                    )
                    .await;
                continue;
            }

            if let Err(e) = self.store.remove(&sha).await {
                eprintln!("blob cleanup retry: minio remove still failing sha256={sha}: {e}");
                let delay = Some(0.0_f64);
                let permanent = false;
                let _ = conn
                    .query(
                        "SELECT outcome, dead_letter_id FROM public.work_queue_fail($1, $2, $3, $4, $5, $6)",
                        &[
                            (&id, Type::INT8),
                            (&gen, Type::INT4),
                            (&worker_id, Type::TEXT),
                            (&e, Type::TEXT),
                            (&delay, Type::FLOAT8),
                            (&permanent, Type::BOOL),
                        ],
                    )
                    .await;
                continue;
            }

            let _ = conn
                .query(
                    "SELECT public.work_queue_complete($1, $2, $3)",
                    &[
                        (&id, Type::INT8),
                        (&gen, Type::INT4),
                        (&worker_id, Type::TEXT),
                    ],
                )
                .await;
        }
    }
}
