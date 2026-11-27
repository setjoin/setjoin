//! Durable `WorkQueue` consumers for Wave 3.2 (`#557`):
//! - [`SearchExtractConsumer`]: consumes `"search.extract"` items concurrently
//!   with per-item lease heartbeats and process-wide [`ExtractionSingleFlight`],
//!   deduplicating content-addressed extraction into `public.search_extracted_text`.
//! - [`SearchIndexConsumer`]: consumes `"search.index_batch"` items, indexing
//!   Mail (headers/body/attachments + S/MIME boundary), Chat (`chat_messages`,
//!   `chat_message_revisions` as `ComplianceOnly`, attachments, pending/enqueued/failed
//!   `scheduled_actions`), and Drive (`drive_nodes` + `drive_file_versions`) into
//!   `TantivySearchEngine`, advancing `public.search_index_watermarks.indexed_outbox_seq`
//!   monotonically, updating `SnapshotFreshnessFence` with exact remaining dirty counts,
//!   and enqueueing continuation items whenever backlog remains.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use setjoin_pg::{ListenEvent, Param, Row, WorkerPool};
use setjoin_search::{
    ensure_search_watermarks_initialized, has_unprocessed_outbox_rows,
    unprocessed_counts_by_corpus, BoxFuture, ContentExtractionService, ContentExtractor,
    DefaultContentExtractor, DocCorpus, ExtractionSingleFlight, ObjectByteReader, SearchEngine,
    SearchError, SearchExtractPayload, SearchIndexBatchPayload, SearchIndexPipeline, SearchIndexer,
    SearchPipelineDb, SnapshotFreshnessFence, WORK_KIND_SEARCH_EXTRACT,
    WORK_KIND_SEARCH_INDEX_BATCH,
};
use setjoin_workqueue::{
    BackoffPolicy, ClaimSpec, WorkItem, WorkQueue, WorkQueueError, WorkRequest, WORK_WAKEUP_CHANNEL,
};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::recovery_worker::ObjectStore;
use crate::supervisor::TaskCtx;

/// Maximum concurrent in-flight `"search.extract"` leases per cluster.
pub const SEARCH_EXTRACT_MAX_CONCURRENCY: i32 = 4;

/// Maximum concurrent in-flight `"search.index_batch"` leases per cluster
/// (single Tantivy writer per index epoch).
pub const SEARCH_INDEX_MAX_CONCURRENCY: i32 = 1;

/// Backoff policy for search extraction/indexing retries: 5s base -> 15m cap.
pub fn search_backoff_policy() -> BackoffPolicy {
    BackoffPolicy::new(Duration::from_secs(5), Duration::from_secs(900))
}

/// Drop-guarded per-item WorkQueue lease heartbeat with explicit lease-loss
/// signaling so workers stop publishing state if their lease is reclaimed.
struct WorkHeartbeatGuard {
    handle: Option<tokio::task::JoinHandle<()>>,
    lease_lost: Arc<AtomicBool>,
    cancel: CancellationToken,
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
        let lease_lost = Arc::new(AtomicBool::new(false));
        let cancel = CancellationToken::new();
        let lost_bg = Arc::clone(&lease_lost);
        let cancel_bg = cancel.clone();
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
                    Ok(false) => {
                        lost_bg.store(true, Ordering::Release);
                        cancel_bg.cancel();
                        return;
                    }
                    Err(_) => {}
                }
            }
        });
        Self {
            handle: Some(handle),
            lease_lost,
            cancel,
        }
    }

    fn lease_lost_flag(&self) -> &Arc<AtomicBool> {
        &self.lease_lost
    }

    fn is_lease_lost(&self) -> bool {
        self.lease_lost.load(Ordering::Acquire)
    }

    fn cancel_token(&self) -> &CancellationToken {
        &self.cancel
    }
}

impl Drop for WorkHeartbeatGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// Adapter bridging boot-verified [`WorkerPool`] to [`SearchPipelineDb`].
#[derive(Clone)]
pub struct WorkerPoolSearchDb {
    pool: WorkerPool,
}

impl WorkerPoolSearchDb {
    #[must_use]
    pub fn new(pool: WorkerPool) -> Self {
        Self { pool }
    }
}

impl SearchPipelineDb for WorkerPoolSearchDb {
    fn query_typed<'a>(
        &'a self,
        sql: &'a str,
        params: &'a [Param<'a>],
    ) -> BoxFuture<'a, Result<Vec<Row>, SearchError>> {
        Box::pin(async move {
            let mut tx = self
                .pool
                .begin_read_write()
                .await
                .map_err(|e| SearchError::Database(format!("worker tx begin failed: {e:?}")))?;
            let rows = match tx.query(sql, params).await {
                Ok(rows) => rows,
                Err(err) => {
                    let _ = tx.rollback().await;
                    return Err(SearchError::Database(format!(
                        "search pipeline query failed: {err:?}"
                    )));
                }
            };
            tx.commit()
                .await
                .map_err(|e| SearchError::Database(format!("worker tx commit failed: {e:?}")))?;
            Ok(rows)
        })
    }
}

/// Adapter bridging gateway [`ObjectStore`] to [`ObjectByteReader`].
pub struct ObjectStoreByteReader<S: ObjectStore> {
    store: Arc<S>,
}

impl<S: ObjectStore> ObjectStoreByteReader<S> {
    #[must_use]
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }
}

impl<S: ObjectStore + 'static> ObjectByteReader for ObjectStoreByteReader<S> {
    fn read_bytes<'a>(
        &'a self,
        key: &'a str,
        max_bytes: usize,
    ) -> BoxFuture<'a, Result<Vec<u8>, SearchError>> {
        Box::pin(async move {
            self.store
                .read(key, max_bytes)
                .await
                .map_err(SearchError::Io)
        })
    }
}

/// Durable `WorkQueue` consumer for `"search.extract"`.
pub struct SearchExtractConsumer<S: ObjectStore> {
    store: Arc<S>,
    extractor: Arc<dyn ContentExtractor>,
    single_flight: Arc<ExtractionSingleFlight>,
    backoff: BackoffPolicy,
    lease_secs: i32,
    batch: i32,
    poll_interval: Duration,
}

impl<S: ObjectStore + 'static> SearchExtractConsumer<S> {
    #[must_use]
    pub fn new(store: Arc<S>) -> Self {
        Self {
            store,
            extractor: Arc::new(DefaultContentExtractor),
            single_flight: Arc::new(ExtractionSingleFlight::default()),
            backoff: search_backoff_policy(),
            lease_secs: 120,
            batch: 4,
            poll_interval: Duration::from_secs(2),
        }
    }

    #[must_use]
    pub fn with_extractor(mut self, extractor: Arc<dyn ContentExtractor>) -> Self {
        self.extractor = extractor;
        self
    }

    #[must_use]
    pub fn with_single_flight(mut self, single_flight: Arc<ExtractionSingleFlight>) -> Self {
        self.single_flight = single_flight;
        self
    }

    #[must_use]
    pub fn with_lease_secs(mut self, lease_secs: i32) -> Self {
        self.lease_secs = lease_secs.max(3);
        self
    }

    #[must_use]
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Claim and settle one batch of `"search.extract"` items concurrently so
    /// every claimed item heartbeats immediately without head-of-line lease expiry.
    pub async fn drain_once(
        &self,
        queue: &WorkQueue,
        worker_id: &str,
        safe_leases: Option<&crate::supervisor::SafeLeaseRegistry>,
    ) -> Result<usize, WorkQueueError> {
        let spec = ClaimSpec::new(
            worker_id.to_owned(),
            vec![WORK_KIND_SEARCH_EXTRACT.to_owned()],
        )
        .with_batch(self.batch)
        .with_lease_secs(self.lease_secs)
        .with_max_concurrency(SEARCH_EXTRACT_MAX_CONCURRENCY);
        let items = queue.claim(&spec).await?;
        let count = items.len();
        if count == 0 {
            return Ok(0);
        }

        let db: Arc<dyn SearchPipelineDb> = Arc::new(WorkerPoolSearchDb::new(queue.pool().clone()));
        let reader: Arc<dyn ObjectByteReader> =
            Arc::new(ObjectStoreByteReader::new(Arc::clone(&self.store)));
        let svc = Arc::new(
            ContentExtractionService::new(db, reader)
                .with_extractor(Arc::clone(&self.extractor))
                .with_single_flight(Arc::clone(&self.single_flight)),
        );

        let mut safe_guards: Vec<Option<crate::supervisor::SafeWorkLeaseGuard>> = items
            .iter()
            .map(|item| safe_leases.map(|r| r.track_work(item.id, item.claim_generation)))
            .collect();

        let mut join_set: JoinSet<(usize, Result<(), WorkQueueError>)> = JoinSet::new();
        for (idx, item) in items.into_iter().enumerate() {
            let hb = WorkHeartbeatGuard::spawn(
                queue.clone(),
                item.id,
                item.claim_generation,
                worker_id.to_owned(),
                self.lease_secs,
            );
            let svc = Arc::clone(&svc);
            let q = queue.clone();
            let wid = worker_id.to_owned();
            let backoff = self.backoff;
            join_set.spawn(async move {
                let res = handle_extract_item(&svc, &q, &wid, backoff, hb, &item).await;
                (idx, res)
            });
        }

        let mut first_err: Option<WorkQueueError> = None;
        while let Some(joined) = join_set.join_next().await {
            match joined {
                Ok((idx, res)) => {
                    if let Some(slot) = safe_guards.get_mut(idx) {
                        if let Some(g) = slot.take() {
                            g.disarm();
                        }
                    }
                    if let Err(err) = res {
                        if first_err.is_none() {
                            first_err = Some(err);
                        }
                    }
                }
                Err(join_err) => {
                    if first_err.is_none() {
                        first_err = Some(WorkQueueError::InvalidArgument(format!(
                            "search.extract task join failed: {join_err}"
                        )));
                    }
                }
            }
        }
        for slot in &mut safe_guards {
            if let Some(g) = slot.take() {
                g.disarm();
            }
        }
        if let Some(err) = first_err {
            return Err(err);
        }
        Ok(count)
    }

    /// Run under [`crate::supervisor::WorkerSupervisor`] until `ctx.cancel`.
    pub async fn run(self, ctx: TaskCtx) -> Result<(), String> {
        let mut wake_rx = match &ctx.listen_hub {
            Some(hub) => hub.subscribe(WORK_WAKEUP_CHANNEL).await.ok(),
            None => None,
        };
        let mut poll = tokio::time::interval(self.poll_interval);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            if ctx.cancel.is_cancelled() {
                return Ok(());
            }
            match self
                .drain_once(&ctx.work_queue, &ctx.node_id, Some(&ctx.safe_leases))
                .await
            {
                Ok(n) if n > 0 => continue,
                Ok(_) => {}
                Err(err) => {
                    eprintln!("search-extract-consumer: drain error: {err}");
                }
            }

            tokio::select! {
                biased;
                _ = ctx.cancel.cancelled() => return Ok(()),
                _ = poll.tick() => {}
                ev = async {
                    match wake_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending::<Option<ListenEvent>>().await,
                    }
                } => {
                    match ev {
                        Some(ListenEvent::Notification(_))
                        | Some(ListenEvent::ResyncRequired { .. }) => {}
                        None => {
                            wake_rx = None;
                        }
                    }
                }
            }
        }
    }
}

async fn handle_extract_item(
    svc: &ContentExtractionService,
    queue: &WorkQueue,
    worker_id: &str,
    backoff: BackoffPolicy,
    hb: WorkHeartbeatGuard,
    item: &WorkItem,
) -> Result<(), WorkQueueError> {
    let payload: SearchExtractPayload = match serde_json::from_value(item.payload.clone()) {
        Ok(p) => p,
        Err(err) => {
            if hb.is_lease_lost() {
                return Ok(());
            }
            let _ = queue
                .dead_letter(
                    item.id,
                    item.claim_generation,
                    worker_id,
                    &format!("invalid search.extract payload: {err}"),
                )
                .await?;
            return Ok(());
        }
    };

    let outcome = tokio::select! {
        biased;
        _ = hb.cancel_token().cancelled() => return Ok(()),
        res = svc.extract_and_cache(&payload) => res,
    };

    if hb.is_lease_lost() {
        return Ok(());
    }

    match outcome {
        Ok(_) => {
            let _ = queue
                .complete(item.id, item.claim_generation, worker_id)
                .await?;
        }
        Err(err) => {
            let delay = backoff.jittered_delay(item.attempts);
            let _ = queue
                .fail_transient(
                    item.id,
                    item.claim_generation,
                    worker_id,
                    &format!("search.extract failed: {err}"),
                    delay,
                )
                .await?;
        }
    }
    Ok(())
}

/// Durable `WorkQueue` consumer for `"search.index_batch"`.
pub struct SearchIndexConsumer<E, S>
where
    E: SearchEngine + SearchIndexer + Send + Sync + 'static,
    S: ObjectStore + 'static,
{
    engine: Arc<E>,
    store: Arc<S>,
    extractor: Arc<dyn ContentExtractor>,
    single_flight: Arc<ExtractionSingleFlight>,
    freshness: Option<Arc<SnapshotFreshnessFence>>,
    backoff: BackoffPolicy,
    lease_secs: i32,
    poll_interval: Duration,
}

impl<E, S> SearchIndexConsumer<E, S>
where
    E: SearchEngine + SearchIndexer + Send + Sync + 'static,
    S: ObjectStore + 'static,
{
    #[must_use]
    pub fn new(engine: Arc<E>, store: Arc<S>) -> Self {
        Self {
            engine,
            store,
            extractor: Arc::new(DefaultContentExtractor),
            single_flight: Arc::new(ExtractionSingleFlight::default()),
            freshness: None,
            backoff: search_backoff_policy(),
            lease_secs: 180,
            poll_interval: Duration::from_secs(2),
        }
    }

    #[must_use]
    pub fn with_extractor(mut self, extractor: Arc<dyn ContentExtractor>) -> Self {
        self.extractor = extractor;
        self
    }

    #[must_use]
    pub fn with_single_flight(mut self, single_flight: Arc<ExtractionSingleFlight>) -> Self {
        self.single_flight = single_flight;
        self
    }

    #[must_use]
    pub fn with_freshness_fence(mut self, fence: Arc<SnapshotFreshnessFence>) -> Self {
        self.freshness = Some(fence);
        self
    }

    #[must_use]
    pub fn with_lease_secs(mut self, lease_secs: i32) -> Self {
        self.lease_secs = lease_secs.max(3);
        self
    }

    #[must_use]
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Claim and settle one `"search.index_batch"` work item.
    pub async fn drain_once(
        &self,
        queue: &WorkQueue,
        worker_id: &str,
        safe_leases: Option<&crate::supervisor::SafeLeaseRegistry>,
    ) -> Result<usize, WorkQueueError> {
        let spec = ClaimSpec::new(
            worker_id.to_owned(),
            vec![WORK_KIND_SEARCH_INDEX_BATCH.to_owned()],
        )
        .with_batch(1)
        .with_lease_secs(self.lease_secs)
        .with_max_concurrency(SEARCH_INDEX_MAX_CONCURRENCY);
        let items = queue.claim(&spec).await?;
        let count = items.len();
        if count == 0 {
            return Ok(0);
        }

        let db: Arc<dyn SearchPipelineDb> = Arc::new(WorkerPoolSearchDb::new(queue.pool().clone()));
        let reader: Arc<dyn ObjectByteReader> =
            Arc::new(ObjectStoreByteReader::new(Arc::clone(&self.store)));
        let extract_svc = Arc::new(
            ContentExtractionService::new(Arc::clone(&db), reader)
                .with_extractor(Arc::clone(&self.extractor))
                .with_single_flight(Arc::clone(&self.single_flight)),
        );
        let pipeline = SearchIndexPipeline::new(db, Arc::clone(&self.engine))
            .with_extraction_service(extract_svc);

        for item in items {
            let safe_guard = safe_leases.map(|r| r.track_work(item.id, item.claim_generation));
            let res = self.handle_item(&pipeline, queue, worker_id, &item).await;
            if let Some(g) = safe_guard {
                g.disarm();
            }
            res?;
        }
        Ok(count)
    }

    async fn handle_item(
        &self,
        pipeline: &SearchIndexPipeline<E>,
        queue: &WorkQueue,
        worker_id: &str,
        item: &WorkItem,
    ) -> Result<(), WorkQueueError> {
        let payload: SearchIndexBatchPayload = if item.payload.is_null() {
            SearchIndexBatchPayload::default()
        } else {
            match serde_json::from_value(item.payload.clone()) {
                Ok(p) => p,
                Err(err) => {
                    let _ = queue
                        .dead_letter(
                            item.id,
                            item.claim_generation,
                            worker_id,
                            &format!("invalid search.index_batch payload: {err}"),
                        )
                        .await?;
                    return Ok(());
                }
            }
        };

        let hb = WorkHeartbeatGuard::spawn(
            queue.clone(),
            item.id,
            item.claim_generation,
            worker_id.to_owned(),
            self.lease_secs,
        );

        let db = WorkerPoolSearchDb::new(queue.pool().clone());
        match pipeline
            .run_batch_cancellable(&payload, Some(Arc::clone(hb.lease_lost_flag())))
            .await
        {
            Ok(summary) => {
                if hb.is_lease_lost() {
                    return Ok(());
                }
                if let Some(fence) = &self.freshness {
                    for (corpus, remaining) in &summary.remaining_dirty {
                        fence.set_watermark(*corpus, summary.generation, *remaining);
                    }
                }
                let scope = payload.corpus.map_or("all", DocCorpus::as_str);
                let cont_payload =
                    serde_json::to_value(&payload).unwrap_or_else(|_| serde_json::json!({}));
                if summary.has_more {
                    // Enqueue a crash-safe follow-up item BEFORE completing the current
                    // leased row, using a distinct idempotency key that cannot coalesce
                    // onto the currently-leased item.
                    let cont_key = format!("search.index_batch:cont:{scope}:after-{}", item.id);
                    let _ = queue
                        .enqueue(
                            &WorkRequest::new(WORK_KIND_SEARCH_INDEX_BATCH, cont_payload.clone())
                                .with_idempotency_key(cont_key),
                        )
                        .await?;
                }
                if hb.is_lease_lost() {
                    return Ok(());
                }
                let _ = queue
                    .complete(item.id, item.claim_generation, worker_id)
                    .await?;
                // Re-check unprocessed outbox rows AFTER complete() deletes the leased
                // work item so any concurrent write that coalesced onto the leased item
                // during execution can never lose its wakeup.
                if !summary.has_more
                    && has_unprocessed_outbox_rows(&db, payload.corpus)
                        .await
                        .unwrap_or(false)
                {
                    let post_key = format!("search.index_batch:{scope}");
                    let _ = queue
                        .enqueue(
                            &WorkRequest::new(WORK_KIND_SEARCH_INDEX_BATCH, cont_payload)
                                .with_idempotency_key(post_key),
                        )
                        .await;
                }
            }
            Err(err) => {
                if hb.is_lease_lost() {
                    return Ok(());
                }
                let delay = self.backoff.jittered_delay(item.attempts);
                let _ = queue
                    .fail_transient(
                        item.id,
                        item.claim_generation,
                        worker_id,
                        &format!("search.index_batch failed: {err}"),
                        delay,
                    )
                    .await?;
            }
        }
        Ok(())
    }

    /// Run under [`crate::supervisor::WorkerSupervisor`] until `ctx.cancel`.
    ///
    /// Seeds the 5 corpus watermark rows (`ON CONFLICT DO NOTHING`) on startup
    /// so V291 write-capture triggers activate strictly when Tier-2 search is enabled.
    pub async fn run(self, ctx: TaskCtx) -> Result<(), String> {
        let poll_db = WorkerPoolSearchDb::new(ctx.pool.clone());
        if let Err(err) = ensure_search_watermarks_initialized(&poll_db).await {
            eprintln!("search-index-consumer: watermark init error: {err}");
        }

        let mut wake_rx = match &ctx.listen_hub {
            Some(hub) => hub.subscribe(WORK_WAKEUP_CHANNEL).await.ok(),
            None => None,
        };
        let mut poll = tokio::time::interval(self.poll_interval);
        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            if ctx.cancel.is_cancelled() {
                return Ok(());
            }
            match self
                .drain_once(&ctx.work_queue, &ctx.node_id, Some(&ctx.safe_leases))
                .await
            {
                Ok(n) if n > 0 => continue,
                Ok(_) => {}
                Err(err) => {
                    eprintln!("search-index-consumer: drain error: {err}");
                }
            }

            tokio::select! {
                biased;
                _ = ctx.cancel.cancelled() => return Ok(()),
                _ = poll.tick() => {
                    // Self-heal lost wakeups and prevent stale dirty_count=0 on the
                    // in-memory SnapshotFreshnessFence whenever unprocessed outbox rows exist.
                    if let Ok(counts) = unprocessed_counts_by_corpus(&poll_db).await {
                        if !counts.is_empty() {
                            if let Some(fence) = &self.freshness {
                                for (corpus, remaining) in &counts {
                                    let current_gen = fence
                                        .watermark(*corpus)
                                        .map_or(0, |wm| wm.generation);
                                    fence.set_watermark(*corpus, current_gen, *remaining);
                                }
                            }
                            let _ = ctx
                                .work_queue
                                .enqueue(
                                    &WorkRequest::new(
                                        WORK_KIND_SEARCH_INDEX_BATCH,
                                        serde_json::json!({}),
                                    )
                                    .with_idempotency_key("search.index_batch:all"),
                                )
                                .await;
                        }
                    }
                }
                ev = async {
                    match wake_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending::<Option<ListenEvent>>().await,
                    }
                } => {
                    match ev {
                        Some(ListenEvent::Notification(_))
                        | Some(ListenEvent::ResyncRequired { .. }) => {}
                        None => {
                            wake_rx = None;
                        }
                    }
                }
            }
        }
    }
}
