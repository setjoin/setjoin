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
    ensure_search_watermarks_initialized, has_unprocessed_outbox_rows, heartbeat_search_leader,
    release_search_leader, try_acquire_search_leader, unprocessed_counts_by_corpus, BoxFuture,
    ContentExtractionService, ContentExtractor, DefaultContentExtractor, DocCorpus,
    EdiscoverySearchExecutor, EngineHealth, ExtractionSingleFlight, LeaderLeaseGate,
    ObjectByteReader, SearchEdiscoveryPayload, SearchEngine, SearchError, SearchExtractPayload,
    SearchIndexBatchPayload, SearchIndexPipeline, SearchIndexer, SearchPipelineDb,
    SearchPurgeEvictPayload, SnapshotFreshnessFence, WORK_KIND_SEARCH_EDISCOVERY,
    WORK_KIND_SEARCH_EXTRACT, WORK_KIND_SEARCH_INDEX_BATCH, WORK_KIND_SEARCH_PURGE_EVICT,
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
    leader_lost: Option<Arc<AtomicBool>>,
    leader_fence: Option<(String, i64)>,
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
            leader_lost: None,
            leader_fence: None,
            backoff: search_backoff_policy(),
            lease_secs: 180,
            poll_interval: Duration::from_secs(2),
        }
    }

    #[must_use]
    pub fn with_leader_lost(mut self, leader_lost: Arc<AtomicBool>) -> Self {
        self.leader_lost = Some(leader_lost);
        self
    }

    #[must_use]
    pub fn with_leader_fence(mut self, node_id: String, fencing_token: i64) -> Self {
        self.leader_fence = Some((node_id, fencing_token));
        self
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
        let mut pipeline = SearchIndexPipeline::new(db, Arc::clone(&self.engine))
            .with_extraction_service(extract_svc);
        if let Some((ref node_id, token)) = self.leader_fence {
            pipeline = pipeline.with_leader_fence(node_id.clone(), token);
        }

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

        let combined_lost = Arc::new(AtomicBool::new(false));
        let hb_flag = Arc::clone(hb.lease_lost_flag());
        let leader_flag = self.leader_lost.clone();
        let combined_watch = Arc::clone(&combined_lost);
        let monitor_handle = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(50));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                if hb_flag.load(Ordering::Acquire)
                    || leader_flag
                        .as_deref()
                        .is_some_and(|f| f.load(Ordering::Acquire))
                {
                    combined_watch.store(true, Ordering::Release);
                    return;
                }
            }
        });
        if self
            .leader_lost
            .as_deref()
            .is_some_and(|f| f.load(Ordering::Acquire))
        {
            combined_lost.store(true, Ordering::Release);
        }

        let db = WorkerPoolSearchDb::new(queue.pool().clone());
        let batch_res = pipeline
            .run_batch_cancellable(&payload, Some(Arc::clone(&combined_lost)))
            .await;
        monitor_handle.abort();
        let lost_now = hb.is_lease_lost() || combined_lost.load(Ordering::Acquire);
        match batch_res {
            Ok(summary) => {
                if lost_now {
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

/// Durable `WorkQueue` consumer for `"search.purge_evict"` (`#558`).
///
/// Runs strictly on the active HA single-writer search leader and invokes
/// `SearchIndexer::evict_and_compact_checked` so lawfully purged document bytes
/// are physically overwritten and unlinked from Tantivy segment files on disk.
pub struct SearchPurgeConsumer<E>
where
    E: SearchEngine + SearchIndexer + Send + Sync + 'static,
{
    engine: Arc<E>,
    freshness: Option<Arc<SnapshotFreshnessFence>>,
    leader_lost: Option<Arc<AtomicBool>>,
    backoff: BackoffPolicy,
    lease_secs: i32,
}

impl<E> SearchPurgeConsumer<E>
where
    E: SearchEngine + SearchIndexer + Send + Sync + 'static,
{
    #[must_use]
    pub fn new(engine: Arc<E>) -> Self {
        Self {
            engine,
            freshness: None,
            leader_lost: None,
            backoff: search_backoff_policy(),
            lease_secs: 180,
        }
    }

    #[must_use]
    pub fn with_freshness_fence(mut self, fence: Arc<SnapshotFreshnessFence>) -> Self {
        self.freshness = Some(fence);
        self
    }

    #[must_use]
    pub fn with_leader_lost(mut self, leader_lost: Arc<AtomicBool>) -> Self {
        self.leader_lost = Some(leader_lost);
        self
    }

    /// Claim and settle one batch of `"search.purge_evict"` work items.
    pub async fn drain_once(
        &self,
        queue: &WorkQueue,
        worker_id: &str,
        safe_leases: Option<&crate::supervisor::SafeLeaseRegistry>,
    ) -> Result<usize, WorkQueueError> {
        if self
            .leader_lost
            .as_deref()
            .is_some_and(|f| f.load(Ordering::Acquire))
        {
            return Ok(0);
        }
        let spec = ClaimSpec::new(
            worker_id.to_owned(),
            vec![WORK_KIND_SEARCH_PURGE_EVICT.to_owned()],
        )
        .with_batch(16)
        .with_lease_secs(self.lease_secs)
        .with_max_concurrency(SEARCH_INDEX_MAX_CONCURRENCY);
        let items = queue.claim(&spec).await?;
        let count = items.len();
        if count == 0 {
            return Ok(0);
        }

        for item in items {
            let safe_guard = safe_leases.map(|r| r.track_work(item.id, item.claim_generation));
            let res = self.handle_item(queue, worker_id, &item).await;
            if let Some(g) = safe_guard {
                g.disarm();
            }
            res?;
        }
        Ok(count)
    }

    async fn handle_item(
        &self,
        queue: &WorkQueue,
        worker_id: &str,
        item: &WorkItem,
    ) -> Result<(), WorkQueueError> {
        let payload: SearchPurgeEvictPayload = match serde_json::from_value(item.payload.clone()) {
            Ok(p) => p,
            Err(err) => {
                let _ = queue
                    .dead_letter(
                        item.id,
                        item.claim_generation,
                        worker_id,
                        &format!("invalid search.purge_evict payload: {err}"),
                    )
                    .await?;
                return Ok(());
            }
        };
        let keys = match payload.into_document_keys() {
            Ok(k) => k,
            Err(err) => {
                let _ = queue
                    .dead_letter(
                        item.id,
                        item.claim_generation,
                        worker_id,
                        &format!("unmappable search.purge_evict key: {err}"),
                    )
                    .await?;
                return Ok(());
            }
        };

        let hb = WorkHeartbeatGuard::spawn(
            queue.clone(),
            item.id,
            item.claim_generation,
            worker_id.to_owned(),
            self.lease_secs,
        );
        let combined_lost = Arc::new(AtomicBool::new(
            self.leader_lost
                .as_deref()
                .is_some_and(|f| f.load(Ordering::Acquire)),
        ));
        let hb_flag = Arc::clone(hb.lease_lost_flag());
        let leader_flag = self.leader_lost.clone();
        let watch = Arc::clone(&combined_lost);
        let mon = tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_millis(50));
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tick.tick().await;
                if hb_flag.load(Ordering::Acquire)
                    || leader_flag
                        .as_deref()
                        .is_some_and(|f| f.load(Ordering::Acquire))
                {
                    watch.store(true, Ordering::Release);
                    return;
                }
            }
        });

        let _ = self.engine.reload_if_disk_epoch_advanced();
        let res = self
            .engine
            .evict_and_compact_checked(&keys, Some(Arc::clone(&combined_lost)))
            .await;
        mon.abort();
        if hb.is_lease_lost() || combined_lost.load(Ordering::Acquire) {
            return Ok(());
        }

        match res {
            Ok(report) => {
                if let Some(fence) = &self.freshness {
                    // Advance ONLY corpora already present in `fence` to the new global
                    // Tantivy generation, preserving each corpus's existing `dirty_count`
                    // (NEVER marking an unset corpus fresh with `dirty_count = 0`).
                    fence.advance_existing_corpora(report.generation);
                }
                let _ = queue
                    .complete(item.id, item.claim_generation, worker_id)
                    .await?;
            }
            Err(err) => {
                let delay = self.backoff.jittered_delay(item.attempts);
                let _ = queue
                    .fail_transient(
                        item.id,
                        item.claim_generation,
                        worker_id,
                        &format!("search.purge_evict failed: {err}"),
                        delay,
                    )
                    .await?;
            }
        }
        Ok(())
    }
}

/// Durable `WorkQueue` consumer for `"search.ediscovery"` (`#558`).
///
/// Executes deterministic watermark-aligned eDiscovery searches (Tantivy `Live` +
/// `ComplianceOnly` unioned with PG outbox tail scan, honest `ExtractionStatusSummary`,
/// and core `admin_audit_log` provenance) with transparent Tier-1 PG fallback.
pub struct SearchEdiscoveryConsumer {
    engine: Option<Arc<dyn SearchEngine>>,
    local_tantivy: Option<Arc<setjoin_search::TantivySearchEngine>>,
    backoff: BackoffPolicy,
    lease_secs: i32,
    poll_interval: Duration,
}

impl SearchEdiscoveryConsumer {
    #[must_use]
    pub fn new(engine: Option<Arc<dyn SearchEngine>>) -> Self {
        Self {
            engine,
            local_tantivy: None,
            backoff: search_backoff_policy(),
            lease_secs: 300,
            poll_interval: Duration::from_secs(2),
        }
    }

    #[must_use]
    pub fn with_local_tantivy(mut self, local: Arc<setjoin_search::TantivySearchEngine>) -> Self {
        if self.engine.is_none() {
            self.engine = Some(Arc::clone(&local) as Arc<dyn SearchEngine>);
        }
        self.local_tantivy = Some(local);
        self
    }

    #[must_use]
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// Claim and settle one `"search.ediscovery"` work item.
    pub async fn drain_once(
        &self,
        queue: &WorkQueue,
        worker_id: &str,
        safe_leases: Option<&crate::supervisor::SafeLeaseRegistry>,
    ) -> Result<usize, WorkQueueError> {
        let spec = ClaimSpec::new(
            worker_id.to_owned(),
            vec![WORK_KIND_SEARCH_EDISCOVERY.to_owned()],
        )
        .with_batch(1)
        .with_lease_secs(self.lease_secs)
        .with_max_concurrency(2);
        let items = queue.claim(&spec).await?;
        let count = items.len();
        if count == 0 {
            return Ok(0);
        }

        let db: Arc<dyn SearchPipelineDb> = Arc::new(WorkerPoolSearchDb::new(queue.pool().clone()));
        let kql_compiler: setjoin_search::KqlCompiler = Arc::new(|kql: &str| {
            setjoin_compliance::kql::parse(kql).map(setjoin_compliance::kql::Predicate::into_parts)
        });
        let mut executor =
            EdiscoverySearchExecutor::new(db, self.engine.clone()).with_kql_compiler(kql_compiler);
        if let Some(ref local) = self.local_tantivy {
            executor = executor.with_local_tantivy(Arc::clone(local));
        }

        for item in items {
            let safe_guard = safe_leases.map(|r| r.track_work(item.id, item.claim_generation));
            let res = self.handle_item(&executor, queue, worker_id, &item).await;
            if let Some(g) = safe_guard {
                g.disarm();
            }
            res?;
        }
        Ok(count)
    }

    async fn handle_item(
        &self,
        executor: &EdiscoverySearchExecutor,
        queue: &WorkQueue,
        worker_id: &str,
        item: &WorkItem,
    ) -> Result<(), WorkQueueError> {
        let payload: SearchEdiscoveryPayload = match serde_json::from_value(item.payload.clone()) {
            Ok(p) => p,
            Err(err) => {
                let _ = queue
                    .dead_letter(
                        item.id,
                        item.claim_generation,
                        worker_id,
                        &format!("invalid search.ediscovery payload: {err}"),
                    )
                    .await?;
                return Ok(());
            }
        };

        let hb = WorkHeartbeatGuard::spawn(
            queue.clone(),
            item.id,
            item.claim_generation,
            worker_id.to_owned(),
            self.lease_secs,
        );
        let outcome = tokio::select! {
            biased;
            _ = hb.cancel_token().cancelled() => return Ok(()),
            res = executor.execute(payload.search_id, payload.actor_id) => res,
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
                let delay = self.backoff.jittered_delay(item.attempts);
                let _ = queue
                    .fail_transient(
                        item.id,
                        item.claim_generation,
                        worker_id,
                        &format!("search.ediscovery failed: {err}"),
                        delay,
                    )
                    .await?;
            }
        }
        Ok(())
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
                    eprintln!("search-ediscovery-consumer: drain error: {err}");
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

/// `SKIP LOCKED`-leased HA single-writer search leader loop (`#558`).
///
/// Only the node holding the active `'search_writer'` lease executes Tantivy
/// writes (`SearchIndexConsumer` & `SearchPurgeConsumer`), with fencing-token
/// heartbeats and immediate graceful release on shutdown (`ctx.cancel`).
pub struct SearchLeaderElector<E, S>
where
    E: SearchEngine + SearchIndexer + Send + Sync + 'static,
    S: ObjectStore + 'static,
{
    engine: Arc<E>,
    store: Arc<S>,
    rpc_url: String,
    lease_secs: i32,
    single_flight: Arc<ExtractionSingleFlight>,
    freshness: Option<Arc<SnapshotFreshnessFence>>,
    leader_gate: Option<Arc<LeaderLeaseGate>>,
    poll_interval: Duration,
}

impl<E, S> SearchLeaderElector<E, S>
where
    E: SearchEngine + SearchIndexer + Send + Sync + 'static,
    S: ObjectStore + 'static,
{
    #[must_use]
    pub fn new(engine: Arc<E>, store: Arc<S>, rpc_url: String, lease_secs: i32) -> Self {
        Self {
            engine,
            store,
            rpc_url,
            lease_secs: lease_secs.clamp(5, 300),
            single_flight: Arc::new(ExtractionSingleFlight::default()),
            freshness: None,
            leader_gate: None,
            poll_interval: Duration::from_secs(2),
        }
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

    /// Attach the shared [`SearchRuntime::leader_gate`] so `/_internal/search/*`
    /// RPCs are strictly deadline-gated on active, unexpired leadership (`503` on demotion/expiry).
    #[must_use]
    pub fn with_leader_gate(mut self, gate: Arc<LeaderLeaseGate>) -> Self {
        self.leader_gate = Some(gate);
        self
    }

    #[must_use]
    pub fn with_poll_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    fn mark_demoted(
        leader_lost: &AtomicBool,
        leader_gate: Option<&LeaderLeaseGate>,
        freshness: Option<&SnapshotFreshnessFence>,
    ) {
        leader_lost.store(true, Ordering::Release);
        if let Some(gate) = leader_gate {
            gate.demote();
        }
        if let Some(fence) = freshness {
            fence.clear_all();
        }
    }

    /// Run the single-writer election, heartbeat, and leader-only write loop until `ctx.cancel`.
    pub async fn run(self, ctx: TaskCtx) -> Result<(), String> {
        let db = WorkerPoolSearchDb::new(ctx.pool.clone());
        let retry_interval = Duration::from_secs(((self.lease_secs.max(6) as u64) / 3).max(1));
        // Conservative local deadline margin so we demote BEFORE the server TTL expires.
        let safe_lease_window =
            Duration::from_secs((self.lease_secs.max(2) as u64).saturating_sub(1));

        if let Some(ref gate) = self.leader_gate {
            gate.demote();
        }

        loop {
            if ctx.cancel.is_cancelled() {
                if let Some(ref gate) = self.leader_gate {
                    gate.demote();
                }
                if let Some(ref fence) = self.freshness {
                    fence.clear_all();
                }
                return Ok(());
            }
            let acquire_started = tokio::time::Instant::now();
            let acq =
                match try_acquire_search_leader(&db, &ctx.node_id, &self.rpc_url, self.lease_secs)
                    .await
                {
                    Ok(a) => a,
                    Err(err) => {
                        eprintln!("search-leader-elector: acquire error: {err}");
                        tokio::select! {
                            biased;
                            _ = ctx.cancel.cancelled() => return Ok(()),
                            _ = tokio::time::sleep(retry_interval) => continue,
                        }
                    }
                };

            if !acq.acquired {
                if let Some(ref gate) = self.leader_gate {
                    gate.demote();
                }
                if let Some(ref fence) = self.freshness {
                    fence.clear_all();
                }
                tokio::select! {
                    biased;
                    _ = ctx.cancel.cancelled() => return Ok(()),
                    _ = tokio::time::sleep(retry_interval) => continue,
                }
            }

            // Elected as the active HA single-writer search leader!
            let fencing_token = acq.fencing_token;
            let initial_deadline = acquire_started + safe_lease_window;
            if let Err(err) = ensure_search_watermarks_initialized(&db).await {
                eprintln!("search-leader-elector: watermark init error: {err}");
            }
            let _ = self.engine.reload_if_disk_epoch_advanced();
            if let Some(ref gate) = self.leader_gate {
                let remaining =
                    initial_deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    gate.demote();
                    continue;
                }
                gate.set_active_for(remaining);
            }

            let leader_lost = Arc::new(AtomicBool::new(false));
            let lease_deadline = Arc::new(std::sync::Mutex::new(initial_deadline));
            let hb_lost = Arc::clone(&leader_lost);
            let hb_deadline = Arc::clone(&lease_deadline);
            let hb_gate = self.leader_gate.clone();
            let hb_freshness = self.freshness.clone();
            let hb_db = db.clone();
            let hb_engine = Arc::clone(&self.engine);
            let hb_node = ctx.node_id.clone();
            let hb_lease_secs = self.lease_secs;
            let hb_cancel = ctx.cancel.clone();
            let hb_handle = tokio::spawn(async move {
                let mut tick = tokio::time::interval(retry_interval);
                tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                tick.tick().await;
                loop {
                    let current_deadline = hb_deadline
                        .lock()
                        .map(|g| *g)
                        .unwrap_or_else(|_| tokio::time::Instant::now());
                    tokio::select! {
                        biased;
                        _ = hb_cancel.cancelled() => return,
                        _ = tokio::time::sleep_until(current_deadline) => {
                            // Local lease TTL expired without a successful renewal -> demote immediately!
                            Self::mark_demoted(
                                &hb_lost,
                                hb_gate.as_deref(),
                                hb_freshness.as_deref(),
                            );
                            return;
                        }
                        _ = tick.tick() => {
                            let renew_started = tokio::time::Instant::now();
                            let remaining = current_deadline.saturating_duration_since(renew_started);
                            if remaining.is_zero() {
                                Self::mark_demoted(
                                    &hb_lost,
                                    hb_gate.as_deref(),
                                    hb_freshness.as_deref(),
                                );
                                return;
                            }
                            let (epoch, generation) = match hb_engine.health() {
                                EngineHealth::Healthy { epoch, generation } => (epoch, generation),
                                _ => (0, 0),
                            };
                            // Bound the DB heartbeat call strictly by `remaining` so a hung
                            // connection during network partition can NEVER block demotion past deadline.
                            let hb_res = tokio::time::timeout(
                                remaining,
                                heartbeat_search_leader(
                                    &hb_db,
                                    &hb_node,
                                    fencing_token,
                                    epoch,
                                    generation,
                                    hb_lease_secs,
                                ),
                            )
                            .await;
                            match hb_res {
                                Ok(Ok(true)) => {
                                    let next_deadline = renew_started + safe_lease_window;
                                    if let Ok(mut g) = hb_deadline.lock() {
                                        *g = next_deadline;
                                    }
                                    if let Some(ref gate) = hb_gate {
                                        let next_rem = next_deadline
                                            .saturating_duration_since(tokio::time::Instant::now());
                                        if next_rem.is_zero() {
                                            Self::mark_demoted(
                                                &hb_lost,
                                                hb_gate.as_deref(),
                                                hb_freshness.as_deref(),
                                            );
                                            return;
                                        }
                                        gate.set_active_for(next_rem);
                                    }
                                }
                                Ok(Ok(false)) | Err(_) => {
                                    Self::mark_demoted(
                                        &hb_lost,
                                        hb_gate.as_deref(),
                                        hb_freshness.as_deref(),
                                    );
                                    return;
                                }
                                Ok(Err(err)) => {
                                    eprintln!("search-leader-elector: heartbeat error: {err}");
                                    if tokio::time::Instant::now() >= current_deadline {
                                        Self::mark_demoted(
                                            &hb_lost,
                                            hb_gate.as_deref(),
                                            hb_freshness.as_deref(),
                                        );
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            });

            let mut index_consumer =
                SearchIndexConsumer::new(Arc::clone(&self.engine), Arc::clone(&self.store))
                    .with_single_flight(Arc::clone(&self.single_flight))
                    .with_leader_lost(Arc::clone(&leader_lost))
                    .with_leader_fence(ctx.node_id.clone(), fencing_token)
                    .with_poll_interval(self.poll_interval);
            let mut purge_consumer = SearchPurgeConsumer::new(Arc::clone(&self.engine))
                .with_leader_lost(Arc::clone(&leader_lost));
            if let Some(ref fence) = self.freshness {
                index_consumer = index_consumer.with_freshness_fence(Arc::clone(fence));
                purge_consumer = purge_consumer.with_freshness_fence(Arc::clone(fence));
            }

            let mut wake_rx = match &ctx.listen_hub {
                Some(hub) => hub.subscribe(WORK_WAKEUP_CHANNEL).await.ok(),
                None => None,
            };
            let mut poll = tokio::time::interval(self.poll_interval);
            poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            while !ctx.cancel.is_cancelled() && !leader_lost.load(Ordering::Acquire) {
                let expired = lease_deadline
                    .lock()
                    .map(|g| tokio::time::Instant::now() >= *g)
                    .unwrap_or(true);
                if expired {
                    Self::mark_demoted(
                        &leader_lost,
                        self.leader_gate.as_deref(),
                        self.freshness.as_deref(),
                    );
                    break;
                }
                // Prioritize lawful purge eviction & compaction ahead of normal indexing.
                match purge_consumer
                    .drain_once(&ctx.work_queue, &ctx.node_id, Some(&ctx.safe_leases))
                    .await
                {
                    Ok(n) if n > 0 => continue,
                    Ok(_) => {}
                    Err(err) => {
                        eprintln!("search-purge-consumer: drain error: {err}");
                    }
                }
                match index_consumer
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
                    _ = ctx.cancel.cancelled() => break,
                    _ = poll.tick() => {
                        if leader_lost.load(Ordering::Acquire) {
                            break;
                        }
                        if let Ok(counts) = unprocessed_counts_by_corpus(&db).await {
                            if !counts.is_empty() {
                                if let Some(ref fence) = self.freshness {
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

            hb_handle.abort();
            let was_active = !leader_lost.load(Ordering::Acquire);
            Self::mark_demoted(
                &leader_lost,
                self.leader_gate.as_deref(),
                self.freshness.as_deref(),
            );
            // Graceful release on shutdown so a standby takes over immediately without TTL wait.
            if ctx.cancel.is_cancelled() && was_active {
                let _ = release_search_leader(&db, &ctx.node_id, fencing_token).await;
                return Ok(());
            }
        }
    }
}
