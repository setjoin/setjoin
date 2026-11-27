//! Content-addressed extraction cache pipeline & full-domain Mail/Chat/Drive
//! outbox indexer (`Wave 3.2`, `#557`).
//!
//! Family isolation: this module stays strictly free of `setjoin-pg/worker-pool`
//! and `setjoin-workqueue/worker` features so `setjoin-search` remains a clean
//! foundation crate (`scripts/check-rust-family-isolation.py`). Composition roots
//! (`bins/gateway/src/supervisor/search_worker.rs`) supply `WorkerPool` + `ObjectStore`
//! adapters implementing [`SearchPipelineDb`] and [`ObjectByteReader`].

use crate::config::{MAX_INFLIGHT_BYTES, MAX_INFLIGHT_DOCS};
use crate::extract::{
    extract_bytes, extract_html_text, truncate_utf8_owned, ExtractionResult, ExtractionStatus,
    ExtractionStoragePlane, EXTRACTOR_VERSION, MAX_EXTRACT_INPUT_BYTES,
};
use crate::model::{
    BoxFuture, DocCorpus, DocumentKey, EngineHealth, IndexDocument, SearchEngine, SearchError,
    SearchIndexer, SearchVisibility,
};
use crate::tantivy_engine::schema_hash;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use setjoin_pg::{Param, Row, Type};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

/// Durable `WorkQueue` kind for content-addressed extraction (`public.search_extracted_text`).
pub const WORK_KIND_SEARCH_EXTRACT: &str = "search.extract";

/// Durable `WorkQueue` kind for full-domain outbox batch indexing into Tantivy.
pub const WORK_KIND_SEARCH_INDEX_BATCH: &str = "search.index_batch";

/// Default maximum outbox rows claimed per corpus per indexing batch.
pub const DEFAULT_INDEX_BATCH_LIMIT: i32 = 200;

/// Conservative per-chunk document ceiling (strictly `<= MAX_INFLIGHT_DOCS`).
const UPSERT_CHUNK_MAX_DOCS: usize = if MAX_INFLIGHT_DOCS > 1_000 {
    1_000
} else {
    MAX_INFLIGHT_DOCS
};

/// Conservative per-chunk estimated byte ceiling (strictly `<= MAX_INFLIGHT_BYTES`, 12 MiB).
const UPSERT_CHUNK_MAX_BYTES: usize = if MAX_INFLIGHT_BYTES > 12_000_000 {
    12_000_000
} else {
    MAX_INFLIGHT_BYTES
};

/// Payload for `"search.extract"` `WorkQueue` items.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchExtractPayload {
    pub content_sha256: String,
    pub storage_plane: ExtractionStoragePlane,
    /// S3 object key for `blob` storage plane (defaults to `blobs.minio_ref` or `content_sha256`).
    #[serde(default)]
    pub object_key: Option<String>,
    /// Optional `drive_file_versions.id` for `drive_file_version` chunk reconstruction.
    #[serde(default)]
    pub drive_version_id: Option<i64>,
    #[serde(default)]
    pub content_type: Option<String>,
    #[serde(default)]
    pub filename: Option<String>,
}

/// Payload for `"search.index_batch"` `WorkQueue` items.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchIndexBatchPayload {
    /// Specific corpus to drain, or `None` to drain all 5 corpora + pending `scheduled_actions`.
    #[serde(default)]
    pub corpus: Option<DocCorpus>,
    #[serde(default)]
    pub batch_limit: Option<i32>,
}

/// Outcome of a single content-addressed extraction request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractCacheOutcome {
    pub content_sha256: String,
    pub cache_hit: bool,
    pub result: ExtractionResult,
}

/// Summary of one full-domain indexing batch pass.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IndexBatchSummary {
    pub outbox_rows_processed: usize,
    pub upserted_docs: usize,
    pub deleted_docs: usize,
    pub scheduled_actions_indexed: usize,
    pub generation: u64,
    pub watermarks: HashMap<DocCorpus, i64>,
    /// Exact remaining unindexed count (`outbox > committed_seq` + remaining `search_dirty_keys`)
    /// per corpus touched in this batch, used to populate `SnapshotFreshnessFence`.
    pub remaining_dirty: HashMap<DocCorpus, u64>,
    /// True when at least one corpus had additional outbox rows beyond `batch_limit`
    /// and requires a follow-up `"search.index_batch"` enqueue.
    pub has_more: bool,
}

/// Object-safe database query boundary for search extraction/indexing workers.
///
/// Implemented for `tokio_postgres::Client` (used in tests) and for `WorkerPool`
/// in `bins/gateway/src/supervisor/search_worker.rs`.
pub trait SearchPipelineDb: Send + Sync {
    fn query_typed<'a>(
        &'a self,
        sql: &'a str,
        params: &'a [Param<'a>],
    ) -> BoxFuture<'a, Result<Vec<Row>, SearchError>>;
}

impl SearchPipelineDb for tokio_postgres::Client {
    fn query_typed<'a>(
        &'a self,
        sql: &'a str,
        params: &'a [Param<'a>],
    ) -> BoxFuture<'a, Result<Vec<Row>, SearchError>> {
        Box::pin(async move {
            let raw: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> =
                params.iter().map(|(v, _)| *v).collect();
            self.query(sql, &raw)
                .await
                .map_err(|e| SearchError::Database(e.to_string()))
        })
    }
}

/// Object-safe bounded object-store reader boundary for extraction workers.
pub trait ObjectByteReader: Send + Sync {
    fn read_bytes<'a>(
        &'a self,
        key: &'a str,
        max_bytes: usize,
    ) -> BoxFuture<'a, Result<Vec<u8>, SearchError>>;
}

/// Pluggable pure-Rust content extractor trait (defaults to [`DefaultContentExtractor`],
/// wrappable in tests to assert single-invocation deduplication).
pub trait ContentExtractor: Send + Sync {
    fn extract(
        &self,
        bytes: &[u8],
        content_type: Option<&str>,
        filename: Option<&str>,
    ) -> ExtractionResult;
}

/// Production content extractor delegating to [`crate::extract::extract_bytes`].
#[derive(Clone, Copy, Debug, Default)]
pub struct DefaultContentExtractor;

impl ContentExtractor for DefaultContentExtractor {
    fn extract(
        &self,
        bytes: &[u8],
        content_type: Option<&str>,
        filename: Option<&str>,
    ) -> ExtractionResult {
        extract_bytes(bytes, content_type, filename)
    }
}

/// Single-flight coordinator preventing redundant concurrent extractions of the
/// same `content_sha256` inside one process, with RAII map cleanup on Drop.
#[derive(Clone, Default)]
pub struct ExtractionSingleFlight {
    locks: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
}

impl ExtractionSingleFlight {
    /// Acquire the per-`sha256` async mutex and return an RAII guard that
    /// removes the map entry when idle even if a queued waiter is cancelled
    /// before acquiring the mutex.
    pub async fn acquire(&self, sha256: &str) -> SingleFlightGuard {
        let entry = {
            let mut map = self
                .locks
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            Arc::clone(
                map.entry(sha256.to_owned())
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
            )
        };
        // Construct the RAII guard BEFORE awaiting the mutex so cancelling a
        // queued waiter also runs Drop and removes the map entry when idle.
        let mut guard = SingleFlightGuard {
            locks: Arc::clone(&self.locks),
            sha256: sha256.to_owned(),
            entry: Arc::clone(&entry),
            _lock: None,
        };
        let lock = entry.lock_owned().await;
        guard._lock = Some(lock);
        guard
    }
}

/// RAII drop guard for [`ExtractionSingleFlight`].
pub struct SingleFlightGuard {
    locks: Arc<Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    sha256: String,
    entry: Arc<tokio::sync::Mutex<()>>,
    _lock: Option<tokio::sync::OwnedMutexGuard<()>>,
}

impl Drop for SingleFlightGuard {
    fn drop(&mut self) {
        // Release the owned mutex guard first so strong_count reflects only map + self.entry.
        self._lock.take();
        let mut map = self
            .locks
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(current) = map.get(&self.sha256) {
            if Arc::ptr_eq(current, &self.entry) && Arc::strong_count(current) <= 2 {
                map.remove(&self.sha256);
            }
        }
    }
}

/// Content-addressed extraction service backed by `public.search_extracted_text`.
pub struct ContentExtractionService {
    db: Arc<dyn SearchPipelineDb>,
    reader: Arc<dyn ObjectByteReader>,
    extractor: Arc<dyn ContentExtractor>,
    single_flight: Arc<ExtractionSingleFlight>,
}

impl ContentExtractionService {
    #[must_use]
    pub fn new(db: Arc<dyn SearchPipelineDb>, reader: Arc<dyn ObjectByteReader>) -> Self {
        Self {
            db,
            reader,
            extractor: Arc::new(DefaultContentExtractor),
            single_flight: Arc::new(ExtractionSingleFlight::default()),
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

    /// Check `public.search_extracted_text` (when digest provenance is server-verified),
    /// read bounded bytes from the appropriate storage plane on miss, verify actual
    /// SHA-256 before sharing/writing cache, run extraction inside `spawn_blocking`,
    /// and persist idempotently.
    pub async fn extract_and_cache(
        &self,
        payload: &SearchExtractPayload,
    ) -> Result<ExtractCacheOutcome, SearchError> {
        let sha = payload.content_sha256.trim().to_ascii_lowercase();
        if !is_valid_sha256(&sha) {
            return Err(SearchError::Internal(
                "invalid content_sha256 for search.extract".to_owned(),
            ));
        }

        match payload.storage_plane {
            ExtractionStoragePlane::Blob => self.extract_blob(&sha, payload).await,
            ExtractionStoragePlane::DriveFileVersion => {
                self.extract_drive_version(&sha, payload).await
            }
        }
    }

    async fn extract_blob(
        &self,
        sha: &str,
        payload: &SearchExtractPayload,
    ) -> Result<ExtractCacheOutcome, SearchError> {
        // Blob SHA-256 is server-verified at upload time -> fast-path cache lookup is safe.
        if let Some(cached) = lookup_extracted_cache(self.db.as_ref(), sha).await? {
            if cached.extractor_version >= EXTRACTOR_VERSION {
                return Ok(ExtractCacheOutcome {
                    content_sha256: sha.to_owned(),
                    cache_hit: true,
                    result: cached,
                });
            }
        }

        let _sf_guard = self.single_flight.acquire(sha).await;

        if let Some(cached) = lookup_extracted_cache(self.db.as_ref(), sha).await? {
            if cached.extractor_version >= EXTRACTOR_VERSION {
                return Ok(ExtractCacheOutcome {
                    content_sha256: sha.to_owned(),
                    cache_hit: true,
                    result: cached,
                });
            }
        }

        let cap_plus_one = MAX_EXTRACT_INPUT_BYTES.saturating_add(1);
        let key = match payload.object_key.as_deref().filter(|s| !s.is_empty()) {
            Some(k) => normalize_blob_object_key(sha, k),
            None => resolve_blob_object_key(self.db.as_ref(), sha).await?,
        };
        let loaded = if let Some(size) = lookup_blob_size(self.db.as_ref(), sha).await? {
            if size > MAX_EXTRACT_INPUT_BYTES as i64 {
                LoadedBytes::Oversized
            } else {
                let data = self.reader.read_bytes(&key, cap_plus_one).await?;
                if data.len() > MAX_EXTRACT_INPUT_BYTES {
                    LoadedBytes::Oversized
                } else {
                    LoadedBytes::Bytes(data)
                }
            }
        } else {
            let data = self.reader.read_bytes(&key, cap_plus_one).await?;
            if data.len() > MAX_EXTRACT_INPUT_BYTES {
                LoadedBytes::Oversized
            } else {
                LoadedBytes::Bytes(data)
            }
        };

        let result = match loaded {
            LoadedBytes::Oversized => ExtractionResult::truncated_input(
                payload.content_type.clone(),
                "input_size_limit_exceeded",
            ),
            LoadedBytes::Bytes(raw) => {
                // Verify actual object bytes match expected SHA-256 before writing shared cache.
                let actual = sha256_hex(&raw);
                if actual != sha {
                    return Err(SearchError::Io(format!(
                        "blob digest mismatch for {sha} (observed {actual}); refusing cache write"
                    )));
                }
                self.run_blocking_extract(
                    raw,
                    payload.content_type.clone(),
                    payload.filename.clone(),
                )
                .await?
            }
        };

        persist_extracted_cache(self.db.as_ref(), sha, ExtractionStoragePlane::Blob, &result)
            .await?;

        Ok(ExtractCacheOutcome {
            content_sha256: sha.to_owned(),
            cache_hit: false,
            result,
        })
    }

    async fn extract_drive_version(
        &self,
        claimed_sha: &str,
        payload: &SearchExtractPayload,
    ) -> Result<ExtractCacheOutcome, SearchError> {
        let version_id = match payload.drive_version_id {
            Some(id) if id > 0 => Some(id),
            _ => resolve_drive_version_id(self.db.as_ref(), claimed_sha).await?,
        };

        let (declared_size, chunks) = match version_id {
            Some(vid) => {
                let sz = lookup_drive_version_size(self.db.as_ref(), vid).await?;
                let ch = lookup_drive_version_chunks(self.db.as_ref(), vid).await?;
                (sz, ch)
            }
            None => (None, Vec::new()),
        };

        // Single-chunk fast path: `drive_chunks.sha256` is server-verified on chunk upload.
        // Only when `chunks.len() == 1 && chunks[0].chunk_sha256 == claimed_sha` may we
        // short-circuit to `search_extracted_text` without downloading bytes.
        let single_chunk_verified = chunks.len() == 1 && chunks[0].chunk_sha256 == claimed_sha;

        if single_chunk_verified {
            if let Some(cached) = lookup_extracted_cache(self.db.as_ref(), claimed_sha).await? {
                if cached.extractor_version >= EXTRACTOR_VERSION {
                    return Ok(ExtractCacheOutcome {
                        content_sha256: claimed_sha.to_owned(),
                        cache_hit: true,
                        result: cached,
                    });
                }
            }
        }

        let _sf_guard = self.single_flight.acquire(claimed_sha).await;

        if single_chunk_verified {
            if let Some(cached) = lookup_extracted_cache(self.db.as_ref(), claimed_sha).await? {
                if cached.extractor_version >= EXTRACTOR_VERSION {
                    return Ok(ExtractCacheOutcome {
                        content_sha256: claimed_sha.to_owned(),
                        cache_hit: true,
                        result: cached,
                    });
                }
            }
        }

        // Load content bytes cleanly (short-circuiting 0-byte Drive files and >20 MiB files).
        let loaded = self
            .load_drive_bytes(declared_size, &chunks, payload)
            .await?;

        match loaded {
            LoadedBytes::Oversized => {
                let result = ExtractionResult::truncated_input(
                    payload.content_type.clone(),
                    "input_size_limit_exceeded",
                );
                // Only cache oversized status under claimed_sha when single-chunk verified
                // or no conflicting cache entry exists with valid text.
                if single_chunk_verified {
                    persist_extracted_cache(
                        self.db.as_ref(),
                        claimed_sha,
                        ExtractionStoragePlane::DriveFileVersion,
                        &result,
                    )
                    .await?;
                }
                Ok(ExtractCacheOutcome {
                    content_sha256: claimed_sha.to_owned(),
                    cache_hit: false,
                    result,
                })
            }
            LoadedBytes::Bytes(raw) => {
                let actual_sha = sha256_hex(&raw);
                if actual_sha == claimed_sha {
                    // Verified whole-file digest matches claimed_sha: check shared cache first,
                    // then extract & persist under claimed_sha.
                    if let Some(cached) =
                        lookup_extracted_cache(self.db.as_ref(), claimed_sha).await?
                    {
                        if cached.extractor_version >= EXTRACTOR_VERSION {
                            return Ok(ExtractCacheOutcome {
                                content_sha256: claimed_sha.to_owned(),
                                cache_hit: true,
                                result: cached,
                            });
                        }
                    }
                    let result = self
                        .run_blocking_extract(
                            raw,
                            payload.content_type.clone(),
                            payload.filename.clone(),
                        )
                        .await?;
                    persist_extracted_cache(
                        self.db.as_ref(),
                        claimed_sha,
                        ExtractionStoragePlane::DriveFileVersion,
                        &result,
                    )
                    .await?;
                    Ok(ExtractCacheOutcome {
                        content_sha256: claimed_sha.to_owned(),
                        cache_hit: false,
                        result,
                    })
                } else {
                    // Client-supplied `drive_file_versions.content_sha256` does NOT match actual
                    // chunk bytes: extract locally for THIS document WITHOUT reading or poisoning
                    // another tenant's shared `search_extracted_text` row!
                    let result = self
                        .run_blocking_extract(
                            raw,
                            payload.content_type.clone(),
                            payload.filename.clone(),
                        )
                        .await?;
                    Ok(ExtractCacheOutcome {
                        content_sha256: actual_sha,
                        cache_hit: false,
                        result,
                    })
                }
            }
        }
    }

    async fn load_drive_bytes(
        &self,
        declared_size: Option<i64>,
        chunks: &[DriveChunkRef],
        payload: &SearchExtractPayload,
    ) -> Result<LoadedBytes, SearchError> {
        let cap_plus_one = MAX_EXTRACT_INPUT_BYTES.saturating_add(1);
        if let Some(sz) = declared_size {
            if sz > MAX_EXTRACT_INPUT_BYTES as i64 {
                return Ok(LoadedBytes::Oversized);
            }
            // Short-circuit 0-byte Drive files without issuing an S3 read.
            if sz == 0 && chunks.is_empty() {
                return Ok(LoadedBytes::Bytes(Vec::new()));
            }
        }
        if !chunks.is_empty() {
            let mut combined = Vec::new();
            for ch in chunks {
                let rem = cap_plus_one.saturating_sub(combined.len());
                if rem == 0 {
                    return Ok(LoadedBytes::Oversized);
                }
                let chunk_bytes = self.reader.read_bytes(&ch.storage_ref, rem).await?;
                if combined.len().saturating_add(chunk_bytes.len()) > MAX_EXTRACT_INPUT_BYTES {
                    return Ok(LoadedBytes::Oversized);
                }
                combined.extend_from_slice(&chunk_bytes);
            }
            return Ok(LoadedBytes::Bytes(combined));
        }
        // Only use an explicit caller-provided object_key; NEVER fall back to
        // reading an unrelated S3 object keyed by client-claimed content_sha256.
        let Some(explicit_key) = payload.object_key.as_deref().filter(|s| !s.is_empty()) else {
            return Err(SearchError::Io(
                "drive file version has no content chunks".to_owned(),
            ));
        };
        let data = self.reader.read_bytes(explicit_key, cap_plus_one).await?;
        if data.len() > MAX_EXTRACT_INPUT_BYTES {
            return Ok(LoadedBytes::Oversized);
        }
        Ok(LoadedBytes::Bytes(data))
    }

    async fn run_blocking_extract(
        &self,
        raw: Vec<u8>,
        content_type: Option<String>,
        filename: Option<String>,
    ) -> Result<ExtractionResult, SearchError> {
        let extractor = Arc::clone(&self.extractor);
        tokio::task::spawn_blocking(move || {
            extractor.extract(&raw, content_type.as_deref(), filename.as_deref())
        })
        .await
        .map_err(|e| SearchError::Internal(format!("extraction task join failed: {e}")))
    }
}

enum LoadedBytes {
    Bytes(Vec<u8>),
    Oversized,
}

struct DriveChunkRef {
    chunk_sha256: String,
    storage_ref: String,
}

enum FinalOp {
    Upsert(IndexDocument),
    Delete,
}

/// Full-domain Mail/Chat/Drive outbox indexing pipeline.
pub struct SearchIndexPipeline<E>
where
    E: SearchEngine + SearchIndexer + Send + Sync,
{
    db: Arc<dyn SearchPipelineDb>,
    engine: Arc<E>,
    extractor: Option<Arc<ContentExtractionService>>,
    leader_fence: Option<(String, i64)>,
}

impl<E> SearchIndexPipeline<E>
where
    E: SearchEngine + SearchIndexer + Send + Sync,
{
    #[must_use]
    pub fn new(db: Arc<dyn SearchPipelineDb>, engine: Arc<E>) -> Self {
        Self {
            db,
            engine,
            extractor: None,
            leader_fence: None,
        }
    }

    #[must_use]
    pub fn with_extraction_service(mut self, extractor: Arc<ContentExtractionService>) -> Self {
        self.extractor = Some(extractor);
        self
    }

    /// Fence outbox settlement and watermark advancement on active HA single-writer
    /// leadership `(node_id, fencing_token)` (`#558`).
    #[must_use]
    pub fn with_leader_fence(mut self, node_id: String, fencing_token: i64) -> Self {
        self.leader_fence = Some((node_id, fencing_token));
        self
    }

    /// Process one outbox batch for either one specified corpus or all five corpora
    /// plus pending `scheduled_actions` (indexed as `ComplianceOnly`), commit Tantivy
    /// in bounded chunks, and advance `search_index_watermarks.indexed_outbox_seq`
    /// monotonically.
    pub async fn run_batch(
        &self,
        payload: &SearchIndexBatchPayload,
    ) -> Result<IndexBatchSummary, SearchError> {
        self.run_batch_cancellable(payload, None).await
    }

    /// Same as [`Self::run_batch`], additionally checking `lease_lost` inside
    /// Tantivy commit publication and before advancing watermarks so a lost
    /// `WorkQueue` lease never publishes stale/split-brain state.
    pub async fn run_batch_cancellable(
        &self,
        payload: &SearchIndexBatchPayload,
        lease_lost: Option<Arc<AtomicBool>>,
    ) -> Result<IndexBatchSummary, SearchError> {
        let lease_ref = lease_lost.as_deref();
        // Seamlessly pick up any strictly newer epoch committed on disk by `mailctl search rebuild`.
        let _ = self.engine.reload_if_disk_epoch_advanced();
        let limit = payload
            .batch_limit
            .unwrap_or(DEFAULT_INDEX_BATCH_LIMIT)
            .clamp(1, 999);
        let corpora: Vec<DocCorpus> = match payload.corpus {
            Some(c) => vec![c],
            None => vec![
                DocCorpus::Mail,
                DocCorpus::MailAttachment,
                DocCorpus::Chat,
                DocCorpus::Drive,
                DocCorpus::DriveFile,
            ],
        };

        let (has_loaded_epoch, local_epoch) = match self.engine.health() {
            EngineHealth::Healthy { epoch, .. } => (true, epoch as i64),
            _ => (false, 0),
        };

        // Capture PostgreSQL server time BEFORE claiming/hydrating so dirty-key
        // retirement never deletes concurrent writes arriving mid-batch.
        let batch_started_at = current_db_timestamp(self.db.as_ref()).await?;

        let mut summary = IndexBatchSummary::default();
        // Per-key chronological collapse: last operation for a DocumentKey wins deterministically.
        let mut final_ops: HashMap<DocumentKey, FinalOp> = HashMap::new();
        let mut corpus_max_seq: Vec<(DocCorpus, i64)> = Vec::new();
        let mut corpus_seqs: HashMap<DocCorpus, Vec<i64>> = HashMap::new();
        let mut processed_seqs: Vec<i64> = Vec::new();
        let mut processed_dirty: Vec<DirtyKeyRef> = Vec::new();
        let mut handled_scheduled_uuids: HashSet<String> = HashSet::new();

        for corpus in corpora {
            let (stored_epoch, _stored_seq) =
                current_watermark_cursor(self.db.as_ref(), corpus).await?;
            if !has_loaded_epoch && stored_epoch > 0 {
                return Err(SearchError::Unavailable(format!(
                    "local search index has no loaded epoch while watermark epoch is {stored_epoch} for {}; rebuild required",
                    corpus.as_str()
                )));
            }
            if has_loaded_epoch && local_epoch < stored_epoch {
                return Err(SearchError::Unavailable(format!(
                    "stale local search epoch {local_epoch} < watermark epoch {stored_epoch} for {}",
                    corpus.as_str()
                )));
            }

            // Always claim unprocessed rows from after_seq = 0 so out-of-order
            // commits (e.g., seq=1 committing after seq=2) are NEVER skipped.
            let mut rows = claim_outbox_batch(self.db.as_ref(), corpus, 0, limit + 1).await?;
            if rows.len() > limit as usize {
                rows.truncate(limit as usize);
                summary.has_more = true;
            }
            if rows.is_empty() {
                continue;
            }
            let mut max_seq = 0i64;
            let cseqs = corpus_seqs.entry(corpus).or_default();
            for entry in &rows {
                if entry.seq > max_seq {
                    max_seq = entry.seq;
                }
                cseqs.push(entry.seq);
                processed_seqs.push(entry.seq);
                summary.outbox_rows_processed += 1;
                processed_dirty.push(DirtyKeyRef {
                    corpus: entry.corpus,
                    scope_id: entry.scope_id,
                    doc_id: entry.entity_id,
                    received_at_us: entry.received_at.map_or(0, |ts| ts.timestamp_micros()),
                    sub_id: entry.sub_id,
                });
                if let Some(aid) = &entry.action_id {
                    handled_scheduled_uuids.insert(aid.clone());
                }
                self.materialize_outbox_entry(entry, &mut final_ops, &mut summary)
                    .await?;
            }
            corpus_max_seq.push((corpus, max_seq));
        }

        // Backstop sweep for un-triggered pending/enqueued/failed scheduled_actions
        // when running an all-corpora batch (skips any already processed via outbox).
        if payload.corpus.is_none() {
            let sweep_count = self
                .materialize_scheduled_actions_sweep(
                    limit,
                    &handled_scheduled_uuids,
                    &mut final_ops,
                )
                .await?;
            summary.scheduled_actions_indexed += sweep_count;
        }

        // Split collapsed per-key operations into disjoint deletes and upserts,
        // clamping any oversized single document safely within Tantivy's batch cap.
        let mut final_deletes: Vec<DocumentKey> = Vec::new();
        let mut final_upserts: Vec<IndexDocument> = Vec::new();
        for (key, op) in final_ops {
            match op {
                FinalOp::Delete => final_deletes.push(key),
                FinalOp::Upsert(doc) => final_upserts.push(clamp_document_to_budget(doc)),
            }
        }

        check_lease_alive(lease_ref)?;

        // Chunk deletes and upserts strictly within Tantivy in-flight doc & byte caps,
        // carrying the lease flag all the way into Tantivy's commit critical section.
        let mut total_deleted = 0usize;
        for chunk in final_deletes.chunks(UPSERT_CHUNK_MAX_DOCS) {
            check_lease_alive(lease_ref)?;
            total_deleted += self
                .engine
                .delete_batch_checked(chunk, lease_lost.clone())
                .await?;
        }
        summary.deleted_docs = total_deleted;

        let mut total_upserted = 0usize;
        for chunk in chunk_index_documents(&final_upserts) {
            check_lease_alive(lease_ref)?;
            total_upserted += self
                .engine
                .upsert_batch_checked(chunk, lease_lost.clone())
                .await?;
        }
        summary.upserted_docs = total_upserted;

        check_lease_alive(lease_ref)?;

        // Delete-only batch on a fresh uninitialized index: skip commit_generation()
        // so empty index initialization never errors; still advance watermarks cleanly.
        let did_write = !final_upserts.is_empty() || !final_deletes.is_empty();
        let generation = if (did_write && (!final_upserts.is_empty() || has_loaded_epoch))
            || (!corpus_max_seq.is_empty() && has_loaded_epoch)
        {
            self.engine
                .commit_generation_checked(lease_lost.clone())
                .await?
        } else {
            match self.engine.health() {
                EngineHealth::Healthy { generation, .. } => generation,
                _ => 0,
            }
        };
        summary.generation = generation;

        let post_epoch = match self.engine.health() {
            EngineHealth::Healthy { epoch, .. } => epoch as i64,
            _ => local_epoch,
        };
        let hash = schema_hash();

        check_lease_alive(lease_ref)?;

        let mut accepted_corpora: HashSet<DocCorpus> = HashSet::new();
        if let Some((ref expected_node, expected_token)) = self.leader_fence {
            // Atomic single-transaction HA leader fence + outbox settlement + watermark advance
            // (`public.search_fenced_settle_batch` locks `'search_writer' FOR UPDATE`, verifies
            // `(holder_node_id, fencing_token, leased_until > now())`, marks outbox rows processed,
            // and advances `search_index_watermarks` in ONE transaction — zero split-brain race).
            for (corpus, max_seq) in corpus_max_seq {
                check_lease_alive(lease_ref)?;
                let seqs_for_corpus = corpus_seqs.remove(&corpus).unwrap_or_default();
                let (settled, returned_epoch, committed_seq) = fenced_settle_batch(
                    self.db.as_ref(),
                    expected_node,
                    expected_token,
                    &seqs_for_corpus,
                    corpus,
                    post_epoch,
                    generation as i64,
                    max_seq,
                    &hash,
                )
                .await?;
                if !settled {
                    return Err(SearchError::Unavailable(
                        "HA search leader atomic fenced settlement rejected (leadership lost)"
                            .to_owned(),
                    ));
                }
                if returned_epoch == post_epoch {
                    accepted_corpora.insert(corpus);
                }
                summary.watermarks.insert(corpus, committed_seq);
                let (remaining_outbox, remaining_dirty_keys) =
                    count_remaining_unindexed(self.db.as_ref(), corpus).await?;
                if remaining_outbox > 0 {
                    summary.has_more = true;
                }
                summary.remaining_dirty.insert(
                    corpus,
                    remaining_outbox.saturating_add(remaining_dirty_keys),
                );
            }
        } else {
            // Unfenced single-node/direct pipeline settlement.
            mark_outbox_processed(self.db.as_ref(), &processed_seqs).await?;
            for (corpus, max_seq) in corpus_max_seq {
                check_lease_alive(lease_ref)?;
                let contiguous_seq =
                    contiguous_processed_seq(self.db.as_ref(), corpus, max_seq).await?;
                let (returned_epoch, committed_seq) = advance_watermark(
                    self.db.as_ref(),
                    corpus,
                    post_epoch,
                    generation as i64,
                    contiguous_seq,
                    &hash,
                )
                .await?;
                if returned_epoch == post_epoch {
                    accepted_corpora.insert(corpus);
                }
                summary.watermarks.insert(corpus, committed_seq);
                let (remaining_outbox, remaining_dirty_keys) =
                    count_remaining_unindexed(self.db.as_ref(), corpus).await?;
                if remaining_outbox > 0 {
                    summary.has_more = true;
                }
                summary.remaining_dirty.insert(
                    corpus,
                    remaining_outbox.saturating_add(remaining_dirty_keys),
                );
            }
        }

        // Delete ONLY processed dirty keys for corpora whose epoch was accepted
        // AND whose dirty_at <= batch_started_at (preserving concurrent writes).
        let eligible_dirty: Vec<DirtyKeyRef> = processed_dirty
            .into_iter()
            .filter(|k| accepted_corpora.contains(&k.corpus))
            .collect();
        delete_processed_dirty_keys(self.db.as_ref(), &eligible_dirty, batch_started_at).await?;

        Ok(summary)
    }

    async fn materialize_outbox_entry(
        &self,
        entry: &OutboxEntry,
        final_ops: &mut HashMap<DocumentKey, FinalOp>,
        summary: &mut IndexBatchSummary,
    ) -> Result<(), SearchError> {
        // Negative entity_id denotes a scheduled_actions compliance tombstone/upsert.
        if entry.entity_id < 0 {
            return self
                .materialize_scheduled_action_outbox(entry, final_ops, summary)
                .await;
        }

        match entry.corpus {
            DocCorpus::Mail => {
                if entry.op == "delete" {
                    if let Some(ts) = entry.received_at {
                        final_ops.insert(
                            DocumentKey::Mail {
                                mailbox_id: entry.scope_id,
                                id: entry.entity_id,
                                received_at: ts,
                            },
                            FinalOp::Delete,
                        );
                    }
                    return Ok(());
                }
                self.hydrate_mail_docs(entry, final_ops).await
            }
            DocCorpus::MailAttachment => {
                if entry.op == "delete" {
                    if let Some(ts) = entry.received_at {
                        final_ops.insert(
                            DocumentKey::MailAttachment {
                                mailbox_id: entry.scope_id,
                                id: entry.entity_id,
                                received_at: ts,
                                sub_id: entry.sub_id,
                            },
                            FinalOp::Delete,
                        );
                    }
                    return Ok(());
                }
                self.hydrate_mail_attachment_doc(entry, final_ops).await
            }
            DocCorpus::Chat => {
                if entry.op == "delete" {
                    final_ops.insert(
                        DocumentKey::Chat {
                            channel_id: entry.scope_id,
                            id: entry.entity_id,
                        },
                        FinalOp::Delete,
                    );
                    final_ops.insert(
                        DocumentKey::Chat {
                            channel_id: entry.scope_id,
                            id: chat_revision_doc_id(entry.entity_id),
                        },
                        FinalOp::Delete,
                    );
                    return Ok(());
                }
                self.hydrate_chat_doc(entry, final_ops).await
            }
            DocCorpus::Drive => {
                if entry.op == "delete" {
                    final_ops.insert(
                        DocumentKey::Drive {
                            space_id: entry.scope_id,
                            id: entry.entity_id,
                        },
                        FinalOp::Delete,
                    );
                    return Ok(());
                }
                self.hydrate_drive_doc(entry, final_ops).await
            }
            DocCorpus::DriveFile => {
                if entry.op == "delete" {
                    final_ops.insert(
                        DocumentKey::DriveFile {
                            space_id: entry.scope_id,
                            id: entry.entity_id,
                            sub_id: entry.sub_id,
                        },
                        FinalOp::Delete,
                    );
                    return Ok(());
                }
                self.hydrate_drive_file_doc(entry, final_ops).await
            }
        }
    }

    async fn hydrate_mail_docs(
        &self,
        entry: &OutboxEntry,
        final_ops: &mut HashMap<DocumentKey, FinalOp>,
    ) -> Result<(), SearchError> {
        let rows = if let Some(ts) = entry.received_at {
            let params: [Param<'_>; 3] = [
                (&entry.scope_id, Type::INT8),
                (&entry.entity_id, Type::INT8),
                (&ts, Type::TIMESTAMPTZ),
            ];
            self.db
                .query_typed(
                    "SELECT m.mailbox_id, m.id, m.received_at, coalesce(m.subject, ''), \
                            m.from_addr, coalesce(m.from_name, ''), \
                            m.to_addrs::text, m.cc_addrs::text, m.message_id, \
                            m.body_text, m.body_html, m.is_deleted, m.held, \
                            coalesce(m.crypto_type = 'smime-encrypted', false) \
                       FROM public.messages m \
                      WHERE m.mailbox_id = $1 AND m.id = $2 AND m.received_at = $3",
                    &params,
                )
                .await?
        } else {
            let params: [Param<'_>; 2] = [
                (&entry.scope_id, Type::INT8),
                (&entry.entity_id, Type::INT8),
            ];
            self.db
                .query_typed(
                    "SELECT m.mailbox_id, m.id, m.received_at, coalesce(m.subject, ''), \
                            m.from_addr, coalesce(m.from_name, ''), \
                            m.to_addrs::text, m.cc_addrs::text, m.message_id, \
                            m.body_text, m.body_html, m.is_deleted, m.held, \
                            coalesce(m.crypto_type = 'smime-encrypted', false) \
                       FROM public.messages m \
                      WHERE m.mailbox_id = $1 AND m.id = $2 \
                      ORDER BY m.received_at DESC LIMIT 1",
                    &params,
                )
                .await?
        };

        let Some(row) = rows.first() else {
            if let Some(ts) = entry.received_at {
                final_ops.insert(
                    DocumentKey::Mail {
                        mailbox_id: entry.scope_id,
                        id: entry.entity_id,
                        received_at: ts,
                    },
                    FinalOp::Delete,
                );
            }
            return Ok(());
        };

        let mailbox_id: i64 = col(row, 0)?;
        let id: i64 = col(row, 1)?;
        let received_at: DateTime<Utc> = col(row, 2)?;
        let subject: String = col(row, 3)?;
        let from_addr: String = col(row, 4)?;
        let from_name: String = col(row, 5)?;
        let to_json: String = col(row, 6)?;
        let cc_json: String = col(row, 7)?;
        let message_id: String = col(row, 8)?;
        let body_text: Option<String> = col(row, 9)?;
        let body_html: Option<String> = col(row, 10)?;
        let is_deleted: bool = col(row, 11)?;
        let held: bool = col(row, 12)?;
        let crypto_sealed: bool = col(row, 13)?;

        let key = DocumentKey::Mail {
            mailbox_id,
            id,
            received_at,
        };
        if is_deleted && !held {
            final_ops.insert(key, FinalOp::Delete);
            return Ok(());
        }
        let visibility = if is_deleted && held {
            SearchVisibility::ComplianceOnly
        } else {
            SearchVisibility::Live
        };

        let mut headers = Vec::new();
        if !from_addr.is_empty() {
            headers.push(from_addr.clone());
        }
        if !from_name.is_empty() {
            headers.push(from_name);
        }
        headers.extend(extract_json_address_strings(&to_json));
        headers.extend(extract_json_address_strings(&cc_json));

        let mut identifiers = Vec::new();
        if !message_id.is_empty() {
            identifiers.push(message_id);
        }
        if !from_addr.is_empty() {
            identifiers.push(from_addr);
        }

        // Hydrate attachments for this message.
        let att_params: [Param<'_>; 2] = [(&id, Type::INT8), (&received_at, Type::TIMESTAMPTZ)];
        let att_rows = self
            .db
            .query_typed(
                "SELECT ma.id, ma.blob_sha256, coalesce(ma.filename, ''), ma.content_type, \
                        et.extraction_status, et.extracted_text \
                   FROM public.message_attachments ma \
                   LEFT JOIN public.search_extracted_text et \
                     ON et.content_sha256 = ma.blob_sha256 \
                  WHERE ma.message_id = $1 AND ma.received_at = $2 \
                  ORDER BY ma.id ASC",
                &att_params,
            )
            .await?;

        let mut combined_body = String::new();
        if !crypto_sealed {
            if let Some(bt) = body_text.filter(|s| !s.trim().is_empty()) {
                combined_body.push_str(&bt);
            } else if let Some(bh) = body_html.filter(|s| !s.trim().is_empty()) {
                combined_body.push_str(&extract_html_text(&bh));
            }
        }

        for arow in att_rows {
            let att_id: i64 = col(&arow, 0)?;
            let blob_sha: String = col(&arow, 1)?;
            let filename: String = col(&arow, 2)?;
            let content_type: String = col(&arow, 3)?;
            let mut status_opt: Option<String> = col(&arow, 4)?;
            let mut text_opt: Option<String> = col(&arow, 5)?;

            if !crypto_sealed && status_opt.is_none() {
                if let Some(svc) = &self.extractor {
                    let req = SearchExtractPayload {
                        content_sha256: blob_sha.clone(),
                        storage_plane: ExtractionStoragePlane::Blob,
                        object_key: None,
                        drive_version_id: None,
                        content_type: Some(content_type.clone()),
                        filename: if filename.is_empty() {
                            None
                        } else {
                            Some(filename.clone())
                        },
                    };
                    // Propagate transient I/O & DB errors so WorkQueue retries cleanly.
                    let outcome = svc.extract_and_cache(&req).await?;
                    status_opt = Some(outcome.result.status.as_str().to_owned());
                    text_opt = outcome.result.extracted_text;
                }
            }

            let indexable_text = if crypto_sealed {
                None
            } else {
                status_opt
                    .as_deref()
                    .and_then(ExtractionStatus::parse)
                    .filter(|st| st.has_indexable_text())
                    .and(text_opt)
            };

            if !crypto_sealed {
                if !filename.is_empty() {
                    identifiers.push(filename.clone());
                    headers.push(filename.clone());
                }
                if let Some(ref txt) = indexable_text {
                    if !txt.is_empty() {
                        if !combined_body.is_empty() {
                            combined_body.push('\n');
                        }
                        combined_body.push_str(txt);
                    }
                }
            }

            let att_identifiers = if crypto_sealed || filename.is_empty() {
                Vec::new()
            } else {
                vec![filename.clone()]
            };
            let att_key = DocumentKey::MailAttachment {
                mailbox_id,
                id,
                received_at,
                sub_id: att_id,
            };
            final_ops.insert(
                att_key.clone(),
                FinalOp::Upsert(IndexDocument {
                    key: att_key,
                    visibility,
                    title: if crypto_sealed {
                        String::new()
                    } else {
                        filename.clone()
                    },
                    body: indexable_text,
                    headers: if crypto_sealed {
                        Vec::new()
                    } else {
                        headers.clone()
                    },
                    identifiers: att_identifiers,
                    sort_i64: received_at.timestamp_micros(),
                    sort_name: if crypto_sealed {
                        String::new()
                    } else {
                        filename
                    },
                    crypto_sealed,
                }),
            );
        }

        final_ops.insert(
            key.clone(),
            FinalOp::Upsert(IndexDocument {
                key,
                visibility,
                title: subject.clone(),
                body: if crypto_sealed || combined_body.is_empty() {
                    None
                } else {
                    Some(combined_body)
                },
                headers,
                identifiers,
                sort_i64: received_at.timestamp_micros(),
                sort_name: subject,
                crypto_sealed,
            }),
        );
        Ok(())
    }

    async fn hydrate_mail_attachment_doc(
        &self,
        entry: &OutboxEntry,
        final_ops: &mut HashMap<DocumentKey, FinalOp>,
    ) -> Result<(), SearchError> {
        let params: [Param<'_>; 1] = [(&entry.sub_id, Type::INT8)];
        let rows = self
            .db
            .query_typed(
                "SELECT m.mailbox_id, m.id, m.received_at, coalesce(m.subject, ''), \
                        m.from_addr, m.is_deleted, m.held, \
                        coalesce(m.crypto_type = 'smime-encrypted', false), \
                        ma.id, ma.blob_sha256, coalesce(ma.filename, ''), ma.content_type, \
                        et.extraction_status, et.extracted_text \
                   FROM public.message_attachments ma \
                   JOIN public.messages m \
                     ON m.id = ma.message_id AND m.received_at = ma.received_at \
                   LEFT JOIN public.search_extracted_text et \
                     ON et.content_sha256 = ma.blob_sha256 \
                  WHERE ma.id = $1",
                &params,
            )
            .await?;

        let Some(row) = rows.first() else {
            if let Some(ts) = entry.received_at {
                final_ops.insert(
                    DocumentKey::MailAttachment {
                        mailbox_id: entry.scope_id,
                        id: entry.entity_id,
                        received_at: ts,
                        sub_id: entry.sub_id,
                    },
                    FinalOp::Delete,
                );
            }
            return Ok(());
        };

        let mailbox_id: i64 = col(row, 0)?;
        let msg_id: i64 = col(row, 1)?;
        let received_at: DateTime<Utc> = col(row, 2)?;
        let subject: String = col(row, 3)?;
        let from_addr: String = col(row, 4)?;
        let is_deleted: bool = col(row, 5)?;
        let held: bool = col(row, 6)?;
        let crypto_sealed: bool = col(row, 7)?;
        let att_id: i64 = col(row, 8)?;
        let blob_sha: String = col(row, 9)?;
        let filename: String = col(row, 10)?;
        let content_type: String = col(row, 11)?;
        let mut status_opt: Option<String> = col(row, 12)?;
        let mut text_opt: Option<String> = col(row, 13)?;

        let key = DocumentKey::MailAttachment {
            mailbox_id,
            id: msg_id,
            received_at,
            sub_id: att_id,
        };
        if is_deleted && !held {
            final_ops.insert(key, FinalOp::Delete);
            return Ok(());
        }
        let visibility = if is_deleted && held {
            SearchVisibility::ComplianceOnly
        } else {
            SearchVisibility::Live
        };

        if !crypto_sealed && status_opt.is_none() {
            if let Some(svc) = &self.extractor {
                let req = SearchExtractPayload {
                    content_sha256: blob_sha,
                    storage_plane: ExtractionStoragePlane::Blob,
                    object_key: None,
                    drive_version_id: None,
                    content_type: Some(content_type),
                    filename: if filename.is_empty() {
                        None
                    } else {
                        Some(filename.clone())
                    },
                };
                let outcome = svc.extract_and_cache(&req).await?;
                status_opt = Some(outcome.result.status.as_str().to_owned());
                text_opt = outcome.result.extracted_text;
            }
        }

        let indexable_text = if crypto_sealed {
            None
        } else {
            status_opt
                .as_deref()
                .and_then(ExtractionStatus::parse)
                .filter(|st| st.has_indexable_text())
                .and(text_opt)
        };

        let mut headers = Vec::new();
        if !subject.is_empty() {
            headers.push(subject);
        }
        if !from_addr.is_empty() {
            headers.push(from_addr);
        }
        let identifiers = if crypto_sealed || filename.is_empty() {
            Vec::new()
        } else {
            vec![filename.clone()]
        };

        final_ops.insert(
            key.clone(),
            FinalOp::Upsert(IndexDocument {
                key,
                visibility,
                title: if crypto_sealed {
                    String::new()
                } else {
                    filename.clone()
                },
                body: indexable_text,
                headers: if crypto_sealed { Vec::new() } else { headers },
                identifiers,
                sort_i64: received_at.timestamp_micros(),
                sort_name: if crypto_sealed {
                    String::new()
                } else {
                    filename
                },
                crypto_sealed,
            }),
        );
        Ok(())
    }

    async fn hydrate_chat_doc(
        &self,
        entry: &OutboxEntry,
        final_ops: &mut HashMap<DocumentKey, FinalOp>,
    ) -> Result<(), SearchError> {
        let params: [Param<'_>; 1] = [(&entry.entity_id, Type::INT8)];
        let rows = self
            .db
            .query_typed(
                "SELECT cm.id, cm.channel_id, cm.body, cm.deleted_at, cm.created_at \
                   FROM public.chat_messages cm \
                  WHERE cm.id = $1",
                &params,
            )
            .await?;

        let Some(row) = rows.first() else {
            final_ops.insert(
                DocumentKey::Chat {
                    channel_id: entry.scope_id,
                    id: entry.entity_id,
                },
                FinalOp::Delete,
            );
            final_ops.insert(
                DocumentKey::Chat {
                    channel_id: entry.scope_id,
                    id: chat_revision_doc_id(entry.entity_id),
                },
                FinalOp::Delete,
            );
            return Ok(());
        };

        let id: i64 = col(row, 0)?;
        let channel_id: i64 = col(row, 1)?;
        let body: String = col(row, 2)?;
        let deleted_at: Option<DateTime<Utc>> = col(row, 3)?;
        let created_at: DateTime<Utc> = col(row, 4)?;

        let visibility = if deleted_at.is_some() {
            SearchVisibility::ComplianceOnly
        } else {
            SearchVisibility::Live
        };

        // Historical edited revisions (`chat_message_revisions`) are strictly
        // `SearchVisibility::ComplianceOnly` under a disjoint negative doc ID so
        // edited-away text NEVER leaks into `Live` user search.
        let rev_rows = self
            .db
            .query_typed(
                "SELECT r.prior_body FROM public.chat_message_revisions r \
                  WHERE r.message_id = $1 ORDER BY r.id ASC",
                &params,
            )
            .await?;
        let mut rev_parts = Vec::new();
        for rrow in rev_rows {
            let prior: String = col(&rrow, 0)?;
            if !prior.trim().is_empty() {
                rev_parts.push(prior);
            }
        }
        let rev_key = DocumentKey::Chat {
            channel_id,
            id: chat_revision_doc_id(id),
        };
        if rev_parts.is_empty() {
            final_ops.insert(rev_key, FinalOp::Delete);
        } else {
            final_ops.insert(
                rev_key.clone(),
                FinalOp::Upsert(IndexDocument {
                    key: rev_key,
                    visibility: SearchVisibility::ComplianceOnly,
                    title: String::new(),
                    body: Some(rev_parts.join("\n")),
                    headers: Vec::new(),
                    identifiers: vec![format!("chat_rev:{id}")],
                    sort_i64: created_at.timestamp_micros(),
                    sort_name: String::new(),
                    crypto_sealed: false,
                }),
            );
        }

        // Chat attachments (filename ALWAYS indexed + verified extracted text).
        let att_rows = self
            .db
            .query_typed(
                "SELECT cma.filename, cma.version_id, coalesce(cma.content_type, ''), \
                        dfv.content_sha256 \
                   FROM public.chat_message_attachments cma \
                   JOIN public.drive_file_versions dfv ON dfv.id = cma.version_id \
                  WHERE cma.message_id = $1 ORDER BY cma.ordinal ASC, cma.id ASC",
                &params,
            )
            .await?;

        let mut full_body = body;
        let mut headers = Vec::new();
        let mut identifiers = Vec::new();
        for arow in att_rows {
            let filename: String = col(&arow, 0)?;
            let version_id: i64 = col(&arow, 1)?;
            let content_type: String = col(&arow, 2)?;
            let sha: String = col(&arow, 3)?;

            if !filename.is_empty() {
                headers.push(filename.clone());
                identifiers.push(filename.clone());
            }

            let extracted = self
                .resolve_drive_version_text(
                    &sha,
                    version_id,
                    if content_type.is_empty() {
                        None
                    } else {
                        Some(content_type)
                    },
                    if filename.is_empty() {
                        None
                    } else {
                        Some(filename)
                    },
                )
                .await?;
            if let Some(txt) = extracted {
                if !txt.is_empty() {
                    if !full_body.is_empty() {
                        full_body.push('\n');
                    }
                    full_body.push_str(&txt);
                }
            }
        }

        let live_key = DocumentKey::Chat { channel_id, id };
        final_ops.insert(
            live_key.clone(),
            FinalOp::Upsert(IndexDocument {
                key: live_key,
                visibility,
                title: headers.first().cloned().unwrap_or_default(),
                body: if full_body.is_empty() {
                    None
                } else {
                    Some(full_body)
                },
                headers,
                identifiers,
                sort_i64: created_at.timestamp_micros(),
                sort_name: String::new(),
                crypto_sealed: false,
            }),
        );
        Ok(())
    }

    async fn hydrate_drive_doc(
        &self,
        entry: &OutboxEntry,
        final_ops: &mut HashMap<DocumentKey, FinalOp>,
    ) -> Result<(), SearchError> {
        let params: [Param<'_>; 1] = [(&entry.entity_id, Type::INT8)];
        let rows = self
            .db
            .query_typed(
                "SELECT dn.id, dn.space_id, dn.name, dn.deleted_at, dn.purged_at, dn.created_at, \
                        df.head_version_id, dfv.content_sha256, dfv.content_type \
                   FROM public.drive_nodes dn \
                   LEFT JOIN public.drive_files df ON df.node_id = dn.id \
                   LEFT JOIN public.drive_file_versions dfv ON dfv.id = df.head_version_id \
                  WHERE dn.id = $1",
                &params,
            )
            .await?;

        let Some(row) = rows.first() else {
            final_ops.insert(
                DocumentKey::Drive {
                    space_id: entry.scope_id,
                    id: entry.entity_id,
                },
                FinalOp::Delete,
            );
            return Ok(());
        };

        let id: i64 = col(row, 0)?;
        let space_id: i64 = col(row, 1)?;
        let name: String = col(row, 2)?;
        let deleted_at: Option<DateTime<Utc>> = col(row, 3)?;
        let purged_at: Option<DateTime<Utc>> = col(row, 4)?;
        let created_at: DateTime<Utc> = col(row, 5)?;
        let head_version_id: Option<i64> = col(row, 6)?;
        let sha_opt: Option<String> = col(row, 7)?;
        let ct_opt: Option<String> = col(row, 8)?;

        let key = DocumentKey::Drive { space_id, id };
        if purged_at.is_some() {
            final_ops.insert(key, FinalOp::Delete);
            if let Some(vid) = head_version_id {
                final_ops.insert(
                    DocumentKey::DriveFile {
                        space_id,
                        id,
                        sub_id: vid,
                    },
                    FinalOp::Delete,
                );
            }
            return Ok(());
        }
        let visibility = if deleted_at.is_some() {
            SearchVisibility::ComplianceOnly
        } else {
            SearchVisibility::Live
        };

        let indexable_text = match (sha_opt, head_version_id) {
            (Some(sha), Some(vid)) => {
                self.resolve_drive_version_text(&sha, vid, ct_opt, Some(name.clone()))
                    .await?
            }
            _ => None,
        };

        let identifiers = if name.is_empty() {
            Vec::new()
        } else {
            vec![name.clone()]
        };

        final_ops.insert(
            key.clone(),
            FinalOp::Upsert(IndexDocument {
                key,
                visibility,
                title: name.clone(),
                body: indexable_text.clone(),
                headers: Vec::new(),
                identifiers: identifiers.clone(),
                sort_i64: created_at.timestamp_micros(),
                sort_name: name.clone(),
                crypto_sealed: false,
            }),
        );

        if let Some(vid) = head_version_id {
            let file_key = DocumentKey::DriveFile {
                space_id,
                id,
                sub_id: vid,
            };
            final_ops.insert(
                file_key.clone(),
                FinalOp::Upsert(IndexDocument {
                    key: file_key,
                    visibility,
                    title: name.clone(),
                    body: indexable_text,
                    headers: Vec::new(),
                    identifiers,
                    sort_i64: created_at.timestamp_micros(),
                    sort_name: name,
                    crypto_sealed: false,
                }),
            );
        }
        Ok(())
    }

    async fn hydrate_drive_file_doc(
        &self,
        entry: &OutboxEntry,
        final_ops: &mut HashMap<DocumentKey, FinalOp>,
    ) -> Result<(), SearchError> {
        let version_id = entry.sub_id;
        let params: [Param<'_>; 1] = [(&version_id, Type::INT8)];
        let rows = self
            .db
            .query_typed(
                "SELECT dn.id, dn.space_id, dn.name, dn.deleted_at, dn.purged_at, \
                        dfv.id, dfv.content_sha256, dfv.content_type, dfv.created_at \
                   FROM public.drive_file_versions dfv \
                   JOIN public.drive_nodes dn ON dn.id = dfv.file_node_id \
                  WHERE dfv.id = $1",
                &params,
            )
            .await?;

        let Some(row) = rows.first() else {
            final_ops.insert(
                DocumentKey::DriveFile {
                    space_id: entry.scope_id,
                    id: entry.entity_id,
                    sub_id: entry.sub_id,
                },
                FinalOp::Delete,
            );
            return Ok(());
        };

        let node_id: i64 = col(row, 0)?;
        let space_id: i64 = col(row, 1)?;
        let name: String = col(row, 2)?;
        let deleted_at: Option<DateTime<Utc>> = col(row, 3)?;
        let purged_at: Option<DateTime<Utc>> = col(row, 4)?;
        let vid: i64 = col(row, 5)?;
        let sha: String = col(row, 6)?;
        let ct_opt: Option<String> = col(row, 7)?;
        let created_at: DateTime<Utc> = col(row, 8)?;

        let key = DocumentKey::DriveFile {
            space_id,
            id: node_id,
            sub_id: vid,
        };
        if purged_at.is_some() {
            final_ops.insert(key, FinalOp::Delete);
            return Ok(());
        }
        let visibility = if deleted_at.is_some() {
            SearchVisibility::ComplianceOnly
        } else {
            SearchVisibility::Live
        };

        let indexable_text = self
            .resolve_drive_version_text(&sha, vid, ct_opt, Some(name.clone()))
            .await?;

        let identifiers = if name.is_empty() {
            Vec::new()
        } else {
            vec![name.clone()]
        };

        final_ops.insert(
            key.clone(),
            FinalOp::Upsert(IndexDocument {
                key,
                visibility,
                title: name.clone(),
                body: indexable_text,
                headers: Vec::new(),
                identifiers,
                sort_i64: created_at.timestamp_micros(),
                sort_name: name,
                crypto_sealed: false,
            }),
        );
        Ok(())
    }

    /// Resolve extracted text for a Drive file version safely:
    /// always routes through `ContentExtractionService` (when present) so
    /// client-supplied `content_sha256` values are verified before reading or
    /// writing shared `search_extracted_text`, and propagates I/O/DB errors.
    async fn resolve_drive_version_text(
        &self,
        claimed_sha: &str,
        version_id: i64,
        content_type: Option<String>,
        filename: Option<String>,
    ) -> Result<Option<String>, SearchError> {
        if let Some(svc) = &self.extractor {
            let req = SearchExtractPayload {
                content_sha256: claimed_sha.to_owned(),
                storage_plane: ExtractionStoragePlane::DriveFileVersion,
                object_key: None,
                drive_version_id: Some(version_id),
                content_type,
                filename,
            };
            let outcome = svc.extract_and_cache(&req).await?;
            return Ok(if outcome.result.status.has_indexable_text() {
                outcome.result.extracted_text
            } else {
                None
            });
        }
        // Without an extraction service (cache-only mode), only trust cache for
        // server-verified single-chunk versions.
        let chunks = lookup_drive_version_chunks(self.db.as_ref(), version_id).await?;
        if chunks.len() == 1 && chunks[0].chunk_sha256 == claimed_sha {
            if let Some(cached) = lookup_extracted_cache(self.db.as_ref(), claimed_sha).await? {
                if cached.status.has_indexable_text() {
                    return Ok(cached.extracted_text);
                }
            }
        }
        Ok(None)
    }

    async fn materialize_scheduled_action_outbox(
        &self,
        entry: &OutboxEntry,
        final_ops: &mut HashMap<DocumentKey, FinalOp>,
        summary: &mut IndexBatchSummary,
    ) -> Result<(), SearchError> {
        let fallback_delete_key = match entry.corpus {
            DocCorpus::Chat => Some(DocumentKey::Chat {
                channel_id: entry.scope_id,
                id: entry.entity_id,
            }),
            DocCorpus::Mail => entry.received_at.map(|ts| DocumentKey::Mail {
                mailbox_id: entry.scope_id,
                id: entry.entity_id,
                received_at: ts,
            }),
            _ => None,
        };

        if entry.op == "delete" {
            if let Some(k) = fallback_delete_key {
                final_ops.insert(k, FinalOp::Delete);
            }
            return Ok(());
        }

        let rows = if let Some(ref aid) = entry.action_id {
            let params: [Param<'_>; 1] = [(aid, Type::TEXT)];
            self.db
                .query_typed(
                    "SELECT id::text, action_kind, fire_at, payload::text, status, mailbox_id \
                       FROM public.scheduled_actions \
                      WHERE id = $1::text::uuid",
                    &params,
                )
                .await?
        } else {
            let params: [Param<'_>; 1] = [(&entry.entity_id, Type::INT8)];
            self.db
                .query_typed(
                    "SELECT id::text, action_kind, fire_at, payload::text, status, mailbox_id \
                       FROM public.scheduled_actions \
                      WHERE public.search_scheduled_action_doc_id(id) = $1",
                    &params,
                )
                .await?
        };

        let Some(row) = rows.first() else {
            if let Some(k) = fallback_delete_key {
                final_ops.insert(k, FinalOp::Delete);
            }
            return Ok(());
        };

        if self
            .materialize_one_scheduled_action_row(row, final_ops)
            .await?
        {
            summary.scheduled_actions_indexed += 1;
        }
        Ok(())
    }

    async fn materialize_scheduled_actions_sweep(
        &self,
        limit: i32,
        skip_uuids: &HashSet<String>,
        final_ops: &mut HashMap<DocumentKey, FinalOp>,
    ) -> Result<usize, SearchError> {
        let lim = i64::from(limit);
        let params: [Param<'_>; 1] = [(&lim, Type::INT8)];
        let rows = self
            .db
            .query_typed(
                "SELECT id::text, action_kind, fire_at, payload::text, status, mailbox_id \
                   FROM public.scheduled_actions \
                  WHERE status IN ('pending', 'enqueued', 'processing', 'failed', 'done') \
                  ORDER BY updated_at DESC \
                  LIMIT $1",
                &params,
            )
            .await?;

        let mut indexed = 0usize;
        for row in rows {
            let id_str: String = col(&row, 0)?;
            if skip_uuids.contains(&id_str) {
                continue;
            }
            if self
                .materialize_one_scheduled_action_row(&row, final_ops)
                .await?
            {
                indexed += 1;
            }
        }
        Ok(indexed)
    }

    async fn materialize_one_scheduled_action_row(
        &self,
        row: &Row,
        final_ops: &mut HashMap<DocumentKey, FinalOp>,
    ) -> Result<bool, SearchError> {
        let id_str: String = col(row, 0)?;
        let action_kind: String = col(row, 1)?;
        let fire_at: DateTime<Utc> = col(row, 2)?;
        let payload_text: String = col(row, 3)?;
        let status: String = col(row, 4)?;
        let mailbox_id: Option<i64> = col(row, 5)?;

        let payload_json: serde_json::Value =
            serde_json::from_str(&payload_text).unwrap_or(serde_json::Value::Null);
        let neg_id = scheduled_action_doc_id(&id_str);

        let is_chat = action_kind.to_ascii_lowercase().contains("chat")
            || payload_json.get("channelId").is_some()
            || payload_json.get("channel_id").is_some();

        let doc_key = if is_chat {
            let channel_id =
                parse_json_i64(&payload_json, &["channelId", "channel_id"]).unwrap_or(0);
            DocumentKey::Chat {
                channel_id,
                id: neg_id,
            }
        } else {
            let mb = mailbox_id
                .or_else(|| parse_json_i64(&payload_json, &["mailbox_id", "mailboxId"]))
                .unwrap_or(0);
            DocumentKey::Mail {
                mailbox_id: mb,
                id: neg_id,
                received_at: fire_at,
            }
        };

        // Keep pending/enqueued/processing/failed indexed as ComplianceOnly; evict on 'done'.
        if !matches!(
            status.as_str(),
            "pending" | "enqueued" | "processing" | "failed"
        ) {
            final_ops.insert(doc_key, FinalOp::Delete);
            return Ok(false);
        }

        if !is_chat && action_kind == "send" {
            // Hydrate referenced draft from public.messages when available (respecting S/MIME).
            if let Some(doc) = self
                .hydrate_scheduled_mail_draft(
                    &doc_key,
                    &id_str,
                    &action_kind,
                    fire_at,
                    mailbox_id,
                    &payload_json,
                )
                .await?
            {
                final_ops.insert(doc_key, FinalOp::Upsert(doc));
                return Ok(true);
            }
        }

        let subject = payload_json
            .get("subject")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(&action_kind)
            .to_owned();
        let mut body_parts = Vec::new();
        for field in ["body", "body_text", "text", "message", "content"] {
            if let Some(s) = payload_json.get(field).and_then(serde_json::Value::as_str) {
                if !s.trim().is_empty() {
                    body_parts.push(s.to_owned());
                }
            }
        }
        if body_parts.is_empty() && !payload_text.is_empty() {
            body_parts.push(payload_text);
        }

        final_ops.insert(
            doc_key.clone(),
            FinalOp::Upsert(IndexDocument {
                key: doc_key,
                visibility: SearchVisibility::ComplianceOnly,
                title: subject.clone(),
                body: Some(body_parts.join("\n")),
                headers: vec![action_kind.clone()],
                identifiers: vec![id_str, action_kind],
                sort_i64: fire_at.timestamp_micros(),
                sort_name: subject,
                crypto_sealed: false,
            }),
        );
        Ok(true)
    }

    async fn hydrate_scheduled_mail_draft(
        &self,
        doc_key: &DocumentKey,
        action_uuid: &str,
        action_kind: &str,
        fire_at: DateTime<Utc>,
        mailbox_id: Option<i64>,
        payload_json: &serde_json::Value,
    ) -> Result<Option<IndexDocument>, SearchError> {
        let Some(msg_id) = parse_json_i64(payload_json, &["message_id", "messageId"]) else {
            return Ok(None);
        };
        let mb = mailbox_id
            .or_else(|| parse_json_i64(payload_json, &["mailbox_id", "mailboxId"]))
            .unwrap_or(0);
        let rec_opt = payload_json
            .get("received_at")
            .or_else(|| payload_json.get("receivedAt"))
            .and_then(serde_json::Value::as_str)
            .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
            .map(|dt| dt.with_timezone(&Utc));

        let rows = if let Some(ts) = rec_opt {
            let params: [Param<'_>; 3] = [
                (&mb, Type::INT8),
                (&msg_id, Type::INT8),
                (&ts, Type::TIMESTAMPTZ),
            ];
            self.db
                .query_typed(
                    "SELECT coalesce(m.subject, ''), m.from_addr, coalesce(m.from_name, ''), \
                            m.to_addrs::text, m.cc_addrs::text, m.body_text, m.body_html, \
                            coalesce(m.crypto_type = 'smime-encrypted', false) \
                       FROM public.messages m \
                      WHERE m.mailbox_id = $1 AND m.id = $2 AND m.received_at = $3",
                    &params,
                )
                .await?
        } else {
            let params: [Param<'_>; 2] = [(&mb, Type::INT8), (&msg_id, Type::INT8)];
            self.db
                .query_typed(
                    "SELECT coalesce(m.subject, ''), m.from_addr, coalesce(m.from_name, ''), \
                            m.to_addrs::text, m.cc_addrs::text, m.body_text, m.body_html, \
                            coalesce(m.crypto_type = 'smime-encrypted', false) \
                       FROM public.messages m \
                      WHERE m.mailbox_id = $1 AND m.id = $2 \
                      ORDER BY m.received_at DESC LIMIT 1",
                    &params,
                )
                .await?
        };

        let Some(row) = rows.first() else {
            return Ok(None);
        };

        let subject: String = col(row, 0)?;
        let from_addr: String = col(row, 1)?;
        let from_name: String = col(row, 2)?;
        let to_json: String = col(row, 3)?;
        let cc_json: String = col(row, 4)?;
        let body_text: Option<String> = col(row, 5)?;
        let body_html: Option<String> = col(row, 6)?;
        let crypto_sealed: bool = col(row, 7)?;

        let mut headers = vec![action_kind.to_owned()];
        if !from_addr.is_empty() {
            headers.push(from_addr.clone());
        }
        if !from_name.is_empty() {
            headers.push(from_name);
        }
        headers.extend(extract_json_address_strings(&to_json));
        headers.extend(extract_json_address_strings(&cc_json));

        let body = if crypto_sealed {
            None
        } else if let Some(bt) = body_text.filter(|s| !s.trim().is_empty()) {
            Some(bt)
        } else {
            body_html
                .filter(|s| !s.trim().is_empty())
                .map(|bh| extract_html_text(&bh))
        };

        Ok(Some(IndexDocument {
            key: doc_key.clone(),
            visibility: SearchVisibility::ComplianceOnly,
            title: subject.clone(),
            body,
            headers,
            identifiers: vec![action_uuid.to_owned(), action_kind.to_owned()],
            sort_i64: fire_at.timestamp_micros(),
            sort_name: subject,
            crypto_sealed,
        }))
    }
}

/// Deterministic strictly-negative `i64` document ID derived from a `scheduled_actions.id` UUID,
/// matching SQL `public.search_scheduled_action_doc_id(uuid)` bit-for-bit and guaranteed never
/// to collide with positive `IDENTITY`/`bigserial` IDs or [`chat_revision_doc_id`].
#[must_use]
pub fn scheduled_action_doc_id(action_uuid: &str) -> i64 {
    let mut hasher = Sha256::new();
    hasher.update(b"scheduled_action:");
    hasher.update(action_uuid.to_ascii_lowercase().as_bytes());
    let digest = hasher.finalize();
    let raw = u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]);
    let positive = (raw & 0x7FFF_FFFF_FFFF_FFFF).max(1) as i64;
    -positive
}

/// Deterministic strictly-negative `i64` document ID for a chat message's historical
/// `chat_message_revisions` compliance document, disjoint from positive `chat_messages.id`
/// and [`scheduled_action_doc_id`].
#[must_use]
pub fn chat_revision_doc_id(message_id: i64) -> i64 {
    let mut hasher = Sha256::new();
    hasher.update(b"chat_message_revisions:");
    hasher.update(message_id.to_string().as_bytes());
    let digest = hasher.finalize();
    let raw = u64::from_be_bytes([
        digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
    ]);
    let positive = (raw & 0x7FFF_FFFF_FFFF_FFFF).max(1) as i64;
    -positive
}

/// Ensure all 5 corpus rows exist in `public.search_index_watermarks` (`ON CONFLICT DO NOTHING`)
/// so the V291 write-capture triggers activate when `SETJOIN_SEARCH_TIER2_ENABLED=true`.
pub async fn ensure_search_watermarks_initialized(
    db: &dyn SearchPipelineDb,
) -> Result<(), SearchError> {
    let _ = db
        .query_typed(
            "INSERT INTO public.search_index_watermarks (corpus, epoch, generation, indexed_outbox_seq, schema_hash) \
             VALUES ('mail', 0, 0, 0, ''), \
                    ('mail_attachment', 0, 0, 0, ''), \
                    ('chat', 0, 0, 0, ''), \
                    ('drive', 0, 0, 0, ''), \
                    ('drive_file', 0, 0, 0, '') \
             ON CONFLICT (corpus) DO NOTHING",
            &[],
        )
        .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Internal DB & chunking helpers
// ---------------------------------------------------------------------------

struct OutboxEntry {
    seq: i64,
    corpus: DocCorpus,
    op: String,
    scope_id: i64,
    entity_id: i64,
    sub_id: i64,
    received_at: Option<DateTime<Utc>>,
    action_id: Option<String>,
}

struct DirtyKeyRef {
    corpus: DocCorpus,
    scope_id: i64,
    doc_id: i64,
    received_at_us: i64,
    sub_id: i64,
}

fn check_lease_alive(lease_lost: Option<&AtomicBool>) -> Result<(), SearchError> {
    if lease_lost.is_some_and(|flag| flag.load(Ordering::Acquire)) {
        return Err(SearchError::Unavailable(
            "workqueue lease lost during search indexing batch".to_owned(),
        ));
    }
    Ok(())
}

/// Normalize a `public.blobs.minio_ref` value into the bucket-scoped object key
/// expected by `ObjectStore::read` (matching `setjoin_backup::worker::resolve_primary_source_key`):
/// - `"<bucket>/<sha>"` (e.g. `"mailblobs/<sha>"`) -> `"<sha>"`
/// - `"blobs/<sha>"` -> `"blobs/<sha>"`
/// - `"<sha>"` -> `"<sha>"`
#[must_use]
pub fn normalize_blob_object_key(sha: &str, minio_ref: &str) -> String {
    let trimmed = minio_ref.trim().trim_start_matches('/');
    if trimmed.is_empty() || trimmed == sha {
        return sha.to_owned();
    }
    if let Some(rest) = trimmed.strip_suffix(sha) {
        if rest == "blobs/" {
            return format!("blobs/{sha}");
        }
        if let Some(prefix) = rest.strip_suffix('/') {
            if !prefix.is_empty() && !prefix.contains('/') {
                return sha.to_owned();
            }
        }
    }
    trimmed.to_owned()
}

/// Check whether any unprocessed `public.search_index_outbox` rows exist (for a
/// single corpus or across all corpora). Used by `SearchIndexConsumer` to prevent
/// lost wakeups when `WorkQueue` coalesces into an in-flight leased item.
pub async fn has_unprocessed_outbox_rows(
    db: &dyn SearchPipelineDb,
    corpus: Option<DocCorpus>,
) -> Result<bool, SearchError> {
    let rows = match corpus {
        Some(c) => {
            let cs = c.as_str();
            let params: [Param<'_>; 1] = [(&cs, Type::TEXT)];
            db.query_typed(
                "SELECT EXISTS ( \
                     SELECT 1 FROM public.search_index_outbox \
                      WHERE corpus = $1 AND processed_at IS NULL \
                 )",
                &params,
            )
            .await?
        }
        None => {
            db.query_typed(
                "SELECT EXISTS ( \
                     SELECT 1 FROM public.search_index_outbox \
                      WHERE processed_at IS NULL \
                 )",
                &[],
            )
            .await?
        }
    };
    match rows.first() {
        Some(r) => col(r, 0),
        None => Ok(false),
    }
}

/// Return per-corpus counts of remaining unindexed work (`unprocessed outbox` +
/// `search_dirty_keys`) for every corpus that currently has backlog > 0.
pub async fn unprocessed_counts_by_corpus(
    db: &dyn SearchPipelineDb,
) -> Result<HashMap<DocCorpus, u64>, SearchError> {
    let rows = db
        .query_typed(
            "SELECT corpus, SUM(cnt)::bigint FROM ( \
                 SELECT corpus, count(*) AS cnt \
                   FROM public.search_index_outbox \
                  WHERE processed_at IS NULL \
                  GROUP BY corpus \
                 UNION ALL \
                 SELECT corpus, count(*) AS cnt \
                   FROM public.search_dirty_keys \
                  GROUP BY corpus \
             ) t \
             GROUP BY corpus",
            &[],
        )
        .await?;
    let mut out = HashMap::new();
    for row in rows {
        let raw: String = col(&row, 0)?;
        let cnt: i64 = col(&row, 1)?;
        if let Some(corpus) = DocCorpus::parse(&raw) {
            if cnt > 0 {
                out.insert(corpus, cnt as u64);
            }
        }
    }
    Ok(out)
}

fn clamp_document_to_budget(mut doc: IndexDocument) -> IndexDocument {
    // Ensure NO single document can ever exceed UPSERT_CHUNK_MAX_BYTES (12 MiB).
    let max_body = crate::config::MAX_DOC_BODY_BYTES;
    if let Some(body) = doc.body.take() {
        let (clamped, _) = truncate_utf8_owned(body, max_body);
        doc.body = Some(clamped);
    }
    if estimate_doc_bytes(&doc) <= UPSERT_CHUNK_MAX_BYTES {
        return doc;
    }
    let (title, _) = truncate_utf8_owned(doc.title, 65_536);
    doc.title = title;
    let (sort_name, _) = truncate_utf8_owned(doc.sort_name, 4_096);
    doc.sort_name = sort_name;
    let mut hdr_budget = 262_144usize;
    let mut kept_headers = Vec::new();
    for h in doc.headers {
        if hdr_budget == 0 {
            break;
        }
        let (ch, _) = truncate_utf8_owned(h, hdr_budget);
        hdr_budget = hdr_budget.saturating_sub(ch.len());
        kept_headers.push(ch);
    }
    doc.headers = kept_headers;
    let mut id_budget = 262_144usize;
    let mut kept_ids = Vec::new();
    for id in doc.identifiers {
        if id_budget == 0 {
            break;
        }
        let (ci, _) = truncate_utf8_owned(id, id_budget);
        id_budget = id_budget.saturating_sub(ci.len());
        kept_ids.push(ci);
    }
    doc.identifiers = kept_ids;
    let overhead = estimate_doc_bytes(&IndexDocument {
        body: None,
        ..doc.clone()
    });
    let remaining_body = UPSERT_CHUNK_MAX_BYTES.saturating_sub(overhead);
    if let Some(body) = doc.body.take() {
        let (clamped, _) = truncate_utf8_owned(body, remaining_body);
        doc.body = Some(clamped);
    }
    doc
}

fn estimate_doc_bytes(doc: &IndexDocument) -> usize {
    let headers_bytes: usize = doc.headers.iter().map(String::len).sum();
    let ident_bytes: usize = doc.identifiers.iter().map(String::len).sum();
    doc.title
        .len()
        .saturating_add(doc.body.as_ref().map_or(0, String::len))
        .saturating_add(headers_bytes)
        .saturating_add(ident_bytes)
        .saturating_add(doc.sort_name.len())
        .saturating_add(64)
}

fn chunk_index_documents(docs: &[IndexDocument]) -> Vec<&[IndexDocument]> {
    let mut chunks = Vec::new();
    let mut start = 0usize;
    while start < docs.len() {
        let mut end = start;
        let mut bytes = 0usize;
        while end < docs.len() && (end - start) < UPSERT_CHUNK_MAX_DOCS {
            let doc_bytes = estimate_doc_bytes(&docs[end]);
            if end > start && bytes.saturating_add(doc_bytes) > UPSERT_CHUNK_MAX_BYTES {
                break;
            }
            bytes = bytes.saturating_add(doc_bytes);
            end += 1;
        }
        chunks.push(&docs[start..end]);
        start = end;
    }
    chunks
}

fn parse_json_i64(val: &serde_json::Value, keys: &[&str]) -> Option<i64> {
    for &k in keys {
        if let Some(v) = val.get(k) {
            if let Some(n) = v.as_i64() {
                return Some(n);
            }
            if let Some(s) = v.as_str() {
                if let Ok(n) = s.trim().parse::<i64>() {
                    return Some(n);
                }
            }
        }
    }
    None
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn col<T: for<'a> tokio_postgres::types::FromSql<'a>>(
    row: &Row,
    idx: usize,
) -> Result<T, SearchError> {
    row.try_get(idx)
        .map_err(|e| SearchError::Database(format!("column {idx} decode failed: {e}")))
}

fn is_valid_sha256(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

async fn lookup_extracted_cache(
    db: &dyn SearchPipelineDb,
    sha: &str,
) -> Result<Option<ExtractionResult>, SearchError> {
    let params: [Param<'_>; 1] = [(&sha, Type::TEXT)];
    let rows = db
        .query_typed(
            "SELECT extraction_status, extractor_version, extracted_text, extracted_bytes, \
                    detected_mime, error_code \
               FROM public.search_extracted_text \
              WHERE content_sha256 = $1",
            &params,
        )
        .await?;
    let Some(row) = rows.first() else {
        return Ok(None);
    };
    let status_raw: String = col(row, 0)?;
    let status = ExtractionStatus::parse(&status_raw)
        .ok_or_else(|| SearchError::Database(format!("unknown extraction_status: {status_raw}")))?;
    let extractor_version: i16 = col(row, 1)?;
    let extracted_text: Option<String> = col(row, 2)?;
    let extracted_bytes: i32 = col(row, 3)?;
    let detected_mime: Option<String> = col(row, 4)?;
    let error_code: Option<String> = col(row, 5)?;
    Ok(Some(ExtractionResult {
        status,
        extractor_version,
        extracted_text,
        extracted_bytes: extracted_bytes.max(0) as usize,
        detected_mime,
        error_code,
    }))
}

async fn persist_extracted_cache(
    db: &dyn SearchPipelineDb,
    sha: &str,
    plane: ExtractionStoragePlane,
    result: &ExtractionResult,
) -> Result<(), SearchError> {
    let plane_str = plane.as_str();
    let status_str = result.status.as_str();
    let extracted_bytes = i32::try_from(result.extracted_bytes).unwrap_or(i32::MAX);
    let params: [Param<'_>; 8] = [
        (&sha, Type::TEXT),
        (&plane_str, Type::TEXT),
        (&status_str, Type::TEXT),
        (&result.extractor_version, Type::INT2),
        (&result.extracted_text, Type::TEXT),
        (&extracted_bytes, Type::INT4),
        (&result.detected_mime, Type::TEXT),
        (&result.error_code, Type::TEXT),
    ];
    let _ = db
        .query_typed(
            "INSERT INTO public.search_extracted_text ( \
                 content_sha256, storage_plane, extraction_status, extractor_version, \
                 extracted_text, extracted_bytes, detected_mime, error_code, \
                 extracted_at, updated_at \
             ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, now(), now()) \
             ON CONFLICT (content_sha256) DO UPDATE \
                 SET extraction_status = EXCLUDED.extraction_status, \
                     extractor_version = EXCLUDED.extractor_version, \
                     extracted_text    = EXCLUDED.extracted_text, \
                     extracted_bytes   = EXCLUDED.extracted_bytes, \
                     detected_mime     = EXCLUDED.detected_mime, \
                     error_code        = EXCLUDED.error_code, \
                     updated_at        = now() \
               WHERE public.search_extracted_text.extractor_version < EXCLUDED.extractor_version",
            &params,
        )
        .await?;
    Ok(())
}

async fn resolve_blob_object_key(
    db: &dyn SearchPipelineDb,
    sha: &str,
) -> Result<String, SearchError> {
    let params: [Param<'_>; 1] = [(&sha, Type::TEXT)];
    let rows = db
        .query_typed(
            "SELECT minio_ref FROM public.blobs WHERE sha256 = $1",
            &params,
        )
        .await?;
    if let Some(row) = rows.first() {
        let minio_ref: String = col(row, 0)?;
        if !minio_ref.is_empty() {
            return Ok(normalize_blob_object_key(sha, &minio_ref));
        }
    }
    Ok(sha.to_owned())
}

async fn lookup_blob_size(
    db: &dyn SearchPipelineDb,
    sha: &str,
) -> Result<Option<i64>, SearchError> {
    let params: [Param<'_>; 1] = [(&sha, Type::TEXT)];
    let rows = db
        .query_typed(
            "SELECT size_bytes FROM public.blobs WHERE sha256 = $1",
            &params,
        )
        .await?;
    match rows.first() {
        Some(row) => Ok(Some(col(row, 0)?)),
        None => Ok(None),
    }
}

async fn resolve_drive_version_id(
    db: &dyn SearchPipelineDb,
    sha: &str,
) -> Result<Option<i64>, SearchError> {
    let params: [Param<'_>; 1] = [(&sha, Type::TEXT)];
    let rows = db
        .query_typed(
            "SELECT id FROM public.drive_file_versions \
              WHERE content_sha256 = $1 ORDER BY id DESC LIMIT 1",
            &params,
        )
        .await?;
    match rows.first() {
        Some(row) => Ok(Some(col(row, 0)?)),
        None => Ok(None),
    }
}

async fn lookup_drive_version_size(
    db: &dyn SearchPipelineDb,
    version_id: i64,
) -> Result<Option<i64>, SearchError> {
    let params: [Param<'_>; 1] = [(&version_id, Type::INT8)];
    let rows = db
        .query_typed(
            "SELECT size_bytes FROM public.drive_file_versions WHERE id = $1",
            &params,
        )
        .await?;
    match rows.first() {
        Some(row) => Ok(Some(col(row, 0)?)),
        None => Ok(None),
    }
}

async fn lookup_drive_version_chunks(
    db: &dyn SearchPipelineDb,
    version_id: i64,
) -> Result<Vec<DriveChunkRef>, SearchError> {
    let params: [Param<'_>; 1] = [(&version_id, Type::INT8)];
    let rows = db
        .query_typed(
            "SELECT vc.chunk_sha256, dc.storage_ref \
               FROM public.drive_version_chunks vc \
               JOIN public.drive_chunks dc \
                 ON dc.scope_key = vc.scope_key AND dc.sha256 = vc.chunk_sha256 \
              WHERE vc.version_id = $1 AND vc.stream = 'content' \
              ORDER BY vc.ordinal ASC",
            &params,
        )
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        out.push(DriveChunkRef {
            chunk_sha256: col(&row, 0)?,
            storage_ref: col(&row, 1)?,
        });
    }
    Ok(out)
}

async fn current_watermark_cursor(
    db: &dyn SearchPipelineDb,
    corpus: DocCorpus,
) -> Result<(i64, i64), SearchError> {
    let c = corpus.as_str();
    let params: [Param<'_>; 1] = [(&c, Type::TEXT)];
    let rows = db
        .query_typed(
            "SELECT epoch, indexed_outbox_seq FROM public.search_index_watermarks WHERE corpus = $1",
            &params,
        )
        .await?;
    match rows.first() {
        Some(row) => Ok((col(row, 0)?, col(row, 1)?)),
        None => Ok((0, 0)),
    }
}

async fn claim_outbox_batch(
    db: &dyn SearchPipelineDb,
    corpus: DocCorpus,
    after_seq: i64,
    limit: i32,
) -> Result<Vec<OutboxEntry>, SearchError> {
    let c = corpus.as_str();
    let params: [Param<'_>; 3] = [
        (&c, Type::TEXT),
        (&after_seq, Type::INT8),
        (&limit, Type::INT4),
    ];
    let rows = db
        .query_typed(
            "SELECT seq, corpus, op, scope_id, entity_id, sub_id, received_at, action_id::text \
               FROM public.search_outbox_claim_batch($1, $2, $3)",
            &params,
        )
        .await?;
    let mut out = Vec::with_capacity(rows.len());
    for row in rows {
        let corpus_raw: String = col(&row, 1)?;
        let parsed = DocCorpus::parse(&corpus_raw)
            .ok_or_else(|| SearchError::Database(format!("invalid outbox corpus: {corpus_raw}")))?;
        out.push(OutboxEntry {
            seq: col(&row, 0)?,
            corpus: parsed,
            op: col(&row, 2)?,
            scope_id: col(&row, 3)?,
            entity_id: col(&row, 4)?,
            sub_id: col(&row, 5)?,
            received_at: col(&row, 6)?,
            action_id: col(&row, 7)?,
        });
    }
    Ok(out)
}

async fn current_db_timestamp(db: &dyn SearchPipelineDb) -> Result<DateTime<Utc>, SearchError> {
    let rows = db.query_typed("SELECT now()", &[]).await?;
    let row = rows
        .first()
        .ok_or_else(|| SearchError::Database("SELECT now() returned no rows".into()))?;
    col(row, 0)
}

async fn mark_outbox_processed(
    db: &dyn SearchPipelineDb,
    seqs: &[i64],
) -> Result<i32, SearchError> {
    if seqs.is_empty() {
        return Ok(0);
    }
    let owned: Vec<i64> = seqs.to_vec();
    let params: [Param<'_>; 1] = [(&owned, Type::INT8_ARRAY)];
    let rows = db
        .query_typed("SELECT public.search_outbox_mark_processed($1)", &params)
        .await?;
    let row = rows.first().ok_or_else(|| {
        SearchError::Database("search_outbox_mark_processed returned no rows".into())
    })?;
    col(row, 0)
}

async fn contiguous_processed_seq(
    db: &dyn SearchPipelineDb,
    corpus: DocCorpus,
    max_claimed_seq: i64,
) -> Result<i64, SearchError> {
    let c = corpus.as_str();
    let params: [Param<'_>; 2] = [(&c, Type::TEXT), (&max_claimed_seq, Type::INT8)];
    let rows = db
        .query_typed(
            "SELECT GREATEST( \
                 0::bigint, \
                 COALESCE( \
                     (SELECT MIN(o.seq) - 1 FROM public.search_index_outbox o \
                       WHERE o.corpus = $1 AND o.processed_at IS NULL), \
                     $2 \
                 ) \
             )::bigint",
            &params,
        )
        .await?;
    let row = rows
        .first()
        .ok_or_else(|| SearchError::Database("contiguous_processed_seq returned no rows".into()))?;
    col(row, 0)
}

#[allow(clippy::too_many_arguments)]
async fn fenced_settle_batch(
    db: &dyn SearchPipelineDb,
    node_id: &str,
    fencing_token: i64,
    seqs: &[i64],
    corpus: DocCorpus,
    epoch: i64,
    generation: i64,
    indexed_outbox_seq: i64,
    schema_hash: &str,
) -> Result<(bool, i64, i64), SearchError> {
    let seqs_vec = seqs.to_vec();
    let c = corpus.as_str();
    let params: [Param<'_>; 8] = [
        (&node_id, Type::TEXT),
        (&fencing_token, Type::INT8),
        (&seqs_vec, Type::INT8_ARRAY),
        (&c, Type::TEXT),
        (&epoch, Type::INT8),
        (&generation, Type::INT8),
        (&indexed_outbox_seq, Type::INT8),
        (&schema_hash, Type::TEXT),
    ];
    let rows = db
        .query_typed(
            "SELECT settled, returned_epoch, committed_outbox_seq \
               FROM public.search_fenced_settle_batch($1, $2, $3, $4, $5, $6, $7, $8)",
            &params,
        )
        .await?;
    let row = rows.first().ok_or_else(|| {
        SearchError::Database("search_fenced_settle_batch returned no rows".into())
    })?;
    Ok((col(row, 0)?, col(row, 1)?, col(row, 2)?))
}

async fn advance_watermark(
    db: &dyn SearchPipelineDb,
    corpus: DocCorpus,
    epoch: i64,
    generation: i64,
    indexed_outbox_seq: i64,
    schema_hash: &str,
) -> Result<(i64, i64), SearchError> {
    let c = corpus.as_str();
    let params: [Param<'_>; 5] = [
        (&c, Type::TEXT),
        (&epoch, Type::INT8),
        (&generation, Type::INT8),
        (&indexed_outbox_seq, Type::INT8),
        (&schema_hash, Type::TEXT),
    ];
    let rows = db
        .query_typed(
            "SELECT epoch, indexed_outbox_seq FROM public.search_watermark_advance($1, $2, $3, $4, $5)",
            &params,
        )
        .await?;
    let row = rows
        .first()
        .ok_or_else(|| SearchError::Database("search_watermark_advance returned no rows".into()))?;
    Ok((col(row, 0)?, col(row, 1)?))
}

async fn delete_processed_dirty_keys(
    db: &dyn SearchPipelineDb,
    keys: &[DirtyKeyRef],
    batch_started_at: DateTime<Utc>,
) -> Result<(), SearchError> {
    if keys.is_empty() {
        return Ok(());
    }
    let corpora: Vec<String> = keys.iter().map(|k| k.corpus.as_str().to_owned()).collect();
    let scope_ids: Vec<i64> = keys.iter().map(|k| k.scope_id).collect();
    let doc_ids: Vec<i64> = keys.iter().map(|k| k.doc_id).collect();
    let received_us: Vec<i64> = keys.iter().map(|k| k.received_at_us).collect();
    let sub_ids: Vec<i64> = keys.iter().map(|k| k.sub_id).collect();
    let params: [Param<'_>; 6] = [
        (&corpora, Type::TEXT_ARRAY),
        (&scope_ids, Type::INT8_ARRAY),
        (&doc_ids, Type::INT8_ARRAY),
        (&received_us, Type::INT8_ARRAY),
        (&sub_ids, Type::INT8_ARRAY),
        (&batch_started_at, Type::TIMESTAMPTZ),
    ];
    let _ = db
        .query_typed(
            "DELETE FROM public.search_dirty_keys d \
              USING unnest($1::text[], $2::bigint[], $3::bigint[], $4::bigint[], $5::bigint[]) \
                    AS p(corpus, scope_id, doc_id, received_at_us, sub_id) \
              WHERE d.corpus = p.corpus \
                AND d.scope_id = p.scope_id \
                AND d.doc_id = p.doc_id \
                AND d.received_at_us = p.received_at_us \
                AND d.sub_id = p.sub_id \
                AND d.dirty_at <= $6",
            &params,
        )
        .await?;
    Ok(())
}

async fn count_remaining_unindexed(
    db: &dyn SearchPipelineDb,
    corpus: DocCorpus,
) -> Result<(u64, u64), SearchError> {
    let c = corpus.as_str();
    let params: [Param<'_>; 1] = [(&c, Type::TEXT)];
    let rows = db
        .query_typed(
            "SELECT \
                 (SELECT count(*) FROM public.search_index_outbox o WHERE o.corpus = $1 AND o.processed_at IS NULL)::bigint, \
                 (SELECT count(*) FROM public.search_dirty_keys d WHERE d.corpus = $1)::bigint",
            &params,
        )
        .await?;
    let (outbox_count, dirty_count): (i64, i64) = match rows.first() {
        Some(r) => (col(r, 0)?, col(r, 1)?),
        None => (0, 0),
    };
    Ok((outbox_count.max(0) as u64, dirty_count.max(0) as u64))
}

fn extract_json_address_strings(raw_json: &str) -> Vec<String> {
    let Ok(val) = serde_json::from_str::<serde_json::Value>(raw_json) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if let Some(arr) = val.as_array() {
        for item in arr {
            if let Some(s) = item.as_str() {
                if !s.trim().is_empty() {
                    out.push(s.trim().to_owned());
                }
            } else if let Some(obj) = item.as_object() {
                for key in ["email", "address", "name"] {
                    if let Some(s) = obj.get(key).and_then(serde_json::Value::as_str) {
                        if !s.trim().is_empty() {
                            out.push(s.trim().to_owned());
                        }
                    }
                }
            }
        }
    }
    out
}

/// Enqueue one outbox entry through `public.search_outbox_enqueue(...)`.
#[allow(clippy::too_many_arguments)]
pub async fn enqueue_outbox(
    db: &dyn SearchPipelineDb,
    corpus: DocCorpus,
    op: &str,
    scope_id: i64,
    entity_id: i64,
    sub_id: i64,
    received_at: Option<DateTime<Utc>>,
    content_sha256: Option<&str>,
) -> Result<i64, SearchError> {
    let c = corpus.as_str();
    let params: [Param<'_>; 7] = [
        (&c, Type::TEXT),
        (&op, Type::TEXT),
        (&scope_id, Type::INT8),
        (&entity_id, Type::INT8),
        (&sub_id, Type::INT8),
        (&received_at, Type::TIMESTAMPTZ),
        (&content_sha256, Type::TEXT),
    ];
    let rows = db
        .query_typed(
            "SELECT public.search_outbox_enqueue($1, $2, $3, $4, $5, $6, $7)",
            &params,
        )
        .await?;
    let row = rows
        .first()
        .ok_or_else(|| SearchError::Database("search_outbox_enqueue returned no rows".into()))?;
    col(row, 0)
}
