//! Embedded MIT `tantivy` Tier-2 candidate engine (`TantivySearchEngine`).
//!
//! Enforces:
//! - Zero plaintext body storage (only `doc_key` is `STORED`).
//! - S/MIME `V029` C7 encryption boundary (`crypto_sealed == true` omits body text,
//!   omits attachment titles/non-envelope identifiers, and indexes cleartext envelope headers only).
//! - Hard writer heap cap `<= 50_000_000` bytes (`writer_threads = 1`, `num_merge_threads = 1`,
//!   `LogMergePolicy`, bounded in-flight ingest byte/doc limits including `sort_name`).
//! - Private local storage (`0o700` on Unix, `CURRENT` atomic JSON manifest, `rebuild.lock`
//!   advisory lock, `epochs/index-vNNNNNN/` `MmapDirectory`), strictly outside `PGDATA` and `pg_dump`.
//! - Atomic `(reader, generation)` swap via `ArcSwap`, reader-safe deferred epoch cleanup on drop,
//!   single shared `Instant` deadline across `Semaphore(4)` + `spawn_blocking` + `catch_unwind`.

use crate::config::{SearchConfig, MAX_DOC_BODY_BYTES, MAX_INFLIGHT_BYTES, MAX_INFLIGHT_DOCS};
use crate::model::{
    BoxFuture, CandidateBatch, CandidateQuery, CursorBinding, DocumentKey, EngineHealth,
    IndexDocument, OpaqueCursor, PurgeCompactionReport, SearchEngine, SearchError, SearchIndexer,
    SearchTier,
};
use crate::tokenizers::{
    register_tokenizers, CjkBigramTokenizer, IdentExactTokenizer, ZhJiebaTokenizer,
    CJK_BIGRAM_TOKENIZER, IDENT_EXACT_TOKENIZER, ZH_JIEBA_TOKENIZER,
};
use crate::two_tier::FreshnessFence;
use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tantivy::collector::TopDocs;
use tantivy::directory::error::{DeleteError, LockError, OpenReadError, OpenWriteError};
use tantivy::directory::{
    Directory, DirectoryLock, FileHandle, FileSlice, Lock, MmapDirectory, WatchCallback,
    WatchHandle, WritePtr,
};
use tantivy::indexer::{IndexWriterOptions, LogMergePolicy};
use tantivy::query::{BooleanQuery, Occur, Query, TermQuery};
use tantivy::schema::{
    Field, IndexRecordOption, Schema, SchemaBuilder, TextFieldIndexing, TextOptions, Value, FAST,
    INDEXED, STORED, STRING,
};
use tantivy::{Index, IndexReader, IndexWriter, ReloadPolicy, TantivyDocument, Term};
use tokio::sync::Semaphore;
use tokio::time::Instant;

/// Logical schema version stamped into `CURRENT`'s `schema_hash`.
const SCHEMA_SPEC_DESCRIPTOR: &str = "setjoin-search-schema-v1:doc_key(STRING|STORED),corpus(STRING),visibility(STRING),scope_key(STRING),sort_i64(I64|INDEXED|FAST),sort_name(STRING|FAST),crypto_sealed(U64|INDEXED|FAST),title_tokens(zh_jieba),body_tokens(zh_jieba|pos),cjk_grams(cjk_bigram),identifiers(ident_exact)";

/// Deterministic SHA-256 hash of the Tantivy schema & tokenizer layout.
#[must_use]
pub fn schema_hash() -> String {
    let mut hasher = Sha256::new();
    hasher.update(SCHEMA_SPEC_DESCRIPTOR.as_bytes());
    hex::encode(hasher.finalize())
}

/// JSON manifest persisted atomically to `<index_dir>/CURRENT`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochManifest {
    pub epoch: u64,
    pub schema_hash: String,
    pub generation: u64,
    pub watermark_ts: Option<DateTime<Utc>>,
    pub clean_shutdown: bool,
}

/// Inspection summary of the active on-disk Tantivy epoch (used by `mailctl search verify`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochInspectStats {
    pub epoch: u64,
    pub generation: u64,
    pub schema_hash: String,
    pub schema_matches: bool,
    pub clean_shutdown: bool,
    pub num_docs: u64,
    pub num_segments: usize,
}

/// Strictly read-only [`Directory`] wrapper around [`MmapDirectory`] used by
/// [`TantivySearchEngine::open_read_only`] (`mailctl search verify`).
///
/// Performs ZERO filesystem write, create, lock-file, or delete syscalls (works
/// even on `chmod 0500` read-only epoch directories).
#[derive(Clone, Debug)]
struct ReadOnlyDirectory {
    inner: MmapDirectory,
}

impl Directory for ReadOnlyDirectory {
    fn get_file_handle(&self, path: &Path) -> Result<Arc<dyn FileHandle>, OpenReadError> {
        self.inner.get_file_handle(path)
    }

    fn open_read(&self, path: &Path) -> Result<FileSlice, OpenReadError> {
        self.inner.open_read(path)
    }

    fn delete(&self, path: &Path) -> Result<(), DeleteError> {
        Err(DeleteError::IoError {
            io_error: Arc::new(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "read-only search directory refuses delete",
            )),
            filepath: path.to_path_buf(),
        })
    }

    fn exists(&self, path: &Path) -> Result<bool, OpenReadError> {
        self.inner.exists(path)
    }

    fn open_write(&self, path: &Path) -> Result<WritePtr, OpenWriteError> {
        Err(OpenWriteError::IoError {
            io_error: Arc::new(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "read-only search directory refuses open_write",
            )),
            filepath: path.to_path_buf(),
        })
    }

    fn atomic_read(&self, path: &Path) -> Result<Vec<u8>, OpenReadError> {
        self.inner.atomic_read(path)
    }

    fn atomic_write(&self, _path: &Path, _data: &[u8]) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "read-only search directory refuses atomic_write",
        ))
    }

    fn sync_directory(&self) -> io::Result<()> {
        Ok(())
    }

    fn acquire_lock(&self, _lock: &Lock) -> Result<DirectoryLock, LockError> {
        Ok(DirectoryLock::from(Box::new(())))
    }

    fn watch(&self, _watch_callback: WatchCallback) -> tantivy::Result<WatchHandle> {
        Ok(WatchHandle::empty())
    }
}

/// Active streaming staging handle for online zero-downtime epoch rebuilds
/// (`begin_rebuild` -> `add_batch`* -> `commit_rebuild`).
///
/// Stages into a unique private `epochs/.staging-{pid}-{seq}-{rand}` directory so
/// concurrent rebuilds never collide; `commit_rebuild` assigns the authoritative
/// epoch number and renames into `epochs/index-vNNNNNN` strictly under `rebuild.lock`.
/// Drops any uncommitted staging directory automatically if aborted before commit.
pub struct StagingEpoch {
    min_epoch: u64,
    staging_dir: PathBuf,
    fields: SearchFields,
    writer: Option<IndexWriter<TantivyDocument>>,
    docs_added: usize,
    committed: bool,
}

impl StagingEpoch {
    /// Minimum target epoch number requested when staging started.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.min_epoch
    }

    /// Total documents staged into this epoch so far.
    #[must_use]
    pub const fn docs_added(&self) -> usize {
        self.docs_added
    }

    /// Append a validated batch of documents into the staging epoch without
    /// touching the live `CURRENT` manifest or active reader.
    pub fn add_batch(&mut self, docs: &[IndexDocument]) -> Result<usize, SearchError> {
        if docs.is_empty() {
            return Ok(0);
        }
        validate_batch_bounds(docs)?;
        let Some(writer) = self.writer.as_mut() else {
            return Err(SearchError::Internal(
                "staging epoch writer already finalized".to_owned(),
            ));
        };
        for doc in docs {
            let tdoc = build_tantivy_document(self.fields, doc);
            writer
                .add_document(tdoc)
                .map_err(|e| SearchError::Internal(format!("tantivy staging add_document: {e}")))?;
        }
        self.docs_added = self.docs_added.saturating_add(docs.len());
        Ok(docs.len())
    }
}

impl Drop for StagingEpoch {
    fn drop(&mut self) {
        self.writer.take();
        if !self.committed && self.staging_dir.exists() {
            let _ = fs::remove_dir_all(&self.staging_dir);
        }
    }
}

#[derive(Clone, Copy)]
struct SearchFields {
    doc_key: Field,
    corpus: Field,
    visibility: Field,
    scope_key: Field,
    sort_i64: Field,
    sort_name: Field,
    crypto_sealed: Field,
    title_tokens: Field,
    body_tokens: Field,
    cjk_grams: Field,
    identifiers: Field,
}

fn build_schema() -> (Schema, SearchFields) {
    let mut builder = SchemaBuilder::default();

    let doc_key = builder.add_text_field("doc_key", STRING | STORED);
    let corpus = builder.add_text_field("corpus", STRING);
    let visibility = builder.add_text_field("visibility", STRING);
    let scope_key = builder.add_text_field("scope_key", STRING);
    let sort_i64 = builder.add_i64_field("sort_i64", INDEXED | FAST);
    let sort_name = builder.add_text_field("sort_name", STRING | FAST);
    let crypto_sealed = builder.add_u64_field("crypto_sealed", INDEXED | FAST);

    // Indexed-only text fields — NEVER STORED (snippets always hydrated from PG).
    let zh_title_opts = TextOptions::default().set_indexing_options(
        TextFieldIndexing::default()
            .set_tokenizer(ZH_JIEBA_TOKENIZER)
            .set_index_option(IndexRecordOption::WithFreqsAndPositions),
    );
    let zh_body_opts = TextOptions::default().set_indexing_options(
        TextFieldIndexing::default()
            .set_tokenizer(ZH_JIEBA_TOKENIZER)
            .set_index_option(IndexRecordOption::WithFreqsAndPositions),
    );
    let cjk_opts = TextOptions::default().set_indexing_options(
        TextFieldIndexing::default()
            .set_tokenizer(CJK_BIGRAM_TOKENIZER)
            .set_index_option(IndexRecordOption::WithFreqs),
    );
    let ident_opts = TextOptions::default().set_indexing_options(
        TextFieldIndexing::default()
            .set_tokenizer(IDENT_EXACT_TOKENIZER)
            .set_index_option(IndexRecordOption::WithFreqs),
    );

    let title_tokens = builder.add_text_field("title_tokens", zh_title_opts);
    let body_tokens = builder.add_text_field("body_tokens", zh_body_opts);
    let cjk_grams = builder.add_text_field("cjk_grams", cjk_opts);
    let identifiers = builder.add_text_field("identifiers", ident_opts);

    let fields = SearchFields {
        doc_key,
        corpus,
        visibility,
        scope_key,
        sort_i64,
        sort_name,
        crypto_sealed,
        title_tokens,
        body_tokens,
        cjk_grams,
        identifiers,
    };
    (builder.build(), fields)
}

/// An immutable, atomically published `(reader, generation, epoch)` snapshot.
///
/// When superseded by an epoch swap, `cleanup_on_drop` is armed so the old epoch
/// directory is removed ONLY after the final in-flight reader `Arc` drops.
pub(crate) struct LoadedEpoch {
    pub(crate) manifest: EpochManifest,
    index: Index,
    reader: IndexReader,
    fields: SearchFields,
    epoch_dir: PathBuf,
    cleanup_on_drop: AtomicBool,
    active_epochs: Arc<Mutex<HashMap<u64, usize>>>,
}

impl LoadedEpoch {
    fn mark_for_cleanup(&self) {
        self.cleanup_on_drop.store(true, Ordering::Release);
    }
}

impl Drop for LoadedEpoch {
    fn drop(&mut self) {
        let mut should_remove = false;
        if let Ok(mut map) = self.active_epochs.lock() {
            if let Some(count) = map.get_mut(&self.manifest.epoch) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    map.remove(&self.manifest.epoch);
                    should_remove = self.cleanup_on_drop.load(Ordering::Acquire);
                }
            }
        }
        if should_remove && self.epoch_dir.exists() {
            let _ = fs::remove_dir_all(&self.epoch_dir);
        }
    }
}

struct SharedState {
    config: SearchConfig,
    loaded: ArcSwap<Option<LoadedEpoch>>,
    active_epochs: Arc<Mutex<HashMap<u64, usize>>>,
    health_error: Mutex<Option<String>>,
    write_mutex: Mutex<()>,
    search_semaphore: Arc<Semaphore>,
    tmp_seq: AtomicU64,
    #[cfg(test)]
    inject_panic: AtomicBool,
    #[cfg(test)]
    inject_delay_ms: AtomicU64,
}

/// Embedded Tantivy Tier-2 candidate engine.
pub struct TantivySearchEngine {
    state: Arc<SharedState>,
}

impl TantivySearchEngine {
    /// Open an existing healthy epoch from `config.index_dir/CURRENT`, or start
    /// cleanly in a degraded state (triggering Tier-1 fallback) if missing/corrupt.
    #[must_use]
    pub fn open_or_degraded(config: SearchConfig) -> Self {
        let clamped_config = config
            .clone()
            .with_writer_heap_bytes(config.writer_heap_bytes);
        let permits = clamped_config.max_concurrent_searches.max(1);
        let state = Arc::new(SharedState {
            config: clamped_config,
            loaded: ArcSwap::from_pointee(None),
            active_epochs: Arc::new(Mutex::new(HashMap::new())),
            health_error: Mutex::new(None),
            write_mutex: Mutex::new(()),
            search_semaphore: Arc::new(Semaphore::new(permits)),
            tmp_seq: AtomicU64::new(1),
            #[cfg(test)]
            inject_panic: AtomicBool::new(false),
            #[cfg(test)]
            inject_delay_ms: AtomicU64::new(0),
        });
        let engine = Self { state };
        if let Err(err) = engine.try_load_current() {
            engine.state.set_degraded(err.to_string());
        }
        engine
    }

    /// Strictly read-only open for `mailctl search verify`: parses `CURRENT` and opens
    /// the active Tantivy epoch WITHOUT running crash recovery, WITHOUT mutating `CURRENT`,
    /// and WITHOUT touching `rebuild.lock`.
    pub fn open_read_only(config: SearchConfig) -> Result<Self, SearchError> {
        let clamped_config = config
            .clone()
            .with_writer_heap_bytes(config.writer_heap_bytes);
        let permits = clamped_config.max_concurrent_searches.max(1);
        let state = Arc::new(SharedState {
            config: clamped_config,
            loaded: ArcSwap::from_pointee(None),
            active_epochs: Arc::new(Mutex::new(HashMap::new())),
            health_error: Mutex::new(None),
            write_mutex: Mutex::new(()),
            search_semaphore: Arc::new(Semaphore::new(permits)),
            tmp_seq: AtomicU64::new(1),
            #[cfg(test)]
            inject_panic: AtomicBool::new(false),
            #[cfg(test)]
            inject_delay_ms: AtomicU64::new(0),
        });
        let engine = Self { state };
        engine.try_load_current_read_only()?;
        Ok(engine)
    }

    fn try_load_current_read_only(&self) -> Result<EpochManifest, SearchError> {
        let current_path = self.state.current_manifest_path();
        if !current_path.exists() {
            return Err(SearchError::Unavailable(format!(
                "search epoch manifest not built at {}",
                current_path.display()
            )));
        }
        let raw = fs::read(&current_path)
            .map_err(|e| SearchError::CorruptIndex(format!("read CURRENT: {e}")))?;
        let manifest: EpochManifest = serde_json::from_slice(&raw)
            .map_err(|e| SearchError::CorruptIndex(format!("parse CURRENT JSON: {e}")))?;
        if manifest.schema_hash != schema_hash() {
            return Err(SearchError::CorruptIndex(format!(
                "schema_hash mismatch: manifest={} expected={}",
                manifest.schema_hash,
                schema_hash()
            )));
        }
        let epoch_dir = self.state.epoch_dir_path(manifest.epoch);
        let loaded = open_loaded_epoch_with_mode(
            &epoch_dir,
            manifest.clone(),
            self.state.config.zh_dict_path.clone(),
            Arc::clone(&self.state.active_epochs),
            true,
        )?;
        self.state.loaded.store(Arc::new(Some(loaded)));
        self.state.clear_degraded();
        Ok(manifest)
    }

    /// Reload `CURRENT` from disk if another process (such as online `mailctl search rebuild`)
    /// atomically published a strictly newer epoch (`disk_epoch > loaded_epoch`).
    ///
    /// Returns `Ok(true)` if a newer epoch was loaded into `ArcSwap`, or `Ok(false)` if
    /// the in-memory epoch is already up-to-date. Old readers keep using their `Arc<LoadedEpoch>`
    /// safely until dropped.
    pub fn reload_if_disk_epoch_advanced(&self) -> Result<bool, SearchError> {
        let Some(disk) = self.state.read_disk_manifest() else {
            return Ok(false);
        };
        let loaded_epoch = self
            .state
            .loaded
            .load()
            .as_ref()
            .as_ref()
            .map_or(0, |e| e.manifest.epoch);
        if disk.epoch <= loaded_epoch {
            return Ok(false);
        }
        let _guard = self
            .state
            .write_mutex
            .lock()
            .map_err(|_| SearchError::Internal("write mutex poisoned".to_owned()))?;
        let current_loaded_epoch = self
            .state
            .loaded
            .load()
            .as_ref()
            .as_ref()
            .map_or(0, |e| e.manifest.epoch);
        let Some(fresh_disk) = self.state.read_disk_manifest() else {
            return Ok(false);
        };
        if fresh_disk.epoch <= current_loaded_epoch {
            return Ok(false);
        }
        if fresh_disk.schema_hash != schema_hash() {
            return Err(SearchError::CorruptIndex(format!(
                "schema_hash mismatch on reload: manifest={} expected={}",
                fresh_disk.schema_hash,
                schema_hash()
            )));
        }
        let epoch_dir = self.state.epoch_dir_path(fresh_disk.epoch);
        let reloaded = open_loaded_epoch(
            &epoch_dir,
            fresh_disk,
            self.state.config.zh_dict_path.clone(),
            Arc::clone(&self.state.active_epochs),
        )?;
        let next_dir = reloaded.epoch_dir.clone();
        let old_slot = self.state.loaded.swap(Arc::new(Some(reloaded)));
        if let Some(old) = old_slot.as_ref().as_ref() {
            if old.epoch_dir != next_dir {
                old.mark_for_cleanup();
            }
        }
        drop(old_slot);
        self.state.clear_degraded();
        Ok(true)
    }

    /// Return the effective clamped writer heap budget (`<= 50_000_000` bytes).
    #[must_use]
    pub fn effective_writer_heap_bytes(&self) -> usize {
        self.state.config.effective_writer_heap_bytes()
    }

    /// Return the currently active epoch manifest, if a healthy epoch is loaded.
    #[must_use]
    pub fn current_manifest(&self) -> Option<EpochManifest> {
        self.state
            .loaded
            .load()
            .as_ref()
            .as_ref()
            .map(|e| e.manifest.clone())
    }

    /// Return the path to `<index_dir>/CURRENT`.
    #[must_use]
    pub fn current_manifest_path(&self) -> PathBuf {
        self.state.current_manifest_path()
    }

    /// Return the path to `<index_dir>/epochs/index-vNNNNNN`.
    #[must_use]
    pub fn epoch_dir_path(&self, epoch: u64) -> PathBuf {
        self.state.epoch_dir_path(epoch)
    }

    /// Attempt to load or reload the epoch pointed to by `CURRENT`.
    pub fn try_load_current(&self) -> Result<EpochManifest, SearchError> {
        let current_path = self.state.current_manifest_path();
        if !current_path.exists() {
            return Err(SearchError::Unavailable(format!(
                "search epoch manifest not built at {}",
                current_path.display()
            )));
        }
        let raw = fs::read(&current_path)
            .map_err(|e| SearchError::CorruptIndex(format!("read CURRENT: {e}")))?;
        let mut manifest: EpochManifest = serde_json::from_slice(&raw)
            .map_err(|e| SearchError::CorruptIndex(format!("parse CURRENT JSON: {e}")))?;
        if manifest.schema_hash != schema_hash() {
            return Err(SearchError::CorruptIndex(format!(
                "schema_hash mismatch: manifest={} expected={}",
                manifest.schema_hash,
                schema_hash()
            )));
        }
        // Crash recovery: if a previous writer crashed between Tantivy commit and
        // CURRENT persistence (clean_shutdown == false), bump generation so new
        // index contents can never be paired with a stale generation or cursor.
        if !manifest.clean_shutdown {
            manifest.generation = manifest.generation.saturating_add(1);
            manifest.clean_shutdown = true;
            if let Ok(_lock) = self.state.acquire_rebuild_lock() {
                let _ = self.state.write_manifest_atomic(&manifest);
            }
        }
        let epoch_dir = self.state.epoch_dir_path(manifest.epoch);
        let loaded = open_loaded_epoch(
            &epoch_dir,
            manifest.clone(),
            self.state.config.zh_dict_path.clone(),
            Arc::clone(&self.state.active_epochs),
        )?;
        self.state.loaded.store(Arc::new(Some(loaded)));
        self.state.clear_degraded();
        Ok(manifest)
    }

    /// Atomically build a new epoch `index-v<N+1>`, validate its reader, fsync +
    /// atomic-rename `CURRENT`, swap `ArcSwap`, and defer old epoch deletion until
    /// all in-flight readers drop.
    pub fn rebuild_epoch(
        &self,
        docs: &[IndexDocument],
        generation: u64,
        watermark_ts: Option<DateTime<Utc>>,
    ) -> Result<EpochManifest, SearchError> {
        self.state
            .rebuild_epoch_sync(docs, generation, watermark_ts)
    }

    /// Begin a streaming online zero-downtime epoch rebuild (`epochs/index-v{N+1}`).
    /// Live reads against the current epoch remain completely uninterrupted until
    /// [`Self::commit_rebuild`] atomically swaps `CURRENT`.
    pub fn begin_rebuild(&self) -> Result<StagingEpoch, SearchError> {
        self.state.begin_rebuild_sync(1)
    }

    /// Begin a streaming online zero-downtime epoch rebuild ensuring the staged epoch
    /// is at least `min_epoch` (used by `mailctl search rebuild` to stay strictly ahead
    /// of existing PostgreSQL `search_index_watermarks.epoch` even on a freshly wiped disk).
    pub fn begin_rebuild_at_min_epoch(&self, min_epoch: u64) -> Result<StagingEpoch, SearchError> {
        self.state.begin_rebuild_sync(min_epoch.max(1))
    }

    /// Finalize, validate, and atomically publish a staged online epoch rebuild
    /// (prunes obsolete unreferenced epochs in-process).
    pub fn commit_rebuild(
        &self,
        staging: StagingEpoch,
        watermark_ts: Option<DateTime<Utc>>,
    ) -> Result<EpochManifest, SearchError> {
        self.state.commit_rebuild_sync(staging, watermark_ts, true)
    }

    /// Finalize, validate, and atomically publish a staged online epoch rebuild
    /// WITHOUT immediately unlinking the previous epoch directory (used by external
    /// `mailctl search rebuild` while a live gateway process may still hold readers
    /// on the previous epoch).
    pub fn commit_rebuild_online(
        &self,
        staging: StagingEpoch,
        watermark_ts: Option<DateTime<Utc>>,
    ) -> Result<EpochManifest, SearchError> {
        self.state.commit_rebuild_sync(staging, watermark_ts, false)
    }

    /// Sweep any unreferenced stale `epochs/index-vNNNNNN` directories not pinned
    /// by `CURRENT` or active readers, returning the number of directories removed.
    #[must_use]
    pub fn garbage_collect_stale_epochs(&self) -> usize {
        self.state.garbage_collect_stale_epochs_sync()
    }

    /// Inspect `CURRENT` and the active on-disk Tantivy epoch (`mailctl search verify`).
    pub fn inspect_epoch(&self) -> Result<EpochInspectStats, SearchError> {
        self.state.inspect_epoch_sync()
    }

    /// Check whether an exact [`DocumentKey`] currently exists in the loaded epoch.
    pub fn contains_doc_key(&self, key: &DocumentKey) -> Result<bool, SearchError> {
        self.state.contains_doc_key_sync(key)
    }

    /// Execute candidate search against a single atomic `(reader, generation)` snapshot
    /// ONLY if `fence.is_corpus_fresh(query.corpus, snapshot.generation)` holds.
    pub async fn candidates_if_fresh(
        &self,
        query: &CandidateQuery,
        fence: &dyn FreshnessFence,
    ) -> Result<CandidateBatch, SearchError> {
        let snapshot = self.load_snapshot();
        let Some(loaded) = snapshot.as_ref().as_ref() else {
            return Err(SearchError::Unavailable(
                "no active Tantivy epoch loaded".to_owned(),
            ));
        };
        let loaded_gen = loaded.manifest.generation;
        if !fence.is_corpus_fresh(query.corpus, loaded_gen).await {
            return Err(SearchError::Unavailable(format!(
                "corpus {:?} is not fresh at generation {loaded_gen}",
                query.corpus
            )));
        }
        self.candidates_on_snapshot(snapshot, query).await
    }

    /// Physically evict purged document keys and compact segments so purged bytes
    /// are overwritten/removed from disk rather than lingering in unmerged segments.
    pub async fn evict_and_compact(
        &self,
        keys: &[DocumentKey],
    ) -> Result<PurgeCompactionReport, SearchError> {
        <Self as SearchIndexer>::evict_and_compact(self, keys).await
    }

    /// Inspect stored field names on the active schema (used to verify zero plaintext storage).
    #[must_use]
    pub fn stored_field_names(&self) -> Vec<String> {
        let (schema, _) = build_schema();
        schema
            .fields()
            .filter(|(_, entry)| entry.is_stored())
            .map(|(_, entry)| entry.name().to_owned())
            .collect()
    }

    /// Load the current atomic `(reader, generation)` snapshot for paired freshness + search,
    /// seamlessly picking up any strictly newer epoch published on disk by online rebuild.
    pub(crate) fn load_snapshot(&self) -> Arc<Option<LoadedEpoch>> {
        let _ = self.reload_if_disk_epoch_advanced();
        self.state.loaded.load_full()
    }

    /// Execute candidate search strictly against a pre-loaded snapshot (eliminating TOCTOU
    /// between freshness-fence validation and reader execution).
    pub(crate) async fn candidates_on_snapshot(
        &self,
        snapshot: Arc<Option<LoadedEpoch>>,
        query: &CandidateQuery,
    ) -> Result<CandidateBatch, SearchError> {
        self.state.candidates_on_snapshot(snapshot, query).await
    }

    #[cfg(test)]
    pub(crate) fn set_inject_panic(&self, on: bool) {
        self.state.inject_panic.store(on, Ordering::SeqCst);
    }

    #[cfg(test)]
    pub(crate) fn set_inject_delay_ms(&self, ms: u64) {
        self.state.inject_delay_ms.store(ms, Ordering::SeqCst);
    }
}

impl SharedState {
    fn current_manifest_path(&self) -> PathBuf {
        self.config.index_dir.join("CURRENT")
    }

    fn epoch_dir_path(&self, epoch: u64) -> PathBuf {
        self.config
            .index_dir
            .join("epochs")
            .join(format!("index-v{epoch:06}"))
    }

    fn ensure_private_index_dir(&self) -> Result<(), SearchError> {
        fs::create_dir_all(&self.config.index_dir)
            .map_err(|e| SearchError::Io(format!("create index_dir: {e}")))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::Permissions::from_mode(0o700);
            fs::set_permissions(&self.config.index_dir, perms)
                .map_err(|e| SearchError::Io(format!("chmod 0700 index_dir: {e}")))?;
        }
        Ok(())
    }

    fn read_disk_manifest(&self) -> Option<EpochManifest> {
        let raw = fs::read(self.current_manifest_path()).ok()?;
        serde_json::from_slice(&raw).ok()
    }

    fn acquire_rebuild_lock(&self) -> Result<File, SearchError> {
        self.ensure_private_index_dir()?;
        let lock_path = self.config.index_dir.join("rebuild.lock");
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lock_path)
            .map_err(|e| SearchError::Io(format!("open rebuild.lock: {e}")))?;
        file.try_lock()
            .map_err(|e| SearchError::Unavailable(format!("rebuild.lock busy: {e}")))?;
        Ok(file)
    }

    fn write_manifest_atomic(&self, manifest: &EpochManifest) -> Result<(), SearchError> {
        self.ensure_private_index_dir()?;
        let seq = self.tmp_seq.fetch_add(1, Ordering::Relaxed);
        let tmp_name = format!("CURRENT.tmp.{}.{seq}", std::process::id());
        let tmp_path = self.config.index_dir.join(tmp_name);
        let target_path = self.current_manifest_path();

        let bytes = serde_json::to_vec_pretty(manifest)
            .map_err(|e| SearchError::Internal(format!("serialize CURRENT: {e}")))?;
        let write_result = (|| -> Result<(), SearchError> {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .open(&tmp_path)
                .map_err(|e| SearchError::Io(format!("create CURRENT.tmp: {e}")))?;
            file.write_all(&bytes)
                .map_err(|e| SearchError::Io(format!("write CURRENT.tmp: {e}")))?;
            file.sync_all()
                .map_err(|e| SearchError::Io(format!("fsync CURRENT.tmp: {e}")))?;
            drop(file);
            fs::rename(&tmp_path, &target_path)
                .map_err(|e| SearchError::Io(format!("atomic rename CURRENT: {e}")))?;
            Ok(())
        })();

        if let Err(err) = write_result {
            let _ = fs::remove_file(&tmp_path);
            return Err(err);
        }
        if let Ok(dir) = File::open(&self.config.index_dir) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    fn prune_stale_orphan_epochs(&self, active_epoch: u64, previous_epoch: Option<u64>) {
        let epochs_dir = self.config.index_dir.join("epochs");
        let Ok(entries) = fs::read_dir(&epochs_dir) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            let Some(num_str) = name.strip_prefix("index-v") else {
                continue;
            };
            let Ok(num) = num_str.parse::<u64>() else {
                continue;
            };
            let in_use = self
                .active_epochs
                .lock()
                .ok()
                .and_then(|m| m.get(&num).copied())
                .unwrap_or(0)
                > 0;
            if !in_use
                && num != active_epoch
                && Some(num) != previous_epoch
                && num + 1 < active_epoch
            {
                let _ = fs::remove_dir_all(&path);
            }
        }
    }

    fn rebuild_epoch_sync(
        &self,
        docs: &[IndexDocument],
        generation: u64,
        watermark_ts: Option<DateTime<Utc>>,
    ) -> Result<EpochManifest, SearchError> {
        // Validate batch bounds BEFORE creating any directory or touching disk.
        validate_batch_bounds(docs)?;

        let _guard = self
            .write_mutex
            .lock()
            .map_err(|_| SearchError::Internal("write mutex poisoned".to_owned()))?;
        let _lock_file = self.acquire_rebuild_lock()?;

        // Always read the latest CURRENT manifest from disk under rebuild.lock so
        // both epoch and generation advance strictly monotonically.
        let disk_manifest = self.read_disk_manifest();
        let disk_epoch = disk_manifest.as_ref().map_or(0, |m| m.epoch);
        let disk_gen = disk_manifest.as_ref().map_or(0, |m| m.generation);
        let loaded_snap = self.loaded.load();
        let mem_epoch = loaded_snap
            .as_ref()
            .as_ref()
            .map_or(0, |e| e.manifest.epoch);
        let mem_gen = loaded_snap
            .as_ref()
            .as_ref()
            .map_or(0, |e| e.manifest.generation);
        drop(loaded_snap);

        let next_epoch = disk_epoch.max(mem_epoch).saturating_add(1);
        let next_generation = generation.max(disk_gen.max(mem_gen).saturating_add(1));
        let next_dir = self.epoch_dir_path(next_epoch);
        if next_dir.exists() {
            fs::remove_dir_all(&next_dir)
                .map_err(|e| SearchError::Io(format!("clean stale epoch dir: {e}")))?;
        }
        fs::create_dir_all(&next_dir)
            .map_err(|e| SearchError::Io(format!("create epoch dir: {e}")))?;

        let build_result = (|| -> Result<LoadedEpoch, SearchError> {
            let (schema, fields) = build_schema();
            let mmap_dir = MmapDirectory::open(&next_dir)
                .map_err(|e| SearchError::Io(format!("open MmapDirectory: {e}")))?;
            let index = Index::create(mmap_dir, schema, tantivy::IndexSettings::default())
                .map_err(|e| SearchError::Io(format!("create Tantivy index: {e}")))?;
            register_tokenizers(&index, self.config.zh_dict_path.clone());

            {
                let mut writer =
                    create_bounded_writer(&index, self.config.effective_writer_heap_bytes())?;
                for doc in docs {
                    let tdoc = build_tantivy_document(fields, doc);
                    writer
                        .add_document(tdoc)
                        .map_err(|e| SearchError::Internal(format!("tantivy add_document: {e}")))?;
                }
                writer
                    .commit()
                    .map_err(|e| SearchError::Io(format!("tantivy commit: {e}")))?;
                writer
                    .wait_merging_threads()
                    .map_err(|e| SearchError::Io(format!("tantivy wait_merging_threads: {e}")))?;
            }

            let manifest = EpochManifest {
                epoch: next_epoch,
                schema_hash: schema_hash(),
                generation: next_generation,
                watermark_ts,
                clean_shutdown: true,
            };

            // Validate by opening a fresh MmapDirectory + IndexReader before publishing CURRENT.
            let validated = open_loaded_epoch(
                &next_dir,
                manifest,
                self.config.zh_dict_path.clone(),
                Arc::clone(&self.active_epochs),
            )?;
            self.write_manifest_atomic(&validated.manifest)?;
            Ok(validated)
        })();

        let validated = match build_result {
            Ok(v) => v,
            Err(err) => {
                let _ = fs::remove_dir_all(&next_dir);
                return Err(err);
            }
        };

        let manifest_out = validated.manifest.clone();
        let old_slot = self.loaded.swap(Arc::new(Some(validated)));
        self.clear_degraded();

        // Reader-safe deferred cleanup: mark the superseded epoch so it is unlinked
        // only when the last Arc<LoadedEpoch> (including any in-flight search) drops.
        let prev_epoch_for_prune = old_slot.as_ref().as_ref().map(|old| {
            if old.epoch_dir != next_dir {
                old.mark_for_cleanup();
            }
            old.manifest.epoch
        });
        drop(old_slot);
        self.prune_stale_orphan_epochs(next_epoch, prev_epoch_for_prune);

        Ok(manifest_out)
    }

    fn begin_rebuild_sync(&self, min_epoch: u64) -> Result<StagingEpoch, SearchError> {
        // Stage into a unique private directory under `epochs/.staging-...` WITHOUT
        // holding `rebuild.lock` so live writers and concurrent rebuilds never block
        // or collide. Authoritative epoch numbering and atomic rename into
        // `epochs/index-vNNNNNN` happen strictly under `rebuild.lock` in `commit_rebuild_sync`.
        let epochs_dir = self.config.index_dir.join("epochs");
        fs::create_dir_all(&epochs_dir)
            .map_err(|e| SearchError::Io(format!("create epochs dir: {e}")))?;

        let seq = self.tmp_seq.fetch_add(1, Ordering::Relaxed);
        let mut rand_bytes = [0u8; 8];
        let _ = ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut rand_bytes);
        let rand_hex = hex::encode(rand_bytes);
        let staging_dir =
            epochs_dir.join(format!(".staging-{}-{seq}-{rand_hex}", std::process::id()));
        fs::create_dir_all(&staging_dir)
            .map_err(|e| SearchError::Io(format!("create private staging dir: {e}")))?;

        let (schema, fields) = build_schema();
        let mmap_dir = MmapDirectory::open(&staging_dir)
            .map_err(|e| SearchError::Io(format!("open staging MmapDirectory: {e}")))?;
        let index = Index::create(mmap_dir, schema, tantivy::IndexSettings::default())
            .map_err(|e| SearchError::Io(format!("create staging Tantivy index: {e}")))?;
        register_tokenizers(&index, self.config.zh_dict_path.clone());
        let writer = create_bounded_writer(&index, self.config.effective_writer_heap_bytes())?;

        Ok(StagingEpoch {
            min_epoch: min_epoch.max(1),
            staging_dir,
            fields,
            writer: Some(writer),
            docs_added: 0,
            committed: false,
        })
    }

    fn commit_rebuild_sync(
        &self,
        mut staging: StagingEpoch,
        watermark_ts: Option<DateTime<Utc>>,
        prune_old: bool,
    ) -> Result<EpochManifest, SearchError> {
        let _guard = self
            .write_mutex
            .lock()
            .map_err(|_| SearchError::Internal("write mutex poisoned".to_owned()))?;

        if let Some(mut writer) = staging.writer.take() {
            writer
                .commit()
                .map_err(|e| SearchError::Io(format!("tantivy staging commit: {e}")))?;
            writer
                .wait_merging_threads()
                .map_err(|e| SearchError::Io(format!("tantivy staging merge wait: {e}")))?;
        }

        // Acquire `rebuild.lock` strictly around authoritative epoch allocation,
        // atomic directory rename into `epochs/index-vNNNNNN`, and `CURRENT` swap.
        let _lock = self.acquire_rebuild_lock()?;
        let disk_manifest = self.read_disk_manifest();
        let disk_epoch = disk_manifest.as_ref().map_or(0, |m| m.epoch);
        let disk_gen = disk_manifest.as_ref().map_or(0, |m| m.generation);
        let loaded_snap = self.loaded.load();
        let mem_epoch = loaded_snap
            .as_ref()
            .as_ref()
            .map_or(0, |e| e.manifest.epoch);
        let mem_gen = loaded_snap
            .as_ref()
            .as_ref()
            .map_or(0, |e| e.manifest.generation);
        drop(loaded_snap);

        let next_epoch = disk_epoch
            .max(mem_epoch)
            .saturating_add(1)
            .max(staging.min_epoch);
        let final_gen = disk_gen.max(mem_gen).saturating_add(1);
        let final_dir = self.epoch_dir_path(next_epoch);
        if final_dir.exists() {
            fs::remove_dir_all(&final_dir)
                .map_err(|e| SearchError::Io(format!("clean target epoch dir: {e}")))?;
        }
        fs::rename(&staging.staging_dir, &final_dir)
            .map_err(|e| SearchError::Io(format!("rename staging epoch dir: {e}")))?;
        staging.staging_dir = final_dir.clone();

        let manifest = EpochManifest {
            epoch: next_epoch,
            schema_hash: schema_hash(),
            generation: final_gen,
            watermark_ts,
            clean_shutdown: true,
        };

        let validated = open_loaded_epoch(
            &final_dir,
            manifest,
            self.config.zh_dict_path.clone(),
            Arc::clone(&self.active_epochs),
        )?;
        self.write_manifest_atomic(&validated.manifest)?;
        staging.committed = true;

        let manifest_out = validated.manifest.clone();
        let next_dir = final_dir;
        let old_slot = self.loaded.swap(Arc::new(Some(validated)));
        self.clear_degraded();

        if prune_old {
            let prev_epoch_for_prune = old_slot.as_ref().as_ref().map(|old| {
                if old.epoch_dir != next_dir {
                    old.mark_for_cleanup();
                }
                old.manifest.epoch
            });
            drop(old_slot);
            self.prune_stale_orphan_epochs(next_epoch, prev_epoch_for_prune);
        } else {
            drop(old_slot);
        }
        Ok(manifest_out)
    }

    fn garbage_collect_stale_epochs_sync(&self) -> usize {
        let current_epoch = self
            .read_disk_manifest()
            .map(|m| m.epoch)
            .or_else(|| {
                self.loaded
                    .load()
                    .as_ref()
                    .as_ref()
                    .map(|e| e.manifest.epoch)
            })
            .unwrap_or(0);
        let epochs_dir = self.config.index_dir.join("epochs");
        let Ok(entries) = fs::read_dir(&epochs_dir) else {
            return 0;
        };
        let mut removed = 0usize;
        for entry in entries.flatten() {
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            let Some(num_str) = name.strip_prefix("index-v") else {
                continue;
            };
            let Ok(num) = num_str.parse::<u64>() else {
                continue;
            };
            if num == current_epoch {
                continue;
            }
            let in_use = self
                .active_epochs
                .lock()
                .ok()
                .and_then(|m| m.get(&num).copied())
                .unwrap_or(0)
                > 0;
            if !in_use && fs::remove_dir_all(&path).is_ok() {
                removed += 1;
            }
        }
        removed
    }

    fn inspect_epoch_sync(&self) -> Result<EpochInspectStats, SearchError> {
        let current_path = self.current_manifest_path();
        if !current_path.exists() {
            return Err(SearchError::Unavailable(format!(
                "search manifest CURRENT missing at {}",
                current_path.display()
            )));
        }
        let raw = fs::read(&current_path)
            .map_err(|e| SearchError::CorruptIndex(format!("read CURRENT: {e}")))?;
        let manifest: EpochManifest = serde_json::from_slice(&raw)
            .map_err(|e| SearchError::CorruptIndex(format!("parse CURRENT JSON: {e}")))?;
        let expected_hash = schema_hash();
        let schema_matches = manifest.schema_hash == expected_hash;
        let epoch_dir = self.epoch_dir_path(manifest.epoch);
        let loaded = open_loaded_epoch(
            &epoch_dir,
            manifest.clone(),
            self.config.zh_dict_path.clone(),
            Arc::clone(&self.active_epochs),
        )?;
        let searcher = loaded.reader.searcher();
        let num_docs = searcher.num_docs();
        let num_segments = searcher.segment_readers().len();
        Ok(EpochInspectStats {
            epoch: manifest.epoch,
            generation: manifest.generation,
            schema_hash: manifest.schema_hash,
            schema_matches,
            clean_shutdown: manifest.clean_shutdown,
            num_docs,
            num_segments,
        })
    }

    fn contains_doc_key_sync(&self, key: &DocumentKey) -> Result<bool, SearchError> {
        let snap = self.loaded.load_full();
        let Some(epoch) = snap.as_ref().as_ref() else {
            return Err(SearchError::Unavailable(
                "no active Tantivy epoch loaded".to_owned(),
            ));
        };
        let searcher = epoch.reader.searcher();
        let term = Term::from_field_text(epoch.fields.doc_key, &key.encode_doc_key());
        let query = TermQuery::new(term, IndexRecordOption::Basic);
        let top = searcher
            .search(&query, &TopDocs::with_limit(1).order_by_score())
            .map_err(|e| SearchError::CorruptIndex(format!("contains_doc_key search: {e}")))?;
        Ok(!top.is_empty())
    }

    fn ensure_active_epoch_for_write(&self) -> Result<(), SearchError> {
        if self.loaded.load().as_ref().is_some() {
            return Ok(());
        }
        let _ = self.rebuild_epoch_sync(&[], 0, None)?;
        Ok(())
    }

    fn verify_disk_epoch_matches(&self, expected: u64) -> Result<EpochManifest, SearchError> {
        let Some(disk) = self.read_disk_manifest() else {
            return Err(SearchError::StaleEpoch {
                expected,
                on_disk: 0,
            });
        };
        if disk.epoch != expected {
            return Err(SearchError::StaleEpoch {
                expected,
                on_disk: disk.epoch,
            });
        }
        Ok(disk)
    }

    fn check_lease(lease_lost: Option<&AtomicBool>) -> Result<(), SearchError> {
        if lease_lost.is_some_and(|f| f.load(Ordering::Acquire)) {
            return Err(SearchError::Unavailable(
                "workqueue lease lost before Tantivy commit publication".to_owned(),
            ));
        }
        Ok(())
    }

    fn upsert_batch_sync(
        &self,
        docs: &[IndexDocument],
        lease_lost: Option<&AtomicBool>,
    ) -> Result<usize, SearchError> {
        validate_batch_bounds(docs)?;
        Self::check_lease(lease_lost)?;
        self.ensure_active_epoch_for_write()?;
        let _guard = self
            .write_mutex
            .lock()
            .map_err(|_| SearchError::Internal("write mutex poisoned".to_owned()))?;
        let _lock = self.acquire_rebuild_lock()?;
        Self::check_lease(lease_lost)?;

        let snapshot = self.loaded.load_full();
        let Some(epoch) = snapshot.as_ref().as_ref() else {
            return Err(SearchError::Unavailable("no active epoch".to_owned()));
        };
        let mut dirty_manifest = self.verify_disk_epoch_matches(epoch.manifest.epoch)?;
        let mut writer =
            create_bounded_writer(&epoch.index, self.config.effective_writer_heap_bytes())?;
        for doc in docs {
            let term = Term::from_field_text(epoch.fields.doc_key, &doc.key.encode_doc_key());
            writer.delete_term(term);
            let tdoc = build_tantivy_document(epoch.fields, doc);
            writer
                .add_document(tdoc)
                .map_err(|e| SearchError::Internal(format!("tantivy add_document: {e}")))?;
        }
        // Final lease check inside the write lock immediately before dirtying manifest & committing!
        Self::check_lease(lease_lost)?;
        dirty_manifest.clean_shutdown = false;
        self.write_manifest_atomic(&dirty_manifest)?;
        writer
            .commit()
            .map_err(|e| SearchError::Io(format!("tantivy commit: {e}")))?;
        self.publish_reloaded_generation_locked(epoch, dirty_manifest.generation, lease_lost)?;
        Ok(docs.len())
    }

    fn delete_batch_sync(
        &self,
        keys: &[DocumentKey],
        lease_lost: Option<&AtomicBool>,
    ) -> Result<usize, SearchError> {
        Self::check_lease(lease_lost)?;
        let _guard = self
            .write_mutex
            .lock()
            .map_err(|_| SearchError::Internal("write mutex poisoned".to_owned()))?;
        let _lock = self.acquire_rebuild_lock()?;
        Self::check_lease(lease_lost)?;
        let snapshot = self.loaded.load_full();
        let Some(epoch) = snapshot.as_ref().as_ref() else {
            return Ok(0);
        };
        let mut dirty_manifest = self.verify_disk_epoch_matches(epoch.manifest.epoch)?;
        let mut writer =
            create_bounded_writer(&epoch.index, self.config.effective_writer_heap_bytes())?;
        for key in keys {
            let term = Term::from_field_text(epoch.fields.doc_key, &key.encode_doc_key());
            writer.delete_term(term);
        }
        Self::check_lease(lease_lost)?;
        dirty_manifest.clean_shutdown = false;
        self.write_manifest_atomic(&dirty_manifest)?;
        writer
            .commit()
            .map_err(|e| SearchError::Io(format!("tantivy delete commit: {e}")))?;
        self.publish_reloaded_generation_locked(epoch, dirty_manifest.generation, lease_lost)?;
        Ok(keys.len())
    }

    fn commit_generation_sync(&self, lease_lost: Option<&AtomicBool>) -> Result<u64, SearchError> {
        Self::check_lease(lease_lost)?;
        let _guard = self
            .write_mutex
            .lock()
            .map_err(|_| SearchError::Internal("write mutex poisoned".to_owned()))?;
        let _lock = self.acquire_rebuild_lock()?;
        Self::check_lease(lease_lost)?;
        let snapshot = self.loaded.load_full();
        let Some(epoch) = snapshot.as_ref().as_ref() else {
            return Err(SearchError::Unavailable("no active epoch".to_owned()));
        };
        let disk = self.verify_disk_epoch_matches(epoch.manifest.epoch)?;
        self.publish_reloaded_generation_locked(epoch, disk.generation, lease_lost)
    }

    /// Physically evict purged document keys and compact segments so purged document
    /// bytes are physically rewritten/removed from disk (zero lingering bytes in old
    /// `.pos`/`.term`/`.idx`/`.store` files).
    fn evict_and_compact_sync(
        &self,
        keys: &[DocumentKey],
        lease_lost: Option<&AtomicBool>,
    ) -> Result<PurgeCompactionReport, SearchError> {
        Self::check_lease(lease_lost)?;
        let _guard = self
            .write_mutex
            .lock()
            .map_err(|_| SearchError::Internal("write mutex poisoned".to_owned()))?;
        let _lock = self.acquire_rebuild_lock()?;
        Self::check_lease(lease_lost)?;

        let snapshot = self.loaded.load_full();
        let Some(epoch) = snapshot.as_ref().as_ref() else {
            return Err(SearchError::Unavailable(
                "no loaded epoch for lawful purge compaction".to_owned(),
            ));
        };
        let epoch_num = epoch.manifest.epoch;
        let epoch_dir = epoch.epoch_dir.clone();
        let old_manifest = epoch.manifest.clone();
        let mut dirty_manifest = self.verify_disk_epoch_matches(epoch_num)?;

        let mut writer =
            create_bounded_writer(&epoch.index, self.config.effective_writer_heap_bytes())?;
        for key in keys {
            let term = Term::from_field_text(epoch.fields.doc_key, &key.encode_doc_key());
            writer.delete_term(term);
        }
        Self::check_lease(lease_lost)?;
        dirty_manifest.clean_shutdown = false;
        self.write_manifest_atomic(&dirty_manifest)?;
        writer
            .commit()
            .map_err(|e| SearchError::Io(format!("tantivy purge delete commit: {e}")))?;

        // Force full segment compaction across all remaining searchable segments so
        // deleted document postings/terms/stored fields are physically rewritten out.
        let seg_ids = epoch
            .index
            .searchable_segment_ids()
            .map_err(|e| SearchError::Io(format!("searchable_segment_ids: {e}")))?;
        let segments_merged = seg_ids.len();
        if !seg_ids.is_empty() {
            writer
                .merge(&seg_ids)
                .wait()
                .map_err(|e| SearchError::Io(format!("tantivy purge segment merge: {e}")))?;
            writer
                .commit()
                .map_err(|e| SearchError::Io(format!("tantivy purge post-merge commit: {e}")))?;
        }
        writer
            .wait_merging_threads()
            .map_err(|e| SearchError::Io(format!("tantivy purge wait_merging_threads: {e}")))?;

        // Publish freshly reloaded generation FIRST, dropping the old snapshot/IndexReader
        // so Tantivy's ManagedDirectory GC can physically unlink every superseded segment file.
        let next_gen = old_manifest
            .generation
            .max(dirty_manifest.generation)
            .saturating_add(1);
        let mut updated = old_manifest;
        updated.generation = next_gen;
        updated.watermark_ts = Some(Utc::now());
        updated.clean_shutdown = true;

        drop(snapshot);
        let reloaded = open_loaded_epoch(
            &epoch_dir,
            updated.clone(),
            self.config.zh_dict_path.clone(),
            Arc::clone(&self.active_epochs),
        )?;
        Self::check_lease(lease_lost)?;
        self.write_manifest_atomic(&updated)?;
        let prev_slot = self.loaded.swap(Arc::new(Some(reloaded)));
        drop(prev_slot);
        self.clear_degraded();

        // Now run ManagedDirectory garbage collection on a fresh Index handle so every
        // unreferenced old segment file containing purged bytes is unlinked from disk.
        let gc_mmap = MmapDirectory::open(&epoch_dir)
            .map_err(|e| SearchError::Io(format!("open gc MmapDirectory: {e}")))?;
        let gc_index = Index::open(gc_mmap)
            .map_err(|e| SearchError::Io(format!("open gc Tantivy index: {e}")))?;
        register_tokenizers(&gc_index, self.config.zh_dict_path.clone());
        let gc_writer =
            create_bounded_writer(&gc_index, self.config.effective_writer_heap_bytes())?;
        let gc_result = gc_writer
            .garbage_collect_files()
            .wait()
            .map_err(|e| SearchError::Io(format!("tantivy garbage_collect_files: {e}")))?;
        drop(gc_writer);
        if !gc_result.failed_to_delete_files.is_empty() {
            return Err(SearchError::Io(format!(
                "tantivy purge GC failed to delete {} stale segment file(s): {:?}",
                gc_result.failed_to_delete_files.len(),
                gc_result.failed_to_delete_files
            )));
        }

        // Also physically remove any pre-rebuild stale `epochs/index-vNNNNNN` directories
        // so retained older epochs can never keep purged bytes on disk. Fail closed (retryable)
        // if an older epoch is still pinned by an active reader or cannot be unlinked.
        self.garbage_collect_stale_epochs_strict(epoch_num)?;

        Ok(PurgeCompactionReport {
            evicted_keys: keys.len(),
            segments_merged,
            epoch: epoch_num,
            generation: next_gen,
        })
    }

    fn garbage_collect_stale_epochs_strict(&self, active_epoch: u64) -> Result<usize, SearchError> {
        let epochs_dir = self.config.index_dir.join("epochs");
        if !epochs_dir.is_dir() {
            return Ok(0);
        }
        let entries = fs::read_dir(&epochs_dir)
            .map_err(|e| SearchError::Io(format!("read epochs dir for purge GC: {e}")))?;
        let mut removed = 0usize;
        for entry in entries {
            let entry = entry
                .map_err(|e| SearchError::Io(format!("iterate epochs dir for purge GC: {e}")))?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            let Some(num_str) = name.strip_prefix("index-v") else {
                continue;
            };
            let Ok(num) = num_str.parse::<u64>() else {
                continue;
            };
            if num == active_epoch {
                continue;
            }
            let in_use = self
                .active_epochs
                .lock()
                .ok()
                .and_then(|m| m.get(&num).copied())
                .unwrap_or(0)
                > 0;
            if in_use {
                return Err(SearchError::Unavailable(format!(
                    "stale search epoch v{num:06} still pinned by active reader during lawful purge compaction"
                )));
            }
            fs::remove_dir_all(&path).map_err(|e| {
                SearchError::Io(format!(
                    "remove stale search epoch {} during lawful purge compaction: {e}",
                    path.display()
                ))
            })?;
            removed += 1;
        }
        Ok(removed)
    }

    /// Atomically publish a new `(reader, generation)` pair into `ArcSwap` + `CURRENT`
    /// so incremental commits immediately invalidate stale cursors and keep reader + generation paired.
    fn publish_reloaded_generation_locked(
        &self,
        epoch: &LoadedEpoch,
        disk_gen: u64,
        lease_lost: Option<&AtomicBool>,
    ) -> Result<u64, SearchError> {
        let next_gen = epoch.manifest.generation.max(disk_gen).saturating_add(1);
        let mut updated = epoch.manifest.clone();
        updated.generation = next_gen;
        updated.watermark_ts = Some(Utc::now());
        updated.clean_shutdown = true;
        let reloaded = open_loaded_epoch(
            &epoch.epoch_dir,
            updated.clone(),
            self.config.zh_dict_path.clone(),
            Arc::clone(&self.active_epochs),
        )?;
        Self::check_lease(lease_lost)?;
        self.write_manifest_atomic(&updated)?;
        self.loaded.store(Arc::new(Some(reloaded)));
        self.clear_degraded();
        Ok(next_gen)
    }

    async fn candidates_on_snapshot(
        self: &Arc<Self>,
        snapshot: Arc<Option<LoadedEpoch>>,
        query: &CandidateQuery,
    ) -> Result<CandidateBatch, SearchError> {
        let deadline = Instant::now() + self.config.query_timeout;

        let Some(epoch) = snapshot.as_ref().as_ref() else {
            let reason = self
                .health_error
                .lock()
                .ok()
                .and_then(|g| g.clone())
                .unwrap_or_else(|| "no active Tantivy epoch loaded".to_owned());
            return Err(SearchError::Unavailable(reason));
        };

        let generation = epoch.manifest.generation;
        let scope_canonical = query.scope_hint.canonical_scope();
        let binding = CursorBinding {
            corpus: query.corpus,
            visibility: query.visibility,
            scope_key: &scope_canonical,
            query_hash: query.terms.query_hash(),
            generation,
        };
        let offset = match query.continuation.as_ref() {
            Some(cursor) => cursor.verify(&self.config.cursor_secret, binding)?,
            None => 0,
        };

        let permit =
            tokio::time::timeout_at(deadline, Arc::clone(&self.search_semaphore).acquire_owned())
                .await
                .map_err(|_| SearchError::Timeout)?
                .map_err(|_| SearchError::Unavailable("search semaphore closed".to_owned()))?;

        let limit = query.effective_limit();
        let mut query_owned = query.clone();
        // Deduplicate and cap ScopeHint BEFORE cloning into spawn_blocking / Tantivy clauses.
        query_owned.scope_hint = query.scope_hint.normalized();
        let snapshot_for_task = Arc::clone(&snapshot);
        let zh_dict_path = self.config.zh_dict_path.clone();
        let cursor_secret = self.config.cursor_secret.clone();
        #[cfg(test)]
        let inject_panic = self.inject_panic.load(Ordering::SeqCst);
        #[cfg(test)]
        let inject_delay_ms = self.inject_delay_ms.load(Ordering::SeqCst);

        let blocking = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            #[cfg(test)]
            if inject_delay_ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(inject_delay_ms));
            }
            let result = catch_unwind(AssertUnwindSafe(
                || -> Result<CandidateBatch, SearchError> {
                    #[cfg(test)]
                    if inject_panic {
                        panic!("injected tantivy panic for catch_unwind verification");
                    }
                    let Some(loaded) = snapshot_for_task.as_ref().as_ref() else {
                        return Err(SearchError::Unavailable("epoch unloaded".to_owned()));
                    };
                    let Some(tantivy_query) =
                        build_search_query(loaded.fields, &query_owned, zh_dict_path)
                    else {
                        return Ok(CandidateBatch {
                            keys: Vec::new(),
                            generation,
                            continuation: None,
                            tier: SearchTier::Tier2Tantivy,
                            degraded: false,
                        });
                    };

                    let searcher = loaded.reader.searcher();
                    // Fetch limit + 1 to detect whether a continuation page exists.
                    let collector = TopDocs::with_limit(limit.saturating_add(1))
                        .and_offset(offset)
                        .order_by_score();
                    let top_docs = searcher
                        .search(&*tantivy_query, &collector)
                        .map_err(|e| SearchError::CorruptIndex(format!("tantivy search: {e}")))?;

                    let has_more = top_docs.len() > limit;
                    let mut keys = Vec::with_capacity(top_docs.len().min(limit));
                    for (_score, addr) in top_docs.into_iter().take(limit) {
                        let doc: TantivyDocument = searcher
                            .doc(addr)
                            .map_err(|e| SearchError::CorruptIndex(format!("tantivy doc: {e}")))?;
                        if let Some(raw_key) = doc
                            .get_first(loaded.fields.doc_key)
                            .and_then(|v| v.as_str())
                        {
                            if let Some(parsed) = DocumentKey::decode_doc_key(raw_key) {
                                keys.push(parsed);
                            }
                        }
                    }

                    let next_offset = offset.saturating_add(keys.len());
                    let (continuation, degraded) = if has_more {
                        if next_offset <= crate::model::MAX_CURSOR_OFFSET {
                            let mint_binding = CursorBinding {
                                corpus: query_owned.corpus,
                                visibility: query_owned.visibility,
                                scope_key: &scope_canonical,
                                query_hash: query_owned.terms.query_hash(),
                                generation,
                            };
                            (
                                Some(OpaqueCursor::mint(
                                    &cursor_secret,
                                    mint_binding,
                                    next_offset,
                                )?),
                                false,
                            )
                        } else {
                            // Offset cap hit while more hits exist -> signal degraded so callers
                            // fall back to Tier-1 instead of treating cap as complete exhaustion.
                            (None, true)
                        }
                    } else {
                        (None, false)
                    };

                    Ok(CandidateBatch {
                        keys,
                        generation,
                        continuation,
                        tier: SearchTier::Tier2Tantivy,
                        degraded,
                    })
                },
            ));

            match result {
                Ok(inner) => inner,
                Err(_) => Err(SearchError::Internal(
                    "tantivy search panicked; caught and degraded".to_owned(),
                )),
            }
        });

        match tokio::time::timeout_at(deadline, blocking).await {
            Ok(Ok(inner)) => inner,
            Ok(Err(join_err)) => Err(SearchError::Internal(format!(
                "tantivy task join error: {join_err}"
            ))),
            Err(_) => Err(SearchError::Timeout),
        }
    }

    fn set_degraded(&self, reason: String) {
        if let Ok(mut slot) = self.health_error.lock() {
            *slot = Some(reason);
        }
    }

    fn clear_degraded(&self) {
        if let Ok(mut slot) = self.health_error.lock() {
            *slot = None;
        }
    }
}

fn create_bounded_writer(
    index: &Index,
    writer_heap_bytes: usize,
) -> Result<IndexWriter<TantivyDocument>, SearchError> {
    let clamped = crate::config::clamp_writer_heap_bytes(writer_heap_bytes);
    let options = IndexWriterOptions::builder()
        .memory_budget_per_thread(clamped)
        .num_worker_threads(1)
        .num_merge_threads(1)
        .build();
    let writer = index
        .writer_with_options(options)
        .map_err(|e| SearchError::Io(format!("open Tantivy IndexWriter: {e}")))?;
    let mut policy = LogMergePolicy::default();
    policy.set_min_num_segments(8);
    writer.set_merge_policy(Box::new(policy));
    Ok(writer)
}

fn validate_batch_bounds(docs: &[IndexDocument]) -> Result<(), SearchError> {
    if docs.len() > MAX_INFLIGHT_DOCS {
        return Err(SearchError::Unavailable(format!(
            "ingest batch exceeds MAX_INFLIGHT_DOCS ({} > {MAX_INFLIGHT_DOCS})",
            docs.len()
        )));
    }
    let total_bytes: usize = docs
        .iter()
        .map(|d| {
            d.title.len()
                + d.sort_name.len()
                + d.body
                    .as_ref()
                    .map_or(0, |b| b.len().min(MAX_DOC_BODY_BYTES))
                + d.headers.iter().map(String::len).sum::<usize>()
                + d.identifiers.iter().map(String::len).sum::<usize>()
        })
        .sum();
    if total_bytes > MAX_INFLIGHT_BYTES {
        return Err(SearchError::Unavailable(format!(
            "ingest batch exceeds MAX_INFLIGHT_BYTES ({total_bytes} > {MAX_INFLIGHT_BYTES})"
        )));
    }
    Ok(())
}

fn truncate_utf8(text: &str, max_bytes: usize) -> &str {
    if text.len() <= max_bytes {
        return text;
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

fn build_tantivy_document(fields: SearchFields, doc: &IndexDocument) -> TantivyDocument {
    let mut tdoc = TantivyDocument::default();
    tdoc.add_text(fields.doc_key, doc.key.encode_doc_key());
    tdoc.add_text(fields.corpus, doc.key.corpus().as_str());
    tdoc.add_text(fields.visibility, doc.visibility.as_str());
    tdoc.add_text(fields.scope_key, doc.key.scope_key());
    tdoc.add_i64(fields.sort_i64, doc.sort_i64);
    tdoc.add_u64(fields.crypto_sealed, u64::from(doc.crypto_sealed));

    // S/MIME Encryption Boundary (V029 C7):
    // When crypto_sealed == true:
    //   - omit body completely and clear sort_name for ALL sealed docs
    //   - on MailAttachment, omit attachment title/filename as well
    //   - restrict identifiers strictly to cleartext envelope headers (never arbitrary doc.identifiers)
    if doc.crypto_sealed {
        tdoc.add_text(fields.sort_name, "");
        if !matches!(doc.key, DocumentKey::MailAttachment { .. }) && !doc.title.is_empty() {
            tdoc.add_text(fields.title_tokens, &doc.title);
            tdoc.add_text(fields.cjk_grams, &doc.title);
            tdoc.add_text(fields.identifiers, &doc.title);
        }
        for hdr in &doc.headers {
            if !hdr.is_empty() {
                tdoc.add_text(fields.title_tokens, hdr);
                tdoc.add_text(fields.cjk_grams, hdr);
                tdoc.add_text(fields.identifiers, hdr);
            }
        }
        return tdoc;
    }

    tdoc.add_text(fields.sort_name, &doc.sort_name);

    if !doc.title.is_empty() {
        tdoc.add_text(fields.title_tokens, &doc.title);
        tdoc.add_text(fields.cjk_grams, &doc.title);
        tdoc.add_text(fields.identifiers, &doc.title);
    }

    for hdr in &doc.headers {
        if !hdr.is_empty() {
            tdoc.add_text(fields.title_tokens, hdr);
            tdoc.add_text(fields.cjk_grams, hdr);
            tdoc.add_text(fields.identifiers, hdr);
        }
    }

    for ident in &doc.identifiers {
        if !ident.is_empty() {
            tdoc.add_text(fields.identifiers, ident);
        }
    }

    if let Some(body) = doc.body.as_deref() {
        let bounded = truncate_utf8(body, MAX_DOC_BODY_BYTES);
        if !bounded.is_empty() {
            tdoc.add_text(fields.body_tokens, bounded);
            tdoc.add_text(fields.cjk_grams, bounded);
            tdoc.add_text(fields.identifiers, bounded);
        }
    }

    tdoc
}

fn open_loaded_epoch(
    epoch_dir: &Path,
    manifest: EpochManifest,
    zh_dict_path: Option<PathBuf>,
    active_epochs: Arc<Mutex<HashMap<u64, usize>>>,
) -> Result<LoadedEpoch, SearchError> {
    open_loaded_epoch_with_mode(epoch_dir, manifest, zh_dict_path, active_epochs, false)
}

fn open_loaded_epoch_with_mode(
    epoch_dir: &Path,
    manifest: EpochManifest,
    zh_dict_path: Option<PathBuf>,
    active_epochs: Arc<Mutex<HashMap<u64, usize>>>,
    read_only: bool,
) -> Result<LoadedEpoch, SearchError> {
    if !epoch_dir.is_dir() {
        return Err(SearchError::CorruptIndex(format!(
            "epoch directory missing: {}",
            epoch_dir.display()
        )));
    }
    let mmap_dir = MmapDirectory::open(epoch_dir)
        .map_err(|e| SearchError::CorruptIndex(format!("open MmapDirectory: {e}")))?;
    let index = if read_only {
        Index::open(ReadOnlyDirectory { inner: mmap_dir })
    } else {
        Index::open(mmap_dir)
    }
    .map_err(|e| SearchError::CorruptIndex(format!("open Tantivy index: {e}")))?;
    register_tokenizers(&index, zh_dict_path);

    let schema = index.schema();
    let fields = SearchFields {
        doc_key: schema
            .get_field("doc_key")
            .map_err(|e| SearchError::CorruptIndex(format!("missing doc_key: {e}")))?,
        corpus: schema
            .get_field("corpus")
            .map_err(|e| SearchError::CorruptIndex(format!("missing corpus: {e}")))?,
        visibility: schema
            .get_field("visibility")
            .map_err(|e| SearchError::CorruptIndex(format!("missing visibility: {e}")))?,
        scope_key: schema
            .get_field("scope_key")
            .map_err(|e| SearchError::CorruptIndex(format!("missing scope_key: {e}")))?,
        sort_i64: schema
            .get_field("sort_i64")
            .map_err(|e| SearchError::CorruptIndex(format!("missing sort_i64: {e}")))?,
        sort_name: schema
            .get_field("sort_name")
            .map_err(|e| SearchError::CorruptIndex(format!("missing sort_name: {e}")))?,
        crypto_sealed: schema
            .get_field("crypto_sealed")
            .map_err(|e| SearchError::CorruptIndex(format!("missing crypto_sealed: {e}")))?,
        title_tokens: schema
            .get_field("title_tokens")
            .map_err(|e| SearchError::CorruptIndex(format!("missing title_tokens: {e}")))?,
        body_tokens: schema
            .get_field("body_tokens")
            .map_err(|e| SearchError::CorruptIndex(format!("missing body_tokens: {e}")))?,
        cjk_grams: schema
            .get_field("cjk_grams")
            .map_err(|e| SearchError::CorruptIndex(format!("missing cjk_grams: {e}")))?,
        identifiers: schema
            .get_field("identifiers")
            .map_err(|e| SearchError::CorruptIndex(format!("missing identifiers: {e}")))?,
    };

    let reader = index
        .reader_builder()
        .reload_policy(ReloadPolicy::Manual)
        .try_into()
        .map_err(|e| SearchError::CorruptIndex(format!("create Tantivy reader: {e}")))?;
    // Validate searcher access immediately before publishing epoch.
    let _ = reader.searcher().num_docs();

    if let Ok(mut map) = active_epochs.lock() {
        *map.entry(manifest.epoch).or_insert(0) += 1;
    }

    Ok(LoadedEpoch {
        manifest,
        index,
        reader,
        fields,
        epoch_dir: epoch_dir.to_path_buf(),
        cleanup_on_drop: AtomicBool::new(false),
        active_epochs,
    })
}

fn build_search_query(
    fields: SearchFields,
    query: &CandidateQuery,
    zh_dict_path: Option<PathBuf>,
) -> Option<Box<dyn Query>> {
    let mut must_clauses: Vec<(Occur, Box<dyn Query>)> = Vec::new();

    // 1. Corpus filter
    must_clauses.push((
        Occur::Must,
        Box::new(TermQuery::new(
            Term::from_field_text(fields.corpus, query.corpus.as_str()),
            IndexRecordOption::Basic,
        )),
    ));

    // 2. Visibility filter
    must_clauses.push((
        Occur::Must,
        Box::new(TermQuery::new(
            Term::from_field_text(fields.visibility, query.visibility.as_str()),
            IndexRecordOption::Basic,
        )),
    ));

    // 3. Scope hint filter (coarse pre-filter; PG still re-authorizes!)
    if let Some(scope_keys) = query.scope_hint.tantivy_scope_keys() {
        if scope_keys.is_empty() {
            return None;
        }
        let scope_clauses: Vec<(Occur, Box<dyn Query>)> = scope_keys
            .into_iter()
            .map(|sk| {
                let q: Box<dyn Query> = Box::new(TermQuery::new(
                    Term::from_field_text(fields.scope_key, &sk),
                    IndexRecordOption::Basic,
                ));
                (Occur::Should, q)
            })
            .collect();
        must_clauses.push((Occur::Must, Box::new(BooleanQuery::new(scope_clauses))));
    }

    // 4. Per-term matching across title_tokens, body_tokens, cjk_grams, identifiers.
    //    Fail closed if any term (or the whole query, e.g. "," or "()") produces zero searchable clauses.
    let jieba_tok = ZhJiebaTokenizer::new(zh_dict_path);
    let mut has_text_clause = false;
    for raw_term in query.terms.terms() {
        let mut per_term_alternatives: Vec<(Occur, Box<dyn Query>)> = Vec::new();

        // Exact identifier match (emails, filenames, UUIDs, ASCII/Unicode tokens)
        for ident in IdentExactTokenizer::query_exact_terms(raw_term) {
            per_term_alternatives.push((
                Occur::Should,
                Box::new(TermQuery::new(
                    Term::from_field_text(fields.identifiers, &ident),
                    IndexRecordOption::Basic,
                )),
            ));
        }

        // CJK bigram / 1-char unigram match (AND across all bigrams of the CJK run)
        let cjk_grams = CjkBigramTokenizer::query_terms(raw_term);
        if !cjk_grams.is_empty() {
            let gram_clauses: Vec<(Occur, Box<dyn Query>)> = cjk_grams
                .into_iter()
                .map(|g| {
                    let q: Box<dyn Query> = Box::new(TermQuery::new(
                        Term::from_field_text(fields.cjk_grams, &g),
                        IndexRecordOption::Basic,
                    ));
                    (Occur::Must, q)
                })
                .collect();
            per_term_alternatives.push((Occur::Should, Box::new(BooleanQuery::new(gram_clauses))));
        }

        // Jieba segmented match across title_tokens and body_tokens
        let zh_terms = jieba_tok.tokenize_terms(raw_term);
        if !zh_terms.is_empty() {
            let title_and: Vec<(Occur, Box<dyn Query>)> = zh_terms
                .iter()
                .map(|t| {
                    let q: Box<dyn Query> = Box::new(TermQuery::new(
                        Term::from_field_text(fields.title_tokens, t),
                        IndexRecordOption::Basic,
                    ));
                    (Occur::Must, q)
                })
                .collect();
            let body_and: Vec<(Occur, Box<dyn Query>)> = zh_terms
                .iter()
                .map(|t| {
                    let q: Box<dyn Query> = Box::new(TermQuery::new(
                        Term::from_field_text(fields.body_tokens, t),
                        IndexRecordOption::Basic,
                    ));
                    (Occur::Must, q)
                })
                .collect();
            per_term_alternatives.push((Occur::Should, Box::new(BooleanQuery::new(title_and))));
            per_term_alternatives.push((Occur::Should, Box::new(BooleanQuery::new(body_and))));
        }

        if per_term_alternatives.is_empty() {
            return None;
        }
        has_text_clause = true;
        must_clauses.push((
            Occur::Must,
            Box::new(BooleanQuery::new(per_term_alternatives)),
        ));
    }

    if !has_text_clause {
        return None;
    }

    Some(Box::new(BooleanQuery::new(must_clauses)))
}

impl SearchEngine for TantivySearchEngine {
    fn candidates<'a>(
        &'a self,
        query: &'a CandidateQuery,
    ) -> BoxFuture<'a, Result<CandidateBatch, SearchError>> {
        Box::pin(async move {
            let snapshot = self.load_snapshot();
            self.candidates_on_snapshot(snapshot, query).await
        })
    }

    fn tier(&self) -> SearchTier {
        SearchTier::Tier2Tantivy
    }

    fn health(&self) -> EngineHealth {
        if let Some(epoch) = self.state.loaded.load().as_ref().as_ref() {
            EngineHealth::Healthy {
                epoch: epoch.manifest.epoch,
                generation: epoch.manifest.generation,
            }
        } else {
            let reason = self
                .state
                .health_error
                .lock()
                .ok()
                .and_then(|g| g.clone())
                .unwrap_or_else(|| "no epoch loaded".to_owned());
            EngineHealth::Degraded { reason }
        }
    }
}

impl SearchIndexer for TantivySearchEngine {
    fn upsert_batch<'a>(
        &'a self,
        docs: &'a [IndexDocument],
    ) -> BoxFuture<'a, Result<usize, SearchError>> {
        self.upsert_batch_checked(docs, None)
    }

    fn delete_batch<'a>(
        &'a self,
        keys: &'a [DocumentKey],
    ) -> BoxFuture<'a, Result<usize, SearchError>> {
        self.delete_batch_checked(keys, None)
    }

    fn commit_generation<'a>(&'a self) -> BoxFuture<'a, Result<u64, SearchError>> {
        self.commit_generation_checked(None)
    }

    fn upsert_batch_checked<'a>(
        &'a self,
        docs: &'a [IndexDocument],
        lease_lost: Option<Arc<AtomicBool>>,
    ) -> BoxFuture<'a, Result<usize, SearchError>> {
        if let Err(err) = validate_batch_bounds(docs) {
            return Box::pin(async move { Err(err) });
        }
        let state = Arc::clone(&self.state);
        let owned_docs = docs.to_vec();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                state.upsert_batch_sync(&owned_docs, lease_lost.as_deref())
            })
            .await
            .map_err(|e| SearchError::Internal(format!("indexer upsert join error: {e}")))?
        })
    }

    fn delete_batch_checked<'a>(
        &'a self,
        keys: &'a [DocumentKey],
        lease_lost: Option<Arc<AtomicBool>>,
    ) -> BoxFuture<'a, Result<usize, SearchError>> {
        let state = Arc::clone(&self.state);
        let owned_keys = keys.to_vec();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                state.delete_batch_sync(&owned_keys, lease_lost.as_deref())
            })
            .await
            .map_err(|e| SearchError::Internal(format!("indexer delete join error: {e}")))?
        })
    }

    fn commit_generation_checked<'a>(
        &'a self,
        lease_lost: Option<Arc<AtomicBool>>,
    ) -> BoxFuture<'a, Result<u64, SearchError>> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || state.commit_generation_sync(lease_lost.as_deref()))
                .await
                .map_err(|e| SearchError::Internal(format!("indexer commit join error: {e}")))?
        })
    }

    fn evict_and_compact_checked<'a>(
        &'a self,
        keys: &'a [DocumentKey],
        lease_lost: Option<Arc<AtomicBool>>,
    ) -> BoxFuture<'a, Result<PurgeCompactionReport, SearchError>> {
        let state = Arc::clone(&self.state);
        let owned_keys = keys.to_vec();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                state.evict_and_compact_sync(&owned_keys, lease_lost.as_deref())
            })
            .await
            .map_err(|e| SearchError::Internal(format!("indexer purge compact join error: {e}")))?
        })
    }

    fn reload_if_disk_epoch_advanced(&self) -> Result<bool, SearchError> {
        TantivySearchEngine::reload_if_disk_epoch_advanced(self)
    }
}
