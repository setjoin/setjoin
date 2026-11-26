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
    IndexDocument, OpaqueCursor, SearchEngine, SearchError, SearchIndexer, SearchTier,
};
use crate::tokenizers::{
    register_tokenizers, CjkBigramTokenizer, IdentExactTokenizer, ZhJiebaTokenizer,
    CJK_BIGRAM_TOKENIZER, IDENT_EXACT_TOKENIZER, ZH_JIEBA_TOKENIZER,
};
use arc_swap::ArcSwap;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tantivy::collector::TopDocs;
use tantivy::directory::MmapDirectory;
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

    /// Load the current atomic `(reader, generation)` snapshot for paired freshness + search.
    pub(crate) fn load_snapshot(&self) -> Arc<Option<LoadedEpoch>> {
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

    fn upsert_batch_sync(&self, docs: &[IndexDocument]) -> Result<usize, SearchError> {
        validate_batch_bounds(docs)?;
        self.ensure_active_epoch_for_write()?;
        let _guard = self
            .write_mutex
            .lock()
            .map_err(|_| SearchError::Internal("write mutex poisoned".to_owned()))?;
        let _lock = self.acquire_rebuild_lock()?;

        let snapshot = self.loaded.load_full();
        let Some(epoch) = snapshot.as_ref().as_ref() else {
            return Err(SearchError::Unavailable("no active epoch".to_owned()));
        };
        let mut dirty_manifest = self.verify_disk_epoch_matches(epoch.manifest.epoch)?;
        dirty_manifest.clean_shutdown = false;
        self.write_manifest_atomic(&dirty_manifest)?;

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
        writer
            .commit()
            .map_err(|e| SearchError::Io(format!("tantivy commit: {e}")))?;
        self.publish_reloaded_generation_locked(epoch, dirty_manifest.generation)?;
        Ok(docs.len())
    }

    fn delete_batch_sync(&self, keys: &[DocumentKey]) -> Result<usize, SearchError> {
        let _guard = self
            .write_mutex
            .lock()
            .map_err(|_| SearchError::Internal("write mutex poisoned".to_owned()))?;
        let _lock = self.acquire_rebuild_lock()?;
        let snapshot = self.loaded.load_full();
        let Some(epoch) = snapshot.as_ref().as_ref() else {
            return Ok(0);
        };
        let mut dirty_manifest = self.verify_disk_epoch_matches(epoch.manifest.epoch)?;
        dirty_manifest.clean_shutdown = false;
        self.write_manifest_atomic(&dirty_manifest)?;

        let mut writer =
            create_bounded_writer(&epoch.index, self.config.effective_writer_heap_bytes())?;
        for key in keys {
            let term = Term::from_field_text(epoch.fields.doc_key, &key.encode_doc_key());
            writer.delete_term(term);
        }
        writer
            .commit()
            .map_err(|e| SearchError::Io(format!("tantivy delete commit: {e}")))?;
        self.publish_reloaded_generation_locked(epoch, dirty_manifest.generation)?;
        Ok(keys.len())
    }

    fn commit_generation_sync(&self) -> Result<u64, SearchError> {
        let _guard = self
            .write_mutex
            .lock()
            .map_err(|_| SearchError::Internal("write mutex poisoned".to_owned()))?;
        let _lock = self.acquire_rebuild_lock()?;
        let snapshot = self.loaded.load_full();
        let Some(epoch) = snapshot.as_ref().as_ref() else {
            return Err(SearchError::Unavailable("no active epoch".to_owned()));
        };
        let disk = self.verify_disk_epoch_matches(epoch.manifest.epoch)?;
        self.publish_reloaded_generation_locked(epoch, disk.generation)
    }

    /// Atomically publish a new `(reader, generation)` pair into `ArcSwap` + `CURRENT`
    /// so incremental commits immediately invalidate stale cursors and keep reader + generation paired.
    fn publish_reloaded_generation_locked(
        &self,
        epoch: &LoadedEpoch,
        disk_gen: u64,
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
    if !epoch_dir.is_dir() {
        return Err(SearchError::CorruptIndex(format!(
            "epoch directory missing: {}",
            epoch_dir.display()
        )));
    }
    let mmap_dir = MmapDirectory::open(epoch_dir)
        .map_err(|e| SearchError::CorruptIndex(format!("open MmapDirectory: {e}")))?;
    let index = Index::open(mmap_dir)
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
        if let Err(err) = validate_batch_bounds(docs) {
            return Box::pin(async move { Err(err) });
        }
        let state = Arc::clone(&self.state);
        let owned_docs = docs.to_vec();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || state.upsert_batch_sync(&owned_docs))
                .await
                .map_err(|e| SearchError::Internal(format!("indexer upsert join error: {e}")))?
        })
    }

    fn delete_batch<'a>(
        &'a self,
        keys: &'a [DocumentKey],
    ) -> BoxFuture<'a, Result<usize, SearchError>> {
        let state = Arc::clone(&self.state);
        let owned_keys = keys.to_vec();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || state.delete_batch_sync(&owned_keys))
                .await
                .map_err(|e| SearchError::Internal(format!("indexer delete join error: {e}")))?
        })
    }

    fn commit_generation<'a>(&'a self) -> BoxFuture<'a, Result<u64, SearchError>> {
        let state = Arc::clone(&self.state);
        Box::pin(async move {
            tokio::task::spawn_blocking(move || state.commit_generation_sync())
                .await
                .map_err(|e| SearchError::Internal(format!("indexer commit join error: {e}")))?
        })
    }
}
