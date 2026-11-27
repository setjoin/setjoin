# `setjoin-search` (`server-rust/crates/search`) — Foundation Contract

Wave 3.1 (`#556`): Two-Tier `SearchEngine` seam, optional `pg_bigm` Tier-1 baseline, and embedded MIT `tantivy` Tier-2 index.
Wave 3.2 (`#557`): Content-addressed pure-Rust extraction cache (`src/extract.rs`, `public.search_extracted_text`), monotonic indexing outbox (`public.search_index_outbox`), full-domain Mail/Chat/Drive indexing pipeline (`src/pipeline.rs`), gateway `WorkQueue` consumers (`bins/gateway/src/supervisor/search_worker.rs`), and Mark-and-Sweep GC cache sweep (`search_extracted_text_gc_sweep` wired into `BlobGcWorker::run_live`).

## Placement & Dependency Posture

- Foundation crate (`server-rust/crates/search`), never under `crates/domains/*`, so domain crates (`setjoin-jmap`, `setjoin-chat`, `setjoin-drive`, `setjoin-compliance`) and binaries (`bins/gateway`) can depend on it while passing `scripts/check-rust-family-isolation.py` (never enables `setjoin-pg/worker-pool` or `setjoin-workqueue/worker`).
- 100% permissive MIT/Apache-2.0/BSD dependencies (`cargo deny -L error --locked check` clean, zero `license-exception-reasons.toml` entries, zero `CC-BY-SA`, zero `zstd-sys`, zero GPL/JVM/C extractors):
  - `tantivy` (`default-features = false, features = ["mmap", "lz4-compression"]`)
  - `jieba-rs` (`default-features = false`, pure-Rust HMM + embedded MIT core dictionary, optional external dictionary via `SETJOIN_SEARCH_ZH_DICT_PATH`)
  - Extraction crates (already workspace-locked): `zip` (`deflate-flate2`), `quick-xml`, `scraper` (`deterministic`), `encoding_rs`, `mail-parser`, `flate2`, plus pure-Rust bounded PDF text extractor
  - `lindera-cc-cedict` and `unidic` explicitly banned in `server-rust/deny.toml` `[bans]`.
- Lazy `OnceLock<Arc<jieba_rs::Jieba>>`: Tier-1-only deployments never allocate the dictionary.

## Extraction & Full-Domain Indexing Pipeline (`#557`)

- **Content-addressed deduplication & digest provenance:** `ContentExtractionService` checks `public.search_extracted_text` by `content_sha256` with a process-wide RAII `ExtractionSingleFlight` (`ON CONFLICT` idempotent write) so identical mail attachments and Drive file versions extract strictly once. Bytes are SHA-256 verified against `content_sha256` before writing/sharing cache so client-supplied spoofed Drive `content_sha256` digests can never read another tenant's cache row or poison shared cache entries; 0-byte Drive files short-circuit without storage fetches.
- **Strict extraction bounds:** `<= 20 MiB` input cap, `<= 32 MiB` shared decompressed ZIP/ODF/PDF stream cap (EOCD entry count pre-checked before `ZipArchive::new`, exact `raw_size > comp_size * 100` ratio check, PDF `/FlateDecode` budget deducted even on blowup), `<= 256` ZIP entries, `<= 512 KiB` UTF-8 boundary-safe output truncation (`TruncatedLimit`). Encrypted (ZIP bit 0, OLE2 `EncryptedPackage`, PDF `/Encrypt`, ODF `encryption-data`, S/MIME), unsupported binary, oversized, and corrupt files record explicit non-`extracted` statuses with `extracted_text IS NULL` and NEVER fail the indexing batch; filenames and headers remain indexed.
- **Full-domain coverage (`WorkQueue` kinds `"search.extract"` & `"search.index_batch"`):**
  - **Gap-free outbox consumption & write capture:** `search_index_outbox` tracks `processed_at` with a partial unprocessed index and `search_outbox_mark_processed(bigint[])`; claiming with `p_after_seq = 0` and advancing `indexed_outbox_seq` to the contiguous watermark guarantees out-of-order commits never drop lower sequences. Worker-owned `SECURITY DEFINER` triggers on `messages` (`BEFORE DELETE` for scoped cascading attachment tombstones + `AFTER`), `message_attachments` (direct delete re-indexes parent Mail), `chat_messages`, `chat_message_revisions`, `chat_message_attachments`, `drive_nodes`, `drive_file_versions`, and `scheduled_actions` remain inert until `SearchIndexConsumer` seeds `search_index_watermarks` under `SETJOIN_SEARCH_TIER2_ENABLED=true`.
  - **Mail:** headers, body, and attachments (strictly respecting S/MIME `crypto_type = 'smime-encrypted'` -> `crypto_sealed = true`, omitting body, attachment text, and attachment `sort_name`).
  - **Chat:** `chat_messages`, historical `chat_message_revisions` (strictly `SearchVisibility::ComplianceOnly` under negative `chat_revision_doc_id`), chat attachments (filename + cached text), and pending/enqueued/processing/failed `scheduled_actions` (camelCase `"channelId"` + scheduled Mail draft hydration) indexed under `SearchVisibility::ComplianceOnly` with negative deterministic `scheduled_action_doc_id` (evicted on `'done'` or `DELETE`).
  - **Drive:** `drive_nodes` names + `drive_file_versions` content reconstructed from `drive_version_chunks` / `drive_chunks`.
  - **Freshness fence, chunking & lease fencing:** Deletes and upserts chunk strictly within Tantivy in-flight caps (`<= 1000` docs, `<= 12 MiB` estimated bytes); only processed `search_dirty_keys` are deleted; `SnapshotFreshnessFence` receives exact remaining `(outbox + dirty)` counts; `has_more` enqueues crash-safe continuation items; heartbeat lease loss cancels publication/completion.
- **GC sweep integration:** `search_extracted_text.content_sha256` and `search_index_outbox.content_sha256` are classified `blobs_internal` in `config/blob-reference-manifest.json` (never pinning deleted blobs), and `BlobGcWorker::run_live` invokes `public.search_extracted_text_gc_sweep()`, which checks BOTH `blob_has_live_reference()` AND `drive_file_versions` (preserving Drive 30-day recoverable admin trash `purged_at IS NOT NULL`) across planes.
- **Supervisor opt-in:** `SearchExtractConsumer` (concurrent per-item heartbeats) & `SearchIndexConsumer` share one `ExtractionSingleFlight` and boot under `WorkerSupervisor` only when `SETJOIN_SEARCH_TIER2_ENABLED=true` (default OFF).

## Verification

- Unit tests: `cargo test --locked --offline -p setjoin-search --lib`
- Live-DB integration tests (`REQUIRE_DB=1`): `cargo test --locked --offline -p setjoin-search --test two_tier_db --test extraction_indexing_db` and `cargo test --locked --offline -p setjoin-gateway --test search_worker_db`
- Migrations & RLS denial proofs: `V290__search_two_tier_optional_pg_bigm.sql` (`V290__search_two_tier.pg`) and `V291__search_extraction_cache_and_outbox.sql` (`V291__search_extraction.pg`)
