# `setjoin-search` (`server-rust/crates/search`) — Foundation Contract

Wave 3.1 (`#556`): Two-Tier `SearchEngine` seam, optional `pg_bigm` Tier-1 baseline, and embedded MIT `tantivy` Tier-2 index.

## Placement & Dependency Posture

- Foundation crate (`server-rust/crates/search`), never under `crates/domains/*`, so domain crates (`setjoin-jmap`, `setjoin-chat`, `setjoin-drive`, `setjoin-compliance`) and binaries (`bins/gateway`) can depend on it while passing `scripts/check-rust-family-isolation.py`.
- 100% permissive MIT/Apache-2.0/BSD dependencies (`cargo deny --locked check` clean, zero `license-exception-reasons.toml` entries, zero `CC-BY-SA`, zero `zstd-sys`):
  - `tantivy` (`default-features = false, features = ["mmap", "lz4-compression"]`)
  - `jieba-rs` (`default-features = false`, pure-Rust HMM + embedded MIT core dictionary, optional external dictionary via `SETJOIN_SEARCH_ZH_DICT_PATH`)
  - `lindera-cc-cedict` and `unidic` explicitly banned in `server-rust/deny.toml` `[bans]`.
- Lazy `OnceLock<Arc<jieba_rs::Jieba>>`: Tier-1-only deployments never allocate the dictionary.

## Security & Architecture Invariants

- **Candidate-key generator ONLY:** Tantivy stores ONLY `doc_key` (`STRING | STORED`). Text fields (`title_tokens`, `body_tokens`, `cjk_grams`, `identifiers`) are indexed-only (never `STORED`).
- **Mandatory PG Re-Authorization (R1–R4):** Every Tier-2 candidate batch MUST pass through `reauthorize_mail_candidates` (`MailboxTx<ReadOnly>`), `reauthorize_chat_candidates` (`UserTx<ReadOnly>`), or `reauthorize_drive_candidates` (`UserTx<ReadOnly>`) on `AppPool` (`setjoin_app`, `NOBYPASSRLS`) with bounded overfetch (`clamp(limit * 3, 64, 500)`, `MAX_OVERFETCH_ROUNDS = 4`, fallback to Tier-1 when exhausted).
- **S/MIME Encryption Boundary (`V029` C7):** When `crypto_sealed == true`, body/attachment text is omitted from both Tantivy and Tier-1 body matching; only cleartext envelope headers remain searchable.
- **Hard Memory & DoS Bounds:** Writer heap strictly clamped to `[15_000_000, 50_000_000]` bytes (default `32_000_000`), `num_worker_threads = 1`, `num_merge_threads = 1`, `LogMergePolicy`. Queries bounded to `<= 256` bytes, `<= 32` terms, no leading wildcards, no user regexes, `Semaphore(4)`, `250ms` timeout, and `catch_unwind`.
- **Storage & `pg_dump` Exclusion:** Private local directory `SETJOIN_SEARCH_INDEX_DIR` (default `/var/lib/setjoin/search`) outside `PGDATA` and `pg_dump`: atomic-renamed `CURRENT` manifest, `rebuild.lock`, `epochs/index-vNNNNNN/`.
- **Default OFF & Graceful Degradation:** `SETJOIN_SEARCH_TIER2_ENABLED` defaults to `false` (zero `feature_toggles` rows added). Missing/corrupt/timed-out/panicked/dirty-watermark Tier-2 state degrades transparently to `Tier1PgSearchEngine`.

## Verification

- Unit tests: `cargo test --locked --offline -p setjoin-search --lib`
- Live-DB integration tests (`REQUIRE_DB=1`): `cargo test --locked --offline -p setjoin-search --test two_tier_db`
- Migration & RLS denial proof: `V290__search_two_tier_optional_pg_bigm.sql` + `mailserver/sql/tests/V290__search_two_tier.pg`
