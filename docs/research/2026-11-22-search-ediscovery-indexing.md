# Self-Hosted Full-Text and eDiscovery Search Options for PostgreSQL + Rust

**Date:** 2026-11-22  
**Ticket:** [setjoin/setjoin#522](https://github.com/setjoin/setjoin/issues/522) (`wayfinder:research`)  
**Feeds into:** [setjoin/setjoin#530](https://github.com/setjoin/setjoin/issues/530) (`Decision: Search and eDiscovery indexing architecture`)  
**Parent Map:** [setjoin/setjoin#520](https://github.com/setjoin/setjoin/issues/520) (`Wayfinder: Post-Go Target Architecture for Setjoin`)

---

## 1. Executive Summary

Evaluating the five candidate search architectures against Setjoin's standing constraints (`PostgreSQL` as sole authority store, single-node `<100` users `4 CPU / 8 GB RAM` floor, forward-only zero-data-loss upgrades, `cargo-deny` license policy, CJK + MIME/attachment/chat/Drive indexing, and deterministic eDiscovery completeness) yields a clear separation:

1. **Disqualified as core/required engines:**
   - **ParadeDB `pg_search`:** Community edition is **AGPL-3.0**, **physical WAL streaming replication/HA is gated to commercial ParadeDB Enterprise**, requires `shared_preload_libraries = 'pg_search'` + per-PG-major-version extension binaries (incompatible with 信创 engines like PolarDB/openGauss and customer-managed PG), and a prior attempt in Setjoin (`_archive/schema/036_pg_search.sql`) broke real deployments and had to be reverted (`mailserver/sql/DOX.md#L478`).
   - **Quickwit:** Minimum **8 GB RAM** (`4 GB RAM/core` guideline) + `120 GB` cache volume exceeds Setjoin's entire single-VPS hardware floor, **does not support document updates**, and treats deletes as expensive GDPR-only tasks.
   - **Meilisearch:** MIT-licensed, but adds a separate LMDB daemon + HTTP sync + **dump/reimport friction across breaking DB upgrades**, duplicating memory pressure on an 8 GB VPS. (However, its MIT-licensed Rust tokenizer **`charabia`** is reusable in-process.)
   - **PGroonga:** PostgreSQL License for the wrapper, but **LGPL-2.1** for Groonga, maintains custom `pgrn.*` files outside PG heap/WAL (requiring `pgroonga.enable_wal` / `pgroonga_wal_resource_manager` + experimental `pgroonga_crash_safer` in `shared_preload_libraries` with write penalties), has `pg_upgrade` and SELinux `mmap` caveats, and is unavailable on 信创 Postgres forks.
2. **Recommended target pattern for `#530` (Tiered: Postgres Authority + Embedded Rust `tantivy` Peripheral):**
   - **Tier 1 (PostgreSQL baseline — always available & eDiscovery fallback):** Keep PostgreSQL as the sole authority for ACLs, legal holds, structured metadata, and deterministic completeness. Close the documented **1–2 character CJK blind spot** in `pg_trgm` (which cannot use GIN trigram indexes for 1–2 char Han terms like `"发票"` inside sentences and falls back to sequential scans) using **`pg_bigm`** (PostgreSQL License, PG 17/18) or **`zhparser`** (PostgreSQL License + BSD-3-Clause SCWS, Chinese-only) where extension-free/Postgres-only mode or 信创 is required.
   - **Tier 2 (Embedded `tantivy` in Rust — MIT, outbox-fed, rebuildable):** Run **`tantivy`** (`0.27.x`, **MIT**) **in-process** inside the Rust server/worker with bounded writer heap (`IndexWriter::new(mem_budget)` e.g. 32–50 MB) and OS page-cache-backed `MmapDirectory`, indexing Mail MIME + extracted attachment text (`blob_sha256`-keyed), Chat (+ revisions), and Drive (+ file contents) from the durable transactional outbox (`#529`). Use **`jieba-rs` (MIT)** + **`lindera` with `ipadic` / `ko-dic` (MIT / Apache-2.0)** — **explicitly avoiding `lindera-cc-cedict` (`CC-BY-SA-4.0`)** to stay 100% compatible with `server-rust/deny.toml`. Enforce authorization and eDiscovery completeness in PostgreSQL (hydrating/filtering IDs and scanning the unindexed outbox tail `id > watermark` if the sidecar lags or is rebuilding).

---

## 2. Current State & Constraints in `c:\Setjoin`

### 2.1 How Search & eDiscovery Work Today

| Surface | Schema / Index | Query Mechanism | Current Limitations & Gaps | Repo Source |
| :--- | :--- | :--- | :--- | :--- |
| **Mail (JMAP `Email/query` & `SearchSnippet/get`)** | `messages` (`PARTITION BY RANGE (received_at)`): `body_tsv`, `subject_tsv`, `from_tsv` via trigger `trg_messages_tsv()` using `'simple'`, per-partition GIN indexes | `@@ websearch_to_tsquery('simple', ...)`, summed `ts_rank(...)`, `ts_headline('simple', ...)` | `'simple'` treats a contiguous CJK run as **one token** (partial CJK terms return 0 hits); `ts_rank` instead of BM25; historical ParadeDB `036_pg_search.sql` was never installed and was reverted in `2026-07-04 queue-B #2`. | [V001__baseline.sql](file:///c:/Setjoin/mailserver/sql/dbschema/V001__baseline.sql#L1436-L1449), [jmap_email.sql](file:///c:/Setjoin/mailserver/sql/reducers/jmap_email.sql#L189-L235), [jmap_thread.sql](file:///c:/Setjoin/mailserver/sql/reducers/jmap_thread.sql#L87-L143), [fulltext_search.pg](file:///c:/Setjoin/mailserver/sql/tests/fulltext_search.pg#L129-L147), [DOX.md](file:///c:/Setjoin/mailserver/sql/DOX.md#L478) |
| **Mail IMAP `SEARCH`** | None dedicated | Raw `ILIKE` on `m.from_addr`, `m.subject`, `m.body_text` | Unindexed `ILIKE` sequential/bitmap scan within mailbox; no attachment text search. | [imap/src/messages.rs](file:///c:/Setjoin/server-rust/crates/protocols/imap/src/messages.rs#L268-L295) |
| **Mail eDiscovery & Content Search** | `messages.{body,subject,from}_tsv`, `ediscovery_cases`, `ediscovery_searches`, `ediscovery_search_results`, `messages.held` / `mailboxes.litigation_hold` | `kql::parse` (`plainto_tsquery('simple', ...)` / `ILIKE` on `from_addr`/`mb.email`) or legacy `websearch_to_tsquery('simple', ...)` executed via `rust_compliance_search_complete` on explicit worker pool; capped at 500 persisted result rows (`COUNT(*)` for total) | Same CJK `'simple'` recall gap; `from:`/`mailbox:`/`fromAddr` use unindexed `'%...%' ILIKE`; **attachment content not indexed** (`message_attachments` has only `filename`, `content_type`, `blob_sha256`). | [compliance/src/search.rs](file:///c:/Setjoin/server-rust/crates/domains/compliance/src/search.rs#L26-L61), [compliance/src/content.rs](file:///c:/Setjoin/server-rust/crates/domains/compliance/src/content.rs#L12-L59), [compliance/src/kql.rs](file:///c:/Setjoin/server-rust/crates/domains/compliance/src/kql.rs#L279-L351), [rust_compliance_search_complete.sql](file:///c:/Setjoin/mailserver/sql/reducers/rust_compliance_search_complete.sql#L5-L21), [V001__baseline.sql](file:///c:/Setjoin/mailserver/sql/dbschema/V001__baseline.sql#L4055-L4066) |
| **Chat (Member `chat_search`)** | `chat_messages.search_tsv` (generated `'simple'` + GIN) + `chat_messages_body_trgm_idx` (`USING GIN (body gin_trgm_ops)`) | Rust detects Han runes via `setjoin_contracts::han::contains`; routes Han queries to `m.body ILIKE '%' \|\| p_query \|\| '%'` (`pg_trgm`), non-Han to `plainto_tsquery('simple', ...)` | Enforces channel membership + `GUEST_HISTORY_FLOOR` (`history_floor_seq`, `joined_at`, parent message floor) in SQL; **`pg_trgm` cannot index 1–2 char CJK terms** (falls back to sequential/full-index recheck); no Japanese/Korean segmentation. | [V119__chat_core.sql](file:///c:/Setjoin/mailserver/sql/dbschema/V119__chat_core.sql#L46-L54), [V122__chat_qol.sql](file:///c:/Setjoin/mailserver/sql/dbschema/V122__chat_qol.sql#L33-L37), [chat_search.sql](file:///c:/Setjoin/mailserver/sql/reducers/chat_search.sql#L18-L73), [han.rs](file:///c:/Setjoin/server-rust/crates/contracts/src/han.rs#L1-L31) |
| **Chat eDiscovery (`chat_ediscovery_search`)** | `chat_messages.search_tsv` + `chat_messages_body_trgm_idx` | Unscoped 4-leg `UNION ALL`: live+soft-deleted `chat_messages`, `chat_message_revisions.prior_body` (on-the-fly `to_tsvector`), `chat_message_attachments.filename` (`ILIKE`), and `scheduled_actions` pending/failed `chat_send` payloads | Legs for `revisions`, `attachments.filename`, and `scheduled_actions` are **unindexed** (sequential scan); attachment file content is deferred; requires `search.run` audit in the same transaction. | [chat_ediscovery_search.sql](file:///c:/Setjoin/mailserver/sql/reducers/chat_ediscovery_search.sql#L1-L169) |
| **Drive (`drive_search_nodes`)** | `drive_nodes` (`name`), `drive_files`, `drive_file_versions` (`content_sha256`, `preview_status`) | `n.name ILIKE v_q ESCAPE '\'` grouped by `space_id`, then batch-filtered by `drive_runtime_capability_sources_set(..., 'read_metadata')` | Name-only `ILIKE` (no `pg_trgm` index yet); **file content FTS completely unimplemented**. | [drive_search_nodes.sql](file:///c:/Setjoin/mailserver/sql/reducers/drive_search_nodes.sql#L1-L64), [V114__drive_core.sql](file:///c:/Setjoin/mailserver/sql/dbschema/V114__drive_core.sql#L56-L107) |

### 2.2 Standing Architecture, Deployment & License Constraints

- **Authority & Peripherals (`CONTEXT.md`, Map `#520`):** PostgreSQL is the sole authority store; Search, S3/SeaweedFS, LiveKit, and Valkey remain strictly peripherals. Business/authorization invariants stay behind reducers/Postgres where multi-statement atomicity matters (`ARCH-028`).
- **Isolation & ACLs (`ARCH-006`, `DATABASE_SECURITY.md`):** Strict single-org per install; isolation is per-`mailbox_id` (mail), per-channel membership + guest history floor (chat), per-node effective ACL capability (`drive_runtime_capability_sources_set`), and org-wide admin permissions (`compliance.write`, `mail.export`, `chat.ediscovery`).
- **Single-Node VPS Hardware Floor (`docs/guides/SINGLE_NODE_SETUP.md#L100-L115`):** `<100 users` profile targets **4 CPU / 8 GB RAM / SSD** already running PostgreSQL 17/18+, SeaweedFS, `setjoin-gateway`, `setjoin-auth`, `livekit-server`, `valkey-server`, and optional `livekit/egress`. Memory headroom for search is tight (~256–512 MB steady-state budget on small installs).
- **PostgreSQL Versions & 信创 (Xinchuang) Matrix:** CI runs **PostgreSQL 17** (`.github/ci/lane-pg.Dockerfile`), single-node docs specify **PostgreSQL 18+** (`SINGLE_NODE_SETUP.md#L102`), and enterprise targets include **信创** Postgres-compatible engines (`PolarDB`, `openGauss`, `GaussDB`, `KingbaseES`, `DM8`, `OceanBase`; `mailserver/sql/xinchuang/README.md`). Any non-standard C/Rust PostgreSQL extension cannot be relied on across customer-managed PG or 信创 targets.
- **License Policy (`server-rust/deny.toml`, `server-rust/license-exception-reasons.toml`, `SINGLE_NODE_SETUP.md#L70-L72`):**
  - `server-rust/deny.toml` allows **only**: `MIT`, `Apache-2.0`, `Apache-2.0 WITH LLVM-exception`, `BSD-2-Clause`, `BSD-3-Clause`, `ISC`, `Zlib`, `0BSD`, `CC0-1.0`, `BSL-1.0`, `Unicode-3.0`, `Unicode-DFS-2016`, `MPL-2.0` (unmodified).
  - `deny.toml` enforces `unmaintained = "all"`, `unsound = "all"`, `yanked = "deny"` across the entire Cargo graph (including transitive and dev dependencies), failing CI unless explicitly justified in `ignore`.
  - Setjoin itself is `PolyForm-Noncommercial-1.0.0` with Community + commercial Enterprise channels (`CONTEXT.md#L171`); `SINGLE_NODE_SETUP.md#L72` explicitly notes avoiding SSPL/RSALv2 dependencies for on-prem redistribution. **AGPL-3.0, GPL, SSPL, and CC-BY-SA-4.0 (if compiled/linked into binaries) are incompatible.**

---

## 3. Primary-Source Evaluation of Candidate Search Engines

### 3.1 ParadeDB `pg_search` (Postgres BM25 Extension)

- **Architecture:** `pgrx`-based Rust extension embedding Tantivy inside PostgreSQL (`CREATE INDEX ... USING bm25 / paradedb`, `shared_preload_libraries = 'pg_search'`).
  - *Primary sources:* [paradedb/paradedb](https://github.com/paradedb/paradedb), [ParadeDB Shared Preload Docs](https://docs.paradedb.com/), [ParadeDB Partitioned Tables Docs](https://docs.paradedb.com/).
- **CJK & Mail/Drive/Chat:** Supports `pdb.lindera` (IPADIC, ko-dic, CC-CEDICT), `pdb.jieba`, `pdb.icu`, and `pdb.chinese_compatible` (CJK unigram). Supports PostgreSQL partitioned tables (`messages` partitioned by `received_at`) via parent-index propagation, though ParadeDB docs note edge-case metadata limits on deeply nested partitions.
- **Upgrade, Backup/Restore & Replication (Critical Blocker):**
  - **Physical WAL replication (streaming standby / HA failover) of `pg_search` indexes is NOT supported in ParadeDB Community** — it is gated to **ParadeDB Enterprise** (Community supports single-node and logical replication only).
  - Requires `pg_search` binary extensions compiled for each PG major version (`17`, `18`), complicating `pg_upgrade` and failing on customer-managed PG / RDS / 信创 engines (`PolarDB`, `openGauss`).
  - Setjoin already experienced this failure mode firsthand: `_archive/schema/036_pg_search.sql` was never installed in live baselines, causing `schema "paradedb" does not exist` errors until reverted in `2026-07-04 queue-B #2` (`mailserver/sql/DOX.md#L478`).
- **License (Critical Blocker):** **AGPL-3.0** (Community) / Commercial (Enterprise). Incompatible with Setjoin's commercial Enterprise redistribution model without a commercial OEM agreement.
- **Verdict:** **Reject.** Licensing + Enterprise-gated physical HA replication + `shared_preload_libraries`/packaging fragility make it unsuitable as Setjoin's search foundation.

### 3.2 Embedded Rust `tantivy` (In-Process Library, Outbox-Fed)

- **Architecture:** Pure-Rust inverted-index library (`quickwit-oss/tantivy`, latest release **`0.27.0`**, **MIT**) compiled directly into `setjoin-gateway` (or a dedicated Rust worker mode inside the workspace). Zero external daemon, zero network serialization hop.
  - *Primary sources:* [quickwit-oss/tantivy](https://github.com/quickwit-oss/tantivy), [crates.io/crates/tantivy](https://crates.io/crates/tantivy), [Tantivy MmapDirectory docs](https://docs.rs/tantivy/latest/tantivy/directory/struct.MmapDirectory.html).
- **CJK Tokenization & `cargo-deny` Audit:**
  - **Chinese:** `jieba-rs` (`0.11.x`, **MIT**) via `tantivy-jieba` (**MIT**) or `cang-jie` (**MIT**), or a minimal custom `tantivy::tokenizer::Tokenizer` wrapper over `jieba-rs`.
  - **Japanese & Korean:** `lindera` / `lindera-tantivy` (**MIT**):
    - `lindera-ipadic` (Japanese): crate **MIT**, upstream IPADIC permissive.
    - `lindera-ko-dic` (Korean): crate **MIT**, upstream `mecab-ko-dic` **Apache-2.0**.
    - **CRITICAL LICENSE TRAP — `lindera-cc-cedict` (Chinese):** while the Rust wrapper crate is MIT, the upstream CC-CEDICT dictionary data is **CC-BY-SA-4.0** (ShareAlike copyleft, **not** in `server-rust/deny.toml`). **Do NOT enable `embed-cc-cedict`**; use `jieba-rs` (**MIT**) for Chinese and `lindera` (`ipadic` + `ko-dic`) for Japanese/Korean, or `meilisearch/charabia` (**MIT**) with only MIT/Apache-2.0 dictionary features enabled.
  - **Exact/substring fallback for short CJK & identifiers (`@`, UUIDs, invoice numbers):** Tantivy also ships `NgramTokenizer` (e.g., bigrams for CJK or edge n-grams for email local-parts/filenames) in pure MIT Rust with zero external dictionary.
  - **RustSec caution:** `tantivy` transitive dependencies have occasionally hit RustSec advisories (e.g., `RUSTSEC-2026-0002` on `lru`). Because `server-rust/deny.toml` sets `unmaintained = "all"` and `unsound = "all"`, a spike/lockfile check with `cargo deny check` is mandatory before adopting a specific `tantivy` version.
- **Memory Footprint & Single-VPS Fit:**
  - `IndexWriter` takes an explicit byte budget (e.g., `index.writer(32_000_000)?` — **32–50 MB** heap arena), flushing segments cleanly to disk when reached.
  - `MmapDirectory` maps immutable segments directly into the **OS page cache** without pre-loading term dictionaries or postings into anonymous heap RAM; multiple reader threads share the same physical pages, and the kernel gracefully evicts cold index pages under memory pressure on an 8 GB VPS.
- **MIME / Attachment / Chat / Drive Indexing:**
  - Pure-Rust, `deny.toml`-compatible extractors exist for every core office/attachment format: `setjoin-mime` (in-repo), `calamine` (**MIT**, `.xlsx`/`.xls`/`.ods`), `quick-xml` (**MIT**) + `zip` (**MIT**) for OOXML (`.docx`/`.pptx`) and ODF (`.odt`), `lopdf` / `pdf-extract` (**MIT**) for text-layer PDFs. Avoid GPL `poppler` and heavy JVM Apache Tika (`500+ MB` RAM).
  - Content-addressed deduplication: mail `message_attachments.blob_sha256` and Drive `drive_file_versions.content_sha256` allow caching extracted text once per SHA-256 hash instead of re-parsing identical attachments forwarded across 50 mailboxes!
- **Upgrade, Backup/Restore & Rebuildability:**
  - Because PostgreSQL holds 100% of authoritative state and SeaweedFS holds 100% of blobs, the Tantivy directory (e.g. `/var/lib/setjoin/search-index`) is a **strictly rebuildable derived cache** — it does **not** need to be transactionally snapshot-coupled to `pg_dump` or `setjoin-backup`.
  - Zero-data-loss upgrades: on an incompatible Tantivy index format bump, `setjoin-updater` / startup detects the version mismatch, opens a fresh epoch directory, and replays from PostgreSQL in the background while Tier-1 Postgres FTS/bigrams continue serving queries.
- **eDiscovery Completeness & Consistency Caveat:**
  - Tantivy is **outside PostgreSQL's ACID transaction** (`commit()` is periodic, e.g., every 1–5 s or N outbox rows). Without care, an eDiscovery search immediately after message delivery or legal-hold placement could miss uncommitted documents.
  - **Mitigation:** Track a monotonic `indexed_outbox_seq` watermark in Postgres; for eDiscovery searches, either trigger an explicit `writer.commit()` + drain pending outbox rows up to current `MAX(seq)`, or union Tantivy results with a Postgres scan over rows `> indexed_outbox_seq` (and fall back to full Postgres scan whenever the index is marked `rebuilding`/`degraded`).
- **Verdict:** **Strongest candidate for Tier 2 search engine.**

### 3.3 External Sidecars: Meilisearch & Quickwit

| Dimension | Meilisearch (`meilisearch/meilisearch`) | Quickwit (`quickwit-oss/quickwit`) |
| :--- | :--- | :--- |
| **License** | **MIT** (Self-hosted Community Edition) | **Apache-2.0** |
| **CJK Support** | Excellent — built-in **`charabia`** (**MIT**) auto-detects scripts (`jieba-rs` for zh, `lindera` IPADIC/ko-dic for ja/ko) | Uses Tantivy tokenizers; custom CJK pipeline config |
| **Memory & Disk Floor** | LMDB mmap; tolerates 1/3 to 1/10 RAM-to-disk ratio, **but** indexing consumes significant RAM spikes and adds another long-lived daemon + HTTP/JSON boundary on an 8 GB VPS | **Incompatible with single-VPS floor:** official docs state **never `< 8 GB RAM`**, **4 GB RAM/core** for indexers, and **120 GB** minimum disk (100 GB split cache + 4 GiB ingest queues) |
| **Updates & Deletes** | Supports document updates/deletes via async task queue | **No document updates** (immutable splits); deletes are **GDPR-only batch rewrites** ("parsimoniously", a few/day). Unusable for mail tag/folder churn, edits, or Drive ACL/rename updates |
| **Upgrades & Backup** | Breaking major releases historically require **`.dump` export -> upgrade binary -> re-import dump** (clashes with `setjoin-updater`'s automated zero-downtime upgrade) | Requires PG Metastore + S3 splits; heavy distributed architecture (indexer/searcher/janitor/metastore) for single-node `<100` users |
| **Security / ACL Risk** | Separate HTTP store risks ACL/filter drift vs Postgres `R1–R4` and Drive `drive_runtime_capability_sources_set` | Same external-daemon ACL/sync drift risk |
| **Verdict** | **Reject as daemon** (keep `charabia` library on radar) | **Reject** (wrong workload: immutable log analytics, not mutable mail/Drive/eDiscovery) |

*Primary sources:* [Meilisearch Docs (Upgrades, Hardware, Language/Charabia)](https://www.meilisearch.com/docs), [meilisearch/charabia](https://github.com/meilisearch/charabia), [Quickwit Single-Node / Hardware / Delete Docs](https://quickwit.io/docs/overview/architecture).

### 3.4 Native PostgreSQL Extensions (`tsvector` GIN, `pg_trgm`, `pg_bigm`, `zhparser`, `pg_jieba`)

| Engine / Extension | License | PG 17/18 & 信创 | `shared_preload_libraries`? | CJK Quality & Recall | Index Size & Constraints |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Built-in `tsvector` (`'simple'`) + GIN** *(current baseline)* | PostgreSQL | 100% built-in (incl. 信创) | No | **Poor for CJK:** `'simple'` treats an entire CJK sentence/run as a single token (`你好世界` ≠ `你好`) | Compact; native WAL/replication/`pg_upgrade`; `ts_rank` (no BM25) |
| **`pg_trgm`** *(currently installed at `V001` & `V122`)* | PostgreSQL | Built-in contrib | No | **Broken for 1–2 char CJK:** 3-gram index **cannot match 1–2 char substrings** inside CJK sentences (e.g., `发票`, `合同`) -> falls back to sequential scan | Moderate GIN size; great for email/domain fuzzy matching (`antiphish`) |
| **`pg_bigm`** (`pgbigm/pg_bigm`) | **PostgreSQL** | PG 17 & 18 supported; custom build on 信创 | **No** (standard `CREATE EXTENSION pg_bigm`) | **100% recall for 1–2+ char CJK** (`LIKE '%发票%'` uses GIN `gin_bigm_ops` directly for zh/ja/ko simultaneously, zero dictionary needed!) | **1.5x–3x raw text size** on disk; **102 MB** (`107,374,180` B) max single column value; no BM25 ranking or morphological stemming |
| **`zhparser`** (`amutu/zhparser` + `hightman/scws`) | **PostgreSQL** + **BSD-3-Clause** (SCWS) | PG 17 & 18 actively packaged (`postgresql-17/18-zhparser`) | No | Good **Chinese** word segmentation via `tsvector`; **does NOT segment Japanese or Korean** | Compact `tsvector` GIN; requires external `scws` + `.xdb` dictionaries installed on PG host |
| **`pg_jieba`** (`jaiminpan/pg_jieba`) | **3-Clause BSD** | **Lags PG 17/18** (upstream compile breakage on newer PG headers) | No | Good **Chinese** segmentation; no ja/ko | C++ CppJieba dependency; weaker packaging/maintenance than `zhparser` |

*Primary sources:* [pgbigm/pg_bigm](https://github.com/pgbigm/pg_bigm), [amutu/zhparser](https://github.com/amutu/zhparser), [hightman/scws](https://github.com/hightman/scws), [jaiminpan/pg_jieba](https://github.com/jaiminpan/pg_jieba), [PostgreSQL `pg_trgm` docs](https://www.postgresql.org/docs/current/pgtrgm.html).

### 3.5 `PGroonga`

- **Architecture:** C PostgreSQL index access method wrapping **Groonga** (`pgrn.*` files inside `PGDATA`), supporting zero-ETL multilingual search (MeCab/bigram/normalizers) and partitioned tables (`pgroonga_physical_table_names()`). PGroonga `4.0.4+` supports PostgreSQL 18 ordered index scans.
  - *Primary sources:* [PGroonga Docs (WAL, Crash Recovery, Partitioning, Replication)](https://pgroonga.github.io/reference/), [PGroonga 4.0.4 PG18 release notes](https://www.postgresql.org/).
- **Licenses:** PGroonga extension is **PostgreSQL License**; underlying **Groonga** library is **LGPL-2.1** (plus optional MeCab GPL/LGPL/BSD).
- **Operational & Safety Caveats:**
  - **Crash safety:** Default PGroonga is **not crash-safe** on PG crash (`REINDEX` needed). Automatic crash recovery requires experimental **`pgroonga_crash_safer`** in `shared_preload_libraries` (`pgroonga.enable_crash_safe = on`), adding write overhead.
  - **Streaming Replication:** Requires `pgroonga.enable_wal = on` (write penalty) or PG 15+ `pgroonga_wal_resource_manager` + `pgroonga_standby_maintainer`.
  - **Upgrades & Host Coupling:** Custom binary files (`pgrn.*`) inside `PGDATA` require careful PGroonga/Groonga major-version upgrade handling during `pg_upgrade`, explicit SELinux `mmap` permissions, and are unavailable on RDS/managed PG or 信创 forks.
- **Verdict:** **Not recommended** as primary engine due to crash-safety/WAL complexity and host PG coupling, though far more license-friendly than ParadeDB.

---

## 4. Comparison Matrix Against Setjoin's Constraints

| Criterion | ParadeDB `pg_search` | Embedded Rust `tantivy` (+ Postgres Tier 1) | Meilisearch Sidecar | Quickwit Sidecar | Native PG + `pg_bigm` / `zhparser` | `PGroonga` |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **License (`deny.toml` / Enterprise)** | **FAIL** (AGPL-3.0) | **PASS** (MIT; avoid CC-BY-SA `cc-cedict`) | PASS (MIT daemon) | PASS (Apache-2.0) | **PASS** (PostgreSQL / BSD-3) | **CAUTION** (PG License + LGPL-2.1 Groonga) |
| **CJK (zh / ja / ko) + English/MIME** | Excellent (`lindera` / `jieba` / `icu`) | **Excellent** (`jieba-rs` + `lindera` ipadic/ko-dic + bigram/ASCII) | Excellent (`charabia`) | Good | **Partial** (`pg_bigm`: exact CJK substring, no stemming/BM25; `zhparser`: zh only) | Excellent |
| **Mail + Attachment + Chat + Drive** | SQL tables only (still needs Rust attachment extractor) | **Unified** (Rust extracts MIME/Office/PDF once per `blob_sha256` & indexes all 3 domains) | Needs HTTP ETL pipeline | No updates; bad for mutable Drive/Mail | SQL-only (large GIN bloat if storing extracted attachment text in PG) | SQL-only (bloat in `pgrn.*`) |
| **eDiscovery Completeness & Audit** | Transactional with PG | **High if designed with watermark + PG tail fallback** (ACID holds/audit stay in PG) | Eventual consistency + ACL drift risk | Eventual consistency + delete bottleneck | **100% ACID** in single PG transaction | **ACID** in PG (unless index crashes without `crash_safer`) |
| **Zero-Data-Loss Upgrade & HA Replication** | **FAIL** (physical WAL replication gated to Enterprise) | **PASS** (derived peripheral; PG backup/WAL unchanged; background epoch rebuild) | **Friction** (`.dump` re-import on major upgrades) | Heavy (PG metastore + S3 splits) | **PASS** (native PG WAL/backup; `pg_bigm` needs extension binary on target) | **CAUTION** (experimental `crash_safer`, WAL penalty, `pg_upgrade` coupling) |
| **Single-VPS RAM (`4 CPU / 8 GB`)** | Medium–High (shared buffers + Tantivy inside PG backends) | **Low & Bounded** (32–50 MB writer heap + shared `mmap` page cache) | Medium–High (separate daemon + LMDB + indexing spikes) | **FAIL** (min 8 GB RAM, 4 GB/core, 120 GB cache) | Low–Medium (`maintenance_work_mem`, GIN pending list) | Medium–High (`mmap` Groonga structures) |
| **信创 / Managed PG Compatibility** | **FAIL** | **PASS** (zero custom PG extensions required) | PASS (external) | PASS (external) | **Partial** (stock PG needs `pg_bigm`;信创 falls back to `'simple'` + `ILIKE`) | **FAIL** |

---

## 5. Architectural Recommendations for Decision `#530`

1. **Keep PostgreSQL as sole authority for eDiscovery, legal holds, ACLs, and audit.**
   - Never mirror complex ACL trees (`drive_runtime_capability_sources_set`, Chat `history_floor_seq`, Mail `mailbox_id`) as the sole security gate inside an external index. Search indexes return candidate IDs; PostgreSQL enforces `R1–R4`, applies legal holds, and writes synchronous audit rows (`chat_access_audit`, `admin_audit_log`).
2. **Adopt a Two-Tier Search Architecture:**
   - **Tier 1 (Zero-extension / Fallback Postgres layer):**
     - Immediately fix the **1–2 char CJK blind spot** in `chat_search`, `chat_ediscovery_search`, `jmap_email_query`, and `kql.rs`. Where `pg_bigm` is permitted (stock Linux PG 17/18 deployments), `pg_bigm` gives indexed 1–2 char CJK `ILIKE` recall without `shared_preload_libraries` or dictionaries; where no extra PG extensions are available (e.g. 信创 / customer-managed PG), keep `'simple'` GIN + `ILIKE` fallback so every query stays functional.
     - Add `pg_trgm` GIN indexes on `drive_nodes(name)` (already anticipated in `drive_search_nodes.sql#L27`) and unindexed eDiscovery legs (`chat_message_revisions.prior_body`, `messages.from_addr`).
   - **Tier 2 (Embedded `tantivy` + pure-Rust extractors, fed by the `#529` durable outbox):**
     - Embed **`tantivy`** (`MIT`) inside `setjoin-gateway` (or a dedicated worker subcommand in `server-rust`) with a bounded writer budget (32–50 MB) and `MmapDirectory` on local NVMe/SSD.
     - Tokenize with **`jieba-rs` (`MIT`) + `lindera-ipadic` (`MIT`) + `lindera-ko-dic` (`MIT`/`Apache-2.0`)** (or `charabia` `MIT` with CC-BY-SA dictionaries disabled) + standard ASCII/email tokenizer + bigram/edge-ngram field for exact code/address matching. Verify `cargo deny check --locked` (`RUSTSEC-2026-0002` / `lru` check) during the `#530` prototype/implementation spec.
     - Deduplicate attachment and Drive text extraction by **`blob_sha256` / `content_sha256`** (stored in a lightweight Postgres extraction-cache or directly pushed to Tantivy), using pure-Rust MIT crates (`setjoin-mime`, `calamine`, `quick-xml`, `zip`, `lopdf`/`pdf-extract`).
     - Guarantee **eDiscovery completeness** with a monotonic `search_outbox_watermark` + hybrid Postgres tail query (scanning `id > watermark` in PG) and automatic fallback to Tier-1 PG scan if Tantivy is rebuilding or unavailable.
     - Treat the Tantivy data directory as **ephemeral/rebuildable**: exclude it from critical backup consistency locks and allow `setjoin-updater` to bump an index epoch and rebuild asynchronously without blocking upgrades.
