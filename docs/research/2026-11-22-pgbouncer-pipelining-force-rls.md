# PgBouncer Prepared Statements, `tokio-postgres` Pipelining, and `FORCE RLS` Behavior

- **Ticket:** [setjoin/setjoin#521](https://github.com/setjoin/setjoin/issues/521)
- **Parent Map:** [setjoin/setjoin#520](https://github.com/setjoin/setjoin/issues/520) (Wayfinder: Post-Go Target Architecture for Setjoin)
- **Unblocks:** [setjoin/setjoin#524](https://github.com/setjoin/setjoin/issues/524) (1-RTT CTE/pipelined `ScopedTx` prototype), [setjoin/setjoin#526](https://github.com/setjoin/setjoin/issues/526), [setjoin/setjoin#527](https://github.com/setjoin/setjoin/issues/527)
- **Date:** 2026-11-22
- **Pinned Workspace Versions Observed:** `tokio-postgres = "0.7.18"`, `deadpool-postgres = "0.14.2"` (`server-rust/Cargo.lock`; `sqlx` is not in the workspace).

---

## Executive Summary

1. **PgBouncer ≥1.21–1.24 supports protocol-level named prepared statements in transaction pooling (`max_prepared_statements > 0`, default `200` in ≥1.24),** deduplicating by query string across server connections (`PGBOUNCER_{unique_id}`). However, `deadpool-postgres` `0.14.2`'s built-in `StatementCache` is an **unbounded** `HashMap` with no LRU eviction, and `RecyclingMethod::Verified` currently adds **+1 RTT** per `pool.get()`. Unnamed extended queries (`query_typed_raw`) already work in 1 RTT per statement with zero PgBouncer cache footprint, provided result columns use built-in types (`text` casts for enums/domains) so `tokio-postgres` does not trigger its named `TYPEINFO_QUERY`.
2. **`tokio-postgres` `0.7.18` natively supports 1-RTT multi-statement pipelining via `tokio::join!` on `&Client`, whereas `sqlx` does not.** In `tokio-postgres`, `Client` is `Send + Sync` and `Connection::poll_write` drains all concurrently polled requests into one TCP flush. Crucially, `tokio-postgres` appends `Sync` to *every* individual extended query (`[Msg1+Sync][Msg2+Sync]...`) rather than libpq's single trailing `Sync`. Combined with collapsing `LOCKED_MAILBOX_SCOPE` + `USER_SCOPE` + `AUDIT_SCOPE` into one `SELECT set_config(...)` call, a multi-statement `BEGIN; SET LOCAL ...` → scope/lock → writeable CTE → receipt → `COMMIT` transaction fits in **1 network RTT** (down from 6–9 RTTs today). Never use `tokio::try_join!` for a `BEGIN ... COMMIT` pipeline (short-circuiting drops `COMMIT` mid-flight) and never put `set_config(...)` inside the same CTE query as an RLS-protected table (planner `InitPlan` evaluation order can read the stale/empty GUC).
3. **Under `SET LOCAL` + `FORCE RLS` + prepared statements, bind parameters (`$1`, `$2`) control generic-plan switching and partition pruning, while the RLS GUC remains an `InitPlan`.** `current_setting('app.current_mailbox_id', true)` is `STABLE`, so even custom plans evaluate it at execution via `InitPlan`; however, R1/R3 bind parameters (`WHERE mailbox_id = $1`) *do* use MCV stats on the first 5 custom plans and switch to uniform selectivity on generic plans (6th+), risking bad plans on skewed mailboxes unless `plan_cache_mode = force_custom_plan` is used on skewed hot paths. Partition pruning on `received_at`-partitioned `messages`/`message_tags` works at plan-time for custom plans and execution-time (`Append`/`ModifyTable`, PG ≥14) for generic plans, **only when `received_at` is constrained in `WHERE`** (queries filtering only by `id` + `mailbox_id`, such as current `jmap_email_set_update`, touch all partitions). PostgreSQL minor versions must include the **CVE-2026-14666** fix (PG 18.6+ / 17.11+ / 16.15+) for safe RLS cached-plan invalidation.
4. **1-RTT pipelining shrinks `decode()` pre-commit veto power and widens the `Unknown` commit window, while preserving Setjoin's advisory-lock + receipt recovery invariant.** Because `COMMIT` is flushed before any `DataRow` returns, business validation (`BZ*` errors, caps) must live in SQL so PostgreSQL aborts into `25P02` *before* reaching `COMMIT` (which PostgreSQL executes as `ROLLBACK` → `ReadyForQuery('I')`). Any socket loss, timeout, or cancellation after the 1-RTT flush without a prior server `ErrorResponse` must return `CommandOutcome::Unknown { operation }` and quarantine the connection (`Object::take`), ideally also issuing `CancelRequest` so PgBouncer does not leave the backend holding `pg_advisory_xact_lock` until `SET LOCAL statement_timeout` fires.

---

## 0. Current Setjoin Baseline (`c:\Setjoin`)

| Component | Current Implementation | Verified Source |
|---|---|---|
| Driver & Pool | `tokio-postgres` `0.7.18` + `deadpool-postgres` `0.14.2` (`RecyclingMethod::Verified`), `NoTls` | `server-rust/Cargo.lock`, `server-rust/crates/pg/src/executor.rs:193-210` |
| Wire Protocol | `query_typed_raw` / `query_typed` / `execute_typed` (unnamed statement `""`), `batch_execute` for `BEGIN; SET LOCAL statement_timeout = ...` / `COMMIT` / `ROLLBACK`; `prepare_cached` never used | `server-rust/crates/pg/src/lib.rs:7-18`, `executor.rs:824-828,1030-1034,1087` |
| PgBouncer Config | `pool_mode = transaction`, `default_pool_size = 25`, `max_client_conn = 200`, `track_extra_parameters = app.encryption_key,app.audit_hmac_key`; `max_prepared_statements` not explicitly set | `mailserver/deploy/pgbouncer.ini:19-68` |
| `FORCE RLS` & Partitions | `messages` & `message_tags` `RANGE`-partitioned by `received_at`; `ENABLE + FORCE ROW LEVEL SECURITY` and `FOR ALL` policies on **parent only** using `(SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint)` `InitPlan`; covering index `(received_at, id) INCLUDE (mailbox_id)` | `mailserver/sql/dbschema/V003__rls_policies.sql:47-90`, `V004__rls_enable.sql:37-55`, `mailserver/sql/tests/rls_partition_via_parent.pg` |
| Recovery Pattern | `TransactionLifecycle` (`setjoin-db`), `pg_advisory_xact_lock(hashtextextended($lock, 0))`, same-tx `INSERT INTO public.rust_operation_receipts`, `CommandOutcome::Unknown { operation }` + `Object::take` quarantine, `lookup_command` waits on same advisory lock at `READ COMMITTED` | `server-rust/crates/db/src/lifecycle.rs`, `server-rust/crates/pg/src/executor.rs:60-61,904-920,1087-1135`, `command.rs:25-70,238-285` |

**Current RTT count per `run_receipted_command` (`executor.rs:791-843,964-994`, `command.rs:214-260`):**
1. `pool.get()` with `RecyclingMethod::Verified` → **+1 RTT** (`simple_query("")`) on recycled connections (`deadpool-postgres-0.14.2/src/config.rs:369`, `lib.rs:160-161`).
2. `batch_execute("BEGIN; SET LOCAL statement_timeout = ...")` → **1 RTT**.
3. `LOCKED_MAILBOX_SCOPE` (`set_config('app.current_mailbox_id', ...)` + `pg_advisory_xact_lock(...)`) → **1 RTT**.
4. `USER_SCOPE` (`set_config('app.current_user_id', ...)`) → **1 RTT**.
5. `AUDIT_SCOPE` (when `audit_keys` configured: `set_config` for `app.encryption_key` and `app.audit_hmac_key`) → **1 RTT**.
6. Command statement(s) (`tx.query(...)`; `run_receipted_command_capped` adds `FOR UPDATE` + `count_sql` = +2 RTTs) → **1–3 RTTs**.
7. `INSERT INTO public.rust_operation_receipts` → **1 RTT**.
8. `batch_execute("COMMIT")` → **1 RTT**.

**Total today:** **6–9 network RTTs** per command (**5–8 RTTs** excluding pool checkout ping).

---

## 1. Protocol-Level Prepared Statements in PgBouncer Transaction Pooling (`≥1.21–1.24`) & Rust Drivers

### 1.1 PgBouncer `max_prepared_statements` Mechanics & Version Evolution

- **PgBouncer 1.21.0 (Oct 2023):** Introduced protocol-level named prepared statement support in `transaction` and `statement` pooling modes when `max_prepared_statements > 0` (default `0` in 1.21–1.23) ([PgBouncer Changelog](https://www.pgbouncer.org/changelog.html), [PgBouncer Config](https://www.pgbouncer.org/config.html)).
  - PgBouncer intercepts Extended Query protocol `Parse` / `Bind` / `Execute` / `Close` messages, deduplicates unique query strings across all clients regardless of client-chosen statement names, maps them internally to `PGBOUNCER_{unique_id}` on backend connections, and transparently re-prepares statements on-the-fly whenever a client's transaction hops to a backend connection that lacks that statement ([PgBouncer Features](https://www.pgbouncer.org/features.html), [PgBouncer Config](https://www.pgbouncer.org/config.html)).
- **PgBouncer 1.22.0 / 1.22.1 (Jan–Mar 2024):** Added tracking for `DEALLOCATE ALL` and `DISCARD ALL` when `max_prepared_statements > 0`, and fixed `COPY FROM STDIN` prepared-statement state bugs introduced in 1.21.0 ([PgBouncer Changelog](https://www.pgbouncer.org/changelog.html)).
- **PgBouncer 1.24.0 (Jan 2025):** Changed `max_prepared_statements` default from `0` to **`200`** (enabled by default) and exposed prepared statement counters in `SHOW STATS` ([PgBouncer Changelog](https://www.pgbouncer.org/changelog.html), [PgBouncer Config](https://www.pgbouncer.org/config.html)).

### 1.2 Pool-Reset, Eviction, and Protocol Caveats

1. **Per-server LRU cache & eviction:** `max_prepared_statements` *"controls the number of prepared statements kept active in an LRU cache on a single server connection"* ([PgBouncer Config](https://www.pgbouncer.org/config.html)). If distinct prepared `(SQL, parameter types)` exceed `max_prepared_statements`, PgBouncer evicts the LRU entry on the server connection and must re-`Parse` on subsequent use. Large values also increase PostgreSQL backend memory (`PreparedStatement` / `CachedPlanSource` structures retained per backend process).
2. **`server_reset_query` vs `server_reset_query_always`:** Default `server_reset_query` is `DISCARD ALL`, which runs in **session** mode only; in **transaction** mode it is skipped unless `server_reset_query_always = 1` ([PgBouncer Config](https://www.pgbouncer.org/config.html)). Enabling `server_reset_query_always = 1` with `DISCARD ALL` wipes server-side prepared statements (`DEALLOCATE ALL`) on every transaction release and defeats prepared statement caching. Setjoin's transaction-local `set_config(..., true)` pattern is already compatible with `server_reset_query_always = 0`.
3. **SQL-level `PREPARE` / `DEALLOCATE <name>` still unsupported:** Explicit SQL `PREPARE name AS ...`, `EXECUTE name`, and single-statement `DEALLOCATE name` are forwarded unrewritten and still break transaction pooling (`42P05` / `26000`). Only `DEALLOCATE ALL` and `DISCARD ALL` are intercepted cleanly in ≥1.22 ([PgBouncer Config](https://www.pgbouncer.org/config.html), [PgBouncer Features](https://www.pgbouncer.org/features.html)).
4. **Unnamed statements (`""`) bypass tracking completely:** Extended-query messages using statement name `""` are ephemeral on the backend, consume zero `max_prepared_statements` LRU slots, and require no cross-backend mapping.

### 1.3 Driver Behavior (`tokio-postgres`, `deadpool-postgres`, `sqlx`)

Verified directly in pinned `tokio-postgres-0.7.18` and `deadpool-postgres-0.14.2` sources:

- **`tokio-postgres` `0.7.18`:**
  - **`client.query(&str, ...)` / `execute(&str, ...)` (`to_statement.rs:17-22`, `prepare.rs:61-133`, `statement.rs:15-30`):** Passing a raw `&str` invokes `prepare::prepare`, allocating a global monotonic name `s0`, `s1`, ... (`NEXT_ID`), sending `Parse(name) + Describe('S', name) + Sync` (1 RTT), then `Bind + Execute + Sync` (1 RTT), then firing `Close('S', name) + Sync` on `StatementInner::drop` — **3 protocol round-trips** and unnecessary PgBouncer named-statement churn.
  - **`query_typed` / `query_typed_raw` / `execute_typed` (`query.rs:62-173`):** Encodes `Parse("", query, param_oids) + Bind("", "", ...) + Describe('S', "") + Execute("", 0) + Sync` in **one buffer / 1 RTT** with no `Close`.
  - **Hidden named statement trap (`prepare.rs:135-151`):** Both `prepare` and `query_typed_raw` call `get_type(client, field.type_oid())` for every result column. If any OID is not built-in (`Type::from_oid(oid).is_none()`), `get_type` prepares and executes `TYPEINFO_QUERY` (`SELECT ... FROM pg_catalog.pg_type WHERE t.oid = $1`) as a **named** statement `sN`! Setjoin's existing rule (`lib.rs:16-18`: cast custom enums/domains to `text` in result lists) prevents this fallback.
- **`deadpool-postgres` `0.14.2`:**
  - **`StatementCache` (`statement_cache.rs:100-182`):** Keyed by `(query, &[Type])` per `ClientWrapper` using `RwLock<HashMap<..., Arc<OnceCell<Statement>>>>`. It is **unbounded (no LRU eviction)**. If used for non-trivial sets of queries over long-lived pool connections, `Statement`s are never dropped/`Close`d on the client, and once distinct statements exceed PgBouncer's `max_prepared_statements`, PgBouncer must evict and re-prepare on backend hops.
  - **`RecyclingMethod` (`config.rs:308-374`):** `Verified` sends `simple_query("")` on every `pool.get()` (+1 RTT). `Clean` runs `CLOSE ALL; SET SESSION AUTHORIZATION DEFAULT; RESET ALL; UNLISTEN *; SELECT pg_advisory_unlock_all(); DISCARD TEMP; DISCARD SEQUENCES;` (explicitly avoiding `DEALLOCATE ALL`/`DISCARD PLANS` to preserve `StatementCache`, though `RESET ALL` clears session GUCs). `Fast` checks only `client.is_closed()` (0 RTT, detects dead sockets on first query).
- **`sqlx` (0.8.x):**
  - `PgConnectOptions::statement_cache_capacity` defaults to `100` with per-connection LRU eviction (issuing protocol `Close` on eviction) ([`docs.rs/sqlx`](https://docs.rs/sqlx/latest/sqlx/postgres/struct.PgConnectOptions.html)).
  - Setting `statement_cache_capacity(0)` without `.persistent(false)` has historical footguns around unnamed/named statement tracking ([`launchbadge/sqlx#67`](https://github.com/launchbadge/sqlx/issues/67)); `.persistent(false)` forces unnamed execution.

---

## 2. Query Pipelining (`tokio-postgres` vs `sqlx`) and Writeable CTEs

### 2.1 `tokio-postgres` `0.7.18` Pipelining Mechanics (1 RTT Multi-Statement)

Verified directly in `tokio-postgres-0.7.18/src/connection.rs` and `client.rs`:

1. **`Client` is `Send + Sync` (`client.rs:87-93,181-189`):** All query methods take `&self`, encode their frame under `buffer: Mutex<BytesMut>`, and send `Request { messages, sender }` into an `mpsc::UnboundedSender<Request>`.
2. **Concurrent poll = single TCP flush (`connection.rs:172-263,301-309`):** Futures do not send anything until **first polled** ([`docs.rs/tokio-postgres`](https://docs.rs/tokio-postgres/latest/tokio_postgres/#pipelining)). When polled concurrently in one task turn via `tokio::join!(f1, f2, f3, ...)`, every future pushes its `Request` into the unbounded channel synchronously on its first poll. When `Connection::poll_write` runs, it loops draining all queued `Request`s into `Framed` (`start_send`) and calls `poll_flush` **once**, putting the entire multi-statement sequence on the wire in **1 network RTT**.
3. **Wire shape differs from `libpq` pipeline mode:**
   - In PostgreSQL `libpq` pipeline mode (`PQenterPipelineMode` + `PQpipelineSync`), multiple `Parse`/`Bind`/`Execute` sequences share **one** trailing `Sync` ([PostgreSQL 17 docs §32.5.1](https://www.postgresql.org/docs/17/libpq-pipeline-mode.html), [§53.2.2](https://www.postgresql.org/docs/17/protocol-flow.html)).
   - In `tokio-postgres` `0.7.18`, *every* `query_typed_raw`/`execute_typed`/`execute` buffer ends with `frontend::sync(buf)` (`query.rs:80,141,265`), and `batch_execute` sends a Simple Query message `Query(...)` (`simple_query.rs:46-69`). Thus `tokio::join!` sends:
     ```text
     [Query("BEGIN; SET LOCAL statement_timeout = 2000")]
     [Parse("") + Bind + Describe + Execute + Sync]   -- combined scope + advisory lock
     [Parse("") + Bind + Describe + Execute + Sync]   -- command / writeable CTE
     [Parse("") + Bind + Describe + Execute + Sync]   -- receipt INSERT (if separate)
     [Query("COMMIT")]
     ```
     all in **1 TCP flush (1 RTT)**.
4. **Error handling inside `tokio::join!` (`BEGIN ... COMMIT`) vs `try_join!`:**
   - Because each statement has its own `Sync`, if the scope/lock or command statement fails inside `BEGIN`, PostgreSQL emits `ErrorResponse` + `ReadyForQuery('E')`, rejects any subsequent non-`COMMIT`/`ROLLBACK` statement in the pipeline with SQLSTATE `25P02` (`in_failed_sql_transaction`) + `ReadyForQuery('E')`, and then executes the trailing `Query("COMMIT")`.
   - In PostgreSQL, **`COMMIT` inside an aborted (`'E'`) transaction acts as `ROLLBACK`** ([PostgreSQL 17 `COMMIT`](https://www.postgresql.org/docs/17/sql-commit.html)): it returns `CommandComplete("ROLLBACK")` (so `batch_execute("COMMIT")` returns `Ok(())`) and `ReadyForQuery('I')`, leaving the backend cleanly idle for PgBouncer!
   - **Never use `tokio::try_join!`:** `try_join!` short-circuits and drops the remaining `COMMIT` future as soon as an earlier statement errors, returning while `COMMIT` and `ReadyForQuery` are still unread on the wire (`connection.rs:153-158` keeps draining internally, but the caller loses synchronization on transaction completion before `pool` return or `ROLLBACK`). Always use non-short-circuiting `tokio::join!` so every pipelined response through `COMMIT`'s `ReadyForQuery` is awaited.
5. **Why `sqlx` cannot do this:** `sqlx::PgConnection` query methods require `&mut self`, preventing concurrent `tokio::join!` pipelining on a single connection; `execute_many` was deprecated/removed; and `sqlx::raw_sql()` (multi-statement Simple Query) **does not support bind parameters** ([`docs.rs/sqlx::raw_sql`](https://docs.rs/sqlx/latest/sqlx/fn.raw_sql.html), [`launchbadge/sqlx`](https://github.com/launchbadge/sqlx)).

### 2.2 Writeable CTEs (`WITH ... INSERT ... UPDATE ... DELETE ... RETURNING`)

- **Shared MVCC Snapshot ([PostgreSQL 17 §7.8.4](https://www.postgresql.org/docs/17/queries-with.html#QUERIES-WITH-MODIFYING)):** All data-modifying CTEs and the outer statement execute against the **same snapshot**. Sibling CTEs cannot observe each other's mutations via table scans; values must pass explicitly through `RETURNING`. Statements targeting the same row twice across CTEs/outer query fail or have undefined visibility.
- **PostgreSQL 18 `OLD`/`NEW` in `RETURNING` ([PostgreSQL 18 Release Notes](https://www.postgresql.org/docs/18/release-18.html)):** Allows `RETURNING OLD.<col>, NEW.<col>` on `INSERT`/`UPDATE`/`DELETE`/`MERGE`, eliminating pre-update `SELECT`s for change detection (e.g., `jmap_email_set_update`'s no-op vs state-bump check) or `ON CONFLICT` insert-vs-update branching (`OLD IS NULL`).
- **CRITICAL TRAP — Do NOT fold `set_config` into the same `WITH` query as RLS-protected tables:**
  - An unreferenced `WITH scope AS (SELECT set_config(...))` CTE can be omitted entirely by the planner.
  - Even if referenced via `CROSS JOIN`, PostgreSQL attaches `(SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint)` as an `InitPlan` on the scan/`ModifyTable` node; executor `InitPlan` evaluation order relative to a `scope` CTE is fragile and can evaluate *before* `set_config` runs, reading `''`/stale GUC and failing closed (`0` rows or `42501`).
  - **Recommended pattern:** Keep `set_config(...)` + `pg_advisory_xact_lock(...)` as a **separate preceding pipelined statement** in the same 1-RTT `tokio::join!` (collapsing Setjoin's current 3 separate scope statements `LOCKED_MAILBOX_SCOPE` + `USER_SCOPE` + `AUDIT_SCOPE` into **one** `SELECT set_config(...), ...` statement). Because PostgreSQL executes pipelined statements strictly sequentially, the GUC is guaranteed committed to the transaction state before the CTE statement is parsed/initialized.
- **Limits of writeable CTEs vs PL/pgSQL reducers:** Multi-item batch operations with per-item isolated error recovery (`BEGIN ... EXCEPTION WHEN OTHERS` in `jmap_email_set_update`'s loop returning partial `updated` + `notUpdated` maps) cannot be expressed as a single atomic SQL CTE without failing the whole batch on one bad item — a key empirical axis for prototype `#524`.

---

## 3. Interaction of `SET LOCAL` + `FORCE ROW LEVEL SECURITY` with Plan Caching & Partition Pruning

### 3.1 Custom vs. Generic Plans (`plancache.c`, `plan_cache_mode`)

- Under `plan_cache_mode = auto` (default), PostgreSQL generates **custom plans** (substituting bound parameter values `$1, $2, ...`) for the **first 5 executions** of a prepared statement on a backend connection, then builds a **generic plan** on the 6th execution and switches permanently for that backend if the generic plan's estimated cost (including planning savings) is ≤ average custom cost ([PostgreSQL 17 `PREPARE`](https://www.postgresql.org/docs/17/sql-prepare.html)).
- **How Setjoin's `FORCE RLS` + `SET LOCAL` interacts:**
  - Setjoin's RLS policy uses `(SELECT NULLIF(current_setting('app.current_mailbox_id', true), '')::bigint)` (`V003__rls_policies.sql:60,79`). Because `current_setting()` is `STABLE` (not `IMMUTABLE` and not a bind parameter), **custom plans do NOT inline the GUC value at plan time**; both custom and generic plans compile it as an `InitPlan` evaluated once per execution.
  - **Bind-parameter skew hazard (R1/R3):** Setjoin's queries *also* bind `mailbox_id = $1` (R1/R3). On executions 1–5 (custom plans), PostgreSQL uses MCV/histogram statistics for the specific `$1` mailbox; on execution 6+, a generic plan assumes uniform `1 / ndistinct(mailbox_id)` selectivity. Across mailboxes with skewed sizes (e.g., 50 vs 5,000,000 messages) sharing backends via PgBouncer, a generic plan locked in by 5 small mailboxes can produce bad index/join choices for large mailboxes (and vice versa). Setting `SET LOCAL plan_cache_mode = force_custom_plan` (or keeping unnamed `query_typed_raw`) avoids this at the cost of per-execution planning CPU.
- **Security & Cached Plan Invalidation (`CVE-2026-14666`):**
  - Custom GUCs (`app.current_mailbox_id`) do not invalidate cached plans and do not need to because `InitPlan` reads the GUC dynamically each execution.
  - Role attributes, role memberships, and RLS policies *do* govern plan validity. PostgreSQL fixed incomplete cached-plan invalidation across role/membership/RLS changes in **CVE-2026-14666** (patched in PostgreSQL **18.6, 17.11, 16.15, 15.19, 14.24**, August 2026) ([PostgreSQL Security Advisory CVE-2026-14666](https://www.postgresql.org/support/security/CVE-2026-14666/)). Production clusters using prepared statements + RLS should enforce these patch levels as a minimum floor.
  - Under `setjoin_app` (non-owner, non-superuser, non-`BYPASSRLS`) with `SET ROLE` blocked by `statement::admit`, `FORCE ROW LEVEL SECURITY` on `messages`/`message_tags` remains strictly active across all cached plans.

### 3.2 Partition Pruning on `received_at`-Partitioned Tables (`messages`, `message_tags`)

- **Plan-time vs Execution-time pruning (`enable_partition_pruning = on`, [PostgreSQL 17 §5.12.4](https://www.postgresql.org/docs/17/ddl-partitioning.html)):**
  - **Unnamed queries / custom plans:** When `received_at` is supplied as a bind parameter (`WHERE received_at = $2` or `>= $2`), PostgreSQL performs **plan-time partition pruning** — non-matching monthly partitions are omitted from the plan entirely.
  - **Generic plans (6th+ execution of prepared statements):** `received_at` is an unknown `Param` at plan time, so plan-time pruning cannot occur. PostgreSQL instead uses **execution-time (run-time) partition pruning**:
    - Works for `SELECT` (`Append` / `MergeAppend` startup & execution pruning) and, since **PostgreSQL 14**, also works for `UPDATE` and `DELETE` (`ModifyTable` startup pruning) ([PostgreSQL 14+ Partitioning / Release Notes](https://www.postgresql.org/docs/17/ddl-partitioning.html)).
    - Requires the query's `WHERE` clause to constrain `received_at` directly with prunable operators (`=`, `<`, `<=`, `>`, `>=`, `BETWEEN`).
- **Setjoin-specific gap observed (`mailserver/sql/reducers/jmap_email.sql:473,495,506,547`):** Current `jmap_email_set_update` queries `messages` by `WHERE id = v_id AND mailbox_id = p_mailbox_id` **without `received_at`**, which touches **all** monthly partitions regardless of custom vs. generic planning. Only lookups/joins carrying `received_at` (such as `message_tags`'s `(message_id, received_at)` FK and `messages_mailbox_covering_idx ON (received_at, id) INCLUDE (mailbox_id)`) prune partitions.

---

## 4. Unknown-Commit Recovery Semantics under Pipelining

Comparing Setjoin's current multi-RTT `ScopedExecutor` (`executor.rs:791-843,1065-1137`, `command.rs:214-285`) against a 1-RTT pipelined `BEGIN; SET LOCAL statement_timeout → scope+lock → command/CTE → receipt → COMMIT`:

| Property | Current Multi-RTT `ScopedTx` | 1-RTT Pipelined `ScopedTx` |
|---|---|---|
| **When `COMMIT` hits the wire** | Only *after* `decode(&rows)` and receipt `INSERT` succeed and `request_commit(auth, now)` passes | Flushed in the **same initial RTT** as `BEGIN`, scope, write, and receipt |
| **Rust pre-commit `decode()` veto** | Supported (decoder error triggers `ROLLBACK`, never sends `COMMIT`) | **Impossible:** `COMMIT` is already in flight before `DataRow`s arrive; all validation/cap/`BZ*` rejections must raise errors in SQL so PG aborts to `'E'` before `COMMIT` |
| **Mid-flight statement error (`ErrorResponse`)** | `tx.fail()`, skips remaining Rust calls, issues `ROLLBACK` | PG enters `'E'`; subsequent pipelined ops return `25P02`; trailing `COMMIT` executes as `ROLLBACK` (`ReadyForQuery('I')`). **Provably `RolledBack`** even if socket later drops |
| **Socket drop / timeout / future cancel after flush** | `Unknown` only if during `COMMIT`; before `COMMIT` + acknowledged `ROLLBACK` = `RolledBack` | **Always `CommandOutcome::Unknown { operation }`** unless a prior server `ErrorResponse` already arrived; connection **must be quarantined (`Object::take`)** |
| **Advisory lock + `lookup_command` composition** | `pg_advisory_xact_lock` held across RTTs until `COMMIT`, `lookup_command` blocks until writer commits/aborts | **Preserved identically:** `pg_advisory_xact_lock` is pipelined before the write and held until PG finishes `COMMIT`/`ROLLBACK`; `lookup_command` still serializes cleanly |
| **Orphaned backend lock hold on client timeout/cancel** | `ReadLease::drop` sends `CancelRequest`; `Lease::drop` relies on `statement_timeout` / drop | Must send **`CancelRequest`** on client timeout/drop (PgBouncer forwards cancel keys to the active backend) **and** keep `SET LOCAL statement_timeout` inside the `BEGIN` frame so a lost client cannot hold `pg_advisory_xact_lock` indefinitely |
| **External side-effect commands (`run_receipted_effect`)** | Holds lock across S3 copy before DB commit | **Not collapsible to 1 RTT** (external I/O sits between preflight lock and final commit) |

---

## 5. Concrete Recommendations for Prototype `#524` & Target Decisions (`#526`, `#527`)

1. **Keep `tokio-postgres` `0.7.18`; do not migrate `ScopedTx` to `sqlx`.** `sqlx::PgConnection` (`&mut self`) prevents `tokio::join!` pipelining and `sqlx::raw_sql()` lacks bind parameters.
2. **Collapse scope statements and benchmark two 1-RTT designs in `#524`:**
   - **Baseline fix (orthogonal to CTE vs reducer):** Merge `LOCKED_MAILBOX_SCOPE` + `USER_SCOPE` + `AUDIT_SCOPE` into **one** `SELECT set_config(...), ..., pg_advisory_xact_lock(...)` statement, and test `RecyclingMethod::Fast` vs `Verified` (currently adding +1 RTT to every `pool.get()`).
   - **Variant A (1-RTT Unnamed Pipelined):** `tokio::join!` over `BEGIN; SET LOCAL statement_timeout` + merged scope/lock + writeable CTE (+ `OLD`/`NEW` `RETURNING` on PG 18) + receipt `INSERT` + `COMMIT` using `query_typed_raw` (no `max_prepared_statements` dependency, always custom-planned).
   - **Variant B (1-RTT Named Prepared):** Same pipeline using `Statement`s with `max_prepared_statements = 200` on PgBouncer ≥1.24, testing `plan_cache_mode = auto` vs `force_custom_plan` under skewed mailbox sizes and measuring parse/plan CPU savings vs `Variant A`. If adopted, replace `deadpool-postgres`'s unbounded `StatementCache` with a bounded LRU cache (`≤ max_prepared_statements`).
3. **Require `received_at` (when available from client/ID index) in hot-path `messages`/`message_tags` SQL** if relying on generic plans so `ModifyTable` / `Append` execution-time partition pruning can eliminate historical partitions.
4. **Enforce minimum platform floors:** PgBouncer **≥1.24** (if enabling prepared statements) with `server_reset_query_always = 0`, and PostgreSQL **≥17.11 / ≥18.6** (CVE-2026-14666 RLS plan-cache fix).
