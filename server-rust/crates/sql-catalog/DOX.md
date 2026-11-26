# `setjoin-sql-catalog` — Zero-proc-macro typed SQL contract catalog (#541)

## Purpose

Leaf crate defining compile-time static SQL contracts (`SqlContract`, `SqlScope`,
`ColumnSpec`, `RlsCheck`) and zero-proc-macro `macro_rules!` SQL helpers
(`pg_rfc3339!`, `pg_go_utc_time!`). Depends **only** on `tokio-postgres`
(`types::Type`), with `#![forbid(unsafe_code)]`, zero procedural macros, zero
`syn`/`quote`, and zero `sqlx`.

## Contracts and invariants

- **Runtime protocol:** `setjoin-pg` capability transaction handles
  (`MailboxTx`, `UserTx`, `AdminReadTx`, `AdminSensitiveRead`, `AdminWriteTx`,
  `WorkerTx`) expose `query_contract` / `execute_contract` helpers taking
  `&'static SqlContract`. Execution continues to use PgBouncer-safe unnamed
  `query_typed_raw` — never named `prepare` or `TYPEINFO_QUERY`.
- **Built-in OIDs only:** every declared parameter and result column `Type`
  must have PostgreSQL OID `< 16384` (`CUSTOM_OID_FORBIDDEN`). Custom enums,
  domains, and composite types must be cast to built-in types (e.g. `::text`).
- **No runtime `format!` SQL:** domains eliminate runtime timestamp/column
  `format!` helpers with `pg_rfc3339!` / `pg_go_utc_time!` and `concat!`.
- **Verifier (`tests/sql-contracts` / `verify-sql-contracts`):**
  aggregates `SQL_CONTRACTS` across migrated domain crates (`blobs`, `rules`,
  `user-settings`, `approvals`, `calendar`) and verifies each contract against
  live disposable PostgreSQL 17 inside rolled-back transactions:
  1. Static preflight: non-empty catalog, unique IDs, `setjoin_pg::statement::admit`,
     zero custom OIDs (`>= 16384`).
  2. Fail-closed role preflight: `setjoin_app` (`rolsuper = false` AND
     `rolbypassrls = false`, PG `>= 170000`) plus `BYPASSRLS` worker role for
     `SqlScope::WorkerBypass`.
  3. Live `prepare_typed` checking exact parameter count/types, result column
     count/types/names, and server-returned OID `< 16384`.
  4. Scoped `EXPLAIN (COSTS OFF, FORMAT JSON)` verifying table/column/function
     `GRANT`s, `BEGIN READ ONLY` write refusal (`25006`), and `FORCE RLS`
     policy expansion under `setjoin_app`.
  5. Active `SAVEPOINT` deny probe for `RlsCheck::PrepareExplainAndRlsDenyProbe`
     against a seeded divergent-ID fixture (`user_id != mailbox_id`, cleaned up
     unconditionally) asserting `42501` or `0` visible rows under unset and
     foreign scope GUCs.

## Verification

- `bash scripts/check-rust-sql-contracts-selftest.sh` — proves all 8 negative
  mutant classes fail deterministically (broken column `42703`, bind type
  `42804`/`BIND_TYPE_MISMATCH`, column type `COLUMN_TYPE_MISMATCH`, custom OID
  `CUSTOM_OID_FORBIDDEN`, `FORCE RLS` violation `42501`/`RLS_VIOLATION` +
  worker-only function `42501`, `format!` SQL `SQL_INTERPOLATION_FORBIDDEN`,
  uncataloged raw SQL `UNCATALOGED_SQL`, proc-macro/`sqlx` injection
  `PROC_MACRO_FORBIDDEN`).
- `bash scripts/check-rust-sql-contracts.sh` — runs static scanner
  (`scripts/check-rust-sql-contracts.py` + `config/sql-contracts-legacy-ratchet.json`)
  and `verify-sql-contracts` against disposable PostgreSQL 17. Auto-discovered
  by `scripts/run-guards.sh` (`# guard-requires: db`).
