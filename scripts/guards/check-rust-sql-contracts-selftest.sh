#!/usr/bin/env bash
# guard-requires: db
# check-rust-sql-contracts-selftest.sh — negative-mutant self-test for
# `scripts/check-rust-sql-contracts.{py,sh}` and `verify-sql-contracts` (#541).
#
# Proves all 8 named negative mutants fail deterministically (`grep -qF`):
#   1. Broken column name (`42703` / `nonexistent_col_mutant`)
#   2. Bind type mismatch (`42804` / `BIND_TYPE_MISMATCH`)
#   3. Result column type mismatch (`COLUMN_TYPE_MISMATCH`)
#   4. Custom OID >= 16384 (`CUSTOM_OID_FORBIDDEN`)
#   5. FORCE RLS violation as `setjoin_app` (`42501` / `RLS_VIOLATION`) AND
#      worker-only function called under `setjoin_app` (`42501`)
#   6. Unverified runtime `format!` SQL interpolation (`SQL_INTERPOLATION_FORBIDDEN`)
#   7. Uncataloged raw SQL literal (`UNCATALOGED_SQL`)
#   8. Proc-macro / `sqlx-macros` injection (`PROC_MACRO_FORBIDDEN`)
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/../_base.sh"

CARGO="${SERVER_RUST_CARGO:-cargo}"

if ! command -v "$CARGO" >/dev/null 2>&1; then
  echo "✗ check-rust-sql-contracts-selftest: cargo not found ($CARGO)" >&2
  exit 1
fi

if [[ -z "${TEST_DB_DSN:-${DB_DSN:-${DB_APP_DSN:-}}}" ]]; then
  echo "✗ check-rust-sql-contracts-selftest: TEST_DB_DSN, DB_DSN, or DB_APP_DSN is required" >&2
  exit 1
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/sql-contracts-selftest.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

if ! "$CARGO" fetch --manifest-path "$ROOT/server/Cargo.toml" --locked --offline >/dev/null 2>&1; then
  "$CARGO" fetch --manifest-path "$ROOT/server/Cargo.toml" --locked
fi

"$CARGO" build --locked --offline \
  --manifest-path "$ROOT/server/Cargo.toml" \
  -p setjoin-sql-contracts \
  --bin verify-sql-contracts >/dev/null

TARGET_DIR="${CARGO_TARGET_DIR:-$ROOT/server/target}"
BIN="$TARGET_DIR/debug/verify-sql-contracts"
if [[ ! -x "$BIN" ]]; then
  echo "✗ check-rust-sql-contracts-selftest: verifier binary missing at $BIN" >&2
  exit 1
fi

assert_mutant_fails() {
  local label="$1"
  local expected1="$2"
  local expected2="$3"
  shift 3
  local out rc=0
  out="$("$@" 2>&1)" || rc=$?
  if [[ "$rc" -eq 0 ]]; then
    echo "✗ selftest [$label]: expected non-zero exit, got 0" >&2
    echo "$out" >&2
    exit 1
  fi
  if ! grep -qF "$expected1" <<<"$out"; then
    echo "✗ selftest [$label]: missing expected marker '$expected1'" >&2
    echo "$out" >&2
    exit 1
  fi
  if [[ -n "$expected2" ]] && ! grep -qF "$expected2" <<<"$out"; then
    echo "✗ selftest [$label]: missing expected marker '$expected2'" >&2
    echo "$out" >&2
    exit 1
  fi
  echo "  ✓ mutant rejected: $label ($expected1${expected2:+ / $expected2})"
}

# Mutant 1: Broken column name (42703 / nonexistent_col_mutant)
cat >"$TMP/m1_broken_col.json" <<'JSON'
[
  {
    "id": "mutant.broken_column",
    "domain": "selftest",
    "sql": "SELECT nonexistent_col_mutant FROM users WHERE id = $1",
    "params": ["int8"],
    "columns": [{"name": "nonexistent_col_mutant", "ty": "text"}],
    "scope": "UserScoped",
    "rls_check": "PrepareAndExplain"
  }
]
JSON
assert_mutant_fails "1. broken column name" "42703" "nonexistent_col_mutant" \
  "$BIN" --mutant-json "$TMP/m1_broken_col.json"

# Mutant 2: Bind type mismatch (42804 / BIND_TYPE_MISMATCH)
cat >"$TMP/m2_bind_type.json" <<'JSON'
[
  {
    "id": "mutant.bind_type_mismatch",
    "domain": "selftest",
    "sql": "SELECT COALESCE(id, $1) FROM users",
    "params": ["text"],
    "columns": [{"name": null, "ty": "int8"}],
    "scope": "UserScoped",
    "rls_check": "PrepareAndExplain"
  }
]
JSON
assert_mutant_fails "2. bind type mismatch" "42804" "BIND_TYPE_MISMATCH" \
  "$BIN" --mutant-json "$TMP/m2_bind_type.json"

# Mutant 3: Result column type mismatch (COLUMN_TYPE_MISMATCH)
cat >"$TMP/m3_col_type.json" <<'JSON'
[
  {
    "id": "mutant.column_type_mismatch",
    "domain": "selftest",
    "sql": "SELECT id FROM users WHERE id = $1",
    "params": ["int8"],
    "columns": [{"name": "id", "ty": "text"}],
    "scope": "UserScoped",
    "rls_check": "PrepareAndExplain"
  }
]
JSON
assert_mutant_fails "3. result column type mismatch" "COLUMN_TYPE_MISMATCH" "" \
  "$BIN" --mutant-json "$TMP/m3_col_type.json"

# Mutant 4a: Server-returned custom OID >= 16384 (CUSTOM_OID_FORBIDDEN)
cat >"$TMP/m4a_custom_oid_server.json" <<'JSON'
[
  {
    "id": "mutant.custom_oid_server",
    "domain": "selftest",
    "sql": "SELECT NULL::vacation_settings AS vs",
    "params": [],
    "columns": [{"name": "vs", "ty": "text"}],
    "scope": "UserScoped",
    "rls_check": "PrepareAndExplain"
  }
]
JSON
assert_mutant_fails "4a. server custom OID >= 16384" "CUSTOM_OID_FORBIDDEN" "" \
  "$BIN" --mutant-json "$TMP/m4a_custom_oid_server.json"

# Mutant 4b: Declared custom OID >= 16384 (CUSTOM_OID_FORBIDDEN)
cat >"$TMP/m4b_custom_oid_declared.json" <<'JSON'
[
  {
    "id": "mutant.custom_oid_declared",
    "domain": "selftest",
    "sql": "SELECT $1::text",
    "params": ["oid:20000"],
    "columns": [{"name": null, "ty": "text"}],
    "scope": "UserScoped",
    "rls_check": "PrepareAndExplain"
  }
]
JSON
assert_mutant_fails "4b. declared custom OID >= 16384" "CUSTOM_OID_FORBIDDEN" "" \
  "$BIN" --mutant-json "$TMP/m4b_custom_oid_declared.json"

# Mutant 5a: FORCE RLS write violation as setjoin_app (42501 / RLS_VIOLATION)
cat >"$TMP/m5a_rls_write.json" <<'JSON'
[
  {
    "id": "mutant.rls_write_violation",
    "domain": "selftest",
    "sql": "INSERT INTO calendar_subscriptions (user_id, calendar_id, url) VALUES ($1 + 1, $2, $3) RETURNING id",
    "params": ["int8", "int8", "text"],
    "columns": [{"name": "id", "ty": "int8"}],
    "scope": "UserScoped",
    "rls_check": "PrepareExplainAndRlsDenyProbe"
  }
]
JSON
assert_mutant_fails "5a. FORCE RLS write violation (setjoin_app)" "42501" "RLS_VIOLATION" \
  "$BIN" --mutant-json "$TMP/m5a_rls_write.json"

# Mutant 5b: Cross-tenant read leak failing FORCE RLS deny probe (RLS_VIOLATION)
# Note: V288 enforced FORCE RLS on `users`, so this mutant queries an RLS-exempt
# org table (`domains`) to simulate an unguarded read leaking a row under the
# foreign-tenant deny probe.
cat >"$TMP/m5b_rls_read_leak.json" <<'JSON'
[
  {
    "id": "mutant.rls_read_leak",
    "domain": "selftest",
    "sql": "SELECT id FROM domains WHERE id > 0 AND $1 > 0 LIMIT 1",
    "params": ["int8"],
    "columns": [{"name": "id", "ty": "int8"}],
    "scope": "UserScoped",
    "rls_check": "PrepareExplainAndRlsDenyProbe"
  }
]
JSON
assert_mutant_fails "5b. FORCE RLS read leak (setjoin_app)" "RLS_VIOLATION" "" \
  "$BIN" --mutant-json "$TMP/m5b_rls_read_leak.json"

# Mutant 5c: Worker-only function called under setjoin_app (42501)
cat >"$TMP/m5c_worker_func.json" <<'JSON'
[
  {
    "id": "mutant.worker_only_func_as_app",
    "domain": "selftest",
    "sql": "SELECT lockout_check($1)::text",
    "params": ["text[]"],
    "columns": [{"name": null, "ty": "text"}],
    "scope": "UserScoped",
    "rls_check": "PrepareAndExplain"
  }
]
JSON
assert_mutant_fails "5c. worker-only function under setjoin_app" "42501" "lockout_check" \
  "$BIN" --mutant-json "$TMP/m5c_worker_func.json"

# Helper: build a clean throwaway workspace for static scanner negative mutants 6-8
make_static_fixture() {
  local dir="$1"
  mkdir -p "$dir/server/crates/sql-catalog/src" \
    "$dir/server/tests/sql-contracts/src" \
    "$dir/server/crates/domains/sample/src" \
    "$dir/config"
  cat >"$dir/server/crates/sql-catalog/Cargo.toml" <<'TOML'
[package]
name = "setjoin-sql-catalog"
version = "0.0.0"
edition = "2021"

[dependencies]
tokio-postgres = "0.7.18"
TOML
  cat >"$dir/server/tests/sql-contracts/Cargo.toml" <<'TOML'
[package]
name = "setjoin-sql-contracts"
version = "0.0.0"
edition = "2021"
TOML
  printf '# clean lockfile\n[[package]]\nname = "tokio-postgres"\nversion = "0.7.18"\n' \
    >"$dir/server/Cargo.lock"
  cat >"$dir/config/sql-contracts-legacy-ratchet.json" <<'JSON'
{
  "catalog_enforced_crates": ["sample"],
  "format_sql": {},
  "uncataloged_sql": {}
}
JSON
  printf 'pub fn ok() {}\n' >"$dir/server/crates/domains/sample/src/lib.rs"
}

# Mutant 6: Unverified runtime format! SQL interpolation (SQL_INTERPOLATION_FORBIDDEN)
make_static_fixture "$TMP/m6"
cat >"$TMP/m6/server/crates/domains/sample/src/lib.rs" <<'RS'
pub fn bad(col: &str) -> String {
    format!("SELECT {col} FROM users WHERE id = $1")
}
RS
assert_mutant_fails "6a. runtime format! SQL interpolation" "SQL_INTERPOLATION_FORBIDDEN" "" \
  python3 "$ROOT/scripts/guards/check-rust-sql-contracts.py" --root "$TMP/m6"

# Mutant 6b: Nested concat! inside runtime format! SQL interpolation
make_static_fixture "$TMP/m6b"
cat >"$TMP/m6b/server/crates/domains/sample/src/lib.rs" <<'RS'
pub fn bad_concat(col: &str) -> String {
    format!(concat!("SELECT ", "{col} FROM users WHERE id = $1"))
}
RS
assert_mutant_fails "6b. format!(concat!(...)) SQL interpolation" "SQL_INTERPOLATION_FORBIDDEN" "" \
  python3 "$ROOT/scripts/guards/check-rust-sql-contracts.py" --root "$TMP/m6b"

# Mutant 7a: Uncataloged raw SQL literal after '\\', '\'', and '"' char literals (UNCATALOGED_SQL)
make_static_fixture "$TMP/m7"
cat >"$TMP/m7/server/crates/domains/sample/src/lib.rs" <<'RS'
pub fn bad() -> &'static str {
    let _bs = '\\';
    let _sq = '\'';
    let _dq = '"';
    "SELECT id FROM users WHERE id = $1"
}
RS
assert_mutant_fails "7a. uncataloged raw SQL literal (char literals)" "UNCATALOGED_SQL" "" \
  python3 "$ROOT/scripts/guards/check-rust-sql-contracts.py" --root "$TMP/m7"

# Mutant 7b: Uncataloged SQL inside #[cfg(not(test))] must NOT be skipped
make_static_fixture "$TMP/m7b"
cat >"$TMP/m7b/server/crates/domains/sample/src/lib.rs" <<'RS'
#[cfg(not(test))]
pub fn prod_only() -> &'static str {
    "WITH RECURSIVE t(id) AS (SELECT id FROM users WHERE id = $1) SELECT id FROM t"
}
RS
assert_mutant_fails "7b. #[cfg(not(test))] WITH RECURSIVE SQL" "UNCATALOGED_SQL" "" \
  python3 "$ROOT/scripts/guards/check-rust-sql-contracts.py" --root "$TMP/m7b"

# Mutant 8a: proc-macro = true in crates/sql-catalog/Cargo.toml (PROC_MACRO_FORBIDDEN)
make_static_fixture "$TMP/m8a"
printf '\n[lib]\nproc-macro = true\n' >>"$TMP/m8a/server/crates/sql-catalog/Cargo.toml"
assert_mutant_fails "8a. proc-macro=true injection" "PROC_MACRO_FORBIDDEN" "" \
  python3 "$ROOT/scripts/guards/check-rust-sql-contracts.py" --root "$TMP/m8a"

# Mutant 8b: sqlx-macros in Cargo.lock (PROC_MACRO_FORBIDDEN)
make_static_fixture "$TMP/m8b"
printf '\n[[package]]\nname = "sqlx-macros"\nversion = "0.8.0"\n' \
  >>"$TMP/m8b/server/Cargo.lock"
assert_mutant_fails "8b. sqlx-macros Cargo.lock injection" "PROC_MACRO_FORBIDDEN" "" \
  python3 "$ROOT/scripts/guards/check-rust-sql-contracts.py" --root "$TMP/m8b"

# Mutant 9a: Forged ReducerWritesCoreAudit outside crates/domains/*/src/sql.rs
make_static_fixture "$TMP/m9a"
cat >"$TMP/m9a/server/crates/domains/sample/src/lib.rs" <<'RS'
use setjoin_sql_catalog::SqlAuditPosture;
pub const FORGED: SqlAuditPosture = SqlAuditPosture::ReducerWritesCoreAudit;
RS
assert_mutant_fails "9a. forged ReducerWritesCoreAudit outside sql.rs" "AUDIT_POSTURE_FORBIDDEN" "" \
  python3 "$ROOT/scripts/guards/check-rust-sql-contracts.py" --root "$TMP/m9a"

# Mutant 9b: CTE-wrapped inline DML + audited reducer in src/sql.rs
make_static_fixture "$TMP/m9b"
mkdir -p "$TMP/m9b/sql/reducers"
cat >"$TMP/m9b/sql/reducers/rust_admin_role_delete.sql" <<'SQL'
CREATE OR REPLACE FUNCTION rust_admin_role_delete(p_actor bigint) RETURNS void AS $$
BEGIN
  PERFORM audit_write(p_actor, 'role_delete', 'role_group', 1, NULL, NULL, NULL, '', 'core');
END;
$$ LANGUAGE plpgsql;
SQL
cat >"$TMP/m9b/server/crates/domains/sample/src/sql.rs" <<'RS'
use setjoin_sql_catalog::{ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type};
pub const CTE_SMUGGLE: SqlContract = SqlContract {
    id: "sample.cte_smuggle",
    domain: "sample",
    sql: "WITH x AS (DELETE FROM users WHERE id = $2 RETURNING 1) SELECT rust_admin_role_delete($1)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};
RS
assert_mutant_fails "9b. CTE-wrapped DML + ReducerWritesCoreAudit" "AUDIT_POSTURE_SQL_INVALID" "" \
  python3 "$ROOT/scripts/guards/check-rust-sql-contracts.py" --root "$TMP/m9b"

# Mutant 9c: 'routine'-only reducer marked ReducerWritesCoreAudit
make_static_fixture "$TMP/m9c"
mkdir -p "$TMP/m9c/sql/reducers"
cat >"$TMP/m9c/sql/reducers/rust_admin_routine_only.sql" <<'SQL'
CREATE OR REPLACE FUNCTION rust_admin_routine_only(p_actor bigint) RETURNS void AS $$
BEGIN
  PERFORM audit_write(p_actor, 'routine_only', 'role_group', 1, NULL, NULL, NULL, '', 'routine');
END;
$$ LANGUAGE plpgsql;
SQL
cat >"$TMP/m9c/server/crates/domains/sample/src/sql.rs" <<'RS'
use setjoin_sql_catalog::{ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type};
pub const ROUTINE_ONLY: SqlContract = SqlContract {
    id: "sample.routine_only",
    domain: "sample",
    sql: "SELECT rust_admin_routine_only($1)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};
RS
assert_mutant_fails "9c. routine-only reducer marked ReducerWritesCoreAudit" "AUDIT_POSTURE_CORE_AUDIT_MISSING" "" \
  python3 "$ROOT/scripts/guards/check-rust-sql-contracts.py" --root "$TMP/m9c"

# Mutant 9d: EXCEPTION WHEN OTHERS wrapping core audit_write
make_static_fixture "$TMP/m9d"
mkdir -p "$TMP/m9d/sql/reducers"
cat >"$TMP/m9d/sql/reducers/rust_admin_swallow.sql" <<'SQL'
CREATE OR REPLACE FUNCTION rust_admin_swallow(p_actor bigint) RETURNS void AS $$
BEGIN
  BEGIN
    PERFORM audit_write(p_actor, 'swallowed', 'role_group', 1, NULL, NULL, NULL, '', 'core');
  EXCEPTION WHEN OTHERS THEN NULL;
  END;
END;
$$ LANGUAGE plpgsql;
SQL
cat >"$TMP/m9d/server/crates/domains/sample/src/sql.rs" <<'RS'
use setjoin_sql_catalog::{ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type};
pub const SWALLOWED_AUDIT: SqlContract = SqlContract {
    id: "sample.swallowed_audit",
    domain: "sample",
    sql: "SELECT rust_admin_swallow($1)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};
RS
assert_mutant_fails "9d. EXCEPTION WHEN OTHERS wrapping audit_write" "AUDIT_POSTURE_SWALLOWED_AUDIT" "" \
  python3 "$ROOT/scripts/guards/check-rust-sql-contracts.py" --root "$TMP/m9d"

# Mutant 9e: Non-$1 first argument (R2 p_actor bypass via $2 or literal)
make_static_fixture "$TMP/m9e1"
mkdir -p "$TMP/m9e1/sql/reducers"
cat >"$TMP/m9e1/sql/reducers/rust_admin_role_delete.sql" <<'SQL'
CREATE OR REPLACE FUNCTION rust_admin_role_delete(p_actor bigint, p_id bigint) RETURNS void AS $$
BEGIN
  PERFORM audit_write(p_actor, 'role_delete', 'role_group', p_id, NULL, NULL, NULL, '', 'core');
END;
$$ LANGUAGE plpgsql;
SQL
cat >"$TMP/m9e1/server/crates/domains/sample/src/sql.rs" <<'RS'
use setjoin_sql_catalog::{ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type};
pub const SWAPPED_ACTOR: SqlContract = SqlContract {
    id: "sample.swapped_actor",
    domain: "sample",
    sql: "SELECT rust_admin_role_delete($2, $1)",
    params: &[Type::INT8, Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};
RS
assert_mutant_fails '9e1. swapped $2 actor arg on ReducerWritesCoreAudit' "AUDIT_POSTURE_SQL_INVALID" "" \
  python3 "$ROOT/scripts/guards/check-rust-sql-contracts.py" --root "$TMP/m9e1"

make_static_fixture "$TMP/m9e2"
mkdir -p "$TMP/m9e2/sql/reducers"
cp "$TMP/m9e1/sql/reducers/rust_admin_role_delete.sql" \
  "$TMP/m9e2/sql/reducers/rust_admin_role_delete.sql"
cat >"$TMP/m9e2/server/crates/domains/sample/src/sql.rs" <<'RS'
use setjoin_sql_catalog::{ColumnSpec, RlsCheck, SqlAuditPosture, SqlContract, SqlScope, Type};
pub const LITERAL_ACTOR: SqlContract = SqlContract {
    id: "sample.literal_actor",
    domain: "sample",
    sql: "SELECT rust_admin_role_delete(1, $1)",
    params: &[Type::INT8],
    columns: &[ColumnSpec::unnamed(Type::VOID)],
    scope: SqlScope::AdminWrite,
    rls_check: RlsCheck::PrepareAndExplain,
    audit: SqlAuditPosture::ReducerWritesCoreAudit,
};
RS
assert_mutant_fails "9e2. literal actor arg on ReducerWritesCoreAudit" "AUDIT_POSTURE_SQL_INVALID" "" \
  python3 "$ROOT/scripts/guards/check-rust-sql-contracts.py" --root "$TMP/m9e2"

echo "✓ check-rust-sql-contracts-selftest: PASS (all 9 negative mutant classes rejected deterministically)"
