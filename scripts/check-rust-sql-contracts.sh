#!/usr/bin/env bash
# guard-requires: db
# check-rust-sql-contracts.sh — Wave 1.3 disposable-Postgres SQL contract guard (#541).
#
# 1. Runs static scanner `scripts/check-rust-sql-contracts.py` (proc-macro/sqlx ban,
#    zero `format!` SQL interpolation, zero uncataloged SQL in enforced crates,
#    monotonic legacy ratchet on pre-Wave-1.8 crates).
# 2. Runs `verify-sql-contracts` against live PostgreSQL 17 under `setjoin_app`
#    (NOBYPASSRLS, NOSUPERUSER) and worker credentials.
set -euo pipefail
# shellcheck disable=SC1091
source "$(dirname "$0")/_base.sh"

CARGO="${SERVER_RUST_CARGO:-cargo}"

python3 "$ROOT/scripts/check-rust-sql-contracts.py" --root "$ROOT"

if ! command -v "$CARGO" >/dev/null 2>&1; then
  echo "✗ check-rust-sql-contracts: cargo not found ($CARGO)" >&2
  exit 1
fi

if [[ -z "${TEST_DB_DSN:-${DB_DSN:-${DB_APP_DSN:-}}}" ]]; then
  echo "✗ check-rust-sql-contracts: TEST_DB_DSN, DB_DSN, or DB_APP_DSN is required" >&2
  exit 1
fi

if ! "$CARGO" fetch --manifest-path "$ROOT/server-rust/Cargo.toml" --locked --offline >/dev/null 2>&1; then
  "$CARGO" fetch --manifest-path "$ROOT/server-rust/Cargo.toml" --locked
fi

"$CARGO" run --locked --offline \
  --manifest-path "$ROOT/server-rust/Cargo.toml" \
  -p setjoin-sql-contracts \
  --bin verify-sql-contracts
