#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-schema-determinism.sh — fresh-load DETERMINISM guard (D2-a).
#
# Builds the combined test schema TWICE through scripts/load-test-schema.sh into
# two databases, `pg_dump --schema-only` each, normalizes away the cosmetic
# noise (dump banner, SET / SELECT pg_catalog.set_config, OWNER TO, COMMENTs,
# blank lines), and asserts the two dumps are BYTE-IDENTICAL.
#
# WHAT THIS PROVES. It proves the loader is DETERMINISTIC: building twice from the
# single V001 baseline (→ reducers → fixtures) produces a byte-identical schema,
# independent of run-to-run ordering. Post-collapse (ARCH-007) the schema↔migration
# duplication is gone (one baseline, one home), so the old fresh-vs-replay
# convergence guard retired — this determinism double-build is the surviving
# load-bearing schema guard.
#
# COST. This is the slow guard (it rebuilds the DB twice). It is wired into
# scripts/test.sh but is the heaviest static check; run it last.
#
# Requires: pg_dump 17.x on PATH (PG_DUMP override; default /opt/homebrew/bin/pg_dump
# then `pg_dump`). A non-empty diff on the first run is a REAL finding (the loader
# is non-deterministic) — surface it, don't normalize it away.
#
# Usage: scripts/check-schema-determinism.sh   (exit 0 = identical, 1 = drift / no DB).
#
# guard-requires: db
# (machine-read by run-guards.sh --no-db: this guard needs a live Postgres.)
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"
set +e

DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-mail}"
DB_A="${DB_A:-mailserver_determinism_a}"
DB_B="${DB_B:-mailserver_determinism_b}"

# pg_dump 17.x (the schema was authored against 17.10).
PG_DUMP="${PG_DUMP:-}"
if [ -z "$PG_DUMP" ]; then
  if [ -x /opt/homebrew/bin/pg_dump ]; then PG_DUMP=/opt/homebrew/bin/pg_dump
  else PG_DUMP=pg_dump; fi
fi

echo "==> schema-determinism guard (double-build + normalized pg_dump diff)"
echo "    using $($PG_DUMP --version 2>/dev/null || echo 'pg_dump: NOT FOUND')"

if ! command -v "$PG_DUMP" >/dev/null 2>&1 && [ ! -x "$PG_DUMP" ]; then
  echo "  pg_dump not found ($PG_DUMP) — cannot run the determinism guard."
  exit 1
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres \
        -c "DROP DATABASE IF EXISTS $DB_A WITH (FORCE);" >/dev/null 2>&1; \
      psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres \
        -c "DROP DATABASE IF EXISTS $DB_B WITH (FORCE);" >/dev/null 2>&1' EXIT

# normalize: strip the non-structural noise that varies between/within dumps.
# Note `\restrict`/`\unrestrict`: pg_dump 17.x emits a RANDOM per-dump session
# token on these lines (a dump-hardening feature, not schema) — it differs on
# every invocation and MUST be stripped, exactly like the banner. The DDL between
# them is what we compare.
normalize() {
  grep -vE '^(--|SET |SELECT pg_catalog\.set_config|COMMENT |\\restrict|\\unrestrict)' "$1" \
    | grep -vE '^[[:space:]]*$' \
    | grep -vE 'OWNER TO '
}

build() { # <db>
  DB_NAME="$1" DB_HOST="$DB_HOST" DB_PORT="$DB_PORT" DB_USER="$DB_USER" \
    bash "$ROOT/scripts/load-test-schema.sh" > "$TMP/load_$1.log" 2>&1
  if ! grep -q "Schema loaded clean" "$TMP/load_$1.log"; then
    echo "  load-test-schema.sh did NOT load $1 cleanly:"
    tail -8 "$TMP/load_$1.log" | sed 's/^/      /'
    return 1
  fi
  return 0
}

echo "    build A ($DB_A) ..."
build "$DB_A" || exit 1
echo "    build B ($DB_B) ..."
build "$DB_B" || exit 1

"$PG_DUMP" -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" --schema-only "$DB_A" > "$TMP/a.sql" 2>"$TMP/a.err" || { echo "  pg_dump A failed:"; sed 's/^/      /' "$TMP/a.err"; exit 1; }
"$PG_DUMP" -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" --schema-only "$DB_B" > "$TMP/b.sql" 2>"$TMP/b.err" || { echo "  pg_dump B failed:"; sed 's/^/      /' "$TMP/b.err"; exit 1; }

normalize "$TMP/a.sql" > "$TMP/a.norm"
normalize "$TMP/b.sql" > "$TMP/b.norm"

if diff -u "$TMP/a.norm" "$TMP/b.norm" > "$TMP/diff.txt"; then
  echo "    two normalized schema dumps are BYTE-IDENTICAL — loader is deterministic."
  exit 0
else
  echo ""
  echo "  DETERMINISM DRIFT — two builds of the SAME loader produced different schema:"
  sed 's/^/      /' "$TMP/diff.txt" | head -60
  echo ""
  echo "  → the loader's apply order is non-deterministic (a same-version pair or a"
  echo "    glob/collation dependency). Pin it (LC_ALL=C sort is already enforced in"
  echo "    load-test-schema.sh) — a real diff here is a finding, not a flake."
  echo "  → BUT if this diff looks like MISSING objects (functions/tables present in one"
  echo "    build, absent in the other) rather than reordered DDL, suspect a swallowed"
  echo "    reducer-load failure — check the per-build load log ($TMP/load_*.log); the"
  echo "    loader now fails loudly on a reducer drop, so this should be rare."
  exit 1
fi
