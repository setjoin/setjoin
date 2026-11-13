#!/usr/bin/env bash
# server-rust-parallel-lane.sh — the server-rust full lane on one Postgres cluster (#550).
#
#   LANE_MODE=parallel (default)  cargo nextest, one cloned database per test, 4-5 tests at once
#   LANE_MODE=serial              the reference lane: plain `cargo test` on one database
#
# Both modes run scripts/check-server-rust.sh unchanged otherwise (family isolation,
# cargo-deny, pilot, schema-simulation, bench-mark-read, adequacy), so a missing, ignored
# or skipped case is red in both.
#
# Inputs (the workflow exports them; a dev host sets them by hand):
#   LANE_PG_HOST/LANE_PG_PORT/LANE_PG_USER/PGPASSWORD   superuser of a throwaway cluster
#   LANE_DB_PREFIX    database name prefix, must contain `_e2e_` (default gofree_e2e_lane_);
#                     this script drops and recreates ONLY ${prefix}tpl and ${prefix}base
#                     and sweeps ${prefix}<24 hex> clones — never any other database
#   LANE_APP_PASSWORD password for setjoin_app (DB_APP_DSN); random when unset
#   LANE_JOBS         concurrent tests (default 5)
#   LANE_ARTIFACT_DIR where the log, junit.xml and test lists land
#   LANE_QUICK        1 = debug run: only `cargo nextest run -E "$LANE_NEXTEST_FILTER"` on the
#                     workspace (no other check, skipped tests allowed); never a lane result
#   LANE_COVERAGE     0 = the replays and mutants run but oracle coverage does not (hosted test
#                     shards); unset = coverage runs, as on a dev host. The hosted workflow also
#                     sets SERVER_RUST_STAGES, SERVER_RUST_NEXTEST_ARCHIVE/_EXTRACT_TO/_PARTITION,
#                     LANE_ADEQUACY_SHARD/_BINARIES/_COVERAGE_ONLY (see check-server-rust.sh)
#   LANE_ADEQUACY_JOBS replays and mutants run side by side (default LANE_JOBS)
#   LANE_SKIP_SCHEMA  1 = reuse an existing ${prefix}tpl (dev host iteration)
#   LANE_LEAK_GUARD   0 = do not make the base database refuse connections during the nextest
#                     and adequacy phases (default 1: a test that bypasses its clone fails loudly)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

MODE="${LANE_MODE:-parallel}"
HOST="${LANE_PG_HOST:-127.0.0.1}"
PORT="${LANE_PG_PORT:?LANE_PG_PORT is required}"
PGU="${LANE_PG_USER:-postgres}"
PREFIX="${LANE_DB_PREFIX:-gofree_e2e_lane_}"
case "$PREFIX" in *_e2e_*) ;; *) echo "LANE_DB_PREFIX must contain _e2e_ (load-test-schema.sh guard)" >&2; exit 2 ;; esac
: "${PGPASSWORD:?PGPASSWORD is required}"
export PGPASSWORD
ART="${LANE_ARTIFACT_DIR:-$ROOT/test-results/server-rust-lane}"
mkdir -p "$ART"
rm -f "$ART/lane-complete.txt"  # the receipt is written only when the lane reaches its end
TPL="${PREFIX}tpl" BASE="${PREFIX}base"
APP_PW="${LANE_APP_PASSWORD:-$(openssl rand -hex 16)}"

stamp() { echo "== lane $(date -u +%FT%TZ) $*"; }
admin() { psql -h "$HOST" -p "$PORT" -U "$PGU" -d postgres -X -q -v ON_ERROR_STOP=1 "$@"; }
dsn() { printf 'postgres://%s:%s@%s:%s/%s' "$1" "$2" "$HOST" "$PORT" "$3"; }
pw_enc() { python3 -c 'import sys,urllib.parse;print(urllib.parse.quote(sys.argv[1],safe=""))' "$1"; }
SUPER_PW="$(pw_enc "$PGPASSWORD")"

stamp "start mode=$MODE head=$(git rev-parse --short HEAD 2>/dev/null) jobs=${LANE_JOBS:-5}"

# ── schema: load once into the template, clone the base database from it ────────────────
if [[ "${LANE_SKIP_SCHEMA:-}" != 1 ]]; then
  stamp "loading schema into $TPL"
  DB_HOST="$HOST" DB_PORT="$PORT" DB_USER="$PGU" DB_NAME="$TPL" bash scripts/load-test-schema.sh >"$ART/schema.log" 2>&1 || {
    tail -40 "$ART/schema.log"
    echo "✗ lane: schema load failed" >&2
    exit 1
  }
  # Roles are cluster-wide: give setjoin_app a credential once (DB_APP_DSN consumers).
  admin -c "ALTER ROLE setjoin_app LOGIN PASSWORD '$APP_PW'" || exit 1
  # Season the sequences: the oracles normalise ids by substring replacement
  # (`<admin>`, `<other>`), which collides with small literals when every id starts at 1,
  # whereas the long-lived shared database the goldens were recorded against has large ids.
  # A fresh clone per test would otherwise see ids 1, 2, 3... (LANE_SEQUENCE_FLOOR=0 disables).
  floor="${LANE_SEQUENCE_FLOOR:-100000}"
  if [[ "$floor" -gt 0 ]]; then
    psql -h "$HOST" -p "$PORT" -U "$PGU" -d "$TPL" -X -q -v ON_ERROR_STOP=1 <<SQL || exit 1
DO \$\$
DECLARE r record; n int := 0;
BEGIN
  -- distinct value per sequence: equal ids across tables would defeat the normalisers too
  FOR r IN SELECT schemaname, sequencename, last_value, max_value FROM pg_sequences
           WHERE schemaname = 'public' ORDER BY sequencename LOOP
    n := n + 1;
    IF coalesce(r.last_value, 0) < $floor AND r.max_value > ($floor + n * 1009) * 10 THEN
      PERFORM setval(format('%I.%I', r.schemaname, r.sequencename), $floor + n * 1009);
    END IF;
  END LOOP;
END \$\$;
SQL
  fi
  admin -c "ALTER DATABASE \"$TPL\" WITH ALLOW_CONNECTIONS false" || exit 1
fi
admin -c "DROP DATABASE IF EXISTS \"$BASE\" WITH (FORCE)" -c "CREATE DATABASE \"$BASE\" TEMPLATE \"$TPL\"" || exit 1

BASE_DSN="$(dsn "$PGU" "$SUPER_PW" "$BASE")"
export TEST_DB_DSN="$BASE_DSN" DB_DSN="$BASE_DSN" DB_DIRECT_DSN="$BASE_DSN"
export DB_APP_DSN="$(dsn setjoin_app "$(pw_enc "$APP_PW")" "$BASE")"
export REQUIRE_DB=1
export LANE_ADMIN_DSN="$(dsn "$PGU" "$SUPER_PW" postgres)" LANE_TEMPLATE_DB="$TPL" LANE_BASE_DB="$BASE" LANE_DB_PREFIX="$PREFIX"
export GOFREE_AIRGAP_FIXTURE_ROOT="${GOFREE_AIRGAP_FIXTURE_ROOT:-/dev/shm}"
export LANE_JOBS="${LANE_JOBS:-5}"

# ── prerequisites that must exist, never be skipped ────────────────────────────────
for need in cargo python3 psql docker; do
  command -v "$need" >/dev/null || { echo "✗ lane: $need not on PATH" >&2; exit 1; }
done
if [[ "$MODE" == parallel ]]; then
  cargo nextest --version >/dev/null 2>&1 || { echo "✗ lane: cargo-nextest not installed (scripts/server-rust-lane-tools.sh)" >&2; exit 1; }
  export SERVER_RUST_NEXTEST=1
fi
cargo deny --version >/dev/null 2>&1 || { echo "✗ lane: cargo-deny not installed" >&2; exit 1; }
[[ -x "${PEBBLE_BIN:-}" ]] || { echo "✗ lane: PEBBLE_BIN is not an executable" >&2; exit 1; }
docker image inspect setjoin-ci-linux-tc:local-amd64 >/dev/null 2>&1 || { echo "✗ lane: image setjoin-ci-linux-tc:local-amd64 missing" >&2; exit 1; }
if [[ ! -f test-results/gofree-tlsfront/peer-receipt.json ]]; then
  stamp "building the frozen Go TLS peer"
  python3 server-rust/tests/conformance/tlsfront/build-peer.py >&2 || { echo "✗ lane: TLS peer build failed" >&2; exit 1; }
fi

# ── quick debug run ───────────────────────────────────────────────────────────────────
if [[ "${LANE_QUICK:-}" == 1 ]]; then
  groups="$(mktemp)"
  python3 scripts/server-rust-lane-groups.py >"$groups" || exit 1
  (cd server-rust && cargo nextest run --workspace --locked --offline --no-fail-fast --profile lane \
    --tool-config-file "lane:$groups" -j "$LANE_JOBS" --color never --success-output never \
    --failure-output immediate-final ${LANE_NEXTEST_FILTER:+-E "$LANE_NEXTEST_FILTER"}) 2>&1 | tee "$ART/lane.log"
  rc="${PIPESTATUS[0]}"
  [[ -f server-rust/target/nextest/lane/junit.xml ]] && cp server-rust/target/nextest/lane/junit.xml "$ART/junit.xml"
  stamp "quick end rc=$rc"
  echo "rc=$rc" >"$ART/lane-complete.txt"
  exit "$rc"
fi

# ── the lane ──────────────────────────────────────────────────────────────────────────
stamp "check-server-rust.sh"
bash scripts/check-server-rust.sh 2>&1 | tee "$ART/lane.log"
rc="${PIPESTATUS[0]}"
stamp "check-server-rust.sh rc=$rc"

# nextest keeps its store under the workspace (server-rust/target/nextest), not CARGO_TARGET_DIR.
# An archive run keeps it under the extracted target dir instead.
for JUNIT in "$ROOT/server-rust/target/nextest/lane/junit.xml" "${CARGO_TARGET_DIR:-/nonexistent}/nextest/lane/junit.xml" \
  "${SERVER_RUST_NEXTEST_EXTRACT_TO:-/nonexistent}/target/nextest/lane/junit.xml"; do
  [[ -f "$JUNIT" ]] && { cp "$JUNIT" "$ART/junit.xml"; break; }
done

# ── leak sweep: only this lane's clones ───────────────────────────────────────────────
leaked="$(psql -h "$HOST" -p "$PORT" -U "$PGU" -d postgres -X -At -c "SELECT datname FROM pg_database WHERE datname ~ '^${PREFIX}[0-9a-f]{24}\$'")"
if [[ -n "$leaked" ]]; then
  echo "lane: $(wc -l <<<"$leaked") leaked clone database(s) swept"
  while read -r db; do admin -c "DROP DATABASE IF EXISTS \"$db\" WITH (FORCE)"; done <<<"$leaked"
fi
stamp "end rc=$rc"
echo "rc=$rc" >"$ART/lane-complete.txt"
exit "$rc"
