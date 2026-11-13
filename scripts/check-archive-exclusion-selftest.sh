#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-archive-exclusion-selftest.sh — proves the ARCH-007 archive-exclusion
# machinery actually FIRES. Models check-audit74-criticals-selftest.sh:
# synthetic scratch tree via mktemp -d + trap cleanup; never mutates the real
# tree; the real loaders are NEVER run against a real cluster — clean-tree
# checks go through the loaders' side-effect-free --preflight-only entry, and
# planted-tree checks must abort in that same preflight, which sits BEFORE the
# first psql call (reload-reducers.sh) / the DROP…WITH (FORCE) recreate block
# (load-test-schema.sh). A recording fake `psql` on PATH proves zero database
# invocations at the moment of every abort (r2.1 hermeticity evidence). The
# fake lives OUTSIDE the resettable fixture tree (r2 verdict: binned inside
# $WORK it was deleted by every build_minirepo reset, so later loader calls
# resolved the REAL psql against a vacuously empty recording file) and its
# resolution + recording are verified before the first loader runs.
#
# Cases (r2 binding):
#   (A) guard against a synthetic archive tree WITH sentinels → PASSES.
#   (B) guard fires:
#       (B1) archive file without the sentinel → fails, names the file.
#       (B2) a shell loader line `psql -f …/_archive/…` → fails, names it.
#       (B3) a `//go:embed _archive/…` directive whose pattern matches real
#            archive SQL beneath the embed dir — an archive-provenanced
#            V<pk>__*.sql carrying the live embed contract's rename-gate name
#            (^V(\d+)__.+\.sql$, dbschema.go:39/:42) → fails, names it.
#   (C) the acceptance case — loaders REFUSE archive-provenanced inputs with
#       the refusal message ("refusing to execute archived SQL"), an ARCH-007
#       reference, and the offending path named, with ZERO psql invocations:
#       (C1) V001__baseline.sql whose resolved path contains /_archive/
#            (symlink) → full load-test-schema.sh refuses before DROP/CREATE.
#       (C2) a migration matching the V[0-9]*__*.sql selection glob
#            (V024__client_versions.sql) symlinked into the scratch dbschema →
#            full load-test-schema.sh refuses, naming it.
#       (C3) a reducer matching load_reducer_set's *.sql glob symlinked into a
#            scratch reducer dir → FULL reload-reducers.sh refuses, naming it.
#       (C4) both loaders' --preflight-only entry refuses the same planted
#            trees (the option-(a) interface the guard contract pins).
#   (D) the REAL tree is green right now, exercised through the preflight
#       only: guard green; both loaders' --preflight-only green with zero psql
#       invocations (no database contact).
# Fixtures are selected by each loader's REAL pattern (V[0-9]*__*.sql / *.sql),
# never by a name the selection would skip.
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

GUARD="$(dirname "$0")/check-archive-exclusion.sh"
RELOAD_REDUCERS="$(dirname "$0")/reload-reducers.sh"
LOAD_TEST_SCHEMA="$(dirname "$0")/load-test-schema.sh"
WORK="$(mktemp -d)"
# FAKE_ROOT — where the recording fake psql and its call log live — is a
# separate tree from $WORK on purpose: build_minirepo() rm -rf's $WORK between
# cases, and a fake binned inside the fixture tree silently vanished, so every
# later `PATH="$FAKE_BIN:$PATH"` loader call resolved the REAL psql while the
# recreated-empty recording file still satisfied "ZERO invocations" (r2 P1).
FAKE_ROOT="$(mktemp -d)"
trap 'rm -rf "$WORK" "$FAKE_ROOT"' EXIT

SENTINEL='-- SETJOIN-ARCHIVE-NONEXECUTED: do not load; provenance only (ARCH-007). Loaders reject this tree.'

# Recording fake psql: every invocation is logged to $FAKE_CALLS and does
# nothing. Any nonzero call count at an abort means a database side effect
# preceded rejection — a hermeticity failure.
FAKE_BIN="$FAKE_ROOT/.fakebin"
FAKE_CALLS="$FAKE_ROOT/.psql.calls"
export FAKE_CALLS
mkdir -p "$FAKE_BIN"
cat >"$FAKE_BIN/psql" <<'FAKE'
#!/usr/bin/env bash
printf '%s\n' "psql $*" >> "${FAKE_CALLS:?FAKE_CALLS must be set}"
exit 0
FAKE
chmod +x "$FAKE_BIN/psql"

reset_calls() { : >"$FAKE_CALLS"; }

# Verify the fake BEFORE any loader runs (r2 P1): PATH resolution must pick
# the fake over the real psql (the exact lookup the loaders do), and the fake
# must actually record. If either fails, every "ZERO psql invocations" claim
# below would be vacuous.
resolved="$(PATH="$FAKE_BIN:$PATH" bash -c 'command -v psql')"
if [ "$resolved" = "$FAKE_BIN/psql" ]; then
  echo "fake psql verified: resolves ahead of the real one and records invocations"
else
  echo "FATAL: fake psql does not resolve ahead of the real one (got: ${resolved:-nothing})" >&2
  exit 1
fi
reset_calls
PATH="$FAKE_BIN:$PATH" psql --archive-selftest-probe >/dev/null 2>&1 || true
if grep -qF -- '--archive-selftest-probe' "$FAKE_CALLS"; then
  reset_calls
else
  echo "FATAL: fake psql did not record its invocation" >&2
  exit 1
fi

# Synthetic mini-repo: everything the guard's contract pins (archive trees,
# loader inputs, the dbschema.go embed contract) plus a benign loader.
build_minirepo() {
  rm -rf "$WORK"
  mkdir -p "$WORK"
  mkdir -p \
    "$WORK/scripts" \
    "$WORK/mailserver/sql/dbschema" \
    "$WORK/mailserver/sql/tests" \
    "$WORK/mailserver/sql/reducers" \
    "$WORK/mailserver/sql/_archive/schema" \
    "$WORK/mailserver/sql/_archive/migrations" \
    "$WORK/authserver/sql/reducers" \
    "$WORK/authserver/sql/_archive/schema" \
    "$WORK/authserver/sql/_archive/migrations"
  cat >"$WORK/scripts/provision-roles.sql" <<'SQL'
CREATE ROLE setjoin_app NOLOGIN;
SQL
  cat >"$WORK/scripts/reload-reducers.sh" <<'SH'
#!/usr/bin/env bash
# synthetic benign loader: an execution-context line with no archive reference
psql -h 127.0.0.1 -f "$1"
SH
  cat >"$WORK/mailserver/sql/dbschema/dbschema.go" <<'GO'
package dbschema

import (
	"embed"
	"regexp"
)

//go:embed *.sql
var migrationFS embed.FS

var filenameRe = regexp.MustCompile(`^V(\d+)__.+\.sql$`)
GO
  printf 'CREATE TABLE baseline_probe(id int);\n' >"$WORK/mailserver/sql/dbschema/V001__baseline.sql"
  printf 'CREATE TABLE fwd_probe(id int);\n' >"$WORK/mailserver/sql/dbschema/V002__forward_probe.sql"
  printf '\\dt\n' >"$WORK/mailserver/sql/tests/_fixtures.sql"
  printf 'CREATE OR REPLACE FUNCTION probe_fn() RETURNS void LANGUAGE sql AS $$ SELECT 1 $$;\n' \
    >"$WORK/mailserver/sql/reducers/001_probe.sql"
  cp "$WORK/mailserver/sql/reducers/001_probe.sql" "$WORK/authserver/sql/reducers/001_probe.sql"
  local rel
  for rel in \
    "mailserver/sql/_archive/schema/024_client_versions.sql" \
    "mailserver/sql/_archive/migrations/V003__probe.sql" \
    "authserver/sql/_archive/schema/020_orphan.sql" \
    "authserver/sql/_archive/migrations/V009__probe.sql"; do
    {
      printf '%s\n' "$SENTINEL"
      printf 'CREATE TABLE archived_probe(id int);\n'
    } >"$WORK/$rel"
  done
}

pass=0
fail=0
ok() {
  echo "  ok: $1"
  pass=$((pass + 1))
}
bad() {
  echo "  FAIL: $1"
  fail=$((fail + 1))
}

run_guard() { # guard the synthetic tree; captures rc/out
  rc=0
  out="$(ARCHIVE_GUARD_ROOT="$WORK" bash "$GUARD" 2>&1)" || rc=$?
}

# Refusal-specific assertions (r2.2): a generic non-zero exit is NOT evidence.
# Requires: non-zero exit + "refusing to execute archived SQL" + ARCH-007
# reference + the offending archive path named + zero recorded psql calls.
assert_refusal() { # label expected-token
  local label="$1" token="$2"
  if [ "$rc" -ne 0 ]; then
    ok "$label: exits non-zero"
  else
    bad "$label: EXITED ZERO on an archived input (false negative!)"
  fi
  if printf '%s' "$out" | grep -q 'refusing to execute archived SQL'; then
    ok "$label: names the refusal (refusing to execute archived SQL)"
  else
    bad "$label: refusal message missing:"$'\n'"$out"
  fi
  if printf '%s' "$out" | grep -q 'ARCH-007'; then
    ok "$label: references ARCH-007"
  else
    bad "$label: no ARCH-007 reference in refusal output"
  fi
  if printf '%s' "$out" | grep -qF "$token"; then
    ok "$label: names the offending file ($token)"
  else
    bad "$label: offending file $token not named in output:"$'\n'"$out"
  fi
  if printf '%s' "$out" | grep -q '/_archive/'; then
    ok "$label: named path is the archive-provenanced one"
  else
    bad "$label: output does not name an /_archive/ path:"$'\n'"$out"
  fi
  if [ ! -s "$FAKE_CALLS" ]; then
    ok "$label: ZERO psql invocations at abort (hermetic — no database contact)"
  else
    bad "$label: psql WAS invoked before the refusal:"$'\n'"$(cat "$FAKE_CALLS")"
  fi
}

echo "(A) guard vs synthetic archive tree with sentinels"
build_minirepo
run_guard
if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q 'check-archive-exclusion: OK'; then
  ok "(A) all-sentinel synthetic tree passes the guard"
else
  bad "(A) guard FAILED against an all-sentinel synthetic tree:"$'\n'"$out"
fi

echo "(B1) guard vs archive file missing its sentinel"
build_minirepo
tail -n +2 "$WORK/authserver/sql/_archive/schema/020_orphan.sql" >"$WORK/strip.tmp"
mv "$WORK/strip.tmp" "$WORK/authserver/sql/_archive/schema/020_orphan.sql"
run_guard
if [ "$rc" -ne 0 ]; then
  ok "(B1) sentinel-stripped archive file fails the guard"
else
  bad "(B1) guard PASSED with a sentinel stripped (false-negative!)"
fi
if printf '%s' "$out" | grep -qF "020_orphan.sql"; then
  ok "(B1) names the sentinel-stripped file"
else
  bad "(B1) did not name the violating file:"$'\n'"$out"
fi

echo "(B2) guard vs a loader line executing toward _archive"
build_minirepo
cat >"$WORK/scripts/rogue_loader.sh" <<'SH'
#!/usr/bin/env bash
psql -f "sql/_archive/migrations/V009__probe.sql"
SH
run_guard
if [ "$rc" -ne 0 ]; then
  ok "(B2) psql -f into _archive fails the guard"
else
  bad "(B2) guard PASSED with a rogue loader line (false-negative!)"
fi
if printf '%s' "$out" | grep -qF "rogue_loader.sh"; then
  ok "(B2) names the rogue loader file"
else
  bad "(B2) did not name the violating file:"$'\n'"$out"
fi

echo "(B3) guard vs a //go:embed directive reaching into _archive"
build_minirepo
# Reachable fixture (r2 P2): the rogue directive's `_archive/*.sql` pattern
# must match REAL SQL beneath the embed dir, and that SQL must be
# archive-provenanced (sentinel) and named in the shape the LIVE embed
# contract's rename gate (^V(\d+)__.+\.sql$, dbschema.go:39/:42) selects —
# exactly the file that would be compiled into the binary as migration V24 if
# the scan missed the directive.
mkdir -p "$WORK/mailserver/sql/dbschema/_archive"
{
  printf '%s\n' "$SENTINEL"
  printf 'CREATE TABLE client_versions_probe(id int);\n'
} \
  >"$WORK/mailserver/sql/dbschema/_archive/V024__client_versions.sql"
embed_fixture="$WORK/mailserver/sql/dbschema/_archive/V024__client_versions.sql"
case "${embed_fixture##*/}" in
  V[0-9]*__*.sql)
    ok "(B3) embed fixture carries the rename-gate name (live V<pk>__*.sql contract selects it)"
    ;;
  *)
    bad "(B3) embed fixture name is NOT selected by the ^V(\\d+)__ rename gate: ${embed_fixture##*/}"
    ;;
esac
if [ -f "$embed_fixture" ] && head -n 1 "$embed_fixture" | grep -q 'SETJOIN-ARCHIVE-NONEXECUTED'; then
  ok "(B3) //go:embed _archive/*.sql matches archive-provenanced SQL (directive reachable, not vacuous)"
else
  bad "(B3) rogue embed pattern has no sentinel-bearing SQL beneath the embed dir (directive vacuous)"
fi
cat >"$WORK/mailserver/sql/dbschema/rogue_embed.go" <<'GO'
package dbschema

import "embed"

//go:embed _archive/*.sql
var rogueFS embed.FS
GO
run_guard
if [ "$rc" -ne 0 ]; then
  ok "(B3) //go:embed _archive/*.sql fails the guard"
else
  bad "(B3) guard PASSED with a rogue embed directive (false-negative!)"
fi
if printf '%s' "$out" | grep -qF "rogue_embed.go"; then
  ok "(B3) names the rogue embed file (scanner rejects the directive binding archived SQL)"
else
  bad "(B3) did not name the violating file:"$'\n'"$out"
fi

echo "(C1) load-test-schema.sh vs baseline whose resolved path is in _archive"
build_minirepo
{
  printf '%s\n' "$SENTINEL"
  printf 'CREATE TABLE baseline_probe(id int);\n'
} \
  >"$WORK/mailserver/sql/_archive/migrations/V001__baseline.sql"
ln -sfn "$WORK/mailserver/sql/_archive/migrations/V001__baseline.sql" \
  "$WORK/mailserver/sql/dbschema/V001__baseline.sql"
reset_calls
rc=0
out="$(PATH="$FAKE_BIN:$PATH" MIGRATIONS_ROOT="$WORK" bash "$LOAD_TEST_SCHEMA" 2>&1)" || rc=$?
assert_refusal "(C1) full loader refuses archive-provenanced baseline" "V001__baseline.sql"

echo "(C2) load-test-schema.sh vs a V[0-9]*__*.sql-selected migration in _archive"
build_minirepo
{
  printf '%s\n' "$SENTINEL"
  printf 'CREATE TABLE client_versions_probe(id int);\n'
} \
  >"$WORK/mailserver/sql/_archive/schema/V024__client_versions.sql"
ln -sfn "$WORK/mailserver/sql/_archive/schema/V024__client_versions.sql" \
  "$WORK/mailserver/sql/dbschema/V024__client_versions.sql"
reset_calls
rc=0
out="$(PATH="$FAKE_BIN:$PATH" MIGRATIONS_ROOT="$WORK" bash "$LOAD_TEST_SCHEMA" 2>&1)" || rc=$?
assert_refusal "(C2) full loader refuses archive-provenanced V024 migration" "V024__client_versions.sql"

echo "(C4a) load-test-schema.sh --preflight-only vs the same planted tree"
reset_calls
rc=0
out="$(PATH="$FAKE_BIN:$PATH" MIGRATIONS_ROOT="$WORK" bash "$LOAD_TEST_SCHEMA" --preflight-only 2>&1)" || rc=$?
assert_refusal "(C4a) preflight-only refuses planted migration tree" "V024__client_versions.sql"

echo "(C3) FULL reload-reducers.sh vs a *.sql-selected reducer in _archive"
build_minirepo
{
  printf '%s\n' "$SENTINEL"
  printf 'CREATE OR REPLACE FUNCTION archived_fn() RETURNS void LANGUAGE sql AS $$ SELECT 1 $$;\n'
} \
  >"$WORK/authserver/sql/_archive/schema/099_probe_reducer.sql"
ln -sfn "$WORK/authserver/sql/_archive/schema/099_probe_reducer.sql" \
  "$WORK/authserver/sql/reducers/099_probe_reducer.sql"
reset_calls
rc=0
out="$(PATH="$FAKE_BIN:$PATH" REDUCERS_ROOT="$WORK" bash "$RELOAD_REDUCERS" 2>&1)" || rc=$?
assert_refusal "(C3) full production loader refuses archive-provenanced reducer" "099_probe_reducer.sql"

echo "(C4b) reload-reducers.sh --preflight-only vs the same planted tree"
reset_calls
rc=0
out="$(PATH="$FAKE_BIN:$PATH" REDUCERS_ROOT="$WORK" bash "$RELOAD_REDUCERS" --preflight-only 2>&1)" || rc=$?
assert_refusal "(C4b) preflight-only refuses planted reducer tree" "099_probe_reducer.sql"

echo "(D) real tree green — exercised through the preflight only"
rc=0
out="$(bash "$GUARD" 2>&1)" || rc=$?
if [ "$rc" -eq 0 ]; then
  ok "(D) guard against the REAL tree passes"
else
  bad "(D) the REAL tree fails the guard right now:"$'\n'"$out"
fi
reset_calls
rc=0
out="$(PATH="$FAKE_BIN:$PATH" bash "$RELOAD_REDUCERS" --preflight-only 2>&1)" || rc=$?
if [ "$rc" -eq 0 ] && [ ! -s "$FAKE_CALLS" ]; then
  ok "(D) reload-reducers.sh --preflight-only green on the real tree (zero psql)"
else
  bad "(D) reload-reducers.sh --preflight-only FAILED on the real tree (rc=$rc):"$'\n'"$out"$'\n'"psql calls:"$'\n'"$(cat "$FAKE_CALLS")"
fi
reset_calls
rc=0
out="$(PATH="$FAKE_BIN:$PATH" bash "$LOAD_TEST_SCHEMA" --preflight-only 2>&1)" || rc=$?
if [ "$rc" -eq 0 ] && [ ! -s "$FAKE_CALLS" ]; then
  ok "(D) load-test-schema.sh --preflight-only green on the real tree (zero psql)"
else
  bad "(D) load-test-schema.sh --preflight-only FAILED on the real tree (rc=$rc):"$'\n'"$out"$'\n'"psql calls:"$'\n'"$(cat "$FAKE_CALLS")"
fi

echo "(E) the fake survived every fixture reset"
# The zero-contact claims above are only evidence if the recording fake was
# actually on PATH the whole time. Under the pre-fix shape (fake binned inside
# $WORK) the first build_minirepo deleted it, so every later loader call would
# have resolved the REAL psql while the empty recording file claimed zero
# invocations. Re-verify resolution AFTER all resets.
resolved="$(PATH="$FAKE_BIN:$PATH" bash -c 'command -v psql' 2>/dev/null)" || resolved=""
if [ "$resolved" = "$FAKE_BIN/psql" ] && [ -f "$FAKE_CALLS" ]; then
  ok "(E) fake psql and its recording file survived every build_minirepo reset"
else
  bad "(E) fake psql vanished mid-run — the zero-contact claims above ran against the REAL psql"
fi

echo ""
if [ "$fail" -ne 0 ]; then
  echo "check-archive-exclusion selftest FAILED ($fail/$((pass + fail)) checks failed)."
  exit 1
fi
echo "check-archive-exclusion selftest: all $pass checks passed (guard + preflights fire, real tree green)."
