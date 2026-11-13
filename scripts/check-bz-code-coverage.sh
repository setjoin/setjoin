#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-bz-code-coverage.sh — every reducer BZ error code has pgTAP COVERAGE.
#
# WHY. check-bz-codes.sh guards that every `RAISE EXCEPTION ... USING
# ERRCODE='BZxxx'` is DOCUMENTED in docs/reducer-error-codes.md. This guard
# checks the orthogonal claim: that every such code is actually EXERCISED by a
# pgTAP assertion somewhere under mailserver/sql/tests/*.pg. A documented-but-
# untested code is an error branch nothing proves still fires — a reducer
# refactor can silently rename/delete the RAISE and no test goes red.
#
# COVERAGE DEFINITION (deliberately permissive — same "over-count is safe"
# convention as check-bz-codes.sh's doc-side match): a code counts as covered
# if the literal string 'BZxxx' appears anywhere in a *.pg test file. In
# practice that is always a throws_ok/throws_like third-argument SQLSTATE, but
# the guard does not require that exact call shape — it only asserts the code
# is referenced by an assertion file, not that the assertion is well-formed.
#
# LEDGER. A code not yet covered must be on the checked-in allowlist
# (scripts/bz-coverage-pending.txt: one "BZxxx<TAB>reducer1.sql[,reducer2.sql]"
# per line, blank/#-comment lines ignored) — same shape as
# mailserver/api/openapi-pending.txt (check-openapi-coverage.sh) and
# scripts/http-error-allowlist.txt (check-http-error-shape.sh). This is a
# fail-closed, TWO-DIRECTION guard, so the ledger can only shrink:
#   · uncovered code, NOT on the ledger        → FAIL (new gap; write a test or ledger it)
#   · ledgered code that IS NOW covered        → FAIL ("stale allowlist" — delete the line)
#
# Usage:
#   scripts/check-bz-code-coverage.sh                 # the guard (exit 1 on drift)
#   scripts/check-bz-code-coverage.sh --self-test      # prove it fires both directions
#   scripts/check-bz-code-coverage.sh --regen-pending  # reseed the ledger from current state
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"
export LC_ALL=C

REDUCERS_DIR="$ROOT/mailserver/sql/reducers"
TESTS_DIR="$ROOT/mailserver/sql/tests"
PENDING="$ROOT/scripts/bz-coverage-pending.txt"

# used_codes DIR — every BZxxx raised via ERRCODE='BZxxx' under DIR, sorted unique.
used_codes() {
  local dir="$1"
  grep -rhoE "ERRCODE[[:space:]]*=[[:space:]]*'BZ[0-9]+'" "$dir"/*.sql 2>/dev/null \
    | grep -oE 'BZ[0-9]+' | sort -u
}

# tested_codes DIR — every BZxxx literally mentioned anywhere in *.pg files under DIR.
tested_codes() {
  local dir="$1"
  grep -rhoE 'BZ[0-9]+' "$dir"/*.pg 2>/dev/null | sort -u
}

# reducer_files_for CODE DIR — comma-joined basenames of every reducer under DIR
# that raises CODE (used to pre-fill the ledger with a useful pointer).
reducer_files_for() {
  local code="$1" dir="$2"
  grep -lE "ERRCODE[[:space:]]*=[[:space:]]*'$code'" "$dir"/*.sql 2>/dev/null \
    | xargs -n1 basename 2>/dev/null | sort -u | paste -sd',' -
}

# pending_codes FILE — field 1 (the code) of every non-comment/blank line, sorted unique.
pending_codes() {
  local f="$1"
  [ -f "$f" ] || return 0
  grep -vE '^[[:space:]]*(#|$)' "$f" | awk -F'\t' '{print $1}' | sort -u
}

# run_guard REDUCERS TESTS PENDING — echoes ✗ lines to stderr, returns 1 on any
# drift. Sets COVERED_COUNT / ALLOWLISTED_COUNT / TOTAL_COUNT as a side effect
# (reporting only — callers that just want pass/fail can ignore them).
run_guard() {
  local rdir="$1" tdir="$2" pfile="$3"
  local used tested pending c is_tested is_pending rc=0
  used="$(used_codes "$rdir")"
  tested="$(tested_codes "$tdir")"
  pending="$(pending_codes "$pfile")"

  TOTAL_COUNT=0
  COVERED_COUNT=0
  ALLOWLISTED_COUNT=0

  while IFS= read -r c; do
    [ -n "$c" ] || continue
    TOTAL_COUNT=$((TOTAL_COUNT + 1))
    is_tested=0; is_pending=0
    grep -qxF "$c" <<<"$tested" && is_tested=1
    grep -qxF "$c" <<<"$pending" && is_pending=1

    if [ "$is_tested" = 1 ]; then
      COVERED_COUNT=$((COVERED_COUNT + 1))
      if [ "$is_pending" = 1 ]; then
        echo "  ✗ stale allowlist entry: $c is now covered by a pgTAP test — delete its line from $pfile" >&2
        rc=1
      fi
    else
      if [ "$is_pending" = 1 ]; then
        ALLOWLISTED_COUNT=$((ALLOWLISTED_COUNT + 1))
      else
        echo "  ✗ $c is raised in a reducer but has no pgTAP assertion and is not ledgered in $pfile" >&2
        echo "     → add a throws_ok/throws_like assertion for $c in mailserver/sql/tests/, or add a ledger line: $c<TAB>$(reducer_files_for "$c" "$rdir")" >&2
        rc=1
      fi
    fi
  done <<<"$used"

  return $rc
}

case "${1:-}" in
  --regen-pending)
    # PENDING = every used code NOT tested, each paired with its raising reducer(s).
    # Coverage debt, honestly re-derived from current state every time this runs.
    used="$(used_codes "$REDUCERS_DIR")"
    tested="$(tested_codes "$TESTS_DIR")"
    {
      echo "# bz-coverage-pending.txt — pgTAP coverage-debt ledger (auto-seeded; see check-bz-code-coverage.sh)."
      echo "# Format: BZxxx<TAB>reducer1.sql[,reducer2.sql]"
      echo "# Every line is a reducer error code with NO pgTAP assertion referencing it yet."
      echo "# Add a throws_ok/throws_like test for the code, then DELETE its line here."
      echo "# A code that is neither tested nor ledgered fails CI; a ledgered code that IS"
      echo "# now tested also fails CI (stale allowlist) — this list only shrinks."
      while IFS= read -r c; do
        [ -n "$c" ] || continue
        grep -qxF "$c" <<<"$tested" && continue
        printf '%s\t%s\n' "$c" "$(reducer_files_for "$c" "$REDUCERS_DIR")"
      done <<<"$used"
    } > "$PENDING.tmp"
    mv "$PENDING.tmp" "$PENDING"
    n="$(grep -cvE '^[[:space:]]*(#|$)' "$PENDING" || true)"
    echo "Regenerated $PENDING ($n pending codes)."
    exit 0
    ;;
  --self-test)
    echo "==> bz-code-coverage guard self-test"
    tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
    mkdir -p "$tmp/reducers" "$tmp/tests"

    # Fixture reducer: raises two synthetic codes (BZ9xx — outside the real
    # 001–1xx range so a collision with an actual reducer code is impossible).
    # BZ901 will be tested, BZ902 will NOT be tested and NOT ledgered.
    cat > "$tmp/reducers/fixture.sql" <<'SQL'
CREATE OR REPLACE FUNCTION fixture_a() RETURNS void AS $$
BEGIN
  RAISE EXCEPTION 'tested' USING ERRCODE='BZ901';
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION fixture_b() RETURNS void AS $$
BEGIN
  RAISE EXCEPTION 'untested' USING ERRCODE='BZ902';
END;
$$ LANGUAGE plpgsql;
SQL

    cat > "$tmp/tests/fixture.pg" <<'PG'
SELECT throws_ok($$ SELECT fixture_a() $$, 'BZ901', NULL, 'fixture_a raises BZ901');
PG

    # (A) BZ902 uncovered, not ledgered → guard MUST fail, naming BZ902.
    : > "$tmp/empty-pending.txt"
    rc_a=0
    out_a="$(run_guard "$tmp/reducers" "$tmp/tests" "$tmp/empty-pending.txt" 2>&1)" || rc_a=$?
    ok_a=0
    if [ "$rc_a" -ne 0 ] && echo "$out_a" | grep -q 'BZ902'; then ok_a=1; fi

    # (B) BZ902 uncovered, ledgered → guard MUST pass.
    printf 'BZ902\tfixture.sql\n' > "$tmp/covering-pending.txt"
    rc_b=0
    out_b="$(run_guard "$tmp/reducers" "$tmp/tests" "$tmp/covering-pending.txt" 2>&1)" || rc_b=$?
    ok_b=0
    [ "$rc_b" -eq 0 ] && ok_b=1

    # (C) BZ901 IS covered but still ledgered (stale) → guard MUST fail, naming
    # BZ901 and "stale".
    printf 'BZ901\tfixture.sql\n' > "$tmp/stale-pending.txt"
    rc_c=0
    out_c="$(run_guard "$tmp/reducers" "$tmp/tests" "$tmp/stale-pending.txt" 2>&1)" || rc_c=$?
    ok_c=0
    if [ "$rc_c" -ne 0 ] && echo "$out_c" | grep -qi 'stale' && echo "$out_c" | grep -q 'BZ901'; then ok_c=1; fi

    if [ "$ok_a" = 1 ] && [ "$ok_b" = 1 ] && [ "$ok_c" = 1 ]; then
      echo "  ✓ (A) uncovered+unledgered code fails, naming it"
      echo "  ✓ (B) uncovered+ledgered code passes"
      echo "  ✓ (C) covered-but-still-ledgered code fails as stale allowlist"
      echo "check-bz-code-coverage self-test: OK"
      exit 0
    fi
    echo "check-bz-code-coverage SELF-TEST FAILED: A(want fail+BZ902)=$rc_a/$ok_a B(want pass)=$rc_b/$ok_b C(want fail+stale+BZ901)=$rc_c/$ok_c" >&2
    echo "--- (A) ---" >&2; echo "$out_a" >&2
    echo "--- (B) ---" >&2; echo "$out_b" >&2
    echo "--- (C) ---" >&2; echo "$out_c" >&2
    exit 1
    ;;
esac

echo "==> BZ error-code pgTAP coverage guard"
if run_guard "$REDUCERS_DIR" "$TESTS_DIR" "$PENDING"; then
  echo "    OK — $COVERED_COUNT/$TOTAL_COUNT codes covered by a pgTAP assertion, $ALLOWLISTED_COUNT ledgered pending in $(basename "$PENDING")."
  exit 0
else
  echo "" >&2
  echo "  BZ coverage drift (see ✗ lines). Add a throws_ok/throws_like test for a new" >&2
  echo "  uncovered code (or ledger it in $PENDING), or delete a stale ledger line" >&2
  echo "  for a code that is now actually tested." >&2
  exit 1
fi
