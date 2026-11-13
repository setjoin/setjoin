#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-ga-gap-list-selftest.sh — proves check-ga-gap-list.sh actually FIRES
# (G0 work-order deliverable 2's required red-first proof).
#
# Plants two synthetic gap files, each a copy of the real header + one bad
# row:
#   (A) a row whose disposition points at a nonexistent plan file.
#   (B) a row with an empty owner column.
# Asserts the guard FAILS each, naming the offending row. Then asserts the
# guard PASSES clean against the real, on-disk gap list (no false positives).
# Never mutates the real gap-list file.
# ──────────────────────────────────────────────────────────────────────────
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
GUARD="$ROOT/scripts/check-ga-gap-list.sh"
REAL_GAP_FILE="$ROOT/docs/audit/2026-07-04-ga-gap-list.md"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

HEADER='| id | area | severity | owner | t-shirt | disposition |
|----|------|----------|-------|---------|--------------|'

pass=0; fail=0
ok()  { echo "  ok: $1"; pass=$((pass+1)); }
bad() { echo "  FAIL: $1"; fail=$((fail+1)); }

# ── Case A: dangling-path disposition must FIRE ──────────────────────────
BAD_A="$TMP/gap_dangling_path.md"
{
  printf '%s\n' "$HEADER"
  printf '| TEST-A1 | test | P2 | tester | S | retired-docs:superpowers/plans/this-file-does-not-exist-nonexistent.md |\n'
} > "$BAD_A"

out_a="$(GAP_FILE="$BAD_A" bash "$GUARD" 2>&1)"; rc_a=$?
if [ "$rc_a" -eq 0 ]; then
  bad "(A) dangling-path row did NOT fire (guard passed, rc=0)"
else
  ok "(A) dangling-path row fails the guard (rc=$rc_a)"
fi
if printf '%s' "$out_a" | grep -q 'TEST-A1'; then
  ok "(A) names the offending row (TEST-A1)"
else
  bad "(A) did not name TEST-A1 in the failure output:"$'\n'"$out_a"
fi

# ── Case B: empty-owner column must FIRE ─────────────────────────────────
BAD_B="$TMP/gap_empty_owner.md"
{
  printf '%s\n' "$HEADER"
  printf '| TEST-B1 | test | P2 |  | S | ACCEPTED-RISK: deliberately empty owner for the selftest |\n'
} > "$BAD_B"

out_b="$(GAP_FILE="$BAD_B" bash "$GUARD" 2>&1)"; rc_b=$?
if [ "$rc_b" -eq 0 ]; then
  bad "(B) empty-owner row did NOT fire (guard passed, rc=0)"
else
  ok "(B) empty-owner row fails the guard (rc=$rc_b)"
fi
if printf '%s' "$out_b" | grep -q "TEST-B1': column 'owner' is empty"; then
  ok "(B) names the offending row + column (TEST-B1 / owner)"
else
  bad "(B) did not name the empty owner column in the failure output:"$'\n'"$out_b"
fi

# ── Case C: the REAL gap list must PASS (no false positives) ────────────
out_c="$(GAP_FILE="$REAL_GAP_FILE" bash "$GUARD" 2>&1)"; rc_c=$?
if [ "$rc_c" -eq 0 ]; then
  ok "(C) the real gap list passes the guard clean"
else
  bad "(C) the REAL gap list fails the guard right now:"$'\n'"$out_c"
fi

echo ""
if [ "$fail" -ne 0 ]; then
  echo "check-ga-gap-list selftest FAILED ($fail/$((pass+fail)) checks failed)."
  exit 1
fi
echo "check-ga-gap-list selftest: all $pass checks passed (guard fires + is precise)."
