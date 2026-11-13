#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-migration-allocation.sh — CA-F migration/BZ allocation guard.
#
# Asserts that CA-Foundation's reserved allocations are singular and have not
# been double-booked, so future specs cannot silently collide with them:
#   • V025 names exactly one file in the dbschema migration tree.
#   • BZ079 appears in at most one reducer file.
#
# Does NOT re-implement the full duplicate-version sweep — that is already
# covered by check-no-duplicate-version.sh. This guard's unique value is the
# reservation-singularity assertion (V025/BZ079 specifically).
#
# Greppy + fast, in the genre of check-no-duplicate-version.sh /
# check-account-scope.sh.
#
# Usage: scripts/check-migration-allocation.sh   (exit 0 = clean, 1 = collision).
# Wired into scripts/test.sh next to check-no-duplicate-version.sh.
# MIGRATION_DIRS / REDUCER_DIR may be overridden by the self-test.
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

MIGRATION_DIRS="${MIGRATION_DIRS:-$ROOT/mailserver/sql/dbschema}"
REDUCER_DIR="${REDUCER_DIR:-$ROOT/mailserver/sql/reducers}"

echo "==> CA-F allocation guard (V025/BZ079 must be singular; no new dup versions)"

fail=0

# ── Duplicate-version sanity within the scanned dirs ─────────────────────
# (Complements check-no-duplicate-version.sh; this guard re-runs the narrow
# V025 slice in fixture mode so the selftest can point MIGRATION_DIRS at a
# temp tree without needing to run the sibling guard.)
for dir in $MIGRATION_DIRS; do
  [ -d "$dir" ] || continue
  dups="$(
    # Controlled migration filenames are intentionally parsed as a sorted listing.
    # shellcheck disable=SC2010
    ls "$dir" 2>/dev/null \
      | grep -E '^V[0-9]+__.*\.sql$' \
      | sed -E 's/^(V[0-9]+)__.*/\1/' \
      | LC_ALL=C sort \
      | uniq -d
  )"
  for v in $dups; do
    fail=1
    echo ""
    echo "  DUPLICATE migration version: $v names >1 file in"
    echo "    $dir"
    # shellcheck disable=SC2010
    ls "$dir" | grep -E "^${v}__.*\.sql$" | sed 's/^/      /'
    echo "  → rename one file to the next free version."
  done
done

# ── V025 reservation: must be exactly one file ───────────────────────────
v025_count=0
for dir in $MIGRATION_DIRS; do
  [ -d "$dir" ] || continue
  # shellcheck disable=SC2010
  c="$(ls "$dir" 2>/dev/null | grep -cE '^V025__' || true)"
  v025_count=$((v025_count + c))
done
if [ "$v025_count" -eq 0 ]; then
  fail=1
  echo ""
  echo "  V025 (CA-Foundation) is MISSING — expected exactly one V025__*.sql file."
  echo "  → CA-F schema was not applied or the file was renamed."
elif [ "$v025_count" -gt 1 ]; then
  fail=1
  echo ""
  echo "  V025 (CA-Foundation) names $v025_count files — must be exactly one."
  echo "  → a second spec has double-booked this migration slot; rename it."
fi

# ── BZ079 reservation: must appear in at most one reducer ────────────────
if [ -d "$REDUCER_DIR" ]; then
  # grep -rl returns 1 when no files match; capture in an array via a subshell.
  mapfile -t bz079_files < <(grep -rl "ERRCODE = 'BZ079'" "$REDUCER_DIR" 2>/dev/null || true)
  bz079_count="${#bz079_files[@]}"
  if [ "$bz079_count" -gt 1 ]; then
    fail=1
    echo ""
    echo "  BZ079 (CA-Foundation) is raised in $bz079_count reducer files — must be at most one."
    printf '      %s\n' "${bz079_files[@]}"
    echo "  → a second reducer has double-booked this BZ code; assign a new BZ slot."
  fi
fi

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "==> CA-F allocation guard FAILED."
  exit 1
fi

echo "    CA-F allocation guard clean (V025 singular; BZ079 in ≤1 reducer; no dup versions)."
