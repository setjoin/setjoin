#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-ga-gap-list.sh — GA-readiness gap-list guard (G0,
# retired-docs:superpowers/plans/archive/2026-07-04-ga-readiness-program-index.md, work order
# deliverable 2).
#
# WHY. G0's whole point is a durable, committed gap list — not a scratch file
# that rots or gets lost (the 74-Important audit manifest already taught this
# lesson the hard way: docs/audit/2026-07-04-audit74-manifest-loss.md). A gap
# list nobody re-checks silently drifts: a row's disposition can point at a
# plan file that gets renamed/deleted, or a new row can get added without
# ever being classified. This guard makes "every row is classified" a fact
# about the filesystem, not a claim in prose — mirrors
# scripts/check-rls-coverage.sh's allowlist-classify-everything convention.
#
# WHAT IT DOES. Finds the markdown table whose header row is
# `| id | area | severity | owner | t-shirt | disposition |` (case-insensitive,
# whitespace-tolerant), skips the `---|---|...` separator row, and treats every
# subsequent `|`-prefixed line up to the first non-`|` line as a data row. For
# each data row:
#   1. Splits on `|` and asserts there are exactly 6 non-empty (post-trim)
#      columns (id/area/severity/owner/t-shirt/disposition).
#   2. Checks `disposition`: either it starts with `ACCEPTED-RISK: ` (a
#      literal tag with a non-empty reason after the colon), OR its leading
#      path token (up to the first space or `(`) resolves to an existing file
#      relative to the repo root. Anything else — an unclassified row, a
#      dangling path, an empty column — FAILS the guard, naming the row's id.
#
# WHAT IT IS NOT. Not a content auditor — doesn't judge whether a
# disposition's reasoning is any good, only whether every row has been
# classified into one of the two allowed shapes. Not a general markdown-table
# linter — only looks at the ONE table under the id/area/severity/owner/
# t-shirt/disposition header.
#
# Usage: scripts/check-ga-gap-list.sh
#   GAP_FILE=<path>  override the gap-list file under test (default: the real
#                     docs/audit/2026-07-04-ga-gap-list.md)
# Self-test: scripts/check-ga-gap-list-selftest.sh (plants a dangling-path row
# + an empty-owner row, asserts the guard fires on each named row, then
# asserts it passes clean against the real file — this guard's TDD red-first
# proof).
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"
set +e  # every fallible step below is checked explicitly

GAP_FILE="${GAP_FILE:-$ROOT/docs/audit/2026-07-04-ga-gap-list.md}"

echo "==> GA gap-list guard: $GAP_FILE"

if [ ! -f "$GAP_FILE" ]; then
  echo "  [GA-GAP-LIST] file not found: $GAP_FILE" >&2
  exit 1
fi

# Extract the gap table's data rows (everything between the header row and
# the first line after it that doesn't start with '|', skipping the '---'
# separator row). Emits one data row per output line, pipe-delimited as-is.
ROWS="$(awk '
  BEGIN { in_table=0; seen_header=0 }
  {
    line=$0
    norm=tolower(line); gsub(/[ \t]+/, "", norm)
    if (!seen_header && norm ~ /^\|id\|area\|severity\|owner\|t-shirt\|disposition\|$/) {
      seen_header=1; in_table=1; next
    }
    if (in_table) {
      if ($0 ~ /^\|[- :|]+\|$/) { next }        # the --- separator row
      if ($0 !~ /^\|/) { in_table=0; next }      # table ended
      print $0
    }
  }
' "$GAP_FILE")"

if [ -z "$ROWS" ]; then
  echo "  [GA-GAP-LIST] no gap-table header ('| id | area | severity | owner | t-shirt | disposition |') found, or zero data rows under it" >&2
  exit 1
fi

fail=0
row_count=0

while IFS= read -r row; do
  [ -z "$row" ] && continue
  row_count=$((row_count + 1))

  # Split on '|': a well-formed "| a | b | c | d | e | f |" row yields
  # 8 awk fields (leading/trailing empty + 6 real columns).
  nf="$(printf '%s' "$row" | awk -F'|' '{print NF}')"
  if [ "$nf" -ne 8 ]; then
    echo "  [GA-GAP-LIST] malformed row (expected 6 columns, got $((nf-2))): $row" >&2
    fail=1
    continue
  fi

  id="$(printf '%s' "$row"        | awk -F'|' '{print $2}' | sed 's/^ *//; s/ *$//')"
  area="$(printf '%s' "$row"      | awk -F'|' '{print $3}' | sed 's/^ *//; s/ *$//')"
  severity="$(printf '%s' "$row"  | awk -F'|' '{print $4}' | sed 's/^ *//; s/ *$//')"
  owner="$(printf '%s' "$row"     | awk -F'|' '{print $5}' | sed 's/^ *//; s/ *$//')"
  tshirt="$(printf '%s' "$row"    | awk -F'|' '{print $6}' | sed 's/^ *//; s/ *$//')"
  disposition="$(printf '%s' "$row" | awk -F'|' '{print $7}' | sed 's/^ *//; s/ *$//')"

  row_id="${id:-<row $row_count>}"

  for pair in "id:$id" "area:$area" "severity:$severity" "owner:$owner" "t-shirt:$tshirt" "disposition:$disposition"; do
    col="${pair%%:*}"
    val="${pair#*:}"
    if [ -z "$val" ]; then
      echo "  [GA-GAP-LIST] row '$row_id': column '$col' is empty" >&2
      fail=1
    fi
  done
  [ -z "$disposition" ] && continue  # already reported above

  if printf '%s' "$disposition" | grep -qE '^ACCEPTED-RISK: .+'; then
    continue
  fi

  # Not an ACCEPTED-RISK tag → the leading token (up to the first space or
  # '(') must resolve to an existing file relative to the repo root.
  path_token="$(printf '%s' "$disposition" | sed -E 's/^([^ (]+).*/\1/')"
  if [ -z "$path_token" ] || [ ! -f "$ROOT/$path_token" ]; then
    echo "  [GA-GAP-LIST] row '$row_id': disposition is neither 'ACCEPTED-RISK: ...' nor an existing file path (got leading token '$path_token'): $disposition" >&2
    fail=1
  fi
done <<< "$ROWS"

if [ "$fail" -ne 0 ]; then
  echo ""
  echo "GA gap-list guard FAILED (see above)." >&2
  exit 1
fi

echo "    $row_count row(s) checked, all classified (existing plan/spec path or ACCEPTED-RISK)."
echo "    GA gap-list guard: clean."
