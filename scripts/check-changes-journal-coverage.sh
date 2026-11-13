#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-changes-journal-coverage.sh — coverage guard (offline #3, F1/§8.6).
#
# Every reducer that advances jmap_email_state (via bump_email_state() or a
# direct `jmap_email_state = jmap_email_state + 1` assignment) MUST either:
#   a) pair with an append_email_change(...) call IN THE SAME REDUCER, OR
#   b) route through notify_state_change() which appends for it (and does NOT
#      itself directly assign jmap_email_state), OR
#   c) be on the ALLOWLIST below with a justification.
#
# A state bump that escapes the journal means jmap_email_changes returns a
# stale delta → offline client cache diverges from the server.
#
# ALLOWLIST entries: "basename.sql:reason" — the file is the journal seam
# itself, the primitive definer, or has a code-level justify (resync sentinel
# or multi-message append proven at the bump site).
#
# Selftest (--selftest): writes a synthetic offender, asserts the guard exits
# non-zero on it, and 0 on the real reducer tree. A guard that never fires is
# theater; the selftest makes "guard broken" un-shippable.
#
# Usage:
#   bash scripts/check-changes-journal-coverage.sh           # check real tree
#   bash scripts/check-changes-journal-coverage.sh --selftest
#
# Wired into scripts/lint.sh.
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Selftest mode (handles --selftest FIRST so find on a missing dir never runs) ──
# --self-test accepted as an alias: run-guards.sh probes for the repo-standard
# spelling (the openapi guards' convention) and passes that form.
if [[ "${1:-}" == "--selftest" || "${1:-}" == "--self-test" ]]; then
  ROOT_FOR_ST="$(cd "$(dirname "$0")/.." && pwd)"
  SELF="$ROOT_FOR_ST/scripts/check-changes-journal-coverage.sh"
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT

  # Synthetic offender: bumps jmap_email_state directly with no append/notify.
  printf 'CREATE OR REPLACE FUNCTION bad_offender() RETURNS void AS $$\nBEGIN\n  UPDATE mailboxes SET jmap_email_state = jmap_email_state + 1 WHERE id = 1;\nEND;\n$$ LANGUAGE plpgsql;\n' \
    > "$tmp/bad_offender.sql"

  # Guard must EXIT NON-ZERO on the synthetic offender directory.
  if bash "$SELF" "$tmp" >/dev/null 2>&1; then
    echo "SELFTEST-FAIL: synthetic offender not caught by the guard"
    exit 1
  fi

  # Guard must EXIT ZERO on the real reducer tree.
  REAL_REDUCERS="$ROOT_FOR_ST/mailserver/sql/reducers"
  if ! bash "$SELF" "$REAL_REDUCERS" >/dev/null 2>&1; then
    echo "SELFTEST-FAIL: guard fails on the real reducer tree (unexpected COVERAGE-FAIL)"
    bash "$SELF" "$REAL_REDUCERS" 2>&1 | head -20
    exit 1
  fi

  echo "SELFTEST-OK: synthetic offender caught; real tree clean."
  exit 0
fi

# ── Real check ────────────────────────────────────────────────────────────────
# Resolve default relative to the script dir (not cwd) so the guard works from
# any working directory (e.g. lint.sh invokes it argument-less from repo root,
# but a stray cwd like /tmp would vacuously succeed with an empty find result).
_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REDUCERS="${1:-$_SCRIPT_DIR/../mailserver/sql/reducers}"

# ponytail: allowlist keyed by basename:reason. Entries are the seam owner,
# the bump primitive definer, and the journal function definer — each has
# at least a resync sentinel or a multi-append at the bump site.
ALLOWLIST=(
  # The journal seam itself: calls bump_email_state() internally AND always
  # appends either a precise row or a resync sentinel in the same txn.
  "notify_state_change.sql:the journal seam — appends precise rows or resync sentinel for every bump"
  # Defines bump_email_state() (the bump primitive) AND adjust_folder_counters
  # which directly bumps and immediately calls append_email_change in the same stmt.
  "utils.sql:defines bump_email_state primitive + adjust_folder_counters calls append_email_change at its bump site"
  # Defines append_email_change() itself — no bump of jmap_email_state here.
  "append_change.sql:defines append_email_change itself; contains no jmap_email_state bump"
)

is_allowlisted() {
  local f; f="$(basename "$1")"
  local entry
  for entry in "${ALLOWLIST[@]}"; do
    [[ "$entry" == "${f}:"* ]] && return 0
  done
  return 1
}

fail=0
while IFS= read -r file; do
  base="$(basename "$file")"

  # Only check files that directly bump jmap_email_state (via the bump
  # primitive or a direct assignment). Callers that go through
  # notify_state_change() without a direct bump are OK — the seam appends.
  if ! grep -Eq 'bump_email_state\(|jmap_email_state[[:space:]]*=[[:space:]]*jmap_email_state[[:space:]]*\+[[:space:]]*1' "$file"; then
    continue
  fi

  # Allow-listed seam owners and primitive definers.
  if is_allowlisted "$base"; then
    continue
  fi

  # A reducer that calls notify_state_change() WITHOUT also open-coding a
  # direct jmap_email_state assignment delegates to the seam → OK.
  # (This path is for reducers like recall.sql that call bump_email_state
  # directly AND call append_email_change — they would pass the next check
  # anyway, but this branch covers any future callers that go through the seam.)
  if grep -Eq 'notify_state_change\(' "$file" \
     && ! grep -Eq 'jmap_email_state[[:space:]]*=[[:space:]]*jmap_email_state' "$file"; then
    continue
  fi

  # Must pair the bump with append_email_change (precise id or resync sentinel).
  if ! grep -Eq 'append_email_change\(' "$file"; then
    echo "COVERAGE-FAIL: $file"
    echo "  bumps jmap_email_state with no append_email_change call and is not on the allowlist."
    echo "  → pair the bump with append_email_change(), or route through notify_state_change()."
    fail=1
  fi
done < <(find "$REDUCERS" -name '*.sql' 2>/dev/null)

if [[ "$fail" -ne 0 ]]; then
  echo ""
  echo "changes-journal coverage guard FAILED — see COVERAGE-FAIL entries above."
  echo "Every jmap_email_state bump must journal a row (precise id or resync sentinel)."
  exit 1
fi

echo "==> changes-journal coverage: clean."
