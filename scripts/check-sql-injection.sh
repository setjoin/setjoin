#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-sql-injection.sh — no fmt.Sprintf-composed SQL (DATABASE_SECURITY.md).
#
# One home for a decision that previously lived as TWO divergent grep spellings
# (ci-local.sh stage 1 vs the retired xinchuang-ci.yml four-clause variant). Any Go file
# that string-formats a %s into a SELECT/INSERT/UPDATE/DELETE is a fail — user
# input belongs in bind parameters, never in the SQL text.
#
# The pattern matches EITHER order of keyword and %s within the same
# Sprintf(...) call: the realistic shape is `SELECT ... %s` (keyword first,
# `%s` interpolated into a WHERE/value position afterwards); an earlier
# version of this guard only matched `%s ... SELECT` (interpolation BEFORE
# the keyword) and so never fired on the common real-world shape.
#
# Self-test (--self-test): plants a violating .go file — using the realistic
# `SELECT ... %s` order — in a temp dir and asserts the scan fires on it, then
# exits 0 — proving the pattern detects the bug class before the real-tree
# verdict is trusted.
#
# Usage:
#   bash scripts/check-sql-injection.sh               # scan the real tree
#   bash scripts/check-sql-injection.sh --self-test   # prove the guard fires
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

# Two clauses joined by alternation so both orderings are caught within one
# Sprintf(...) call: keyword-then-%s (the common real shape, e.g.
# `fmt.Sprintf("SELECT * FROM t WHERE x = '%s'", v)`) and %s-then-keyword.
PATTERN='fmt\.Sprintf\([^)]*(SELECT|INSERT|UPDATE|DELETE)[^)]*%s|fmt\.Sprintf\([^)]*%s[^)]*(SELECT|INSERT|UPDATE|DELETE)'

# ponytail: allowlist keyed by basename, entries "file:reason" — same shape as
# check-changes-journal-coverage.sh's ALLOWLIST. Only for files where every
# %s slot is a compile-time-literal column/table name (never attacker input)
# and every actual value rides a bind parameter ($N) — a dynamic-SET-clause
# pattern the regex can't distinguish from real interpolated values.
ALLOWLIST=(
  # ApplyUserUpdate's `%s = $%d` column list: `%s` is always a map key drawn
  # from ldaputil.SyncAttrs()'s hardcoded literal keys or a caller's inline
  # literal (e.g. "ad_usn_changed") — never an LDAP/AD-supplied string — and
  # every value is bound via $argIdx, never interpolated.
  "ldaputil.go:dynamic SET column names are compile-time literals; values are always \$N bind params"
  # pushjobs' claimOn/markDoneOn/retryOrFailOn (Chat A3.5 Task 3) parametrize
  # the shared claim/done/retry SQL by table so mail's push_intents and
  # chat's chat_push_intents drain legs reuse one implementation instead of
  # two copies. `table` is always one of the two Go string constants
  # (pushIntentsTable/chatIntentsTable) declared at the top of worker.go,
  # never request-derived; every actual value (id, errMsg, backoff seconds)
  # rides a bind parameter ($N).
  "worker.go:table is always a fixed Go string constant (pushIntentsTable/chatIntentsTable); values are always \$N bind params"
)

is_allowlisted() {
  local f; f="$(basename "$1")"
  local entry
  for entry in "${ALLOWLIST[@]}"; do
    [[ "$entry" == "${f}:"* ]] && return 0
  done
  return 1
}

scan() { # scan <dir>... → 0 offender found (printed, allowlist filtered), non-zero clean
  # -E (POSIX ERE), NOT -P: macOS /usr/bin/grep is BSD and has no -P — the old
  # inline `grep -rnP` this guard replaced exited 2 ("invalid option") with
  # stderr swallowed and read as CLEAN on every macOS run. The pattern is
  # ERE-safe, and stderr stays visible so a grep failure can never pass silently.
  local hits found=1
  hits="$(grep -rnE --include='*.go' "$PATTERN" "$@" || true)"
  [ -z "$hits" ] && return 1
  while IFS= read -r line; do
    [ -z "$line" ] && continue
    file="${line%%:*}"
    if is_allowlisted "$file"; then
      continue
    fi
    echo "$line"
    found=0
  done <<< "$hits"
  return $found
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  # Realistic shape from the review finding: keyword BEFORE %s, single
  # interpolation. The earlier pattern (%s-then-keyword only) never matched
  # this order — that gap is exactly what this self-test now proves closed.
  cat > "$tmp/offender.go" <<'EOF'
package bad

import "fmt"

func q(user string) string {
	return fmt.Sprintf("SELECT * FROM users WHERE name = '%s'", user)
}
EOF
  if ! scan "$tmp" > /dev/null; then
    echo "check-sql-injection SELF-TEST FAILED: pattern does not detect 'SELECT ... %s' (see review finding C7)" >&2
    exit 1
  fi
  echo "check-sql-injection self-test: OK (guard fires on 'SELECT ... %s', not just '%s ... SELECT')"
  exit 0
fi

if scan "$ROOT/mailserver" "$ROOT/authserver" "$ROOT/shared"; then
  echo "check-sql-injection FAILED: fmt.Sprintf-composed SQL found (see above) — use bind parameters." >&2
  exit 1
fi
echo "check-sql-injection: clean (no string-concat SQL in mailserver/ authserver/ shared/)."
