#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-log-keys.sh — structured-log field-key convention guard.
#
# WHY. slog attribute keys are the columns an operator greps/filters logs by.
# Mixing camelCase (`"userID"`, `"jobID"`) with the snake_case the rest of the
# tree uses (`"user_id"`, `"job_id"`) means the same fact lands under two
# different keys, and a log query for one silently misses the other. This
# guard keeps every log key snake_case. (2026-07-05: 45 camelCase keys across
# 17 files were converted; this prevents the drift from returning.)
#
# It is a CALL-based guard: it only inspects quoted tokens on lines that are
# slog / logger calls (slog.Info/String/…, logger.Warn/…, .With(…)), so a
# camelCase string in ordinary code or a comment is never flagged. Test files
# are out of scope (production log consistency only).
#
# Scope: authserver/, mailserver/, shared/ (the HTTP-serving Go modules).
# mailctl uses fmt for human output, not structured logging.
#
# Usage: scripts/check-log-keys.sh [--self-test]
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

LOGCALL='(slog\.(Info|Warn|Error|Debug|String|Int|Int64|Bool|Any|Duration|Float64|Time|Group)|\.With|[Ll]ogger\.(Info|Warn|Error|Debug))\('

# scan MODULE_DIRS... — prints "path:line: <src>" for every slog/logger call
# line carrying a quoted camelCase token, under the given dirs.
scan() {
  local dir
  for dir in "$@"; do
    [ -d "$ROOT/$dir" ] || continue
    # `|| true`: grep exits 1 on no-match, which would trip set -e/pipefail even
    # though "no camelCase keys" is the success case.
    { grep -rnE "${LOGCALL}.*\"[a-z]+[A-Z][a-zA-Z]*\"" \
        --include='*.go' "$ROOT/$dir" 2>/dev/null \
      | grep -v '_test\.go:' \
      | sed "s#^${ROOT}/##" ; } || true
  done
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/mailserver/internal/user"
  cat > "$tmp/mailserver/internal/user/handler.go" <<'EOF'
package user

import "log/slog"

func Handle(logger *slog.Logger) {
	logger.Error("lookup failed", "userID", 7)         // camelCase KEY — must fire
	logger.Info("lookup ok", "user_id", 7)             // snake_case KEY — must NOT fire
	logger.Info("status changed to inProgress please") // camelCase in MESSAGE only — must NOT fire
}
EOF
  ROOT="$tmp"
  hits="$(scan mailserver)"
  if echo "$hits" | grep -q '"userID"' && ! echo "$hits" | grep -qE 'user_id|inProgress'; then
    echo "check-log-keys self-test: OK (fires on camelCase key, silent on snake_case key + camelCase message)"
    exit 0
  fi
  echo "check-log-keys SELF-TEST FAILED — did not fire as expected:" >&2
  echo "$hits" >&2
  exit 1
fi

echo "==> log-key convention guard: camelCase slog keys"
violations="$(scan authserver mailserver shared)"
if [ -n "$violations" ]; then
  echo "camelCase log keys found (use snake_case):" >&2
  echo "$violations" | sed 's/^/    /' >&2
  echo "    slog attribute keys are snake_case (user_id, job_id) so log queries match." >&2
  exit 1
fi
echo "    log-key guard: clean."
