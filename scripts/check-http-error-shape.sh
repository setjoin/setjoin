#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-http-error-shape.sh — RFC 7807 error-shape guard.
#
# WHY. docs/standards/API_ERROR_SHAPE.md requires every app-JSON-API error
# response to be application/problem+json via httputil.WriteProblem /
# WriteProblemStatus. The plain-text `http.Error(w, msg, code)` emitter is
# the deprecated pre-conversion pattern — it writes text/plain and no
# machine-readable `type`, breaking clients that parse Problem.type/detail.
# This is a CALL-based guard (it finds actual `http.Error(` call sites via
# gofmt-stable source scanning, not a string grep for the word "error") so it
# cannot be defeated by renaming a variable or a log line that happens to
# contain "error".
#
# A handler package is either a genuine non-JSON surface (health probe,
# WebDAV/CalDAV/CardDAV, OAuth2/OIDC discovery, a click-redirect handler) —
# allowlisted in scripts/http-error-allowlist.txt — or it is an app-JSON-API
# handler, in which case a plain http.Error( call is a violation.
#
# Scope: authserver/, mailserver/, shared/ (the three HTTP-serving Go
# modules). mailctl is a CLI with no http.Error call sites today.
#
# Usage: scripts/check-http-error-shape.sh [--self-test]
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

ALLOWLIST="$ROOT/scripts/http-error-allowlist.txt"

# allowed_path PATH — true if PATH (repo-root-relative) matches an entry in
# the allowlist: an exact file match, or under a directory entry (trailing /).
allowed_path() {
  local path="$1" entry
  while IFS= read -r entry; do
    entry="${entry%%#*}"                       # strip inline comments
    entry="$(echo "$entry" | xargs)"           # trim whitespace
    [ -z "$entry" ] && continue
    if [ "${entry: -1}" = "/" ]; then
      case "$path" in "$entry"*) return 0 ;; esac
    else
      [ "$path" = "$entry" ] && return 0
    fi
  done < "$ALLOWLIST"
  return 1
}

# scan MODULE_DIRS... — prints "path:line" for every non-allowlisted
# `http.Error(` call site under the given module directories.
scan() {
  local dir
  for dir in "$@"; do
    [ -d "$ROOT/$dir" ] || continue
    while IFS= read -r hit; do
      local file="${hit%%:*}"
      local rel="${file#"$ROOT"/}"
      allowed_path "$rel" || echo "${rel}:${hit#*:}"
    done < <(grep -rnE '(^|[^.[:alnum:]_])http\.Error\(' \
                --include='*.go' "$ROOT/$dir" 2>/dev/null \
              | grep -v '_test\.go:')
  done
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/mailserver/internal/user" "$tmp/mailserver/internal/health"
  cat > "$tmp/mailserver/internal/user/handler.go" <<'EOF'
package user

import "net/http"

func Handle(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "bad request", http.StatusBadRequest)
}
EOF
  cat > "$tmp/mailserver/internal/health/handler.go" <<'EOF'
package health

import "net/http"

func Ready(w http.ResponseWriter, r *http.Request) {
	http.Error(w, "not ready", http.StatusServiceUnavailable)
}
EOF
  printf 'mailserver/internal/health/\n' > "$tmp/allowlist.txt"

  # Override ROOT/ALLOWLIST in-process (scan/allowed_path read these globals)
  # and call the guard's own functions directly — no subshell re-injection.
  ROOT="$tmp"
  ALLOWLIST="$tmp/allowlist.txt"
  hits="$(scan mailserver)"

  if echo "$hits" | grep -q "mailserver/internal/user/handler.go" && \
     ! echo "$hits" | grep -q "mailserver/internal/health/handler.go"; then
    echo "check-http-error-shape self-test: OK (fires on internal/user, silent on allowlisted internal/health)"
    exit 0
  fi
  echo "check-http-error-shape SELF-TEST FAILED — did not fire as expected:" >&2
  echo "$hits" >&2
  exit 1
fi

echo "==> RFC 7807 error-shape guard: http.Error( outside the allowlist"
violations="$(scan authserver mailserver shared)"
if [ -n "$violations" ]; then
  echo "http.Error( found outside scripts/http-error-allowlist.txt:" >&2
  echo "$violations" | sed 's/^/    /' >&2
  echo "    Use httputil.WriteProblem / WriteProblemStatus (see docs/standards/API_ERROR_SHAPE.md)," >&2
  echo "    or add a narrow allowlist entry if this is a genuine non-JSON surface." >&2
  exit 1
fi
echo "    http-error-shape guard: clean."
