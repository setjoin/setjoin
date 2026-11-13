#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-ldap-bound-state.sh — guard against the LDAP GAL disclosure bug
# (chat review A1; mailserver/internal/ldap/search.go handleSearch/
# handleCompare). handleBind refused anonymous binds "for security", but a
# client that skipped Bind entirely — sending Search or Compare as its first
# PDU — got the full directory back with no auth check at all.
#
# The fix: handleBind sets a per-connection bound flag
# (m.Client.SetData(true)) only after auth.CheckPassword succeeds; every
# data-returning LDAP handler (Search, Compare — the two ops registered via
# routes.Search()/routes.Compare() in server.go) must call isBound(msg) and
# reject before touching the DB or writing any result.
#
# So: every function name passed to routes.Search(...)/routes.Compare(...) in
# server.go MUST have its body call isBound(. A handler registered there that
# doesn't is presumed to be a reintroduction of the unauthenticated-disclosure
# bug and fails the build, naming the handler.
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LDAP_DIR="$ROOT/mailserver/internal/ldap"

# body_calls_isBound <dir> <funcName> → 0 if the function's body (from its
# `func (s *Server) NAME(` line up to the next top-level `func ` or EOF)
# contains a call to isBound(.
body_calls_isBound() {
  local dir="$1" fn="$2"
  local f
  for f in "$dir"/*.go; do
    case "$f" in *_test.go) continue ;; esac
    grep -q "func (s \*Server) $fn(" "$f" || continue
    awk -v fn="$fn" '
      BEGIN { found=0; in_fn=0 }
      $0 ~ "^func \\(s \\*Server\\) " fn "\\(" { in_fn=1 }
      in_fn && /isBound\(/ { found=1 }
      in_fn && !/^func \(s \*Server\) '"$fn"'\(/ && /^func / { in_fn=0 }
      END { exit found ? 0 : 1 }
    ' "$f" && return 0
  done
  return 1
}

# ── self-test: prove the scan actually fires on a planted unguarded handler.
selftest() {
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  mkdir -p "$tmp/ldap"
  cat > "$tmp/ldap/server.go" <<'EOF'
package ldap
func (s *Server) Start() {
	routes.Search(s.handleSearchGuarded)
	routes.Compare(s.handleCompareUnguarded)
}
EOF
  cat > "$tmp/ldap/search.go" <<'EOF'
package ldap
func (s *Server) handleSearchGuarded(w ResponseWriter, msg *Message) {
	if !isBound(msg) {
		return
	}
	doSearch()
}
func (s *Server) handleCompareUnguarded(w ResponseWriter, m *Message) {
	doCompare()
}
EOF
  if ! body_calls_isBound "$tmp/ldap" "handleSearchGuarded"; then
    echo "SELFTEST FAIL: flagged a guarded handler as unguarded" >&2; return 1
  fi
  if body_calls_isBound "$tmp/ldap" "handleCompareUnguarded"; then
    echo "SELFTEST FAIL: missed the unguarded handler" >&2; return 1
  fi
}

selftest

# (1) Extract every handler name registered for Search/Compare in server.go —
# the two data-returning ops (Bind/Extended/Abandon aren't data-returning;
# Add/Delete/Modify route to the always-rejecting handleReadOnly).
handlers="$(grep -oE 'routes\.(Search|Compare)\(s\.[A-Za-z0-9_]+\)' "$LDAP_DIR/server.go" \
  | sed -E 's/routes\.(Search|Compare)\(s\.([A-Za-z0-9_]+)\)/\2/')"

if [ -z "$handlers" ]; then
  echo "check-ldap-bound-state: FAIL — no routes.Search()/routes.Compare() registration found in server.go (did the route wiring move?)" >&2
  exit 1
fi

viol=""
while IFS= read -r fn; do
  [ -z "$fn" ] && continue
  if ! body_calls_isBound "$LDAP_DIR" "$fn"; then
    viol="$viol  $fn"$'\n'
  fi
done <<< "$handlers"

if [ -n "$viol" ]; then
  echo "check-ldap-bound-state: FAIL — data-returning LDAP handler(s) do not call isBound() before serving data:" >&2
  echo "$viol" >&2
  echo "  Fix: add 'if !isBound(msg) { reject }' at the top of the handler (see handleSearch/handleCompare in search.go)." >&2
  exit 1
fi
echo "check-ldap-bound-state: OK — every routes.Search()/routes.Compare() handler (${handlers//$'\n'/, }) asserts bound-state"
