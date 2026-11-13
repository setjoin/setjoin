#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-scope-containment.sh — guard for the Drive P1 native-token scope
# containment invariant (retired-docs:superpowers/plans/archive/2026-07-09-drive-P1-core.md,
# batch-3 item 6; mailserver/internal/auth/jwt.go IssueDriveNativeToken).
#
# A scoped mirror token (non-empty `Scp`, minted for a native client) MUST
# authenticate only its named HTTP surface. chain.AuthenticateRequest enforces
# that for the REST surface; the WS/SSE push handshakes — which can't route
# through it (no Authorization header) — go through auth.AuthenticatePushToken,
# the ONE push-acceptance seam, which blanket-rejects any non-empty `Scp`. The
# Go test TestAuthenticatePushToken_Guards is the primary defense; this script
# is the backstop.
#
# Two assertions:
#  (1) The push handlers (mailserver/internal/ws) MUST NOT validate a token
#      directly (`.JWT().Validate(`) — acceptance must go through the seam.
#  (2) Belt-and-suspenders: any OTHER live (non-test) `.JWT().Validate(` site in
#      mailserver must carry a `.Scp` guard within the following 20 lines.
# ──────────────────────────────────────────────────────────────────────────
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# scan <root-dir> → prints "file:line" for every unguarded direct-validate site.
scan() {
  local base="$1" f ln
  # Every direct-validate site: `.JWT().Validate(` outside _test.go files.
  while IFS=: read -r f ln _; do
    [ -z "$f" ] && continue
    # Look at the 20 lines starting AT the match for a Scp rejection. 15 was
    # too tight: ws/handler.go's Upgrade has a Sec-WebSocket-Protocol check
    # between Validate() and its Scp guard, pushing the guard to line+16 and
    # false-flagging an already-guarded site.
    if ! sed -n "${ln},$((ln + 20))p" "$f" | grep -q '\.Scp'; then
      echo "$f:$ln"
    fi
  done < <(grep -rnE '\.JWT\(\)\.Validate\(' --include='*.go' "$base" 2>/dev/null | grep -v '_test\.go')
}

# ── self-test: a fixture with a guarded and an unguarded site; the scan must
# flag exactly the unguarded one. ──────────────────────────────────────────
selftest() {
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  cat > "$tmp/guarded.go" <<'EOF'
package x
func a() {
	claims, err := h.chain.JWT().Validate(tokenStr)
	if err != nil { return }
	if claims.Scp != "" { return }
}
EOF
  cat > "$tmp/unguarded.go" <<'EOF'
package x
func b() {
	claims, _ := h.chain.JWT().Validate(tokenStr)
	_ = claims.Type
}
EOF
  local out; out="$(scan "$tmp")"
  # Anchor on a leading slash — "/unguarded.go" contains the substring
  # "guarded.go", so an unanchored match would false-positive.
  if echo "$out" | grep -q '/guarded\.go'; then
    echo "SELFTEST FAIL: flagged a guarded site" >&2; return 1
  fi
  if ! echo "$out" | grep -q '/unguarded\.go'; then
    echo "SELFTEST FAIL: missed an unguarded site" >&2; return 1
  fi
}

selftest

# (1) Push handlers must never validate a token directly — acceptance is the
# AuthenticatePushToken seam. A reintroduced .JWT().Validate( here is the exact
# regression this guards (a Type-only check once let a drive token open a full
# JMAP session).
push_direct="$(grep -rnE '\.JWT\(\)\.Validate\(' --include='*.go' \
  "$ROOT/mailserver/internal/ws" 2>/dev/null | grep -v '_test\.go' || true)"
if [ -n "$push_direct" ]; then
  echo "check-scope-containment: FAIL — ws push handler validates a token directly instead of via chain.AuthenticatePushToken:" >&2
  echo "$push_direct" | sed 's/^/  /' >&2
  echo "  Fix: call h.chain.AuthenticatePushToken(tokenStr) (see ws/handler.go)." >&2
  exit 1
fi

# (2) Any remaining direct-validate site anywhere in mailserver must self-guard.
viol="$(scan "$ROOT/mailserver")"
if [ -n "$viol" ]; then
  echo "check-scope-containment: FAIL — direct token-validate site(s) with no Scp guard:" >&2
  echo "$viol" | sed 's/^/  /' >&2
  echo "  Fix: reject non-empty claims.Scp before accepting the token (see ws/handler.go)." >&2
  exit 1
fi
echo "check-scope-containment: OK — all direct .JWT().Validate( sites reject scoped tokens"
