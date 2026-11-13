#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────
# check-reducererr-contract.sh — the BZ error contract is CONSUMED, not copied.
#
# WHY (arch c6; promoted to shared/ per arch #A8). Every BZ business error's
# wire projection (HTTP status, JMAP type, detail passthrough) lives in ONE
# place: shared/reducererr (codeClass + Detail + the golden contract matrix in
# contract_test.go) — consumed by both mailserver and authserver (separate Go
# modules, one shared package). Before c6, ~27 files hand-rolled `pgErr.Code`
# switches that silently DIVERGED from the classification (BZ095 409-vs-404,
# BZ104 400-vs-403, BZ109 422-vs-500, …); before #A8, authserver couldn't
# import the mailserver-homed package at all and had to hand-roll its own two
# branches.
#
# INVARIANT: no non-test Go file outside shared/reducererr/ may branch on a
# BZ-prefixed SQLSTATE literal via pgErr.Code comparison, a `case "BZ…"` arm,
# or strings.Contains — status/type/detail must come from reducererr.Classify /
# Detail; a SEMANTIC business-condition branch (idempotent success, bespoke
# render page) must use reducererr.IsCode. SQLSTATE constraint codes (23505,
# 23514, 22023, P0001, …) are deliberately OUT of scope — those switches are
# fine. The synthetic 403 BZ095 JSON body in middleware/device_trust_gate.go is
# a map literal (not a code branch) and does not match these patterns — it is
# the SPA deviceBlock contract, pinned by TestDeviceLockdownGate_SyntheticBZ095Body.
#
# Usage: scripts/check-reducererr-contract.sh [--self-test]
# ──────────────────────────────────────────────────────────────────────────
source "$(dirname "$0")/_base.sh"

GO_TREE="$ROOT"

# Keyed allowlist: repo-relative path → each entry carries its reason. A file
# listed here may keep a BZ-literal branch; everything else fails the guard.
ALLOWED_FILES=(
  # undo_send keeps a bespoke strings.Contains map: BZ021→404, BZ022→410 Gone
  # — deliberately divergent from user/recall.go, which projects BZ022 through
  # the class (409). Documented as the ambiguous pair in the contract matrix.
  'mailserver/internal/user/undo_send.go'
  # mailctl is an HTTP CLIENT (separate module): exitFor() maps the gateway's
  # RESPONSE TEXT ("HTTP 409" / a BZ087 detail) to a CLI exit code — a consumer
  # of the wire contract, not a producer; it never sees a pgconn.PgError.
  'mailctl/ca_verbs.go'
)

# Patterns that mean "hand-rolled BZ wire mapping":
#   .Code == "BZ…" / .Code != "BZ…"   — pgconn.PgError code comparison
#   case "BZ…"                        — switch arm over a code variable
#   Contains(… "BZ…"                  — string-matching the code out of err text
BAN_RE='\.Code[[:space:]]*[!=]=[[:space:]]*"BZ[0-9]|case[[:space:]]+"BZ[0-9]|Contains\([^)]*"BZ[0-9]'

check_bz_branches() {
  local files hits line file allowed a rc=0
  # find-based walk (NOT `grep -r`): some grep builds silently truncate trees.
  files=$(find "$GO_TREE" \
            -type d \( -name node_modules -o -name .git -o -name worktrees -o -name _archive -o -name build \) -prune \
            -o -type f -name '*.go' ! -name '*_test.go' ! -path '*/shared/reducererr/*' -print)
  [ -z "$files" ] && return 0
  hits=$(printf '%s\n' "$files" | xargs grep -nE "$BAN_RE" 2>/dev/null) || true
  [ -z "$hits" ] && return 0
  while IFS= read -r line; do
    file="${line%%:*}"
    file="${file#"$GO_TREE"/}"
    allowed=1
    for a in "${ALLOWED_FILES[@]}"; do
      [ "$file" = "$a" ] && { allowed=0; break; }
    done
    if [ $allowed -ne 0 ]; then
      echo "  [REDUCERERR] hand-rolled BZ-code branch: $line" >&2
      echo "               → project through reducererr.Classify/HTTPStatus/Detail (wire mapping) or reducererr.IsCode (semantic branch), or allowlist the file in check-reducererr-contract.sh with a reason." >&2
      rc=1
    fi
  done <<< "$hits"
  return $rc
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/tree/pkg" "$tmp/tree/mailserver/internal/user" "$tmp/tree/shared/reducererr"
  # Offender 1: pgErr.Code comparison against a BZ literal (must fire).
  cat > "$tmp/tree/pkg/offender.go" <<'EOF'
package pkg
func a(code string) bool { return pgErr.Code == "BZ042" }
EOF
  GO_TREE="$tmp/tree"
  cmp_rc=0; check_bz_branches >/dev/null 2>&1 || cmp_rc=$?
  # Offender 2: a case arm over BZ literals (must fire).
  cat > "$tmp/tree/pkg/offender.go" <<'EOF'
package pkg
func b(c string) int {
	switch c {
	case "BZ106", "BZ108":
		return 409
	}
	return 500
}
EOF
  case_rc=0; check_bz_branches >/dev/null 2>&1 || case_rc=$?
  # Allowlisted path (must pass) + reducererr itself (excluded, must pass) +
  # an IsCode call site (sanctioned seam, must pass).
  cat > "$tmp/tree/pkg/offender.go" <<'EOF'
package pkg
func c(err error) bool { return reducererr.IsCode(err, "BZ015") }
EOF
  cat > "$tmp/tree/mailserver/internal/user/undo_send.go" <<'EOF'
package user
func d() bool { return pgErr.Code == "BZ022" }
EOF
  cat > "$tmp/tree/shared/reducererr/projection.go" <<'EOF'
package reducererr
func e(c string) bool {
	switch c {
	case "BZ081":
		return true
	}
	return false
}
EOF
  clean_rc=0; check_bz_branches >/dev/null 2>&1 || clean_rc=$?
  if [ $cmp_rc -ne 0 ] && [ $case_rc -ne 0 ] && [ $clean_rc -eq 0 ]; then
    echo "check-reducererr-contract self-test: OK (fires on .Code== and case \"BZ…\"; IsCode + allowlist + reducererr-internal pass)"
    exit 0
  fi
  echo "check-reducererr-contract SELF-TEST FAILED: cmp=$cmp_rc(want!=0) case=$case_rc(want!=0) clean=$clean_rc(want 0)" >&2
  exit 1
fi

echo "==> Reducererr-contract guard: no hand-rolled BZ-code branches outside internal/reducererr/"
if ! check_bz_branches; then
  echo "Reducererr-contract guard FAILED (see above)." >&2
  exit 1
fi
echo "    Reducererr-contract guard: clean."
