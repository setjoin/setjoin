#!/usr/bin/env bash
# A6 structural guard: Go Drive authorization may not read the legacy space
# roster or role helper directly.  The sole table read is the manager-gated
# roster projection in members.go; all authority checks use exact capability
# functions. SQL-side adapters are exhaustively classified by the companion
# check-drive-authorization-ledger.sh guard.
set -euo pipefail
ROOT=${DRIVE_MEMBERSCOPE_ROOT:-"$(cd "$(dirname "$0")/.." && pwd)"}
DRIVE_DIR="$ROOT/mailserver/internal/drive"

run_guard() {
  local viol="" f
  while IFS= read -r f; do
    [ -z "$f" ] && continue
    case "$(basename "$f")" in
      members.go) ;;
      *) viol+="  $f"$'\n' ;;
    esac
  done < <(rg -l 'drive_space_members|drive_member_role|driveMemberScopeSQL|driveMemberScopeUnionSQL' \
    "$DRIVE_DIR" --glob='*.go' --glob='!*_test.go' || true)

  if [ -n "$viol" ]; then
    echo "check-drive-memberscope: FAIL — legacy Drive authority primitive in Go:" >&2
    printf '%s' "$viol" >&2
    echo "Fix: use drive_runtime_has_node_capability, drive_user_has_space_access, or a reviewed projection adapter." >&2
    return 1
  fi
  echo "check-drive-memberscope: OK — Go Drive authority uses exact capability adapters"
}

if [ "${1:-}" = "--self-test" ]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/mailserver/internal/drive"
  printf '%s\n' 'package drive' 'const q = "drive_member_role(1,2)"' \
    > "$tmp/mailserver/internal/drive/bad.go"
  ROOT="$tmp"
  DRIVE_DIR="$tmp/mailserver/internal/drive"
  if run_guard >/dev/null 2>&1; then
    echo "check-drive-memberscope: SELF-TEST FAIL — planted legacy primitive was accepted" >&2
    exit 1
  fi
  echo "check-drive-memberscope: SELF-TEST OK — planted legacy primitive rejected"
  exit 0
fi

run_guard
