#!/usr/bin/env bash
# Drive ACL migrations start at V184. The chain was a contiguous suffix
# V184..V193; after the global V-numberspace was consumed by non-drive
# migrations, the chain continues out-of-band at V255 (drive-space-update RLS
# backstop, reviewed D-decision work). The pinned sequence below is that
# reviewed chain: a drive-ACL migration with an UNLISTED number, a MISSING
# pinned phase, a DUPLICATE, or an out-of-order file all fail — a rebase
# collision or a skipped ACL phase is still caught, and new phases must be
# appended here consciously.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DBSCHEMA_DIR="${DBSCHEMA_DIR:-$ROOT/mailserver/sql/dbschema}"

# Reviewed drive-ACL chain, in order.
PINNED_CHAIN=(184 185 186 187 188 189 190 191 192 193 255 269)  # 269: meet Drive-History receipt ledger (V269__drive_meet_history, nightly-16; FORCE RLS, drive_audit posture — consciously appended)

check_chain() {
  local dir="$1" found expected v have in_chain seen
  found="$({
    find "$dir" -maxdepth 1 -type f \( -name 'V[0-9]*__drive_*.sql' -o -name 'V[0-9]*__directory_group_authority.sql' \) -print
  } | sed -E 's#^.*/V([0-9]+)__.*#\1#' | awk '$1 >= 184' | sort -n)"
  if [ -z "$found" ]; then
    echo "drive ACL migration chain: missing V184 foundation" >&2
    return 1
  fi
  have="$(printf '%s\n' "$found" | grep -c .)"
  in_chain=0
  for expected in "${PINNED_CHAIN[@]}"; do
    seen="$(printf '%s\n' "$found" | grep -cx "$expected" || true)"
    case "$seen" in
      0) ;;
      1) in_chain=$((in_chain + 1)) ;;
      *)
        echo "drive ACL migration chain: duplicate drive migration V$(printf '%03d' "$expected")" >&2
        return 1
        ;;
    esac
  done
  if [ "$have" -ne "$in_chain" ]; then
    found="$(printf '%s\n' "$found" | head -1)"
    echo "drive ACL migration chain: unplanned drive migration V$(printf '%03d' "$found") — not in the pinned chain; append it to PINNED_CHAIN consciously (scripts/check-drive-acl-migration-chain.sh)" >&2
    return 1
  fi
  local i=0
  for expected in "${PINNED_CHAIN[@]}"; do
    v="$(printf '%s\n' "$found" | sed -n "$((i + 1))p")"
    if [ -z "$v" ]; then
      echo "drive ACL migration chain: pinned phase V$(printf '%03d' "$expected") missing" >&2
      return 1
    fi
    if [ "$v" -ne "$expected" ]; then
      echo "drive ACL migration chain: expected V$(printf '%03d' "$expected") at position $((i + 1)), found V$(printf '%03d' "$v")" >&2
      return 1
    fi
    i=$((i + 1))
  done
}

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  local_test() {
    local dir="$1" want="$2" out
    if out="$(check_chain "$dir" 2>&1)"; then
      [ "$want" = "pass" ] && return 0
      echo "check-drive-acl-migration-chain SELF-TEST FAILED: $3 was accepted" >&2
      return 1
    fi
    [ "$want" = "fail" ] && return 0
    echo "check-drive-acl-migration-chain SELF-TEST FAILED: $3 rejected unexpectedly: $out" >&2
    return 1
  }
  full_fixture() {
    local dir="$1" v
    mkdir -p "$dir"
    for v in "${PINNED_CHAIN[@]}"; do
      : >"$dir/V${v}__drive_phase.sql"
    done
  }
  # Missing pinned phase: fail.
  rm -rf "$tmp/gap"
  full_fixture "$tmp/gap"
  rm "$tmp/gap/V185__drive_phase.sql"
  local_test "$tmp/gap" fail "pinned-phase gap"
  # Full pinned chain in order: pass.
  rm -rf "$tmp/full"
  full_fixture "$tmp/full"
  local_test "$tmp/full" pass "full pinned chain"
  # Unplanned phase: fail.
  : >"$tmp/full/V999__drive_unplanned.sql"
  local_test "$tmp/full" fail "unplanned phase"
  rm "$tmp/full/V999__drive_unplanned.sql"
  # Duplicate phase: fail.
  : >"$tmp/full/V188__drive_duplicate.sql"
  local_test "$tmp/full" fail "duplicate phase"
  rm "$tmp/full/V188__drive_duplicate.sql"
  # Out-of-order file names cannot reorder the numeric sort, so a stale-number
  # rebase collision surfaces as unplanned/duplicate — covered above.
  echo "check-drive-acl-migration-chain: SELF-TEST OK — gap, unplanned, duplicate rejected; full pinned chain accepted"
  exit 0
fi

echo "==> Drive ACL migration chain (pinned sequence, V184..V193 + V255)"
check_chain "$DBSCHEMA_DIR"
echo "    pinned chain complete and in order."
