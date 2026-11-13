#!/usr/bin/env bash
# check-drive-authorization-ledger.sh — exact A0 inventory guard for every
# production Drive membership primitive and Drive-tree recursive walk.
#
# The TSV is intentionally count-based rather than line-number-based: harmless
# edits may move a site, but adding/removing an authorization primitive or tree
# recursion requires an explicit classification and migration-phase update.
set -euo pipefail

ROOT=${DRIVE_AUTH_SCAN_ROOT:-"$(cd "$(dirname "$0")/.." && pwd)"}
LEDGER=${DRIVE_AUTH_LEDGER:-"$ROOT/docs/verification/2026-08-03-drive-acl-authorization-sites.tsv"}

classes='^(root_adapter|roster_projection|bound_source|outer_cap|exact_authorization|direct_drift|compatibility_writer|tree_fact)$'
phases='^A(1|2|3|4|5|6)$'

count_literal() {
  local literal="$1" file="$2"
  awk -v needle="$literal" '
    {
      rest=$0
      while ((at=index(rest, needle)) != 0) {
        n++
        rest=substr(rest, at+length(needle))
      }
    }
    END { print n+0 }
  ' "$file"
}

inventory() {
  local f rel member_role space_members recursive
  {
    find "$ROOT/mailserver/internal/drive" -maxdepth 1 -type f -name '*.go' ! -name '*_test.go' -print
    [ ! -f "$ROOT/mailserver/internal/guestgate/allowlist.go" ] || printf '%s\n' "$ROOT/mailserver/internal/guestgate/allowlist.go"
    find "$ROOT/mailserver/sql/reducers" -maxdepth 1 -type f -name '*.sql' -print
  } | sort -u | while IFS= read -r f; do
    member_role=$(count_literal 'drive_member_role' "$f")
    space_members=$(count_literal 'drive_space_members' "$f")
    recursive=0
    case "$f" in
      "$ROOT"/mailserver/internal/drive/*|"$ROOT"/mailserver/sql/reducers/drive_*)
        recursive=$(count_literal 'WITH RECURSIVE' "$f")
        ;;
    esac
    if [ "$member_role" -gt 0 ] || [ "$space_members" -gt 0 ] || [ "$recursive" -gt 0 ]; then
      rel=${f#"$ROOT/"}
      printf '%s\t%s\t%s\t%s\n' "$rel" "$member_role" "$space_members" "$recursive"
    fi
  done
}

ledger_inventory() {
  awk -F '\t' -v classes="$classes" -v phases="$phases" '
    BEGIN { bad=0 }
    /^#/ || NF==0 { next }
    NF != 6 {
      printf "ledger malformed at line %d: expected 6 tab-separated fields\n", NR > "/dev/stderr"
      bad=1
      next
    }
    $2 !~ classes {
      printf "ledger invalid class at line %d: %s\n", NR, $2 > "/dev/stderr"
      bad=1
    }
    $3 !~ /^[0-9]+$/ || $4 !~ /^[0-9]+$/ || $5 !~ /^[0-9]+$/ {
      printf "ledger invalid count at line %d\n", NR > "/dev/stderr"
      bad=1
    }
    $6 !~ phases {
      printf "ledger invalid phase at line %d: %s\n", NR, $6 > "/dev/stderr"
      bad=1
    }
    seen[$1]++ {
      printf "ledger duplicate path at line %d: %s\n", NR, $1 > "/dev/stderr"
      bad=1
    }
    { printf "%s\t%s\t%s\t%s\n", $1, $3, $4, $5 }
    END { if (bad) exit 1 }
  ' "$LEDGER" | sort
}

run_guard() {
  [ -f "$LEDGER" ] || {
    echo "check-drive-authorization-ledger: missing ledger: $LEDGER" >&2
    return 1
  }
  local actual expected
  actual=$(inventory)
  expected=$(ledger_inventory)
  if [ "$actual" != "$expected" ]; then
    echo "check-drive-authorization-ledger: FAIL — production inventory differs from classified ledger" >&2
    diff -u <(printf '%s\n' "$expected") <(printf '%s\n' "$actual") >&2 || true
    echo "Classify the site and its A1–A6 migration owner; never update counts blindly." >&2
    return 1
  fi
  printf 'check-drive-authorization-ledger: OK — %s classified production files\n' \
    "$(printf '%s\n' "$actual" | awk 'NF {n++} END {print n+0}')"
}

if [ "${1:-}" = "--self-test" ]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/mailserver/internal/drive" "$tmp/mailserver/internal/guestgate" \
    "$tmp/mailserver/sql/reducers" "$tmp/docs/verification"
  printf '%s\n' 'SELECT drive_member_role(1, 2);' > "$tmp/mailserver/sql/reducers/drive_fixture.sql"
  printf '%s\n' '# path	class	member_role	space_members	recursive	phase' \
    > "$tmp/docs/verification/2026-08-03-drive-acl-authorization-sites.tsv"
  ROOT="$tmp"
  LEDGER="$tmp/docs/verification/2026-08-03-drive-acl-authorization-sites.tsv"
  if run_guard >/dev/null 2>&1; then
    echo "check-drive-authorization-ledger: SELF-TEST FAIL — unledgered site was accepted" >&2
    exit 1
  fi
  printf '%s\n' \
    'mailserver/sql/reducers/drive_fixture.sql	exact_authorization	0	0	0	A6' \
    >> "$tmp/docs/verification/2026-08-03-drive-acl-authorization-sites.tsv"
  if run_guard >/dev/null 2>&1; then
    echo "check-drive-authorization-ledger: SELF-TEST FAIL — wrong count was accepted" >&2
    exit 1
  fi
  echo "check-drive-authorization-ledger: SELF-TEST OK — unledgered and count-drift mutants rejected"
  exit 0
fi

run_guard
