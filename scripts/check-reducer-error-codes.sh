#!/usr/bin/env bash
# Guard reducer error-code registry/classifier coverage and the audited
# BZ234/BZ241 message budgets. Reducers only: migrations and pgTAP fixtures are
# deliberately excluded.
set -euo pipefail

ROOT="${ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"
REDUCERS="${REDUCERS:-$ROOT/mailserver/sql/reducers}"
REGISTRY="${REGISTRY:-$ROOT/docs/reducer-error-codes.md}"
CONTRACT="${CONTRACT:-$ROOT/shared/reducererr/contract_test.go}"

raised_codes() {
  perl -0ne 'while (/ERRCODE\s*=\s*\x27(BZ\d{3})\x27/g) { print "$1\n" }' "$REDUCERS"/*.sql | sort -u
}

registered_codes() {
  grep -oE 'BZ[0-9]{3}' "$REGISTRY" | sort -u
}

classified_codes() {
  grep -oE '\{"BZ[0-9]{3}"' "$CONTRACT" | tr -d '{"' | sort -u
}

missing_from() {
  comm -23 <(raised_codes) <("$1")
}

if [[ "${1:-}" == "--self-test" ]]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  REDUCERS="$tmp/reducers"
  REGISTRY="$tmp/registry.md"
  CONTRACT="$tmp/contract.go"
  mkdir -p "$REDUCERS"
  printf "RAISE EXCEPTION 'x' USING ERRCODE = 'BZ234';\nRAISE EXCEPTION 'y' USING ERRCODE='BZ999';\n" >"$REDUCERS/x.sql"
  printf '| **BZ234** | registered |\n' >"$REGISTRY"
  printf 'var rows=[]row{{"BZ234"}}\n' >"$CONTRACT"
  [[ "$(missing_from registered_codes)" == "BZ999" ]]
  [[ "$(missing_from classified_codes)" == "BZ999" ]]
  echo "reducer error-code guard self-test passed"
  exit 0
fi

fail=0
missing_registry="$(missing_from registered_codes)"
if [[ -n "$missing_registry" ]]; then
  echo "Reducer codes missing from docs/reducer-error-codes.md:" >&2
  printf '%s\n' "$missing_registry" >&2
  fail=1
fi
missing_classifier="$(missing_from classified_codes)"
if [[ -n "$missing_classifier" ]]; then
  echo "Reducer codes missing from the reducererr wire contract/classifier:" >&2
  printf '%s\n' "$missing_classifier" >&2
  fail=1
fi

message_count() {
  local code="$1"
  perl -ne '
    if (/RAISE EXCEPTION\s+(.+)/) {$message=$1}
    if (/ERRCODE\s*=\s*\x27'"$code"'\x27/) {print "$message\n"}
    if (eof) {close ARGV; $.=0}
  ' "$REDUCERS"/*.sql | sort -u | wc -l | tr -d ' '
}

check_budget() {
  local code="$1" allowance="$2" actual
  actual="$(message_count "$code")"
  if (( actual > allowance )); then
    echo "$code has $actual distinct reducer messages; audited allowance is $allowance." >&2
    fail=1
  fi
}

# BZ234 retains state/preflight/no-oracle conflicts. Its 29th audited message
# rejects an unsupported source-to-source identity pair before any state changes.
# BZ241 is the deliberately narrow malformed-argument class.
# Raising either budget requires a fresh audit.
check_budget BZ234 29
check_budget BZ241 15

if (( fail != 0 )); then
  exit 1
fi
echo "reducer error-code registry, classifier, and message budgets: OK"
