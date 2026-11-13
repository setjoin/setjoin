#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE="$ROOT/config/errcheck-mailserver.baseline"
RAW="$(mktemp)"
CURRENT="$(mktemp)"
NEW="$(mktemp)"
trap 'rm -f "$RAW" "$CURRENT" "$NEW"' EXIT

set +e
(
  cd "$ROOT/mailserver"
  golangci-lint run --enable-only errcheck --max-issues-per-linter=0 --max-same-issues=0 ./...
) >"$RAW" 2>&1
status=$?
set -e
if ((status > 1)); then
  cat "$RAW" >&2
  echo "errcheck-ratchet: analyzer failed with status $status" >&2
  exit "$status"
fi

sed -n -E 's#^([^:]+):[0-9]+:[0-9]+: Error return value (.*) is not checked \(errcheck\)$#\1|\2#p' "$RAW" |
  LC_ALL=C sort >"$CURRENT"
sed '/^#/d;/^[[:space:]]*$/d' "$BASELINE" | LC_ALL=C sort |
  comm -13 - "$CURRENT" >"$NEW"

if [[ -s "$NEW" ]]; then
  echo "errcheck-ratchet: new unchecked return values:" >&2
  cat "$NEW" >&2
  exit 1
fi

printf 'errcheck-ratchet: PASS (%s registered debt entries; no additions)\n' "$(wc -l <"$CURRENT" | tr -d ' ')"
