#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASELINE="$ROOT/config/shfmt.baseline"
CURRENT="$(mktemp)"
NEW="$(mktemp)"
trap 'rm -f "$CURRENT" "$NEW"' EXIT

files=()
while IFS= read -r file; do
  case "$file" in
    docs/ref/* | docs/examples/* | mailserver/deploy/generated/*) continue ;;
  esac
  files+=("$ROOT/$file")
done < <(git -C "$ROOT" ls-files '*.sh')

{ shfmt -l -i 2 -ci "${files[@]}" || true; } |
  sed "s#^$ROOT/##" | LC_ALL=C sort >"$CURRENT"
sed '/^#/d;/^[[:space:]]*$/d' "$BASELINE" | LC_ALL=C sort |
  comm -13 - "$CURRENT" >"$NEW"
if [[ -s "$NEW" ]]; then
  echo "shfmt-ratchet: new non-conforming files:" >&2
  cat "$NEW" >&2
  exit 1
fi
printf 'shfmt-ratchet: PASS (%s registered files; no additions)\n' "$(wc -l <"$CURRENT" | tr -d ' ')"
