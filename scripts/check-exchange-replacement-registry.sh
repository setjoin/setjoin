#!/usr/bin/env bash
# Deterministic single-authority guard for the Exchange replacement registry.
source "$(dirname "$0")/_base.sh"

if [ "${1:-}" = "--self-test" ]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  cp -R "$ROOT/config/exchange-replacement" "$tmp/config"
  node -e 'const fs=require("fs"); const p=process.argv[1]; const x=JSON.parse(fs.readFileSync(p)); x.capabilities.push({...x.capabilities[0]}); fs.writeFileSync(p,JSON.stringify(x));' "$tmp/config/registry-v1.json"
  if EXCHANGE_REPLACEMENT_SOURCE_DIR="$tmp/config" node "$ROOT/scripts/exchange-replacement-registry.mjs" --check >/dev/null 2>&1; then
    echo "exchange replacement registry self-test failed: duplicate capability was accepted" >&2
    exit 1
  fi
  echo "check-exchange-replacement-registry self-test: OK"
  exit 0
fi

node "$ROOT/scripts/exchange-replacement-registry.mjs" --check
node --test "$ROOT/scripts/exchange-replacement-registry.test.mjs"
