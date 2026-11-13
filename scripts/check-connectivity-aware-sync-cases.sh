#!/usr/bin/env bash
# CONTRACT: connectivity-aware-sync-e0-contracts
# Fail-closed E0 scenario/evidence contract guard. Product/runtime cases remain
# honestly planned until their owning implementation units produce exact results.
# shellcheck disable=SC1091
source "$(dirname "$0")/_base.sh"
set -euo pipefail

MANIFEST="$ROOT/docs/verification/connectivity-aware-sync-cases.json"
VALIDATOR="$ROOT/scripts/check-connectivity-aware-sync-cases.mjs"
SELF_TEST="$ROOT/scripts/check-connectivity-aware-sync-cases.test.mjs"

if [[ "${1:-}" == "--self-test" ]]; then
  exec node "$SELF_TEST"
fi
if [[ $# -ne 0 ]]; then
  echo "usage: bash scripts/check-connectivity-aware-sync-cases.sh [--self-test]" >&2
  exit 2
fi

node "$VALIDATOR" "$MANIFEST"
