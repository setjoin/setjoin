#!/usr/bin/env bash
# Fail-closed exact-case and result-evidence validator for Architecture R3.
source "$(dirname "$0")/_base.sh"

REGISTRY="$ROOT/docs/verification/architecture-r3-cases.json"
CHECKER="$ROOT/scripts/check-architecture-r3-evidence.mjs"

if [[ "${1:-}" == "--self-test" ]]; then
  [[ $# -eq 1 ]] || { echo "usage: bash scripts/check-architecture-r3-evidence.sh [--self-test|RESULT [--gate merge|release]]" >&2; exit 2; }
  node "$ROOT/scripts/check-architecture-r3-evidence.test.mjs"
  exec node "$ROOT/scripts/aggregate-architecture-r3-evidence.test.mjs"
fi

if [[ $# -eq 0 ]]; then
  exec node "$CHECKER" "$REGISTRY"
fi

exec node "$CHECKER" "$REGISTRY" "$@"
