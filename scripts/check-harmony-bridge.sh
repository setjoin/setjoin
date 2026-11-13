#!/usr/bin/env bash
# Compatibility entry point retained for callers of the former hand-maintained
# Harmony member-list guard. The generated native-contract checker now derives
# the authority from types.ts and validates the actual ArkTS registration arrays,
# BridgeProxy methods, and BridgeShim calls without a second contract list.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "${1:-}" in
  "") exec node "$ROOT/scripts/native-contract-conformance.mjs" --check ;;
  --self-test) exec node "$ROOT/scripts/native-contract-conformance.mjs" --self-test ;;
  --help) exec node "$ROOT/scripts/native-contract-conformance.mjs" --help ;;
  *)
    echo "usage: $0 [--self-test|--help]" >&2
    exit 2
    ;;
esac
