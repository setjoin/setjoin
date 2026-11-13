#!/usr/bin/env bash
# Standard Architecture R2 native-contract gate. The Node implementation owns
# TypeScript compiler use and the platform-seam structural projections.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "${1:-}" in
  "") mode="--check" ;;
  --self-test) mode="--self-test" ;;
  --help)
    exec node "$ROOT/scripts/native-contract-conformance.mjs" --help
    ;;
  *)
    echo "usage: $0 [--self-test|--help]" >&2
    exit 2
    ;;
esac

node "$ROOT/scripts/native-contract-conformance.mjs" "$mode"
