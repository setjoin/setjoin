#!/usr/bin/env bash
# Cross-shell MAM golden-corpus gate for the TypeScript, Rust and ArkTS pure
# lifecycle modules plus Harmony adapter/composition static wiring. ArkTS runtime
# execution remains device-gated; a passing static/build lane is not device proof.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "${1:-}" in
  "") exec node "$ROOT/scripts/mam-lifecycle-conformance.mjs" --check ;;
  --self-test) exec node "$ROOT/scripts/mam-lifecycle-conformance.mjs" --self-test ;;
  *) echo "usage: $0 [--self-test]" >&2; exit 2 ;;
esac
