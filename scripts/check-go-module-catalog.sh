#!/usr/bin/env bash
# The repository's Go modules and their build/test/lint/security capabilities
# have one fixed source of truth. A new go.mod that is not classified fails.
source "$(dirname "$0")/_base.sh"

if [[ "${1:-}" == "--self-test" ]]; then
  node "$ROOT/scripts/go-module-catalog.test.mjs" --mutant
  exit
fi

node "$ROOT/scripts/go-module-catalog.mjs" check

for capability in test lint vulnerability coverage; do
  ids="$(node "$ROOT/scripts/go-module-catalog.mjs" list "$capability" | cut -f1 | paste -sd, -)"
  [[ -n "$ids" ]] || { echo "E_ARCH_R4_GOMODS_EMPTY capability=$capability" >&2; exit 1; }
done

node "$ROOT/scripts/go-module-catalog.test.mjs"
