#!/usr/bin/env bash
# Bounded, deterministic seed-corpus fuzz smoke for parser boundaries. Long
# mutation campaigns belong in a scheduled lane; this merge lane proves both
# fuzz targets remain runnable and retains their exact output as evidence.
source "$(dirname "$0")/_base.sh"
set -euo pipefail

OUT="${GO_FUZZ_OUTPUT:-$ROOT/test-results/go/fuzz-smoke.txt}"
mkdir -p "$(dirname "$OUT")"
: > "$OUT"

run_target() {
  local target="$1"
  echo "==> Go fuzz smoke: $target" | tee -a "$OUT"
  (
    cd "$ROOT/mailserver"
    go test ./internal/imap -run '^$' -fuzz "^${target}$" -fuzztime=20x
  ) 2>&1 | tee -a "$OUT"
}

run_target FuzzBuildSearchClause
run_target FuzzParseAddrTuple
grep -Fq 'PASS' "$OUT"
echo "go-fuzz-smoke: PASS (2 targets, 20 mutations each)" | tee -a "$OUT"
