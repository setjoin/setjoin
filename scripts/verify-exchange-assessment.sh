#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${1:---doctor}"
RESULT_ROOT="$ROOT/test-results/exchange-assessment"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
RESULT_DIR="$RESULT_ROOT/$RUN_ID"
mkdir -p "$RESULT_DIR"
RESULTS="$RESULT_DIR/cases.tsv"
: >"$RESULTS"

case_run() {
  local case_id="$1"
  shift
  if "$@" >"$RESULT_DIR/$case_id.log" 2>&1; then
    printf '%s\tpass\n' "$case_id" >>"$RESULTS"
    printf '[PASS] %s\n' "$case_id"
  else
    printf '%s\tfail\n' "$case_id" >>"$RESULTS"
    printf '[FAIL] %s (see %s)\n' "$case_id" "$RESULT_DIR/$case_id.log" >&2
    return 1
  fi
}

doctor() {
  case_run EX-DOCTOR-REGISTRY test -r "$ROOT/config/exchange-replacement/registry-v1.json"
  case_run EX-DOCTOR-CATALOG test -r "$ROOT/config/exchange-replacement/discovery-catalog-v1.json"
  case_run EX-DOCTOR-NODE command -v node
  case_run EX-DOCTOR-GO command -v go
  case_run EX-DOCTOR-COLLECTOR bash "$ROOT/scripts/exchange-assessment/verify-collector.sh"
}

quick() {
  doctor
  case_run EX-QUICK-COMPILER node "$ROOT/scripts/exchange-replacement-registry.test.mjs"
  case_run EX-QUICK-DRIFT bash "$ROOT/scripts/check-exchange-replacement-registry.sh"
  case_run EX-QUICK-MAILCTL bash -c "cd '$ROOT/mailctl' && go test -run 'TestExchange(V1|Collect|Bundle|Diagnose|A0)' ./..."
  case_run EX-QUICK-CRYPTO bash -c "cd '$ROOT' && go test ./shared/exchangeartifact ./shared/cryptokey"
}

core() {
  quick
  case_run EX-CORE-SCHEMA bash "$ROOT/scripts/load-test-schema.sh"
  case_run EX-CORE-REDUCERS pg_prove -h 127.0.0.1 -p 5432 -U mail -d mailserver_test \
    "$ROOT/mailserver/sql/tests/exchange_replacement_schema.pg" \
    "$ROOT/mailserver/sql/tests/exchange_assessment_reducers.pg" \
    "$ROOT/mailserver/sql/tests/exchange_assessment_evidence_lifecycle.pg" \
    "$ROOT/mailserver/sql/tests/exchange_assessment_import.pg"
  case_run EX-CORE-GO bash -c "cd '$ROOT' && go test ./mailserver/internal/admin ./mailserver/internal/continuity ./mailserver/internal/migration ./mailserver/cmd/mailserverd"
  case_run EX-CORE-WEB-CHECK npm --prefix "$ROOT/mailserver/webmail" run check
  case_run EX-CORE-WEB-UNIT bash -c "cd '$ROOT/mailserver/webmail' && npx vitest run src/lib/admin/consoles.test.ts 'src/routes/admin/(mail)/exchange-replacement/exchange-replacement.test.ts'"
  case_run EX-CORE-WEB-E2E bash "$ROOT/scripts/playwright-supported.sh" -- npm --prefix "$ROOT/mailserver/webmail" run test:e2e -- --config playwright.exchange.config.ts
}

live() {
  core
  : "${EXCHANGE_SUPPORT_CELL:?EXCHANGE_SUPPORT_CELL must name the approved support cell}"
  : "${EXCHANGE_COLLECTOR_OUTPUT:?EXCHANGE_COLLECTOR_OUTPUT must name the customer-local redacted collector JSON}"
  test -f "$EXCHANGE_COLLECTOR_OUTPUT"
  local live_dir="$RESULT_DIR/live-output"
  case_run EX-LIVE-COLLECT bash -c "cd '$ROOT/mailctl' && go run . exchange assess collect --input '$EXCHANGE_COLLECTOR_OUTPUT' --output '$live_dir' --non-interactive"
  case_run EX-LIVE-INSPECT bash -c "cd '$ROOT/mailctl' && go run . exchange assess inspect '$live_dir/bundle.sja' --json"
  printf '%s\n' "$EXCHANGE_SUPPORT_CELL" >"$RESULT_DIR/support-cell.txt"
}

case "$MODE" in
  --doctor) doctor ;;
  --quick) quick ;;
  --core) core ;;
  --live) live ;;
  *) printf 'usage: %s --doctor|--quick|--core|--live\n' "$0" >&2; exit 2 ;;
esac

node - "$RESULTS" "$RESULT_DIR/results.json" "$MODE" "$RUN_ID" <<'NODE'
const fs=require('fs');
const [input,output,mode,runId]=process.argv.slice(2);
const cases=fs.readFileSync(input,'utf8').trim().split('\n').filter(Boolean).map((line)=>{const [id,verdict]=line.split('\t');return {id,verdict};});
fs.writeFileSync(output,JSON.stringify({schemaVersion:'setjoin.exchange.verification/v1',mode,runId,createdAt:new Date().toISOString(),cases},null,2)+'\n');
NODE
printf 'Exchange assessment %s passed; evidence: %s\n' "$MODE" "$RESULT_DIR/results.json"
