#!/usr/bin/env bash
# CONTRACT: future-code-test-gates
# Guard-the-guards check for the first testing-policy slice. It prevents the
# Webmail coverage command from drifting back to plain Vitest locally or in CI,
# and keeps policy/registry changes inside the workflow path filter.
source "$(dirname "$0")/_base.sh"
set -euo pipefail

TEST_SH="${TEST_GATE_TEST_SH:-$ROOT/scripts/test.sh}"
VERIFY_ALL="${TEST_GATE_VERIFY_ALL:-$ROOT/scripts/verify-all.sh}"
ONBOARDING="${TEST_GATE_ONBOARDING:-$ROOT/scripts/e2e-onboarding.sh}"
PLAYWRIGHT_RUNNER="${TEST_GATE_PLAYWRIGHT_RUNNER:-$ROOT/scripts/playwright-supported.sh}"
WORKFLOW="${TEST_GATE_WORKFLOW:-$ROOT/.github/workflows/webmail.yml}"
PACKAGE_JSON="${TEST_GATE_PACKAGE:-$ROOT/mailserver/webmail/package.json}"
VITE_CONFIG="${TEST_GATE_VITE:-$ROOT/mailserver/webmail/vite.config.js}"
PLAYWRIGHT_CONFIG="${TEST_GATE_PLAYWRIGHT:-$ROOT/mailserver/webmail/playwright.config.ts}"
CSP_CONFIG="${TEST_GATE_PLAYWRIGHT_CSP:-$ROOT/mailserver/webmail/playwright.csp.config.ts}"
E2E_STACK="${TEST_GATE_E2E_STACK:-$ROOT/mailserver/webmail/e2e/scripts/start-test-stack.sh}"
ARCHITECTURE_R2="${TEST_GATE_ARCHITECTURE_R2:-$ROOT/scripts/verify-architecture-r2.sh}"
ARCHITECTURE_R2_METRICS="${TEST_GATE_ARCHITECTURE_R2_METRICS:-$ROOT/scripts/check-architecture-r2-dx-metrics.sh}"
LANE_WORKFLOW="${TEST_GATE_LANE_WORKFLOW:-$ROOT/.github/workflows/server-rust-lane.yml}"
RUN_GUARDS="${TEST_GATE_RUN_GUARDS:-$ROOT/scripts/run-guards.sh}"

require_literal() {
  local file="$1" literal="$2" label="$3"
  if [[ ! -f "$file" ]]; then
    echo "test-gate-wiring: missing $label: $file" >&2
    return 1
  fi
  if ! grep -Fq -- "$literal" "$file"; then
    echo "test-gate-wiring: $label is missing required wiring: $literal" >&2
    return 1
  fi
}

require_job_literal() {
  local file="$1" job="$2" literal="$3" label="$4"
  if [[ ! -f "$file" ]]; then
    echo "test-gate-wiring: missing $label: $file" >&2
    return 1
  fi
  if ! awk -v header="  ${job}:" -v literal="$literal" '
    $0 == header { in_job = 1; next }
    in_job && $0 ~ /^  [[:alnum:]_-]+:$/ { exit }
    in_job && index($0, literal) { found = 1 }
    END { exit(found ? 0 : 1) }
  ' "$file"; then
    echo "test-gate-wiring: $label is missing required wiring in job $job: $literal" >&2
    return 1
  fi
}

run_check() {
  local failed=0
  require_literal "$TEST_SH" 'npm run test:coverage' 'scripts/test.sh' || failed=1
  require_literal "$TEST_SH" 'run-guards.sh' 'scripts/test.sh structural guard manifest' || failed=1
  require_literal "$RUN_GUARDS" 'for g in "$ROOT"/scripts/check-*.sh' 'run-guards filesystem manifest' || failed=1
  require_literal "$ARCHITECTURE_R2" 'check-native-contract-conformance.sh' 'Architecture R2 native static gate' || failed=1
  require_literal "$ARCHITECTURE_R2" 'native-contract-conformance.test.ts' 'Architecture R2 Electron recorder gate' || failed=1
  require_literal "$ARCHITECTURE_R2" 'cargo test --manifest-path clients/desktop/src-tauri/Cargo.toml bridge' 'Architecture R2 Tauri projection gate' || failed=1
  require_literal "$ARCHITECTURE_R2" 'local classification=warm samples=20 warmups=2' 'Architecture R2 scheduled p95 defaults' || failed=1
  require_literal "$ARCHITECTURE_R2" 'node "$METRICS" validate "$final_dir/aggregate.json"' 'Architecture R2 shared metrics validator' || failed=1
  require_literal "$ARCHITECTURE_R2" "src/routes/admin/(system)/features/features.test.ts" 'Architecture R2 registry UI reconciliation gate' || failed=1
  require_literal "$ARCHITECTURE_R2_METRICS" 'node "$METRICS" validate "$aggregate"' 'Architecture R2 local metrics consumer' || failed=1
  require_literal "$TEST_SH" 'Reloading clean schema before Go tests' 'scripts/test.sh clean Go database precondition' || failed=1
  require_literal "$TEST_SH" 'bash "$ROOT/scripts/load-test-schema.sh"' 'scripts/test.sh schema reload' || failed=1
  require_literal "$TEST_SH" "VALUES ('go-tests.local', TRUE)" 'scripts/test.sh deterministic local-domain fixture' || failed=1
  require_literal "$TEST_SH" 'go-module-catalog.mjs" list test' 'scripts/test.sh catalog-driven Go JSON evidence' || failed=1
  require_literal "$ROOT/config/go-modules.json" '"id": "setjoin-release"' 'release publisher catalog entry' || failed=1
  require_literal "$ROOT/scripts/run-go-test-evidence.sh" '-coverpkg=./...' 'whole-module Go coverage denominator' || failed=1
  require_literal "$TEST_SH" 'run-pgtap-evidence.sh" test-results/pgtap/mailserver.tap' 'scripts/test.sh pgTAP evidence' || failed=1
  require_literal "$TEST_SH" '--verify go-json' 'scripts/test.sh Go evidence verification' || failed=1
  require_literal "$TEST_SH" '--verify tap' 'scripts/test.sh pgTAP evidence verification' || failed=1
  require_literal "$TEST_SH" 'report-go-coverage.mjs" --mode enforce' 'scripts/test.sh Go coverage enforcement' || failed=1
  require_literal "$TEST_SH" 'run-go-fuzz-smoke.sh' 'scripts/test.sh bounded fuzz evidence' || failed=1
  require_literal "$TEST_SH" 'report-changed-coverage.mjs" --mode enforce' 'scripts/test.sh changed-coverage enforcement' || failed=1
  require_literal "$VERIFY_ALL" 'bash "$ROOT/scripts/test.sh"' 'scripts/verify-all.sh canonical core gate' || failed=1
  require_literal "$VERIFY_ALL" '--verify playwright-json' 'scripts/verify-all.sh Playwright evidence verification' || failed=1
  require_literal "$VERIFY_ALL" 'bash "$ROOT/scripts/playwright-supported.sh" -- npm run test:e2e' 'scripts/verify-all.sh supported browser runner' || failed=1
  require_literal "$VERIFY_ALL" 'e2e-browser-complete.sh' 'scripts/verify-all.sh complete browser matrix' || failed=1
  require_literal "$ROOT/scripts/e2e-browser-complete.sh" 'check-complete-browser-evidence.mjs' 'complete browser cross-phase evidence verifier' || failed=1
  require_literal "$ONBOARDING" 'bash "$ROOT/scripts/playwright-supported.sh" --' 'onboarding supported browser runner' || failed=1
  require_literal "$PLAYWRIGHT_RUNNER" 'PLAYWRIGHT_CONNECT_WS_ENDPOINT' 'supported browser endpoint input' || failed=1
  require_literal "$PLAYWRIGHT_RUNNER" 'this Linux host is outside the supported browser matrix' 'unsupported Linux fail-closed gate' || failed=1
  require_literal "$WORKFLOW" 'run: npm run test:coverage' 'Webmail CI' || failed=1
  require_literal "$WORKFLOW" 'run: bash scripts/check-test-evidence-results.sh --verify vitest-json' 'Webmail evidence verification' || failed=1
  require_literal "$WORKFLOW" 'COVERAGE_BASE: ${{ github.event.pull_request.base.sha || github.event.before }}' 'Webmail merge-base coverage input' || failed=1
  require_job_literal "$WORKFLOW" 'webmail-tests' 'fetch-depth: 0' 'Webmail merge-base checkout history' || failed=1
  require_literal "$WORKFLOW" 'run: node scripts/report-changed-coverage.mjs --mode enforce' 'Webmail changed-coverage enforcement' || failed=1
  require_job_literal "$LANE_WORKFLOW" 'pgtap' 'bash scripts/run-pgtap-lane.sh scripts/pgtap-known-red.txt' 'server-rust lane pgTAP execution through the known-red runner' || failed=1
  require_literal "$ROOT/scripts/run-pgtap-lane.sh" 'scripts/run-pgtap-evidence.sh test-results/pgtap/mailserver.tap' 'pgTAP lane runner mailserver evidence' || failed=1
  require_literal "$ROOT/scripts/run-pgtap-lane.sh" 'scripts/run-pgtap-evidence.sh test-results/pgtap/authserver.tap' 'pgTAP lane runner authserver evidence' || failed=1
  require_literal "$ROOT/scripts/run-pgtap-lane.sh" 'STALE known-red pgTAP' 'pgTAP known-red ratchet' || failed=1
  require_literal "$LANE_WORKFLOW" '--verify tap' 'server-rust lane pgTAP evidence verification' || failed=1
  require_literal "$LANE_WORKFLOW" 'needs: [plan, debug, build, roots, pgtap, guards,' 'server-rust lane aggregate gates on pgTAP and guards' || failed=1
  require_literal "$LANE_WORKFLOW" '"roots", "pgtap", "guards", "shard"' 'server-rust lane aggregate requires the guards job' || failed=1
  require_job_literal "$LANE_WORKFLOW" 'guards' 'bash scripts/run-guards.sh --known-red scripts/guards-known-red.txt' 'server-rust lane runs every guard through run-guards.sh' || failed=1
  require_job_literal "$LANE_WORKFLOW" 'guards' 'bash scripts/run-guards-selftest.sh' 'server-rust lane proves the known-red ratchet before the guards' || failed=1
  require_job_literal "$LANE_WORKFLOW" 'guards' 'run: npm ci' 'server-rust lane guards job installs webmail dependencies' || failed=1
  require_job_literal "$LANE_WORKFLOW" 'guards' 'cargo install cargo-deny --locked --version 0.19.0' 'server-rust lane guards job installs cargo-deny' || failed=1
  require_job_literal "$LANE_WORKFLOW" 'guards' 'echo "DB_DSN=' 'server-rust lane guards job exports DB_DSN' || failed=1
  require_job_literal "$LANE_WORKFLOW" 'guards' 'SERVER_RUST_STAGES: static' 'server-rust lane guards job runs check-server-rust static stage only' || failed=1
  require_job_literal "$LANE_WORKFLOW" 'guards' "needs.plan.outputs.debug != 'true'" 'server-rust lane guards job runs on every non-debug pull request' || failed=1
  require_literal "$PACKAGE_JSON" '"test:coverage": "vitest run --coverage --reporter=default --reporter=json --outputFile.json=test-results/vitest.json"' 'Webmail package script' || failed=1
  require_literal "$VITE_CONFIG" "reporter: ['text', 'json', 'json-summary']" 'Webmail coverage reporters' || failed=1
  require_literal "$VITE_CONFIG" "include: ['src/**/*.{js,ts,svelte}']" 'Webmail whole-source denominator' || failed=1
  require_literal "$VITE_CONFIG" 'thresholds: { statements: 80, branches: 70, functions: 80, lines: 82 }' 'Webmail coverage thresholds' || failed=1
  require_literal "$PLAYWRIGHT_CONFIG" "outputFile: './test-results/playwright.json'" 'Playwright JSON reporter' || failed=1
  require_literal "$CSP_CONFIG" "?? './test-results/playwright-csp.json'" 'CSP Playwright JSON reporter default' || failed=1
  require_literal "$CSP_CONFIG" 'outputFile: JSON_REPORT' 'CSP Playwright JSON reporter wiring' || failed=1
  require_literal "$E2E_STACK" 'SMTP_INBOUND_ADDR="127.0.0.1:${SMTP_INBOUND_PORT}"' 'E2E loopback SMTP inbound listener' || failed=1
  require_literal "$E2E_STACK" 'SMTP_SUBMISSION_ADDR="127.0.0.1:${SMTP_SUBMISSION_PORT}"' 'E2E loopback SMTP submission listener' || failed=1
  require_literal "$E2E_STACK" 'IMAP_ADDR="127.0.0.1:${IMAP_PORT}"' 'E2E loopback IMAP listener' || failed=1
  require_literal "$E2E_STACK" 'if ! kill -0 "$AUTH_PID"' 'E2E child-exit readiness fence' || failed=1
  require_literal "$E2E_STACK" 'if [ "$ready" -ne 1 ]' 'E2E readiness timeout fence' || failed=1
  [[ "$failed" -eq 0 ]]
}

if [[ "${1:-}" == "--self-test" ]]; then
  run_check >/dev/null
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  printf '#!/usr/bin/env bash\nnpm test\n' > "$tmp/test.sh"
  original_test_sh="$TEST_SH"
  TEST_SH="$tmp/test.sh"
  if run_check >/dev/null 2>&1; then
    echo "test-gate-wiring self-test: plain npm test was accepted" >&2
    exit 1
  fi
  TEST_SH="$original_test_sh"
  printf 'name: fixture\nrun: npm test\n' > "$tmp/workflow.yml"
  original_workflow="$WORKFLOW"
  WORKFLOW="$tmp/workflow.yml"
  if run_check >/dev/null 2>&1; then
    echo "test-gate-wiring self-test: workflow without coverage was accepted" >&2
    exit 1
  fi
  WORKFLOW="$original_workflow"
  awk '
    $0 == "  webmail-tests:" { in_job = 1 }
    in_job && !removed && /fetch-depth: 0/ { removed = 1; next }
    { print }
  ' "$original_workflow" > "$tmp/workflow-shallow-webmail.yml"
  WORKFLOW="$tmp/workflow-shallow-webmail.yml"
  if run_check >/dev/null 2>&1; then
    echo "test-gate-wiring self-test: shallow webmail checkout was accepted" >&2
    exit 1
  fi
  WORKFLOW="$original_workflow"
  original_lane="$LANE_WORKFLOW"
  sed 's/pgtap, guards,/pgtap,/; s/"pgtap", "guards"/"pgtap"/' "$original_lane" > "$tmp/lane-no-guards-gate.yml"
  LANE_WORKFLOW="$tmp/lane-no-guards-gate.yml"
  if run_check >/dev/null 2>&1; then
    echo "test-gate-wiring self-test: lane aggregate without the guards job was accepted" >&2
    exit 1
  fi
  sed 's#bash scripts/run-guards.sh --known-red#true --known-red#' "$original_lane" > "$tmp/lane-no-guards-run.yml"
  LANE_WORKFLOW="$tmp/lane-no-guards-run.yml"
  if run_check >/dev/null 2>&1; then
    echo "test-gate-wiring self-test: lane guards job that does not run run-guards.sh was accepted" >&2
    exit 1
  fi
  sed 's#bash scripts/run-pgtap-lane.sh#true#' "$original_lane" > "$tmp/lane-no-pgtap-run.yml"
  LANE_WORKFLOW="$tmp/lane-no-pgtap-run.yml"
  if run_check >/dev/null 2>&1; then
    echo "test-gate-wiring self-test: lane pgtap job that does not run run-pgtap-lane.sh was accepted" >&2
    exit 1
  fi
  LANE_WORKFLOW="$original_lane"
  printf 'export default {}\n' > "$tmp/playwright.config.ts"
  original_playwright_config="$PLAYWRIGHT_CONFIG"
  PLAYWRIGHT_CONFIG="$tmp/playwright.config.ts"
  if run_check >/dev/null 2>&1; then
    echo "test-gate-wiring self-test: Playwright config without JSON reporter was accepted" >&2
    exit 1
  fi
  PLAYWRIGHT_CONFIG="$original_playwright_config"
  sed "/?? '\.\/test-results\/playwright-csp.json'/d" "$CSP_CONFIG" > "$tmp/playwright.csp.config.ts"
  original_csp_config="$CSP_CONFIG"
  CSP_CONFIG="$tmp/playwright.csp.config.ts"
  if run_check >/dev/null 2>&1; then
    echo "test-gate-wiring self-test: CSP reporter without the retained default evidence path was accepted" >&2
    exit 1
  fi
  CSP_CONFIG="$original_csp_config"
  sed '/playwright-supported.sh.*npm run test:e2e/d' "$VERIFY_ALL" > "$tmp/verify-all-host-browser.sh"
  original_verify_all="$VERIFY_ALL"
  VERIFY_ALL="$tmp/verify-all-host-browser.sh"
  if run_check >/dev/null 2>&1; then
    echo "test-gate-wiring self-test: browser lane bypassed supported runner" >&2
    exit 1
  fi
  VERIFY_ALL="$original_verify_all"
  sed '/IMAP_ADDR="127.0.0.1:${IMAP_PORT}"/d' "$E2E_STACK" > "$tmp/e2e-stack-exposed-imap.sh"
  original_e2e_stack="$E2E_STACK"
  E2E_STACK="$tmp/e2e-stack-exposed-imap.sh"
  if run_check >/dev/null 2>&1; then
    echo "test-gate-wiring self-test: E2E stack without loopback IMAP was accepted" >&2
    exit 1
  fi
  E2E_STACK="$original_e2e_stack"
  echo "test-gate-wiring self-test: PASS"
  exit 0
fi

if [[ $# -ne 0 ]]; then
  echo "usage: check-test-gate-wiring.sh [--self-test]" >&2
  exit 2
fi

run_check
echo "test-gate-wiring: PASS"
