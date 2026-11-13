#!/usr/bin/env bash
# CONTRACT: future-code-test-gates
# Validates result bindings during structural guards and verifies that exact
# named tests executed (not merely that a test file exists) when called with
# --verify. The self-test covers Vitest, Go JSON, TAP, and Playwright JSON plus
# missing/skipped-result failures.
source "$(dirname "$0")/_base.sh"
set -euo pipefail

ADAPTER="$ROOT/scripts/test-evidence-report.mjs"
MANIFEST="${TEST_EVIDENCE_MANIFEST:-$ROOT/docs/verification/feature-test-contracts.json}"
RESULT_ROOT="${TEST_EVIDENCE_ROOT:-$ROOT}"

run_adapter() {
  node "$ADAPTER" --root "$RESULT_ROOT" --manifest "$MANIFEST" "$@"
}

run_fixture() {
  local fixture_manifest="$1"
  shift
  node "$ADAPTER" --root "$tmp" --manifest "$fixture_manifest" "$@"
}

if [[ "${1:-}" == "--self-test" ]]; then
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/results" "$tmp/tests" "$tmp/sql" "$tmp/e2e"

  cat > "$tmp/results/vitest.json" <<JSON
{"testResults":[{"name":"$tmp/tests/ui.test.ts","assertionResults":[{"fullName":"ui suite renders safely","status":"passed"}]}]}
JSON
  cat > "$tmp/results/go.json" <<'JSON'
{"Action":"run","Package":"example/pkg","Test":"TestBoundary"}
{"Action":"pass","Package":"example/pkg","Test":"TestBoundary"}
JSON
  cat > "$tmp/results/pgtap.txt" <<TAP
$tmp/sql/example.pg ..........
ok 1 - cross tenant access is denied
1..1
TAP
  cat > "$tmp/results/playwright.json" <<JSON
{"config":{"rootDir":"$tmp/e2e"},"suites":[{"title":"example.spec.ts","file":"example.spec.ts","specs":[],"suites":[{"title":"suite","specs":[{"title":"works","file":"example.spec.ts","tests":[{"projectName":"chromium","expectedStatus":"passed","status":"expected","results":[{"status":"passed"}]}]}]}]}]}
JSON
  cat > "$tmp/manifest.json" <<'JSON'
{"contracts":[{"id":"fixture","requirements":[{"id":"formats","evidence":[
{"id":"vitest","skipPolicy":"forbid","result":{"format":"vitest-json","report":"results/vitest.json","suite":"tests/ui.test.ts","testId":"ui suite renders safely"}},
{"id":"go","skipPolicy":"forbid","result":{"format":"go-json","report":"results/go.json","suite":"example/pkg","testId":"TestBoundary"}},
{"id":"tap","skipPolicy":"forbid","result":{"format":"tap","report":"results/pgtap.txt","suite":"sql/example.pg","testId":"cross tenant access is denied"}},
{"id":"playwright","skipPolicy":"forbid","result":{"format":"playwright-json","report":"results/playwright.json","suite":"e2e/example.spec.ts#chromium","testId":"suite works"}}
]}]}]}
JSON

  run_fixture "$tmp/manifest.json" --verify >/dev/null

  sed 's/"status":"passed"/"status":"skipped"/' "$tmp/results/vitest.json" > "$tmp/results/vitest-skipped.json"
  sed 's#results/vitest.json#results/vitest-skipped.json#' "$tmp/manifest.json" > "$tmp/skipped-manifest.json"
  if run_fixture "$tmp/skipped-manifest.json" --verify --format vitest-json >/dev/null 2>&1; then
    echo "test-evidence self-test: skipped Vitest case was accepted" >&2
    exit 1
  fi

  sed 's/TestBoundary/TestMissing/' "$tmp/manifest.json" > "$tmp/missing-case-manifest.json"
  if run_fixture "$tmp/missing-case-manifest.json" --verify --format go-json >/dev/null 2>&1; then
    echo "test-evidence self-test: missing Go case was accepted" >&2
    exit 1
  fi

  sed 's#results/playwright.json#results/absent.json#' "$tmp/manifest.json" > "$tmp/missing-report-manifest.json"
  if run_fixture "$tmp/missing-report-manifest.json" --verify --format playwright-json >/dev/null 2>&1; then
    echo "test-evidence self-test: missing Playwright report was accepted" >&2
    exit 1
  fi

  sed 's/"status":"expected"/"status":"flaky"/; s/"results":\[{"status":"passed"}\]/"results":[{"status":"failed"},{"status":"passed"}]/' \
    "$tmp/results/playwright.json" > "$tmp/results/playwright-flaky.json"
  sed 's#results/playwright.json#results/playwright-flaky.json#' "$tmp/manifest.json" > "$tmp/flaky-manifest.json"
  if run_fixture "$tmp/flaky-manifest.json" --verify --format playwright-json >/dev/null 2>&1; then
    echo "test-evidence self-test: flaky Playwright retry was accepted" >&2
    exit 1
  fi

  echo "test-evidence self-test: PASS (Vitest, Go JSON, TAP, Playwright JSON; skipped/missing/flaky fail closed)"
  exit 0
fi

if [[ "${1:-}" == "--verify" ]]; then
  args=(--verify)
  if [[ -n "${2:-}" ]]; then args+=(--format "$2"); fi
  if [[ -n "${TEST_EVIDENCE_OUTPUT:-}" ]]; then args+=(--output "$TEST_EVIDENCE_OUTPUT"); fi
  run_adapter "${args[@]}"
  exit 0
fi

if [[ $# -ne 0 ]]; then
  echo "usage: check-test-evidence-results.sh [--self-test|--verify [format]]" >&2
  exit 2
fi

run_adapter --validate-bindings
