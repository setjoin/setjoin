#!/usr/bin/env bash
# Run one Go module with normal human-readable output while retaining the exact
# `go test -json` event stream used by the result-bound evidence gate.
source "$(dirname "$0")/_base.sh"
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "usage: run-go-test-evidence.sh MODULE REPORT GO_TEST_ARGS..." >&2
  exit 2
fi

module="$1"
report="$2"
shift 2

module_row="$(node "$ROOT/scripts/go-module-catalog.mjs" get "$module")" || exit 2
IFS=$'\t' read -r module_id module_path _module_workspace _module_kind _module_tags module_gowork <<<"$module_row"
if ! node "$ROOT/scripts/go-module-catalog.mjs" list test | cut -f1 | grep -Fxq "$module_id"; then
  echo "go-test-evidence: module is not test-capable: $module" >&2
  exit 2
fi
case "$report" in
  test-results/go/*.json)
    if [[ "$report" == *"/../"* || "$report" == *"/./"* || "$report" == *"//"* ]]; then
      echo "go-test-evidence: report path is not normalized: $report" >&2
      exit 2
    fi
    report_path="$ROOT/$report"
    ;;
  *) echo "go-test-evidence: report must be under test-results/go/: $report" >&2; exit 2 ;;
esac

coverage_path="$ROOT/test-results/coverage/go/$module.out"
mkdir -p "$(dirname "$report_path")" "$(dirname "$coverage_path")"

echo "==> Testing $module (JSON: ${report_path#"$ROOT"/}; coverage: ${coverage_path#"$ROOT"/})"
# -coverpkg=./... makes the denominator the whole module, including packages
# with no local _test.go files. Without it, entirely untested packages vanish
# from the profile and inflate the reported module percentage.
if [[ "$module_gowork" == "off" ]]; then
  (cd "$ROOT/$module_path" && GOWORK=off go test -json -covermode=atomic -coverpkg=./... -coverprofile="$coverage_path" "$@") \
    | node "$ROOT/scripts/stream-go-test-json.mjs" "$report_path"
else
  (cd "$ROOT/$module_path" && go test -json -covermode=atomic -coverpkg=./... -coverprofile="$coverage_path" "$@") \
  | node "$ROOT/scripts/stream-go-test-json.mjs" "$report_path"
fi
