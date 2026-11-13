#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOCK="$ROOT/config/quality-tool-versions.json"

version_output() {
  case "$1" in
    ruff) ruff --version ;;
    shfmt) shfmt --version ;;
    gitleaks) gitleaks version ;;
    actionlint) actionlint -version ;;
    *) return 2 ;;
  esac
}

failed=0
for tool in ruff shfmt gitleaks actionlint; do
  expected="$(jq -r --arg tool "$tool" '.tools[$tool]' "$LOCK")"
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "quality-version: MISSING $tool@$expected"
    failed=1
    continue
  fi
  actual="$(version_output "$tool" 2>&1)"
  if grep -Fq "$expected" <<<"$actual"; then
    echo "quality-version: PASS $tool@$expected"
  else
    echo "quality-version: FAIL $tool expected=$expected output=${actual//$'\n'/; }" >&2
    failed=1
  fi
done

expected_psa="$(jq -r '.tools.PSScriptAnalyzer' "$LOCK")"
if command -v pwsh >/dev/null 2>&1; then
  actual_psa="$(pwsh -NoProfile -Command '(Get-Module -ListAvailable PSScriptAnalyzer | Sort-Object Version -Descending | Select-Object -First 1).Version.ToString()')"
  if [[ "$actual_psa" == "$expected_psa" ]]; then
    echo "quality-version: PASS PSScriptAnalyzer@$expected_psa"
  else
    echo "quality-version: FAIL PSScriptAnalyzer expected=$expected_psa actual=${actual_psa:-missing}" >&2
    failed=1
  fi
else
  echo "quality-version: MISSING PSScriptAnalyzer@$expected_psa"
  echo "quality-version: INFO PSScriptAnalyzer is enforced on Windows CI"
fi
exit "$failed"
