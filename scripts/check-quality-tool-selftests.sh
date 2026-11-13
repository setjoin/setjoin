#!/usr/bin/env bash
set -euo pipefail

TASK_TMP="$(mktemp -d "${TMPDIR:-/tmp}/setjoin-quality-selftest.XXXXXX")"
trap 'find "$TASK_TMP" -depth -delete' EXIT

expect_failure() {
  local name="$1"
  shift
  if "$@" >/dev/null 2>&1; then
    echo "quality self-test: $name accepted a planted defect" >&2
    exit 1
  fi
  echo "quality self-test: PASS $name"
}

mkdir -p "$TASK_TMP/.github/workflows"

printf 'import os\n' >"$TASK_TMP/bad.py"
expect_failure ruff-check ruff check "$TASK_TMP/bad.py"

printf '#!/usr/bin/env bash\nif true;then echo bad;fi\n' >"$TASK_TMP/bad.sh"
expect_failure shfmt shfmt -d -i 2 -ci "$TASK_TMP/bad.sh"

cat >"$TASK_TMP/gitleaks.toml" <<'EOF'
title = "Setjoin quality self-test"
[[rules]]
id = "setjoin-planted-secret"
description = "Synthetic finding used only to prove the scanner exit contract"
regex = '''SELFTEST_SECRET_[A-Z]{16}'''
EOF
printf 'SELFTEST_SECRET_ABCDEFGHIJKLMNOP\n' >"$TASK_TMP/planted-secret.txt"
expect_failure gitleaks gitleaks dir "$TASK_TMP" --config "$TASK_TMP/gitleaks.toml" --no-banner

cat >"$TASK_TMP/.github/workflows/bad.yml" <<'EOF'
name: planted defect
on: [push]
jobs:
  broken:
    runs-on: ubuntu-latest
    steps:
      - run: echo "${{ github.event.issue.title }}"
EOF
expect_failure actionlint actionlint "$TASK_TMP/.github/workflows/bad.yml"

if command -v pwsh >/dev/null 2>&1 && pwsh -NoProfile -Command 'if (Get-Module -ListAvailable PSScriptAnalyzer) { exit 0 } else { exit 1 }'; then
  printf 'Write-Host "planted"\n' >"$TASK_TMP/bad.ps1"
  expect_failure PSScriptAnalyzer pwsh -NoProfile -Command \
    "if (Invoke-ScriptAnalyzer -Path '$TASK_TMP/bad.ps1' -Severity Warning) { exit 1 }"
else
  echo "quality self-test: SKIP PSScriptAnalyzer (module unavailable)"
fi
