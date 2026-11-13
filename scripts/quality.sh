#!/usr/bin/env bash
# One front door for repository-native static analysis. It never installs tools,
# downloads rule databases, mutates source, or targets production systems.
set -euo pipefail

ROOT="${QUALITY_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
MODE="${1:-fast}"

usage() {
  cat <<'EOF'
Usage: bash scripts/quality.sh <list|doctor|fast|full|security>

  list      Print the fixed language/tool catalog.
  doctor    Report required tool availability; no scans.
  fast      Blocking local checks: Go/Web/Electron/Rust/Shell/Python/PowerShell syntax.
  full      fast plus Rust Clippy and platform-owned checks when on that platform.
  security  Existing dependency, secret and workflow authorities.
EOF
}

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "quality: required tool missing: $1" >&2
    return 1
  }
}

report_tool() {
  if command -v "$1" >/dev/null 2>&1; then
    printf '  READY      %s\n' "$1"
  else
    printf '  MISSING    %s\n' "$1"
  fi
}

has_psscriptanalyzer() {
  command -v pwsh >/dev/null 2>&1 &&
    pwsh -NoProfile -Command 'if (Get-Module -ListAvailable PSScriptAnalyzer) { exit 0 } else { exit 1 }'
}

shell_files() {
  git -C "$ROOT" ls-files '*.sh' | while IFS= read -r file; do
    case "$file" in
      docs/ref/* | docs/examples/* | mailserver/deploy/generated/*) continue ;;
      *) printf '%s\n' "$ROOT/$file" ;;
    esac
  done
}

run_shell() {
  local -a files=()
  while IFS= read -r file; do files+=("$file"); done < <(shell_files)
  need shellcheck
  shellcheck -x -S warning "${files[@]}"
  for file in "${files[@]}"; do
    case "$(head -n 1 "$file")" in
      *bash*) bash -n "$file" ;;
      *sh*) sh -n "$file" ;;
    esac
  done
}

# The Python lane's input universe is declared once in the catalog
# (config/quality-tools.json python entry: include/exclude globs over tracked
# files) and computed by scripts/check-quality-input-coverage.sh. Both Python
# consumers below take their inputs ONLY from this list — never re-hardcode
# file paths here; check-quality-input-coverage.sh's self-test fails any
# consumer whose actual inputs diverge from the declared inventory.
python_lane_files() {
  bash "$ROOT/scripts/check-quality-input-coverage.sh" --eligible-files python
}

# Load the declared python lane inventory into the caller's `files` array.
# The producer's exit status is propagated: a FAILED inventory (broken
# catalog, undeclared lane) must fail the lane loudly — never degrade into an
# empty list that reads as a successful "no eligible files" skip (a process
# substitution loses the producer's status, which is exactly the hole this
# closes). An empty list is only accepted from a producer that succeeded.
load_lane_files() {
  local inventory file status=0
  inventory="$(python_lane_files)" || status=$?
  if [[ "$status" -ne 0 ]]; then
    echo "quality: python lane inventory failed (status $status); refusing to skip" >&2
    return "$status"
  fi
  files=()
  while IFS= read -r file; do
    [[ -z "$file" ]] && continue
    files+=("$file")
  done <<<"$inventory"
}

run_python_syntax() {
  need python3
  local -a files=()
  load_lane_files
  if [ "${#files[@]}" -eq 0 ]; then
    echo "Python syntax: no eligible files"
    return 0
  fi
  python3 - "${files[@]}" <<'PY'
import pathlib
import sys

for name in sys.argv[1:]:
    file = pathlib.Path(name)
    compile(file.read_bytes(), str(file), "exec")
print("Python syntax: clean")
PY
}

run_python_quality() {
  need ruff
  local -a files=()
  load_lane_files
  if [ "${#files[@]}" -eq 0 ]; then
    echo "Python ruff: no eligible files"
    return 0
  fi
  ruff check "${files[@]}"
  ruff format --check "${files[@]}"
}

run_powershell_syntax() {
  if command -v pwsh >/dev/null 2>&1; then
    pwsh -NoProfile -File "$ROOT/scripts/quality-powershell.ps1" -SyntaxOnly
  else
    echo "==> SKIP PowerShell syntax (pwsh unavailable; Windows CI owns the platform gate)"
  fi
}

run_database_static_guards() {
  local name guard companion
  local -a names=(
    check-account-scope
    check-gateway-ownership
    check-reducer-error-codes
    check-rls-coverage
    check-rls-scope-wrap
    check-sql-injection
  )
  for name in "${names[@]}"; do
    guard="$ROOT/scripts/$name.sh"
    companion="$ROOT/scripts/$name-selftest.sh"
    if [[ -f "$companion" ]]; then
      bash "$companion"
    elif grep -q -- '--self-test' "$guard"; then
      bash "$guard" --self-test
    fi
    bash "$guard"
  done
}

run_fast() {
  bash "$ROOT/scripts/lint.sh"
  bash "$ROOT/scripts/check-errcheck-ratchet.sh"
  echo "==> Rust formatting"
  (cd "$ROOT/clients" && cargo fmt --all -- --check)
  cargo fmt --manifest-path "$ROOT/clients/desktop/src-tauri/Cargo.toml" --all -- --check
  echo "==> Electron TypeScript and Biome"
  (cd "$ROOT/clients/desktop/electron" && npm run typecheck && npm run lint)
  echo "==> Shell syntax and ShellCheck"
  run_shell
  bash "$ROOT/scripts/check-shfmt-ratchet.sh"
  echo "==> Python syntax"
  run_python_syntax
  run_python_quality
  echo "==> PowerShell syntax"
  run_powershell_syntax
}

run_full() {
  run_fast
  echo "==> Database ownership/RLS/reducer static guards"
  run_database_static_guards
  echo "==> Rust Clippy"
  (cd "$ROOT/clients" && cargo clippy --workspace --all-targets --exclude ohos-native -- -D warnings)
  (cd "$ROOT/clients" && cargo clippy -p ohos-native --lib -- -D warnings)
  cargo clippy --manifest-path "$ROOT/clients/desktop/src-tauri/Cargo.toml" --all-targets -- -D warnings

  if has_psscriptanalyzer; then
    pwsh -NoProfile -File "$ROOT/scripts/quality-powershell.ps1"
  else
    echo "==> SKIP PSScriptAnalyzer (Windows CI owns the required platform gate)"
  fi
}

run_security() {
  bash "$ROOT/scripts/verify-all.sh" security

  need gitleaks
  gitleaks git "$ROOT" --pre-commit --redact=100 --no-banner

  need actionlint
  (cd "$ROOT" && actionlint)
}

doctor() {
  local tool
  echo "Blocking tools"
  for tool in go golangci-lint node npm cargo shellcheck python3 jq; do
    report_tool "$tool"
  done
  bash "$ROOT/scripts/check-quality-tool-versions.sh"
  echo "Pinned repository tools"
  for tool in ruff shfmt gitleaks actionlint; do
    report_tool "$tool"
  done
  if has_psscriptanalyzer; then
    echo "  READY      PSScriptAnalyzer"
  else
    echo "  PLATFORM   PSScriptAnalyzer (required on Windows CI)"
  fi
}

case "$MODE" in
  list) jq . "$ROOT/config/quality-tools.json" ;;
  doctor) doctor ;;
  fast) run_fast ;;
  full) run_full ;;
  security) run_security ;;
  -h | --help) usage ;;
  *)
    echo "quality: unknown mode: $MODE" >&2
    usage >&2
    exit 2
    ;;
esac
