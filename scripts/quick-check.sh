#!/usr/bin/env bash
# Quick check for agent branches (.github/workflows/quick-check.yml); CI-side, so nobody compiles Rust locally.
#   quick-check.sh plan   write the changed workspace packages to $LANE_QC_OUT/packages.txt
#   quick-check.sh run    cargo check --tests + cargo test --lib per package, cheap guards, rustfmt on added files
# Env: LANE_QC_PACKAGES (space-separated override), LANE_QC_TESTS (extra test name filters; option-like args rejected, zero executed tests = FAIL), LANE_QC_OUT (artifact dir).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="${LANE_QC_OUT:-$ROOT/lane-artifacts}"
mkdir -p "$OUT"
BASE="${LANE_QC_BASE:-origin/main}"

plan() {
  if [ -n "${LANE_QC_PACKAGES:-}" ]; then
    printf '%s\n' $LANE_QC_PACKAGES > "$OUT/packages.txt"
    return 0
  fi
  git diff --name-only "$BASE...HEAD" > "$OUT/changed.txt" || { echo "quick-check plan: git diff failed" >&2; exit 1; }
  cargo metadata --locked --no-deps --format-version 1 --manifest-path server-rust/Cargo.toml |
    python3 -c '
import json, os, sys
meta = json.load(sys.stdin)
root = os.getcwd()
dirs = {p["name"]: os.path.relpath(os.path.dirname(p["manifest_path"]), root) for p in meta["packages"]}
changed = [l.strip() for l in open(sys.argv[1]) if l.strip()]
if any(f in ("server-rust/Cargo.toml", "server-rust/Cargo.lock") or f.startswith("server-rust/rust-toolchain") for f in changed):
    hit = set(dirs)
else:
    hit = {n for n, d in dirs.items() if any(f == d or f.startswith(d + "/") for f in changed)}
print("\n".join(sorted(hit)))
' "$OUT/changed.txt" > "$OUT/packages.txt" || { echo "quick-check plan: cargo metadata failed" >&2; exit 1; }
}

SUMMARY="$OUT/summary.md"
FAILED=0
: > "$SUMMARY"
step() { # name cmd...
  local name="$1"; shift
  local log="$OUT/log-$(printf '%s' "$name" | tr -c 'A-Za-z0-9' '_').txt"
  if "$@" > "$log" 2>&1; then
    echo "- PASS: $name" >> "$SUMMARY"
  else
    FAILED=1
    echo "- FAIL: $name" >> "$SUMMARY"
    { echo; echo "First 40 error lines of $name:"; echo '```'
      { grep -E '^error|error(\[|:)|FAILED|panicked|^FAIL|FAIL:|Diff in|ERROR|WORKFLOW-HYGIENE-FAIL' "$log" || tail -n 40 "$log"; } | head -n 40
      echo '```'; echo; } >> "$SUMMARY"
  fi
}
skip() { echo "- SKIP: $1 ($2)" >> "$SUMMARY"; }

run() {
  plan
  mapfile -t pkgs < <(grep -v '^$' "$OUT/packages.txt" 2>/dev/null || true)
  if [ "${#pkgs[@]}" -eq 0 ]; then
    skip "cargo check/test" "no Rust workspace package changed"
  else
    echo "packages: ${pkgs[*]}"
    for p in "${pkgs[@]}"; do
      step "cargo check --tests -p $p" bash -c 'cd server-rust && cargo check --locked --tests -p "$1"' _ "$p"
    done
    for p in "${pkgs[@]}"; do
      # shellcheck disable=SC2086
      step "cargo test --lib -p $p ${LANE_QC_TESTS:-}" bash scripts/quick-check-tests.sh run "$p" ${LANE_QC_TESTS:-}
    done
  fi
  step "check-gofree-route-inventory" python3 scripts/check-gofree-route-inventory.py
  step "check-agent-context-budget" bash scripts/check-agent-context-budget.sh
  step "check-agent-docs" bash scripts/check-agent-docs.sh
  step "check-workflow-log-hygiene" bash scripts/check-workflow-log-hygiene.sh
  mapfile -t added < <(git diff --name-only --diff-filter=A "$BASE...HEAD" -- '*.rs' 2>/dev/null)
  if [ "${#added[@]}" -eq 0 ]; then
    skip "rustfmt added files" "no Rust file added"
  else
    step "rustfmt --check added files (${#added[@]})" rustfmt --edition 2021 --check "${added[@]}"
  fi
  cat "$SUMMARY"
  return "$FAILED"
}

case "${1:-run}" in
  plan) plan; cat "$OUT/packages.txt" ;;
  run) run ;;
  *) echo "usage: $0 plan|run" >&2; exit 2 ;;
esac
