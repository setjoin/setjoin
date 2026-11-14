#!/usr/bin/env bash
# pre-ci.sh — run before any push that triggers the server-rust full lane (~2 min, no DB).
# Catches what has cost whole lane runs: stale adequacy manifest, cargo-deny policy, workflow
# shell syntax, bind-:0-then-drop port handoffs, tracked bytecode, context budgets, hosted-lane
# shard merge.
#
#   bash scripts/pre-ci.sh                    run every check, one summary line each
#   bash scripts/pre-ci.sh --lane <filter>    also print (not run) the LANE_QUICK command for
#                                             nextest binary ids matching <filter>; `changed`
#                                             derives the filter from changed server-rust test files
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 2
WF=(.github/workflows/server-rust-lane.yml .github/workflows/ci-images.yml .github/actions/lane-setup/action.yml)
lane_filter=""
case "${1:-}" in
  "") ;;
  --lane) lane_filter="${2:?usage: pre-ci.sh [--lane <binary_id filter|changed>]}" ;;
  *) echo "usage: pre-ci.sh [--lane <binary_id filter|changed>]" >&2; exit 2 ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
fails=()
results=()
# check NAME CMD...: runs CMD, records a one-line summary; output is shown only on failure.
check() {
  local name="$1"; shift
  if "$@" >"$tmp/out" 2>&1; then
    results+=("PASS $name")
    grep '^WARN' "$tmp/out" | sed 's/^/    /'
  else
    results+=("FAIL $name")
    fails+=("$name")
    sed 's/^/    /' "$tmp/out" | tail -40
  fi
}

workflow_shell() {
  python3 - "$tmp" "${WF[@]}" <<'PY' || return 1
import re, sys, yaml
n = 0
for path in sys.argv[2:]:
    doc = yaml.safe_load(open(path))
    # a workflow has jobs.<id>.steps, a composite action runs.steps
    groups = [job["steps"] for job in doc["jobs"].values()] if "jobs" in doc else [doc["runs"]["steps"]]
    for steps in groups:
        for step in steps:
            if "run" in step:
                n += 1
                # GitHub expressions are not shell: swap in a placeholder for the syntax checks
                open(f"{sys.argv[1]}/run{n}.sh", "w").write(re.sub(r"\$\{\{.*?\}\}", "GHA_EXPR", step["run"]))
print(n, "run blocks")
PY
  local f rc=0
  for f in "$tmp"/run*.sh; do bash -n "$f" || { echo "bash -n failed: $f"; rc=1; }; done
  if command -v shellcheck >/dev/null 2>&1; then
    for f in "$tmp"/run*.sh; do shellcheck -S error -s bash "$f" || rc=1; done
  else
    echo "WARN: shellcheck not installed, skipped"
  fi
  if command -v actionlint >/dev/null 2>&1; then
    actionlint "${WF[@]:0:2}" || rc=1
  else
    echo "WARN: actionlint not installed, skipped"
  fi
  return "$rc"
}

port_handoff() {
  local hits
  hits="$(grep -rn -A2 'bind("127.0.0.1:0")' server-rust --include=*.rs | grep 'drop(' || true)"
  [[ -z "$hits" ]] || { echo "bind-:0-then-drop port handoff (another process can take the port):"; echo "$hits"; return 1; }
}

tracked_bytecode() {
  local hits
  hits="$(git ls-files | grep -E '(^|/)__pycache__/|\.pyc$' || true)"
  [[ -z "$hits" ]] || { echo "tracked bytecode:"; echo "$hits"; return 1; }
}

check "adequacy preflight" python3 scripts/check-gofree-oracle-adequacy.py --preflight-only
check "adequacy_guard_test" python3 server-rust/tests/conformance/tests/adequacy_guard_test.py
check "coverage_report_test" python3 server-rust/tests/conformance/tests/coverage_report_test.py
check "merge-lane-shards test" python3 scripts/test-merge-lane-shards.py
check "rehearsal guard test" python3 scripts/test-check-gofree-rehearsal.py
check "rehearsal static" python3 scripts/check-gofree-rehearsal.py static
# cargo-deny: the pinned binary the lane uses (scripts/server-rust-lane-tools.sh puts it in
# LANE_BIN_DIR), else one on PATH. Missing is a FAIL unless PRE_CI_SKIP_DENY=1 (then SKIP).
cargo_deny() {
  local bin="${LANE_BIN_DIR:-$HOME/.cache/setjoin-server-rust-lane/bin}"
  if [[ -x "$bin/cargo-deny" ]]; then
    PATH="$bin:$PATH"
  elif ! cargo deny --version >/dev/null 2>&1; then
    echo "cargo-deny not found in $bin or on PATH; run: bash scripts/server-rust-lane-tools.sh (or set PRE_CI_SKIP_DENY=1 to skip)"
    return 3
  fi
  (cd server-rust && cargo deny --locked check)
}
if [[ "${PRE_CI_SKIP_DENY:-}" == 1 ]]; then
  results+=("SKIP cargo deny (PRE_CI_SKIP_DENY=1)")
else
  check "cargo deny" cargo_deny
fi
if [[ -f "$WF" ]]; then
  check "workflow run blocks (bash -n, shellcheck, actionlint)" workflow_shell
else
  echo "SKIP workflow run blocks: $WF is absent until the GitHub-hosted lane lands"
fi
check "port handoff (bind :0 then drop)" port_handoff
check "tracked __pycache__/.pyc" tracked_bytecode
check "agent context budget" bash scripts/check-agent-context-budget.sh

# Changed test files -> nextest binary names (tests/<name>.rs). A file in a tests/<dir>/ module
# directory resolves to every tests/*.rs that declares `mod <dir>;`; unresolvable ones are listed.
changed_binaries() {
  local f dir d top m found
  while IFS= read -r f; do
    [[ "$f" == server-rust/*/tests/* || "$f" == server-rust/*/*/tests/* || "$f" == server-rust/tests/* ]] || continue
    [[ "$f" == *.rs ]] || continue
    dir="${f%%/tests/*}/tests"
    top="${f#"$dir"/}"
    if [[ "$top" != */* ]]; then basename "$top" .rs; continue; fi
    d="${top%%/*}"
    found=0
    for m in "$dir"/*.rs; do
      [[ -f "$m" ]] || continue
      if grep -qE "^[[:space:]]*(pub[[:space:]]+)?mod[[:space:]]+$d[[:space:]]*;" "$m"; then basename "$m" .rs; found=1; fi
    done
    [[ "$found" == 1 ]] || echo "pre-ci: cannot resolve $f to a test binary" >&2
  done < <({ git diff --name-only HEAD; git ls-files --others --exclude-standard; } | sort -u) | sort -u | paste -sd'|' -
}

if [[ -n "$lane_filter" ]]; then
  if [[ "$lane_filter" == changed ]]; then
    lane_filter="$(changed_binaries)"
    [[ -n "$lane_filter" ]] || echo "no changed test binaries resolved; give an explicit --lane <filter>"
  fi
  if [[ -n "$lane_filter" ]]; then
    lane_expr="$(tr '|' '\n' <<<"$lane_filter" | sed 's/.*/binary_id(~&)/' | paste -sd'#' - | sed 's/#/ | /g')"
    echo "quick lane (not run): LANE_QUICK=1 LANE_NEXTEST_FILTER='${lane_expr}' LANE_PG_PORT=<port> PGPASSWORD=<pw> bash scripts/server-rust-parallel-lane.sh"
    echo "  or the workflow_dispatch input filter: ${lane_expr}"
  fi
fi

echo "== pre-ci summary =="
printf '%s\n' "${results[@]}"
if ((${#fails[@]})); then
  echo "pre-ci: FAILED (${#fails[@]}): ${fails[*]}"
  exit 1
fi
echo "pre-ci: all checks passed"
