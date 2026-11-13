#!/usr/bin/env bash
# Architecture Deepening Round 4: thin, source-bound focused test dispatcher.
# Resolved relative to this script at runtime.
# shellcheck disable=SC1091
source "$(dirname "$0")/_base.sh"
set -euo pipefail

RESULTS_ROOT="${ARCH_R4_RESULTS_ROOT:-$ROOT/test-results/architecture-r4}"
REGISTRY="$ROOT/docs/verification/architecture-r4-cases.json"
LANES=(ldap config native webdav jmap toggle asr units gomods tasks sw cron features)
NODE_BIN="${ARCH_R4_NODE_BIN:-$(command -v node)}"
VERBOSE=0

usage() {
  cat <<'EOF'
Usage: bash scripts/verify-architecture-r4.sh COMMAND [OPTIONS]

Commands:
  --help                  Show this contract.
  --doctor                Report prerequisites and exact lane commands.
  list                    List 13 stable lanes and case IDs.
  ldap|config|native|webdav|jmap|toggle|asr|units|gomods|tasks|sw|cron|features
                          Run one focused lane and publish atomic evidence.
  LANE [--self-test] [--verbose]
                          Run a lane, or plant a disposable failure; stream child output with --verbose.
  quick [--verbose]       Run all lanes in order; fail on the first red lane.
  full [--verbose]        Run quick, then repository build/lint/test front doors.
  evidence [--run-id ID]  Validate latest or named manifest and artifact hash.

Evidence: test-results/architecture-r4/<run-id>/manifest.json
EOF
}

contains_lane() {
  local wanted="$1" lane
  for lane in "${LANES[@]}"; do
    [[ "$lane" == "$wanted" ]] && return 0
  done
  return 1
}

need() {
  command -v "$1" >/dev/null 2>&1
}

diagnostic() {
  local code="$1" problem="$2" cause="$3" location="$4" artifact="$5" fix="$6" rerun="$7"
  printf '%s\n' "$code" >&2
  printf 'problem: %s\n' "$problem" >&2
  printf 'cause: %s\n' "$cause" >&2
  printf 'location: %s\n' "$location" >&2
  printf 'artifact: %s\n' "$artifact" >&2
  printf 'fix: %s\n' "$fix" >&2
  printf 'rerun: %s\n' "$rerun" >&2
  printf 'docs: docs/superpowers/plans/archive/2026-08-13-architecture-deepening-round-4.md\n' >&2
}

parse_verbose_only() {
  if [[ $# -gt 1 || ( $# -eq 1 && "$1" != "--verbose" ) ]]; then
    return 2
  fi
  if [[ $# -eq 1 ]]; then
    VERBOSE=1
  fi
}

case_id() {
  "$NODE_BIN" - "$REGISTRY" "$1" <<'NODE'
const fs = require('node:fs');
const registry = JSON.parse(fs.readFileSync(process.argv[2]));
const row = registry.cases.find((candidate) => candidate.lane === process.argv[3]);
if (!row) process.exit(2);
process.stdout.write(row.caseId);
NODE
}

list_cases() {
  "$NODE_BIN" - "$REGISTRY" <<'NODE'
const fs = require('node:fs');
const registry = JSON.parse(fs.readFileSync(process.argv[2]));
for (const entry of registry.cases) {
  console.log(`${entry.lane}\t${entry.caseId}`);
}
NODE
}

lane_tools() {
  case "$1" in
    native) echo "node cargo" ;;
    tasks|sw) echo "node npm" ;;
    units|gomods) echo "node go bash" ;;
    asr) echo "node go pkg-config" ;;
    *) echo "node go" ;;
  esac
}

doctor() {
  local lane tool missing
  echo "architecture-r4 doctor"
  echo "  source: commit=$(git -C "$ROOT" rev-parse --short HEAD) dirty=$(git -C "$ROOT" status --porcelain=v1 -uall | shasum -a 256 | cut -d' ' -f1)"
  for lane in "${LANES[@]}"; do
    missing=()
    for tool in $(lane_tools "$lane"); do need "$tool" || missing+=("$tool"); done
    if [[ "$lane" == asr ]] && need pkg-config && ! pkg-config --exists opus; then missing+=("libopus-dev"); fi
    if ((${#missing[@]})); then
      echo "  $lane: missing=${missing[*]}; rerun=bash scripts/verify-architecture-r4.sh $lane"
    else
      echo "  $lane: ready; case=$(case_id "$lane"); estimate<=5m; rerun=bash scripts/verify-architecture-r4.sh $lane"
    fi
  done
}

run_all_lanes() {
  local lane
  for lane in "${LANES[@]}"; do
    run_lane "$lane"
  done
}

run_lane_command() {
  local lane="$1"
  case "$lane" in
    ldap)
      (cd "$ROOT/mailserver" && go test -race ./internal/ldap -count=1)
      bash "$ROOT/scripts/check-ldap-bound-state.sh"
      ;;
    config)
      (cd "$ROOT/shared" && go test -race ./config -count=1)
      (cd "$ROOT/authserver" && go test -race ./internal/config -count=1)
      (cd "$ROOT/mailserver" && go test -race ./internal/config -count=1)
      ;;
    native)
      cargo test --manifest-path "$ROOT/clients/Cargo.toml" -p capability-session
      cargo check --manifest-path "$ROOT/clients/Cargo.toml" -p desktop-native
      cargo check --manifest-path "$ROOT/clients/Cargo.toml" -p ohos-native --lib
      cargo test --manifest-path "$ROOT/clients/desktop/src-tauri/Cargo.toml" --lib
      ;;
    webdav) (cd "$ROOT/mailserver" && go test -race ./internal/webdav ./internal/caldav ./internal/carddav -count=1) ;;
    jmap) (cd "$ROOT/mailserver" && go test -race ./internal/jmap ./internal/ws -count=1) ;;
    toggle)
      (cd "$ROOT/shared" && go test -race ./toggle -count=1)
      (cd "$ROOT/authserver" && go test ./cmd/authserverd -count=1)
      (cd "$ROOT/mailserver" && go test ./cmd/mailserverd -count=1)
      ;;
    asr) (cd "$ROOT/asrbot" && GOWORK=off go test -race -tags nolibopusfile ./internal/bot -count=1) ;;
    units) bash "$ROOT/scripts/check-deploy-unit-catalog.sh" --self-test ;;
    gomods) bash "$ROOT/scripts/check-go-module-catalog.sh" && bash "$ROOT/scripts/check-go-module-catalog.sh" --self-test ;;
    tasks)
      (cd "$ROOT/mailserver/webmail" && npm exec vitest run src/lib/tasks/actionCoordinator.test.ts src/lib/components/TasksApp.behavior.test.ts src/lib/components/ui/Toast.test.ts)
      (cd "$ROOT/mailserver/webmail" && npm run check)
      ;;
    sw) (cd "$ROOT/mailserver/webmail" && npm exec vitest run src/lib/push/notificationCommand.test.ts src/service-worker.test.ts) ;;
    cron) (cd "$ROOT/mailserver" && go test -race ./internal/cron -count=20) ;;
    features)
      (cd "$ROOT/shared" && go test -race ./toggle -count=1)
      (cd "$ROOT/mailserver" && go test ./internal/admin -run 'Feature' -count=1)
      (cd "$ROOT/mailctl" && go test ./... -run 'Feature' -count=1)
      (cd "$ROOT/mailserver/webmail" && npm exec vitest run src/lib/admin/featureHelpers.test.ts)
      ;;
    *) return 2 ;;
  esac
}

source_fingerprint() {
  local commit dirty
  commit="$(git -C "$ROOT" rev-parse HEAD)"
  dirty="$(git -C "$ROOT" status --porcelain=v1 -uall | shasum -a 256 | cut -d' ' -f1)"
  printf '%s:%s' "$commit" "$dirty"
}

publish() {
  local lane="$1" verdict="$2" started="$3" ended="$4" tmp="$5" code="$6" run_id final
  run_id="$(date -u +%Y%m%dT%H%M%SZ)-$(git -C "$ROOT" rev-parse --short=8 HEAD)-$$-$lane"
  final="$RESULTS_ROOT/$run_id"
  ARCH_R4_LANE="$lane" ARCH_R4_CASE="$(case_id "$lane")" ARCH_R4_VERDICT="$verdict" \
  ARCH_R4_STARTED="$started" ARCH_R4_ENDED="$ended" ARCH_R4_SOURCE="$(source_fingerprint)" \
    ARCH_R4_CODE="$code" ARCH_R4_LOG="$tmp/output.log" "$NODE_BIN" >"$tmp/manifest.json.tmp" <<'NODE'
const fs = require('node:fs');
const crypto = require('node:crypto');
const bytes = fs.readFileSync(process.env.ARCH_R4_LOG);
const manifest = {
  schemaVersion: 1,
  lane: process.env.ARCH_R4_LANE,
  caseId: process.env.ARCH_R4_CASE,
  verdict: process.env.ARCH_R4_VERDICT,
  diagnosticCode: process.env.ARCH_R4_CODE || null,
  sourceFingerprint: process.env.ARCH_R4_SOURCE,
  startedAt: process.env.ARCH_R4_STARTED,
  endedAt: process.env.ARCH_R4_ENDED,
  artifacts: [{
    path: 'output.log',
    sha256: crypto.createHash('sha256').update(bytes).digest('hex'),
  }],
};
process.stdout.write(`${JSON.stringify(manifest, null, 2)}\n`);
NODE
  mv "$tmp/manifest.json.tmp" "$tmp/manifest.json"
  mkdir -p "$RESULTS_ROOT"; mv "$tmp" "$final"
  printf '{"schemaVersion":1,"runId":"%s"}\n' "$run_id" >"$RESULTS_ROOT/.latest.$$"
  mv "$RESULTS_ROOT/.latest.$$" "$RESULTS_ROOT/latest.json"
  echo "architecture-r4: $verdict lane=$lane case=$(case_id "$lane") manifest=${final#"$ROOT"/}/manifest.json"
}

run_lane() {
  local lane="$1" started ended tmp result verdict code
  for tool in $(lane_tools "$lane"); do
    need "$tool" || { echo "E_ARCH_R4_${lane^^}_PREREQUISITE missing=$tool" >&2; return 2; }
  done
  mkdir -p "$(dirname "$RESULTS_ROOT")"
  tmp="$(mktemp -d "$RESULTS_ROOT.tmp.XXXXXX")"; started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  set +e
  (set -e; run_lane_command "$lane") >"$tmp/output.log" 2>&1
  result=$?
  set -e
  if [[ "$VERBOSE" -eq 1 || "$result" -ne 0 ]]; then
    cat "$tmp/output.log"
  fi
  ended="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if [[ "$result" -eq 0 ]]; then
    verdict=passed
    code=""
  else
    verdict=failed
    code="E_ARCH_R4_${lane^^}_TEST"
    echo "$code result=$result" | tee -a "$tmp/output.log" >&2
  fi
  publish "$lane" "$verdict" "$started" "$ended" "$tmp" "$code"
  return "$result"
}

self_test() {
  local lane="$1" tmp fake_tool result latest run_id manifest
  tmp="$(mktemp -d)"
  case "$lane" in
    native) fake_tool=cargo ;;
    tasks|sw) fake_tool=npm ;;
    gomods) fake_tool=node ;;
    *) fake_tool=go ;;
  esac
  cat >"$tmp/$fake_tool" <<EOF
#!/usr/bin/env bash
case "\${1:-}" in version|--version) echo planted-$fake_tool; exit 0;; esac
echo R4_PLANTED_${lane^^} >&2
exit 97
EOF
  chmod +x "$tmp/$fake_tool"
  set +e
  PATH="$tmp:$PATH" ARCH_R4_NODE_BIN="$NODE_BIN" ARCH_R4_RESULTS_ROOT="$tmp/results" bash "$ROOT/scripts/verify-architecture-r4.sh" "$lane" >/dev/null 2>&1
  result=$?
  set -e
  [[ "$result" -ne 0 ]] || { echo "E_ARCH_R4_${lane^^}_SELFTEST planted failure passed" >&2; return 1; }
  latest="$tmp/results/latest.json"
  [[ -f "$latest" ]] || { echo "E_ARCH_R4_${lane^^}_SELFTEST no manifest" >&2; return 1; }
  run_id="$("$NODE_BIN" -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1])).runId)' "$latest")"
  manifest="$tmp/results/$run_id/manifest.json"
  "$NODE_BIN" - "$manifest" "$lane" <<'NODE'
const fs=require('node:fs'); const m=JSON.parse(fs.readFileSync(process.argv[2]));
if(m.lane!==process.argv[3]||m.verdict!=='failed'||!m.diagnosticCode) process.exit(1);
NODE
  rm -rf "$tmp"
  echo "architecture-r4 self-test: PASS lane=$lane"
}

evidence() {
  local run_id="" latest manifest check_output check_result current_source
  if [[ "${1:-}" == "--run-id" ]]; then
    [[ $# -eq 2 && -n "${2:-}" ]] || {
      diagnostic E_ARCH_R4_EVIDENCE_USAGE "evidence arguments are invalid" "--run-id requires exactly one non-empty ID" "scripts/verify-architecture-r4.sh:evidence" "none" "copy a run ID from test-results/architecture-r4/latest.json" "bash scripts/verify-architecture-r4.sh evidence --run-id <id>"
      return 2
    }
    run_id="$2"
  elif [[ $# -ne 0 ]]; then
    diagnostic E_ARCH_R4_EVIDENCE_USAGE "evidence arguments are invalid" "unknown arguments: $*" "scripts/verify-architecture-r4.sh:evidence" "none" "use evidence with no arguments or --run-id ID" "bash scripts/verify-architecture-r4.sh evidence --run-id <id>"
    return 2
  fi
  if [[ -z "$run_id" ]]; then
    latest="$RESULTS_ROOT/latest.json"
    [[ -f "$latest" ]] || {
      diagnostic E_ARCH_R4_EVIDENCE_MISSING "no Architecture R4 evidence is available" "latest.json does not exist" "$latest" "none" "run one named lane first" "bash scripts/verify-architecture-r4.sh list"
      return 1
    }
    set +e
    run_id="$("$NODE_BIN" - "$latest" <<'NODE'
const fs = require('node:fs');
try {
  const pointer = JSON.parse(fs.readFileSync(process.argv[2]));
  if (typeof pointer.runId !== 'string' || !pointer.runId) process.exit(2);
  process.stdout.write(pointer.runId);
} catch {
  process.exit(2);
}
NODE
)"
    check_result=$?
    set -e
    [[ "$check_result" -eq 0 ]] || {
      diagnostic E_ARCH_R4_EVIDENCE_MALFORMED "the latest evidence pointer is malformed" "latest.json is not valid schemaVersion 1 pointer data" "$latest" "none" "remove the ignored broken pointer and rerun one lane" "bash scripts/verify-architecture-r4.sh list"
      return 1
    }
  fi
  manifest="$RESULTS_ROOT/$run_id/manifest.json"
  [[ -f "$manifest" ]] || {
    diagnostic E_ARCH_R4_EVIDENCE_MISSING "the requested Architecture R4 run does not exist" "manifest.json was not found for run-id=$run_id" "$manifest" "run-id=$run_id" "choose an existing run ID or run the lane again" "bash scripts/verify-architecture-r4.sh evidence"
    return 1
  }
  current_source="$(source_fingerprint)"
  set +e
  check_output="$(ARCH_R4_EXPECTED_SOURCE="$current_source" "$NODE_BIN" - "$manifest" 2>&1 <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const manifestPath = process.argv[2];

function fail(code, cause) {
  console.error(`${code}|${cause}`);
  process.exit(1);
}

try {
  const manifest = JSON.parse(fs.readFileSync(manifestPath));
  if (manifest.schemaVersion !== 1 || manifest.verdict !== 'passed' || typeof manifest.caseId !== 'string' || !Array.isArray(manifest.artifacts)) {
    fail('E_ARCH_R4_EVIDENCE_MALFORMED', 'manifest schema, verdict, caseId, or artifacts is invalid');
  }
  if (manifest.sourceFingerprint !== process.env.ARCH_R4_EXPECTED_SOURCE) {
    fail('E_ARCH_R4_EVIDENCE_STALE', `expected=${process.env.ARCH_R4_EXPECTED_SOURCE} actual=${manifest.sourceFingerprint}`);
  }
  for (const artifact of manifest.artifacts) {
    if (!artifact || typeof artifact.path !== 'string' || typeof artifact.sha256 !== 'string') {
      fail('E_ARCH_R4_EVIDENCE_MALFORMED', 'artifact entry is invalid');
    }
    const file = path.join(path.dirname(manifestPath), artifact.path);
    if (!fs.existsSync(file)) fail('E_ARCH_R4_EVIDENCE_ARTIFACT', `missing=${file}`);
    const digest = crypto.createHash('sha256').update(fs.readFileSync(file)).digest('hex');
    if (digest !== artifact.sha256) {
      fail('E_ARCH_R4_EVIDENCE_ARTIFACT', `path=${file} expected=${artifact.sha256} actual=${digest}`);
    }
  }
  console.log(`architecture-r4 evidence: PASS lane=${manifest.lane} case=${manifest.caseId}`);
} catch (error) {
  fail('E_ARCH_R4_EVIDENCE_MALFORMED', error.message);
}
NODE
)"
  check_result=$?
  set -e
  if [[ "$check_result" -ne 0 ]]; then
    local evidence_code evidence_cause
    evidence_code="${check_output%%|*}"; evidence_cause="${check_output#*|}"
    diagnostic "$evidence_code" "Architecture R4 evidence validation failed" "$evidence_cause" "$manifest" "run-id=$run_id" "rerun the owning lane on the current source state" "bash scripts/verify-architecture-r4.sh list"
    return 1
  fi
  printf '%s\n' "$check_output"
}

command="${1:---help}"
shift || true
case "$command" in
  --help|-h) usage ;;
  --doctor) doctor ;;
  list) list_cases ;;
  quick)
    parse_verbose_only "$@" || {
      diagnostic E_ARCH_R4_CLI_USAGE "quick arguments are invalid" "expected only --verbose" "scripts/verify-architecture-r4.sh" "none" "remove unsupported arguments" "bash scripts/verify-architecture-r4.sh quick --verbose"
      exit 2
    }
    run_all_lanes
    ;;
  full)
    parse_verbose_only "$@" || {
      diagnostic E_ARCH_R4_CLI_USAGE "full arguments are invalid" "expected only --verbose" "scripts/verify-architecture-r4.sh" "none" "remove unsupported arguments" "bash scripts/verify-architecture-r4.sh full --verbose"
      exit 2
    }
    run_all_lanes
    bash "$ROOT/scripts/build.sh"
    bash "$ROOT/scripts/lint.sh"
    bash "$ROOT/scripts/test.sh"
    ;;
  evidence) evidence "$@" ;;
  *)
    contains_lane "$command" || {
      diagnostic E_ARCH_R4_CLI_UNKNOWN "unknown Architecture R4 lane or command" "command=$command" "scripts/verify-architecture-r4.sh" "none" "choose one of the 13 names printed by list" "bash scripts/verify-architecture-r4.sh list"
      exit 2
    }
    if [[ "${1:-}" == "--self-test" ]]; then
      [[ $# -le 2 && ( $# -eq 1 || "${2:-}" == "--verbose" ) ]] || {
        diagnostic E_ARCH_R4_CLI_USAGE "lane arguments are invalid" "lane=$command arguments=$*" "scripts/verify-architecture-r4.sh" "none" "use only --self-test and optional --verbose" "bash scripts/verify-architecture-r4.sh $command --self-test"
        exit 2
      }
      [[ $# -eq 1 ]] || VERBOSE=1
      self_test "$command"
    else
      parse_verbose_only "$@" || {
        diagnostic E_ARCH_R4_CLI_USAGE "lane arguments are invalid" "lane=$command arguments=$*" "scripts/verify-architecture-r4.sh" "none" "use no flag or --verbose" "bash scripts/verify-architecture-r4.sh $command --verbose"
        exit 2
      }
      run_lane "$command"
    fi
    ;;
esac
