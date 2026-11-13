#!/usr/bin/env bash
# Connectivity-aware sync verification front door.
#
# E0 owns discovery, fail-closed lane truth, and the integration seam. It does
# not own the connectivity-aware-sync case manifest or its validator; those are
# DX0 inputs and are intentionally referenced, never created here.
# shellcheck disable=SC1091
source "$(dirname "$0")/_base.sh"

SCRIPT="$ROOT/scripts/verify-connectivity-aware-sync.sh"
CASE_MANIFEST_REL="docs/verification/connectivity-aware-sync-cases.json"
CASE_MANIFEST="$ROOT/$CASE_MANIFEST_REL"
# The shell wrapper is the DX0 manifest guard; the .mjs file owns exact
# manifest/case selection and is invoked directly so --case is not dropped.
CASE_VALIDATOR="$ROOT/scripts/check-connectivity-aware-sync-cases.mjs"
RESULTS_REL="test-results/connectivity-aware-sync"
RESULTS_ROOT="$ROOT/$RESULTS_REL"
WEBMAIL="$ROOT/mailserver/webmail"
WORK_CONTRACT_TEST="src/lib/offline/work-contract.test.ts"

MODE="quick"
CASE_ID=""
SELF_TEST=0
ACTION=""
EXPLAIN_ID=""
RUN_DIR=""
RUN_ID_VALUE="$(printenv RUN_ID 2>/dev/null || true)"
SELF_TEST_SCENARIO="$(printenv CAS_SELF_TEST_SCENARIO 2>/dev/null || true)"

usage() {
  cat <<'EOF'
Usage: bash scripts/verify-connectivity-aware-sync.sh [MODE] [options]

Modes:
  doctor     Read-only tool, version, supported-browser, and Ubuntu capability report.
  list       Print lane purpose, prerequisites, budgets, status, and artifacts.
  quick      E0 focused proof; runs only currently real contract/registry checks.
  core       Selected E6 runtime case consumes E6_GENERATION + E6_AGGREGATE_SHA256;
             other full local gates remain NOT RUN until their owners land.
  browser    Supported-host semantic/pixel proof; NOT RUN at E0.
  native     Electron/iOS-simulator/Android-emulator proof; NOT RUN at E0.
  ubuntu     Disposable tc-netem/load/rollback rehearsal; NOT RUN at E0.
  all        Cumulative quick -> core -> browser -> native; fail-closed at E0.

Options:
  --case ID       Select exactly one case ID from the DX0 manifest; forwarded
                  verbatim as --case ID to the case validator.
  --self-test     Exercise synthetic missing-tool, stale-state, and unsupported
                  lane failures without creating repository or runtime state.
  --cleanup       Reserved for the future idempotent cleanup receipt (DX3).
  --explain ID    Reserved for the future privacy-safe decision explanation (DX5).
  -h, --help      Show this text.

Artifacts:
  test-results/connectivity-aware-sync/<run-id>/
  Only quick/core/all attempts create artifacts. The current lane never writes
  database, network, process, qdisc, browser, native, or production state.
EOF
}

cli_error() {
  printf 'verify-connectivity-aware-sync: %s\n' "$1" >&2
  printf 'Run: bash scripts/verify-connectivity-aware-sync.sh --help\n' >&2
  return 2
}

one_line() {
  printf '%s\n' "$1" | sed -n '1p'
}

relative_path() {
  printf '%s\n' "$1" | sed "s#^$ROOT/##"
}

tool_version() {
  local tool="$1" output
  case "$tool" in
    go) output="$(go version 2>&1 || true)" ;;
    *) output="$("$tool" --version 2>&1 || true)" ;;
  esac
  output="$(one_line "$output")"
  [[ -n "$output" ]] || return 1
  printf '%s' "$output"
}

missing_tool_error() {
  local tool="$1"
  printf "FAIL CAS-DX-MISSING-TOOL: required tool \`%s\` is missing or outside the pinned range.\n" "$tool" >&2
  printf "Cause: \`%s --version\` could not be completed by the requested lane.\n" "$tool" >&2
  printf 'Fix: install the named prerequisite using the repository-supported toolchain.\n' >&2
  printf 'Next: bash scripts/verify-connectivity-aware-sync.sh doctor\n' >&2
  return 1
}

check_tool() {
  local tool="$1" path version
  path="$(command -v "$tool" 2>/dev/null || true)"
  if [[ -z "$path" ]]; then
    missing_tool_error "$tool"
    return 1
  fi
  if ! version="$(tool_version "$tool")"; then
    missing_tool_error "$tool"
    return 1
  fi
  printf 'PASS %-12s path=%s version=%s\n' "$tool" "$path" "$version"
}

browser_doctor() {
  local report runtime_line
  if ! command -v node >/dev/null 2>&1; then
    printf 'UNSUPPORTED browser-host capability=false reason=node-missing\n'
    printf 'Next: install Node.js, then rerun the doctor.\n'
    return 1
  fi
  if [[ ! -f "$WEBMAIL/node_modules/@playwright/test/package.json" ]]; then
    printf 'UNSUPPORTED browser-host capability=false reason=playwright-package-missing\n'
    printf 'Next: install the pinned Webmail dependencies, then rerun the doctor.\n'
    return 1
  fi
  if [[ ! -x "$ROOT/scripts/playwright-supported.sh" ]]; then
    printf 'UNSUPPORTED browser-host capability=false reason=supported-runner-missing\n'
    printf 'Next: restore scripts/playwright-supported.sh before requesting browser evidence.\n'
    return 1
  fi
  if report="$(bash "$ROOT/scripts/playwright-supported.sh" --check 2>&1)"; then
    runtime_line="$(one_line "$report")"
    case "$runtime_line" in
      runtime=host*|runtime=connect*)
        printf 'PASS browser-host capability=true %s\n' "$runtime_line"
        return 0
        ;;
      runtime=container*)
        printf 'UNSUPPORTED browser-host capability=false reason=container-is-diagnostic-only detail=%s\n' "$runtime_line"
        printf 'Next: use a supported host or an explicit loopback browser endpoint.\n'
        return 1
        ;;
      runtime=unsupported*)
        printf 'UNSUPPORTED browser-host capability=false detail=%s\n' "$runtime_line"
        printf 'Next: use Ubuntu 22.04/24.04, macOS, or a supported host through PLAYWRIGHT_CONNECT_WS_ENDPOINT.\n'
        return 1
        ;;
      *)
        printf 'UNSUPPORTED browser-host capability=false reason=unrecognized-runner-report detail=%s\n' "$runtime_line"
        printf 'Next: inspect scripts/playwright-supported.sh --check and rerun the doctor.\n'
        return 1
        ;;
    esac
  fi
  runtime_line="$(one_line "$report")"
  printf 'UNSUPPORTED browser-host capability=false reason=runner-check-failed detail=%s\n' "$runtime_line"
  printf 'Next: configure a supported browser host or a loopback browser endpoint.\n'
  return 1
}

ubuntu_doctor() {
  local os_name arch distro_id version_id tc_state ip_state container_state host_capability
  os_name="$(uname -s 2>/dev/null || printf unknown)"
  arch="$(uname -m 2>/dev/null || printf unknown)"
  distro_id="unknown"
  version_id="unknown"
  if [[ -r /etc/os-release ]]; then
    while IFS='=' read -r key value; do
      value="$(printf '%s\n' "$value" | sed 's/^"//; s/"$//')"
      case "$key" in
        ID) distro_id="$value" ;;
        VERSION_ID) version_id="$value" ;;
      esac
    done < /etc/os-release
  fi
  if command -v tc >/dev/null 2>&1; then tc_state=present; else tc_state=missing; fi
  if command -v ip >/dev/null 2>&1; then ip_state=present; else ip_state=missing; fi
  if command -v docker >/dev/null 2>&1; then
    container_state=docker
  elif command -v podman >/dev/null 2>&1; then
    container_state=podman
  else
    container_state=missing
  fi
  host_capability=false
  if [[ "$distro_id" == ubuntu && "$tc_state" == present && "$ip_state" == present ]]; then
    host_capability=true
  fi
  printf 'ubuntu-host capability=%s os=%s arch=%s distro=%s version=%s tc=%s ip=%s container=%s\n' \
    "$host_capability" "$os_name" "$arch" "$distro_id" "$version_id" \
    "$tc_state" "$ip_state" "$container_state"
  printf 'ubuntu-lane capability=false status=planned prerequisite=DX3/E6 disposable host\n'
  printf 'Effect: the doctor did not inspect or change qdisc, firewall, database, or process state.\n'
}

doctor() {
  local failed=0 tool
  printf 'connectivity-aware-sync doctor (read-only)\n'
  printf 'host os=%s arch=%s\n' "$(uname -s 2>/dev/null || printf unknown)" "$(uname -m 2>/dev/null || printf unknown)"
  for tool in bash node npm go cargo psql pg_isready git jq curl; do
    if check_tool "$tool"; then :; else failed=1; fi
  done
  if browser_doctor; then :; else failed=1; fi
  ubuntu_doctor
  if [[ -f "$CASE_MANIFEST" ]]; then
    printf 'case-manifest status=present path=%s\n' "$CASE_MANIFEST_REL"
  else
    printf 'case-manifest status=pending path=%s\n' "$CASE_MANIFEST_REL"
  fi
  if [[ -f "$CASE_VALIDATOR" ]]; then
    printf 'case-validator status=present path=scripts/check-connectivity-aware-sync-cases.mjs\n'
  else
    printf 'case-validator status=pending path=scripts/check-connectivity-aware-sync-cases.mjs\n'
  fi
  return "$failed"
}

list_matrix() {
  cat <<EOF
connectivity-aware-sync verification matrix (E0/DX1)

MODE      PURPOSE                                      PREREQUISITES                         BUDGET       STATUS
doctor    Read-only tool/version/capability truth      bash; local toolchain                 <30 seconds  IMPLEMENTED
list      Discover lanes and retained evidence         bash                                   <1 second    IMPLEMENTED
quick     E0 contract/manifest/type/registry proof     bash; Node; npm; DX0 manifest + validator <=5 minutes  IMPLEMENTED: E0 only; E1+ product guards pending
core      Full local pgTAP/Go/Vitest/Rust/bridge      quick plus E1+ implementations          <=25 minutes PLANNED: fail-closed until later units land
browser   Supported-host semantic/pixel state board   DX2 browser lane + explicit origin      bounded      PLANNED: NOT RUN at E0
native    Electron/iOS simulator/Android conformance  DX2/E4 adapters and runtimes            bounded      PLANNED: NOT RUN at E0
ubuntu    Disposable tc-netem/load/rollback           DX3/E6 authorized Ubuntu host            bounded      PLANNED: NOT RUN at E0
all       quick -> core -> browser -> native           every mandatory lane above              <=60 minutes FAIL-CLOSED: later lanes pending

Exact-case selection:
  --case <manifest-ID> is passed verbatim to the DX0 case validator. Substring
  or generic test-name filtering is not part of this release contract.

Connectivity case inputs owned by the disjoint DX0 task:
  manifest:  $CASE_MANIFEST_REL
  validator: scripts/check-connectivity-aware-sync-cases.mjs
  guard:     scripts/check-connectivity-aware-sync-cases.sh

Retained artifact root:
  $RESULTS_REL/<run-id>/

Current boundary:
  E0 has no connectivity-aware-sync product implementation, migration,
  deployment, network shaping, authorization, browser, native, or Ubuntu proof.
  No production capability or feature flag is enabled by this front door.
EOF
}

short_commit() {
  if command -v git >/dev/null 2>&1; then
    git -C "$ROOT" rev-parse --short=12 HEAD 2>/dev/null || printf nogit
  else
    printf nogit
  fi
}

valid_run_id() {
  case "$1" in
    ''|*[!A-Za-z0-9._-]*) return 1 ;;
    *) return 0 ;;
  esac
}

stale_state_error() {
  local stale_id="$1"
  printf 'FAIL CAS-DX-STALE-STATE: isolated database, port, process, or qdisc from RUN_ID=%s remains.\n' "$stale_id" >&2
  printf 'Cause: the run-owned state cannot be proven clean; E0 never removes or guesses at it.\n' >&2
  printf 'Fix: inspect the retained run and wait for the DX3 idempotent cleanup receipt.\n' >&2
  printf 'Next: RUN_ID=%s bash scripts/verify-connectivity-aware-sync.sh ubuntu --cleanup\n' "$stale_id" >&2
  return 1
}

start_evidence() {
  local lane="$1" commit
  commit="$(short_commit)"
  if [[ -z "$RUN_ID_VALUE" ]]; then
    RUN_ID_VALUE="$(date -u +%Y%m%dT%H%M%SZ)-$commit-$$"
  fi
  if ! valid_run_id "$RUN_ID_VALUE"; then
    printf 'FAIL CAS-DX-INVALID-RUN-ID: RUN_ID must contain only letters, numbers, dot, underscore, and hyphen.\n' >&2
    printf 'Fix: unset RUN_ID or provide a bounded run identifier.\n' >&2
    return 1
  fi
  RUN_DIR="$RESULTS_ROOT/$RUN_ID_VALUE"
  if [[ -e "$RUN_DIR" ]]; then
    stale_state_error "$RUN_ID_VALUE"
    return 1
  fi
  mkdir -p "$RESULTS_ROOT"
  mkdir "$RUN_DIR"
  {
    printf 'schemaVersion=1\n'
    printf 'lane=%s\n' "$lane"
    printf 'runId=%s\n' "$RUN_ID_VALUE"
    printf 'commit=%s\n' "$commit"
    printf 'startedAt=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if [[ -n "$CASE_ID" ]]; then
      printf 'caseSelection=%s\n' "$CASE_ID"
    else
      printf 'caseSelection=all-current\n'
    fi
    printf 'productionCapability=OFF\n'
  } > "$RUN_DIR/run.txt"
  {
    local tool
    for tool in bash node npm go cargo psql pg_isready git jq curl; do
      if command -v "$tool" >/dev/null 2>&1; then
        printf '%s=%s\n' "$tool" "$(tool_version "$tool" || printf unavailable)"
      else
        printf '%s=missing\n' "$tool"
      fi
    done
  } > "$RUN_DIR/versions.txt"
  printf 'Evidence root: %s\n' "$(relative_path "$RUN_DIR")"
}

finish_evidence() {
  local status="$1"
  {
    printf 'status=%s\n' "$status"
    printf 'endedAt=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  } >> "$RUN_DIR/run.txt"
  printf 'Retained evidence: %s\n' "$(relative_path "$RUN_DIR")"
}

missing_case_integration() {
  printf 'FAIL CAS-DX-MISSING-CASE-VALIDATOR: E0 quick cannot validate named connectivity-aware-sync cases.\n' >&2
  printf 'Cause: the planned manifest %s or validator %s is not present.\n' \
    "$CASE_MANIFEST_REL" "scripts/check-connectivity-aware-sync-cases.mjs" >&2
  printf 'Fix: land the disjoint DX0 case manifest and validator before claiming quick evidence.\n' >&2
  if [[ -n "$CASE_ID" ]]; then
    printf 'Next: bash scripts/verify-connectivity-aware-sync.sh quick --case %s\n' "$CASE_ID" >&2
  else
    printf 'Next: bash scripts/verify-connectivity-aware-sync.sh quick\n' >&2
  fi
  return 1
}

run_case_validator() {
  if [[ ! -f "$CASE_MANIFEST" || ! -f "$CASE_VALIDATOR" ]]; then
    missing_case_integration
    return 1
  fi
  if ! command -v node >/dev/null 2>&1; then
    missing_tool_error node
    return 1
  fi
  if [[ -n "$CASE_ID" ]]; then
    node "$CASE_VALIDATOR" "$CASE_MANIFEST" --case "$CASE_ID"
  else
    node "$CASE_VALIDATOR" "$CASE_MANIFEST"
  fi
}

run_registry_guard() {
  local log="$RUN_DIR/toggle-registry.log" status
  if bash "$ROOT/scripts/check-toggle-registry.sh" > "$log" 2>&1; then
    printf 'PASS CAS-E0-REGISTRY: existing finite feature-toggle registry guard.\n'
    return 0
  else
    status=$?
  fi
  printf 'FAIL CAS-E0-REGISTRY: existing finite feature-toggle registry guard failed.\n' >&2
  printf 'Evidence: %s\n' "$(relative_path "$log")" >&2
  printf 'Cause: check-toggle-registry.sh exited with status %s.\n' "$status" >&2
  printf 'Fix: inspect the retained registry log; do not add a connectivity key outside the finite toggle rail.\n' >&2
  printf 'Next: bash scripts/verify-connectivity-aware-sync.sh quick\n' >&2
  return 1
}

run_work_contract_test() {
  local log="$RUN_DIR/work-contract-vitest.log" status
  if (cd "$WEBMAIL" && npm exec vitest run "$WORK_CONTRACT_TEST") > "$log" 2>&1; then
    printf 'PASS CAS-E0-WORK-CONTRACT: frozen TypeScript work and bridge contract.\n'
    return 0
  else
    status=$?
  fi
  printf 'FAIL CAS-E0-WORK-CONTRACT: focused TypeScript contract test failed.\n' >&2
  printf 'Evidence: %s\n' "$(relative_path "$log")" >&2
  printf 'Cause: Vitest exited with status %s.\n' "$status" >&2
  printf 'Fix: repair the frozen E0 contract or its exact assertions; do not weaken the case manifest.\n' >&2
  printf 'Next: bash scripts/verify-connectivity-aware-sync.sh quick\n' >&2
  return 1
}

run_quick() {
  local failed=0 case_log case_status
  if ! start_evidence quick; then
    return 1
  fi
  if run_registry_guard; then :; else failed=1; fi

  if run_work_contract_test; then :; else failed=1; fi

  case_log="$RUN_DIR/case-validator.log"
  if run_case_validator > "$case_log" 2>&1; then
    printf 'PASS CAS-DX-CASE-MANIFEST: exact connectivity-aware-sync case selection validated.\n'
  else
    case_status=$?
    sed -n '1,60p' "$case_log" >&2 || true
    printf 'FAIL CAS-DX-CASE-MANIFEST: no connectivity-aware-sync case proof was claimed.\n' >&2
    printf 'Evidence: %s\n' "$(relative_path "$case_log")" >&2
    printf 'Cause: the case validator returned status %s or the DX0 integration is pending.\n' "$case_status" >&2
    printf 'Fix: complete the manifest/validator integration or repair the named case.\n' >&2
    if [[ -n "$CASE_ID" ]]; then
      printf 'Next: bash scripts/verify-connectivity-aware-sync.sh quick --case %s\n' "$CASE_ID" >&2
    else
      printf 'Next: bash scripts/verify-connectivity-aware-sync.sh quick\n' >&2
    fi
    failed=1
  fi

  if [[ "$failed" -eq 0 ]]; then
    finish_evidence pass
    printf 'connectivity-aware-sync quick PASS (E0-only checks; no later lane claimed)\n'
    return 0
  fi
  finish_evidence failed
  if [[ -f "$CASE_MANIFEST" && -f "$CASE_VALIDATOR" ]]; then
    printf 'connectivity-aware-sync quick FAILED (an implemented E0 check failed; no later lane claimed)\n' >&2
  else
    printf 'connectivity-aware-sync quick PENDING (DX0 case integration is incomplete; no later lane claimed)\n' >&2
  fi
  return 1
}

not_run_lane() {
  local lane="$1" rerun_case=""
  if [[ -n "$CASE_ID" ]]; then
    rerun_case=" --case $CASE_ID"
  fi
  case "$lane" in
    core)
      printf 'NOT RUN CAS-DX-CORE-PLANNED: full local pgTAP/Go/Vitest/Rust/bridge proof is not implemented in E0.\n'
      printf 'Prerequisite: E1+ product contracts and their named test/result bindings must land.\n'
      printf 'Effect: no full local lane was started and no E1+ pass was claimed.\n'
      printf 'Next: complete the owning E1+ units, then rerun: bash scripts/verify-connectivity-aware-sync.sh core%s\n' "$rerun_case"
      ;;
    browser)
      printf 'NOT RUN CAS-E4-BROWSER: supported-browser semantic/pixel proof is not implemented in E0.\n'
      printf 'Prerequisite: DX2/E4/E5 browser checks and an explicit supported origin from doctor.\n'
      printf 'Effect: no browser was launched and no browser capability or release evidence was claimed.\n'
      printf 'Next: complete the browser lane, then rerun: bash scripts/verify-connectivity-aware-sync.sh browser%s\n' "$rerun_case"
      ;;
    native)
      printf 'NOT RUN CAS-E4-NATIVE: Electron/iOS-simulator/Android-emulator conformance is not implemented in E0.\n'
      printf 'Prerequisite: DX2/E4 shell adapters, simulator/emulator runtimes, and exact conformance cases.\n'
      printf 'Effect: no native runtime was launched; foreground/reconnect support remains unclaimed by this lane.\n'
      printf 'Next: complete the native lane, then rerun: bash scripts/verify-connectivity-aware-sync.sh native%s\n' "$rerun_case"
      printf 'Physical capability: NOT RUN CAS-E4-IOS-BACKGROUND: physical-device execution proof is absent.\n'
      ;;
    ubuntu)
      printf 'NOT RUN CAS-E6-UBUNTU: disposable Ubuntu tc-netem/load/rollback proof is not implemented in E0.\n'
      printf 'Prerequisite: DX3/E6 on an authorized disposable Ubuntu host with tc-netem and cleanup receipt support.\n'
      printf 'Effect: no qdisc, firewall, database, service, process, or production state was touched.\n'
      printf 'Next: complete the Ubuntu lane, then rerun: bash scripts/verify-connectivity-aware-sync.sh ubuntu%s\n' "$rerun_case"
      ;;
    *)
      printf 'NOT RUN CAS-DX-UNIMPLEMENTED: lane %s is not implemented in E0.\n' "$lane"
      printf 'Prerequisite: the owning implementation unit and exact case bindings must land.\n'
      printf 'Effect: no lane work was started.\n'
      printf 'Next: inspect list, complete the owner unit, then rerun the lane.\n'
      ;;
  esac
  return 1
}

run_core() {
  local failed=0
  case "$CASE_ID" in
    CAS-E6-CRITICAL-SAMPLE-FLOOR|CAS-E6-PAIRED-REGRESSION|CAS-E6-FAILED-REQUEST-ACCOUNTING|CAS-E6-CROSSPROCESS-CRITICAL-SATURATION)
      if [[ -z "${E6_GENERATION:-}" || -z "${E6_AGGREGATE_SHA256:-}" ]]; then
        printf 'E6 case requires E6_GENERATION and its independently recorded E6_AGGREGATE_SHA256; no measurement or receipt was fabricated.\n' >&2
        return 1
      fi
      node "$ROOT/scripts/consume-connectivity-e6-results.mjs" "$E6_GENERATION" "$E6_AGGREGATE_SHA256" --case "$CASE_ID"
      return $?
      ;;
  esac
  if run_quick; then :; else failed=1; fi
  if not_run_lane core; then :; else failed=1; fi
  return "$failed"
}

run_all() {
  local failed=0 lane
  if run_quick; then :; else failed=1; fi
  for lane in core browser native; do
    if not_run_lane "$lane"; then :; else failed=1; fi
  done
  printf 'FAIL CAS-DX-ALL-INCOMPLETE: all cannot pass while mandatory later lanes remain unimplemented.\n' >&2
  printf 'Cause: E0 has no core, browser, or native release evidence; ubuntu is a separate lane.\n' >&2
  printf 'Fix: land each owning unit and keep every missing required case fail-closed.\n' >&2
  printf 'Next: bash scripts/verify-connectivity-aware-sync.sh list\n' >&2
  return "$failed"
}

reserved_action() {
  case "$ACTION" in
    cleanup)
      printf 'NOT RUN CAS-DX-CLEANUP-UNIMPLEMENTED: --cleanup is reserved for the DX3 idempotent cleanup receipt.\n' >&2
      printf 'Prerequisite: DX3 must own run-scoped qdisc, database, port, process, temp-file, and firewall cleanup.\n' >&2
      printf 'Effect: no cleanup action was attempted; host state was not changed.\n' >&2
      printf 'Next: after DX3 lands, rerun: RUN_ID=%s bash scripts/verify-connectivity-aware-sync.sh ubuntu --cleanup\n' \
        "$(if [[ -n "$RUN_ID_VALUE" ]]; then printf '%s' "$RUN_ID_VALUE"; else printf '<run-id>'; fi)" >&2
      ;;
    explain)
      printf 'NOT RUN CAS-DX-EXPLAIN-UNIMPLEMENTED: --explain is reserved for the DX5 privacy-safe decision record reader.\n' >&2
      printf 'Prerequisite: DX5 must land the allowlisted decision schema and evidence validator.\n' >&2
      printf 'Effect: no retained decision record was read and no identifiers or content were inspected.\n' >&2
      printf 'Next: after DX5 lands, rerun: bash scripts/verify-connectivity-aware-sync.sh quick --explain %s\n' "$EXPLAIN_ID" >&2
      ;;
    *)
      cli_error "unknown reserved action: $ACTION"
      ;;
  esac
  return 1
}

scenario_dispatch() {
  case "$1" in
    missing-tool) missing_tool_error cargo ;;
    stale-state) stale_state_error self-test ;;
    unsupported-browser) not_run_lane browser ;;
    unsupported-native) not_run_lane native ;;
    unsupported-ubuntu) not_run_lane ubuntu ;;
    *) cli_error "unknown internal self-test scenario: $1" ;;
  esac
}

expected_failure() {
  local label="$1" needle="$2" output status
  shift 2
  if output="$("$@" 2>&1)"; then
    status=0
  else
    status=$?
  fi
  if [[ "$status" -eq 0 ]]; then
    printf 'self-test failure: %s unexpectedly passed\n' "$label" >&2
    return 1
  fi
  if [[ "$output" != *"$needle"* ]]; then
    printf 'self-test failure: %s omitted expected text: %s\n' "$label" "$needle" >&2
    printf '%s\n' "$output" >&2
    return 1
  fi
  return 0
}

run_self_test() {
  local failed=0
  expected_failure missing-tool 'FAIL CAS-DX-MISSING-TOOL:' \
    env CAS_SELF_TEST_SCENARIO=missing-tool bash "$SCRIPT" doctor || failed=1
  expected_failure stale-state 'FAIL CAS-DX-STALE-STATE:' \
    env CAS_SELF_TEST_SCENARIO=stale-state bash "$SCRIPT" quick || failed=1
  expected_failure unsupported-browser 'NOT RUN CAS-E4-BROWSER:' \
    env CAS_SELF_TEST_SCENARIO=unsupported-browser bash "$SCRIPT" browser || failed=1
  expected_failure unsupported-native 'NOT RUN CAS-E4-NATIVE:' \
    env CAS_SELF_TEST_SCENARIO=unsupported-native bash "$SCRIPT" native || failed=1
  expected_failure unsupported-ubuntu 'NOT RUN CAS-E6-UBUNTU:' \
    env CAS_SELF_TEST_SCENARIO=unsupported-ubuntu bash "$SCRIPT" ubuntu || failed=1
  if [[ "$failed" -ne 0 ]]; then
    printf 'connectivity-aware-sync self-test: FAIL\n' >&2
    return 1
  fi
  printf 'connectivity-aware-sync self-test: PASS (missing-tool, stale-state, unsupported-browser/native/ubuntu)\n'
  printf 'Self-test effect: no repository, database, network, process, qdisc, or production state changed.\n'
}

if [[ -n "$SELF_TEST_SCENARIO" ]]; then
  scenario_dispatch "$SELF_TEST_SCENARIO"
  exit $?
fi

if [[ $# -gt 0 && "$1" != --* ]]; then
  MODE="$1"
  shift
elif [[ $# -gt 0 && "$1" == --help ]]; then
  MODE=help
  shift
elif [[ $# -gt 0 && "$1" == -h ]]; then
  MODE=help
  shift
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --case)
      [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || { cli_error '--case requires one manifest ID'; exit 2; }
      [[ -z "$CASE_ID" ]] || { cli_error '--case may be specified only once'; exit 2; }
      case "$2" in
        *[[:space:]]*) cli_error '--case must be one exact manifest ID without whitespace'; exit 2 ;;
      esac
      CASE_ID="$2"
      shift 2
      ;;
    --self-test)
      [[ "$SELF_TEST" -eq 0 ]] || { cli_error '--self-test may be specified only once'; exit 2; }
      SELF_TEST=1
      shift
      ;;
    --cleanup)
      [[ -z "$ACTION" ]] || { cli_error '--cleanup and --explain cannot be combined'; exit 2; }
      ACTION=cleanup
      shift
      ;;
    --explain)
      [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || { cli_error '--explain requires one decision ID'; exit 2; }
      [[ -z "$ACTION" ]] || { cli_error '--cleanup and --explain cannot be combined'; exit 2; }
      ACTION=explain
      EXPLAIN_ID="$2"
      shift 2
      ;;
    -h|--help)
      MODE=help
      shift
      ;;
    *)
      cli_error "unknown argument: $1"
      exit 2
      ;;
  esac
done

case "$MODE" in
  help)
    usage
    ;;
  list)
    [[ "$SELF_TEST" -eq 0 && -z "$ACTION" ]] || { cli_error 'list cannot combine with --self-test, --cleanup, or --explain'; exit 2; }
    list_matrix
    ;;
  doctor)
    [[ "$SELF_TEST" -eq 0 && -z "$ACTION" ]] || { cli_error 'doctor cannot combine with --self-test, --cleanup, or --explain'; exit 2; }
    doctor
    ;;
  quick)
    if [[ -n "$ACTION" ]]; then reserved_action; elif [[ "$SELF_TEST" -eq 1 ]]; then run_self_test; else run_quick; fi
    ;;
  core)
    if [[ -n "$ACTION" ]]; then reserved_action; elif [[ "$SELF_TEST" -eq 1 ]]; then run_self_test; else run_core; fi
    ;;
  browser|native|ubuntu)
    if [[ -n "$ACTION" ]]; then reserved_action; elif [[ "$SELF_TEST" -eq 1 ]]; then run_self_test; else not_run_lane "$MODE"; fi
    ;;
  all)
    if [[ -n "$ACTION" ]]; then reserved_action; elif [[ "$SELF_TEST" -eq 1 ]]; then run_self_test; else run_all; fi
    ;;
  *)
    cli_error "unknown mode: $MODE"
    exit 2
    ;;
esac
