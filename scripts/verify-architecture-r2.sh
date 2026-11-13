#!/usr/bin/env bash
# Focused Architecture Deepening Round 2 verification front door. This script
# composes named project checks; it owns no runtime, business, or migration
# authority.
source "$(dirname "$0")/_base.sh"

RESULTS_ROOT="$ROOT/test-results/architecture-r2"
METRICS="$ROOT/scripts/architecture-r2-metrics.mjs"

usage() {
  cat <<'EOF'
Usage: bash scripts/verify-architecture-r2.sh [COMMAND]

Commands:
  --help                    Show this contract without writing files.
  --doctor                  Report each lane as ready, unsupported, or missing prerequisite.
  route|app|hold|worker|registry|native
                            Run one focused verdict.
  LANE --self-test          Prove the named lane catches a planted failure.
  quick                     Run the hermetic quick lane (also the no-argument default).
  full                      Run deterministic, database, client, and canonical gates.
  benchmark [OPTIONS]       Measure the warm quick-lane TTHW contract.

Benchmark options:
  --class warm|cold         Population class (default warm).
  --samples N               Recorded samples (default 20; CI surrogate uses 5).
  --warmup N                Unrecorded warmups (default 2; CI surrogate uses 1).

Focused commands never deploy or use production state. Database work derives a
worktree-unique mailserver_test_arch_r2_<hash> name and validates it again inside
every mutating entrypoint. Runtime mobile and Ubuntu evidence remain separate.

Evidence:
  test-results/architecture-r2/<lane>/runs/<UTC>-<commit>-<pid>/
  test-results/architecture-r2/<lane>/latest.json
  test-results/architecture-r2/dx/<UTC>-<commit>-<class>/
EOF
}

need() {
  command -v "$1" >/dev/null 2>&1
}

version_line() {
  local tool="$1"
  if need "$tool"; then
    if [[ "$tool" == "go" ]]; then
      go version 2>&1 | head -n 1
    else
      "$tool" --version 2>&1 | head -n 1
    fi
  else
    echo missing
  fi
}

worktree_db_name() {
  local hash
  hash="$(printf '%s' "$ROOT" | shasum -a 256 | cut -c1-12)"
  echo "${DB_NAME:-mailserver_test_arch_r2_$hash}"
}

doctor() {
  local base_ready=true client_ready=true db_ready=true mobile_state
  for tool in bash go node npm shasum; do
    need "$tool" || base_ready=false
  done
  need cargo || client_ready=false
  for tool in psql pg_prove; do need "$tool" || db_ready=false; done

  echo "architecture-r2 doctor"
  echo "  host: os=$(uname -s) arch=$(uname -m)"
  echo "  go: $(version_line go)"
  echo "  node: $(version_line node)"
  echo "  npm: $(version_line npm)"
  echo "  rust: $(version_line rustc)"
  echo "  psql: $(version_line psql)"
  echo "  test_database: $(worktree_db_name)"
  $base_ready && echo "  route/app/hold/worker/registry-static: ready" || echo "  route/app/hold/worker/registry-static: missing prerequisite (install Go, Node/npm, Bash, and shasum)"
  $client_ready && echo "  native-static: ready" || echo "  native-static: missing prerequisite (install Rust with cargo)"
  $db_ready && echo "  registry-db/full-db: ready" || echo "  registry-db/full-db: missing prerequisite (install PostgreSQL client and pgTAP pg_prove)"

  if [[ "$(uname -s)" == "Darwin" ]] && need xcrun; then
    echo "  ios-simulator: ready (explicit mobile lane; not part of quick/full)"
  else
    echo "  ios-simulator: unsupported or missing prerequisite (requires macOS + Xcode; never silently skipped)"
  fi
  if need adb; then
    mobile_state=ready
  else
    mobile_state="missing prerequisite (install Android platform-tools and an emulator; never silently skipped)"
  fi
  echo "  android-emulator: $mobile_state"
}

now_ms() {
  node -e 'process.stdout.write(String(Date.now()))'
}

publish_manifest() {
  local lane="$1" mode="$2" status="$3" started="$4" ended="$5" run_dir="$6" log_path="$7" started_utc="$8" diagnostic_latency="$9"
  local commit short utc manifest_tmp command classification intent
  commit="$(git -C "$ROOT" rev-parse HEAD)"
  short="${commit:0:8}"
  utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  command="bash scripts/verify-architecture-r2.sh $lane"
  classification="${ARCH_R2_CLASSIFICATION:-unclassified}"
  intent=clean-verdict
  if [[ "$mode" == "self-test" ]]; then
    command="$command --self-test"
    intent=planted-failure-detection
  fi
  manifest_tmp="$run_dir/latest.json.tmp"
  ARCH_R2_LANE="$lane" ARCH_R2_MODE="$mode" ARCH_R2_STATUS="$status" \
    ARCH_R2_STARTED="$started" ARCH_R2_ENDED="$ended" ARCH_R2_COMMIT="$commit" \
    ARCH_R2_STARTED_UTC="$started_utc" ARCH_R2_ENDED_UTC="$utc" \
    ARCH_R2_LOG="$(basename "$log_path")" ARCH_R2_LOG_PATH="$log_path" \
    ARCH_R2_COMMAND="$command" ARCH_R2_CLASSIFICATION="$classification" \
    ARCH_R2_INTENT="$intent" ARCH_R2_DIAGNOSTIC="$diagnostic_latency" \
    ARCH_R2_OS="$(uname -s)" ARCH_R2_ARCH="$(uname -m)" \
    ARCH_R2_BASH="$(version_line bash)" ARCH_R2_GO="$(version_line go)" \
    ARCH_R2_NODE="$(version_line node)" ARCH_R2_NPM="$(version_line npm)" \
    ARCH_R2_RUST="$(version_line rustc)" ARCH_R2_PSQL="$(version_line psql)" \
    node > "$manifest_tmp" <<'NODE'
const fs = require('node:fs');
const crypto = require('node:crypto');
const log = process.env.ARCH_R2_LOG;
const bytes = fs.readFileSync(process.env.ARCH_R2_LOG_PATH);
const started = Number(process.env.ARCH_R2_STARTED);
const ended = Number(process.env.ARCH_R2_ENDED);
process.stdout.write(JSON.stringify({
  schemaVersion: 1,
  lane: process.env.ARCH_R2_LANE,
  mode: process.env.ARCH_R2_MODE,
  intent: process.env.ARCH_R2_INTENT,
  command: process.env.ARCH_R2_COMMAND,
  commit: process.env.ARCH_R2_COMMIT,
  classification: process.env.ARCH_R2_CLASSIFICATION,
  status: process.env.ARCH_R2_STATUS,
  verdict: process.env.ARCH_R2_STATUS,
  startedAt: process.env.ARCH_R2_STARTED_UTC,
  endedAt: process.env.ARCH_R2_ENDED_UTC,
  durationMs: ended - started,
  diagnosticLatencyMs: process.env.ARCH_R2_DIAGNOSTIC === '' ? null : Number(process.env.ARCH_R2_DIAGNOSTIC),
  prerequisites: {status: 'ready'},
  environment: {os: process.env.ARCH_R2_OS, architecture: process.env.ARCH_R2_ARCH},
  tools: {
    bash: process.env.ARCH_R2_BASH,
    go: process.env.ARCH_R2_GO,
    node: process.env.ARCH_R2_NODE,
    npm: process.env.ARCH_R2_NPM,
    rust: process.env.ARCH_R2_RUST,
    postgresClient: process.env.ARCH_R2_PSQL
  },
  artifacts: [{path: log, sha256: crypto.createHash('sha256').update(bytes).digest('hex')}]
}, null, 2) + '\n');
NODE
  mv "$manifest_tmp" "$run_dir/manifest.json"
  mkdir -p "$RESULTS_ROOT/$lane/runs"
  local final_dir
  final_dir="$RESULTS_ROOT/$lane/runs/$(date -u +%Y%m%dT%H%M%SZ)-$short-$$-$mode"
  mv "$run_dir" "$final_dir"
  local pointer_tmp="$RESULTS_ROOT/$lane/.latest.json.$$"
  ARCH_R2_TARGET="${final_dir#$ROOT/}/manifest.json" node > "$pointer_tmp" <<'NODE'
process.stdout.write(JSON.stringify({schemaVersion: 1, manifest: process.env.ARCH_R2_TARGET}, null, 2) + '\n');
NODE
  mv "$pointer_tmp" "$RESULTS_ROOT/$lane/latest.json"
  echo "architecture-r2 evidence: ${final_dir#$ROOT/}/manifest.json"
}

run_with_evidence() {
  local lane="$1" mode="$2" fn="$3" started ended status_code status tmp log statuses started_utc diagnostic_stamp diagnostic_latency
  mkdir -p "$RESULTS_ROOT/$lane"
  tmp="$(mktemp -d "$RESULTS_ROOT/$lane/.run.XXXXXX")"
  log="$tmp/output.log"
  diagnostic_stamp="$tmp/first-diagnostic-ms"
  started_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  started="$(now_ms)"
  set +e
  (cd "$ROOT" && "$fn") 2>&1 | while IFS= read -r line; do
    printf '%s\n' "$line"
    if [[ ! -e "$diagnostic_stamp" && "$line" == E_* ]]; then
      now_ms > "$diagnostic_stamp.tmp"
      mv "$diagnostic_stamp.tmp" "$diagnostic_stamp"
    fi
  done | tee "$log"
  statuses=("${PIPESTATUS[@]}")
  status_code=${statuses[0]}
  set -e
  ended="$(now_ms)"
  if [[ "$status_code" -eq 0 ]]; then status=pass; else status=failed; fi
  diagnostic_latency=""
  if [[ -f "$diagnostic_stamp" ]]; then diagnostic_latency="$(( $(<"$diagnostic_stamp") - started ))"; fi
  publish_manifest "$lane" "$mode" "$status" "$started" "$ended" "$tmp" "$log" "$started_utc" "$diagnostic_latency"
  return "$status_code"
}

route_verdict() {
  bash "$ROOT/scripts/check-route-inventory.sh"
}
route_self_test() { bash "$ROOT/scripts/check-route-inventory.sh" --self-test; }

app_verdict() { bash "$ROOT/scripts/check-app-catalog.sh"; }
app_self_test() { bash "$ROOT/scripts/check-app-catalog.sh" --self-test; }

hold_verdict() { bash "$ROOT/scripts/check-upgrade-contracts.sh"; }
hold_self_test() { bash "$ROOT/scripts/check-upgrade-contracts.sh" --self-test; }

worker_verdict() { bash "$ROOT/scripts/check-worker-launch-inventory.sh"; }
worker_self_test() { bash "$ROOT/scripts/check-worker-launch-inventory.sh" --self-test; }

registry_verdict() {
  (cd "$ROOT/shared" && go test ./toggle ./toggle/cmd/feature-registry-gen)
  (cd "$ROOT" && go run ./shared/toggle/cmd/feature-registry-gen --check)
  bash "$ROOT/scripts/check-toggle-registry.sh"
  (cd "$ROOT/mailserver/webmail" && npx vitest run \
    'src/routes/admin/(system)/features/features.test.ts' \
    src/lib/admin/featureHelpers.test.ts)
}
registry_self_test() { bash "$ROOT/scripts/check-toggle-registry.sh" --self-test; }

native_verdict() {
  bash "$ROOT/scripts/check-native-contract-conformance.sh"
  (cd "$ROOT/clients/desktop/electron" && npx vitest run src/native-contract-conformance.test.ts src/bridge.test.ts src/ipc.test.ts)
  (cd "$ROOT" && cargo test --manifest-path clients/desktop/src-tauri/Cargo.toml bridge)
}
native_self_test() { bash "$ROOT/scripts/check-native-contract-conformance.sh" --self-test; }

run_lane() {
  local lane="$1" mode="${2:-verdict}" fn
  case "$lane:$mode" in
    route:verdict) fn=route_verdict ;; route:self-test) fn=route_self_test ;;
    app:verdict) fn=app_verdict ;; app:self-test) fn=app_self_test ;;
    hold:verdict) fn=hold_verdict ;; hold:self-test) fn=hold_self_test ;;
    worker:verdict) fn=worker_verdict ;; worker:self-test) fn=worker_self_test ;;
    registry:verdict) fn=registry_verdict ;; registry:self-test) fn=registry_self_test ;;
    native:verdict) fn=native_verdict ;; native:self-test) fn=native_self_test ;;
    *) echo "verify-architecture-r2: unknown lane/mode $lane:$mode" >&2; return 2 ;;
  esac
  run_with_evidence "$lane" "$mode" "$fn"
}

run_quick() {
  local failed=()
  for lane in route app hold worker registry native; do
    if ! run_lane "$lane" verdict; then failed+=("$lane"); fi
  done
  if [[ ${#failed[@]} -gt 0 ]]; then
    echo "verify-architecture-r2: quick failed lanes: ${failed[*]}" >&2
    return 1
  fi
  echo "verify-architecture-r2: quick PASS"
}

run_registry_db() {
  local db dsn evidence_dir evidence_tmp
  db="$(worktree_db_name)"
  dsn="postgres://mail@127.0.0.1:5432/${db}?sslmode=disable"
  echo "verify-architecture-r2: registry DB lane uses $db"
  ARCH_R2_TEST_MODE=1 DB_NAME="$db" bash "$ROOT/scripts/load-test-schema.sh"
  ARCH_R2_TEST_MODE=1 DB_NAME="$db" bash "$ROOT/scripts/run-pgtap-evidence.sh" \
    test-results/pgtap/feature-toggle-registry.tap -d "$db" \
    "$ROOT/mailserver/sql/tests/feature_toggle_registry.pg"
  (cd "$ROOT/shared" && DB_DSN="$dsn" go test ./toggle -run 'TestRegistryLegacyWriteAndCutoverSerialize')
  (cd "$ROOT/mailserver" && DB_OWNER_DSN="$dsn" go test ./internal/updater -run 'Test(PGFeatureRegistryStateReadsInstalledV183|FeatureRegistryContractPreflightPostCommitAndRollback|U2PreflightRefusesIncompatibleEnforceBeforeHostAction)')
  evidence_dir="$ROOT/test-results/toggle-registry"
  mkdir -p "$evidence_dir"
  evidence_tmp="$(mktemp "$evidence_dir/.compatibility.XXXXXX")"
  ARCH_R2_DB="$db" node > "$evidence_tmp" <<'NODE'
const evidence = {
  schemaVersion: 1,
  database: process.env.ARCH_R2_DB,
  verdict: "pass",
  cases: [
    "v183_pgTAP_set_delete_mode_audit_notify",
    "n_minus_1_concurrent_unknown_write_fence",
    "signed_manifest_registry_digest_modes",
    "updater_preflight_before_host_action",
    "post_commit_digest_and_zero_unknown",
    "observe_rollback_and_enforce_refusal"
  ]
};
process.stdout.write(JSON.stringify(evidence, null, 2) + "\n");
NODE
  mv "$evidence_tmp" "$evidence_dir/compatibility.json"
}

run_full() {
  run_quick
  run_with_evidence registry-db verdict run_registry_db
  bash "$ROOT/scripts/verify-all.sh" all
  echo "verify-architecture-r2: full PASS (mobile remains an explicit separate lane)"
}

benchmark() {
  local classification=warm samples=20 warmups=2 warmup_explicit=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --class)
        [[ $# -ge 2 ]] || { usage >&2; return 2; }
        classification="$2"; shift 2 ;;
      --samples)
        [[ $# -ge 2 ]] || { usage >&2; return 2; }
        samples="$2"; shift 2 ;;
      --warmup)
        [[ $# -ge 2 ]] || { usage >&2; return 2; }
        warmups="$2"; warmup_explicit=1; shift 2 ;;
      *) usage >&2; return 2 ;;
    esac
  done
  [[ "$classification" == "warm" || "$classification" == "cold" ]] || { echo "verify-architecture-r2: --class must be warm or cold" >&2; return 2; }
  [[ "$samples" =~ ^[1-9][0-9]*$ ]] || { echo "verify-architecture-r2: --samples must be a positive integer" >&2; return 2; }
  [[ "$warmups" =~ ^[0-9]+$ ]] || { echo "verify-architecture-r2: --warmup must be a non-negative integer" >&2; return 2; }
  if [[ "$classification" == "cold" && "$warmup_explicit" -eq 0 ]]; then warmups=0; fi

  local dx_root run_tmp commit short started_utc population_key diagnostic_started diagnostic_ended diagnostic_latency
  local warmup sample ordinal sample_started sample_ended sample_status final_dir pointer_tmp aggregate_rel verdict
  dx_root="$RESULTS_ROOT/dx"
  mkdir -p "$dx_root"
  run_tmp="$(mktemp -d "$dx_root/.run.XXXXXX")"
  commit="$(git -C "$ROOT" rev-parse HEAD)"
  short="${commit:0:8}"
  started_utc="$(date -u +%Y%m%dT%H%M%SZ)"
  node "$METRICS" fingerprint "$ROOT" "$run_tmp/fingerprint.json"
  population_key="$(node -e 'const p=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8")); process.stdout.write(p.populationKey)' "$run_tmp/fingerprint.json")"

  diagnostic_started="$(now_ms)"
  set +e
  node "$METRICS" diagnostic >"$run_tmp/diagnostic-probe.log" 2>&1
  sample_status=$?
  set -e
  diagnostic_ended="$(now_ms)"
  diagnostic_latency=$((diagnostic_ended - diagnostic_started))
  if [[ "$sample_status" -ne 1 ]] || ! grep -q '^E_ARCH_R2_METRICS problem=planted_failure' "$run_tmp/diagnostic-probe.log"; then
    final_dir="$dx_root/${started_utc}-${short}-${classification}-$$.failed"
    mv "$run_tmp" "$final_dir"
    echo "verify-architecture-r2: stable planted diagnostic probe failed; retained ${final_dir#$ROOT/}" >&2
    return 1
  fi

  for ((warmup = 1; warmup <= warmups; warmup++)); do
    echo "verify-architecture-r2: warmup $warmup/$warmups"
    if ! ARCH_R2_CLASSIFICATION="$classification" run_quick >"$run_tmp/warmup-$(printf '%03d' "$warmup").log" 2>&1; then
      final_dir="$dx_root/${started_utc}-${short}-${classification}-$$.failed"
      mv "$run_tmp" "$final_dir"
      echo "verify-architecture-r2: warmup failed; retained ${final_dir#$ROOT/}" >&2
      # run_quick's failing-lane summary and the lane's own output only exist
      # in the retained log — surface them before the retained-only pointer,
      # or CI diagnostics stop at "warmup failed".
      tail -n 40 "$final_dir/warmup-$(printf '%03d' "$warmup").log" >&2
      return 1
    fi
  done

  mkdir -p "$run_tmp/samples"
  for ((sample = 1; sample <= samples; sample++)); do
    ordinal="$(printf '%03d' "$sample")"
    echo "verify-architecture-r2: sample $sample/$samples"
    sample_started="$(now_ms)"
    set +e
    ARCH_R2_CLASSIFICATION="$classification" run_quick >"$run_tmp/samples/$ordinal.log" 2>&1
    sample_status=$?
    set -e
    sample_ended="$(now_ms)"
    if [[ "$sample_status" -eq 0 ]]; then sample_status=pass; else sample_status=failed; fi
    node "$METRICS" record-sample \
      "$run_tmp/samples/$ordinal.json" "$run_tmp/samples/$ordinal.log" \
      "$commit" "$classification" "$population_key" "$sample" \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$((sample_ended - sample_started))" \
      "$diagnostic_latency" "$sample_status"
  done

  verdict="$(node "$METRICS" aggregate "$run_tmp" "$samples" "$warmups" "$classification")"
  final_dir="$dx_root/${started_utc}-${short}-${classification}-$$"
  mv "$run_tmp" "$final_dir"
  aggregate_rel="${final_dir#$ROOT/}/aggregate.json"
  pointer_tmp="$dx_root/.latest.json.$$"
  ARCH_R2_AGGREGATE="$aggregate_rel" node > "$pointer_tmp" <<'NODE'
process.stdout.write(JSON.stringify({schemaVersion: 1, aggregate: process.env.ARCH_R2_AGGREGATE}, null, 2) + '\n');
NODE
  mv "$pointer_tmp" "$dx_root/latest.json"
  echo "verify-architecture-r2: benchmark $verdict; evidence $aggregate_rel"
  node "$METRICS" validate "$final_dir/aggregate.json"
}

case "${1:-quick}" in
  --help) usage ;;
  --doctor) doctor ;;
  quick) [[ $# -eq 0 || $# -eq 1 ]] || { usage >&2; exit 2; }; run_quick ;;
  full) [[ $# -eq 1 ]] || { usage >&2; exit 2; }; run_full ;;
  benchmark) shift; benchmark "$@" ;;
  route|app|hold|worker|registry|native)
    lane="$1"
    case "${2:-}" in
      "") [[ $# -eq 1 ]] || { usage >&2; exit 2; }; run_lane "$lane" verdict ;;
      --self-test) [[ $# -eq 2 ]] || { usage >&2; exit 2; }; run_lane "$lane" self-test ;;
      *) usage >&2; exit 2 ;;
    esac
    ;;
  *) usage >&2; exit 2 ;;
esac
