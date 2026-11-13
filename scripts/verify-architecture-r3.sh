#!/usr/bin/env bash
# Focused Architecture Deepening Round 3 verification front door. This thin
# composer runs existing package/script tests and owns only diagnostics and
# atomic evidence publication.
source "$(dirname "$0")/_base.sh"

RESULTS_ROOT="${ARCH_R3_RESULTS_ROOT:-$ROOT/test-results/architecture-r3}"
RELEASE_ROOT="${ARCH_R3_RELEASE_EVIDENCE_ROOT:-$RESULTS_ROOT/release-evidence}"
AGGREGATE_ROOT="$RESULTS_ROOT/aggregate"
REGISTRY="$ROOT/docs/verification/architecture-r3-cases.json"
CHECKER="$ROOT/scripts/check-architecture-r3-evidence.mjs"
AGGREGATOR="$ROOT/scripts/aggregate-architecture-r3-evidence.mjs"
LANES=(aal2 auth-completion migration-checkpoint webhook-outbox mam-lifecycle chat-reconcile compose-state caption-pipeline)
OUTPUT_JSON=0
VERBOSE=0

usage() {
  cat <<'EOF'
Usage: bash scripts/verify-architecture-r3.sh [COMMAND] [OPTIONS]

Commands:
  --help                  Show this contract without writing files.
  --doctor                Read-only prerequisite and lane readiness report.
  quick                   Run all eight focused lanes (no-argument default).
  aal2|auth-completion|migration-checkpoint|webhook-outbox
  mam-lifecycle|chat-reconcile|compose-state|caption-pipeline
                          Run one focused lane.
  LANE [--self-test] [--json] [--verbose]
                          Run, machine-report, stream, or mutation-test one lane.
  compatibility           Validate retained-binary and residue receipts.
  devices                 Validate physical iOS/Android/Harmony receipts.
  live-media              Validate the pinned LiveKit/Opus/FunASR receipt.
  core                    Run quick, aggregate and check every merge case.
  full                    Run core plus all release evidence and release checker.
  evidence [--run-id ID]  Aggregate/check current evidence, or validate one run.
  benchmark [--samples N] [--warmup N]
                          Measure quick (defaults: 20 samples, 2 warmups).

Escalation commands never substitute local surrogates for retained binaries,
physical devices, or live media. Missing receipts fail with stable
E_ARCH_R3_*_MISSING diagnostics; they are never reported as skipped/passed.

Evidence:
  test-results/architecture-r3/<run-id>/manifest.json
  test-results/architecture-r3/latest.json
  test-results/architecture-r3/aggregate/<run-id>/result.json
  test-results/architecture-r3/dx/<run-id>/aggregate.json
EOF
}

need() { command -v "$1" >/dev/null 2>&1; }

version_line() {
  local tool="$1"
  if need "$tool"; then
    if [[ "$tool" == go ]]; then go version 2>&1 | head -n 1
    else "$tool" --version 2>&1 | head -n 1
    fi
  else
    echo missing
  fi
}

diagnostic() {
  local code="$1" problem="$2" cause="$3" location="$4" artifact="$5" fix="$6" rerun="$7"
  printf '%s problem=%q cause=%q location=%q artifact=%q fix=%q rerun=%q\n' \
    "$code" "$problem" "$cause" "$location" "$artifact" "$fix" "$rerun" >&2
}

usage_error() {
  local cause="$1" artifact="$2"
  diagnostic E_ARCH_R3_USAGE "invalid_cli_invocation" "$cause" \
    "$ROOT/scripts/verify-architecture-r3.sh" "$artifact" \
    "run_help_and_choose_a_documented_command_or_option" \
    "bash scripts/verify-architecture-r3.sh --help"
  usage >&2
  return 2
}

lane_tools() {
  case "$1" in
    aal2) echo "node git shasum go" ;;
    auth-completion) echo "node git shasum go psql pg_isready" ;;
    migration-checkpoint) echo "node git shasum go psql pg_prove pg_isready" ;;
    webhook-outbox) echo "node git shasum go psql pg_prove pg_isready" ;;
    mam-lifecycle) echo "node git shasum npm cargo" ;;
    chat-reconcile|compose-state) echo "node git shasum npm npx" ;;
    caption-pipeline) echo "node git shasum go pkg-config" ;;
    *) return 2 ;;
  esac
}

missing_tools() {
  local lane="$1" tool missing=()
  for tool in $(lane_tools "$lane"); do need "$tool" || missing+=("$tool"); done
  printf '%s' "${missing[*]:-}"
}

doctor() {
  local lane missing state mutation estimate group
  echo "architecture-r3 doctor"
  echo "  host: os=$(uname -s) arch=$(uname -m)"
  echo "  go: $(version_line go)"
  echo "  node: $(version_line node)"
  echo "  npm: $(version_line npm)"
  echo "  psql: $(version_line psql)"
  for lane in "${LANES[@]}"; do
    missing="$(missing_tools "$lane")"
    state=ready
    if [[ -n "$missing" ]]; then state="missing prerequisite (install: $missing)"; fi
    if [[ "$lane" =~ ^(auth-completion|migration-checkpoint|webhook-outbox)$ ]] && need pg_isready && ! pg_isready -h "${PGHOST:-127.0.0.1}" -p "${PGPORT:-5432}" >/dev/null 2>&1; then
      state="missing prerequisite (start PostgreSQL at ${PGHOST:-127.0.0.1}:${PGPORT:-5432})"
    fi
    if [[ "$lane" == caption-pipeline ]] && need pkg-config && ! pkg-config --exists opus; then
      state="missing prerequisite (install libopus development files)"
    fi
    case "$lane" in
      auth-completion) mutation="disposable local-test-database reload + fail-closed DB-backed Go fixtures"; estimate="<=180s" ;;
      migration-checkpoint) mutation="local-test-database reducer reload + rollback-only pgTAP fixtures"; estimate="<=180s" ;;
      webhook-outbox) mutation="disposable local-test-database + rollback/cleanup fixtures"; estimate="<=180s" ;;
      *) mutation="repository-read-only; writes ignored test evidence only"; estimate="<=90s" ;;
    esac
    echo "  $lane: $state; estimate=$estimate; mutation=$mutation; run=bash scripts/verify-architecture-r3.sh $lane"
  done
  for group in compatibility devices live-media; do
    if node "$CHECKER" "$REGISTRY" --release-group "$group" "$RELEASE_ROOT" >/dev/null 2>&1; then state=ready; else state="missing evidence"; fi
    echo "  $group: $state; mutation=read-only receipt validation; run=bash scripts/verify-architecture-r3.sh $group"
  done
  echo "  core: ready when all focused prerequisites are ready; estimate=<=25m; mutation=focused boundaries + ignored aggregate evidence"
  echo "  full: requires core plus retained binary, physical devices and live-media receipts; no surrogate acceptance"
  echo "  release_evidence_root: $RELEASE_ROOT"
  echo "  upgrade rehearsal: RUN_PREFIX=<unique> bash scripts/unified-deployment-readiness.sh provision"
  echo "  compatibility follow-up: RUN_PREFIX=<same> bash scripts/transactional-upgrade-rehearsal.sh rewind"
  echo "  toolchain upgrade smoke: bash scripts/post-upgrade-smoke.sh"
}

dirty_digest() {
  git -C "$ROOT" status --porcelain=v1 -uall | shasum -a 256 | cut -d' ' -f1
}

publish_manifest() {
  local lane="$1" mode="$2" verdict="$3" started_ms="$4" ended_ms="$5" started_at="$6" run_tmp="$7" log_path="$8" diagnostic_code="$9"
  local commit dirty ended_at run_id final_dir pointer_tmp manifest_tmp
  commit="$(git -C "$ROOT" rev-parse HEAD)"
  dirty="$(dirty_digest)"
  ended_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  run_id="$(date -u +%Y%m%dT%H%M%SZ)-${commit:0:8}-$$-$lane-$mode"
  final_dir="$RESULTS_ROOT/$run_id"
  manifest_tmp="$run_tmp/manifest.json.tmp"
  ARCH_R3_LANE="$lane" ARCH_R3_MODE="$mode" ARCH_R3_VERDICT="$verdict" \
    ARCH_R3_STARTED_MS="$started_ms" ARCH_R3_ENDED_MS="$ended_ms" \
    ARCH_R3_STARTED_AT="$started_at" ARCH_R3_ENDED_AT="$ended_at" \
    ARCH_R3_COMMIT="$commit" ARCH_R3_DIRTY="$dirty" ARCH_R3_LOG="$log_path" \
    ARCH_R3_DIAGNOSTIC="$diagnostic_code" ARCH_R3_OS="$(uname -s)" \
    ARCH_R3_ARCH="$(uname -m)" ARCH_R3_GO="$(version_line go)" \
    ARCH_R3_NODE="$(version_line node)" ARCH_R3_NPM="$(version_line npm)" \
    node >"$manifest_tmp" <<'NODE'
const fs = require('node:fs');
const crypto = require('node:crypto');
const bytes = fs.readFileSync(process.env.ARCH_R3_LOG);
process.stdout.write(JSON.stringify({
  schemaVersion: 1,
  lane: process.env.ARCH_R3_LANE,
  mode: process.env.ARCH_R3_MODE,
  command: `bash scripts/verify-architecture-r3.sh ${process.env.ARCH_R3_LANE}${process.env.ARCH_R3_MODE === 'self-test' ? ' --self-test' : ''}`,
  source: {commit: process.env.ARCH_R3_COMMIT, dirtyDigest: process.env.ARCH_R3_DIRTY},
  verdict: process.env.ARCH_R3_VERDICT,
  diagnosticCode: process.env.ARCH_R3_DIAGNOSTIC || null,
  startedAt: process.env.ARCH_R3_STARTED_AT,
  endedAt: process.env.ARCH_R3_ENDED_AT,
  durationMs: Number(process.env.ARCH_R3_ENDED_MS) - Number(process.env.ARCH_R3_STARTED_MS),
  diagnosticLatencyMs: process.env.ARCH_R3_VERDICT === 'failed'
    ? Number(process.env.ARCH_R3_ENDED_MS) - Number(process.env.ARCH_R3_STARTED_MS) : null,
  environment: {os: process.env.ARCH_R3_OS, architecture: process.env.ARCH_R3_ARCH},
  tools: {go: process.env.ARCH_R3_GO, node: process.env.ARCH_R3_NODE, npm: process.env.ARCH_R3_NPM},
  cases: [{caseId: ({
    'aal2': 'ARCH-R3-R1-FRESH-AAL2',
    'auth-completion': 'ARCH-R3-R2-AUTH-COMPLETION',
    'migration-checkpoint': 'ARCH-R3-R3-CHECKPOINT',
    'webhook-outbox': 'ARCH-R3-R4-WEBHOOK-OUTBOX',
    'mam-lifecycle': 'ARCH-R3-R5-MAM-CONFORMANCE',
    'chat-reconcile': 'ARCH-R3-R6-CHAT-RECONCILE',
    'compose-state': 'ARCH-R3-R7-COMPOSE-STATE',
    'caption-pipeline': 'ARCH-R3-R8-CAPTION-HERMETIC',
  })[process.env.ARCH_R3_LANE], verdict: process.env.ARCH_R3_VERDICT}],
  artifacts: [{path: 'output.log', sha256: crypto.createHash('sha256').update(bytes).digest('hex')}]
}, null, 2) + '\n');
NODE
  mv "$manifest_tmp" "$run_tmp/manifest.json"
  mkdir -p "$RESULTS_ROOT"
  mv "$run_tmp" "$final_dir"
  pointer_tmp="$RESULTS_ROOT/.latest.json.$$"
  ARCH_R3_MANIFEST="${final_dir#$ROOT/}/manifest.json" node >"$pointer_tmp" <<'NODE'
process.stdout.write(JSON.stringify({schemaVersion: 1, manifest: process.env.ARCH_R3_MANIFEST}, null, 2) + '\n');
NODE
  mv "$pointer_tmp" "$RESULTS_ROOT/latest.json"
  PUBLISHED_MANIFEST="${final_dir#$ROOT/}/manifest.json"
}

aal2_verdict() { (cd "$ROOT/shared" && go test ./jwtutil -run 'TestVerifyFreshAAL2' -count=1); }
auth_completion_verdict() {
  local host="${PGHOST:-127.0.0.1}" port="${PGPORT:-5432}" user="${PGUSER:-mail}" db="${DB_NAME:-mailserver_test}"
  local dsn="${DB_DSN:-postgres://${user}:${PGPASSWORD:-mail}@${host}:${port}/${db}?sslmode=disable}"
  local go_json
  go_json="$(mktemp)"
  trap 'rm -f "$go_json"' RETURN
	PGPASSWORD="${PGPASSWORD:-mail}" DB_HOST="$host" DB_PORT="$port" DB_USER="$user" DB_NAME="$db" \
		bash "$ROOT/scripts/load-test-schema.sh" || return $?
  PGPASSWORD="${PGPASSWORD:-mail}" psql -X -v ON_ERROR_STOP=1 \
    -h "$host" -p "$port" -U "$user" -d "$db" \
		-c "INSERT INTO domains(name,is_local) VALUES('auth-completion.test',true) ON CONFLICT(name) DO UPDATE SET is_local=true" >/dev/null || return $?
  set +e
  (cd "$ROOT/authserver" && DB_DSN="$dsn" REQUIRE_DB=1 go test -json ./internal/handlers \
    -run 'Test(CompletionRequest|CompletionGate_|MFAPendingCompletion|CommitDeferredTokenResponse|CallerOwnedCompletion|TOTPEnrollment|FencedTOTPEnrollment|NormalizedSSOEnrollment)' \
    -count=1) | tee "$go_json"
  local go_status="${PIPESTATUS[0]}"
  set -e
  [[ "$go_status" -eq 0 ]] || return "$go_status"
  node - "$go_json" <<'NODE'
const fs = require('node:fs');
const skipped = fs.readFileSync(process.argv[2], 'utf8').trim().split('\n').filter(Boolean)
  .map(line => { try { return JSON.parse(line); } catch { return null; } })
  .filter(x => x && x.Action === 'skip' && x.Test);
if (skipped.length) {
  console.error(`E_ARCH_R3_AUTH_ORDER problem=skipped_required_test cause=db_contract_not_exercised tests=${skipped.map(x => x.Test).join(',')}`);
  process.exit(1);
}
NODE
}
migration_checkpoint_verdict() {
  local host="${PGHOST:-127.0.0.1}" port="${PGPORT:-5432}" user="${PGUSER:-mail}" db="${DB_NAME:-mailserver_test}"
	pg_isready -h "$host" -p "$port" >/dev/null || return $?
	(cd "$ROOT/mailserver" && go test ./internal/migration -run 'Test(IMAPCheckpoint|IMAPSourceSession|ProviderSourceSessions|SourceSession|ConnectorPhase|MillionObject|EWSResume)' -count=1) || return $?
  psql -X -v ON_ERROR_STOP=1 -h "$host" -p "$port" -U "$user" -d "$db" \
		-f "$ROOT/mailserver/sql/reducers/migration_checkpoint_commit.sql" >/dev/null || return $?
  pg_prove -h "$host" -p "$port" -U "$user" -d "$db" "$ROOT/mailserver/sql/tests/migration_source_identity.pg"
}
webhook_outbox_verdict() {
  local host="${PGHOST:-127.0.0.1}" port="${PGPORT:-5432}" user="${PGUSER:-mail}" db="${DB_NAME:-mailserver_test}"
  local dsn="${DB_DSN:-postgres://${user}:${PGPASSWORD:-mail}@${host}:${port}/${db}?sslmode=disable}"
	pg_isready -h "$host" -p "$port" >/dev/null || return $?
	go run ./shared/toggle/cmd/feature-registry-gen --check || return $?
  PGPASSWORD="${PGPASSWORD:-mail}" DB_HOST="$host" DB_PORT="$port" DB_USER="$user" DB_NAME="$db" \
		bash "$ROOT/scripts/load-test-schema.sh" || return $?
  PGPASSWORD="${PGPASSWORD:-mail}" pg_prove -h "$host" -p "$port" -U "$user" -d "$db" \
    "$ROOT/mailserver/sql/tests/webhook_publication_outbox.pg" \
    "$ROOT/mailserver/sql/tests/webhook_delivery_admission.pg" \
    "$ROOT/mailserver/sql/tests/webhook_persistent_events.pg" \
    "$ROOT/mailserver/sql/tests/webhook_mail_facts.pg" \
    "$ROOT/mailserver/sql/tests/mail_external_approval.pg" \
    "$ROOT/mailserver/sql/tests/scheduled_action_send.pg" \
    "$ROOT/mailserver/sql/tests/jmap_email_submission.pg" \
		"$ROOT/mailserver/sql/tests/migration_orchestrate.pg" || return $?
  DB_DSN="$dsn" REQUIRE_DB=1 go test ./mailserver/internal/smtp \
		-run 'TestSubmission(HeldIsAcceptedWithoutMailSentFact|CommitFailureLeavesNoMailSentFact|StoresRawBlob|BlobStoreFailureIsFailClosed)|TestHandleDataNoTrailingOKOnFailure' -count=1 || return $?
  DB_DSN="$dsn" REQUIRE_DB=1 go test ./mailserver/internal/jmap \
		-run 'Test(EmailSubmissionSetRoutesToWorkerCaller|ApprovalHeld_DraftPreserved)' -count=1 || return $?
  DB_DSN="$dsn" REQUIRE_DB=1 go test ./mailserver/internal/approval \
		-run 'Test(DecideRoutesMailReplayToWorkerPool|EmailPagePOSTRoutesMailReplayToWorkerPool)' -count=1 || return $?
  DB_DSN="$dsn" REQUIRE_DB=1 go test ./mailserver/internal/admin \
		-run 'Test(UsersDeleteWebhookFollowsTransactionOutcome|UsersCreateUpdateWebhookPublicationFollowsFlag|AdminWebhooksCreateAllowsExplicitOrganizationScope)' -count=1 || return $?
  DB_DSN="$dsn" REQUIRE_DB=1 go test ./mailserver/internal/user \
		-run 'TestSelfServiceWebhookScopeCannotEscalate' -count=1 || return $?
  DB_DSN="$dsn" REQUIRE_DB=1 go test ./mailserver/internal/webhook \
		-run 'Test(EnqueueDurablePersistsBeforeHTTPAndUsesStableEventID|DispatchForUserScopesLegacyUserDeletedWhileFlagOff|DeliverOne_LogsDeliveryAndRetryUpdatesSameRow|DeliveryBatchUsesFixedConcurrency|RetryTickExceedsDeliveryTimeout|DeliveryLeaseCoversHTTPAndSettlement|DurableSlowEndpointAdmissionIsBoundedAndFair|DurableCircuitOpenPersistsRetryState|DurableShutdownDrainsOnlyAlreadyAdmittedTasks)' -count=1 || return $?
  go test ./mailserver/cmd/mailserverd \
		-run 'Test(WorkerLaunchInventoryGolden|WorkerSemanticsCoversNamedLaunches)' -count=1 || return $?
  go test ./shared/toggle \
		-run 'Test(DefinitionsAreSortedUniqueAndDefensive|RegistryCoversAllConstants|RegistryMatrix)' -count=1 || return $?
}
mam_lifecycle_verdict() {
	bash "$ROOT/scripts/check-mam-lifecycle-conformance.sh" || return $?
	(cd "$ROOT/clients/desktop/electron" && npx vitest run src/mam.test.ts src/mamLifecycleOwner.test.ts src/main.test.ts) || return $?
  (cd "$ROOT" && cargo test --manifest-path clients/desktop/src-tauri/Cargo.toml mam_lifecycle)
}
chat_reconcile_verdict() {
  (cd "$ROOT/mailserver/webmail" && npx vitest run src/lib/chat/store.svelte.test.ts)
}
compose_state_verdict() {
  (cd "$ROOT/mailserver/webmail" && npx vitest run \
    src/lib/stores/composeStore.svelte.test.ts \
    src/lib/components/ComposeScreen.test.ts)
}
caption_pipeline_verdict() {
  (cd "$ROOT/asrbot" && GOWORK=off go test -race -tags nolibopusfile ./internal/bot -run 'TestTrackWorkerOwnsDecodeVADStreamDrainAndPublish' -count=1)
}

planted_tool_failure() {
  local lane="$1" tool="$2" expected_code="$3" tmp marker before after status manifest_rel manifest
  marker="ARCH_R3_PLANTED_${lane//-/_}"
  before="$(dirty_digest)"
  tmp="$(mktemp -d)"
  printf '%s\n' '#!/usr/bin/env bash' \
    'case "${1:-}" in version|--version) echo "planted tool version"; exit 0;; esac' \
    "echo '$marker' >&2" 'exit 97' >"$tmp/$tool"
  chmod +x "$tmp/$tool"
  set +e
  PATH="$tmp:$PATH" ARCH_R3_RESULTS_ROOT="$tmp/results" \
    bash "$ROOT/scripts/verify-architecture-r3.sh" "$lane" --json \
    >"$tmp/child.out" 2>"$tmp/child.err"
  status=$?
  set -e
  after="$(dirty_digest)"
  if [[ "$status" -eq 0 || ! -f "$tmp/results/latest.json" ]]; then
    diagnostic E_ARCH_R3_SELF_TEST "planted_failure_not_detected" "disposable_tool_mutant_did_not_turn_red" "$lane" "none" "restore_the_lane_self_test_contract" "bash scripts/verify-architecture-r3.sh $lane --self-test"
    rm -rf "$tmp"
    return 1
  fi
  manifest_rel="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1])).manifest)' "$tmp/results/latest.json")"
  manifest="$manifest_rel"
  [[ "$manifest" == /* ]] || manifest="$ROOT/$manifest"
  if ! ARCH_R3_MANIFEST="$manifest" ARCH_R3_CODE="$expected_code" ARCH_R3_MARKER="$marker" node <<'NODE'
const fs=require('node:fs'), path=require('node:path');
const manifest=JSON.parse(fs.readFileSync(process.env.ARCH_R3_MANIFEST));
const log=fs.readFileSync(path.join(path.dirname(process.env.ARCH_R3_MANIFEST),'output.log'),'utf8');
if(manifest.mode!=='verdict'||manifest.verdict!=='failed'||manifest.diagnosticCode!==process.env.ARCH_R3_CODE) process.exit(1);
if(!log.includes(process.env.ARCH_R3_MARKER)||!log.includes(process.env.ARCH_R3_CODE)) process.exit(1);
NODE
  then
    diagnostic E_ARCH_R3_SELF_TEST "planted_failure_manifest_invalid" "actual_lane_did_not_retain_expected_failure" "$lane" "$manifest" "restore_the_lane_diagnostic_contract" "bash scripts/verify-architecture-r3.sh $lane --self-test"
    rm -rf "$tmp"
    return 1
  fi
  if [[ "$before" != "$after" ]]; then
    diagnostic E_ARCH_R3_SELF_TEST "worktree_changed" "self_test_mutated_repository" "$lane" "$manifest" "make_the_mutant_disposable" "bash scripts/verify-architecture-r3.sh $lane --self-test"
    rm -rf "$tmp"
    return 1
  fi
  echo "$marker detected by actual $lane lane; failed manifest/code validated; worktree digest unchanged"
  rm -rf "$tmp"
}

aal2_self_test() { planted_tool_failure aal2 go E_ARCH_R3_AAL2; }
auth_completion_self_test() { planted_tool_failure auth-completion go E_ARCH_R3_AUTH_ORDER; }
migration_checkpoint_self_test() { planted_tool_failure migration-checkpoint go E_ARCH_R3_CHECKPOINT_AHEAD; }
webhook_outbox_self_test() { planted_tool_failure webhook-outbox go E_ARCH_R3_WEBHOOK_AUDIENCE; }
mam_lifecycle_self_test() { planted_tool_failure mam-lifecycle npx E_ARCH_R3_MAM_PARITY; }
chat_reconcile_self_test() { planted_tool_failure chat-reconcile npx E_ARCH_R3_CHAT_STALE; }
compose_state_self_test() { planted_tool_failure compose-state npx E_ARCH_R3_COMPOSE_STALE; }
caption_pipeline_self_test() { planted_tool_failure caption-pipeline go E_ARCH_R3_CAPTION_DRAIN; }

run_with_evidence() {
  local lane="$1" mode="$2" fn="$3" code="$4" started ended status verdict tmp log started_at artifact diagnostic_code=""
  mkdir -p "$RESULTS_ROOT"
  tmp="$(mktemp -d "$RESULTS_ROOT/.run.XXXXXX")"
  log="$tmp/output.log"
  artifact="$RESULTS_ROOT/latest.json"
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  started="$(node -e 'process.stdout.write(String(Date.now()))')"
  set +e
  if [[ "$VERBOSE" -eq 1 ]]; then
    if [[ "$OUTPUT_JSON" -eq 1 ]]; then
      (cd "$ROOT" && set -e; "$fn") > >(tee "$log" >&2) 2> >(tee -a "$log" >&2)
    else
      (cd "$ROOT" && set -e; "$fn") > >(tee "$log") 2> >(tee -a "$log" >&2)
    fi
    status=$?
  else
    (cd "$ROOT" && set -e; "$fn") >"$log" 2>&1
    status=$?
  fi
  set -e
  ended="$(node -e 'process.stdout.write(String(Date.now()))')"
  if [[ "$status" -eq 0 ]]; then
    verdict=pass
  else
    verdict=failed
    diagnostic_code="$code"
    diagnostic "$code" "focused_lane_failed" "existing_verification_command_failed" "$lane" "$artifact" "inspect_output_and_fix_the_named_invariant" "bash scripts/verify-architecture-r3.sh $lane" 2>&1 | tee -a "$log" >&2
  fi
  publish_manifest "$lane" "$mode" "$verdict" "$started" "$ended" "$started_at" "$tmp" "$log" "$diagnostic_code"
  if [[ "$OUTPUT_JSON" -eq 1 ]]; then
    ARCH_R3_MANIFEST="$PUBLISHED_MANIFEST" ARCH_R3_LANE="$lane" ARCH_R3_MODE="$mode" \
      ARCH_R3_VERDICT="$verdict" node <<'NODE'
process.stdout.write(JSON.stringify({
  schemaVersion: 1,
  lane: process.env.ARCH_R3_LANE,
  mode: process.env.ARCH_R3_MODE,
  verdict: process.env.ARCH_R3_VERDICT,
  manifest: process.env.ARCH_R3_MANIFEST,
}) + '\n');
NODE
  else
    echo "architecture-r3 $lane $mode $verdict; evidence $PUBLISHED_MANIFEST"
  fi
  return "$status"
}

run_lane() {
  local lane="$1" mode="${2:-verdict}" missing fn code
  missing="$(missing_tools "$lane")"
  if [[ -n "$missing" ]]; then
    diagnostic E_ARCH_R3_PREREQUISITE "missing_prerequisite" "required_tool_not_found" "$missing" "none" "install_the_named_tool" "bash scripts/verify-architecture-r3.sh --doctor"
    return 1
  fi
  if [[ "$lane" =~ ^(auth-completion|migration-checkpoint|webhook-outbox)$ ]] && ! pg_isready -h "${PGHOST:-127.0.0.1}" -p "${PGPORT:-5432}" >/dev/null 2>&1; then
    diagnostic E_ARCH_R3_PREREQUISITE "missing_prerequisite" "postgres_not_ready" "${PGHOST:-127.0.0.1}:${PGPORT:-5432}" "none" "start_the_local_test_database" "bash scripts/verify-architecture-r3.sh --doctor"
    return 1
  fi
  if [[ "$lane" == caption-pipeline ]] && ! pkg-config --exists opus; then
    diagnostic E_ARCH_R3_PREREQUISITE "missing_prerequisite" "libopus_not_found" "pkg-config:opus" "none" "install_libopus_development_files" "bash scripts/verify-architecture-r3.sh --doctor"
    return 1
  fi
  case "$lane:$mode" in
    aal2:verdict) fn=aal2_verdict; code=E_ARCH_R3_AAL2 ;;
    auth-completion:verdict) fn=auth_completion_verdict; code=E_ARCH_R3_AUTH_ORDER ;;
    migration-checkpoint:verdict) fn=migration_checkpoint_verdict; code=E_ARCH_R3_CHECKPOINT_AHEAD ;;
    webhook-outbox:verdict) fn=webhook_outbox_verdict; code=E_ARCH_R3_WEBHOOK_AUDIENCE ;;
    mam-lifecycle:verdict) fn=mam_lifecycle_verdict; code=E_ARCH_R3_MAM_PARITY ;;
    chat-reconcile:verdict) fn=chat_reconcile_verdict; code=E_ARCH_R3_CHAT_STALE ;;
    compose-state:verdict) fn=compose_state_verdict; code=E_ARCH_R3_COMPOSE_STALE ;;
    caption-pipeline:verdict) fn=caption_pipeline_verdict; code=E_ARCH_R3_CAPTION_DRAIN ;;
    aal2:self-test) fn=aal2_self_test; code=E_ARCH_R3_AAL2 ;;
    auth-completion:self-test) fn=auth_completion_self_test; code=E_ARCH_R3_AUTH_ORDER ;;
    migration-checkpoint:self-test) fn=migration_checkpoint_self_test; code=E_ARCH_R3_CHECKPOINT_AHEAD ;;
    webhook-outbox:self-test) fn=webhook_outbox_self_test; code=E_ARCH_R3_WEBHOOK_AUDIENCE ;;
    mam-lifecycle:self-test) fn=mam_lifecycle_self_test; code=E_ARCH_R3_MAM_PARITY ;;
    chat-reconcile:self-test) fn=chat_reconcile_self_test; code=E_ARCH_R3_CHAT_STALE ;;
    compose-state:self-test) fn=compose_state_self_test; code=E_ARCH_R3_COMPOSE_STALE ;;
    caption-pipeline:self-test) fn=caption_pipeline_self_test; code=E_ARCH_R3_CAPTION_DRAIN ;;
    *) return 2 ;;
  esac
  run_with_evidence "$lane" "$mode" "$fn" "$code"
}

run_quick() {
  local lane failed=()
  for lane in "${LANES[@]}"; do
    if ! run_lane "$lane" verdict; then failed+=("$lane"); fi
  done
  if [[ ${#failed[@]} -gt 0 ]]; then
    diagnostic E_ARCH_R3_QUICK "quick_failed" "one_or_more_focused_lanes_failed" "${failed[*]}" "$RESULTS_ROOT" "fix_each_named_lane" "bash scripts/verify-architecture-r3.sh quick"
    return 1
  fi
  echo "architecture-r3 quick PASS"
}

check_release_group() {
  local group="$1" code="$2" log status
  log="$(mktemp)"
  set +e
  node "$CHECKER" "$REGISTRY" --release-group "$group" "$RELEASE_ROOT" >"$log" 2>&1
  status=$?
  set -e
  if [[ "$status" -ne 0 ]]; then
    diagnostic "$code" "missing_or_invalid_release_evidence" "required_receipt_not_source_bound_and_passing" "$RELEASE_ROOT/$group" "$RELEASE_ROOT" "produce_the_named_real_environment_receipts" "bash scripts/verify-architecture-r3.sh $group"
    sed -n '1,20p' "$log" >&2
    rm -f "$log"
    return 1
  fi
  cat "$log"
  rm -f "$log"
}

compatibility_verdict() { check_release_group compatibility E_ARCH_R3_COMPATIBILITY_MISSING; }
devices_verdict() { check_release_group devices E_ARCH_R3_DEVICES_MISSING; }
live_media_verdict() { check_release_group live-media E_ARCH_R3_LIVE_MEDIA_MISSING; }

aggregate_and_check() {
  local gate="$1" result
  if [[ "$gate" == release ]]; then
    result="$(node "$AGGREGATOR" --gate release --release-root "$RELEASE_ROOT")" || return
  else
    result="$(node "$AGGREGATOR" --gate merge)" || return
  fi
  node "$CHECKER" "$REGISTRY" "$result" --gate "$gate"
  echo "architecture-r3 evidence result: ${result#$ROOT/}"
}

run_core() {
  run_quick
  aggregate_and_check merge
  echo "architecture-r3 core PASS"
}

run_full() {
  run_core
  compatibility_verdict
  devices_verdict
  live_media_verdict
  aggregate_and_check release
  echo "architecture-r3 full PASS"
}

evidence_query() {
  local run_id="${1:-}" candidate gate
  if [[ -z "$run_id" ]]; then
    aggregate_and_check merge
    return
  fi
  if [[ ! "$run_id" =~ ^[A-Za-z0-9._-]+$ ]]; then
    diagnostic E_ARCH_R3_EVIDENCE "invalid_run_id" "unsafe_path_component" "$run_id" "none" "copy_the_exact_run_directory_name" "bash scripts/verify-architecture-r3.sh evidence --run-id <id>"
    return 2
  fi
  candidate="$AGGREGATE_ROOT/$run_id/result.json"
  if [[ -f "$candidate" ]]; then
    gate="$(node -e 'const r=JSON.parse(require("fs").readFileSync(process.argv[1])); process.stdout.write(r.cases.some(x=>x.case_id==="ARCH-R3-R8-LIVE-MEDIA")?"release":"merge")' "$candidate")"
    node "$CHECKER" "$REGISTRY" "$candidate" --gate "$gate"
    echo "architecture-r3 evidence result: ${candidate#$ROOT/}"
    return
  fi
  candidate="$RESULTS_ROOT/$run_id/manifest.json"
  if [[ -f "$candidate" ]]; then
    node "$CHECKER" "$REGISTRY" --lane-manifest "$candidate"
    echo "architecture-r3 lane manifest: ${candidate#$ROOT/}"
    return
  fi
  diagnostic E_ARCH_R3_EVIDENCE_MISSING "missing_run" "run_id_not_found" "$run_id" "$RESULTS_ROOT" "list_test-results_architecture-r3_or_run_a_lane" "bash scripts/verify-architecture-r3.sh evidence"
  return 1
}

fingerprint_json() {
  ARCH_R3_COMMIT="$(git -C "$ROOT" rev-parse HEAD)" ARCH_R3_DIRTY="$(dirty_digest)" \
    ARCH_R3_OS="$(uname -s)" ARCH_R3_ARCH="$(uname -m)" \
    ARCH_R3_GO="$(version_line go)" ARCH_R3_NODE="$(version_line node)" \
    ARCH_R3_NPM="$(version_line npm)" node <<'NODE'
const crypto = require('node:crypto');
const value = {commit: process.env.ARCH_R3_COMMIT, dirtyDigest: process.env.ARCH_R3_DIRTY,
  os: process.env.ARCH_R3_OS, architecture: process.env.ARCH_R3_ARCH,
  tools: {go: process.env.ARCH_R3_GO, node: process.env.ARCH_R3_NODE, npm: process.env.ARCH_R3_NPM}};
value.populationKey = crypto.createHash('sha256').update(JSON.stringify(value)).digest('hex');
process.stdout.write(JSON.stringify(value));
NODE
}

benchmark_quick() {
  local samples=20 warmups=2 sample warmup started ended status ordinal initial_fp current_fp
  local dx_root tmp final pointer result verdict
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --samples) [[ $# -ge 2 ]] || { usage >&2; return 2; }; samples="$2"; shift 2 ;;
      --warmup) [[ $# -ge 2 ]] || { usage >&2; return 2; }; warmups="$2"; shift 2 ;;
      *) usage >&2; return 2 ;;
    esac
  done
  [[ "$samples" =~ ^[1-9][0-9]*$ ]] || { diagnostic E_ARCH_R3_BENCHMARK "invalid_samples" "expected_positive_integer" "$samples" "none" "choose_a_positive_sample_count" "bash scripts/verify-architecture-r3.sh benchmark"; return 2; }
  [[ "$warmups" =~ ^[0-9]+$ ]] || { diagnostic E_ARCH_R3_BENCHMARK "invalid_warmups" "expected_nonnegative_integer" "$warmups" "none" "choose_a_nonnegative_warmup_count" "bash scripts/verify-architecture-r3.sh benchmark"; return 2; }
  dx_root="$RESULTS_ROOT/dx"
  mkdir -p "$dx_root"
  tmp="$(mktemp -d "$dx_root/.run.XXXXXX")"
  initial_fp="$(fingerprint_json)"
  printf '%s\n' "$initial_fp" >"$tmp/fingerprint.json"
  for ((warmup=1; warmup<=warmups; warmup++)); do
    echo "architecture-r3 benchmark warmup $warmup/$warmups"
    if ! run_quick >"$tmp/warmup-$(printf '%03d' "$warmup").log" 2>&1; then
      diagnostic E_ARCH_R3_BENCHMARK "warmup_failed" "quick_lane_failed" "$warmup" "$tmp" "inspect_the_warmup_log" "bash scripts/verify-architecture-r3.sh benchmark"
      return 1
    fi
    current_fp="$(fingerprint_json)"
    [[ "$current_fp" == "$initial_fp" ]] || { diagnostic E_ARCH_R3_BENCHMARK "fingerprint_changed" "working_tree_or_toolchain_changed_during_population" "warmup-$warmup" "$tmp/fingerprint.json" "stop_concurrent_edits_and_restart" "bash scripts/verify-architecture-r3.sh benchmark"; return 1; }
  done
  mkdir -p "$tmp/samples"
  for ((sample=1; sample<=samples; sample++)); do
    ordinal="$(printf '%03d' "$sample")"
    echo "architecture-r3 benchmark sample $sample/$samples"
    started="$(node -e 'process.stdout.write(String(Date.now()))')"
    set +e
    run_quick >"$tmp/samples/$ordinal.log" 2>&1
    status=$?
    set -e
    ended="$(node -e 'process.stdout.write(String(Date.now()))')"
    current_fp="$(fingerprint_json)"
    if [[ "$current_fp" != "$initial_fp" ]]; then
      diagnostic E_ARCH_R3_BENCHMARK "fingerprint_changed" "working_tree_or_toolchain_changed_during_population" "sample-$sample" "$tmp/fingerprint.json" "stop_concurrent_edits_and_restart" "bash scripts/verify-architecture-r3.sh benchmark"
      return 1
    fi
    ARCH_R3_ORDINAL="$sample" ARCH_R3_DURATION="$((ended-started))" ARCH_R3_STATUS="$status" \
      ARCH_R3_POPULATION="$(node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(process.argv[1])).populationKey)' "$tmp/fingerprint.json")" \
      node >"$tmp/samples/$ordinal.json" <<'NODE'
process.stdout.write(JSON.stringify({schemaVersion:1, ordinal:Number(process.env.ARCH_R3_ORDINAL),
  durationMs:Number(process.env.ARCH_R3_DURATION), verdict:process.env.ARCH_R3_STATUS==='0'?'pass':'failed',
  populationKey:process.env.ARCH_R3_POPULATION}, null, 2)+'\n');
NODE
  done
  ARCH_R3_SAMPLES="$samples" ARCH_R3_WARMUPS="$warmups" node - "$tmp" <<'NODE'
const fs=require('node:fs'), path=require('node:path'), crypto=require('node:crypto');
const root=process.argv[2], fingerprint=JSON.parse(fs.readFileSync(path.join(root,'fingerprint.json')));
const files=fs.readdirSync(path.join(root,'samples')).filter(x=>x.endsWith('.json')).sort();
const rows=files.map(x=>JSON.parse(fs.readFileSync(path.join(root,'samples',x))));
const durations=rows.map(x=>x.durationMs).sort((a,b)=>a-b), expected=Number(process.env.ARCH_R3_SAMPLES);
const p95=durations[Math.ceil(0.95*durations.length)-1];
const complete=rows.length===expected && rows.every(x=>x.verdict==='pass'&&x.populationKey===fingerprint.populationKey);
const qualification=expected===20&&Number(process.env.ARCH_R3_WARMUPS)===2?'scheduled_p95':'diagnostic';
const verdict=complete&&p95<=300000?'pass':'failed';
const result={schemaVersion:1, verdict, qualification, expectedSamples:expected, recordedSamples:rows.length,
  warmupCount:Number(process.env.ARCH_R3_WARMUPS), fingerprint, formula:{name:'nearest-rank',p95Index:Math.ceil(0.95*durations.length)},
  metrics:{p95DurationMs:p95,maxDurationMs:Math.max(...durations)}, samples:rows,
  artifacts:files.flatMap((x)=>{
    const log=x.replace(/\.json$/,'.log');
    return [x,log].map(name=>({path:`samples/${name}`,sha256:crypto.createHash('sha256').update(fs.readFileSync(path.join(root,'samples',name))).digest('hex')}));
  })};
fs.writeFileSync(path.join(root,'aggregate.json.tmp'),JSON.stringify(result,null,2)+'\n');
fs.renameSync(path.join(root,'aggregate.json.tmp'),path.join(root,'aggregate.json'));
if(verdict!=='pass') process.exitCode=1;
NODE
  status=$?
  final="$dx_root/$(date -u +%Y%m%dT%H%M%SZ)-$(git -C "$ROOT" rev-parse --short=8 HEAD)-$$"
  mv "$tmp" "$final"
  if [[ "$status" -ne 0 ]]; then
    diagnostic E_ARCH_R3_BENCHMARK "p95_gate_failed" "incomplete_failed_or_over_300_seconds" "$final/aggregate.json" "$final" "inspect_samples_and_remove_the_regression" "bash scripts/verify-architecture-r3.sh benchmark"
    return 1
  fi
  pointer="$dx_root/.latest.json.$$"
  ARCH_R3_AGGREGATE="${final#$ROOT/}/aggregate.json" node >"$pointer" <<'NODE'
process.stdout.write(JSON.stringify({schemaVersion:1,aggregate:process.env.ARCH_R3_AGGREGATE},null,2)+'\n');
NODE
  mv "$pointer" "$dx_root/latest.json"
  result="$final/aggregate.json"
  node "$CHECKER" "$REGISTRY" --benchmark "$result"
  verdict="$(node -e 'const x=JSON.parse(require("fs").readFileSync(process.argv[1])); process.stdout.write(`${x.verdict} p95=${x.metrics.p95DurationMs}ms samples=${x.recordedSamples}`)' "$result")"
  echo "architecture-r3 benchmark $verdict; evidence ${result#$ROOT/}"
}

case "${1:-quick}" in
  --help) [[ $# -eq 1 ]] || { usage >&2; exit 2; }; usage ;;
  --doctor) [[ $# -eq 1 ]] || { usage >&2; exit 2; }; doctor ;;
  quick) [[ $# -le 1 ]] || { usage >&2; exit 2; }; run_quick ;;
  aal2|auth-completion|migration-checkpoint|webhook-outbox|mam-lifecycle|chat-reconcile|compose-state|caption-pipeline)
    lane="$1"
    shift
    mode=verdict
    while [[ $# -gt 0 ]]; do
      case "$1" in
        --self-test) [[ "$mode" == verdict ]] || { usage >&2; exit 2; }; mode=self-test ;;
        --json) [[ "$OUTPUT_JSON" -eq 0 ]] || { usage >&2; exit 2; }; OUTPUT_JSON=1 ;;
        --verbose) [[ "$VERBOSE" -eq 0 ]] || { usage >&2; exit 2; }; VERBOSE=1 ;;
        *) usage_error "unknown_lane_option" "$1"; exit 2 ;;
      esac
      shift
    done
    run_lane "$lane" "$mode"
    ;;
  compatibility) [[ $# -eq 1 ]] || { usage >&2; exit 2; }; compatibility_verdict ;;
  devices) [[ $# -eq 1 ]] || { usage >&2; exit 2; }; devices_verdict ;;
  live-media) [[ $# -eq 1 ]] || { usage >&2; exit 2; }; live_media_verdict ;;
  core) [[ $# -eq 1 ]] || { usage >&2; exit 2; }; run_core ;;
  full) [[ $# -eq 1 ]] || { usage >&2; exit 2; }; run_full ;;
  evidence)
    case "$#" in
      1) evidence_query ;;
      3) [[ "$2" == --run-id ]] || { usage >&2; exit 2; }; evidence_query "$3" ;;
      *) usage >&2; exit 2 ;;
    esac ;;
  benchmark) shift; benchmark_quick "$@" ;;
  *) usage_error "unknown_command" "${1:-}"; exit 2 ;;
esac
