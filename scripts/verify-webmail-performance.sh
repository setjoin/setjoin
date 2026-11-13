#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEBMAIL="$ROOT/mailserver/webmail"
MODE="${1:-quick}"
shift || true
SELF_TEST=0
SAMPLES=""
WARMUP=""
PRIOR_ARTIFACT=""
DRY_RUN=0

while [ "$#" -gt 0 ]; do
  case "$1" in
    --self-test) SELF_TEST=1; shift ;;
    --samples) SAMPLES="${2:?--samples needs a positive integer}"; shift 2 ;;
    --warmup) WARMUP="${2:?--warmup needs a non-negative integer}"; shift 2 ;;
    --prior-artifact) PRIOR_ARTIFACT="${2:?--prior-artifact needs a retained artifact directory}"; shift 2 ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help) MODE=help; shift ;;
    *) echo "verify-webmail-performance: unknown argument: $1" >&2; exit 2 ;;
  esac
done

usage() {
  cat <<'EOF'
Usage: bash scripts/verify-webmail-performance.sh [MODE] [options]

Modes:
  quick        Production build plus deterministic ledger/font/locale/worker/responder gates (default, target <=5 minutes)
  ledger       Build-bound asset, encoding, critical-shell, and byte-budget gate
  fonts        Physical CJK shard and system-first CSS contract
  locale       Active-catalog bootstrap, atomic switching, and push-dictionary parity
  responder    Production Go static responder HTTP contract
  worker       Cache classifier and current/previous/candidate generation contract
  diagnostic   One real Go-gateway browser sample per public/Inbox scenario
  ci           Five samples after one warmup through the same Go/browser seam
  release      Twenty samples after two warmups; intended for a supported release host
  rehearsal    Update/recovery rehearsal from the actual retained prior signed
               artifact: prior generation acknowledged, gateway flipped to the
               candidate, prior generation proven recoverable. Writes only its
               own rehearsal-receipt.v1.json (kind: rehearsal); it never
               advances latest.json and is never passable as a timing run.
  hosts        Read-only host eligibility listing for the browser lanes
  --doctor     Read-only prerequisite report
  --help       This text; writes nothing

Options:
  --samples N          Override the browser sample count for diagnostic/ci/release
  --warmup N           Override the discarded warmup count
  --prior-artifact DIR Retained prior artifact bundle for rehearsal:
                       asset-ledger.v1.json plus a web/ copy of the prior web
                       root. Rejected by the timing modes.
  --dry-run            Print the resolved plan (mode, kind, samples, host
                       eligibility, run layout) and exit 0 without building,
                       serving, or browsing. Writes nothing.
  --self-test          Run only the planted-failure/deterministic test for a
                       focused lane

Environment:
  PERF_REUSE_VERIFIED_BUILD=1
               Resume a failed browser attempt from an already-built artifact;
               the build-bound ledger is revalidated before services start.

Artifacts:
  mailserver/webmail/test-results/webmail-performance/runs/<UTC>-<commit>-<build-id>/
    timing receipt run.json (kind: timing) plus performance-summary.v1.json
  mailserver/webmail/test-results/webmail-performance/runs/<UTC>-<commit>-<build-id>-rehearsal/
    rehearsal receipt rehearsal-receipt.v1.json (kind: rehearsal); flip
    markers under flip-control/; never touches latest.json
  mailserver/webmail/test-results/webmail-performance/latest.json (advanced only by a passing timing run)
EOF
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "E_WEBMAIL_PERF_INPUTS_ABSENT problem=tool_missing cause=command_not_found value=$1 artifact=toolchain fix='install the named prerequisite' rerun='bash scripts/verify-webmail-performance.sh --doctor'" >&2
    exit 1
  }
}

positive_integer() { case "$1" in ''|*[!0-9]*|0) return 1 ;; *) return 0 ;; esac; }
nonnegative_integer() { case "$1" in ''|*[!0-9]*) return 1 ;; *) return 0 ;; esac; }

pick_free_port() {
  local base="$1" candidate offset
  offset=$(( $$ % 500 ))
  for _ in $(seq 0 499); do
    candidate=$(( base + offset ))
    if ! lsof -tiTCP:"$candidate" -sTCP:LISTEN >/dev/null 2>&1; then
      echo "$candidate"
      return 0
    fi
    offset=$(( (offset + 1) % 500 ))
  done
  echo "E_WEBMAIL_PERF_RUNTIME_FAILURE problem=no_free_loopback_port cause=range_exhausted value=$base artifact=runtime fix='stop stale local test services' rerun='bash scripts/verify-webmail-performance.sh $MODE'" >&2
  return 1
}

doctor() {
  local failed=0 command
  for command in node npm go python3 psql pg_isready curl weed; do
    if command -v "$command" >/dev/null 2>&1; then
      printf 'PASS %-14s %s\n' "$command" "$(command -v "$command")"
    else
      printf 'MISSING %-11s install before the matching lane\n' "$command"
      failed=1
    fi
  done
  if bash "$ROOT/scripts/playwright-supported.sh" --check >/dev/null 2>&1; then
    echo 'PASS browser-host   supported Playwright runtime'
  else
    echo 'UNSUPPORTED browser-host   configure a supported host or loopback browser endpoint'
    failed=1
  fi
  [ -f "$WEBMAIL/assets/fonts/source/noto-sans-sc-400.woff2" ] && echo 'PASS font-source    pinned Noto sources present' || { echo 'MISSING font-source'; failed=1; }
  [ -f "$WEBMAIL/e2e/fixtures/seed.sql" ] && echo 'PASS mailbox-corpus fixed E2E seed present' || { echo 'MISSING mailbox-corpus'; failed=1; }
  return "$failed"
}

run_vitest() {
  (cd "$WEBMAIL" && npx vitest run "$@")
}

host_supported_check() {
  bash "$ROOT/scripts/playwright-supported.sh" --check >/dev/null 2>&1
}

host_class() {
  printf '%s-%s' "$(uname -s)" "$(uname -m)"
}

policy_violation() {
  echo "E_WEBMAIL_PERF_POLICY_VIOLATION problem=$1 cause=$2 value=$3 artifact=$4 fix=$5 rerun=$6" >&2
  exit 2
}

print_host_eligibility() {
  # Reuses scripts/playwright-supported.sh --check, the same supported-host
  # seam the browser lanes themselves route through.
  local runtime_line supported=0
  if runtime_line="$(bash "$ROOT/scripts/playwright-supported.sh" --check 2>&1)"; then
    supported=1
  fi
  printf 'host-class       %s\n' "$(host_class)"
  if [ "$supported" -eq 1 ]; then
    printf 'browser-host     supported\n'
    printf '%s\n' "$runtime_line" | sed 's/^/  /'
  else
    printf 'browser-host     UNSUPPORTED\n'
    printf '%s\n' "$runtime_line" | grep -v '^[[:space:]]' | grep -v '^node:internal' | grep -v '^Error: ' | sed '/^$/d' | head -3 | sed 's/^/  /'
    printf 'fix              run on macOS, Windows, Ubuntu 22.04/24.04, or configure PLAYWRIGHT_CONNECT_WS_ENDPOINT\n'
  fi
  printf 'diagnostic/ci    %s\n' "$([ "$supported" -eq 1 ] && echo eligible || echo 'not eligible: browser-host unsupported')"
  printf 'release (20)     %s\n' "$([ "$supported" -eq 1 ] && echo 'eligible: supported host; set PERF_REQUIRE_SYSTEM_CJK_ZERO=1 where the system CJK stack is part of the supported matrix' || echo 'not eligible: the 20-sample population requires a supported host')"
  printf 'rehearsal        %s\n' "$([ "$supported" -eq 1 ] && echo 'eligible host; requires --prior-artifact (the actual retained prior signed artifact)' || echo 'not eligible: browser-host unsupported')"
  return "$(( 1 - supported ))"
}

run_receipts_self_test() {
  (cd "$WEBMAIL" && node scripts/performance-receipts.mjs self-test)
}

browser_dry_run() {
  require_command node
  require_command npm
  require_command go
  require_command psql
  require_command pg_isready
  require_command curl
  require_command weed
  positive_integer "$SAMPLES" || { echo 'verify-webmail-performance: --samples must be a positive integer' >&2; exit 2; }
  nonnegative_integer "$WARMUP" || { echo 'verify-webmail-performance: --warmup must be a non-negative integer' >&2; exit 2; }
  echo "WEBMAIL PERF $MODE dry-run kind=timing samples=$SAMPLES warmup=$WARMUP planned_page_loads=$(( (SAMPLES + WARMUP) * 2 )) receipt=run.json"
  echo "run layout       mailserver/webmail/test-results/webmail-performance/runs/<UTC>-$(git -C "$ROOT" rev-parse --short=12 HEAD)-<build-id>/"
  print_host_eligibility
  run_receipts_self_test
  echo "WEBMAIL PERF $MODE DRY-RUN PASS: command surface validated; no build, no stack, no browser, no writes"
}

rehearsal_dry_run() {
  require_command node
  require_command npm
  require_command go
  require_command psql
  require_command pg_isready
  require_command curl
  require_command weed
  if [ -n "$SAMPLES" ] || [ -n "$WARMUP" ]; then
    policy_violation \
      'rehearsal_rejects_sample_counts' \
      'the_rehearsal_is_not_a_timing_population' \
      "${SAMPLES:-}${WARMUP:+/$WARMUP}" \
      '--samples/--warmup' \
      'run diagnostic/ci/release for the timing population' \
      "rerun='bash scripts/verify-webmail-performance.sh rehearsal'"
  fi
  if [ -n "$PRIOR_ARTIFACT" ]; then
    (cd "$WEBMAIL" && node scripts/performance-receipts.mjs validate-prior-artifact --artifact "$PRIOR_ARTIFACT") || exit 1
  else
    echo 'prior-artifact   not set: the real rehearsal lane refuses to start without --prior-artifact' >&2
  fi
  echo "WEBMAIL PERF rehearsal dry-run kind=rehearsal receipt=rehearsal-receipt.v1.json latest_json=untouched"
  echo "run layout       mailserver/webmail/test-results/webmail-performance/runs/<UTC>-$(git -C "$ROOT" rev-parse --short=12 HEAD)-<build-id>-rehearsal/"
  print_host_eligibility
  run_receipts_self_test
  echo 'WEBMAIL PERF rehearsal DRY-RUN PASS: command surface validated; no build, no stack, no browser, no writes'
}

run_rehearsal_self_test() {
  run_receipts_self_test
  # Bash-side guards: each refusal must fire before any build or service work.
  local script="$ROOT/scripts/verify-webmail-performance.sh" output rc
  output="$(bash "$script" rehearsal --samples 2 2>&1)" && rc=0 || rc=$?
  [ "$rc" -eq 2 ] || { echo "rehearsal self-test: --samples was not rejected (exit $rc)" >&2; exit 1; }
  grep -q 'E_WEBMAIL_PERF_POLICY_VIOLATION problem=rehearsal_rejects_sample_counts' <<<"$output" || {
    echo 'rehearsal self-test: --samples rejection lacks the policy grammar' >&2
    exit 1
  }
  output="$(bash "$script" diagnostic --prior-artifact /tmp 2>&1)" && rc=0 || rc=$?
  [ "$rc" -eq 2 ] || { echo "rehearsal self-test: timing --prior-artifact was not rejected (exit $rc)" >&2; exit 1; }
  grep -q 'E_WEBMAIL_PERF_POLICY_VIOLATION problem=prior_artifact_is_rehearsal_only' <<<"$output" || {
    echo 'rehearsal self-test: timing --prior-artifact rejection lacks the policy grammar' >&2
    exit 1
  }
  output="$(bash "$script" rehearsal 2>&1)" && rc=0 || rc=$?
  [ "$rc" -eq 1 ] || { echo "rehearsal self-test: missing --prior-artifact was not refused (exit $rc)" >&2; exit 1; }
  grep -q 'E_WEBMAIL_PERF_INPUTS_ABSENT problem=retained_prior_artifact_required' <<<"$output" || {
    echo 'rehearsal self-test: missing --prior-artifact lacks the inputs grammar' >&2
    exit 1
  }
  echo 'WEBMAIL PERFORMANCE rehearsal SELF-TEST PASS: receipt guards, sample-count refusal, and timing/rehearsal separation verified without a browser'
}

run_lane_self_test() {
  case "$MODE" in
    quick|ledger) (cd "$WEBMAIL" && npm run test:performance) ;;
    fonts) run_vitest src/lib/theme/font-shards.test.ts src/lib/theme/tokens.test.ts ;;
    locale) run_vitest src/lib/i18n/index.test.ts src/lib/i18n/push-dictionary.test.ts ;;
    responder) (cd "$ROOT/mailserver" && go test ./cmd/mailserverd -run 'TestSPAStaticHandler' -count=1) ;;
    worker) run_vitest src/lib/native/sw-strategy.test.ts src/lib/native/sw-generation.test.ts src/lib/native/sw-coordinator.test.ts ;;
    diagnostic|ci|release) echo "E_WEBMAIL_PERF_POLICY_VIOLATION problem=browser_self_test_not_static cause=use_the_worker_or_ledger_planted_failure value=$MODE artifact=verification fix='run a focused deterministic self-test' rerun='bash scripts/verify-webmail-performance.sh worker --self-test'" >&2; exit 2 ;;
    *) echo "verify-webmail-performance: --self-test is not valid for $MODE" >&2; exit 2 ;;
  esac
}

build_and_ledger() {
  (cd "$WEBMAIL" && npm run build)
  (cd "$WEBMAIL" && npm run test:performance)
  bash "$ROOT/scripts/check-webmail-performance.sh" --require
}

focused_lane() {
  case "$MODE" in
    ledger) build_and_ledger ;;
    fonts) run_lane_self_test ;;
    locale) run_lane_self_test ;;
    responder) run_lane_self_test ;;
    worker) run_lane_self_test ;;
  esac
}

quick() {
  require_command node
  require_command npm
  require_command go
  if [ "${PERF_REUSE_VERIFIED_BUILD:-0}" = "1" ]; then
    bash "$ROOT/scripts/check-webmail-performance.sh" --require
  else
    build_and_ledger
  fi
  run_vitest \
    src/lib/theme/font-shards.test.ts \
    src/lib/theme/tokens.test.ts \
    src/lib/i18n/index.test.ts \
    src/lib/i18n/push-dictionary.test.ts \
    src/lib/performance/marks.test.ts \
    src/lib/native/sw-strategy.test.ts \
    src/lib/native/sw-generation.test.ts \
    src/lib/native/sw-coordinator.test.ts
  (cd "$ROOT/mailserver" && go test ./cmd/mailserverd -run 'TestSPAStaticHandler|TestSPAFallback' -count=1)
}

browser_lane() {
  if [ -n "$PRIOR_ARTIFACT" ]; then
    policy_violation \
      'prior_artifact_is_rehearsal_only' \
      'timing_modes_never_consume_a_prior_artifact_bundle' \
      "$PRIOR_ARTIFACT" \
      '--prior-artifact' \
      'use the rehearsal mode for the retained-prior-artifact update path' \
      "rerun='bash scripts/verify-webmail-performance.sh rehearsal --help'"
  fi
  require_command node
  require_command npm
  require_command go
  require_command psql
  require_command pg_isready
  require_command curl
  require_command weed
  positive_integer "$SAMPLES" || { echo 'verify-webmail-performance: --samples must be a positive integer' >&2; exit 2; }
  nonnegative_integer "$WARMUP" || { echo 'verify-webmail-performance: --warmup must be a non-negative integer' >&2; exit 2; }
  local started_at host_supported
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  host_supported=0
  host_supported_check && host_supported=1
  echo "WEBMAIL PERF $MODE plan kind=timing samples=$SAMPLES warmup=$WARMUP planned_page_loads=$(( (SAMPLES + WARMUP) * 2 )) receipt=run.json host_class=$(host_class) host_supported=$host_supported"

  if [ "${PERF_REUSE_VERIFIED_BUILD:-0}" = "1" ]; then
    bash "$ROOT/scripts/check-webmail-performance.sh" --require
  else
    build_and_ledger
  fi

  local timestamp commit build_id run_id run_dir db_name gateway_port auth_port s3_port smtp_port submission_port imap_port stack_pid
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  commit="$(git -C "$ROOT" rev-parse --short=12 HEAD)"
  build_id="$(node -e 'process.stdout.write(JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8")).version)' "$WEBMAIL/build/_app/version.json")"
  run_id="${timestamp}-${commit}-${build_id}"
  run_dir="$WEBMAIL/test-results/webmail-performance/runs/$run_id"
  db_name="setjoin_perf_${timestamp//[^0-9]/}_$$_e2e"
  mkdir -p "$run_dir"
  gateway_port="${PERF_GATEWAY_PORT:-$(pick_free_port 28000)}"
  auth_port="${PERF_AUTH_PORT:-$(pick_free_port 29000)}"
  s3_port="${PERF_S3_PORT:-$(pick_free_port 30000)}"
  smtp_port="${PERF_SMTP_PORT:-$(pick_free_port 31000)}"
  submission_port="${PERF_SUBMISSION_PORT:-$(pick_free_port 32000)}"
  imap_port="${PERF_IMAP_PORT:-$(pick_free_port 33000)}"

  E2E_SKIP_WEBMAIL_BUILD=1 \
  E2E_DB_NAME="$db_name" \
  E2E_GATEWAY_PORT="$gateway_port" E2E_AUTH_PORT="$auth_port" E2E_S3_PORT="$s3_port" \
  E2E_SMTP_INBOUND_PORT="$smtp_port" E2E_SMTP_SUBMISSION_PORT="$submission_port" E2E_IMAP_PORT="$imap_port" \
    bash "$WEBMAIL/e2e/scripts/start-test-stack.sh" >"$run_dir/stack.log" 2>&1 &
  stack_pid=$!
  cleanup() {
    kill "$stack_pid" 2>/dev/null || true
    wait "$stack_pid" 2>/dev/null || true
  }
  trap cleanup EXIT INT TERM

  local ready=0
  for _ in $(seq 1 120); do
    if curl -fsS "http://localhost:${gateway_port}/health" >/dev/null 2>&1; then ready=1; break; fi
    if ! kill -0 "$stack_pid" 2>/dev/null; then break; fi
    sleep 1
  done
  if [ "$ready" -ne 1 ]; then
    tail -80 "$run_dir/stack.log" >&2 || true
    echo "E_WEBMAIL_PERF_RUNTIME_FAILURE problem=gateway_not_ready cause=test_stack_failed value=$gateway_port artifact=stack.log fix='inspect the retained stack log' rerun='bash scripts/verify-webmail-performance.sh $MODE --samples $SAMPLES --warmup $WARMUP'" >&2
    exit 1
  fi

  (cd "$WEBMAIL" && \
    E2E_SERVER="http://localhost:${gateway_port}" \
    PERF_SAMPLES="$SAMPLES" PERF_WARMUP="$WARMUP" \
    PERF_REQUIRE_SYSTEM_CJK_ZERO="${PERF_REQUIRE_SYSTEM_CJK_ZERO:-0}" \
    bash "$ROOT/scripts/playwright-supported.sh" -- \
      npx playwright test e2e/webmail-performance.spec.ts --project=chromium --retries=0)

  cp "$WEBMAIL/test-results/playwright.json" "$run_dir/playwright.json"
  cp "$WEBMAIL/test-results/performance/asset-ledger.v1.json" "$run_dir/asset-ledger.v1.json"
  cp "$WEBMAIL/test-results/performance/asset-ledger.v1.txt" "$run_dir/asset-ledger.v1.txt"
  node "$WEBMAIL/scripts/performance-evidence.mjs" "$run_dir/playwright.json" "$run_dir/performance-summary.v1.json" "$SAMPLES"
  # Receipts are written only through the guarded seam: the timing writer
  # refuses rehearsal receipts/rehearsal run directories and is the only
  # writer allowed to advance latest.json.
  RUN_DIR="$run_dir" RUN_ID="$run_id" MODE="$MODE" SAMPLES="$SAMPLES" WARMUP="$WARMUP" ROOT="$ROOT" \
  BUILD_ID="$build_id" COMMIT="$commit" STARTED_AT="$started_at" HOST_SUPPORTED="$host_supported" \
    node "$WEBMAIL/scripts/performance-receipts.mjs" write-timing
  cleanup
  trap - EXIT INT TERM
  echo "WEBMAIL PERFORMANCE $MODE PASS kind=timing samples=$SAMPLES warmup=$WARMUP duration_recorded=yes evidence=${run_dir#$ROOT/}"
}

await_marker() {
  local marker="$1" timeout="$2" elapsed=0
  while [ ! -f "$marker" ]; do
    if [ "$elapsed" -ge "$timeout" ]; then
      return 1
    fi
    if [ -n "${playwright_pid:-}" ] && ! kill -0 "$playwright_pid" 2>/dev/null; then
      return 1
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done
}

served_build_id() {
  curl -fsS "http://localhost:${gateway_port}/_app/version.json" | node -e '
    let raw = "";
    process.stdin.on("data", (chunk) => { raw += chunk; });
    process.stdin.on("end", () => {
      const value = JSON.parse(raw).version;
      if (typeof value !== "string" || value.length === 0) process.exit(2);
      process.stdout.write(value);
    });
  '
}

assert_served_build() {
  local expected="$1" phase="$2" served
  served="$(served_build_id)" || {
    echo "E_WEBMAIL_PERF_RUNTIME_FAILURE problem=served_version_unreadable cause=version_endpoint_failed value=$phase artifact=stack.log fix='inspect the retained stack log' rerun='bash scripts/verify-webmail-performance.sh rehearsal'" >&2
    return 1
  }
  if [ "$served" != "$expected" ]; then
    echo "E_WEBMAIL_PERF_INVALID_EVIDENCE problem=rehearsal_served_build_mismatch cause=${phase}_phase_served_an_unexpected_build value=${served}!=${expected} artifact=stack.log fix='verify the retained prior artifact and the candidate build ids' rerun='bash scripts/verify-webmail-performance.sh rehearsal'" >&2
    return 1
  fi
}

rehearsal_lane() {
  if [ -n "$SAMPLES" ] || [ -n "$WARMUP" ]; then
    policy_violation \
      'rehearsal_rejects_sample_counts' \
      'the_rehearsal_is_not_a_timing_population' \
      "${SAMPLES:-}${WARMUP:+/$WARMUP}" \
      '--samples/--warmup' \
      'run diagnostic/ci/release for the timing population' \
      "rerun='bash scripts/verify-webmail-performance.sh rehearsal'"
  fi
  if [ -z "$PRIOR_ARTIFACT" ]; then
    echo "E_WEBMAIL_PERF_INPUTS_ABSENT problem=retained_prior_artifact_required cause=rehearsal_needs_the_actual_retained_prior_signed_artifact value=<unset> artifact=--prior-artifact fix='retain the prior release as asset-ledger.v1.json plus a web/ copy of its web root and pass --prior-artifact' rerun='bash scripts/verify-webmail-performance.sh rehearsal --help'" >&2
    exit 1
  fi
  require_command node
  require_command npm
  require_command go
  require_command psql
  require_command pg_isready
  require_command curl
  require_command weed

  local started_at host_supported
  started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  host_supported=0
  host_supported_check && host_supported=1

  if [ "${PERF_REUSE_VERIFIED_BUILD:-0}" = "1" ]; then
    bash "$ROOT/scripts/check-webmail-performance.sh" --require
  else
    build_and_ledger
  fi

  local candidate_build_id prior_json prior_build_id prior_web_dir
  candidate_build_id="$(node -e 'process.stdout.write(JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8")).version)' "$WEBMAIL/build/_app/version.json")"
  prior_json="$(cd "$WEBMAIL" && node scripts/performance-receipts.mjs validate-prior-artifact --artifact "$PRIOR_ARTIFACT" --candidate-build-id "$candidate_build_id")" || exit 1
  prior_build_id="$(printf '%s' "$prior_json" | node -e 'let raw=""; process.stdin.on("data",(c)=>{raw+=c;}); process.stdin.on("end",()=>process.stdout.write(JSON.parse(raw).buildId));')"
  prior_web_dir="$PRIOR_ARTIFACT/web"

  local timestamp commit run_id run_dir db_name gateway_port auth_port s3_port smtp_port submission_port imap_port stack_pid playwright_pid
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  commit="$(git -C "$ROOT" rev-parse --short=12 HEAD)"
  run_id="${timestamp}-${commit}-${candidate_build_id}-rehearsal"
  run_dir="$WEBMAIL/test-results/webmail-performance/runs/$run_id"
  db_name="setjoin_perf_${timestamp//[^0-9]/}_$$_rehearsal"
  mkdir -p "$run_dir/flip-control"
  gateway_port="${PERF_GATEWAY_PORT:-$(pick_free_port 28000)}"
  auth_port="${PERF_AUTH_PORT:-$(pick_free_port 29000)}"
  s3_port="${PERF_S3_PORT:-$(pick_free_port 30000)}"
  smtp_port="${PERF_SMTP_PORT:-$(pick_free_port 31000)}"
  submission_port="${PERF_SUBMISSION_PORT:-$(pick_free_port 32000)}"
  imap_port="${PERF_IMAP_PORT:-$(pick_free_port 33000)}"
  echo "WEBMAIL PERF rehearsal plan kind=rehearsal prior_build=$prior_build_id candidate_build=$candidate_build_id receipt=rehearsal-receipt.v1.json latest_json=untouched"

  E2E_SKIP_WEBMAIL_BUILD=1 \
  E2E_DB_NAME="$db_name" \
  E2E_GATEWAY_PORT="$gateway_port" E2E_AUTH_PORT="$auth_port" E2E_S3_PORT="$s3_port" \
  E2E_SMTP_INBOUND_PORT="$smtp_port" E2E_SMTP_SUBMISSION_PORT="$submission_port" E2E_IMAP_PORT="$imap_port" \
  E2E_GATEWAY_FLIP_DIR="$run_dir/flip-control" \
  WEBSITE_DIR="$prior_web_dir" \
    bash "$WEBMAIL/e2e/scripts/start-test-stack.sh" >"$run_dir/stack.log" 2>&1 &
  stack_pid=$!
  cleanup() {
    if [ -n "${playwright_pid:-}" ]; then
      kill "$playwright_pid" 2>/dev/null || true
      wait "$playwright_pid" 2>/dev/null || true
    fi
    kill "$stack_pid" 2>/dev/null || true
    wait "$stack_pid" 2>/dev/null || true
  }
  trap cleanup EXIT INT TERM

  local ready=0
  for _ in $(seq 1 120); do
    if curl -fsS "http://localhost:${gateway_port}/health" >/dev/null 2>&1; then ready=1; break; fi
    if ! kill -0 "$stack_pid" 2>/dev/null; then break; fi
    sleep 1
  done
  if [ "$ready" -ne 1 ]; then
    tail -80 "$run_dir/stack.log" >&2 || true
    echo "E_WEBMAIL_PERF_RUNTIME_FAILURE problem=gateway_not_ready cause=test_stack_failed value=$gateway_port artifact=stack.log fix='inspect the retained stack log' rerun='bash scripts/verify-webmail-performance.sh rehearsal'" >&2
    exit 1
  fi
  assert_served_build "$prior_build_id" prior || exit 1

  (cd "$WEBMAIL" && \
    E2E_SERVER="http://localhost:${gateway_port}" \
    PERF_REHEARSAL_PRIOR_BUILD_ID="$prior_build_id" \
    PERF_REHEARSAL_CANDIDATE_BUILD_ID="$candidate_build_id" \
    PERF_REHEARSAL_CONTROL_DIR="$run_dir/flip-control" \
    PLAYWRIGHT_JSON_OUTPUT_FILE="$run_dir/playwright.json" \
    bash "$ROOT/scripts/playwright-supported.sh" -- \
      npx playwright test --config playwright.rehearsal.config.ts --project=chromium --retries=0 \
      >"$run_dir/rehearsal-browser.log" 2>&1) &
  playwright_pid=$!

  await_marker "$run_dir/flip-control/prior-acknowledged.json" 360 || {
    tail -40 "$run_dir/rehearsal-browser.log" >&2 || true
    echo "E_WEBMAIL_PERF_RUNTIME_FAILURE problem=prior_generation_not_acknowledged cause=rehearsal_prior_phase_did_not_complete value=$prior_build_id artifact=rehearsal-browser.log fix='inspect the retained browser log and stack log' rerun='bash scripts/verify-webmail-performance.sh rehearsal'" >&2
    exit 1
  }

  node -e 'process.stdout.write(JSON.stringify({ websiteDir: process.argv[1] }))' "$WEBMAIL/build" >"$run_dir/flip-control/flip-request.json"
  await_marker "$run_dir/flip-control/flip-done.json" 420 || {
    tail -40 "$run_dir/stack.log" >&2 || true
    echo "E_WEBMAIL_PERF_RUNTIME_FAILURE problem=gateway_flip_incomplete cause=stack_did_not_confirm_the_flip value=$WEBMAIL/build artifact=stack.log fix='inspect the retained stack log' rerun='bash scripts/verify-webmail-performance.sh rehearsal'" >&2
    exit 1
  }
  assert_served_build "$candidate_build_id" candidate || exit 1

  local browser_rc=0
  wait "$playwright_pid" || browser_rc=$?
  playwright_pid=""
  if [ "$browser_rc" -ne 0 ]; then
    tail -40 "$run_dir/rehearsal-browser.log" >&2 || true
    echo "E_WEBMAIL_PERF_RUNTIME_FAILURE problem=rehearsal_browser_failed cause=update_rehearsal_spec_failed value=exit=$browser_rc artifact=rehearsal-browser.log fix='inspect the retained browser log and playwright report' rerun='bash scripts/verify-webmail-performance.sh rehearsal'" >&2
    exit 1
  fi
  [ -f "$run_dir/flip-control/update-complete.json" ] || {
    echo "E_WEBMAIL_PERF_INVALID_EVIDENCE problem=rehearsal_update_unproven cause=update_complete_marker_absent value=flip-control/update-complete.json artifact=$run_id fix='rerun the rehearsal; the update path must complete inside one browser session' rerun='bash scripts/verify-webmail-performance.sh rehearsal'" >&2
    exit 1
  }

  cp "$WEBMAIL/test-results/performance/asset-ledger.v1.json" "$run_dir/asset-ledger.v1.json"
  local prior_served candidate_served
  prior_served="$(node -e 'process.stdout.write(String(JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8")).servedBuildId))' "$run_dir/flip-control/prior-acknowledged.json")"
  candidate_served="$(node -e 'process.stdout.write(String(JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8")).servedBuildId))' "$run_dir/flip-control/update-complete.json")"
  PHASES_JSON="$(node -e '
    process.stdout.write(JSON.stringify([
      { name: "phase-prior", servedBuildId: process.argv[1], audit: "flip-control/prior-acknowledged.json" },
      { name: "phase-candidate", servedBuildId: process.argv[2], audit: "flip-control/update-complete.json" },
    ]));
  ' "$prior_served" "$candidate_served")"
  # The rehearsal writer refuses timing receipts, never advances latest.json,
  # and revalidates the retained prior bundle before signing the receipt.
  RUN_DIR="$run_dir" RUN_ID="$run_id" COMMIT="$commit" \
  CANDIDATE_BUILD_ID="$candidate_build_id" PRIOR_BUILD_ID="$prior_build_id" \
  PRIOR_ARTIFACT_DIR="$PRIOR_ARTIFACT" CANDIDATE_LEDGER="$run_dir/asset-ledger.v1.json" \
  PHASES_JSON="$PHASES_JSON" ROOT="$ROOT" STARTED_AT="$started_at" HOST_SUPPORTED="$host_supported" \
    node "$WEBMAIL/scripts/performance-receipts.mjs" write-rehearsal
  cleanup
  trap - EXIT INT TERM
  echo "WEBMAIL PERFORMANCE rehearsal PASS kind=rehearsal prior_build=$prior_build_id candidate_build=$candidate_build_id receipt=rehearsal-receipt.v1.json latest_json=untouched evidence=${run_dir#$ROOT/}"
}

case "$MODE" in
  help|-h|--help) usage ;;
  --doctor|doctor) doctor ;;
  hosts|--host-eligibility) print_host_eligibility ;;
  quick|ledger|fonts|locale|responder|worker)
    if [ "$SELF_TEST" -eq 1 ]; then run_lane_self_test; elif [ "$MODE" = quick ]; then quick; else focused_lane; fi
    ;;
  diagnostic)
    SAMPLES="${SAMPLES:-1}"; WARMUP="${WARMUP:-0}"
    if [ "$DRY_RUN" -eq 1 ]; then browser_dry_run; else browser_lane; fi
    ;;
  ci)
    SAMPLES="${SAMPLES:-5}"; WARMUP="${WARMUP:-1}"
    if [ "$DRY_RUN" -eq 1 ]; then browser_dry_run; else browser_lane; fi
    ;;
  release)
    SAMPLES="${SAMPLES:-20}"; WARMUP="${WARMUP:-2}"
    if [ "$DRY_RUN" -eq 1 ]; then browser_dry_run; else browser_lane; fi
    ;;
  rehearsal)
    if [ "$SELF_TEST" -eq 1 ]; then run_rehearsal_self_test
    elif [ "$DRY_RUN" -eq 1 ]; then rehearsal_dry_run
    else rehearsal_lane
    fi
    ;;
  *) echo "verify-webmail-performance: unknown mode: $MODE" >&2; usage >&2; exit 2 ;;
esac
