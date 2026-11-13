#!/usr/bin/env bash
# Hermetic CLI/diagnostic/evidence contract tests for verify-architecture-r3.sh.
source "$(dirname "$0")/_base.sh"

VERIFY="$ROOT/scripts/verify-architecture-r3.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

fail() { echo "verify-architecture-r3 test: $*" >&2; exit 1; }

bash "$VERIFY" --help >"$tmp/help"
grep -q 'no-argument default' "$tmp/help" || fail "help omits quick default"
grep -q 'compatibility.*retained-binary' "$tmp/help" || fail "help omits compatibility suite"
grep -q 'LANE \[--self-test\] \[--json\] \[--verbose\]' "$tmp/help" || fail "help omits lane flag grammar"
grep -q 'evidence \[--run-id ID\]' "$tmp/help" || fail "help omits evidence query"

set +e
bash "$VERIFY" unknown-command >"$tmp/unknown.out" 2>"$tmp/unknown.err"
status=$?
set -e
[[ "$status" -eq 2 ]] || fail "unknown command exit=$status, want 2"
grep -q '^E_ARCH_R3_USAGE problem=.*cause=unknown_command.*artifact=unknown-command' "$tmp/unknown.err" || fail "unknown command lacks actionable usage diagnostic"

set +e
bash "$VERIFY" aal2 --unknown-option >"$tmp/unknown-option.out" 2>"$tmp/unknown-option.err"
status=$?
set -e
[[ "$status" -eq 2 ]] || fail "unknown option exit=$status, want 2"
grep -q '^E_ARCH_R3_USAGE problem=.*cause=unknown_lane_option.*artifact=--unknown-option' "$tmp/unknown-option.err" || fail "unknown lane option lacks actionable usage diagnostic"

ARCH_R3_RESULTS_ROOT="$tmp/results" bash "$VERIFY" --doctor >"$tmp/doctor"
for lane in aal2 auth-completion migration-checkpoint webhook-outbox mam-lifecycle chat-reconcile compose-state caption-pipeline; do
  grep -q "  $lane:" "$tmp/doctor" || fail "doctor omits $lane"
done

for group in compatibility devices live-media; do
  set +e
  ARCH_R3_RELEASE_EVIDENCE_ROOT="$tmp/missing-release" bash "$VERIFY" "$group" >"$tmp/$group.out" 2>"$tmp/$group.err"
  status=$?
  set -e
  [[ "$status" -eq 1 ]] || fail "$group missing evidence exit=$status, want 1"
  code="E_ARCH_R3_$(printf '%s' "$group" | tr '[:lower:]-' '[:upper:]_')_MISSING"
  grep -q "^$code problem=" "$tmp/$group.err" || fail "$group lacks stable missing diagnostic"
done

for lane in aal2 auth-completion migration-checkpoint webhook-outbox mam-lifecycle chat-reconcile compose-state caption-pipeline; do
  lane_results="$tmp/self-$lane"
  ARCH_R3_RESULTS_ROOT="$lane_results" bash "$VERIFY" "$lane" --self-test --json >"$tmp/$lane-self.json"
  node - "$tmp/$lane-self.json" <<'NODE'
const fs=require('node:fs');
const lines=fs.readFileSync(process.argv[2],'utf8').trim().split('\n');
const result=JSON.parse(lines.at(-1));
if(result.mode!=='self-test'||result.verdict!=='pass') process.exit(1);
NODE
done

# DB-backed auth completion must fail before Go when the disposable PostgreSQL
# prerequisite is unavailable; it may never degrade into testsupport t.Skip.
mkdir -p "$tmp/nodb-bin"
printf '%s\n' '#!/usr/bin/env bash' 'exit 1' >"$tmp/nodb-bin/pg_isready"
chmod +x "$tmp/nodb-bin/pg_isready"
set +e
PATH="$tmp/nodb-bin:$PATH" bash "$VERIFY" auth-completion >"$tmp/auth-nodb.out" 2>"$tmp/auth-nodb.err"
status=$?
set -e
[[ "$status" -eq 1 ]] || fail "auth missing-DB exit=$status, want 1"
grep -q '^E_ARCH_R3_PREREQUISITE problem=' "$tmp/auth-nodb.err" || fail "auth missing-DB lacks fail-closed diagnostic"
grep -q 'REQUIRE_DB=1' "$VERIFY" || fail "auth lane does not force DB-backed fixtures"
grep -q "Action === 'skip'" "$VERIFY" || fail "auth lane does not reject skipped required tests"

for code in E_ARCH_R3_AAL2 E_ARCH_R3_AUTH_ORDER E_ARCH_R3_CHECKPOINT_AHEAD \
  E_ARCH_R3_WEBHOOK_AUDIENCE E_ARCH_R3_MAM_PARITY E_ARCH_R3_CHAT_STALE \
  E_ARCH_R3_COMPOSE_STALE E_ARCH_R3_CAPTION_DRAIN; do
  grep -q "$code" "$VERIFY" || fail "diagnostic registry omits $code"
done

ARCH_R3_RESULTS_ROOT="$tmp/results" bash "$VERIFY" mam-lifecycle --self-test >"$tmp/mam-self"
pointer="$tmp/results/latest.json"
[[ -f "$pointer" ]] || fail "self-test did not publish latest pointer"
manifest_rel="$(node -e 'const x=JSON.parse(require("fs").readFileSync(process.argv[1])); process.stdout.write(x.manifest)' "$pointer")"
if [[ "$manifest_rel" == /* ]]; then manifest="$manifest_rel"; else manifest="$ROOT/$manifest_rel"; fi
[[ -f "$manifest" ]] || fail "pointer names missing manifest: $manifest_rel"
node - "$manifest" <<'NODE'
const fs = require('node:fs');
const m = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
if (m.schemaVersion !== 1 || m.lane !== 'mam-lifecycle' || m.mode !== 'self-test' || m.verdict !== 'pass') process.exit(1);
if (!/^[0-9a-f]{64}$/.test(m.source.dirtyDigest) || !/^[0-9a-f]{64}$/.test(m.artifacts[0].sha256)) process.exit(1);
NODE

find "$tmp/results" -name '*.tmp' -o -name '.latest.json.*' | grep -q . && fail "atomic publication leaked temporary files"

mkdir -p "$tmp/bin" "$tmp/failure-results"
printf '%s\n' \
  '#!/usr/bin/env bash' \
  'if [[ "${1:-}" == "version" || "${1:-}" == "--version" ]]; then echo "go version planted"; exit 0; fi' \
  'echo "planted Go test failure" >&2' \
  'exit 9' >"$tmp/bin/go"
chmod +x "$tmp/bin/go"
set +e
PATH="$tmp/bin:$PATH" ARCH_R3_RESULTS_ROOT="$tmp/failure-results" bash "$VERIFY" aal2 >"$tmp/failure.out" 2>"$tmp/failure.err"
status=$?
set -e
[[ "$status" -eq 9 ]] || fail "failed lane exit=$status, want underlying 9"
grep -q '^E_ARCH_R3_AAL2 problem=' "$tmp/failure.err" || fail "failed lane lacks stable diagnostic"
failure_manifest_rel="$(node -e 'const x=JSON.parse(require("fs").readFileSync(process.argv[1])); process.stdout.write(x.manifest)' "$tmp/failure-results/latest.json")"
failure_manifest="$failure_manifest_rel"
[[ "$failure_manifest" == /* ]] || failure_manifest="$ROOT/$failure_manifest"
node - "$failure_manifest" <<'NODE'
const fs = require('node:fs');
const m = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const log = fs.readFileSync(process.argv[2].replace(/manifest\.json$/, 'output.log'), 'utf8');
if (m.verdict !== 'failed' || m.diagnosticCode !== 'E_ARCH_R3_AAL2') process.exit(1);
if (!log.includes('planted Go test failure') || !log.includes('E_ARCH_R3_AAL2')) process.exit(1);
NODE

set +e
bash "$VERIFY" evidence --run-id '../escape' >"$tmp/evidence.out" 2>"$tmp/evidence.err"
status=$?
set -e
[[ "$status" -eq 2 ]] || fail "unsafe evidence run-id exit=$status, want 2"
grep -q '^E_ARCH_R3_EVIDENCE problem=' "$tmp/evidence.err" || fail "unsafe evidence run-id lacks stable diagnostic"

set +e
bash "$VERIFY" benchmark --samples 0 >"$tmp/benchmark.out" 2>"$tmp/benchmark.err"
status=$?
set -e
[[ "$status" -eq 2 ]] || fail "invalid benchmark samples exit=$status, want 2"
grep -q '^E_ARCH_R3_BENCHMARK problem=' "$tmp/benchmark.err" || fail "benchmark grammar lacks stable diagnostic"

for literal in 'warmups=2' 'samples=20' 'p95<=300000' 'fingerprint_changed'; do
  grep -q "$literal" "$VERIFY" || fail "benchmark contract omits $literal"
done
echo "verify-architecture-r3 test: PASS"
