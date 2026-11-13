#!/usr/bin/env bash
# Deterministic CLI/schema/evidence mutants for the R5 front door.
# shellcheck disable=SC1091
source "$(dirname "$0")/_base.sh"
set -euo pipefail

VERIFY="$ROOT/scripts/verify-architecture-r5.sh"
CHECKER="$ROOT/scripts/check-architecture-r5-cases.mjs"
REGISTRY="$ROOT/docs/verification/architecture-r5-cases.json"
FINGERPRINT_TOOL="$ROOT/scripts/lib/source-fingerprint.mjs"
tmp="$(mktemp -d)"
source_mutant="$ROOT/docs/verification/.architecture-r5-source-mutant.bin"
source_mutant_owned=0
cleanup() {
  [[ "$source_mutant_owned" -eq 0 ]] || rm -f "$source_mutant"
  rm -rf "$tmp"
}
trap cleanup EXIT
before="$(node "$FINGERPRINT_TOOL" compute --root "$ROOT")"

fail() { echo "E_ARCH_R5_SCRIPT_TEST $*" >&2; exit 1; }

bash -n "$VERIFY"
bash -n "$ROOT/scripts/check-architecture-r5-collisions.sh"
node "$ROOT/scripts/lib/source-fingerprint.test.mjs" >"$tmp/fingerprint.out"
node "$CHECKER" validate >"$tmp/registry.out"
grep -q '14 exact cases' "$tmp/registry.out"

bash "$VERIFY" --help >"$tmp/help"
grep -q 'list                    List 14 exact candidates' "$tmp/help"
grep -q 'LANE \[--self-test\] \[--verbose\]' "$tmp/help"
grep -q 'evidence \[--run-id ID\]' "$tmp/help"
[[ "$(bash "$VERIFY" list | wc -l | tr -d ' ')" -eq 14 ]] || fail 'list is not exactly 14 rows'
bash "$VERIFY" --doctor >"$tmp/doctor"
grep -Eq '  source: fingerprint=v2:[0-9a-f]{40,64}:[0-9a-f]{64} registry=[0-9a-f]{64}$' "$tmp/doctor" || fail 'doctor does not report the shared v2 source fingerprint'
for lane in smtp auth-json artifacts rehearsal ca admin jmap-account evidence-boundary auth-cookie chat exchange-fold compose calendar offline-defer; do
  grep -q "  $lane:" "$tmp/doctor" || fail "doctor omits $lane"
  bash "$VERIFY" "$lane" --self-test >"$tmp/self-$lane"
done

set +e
bash "$VERIFY" not-a-lane >"$tmp/unknown.out" 2>"$tmp/unknown.err"; unknown_status=$?
bash "$VERIFY" smtp --not-a-flag >"$tmp/flag.out" 2>"$tmp/flag.err"; flag_status=$?
ARCH_R5_RESULTS_ROOT="$tmp/missing" bash "$VERIFY" evidence >"$tmp/missing.out" 2>"$tmp/missing.err"; missing_status=$?
bash "$VERIFY" evidence --run-id '../escape' >"$tmp/escape.out" 2>"$tmp/escape.err"; escape_status=$?
set -e
if [[ "$unknown_status" -ne 2 ]] || ! grep -q '^E_ARCH_R5_CLI_UNKNOWN$' "$tmp/unknown.err"; then fail 'unknown command was not rejected'; fi
if [[ "$flag_status" -ne 2 ]] || ! grep -q '^E_ARCH_R5_CLI_USAGE$' "$tmp/flag.err"; then fail 'unknown option was not rejected'; fi
if [[ "$missing_status" -ne 1 ]] || ! grep -q '^E_ARCH_R5_EVIDENCE_MISSING$' "$tmp/missing.err"; then fail 'missing evidence was accepted'; fi
if [[ "$escape_status" -ne 2 ]] || ! grep -q '^E_ARCH_R5_EVIDENCE_USAGE$' "$tmp/escape.err"; then fail 'unsafe run ID was accepted'; fi
for output in "$tmp/unknown.err" "$tmp/flag.err" "$tmp/missing.err" "$tmp/escape.err"; do
  for field in problem cause location artifact fix rerun docs; do grep -q "^$field:" "$output" || fail "$(basename "$output") omits $field"; done
done

# Terminal ownership receipts validate but remain distinguishable from product green.
ARCH_R5_RESULTS_ROOT="$tmp/terminal" bash "$VERIFY" exchange-fold >"$tmp/exchange.out"
grep -q 'architecture-r5: terminal.*disposition=folded' "$tmp/exchange.out"
ARCH_R5_RESULTS_ROOT="$tmp/terminal" bash "$VERIFY" evidence >"$tmp/evidence.out"
grep -q 'TERMINAL.*disposition=folded' "$tmp/evidence.out"
run_id="$(node -e 'const p=JSON.parse(require("fs").readFileSync(process.argv[1]));process.stdout.write(p.runId)' "$tmp/terminal/latest.json")"
manifest="$tmp/terminal/$run_id/manifest.json"
node - "$manifest" <<'NODE'
const fs=require('node:fs');const m=JSON.parse(fs.readFileSync(process.argv[2]));
if(!/^v2:[0-9a-f]{40,64}:[0-9a-f]{64}$/.test(m.source?.fingerprint))process.exit(1);
const [,commit,digest]=m.source.fingerprint.split(':');
if(m.source.commit!==commit||m.source.dirtyDigest!==digest)process.exit(1);
NODE
cp "$manifest" "$tmp/terminal-manifest.good"
node - "$manifest" <<'NODE'
const fs=require('node:fs');const file=process.argv[2];const m=JSON.parse(fs.readFileSync(file));
m.source.fingerprint=m.source.fingerprint.slice(3);fs.writeFileSync(file,`${JSON.stringify(m,null,2)}\n`);
NODE
set +e
ARCH_R5_RESULTS_ROOT="$tmp/terminal" bash "$VERIFY" evidence --run-id "$run_id" >"$tmp/version.out" 2>"$tmp/version.err"; version_status=$?
set -e
if [[ "$version_status" -ne 1 ]] || ! grep -q '^E_ARCH_R5_EVIDENCE_VERSION$' "$tmp/version.err"; then fail 'unversioned R5 evidence fingerprint was accepted'; fi
cp "$tmp/terminal-manifest.good" "$manifest"
printf 'tamper\n' >>"${manifest%manifest.json}output.log"
set +e
ARCH_R5_RESULTS_ROOT="$tmp/terminal" bash "$VERIFY" evidence --run-id "$run_id" >"$tmp/tamper.out" 2>"$tmp/tamper.err"; tamper_status=$?
set -e
if [[ "$tamper_status" -ne 1 ]] || ! grep -q '^E_ARCH_R5_EVIDENCE_ARTIFACT$' "$tmp/tamper.err"; then fail 'tampered artifact was accepted'; fi

# Content mutation of an already-dirty path must be detected even though its
# porcelain status line remains unchanged. The lane still publishes its HOLD
# receipt, and later validation must reject the pre-mutation fingerprint.
[[ ! -e "$source_mutant" ]] || fail 'source mutant path already exists'
node -e 'require("fs").writeFileSync(process.argv[1],Buffer.from([0,82,53,45,100,105,114,116,121]))' "$source_mutant"
source_mutant_owned=1
set +e
ARCH_R5_PLANTED_SOURCE_MUTATION=1 ARCH_R5_RESULTS_ROOT="$tmp/source-change" \
  bash "$VERIFY" exchange-fold >"$tmp/source-change.out" 2>"$tmp/source-change.err"
source_change_status=$?
set -e
if [[ "$source_change_status" -ne 3 ]] || ! grep -q '^E_ARCH_R5_EVIDENCE_STALE$' "$tmp/source-change.err"; then fail 'dirty-file byte mutation did not HOLD the lane'; fi
source_run_id="$(node -e 'const p=JSON.parse(require("fs").readFileSync(process.argv[1]));process.stdout.write(p.runId)' "$tmp/source-change/latest-exchange-fold.json")"
source_manifest="$tmp/source-change/$source_run_id/manifest.json"
node - "$source_manifest" <<'NODE'
const fs=require('node:fs');const m=JSON.parse(fs.readFileSync(process.argv[2]));
if(m.verdict!=='held'||m.disposition!=='hold'||m.diagnosticCode!=='E_ARCH_R5_EVIDENCE_STALE'||m.predicate.reason!=='source-changed-during-lane')process.exit(1);
NODE
set +e
ARCH_R5_RESULTS_ROOT="$tmp/source-change" bash "$VERIFY" evidence --run-id "$source_run_id" >"$tmp/source-evidence.out" 2>"$tmp/source-evidence.err"
source_evidence_status=$?
set -e
if [[ "$source_evidence_status" -ne 1 ]] || ! grep -q '^E_ARCH_R5_EVIDENCE_STALE$' "$tmp/source-evidence.err"; then fail 'published pre-mutation fingerprint was accepted'; fi
rm -f "$source_mutant"
source_mutant_owned=0

# Strict registry schema mutants: unknown field, duplicate exact ID, forbidden
# disposition, weakened HOLD list, duplicate JSON key, and missing case.
for mutant in unknown duplicate disposition hold missing; do
  cp "$REGISTRY" "$tmp/$mutant.json"
done
node - "$tmp/unknown.json" "$tmp/duplicate.json" "$tmp/disposition.json" "$tmp/hold.json" "$tmp/missing.json" <<'NODE'
const fs=require('node:fs');
const files=process.argv.slice(2);const read=(f)=>JSON.parse(fs.readFileSync(f));const write=(f,v)=>fs.writeFileSync(f,`${JSON.stringify(v,null,2)}\n`);
let r=read(files[0]);r.cases[0].unexpected=true;write(files[0],r);
r=read(files[1]);r.cases[1].candidate=r.cases[0].candidate;write(files[1],r);
r=read(files[2]);r.cases[0].allowedDispositions=['skipped'];write(files[2],r);
r=read(files[3]);r.cases[0].predicate.holdOn=['malformed'];write(files[3],r);
r=read(files[4]);r.cases.pop();write(files[4],r);
NODE
printf '{"schemaVersion":1,"schemaVersion":1}\n' >"$tmp/duplicate-key.json"
for mutant in unknown duplicate disposition hold missing duplicate-key; do
  set +e
  ARCH_R5_REGISTRY="$tmp/$mutant.json" node "$CHECKER" validate >"$tmp/$mutant.out" 2>"$tmp/$mutant.err"; status=$?
  set -e
  if [[ "$status" -ne 1 ]] || ! grep -q 'E_ARCH_R5_REGISTRY' "$tmp/$mutant.err"; then fail "registry mutant $mutant was accepted"; fi
done

bash "$ROOT/scripts/check-architecture-r5-collisions.test.sh" >"$tmp/collision.out"
find "$tmp" -name '*.tmp' -o -name '.latest.*' | grep -q . && fail 'atomic publication leaked temporary files'
after="$(node "$FINGERPRINT_TOOL" compute --root "$ROOT")"
[[ "$before" == "$after" ]] || fail 'self-tests changed the worktree digest'

echo 'architecture-r5 script contract: PASS (14 lanes, schema mutants, planted failures, binary-safe dirty mutation, source-bound terminal evidence, tamper, collisions, unchanged worktree)'
