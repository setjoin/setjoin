#!/usr/bin/env bash
# Hermetic v1-layout publication and evidence-adapter contract. No boundary lane runs here.
# shellcheck disable=SC1091
source "$(dirname "$0")/_base.sh"
set -euo pipefail

script="$ROOT/scripts/verify-security-boundaries.sh"
fingerprint_tool="$ROOT/scripts/lib/source-fingerprint.mjs"
publication_tool="$ROOT/scripts/lib/security-program-publication.mjs"
json_tool="$ROOT/scripts/lib/security-program-json.mjs"
registry="$ROOT/docs/verification/security-boundary-cases.json"

fail() {
  echo "E_SECURITY_BOUNDARY_SCRIPT_TEST $*" >&2
  exit 1
}

before="$(node "$fingerprint_tool" compute --root "$ROOT")"
help="$(bash "$script" --help)"
grep -q 'source-bound evidence' <<<"$help"
grep -q 'security-boundaries/<run-id>/manifest.json' <<<"$help"
[[ "$(bash "$script" list | wc -l | tr -d ' ')" == 8 ]]
set +e
doctor_output="$(bash "$script" --doctor)"
doctor_rc=$?
set -e
grep -Eq '^  source: v2:[0-9a-f]{40,64}:[0-9a-f]{64}$' <<<"$doctor_output"
grep -q '^  evidence-adapter: ready (v2 immutable lineage)$' <<<"$doctor_output"
[[ "$doctor_rc" -eq 0 || "$doctor_rc" -eq 1 ]]

tmp="$(mktemp -d)"
trap 'chmod -R u+w "$tmp" 2>/dev/null; rm -rf -- "$tmp"' EXIT

# Exercise the boundary adapter's publish path directly after sourcing the CLI.
# Sourcing only defines functions; it cannot dispatch a real G0-G4 lane.
(
  export SECURITY_BOUNDARY_RESULTS_ROOT="$tmp/valid"
  # shellcheck source=verify-security-boundaries.sh
  source "$script"
  printf 'verified\n' >"$tmp/valid-output.log"
  SEC_ADAPTER_MODE=publish SEC_LANE=contracts SEC_CASE=SEC-ALL-CONTRACTS SEC_VERDICT=passed \
    SEC_SOURCE="$before" SEC_DURATION_MS=1 SEC_EXIT=0 SEC_LOG="$tmp/valid-output.log" \
    SEC_RUN_ID=run-valid SEC_REGISTRY="$registry" SEC_GENERATIONS_ROOT="$GENERATIONS_ROOT" \
    SEC_LATEST_POINTER="$LATEST_POINTER" SEC_FINGERPRINT_TOOL="$fingerprint_tool" \
    SEC_PUBLICATION_TOOL="$publication_tool" SEC_JSON_TOOL="$json_tool" \
    boundary_evidence_adapter >"$tmp/publish.json"
  grep -q '"generationId":"run-valid"' "$tmp/publish.json"

  # v1 layout contract: the pointer derives from RESULTS_ROOT (never an in-root
  # latest.json) and generations sit directly in the evidence root.
  [[ "$LATEST_POINTER" == "${RESULTS_ROOT}-latest.json" ]] || fail "pointer must derive from RESULTS_ROOT: $LATEST_POINTER"
  [[ "$GENERATIONS_ROOT" == "$RESULTS_ROOT" ]] || fail "v1 generations must sit directly in the evidence root: $GENERATIONS_ROOT"

  set +e
  SEC_ADAPTER_MODE=publish SEC_LANE=contracts SEC_CASE=SEC-ALL-CONTRACTS SEC_VERDICT=passed \
    SEC_SOURCE="$before" SEC_DURATION_MS=1 SEC_EXIT=0 SEC_LOG="$tmp/valid-output.log" \
    SEC_RUN_ID='../escape' SEC_REGISTRY="$registry" SEC_GENERATIONS_ROOT="$GENERATIONS_ROOT" \
    SEC_LATEST_POINTER="$LATEST_POINTER" SEC_FINGERPRINT_TOOL="$fingerprint_tool" \
    SEC_PUBLICATION_TOOL="$publication_tool" SEC_JSON_TOOL="$json_tool" \
    boundary_evidence_adapter >"$tmp/unsafe-run.out" 2>"$tmp/unsafe-run.err"
  unsafe_run_rc=$?
  set -e
  [[ "$unsafe_run_rc" -eq 1 ]]
  grep -q '^E_SECURITY_EVIDENCE_INVALID ' "$tmp/unsafe-run.err"
)

SECURITY_BOUNDARY_RESULTS_ROOT="$tmp/valid" bash "$script" evidence >"$tmp/valid.log"
grep -q 'security-boundaries evidence: PASS' "$tmp/valid.log"
grep -q 'run-valid/manifest.json' "$tmp/valid.log"

# Legacy residue (a v2/ tree or an in-root latest.json) must refuse with exit 2
# and the isolation instruction — BEFORE any publication is attempted.
for residue in v2 latest.json; do
  residue_root="$tmp/residue-$residue"
  mkdir -p "$residue_root/v2/generations" "$residue_root"
  printf '{}' >"$residue_root/latest.json"
  set +e
  SECURITY_BOUNDARY_RESULTS_ROOT="$residue_root" bash "$script" list >"$tmp/residue.out" 2>&1
  residue_rc=$?
  set -e
  [[ "$residue_rc" -eq 2 ]] || fail "legacy residue $residue must exit 2 (got $residue_rc)"
  grep -q 'isolate-legacy' "$tmp/residue.out" || fail "residue $residue output must name --isolate-legacy"
done

# --isolate-legacy is refuse-safe: no residue -> exit 2; a moved-out pointer ->
# exit 2; and it must not touch the real test-results tree.
set +e
SECURITY_BOUNDARY_RESULTS_ROOT="$tmp/clean" bash "$script" --isolate-legacy >/dev/null 2>&1
no_residue_rc=$?
mkdir -p "$tmp/isolate/v2/generations"
printf '{}' >"$tmp/isolate/latest.json"
SECURITY_BOUNDARY_RESULTS_ROOT="$tmp/isolate" bash "$script" --isolate-legacy >"$tmp/isolate.out" 2>&1
isolate_rc=$?
set -e
[[ "$no_residue_rc" -eq 2 ]] || fail "isolate-legacy without residue must exit 2 (got $no_residue_rc)"
[[ "$isolate_rc" -eq 0 ]] || fail "isolate-legacy with residue must succeed (got $isolate_rc)"
grep -q 'isolated 2 legacy evidence entries' "$tmp/isolate.out" || fail "isolate-legacy must report the moved count"
archived="$(ls -d "$tmp"/isolate-legacy-* 2>/dev/null | head -1)"
[[ -n "$archived" && -d "$archived/v2/generations" ]] || fail "isolate-legacy must retain the v2 tree under the archive"
[[ -e "$tmp/isolate/v2" ]] && fail "isolate-legacy must empty the evidence root"

# A lane whose source changes between its pre/post fingerprints must never publish.
(
  export SECURITY_BOUNDARY_RESULTS_ROOT="$tmp/source-race"
  # shellcheck source=verify-security-boundaries.sh
  source "$script"
  printf '0\n' >"$tmp/fingerprint-calls"
  need() { return 0; }
  evidence_adapter_ready() { return 0; }
  run_lane_command() { return 0; }
  source_fingerprint() {
    local fingerprint_calls
    fingerprint_calls="$(<"$tmp/fingerprint-calls")"
    fingerprint_calls=$((fingerprint_calls + 1))
    printf '%s\n' "$fingerprint_calls" >"$tmp/fingerprint-calls"
    printf 'v2:%040d:%064d\n' 0 "$fingerprint_calls"
  }
  if run_lane contracts >"$tmp/source-race.out" 2>"$tmp/source-race.err"; then
    source_race_rc=0
  else
    source_race_rc=$?
  fi
  [[ "$source_race_rc" -eq 1 ]]
  grep -q '^E_SECURITY_SOURCE_CHANGED lane=contracts ' "$tmp/source-race.err"
  [[ ! -e "$LATEST_POINTER" ]]
)

# Build adversarial immutable generations through the generic crash-safe primitive.
# The boundary adapter must still reject their semantically invalid manifests.
SEC_FIXTURE_ROOT="$tmp" SEC_FIXTURE_FINGERPRINT="$before" SEC_PUBLICATION_TOOL="$publication_tool" SEC_JSON_TOOL="$json_tool" node --input-type=module <<'NODE'
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const { canonicalJson } = await import(pathToFileURL(process.env.SEC_JSON_TOOL));
const { publishVerifiedGeneration } = await import(pathToFileURL(process.env.SEC_PUBLICATION_TOOL));
const root = process.env.SEC_FIXTURE_ROOT;
const fingerprint = process.env.SEC_FIXTURE_FINGERPRINT;
const output = Buffer.from('verified\n');
const digest = crypto.createHash('sha256').update(output).digest('hex');
const fixedNow = new Date('2026-09-03T00:00:00.000Z');

function manifest() {
  return {
    schema: 'setjoin.security-program.security-boundaries-manifest/v2',
    lane: 'contracts',
    caseId: 'SEC-ALL-CONTRACTS',
    verdict: 'passed',
    sourceFingerprint: fingerprint,
    metrics: { schema: 'setjoin.security-program.security-boundaries-metrics/v2', durationMs: 1, logBytes: output.length },
    exitCode: 0,
    artifacts: [{ schema: 'setjoin.security-program.security-boundaries-artifact/v2', path: 'output.log', sha256: digest, size: output.length }],
  };
}

function publish(name, mutate = () => {}) {
  const value = manifest();
  mutate(value);
  return publishVerifiedGeneration({
    generationsDirectory: path.join(root, name),
    pointerPath: path.join(root, name + '-latest.json'),
    generationId: `run-${name}`,
    files: { 'manifest.json': canonicalJson(value), 'output.log': output },
    now: fixedNow,
  });
}

publish('unknown-field', (value) => { value.unexpected = true; });
publish('traversal', (value) => { value.artifacts[0].path = '../outside.log'; });
publish('wrong-lane', (value) => { value.lane = 'not-a-lane'; });
publish('wrong-case', (value) => { value.caseId = 'SEC-G0-LOCAL-BOOTSTRAP'; });
publish('old-fingerprint', (value) => { value.sourceFingerprint = value.sourceFingerprint.slice(3); });
publish('stale-fingerprint', (value) => { value.sourceFingerprint = `${value.sourceFingerprint.slice(0, -1)}${value.sourceFingerprint.endsWith('0') ? '1' : '0'}`; });
publish('hash-mismatch', (value) => { value.artifacts[0].sha256 = '0'.repeat(64); });
publish('symlink-artifact');
const symlinkGenDir = path.join(root, 'symlink-artifact', 'run-symlink-artifact');
const symlinkOutput = path.join(symlinkGenDir, 'output.log');
// Published generations are 0444 files inside a 0555 directory (immutable
// semantics) — unwrap BOTH before replacing, or rmSync gets EACCES on the
// parent, not the file.
fs.chmodSync(symlinkGenDir, 0o755);
fs.chmodSync(symlinkOutput, 0o644);
fs.rmSync(symlinkOutput);
fs.writeFileSync(path.join(root, 'outside.log'), 'outside\n');
fs.symlinkSync(path.join(root, 'outside.log'), symlinkOutput);

const pointerTemplate = {
  schema: 'setjoin.security-program.latest-pointer/v1',
  generationId: '../escape',
  generationHash: '0'.repeat(64),
  predecessorGenerationId: null,
  predecessorGenerationHash: null,
  createdAt: fixedNow.toISOString(),
};
for (const [name, pointer] of [
  ['unsafe-pointer', pointerTemplate],
  ['unknown-pointer-field', { ...pointerTemplate, generationId: 'safe', unexpected: true }],
]) {
  const fixtureRoot = path.join(root, name);
  fs.mkdirSync(fixtureRoot, { recursive: true });
  fs.writeFileSync(path.join(fixtureRoot + '-latest.json'), canonicalJson(pointer));
}

function lineage(name, tamper) {
  const generationsDirectory = path.join(root, name);
  const pointerPath = path.join(root, name + '-latest.json');
  publishVerifiedGeneration({ generationsDirectory, pointerPath, generationId: 'lineage-one', files: { 'manifest.json': canonicalJson(manifest()), 'output.log': output }, now: fixedNow });
  const firstPointer = fs.readFileSync(pointerPath);
  publishVerifiedGeneration({ generationsDirectory, pointerPath, generationId: 'lineage-two', files: { 'manifest.json': canonicalJson(manifest()), 'output.log': output }, now: new Date(fixedNow.getTime() + 1_000) });
  // Published artifacts are 0444 (immutable semantics); unwrap before tampering.
  if (tamper === 'rollback') {
    fs.chmodSync(pointerPath, 0o644);
    fs.writeFileSync(pointerPath, firstPointer);
  }
  if (tamper === 'receipt') {
    const receiptPath = path.join(generationsDirectory, 'lineage-two', 'generation-receipt.json');
    const receipt = JSON.parse(fs.readFileSync(receiptPath));
    receipt.predecessorGenerationHash = '0'.repeat(64);
    fs.chmodSync(receiptPath, 0o644);
    fs.writeFileSync(receiptPath, canonicalJson(receipt));
  }
}
lineage('pointer-rollback', 'rollback');
lineage('lineage-tamper', 'receipt');

// A generation carrying a broken sourceFingerprint: the evidence gate must
// fail on VERSION (unparseable fingerprint), not layout residue. Published
// through the real library so the sealed pointer and lineage are genuine; the
// pointer sits at the sibling position the runner derives from RESULTS_ROOT.
{
  const gensDirectory = path.join(root, 'legacy-v1');
  const value = manifest();
  value.sourceFingerprint = 'v1:not-a-v2-fingerprint';
  publishVerifiedGeneration({
    generationsDirectory: gensDirectory,
    pointerPath: path.join(root, 'legacy-v1-latest.json'),
    generationId: '20260101T000000Z-00000000-0000-legacy',
    files: { 'manifest.json': canonicalJson(value), 'output.log': output },
    now: fixedNow,
  });
}

NODE

expect_rejected() {
  local name="$1" expected_code="$2" status
  local output="$tmp/$name.log"
  set +e
  SECURITY_BOUNDARY_RESULTS_ROOT="$tmp/$name" bash "$script" evidence >"$output" 2>&1
  status=$?
  set -e
  [[ "$status" -eq 1 ]] || fail "$name evidence exit=$status, want 1"
  grep -q "$expected_code" "$output" || fail "$name omitted $expected_code"
}

for name in unknown-field traversal wrong-lane wrong-case hash-mismatch symlink-artifact unsafe-pointer unknown-pointer-field pointer-rollback lineage-tamper; do
  expect_rejected "$name" E_SECURITY_EVIDENCE_INVALID
done
expect_rejected old-fingerprint E_SECURITY_EVIDENCE_VERSION
expect_rejected stale-fingerprint E_SECURITY_EVIDENCE_STALE
expect_rejected legacy-v1 E_SECURITY_EVIDENCE_VERSION
expect_rejected missing E_SECURITY_EVIDENCE_MISSING

set +e
bash "$script" unknown >"$tmp/unknown.log" 2>&1
unknown_rc=$?
set -e
[[ "$unknown_rc" -eq 2 ]]
grep -q E_SECURITY_CLI_UNKNOWN "$tmp/unknown.log"

after="$(node "$fingerprint_tool" compute --root "$ROOT")"
[[ "$before" == "$after" ]] || fail 'contract test changed the source fingerprint'

echo 'security-boundaries script contract: PASS (v2 immutable publication, pre/post source binding, closed manifest, strict source/case/artifact, rollback/tamper/traversal/symlink rejection, unchanged worktree, zero real lane starts)'
