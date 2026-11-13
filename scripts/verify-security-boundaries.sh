#!/usr/bin/env bash
# Security Boundary Remediation: source-bound focused verification dispatcher.
# shellcheck disable=SC1091
source "$(dirname "$0")/_base.sh"
set -euo pipefail

RESULTS_ROOT="${SECURITY_BOUNDARY_RESULTS_ROOT:-$ROOT/test-results/security-boundaries}"
# v1 layout: dated generations live DIRECTLY under the evidence root, which is
# what scripts/check-deep-security-remediation.mjs requires — evidenceRoot must
# stay test-results/security-boundaries and every per-lane manifestPath must be
# "<evidenceRoot>/<generationId>/manifest.json". The earlier v2 runner nested
# generations under an extra v2/ directory, so a republished aggregate manifest
# could never satisfy the checker (recorded as the ER6 lane-9 harness-model
# decision). Nothing has ever published against the v2 path, so the runner
# publishes v1 rather than teaching the checker a second layout.
GENERATIONS_ROOT="$RESULTS_ROOT"
# The authoritative pointer must live OUTSIDE the generations directory: the
# publication library scans that directory and treats every non-hidden entry as
# a generation directory (readCurrentGeneration also refuses any sibling of a
# pending generation, so latest.json.tmp-<gen> during first publication would
# abort publication). The checker never reads latest.json from disk — it only
# forbids latest references INSIDE the aggregate manifest — so moving the
# pointer here changes nothing the checker sees.
LATEST_POINTER="${RESULTS_ROOT}-latest.json"
REGISTRY="$ROOT/docs/verification/security-boundary-cases.json"
LANES=(bootstrap recovery push migration ingress audit updates contracts)
DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_USER="${DB_USER:-mail}"
DB_NAME="${DB_NAME:-mailserver_test}"
NODE_BIN="${SECURITY_BOUNDARY_NODE_BIN:-$(command -v node || true)}"
FINGERPRINT_TOOL="$ROOT/scripts/lib/source-fingerprint.mjs"
PUBLICATION_TOOL="$ROOT/scripts/lib/security-program-publication.mjs"
JSON_TOOL="$ROOT/scripts/lib/security-program-json.mjs"
VERBOSE=0
PUBLISHED_OUTPUT=""

usage() {
  cat <<'EOF'
Usage: bash scripts/verify-security-boundaries.sh COMMAND [--verbose]

Commands:
  --doctor     Report prerequisites and test-database readiness without mutation.
  --isolate-legacy  One-time migration: move pre-v1 evidence (a v2/ tree, an
                    in-root latest.json) to a retained sibling archive.
  list         List stable lanes and required case IDs.
  bootstrap|recovery|push|migration|ingress|audit|updates|contracts
               Run one lane and publish source-bound evidence.
  all          Run every lane and reject the first missing or failed case.
  evidence     Validate the latest evidence manifest, source fingerprint and log hash.

Evidence: test-results/security-boundaries/<run-id>/manifest.json
Prepare the disposable database when needed with: bash scripts/load-test-schema.sh
EOF
}

contains_lane() {
  local wanted="$1" lane
  for lane in "${LANES[@]}"; do
    [[ "$lane" == "$wanted" ]] && return 0
  done
  return 1
}

need() { command -v "$1" >/dev/null 2>&1; }

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
for (const entry of registry.cases) console.log(`${entry.lane}\t${entry.caseId}`);
NODE
}

source_fingerprint() {
  "$NODE_BIN" "$FINGERPRINT_TOOL" compute --root "$ROOT"
}

evidence_adapter_ready() {
  [[ -n "$NODE_BIN" && -f "$FINGERPRINT_TOOL" && ! -L "$FINGERPRINT_TOOL" &&
    -f "$PUBLICATION_TOOL" && ! -L "$PUBLICATION_TOOL" &&
    -f "$JSON_TOOL" && ! -L "$JSON_TOOL" ]]
}

boundary_evidence_adapter() {
  "$NODE_BIN" --input-type=module <<'NODE'
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

const { assertClosedSchema, canonicalJson, parseStrictJson } = await import(pathToFileURL(process.env.SEC_JSON_TOOL));
const { publishVerifiedGeneration, readVerifiedLatest } = await import(pathToFileURL(process.env.SEC_PUBLICATION_TOOL));
const { parseFingerprint } = await import(pathToFileURL(process.env.SEC_FINGERPRINT_TOOL));

const MANIFEST_SCHEMA = 'setjoin.security-program.security-boundaries-manifest/v2';
const METRICS_SCHEMA = 'setjoin.security-program.security-boundaries-metrics/v2';
const ARTIFACT_SCHEMA = 'setjoin.security-program.security-boundaries-artifact/v2';

function adapterFail(code, message) {
  const error = new Error(message);
  error.adapterCode = code;
  throw error;
}

function exactKeys(value, required, name) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) adapterFail('E_SECURITY_EVIDENCE_INVALID', `${name} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...required].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    adapterFail('E_SECURITY_EVIDENCE_INVALID', `${name} fields are not closed`);
  }
}

function loadRegistry() {
  const registry = parseStrictJson(fs.readFileSync(process.env.SEC_REGISTRY, 'utf8'));
  exactKeys(registry, ['schemaVersion', 'plan', 'cases'], 'registry');
  if (registry.schemaVersion !== 1 || typeof registry.plan !== 'string' || !Array.isArray(registry.cases) || registry.cases.length !== 8) {
    adapterFail('E_SECURITY_EVIDENCE_INVALID', 'registry identity is invalid');
  }
  const lanes = new Set();
  for (const row of registry.cases) {
    // ER4 (deep-security plan): the registry case schema gains an optional
    // reopenedOccurrenceIds[] array. The key set stays closed: caseId/lane are
    // required, reopenedOccurrenceIds is the only permitted addition, and
    // unknown keys are still rejected.
    const rowKeys = Object.keys(row).sort();
    const requiredKeys = ['caseId', 'lane'];
    const allowedKeys = ['caseId', 'lane', 'reopenedOccurrenceIds'];
    if (requiredKeys.some((k) => !rowKeys.includes(k)) || rowKeys.some((k) => !allowedKeys.includes(k))) {
      adapterFail('E_SECURITY_EVIDENCE_INVALID', 'registry case fields are not closed');
    }
    if (row.reopenedOccurrenceIds !== undefined) {
      const reopened = row.reopenedOccurrenceIds;
      if (!Array.isArray(reopened) || reopened.some((id) => !/^occ_[0-9a-f]{24}$/.test(id))) {
        adapterFail('E_SECURITY_EVIDENCE_INVALID', 'registry reopenedOccurrenceIds is invalid');
      }
    }
    if (typeof row.lane !== 'string' || typeof row.caseId !== 'string' || !/^[a-z][a-z-]*$/.test(row.lane) || !/^SEC-[A-Z0-9-]+$/.test(row.caseId) || lanes.has(row.lane)) {
      adapterFail('E_SECURITY_EVIDENCE_INVALID', 'registry case identity is invalid');
    }
    lanes.add(row.lane);
  }
  return registry;
}

function validateManifest(manifest, output, { requirePassed, expectedFingerprint } = {}) {
  assertClosedSchema(manifest, {
    schema: MANIFEST_SCHEMA,
    required: ['lane', 'caseId', 'verdict', 'sourceFingerprint', 'metrics', 'exitCode', 'artifacts'],
    name: 'security-boundary manifest',
  });
  const registry = loadRegistry();
  const expectedCase = registry.cases.find((row) => row.lane === manifest.lane);
  if (!expectedCase || manifest.caseId !== expectedCase.caseId) adapterFail('E_SECURITY_EVIDENCE_INVALID', 'lane and case do not match the registry');
  if (!['passed', 'failed'].includes(manifest.verdict)) adapterFail('E_SECURITY_EVIDENCE_INVALID', 'manifest verdict is invalid');
  if (!Number.isSafeInteger(manifest.exitCode) || manifest.exitCode < 0 || manifest.exitCode > 255) adapterFail('E_SECURITY_EVIDENCE_INVALID', 'manifest exitCode is invalid');
  if ((manifest.verdict === 'passed') !== (manifest.exitCode === 0)) adapterFail('E_SECURITY_EVIDENCE_INVALID', 'manifest verdict and exitCode disagree');
  if (requirePassed && (manifest.verdict !== 'passed' || manifest.exitCode !== 0)) adapterFail('E_SECURITY_EVIDENCE_INVALID', 'latest evidence is not passed');

  assertClosedSchema(manifest.metrics, {
    schema: METRICS_SCHEMA,
    required: ['durationMs', 'logBytes'],
    name: 'security-boundary metrics',
  });
  if (!Number.isSafeInteger(manifest.metrics.durationMs) || manifest.metrics.durationMs < 0
      || !Number.isSafeInteger(manifest.metrics.logBytes) || manifest.metrics.logBytes !== output.length) {
    adapterFail('E_SECURITY_EVIDENCE_INVALID', 'manifest metrics are invalid');
  }

  if (!Array.isArray(manifest.artifacts) || manifest.artifacts.length !== 1) adapterFail('E_SECURITY_EVIDENCE_INVALID', 'manifest must contain exactly one artifact');
  const artifact = manifest.artifacts[0];
  assertClosedSchema(artifact, {
    schema: ARTIFACT_SCHEMA,
    required: ['path', 'sha256', 'size'],
    name: 'security-boundary artifact',
  });
  if (artifact.path !== 'output.log' || !/^[0-9a-f]{64}$/.test(artifact.sha256)
      || !Number.isSafeInteger(artifact.size) || artifact.size !== output.length
      || crypto.createHash('sha256').update(output).digest('hex') !== artifact.sha256) {
    adapterFail('E_SECURITY_EVIDENCE_INVALID', 'output.log artifact identity is invalid');
  }

  let actual;
  let expected;
  try {
    actual = parseFingerprint(manifest.sourceFingerprint);
    if (expectedFingerprint !== undefined) expected = parseFingerprint(expectedFingerprint);
  } catch (error) {
    adapterFail('E_SECURITY_EVIDENCE_VERSION', error.message);
  }
  if (expected && actual.value !== expected.value) adapterFail('E_SECURITY_EVIDENCE_STALE', 'evidence source is stale');
  return manifest;
}

async function publish() {
  const output = fs.readFileSync(process.env.SEC_LOG);
  const manifest = validateManifest({
    schema: MANIFEST_SCHEMA,
    lane: process.env.SEC_LANE,
    caseId: process.env.SEC_CASE,
    verdict: process.env.SEC_VERDICT,
    sourceFingerprint: process.env.SEC_SOURCE,
    metrics: {
      schema: METRICS_SCHEMA,
      durationMs: Number(process.env.SEC_DURATION_MS),
      logBytes: output.length,
    },
    exitCode: Number(process.env.SEC_EXIT),
    artifacts: [{
      schema: ARTIFACT_SCHEMA,
      path: 'output.log',
      sha256: crypto.createHash('sha256').update(output).digest('hex'),
      size: output.length,
    }],
  }, output);
  const result = publishVerifiedGeneration({
    generationsDirectory: process.env.SEC_GENERATIONS_ROOT,
    pointerPath: process.env.SEC_LATEST_POINTER,
    generationId: process.env.SEC_RUN_ID,
    files: { 'manifest.json': canonicalJson(manifest), 'output.log': output },
  });
  process.stdout.write(JSON.stringify(result));
}

async function verify() {
  const verified = readVerifiedLatest({
    generationsDirectory: process.env.SEC_GENERATIONS_ROOT,
    pointerPath: process.env.SEC_LATEST_POINTER,
  });
  const generationsRoot = path.resolve(process.env.SEC_GENERATIONS_ROOT);
  const generationDirectory = path.resolve(generationsRoot, verified.generationId);
  if (path.dirname(generationDirectory) !== generationsRoot) adapterFail('E_SECURITY_EVIDENCE_INVALID', 'generation resolved outside the evidence root');
  const actualFiles = fs.readdirSync(generationDirectory).sort();
  // The publication lib's durable-write protocol leaves a fourth file — the
  // survivor marker — in every committed generation; the closed-set check
  // must match the publication format (see
  // scripts/lib/security-program-publication.mjs PUBLICATION_SURVIVOR_FILE).
  const expectedFiles = ['generation-receipt.json', 'manifest.json', 'output.log', 'publication-survivor.json'];
  if (actualFiles.length !== expectedFiles.length || actualFiles.some((entry, index) => entry !== expectedFiles[index])) {
    adapterFail('E_SECURITY_EVIDENCE_INVALID', 'generation file set is not closed');
  }
  const manifestPath = path.join(generationDirectory, 'manifest.json');
  const outputPath = path.join(generationDirectory, 'output.log');
  for (const [filename, name] of [[manifestPath, 'manifest.json'], [outputPath, 'output.log']]) {
    const info = fs.lstatSync(filename);
    if (!info.isFile() || info.isSymbolicLink()) adapterFail('E_SECURITY_EVIDENCE_INVALID', `${name} must be a regular in-root file`);
  }
  const output = fs.readFileSync(outputPath);
  const manifest = validateManifest(parseStrictJson(fs.readFileSync(manifestPath, 'utf8')), output, {
    requirePassed: true,
    expectedFingerprint: process.env.SEC_EXPECTED_SOURCE,
  });
  process.stdout.write(JSON.stringify({ generationId: verified.generationId, lane: manifest.lane, caseId: manifest.caseId }));
}

try {
  if (process.env.SEC_ADAPTER_MODE === 'publish') await publish();
  else if (process.env.SEC_ADAPTER_MODE === 'verify') await verify();
  else adapterFail('E_SECURITY_EVIDENCE_INVALID', 'unknown evidence adapter mode');
} catch (error) {
  const code = error.adapterCode ?? 'E_SECURITY_EVIDENCE_INVALID';
  process.stderr.write(`${code} ${error.code ?? ''} ${error.message}\n`);
  process.exit(1);
}
NODE
}

doctor() {
  local tool state=ready
  echo "security-boundaries doctor"
  for tool in git shasum go cargo node pg_prove psql; do
    if need "$tool"; then
      echo "  $tool: ready"
    else
      echo "  $tool: missing"
      state=missing
    fi
  done
  if need psql && psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" -Atqc 'SELECT 1' >/dev/null 2>&1; then
    echo "  database: ready ($DB_NAME)"
  else
    echo "  database: unavailable ($DB_NAME); prepare with bash scripts/load-test-schema.sh"
    state=missing
  fi
  if evidence_adapter_ready; then
    echo "  evidence-adapter: ready (v2 immutable lineage)"
    echo "  source: $(source_fingerprint)"
  else
    echo "  evidence-adapter: missing (node or required security-program module unavailable)"
    echo "  source: unavailable"
    state=missing
  fi
  for lane in "${LANES[@]}"; do
    echo "  $lane: case=$(case_id "$lane"); rerun=bash scripts/verify-security-boundaries.sh $lane"
  done
  [[ "$state" == ready ]]
}

pg_cases() {
  pg_prove -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" "$@"
}

run_lane_command() {
  case "$1" in
    bootstrap)
      (cd "$ROOT/mailctl" && go test ./... -run 'BootstrapAdmin|Restore' -count=1)
      (cd "$ROOT/mailserver" && go test ./cmd/mailserverd ./internal/admin -run 'Setup|Admin|RouteInventory' -count=1)
      pg_cases "$ROOT/mailserver/sql/tests/ensure_admin.pg"
      ;;
    recovery)
      (cd "$ROOT/mailserver" && go test ./internal/backup ./internal/restore -count=1)
      pg_cases "$ROOT/mailserver/sql/tests/restore_config_policy.pg"
      ;;
    push)
      (cd "$ROOT/authserver" && go test ./internal/authn ./internal/handlers -run 'Push|MFAApprove|Device' -count=1)
      cargo test --manifest-path "$ROOT/clients/Cargo.toml" -p guard-core push_approval -- --nocapture
      ;;
    migration)
      (cd "$ROOT/shared" && go test ./ssrf -count=1)
      (cd "$ROOT/mailserver" && go test ./internal/migration -count=1)
      pg_cases "$ROOT/mailserver/sql/tests/migration_orchestrate.pg"
      ;;
    ingress)
      (cd "$ROOT/shared" && go test ./httputil ./threat -count=1)
      (cd "$ROOT/mailserver" && go test ./internal/admin ./internal/caldav ./internal/carddav -count=1)
      ;;
    audit)
      (cd "$ROOT/shared" && go test ./pgxutil -count=1)
      pg_cases "$ROOT/mailserver/sql/tests/audit_chain_cutover.pg"
      ;;
    updates)
      (cd "$ROOT/shared" && go test ./release -count=1)
      (cd "$ROOT/mailserver" && go test ./internal/updates -count=1)
      ;;
    contracts)
      bash "$ROOT/scripts/check-route-inventory.sh"
      bash "$ROOT/scripts/check-openapi-coverage.sh" --self-test
      bash "$ROOT/scripts/check-openapi-visibility.sh" --self-test
      bash "$ROOT/scripts/check-agent-context-budget.sh"
      bash "$ROOT/scripts/check-quality-tool-catalog.sh" --self-test
      ;;
    *) return 2 ;;
  esac
}

publish() {
  local lane="$1" verdict="$2" started="$3" ended="$4" tmp="$5" exit_code="$6" source="$7"
  local run_id duration_ms published
  run_id="$(date -u +%Y%m%dT%H%M%SZ)-$(git -C "$ROOT" rev-parse --short=8 HEAD)-$$-$lane"
  duration_ms="$((ended - started))"
  published="$(SEC_ADAPTER_MODE=publish SEC_LANE="$lane" SEC_CASE="$(case_id "$lane")" SEC_VERDICT="$verdict" \
  SEC_SOURCE="$source" SEC_DURATION_MS="$duration_ms" SEC_EXIT="$exit_code" \
  SEC_LOG="$tmp/output.log" SEC_RUN_ID="$run_id" SEC_REGISTRY="$REGISTRY" \
  SEC_GENERATIONS_ROOT="$GENERATIONS_ROOT" SEC_LATEST_POINTER="$LATEST_POINTER" \
  SEC_FINGERPRINT_TOOL="$FINGERPRINT_TOOL" SEC_PUBLICATION_TOOL="$PUBLICATION_TOOL" SEC_JSON_TOOL="$JSON_TOOL" \
    boundary_evidence_adapter)"
  [[ -n "$published" ]] || return 1
  PUBLISHED_OUTPUT="$GENERATIONS_ROOT/$run_id/output.log"
  rm -rf -- "$tmp"
  echo "security-boundaries: $verdict lane=$lane case=$(case_id "$lane") manifest=${GENERATIONS_ROOT#"$ROOT"/}/$run_id/manifest.json"
}

run_lane() {
  local lane="$1" started ended tmp result verdict source_before source_after
  for tool in git shasum go cargo node pg_prove psql; do
    need "$tool" || {
      echo "E_SECURITY_PREREQUISITE lane=$lane missing=$tool" >&2
      return 2
    }
  done
  evidence_adapter_ready || {
    echo "E_SECURITY_PREREQUISITE lane=$lane missing=v2-evidence-adapter" >&2
    return 2
  }
  mkdir -p "$(dirname "$RESULTS_ROOT")"
  tmp="$(mktemp -d "$RESULTS_ROOT.tmp.XXXXXX")"
  source_before="$(source_fingerprint)"
  started="$("$NODE_BIN" -e 'process.stdout.write(String(Date.now()))')"
  set +e
  (
    set -e
    run_lane_command "$lane"
  ) >"$tmp/output.log" 2>&1
  result=$?
  set -e
  ended="$("$NODE_BIN" -e 'process.stdout.write(String(Date.now()))')"
  source_after="$(source_fingerprint)"
  if [[ "$source_before" != "$source_after" ]]; then
    echo "E_SECURITY_SOURCE_CHANGED lane=$lane source changed during verification" >&2
    return 1
  fi
  if [[ "$result" -eq 0 ]]; then verdict=passed; else verdict=failed; fi
  publish "$lane" "$verdict" "$started" "$ended" "$tmp" "$result" "$source_before"
  if [[ "$VERBOSE" -eq 1 || "$result" -ne 0 ]]; then
    cat "$PUBLISHED_OUTPUT"
  fi
  return "$result"
}

validate_evidence() {
  local verified generation_id
  # (The pre-flight legacy guard already refuses any in-root latest.json, so a
  # missing pointer here is simply "nothing published yet".)
  if [[ ! -e "$LATEST_POINTER" && ! -L "$LATEST_POINTER" ]]; then
    echo "E_SECURITY_EVIDENCE_MISSING latest=$LATEST_POINTER" >&2
    return 1
  fi
  verified="$(SEC_ADAPTER_MODE=verify SEC_REGISTRY="$REGISTRY" SEC_EXPECTED_SOURCE="$(source_fingerprint)" \
  SEC_GENERATIONS_ROOT="$GENERATIONS_ROOT" SEC_LATEST_POINTER="$LATEST_POINTER" \
  SEC_FINGERPRINT_TOOL="$FINGERPRINT_TOOL" SEC_PUBLICATION_TOOL="$PUBLICATION_TOOL" SEC_JSON_TOOL="$JSON_TOOL" \
    boundary_evidence_adapter)" || return 1
  generation_id="$("$NODE_BIN" -e 'process.stdout.write(JSON.parse(process.argv[1]).generationId)' "$verified")"
  echo "security-boundaries evidence: PASS manifest=${GENERATIONS_ROOT#"$ROOT"/}/$generation_id/manifest.json"
}

if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then
  return 0
fi

command_name="${1:---help}"
shift || true
if [[ $# -gt 1 || ($# -eq 1 && "$1" != "--verbose") ]]; then
  usage >&2
  exit 2
fi
[[ "${1:-}" == "--verbose" ]] && VERBOSE=1

# Legacy-layout guard: a v2/ tree or an in-root latest.json is residue of the
# pre-v1 runner. The publication library would treat them as generation
# directories and fail confusingly mid-publication — fail here, with the fix.
if [[ "$command_name" != "--isolate-legacy" && "$command_name" != "--help" && "$command_name" != "-h" && "$command_name" != "--doctor" ]]; then
  legacy=""
  [ -e "$RESULTS_ROOT/v2" ] && legacy="$legacy v2/"
  [ -e "$RESULTS_ROOT/latest.json" ] && legacy="$legacy latest.json"
  if [ -n "$legacy" ]; then
    echo "legacy evidence-layout residue detected ($legacy ) in $RESULTS_ROOT — refusing to publish." >&2
    echo "Run: bash $0 --isolate-legacy   (moves them to a retained sibling archive; nothing is deleted)" >&2
    exit 2
  fi
fi

case "$command_name" in
  --help | -h) usage ;;
  --doctor) doctor ;;
  --isolate-legacy)
    # One-time evidence-preserving migration. Earlier runners nested generations
    # under v2/ and kept latest.json inside the evidence root; the publication
    # library scans the evidence root and treats every non-hidden entry as a
    # generation directory, so those legacy entries make a fresh v1 publication
    # fail with "generation history exists without an authoritative pointer".
    # This moves EVERYTHING currently in the evidence root (legacy generations,
    # the v2/ tree, any stale pointer) to a sibling archive directory. Nothing
    # is deleted; the new publication starts from a clean root.
    # Refuse no-op or dangerous runs: nothing to isolate, or the moved-out
    # pointer already exists (isolating twice would orphan it).
    if [ ! -e "$RESULTS_ROOT/v2" ] && [ ! -e "$RESULTS_ROOT/latest.json" ]; then
      echo "nothing to isolate: no v2/ tree and no in-root latest.json under $RESULTS_ROOT" >&2
      exit 2
    fi
    if [ -e "$LATEST_POINTER" ]; then
      echo "refusing to isolate: the moved-out pointer $LATEST_POINTER already exists — isolate-legacy already ran" >&2
      exit 2
    fi
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    dest="${RESULTS_ROOT}-legacy-${stamp}"
    mkdir -p "$dest"
    moved=0
    shopt -s dotglob nullglob
    for entry in "$RESULTS_ROOT"/*; do
      [ -e "$entry" ] || continue
      mv "$entry" "$dest/" && moved=$((moved + 1))
    done
    shopt -u dotglob
    echo "isolated $moved legacy evidence entries -> $dest (retained; nothing deleted)"
    manifest="$ROOT/docs/verification/security-boundary-evidence-manifest.json"
    if [ -f "$manifest" ]; then
      echo "NOTE: if docs/verification/security-boundary-evidence-manifest.json names generations that lived under security-boundaries/v2/, they were just isolated — republish the lanes and re-register the manifest (ER7 second-voice fix plan)."
    fi
    ;;
  list) list_cases ;;
  all)
    for lane in "${LANES[@]}"; do run_lane "$lane"; done
    ;;
  evidence) validate_evidence ;;
  *)
    contains_lane "$command_name" || {
      echo "E_SECURITY_CLI_UNKNOWN command=$command_name" >&2
      usage >&2
      exit 2
    }
    run_lane "$command_name"
    ;;
esac
