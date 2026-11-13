#!/usr/bin/env bash
# Office Foundation / Drive History O0-DX verification front door.
#
# This slice validates the frozen contracts and runs a dependency-free contract
# simulation. It does not enable a feature, start an editor, read credentials,
# access a customer tenant, or claim renderer compatibility. The implemented
# provider-core/WOPI unit lane attaches in `core`; live Collabora remains an
# explicit external gate.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
PROVIDER_MANIFEST="${OFFICE_PROVIDER_MANIFEST:-$ROOT/config/office-provider-manifest-v1.json}"
ACCEPTANCE_MANIFEST="${OFFICE_ACCEPTANCE_MANIFEST:-$ROOT/config/office-v1-acceptance-manifest.json}"
EVIDENCE_ROOT="${OFFICE_EVIDENCE_ROOT:-$ROOT/test-results/office-foundation}"
MODE="doctor"
JSON_MODE=0
SELF_TEST=0
RUN_ID=""
CORE_TEST_STATUS="not_run"
POSITIONAL=()

usage() {
  cat <<'EOF'
Usage: bash scripts/verify-office-foundation.sh MODE [options]

Modes:
  doctor             Read-only local prerequisite and manifest report (default)
  quick              Offline deterministic fake-provider contract proof
  core               Manifest + provider-core contract lane; no live editor
  live-collabora     Optional external Collabora readiness gate
  evidence FILE      Verify a retained run manifest and source digests
  explain CODE       Explain one stable Office diagnostic code offline

Options:
  --json             Emit one machine-readable summary object
  --run-id ID        Use a bounded evidence run ID for quick/core
  --self-test        Run disposable planted-failure checks for this front door
  -h, --help         Show this help

The fake quick path requires no Collabora, database, object store, credentials,
customer data, browser session, or network. A live profile requires operator-
supplied, approved evidence and remains a separate rollout gate.
EOF
}

die() {
  echo "$1" >&2
  exit 1
}

is_safe_id() {
  [[ "$1" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$ ]]
}

hash_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file" | awk '{print $1}'
  else
    return 1
  fi
}

json_file_is_object() {
  local file="$1"
  node - "$file" <<'NODE'
const fs = require('node:fs');
const file = process.argv[2];
try {
  const value = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!value || Array.isArray(value) || typeof value !== 'object') process.exit(1);
} catch {
  process.exit(1);
}
NODE
}

validate_manifests() {
  [[ -f "$PROVIDER_MANIFEST" ]] || { echo "E_OFFICE_MANIFEST_INVALID missing provider manifest: $PROVIDER_MANIFEST" >&2; return 1; }
  [[ -f "$ACCEPTANCE_MANIFEST" ]] || { echo "E_OFFICE_MANIFEST_INVALID missing acceptance manifest: $ACCEPTANCE_MANIFEST" >&2; return 1; }
  json_file_is_object "$PROVIDER_MANIFEST" || { echo "E_OFFICE_MANIFEST_INVALID provider manifest is not an object" >&2; return 1; }
  json_file_is_object "$ACCEPTANCE_MANIFEST" || { echo "E_OFFICE_MANIFEST_INVALID acceptance manifest is not an object" >&2; return 1; }
  node - "$PROVIDER_MANIFEST" "$ACCEPTANCE_MANIFEST" <<'NODE'
const fs = require('node:fs');
const [providerPath, acceptancePath] = process.argv.slice(2);
const provider = JSON.parse(fs.readFileSync(providerPath, 'utf8'));
const acceptance = JSON.parse(fs.readFileSync(acceptancePath, 'utf8'));
const fail = (message) => { console.error(`E_OFFICE_MANIFEST_INVALID ${message}`); process.exit(1); };
const defaults = ['feature.drive', 'feature.drive_history', 'feature.office_editing', 'feature.office_local_open'];
if (provider.schemaVersion !== 'setjoin.office.provider-manifest/v1') fail('unexpected provider schemaVersion');
if (acceptance.schemaVersion !== 'setjoin.office.acceptance-manifest/v1') fail('unexpected acceptance schemaVersion');
for (const key of defaults) {
  if (provider.featureDefaults?.[key] !== 'on' || acceptance.featureDefaults?.[key] !== 'on') fail(`${key} must remain default ON`);
}
if (provider.authority?.owner !== 'setjoin') fail('Drive authority must remain setjoin');
if (provider.authority?.providerCredentials !== 'none') fail('provider credentials must be none');
if (provider.webPolicy?.offlineEditing !== 'not_advertised') fail('web offline editing must not be advertised');
if (provider.webPolicy?.localOpen !== 'desktop_only') fail('local open must remain desktop-only');
const providers = provider.providers;
if (!Array.isArray(providers) || !providers.some((row) => row.id === 'fake' && row.status === 'test_only')) fail('fake test provider row missing');
const collabora = providers.find((row) => row.id === 'collabora');
if (!collabora || collabora.status !== 'external_gate') fail('Collabora must remain an external gate');
if (collabora.dataEgress !== 'wopi_host_only_by_default') fail('Collabora egress posture is not explicit');
if (acceptance.releaseClaimState !== 'blocked_until_exact_evidence') fail('release claims must remain blocked');
if (acceptance.corpus?.minimumFiles !== 50) fail('V1 corpus minimum must be 50');
if (acceptance.corpus?.upstreamRenderingKernel !== 'excluded_from_compatibility_tests') fail('upstream rendering kernel must be excluded from compatibility tests');
if (acceptance.retryPolicy?.functionalCaseRetries !== 0) fail('functional retries must be zero');
if (acceptance.performance?.openCohortsPerShard !== 500 || acceptance.performance?.activeEditorsPerShard !== 50) fail('concurrency baseline drifted');
if (!Array.isArray(acceptance.requiredCases) || acceptance.requiredCases.length < 5) fail('required case manifest is incomplete');
if (acceptance.evidence?.credentials !== 'never_retained' || acceptance.evidence?.documentBytes !== 'never_retained') fail('evidence retention boundary is unsafe');
console.log('office manifests: PASS');
NODE
}

admitted_feature_defaults_json() {
  # DX-T3 correction: doctor JSON reports the admitted feature registry copied
  # from the versioned provider manifest (validate_manifests already proved it
  # matches the acceptance manifest), never a hardcoded policy claim.
  node - "$PROVIDER_MANIFEST" <<'NODE'
const fs = require('node:fs');
const provider = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
process.stdout.write(JSON.stringify(provider.featureDefaults));
NODE
}

external_gate_report() {
  local missing=()
  command -v curl >/dev/null 2>&1 || missing+=("curl")
  [[ -n "${OFFICE_COLLABORA_URL:-}" ]] || missing+=("OFFICE_COLLABORA_URL")
  [[ -n "${OFFICE_COLLABORA_IMAGE_DIGEST:-}" ]] || missing+=("OFFICE_COLLABORA_IMAGE_DIGEST")
  [[ -n "${OFFICE_COLLABORA_SOURCE_DIGEST:-}" ]] || missing+=("OFFICE_COLLABORA_SOURCE_DIGEST")
  [[ -n "${OFFICE_COLLABORA_FONT_DIGEST:-}" ]] || missing+=("OFFICE_COLLABORA_FONT_DIGEST")
  if [[ -z "${OFFICE_COLLABORA_LICENSE_EVIDENCE:-}" || ! -f "${OFFICE_COLLABORA_LICENSE_EVIDENCE:-}" ]]; then
    missing+=("OFFICE_COLLABORA_LICENSE_EVIDENCE")
  fi
  if ((${#missing[@]})); then
    printf '%s\n' "${missing[*]}"
    return 1
  fi
  return 0
}

run_fake_contract() {
  local output="$1"
  node >"$output" <<'NODE'
const fail = (message) => { console.error(`E_OFFICE_FAKE_CONTRACT ${message}`); process.exit(1); };
const state = {
  mainVersion: 'v1',
  nextVersion: 2,
  nextReceipt: 1,
  nextBranch: 1,
  receipts: [],
  history: []
};
const launch = { sessionId: 'session-1', baseVersion: state.mainVersion, lockEpoch: 1 };
if (!launch.sessionId || launch.baseVersion !== 'v1') fail('launch did not bind a Drive base');
const accepted = { receiptId: `receipt-${state.nextReceipt++}`, responseClass: 'accepted', expectedBase: launch.baseVersion, resultVersion: `v${state.nextVersion++}` };
state.mainVersion = accepted.resultVersion;
state.receipts.push(accepted);
state.history.push({ source: 'office', kind: 'office.save', receiptId: accepted.receiptId, versionId: accepted.resultVersion });
const stale = { receiptId: `receipt-${state.nextReceipt++}`, responseClass: 'branched', expectedBase: launch.baseVersion, resultBranch: `branch-${state.nextBranch++}`, resultVersion: `v${state.nextVersion++}` };
state.receipts.push(stale);
state.history.push({ source: 'office', kind: 'office.save.branch', receiptId: stale.receiptId, branchId: stale.resultBranch, versionId: stale.resultVersion });
if (state.mainVersion !== accepted.resultVersion) fail('stale save moved Main');
if (state.receipts.length !== 2 || state.history.length !== 2) fail('receipt/history cardinality is not deterministic');
process.stdout.write(JSON.stringify({
  contract: 'setjoin.office.provider-core/v1',
  status: 'pass',
  claimBoundary: 'contract_scaffold_not_production_evidence',
  launch: 'pass',
  lock: 'pass',
  receipt: accepted.receiptId,
  version: accepted.resultVersion,
  history: 'pass',
  staleSave: 'pass',
  branch: stale.resultBranch,
  mainUnchanged: true,
  responseClasses: ['accepted', 'branched']
}, null, 2) + '\n');
NODE
}

write_evidence() {
  local mode="$1" result_dir="$2" fake_result="$3"
  local provider_sha acceptance_sha
  provider_sha="$(hash_file "$PROVIDER_MANIFEST")" || die "E_OFFICE_TOOL_MISSING SHA-256 tool unavailable"
  acceptance_sha="$(hash_file "$ACCEPTANCE_MANIFEST")" || die "E_OFFICE_TOOL_MISSING SHA-256 tool unavailable"
  local manifest="$result_dir/manifest.json"
  PROVIDER_MANIFEST="$PROVIDER_MANIFEST" ACCEPTANCE_MANIFEST="$ACCEPTANCE_MANIFEST" \
    PROVIDER_SHA="$provider_sha" ACCEPTANCE_SHA="$acceptance_sha" \
    RUN_ID="$RUN_ID" VERIFY_MODE="$mode" CORE_TEST_STATUS="$CORE_TEST_STATUS" RESULT_DIR="$result_dir" FAKE_RESULT="$fake_result" \
    node - "$manifest" <<'NODE'
const fs = require('node:fs');
const crypto = require('node:crypto');
const [output] = process.argv.slice(2);
const hash = (path) => crypto.createHash('sha256').update(fs.readFileSync(path)).digest('hex');
const fake = JSON.parse(fs.readFileSync(process.env.FAKE_RESULT, 'utf8'));
const result = {
  schemaVersion: 'setjoin.office.verification/v1',
  runId: process.env.RUN_ID,
  mode: process.env.VERIFY_MODE,
  verdict: 'pass',
  claimBoundary: 'contract_scaffold_not_production_evidence',
  createdAt: new Date().toISOString(),
  stages: [
    { id: 'manifest', verdict: 'pass' },
    { id: 'fake-provider-contract', verdict: fake.status, mainUnchanged: fake.mainUnchanged },
    { id: 'office-core-unit-tests', verdict: process.env.CORE_TEST_STATUS }
  ],
  fakeProvider: fake,
  coreTestStatus: process.env.CORE_TEST_STATUS,
  externalGates: { collabora: 'external_gate' },
  sourceManifests: {
    provider: { path: process.env.PROVIDER_MANIFEST, sha256: process.env.PROVIDER_SHA },
    acceptance: { path: process.env.ACCEPTANCE_MANIFEST, sha256: process.env.ACCEPTANCE_SHA }
  },
  sourceDigestRecheck: {
    provider: hash(process.env.PROVIDER_MANIFEST),
    acceptance: hash(process.env.ACCEPTANCE_MANIFEST)
  },
  evidenceRoot: process.env.RESULT_DIR
};
fs.writeFileSync(output, JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
fs.writeFileSync(`${process.env.RESULT_DIR}/latest.json`, JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
NODE
  echo "$manifest"
}

doctor() {
  local fake="ready" collabora="external_gate" node_status="pass" hash_status="pass"
  command -v node >/dev/null 2>&1 || node_status="missing"
  hash_file "$PROVIDER_MANIFEST" >/dev/null 2>&1 || hash_status="missing"
  if [[ "$node_status" != pass || "$hash_status" != pass ]]; then
    if ((JSON_MODE)); then
      printf '{"schemaVersion":"setjoin.office.doctor/v1","verdict":"blocked","fakeProvider":"%s","collabora":"%s","node":"%s","sha256":"%s"}\n' "$fake" "$collabora" "$node_status" "$hash_status"
    else
      printf 'BLOCKED node=%s sha256=%s\n' "$node_status" "$hash_status"
    fi
    return 1
  fi
  validate_manifests >/dev/null
  local live_note="missing external prerequisites"
  if external_gate_report >/dev/null 2>&1; then
    live_note="prerequisites present; live adapter evidence still required"
  fi
  if ((JSON_MODE)); then
    local feature_defaults
    feature_defaults="$(admitted_feature_defaults_json)"
    printf '{"schemaVersion":"setjoin.office.doctor/v1","verdict":"pass","fakeProvider":"%s","collabora":"%s","liveNote":"%s","featureDefaults":%s}\n' "$fake" "$collabora" "$live_note" "$feature_defaults"
  else
    echo "PASS fake-provider   deterministic contract path ready"
    echo "EXTERNAL_GATE collabora   $live_note"
    echo "PASS feature-policy  Office and Drive controls are admitted by the pre-release default"
  fi
}

focused_run() {
  local mode="$1"
  validate_manifests >/dev/null
  [[ -n "$RUN_ID" ]] || RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
  is_safe_id "$RUN_ID" || die "E_OFFICE_INPUT_INVALID run ID contains unsafe characters"
  local result_dir="$EVIDENCE_ROOT/$RUN_ID"
  mkdir -p "$result_dir"
  chmod 700 "$result_dir"
  local fake_result="$result_dir/fake-result.json"
  run_fake_contract "$fake_result"
  CORE_TEST_STATUS="not_run"
  if [[ "$mode" == "core" ]]; then
    if [[ -f "$ROOT/mailserver/internal/office/handler_test.go" || -f "$ROOT/mailctl/office_test.go" ]]; then
      if {
        if [[ -f "$ROOT/mailserver/internal/office/handler_test.go" ]]; then
          (cd "$ROOT/mailserver" && go test ./internal/office -count=1)
        fi
        if [[ -f "$ROOT/mailctl/office_test.go" ]]; then
          (cd "$ROOT/mailctl" && go test ./... -run '^TestOffice' -count=1)
        fi
      } >"$result_dir/office-core.log" 2>&1; then
        CORE_TEST_STATUS="pass"
      else
        CORE_TEST_STATUS="fail"
        cat "$result_dir/office-core.log" >&2
        return 1
      fi
    else
      CORE_TEST_STATUS="contract_scaffold"
      echo "OFFICE_CORE_PENDING provider-core package is not present; retaining contract scaffold result" >"$result_dir/office-core.log"
    fi
  fi
  local manifest
  manifest="$(write_evidence "$mode" "$result_dir" "$fake_result")"
  if ((JSON_MODE)); then
    node - "$manifest" <<'NODE'
const fs = require('node:fs');
const value = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
process.stdout.write(JSON.stringify(value) + '\n');
NODE
  else
    echo "PASS $mode          fake contract launch=pass lock=pass receipt=pass version=pass history=pass stale-branch=pass main-unchanged=true"
    echo "EXTERNAL_GATE collabora   live WOPI/renderer/license evidence not present"
    echo "evidence=$manifest"
  fi
}

live_collabora() {
  validate_manifests >/dev/null
  local missing
  if missing="$(external_gate_report)"; then
    if ((JSON_MODE)); then
      printf '{"schemaVersion":"setjoin.office.live/v1","verdict":"external_gate","missing":[],"reason":"O2 live adapter evidence is not implemented in this contract slice","claim":"not_promoted"}\n'
    else
      echo "EXTERNAL_GATE collabora prerequisites are present; O2 live adapter evidence is still required"
    fi
    return 1
  fi
  if ((JSON_MODE)); then
    node - "$missing" <<'NODE'
const missing = process.argv[2].split(/\s+/).filter(Boolean);
process.stdout.write(JSON.stringify({schemaVersion:'setjoin.office.live/v1', verdict:'blocked', code:'E_OFFICE_EXTERNAL_GATE', missing, claim:'not_promoted'}) + '\n');
NODE
  else
    echo "E_OFFICE_EXTERNAL_GATE missing approved Collabora prerequisites: $missing" >&2
    echo "fix: provide the exact lab/customer evidence paths, then rerun: bash scripts/verify-office-foundation.sh live-collabora" >&2
  fi
  return 1
}

verify_evidence() {
  local manifest_path="${1:-}"
  [[ -n "$manifest_path" ]] || die "usage: verify-office-foundation.sh evidence <manifest.json>"
  [[ -f "$manifest_path" ]] || die "E_OFFICE_EVIDENCE_INVALID missing manifest: $manifest_path"
  node - "$manifest_path" >/dev/null <<'NODE'
const fs = require('node:fs');
const path = process.argv[2];
const value = JSON.parse(fs.readFileSync(path, 'utf8'));
const fail = (message) => { console.error(`E_OFFICE_EVIDENCE_INVALID ${message}`); process.exit(1); };
if (value.schemaVersion !== 'setjoin.office.verification/v1') fail('schemaVersion mismatch');
if (!value.runId || value.verdict !== 'pass') fail('manifest is not a passing retained run');
if (value.claimBoundary !== 'contract_scaffold_not_production_evidence') fail('claim boundary missing');
if (value.externalGates?.collabora !== 'external_gate') fail('external Collabora gate missing');
for (const key of ['provider', 'acceptance']) {
  const row = value.sourceManifests?.[key];
  if (!row?.path || !/^[0-9a-f]{64}$/.test(row.sha256)) fail(`${key} source digest missing`);
}
process.stdout.write('pass');
NODE
  local provider_path acceptance_path provider_expected acceptance_expected
  provider_path="$(node - "$manifest_path" <<'NODE'
const fs = require('node:fs');
const v = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
process.stdout.write(`${v.sourceManifests.provider.path}\n${v.sourceManifests.acceptance.path}`);
NODE
)"
  acceptance_path="$(printf '%s\n' "$provider_path" | sed -n '2p')"
  provider_path="$(printf '%s\n' "$provider_path" | sed -n '1p')"
  [[ -f "$provider_path" && -f "$acceptance_path" ]] || die "E_OFFICE_EVIDENCE_INVALID source manifest missing"
  provider_expected="$(node - "$manifest_path" <<'NODE'
const fs = require('node:fs');
const v = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
process.stdout.write(v.sourceManifests.provider.sha256);
NODE
)"
  acceptance_expected="$(node - "$manifest_path" <<'NODE'
const fs = require('node:fs');
const v = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
process.stdout.write(v.sourceManifests.acceptance.sha256);
NODE
)"
  [[ "$(hash_file "$provider_path")" == "$provider_expected" ]] || die "E_OFFICE_EVIDENCE_INVALID provider manifest hash mismatch"
  [[ "$(hash_file "$acceptance_path")" == "$acceptance_expected" ]] || die "E_OFFICE_EVIDENCE_INVALID acceptance manifest hash mismatch"
  if ((JSON_MODE)); then
    printf '{"schemaVersion":"setjoin.office.evidence/v1","verdict":"pass","manifest":"%s"}\n' "$manifest_path"
  else
    echo "evidence: PASS $manifest_path"
  fi
}

explain() {
  local code="${1:-}"
  case "$code" in
    E_OFFICE_PROVIDER_UNREADY)
      echo "$code: the selected provider is unavailable or not admitted; effect=online editing unavailable; fix=run doctor, inspect the provider/build gate, then rerun the named lane." ;;
    E_OFFICE_PROOF_REJECTED)
      echo "$code: a proof, token, capability, lock, or fence check failed; effect=the callback is denied without revealing file existence; fix=use the run ID and current authorization evidence, never retry with a broader credential." ;;
    E_OFFICE_SAVE_RECEIPT_REPLAY)
      echo "$code: a save response was retried after a commit; effect=the stored receipt/result is replayed and no second version is created; fix=refresh from Drive History and continue from the returned result." ;;
    E_OFFICE_UNSUPPORTED_OFFLINE_WEB)
      echo "$code: browser/PWA offline editing is outside V1; effect=web offers online editing or authorized preview/download only; fix=use an evidenced desktop local-open cell if permitted." ;;
    E_OFFICE_EXTERNAL_GATE)
      echo "$code: Collabora or another external evidence dependency is missing; effect=live editing is not promoted while Drive History and the fake contract remain independent; fix=provide approved build/source/font/license evidence and rerun live-collabora." ;;
    E_OFFICE_MANIFEST_INVALID)
      echo "$code: a versioned Office contract is missing, malformed, or violates a frozen boundary; effect=the lane fails closed; fix=review both manifests and rerun doctor." ;;
    E_OFFICE_EVIDENCE_INVALID)
      echo "$code: retained evidence is missing, malformed, or no longer matches its source digests; effect=the run cannot support a claim; fix=discard the stale run and rerun the exact lane." ;;
    E_OFFICE_FAKE_CONTRACT)
      echo "$code: deterministic contract simulation did not preserve receipt/version/history/branch invariants; effect=quick is red; fix=repair the provider-core implementation before adding a live editor." ;;
    *)
      echo "E_OFFICE_UNKNOWN_CODE unknown diagnostic code: ${code:-<empty>}" >&2
      return 1
      ;;
  esac
}

self_test() {
  local tmp
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/setjoin-office-foundation-selftest.XXXXXX")"
  trap 'rm -rf "$tmp"' RETURN
  # DX-T3 paired human/JSON regression: after doctor's own manifest validation,
  # both output modes must describe the same admitted feature registry and the
  # stale default_off claim must stay gone.
  OFFICE_EVIDENCE_ROOT="$tmp/evidence" "$SCRIPT" doctor >"$tmp/doctor-human.txt"
  grep -q "PASS feature-policy  Office and Drive controls are admitted by the pre-release default" "$tmp/doctor-human.txt" || {
    echo "office verification self-test: human doctor lost the admitted-default feature-policy line" >&2
    return 1
  }
  OFFICE_EVIDENCE_ROOT="$tmp/evidence" "$SCRIPT" doctor --json >"$tmp/doctor.json"
  PROVIDER_MANIFEST="$PROVIDER_MANIFEST" ACCEPTANCE_MANIFEST="$ACCEPTANCE_MANIFEST" DOCTOR_JSON="$tmp/doctor.json" node <<'NODE' || return 1
const fs = require('node:fs');
const fail = (message) => { console.error(`office verification self-test: ${message}`); process.exit(1); };
const doctor = JSON.parse(fs.readFileSync(process.env.DOCTOR_JSON, 'utf8'));
const provider = JSON.parse(fs.readFileSync(process.env.PROVIDER_MANIFEST, 'utf8'));
const acceptance = JSON.parse(fs.readFileSync(process.env.ACCEPTANCE_MANIFEST, 'utf8'));
if (doctor.schemaVersion !== 'setjoin.office.doctor/v1') fail('doctor JSON schemaVersion drifted');
if (doctor.verdict !== 'pass') fail('doctor JSON verdict is not pass');
if (JSON.stringify(doctor.featureDefaults) !== JSON.stringify(provider.featureDefaults)) fail('doctor JSON featureDefaults do not equal the admitted provider registry');
if (JSON.stringify(provider.featureDefaults) !== JSON.stringify(acceptance.featureDefaults)) fail('provider and acceptance feature registries diverge');
for (const value of Object.values(doctor.featureDefaults ?? {})) {
  if (value !== 'on') fail('admitted registry must remain default ON');
}
if (fs.readFileSync(process.env.DOCTOR_JSON, 'utf8').includes('default_off')) fail('doctor JSON still emits the stale default_off claim');
NODE
  OFFICE_EVIDENCE_ROOT="$tmp/evidence" "$SCRIPT" quick --run-id selftest >/dev/null
  local manifest="$tmp/evidence/selftest/manifest.json"
  OFFICE_EVIDENCE_ROOT="$tmp/evidence" "$SCRIPT" evidence "$manifest" >/dev/null
  if "$SCRIPT" unknown >/dev/null 2>&1; then
    echo "office verification self-test: unknown mode accepted" >&2
    return 1
  fi
  if "$SCRIPT" explain E_OFFICE_NOT_A_REAL_CODE >/dev/null 2>&1; then
    echo "office verification self-test: unknown explain code accepted" >&2
    return 1
  fi
  cp "$PROVIDER_MANIFEST" "$tmp/provider.json"
  node - "$tmp/provider.json" <<'NODE'
const fs = require('node:fs');
const path = process.argv[2];
const value = JSON.parse(fs.readFileSync(path, 'utf8'));
value.featureDefaults['feature.drive'] = 'off';
fs.writeFileSync(path, JSON.stringify(value));
NODE
  if OFFICE_PROVIDER_MANIFEST="$tmp/provider.json" "$SCRIPT" doctor >/dev/null 2>&1; then
    echo "office verification self-test: default-ON mutant accepted" >&2
    return 1
  fi
  cp "$PROVIDER_MANIFEST" "$tmp/provider-hash.json"
  OFFICE_PROVIDER_MANIFEST="$tmp/provider-hash.json" OFFICE_EVIDENCE_ROOT="$tmp/hash-evidence" "$SCRIPT" quick --run-id hash >/dev/null
  node - "$tmp/provider-hash.json" <<'NODE'
const fs = require('node:fs');
const path = process.argv[2];
const value = JSON.parse(fs.readFileSync(path, 'utf8'));
value.providers[0].status = 'mutated_after_run';
fs.writeFileSync(path, JSON.stringify(value));
NODE
  if OFFICE_PROVIDER_MANIFEST="$tmp/provider-hash.json" "$SCRIPT" evidence "$tmp/hash-evidence/hash/manifest.json" >/dev/null 2>&1; then
    echo "office verification self-test: evidence hash mutant accepted" >&2
    return 1
  fi
  echo "office verification self-test: PASS (doctor, paired human/JSON feature-policy parity, quick, evidence, unknown mode/code, default-ON and hash mutants)"
}

parse_args() {
  if (($#)); then
    case "$1" in
      --doctor) MODE=doctor; shift ;;
      --quick) MODE=quick; shift ;;
      --core) MODE=core; shift ;;
      --live-collabora|--live) MODE=live-collabora; shift ;;
      --help|-h) usage; exit 0 ;;
      doctor|quick|core|live-collabora|evidence|explain) MODE="$1"; shift ;;
      --json|--self-test|--run-id) ;;
      *) MODE="$1"; shift ;;
    esac
  fi
  while (($#)); do
    case "$1" in
      --json) JSON_MODE=1; shift ;;
      --self-test) SELF_TEST=1; shift ;;
      --run-id)
        (($# > 1)) || die "--run-id requires a value"
        RUN_ID="$2"; shift 2 ;;
      --help|-h) usage; exit 0 ;;
      *) POSITIONAL+=("$1"); shift ;;
    esac
  done
}

parse_args "$@"
if ((SELF_TEST)); then
  self_test
  exit 0
fi
case "$MODE" in
  doctor) doctor ;;
  quick|core) focused_run "$MODE" ;;
  live-collabora) live_collabora ;;
  evidence) verify_evidence "${POSITIONAL[0]:-}" ;;
  explain) explain "${POSITIONAL[0]:-}" ;;
  *) usage >&2; exit 2 ;;
esac
