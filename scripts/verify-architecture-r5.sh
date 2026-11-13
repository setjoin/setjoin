#!/usr/bin/env bash
# Architecture Deepening Round 5: thin, source-bound 14-disposition dispatcher.
# shellcheck disable=SC1091
source "$(dirname "$0")/_base.sh"
set -euo pipefail

RESULTS_ROOT="${ARCH_R5_RESULTS_ROOT:-$ROOT/test-results/architecture-r5}"
REGISTRY="$ROOT/docs/verification/architecture-r5-cases.json"
CHECKER="$ROOT/scripts/check-architecture-r5-cases.mjs"
NODE_BIN="${ARCH_R5_NODE_BIN:-$(command -v node || true)}"
FINGERPRINT_TOOL="$ROOT/scripts/lib/source-fingerprint.mjs"
LANES=(smtp auth-json artifacts rehearsal ca admin jmap-account evidence-boundary auth-cookie chat exchange-fold compose calendar offline-defer)
VERBOSE=0

usage() {
  cat <<'EOF'
Usage: bash scripts/verify-architecture-r5.sh COMMAND [OPTIONS]

Commands:
  --help                  Show this Round-5-only contract.
  --doctor                Read-only prerequisites, predicate state, estimate, and rerun.
  list                    List 14 exact candidates, case IDs, dispositions, and owners.
  smtp|auth-json|artifacts|rehearsal|ca|admin|jmap-account|evidence-boundary
  auth-cookie|chat|exchange-fold|compose|calendar|offline-defer
                          Run one source-selected lane and publish atomic evidence.
  LANE [--self-test] [--verbose]
                          Run a lane, or plant a disposable red-only failure.
  quick [--verbose]       Run all 14 lanes and publish an aggregate; fail on HOLD/red.
  full [--verbose]        Run quick, then repository build, lint, and test front doors.
  evidence [--run-id ID]  Validate latest or named source-bound manifest and hashes.

Evidence: test-results/architecture-r5/<run-id>/manifest.json
Terminal no-change/fold/defer receipts are dispositions, not product-green claims.
HOLD is exit 3. There is no evidence-skip override.
EOF
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
  printf 'docs: retired-docs:superpowers/plans/archive/2026-08-24-architecture-deepening-round-5.md\n' >&2
}

contains_lane() {
  local wanted="$1" lane
  for lane in "${LANES[@]}"; do [[ "$lane" == "$wanted" ]] && return 0; done
  return 1
}

lane_code() {
  printf '%s' "$1" | tr '[:lower:]-' '[:upper:]_'
}

source_fingerprint() {
  "$NODE_BIN" "$FINGERPRINT_TOOL" compute --root "$ROOT"
}

parse_source_fingerprint() {
  "$NODE_BIN" "$FINGERPRINT_TOOL" parse --value "$1"
}

registry_hash() {
  shasum -a 256 "$REGISTRY" | cut -d' ' -f1
}

validate_registry() {
  [[ -n "$NODE_BIN" ]] || return 1
  "$NODE_BIN" "$CHECKER" validate
}

entry_json() {
  "$NODE_BIN" "$CHECKER" case "$1"
}

evaluation_json() {
  "$NODE_BIN" "$CHECKER" evaluate "$1"
}

json_field() {
  "$NODE_BIN" -e 'const value=JSON.parse(process.argv[1]);const keys=process.argv[2].split(".");let out=value;for(const key of keys)out=out[key];process.stdout.write(out===null?"":String(out))' "$1" "$2"
}

selected_commands() {
  local entry="$1" disposition="$2"
  "$NODE_BIN" -e 'const e=JSON.parse(process.argv[1]);const commands=process.argv[2]===e.predicate.passDisposition?e.commands:e.alternateCommands;for(const command of commands)console.log(command)' "$entry" "$disposition"
}

parse_verbose_only() {
  if [[ $# -gt 1 || ( $# -eq 1 && "$1" != "--verbose" ) ]]; then return 2; fi
  [[ $# -eq 0 ]] || VERBOSE=1
}

lane_tools() {
  case "$1" in
    smtp|ca|auth-json|auth-cookie|artifacts) echo "node git shasum bash go" ;;
    rehearsal|evidence-boundary|exchange-fold|offline-defer) echo "node git shasum bash" ;;
    admin|jmap-account|chat|compose|calendar) echo "node git shasum bash npm" ;;
    *) echo "node git shasum bash" ;;
  esac
}

doctor() {
  local lane tool missing entry evaluation state disposition gate estimate owner
  validate_registry >/dev/null || {
    diagnostic E_ARCH_R5_REGISTRY "Round 5 cannot be selected" "the exact case registry is missing or malformed" "$REGISTRY" "none" "repair the registry and its planted schema tests" "node scripts/check-architecture-r5-cases.mjs validate"
    return 1
  }
  echo "architecture-r5 doctor"
  echo "  source: fingerprint=$(source_fingerprint) registry=$(registry_hash)"
  for lane in "${LANES[@]}"; do
    missing=""
    for tool in $(lane_tools "$lane"); do command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"; done
    entry="$(entry_json "$lane")"; evaluation="$(evaluation_json "$lane")"
    state="$(json_field "$evaluation" state)"; disposition="$(json_field "$evaluation" disposition)"
    gate="$(json_field "$entry" gateClass)"; estimate="$(json_field "$entry" warmEstimateSeconds)"; owner="$(json_field "$entry" owner)"
    if [[ "$state" == hold ]]; then
      echo "  $lane: HOLD; cause=required source predicate is absent or unknown; gate=$gate; owner=$owner; rerun=bash scripts/verify-architecture-r5.sh $lane --verbose"
    elif [[ -n "$missing" ]]; then
      echo "  $lane: missing=${missing# }; predicate=$state/$disposition; gate=$gate; owner=$owner; rerun=bash scripts/verify-architecture-r5.sh $lane"
    else
      echo "  $lane: ready; predicate=$state/$disposition; gate=$gate; estimate<=${estimate}s; owner=$owner; rerun=bash scripts/verify-architecture-r5.sh $lane"
    fi
  done
}

publish_lane() {
  local lane="$1" verdict="$2" disposition="$3" reason="$4" started="$5" ended="$6" duration="$7" tmp="$8" code="$9" source="${10}" commands_file="${11}"
  local entry run_id final
  entry="$(entry_json "$lane")"
  run_id="$(date -u +%Y%m%dT%H%M%SZ)-$(git -C "$ROOT" rev-parse --short=8 HEAD)-$$-$lane"
  final="$RESULTS_ROOT/$run_id"
  ARCH_R5_ENTRY="$entry" ARCH_R5_VERDICT="$verdict" ARCH_R5_DISPOSITION="$disposition" \
  ARCH_R5_REASON="$reason" ARCH_R5_STARTED="$started" ARCH_R5_ENDED="$ended" ARCH_R5_DURATION="$duration" \
  ARCH_R5_SOURCE_JSON="$(parse_source_fingerprint "$source")" ARCH_R5_REGISTRY_SHA="$(registry_hash)" ARCH_R5_CODE="$code" \
  ARCH_R5_LOG="$tmp/output.log" ARCH_R5_COMMANDS="$commands_file" "$NODE_BIN" >"$tmp/manifest.json.tmp" <<'NODE'
const fs=require('node:fs'); const crypto=require('node:crypto');
const entry=JSON.parse(process.env.ARCH_R5_ENTRY); const source=JSON.parse(process.env.ARCH_R5_SOURCE_JSON);
const bytes=fs.readFileSync(process.env.ARCH_R5_LOG);
const commands=fs.readFileSync(process.env.ARCH_R5_COMMANDS,'utf8').split('\n').filter(Boolean);
const manifest={
  schemaVersion:1, kind:'lane', program:'architecture-deepening-round-5', candidate:entry.candidate,
  lane:entry.lane, caseId:entry.caseId, verdict:process.env.ARCH_R5_VERDICT,
  disposition:process.env.ARCH_R5_DISPOSITION, diagnosticCode:process.env.ARCH_R5_CODE||null,
  predicate:{type:entry.predicate.type,reason:process.env.ARCH_R5_REASON},
  source:{fingerprint:source.value,commit:source.commit,dirtyDigest:source.digest,registrySha256:process.env.ARCH_R5_REGISTRY_SHA},
  startedAt:process.env.ARCH_R5_STARTED, endedAt:process.env.ARCH_R5_ENDED,
  durationSeconds:Number(process.env.ARCH_R5_DURATION), commands,
  artifacts:[{path:'output.log',sha256:crypto.createHash('sha256').update(bytes).digest('hex')}],
};
process.stdout.write(`${JSON.stringify(manifest,null,2)}\n`);
NODE
  mv "$tmp/manifest.json.tmp" "$tmp/manifest.json"
  mkdir -p "$RESULTS_ROOT"
  mv "$tmp" "$final"
  printf '{"schemaVersion":1,"kind":"lane","runId":"%s"}\n' "$run_id" >"$RESULTS_ROOT/.latest-$lane.$$"
  mv "$RESULTS_ROOT/.latest-$lane.$$" "$RESULTS_ROOT/latest-$lane.json"
  printf '{"schemaVersion":1,"kind":"lane","runId":"%s"}\n' "$run_id" >"$RESULTS_ROOT/.latest.$$"
  mv "$RESULTS_ROOT/.latest.$$" "$RESULTS_ROOT/latest.json"
  echo "architecture-r5: $verdict lane=$lane case=$(json_field "$entry" caseId) disposition=$disposition manifest=${final#"$ROOT"/}/manifest.json"
}

run_selected_commands() {
  local lane="$1" commands_file="$2" command result
  if [[ "${ARCH_R5_PLANTED_LANE:-}" == "$lane" ]]; then
    echo "R5_PLANTED_$(lane_code "$lane")" >&2
    return 97
  fi
  if [[ "${ARCH_R5_PLANTED_SOURCE_MUTATION:-0}" == 1 ]]; then
    local mutant="$ROOT/docs/verification/.architecture-r5-source-mutant.bin"
    [[ -f "$mutant" && ! -L "$mutant" ]] || return 98
    "$NODE_BIN" -e 'require("fs").appendFileSync(process.argv[1],Buffer.from([0,82,53,45,109,117,116,97,116,101,100]))' "$mutant"
  fi
  result=0
  while IFS= read -r command; do
    [[ -n "$command" ]] || continue
    printf '$ %s\n' "$command"
    (cd "$ROOT" && bash -c "$command")
    result=$?
    [[ "$result" -eq 0 ]] || return "$result"
  done <"$commands_file"
  return 0
}

run_lane() {
  local lane="$1" entry evaluation state disposition reason source_before source_after started ended started_epoch ended_epoch duration tmp commands_file result verdict code rc
  validate_registry >/dev/null || {
    diagnostic E_ARCH_R5_REGISTRY "Round 5 lane cannot run" "the exact case registry is missing or malformed" "$REGISTRY" "none" "repair the registry and rerun its schema test" "node scripts/check-architecture-r5-cases.mjs validate"
    return 1
  }
  entry="$(entry_json "$lane")"
  if [[ "${ARCH_R5_PLANTED_LANE:-}" == "$lane" ]]; then
    state=selected; disposition="$(json_field "$entry" predicate.passDisposition)"; reason=planted-red-only-fixture
  else
    evaluation="$(evaluation_json "$lane")"; state="$(json_field "$evaluation" state)"; disposition="$(json_field "$evaluation" disposition)"; reason="$(json_field "$evaluation" reason)"
  fi
  mkdir -p "$RESULTS_ROOT"
  tmp="$(mktemp -d "$RESULTS_ROOT/.tmp.XXXXXX")"; commands_file="$tmp/commands.txt"
  source_before="$(source_fingerprint)"; started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; started_epoch="$(date +%s)"
  if [[ "$state" == hold ]]; then
    : >"$commands_file"
    printf 'predicate HOLD: %s\n' "$reason" >"$tmp/output.log"
    result=3
  else
    selected_commands "$entry" "$disposition" >"$commands_file"
    set +e
    run_selected_commands "$lane" "$commands_file" >"$tmp/output.log" 2>&1
    result=$?
    set -e
  fi
  ended="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; ended_epoch="$(date +%s)"; duration=$((ended_epoch-started_epoch)); source_after="$(source_fingerprint)"
  verdict=failed; code="E_ARCH_R5_$(lane_code "$lane")_TEST"; rc="$result"
  if [[ "$source_before" != "$source_after" ]]; then
    verdict=held; disposition=hold; code=E_ARCH_R5_EVIDENCE_STALE; reason='source-changed-during-lane'; rc=3
    echo "$code source changed during lane" >>"$tmp/output.log"
  elif [[ "$state" == hold ]]; then
    verdict=held; disposition=hold; code="E_ARCH_R5_$(lane_code "$lane")_HOLD"; rc=3
  elif [[ "$disposition" == collision-held ]]; then
    verdict=held; code=E_ARCH_R5_ADMIN_COLLISION_HOLD; rc=3
  elif [[ "$result" -eq 0 && "$disposition" == implemented ]]; then
    verdict=passed; code=""; rc=0
  elif [[ "$result" -eq 0 ]]; then
    verdict=terminal; code=""; rc=0
  fi
  [[ "$VERBOSE" -eq 0 && "$rc" -eq 0 ]] || cat "$tmp/output.log"
  [[ -z "$code" ]] || echo "$code result=$result" >>"$tmp/output.log"
  publish_lane "$lane" "$verdict" "$disposition" "$reason" "$started" "$ended" "$duration" "$tmp" "$code" "$source_before" "$commands_file"
  if [[ "$rc" -ne 0 ]]; then
    diagnostic "$code" "Architecture R5 lane did not reach an acceptable terminal disposition" "lane=$lane predicate=$reason result=$result" "scripts/verify-architecture-r5.sh:$lane" "${RESULTS_ROOT#"$ROOT"/}/latest-$lane.json" "inspect the retained output and satisfy the registered source predicate without weakening evidence" "bash scripts/verify-architecture-r5.sh $lane --verbose"
  fi
  return "$rc"
}

publish_aggregate() {
  local source tmp run_id final lane pointer manifest
  source="$(source_fingerprint)"; mkdir -p "$RESULTS_ROOT"; tmp="$(mktemp -d "$RESULTS_ROOT/.aggregate.XXXXXX")"
  : >"$tmp/manifests.txt"
  for lane in "${LANES[@]}"; do
    pointer="$RESULTS_ROOT/latest-$lane.json"
    [[ -f "$pointer" ]] || { diagnostic E_ARCH_R5_AGGREGATE_INCOMPLETE "Round 5 aggregate is incomplete" "missing latest pointer for lane=$lane" "$pointer" "none" "run the missing lane on the current source" "bash scripts/verify-architecture-r5.sh $lane"; return 1; }
    run_id="$("$NODE_BIN" -e 'const p=JSON.parse(require("fs").readFileSync(process.argv[1]));process.stdout.write(p.runId)' "$pointer")"
    manifest="$RESULTS_ROOT/$run_id/manifest.json"; printf '%s\n' "$manifest" >>"$tmp/manifests.txt"
  done
  ARCH_R5_SOURCE_JSON="$(parse_source_fingerprint "$source")" ARCH_R5_REGISTRY_SHA="$(registry_hash)" ARCH_R5_MANIFESTS="$tmp/manifests.txt" ARCH_R5_ROOT="$ROOT" "$NODE_BIN" >"$tmp/manifest.json.tmp" <<'NODE'
const fs=require('node:fs');const crypto=require('node:crypto');const path=require('node:path');
const source=JSON.parse(process.env.ARCH_R5_SOURCE_JSON);
const rows=[];for(const filename of fs.readFileSync(process.env.ARCH_R5_MANIFESTS,'utf8').trim().split('\n')){
 const bytes=fs.readFileSync(filename);const m=JSON.parse(bytes);
 if(!['passed','terminal'].includes(m.verdict)||m.source.fingerprint!==source.value||m.source.commit!==source.commit||m.source.dirtyDigest!==source.digest||m.source.registrySha256!==process.env.ARCH_R5_REGISTRY_SHA)throw new Error(`stale or nonterminal lane ${m.lane}`);
 rows.push({lane:m.lane,caseId:m.caseId,disposition:m.disposition,manifest:path.relative(process.env.ARCH_R5_ROOT,filename),sha256:crypto.createHash('sha256').update(bytes).digest('hex')});
}
const manifest={schemaVersion:1,kind:'aggregate',program:'architecture-deepening-round-5',verdict:'terminal',source:{fingerprint:source.value,commit:source.commit,dirtyDigest:source.digest,registrySha256:process.env.ARCH_R5_REGISTRY_SHA},cases:rows};
process.stdout.write(`${JSON.stringify(manifest,null,2)}\n`);
NODE
  mv "$tmp/manifest.json.tmp" "$tmp/manifest.json"; run_id="$(date -u +%Y%m%dT%H%M%SZ)-$(git -C "$ROOT" rev-parse --short=8 HEAD)-$$-aggregate"; final="$RESULTS_ROOT/$run_id"; mv "$tmp" "$final"
  printf '{"schemaVersion":1,"kind":"aggregate","runId":"%s"}\n' "$run_id" >"$RESULTS_ROOT/.latest.$$"; mv "$RESULTS_ROOT/.latest.$$" "$RESULTS_ROOT/latest.json"
  echo "architecture-r5 aggregate: terminal cases=14 manifest=${final#"$ROOT"/}/manifest.json"
}

run_all_lanes() {
  local lane
  for lane in "${LANES[@]}"; do run_lane "$lane"; done
  publish_aggregate
}

self_test() {
  local lane="$1" tmp result pointer run_id manifest
  tmp="$(mktemp -d)"
  set +e
  ARCH_R5_PLANTED_LANE="$lane" ARCH_R5_RESULTS_ROOT="$tmp/results" bash "$ROOT/scripts/verify-architecture-r5.sh" "$lane" >"$tmp/output" 2>&1
  result=$?
  set -e
  [[ "$result" -ne 0 ]] || { echo "E_ARCH_R5_$(lane_code "$lane")_SELFTEST planted failure passed" >&2; return 1; }
  pointer="$tmp/results/latest-$lane.json"; [[ -f "$pointer" ]] || { echo "E_ARCH_R5_$(lane_code "$lane")_SELFTEST missing pointer" >&2; return 1; }
  run_id="$("$NODE_BIN" -e 'const p=JSON.parse(require("fs").readFileSync(process.argv[1]));process.stdout.write(p.runId)' "$pointer")"; manifest="$tmp/results/$run_id/manifest.json"
  "$NODE_BIN" - "$manifest" "$lane" <<'NODE'
const fs=require('node:fs');const m=JSON.parse(fs.readFileSync(process.argv[2]));
if(m.kind!=='lane'||m.lane!==process.argv[3]||!['failed','held'].includes(m.verdict)||!m.diagnosticCode||m.artifacts.length!==1)process.exit(1);
NODE
  echo "architecture-r5 self-test: PASS lane=$lane"
}

evidence() {
  local run_id="" pointer manifest output result current_source
  if [[ "${1:-}" == --run-id ]]; then
    [[ $# -eq 2 && "${2:-}" =~ ^[A-Za-z0-9._-]+$ ]] || { diagnostic E_ARCH_R5_EVIDENCE_USAGE "evidence arguments are invalid" "--run-id requires one safe ID" "scripts/verify-architecture-r5.sh:evidence" "none" "copy an exact run ID from latest.json" "bash scripts/verify-architecture-r5.sh evidence --run-id ID"; return 2; }
    run_id="$2"
  elif [[ $# -ne 0 ]]; then
    diagnostic E_ARCH_R5_EVIDENCE_USAGE "evidence arguments are invalid" "unknown arguments: $*" "scripts/verify-architecture-r5.sh:evidence" "none" "use no arguments or --run-id ID" "bash scripts/verify-architecture-r5.sh evidence"
    return 2
  fi
  if [[ -z "$run_id" ]]; then
    pointer="$RESULTS_ROOT/latest.json"; [[ -f "$pointer" ]] || { diagnostic E_ARCH_R5_EVIDENCE_MISSING "no Round 5 evidence is available" "latest.json is missing" "$pointer" "none" "run a named lane first" "bash scripts/verify-architecture-r5.sh list"; return 1; }
    set +e; run_id="$("$NODE_BIN" -e 'try{const p=JSON.parse(require("fs").readFileSync(process.argv[1]));if(p.schemaVersion!==1||!/^[A-Za-z0-9._-]+$/.test(p.runId))process.exit(2);process.stdout.write(p.runId)}catch{process.exit(2)}' "$pointer")"; result=$?; set -e
    [[ "$result" -eq 0 ]] || { diagnostic E_ARCH_R5_EVIDENCE_MALFORMED "latest Round 5 evidence pointer is malformed" "latest.json is not a safe schema-v1 pointer" "$pointer" "none" "remove the ignored broken pointer and rerun a lane" "bash scripts/verify-architecture-r5.sh list"; return 1; }
  fi
  manifest="$RESULTS_ROOT/$run_id/manifest.json"; [[ -f "$manifest" ]] || { diagnostic E_ARCH_R5_EVIDENCE_MISSING "requested Round 5 evidence does not exist" "manifest is missing for run-id=$run_id" "$manifest" "run-id=$run_id" "choose an existing run ID or rerun the lane" "bash scripts/verify-architecture-r5.sh evidence"; return 1; }
  current_source="$(source_fingerprint)"
  set +e
  output="$(ARCH_R5_EXPECTED_SOURCE="$current_source" ARCH_R5_EXPECTED_REGISTRY="$(registry_hash)" ARCH_R5_REGISTRY="$REGISTRY" ARCH_R5_ROOT="$ROOT" ARCH_R5_FINGERPRINT_TOOL="$FINGERPRINT_TOOL" "$NODE_BIN" - "$manifest" 2>&1 <<'NODE'
const fs=require('node:fs');const path=require('node:path');const crypto=require('node:crypto');const {pathToFileURL}=require('node:url');
const filename=process.argv[2];const fail=(code,cause)=>{console.error(`${code}|${cause}`);process.exit(1)};
async function main(){
 const {parseFingerprint}=await import(pathToFileURL(process.env.ARCH_R5_FINGERPRINT_TOOL));
 const m=JSON.parse(fs.readFileSync(filename));const registry=JSON.parse(fs.readFileSync(process.env.ARCH_R5_REGISTRY));
 let source;let expected;
 try{source=parseFingerprint(m.source?.fingerprint);expected=parseFingerprint(process.env.ARCH_R5_EXPECTED_SOURCE)}catch(error){fail('E_ARCH_R5_EVIDENCE_VERSION',error.message)}
 if(m.schemaVersion!==1||m.program!=='architecture-deepening-round-5'||!['lane','aggregate'].includes(m.kind))fail('E_ARCH_R5_EVIDENCE_MALFORMED','invalid manifest identity');
 if(source.value!==expected.value||m.source?.commit!==source.commit||m.source?.dirtyDigest!==source.digest||m.source?.registrySha256!==process.env.ARCH_R5_EXPECTED_REGISTRY)fail('E_ARCH_R5_EVIDENCE_STALE','source or registry fingerprint differs from current tree');
 if(m.kind==='lane'){
  const row=registry.cases.find(x=>x.lane===m.lane&&x.caseId===m.caseId&&x.candidate===m.candidate);
  if(!row||!row.allowedDispositions.includes(m.disposition)||!['passed','terminal'].includes(m.verdict))fail('E_ARCH_R5_EVIDENCE_DISPOSITION','lane is failed, held, unknown, or uses a forbidden disposition');
  for(const artifact of m.artifacts??[]){if(!artifact||typeof artifact.path!=='string'||path.isAbsolute(artifact.path)||artifact.path.includes('..')||!/^[0-9a-f]{64}$/.test(artifact.sha256))fail('E_ARCH_R5_EVIDENCE_MALFORMED','invalid artifact entry');const artifactFile=path.join(path.dirname(filename),artifact.path);if(!fs.existsSync(artifactFile)||crypto.createHash('sha256').update(fs.readFileSync(artifactFile)).digest('hex')!==artifact.sha256)fail('E_ARCH_R5_EVIDENCE_ARTIFACT',`missing or mismatched ${artifact.path}`);}
  console.log(`architecture-r5 evidence: ${m.verdict.toUpperCase()} lane=${m.lane} case=${m.caseId} disposition=${m.disposition}`);
 }else{
  if(m.verdict!=='terminal'||!Array.isArray(m.cases)||m.cases.length!==registry.cases.length||new Set(m.cases.map(x=>x.lane)).size!==registry.cases.length)fail('E_ARCH_R5_EVIDENCE_INCOMPLETE','aggregate does not contain 14 unique terminal cases');
  for(const row of m.cases){const expected=registry.cases.find(x=>x.lane===row.lane&&x.caseId===row.caseId);if(!expected||!expected.allowedDispositions.includes(row.disposition)||!/^[0-9a-f]{64}$/.test(row.sha256))fail('E_ARCH_R5_EVIDENCE_DISPOSITION',`invalid aggregate row ${row.lane}`);const laneFile=path.resolve(process.env.ARCH_R5_ROOT,row.manifest);if(!laneFile.startsWith(process.env.ARCH_R5_ROOT+path.sep)||!fs.existsSync(laneFile)||crypto.createHash('sha256').update(fs.readFileSync(laneFile)).digest('hex')!==row.sha256)fail('E_ARCH_R5_EVIDENCE_ARTIFACT',`aggregate child mismatch ${row.lane}`);}
  console.log('architecture-r5 evidence: TERMINAL aggregate cases=14');
 }
}
main().catch((error)=>fail('E_ARCH_R5_EVIDENCE_MALFORMED',error.message));
NODE
)"; result=$?; set -e
  if [[ "$result" -ne 0 ]]; then
    diagnostic "${output%%|*}" "Round 5 evidence validation failed" "${output#*|}" "$manifest" "run-id=$run_id" "rerun the owning lane or aggregate on the current source" "bash scripts/verify-architecture-r5.sh list"
    return 1
  fi
  printf '%s\n' "$output"
}

command="${1:---help}"; shift || true
case "$command" in
  --help|-h) [[ $# -eq 0 ]] || exit 2; usage ;;
  --doctor) [[ $# -eq 0 ]] || exit 2; doctor ;;
  list)
    [[ $# -eq 0 ]] || { diagnostic E_ARCH_R5_CLI_USAGE "list arguments are invalid" "list accepts no arguments" "scripts/verify-architecture-r5.sh" "none" "remove unsupported arguments" "bash scripts/verify-architecture-r5.sh list"; exit 2; }
    validate_registry >/dev/null || { diagnostic E_ARCH_R5_REGISTRY "Round 5 cases cannot be listed" "the exact case registry is missing or malformed" "$REGISTRY" "none" "repair the registry and its planted schema tests" "node scripts/check-architecture-r5-cases.mjs validate"; exit 1; }
    "$NODE_BIN" "$CHECKER" list
    ;;
  quick)
    parse_verbose_only "$@" || { diagnostic E_ARCH_R5_CLI_USAGE "quick arguments are invalid" "expected only --verbose" "scripts/verify-architecture-r5.sh" "none" "remove unsupported arguments" "bash scripts/verify-architecture-r5.sh quick --verbose"; exit 2; }
    run_all_lanes
    ;;
  full)
    parse_verbose_only "$@" || { diagnostic E_ARCH_R5_CLI_USAGE "full arguments are invalid" "expected only --verbose" "scripts/verify-architecture-r5.sh" "none" "remove unsupported arguments" "bash scripts/verify-architecture-r5.sh full --verbose"; exit 2; }
    run_all_lanes; bash "$ROOT/scripts/build.sh"; bash "$ROOT/scripts/lint.sh"; bash "$ROOT/scripts/test.sh"
    ;;
  evidence) evidence "$@" ;;
  *)
    contains_lane "$command" || { diagnostic E_ARCH_R5_CLI_UNKNOWN "unknown Round 5 lane or command" "command=$command" "scripts/verify-architecture-r5.sh" "none" "choose one of the 14 names printed by list" "bash scripts/verify-architecture-r5.sh list"; exit 2; }
    if [[ "${1:-}" == --self-test ]]; then
      [[ $# -le 2 && ( $# -eq 1 || "${2:-}" == --verbose ) ]] || { diagnostic E_ARCH_R5_CLI_USAGE "lane arguments are invalid" "lane=$command arguments=$*" "scripts/verify-architecture-r5.sh" "none" "use --self-test and optional --verbose" "bash scripts/verify-architecture-r5.sh $command --self-test"; exit 2; }
      [[ $# -eq 1 ]] || VERBOSE=1; self_test "$command"
    else
      parse_verbose_only "$@" || { diagnostic E_ARCH_R5_CLI_USAGE "lane arguments are invalid" "lane=$command arguments=$*" "scripts/verify-architecture-r5.sh" "none" "use no flag or --verbose" "bash scripts/verify-architecture-r5.sh $command --verbose"; exit 2; }
      run_lane "$command"
    fi
    ;;
esac
