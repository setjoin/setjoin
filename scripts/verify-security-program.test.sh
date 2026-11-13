#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
program="$script_dir/verify-security-program.sh"
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/setjoin-security-program.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT

run_ok() {
  local name="$1"
  shift
  "$program" "$@" --json >"$tmp_dir/$name.out" 2>"$tmp_dir/$name.err"
  test ! -s "$tmp_dir/$name.err"
}

run_fail() {
  local expected_exit="$1"
  local expected_code="$2"
  local name="$3"
  shift 3
  set +e
  "$program" "$@" --json >"$tmp_dir/$name.out" 2>"$tmp_dir/$name.err"
  local actual_exit=$?
  set -e
  test "$actual_exit" -eq "$expected_exit"
  node -e 'const fs=require("fs"); const v=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); if(v.code!==process.argv[2]||v.scannerStarts!==0||v.networkStarts!==0) process.exit(1)' "$tmp_dir/$name.err" "$expected_code"
}

run_ok help help
run_ok help_alias --help
run_ok doctor doctor
run_ok doctor_canonical --doctor --offline
run_ok list list
run_ok coverage_list coverage list
run_ok coverage_list_paths coverage list --section S02 --paths
# Execute-mode publication is covered below by disposable primitive fixtures;
# the hermetic front door never rewrites repository-owned C0 evidence.
run_ok compile_check inventory compile --check
run_ok status status
run_ok coverage_status coverage status
run_ok show_epoch show epoch
run_ok show_sections show sections
run_ok show_shards show shards
run_ok coverage_show coverage show --section S01
run_ok explain_c0 explain C0
run_ok explain_hold explain HOLD
run_ok explain_unavailable explain E_SECURITY_PROGRAM_SCAN_UNAVAILABLE
run_ok coverage_explain coverage explain HOLD
run_ok coverage_explain_dx coverage explain E_SECURITY_PROGRAM_DX_INCOMPLETE

path_token="$(node -e 'const fs=require("fs"); const v=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); process.stdout.write(v.shards[0].paths[0].pathToken)' "$tmp_dir/coverage_list_paths.out")"
run_ok coverage_show_path coverage show --path-token "$path_token"
run_ok coverage_evidence coverage evidence
run_ok coverage_migrate_check coverage migrate --check
run_ok coverage_migrate_v2_check coverage migrate --check --to v2
run_ok coverage_benchmark coverage benchmark --journey resume --samples 5 --warmup 2

"$program" --doctor >"$tmp_dir/doctor.pipe" 2>"$tmp_dir/doctor.pipe.err"
test ! -s "$tmp_dir/doctor.pipe.err"
rg -Fxq $'command\tdoctor' "$tmp_dir/doctor.pipe"
rg -Fxq $'conclusion\tCONTROL PLANE USABLE' "$tmp_dir/doctor.pipe"
rg -Fxq $'scannerStarts\t0' "$tmp_dir/doctor.pipe"
if rg -q '[{}]' "$tmp_dir/doctor.pipe"; then
  echo "security-program self-test: pipe output contains JSON delimiters" >&2
  exit 1
fi

node --input-type=module - "$script_dir/security-program.mjs" <<'NODE' >"$tmp_dir/doctor.human"
const api = await import(process.argv[2]);
const text = api.renderOutput({
  schema: 'setjoin.security-program.control/v1', command: 'doctor', status: 'PASS',
  scannerStarts: 0, networkStarts: 0, conclusion: 'CONTROL PLANE USABLE',
}, 'human');
process.stdout.write(text);
const mac = api.classifyReadPlatform('darwin', 'arm64', 'mac-ci-m5');
const linux = api.classifyReadPlatform('linux', 'x64', 'ubuntu-ci-m920x');
if (!mac.supportedReadPath || mac.hostClass !== 'mac-ci-m5'
    || !linux.supportedReadPath || linux.hostClass !== 'ubuntu-ci-m920x'
    || api.classifyReadPlatform('linux', 'arm64', 'ubuntu-ci-m920x').supportedReadPath) process.exit(1);
try {
  api.assertSupportedReadPlatform(api.classifyReadPlatform('linux', 'arm64', 'ubuntu-ci-m920x'));
  process.exit(1);
} catch (error) {
  if (error.code !== 'E_SECURITY_PROGRAM_PLATFORM_UNSUPPORTED' || error.exitCode !== 4) process.exit(1);
}
try {
  api.assertBenchmarkTargets({ doctorStatusP95Ms: 120000, fullJourneyP95Ms: 1 });
  process.exit(1);
} catch (error) {
  if (error.code !== 'E_SECURITY_PROGRAM_BENCHMARK_TARGET_MISSED' || error.exitCode !== 1) process.exit(1);
}
for (const mode of ['human', 'pipe', 'json']) {
  for (const artifactRef of [
    '/Users/private-operator/bundle', '/root/bundle', '/var/lib/setjoin/bundle',
    'bundle (/root/setjoin-private/evidence)', 'bundle[/var/lib/setjoin/private/evidence]',
    'D:\\Profiles\\operator\\bundle', 'path(D:\\Profiles\\operator\\evidence)',
    '\\\\server\\share\\bundle', 'bundle[\\\\server\\share\\evidence]',
  ]) {
    try {
      api.renderOutput({ command: 'privacy-mutant', status: 'PASS', artifactRef }, mode);
      process.exit(1);
    } catch (error) {
      if (error.code !== 'E_SECURITY_PROGRAM_OUTPUT_PRIVACY') process.exit(1);
    }
  }
  api.renderOutput({ command: 'privacy-control', status: 'PASS', docs: 'https://docs.example.test/security' }, mode);
}
const controlValue = { command: 'render', status: 'PASS', path: 'shared/weird\rname\u001b[2Jspoof\u0007\u0085c1\u202Etxt.exe\u2066x' };
for (const mode of ['human', 'pipe', 'json']) {
  const rendered = api.renderOutput(controlValue, mode);
  if (mode !== 'json') {
    const values = mode === 'pipe'
      ? rendered.trimEnd().split('\n').map((line) => line.slice(line.indexOf('\t') + 1))
      : rendered.trimEnd().split('\n').map((line) => line.includes(': ') ? line.slice(line.indexOf(': ') + 2) : line);
    if (values.some((item) => /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(item))) process.exit(1);
  } else if (/[\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/u.test(rendered)
      || JSON.parse(rendered).path !== controlValue.path) process.exit(1);
  if (!rendered.includes('\\r') || !rendered.includes('\\u001b') || !rendered.includes('\\u0007')
      || !rendered.includes('\\u0085') || !rendered.includes('\\u202e') || !rendered.includes('\\u2066')) process.exit(1);
}
for (const code of api.diagnosticCatalogCodes()) {
  const diagnostic = api.diagnosticExample(code);
  for (const mode of ['human', 'pipe', 'json']) {
    const rendered = api.renderOutput(diagnostic, mode);
    if (!rendered.includes(code) || /[\u202a-\u202e\u2066-\u2069]/u.test(rendered)) process.exit(1);
    if (mode === 'json' && JSON.parse(rendered).code !== code) process.exit(1);
  }
}
NODE
test "$(head -n 1 "$tmp_dir/doctor.human")" = 'doctor: PASS'
test "$(tail -n 1 "$tmp_dir/doctor.human")" = 'CONTROL PLANE USABLE'
if rg -q '/Users/|/home/|findingBodies' "$tmp_dir/doctor.human" "$tmp_dir/doctor.pipe"; then
  echo "security-program self-test: rendered output leaked a forbidden field" >&2
  exit 1
fi

run_fail 3 E_SECURITY_PROGRAM_SCAN_UNAVAILABLE scan scan
run_fail 3 E_SECURITY_PROGRAM_SCAN_UNAVAILABLE start start
run_fail 3 E_SECURITY_PROGRAM_SCAN_UNAVAILABLE resume resume
run_fail 3 E_SECURITY_PROGRAM_SCAN_UNAVAILABLE coverage_start coverage start --shard S01/P01
run_fail 3 E_SECURITY_PROGRAM_DX_INCOMPLETE coverage_resume coverage resume
run_fail 1 E_SECURITY_PROGRAM_PATH_TOKEN_UNKNOWN coverage_show_unknown coverage show --path-token "pt_v1_$(printf '0%.0s' {1..64})"
run_fail 3 E_SECURITY_PROGRAM_SCAN_UNAVAILABLE doctor_probe --doctor --probe-scanner
run_fail 2 E_SECURITY_PROGRAM_USAGE invalid invalid-command
run_fail 2 E_SECURITY_PROGRAM_USAGE invalid_show show nope
run_fail 2 E_SECURITY_PROGRAM_USAGE invalid_compile inventory compile --maybe
run_fail 2 E_SECURITY_PROGRAM_USAGE invalid_self_test --self-test extra
run_fail 2 E_SECURITY_PROGRAM_USAGE invalid_benchmark coverage benchmark --journey resume --samples 0 --warmup 2
run_fail 3 E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED invalid_migration_target coverage migrate --check --to v3
run_fail 4 E_SECURITY_PROGRAM_APPROVAL_REQUIRED migration_execute_blocked coverage migrate --to v2 --execute
run_fail 1 E_SECURITY_PROGRAM_ATTEMPT_UNKNOWN attach_unknown coverage attach --attempt attempt-fixture
run_fail 1 E_SECURITY_PROGRAM_ATTEMPT_UNKNOWN reconcile_start_unknown coverage reconcile-start --attempt attempt-fixture
run_fail 1 E_SECURITY_PROGRAM_ATTEMPT_UNKNOWN reconcile_completion_unknown coverage reconcile-completion --attempt attempt-fixture
run_fail 4 E_SECURITY_PROGRAM_APPROVAL_REQUIRED start_dry_run_blocked coverage start --shard S01/P01 --approval approval-fixture --dry-run

set +e
"$program" invalid-command >"$tmp_dir/invalid.pipe.out" 2>"$tmp_dir/invalid.pipe.err"
invalid_pipe_exit=$?
set -e
test "$invalid_pipe_exit" -eq 2
rg -Fxq $'code\tE_SECURITY_PROGRAM_USAGE' "$tmp_dir/invalid.pipe.err"
if rg -Fq $'\tundefined' "$tmp_dir/invalid.pipe.err"; then
  echo 'security-program self-test: pipe diagnostic rendered absent fields as undefined' >&2
  exit 1
fi

node - "$tmp_dir" <<'NODE'
const fs = require('node:fs');
const path = require('node:path');
const dir = process.argv[2];
for (const name of ['compile_check', 'doctor']) {
  const value = JSON.parse(fs.readFileSync(path.join(dir, `${name}.out`), 'utf8'));
  if (name.startsWith('compile_') && (value.scannerStarts !== 0 || value.networkStarts !== 0)) process.exit(1);
  if (name === 'doctor') {
    if (value.scannerAvailable !== false || value.networkRequired !== false || value.scanLaunch !== 'HOLD') process.exit(1);
    if (value.conclusion !== 'CONTROL PLANE USABLE' || value.scannerStarts !== 0 || value.networkStarts !== 0) process.exit(1);
    if (!Array.isArray(value.capabilities) || !value.capabilities.some((row) => row.id === 't7-dx' && row.state === 'HOLD')) process.exit(1);
    if (!value.capabilities.some((row) => row.id === 't7-route-review' && row.state === 'PASS')) process.exit(1);
    if (Object.hasOwn(value, 'modelPolicy')) process.exit(1);
  }
}
const listed = JSON.parse(fs.readFileSync(path.join(dir, 'coverage_list_paths.out'), 'utf8'));
if (listed.sections.length !== 1 || listed.sections[0].id !== 'S02' || listed.shards.length !== 1 || listed.shards[0].paths.length !== 219) process.exit(1);
if (!listed.shards[0].paths.every((entry) => /^pt_v1_[0-9a-f]{64}$/.test(entry.pathToken))) process.exit(1);
const shown = JSON.parse(fs.readFileSync(path.join(dir, 'coverage_show_path.out'), 'utf8'));
if (shown.pathToken !== listed.shards[0].paths[0].pathToken || shown.path !== listed.shards[0].paths[0].path || shown.shardId !== 'S02/P01') process.exit(1);
const resumed = JSON.parse(fs.readFileSync(path.join(dir, 'coverage_resume.err'), 'utf8'));
if (resumed.domainState !== 'FRESH' || resumed.next !== null || !resumed.whySafe || resumed.scannerStarts !== 0) process.exit(1);
for (const name of ['coverage_resume', 'coverage_show_unknown', 'invalid']) {
  const failure = JSON.parse(fs.readFileSync(path.join(dir, `${name}.err`), 'utf8'));
  for (const field of ['code', 'problem', 'cause', 'actual', 'effect', 'safeAction', 'artifactRef', 'rerun', 'docs', 'domainState']) {
    if (!(field in failure)) process.exit(1);
  }
  if (!Array.isArray(failure.rerun.argv) || failure.scannerStarts !== 0 || failure.networkStarts !== 0) process.exit(1);
}
const evidence = JSON.parse(fs.readFileSync(path.join(dir, 'coverage_evidence.out'), 'utf8'));
if (!evidence.verified || evidence.authorizedPathCount !== 5824 || evidence.findingBodiesExposed || evidence.absolutePathsExposed) process.exit(1);
const migration = JSON.parse(fs.readFileSync(path.join(dir, 'coverage_migrate_check.out'), 'utf8'));
if (migration.migrationRequired !== false || migration.effect !== 'No evidence was rewritten' || migration.schemas.control !== 'setjoin.security-program.control/v1') process.exit(1);
const migrationV2 = JSON.parse(fs.readFileSync(path.join(dir, 'coverage_migrate_v2_check.out'), 'utf8'));
if (migrationV2.targetVersion !== 'v2' || migrationV2.migrationRequired !== true || !migrationV2.adapterInvoked
    || migrationV2.sourceProjectionSchema !== 'setjoin.security-program.projection/v1'
    || migrationV2.targetProjectionSchema !== 'setjoin.security-program.projection/v2'
    || !/^[0-9a-f]{64}$/.test(migrationV2.sourceProjectionSha256)
    || !/^[0-9a-f]{64}$/.test(migrationV2.targetProjectionSha256)
    || !migrationV2.schemas.supportedProjectionAdapters.includes('setjoin.security-program.projection/v1->v2')) process.exit(1);
const benchmark = JSON.parse(fs.readFileSync(path.join(dir, 'coverage_benchmark.out'), 'utf8'));
if (benchmark.schema !== 'setjoin.security-program.benchmark/v1' || benchmark.status !== 'PASS'
    || benchmark.journey !== 'resume' || benchmark.samples !== 5 || benchmark.discardedWarmups !== 2
    || benchmark.results.length !== 8 || benchmark.scannerStarts !== 0 || benchmark.networkStarts !== 0
    || benchmark.developerIdentityExposed || benchmark.absolutePathsExposed || benchmark.findingBodiesExposed
    || benchmark.observed.doctorStatusP95Ms >= benchmark.targets.doctorStatusP95Ms
    || benchmark.observed.fullJourneyP95Ms >= benchmark.targets.fullJourneyP95Ms) process.exit(1);
const expectedStates = ['fresh', 'active', 'detached', 'orphaned', 'completion-unknown', 'blocked', 'eligible', 'complete'];
if (JSON.stringify(benchmark.results.map((row) => row.state)) !== JSON.stringify(expectedStates)
    || !/^[0-9a-f]{64}$/.test(benchmark.evidenceSha256)
    || !/^[0-9a-f]{64}$/.test(benchmark.sourceBinding?.controlSourceSha256)
    || benchmark.targets.doctorStatusP95Ms !== 120000 || benchmark.targets.fullJourneyP95Ms !== 300000
    || benchmark.results.some((row) => row.samples !== 5 || row.actionValidated !== true
      || row.validationMode !== 'persisted-state-subprocess' || !Number.isInteger(row.resumeExitCode)
      || typeof row.whySafe !== 'string' || row.whySafe.length === 0
      || row.scannerStarts !== 0 || row.networkStarts !== 0
      || row.measurementClass !== 'warm-after-discarded-warmups')) process.exit(1);
const command = (...args) => ({ argv: ['bash', 'scripts/verify-security-program.sh', ...args] });
const expectedRows = [
  ['HOLD', 'FRESH', 'WAIT_FOR_DX', 'SAFE_HOLD', null, 3, null],
  ['OK', 'ACTIVE', 'REJOIN_EXISTING', 'SAFE_ATTACH', command('coverage', 'attach', '--attempt', 'attempt-fixture'), 0, 0],
  ['OK', 'DETACHED', 'REJOIN_EXISTING', 'SAFE_ATTACH', command('coverage', 'attach', '--attempt', 'attempt-fixture'), 0, 0],
  ['HOLD', 'ORPHANED_START', 'RECONCILE_START', 'SAFE_RECONCILE', command('coverage', 'reconcile-start', '--attempt', 'attempt-fixture'), 3, 3],
  ['HOLD', 'COMPLETION_UNKNOWN', 'RECONCILE_COMPLETION', 'SAFE_RECONCILE', command('coverage', 'reconcile-completion', '--attempt', 'attempt-fixture'), 3, 3],
  ['BLOCKED', 'BLOCKED', 'RESOLVE_PREREQUISITE', 'SAFE_BLOCKED', command('--doctor', '--offline'), 4, 0],
  ['OK', 'ELIGIBLE', 'START_DRY_RUN', 'SAFE_DRY_RUN', command('coverage', 'start', '--shard', 'S01/P01', '--approval', 'approval-fixture', '--dry-run'), 0, 0],
  ['OK', 'COMPLETE', 'ALL_COVERAGE_RECONCILED', 'SAFE_TERMINAL', null, 0, null],
];
for (let index = 0; index < benchmark.results.length; index += 1) {
  const row = benchmark.results[index];
  const actual = [row.exitFamily, row.stateBranch, row.action, row.targetVerdict,
    row.next ?? null, row.resumeExitCode, row.nextActionExitCode];
  if (JSON.stringify(actual) !== JSON.stringify(expectedRows[index]) || row.fullJourneyP95Ms <= row.doctorStatusP95Ms) process.exit(1);
}

const invalid = JSON.parse(fs.readFileSync(path.join(dir, 'invalid.err'), 'utf8'));
if (invalid.rerun.argv.at(-1) !== '--help' || !Array.isArray(invalid.helpCommands) || invalid.helpCommands.length === 0) process.exit(1);
const unsupportedMigration = JSON.parse(fs.readFileSync(path.join(dir, 'invalid_migration_target.err'), 'utf8'));
if (unsupportedMigration.rerun.argv.join(' ') !== 'bash scripts/verify-security-program.sh coverage migrate --check') process.exit(1);
NODE

node --input-type=module - "$script_dir/security-program.mjs" \
  "$script_dir/../docs/verification/security-coverage-dx-benchmark-2026-10-29.json" <<'NODE'
import fs from 'node:fs';
const api = await import(process.argv[2]);
const json = await import(new URL('./lib/security-program-json.mjs', new URL(process.argv[2], 'file:')));
const retained = JSON.parse(fs.readFileSync(process.argv[3], 'utf8'));
api.verifyBenchmarkDocument(retained);
const loosened = structuredClone(retained);
loosened.targets = { doctorStatusP95Ms: 9000000, fullJourneyP95Ms: 9000000 };
const { evidenceSha256: ignored, ...body } = loosened;
loosened.evidenceSha256 = json.sha256Hex(json.canonicalJson(body));
try { api.verifyBenchmarkDocument(loosened); process.exit(1); }
catch (error) { if (error.code !== 'E_SECURITY_PROGRAM_EVIDENCE_INVALID') process.exit(1); }
NODE

# T7-DX documentation-currentness: the same no-launch fresh-shell path is
# discoverable from all three entry points and every shared guide exists.
for entry in "$script_dir/../README.md" "$script_dir/../CONTRIBUTING.md" \
  "$script_dir/../docs/guides/security-remediation/START-HERE.md"; do
  rg -Fq 'bash scripts/verify-security-program.sh --doctor' "$entry"
  rg -Fq 'bash scripts/verify-security-program.sh coverage status' "$entry"
  rg -Fq 'bash scripts/verify-security-program.sh coverage resume' "$entry"
done
for guide in START-HERE.md coverage-quickstart.md remediation-quickstart.md \
  command-reference.md troubleshooting.md schemas-and-migrations.md handling-and-retention.md; do
  test -f "$script_dir/../docs/guides/security-remediation/$guide"
done
rg -Fq 'coverage migrate --check' "$script_dir/../docs/guides/security-remediation/command-reference.md"
rg -Fq 'coverage benchmark --journey resume --samples 5 --warmup 2' "$script_dir/../docs/guides/security-remediation/command-reference.md"
rg -Fq 'coverage migrate --check [--to v2]' "$script_dir/../docs/guides/security-remediation/command-reference.md"
for grammar in \
  'coverage attach --attempt ID' \
  'coverage reconcile-start --attempt ID' \
  'coverage reconcile-completion --attempt ID' \
  'coverage start --shard ID --approval ID --dry-run' \
  'coverage lease adopt --attempt ID --acknowledge-stale-owner' \
  'coverage rollback --generation ID --execute'; do
  rg -Fq "$grammar" "$script_dir/../docs/guides/security-remediation/command-reference.md"
  rg -Fq "$grammar" "$tmp_dir/help.out"
done
rg -Fq 'source-bound retained JSON' "$script_dir/../CONTRIBUTING.md"
rg -Fq 'PROVISIONAL_SECTION_CATALOG' "$script_dir/../CONTRIBUTING.md"
for code in $(rg -o --no-filename 'E_SECURITY_PROGRAM_[A-Z0-9_]+' \
  "$script_dir/security-program.mjs" "$script_dir"/lib/security-program-*.mjs | sort -u); do
  sed -n '/const ERROR_CATALOG/,/^});/p' "$script_dir/security-program.mjs" | rg -Fq "$code"
  rg -Fq "$code" "$script_dir/../docs/guides/security-remediation/troubleshooting.md"
  "$program" coverage explain "$code" --json >"$tmp_dir/explain-$code.out"
  node -e 'const fs=require("node:fs"); const v=JSON.parse(fs.readFileSync(process.argv[1],"utf8")); if(v.status!=="PASS"||v.subject!==process.argv[2]||v.scannerStarts!==0||v.networkStarts!==0)process.exit(1)' \
    "$tmp_dir/explain-$code.out" "$code"
done
rg -Fq 'fresh-session T7-DX review' "$script_dir/../README.md"
rg -Fq 'fresh-session T7-DX review' "$script_dir/../docs/guides/security-remediation/START-HERE.md"
if rg -n 'Opus 5|independent route review close' \
  "$script_dir/../README.md" "$script_dir/../docs/guides/security-remediation"; then
  echo 'security-program docs contain superseded review instructions' >&2
  exit 1
fi
rg -Fq 'it never starts a scanner' "$script_dir/../docs/guides/security-remediation/START-HERE.md"

# The control and wrapper sources have no network client and no scanner launch
# import. Git is the only subprocess used, inside the frozen inventory compiler.
if rg -n "node:(?:http|https|net|tls|dns)|\bfetch\s*\(|scanner.*(?:spawn|exec)|(?:spawn|exec).*scanner" \
  "$script_dir/security-program.mjs" "$script_dir/verify-security-program.sh"; then
  echo "security-program self-test: forbidden network/scanner launch surface" >&2
  exit 1
fi

# T7-ROUTE remains a zero-launch gate. Keep its inventory, persistence,
# route-authority, canonical-record, and pinned offline-workbench proofs behind
# the single repository verification front door.
# Scanner-adapter suites need the pinned codex-security plugin; the offline
# workbench suite needs the macOS Homebrew runtime. Each is skipped by name when
# its host prerequisite is absent.
codex_security_plugin="$HOME/.codex/plugins/cache/openai-curated-remote/codex-security/0.1.24"
skipped=()
for suite in inventory primitives lifecycle migrations resume targets records workbench scale; do
  case "$suite" in
    primitives | targets | records)
      if [ ! -d "$codex_security_plugin" ]; then
        echo "security-program-$suite test: SKIP (codex-security 0.1.24 plugin not installed)"
        skipped+=("$suite")
        continue
      fi
      ;;
    workbench)
      if [ "$(uname -s)" != Darwin ]; then
        echo "security-program-$suite test: SKIP (macOS-only offline workbench)"
        skipped+=("$suite")
        continue
      fi
      ;;
  esac
  node "$script_dir/security-program-$suite.test.mjs"
done

echo "verify-security-program test: PASS (scanner=0 network=0; skipped: ${skipped[*]:-none})"
