# Help and JSON output fixtures

Captured, sanitized examples for the remediation checker and the security-program
dispatcher. Every block names the exact command that produced it, its exit code,
and where the output went (stdout/stderr). All commands were run read-only against
the tracked tree at revision `2dea65db02a1ffc10e8bb3462c3314a57b08eb3d`,
2026-09-19; nothing in the working tree was modified to produce them.

Two blocks are labeled `sandbox capture`: they were produced the same way but
inside a disposable `/tmp` copy of the tracked tree (made with
`git archive HEAD | tar -x -C "$dir"`) with one planted mutation, because a
failing state cannot exist in a healthy tree. Each such block documents its exact
mutation so the capture is reproducible.

Output modes: the dispatcher renders human text on an interactive terminal,
stable `field<TAB>value` rows when stdout is redirected (all pipe-mode captures
below), and versioned JSON with one `--json` anywhere in the command. Diagnostics
always go to stderr. The checker prints plain text only.

Counts inside these captures (inventory paths, occurrence counts, mutant counts,
timings) are the tools' live output at capture time. They are evidence of what the
commands printed, not claims to rely on: always trust the corresponding live run
over any number printed here.

## Checker

### `node scripts/check-deep-security-remediation.mjs --help` — exit 0, stdout

```text
usage: node scripts/check-deep-security-remediation.mjs [--check|--self-test|--help]
exit codes: 0 clean · 1 verified failure · 2 usage · 3 reopened/HOLD
```

### `bash scripts/check-deep-security-remediation.sh` (check) — exit 0, stdout

Verbatim at capture time; the summary counts are live output, not a claim.

```text
deep-security-remediation: four ledgers + design applicability internally consistent;
  143/143 sealed occurrences dispositioned (143 fixed, 0 no_change, 0 blocked),
  nightly triage join recomputed and reconciled, counts reconcile, all citations resolve;
  ER3 frozen transition grammar hash-pinned and remediation chain validation armed;
  ER4 predecessor overlap mapped (26 occurrences, 0 admitted same-underlying-issue),
  predecessor registry reopenedOccurrenceIds[] consistent (all lanes empty), and
  eight per-lane evidence pointers + aggregate manifest reconciled.
```

### `bash scripts/check-deep-security-remediation.sh --self-test` — exit 0, stdout

Planted-mutant battery (runs first under `scripts/run-guards.sh`). Full capture
kept; the mutant count is whatever the live run reports.

```text
  mutant caught: missing occurrence row -> E_SEC_REM_IDENTITY
  mutant caught: duplicate occurrence row -> E_SEC_REM_UNIQUE
  mutant caught: identity tamper (ruleId) -> E_SEC_REM_IDENTITY
  mutant caught: fixed without proof -> E_SEC_REM_CLAIM
  mutant caught: dangling evidence path -> E_SEC_REM_PATH
  mutant caught: counts drift -> E_SEC_REM_COUNTS
  mutant caught: stale sealed-index pin -> E_SEC_REM_STALE
  mutant caught: batch binding tamper -> E_SEC_REM_BATCH
  mutant caught: enum escape -> E_SEC_REM_ENUM
  mutant caught: nightly join fabrication -> E_SEC_REM_JOIN
  mutant caught: patch dependency cycle -> E_SEC_REM_DAG
  mutant caught: overlap join drift -> E_SEC_REM_JOIN
  mutant caught: compatibility join-flag lie -> E_SEC_REM_COMPAT
  mutant caught: derived collides with sealed id -> E_SEC_REM_DERIVED
  mutant caught: derived arithmetic weakened -> E_SEC_REM_DERIVED
  mutant caught: open-coverage count drift -> E_SEC_REM_COUNTS
  mutant caught: open-coverage false embedding claim -> E_SEC_REM_CLAIM
  mutant caught: blanket N/A bypass -> E_SEC_REM_DESIGN
  mutant caught: OWED without reopen gate -> E_SEC_REM_DESIGN
  mutant caught: dangling design evidence path -> E_SEC_REM_PATH
  er3 control: valid start+complete chain validates clean
  mutant caught: ER3 authority demotion -> E_SEC_REM_ER3
  mutant caught: ER3 chain break (missing start) -> E_SEC_REM_ER3
  mutant caught: ER3 terminal-state lie -> E_SEC_REM_ER3
  mutant caught: ER3 complete without evidence binding -> E_SEC_REM_ER3
  mutant caught: ER3 attempt arithmetic lie -> E_SEC_REM_ER3
  mutant caught: ER3 frozen grammar tamper -> E_SEC_REM_STALE
  mutant caught: registry reopen without overlap admission -> E_SEC_REM_REOPENED
  mutant caught: same-underlying-issue not recorded reopened -> E_SEC_REM_REOPENED
  mutant caught: reopened occurrence outside sealed baseline -> E_SEC_REM_IDENTITY
  mutant caught: malformed reopenedOccurrenceIds type -> E_SEC_REM_SCHEMA
  mutant caught: predecessor seed floor drop -> E_SEC_REM_COUNTS
  mutant caught: evidence aggregate drift -> E_SEC_REM_EVIDENCE
  mutant caught: mutable latest evidence pointer -> E_SEC_REM_EVIDENCE
  mutant caught: pointer date not matching generation -> E_SEC_REM_EVIDENCE
  mutant caught: per-lane pointer dropped -> E_SEC_REM_COUNTS
  exit-3 mutant caught: coherent unresolved reopen -> reopened/HOLD (exit 3; lane=recovery state=unresolved disposition=blocked verificationStatus=none)
  exit-3 resolution control: fixed + receipt_bound reopened row clears the HOLD (no silent-pass inversions)
  reopened/HOLD baseline: no recorded reopened occurrence; exit 0
--self-test: all 36 planted mutants + 2 validation control leg(s) caught; clean baseline validates with zero errors.
```

### `node scripts/check-deep-security-remediation.mjs --bogus` — exit 2, stdout

```text
usage: node scripts/check-deep-security-remediation.mjs [--check|--self-test|--help] (got --bogus)
```

### Exit 1 — verified failure (sandbox capture), stderr

Mutation: in the sandbox copy only,
`docs/verification/security-boundary-evidence-manifest.json`
`aggregate.combinedSha256` was replaced with 64 `0` characters (the self-test's
"evidence aggregate drift" mutant, applied on disk).

```text
E_SEC_REM_EVIDENCE evidenceManifest.aggregate.combinedSha256 does not reconcile with the eight per-lane pointers
deep-security-remediation: 1 contract violation(s)
```

### Exit 3 — reopened/HOLD (sandbox capture), stderr

Mutation: in the sandbox copy only, a coherent source-keyed reopen was planted —
`security-boundary-cases.json` push lane `reopenedOccurrenceIds` set to
`occ_01af2cba8988c33e7b45c80b`, and the matching
`deep-security-remediation-overlap.json` `predecessorOverlap` entry changed from
`derived` to `same-underlying-issue` with counts kept honest — while the ledger
row stayed `blocked/none`. This is the self-test's exit-3 control shape (the
self-test itself plants the recovery lane).

```text
deep-security-remediation: reopened/HOLD — a predecessor boundary case is re-opened with unresolved sealed occurrences:
  lane=push occurrence=occ_01af2cba8988c33e7b45c80b state=unresolved disposition=blocked verificationStatus=none
  1 unresolved reopened occurrence(s); trace and classify each (W0), clear only with focused proof, never a silent pass.
```

## Dispatcher

### `bash scripts/verify-security-program.sh --help` — exit 0, stdout (redirected = pipe rows)

```text
command	help
commands[0]	inventory compile --check
commands[1]	inventory compile --execute
commands[2]	--doctor [--json] [--offline]
commands[3]	coverage list [--section S01] [--paths]
commands[4]	coverage status
commands[5]	coverage show --section S01
commands[6]	coverage show --path-token TOKEN
commands[7]	coverage resume
commands[8]	coverage attach --attempt ID
commands[9]	coverage reconcile-start --attempt ID
commands[10]	coverage reconcile-completion --attempt ID
commands[11]	coverage start --shard ID --approval ID --dry-run
commands[12]	coverage lease adopt --attempt ID --acknowledge-stale-owner
commands[13]	coverage rollback --generation ID --execute
commands[14]	coverage evidence
commands[15]	coverage migrate --check [--to v2]
commands[16]	coverage benchmark --journey resume --samples 5 --warmup 2
commands[17]	coverage explain [C0|HOLD|error-code]
exitCodes.0	verified or terminal
exitCodes.1	invalid or missing evidence
exitCodes.2	usage error
exitCodes.3	HOLD
exitCodes.4	blocked prerequisite
schema	setjoin.security-program.control/v1
status	PASS
unavailable[0]	scan launch
unavailable[1]	coverage start --execute
unavailable[2]	lease adoption
unavailable[3]	rollback execution
unavailable[4]	external capability probe
```

### `bash scripts/verify-security-program.sh --help --json` — exit 0, stdout

```json
{
  "command": "help",
  "commands": [
    "inventory compile --check",
    "inventory compile --execute",
    "--doctor [--json] [--offline]",
    "coverage list [--section S01] [--paths]",
    "coverage status",
    "coverage show --section S01",
    "coverage show --path-token TOKEN",
    "coverage resume",
    "coverage attach --attempt ID",
    "coverage reconcile-start --attempt ID",
    "coverage reconcile-completion --attempt ID",
    "coverage start --shard ID --approval ID --dry-run",
    "coverage lease adopt --attempt ID --acknowledge-stale-owner",
    "coverage rollback --generation ID --execute",
    "coverage evidence",
    "coverage migrate --check [--to v2]",
    "coverage benchmark --journey resume --samples 5 --warmup 2",
    "coverage explain [C0|HOLD|error-code]"
  ],
  "exitCodes": {
    "0": "verified or terminal",
    "1": "invalid or missing evidence",
    "2": "usage error",
    "3": "HOLD",
    "4": "blocked prerequisite"
  },
  "schema": "setjoin.security-program.control/v1",
  "status": "PASS",
  "unavailable": [
    "scan launch",
    "coverage start --execute",
    "lease adoption",
    "rollback execution",
    "external capability probe"
  ]
}
```

### `bash scripts/verify-security-program.sh --doctor` — exit 0, stdout (pipe rows)

```text
c0	PASS
capabilities[0].id	source-and-inventory
capabilities[0].state	PASS
capabilities[1].id	canonical-publication
capabilities[1].state	PASS
capabilities[2].id	read-only-cli
capabilities[2].state	PASS
capabilities[3].architecture	arm64
capabilities[3].hostClass	local-unclassified
capabilities[3].id	platform-read-path
capabilities[3].platform	darwin
capabilities[3].state	PASS
capabilities[3].supportedReadPath	true
capabilities[4].id	t7-route-review
capabilities[4].state	PASS
capabilities[5].code	E_SECURITY_PROGRAM_DX_INCOMPLETE
capabilities[5].id	t7-dx
capabilities[5].state	HOLD
capabilities[6].code	E_SECURITY_PROGRAM_SCAN_UNAVAILABLE
capabilities[6].id	scan-launch
capabilities[6].state	HOLD
command	doctor
conclusion	CONTROL PLANE USABLE
networkRequired	false
networkStarts	0
scanLaunch	HOLD
scannerAvailable	false
scannerStarts	0
schema	setjoin.security-program.control/v1
status	PASS
```

Interactive terminals render the same document as human text; it begins
`doctor: PASS` and ends `CONTROL PLANE USABLE` (asserted by the dispatcher
self-test).

### `bash scripts/verify-security-program.sh --doctor --json` — exit 0, stdout

```json
{
  "c0": "PASS",
  "capabilities": [
    { "id": "source-and-inventory", "state": "PASS" },
    { "id": "canonical-publication", "state": "PASS" },
    { "id": "read-only-cli", "state": "PASS" },
    {
      "architecture": "arm64",
      "hostClass": "local-unclassified",
      "id": "platform-read-path",
      "platform": "darwin",
      "state": "PASS",
      "supportedReadPath": true
    },
    { "id": "t7-route-review", "state": "PASS" },
    { "code": "E_SECURITY_PROGRAM_DX_INCOMPLETE", "id": "t7-dx", "state": "HOLD" },
    { "code": "E_SECURITY_PROGRAM_SCAN_UNAVAILABLE", "id": "scan-launch", "state": "HOLD" }
  ],
  "command": "doctor",
  "conclusion": "CONTROL PLANE USABLE",
  "networkRequired": false,
  "networkStarts": 0,
  "scanLaunch": "HOLD",
  "scannerAvailable": false,
  "scannerStarts": 0,
  "schema": "setjoin.security-program.control/v1",
  "status": "PASS"
}
```

### `bash scripts/verify-security-program.sh coverage status` — exit 0, stdout (pipe rows)

```text
authorizedCount	5824
command	status
excludedCount	375
exclusionClassCount	4
exclusionCounts.agent-worktrees	1
exclusionCounts.vendored-biometric-reference	21
exclusionCounts.vendored-reference-docs	287
exclusionCounts.vendored-security-reference	66
exclusionPolicySha256	2b98ae3ac8ec76ddc0ad139b78a1e6ea5e9e777027815b2b8d8bcb13b1b6dede
historicalCandidateCount	6163
inventoryDecision	MATCHED
inventorySha256	b48c312ddc01b7410463eeb1bc659da6a28b2ee2bff50a4d422bf95b5b7407af
networkStarts	0
ownerSectionCount	30
phase	C0
phases.C0.claimed	true
phases.C0.state	PASS
phases.C0.verified	true
phases.C0.5.claimed	false
phases.C0.5.state	HOLD
phases.C0.5.verified	false
phases.C1.claimed	false
phases.C1.state	HOLD
phases.C1.verified	false
phases.C2.claimed	false
phases.C2.state	HOLD
phases.C2.verified	false
phases.C3.claimed	false
phases.C3.state	HOLD
phases.C3.verified	false
phases.D1.claimed	false
phases.D1.state	HOLD
phases.D1.verified	false
publication	MATCHED
revision	727f40ad1274d950926369913a464bcc8f2e0236
scanLaunch	HOLD
scannerStarts	0
schema	setjoin.security-program.control/v1
shardCount	30
status	PASS
treePathCount	6199
```

### `bash scripts/verify-security-program.sh coverage resume` — exit 3 (intentional HOLD), stderr (pipe rows)

The expected fresh-session result while T7-DX acceptance is open:

```text
action	WAIT_FOR_DX
actual.reason	T7-DX acceptance must close before C0.5 can be admitted
actual.state	withheld
artifactRef	plan:whole-codebase-security-coverage#T7-DX
cause	The remaining T7-DX runtime gates are still open
code	E_SECURITY_PROGRAM_DX_INCOMPLETE
command	coverage resume
docs	docs/guides/security-remediation/troubleshooting.md
domainState	FRESH
effect	No shard is eligible and no scanner may start
exitFamily	HOLD
networkStarts	0
next	null
problem	The operator control plane is incomplete
rerun.argv[0]	bash
rerun.argv[1]	scripts/verify-security-program.sh
rerun.argv[2]	--doctor
rerun.argv[3]	--offline
safeAction	Complete the named gates before C0.5
scanLaunch	HOLD
scannerStarts	0
schema	setjoin.security-program.diagnostic/v1
stateBranch	FRESH
status	HOLD
targetVerdict	SAFE_HOLD
whySafe	No admitted attempt or shard authority exists, so no scanner may start
```

### `bash scripts/verify-security-program.sh coverage resume --json` — exit 3, stderr (JSON diagnostic)

The same diagnostic in versioned JSON (stdout stays empty):

```json
{
  "action": "WAIT_FOR_DX",
  "actual": {
    "reason": "T7-DX acceptance must close before C0.5 can be admitted",
    "state": "withheld"
  },
  "artifactRef": "plan:whole-codebase-security-coverage#T7-DX",
  "cause": "The remaining T7-DX runtime gates are still open",
  "code": "E_SECURITY_PROGRAM_DX_INCOMPLETE",
  "command": "coverage resume",
  "docs": "docs/guides/security-remediation/troubleshooting.md",
  "domainState": "FRESH",
  "effect": "No shard is eligible and no scanner may start",
  "exitFamily": "HOLD",
  "networkStarts": 0,
  "next": null,
  "problem": "The operator control plane is incomplete",
  "rerun": {
    "argv": ["bash", "scripts/verify-security-program.sh", "--doctor", "--offline"]
  },
  "safeAction": "Complete the named gates before C0.5",
  "scanLaunch": "HOLD",
  "scannerStarts": 0,
  "schema": "setjoin.security-program.diagnostic/v1",
  "stateBranch": "FRESH",
  "status": "HOLD",
  "targetVerdict": "SAFE_HOLD",
  "whySafe": "No admitted attempt or shard authority exists, so no scanner may start"
}
```

### `bash scripts/verify-security-program.sh bogus-command` — exit 2, stderr (pipe rows)

A usage failure is one versioned diagnostic; `rerun.argv` points at `--help` and
`helpCommands` carries the full valid grammar (18 rows, elided here — the exact
list is the `commands[]` array in the `--help --json` capture above):

```text
actual.reason	unknown command or arguments; run help
actual.state	withheld
artifactRef	control:E_SECURITY_PROGRAM_USAGE
cause	Arguments do not match a supported command
code	E_SECURITY_PROGRAM_USAGE
command	diagnostic
docs	docs/guides/security-remediation/troubleshooting.md
domainState	HOLD
effect	The requested transition was not performed
exitFamily	FAIL
helpCommands[0]	inventory compile --check
  … helpCommands[1..17] elided; identical to commands[] in --help --json …
networkStarts	0
problem	The command grammar is invalid
rerun.argv[0]	bash
rerun.argv[1]	scripts/verify-security-program.sh
rerun.argv[2]	--help
safeAction	Run --help
scanLaunch	HOLD
scannerStarts	0
schema	setjoin.security-program.diagnostic/v1
status	FAIL
```

### `bash scripts/verify-security-program.sh coverage explain HOLD` — exit 0, stdout

```text
command	explain HOLD
explanation	HOLD means later scan operations are intentionally unavailable until their separately reviewed implementation slices land.
schema	setjoin.security-program.control/v1
status	PASS
subject	HOLD
```

### `bash scripts/verify-security-program.sh coverage explain E_SECURITY_PROGRAM_APPROVAL_REQUIRED` — exit 0, stdout

```text
command	explain E_SECURITY_PROGRAM_APPROVAL_REQUIRED
diagnostic.cause	No matching immutable approval is bound to the attempt
diagnostic.code	E_SECURITY_PROGRAM_APPROVAL_REQUIRED
diagnostic.docs	docs/guides/security-remediation/troubleshooting.md
diagnostic.effect	The unsafe transition is blocked
diagnostic.problem	The requested operation lacks explicit approval
diagnostic.safeAction	Obtain a reviewed approval before retrying
networkStarts	0
scanLaunch	HOLD
scannerStarts	0
schema	setjoin.security-program.control/v1
status	PASS
subject	E_SECURITY_PROGRAM_APPROVAL_REQUIRED
```

### `coverage explain` on a checker code — exit 2, stderr (JSON)

`coverage explain` knows `C0`, `HOLD`, and the `E_SECURITY_PROGRAM_*` catalog
only. `bash scripts/verify-security-program.sh coverage explain E_SEC_REM_STALE --json`
returns the usage diagnostic (abridged; full shape as the exit-2 capture above):

```json
{
  "actual": { "reason": "unknown explain subject", "state": "withheld" },
  "artifactRef": "control:E_SECURITY_PROGRAM_USAGE",
  "code": "E_SECURITY_PROGRAM_USAGE",
  "command": "diagnostic",
  "exitFamily": "FAIL",
  "problem": "The command grammar is invalid",
  "rerun": { "argv": ["bash", "scripts/verify-security-program.sh", "--help"] },
  "safeAction": "Run --help",
  "schema": "setjoin.security-program.diagnostic/v1",
  "status": "FAIL"
}
```

Checker codes are explained by the [error catalog](error-catalog.md) instead.

### `bash scripts/verify-security-program.sh coverage evidence` — exit 0, stdout

```text
absolutePathsExposed	false
artifactRef	verification:security-coverage-c0
authorizedPathCount	5824
command	coverage evidence
findingBodiesExposed	false
generationId	owners-as-shards/v1
inventorySha256	b48c312ddc01b7410463eeb1bc659da6a28b2ee2bff50a4d422bf95b5b7407af
networkStarts	0
revision	727f40ad1274d950926369913a464bcc8f2e0236
scanLaunch	HOLD
scannerStarts	0
schema	setjoin.security-program.control/v1
sectionCount	30
shardCount	30
status	PASS
verified	true
```

### `bash scripts/verify-security-program.sh coverage migrate --check` — exit 0, stdout

```text
adapterInvoked	true
attemptFenceState	FREE
command	coverage migrate --check
effect	No evidence was rewritten
migrationRequired	false
networkStarts	0
scanLaunch	HOLD
scannerStarts	0
schema	setjoin.security-program.control/v1
schemas.control	setjoin.security-program.control/v1
schemas.diagnostic	setjoin.security-program.diagnostic/v1
schemas.epoch	setjoin.security-program.epoch/v1
schemas.sections	setjoin.security-program.sections/v1
schemas.shards	setjoin.security-program.shards/v1
schemas.supportedProjectionAdapters[0]	setjoin.security-program.projection/v1->v2
sourceProjectionSchema	setjoin.security-program.projection/v2
sourceProjectionSha256	6ed8b9a97e2af31f34812d810161bf2a1b88e97ce1ce10afc975d4693a9b2868
status	PASS
targetProjectionSchema	setjoin.security-program.projection/v2
targetProjectionSha256	6ed8b9a97e2af31f34812d810161bf2a1b88e97ce1ce10afc975d4693a9b2868
targetVersion	current
```

With `--to v2` the same command reports `targetVersion v2`,
`migrationRequired true` (the v1-to-v2 dry check), and distinct
source/target projection hashes; it still publishes nothing.

### `bash scripts/verify-security-program.sh coverage show --section S01` — exit 0, stdout

```text
command	coverage show --section S01
inventorySha256	b48c312ddc01b7410463eeb1bc659da6a28b2ee2bff50a4d422bf95b5b7407af
pathCount	71
pathListSha256	551b8f8387ec8aa5a53daae069f9956f4159eda2373eecceed53a779228c5f70
revision	727f40ad1274d950926369913a464bcc8f2e0236
scanLaunch	HOLD
schema	setjoin.security-program.control/v1
sectionId	S01
shardId	S01/P01
status	PASS
```

### `bash scripts/verify-security-program.sh coverage list` — exit 0, stdout (head/tail; 204 rows total)

Lists phases and all 30 owner sections/shards. Head:

```text
command	list
networkStarts	0
phases[0].id	C0
phases[0].name	canonical inventory
phases[0].state	AVAILABLE
phases[1].id	C0.5
phases[1].name	pilot
phases[1].state	HOLD
phases[2].id	C1
phases[2].name	standard coverage
phases[2].state	HOLD
phases[3].id	D1
phases[3].name	targeted deep review
phases[3].state	HOLD
  … phases[4..5] and sections[0..29]/shards[0..28] elided …
```

Tail:

```text
shards[29].ownerSectionId	S30
shards[29].pathCount	23
shards[29].pathListSha256	885c6eb1a0c083cf43182c864afdb8189758967221fc8e39a1937fecd7712527
status	PASS
```

`coverage list --section S02 --paths` adds one row per frozen path with an opaque
`pt_v1_<64-hex>` token (219 rows for S02/P01 at capture time — take the live
count from the command, never from this sentence); resolve one with
`coverage show --path-token TOKEN`.

### `bash scripts/verify-security-program.sh coverage benchmark --journey resume --samples 5 --warmup 2` — exit 0, stdout (head; 205 rows total)

Measured 48s wall on the capture host; the full document carries eight journey
rows (one per resume state branch) plus privacy flags:

```text
absolutePathsExposed	false
architecture	arm64
command	coverage benchmark --journey resume
developerIdentityExposed	false
discardedWarmups	2
evidenceSha256	896c9090fbad924ffa4050b8e8090f160b429ce138019c7f44586ab0c852c711
findingBodiesExposed	false
generatedAt	2026-09-19T14:20:16.679Z
hostClass	local-unclassified
journey	resume
networkStarts	0
observed.doctorStatusP95Ms	419.415
observed.fullJourneyP95Ms	809.872
platform	darwin
  … results[0..7] result rows and interleaved scalars elided …
```

Tail, verbatim:

```text
samples	5
scanLaunch	HOLD
scannerStarts	0
schema	setjoin.security-program.benchmark/v1
sourceBinding.controlSourceSha256	4352384c88f6f4fd8e3d35058ddac2adde1687913c0b1793106da7c3818de35c
sourceBinding.inventorySha256	b48c312ddc01b7410463eeb1bc659da6a28b2ee2bff50a4d422bf95b5b7407af
sourceBinding.revision	727f40ad1274d950926369913a464bcc8f2e0236
sourceBinding.shardGenerationId	owners-as-shards/v1
status	PASS
supportedReadPath	true
targets.doctorStatusP95Ms	120000
targets.fullJourneyP95Ms	300000
```

Timings are the capture host's live numbers; the targets (120s doctor p95,
300s full-journey p95) are the stable part of this document.

## Reproducing a capture

Run any command exactly as labeled and diff against the block. For the two
sandbox blocks: `git archive HEAD | tar -x -C /tmp/repro &&` apply the mutation
documented in the block, then run the checker from `/tmp/repro`. Never plant a
mutation in your working tree to reproduce a fixture.
