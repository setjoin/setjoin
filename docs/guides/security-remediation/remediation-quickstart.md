# Remediation quickstart

The operator journey for the deep security remediation program: check state,
prove the guard, read program state, inspect one occurrence, and understand how
a disposition update is published. Every command here is read-only and was run
while writing this guide; captured outputs live in [fixtures](fixtures.md).

Remediation itself closed through the same gate: ER5 took all 143 sealed
occurrences to `fixed` closure proof via the remediation transition contract
below (the checker's summary counts are row-derived — 0 `blocked` rows remain),
that contract still gates any further disposition change, and release remains
deferred until C3 reconciles the complete
Standard, targeted Deep, delta, deferred-record, open-question, and G0-G4
overlap sets. Do not turn a partial scan result into an implementation queue.

## 1. Check the evidence state

```bash
bash scripts/check-deep-security-remediation.sh
```

Offline and read-only. Exit 0 means the four ledgers, design applicability, the
frozen ER3 transition grammar pin, the predecessor overlap mapping, the reopened
registry, and the eight per-lane evidence pointers all reconcile; the summary
lines print the live counts. Exit 1 prints each violation as `CODE message`
([error catalog](error-catalog.md)). Exit 3 is the intentional reopened/HOLD —
a predecessor lane recorded a reopened occurrence that no focused proof has
cleared yet; each `lane=… occurrence=… state=…` line names work that owns the
hold. Exit 2 is usage (the wrapper takes no argument for a check run).

## 2. Prove the guard before trusting a pass

```bash
bash scripts/check-deep-security-remediation.sh --self-test
```

Runs the planted-mutant battery in memory against deep-cloned content and ends
with `--self-test: all N planted mutants caught; clean baseline validates with
zero errors.` It also exercises both exit-3 directions: a coherent unresolved
reopen holds, and `fixed` + `receipt_bound` clears it. `run-guards.sh` runs
this checker (self-test first) as a repo guard. `--help` prints the one-line
usage; the wrapper does not forward `--check` — use the bare wrapper or
`node scripts/check-deep-security-remediation.mjs --check`.

## 3. Read the program control-plane state

```bash
bash scripts/verify-security-program.sh --doctor
bash scripts/verify-security-program.sh coverage status
bash scripts/verify-security-program.sh coverage resume
```

Doctor verifies the frozen C0 authority and read platform; status prints phase
and inventory reconciliation; resume reconstructs the safe attempt state. All
three are no-launch: exit 3 from `coverage resume` (`E_SECURITY_PROGRAM_DX_INCOMPLETE`,
`action WAIT_FOR_DX`) is the expected fresh-session result while the
fresh-session T7-DX review remains open — it means the control plane is honest
and nothing is eligible, not that your run failed. See
[command-reference](command-reference.md) for the full read-only grammar.

## 4. Inspect one occurrence (focused case)

The checker takes no occurrence-selection flag: its CLI is exactly
`[--check|--self-test|--help]`, so a "focused case" is a read-only single-row
trace with the same tools, not a different mode. For example, to pull one
occurrence's disposition state (this row is the self-test's reopen subject):

```bash
node -e 'const l=require("./docs/verification/deep-security-remediation-ledger.json"); const r=l.rows.find(x=>x.occurrenceId==="occ_01af2cba8988c33e7b45c80b"); console.log(JSON.stringify({occurrenceId:r.occurrenceId,findingId:r.findingId,title:r.title,disposition:r.disposition,localStatus:r.localStatus,verificationStatus:r.verificationStatus,releaseStatus:r.releaseStatus},null,2))'
```

which prints the row's identity and state axes:

```json
{
  "occurrenceId": "occ_01af2cba8988c33e7b45c80b",
  "findingId": "csf_0dccfde24d65a26147afcdde",
  "title": "Approved push-MFA challenges can be replayed across sessions and after expiry",
  "disposition": "blocked",
  "localStatus": "unmapped",
  "verificationStatus": "none",
  "releaseStatus": "not_ready"
}
```

Cross-reference an exit-3 hold line's `occurrence=` ID the same way, and check
its lane entry in `docs/verification/security-boundary-cases.json`
(`reopenedOccurrenceIds[]`). If a checker diagnostic names a code, read it in the
[error catalog](error-catalog.md); `coverage explain CODE` explains dispatcher
codes offline (it does not know checker codes).

## 5. How a disposition update is published (ER3 contract)

Dispositions never change by editing a ledger row's state fields by hand. The
remediation namespace owns them through four operations over one sealed
occurrence, frozen in `docs/verification/deep-security-remediation-transitions.json`
(generated from `shared/securityprogram` via `go run ./securityprogram/cmd/gencontract`,
hash-pinned by the checker — never hand-edit either side):

- `status` — read-only projection of the row's state, active attempt, and
  allowed operations. Always allowed.
- `start` — opens an attempt on an open sealed occurrence
  (`blocked` disposition, `none` verification). Requires `attemptId` and
  `runId`; an active attempt on the same occurrence, or a non-open state, is
  rejected.
- `complete` — closes an active attempt with a closure claim. Requires an
  `attemptId` matching the active attempt, a `runId`, an outcome of `fixed` or
  `no_change` (eligible only from `no_change_candidate` local status), a closure patch binding trigger,
  legitimate, and bypass evidence, occurrence-specific tests, and an evidence
  manifest path that is repository-relative with no traversal. Produces
  `proof_patched` local status, `receipt_bound` verification, and a `not_ready`
  release status.
- `reject` — closes an active attempt with its matching `attemptId`, a `runId`
  and a cited reason; disposition/local status return to `blocked`, verification
  to `none`, and release status to `not_ready`.

The **2026-09-22 grammar change** uses artifact schema
`setjoin.sec.deep-security-remediation-transitions/v2`; the request/history
contract remains `setjoin.sec.security-program-remediation/v1`. Concrete rules in
`shared/securityprogram/rules.go` drive both Go staging and artifact generation.
Each operation's `from` constrains named axes (omitted axes are unconstrained).
Its `to` overlays the input state, preserving unmentioned axes; `localRewrites`
then applies the declared local-state rewrite. `outcomes` selects disposition
subject to `outcomeFrom`. `requires` names caller fields and `receiptRequires`
names minted evidence fields. The checker interprets these facts; it does not
treat enum membership alone as an allowed transition. All three mutations
require an open sealed state; `status` records no transition.

The old grammar artifact is retained byte-for-byte at
`shared/securityprogram/testdata/transitions-v1.json`. Existing v1 histories are
checked without rewriting them. Unknown grammar/history versions fail closed
with a version diagnostic. Any historical difference must be classified as a
checker defect, artifact defect or version/compatibility requirement with an
owner before promoting stricter enforcement; actual closure questions return to
ER4/ER6. Roll back the Go rule/generator, checker and generated artifact/pin
together if necessary, preserving both grammar fixtures and original evidence.
This grammar change needs no data migration and changes no release verdict.

Every operation validates, for that specific occurrence: the contract version
(`setjoin.sec.security-program-remediation/v1`), the caller authority
(`service_role` only — anything else is `E_SECURITY_PROGRAM_APPROVAL_REQUIRED`),
existence in the sealed ledger (unknown IDs are never guessed), and the current
state. The frozen contract binds `scripts/verify-security-program.sh` as the
canonical controller; the dispatcher's `coverage` namespace today exposes the
read/resume/dry-run paths and holds execution verbs, and the plan's
"Initial verification front doors" name the `remediation full` /
`remediation evidence` dispatcher commands as required gates when that front
door lands — this guide documents the contract those commands must implement,
not a runnable subcommand. Until then, the checker is the enforcement point:
any ledger row carrying `remediationTransitions` is validated against the same
frozen grammar. The guard wrapper runs independent valid/invalid histories and
historical compatibility tests before its requested check/self-test mode.
`go test ./securityprogram/...` from `shared/` sends real serialized start/complete,
start/reject and retry outputs through the same checker, with independent state,
count, statement and evidence-hash assertions. Node is a required local test
dependency; missing tooling is a failure. The existing publication/crash and
authority tests remain separate from transition proof.

## 6. Evidence publication and the per-lane pointer manifest

Predecessor boundary evidence resolves through
`docs/verification/security-boundary-evidence-manifest.json`: one dated
immutable pointer per lane (audit, bootstrap, contracts, ingress, migration,
push, recovery, updates) plus one aggregate. The contract the checker enforces:

- Each pointer names a dated immutable generation (`generationId`,
  `manifestPath`, `manifestSha256`, `publishedAt` equal to the generation
  timestamp, `verdict`, `exitCode`, `evidenceSchemaVersion`,
  `sourceFingerprint`) and must bind a passed generation to count as
  completion evidence.
- The overwriteable `latest.json` is retained run output, never completion
  evidence; a `latest` reference in the manifest is a violation
  (`E_SEC_REM_EVIDENCE`).
- Republishing a lane means producing a new dated generation and pointing the
  manifest at it, then updating the aggregate — never rewriting a pointer in
  place. `aggregate.combinedSha256` is recomputed mechanically over the eight
  per-lane pointers.
- A lane recorded with reopened occurrences holds at exit 3 until each ID is
  cleared by source-keyed adjudication with focused proof.

Handling, retention, and escalation hygiene: [handling-and-retention](handling-and-retention.md).

## 7. Measure your own path in

Time your first pass with the [TTHW and boomerang cases](tthw-boomerang.md);
returning operators resume from the ledgers and the dispatcher state instead of
re-deriving any of the above.

## Where to go next

- [Error catalog](error-catalog.md) — every `E_SEC_REM_*` and
  `E_SECURITY_PROGRAM_*` code with remedy and exit code.
- [Fixtures](fixtures.md) — captured `--help` and JSON output for both tools.
- [Troubleshooting](troubleshooting.md) — dispatcher code remedies and the
  offline `coverage explain` surface.
