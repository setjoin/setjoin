# Deep security remediation error catalog

Every stable error code emitted by the two remediation DX surfaces, with meaning,
operator remedy, and exit code. Captured examples live in [fixtures](fixtures.md);
every fixture names the exact command that produced it.

- Checker: `scripts/check-deep-security-remediation.mjs` (codes `E_SEC_REM_*`).
- Dispatcher/program namespace: `scripts/verify-security-program.sh` +
  `shared/securityprogram` (codes `E_SECURITY_PROGRAM_*`).

Exit-code legends are the ones each `--help` prints: the checker uses
`0 clean · 1 verified failure · 2 usage · 3 reopened/HOLD`; the dispatcher uses
`0 verified or terminal · 1 invalid or missing evidence · 2 usage error · 3 HOLD ·
4 blocked prerequisite`.

`coverage explain CODE` explains the `E_SECURITY_PROGRAM_*` catalog codes offline.
It does not know checker codes: `coverage explain E_SEC_REM_STALE` is a usage error
(exit 2, captured in fixtures.md) — checker codes are explained by this catalog.

## Checker codes (`E_SEC_REM_*`, scripts/check-deep-security-remediation.mjs)

Every `E_SEC_REM_*` diagnostic is a verified failure of the ER1-ER4 evidence
contract: the checker prints `CODE message` lines on stderr, then a summary line,
then exits 1. None of these codes is retryable by rerunning alone — each names a
ledger/registry/manifest defect an owner must repair. Usage errors (exit 2) carry
no code; exit 3 (reopened/HOLD) is not a code — see its section below.

| Code | Meaning | Operator remedy | Exit |
|---|---|---|---|
| `E_SEC_REM_SCHEMA` | A JSON document is unparseable, a schema/version field is wrong, or a structural field is missing/malformed (e.g. `boundaryCases` rows, `reopenedOccurrenceIds` type, overlap schema version). | Fix the named document to its pinned schema; never loosen the schema check. | 1 |
| `E_SEC_REM_IDENTITY` | Identity fields drifted from the sealed 143-row baseline (occurrenceId/findingId/ruleId/title/scanLocations), a sealed occurrence has no disposition row or vice versa, or a reopened ID is outside the sealed baseline. | Restore the sealed identity values from `sec-ledger-index.json`; never re-derive by hand. | 1 |
| `E_SEC_REM_UNIQUE` | Duplicate occurrence or finding rows in the ledger. | De-duplicate; one disposition row per sealed occurrence. | 1 |
| `E_SEC_REM_COUNTS` | Declared counts do not reconcile with recomputed rows (ledger counts, boundary-case lane count, per-lane pointer count, derived counts, plan-recorded totals). | Recompute and correct the declared counts from the rows; never edit rows to match a stale count. | 1 |
| `E_SEC_REM_STALE` | A pinned hash no longer matches the source bytes: sealed baseline pin, frozen ER3 grammar pin, canonical scan hashes, triage join inputs, or a bound evidence generation. | Rebind with justification and re-pin both sides (for the grammar: regenerate via `shared/securityprogram/cmd/gencontract`); never re-pin silently. | 1 |
| `E_SEC_REM_PATH` | A cited evidence/design path is missing or unreadable (including the ER1 contract files themselves at load time). | Restore the cited path or correct the citation; citations must resolve. | 1 |
| `E_SEC_REM_BATCH` | Plan-batch binding broken: duplicate/missing batches, over-cap batch, an occurrence in two batches, or `resumeBatch` not matching the plan batch. | Repair the batch binding against the canonical plan text. | 1 |
| `E_SEC_REM_ENUM` | A field escaped its closed enum (`disposition`, `localStatus`, `releaseStatus`, `verificationStatus`). | Use only the closed vocabularies documented in the frozen transition contract. | 1 |
| `E_SEC_REM_CLAIM` | A closure/release claim outruns its evidence: `fixed`/`no_change` without closure patch, tests, or receipt-bound verification; `blocked` without a cited reason; `release_ready` without a verified disposition; contradictory verification statement. | Add the missing occurrence-specific proof or downgrade the claim to what the evidence supports. | 1 |
| `E_SEC_REM_JOIN` | The nightly triage join drifted from its `triage-ledger.jsonl` source, a joined finding ID is unknown, join flags/counts contradict recomputation, or overlap join counts drifted. | Recompute the join from the source ledger and repair the derived document, not the source. | 1 |
| `E_SEC_REM_COMPAT` | A settled compatibility surface is outside the sealed baseline or its join flag contradicts the recomputed join. | Restore the surface binding from the sealed set. | 1 |
| `E_SEC_REM_DERIVED` | A derived sibling collides with a sealed ID or weakens sealed completion arithmetic. | Remove the collision/re-derive; sealed arithmetic is immutable. | 1 |
| `E_SEC_REM_DESIGN` | Design-applicability violation: enum escape, blanket N/A on a boundary row, `OWED` without a reopen gate, `N/A`/`UNADJUDICATED` without the required reason/note, missing evidence paths, duplicate cluster. | Supply the required reason/gate/evidence or set the honest status; the no-blanket-N/A boundary row must stay. | 1 |
| `E_SEC_REM_DAG` | The shared patch dependency graph has a cycle. | Break the cycle in the declared dependencies. | 1 |
| `E_SEC_REM_ER3` | A recorded remediation transition violates the frozen grammar: authority demotion, chain break, attempt arithmetic lie, terminal-state disagreement, `complete` without evidence binding, `reject` without cited reason. | Repair the transition history to the frozen grammar; the grammar itself is generated, never hand-edited. | 1 |
| `E_SEC_REM_ER3_CONTRACT` | The frozen grammar document itself is structurally broken (schema, contract version, canonical controller binding, authority, enums, operations, or shared catalog entries). | Regenerate via `go run ./securityprogram/cmd/gencontract` (from `shared/securityprogram`) and re-pin together with the checker hash. | 1 |
| `E_SEC_REM_REOPENED` | Bidirectional coherence failure between the predecessor registry and the overlap derivation: a registry reopen without a `same-underlying-issue` admission, or an admission not recorded reopened in its lane's `reopenedOccurrenceIds[]`. | Make both sides agree: admit the overlap entry with a source-keyed basis AND record the ID reopened in the lane registry (or undo the wrong side). | 1 |
| `E_SEC_REM_EVIDENCE` | Per-lane evidence-pointer violation: not a dated immutable generation, mutable `latest` pointer, sha256/publishedAt/verdict binding failure, aggregate drift, or lane count not 8. | Republish a new dated generation and point the manifest at it; never rewrite a pointer in place or resurrect `latest.json` as completion evidence. | 1 |

### Exit 3 — reopened/HOLD semantics (checker)

Exit 3 is not an error in the recorded evidence; it is an intentional HOLD. When a
lane's `reopenedOccurrenceIds[]` (docs/verification/security-boundary-cases.json)
names a sealed occurrence whose ledger row is not resolved — meaning disposition
`fixed`/`no_change` AND verificationStatus `receipt_bound`/`derived_green` — the
checker prints each unresolved `lane=… occurrence=… state=… disposition=…
verificationStatus=…` line and exits 3. A missing ledger row also holds
(`state=missing-ledger-row`).

Clearing a hold is the W0 path: trace and classify the occurrence, land the focused
closure proof, set the row to `fixed`/`no_change` with receipt-bound verification —
never a silent pass and never editing the registry to empty. The self-test proves
both directions: a coherent unresolved reopen holds, and `fixed + receipt_bound`
clears it. Captured live exit-3 output: [fixtures.md](fixtures.md).

### Checker usage errors (exit 2)

Any argument other than `--check`, `--self-test`, `--help`, `-h` (as the first
argument to the .mjs) prints the one-line usage and exits 2. The `.sh` wrapper
accepts only no argument (check), `--self-test`, `--help`, `-h` — it does not
forward `--check`; use the bare wrapper or the .mjs for a check run.

## Dispatcher/namespace codes (`E_SECURITY_PROGRAM_*`)

The canonical catalog lives in `scripts/security-program.mjs` (`ERROR_CATALOG`,
problem/cause/safe-action triples); `shared/securityprogram/contract.go` mirrors
the eight triples its namespace emits, and its guard tests keep the two in
lockstep — the namespace allocates no new codes. `coverage explain CODE` renders
any catalog triple offline. Exit codes below come from the dispatcher's exit
normalization and its self-test assertions.

| Code | Meaning | Operator remedy | Exit |
|---|---|---|---|
| `E_SECURITY_PROGRAM_USAGE` | Command grammar invalid. | Use the diagnostic's `helpCommands` and exact `rerun.argv` (points at `--help`). | 2 |
| `E_SECURITY_PROGRAM_PATH_TOKEN_UNKNOWN` | A path token does not resolve uniquely in the frozen inventory. | Copy a current token from `coverage list --paths`. | 1 |
| `E_SECURITY_PROGRAM_ATTEMPT_UNKNOWN` | The requested attempt ID is not the current verified attempt in the required state (includes unknown IDs passed to `attach`/`reconcile-*`, and occurrence IDs unknown to the Go namespace). | Run `coverage resume` and use its exact next argv. | 1 |
| `E_SECURITY_PROGRAM_NOT_PUBLISHED` | Canonical C0 records are missing or do not match. | Run the check/publication path before the dependent command; never hand-craft records. | 4 |
| `E_SECURITY_PROGRAM_APPROVAL_REQUIRED` | The transition lacks a bound immutable approval (migration `--execute`, rollback `--execute`, non-`service_role` authority in the Go namespace). | Obtain the named separate approval; no flag bypass exists. | 4 |
| `E_SECURITY_PROGRAM_PREREQUISITE_BLOCKED` | The persisted attempt/branch has an unmet prerequisite. | Run the exact read-only next command in the diagnostic and resolve the prerequisite. | 4 |
| `E_SECURITY_PROGRAM_PUBLICATION_BUSY` | Another publisher or a retained crash lock owns the publication. | Reconcile the publication lock before retrying. | 4 |
| `E_SECURITY_PROGRAM_PLATFORM_UNSUPPORTED` | Host is not a supported read platform (macOS arm64 / Ubuntu x86_64 classes). | Move to the named supported read environment. | 4 |
| `E_SECURITY_PROGRAM_DX_INCOMPLETE` | T7-DX acceptance is still open, so C0.5 cannot be admitted (the `FRESH` resume branch). | Complete the named gates; `coverage resume` stays HOLD meanwhile. | 3 |
| `E_SECURITY_PROGRAM_SCAN_UNAVAILABLE` | Scan launch/probing/lease adoption/coverage execution intentionally unavailable in the no-launch slice. | Stop; complete admission prerequisites. Never bypass by editing retained evidence. | 3 |
| `E_SECURITY_PROGRAM_ORPHANED_START` | A durable start has no confirmed scan identity. | Run `coverage reconcile-start --attempt ID`; never retry the start blindly. | 3 |
| `E_SECURITY_PROGRAM_COMPLETION_UNKNOWN` | A known scan has no verified terminal result. | Run `coverage reconcile-completion --attempt ID`; never launch again. | 3 |
| `E_SECURITY_PROGRAM_LIVE_LEASE` | Another owner holds the global scan lease. | Attach to the existing owner or wait; never replace it. | 3 |
| `E_SECURITY_PROGRAM_SOURCE_CHANGED` | Source no longer matches the bound fingerprint. | Create a new reviewed epoch; do not reuse prior authority. | 3 |
| `E_SECURITY_PROGRAM_SCHEMA_UNSUPPORTED` | An evidence schema/version is unsupported (including an unknown migration target or contract version in the Go namespace). | Run `coverage migrate --check` with a supported target. | 3 |
| `E_SECURITY_PROGRAM_MIGRATION_ATTEMPT_ACTIVE` | Migration is fenced by an unfinished attempt. | Resolve or reconcile the attempt before migrating (`coverage resume`). | 3 |
| `E_SECURITY_PROGRAM_EVIDENCE_INVALID` | Retained evidence failed validation (hash, binding, envelope, resume state that cannot advance). | Quarantine the artifact and reconcile from retained authority. | 1 |
| `E_SECURITY_PROGRAM_OUTPUT_PRIVACY` | Command output contained a private absolute path or protected payload field. | Replace private paths/payloads with logical references; the renderer refuses instead of emitting. | 1 |
| `E_SECURITY_PROGRAM_C0_COUNT_MISMATCH` | Frozen C0 counts do not match the approved decision. | Reconcile the frozen inventory totals with the approved C0 decision. | 1 |
| `E_SECURITY_PROGRAM_C0_OWNERSHIP_MISMATCH` | S01-S30 are not the exact authorized inventory union. | Repair the section/shard partition to the exact authorized union. | 1 |
| `E_SECURITY_PROGRAM_BENCHMARK_TARGET_MISSED` | A benchmark run missed its p95 target. | Retain the red run and diagnose the control-plane regression; direct automation exits nonzero. | 1 |
| `E_SECURITY_PROGRAM_INTERNAL` | The control plane failed closed on an unexpected error. | Retain the stable diagnostic, rerun the offline doctor; do not infer success. | 1 |
| `E_SECURITY_PROGRAM_LEASE_EXPIRED` | The retained scan lease expired; its owner cannot renew safely. | Reconcile the expired owner's attempt before adopting a lease. | 1 (reserved; see note) |
| `E_SECURITY_PROGRAM_BUNDLE_UNAVAILABLE` | A retained bundle is missing or unreadable. | Restore the retained bundle without changing its receipt. | 1 (reserved; see note) |
| `E_SECURITY_PROGRAM_BUNDLE_INSIDE_WORKTREE` | Evidence bundle configured inside a worktree. | Use the approved external migration path. | 1 (reserved; see note) |

Note on reserved codes: `LEASE_EXPIRED`,
`BUNDLE_UNAVAILABLE`, and `BUNDLE_INSIDE_WORKTREE` are catalog-reserved triples
(listed by `coverage explain`) whose owning gates have not landed in the current
no-launch CLI; when a gate emits them without an explicit exit override, the
dispatcher's fallback classifier normalizes them to exit 1. Treat the code, not
the exit, as the contract.

### Go remediation namespace (`shared/securityprogram`)

The namespace is a library: it emits only the eight shared codes above
(`CodeUsage`, `CodeApprovalRequired`, `CodeAttemptUnknown`, `CodeEvidenceInvalid`,
`CodeSchemaUnsupported`, `CodePrerequisiteBlocked`, `CodePublicationBusy`,
`CodeInternal`); process exit codes belong to the embedding controller. Every
error carries op + occurrence-specific detail, and `CodeOf` maps non-namespace
errors to `CodeInternal` (fail closed). See the [operator quickstart](remediation-quickstart.md)
for the transition lifecycle these codes guard.

## Fixture hygiene

Diagnostics contain only stable IDs, hashes, counts, states, and logical artifact
references — never credentials, finding bodies, or private bundle paths. The
dispatcher enforces this at render time (`E_SECURITY_PROGRAM_OUTPUT_PRIVACY`). If
you capture new examples for this directory, capture them read-only, keep them
repo-public, and mark each with the command and revision that produced it
([fixtures.md](fixtures.md) shows the pattern).
