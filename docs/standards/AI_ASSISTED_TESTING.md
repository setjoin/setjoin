# AI-assisted testing and verification

Status: mandatory, enforced
Effective: 2026-07-22
Evidence background: `retired-docs:superpowers/research/2026-07-22-ai-generated-code-testing-standards.md`

## Purpose

AI-authored code does not get a weaker correctness bar, and a universal 100%
line-coverage target does not make it correct. Setjoin requires complete,
traceable evidence for shipped behavior and risk while using structural
coverage as one signal among several.

This standard applies to every new or changed behavior. Legacy gaps are
measured and ratcheted; they are not silently declared covered and do not need
to be backfilled in one change.

## Required evidence

Every shipped acceptance criterion must have one of:

1. an automated merge-blocking test;
2. an explicit release-blocking environment test;
3. a time-bounded exception with an owner, independent approver, reason,
   tracking reference, and expiry date.

An inventory entry is not evidence by itself. A claimed automated test counts
only when its owning lane executes it and the result is available to the gate.
A missing, errored, or unexpectedly skipped required test is a failure.

Critical boundaries include authentication, authorization, tenancy and account
scope, secrets, destructive operations, migrations, backup/restore, durable
queues, revocation, and security-policy enforcement. A change to one of these
must enumerate the applicable success, denial, cross-tenant, retry,
idempotency, recovery, and rollback obligations. “Not applicable” is a review
decision, not an omitted row.

## Gate classes

### Merge-blocking

Merge gates run on every applicable pull request, fail closed, and require only
repository-controlled or localhost dependencies. Missing tooling is an error
with an installation instruction, never a successful skip.

The default merge evidence is:

- structural guards and their planted-violation self-tests;
- Go unit/integration tests with DB-backed tests forced to execute;
- complete pgTAP reducer suites against a freshly loaded disposable database;
- Webmail type checking and Vitest coverage thresholds;
- host-runnable Rust and client tests in their owning lanes;
- dependency and vulnerability checks according to the existing gate contract.

### Release-blocking

Browser journeys, protocol containers, native-device lanes, real restore and
restart rehearsals, performance checks, and production-policy exercises may
require an explicit environment. They do not block every commit, but they must
run before the affected release. An unavailable environment is reported as
not-run and can never be presented as a pass.

The release record names the origin/device/environment, input boundary,
observable result, and retained artifact. Production credentials, customer
data, and production mutation are not implied by this standard.

## Coverage policy

### Requirements and invariants

- Target 100% traceability from shipped acceptance criteria to real evidence.
- Target 100% evidence for every applicable critical invariant and failure
  obligation.
- A skipped or missing required test does not satisfy either target.

### Structural coverage

- Preserve measured global coverage as a no-regression ratchet.
- New or changed testable code targets at least 90% changed-line coverage.
- Narrow pure logic targets 99% when the remaining branches are deterministic
  and testable.
- Critical decision code targets 90–100% of the structural measure the language
  actually provides, plus explicit adversarial tests for important branches.

The 90% changed-code threshold is merge-blocking for both Webmail and Go, with
95% required for configured critical paths. Both reporters use
`git diff --find-renames`, count executable changed lines rather than whole-file
age, ignore deleted lines, compare `HEAD` with the merge-base of the configured
base revision, include untracked production source as wholly new code, and fail
when source maps, coverprofile blocks, or file attribution are missing. Webmail
maps V8 statement spans back through source maps; Go expands native
statement/block spans across their executable source lines and synthesizes
new-file hunks for untracked `.go` files before attribution. Generated output
and platform-gated code require narrow, documented mechanical exclusions
applied before the denominator is computed.

Do not call Go's `-covermode=atomic` branch coverage. Go's native profile is
statement/block coverage; `atomic` changes counter synchronization. Critical Go
branches therefore require named behavioral cases even when statement coverage
is high.

PL/pgSQL coverage currently means reducer/requirement/error-path pgTAP evidence,
not an invented line percentage. Line-level SQL coverage may become a separate
ratchet only after a stable measurement tool is deployed and baselined.

### Current Webmail baseline

`npm run test:coverage` is a local and remote merge gate. The measured
2026-07-23 baseline is 83.20% statements, 70.00% branches, 82.67% functions,
and 84.80% lines. `vite.config.js` explicitly includes every
`src/**/*.{js,ts,svelte}` file so never-imported production files remain in the
denominator, and enforces floors of 80% statements, 70%
branches, 80% functions, and 82% lines. The small margin absorbs source-map and
supported Node patch-level rounding without hiding a material regression.
Raising a threshold requires a fresh measured baseline; lowering one requires
an explicit review and rationale.

Go coverage uses `-coverpkg=./...` inside each module, so packages without tests
remain in the module denominator. Test files, generated protobufs, package
documentation, the updater's explicitly test-only release-fixture generator,
and the Linux-only immutable-file adapter are mechanically excluded from the
changed-line denominator; ordinary product code is not. The fixture generator
is exercised as test infrastructure, while the exact Linux adapter is covered
by the Ubuntu deployment lane and its Linux-build-tagged tests because a Darwin
profile cannot attribute it. The dated report is retained in
`test-results/coverage/go-summary.json`; the enforced floors live in
`docs/verification/go-coverage-thresholds.json`. On 2026-07-23 the honest
whole-module measurement was 47.85% aggregate statement/block coverage, with
module floors of 40% for authserver, 46% for mailserver, 67% for shared, 21%
for mailctl, and 49% for asrbot. The same run covered 35/35 changed Go product
lines and 27/27 configured critical changed lines. These floors and changed-line
gates are structural ratchets, not a substitute for exact named behavioral
evidence at critical boundaries.

## Test effectiveness

For a critical guard, prove that the test detects removal or bypass of the
guard. Prefer a targeted planted violation, dependency fault, or controlled
fault-injection seam in the merge lane. Whole-module mutation tools belong in a
scheduled audit lane unless their runtime and determinism are demonstrated.

Do not mutate production source in place during a gate. A self-test operates on
a copy, fixture, injected dependency, or generated mutant and must prove the
detector turns red before its green verdict is trusted.

## Independent oracle

Tests must cite or derive from an authority independent of the implementation:
a specification, ADR, protocol reference, security invariant, incident, or
independent review. The same coding agent reading its own implementation is not
the sole authority for critical behavior.

Critical tests record their authority in the nearest test contract, test
comment, or owning DOX. Human or independent model review remains a process
control and does not replace executable evidence.

## Feature/test contracts

The machine-readable registry is
`docs/verification/feature-test-contracts.json`. Its validator is
`scripts/check-feature-test-contracts.sh`.

`docs/verification/required-test-evidence.json` separately pins the required
requirement and evidence IDs. `scripts/check-required-test-evidence.sh` rejects
silent deletion, renaming, or duplication of those IDs, so shrinking the
feature registry cannot make an obligation disappear unnoticed.

The registry is enforced. An `enforced` entry may claim
a structural guard that:

- is auto-discovered by `scripts/run-guards.sh`;
- has a planted-violation self-test;
- contains the referenced selector;
- fails closed in local and remote CI.

It may also claim an exact result-bound test when a self-tested adapter matches
the registry's suite and test id against a retained machine report and fails on
missing, ambiguous, skipped, failed, malformed, absent, or flaky-after-retry
results. Live result bindings cover Vitest JSON, Go JSON, verbose pgTAP/TAP,
and Playwright JSON. Each binding names its `merge` or `release` gate class;
Go and pgTAP reports are retained by CI for 14 days, while the explicit browser
lane retains the mutable suite's explicit origin separately from the isolated
static-CSP origin, JSON verdicts, failure traces/screenshots, and Guest
terminal-state screenshots under `mailserver/webmail/test-results/`.

This restriction is deliberate: merely pointing at a Go, Vitest, pgTAP, or
Playwright file does not prove that a named case executed or was not skipped.
Only exact result-bound cases may be `enforced`; broader file-only claims remain
`planned` until a machine report and owning lane prove their outcomes.

Each enforced requirement declares obligations and evidence that covers every
obligation, or a governed exception. Duplicate ids, missing files/selectors,
uncovered obligations, stale/expired exceptions, absolute/out-of-root paths,
and unknown schema fields fail the guard.

## Exceptions

An exception contains all of:

- accountable owner;
- independent approver different from the owner;
- concrete reason and bounded risk;
- tracking issue or plan;
- expiry date.

Expired exceptions fail CI. Permanent exclusions belong in a language/tool
configuration with a durable rationale; they are not renewable exception rows.

## Rollout

1. **Enforced now:** global Webmail and per-module Go floors, plus independent
   Webmail and Go gates for 90% changed-line coverage and 95% changed-line
   coverage on configured critical paths. Structural wiring and the contract
   registry fail closed locally and in remote CI.
2. **Exact evidence now:** Vitest, Go, pgTAP, and Playwright emit retained machine
   results and exact registry bindings are enforced in their owning merge or
   release lanes. Adapter self-tests plant skipped, missing, malformed, ambiguous,
   and flaky failures. Changed-code self-tests cover rename/new-path attribution,
   source-map/file absence, exclusions, thresholds, and deleted-only diffs.
3. **Scheduled assurance:** mutation/fault campaigns, browser/native/recovery,
   performance, and security release evidence.

Repository files can define and exercise checks, but required-check settings on
the hosting platform are an external administrative action and must be verified
separately.
