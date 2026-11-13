# Security remediation and refactor sequencing

Date: 2026-09-07. Status: recorded recommendation for later implementation.
The user currently prioritizes plan review/scoring. This note authorizes no scan,
finding adjudication, product code, runtime tests, deployment or Git publication.
Owner: composable program,
with existing security/domain remediation owners, not a new parallel executor.

## Recommendation

Combine scheduling and dependencies, not security finding identities. Fix confirmed
serious security defects before the broad refactor; combine a fix with a bounded
refactor only where it directly removes the root cause and can close promptly.
Never refactor first and assume disappearance of the old file means the bug is fixed.
Do not require every low-risk finding to close before unrelated safe refactor work.

The 2026-09-06 read-only inventory found 274 scanner-reported validated findings in
72 target artifact directories: 17 HIGH, 80 MEDIUM, 177 LOW after normalizing casing
and `resolvedSeverity`/`severity`. This is a historical partial-scan count, not a
whole-repository assurance or 274 independently confirmed unique vulnerabilities.
Source: `retired-docs:zcode-security-deep/artifacts/<target>/findings.json`; scanner epoch in
`retired-docs:zcode-security-deep/queue.json` was `727f40ad1274d950926369913a464bcc8f2e0236`.
Its mechanical validator checks JSON/inventory/revision bookkeeping, not each
source-to-impact exploit chain. Preserve original evidence and model attribution.

## Later work order

1. Freeze intake identities, artifact hashes, scan revision and current source
   fingerprints. Account for missing/deferred scan scope. Preserve one disposition
   per supplied finding; correlate overlaps with existing remediation IDs without
   deleting original reports or counting one fix as independent discoveries.
2. Adjudicate the 17 reported HIGH findings first, then inspect MEDIUM findings for
   serious authority/data boundaries. Confirm reachability, actor, supported
   configuration, controls, consequence and counterevidence against current code.
   Rank by exploitability and impact, not severity labels alone. Unresolved evidence
   remains needs-review; an unavailable test is not proof of a false positive.
3. Route each confirmed issue to exactly one existing execution owner:

   | Route | Admission rule |
   |---|---|
   | Fix first | Account takeover, cross-tenant access, severe exposure/loss, privileged execution or similar serious boundary failure; use the smallest complete verified fix |
   | Fix with bounded refactor | Same root cause and directly affected milestone; no unrelated multi-month prerequisite; explicit regression and replacement-path proof |
   | Independent localized fix | Defect unrelated to the architectural change; do not invent a platform dependency |
   | Investigate / evidenced closure | Uncertain, overlapping or already-fixed reports; retain proof gaps or concrete defeating evidence, never silent dismissal |

4. For implementation, demonstrate the original failure with a safe regression
   test or qualified alternative proof before changing behavior. Apply the fix or
   bounded refactor, run the same oracle and adjacent security/compatibility tests,
   then test the actual integration boundary. A test unable to run remains an open
   evidence gate. Removal needs proof the entry point is retired and the replacement
   does not preserve the vulnerable path.
5. Maintain one finding-to-milestone map with original ID, current verdict, affected
   source fingerprint, owner, prerequisite, regression selector, closure evidence
   and remaining release gate. One structural fix may close several reports only
   when each report's specific consequence is independently covered.
6. Split implementation into reviewable, resumable batches. Reopen only changed
   contracts and their direct consumers; preserve existing domain tests, historical
   scores and mandatory CI. Never merge a broad cleanup into a security patch solely
   because both touch the same directory.

## Gates and non-goals

Pre-release status permits coordinated structural corrections; it does not make
data loss or authority bypass acceptable. No claim of production exposure is made.
Mandatory security gates remain first when execution starts. Current plan review
may continue before that execution; no issue is dismissed or marked fixed by this
documentation task. Independent reviews, actual implementation approval and existing
release evidence requirements remain unchanged. Do not add a second security scanner,
finding database, generic authorization engine or competing refactor roadmap.

## Source-derived repair candidates recorded during planning

The later [membership caller contract](composable-chat-membership-writer-closure.md#federation-repair-rejected-frame-isolation-before-extracting-interfaces)
records MW-F01 (invite poison after membership/reactivation writes) and MW-F02
(NULL operation bypassing room-scope dispatch), with exact source anchors and
MW-T10/11 regression oracles. These are source-derived findings, not executed
exploits, newly adjudicated scan occurrences or a change to the historical 274
count. On authorized remediation intake, correlate their source/symbol/impact
with existing canonical findings first, then assign one existing C2/security owner.
Preserve the rejected-frame no-domain-effects and explicit-op authorization
contracts; repair before extracting this boundary. Do not wait for a broad
plugin refactor or claim either defect fixed because its plan now exists.

The [policy transaction contract](composable-chat-policy-transaction-closure.md)
similarly records the two-call admin classification partial-write path and its
atomic reducer repair. Its PC-T cases belong to the existing Chat/admin owner.
All three remain planned/unfixed by this documentation task; concurrent-lock
candidates in adjacent sheets retain their lower, unproven status.
