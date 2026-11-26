# Chat hold and attachment writer serialization

Date: 2026-09-07. Status: bounded planning addition to the
[Chat purge boundary](composable-chat-drive-purge-boundary.md), not implementation,
a reproduced vulnerability, runtime evidence or a full lock-graph sign-off.
Owners: Chat compliance and Drive reducers. This preserves existing retention,
hold scope, privileges and backup selection; it does not introduce a plugin API.

## Source-backed differences

| Path | Observed ordering | Consequence for implementation planning |
|---|---|---|
| [Direct hold](../../mailserver/sql/reducers/chat_channel_set_hold.sql:46) | Channel row `FOR UPDATE`, then hold change and audit. Same-reason re-set is idempotent; release requires a matching nonblank reason. | This protects competing direct-hold writers, but is not by itself a proof that every destructive statement shares that boundary. Preserve these distinct set/release outcomes. |
| [Case hold set](../../mailserver/sql/reducers/chat_case_hold_set.sql:39) | Case status read precedes scope advisory lock; custodian uses `chat_hold_user_`, channel scope uses `chat_hold_chan_`. Insert hold, snapshot membership/authored-channel union, insert coverage and audit. The union has no ordering clause. | Do not mistake the two advisory namespaces for the channel row lock. Qualify case-close overlap and cross-channel audit locking; no closed-case race is claimed reproduced. Historical coverage must still include departed authors. |
| [Case release](../../mailserver/sql/reducers/chat_case_hold_release.sql:39) | Hold row lock and release update precede sorted coverage-channel advisory locks and last-active-case audit checks. | Sorted release loops alone do not establish a globally consistent order with other writers. Keep coverage history, other active holds and the separate direct-hold audit stream. Do not split this transaction into visible partial releases merely to reduce lock count. |
| [Join coverage trigger](../../mailserver/sql/dbschema/V127__chat_oversight.sql:84) | An AFTER INSERT membership trigger takes the custodian advisory lock, looks up active holds, inserts missing coverage and audits. | The trigger does not acquire its lock before the initiating membership INSERT. Trace caller and FK locks as well; a helper-only ordering diagram is insufficient. Preserve coverage on leave and idempotent insertion. |
| [Send attachment](../../mailserver/sql/reducers/chat_message.sql:354) | Channel state UPDATE precedes message insertion. Attachment processing ensures a Chat Drive space, creates a new node and version, then inserts the message/attachment link. [Node creation](../../mailserver/sql/reducers/drive_node_create.sql:42) acquires the Drive tree lock. | The ordinary send path creates a fresh node per attachment; it does not simply attach an arbitrary existing node. Its visible channel-before-tree order contrasts with purge's tree-before-late-channel-update path. This is an inversion candidate, not a demonstrated deadlock. |
| [Version writer](../../mailserver/sql/reducers/drive_file_put_version.sql:45) | Rejects already-linked Chat/Meet immutable records before ref/file-lock checks and subsequent manifest work. | A check's presence is not concurrent-writer closure. Inventory every attachment-link writer and effective privilege before concluding that no competing existing-node link is possible. Shared chunk content is not shared node identity or a backup pin. |

The purge-side sequence and scheduled-only gap are owned by CT01–CT07. New-space
creation also calls Drive audit/notify; therefore the observed channel/tree edges
are only a projection of the real transaction. Audit, FK, RLS, classification,
case-close and membership entry paths remain required closure inputs.

## Ordered work before implementation admission

1. **Close the actual participants.** Enumerate writes to direct hold, case state,
   case holds/coverage, membership, channel classification/retention and attachment
   links in reducers, migrations/triggers and authorized workers. Map each initiating
   transaction, including outer locks and later audit/notification effects. Record
   current signatures, lock keys/modes and privilege grants; an audit actor argument
   alone must never become authorization for a new public endpoint.
2. **Freeze one serialization protocol, not one extra lock.** Preferred candidate
   is an owning per-channel destructive-decision boundary shared by hold-affecting
   writes and purge, composed with the existing custodian/case and Drive boundaries.
   Decide whether the existing channel row is sufficient or another boundary is
   needed only after the graph is closed. Specify a total order for every resource
   class and sorted multi-channel acquisition; trace node/tree, audit and FK locks
   too. Do not simply insert a channel lock after a writer has already acquired
   incompatible locks. No final primitive/order is approved by this paper.
3. **Specify the committed outcome.** Re-evaluate hold, classification, retention
   and candidate eligibility after the serialization boundary, with demonstrated
   visibility under the actual transaction isolation. A pre-lock read or SQL
   `STABLE` predicate is not accepted as visibility evidence. If the hold operation
   commits first, subsequent purge may not delete the protected data, including
   scheduled-only content. If a lawful purge commits first, a later hold cannot
   resurrect that content; the response/audit must not imply it did. An in-flight
   hold request is pending, not already effective. Preserve existing atomic hold
   semantics; any proposed asynchronous or partial activation needs product review.
4. **Bound without weakening protection.** Measure maximum custodian fan-out,
   lock count, wait duration and audit payload against the joint resource envelope.
   A confirmed pre-commit abort must roll back without reporting a successful
   hold/release or committed purge. Observer timeout, lost response and cancellation
   racing commit leave the outcome unknown until authoritative reconciliation;
   infer neither success nor rollback and do not release pins on that basis.
   An oversized request needs a reviewed admission outcome,
   not silent truncation of coverage. Retain the existing trigger as defense in
   depth until equivalent protection is proven; do not rely on retrying deadlocks
   as the correctness argument.
5. **Integrate with CT, then qualify.** Bind the chosen protocol to CT's bounded
   destructive batches and backup-pin lifecycle. Do not add a second Chat-specific
   object store or GC engine. Backend deletion cessation and backup reconstruction
   remain separate acceptance gates; SQL serialization does not establish either.

## Proposed deterministic cases

HW-T IDs are obligations, not executable tests or passing evidence. Implement with
two or more real database connections and explicit barriers at the named boundary,
not timing sleeps. Record commits, errors, message/scheduled/link/node state, active
coverage and audit facts independently of response text. Run both commit orders;
include confirmed abort, cancellation before/after commit and lost response. An
aborted operation never counts as success; an unknown outcome is reconciled from
authoritative committed facts before retry or cleanup, not presumed rolled back.

| Case | Required oracle |
|---|---|
| HW-T01 Hold versus purge | Direct, channel-case and custodian holds against message and scheduled-only purge: hold-first preserves covered content; purge-first reports only lawful committed deletion. No successful hold acknowledgment before its commit. |
| HW-T02 Join/set/release | Join before/after custodian snapshot, leave after coverage, and release during join: no missed active coverage, duplicate set audit or pruned history. Multiple active cases and the direct hold remain independent. |
| HW-T03 Case and policy mutation | Case-close, classification promotion and retention changes overlap hold admission and purge. Freeze each domain's permitted outcome from its owning contract before coding assertions; no stale pre-lock admission. |
| HW-T04 Attachment and cleanup | Normal fresh-node send overlaps purge in the same Chat Drive space, including first-space creation and shared chunk content. Committed sends retain exact bytes/links; unrelated purge progresses without orphaning them. Any other admitted link writer gets its own existing-node race fixture. |
| HW-T05 Lock composition | Two overlapping multi-channel holds/releases, send and purge acquire the qualified real lock graph under reversed arrival order. No unbounded wait, silent partial coverage or double audit. Verify worst admitted fan-out, rollback and fair purge progress; deadlock retries alone do not pass. |
| HW-T06 Backup overlap | Capture selected attachment metadata and pins while holds, sends and purge interleave. Independently reconstruct the captured version after live-node reclamation; no unselected content export, fabricated live ref or premature pin release. |

## Caller closure supplement — case close and ordinary member add

[CloseCase](../../mailserver/internal/admin/admin_ediscovery_cases.go:179) performs
an active→closed case UPDATE in one pool call, then a separate best-effort global
audit call whose error is ignored. The body does not release Chat holds or acquire
their advisory locks. Combined with case hold set's pre-lock status read, this
leaves case-close versus new-hold admission unqualified. Existing hold truth depends
on unreleased coverage, not case status: **closing a case must not be treated as an
implicit hold release** by the refactor. This is the current source behavior, not
an assertion that every historical product specification has been reconciled.

Plan case close as an authorized owning reducer transaction with its audit, sharing
the qualified case-state boundary with new hold admission. Recheck active state
under that boundary. Close-first rejects a new set; set-first may commit its hold
before close and the hold remains until the explicit release path. Preserve existing
error outcomes for missing/already-closed cases unless the owning contract review
approves a change. Any proposal to automatically release holds requires a separate
product/security decision, not a convenience cleanup during app uninstall.

[Ordinary member add](../../mailserver/sql/reducers/chat_channel.sql:399) locks the
channel row before checking role, calling guest helpers and inserting membership.
The AFTER INSERT coverage trigger subsequently takes the custodian advisory lock.
Case hold set takes that custodian lock before coverage insertion and its channel
foreign-key interaction. This supplies a concrete **candidate reverse order**:
member add channel→custodian versus hold set custodian→channel reference. Qualify
the actual conflicting FK lock modes under loaded schema; do not claim a reproduced
deadlock. Use an authored-but-departed custodian so hold coverage can target the
same channel without requiring the in-flight join to be visible. Reordering just
the trigger cannot repair outer locks already taken by the initiating transaction.

Add these fixtures to existing HW cases, not a separate scheduler or hold engine:

- **HW-T02 extension:** pause ordinary add after its channel lock, pause custodian
  hold after its scope lock, then release barriers in both orders. Preserve complete
  coverage and membership, bounded completion and rollback truth. Include the
  departed-author fixture and retain the accepted guest/federation restrictions.
- **HW-T03 extension:** pause hold set before/after its active-case check while
  close commits; test close-first and set-first outcomes above. Inject close-audit
  failure: the proposed reducer must roll back the case transition on confirmed
  abort. Lost response remains an unknown commit outcome until reconciled.
- **HW-T05 extension:** include actual outer membership locks and coverage FKs in
  the matrix, not only the helper's advisory lock. Guest grant helpers, removal,
  creation/DM paths, default-channel joins and federation/worker membership writers
  are separate inventory entries; the ordinary-add sample does not close them.

Root supplement reads: `admin_ediscovery_cases.go`179–222, `chat_channel.sql`399–522
and V12776–112, with earlier complete hold-set/hold-helper reads. No product test,
full handler middleware or later-FK/role qualification is implied. The bounded
source-mapping receipt and independent review are recorded in the continuation
ledger. This supplement narrows HW steps1–2 but does not approve a final lock order.

## Evidence boundary and remaining gate

The [finite membership inventory and Meet slice](composable-chat-membership-writer-closure.md)
names five remaining writer groups and preserves their exact read/qualification
boundaries, including the separate indirect-write closure requirement.

The [policy transaction continuation](composable-chat-policy-transaction-closure.md)
identifies a concrete classification partial-write path, audit before-image and
execution-grant obligations, with a bounded repair ordered before lock redesign.
Its source-backed plan does not close the remaining caller/privilege graph.

Full source reads for this addition: `chat_channel_set_hold.sql` (77 lines),
`chat_case_hold_set.sql` (103), `chat_case_hold_release.sql` (85),
`chat_space_ensure.sql` (93), `drive_node_create.sql` (90), V127 (127).
Sampled: `chat_message.sql` 139–519; `drive_file_put_version.sql` 1–115.
Classification was search-only, not a full read. CT's earlier purge receipt remains
the authority for its unchanged source observations; no source-owner DOX, later
schema or full role closure is implied. No product test was run.

Implementation admission stays HOLD until steps1–2 close the participant/lock
graph and the domain outcomes for HW-T03 are frozen. This is a finite next review
unit, not permission to implement a speculative lock hierarchy. UI decisions,
backend qualification and the aggregate plan score remain outside this packet.
