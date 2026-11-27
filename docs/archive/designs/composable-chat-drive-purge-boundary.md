# Chat purge and Drive backup participation

Date: 2026-09-07. Status: source-backed planning continuation, not implementation
or executed recovery evidence. Owners: Chat compliance, Drive reducers and the
existing backup coordinator. This narrows the Chat caller left open by the
[Drive deletion map](composable-drive-deletion-reference-tails.md), under the
[backup participation](composable-backup-object-participation.md) and
[snapshot](composable-backup-snapshot-contract.md) contracts. No retention duration,
legal-hold policy, privilege or generic plugin execution engine changes here.

## Observed behavior and resulting obligations

| ID | Current source boundary | Planning consequence |
|---|---|---|
| CT01 Admission | [chat_purge_expired:37–61](../../mailserver/sql/reducers/chat_purge_expired.sql:37) exits when compliance is disabled; scans regular, unheld channels with effective retention. [Retention resolution](../../mailserver/sql/reducers/chat_effective_retention.sql:14) uses channel override, then enabled/effective kind-specific minimum, then all-kind minimum. [Hold helper](../../mailserver/sql/reducers/chat_scope_helper.sql:32) includes direct and unreleased case holds. | Reuse these domain predicates; backup cannot authorize purging by substituting its own Go selection. Full concurrent policy/hold enforcement and privilege closure are not established by this read. |
| CT02 Three destruction classes | [Purge:68–159](../../mailserver/sql/reducers/chat_purge_expired.sql:68) gathers attachment nodes for all expired messages, deletes expired non-pending scheduled Chat actions, then deletes messages in an ID-ordered limited set. [V120:42–64](../../mailserver/sql/dbschema/V120__chat_drive_binding.sql:42) cascades attachment links on message deletion, but its Drive node/version references have no delete action. | Distinguish message bodies/revisions, scheduled content, and attachment graph/bytes. An expired-message count alone does not describe all destructive effects. Candidate node aggregation and scheduled deletion are not bounded by the message LIMIT in this body. |
| CT03 Immediate attachment reclamation | [Purge:186–198](../../mailserver/sql/reducers/chat_purge_expired.sql:186) marks collected nodes deleted/purged only when no remaining Chat attachment link exists, then calls hard destroy with the same absence predicate. Hard destroy may skip or raise under its own conditions. | This is the explicit Chat path past Drive's ordinary trash grace, not a reason to change either domain's retention policy. It must join snapshot pin and deletion-ticket handling before the new backup profile is admitted. Shared chunk refcounts are not snapshot protection. |
| CT04 Federation residue | [Purge:157](../../mailserver/sql/reducers/chat_purge_expired.sql:157) redacts outbox copies using keys from the actual deleted messages. [Redactor:106–151](../../mailserver/sql/reducers/federation_outbox_redact_purged.sql:106) updates payload, preserving rows; predicates distinguish peer, room and origin for DM/hub/spoke cases. | Preserve origin-qualified matching and transport sequence continuity. Backup/restore may retain admitted historical evidence but must not reactivate or replay the old outbox. Local redaction cannot recall content already delivered to peers; federation sender/in-flight closure remains open. |
| CT05 Audit and rollback | [Purge:202–271](../../mailserver/sql/reducers/chat_purge_expired.sql:202) advances last-purged sequence only for deleted messages; records message digest elements and scheduled IDs in an audit act. Scheduled-only destruction records an act but returns no message-summary row. Only `BZ194` is caught by the per-channel block. [V126:150–162](../../mailserver/sql/dbschema/V126__chat_compliance.sql:150) raises that code on held message DELETE. | Preserve audit/counts and distinguish channel savepoint rollback from whole-call failure. An uncaught Drive WORM/other failure is not a hold skip. Do not claim all hold races are handled solely because this trigger exists; scheduled-only paths, isolation visibility and hold writers need their own proof. |
| CT06 Budget versus commit | [chat_purge_run:281–303](../../mailserver/sql/reducers/chat_purge_expired.sql:281) repeatedly invokes 5,000-message passes and checks a 90-second wall-clock deadline after each return. There is no COMMIT in either function. [Cron:55](../../mailserver/internal/cron/tasks.go:55) invokes one SELECT with a 300-second timeout; [executor](../../mailserver/internal/cron/worker.go:27) performs one pool Exec. | Repeated function passes are not durable commits. A late exception/cancellation can roll back earlier passes in that call; a long single pass can overrun the soft deadline before it is checked. Do not inherit the comment's durable-drain implication as qualified performance evidence. |
| CT07 UI preview | [Dry run:51–61](../../mailserver/sql/reducers/chat_purge_expired.sql:51) counts expired messages only, without applying the execution message LIMIT, then continues before scheduled/attachment work. [Admin preview:700–743](../../mailserver/internal/admin/admin_chat_compliance.go:700) returns per-channel and total message counts. | Label the current projection as message-retention preview, not total files/bytes/scheduled content deleted or an exact batch confirmation. A future complete destructive preview needs typed counts, retained/unknown effects and a revision-bound scope; do not change today's wire shape without its contract review. |

The visible purge sequence is scheduled/message mutations → federation outbox
mutation → Drive node UPDATE → hard-destroy tree lock and reference/chunk effects
→ channel state → Chat audit. This adds a node-before-tree caller to the prior
inversion candidates. Actual FK/trigger lock modes, audit helper order and concurrent
writers remain unclosed; this is not a proven deadlock or full graph.

## Proposed implementation-review order

1. **Capture closure and identity.** Register Chat purge as a participant affecting
   selected Drive bytes. Snapshot metadata must capture the admitted Chat/attachment
   relationships at the same consistency boundary, or explicitly advertise Drive-only
   recovery. Include scheduled-content disposition and retained audit dependencies
   for any Chat recovery claim. Transport residue is not an archive or executable
   restore workload. This does not authorize capturing unselected message content.
2. **Protection integration.** Preserve domain retention and hold checks. Captured
   metadata may outlive live references; durable pins protect required bytes across
   immediate hard destroy and subsequent GC/orphan removal. Failed partial pin
   registration cannot admit capture. Never implement a pin by faking live refs,
   extending legal holds or exempting a worker from the domain gate.
3. **Bound actual work.** Freeze separate limits for message deletion, scheduled
   deletion, node candidates, cascade work and audit payload, with measured resource
   costs under the [joint envelope](composable-joint-resource-envelope.md). Use a
   stable bounded candidate set and owning reducers; no unbounded pre-aggregation
   masquerading as a bounded message batch. Include zero-message scheduled-only
   backlog and fair progress across channels, not just total message throughput.
4. **Choose and prove commit granularity.** Preferred review candidate: the existing
   worker invokes a bounded reducer transaction repeatedly and records committed
   results, checking the deadline between transactions. Authorization, selection,
   mutations and audit remain inside the reducer. Do not put transaction control
   inside a SELECT-invoked function or move policy into Go. Freeze per-batch replay,
   fairness, total-run summary and concurrent-worker serialization before changing
   orchestration. If one-call execution is retained, advertise one-call rollback
   and qualify its worst-case work instead of claiming incremental durability.
5. **Preview/observability.** Reuse the unified UI contract: distinguish messages,
   scheduled items, attachment nodes, logical bytes and actual physical deletion.
   Unknown reclaimable bytes remain unknown. Scheduled-only progress and held/failed
   work are visible without exposing restricted hold reasons or content. A cron
   invocation returning no SQL error is not evidence of verified blob deletion.

These are proposed changes, not a mandate for a new scheduler, new retention policy
or an unreviewed public API. Existing per-process task reservation is visible in
[Task.reserve](../../mailserver/internal/cron/task.go:67); it does not establish
cross-process single-flight. Preserve the current worker boundary until its admitted
replacement and concurrency tests pass.

## Exact proposed acceptance cases

CT-T IDs are new test obligations, not executable selectors or passed results.

| Case | Injection and independent oracle |
|---|---|
| CT-T01 Captured attachment | Capture/pin a version, then purge its last Chat message and run Drive cleanup. Live message/node/ref effects match policy; backup independently reconstructs the exact selected content/preview. A surviving sibling reference remains; no unselected metadata export. Partial pins fail capture. |
| CT-T02 Hold and rollback | Direct/case hold before admission and during message/scheduled-only work; separate Drive `BZ145` failure after earlier channel progress. Require the qualified visibility/serialization policy, preserved held content and exact audit/count rollback. In current one-call mode, uncaught failure rolls back the call; never count earlier returned rows as committed. |
| CT-T03 Bounded mixed backlog | One message with many effects, many attachment candidates beyond the message batch, scheduled-only backlog, zero/null/negative batch inputs and slow cascades. Approved limits reject or bound actual work; later channels progress. A soft deadline is not a hard intra-query guarantee. |
| CT-T04 Commit/restart | Inject failure before/after each chosen transaction commit and lost response; resume from committed facts without duplicate audit effects or skipped remaining work. Distinguish observer timeout from cancellation, and unknown commit outcome from rollback. No backup-pin release on timeout. |
| CT-T05 Federation collision | Identical message keys across peers/origins/rooms for DM, hub and spoke: only intended local residue redacts, unrelated rows/sequence survive. Restore never dispatches imported outbox. In-flight/already-delivered copies are separately classified, not reported recalled. |
| CT-T06 Preview and effect counts | Message-only, scheduled-only, shared attachments, retained nodes and failed cleanup: UI/CLI show supported typed counts and unknown physical bytes honestly; no zero-message label implying zero destructive effects. Changed scope invalidates any new exact-confirmation preview. |

Existing [integration tests](../../mailserver/internal/chat/purge_integration_test.go)
were read, not run: `TestPurgeReclaimsAttachmentStorage` checks message/node removal,
chunk count and GC queue; `TestPurgeHeldChannelAttachmentSurvives` checks held data.
They do not execute the final object deletion or prove new backup pins, delayed
effects, concurrent holds or separately committed drain batches. Keep their existing
assertions and add the new cases; do not weaken them to accommodate a redesign.

## Read receipt and remaining scope

The [hold and attachment writer continuation](composable-chat-hold-writer-serialization.md)
records observed lock differences, ordered closure work and six additional proposed
concurrency cases. It narrows the remaining scope; it does not prove serialization.

Full reads: `chat_purge_expired.sql` 1–303, `chat_effective_retention.sql` 1–23,
`chat_scope_helper.sql` 1–39, `federation_outbox_redact_purged.sql` 1–155,
Chat `purge_integration_test.go` 1–218, cron `task.go` 1–149. Ranges: cron worker
1–185; cron tasks matching lines including55; admin Chat compliance690–743;
V1201–100 and V126135–180. Names/hashes/ranges are bound in the
input receipt.
Root/docs/dispatch instructions and BP/DT contracts reuse earlier complete reads
with unchanged root/docs hashes; this does not upgrade sampled source-owner DOX.

Still open: hold/classification writers and isolation, attachment creation races,
later schema/trigger/privilege definitions, audit/federation dispatch internals,
cron multi-instance admission, complete selected-restore visibility matrix and
storage adapters. Source comments are not deployed-schema or runtime evidence.
Task `sj-plan-chat-purge-20260907` created no application/runtime resources and ran
no product tests or Git operations. Implementation remains separately gated.
