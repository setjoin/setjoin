# Storage E5 / E9 — durable physical deletion obligations

Date: 2026-09-08. Proposed transition contract, not deployed schema, migration,
compliance qualification or numerical score. Owning invariant:
[shared lifecycle protection](storage-lifecycle-protection-contract.md).
[E0 work order](storage-specification-completion-map.md) must close all producers,
readers, hold owners and deleters before concrete schema/lock/provider freeze.

## Source motivation and preserved safeguards

Root read `mailserver/internal/blob/handler.go:150–305`: attachment cleanup
atomically deletes only a zero-reference metadata row, then calls remote removal.
The queue's cascading deletion means that successful metadata removal does not
itself leave that queue entry available to retry a later remote failure. Its
existing pre-delete reference/FK protection must be preserved; it does not settle
the later remote-I/O/recreation window. Raw cleanup separately checks
`messages.raw_ref`, removes the exact key, and dequeues after successful removal;
its check is not a complete shared-reference/reader census or held lock through I/O.
These source observations do not claim a reproduced failure or full caller audit.

Root also read the current baseline hold trigger at1416–1436 and retention
reducer1–113 (actual EOF). `OLD.held` blocks message DELETE; retention catches only BZ015 and
lets other failures propagate. Preserve that transactional protection and honest
error behavior. A mailbox policy, stored message hold, physical provider hold and
temporary reader pin remain different owners, not interchangeable booleans.

| Source | Whole-file SHA-256; ranges above are actual reads |
| --- | --- |
| `mailserver/internal/blob/handler.go` | `17702fdf0fd793ca77b3d3598af37e290dc87a7ac332f5785e8c73f50c220e53` |
| `mailserver/sql/dbschema/V001__baseline.sql` | `a5cfe54ffeb452f51a14ac1d3d896a6ef9bb766f66cd0720051bd68d9b529a14` |
| `mailserver/sql/reducers/retention.sql` | `7933fa9b45f87ef90aff2a323ce20a0a75f77fd7b58d84771bc84603e75a7387` |

## Proposed transitions

Names are semantic only; exact row keys, grants, statuses and wire receipts remain
the joint E5/B1 protocol output. Business eligibility remains reducer-authoritative;
the byte worker executes a narrowly bound obligation and reports observations.

| Transition | Required authority / durable result |
| --- | --- |
| Candidate | A due queue row is only a hint. Recheck the exact representation and current logical references, independent pins and compliance predicates under the shared serialization boundary |
| Admit deletion | Atomically preserve an operation-owned physical obligation before removing its last bookkeeping parent. The obligation survives metadata deletion, queue cascades, restart and lease expiry; bind exact provider/placement, security scope, encoding generation, immutable object/version and fence |
| Execute | Current executor may act only on that exact admitted identity under a qualified late-effect protocol. Do not hold an unbounded database transaction across remote I/O; do not infer that a database fence cancels a remote request |
| Observe | Record confirmed absence/removal, provider retention denial, transient failure or unknown outcome separately. Response loss is unknown until reconciled; it is not successful deletion or authorization to delete another generation |
| Reconcile | Freshly inspect owner/protection disposition and exact remote identity before retry. Preserve unresolved effects and block conflicting adoption unless immutable identity isolation makes it safe. Provider denial remains visible and retryable only under current eligibility |
| Complete | Commit a terminal receipt only for the exact settled obligation. Remove active retry work only after terminal persistence; retain bounded audit/evidence according to existing policy, not permanent detailed payload history |

The operation record cannot disappear through the very foreign-key cascade that
removes the logical object it tracks. It also cannot retain dangling references
that prevent every eligible logical removal forever. E5 must select the concrete
independent tombstone/outbox relationship and lock order, with no duplicate
generic lifecycle service. Existing Drive keyed GC stays in place until an
equivalent replacement is qualified; this closes Mail's physical boundary under
the same ownership rules, not an assertion that both currently share code.

## Concurrent protection and identity reuse

Before remote deletion is issued, new protection/adoption may win serialization
and invalidate the candidate. After issue, that physical identity cannot be
promised safe for a new owner until the effect is settled or an independently
immutable version isolates it. A request arriving during this window must receive
an explicit retry/block outcome or adopt a different qualified physical identity;
it cannot be acknowledged against potentially disappearing bytes.

Do not decide this from plaintext hash equality alone. A newly uploaded same-hash
object at a reused key is not necessarily the object the old request was allowed
to delete. The provider adapter must freeze conditional/versioned deletion or
equivalent identity isolation and its absence semantics. Provider capabilities
that cannot satisfy this contract remain unqualified for this operation.

Logical owner release and aggregate physical hold clearing remain separate as in
the export/hold map.
Removing A's authorized hold does not remove B's hold; clearing the last legal
hold does not defeat timed WORM or independent reader/backup/migration protection.
No deletion retry may turn off provider protection merely to make progress.

## Proposed failure cases — none executed

| Case | Required observable result |
| --- | --- |
| PD-01 parent cascade then remote failure | Crash/fail after metadata/queue deletion and before/after remote request; durable exact obligation survives and resumes without reconstructing authorization from a bare key |
| PD-02 response loss | Remote deletion succeeds but response/receipt is lost; reconcile one exact identity and persist one terminal result, without touching a replacement object |
| PD-03 renewed reference | Reference/pin/hold arrives before admission or remote issue; serialize disposition. After issue, do not acknowledge new ownership of endangered bytes |
| PD-04 same-key recreation | Delay old remote deletion, attempt new upload/adoption and resume old worker; new accepted content survives or adoption is explicitly blocked until safe |
| PD-05 protection denial | Object-lock/retention denial is visible retained work, not success; no worker bypass, cleared hold or uncontrolled retry loop |
| PD-06 partial raw ownership | Raw key remains needed by accepted outbound/held delivery or reader without a live message row; shared owner census prevents premature deletion |
| PD-07 logical hold | Held message DELETE remains rejected transactionally, including attachment cascades; non-hold reducer failures remain failures rather than apparent skipped success |

Before implementation freeze exact receipt/error schema, retry backoff/age/capacity
bounds, reconciliation escalation and source-keyed fixtures/lanes. Candidate queues
must not become unbounded silent leaks; reaching a bound produces visible blocked
work, not destructive fallback. These cases extend LP/EH oracles without treating
existing test names or source comments as executed race evidence.
