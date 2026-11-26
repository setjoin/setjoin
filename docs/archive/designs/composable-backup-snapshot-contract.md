# Selected backup — snapshot protection and publication

Date: 2026-09-06
Status: B1 detailed proposal; no schema, backup command or production timing changed.
Owner: existing backup/recovery module and domain-owned reducers.
Authority: B1 plan.
Source baseline: [B0 inventory](composable-backup-data-inventory.md), especially
BC02–BC08 and the GC participant table. Restore is separately specified in the
[inactive-copy contract](composable-inactive-restore-contract.md).

## Small shared interface

Logical commands below are proposed interfaces, not allocated routes/permissions.
UI, CLI and admitted automation share this contract; plugins never receive backup
worker credentials or arbitrary SQL/object-store access.

| Command | Input | Authoritative outcome |
|---|---|---|
| Preview | Authenticated scope, preset, selected roots, approved backup destination | Requested/effective scope, dependencies, counts/estimates, exclusions, key/retention needs and revision-bound blockers |
| Capture | Stable operation key, exact preview revision and destination/profile digest | One operation bound to confirmed scope, or stale/denied/unsupported; no success from submission |
| Observe | Operation identity | Current authorized state, last durable receipts, actual copied/verified counts and cancellation availability |
| Cancel | Operation identity and expected generation | Cancel requested before seal; reconciliation afterward. Never deletes an existing recovery point |

An admitted preset lists its recoverable data classes explicitly. Configuration only
does not contain business-data recovery; selected scope expands dependencies only
with visible authorization; Full remains blocked if any required class lacks a
recoverable inventory. Do not rename a Drive-only capture Full. Scheduled policies
need their own reviewed scope-expansion/authorization contract; a manual exact
preview does not silently authorize future changed content or another destination.

## Preview and capture consistency

Preview is an estimate, not a long-lived PostgreSQL snapshot or byte pin. Bind its
revision to selection, ownership/ACL/policy revisions, structural/version closure,
destination, supported profiles and key requirements; do not put secrets in it.
At capture, recheck authority and recompute effective scope under snapshot S. If
the confirmed graph or dependencies changed, report stale and return a fresh preview.
Do not silently follow a moved root, include newer versions or broaden identities.
Transport-level request IDs are not stable capture keys.

After successful capture admission, later ordinary edits do not change S. Current
authority still gates subsequent copying and publication; revocation fences work,
but cleanup retains already accepted obligations according to the domain policy.
The UI distinguishes “as of capture” from current file state. If an active workload
repeatedly invalidates preview, report that conflict; any policy permitting bounded
content drift must be separately specified rather than inferred by the worker.

## Candidate durable records and states

Use reducer-owned logical records for operation intent/fence, participant epoch,
snapshot/ref inventory digest, per-object protection, copy verification, seal and
publication receipts. Names are record roles, not an allocated migration.
Legacy backup direct-SQL CAS must be migrated deliberately, not described as already
following this reducer contract. State/audit/notifications commit together.

```text
requested -> closing-delete-admission -> captured-and-protected -> copying
          -> verifying -> sealed -> publication-pending -> published
before seal: cancel/failure -> reconciling -> aborted (with retained items visible)
after seal:  interruption -> publication reconciliation, not conflicting re-seal
```

Each state change uses current executor generation/lease and expected operation
revision. A sealed operation has one immutable accepted artifact set; it cannot be
cancelled into a different recovery result. “Published” means independently stored
and verified recovery material, not merely sealed in the live database.

## Deletion barrier and durable protection

1. Register a reducer-owned deletion-admission blocker for the affected byte plane.
   Shared regular Drive scope `g` prevents treating a folder-prefix pause as enough.
   Enumerate and acknowledge every relevant deleter at its current capability epoch;
   unknown/missing participants block capture. New/restarted participants must read
   the durable blocker before deleting, not inherit a stale process-local decision.
2. Settle all previously admitted deletes, including GC's DB-delete/object-delete
   gap, before establishing S. Once closed, no new deletion ticket may pass. B0's
   queue GC and canonical-orphan sweep both participate. Uncertain external deletion
   outcome remains unresolved, not an acknowledgement that bytes are safe.
3. Establish S with the existing exported-snapshot approach; enumerate and digest
   typed metadata plus exact scoped object references. In a separate writable
   transaction persist operation-owned protections for every referenced object.
   The read-only snapshot transaction cannot write those protections itself.
4. Check completeness against the sealed capture inventory while the blocker still
   applies. Only then release this operation's broad blocker. All deleters consult
   durable per-object protection under the same object lock/fence protocol, including
   current-row-absent orphan removal. Never fake reference counts or compliance holds.
5. Copy/hash/verify protected objects and assembled streams into the approved
   independent destination. Missing bytes or unknown verification fails publication.
   Destination receipt covers actual bytes, not just successful upload responses.

Ordinary writes need not stop, but all producers must obey the same canonical-key
protocol. B0 identifies preview's direct-write path as an explicit participation
gap. Define fixed lock order and enumerate direct deletion/admin paths before
admission. This contract does not control a storage administrator deleting bytes
outside Setjoin; backend retention and independently verified recovery remain
separate qualified capabilities.

Do not retain S or the broad blocker for the entire byte-copy phase. If metadata
enumeration cannot finish within its admitted budget, abort before dropping the
blocker after durable reconciliation; never proceed with partial pins. Individual
protections survive executor expiry and remain visible until verified publication
or reconciled abort. A crashed worker cannot leave an invisible permanent GC pause.

## Publication and cancellation ordering

Write candidate artifacts under operation-owned immutable identities; verify them
before the reducer accepts a single seal binding metadata, byte inventory, scope,
schema/format, destination and recovery/key requirements. The accepted seal is the
logical commit decision; source protections still remain until publication verifies.

A protected coordinator produces the final authenticated manifest/commit evidence
only for that accepted seal. A data-copy worker cannot independently sign, change
the accepted inventory or advance a mutable latest pointer. A stale worker may at
most repeat identical immutable writes; those writes alone are not recovery-point
authority. Restore verifies the final evidence against an independently trusted
recovery root, not a key supplied solely by the same untrusted manifest.

Object storage and PostgreSQL are not one atomic transaction. Crash after seal but
before final manifest publication stays publication-pending. Resume reconciles the
same immutable seal; cancellation cannot revoke that decision after another worker
may have published it. Crash after publication before local receipt reconciles by
reading and verifying the exact artifact. Publish latest as a derived convenience,
not authority over the immutable recovery set. Release source protections only
after independent publication evidence, or pre-seal abort reconciliation.

Before seal, cancellation fences admission and in-flight effects; reconcile any
uncertain writes before reporting terminal cleanup. Retain protected/held bytes
and unknown outcomes; delete only exact unreferenced task-owned staging objects.
Existing backups, shared objects, another operation's pins and retention policies
are not cancellation targets. Lost responses use Observe under current authority.

## Bounded rehearsal and exact review tasks

Synthetic fixture only: 30-second executor claim, heartbeat every 5 seconds,
30-second broad-barrier acquisition/enumeration budget, 120-second observer wait.
Observer timeout does not cancel or fence the worker. Barrier deadline causes
pre-seal abort/reconciliation, not unsafe release; lease expiry fences mutation but
does not release pins. Restart cannot reset the operation's approved deadline.
Production limits must be measured for metadata cardinality, deletion latency,
copy volume, retry/reconciliation and retained-byte budget before qualification.

| Slice / proposed test | Required output / oracle |
|---|---|
| BS1 / BS-T01 | Exact class/closure schemas and permission mapping; preview-to-snapshot edit, ACL change and destination change refuse stale intent |
| BS2 / BS-T02 | Participant registry/epochs and lock order; GC phase-gap, orphan sweep, preview upload and restarted deleter cannot remove captured bytes |
| BS3 / BS-T03 | Durable pins plus quota/retention accounting; crash during partial registration keeps blocker or reconciles abort, never unprotected success |
| BS4 / BS-T04 | Immutable manifest and authenticated seal protocol; stale worker, altered artifact, failed final upload and response loss cannot invent a complete point |
| BS5 / BS-T05 | Paired cancel-before-seal and cancel-after-seal; one terminal decision, no competing manifests or premature protection release |
| BS6 / BS-T06 | Independent destination reconstruction against BI-T01–BI-T09; missing/corrupt Drive content/preview/key dependency refuses recovery claims |

Wire schemas, signing/commit evidence encoding, lock/participant inventory and
production budgets remain explicit freeze work. Tests named here are obligations,
not new executable tests or passed evidence. This plan grants no new trust privilege.

Continuation evidence: the [object-participation map](composable-backup-object-participation.md)
traces the bounded GC, staging, preview and Mail-capture paths; the
[resource envelope](composable-joint-resource-envelope.md) separates existing costs,
proposed budgets and later measurement. Neither replaces the BS1–BS6 contract or
qualifies the unresolved transitive/backend paths.
