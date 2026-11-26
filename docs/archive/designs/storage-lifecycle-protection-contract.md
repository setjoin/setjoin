# Storage E5–E7 / Backup B1 — independent protection and cutover

Date: 2026-09-08. Proposed invariant/transition packet, not a deployed schema,
lock implementation, encryption format or numerical score.
Owners: Storage E5–E7
and [Backup B1](composable-backup-data-inventory.md). E0 must close participating
producers/readers/deleters before the concrete lock/protocol freeze.

## Source baseline, not the new coordinator

Root read the complete `mailserver/internal/storage/migration.go` and
`mailserver/internal/admin/admin_storage_migrate.go`. Their hashes are respectively
`e3c30a5e7ef494998ec82df41b3c92579131c07b3c9a66f7cbf1b59c9be2c702`
and `e45614933cd09d72c58c317e6d6c5436cd15a7c105970c14e9f87b13f0094e21`.
The former records a `dual_write` label without implementing dual writes, queries
positive-ref attachment blobs, skips existing destinations on HEAD success without
byte verification, continues past several per-object failures and sets total to
the migrated count. The handler creates a fresh in-memory migration object for
cancel; updating its database status does not establish that the original worker
has stopped. These are bounded source facts, not executed race/failure evidence.

Do not reuse those status names or reported percentage as proof of a complete
inventory, actual cancellation, cutover, encryption or source protection. The
new coordinator retains reducer authority and the accepted maintenance-first
mode. It must reconcile existing accepted work, not cosmetically rename this loop.
No route authorization, full caller graph or existing tests were audited here.

## Distinct identities and owners

An object protection binds the exact provider/placement identity, security scope,
encoding generation and immutable physical object/version identity. A plaintext
hash or a directory prefix alone is insufficient. Logical file/version/message
references remain domain-owned; physical protection does not create read access.

| Protection class | Acquirer / reason | Only permitted release basis |
| --- | --- | --- |
| Live domain reference | Drive/Mail/domain reducers retain accepted content and work obligations | Authoritative reference transition; preserve other domains' references and independent protections |
| In-flight reader | Owning authorized read operation against a selected immutable representation | Completed/aborted reader plus proven end of dependent physical access; timeout alone is not proof that remote work stopped |
| Backup capture | Backup owner binds exact snapshot/reference inventory | Independent verified copy and committed recovery point, or explicit aborted-capture reconciliation proving no remaining dependency |
| Migration source | Storage operation retains source during conversion/movement and rollback window | Definitively reconciled pre-cutover abort releases only this operation's obsolete protection without deleting the authoritative source; after cutover, separate source-retirement approval requires all recovery, minimum retention, reader and hold gates |
| Migration staging | Exact operation/executor owns unpublished target objects | Ownership-verified failed/aborted staging reconciliation, or conversion to authoritative target references/protections at commit |
| Compliance retention / legal hold | Existing domain/compliance authority | Its own current eligibility and separately authorized release, never a backup/migration expiry |

Each record has one owner/operation identity and immutable protected-object binding;
replay returns that owner's existing result and rejects changed input. Release is
compare-and-reconcile against the exact owner and generation, not “clear all pins
for this hash.” Backup and migration cannot release each other's protection.
Do not forge `ref_count`, reuse upload claims as snapshot pins, or disguise temporary
backup protection as compliance retention. Their lifetimes and authority differ.

The concrete E5/B1 schema must define row keys, indexes, mutation grants, exact
lock order, fan-out limits, generation/fence comparison and receipt projections.
This table specifies ownership, not another app-access capability or universal
public pin API. Workers never receive a bypass that can remove domain holds.

## Physical deletion admission and late effects

Delete eligibility requires the conjunction of current domain-reference absence,
all independent protection dispositions and compliance eligibility. Check it at
the same authoritative object serialization boundary as producer/adoption and
protection registration; a read-then-delete gap cannot be fixed by a UI warning.
Drive's existing keyed GC/orphan protocol remains until a replacement is qualified;
Mail's message-only orphan check is not assumed equivalent.

A database lease/fence rejects stale database commits; it does not cancel an
already-issued object-store request. The concrete provider protocol must bind an
exact immutable object/version and settle or safely isolate every in-flight delete
before that identity can be adopted, reused or released from a barrier. If the
provider cannot supply equivalent preconditions/identity isolation, the affected
operation stays fenced for reconciliation rather than pretending a revoked worker
cannot delete bytes. No stale completion may delete a new object at a reused key.

Likewise, late copies/writes must remain in operation-owned staging or use a
qualified immutable publication protocol. A stale writer cannot overwrite an
active representation merely because its later database commit is refused.
Unknown physical effects require an exact visible obligation and bounded recovery
procedure; they are not successful cancellation or permission for broad cleanup.

## Maintenance-first transition table

Names below are proposed semantic states, not existing database/wire enums.

| Transition | Required committed authority/evidence | Failure / replay result |
| --- | --- | --- |
| Admit operation | Current actor/policy, source/target identities, exact scope, recovery/space/profile prerequisites, D12/E4 key admission and operation key | Changed input rejects; migration/generation changes pause during KMS grace; no implicit switch or probe side effects |
| Acquire maintenance fence | All affected producers and accepted-work handlers acknowledge the owning write fence; settle or reconcile pre-fence effects | No copy-phase readiness while a participant or accepted write is unresolved; unrelated domains need not be stopped |
| Capture and protect | Fixed inventory of logical references and exact bytes, including held/queued/retained categories; durable independent source protections | Missing category or partial protection is incomplete, never an empty inventory |
| Copy / transform | Bound source and target generations, E3 verification rules, current executor fence, D12/E4 admission and exact owned staging | KMS grace pauses migration; reconcile already-issued effects without admitting new copy work. Per-object failure retained by identity; retry cannot replace denominator with successful count |
| Verify target | Complete inventory reconciled, exact lengths/digests/authenticated representations and required retention/provider properties | HEAD existence, size alone, upload acknowledgement or percentages cannot authorize cutover |
| Commit cutover | One reducer-owned atomic active-generation/reference transition with current authority, fence, freshly revalidated D12/E4 admission and full verification receipt | KMS grace blocks this generation change. Lost response reads committed receipt; retry never repeats a different switch or silently rolls back |
| Abort before cutover | Current authorized abort plus definitive receipt that no cutover committed; reconcile or safely isolate every issued target/remote effect | Source stays authoritative. Release only this operation's obsolete protection and maintenance blocker when no dependency remains; preserve other owners and unresolved effects. Never delete source or infer rollback from a lost response |
| Resume admitted writes | Current authoritative generation (source after confirmed abort, target after cutover) and required dependencies ready under current policy and D12/E4 ordinary-I/O admission | Recompute authority; do not restore historical grants or flags. New writes bind that generation; ordinary grace eligibility does not authorize migration restart |
| Retain source | At least seven days plus independently required recovery/reader/backup/compliance obligations | Timer expiry establishes eligibility only, never deletion; source loss is a degraded recovery fact |
| Retire source | Separate explicit administrator approval, fresh inventory/protection/hold checks and exact physical-effect reconciliation | Revalidate before each deletion; newly acquired protection blocks affected removal; partial retirement stays visible |

The maintenance fence begins before capture/copy in this first mode. Do not
silently add the deferred online base-copy/journal catch-up mode. Retained source
does not by itself make post-cutover rollback safe: after target writes, either
prove all committed writes survive the approved reverse/recovery path or remain
fenced for recovery. Ordinary cancellation before cutover cannot mean rollback
after it. A receipt says which result committed, not what the operator last saw.

D12/E4 remains the key-policy authority: eligible ordinary cached-key I/O may
continue only within its approved scope, deadline and active generation during
grace; generation changes and encryption/provider migration pause. Explicit
revocation or expiry fails closed. Recovery requires current revalidation before
resuming migration or committing cutover, never an extended grace deadline or
restoration of historical key authority. Releasing a confirmed pre-cutover abort's
obsolete pin is not source retirement and does not impose the post-cutover
seven-day retention timer; remaining independent protections still apply.

## Backup interaction and recovery from interruption

Backup B1 retains its deletion-admission barrier → snapshot → durable exact-object
protection sequence. Snapshot MVCC is not byte retention. A concurrent migration
must either preserve that snapshot's exact encoding/placement/key dependencies or
defer the conflicting transition; it cannot silently rewrite the captured inventory
to whichever generation happens to be active later. Shared physical bytes may
have several independent protections; copying once does not merge their authority.

On restart, enumerate unfinished operations and their durable obligations before
re-enabling conflicting writers/deleters. An executor lease expiring fences that
executor but does not prove its objects are unneeded. Reconcile backend results,
receipts and remaining consumers; preserve operator-visible blocked/retained work.
Freeze finite timeout, capacity and escalation bounds before implementation, with
safe fail-closed behavior when reconciliation cannot meet them. No invisible
indefinite global GC suspension or automatic deletion is an acceptable fallback.

## Proposed acceptance cases — none executed

| Case | Required observable result |
| --- | --- |
| LP-01 independent owners | Backup and migration protect the same object; finishing either leaves the other's protection intact |
| LP-02 domain-only references | A held/outbound/reader-only owner remains after message deletion; no premature physical removal |
| LP-03 snapshot gap | Last live ref disappears after snapshot but before copy; durable snapshot protection preserves exact captured bytes |
| LP-04 two-stage GC/orphan | Inject protection/adoption around both Drive GC stages and orphan cleanup; all admitted owners serialize without loss |
| LP-05 late remote delete | Pause an issued delete, expire/reassign executor and attempt same-key adoption; delayed completion cannot destroy newly admitted content |
| LP-06 late target write | Delay a stale copy/upload past cancellation or cutover; active target bytes/identity remain unchanged |
| LP-07 honest denominator | One object is unreadable, malformed or missing while others copy; operation cannot report complete/cutover by counting only successes |
| LP-08 cutover response loss | Commit then drop response; operation lookup returns one immutable result, with no duplicate switch or stale rollback |
| LP-09 source retention | Minimum time passes but backup/reader/hold remains; retirement blocked. After all gates, separate approval still required |
| LP-10 target writes then rollback | Retained old source lacks a new committed target write; refuse naive pointer reversal and show required reconciliation |
| LP-11 crash and unresolved effects | Crash at protection/copy/verification/commit/release boundaries; restart preserves dependencies. Confirmed pre-cutover abort resumes eligible source writes and releases only its obsolete pin/blocker; unknown cutover or remote effects remain reconciled/fenced, with no source deletion or removal of another owner's protection |
| LP-12 generation-bound backup | Capture old generation while migration advances; restore uses its exact byte/key inventory and cannot silently substitute active generation |
| LP-13 KMS pause and recovery | Outage during admission/copy/final commit pauses migration and generation changes while only D12-eligible ordinary I/O continues; expiry/revocation closes that I/O. Recovery revalidates current authority before migration resumes, without resetting grace or admitting a stale cutover |

E9/B1 must bind these to the source-keyed E0 participants, concrete schema/provider
protocol, executable fixtures/lanes and retained evidence. E3/E4 cryptographic/key
contracts and lock/resource freezes remain joint prerequisites. This packet neither
claims all current code obeys these rules nor replaces domain or compliance owners.
