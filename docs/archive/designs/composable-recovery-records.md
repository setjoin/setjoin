# Recovery records and enforcement packet

Date: 2026-09-06
Status: proposed persistence design for B1/BS1–BS3 and B2/IR2–IR4; no migration,
permission, endpoint or runtime behavior is allocated by this document.
Authority: app-data lifecycle.
Behavior: [snapshot](composable-backup-snapshot-contract.md) and
[inactive restore](composable-inactive-restore-contract.md) contracts remain authoritative.

## One coordinator, domain-owned data

Extend the existing backup/recovery module; do not introduce another generic job
engine or plugin-controlled SQL importer. Proposed `recovery_*` names below describe
relations to allocate in the owning schema review. Domain reducers own imported
objects, reference counts, ACL, quotas, state bumps and audit. Go only translates
commands and performs bounded I/O under admitted work receipts.

Scope is a server-resolved typed reference to the existing installation/domain/app
ownership model, not an invented universal tenant ID or a manifest-supplied owner.
Every command must resolve current actor authority against that reference; opaque
operation UUIDs are identifiers, never bearer capabilities. New records need an
explicit isolation classification and R1–R4 tests under the actual runtime roles.
Neither worker BYPASSRLS nor an admin page substitutes for logical authorization.

## Proposed relations and constraints

All operation-child foreign keys include the operation identity. Typed identities
retain their source type and scope; a digest alone never identifies authorized data.
Use database timestamps for leases, integer generations/revisions and bounded
versioned structured fields. Opaque payloads cannot contain SQL or executable hooks.

| Relation / key | Required fields and database invariant |
|---|---|
| `recovery_operations` / UUID | Kind backup or selected-restore; validated authority scope and actor reference; canonical intent digest; stable caller key; expected preview digest; requested/effective scope digests; immutable source/destination/profile references; state; revision; executor generation/identity/lease expiry; cancellation request; timestamps. Unique `(authority scope, kind, caller key)`; changed intent conflicts, never rebinds |
| `recovery_captures` / operation | Snapshot metadata artifact reference/digest; typed inventory digest/counts; capture timestamp; barrier epoch and admitted participant-set digest. One accepted capture per operation; no transition to copying before completeness proof |
| `recovery_delete_barriers` / plane + operation | Durable closed-admission flag, epoch, approved deadline and reconciliation state. Multiple operations can block the same plane; clearing one never clears another |
| `recovery_delete_tickets` / UUID | Plane, object identity, participant identity/epoch, admission generation and pending/confirmed-deleted/confirmed-not-deleted/unknown result. Owns an exclusive durable same-key deletion reservation; unknown is nonterminal and executor expiry cannot release it |
| `recovery_participant_acks` / operation + participant | Expected capability epoch and settled ticket watermark. An acknowledgement is valid only for the frozen participant set; new/restarted deleters must consult durable admission state |
| `recovery_object_protections` / operation + purpose + object identity | Source-capture or destination-stage purpose; approved store identity, scoped canonical key, storage generation, expected digest/size; release receipt. No TTL deletes protection; index the full lookup used by all GC/orphan paths |
| `recovery_object_receipts` / operation + phase + object identity | Admitted candidate identity, verified digest/size and executor generation; immutable successful receipt. Count distinct expected objects, not number of retries; changed bytes conflict |
| `recovery_seals` / operation | Exactly one accepted inventory/metadata/artifact-set digest, destination/profile/recovery requirements and seal receipt. Immutable after acceptance; final publication must reference this exact seal |
| `recovery_publications` / operation | Exact final manifest/commit identity and independently verified digest/trust reference; pending or verified receipt. Verified publication never follows solely from worker upload success |
| `recovery_copies` / UUID, unique operation | Approved target scope; inactive/published state, visibility revision and admitted profile. Runtime activation receipt separate from data publication; neither flag revives source sessions/jobs |
| `recovery_identity_map` / operation + source installation + kind + source ID | Source provenance, target kind/ID and mapping approval digest. New object targets unique within operation/kind; approved principal mappings may intentionally converge and therefore use a separate typed mapping class |
| `recovery_command_receipts` / operation + command + stable key | Canonical command intent, committed result revision and sanitized result. Repeated identical intent returns same durable outcome under current read authority; no duplicate mutation/audit effect |

CHECK constraints enforce row states and required field pairs, not cross-row
completeness, authorized transitions or quotas. Those belong in owning reducers.
Protection/ticket lookups and command-key uniqueness require explicit indexes before
scale admission. Retention must distinguish user-visible recovery history, security
audit, unresolved effects and temporary candidates; no generic cascade may delete
pins, receipts or imported domain data when deleting an operation record.

For RR1, one selected-restore operation owns exactly one copy and one immutable,
dependency-closed local consistency group. That copy has one publication transition
and receipt. A request intentionally split into independently publishable groups
uses separately previewed/admitted operations and copy identities, not partial
visibility inside one copy. Report their individual outcomes; no synthetic global
success or rollback. If references require atomic cross-group visibility, do not
split them: admit one supported group or block that profile. This preserves the
unique-operation copy constraint and requires no new batch coordinator.

## Reducer command boundary

Proposed names are internal interface candidates, not public API commitments.
Commands perform state change, receipt, audit and permitted progress notification
in one transaction. They never hold a database transaction across object-store I/O.

| Candidate command | Transactional checks / result |
|---|---|
| `recovery_admit` | Resolve live scope/authority; canonicalize intent; verify preview/profile/destination revisions; reuse exact key or create requested operation |
| `recovery_claim` / `recovery_renew` | Lock operation, enforce executable state and current worker admission; claim increments generation, renew requires same unexpired owner/generation. Heartbeat does not change confirmed intent or manufacture a new preview |
| `recovery_close_deletion_admission` | Install this operation's blocker and freeze expected participant set; reject unknown participant capabilities. Ticket admission checks all blockers in the same serialization protocol |
| `recovery_accept_capture` | Match snapshot inventory digest and expected count against registered protections plus acknowledged/settled deletion boundary; accept one capture or refuse. Partial registration never releases the blocker |
| `recovery_accept_object` | Current admitted phase, executor fence and exact expected object; verify trusted verifier receipt and record idempotently. A plugin-provided hash assertion is not verification |
| `recovery_seal` / `recovery_accept_publication` | Seal requires complete independently verified artifact set and current publication authority. Publication reconciliation accepts only the existing seal's authenticated immutable result |
| `recovery_stage_batch` | Typed profile and mappings; domain-owned insertion under inactive target; validate ownership/graph/quota. No raw restore SQL or owner-credential workaround |
| `recovery_publish_copy` | Fresh target/mapping/grant/hold revisions, complete graph and verified bytes, current domain authority; atomically expose one admitted local consistency group and commit receipt |
| `recovery_cancel` / `recovery_reconcile` | Before seal/publication, fence work and reconcile exact owned effects. After irreversible commit, reconcile that result; never relabel it aborted or silently unpublish |

Every executor mutation checks owner, generation, expected semantic revision and
lease expiry using database time **after obtaining the serialization lock**. A
transaction-start timestamp is insufficient after a long lock wait. Claim expiry
fences commits, not durable protections; observation expiry changes no work state.
Successful receipt lookup requires current read authority but no new executor lease.
Revocation stops new privileged effects; a narrowly admitted recovery coordinator
must still reconcile an already accepted seal without granting the revoked actor
access or permitting a different result. Record that recovery authority separately.

## Deletion and staging ordering to freeze

The proposed common order is plane admission lock → operation records in stable UUID
order → domain/object locks in canonical scoped-key order. A deleter obtains a
durable ticket before external deletion; the barrier cannot claim settled while
any pre-barrier ticket remains pending/unknown. A restarted worker reconciles the
same ticket, not an untracked retry. No network call holds these database locks in
the proposed protocol. This differs from current lock-through-I/O
[deletion](../../mailserver/internal/drive/worker.go:277) and
[promotion](../../mailserver/internal/drive/chunks.go:339) paths; do not shorten those
existing critical sections before their replacement is qualified.

Ticket admission atomically excludes active references, protections and producer
reservations under the same scoped-object fence. Conversely, pending/unknown delete
reservations block same-key promotion, new reference attachment and acceptance of
source or destination protections. A protection request cannot race past an already
admitted DELETE just because metadata is now absent. All producers participate,
including preview generation and restoration to a deduplicated canonical key.

Release the deletion reservation only after the external attempt is known to have
ceased and its outcome is reconciled. Worker lease expiry, process restart, a HEAD
response or loss of an HTTP response alone cannot prove a delayed request will never
execute. Unknown remains reserved and operator-visible until the adapter's qualified
cessation/outcome proof succeeds; never reuse the key on a timer. If the storage
profile cannot provide that proof, it cannot adopt this unlocked-I/O protocol and
stays on its existing reviewed serialization path or blocks the new recovery profile.

Register destination-stage protection before issuing canonical-object promotion.
The later domain transaction attaches references and acknowledges protection release
under the same object fence; rollback retains protection. Source inventory metadata
is persisted before releasing its exported snapshot, with exact digest/count checks.
The broad source barrier remains until all capture pins are durable. Pin enumeration
may be batched, but the complete-inventory acceptance is one logical commit.

This is not yet a proven repository-wide lock order. Every existing caller must be
mapped before choosing concrete lock keys; any inverse existing order must be
migrated or the profile stays unqualified. A snapshot identifier is not a durable
snapshot after its exporting transaction closes. Crash before complete metadata
capture must abandon/re-preview, never reopen a different snapshot under the old ID.

## Current enforcement anchors, not inherited authority

Bounded source inspection covers ten core files plus permission/console registries
and route registration. Underlying capability reducers, RLS grants, auth refresh,
other workers and backend lifecycle policies remain unverified in this pass.

| Existing anchor | Consequence for the proposed contract |
|---|---|
| [Permission registry](../../shared/permissions/permissions.go:27), [backup routes](../../mailserver/cmd/mailserverd/main.go:3784), [console guard](../../mailserver/internal/admin/consoles.go:52) | Existing IDs include `backup.read`, `backup.write`, `system.upgrade`, `system.recovery`, not generic `restore.*`. Create/delete use `backup.write`; list/download use an any-of System console guard, not exclusively `backup.read`. Do not silently reuse this broad OR gate for selected-copy inspection |
| [Backup handler](../../mailserver/internal/admin/admin_system.go:56), [job schema](../../mailserver/sql/dbschema/V005__backup_restore.sql:27), [claim/completion](../../mailserver/internal/backup/engine.go:463) | Direct pending insert and pending-to-running CAS exist; the inspected completion statements update by ID, not executor generation. Migrate deliberately; an INSERT notification is not already the proposed transactional reducer contract |
| [Setup socket](../../mailserver/cmd/mailserverd/setup_control.go:59), [first-boot restore](../../mailserver/internal/admin/admin_setup.go:240), [restore job methods](../../mailserver/internal/restore/engine.go:227) | Socket mode 0600 and no-users initialization boundary differ from authenticated live selected restore. Preserve first-boot behavior; do not expose its authority as an ordinary app API |
| [Recovery route families](../../mailserver/cmd/mailserverd/main.go:3817) | `system.upgrade` recovery-set/proof registration and `system.recovery` client-assisted Mail recovery are different intents, not evidence of an existing permission to publish a restored Drive copy |
| [Audited permission middleware](../../mailserver/internal/middleware/console_guard.go:45) | Claims permission checks and domain scope propagation do not establish reducer-side current authority. Freeze live revocation, step-up and domain checks per new intent, not only a route-name mapping |
| [Drive metadata/content](../../mailserver/internal/drive/content.go:177) | `listVersions`, `versionMetaAndManifest`, `getContent`, `streamManifest`: inactive-copy denial must reach authoritative metadata/download capabilities and alternate consumers; hiding a new space in navigation is insufficient |
| [Preview worker](../../mailserver/internal/drive/preview.go:101), [preview reads](../../mailserver/internal/drive/preview.go:304) | `tick`, `render`, `contentManifest`, `previewMetaAndManifest`, `getPreview`: cover both request admission and pending-job selection/attachment. Canonical preview writes must join the object-protection protocol |
| [Drive GC](../../mailserver/internal/drive/worker.go:187), [orphan cleanup](../../mailserver/internal/drive/worker.go:379), [temporary cleanup](../../mailserver/internal/drive/worker.go:481) | `gcChunks`, `gcDeleteOne`, `reapCanonicalOrphan`, `reapTmp`: cover the metadata/object deletion gap and row-absent cleanup. If restore uses the temporary namespace, its cleanup must recognize operation ownership too |

RR1 must allocate explicit rights for preview/inspect, stage, publish and activation
through the existing permission catalog and domain policy. This document deliberately
does not invent those final IDs or infer them from `backup.write`. Backup-source
read permission and destination write/publish permission are independent; access to
an encrypted backup does not grant access to its plaintext inspection projection.

### Proposed permission mapping for RR1

This is the recommended allocation for review, not a change to today's registry or
built-in roles. Candidate `restore.*` identifiers below do not exist in the inspected
registry. Keep them under recovery ownership, not a generic plugin grant namespace.

| Intent | Proposed admission authority | Additional authority / disclosure boundary |
|---|---|---|
| List recovery points / observe sanitized operation status | Existing `backup.read`, explicitly checked for this new surface | Scope-filtered status/counts only; filenames, subjects, historical ACL, errors containing paths and plaintext are not a safe summary by default |
| Capture selected backup | Existing `backup.write` plus approved source-recovery scope and destination policy | Recompute effective closure; an operator must not export another scope merely by supplying its IDs. Full/admin recovery uses an explicit recovery authority, not ordinary file-read ACL by assumption |
| Stage separate inactive copy | Candidate `restore.stage` plus source-point recovery authorization and current target-domain import authority | Reads bytes only inside the protected importer. Does not grant the initiating operator plaintext inspection, ordinary content access or runtime activation |
| Inspect inactive content | Candidate `restore.inspect` plus exact copy/source-class scope | Sensitive plaintext read; isolated projection only, no ordinary shares/WOPI. A recovery key or stage permission alone is insufficient |
| Publish staged data | Candidate `restore.publish` plus current destination-domain grant/ownership authority | Re-preview exact principals, target and disclosure changes. No restored grants silently become live; neither stage nor inspect implies publish |
| Activate an app against published data | Existing applicable `apps.manage` and, for Office policy changes, `office.manage`, through their owning lifecycle contract | Requires current admitted runtime/provider/grants/secret bindings; recovery permission cannot replace them. Existing CODE install support is not proof that generic activation is implemented |
| Cancel pre-commit operation | Its admission permission (`backup.write` or candidate `restore.stage`) plus exact current operation scope | No blanket authority to delete backup history, published content or held/shared data. Cancellation reconciles uncertain effects before claiming cleanup |
| Read/export recovery audit | Existing applicable `audit.read` / `audit.export`, subject to audit scope policy | Sanitized control-plane audit does not confer inspection or raw backup download rights |

Do not require every backup operator to hold every user's ordinary ACL: disaster
recovery may need an explicitly delegated recovery scope. That delegation is a
separate server-owned, reviewable authority over named data classes and destinations,
not an automatic privilege added to existing `backup.write`. Until its exact domain
binding is admitted, the unsupported scope is blocked rather than silently broadened.

Propose sensitive-assignment treatment for all three new rights, including inspection;
do not auto-add them to existing custom roles, plugin manifests or delegated groups.
Existing built-in super-administrator semantics and separation-of-duty policy must be
mapped explicitly at migration review; this packet neither removes nor extends them.
Showing a confirmation checkbox while assigning a role is not operation step-up.

Human publication and plaintext inspection require the owning security policy's
fresh, server-validated step-up bound to actor/session, intended action, scope and
preview revision. Do not accept caller booleans, old grant snapshots or a browser
timestamp as proof. Exact supported factor, proof lifetime and single-use/retry
behavior must reuse the existing security contract where compatible; otherwise the
new action remains unavailable until that contract is specified. Scheduled capture
uses a separately admitted noninteractive policy, never a fabricated human step-up.

After revocation, refuse new inspection pages/downloads and publication immediately
at their authoritative checks; stop newly admitted copy effects. Already delivered
bytes cannot be recalled. Long-lived readers/workers need bounded reauthorization
and an explicit maximum stale-access interval before qualification, not just an
entrypoint check. Reconciliation of a committed seal uses the coordinator's narrow
repair authority and cannot restore the revoked operator's read access.

Add RR1 fixtures for: backup-only operator denied inspection; stage-only operator
denied publish; app manager denied recovery content; cross-domain IDs denied; changed
principal mapping invalidates publish; revocation during inspection/copy; audited
step-up failure; unchanged-key retry after successful publication returns only an
authorized receipt. A pair of scoped operators must exercise each positive/negative
case with deliberately different user, mailbox, domain and copy identities.

### Reuse constraints found in the current security code

A five-source check narrows the implementation starting points, not the full auth
audit. [SensitivePermissions](../../shared/permissions/permissions.go:150) confirms
assignment sensitivity only. [PermClasses](../../shared/permissions/classes.go:14)
currently classifies backup read/write and system upgrade as system; the inspected
map has no Drive/Office/app or `system.recovery` entries. `ClassOf`/`ValidateRoleClass`
reject absent entries for classed roles; no claim is made about all unclassed roles.
RR1 must assign SoD classes deliberately for the new rights and test classed/unclassed
role migration, not copy a permission without its classification.

[upgrade_actor_authorized](../../mailserver/sql/reducers/upgrade_actor_authorized.sql:1)
is a concrete existing predicate: enabled actor, `system.upgrade`, null scope and
unconfined effective authority. It is not a general scoped restore authorizer.
[upgrade_challenge_complete](../../mailserver/sql/reducers/upgrade_challenge_complete.sql:19)
binds elevation to challenge, session/factor evidence and release/preview/policy
generations. Its five-minute elevation is an upgrade fact, not a recovery default.
The inspected completed-challenge replay precedes the actor-authority check and
uses statement-time expiry checks. Reuse the security owner and proof machinery,
but explicitly adapt authorization-first receipt reads and post-lock time checks;
do not assert this existing reducer already meets the new recovery contract.

[Authentication permission resolution](../../mailserver/internal/auth/chain.go:473)
refreshes admin permission/global/domain fields when resolution succeeds. Resolver
internals, incoming claim initialization on failure and in-flight revocation are
not established by this bounded read. RR1 must trace these before admitting the
new actions; middleware refresh alone is not the required live reducer/worker fence.

## Qualification gates and exact cases

| Gate | Required proof before implementation approval / later execution evidence |
|---|---|
| RR1 Schema and permission freeze | Owning migration/reducer names, isolated record classifications, permission/step-up mapping, indexes and bounded parser limits; no broad existing admin permission silently grants publish/activate |
| RR2 Fenced transitions | Competing claim, renewal, lock-wait expiry, changed-intent retry and lost response: one result; observer timeout does not fence a valid worker |
| RR3 Every byte participant | Source-keyed producer/deleter matrix, lock-order audit, crash in DB/object deletion gap, delayed DELETE against concurrent restore/preview promotion, unknown deletion after lease expiry, partial pins and restarted orphan sweeper: no admitted unprotected capture or same-key reuse while deletion remains executable |
| RR4 Inactive domain gates | Every reader and dispatch participant for the admitted profile; normal reads/effects denied before and after restart, current scoped operator inspection allowed |
| RR5 Publication and cleanup | Before/after seal cancellation, response-loss reconciliation, permission revocation, holds/shared objects: one immutable publication and accurate retained/unknown counts |

This packet narrows persistence decisions; it does not close RR1–RR5. Initial selected
restore remains separate-copy only. A profile with unverified participants fails
closed; ordinary backup/full-reset restore behavior must retain its existing tests
until deliberately migrated. No product tests were executed for this design.
