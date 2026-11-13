# Inactive selected restore — identity, effects and publication

Date: 2026-09-06
Status: B2/LC-P5 detailed proposal, not frozen, implemented or runtime-tested.
Owner: existing restore/recovery module, Drive reducers and each selected domain.
Authority: app-data lifecycle B2.
Inputs: [B0 inventory](composable-backup-data-inventory.md),
[lifecycle LC10–LC11](composable-lifecycle-transitions.md),
UI UM17–UM18.

## Existing implementation versus new contract

The inspected [full restore coordinator](../../mailctl/restore.go:265) copies Mail
blob content into an empty target, resets its schema, then restores a database dump.
It is not an importer for an inactive copy inside an already populated installation.
Do not invoke its schema reset, raw SQL or `pg_restore` on the live database to
implement selected recovery. B0 BC04–BC08 identifies these separate workflows.

The [configuration policy](../../mailserver/sql/dbschema/V229__restore_config_policy.sql:49)
classifies encrypted entries as rotate and unknown entries as quarantine. Its
application helper has its own source-verification condition; neither a signature
nor a successful safe-key application grants general activation authority. The
[restore engine](../../mailserver/internal/restore/engine.go:100) checks configuration
against a manifest only when its manifest HEAD succeeds. New selected recovery must
require its complete verified manifest, not inherit that optional-check path.

Everything below specifies new behavior. Reuse the recovery module and domain
reducers; do not invent a second general importer/executor or give plugins owner
database, object-store or raw SQL access.

## One interface, distinct intents

UI and CLI use the same domain interface; internal callers need no compulsory HTTP
hop. These are logical commands, not allocated public endpoints or new permissions.

| Intent | Inputs from caller | Authoritative result |
|---|---|---|
| Preview | Recovery-point identity, selected roots, explicit target and requested mode | Verified coverage, required mappings/key references, effective scope, estimate and blockers; no content imported |
| Stage | Preview revision, approved mapping digest, stable operation key | One operation and inactive-copy identity, or stale/denied/unsupported; not activation |
| Observe | Operation/copy identity | Current authorized progress, verified counts, exclusions and last durable receipt; no implicit retry |
| Publish data | Fresh inactive-copy revision and target/grant impact preview | Deliberate current-access publication of verified data; runtime/effects still separately gated |
| Activate | Fresh published-copy/runtime/dependency/grant/secret revisions | Receipt for separately admitted runtime and future work; never replay historical jobs automatically |
| Cancel | Operation identity and expected generation | Cancellation requested, then stopped/retained/cleaned as actually reconciled; no backup deletion |

Live replacement is not an alias for Publish data. It requires a separate preview
against exact live target versions, holds, ACL and accepted work, then domain
conflict/version rules. First selected-restore slice supports separate copies only;
replacement remains explicitly unavailable until its own B2 packet passes review.
That sequencing does not abandon the accepted future replacement capability.

## Persistent identity and mapping proposal

The reducer-owned operation binds immutable recovery manifest digest, source
installation/timeline, schema/format profiles, effective scope, destination,
mapping digest, actor authorization reference, executor generation and receipts.
Source and destination scope are separate fields; neither comes from an unchecked
manifest tenant/user ID. Every mutation rechecks current target authorization.

Keep a durable mapping keyed by `(operation, source installation, object kind,
source ID)` with a unique destination identity for each new object. Repeated chunks
of work reuse that mapping. Never match by numeric ID, email, name or path alone.
Approval of a principal mapping is a distinct current authority check, not an
instruction to create users, restore credentials or expand administrator rights.

| Source class | Inactive-copy disposition |
|---|---|
| App installation / Drive space | Allocate new domain-owned identity under an approved organization/app ownership model; no personal installer ownership shortcut |
| File, node, version, branch, label | Allocate stable destination identities; preserve graph links through the map, including nullable ancestry and retained deletion state |
| User/group/owner reference | Preserve source provenance; resolve only explicitly admitted target mappings. Missing necessary owner/principal mapping blocks publication, not substitution with installer |
| ACL, membership, delegation | Preserve historical evidence separately; no live imported grants during staging. Publish requires an explicit current-authority grant projection and its approved consequences |
| Audit / save receipt | Keep immutable source bytes/digest and source IDs; attach mapping/provenance separately. Never rewrite a signed history chain to use new IDs |
| Token, Office session/lock, lease, cursor, executable queue item | Historical/inactive disposition only; never revive authority, resume source cursors or dispatch imported pending work |
| Secret reference / wrapped key material | Bind declared purpose and source generation; unlock only through the accepted recovery mechanism. New runtime bindings require current custody and endpoint approval |
| External IDs / remote app state | Keep opaque provenance without contacting the remote system; unresolved required export or safe mapping blocks the advertised recovery class |

Plan the cyclic Drive import as: validate the complete typed graph → allocate all
IDs → insert owned skeleton rows with permitted nullable links → attach versions,
branches and streams → resolve deferred links → independently verify closure.
Do not disable foreign keys, RLS, audit triggers or quota checks to fit malformed
input. Exact reducer schema and legal intermediate states are a freeze prerequisite;
if the domain cannot express them safely, use isolated recovery rather than a live
database workaround. Never execute backup-supplied SQL, scripts or module hooks.

## Byte staging and protection

Treat manifests and file bytes as untrusted input even when source signatures verify.
Use a versioned, bounded typed parser; reject duplicate/conflicting IDs, invalid
ordinals, unsupported mandatory fields/profiles, path traversal and oversized graphs
before promotion. Keys in a manifest identify data, not arbitrary storage URLs.
Read only from the operator-approved backup source through the existing adapter.

Drive owns destination scope selection, canonical object keys, reference registration,
quota and retention. A secure `s<source-space-id>` prefix is not transformed merely
by replacing digits. Verify backup bytes, assemble streams and verify whole hashes;
re-encode into the destination's admitted storage generation where necessary.
Hash identity does not authorize cross-security-scope deduplication.

Bound destination canonical bytes to operation-owned protection before they can be
reclaimed; release only after committed destination references or reconciled cleanup.
Unfinished stage must participate in both GC and orphan-removal protection. The B1
source-capture pin is not automatically a destination pin. Cross-module lock ordering
and all producers/deleters must be audited together; do not hold a DB transaction
open while downloading bytes. Existing upload claims are not indefinite restore pins.

## Inactivity is a server-enforced state

Staging and inspection must not expose data through ordinary Drive browsing/search,
sync, DAV, public shares, Office/WOPI, Mail attachment routes or installed app access.
Only an actor with current, exact-copy/source-class inspection authority and the
required step-up receives the scoped inspection projection, as defined in the
[RR1 permission map](composable-recovery-records.md#proposed-permission-mapping-for-rr1).
Initiating Stage, possessing a recovery key or holding an operator role alone does
not grant that authority. Preview/render helpers are allowed only through that projection and
must obey its isolation, content-safety and no-external-fetch rules.

Before admitting a same-installation clone profile, enumerate every relevant read,
worker and dispatch path. Reducers must exclude inactive copies from ordinary
selection and refuse their executable effects. Existing worker credentials do not
bypass this logical gate. Prove scheduled sends, webhooks, notifications, Office
launches, watches, indexing/sync exposure and app jobs remain suppressed on restart.
Restore-progress observation and its narrowly scoped audit are allowed control-plane
effects; they must not publish imported content as normal domain notifications.

If any participant cannot honor the gate, reject that profile and offer a separately
authorized isolated restore environment with no outbound connectivity. Never pause
all unrelated live customer work to simulate isolation. General app binary startup
is not required for inspection; declared app data importers need their own admitted
non-executing format/validation contract, not permission to run arbitrary install code.

Publication uses a current policy/hold/target-revision check and one authoritative
visibility transition for the admitted consistency group. Do not promise an atomic
switch across external providers. Unsupported multi-domain publication stays blocked
or requires separately previewed groups with honest partial status, not hidden
automatic partial success. Activation creates only new authorized runtime state;
historical accepted-work obligations remain retained and require explicit domain
reconciliation, not blanket replay or silent deletion.

Publication granularity follows RR1: one operation/copy is one dependency-closed
local consistency group with a single publication receipt. Separately previewed
groups use separate operations/copies and explicit per-group outcomes. Reject a
split with unresolved cross-group visibility dependencies; do not expose part of
one copy by incrementally toggling its single visibility revision.

## Failure, receipts and timing

Each command binds its stable key to canonical intent and target; changed intent
refuses. Observation uses current read authority, not a historical token. A lost
response returns checking-status until a durable result is known; retry cannot
publish twice or bypass revoked permission. Restart reloads inactive state, mapping,
receipts and executor fence before doing work.

Cancellation closes work admission and fences the executor. Cleanup rechecks exact
ownership, active references and retention per item. Shared bytes, source backups,
held provenance and foreign resources are untouched; report retained or unknown
outcomes explicitly. Cancellation after publication is not automatic unpublication
or rollback; offer the currently authorized next action instead.

For a synthetic test profile only, use a 30-second executor claim, heartbeat every
5 seconds and a 120-second observation deadline. Only executor lease expiry fences
work and requires executor reconciliation. Observation timeout merely stops waiting
and reports the last confirmed or unknown outcome; the valid executor may continue.
Neither timeout activates/deletes a copy or releases protection. Final commit checks
executor generation/lease expiry atomically, independently of observer lifetime.
Test both an observer timing out while a renewed executor lease remains valid and
an executor lease expiring while observation continues.
These are proposed fault-injection fixtures, not production restore-time promises.

The accepted key recovery D7–D12
remains authoritative: backup carries wrapped material, not the raw recovery key;
missing keys never permit plaintext fallback. A new destination generation or key
requirement cannot use ordinary-read/write KMS grace as migration authorization.
The key-slot repair's 15-minute expectation is not a file/DB disaster-restore RTO.
Measure and display copy, verification, import and publication stages separately;
unknown throughput gives “estimating,” not an invented finish time.

## Ordered implementation-review packet

| Slice | Required output and exact failure oracle |
|---|---|
| IR1 Typed graph/profile | Versioned parser limits, class support catalog and manifest verifier. Corrupt, unsigned/untrusted, conflicting or unsupported required records cannot reach staging |
| IR2 Mapping and byte protection | Reducer schema, lock order, target-generation mapping, quota and holds. Crash/retry reuses IDs; shared bytes and secure scopes remain correct |
| IR3 Inactive projection/effects | Exhaustive admitted-profile reader/worker matrix. Ordinary reads and every imported outbound path denied before and after restart; separately authorized scoped inspection positive passes and stage-only inspection denies |
| IR4 Publish/activate | Exact permission mapping, CAS, compatibility and receipt ordering. Revocation/hold/change after preview refuses; response loss resolves one result; old jobs never auto-dispatch; two independently closed groups have separate receipts, cross-dependent split refuses |
| IR5 Recovery validation | Extend existing recovery/Drive lanes with BI-T01–BI-T09 and AB-T07/09. Restore two files sharing a chunk, branch/preview history, missing principal, revoked token and retained audit; verify independently |

Outstanding freeze inputs: concrete schema/reducer names and permissions, complete
reader/worker matrix, scoped audit proof, parser/size/quota limits, destination
protection implementation and measured production budgets. These are named next
engineering outputs, not claims that another high-level outline closes B2.
