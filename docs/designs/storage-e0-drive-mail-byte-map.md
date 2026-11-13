# Storage E0 — initial Drive and mail byte map

Date: 2026-09-08. Status: partial source inventory, not E0 completion, a new
encryption profile, implementation authorization, runtime test or numeric score.
Work order: [Storage specification completion map](storage-specification-completion-map.md).

## Denominator and authority

This slice covers sampled ordinary Drive upload/version/read/delete paths and
mail attachment upload/read/copy/delete paths, plus their direct storage and
backup/restore seams. It does not close every transitive caller or data class.
Reducers retain business authority; physical byte transports are not substitutes
for version, authorization, reference, legal-hold or recovery ownership.

The full delegated read/hash receipt was retained as private task evidence
(`storage-e0-drive-mail-source-report.md`, not in this repository).
Whole-file hashes there bind freshness; inspected ranges, not hashes, describe
read coverage. No listed test was executed for this inventory.

## Current paths and required future bindings

| Boundary | Inspected current behavior | Required E0/E3–E7 closure |
| --- | --- | --- |
| Drive upload | [chunks.go](../../mailserver/internal/drive/chunks.go:181) stages bounded chunks under random temporary keys, verifies SHA-256, and serializes canonical promotion/registration by key. Regular keys use `drive/g/<sha>`; other scopes use `drive/s<space>/<sha>`. [Registration](../../mailserver/sql/reducers/drive_chunk_register.sql:53) records upload claims without adding a live reference | Map existing scope/hash identity to future immutable encoding and placement generations. Current `g` is not evidence of the proposed encryption security scope. Distinguish temporary bytes, claims and referenced content |
| Drive publication and logical restore | [Put version](../../mailserver/sql/reducers/drive_file_put_version.sql:6) owns authorization, manifest/upload proof, quota, conflict branch, references, audit and notification. [Restore version](../../mailserver/sql/reducers/drive_file_restore_version.sql:7) delegates a same-file manifest save; it is not a physical object-copy operation | Preserve Drive version/DAG authority. Specify representation reuse/transform and verification for retries and restored versions |
| Drive read/Range | [Authorized manifest resolution](../../mailserver/internal/drive/content.go:236) and [streaming](../../mailserver/internal/drive/content.go:312) use ordered chunks and direct MinIO full/range reads. No reader-pin admission/release appears in these inspected functions | Bind immutable representation selection, authenticated Range delivery, in-flight reader lifetime and retirement coordination; existing references do not prove future backup/migration pins |
| Drive deletion | [Manifest triggers](../../mailserver/sql/dbschema/V114__drive_core.sql:413) maintain chunk references. [Logical destroy](../../mailserver/sql/reducers/drive_node_destroy.sql:48), [hard destroy](../../mailserver/sql/reducers/drive_node_destroy_hard.sql:38) and [version pruning](../../mailserver/sql/reducers/drive_version_prune.sql:16) have distinct eligibility. [GC](../../mailserver/internal/drive/worker.go:240) removes metadata, then reacquires the producer key lock and rechecks absence during object deletion | Close trash sweep, orphan inventory, temporary cleanup and transitive callers; preserve current serialization until a replacement is qualified. All independent reader/backup/migration/hold protections must participate |
| Mail attachment writers | [JMAP Upload](../../mailserver/internal/jmap/blob.go:245) and [PUT /blobs](../../mailserver/internal/blob/handler.go:436) both stage then copy to bare SHA-256 keys. JMAP initializes/increments `ref_count` and logs a registration error before returning201; `/blobs` initializes zero for trigger-owned references, fails registration errors and invokes its optional retention registry | Reconcile upload registration, unattached-upload lifetime, reference ownership and durable-success semantics. Do not merge these paths conceptually without adjudicating their different behavior |
| Mail read/cache | [JMAP Download](../../mailserver/internal/jmap/blob.go:349) checks owned/delegated mailbox authority. [Immutable serving](../../mailserver/internal/jmap/content_serve.go:17) supplies ETag/Range behavior. [Blob Get](../../mailserver/internal/blob/handler.go:282) authorizes before a hash-keyed plaintext memory cache. [Native transfer](../../mailserver/internal/jmap/attachment_transfer.go:231) additionally rechecks device/session/policy generation | Bind cache lifetime/invalidation, key/representation generation and plaintext resource limits; cached bytes and digest validators are not grants. Native offline storage retains its own owner |
| Mail logical copy and containing-message objects | [Blob/copy](../../mailserver/internal/jmap/blob.go:110) checks authorized existence, not physical copy. [Attachment assembly](../../mailserver/internal/jmap/mail_attach.go:27) reads attachment bytes into MIME and writes a new raw-message object. [SMTP raw writer](../../mailserver/internal/smtp/raw_blob.go:17) stores message bytes; sampled inbound keys use `inbound/<sha>` | Keep attachment objects and attachment-containing raw messages distinct. Close all `raw_ref` producers/consumers, including inline messages; this sample does not close MIME extraction, outbound or IMAP |
| Mail reference/deletion | [Attachment insertion trigger](../../mailserver/sql/dbschema/V075__attachment_blob_refcount_inc.sql:11) increments references; deletion decrements references, and a resulting zero count queues cleanup. [Purge](../../mailserver/sql/reducers/jmap_email.sql:817) separately queues unshared raw references. [Attachment cleanup](../../mailserver/internal/blob/handler.go:193) deletes an eligible row then removes bytes; [raw cleanup](../../mailserver/internal/blob/handler.go:239) checks live message references and skips inline content | This is not Drive's keyed two-transaction protocol. Bind re-upload/adoption, physical deletion, legal retention and future pins across the DB/object gap; add exact crash/race/retry oracles |
| Adapter/recovery seam | [Wiring](../../mailserver/cmd/mailserverd/main.go:720) uses direct MinIO for ordinary Drive/mail bytes and a separate storage-driver retention capability. [S3 driver](../../mailserver/internal/storage/s3_hot_driver.go:41) preserves caller keys. [Backup](../../mailserver/internal/backup/engine.go:198) inventories referenced `blobs` and uses `blobs/<hash>`; [restore](../../mailserver/internal/restore/engine.go:281) uses that prefix too. [Legacy migration](../../mailserver/internal/storage/migration.go:130) uses bare hashes and has no implemented dual-write | Adjudicate namespace/class coverage using exact constructors and a real round trip. Do not claim this inventory includes Drive chunks or every raw message. Bind generation-aware verification and independent recovery pins, without treating the legacy copier as the new migrator |

## Source-derived discrepancies to resolve before format freeze

These are concrete code differences and proposed adjudication work, not a claimed
customer incident or completed security validation. Coordinate overlapping findings
with [security/refactor sequencing](security-remediation-refactor-sequencing.md);
do not normalize them away during refactoring or launch a separate broad scan.

1. **Writer versus recovery namespace:** sampled live attachment writers use bare
   hashes; backup/restore use `blobs/<hash>`. Sampled constructors use the same
   primary bucket and the adapter preserves supplied keys. Trace remaining wiring
   and execute an authorized upload→backup→isolated-restore→authorized-read case in
   the later implementation/verification phase. Require exact class/key/byte
   equality and missing-object failures; do not “repair” by silently guessing keys.
2. **Upload registration/refcount parity:** compare both upload entrypoints through
   successful attachment adoption, unattached expiry, registration failure and
   retry. Freeze which owner protects a temporary upload and which owner counts a
   durable attachment. A201 response without required durable registration cannot
   become the encrypted writer's acceptance contract by accident.
3. **Deletion race/pin closure:** enumerate re-upload and adoption between metadata
   deletion and physical deletion, including raw-message references. Determine
   existing protection first, then bind missing generation/reader/backup/migration
   protection to one qualified lifecycle. Do not erase Drive's existing lock scope.
4. **Direct versus adapter consumers:** list both explicitly. Moving an adapter
   alone does not encrypt callers that still access MinIO directly. Include Range,
   plaintext memory cache, MIME assembly and late key revocation in the joint
   E3/E4/E5 review.

The current primary backup copy code verifies size **and digest**, including same-size
existing destinations and committed copies; restore also verifies digests. The
replica same-size skip is a different branch, now explicitly covered by
[BI-T12–14](composable-backup-data-inventory.md#backup-transport-qualification-amendment--2026-09-08).
Earlier
size-only observations must not be repeated as current findings. These checks do
not themselves establish correct namespaces or complete backup-class coverage.

## Existing test anchors and future exact oracles

Inspected test bodies, **not executed results**:

- [Drive chunk upload](../../mailserver/internal/drive/chunks_test.go:145),
  [GC/re-upload live test](../../mailserver/internal/drive/worker_gc_race_live_test.go:34),
  [registration pgTAP](../../mailserver/sql/tests/drive_chunk_register.pg:1).
  The live helper skips without `DB_DSN`; a skipped run cannot qualify the lane.
- [Mail reference lifecycle](../../mailserver/sql/tests/blob_refcount.pg:1),
  [cleanup](../../mailserver/internal/blob/cleanup_test.go:57),
  [download authority](../../mailserver/internal/jmap/blob_download_test.go:78),
  [Range/If-Range/HEAD](../../mailserver/internal/jmap/content_serve_test.go:35).
  The inspected cleanup stale-candidate case changes the count before reaping,
  not after metadata deletion; it does not close that later race.
- [Backup integrity](../../mailserver/internal/backup/blob_integrity_test.go:57) and
  [restore corruption/failure](../../mailserver/internal/restore/manifest_restore_test.go:260).
  Synthetic adapter fixtures alone do not prove the live-writer namespace round trip.

Bind each future case to owner, fixture, lane/profile, exact oracle and retained
source/generation evidence. Required additions include namespace round trip,
registration failure, all deleters versus pins, Range/copy during generation
changes, cache/key revocation and migration crash/cancellation/recovery. This is
an unfilled binding list, not proof that no related test exists anywhere else.

## E0-C3 proposed compatibility contract — 2026-09-08

This section specifies intended repairs for discrepancies1–2, not their existing
implementation, a public API change or the E3 format freeze. It uses the common
[protection/deletion owner](storage-lifecycle-protection-contract.md) and preserves
domain reducers as authority. Physical transport and digest equality never grant
access to another user's Mail/Drive data.

### Exact logical identity versus physical location

Future capture/restore records must distinguish logical domain identity from the
exact source and destination placement, bucket/root binding, object key, immutable
version where supported, byte length/digest and encoding generation. Names are
semantic requirements here; E3/E5 own final schema/wire names and validation.
Resolve locations through admitted server-side placement profiles, not an endpoint
or filesystem path accepted directly from an untrusted backup or client.

For the current unencoded profile, freeze explicit per-class mappings from actual
writer/owner records: shared attachment keys, Drive storage_ref keys, raw_ref
objects and database-held inline/literal content are different representations.
Do not construct every live key as blobs/<hash>, strip a prefix from every raw_ref,
or probe several guessed keys and accept the first readable object. A hash is an
integrity expectation, not a location or an authorization identifier.

Backup may intentionally use its own namespaced layout, but its manifest must bind
the exact verified source-to-backup-to-restored-target mapping. Restored logical
references point to the admitted target representation; do not copy an old location
string into a new placement blindly. If a legacy profile lacks enough information,
report the affected entries as unresolved and require owned source reconciliation
before declaring capture/restore complete. No silent missing-to-empty conversion,
content refetch or permissive fallback is admitted by this plan.

Resolve each admitted legacy discriminator from its owning writer/schema evidence.
Inline/literal bytes travel in their declared database representation, not as
synthetic object keys. Unsupported or ambiguous pairs fail the operation's declared
completeness gate without overwriting or deleting the only source. This is a
compatibility requirement, not permission to rewrite existing namespaces in place.

### Upload protection is not an attachment reference

Both upload front doors must use reducer-owned attempt/publication bookkeeping
bound to the authenticated actor, account where applicable, admitted security scope
and exact immutable representation. Gateways transport and measure bytes; reducers
admit ownership and durable transitions. Preserve current endpoint/account/delegation
admission and recheck the separate domain operation's authority at attachment time.
Do not invent a required new JMAP request field or replace protocol blob IDs with
an internal operation ID. Compatibility means the supported JMAP protocol contract,
not freezing an existing implementation discrepancy as a requirement.

An accepted upload establishes a bounded, owner-scoped claim protecting otherwise
unreferenced bytes. It does not increment the durable attachment count. Existing
attachment/other-domain reference triggers remain responsible for real references;
claims, active readers, backup and compliance obligations remain separate owners.
Expiry needs explicit durable scheduling/reconciliation even if a blob starts with
zero references and never receives a reference UPDATE; inserting zero cannot be
assumed to trigger the existing zero-transition cleanup queue.
Repeated protocol uploads may create distinct claims: equal content is not proof
of the same request, actor or permission. Replay of an internally identified attempt
must compare its original input; it cannot mutate a different upload's result.
Internal attempt receipts may be distinct while uploader/account/blob eligibility,
quota and expiry are reconciled together; do not charge or release other owners'
claims because they contain equal bytes.

The checked-in [RFC8620](../ref/rfc/rfc8620.txt), sections6–6.3, supplies concrete
JMAP constraints. Until referenced by an authorized object, uploaded content is
accessible only to its uploader, including in shared accounts; its eligible owner
must be able to use the supported download/copy/adoption paths without granting
other account members access merely from a shared hash. Keep unreferenced quota
separate from ordinary account quota and per user in shared accounts, sized to
support an admitted object's total referenced bytes. Quota pressure evicts eligible
unreferenced blobs oldest first; otherwise retain upload eligibility for at least
one hour. Re-upload should reset the uploader's expiry. This protocol lifetime is
unrelated to the separately accepted one-hour KMS grace.

Do not physically delete a blob during the method removing its last reference:
same-method destroy/create reuse must remain possible. Bind that method's lifetime
to authoritative completion/reconciliation. Quota eviction or claim expiry releases
only the relevant logical eligibility, never another reference, reader, hold or
backup protection. Logical quota reclamation is not proof of free physical space;
if capacity still cannot admit the upload, return the appropriate resource error.

Record actual measured byte length and digest, not an unknown Content-Length or
failed HEAD converted to zero. A genuinely admitted empty object remains distinct
from missing/unknown bytes. Consume and verify the supplied content under the
endpoint's resource limit before claiming upload success; deduplication does not
permit an unauthorized existing-object shortcut or overwrite of another encoding.

Return durable success only after canonical publication, metadata and the owner's
claim are committed and any policy-required protection has passed its admission
gate. Optional/unconfigured protection must be reported separately, not called
enforced. If registration fails or a response is lost, reconcile the exact attempt;
do not report201 solely because bytes reached storage, or delete a shared canonical
object that pre-existed or gained another owner. Failed/partial temporary writes
remain exact owned cleanup obligations, including late effects after cancellation.

At adoption, validate current authority and the actor/account-bound eligible claim
or another explicitly authorized existing-content path, then create the logical
reference and release only the consumed claim in one reducer transaction. Verified
blob/claim metadata, not request-supplied attachment size, must determine
quota and durable byte-size accounting; inconsistent client metadata is rejected
or normalized under the owning domain's explicit contract before acceptance.
Existing authorized attachment reuse need not fabricate a fresh upload. Claim expiry cannot
delete referenced or independently protected bytes; expiry/reaper admission shares
the producer/adoption serialization boundary. E5 must freeze the actual claim schema,
finite lifetime/resource limits, indexes, lock order and response-loss receipt before
implementation. Historical counters must be reconciled from source-bound reference
owners under a qualified migration; never mass-reset ref_count to zero.

### Proposed cases — none executed

| Case | Required observable result |
| --- | --- |
| NC-01 exact mapping | Capture and isolated restore cross bare hash, prefixed raw object, Drive key, inline and literal/sentinel representations. Exact class/location/bytes and rebuilt logical references agree; guessed or ambiguous mappings cannot pass |
| NC-02 placement trust | Inject a foreign placement, endpoint/path, same hash in another scope and unsupported encoding. Rejected inputs cause no unauthorized source fetch or target mutation; admitted target remapping retains exact integrity |
| NC-03 upload parity | Exercise both upload front doors, measured zero/chunked/short bodies, failed HEAD/registration and retries. Success size is observed, required publication/claim exists, and durable reference count changes only on actual reference transitions. An ordinary repeated HTTP upload is not automatically an internal-attempt replay or Email/set creation deduplication |
| NC-04 ownership and adoption | Upload/reuse identical bytes for separate users/accounts, revoke a grant before adoption, replay changed input and attach through authorized existing-content reuse. Underreported client size cannot bypass quota. Failed per-creation transactions restore claim/reference state; retained drafts, Sent copies and multiple links remain separately owned references. No cross-owner claim consumption or duplicate internal transition; supported public protocol remains usable |
| NC-05 expiry and failure | Include a zero-reference INSERT that never receives UPDATE; expire its claim without a fabricated decrement. Race expiry, re-upload/adoption, active read, another domain reference and backup/hold protection against lost copy/delete responses and crash. Existing shared bytes survive; owned unknown effects remain reconciliable. Bind LP/PD rather than a second deletion coordinator |
| NC-06 JMAP interoperability | At59:59/60:00/60:01 test uploader-only unreferenced access, independent shared-user quota, re-upload expiry reset, oldest-first quota eviction, and same-method destroy/create reuse. Exercise standard upload/download and Blob/copy shapes and errors; no internal attempt ID becomes a required protocol field |

Root re-read JMAP Upload245–348, Blob Put436–528 and the full V075 attachment
increment trigger. Go hashes match the census; these source reads and proposed
cases do not establish runtime parity or complete the remaining callsite census.
Root also read RFC8620:3229–3470 and Blob/copy110–177 plus registration553.
RFC SHA-256:2faef52947b75a4a624154ae6bde930688c1a2f122f05925273c7d8a9a85cd25;
V075 SHA-256:dfddee211b9cd05bdc2644d27d47ca5e9b1be9513958a266501552ff9beb96bb.
Adoption-size and zero-transition checks additionally read jmap_email.sql:1137–1206
and V001__baseline.sql:1193–1204,11006–11014. Their whole-file SHA-256 values are
01756385b9bff3126aedfdf18036faf8fc04a09314c9318e3fe62ef71f1d7b0c and
a5cfe54ffeb452f51a14ac1d3d896a6ef9bb766f66cd0720051bd68d9b529a14 respectively.
The current Blob/copy helper uses toAccountId/ids/list rather than the reference's
accountId/blobIds/copied map and performs no target publication in the inspected
body. Therefore the implementation plan must reconcile routing, capability and
wire-shape compatibility as well as claims; existing documentation's DONE label is
not interoperability evidence. This bounded source comparison is not a full JMAP
conformance audit or permission to silently broaden current account grants.

## Historical omitted scope at the initial map checkpoint

Next close raw-message consumers and ordinary Drive sweep/read/copy transitive
callers, then previews and Office/WOPI. Chat/Meet, app volumes, HR/legal/archive/
export, native stores, backup replicas/manifests/configuration/key material and
disaster activation keep their domain and recovery owners; none is silently
covered by the words “Drive and mail.” Full E0 and its capability/status schema
remain open. No new user choice is needed for this factual inventory.

Subsequent bounded maps and the [current finite census](storage-specification-completion-map.md#e0-finite-closure--current-residual-work)
supersede this historical queue, without relabeling the original source coverage.

Root independently inspected JMAP Upload245–348, blob cleanup193–278, backup
198–277 and restore281–351 to verify the highest-impact distinctions. Remaining
rows retain delegated bounded-read attribution. No code or test suite changed.
