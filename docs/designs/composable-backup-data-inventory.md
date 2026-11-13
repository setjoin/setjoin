# Composable backup — source-bound data inventory

Date: 2026-09-06

Status: B0 planning inventory; no schema, backup preset, restore flow or GC change
is implemented or approved by this document. Authoring only; no review score.

## Scope and evidence language

The app-data lifecycle plan
B0 owns this inventory. The [lifecycle packet](composable-lifecycle-transitions.md)
LC09–LC11 and [Drive paper Provider](composable-reference-drive-provider.md) consume
it. Existing backup/restore, Drive and domain owners retain authority; this document
creates no new role, tenant boundary, app privilege or deletion policy.

**Source fact** means the named migration, reducer or Go implementation contains
the described behavior. No running database, object store, configured deployment,
backup artifact or independent restore was inspected. Migration presence is not
proof that a particular installation has applied it. **Capture path** means code
selects or copies the category. **Restore proof** requires independent execution
and content/authority checks; none is claimed here. **Proposal** means B1/B2 design
work, not an existing table, endpoint, manifest version or completed feature.

Graphify query `drive recovery snapshot` was truncated and poorly focused; the
focused `SnapshotBlobs` explanation identified `Engine.processRun` calling
`Engine.SnapshotBlobs` in `mailserver/internal/backup/engine.go`. Direct source
inspection below establishes the bounded facts. The hash appendix binds the main
inspected inputs; this is not an exhaustive migration/table/foreign-key inventory.

## 1. Existing Drive relationships and byte identities

This relationship sketch describes source tables, not a proposed backup schema:

```text
drive_spaces -> drive_nodes(parent_id tree) -> drive_files
                                               | head_version_id (Main)
                                               v
                                      drive_file_versions
                                        | parent/conflict/merged_from
                                        | branch_id <-> drive_file_branches
                                        v
                  drive_version_chunks(version_id, stream, ordinal)
                                        | (scope_key, chunk_sha256)
                                        v
                  drive_chunks(scope_key, sha256, size_bytes, storage_ref)
                                        v
                       drive/<scope_key>/<sha256> object bytes

node ACL meaning: grants + inheritance breaks + tree/closure + current principals
Attachment capture: blobs.sha256 -> blobs/<sha256> (BC02's capture convention)
Raw mail:           separate representation/reference census; see below
```

| ID / category | Exact source and relationship | Required recovery meaning / boundary |
|---|---|---|
| DI01 — space ownership and policy | [V114](../../mailserver/sql/dbschema/V114__drive_core.sql):21–53: `drive_spaces(id,owner_user_id,is_personal,classification,retention_days,worm_mode,export_policy,quota_bytes,used_bytes,change_seq)` and `drive_space_members(space_id,user_id,role,granted_by)`. [V184](../../mailserver/sql/dbschema/V184__drive_node_acl_foundation.sql):9–14 adds `acl_mode`, protocol and irreversible-cutover state. | Preserve classification, policy and ownership meaning, not merely names. Current `owner_user_id` references `users`; an organization-owned app space is an accepted product direction, not an existing `app_installation_id` field established here. Owner mapping needs an explicit contract. |
| DI02 — tree, file and deletion state | V114:56–110: `drive_nodes(id,space_id,parent_id,kind,name,deleted_at,created_by)`; `drive_files(node_id,space_id,head_version_id,size_bytes,content_type)`. [Hard destroy](../../mailserver/sql/reducers/drive_node_destroy_hard.sql):45–106 consumes `purged_at`, performs leaf-first/FK-aware removal and decrements quota. | Restore parentage, file identity and recorded deletion tier. Include still-retained selected versions even when their nodes are soft-deleted; do not relabel trash as live. The complete later trash-field migration inventory remains to be bound before serialization. |
| DI03 — immutable version graph | V114:89–113: `drive_file_versions` has whole-content SHA-256, size, chunk size, author, time, parent and conflict links. [V115](../../mailserver/sql/dbschema/V115__drive_versioning.sql):40–42 adds `merged_from_version_id` and `branch_id`. | Reconstruct the captured graph, including nullable ancestry that was already pruned. Main-only export is not retained-history recovery. Cross-file merge provenance cannot be dropped or followed into unrelated content silently. |
| DI04 — branches, labels, locks | V115:14–74: `drive_file_branches` binds file/space, head/fork versions, status and actors; `drive_version_labels(version_id,label)`; `drive_file_locks` binds file/branch/opened version and expiry; `drive_folder_admins` binds delegated authority to a node. | Branch/version FKs form a cycle. Restore labels and branch heads/fork bases without inventing a Main branch row. Locks are captured operational provenance, not authorization to resurrect a live session in a clone. Folder-admin authority belongs with ACL metadata, not UI preferences. |
| DI05 — canonical content and preview chunks | V114:115–137: `drive_chunks` primary key is `(scope_key,sha256)`, not hash alone; `drive_version_chunks` primary key is `(version_id,stream,ordinal)`, `stream` is `content` or `preview`, and the chunk FK carries both scope and hash. [Chunk promotion](../../mailserver/internal/drive/chunks.go):390–395 writes `drive/<scope>/<sha>`. | Enumerate exact ordered references in the selected version set, then deduplicate physical copies by namespace + scope + hash. `g` is shared regular-space storage; `s<space_id>` is secure/GxP-scoped. A prefix alone is neither selected ownership nor authorization. |
| DI06 — previews and rebuild limits | [PreviewWorker.render](../../mailserver/internal/drive/preview.go):143–229 reads content, invokes the configured renderer, rejects empty PDF, writes canonical chunks, then calls [drive_preview_attach](../../mailserver/sql/reducers/drive_preview_attach.sql):25–87. That reducer replaces only `stream='preview'` refs and sets whole-preview hash/status. | Ready preview bytes are existing referenced data, not automatically disposable cache. Include them unless a separately verified rebuild profile permits omission and states changed rendering/availability impact. Capture preview status/hash consistently with its stream. Renderer presence alone is not deterministic rebuild evidence. |
| DI07 — ACL anchors and revocation state | V184:20–124: `drive_acl_grants`, `drive_acl_breaks`, `drive_node_closure`, `drive_acl_generations(epoch,retained_after_cursor)`, `drive_access_invalidations`. [V188](../../mailserver/sql/dbschema/V188__drive_acl_group_principals.sql):6–35 adds user/group subject shape and group generation. | Permissions require grants, inheritance breaks, ancestor relationships, scope mode and principal state together. Restore must not turn revoked/expired grants active or reuse a historical epoch as current authority. Closure is derived, but omission needs a tested reconstruction and exact comparison. |
| DI08 — principal and approval dependencies | [V186](../../mailserver/sql/dbschema/V186__directory_group_authority.sql):22–89 binds `directory_groups` to domain/source, generation and `directory_group_members(group_id,user_id,membership_source)`; V188 group grants reference those groups. [V189](../../mailserver/sql/dbschema/V189__drive_access_governance.sql):30–108 links Drive grants/policies/details to `approval_requests`, `approval_policies`, users and groups. | Record required identity/group/approval dependencies and their purpose. An ID cannot be rebound to a different target user merely because the number matches. This does not authorize copying all identities, credentials, role grants or approval payloads; unsupported or unauthorized dependency closure blocks selected recovery. |
| DI09 — historical audit and sync state | V114:149–187: `drive_changes`, `drive_watches`, `drive_audit_log` with per-space chain checksum in `after_state`; V184 invalidation cursor/epoch. [drive_maintenance_sweep](../../mailserver/sql/reducers/drive_maintenance_sweep.sql):33–46 prunes journals at the source's retention boundary. | Preserve available audit provenance and chain validation material; do not claim older pruned history exists. Selected audit extraction must not expose unrelated space history or break the chain silently. Watches/subscriptions stay inactive after clone. Source cursors require target reconciliation, not blind continuation. |
| DI10 — transient claims and grants | V114:139–173: `drive_upload_claims`, `drive_chunk_gc_queue`; [V190](../../mailserver/sql/dbschema/V190__drive_acl_upload_binding.sql):5–20: `drive_upload_authorizations` binds user, target, ACL epoch and expiry. [V116](../../mailserver/sql/dbschema/V116__drive_compliance.sql):20–31: `drive_export_grants` token hash/version/actor/expiry; V189:114–131: bounded-use leases. | Do not restore live upload/download authority or replay GC queue items into a clone. Capture any required provenance separately from executable state. Uncommitted uploads are not accepted file versions. Existing queue/claim rows in a full DB dump are not a safe clone disposition. |
| DI11 — retention obligations | V114:119–121 and V116:52–59 distinguish chunk `retain_until` target from `worm_applied_until` observation. [drive_version_prune](../../mailserver/sql/reducers/drive_version_prune.sql):21–46 skips GxP and branch/head/merge/lock/Chat/Meet references. | Preserve target retention and verify destination enforcement independently; source confirmation does not prove destination Object Lock. Retained zero-ref chunks and already-rowless locked objects require explicit coverage adjudication, not automatic trash deletion or a claimed complete inventory. |
| DI12 — closed Office structured state | [V220](../../mailserver/sql/dbschema/V220__office_foundation.sql):9–35 has provider policy/config/preferences; :38–109 has sessions, launches, WOPI locks and save receipts linking expected/result versions/branches. [V224](../../mailserver/sql/dbschema/V224__office_delivery_control.sql):68–125 has closed `collabora-code` revisions, artifact/runtime config and operation/lease state. | Configuration, durable save provenance and executable sessions have different restore dispositions. Generic app manifests/namespaced databases are future declarations, not these closed Office tables renamed as a deployed extension schema. Office history receipts need their exact dependency closure without reactivating tokens, executors or provider routes. |

Whole-file `content_sha256` identifies assembled content; it is not necessarily
one chunk key. Physical counts deduplicate `(namespace,scope,hash)`; logical Drive
quota counts version sizes, even when versions share chunks. V114:36 and :416–443
make that distinction explicit: version-chunk INSERT/DELETE triggers maintain
chunk reference counts and enqueue zero-ref chunks. A selected restore cannot
copy the original global `g` reference count unchanged into a smaller target.

### Mail representation amendment — 2026-09-08

The bounded raw-message map
establishes that `raw_ref` is not uniformly an attachment object identity: inspected
producers use inline RFC5322, bare hashes, `inbound/<hash>`, `blobs/<hash>`, and an
APPEND sentinel whose literal lives in a database field. The
[initial attachment map](storage-e0-drive-mail-byte-map.md) also records the
bare-hash/capture-prefix discrepancy requiring adjudication. The diagram above
therefore describes BC02's convention, not all Mail storage or qualified coverage.

For B0/B1, classify database-held literals separately from exact external object
references and accepted-work references. Do not normalize keys by stripping or
adding a prefix, interpret every `raw_ref` as a hash, or turn an unresolved sentinel
into an empty message. A full DB dump can preserve inline data while still omitting
externally referenced raw bytes; attachment set equality cannot prove full Mail
recoverability. Held/outbound/scheduled references and their final ownership census
remain separate source-mapping obligations, not presumed covered by `messages`.

The scan/search map
likewise separates database text, search vectors and DLP metadata from S3 bytes.
Their protection/backup/rebuild disposition must be stated independently. Object
encryption, S/MIME encryption and encrypted database backups are different claims.

### Shared Chat/HR owners — 2026-09-08

The source-bound Chat/HR map
distinguishes Chat preview images and HR receipt links in shared `blobs` from
ordinary Chat attachments in Drive versions/chunks. Positive blob refcounts alone
do not identify the selected app or prove its logical recovery closure. Preserve
each selected cache/receipt/version owner while deduplicating exact physical copies;
never copy a source aggregate count as the restored count for a selected subset.

An approval becoming terminal does not release its receipt dependency. A preview
cache's TTL is not the lifetime of a captured backup: once included, the independent
backup owner protects the captured representation through verified copy/commit.
Omitting derived previews still requires a qualified rebuild/omission profile and
truthful recovery impact; do not silently refetch remote URLs during inactive
restore. Neither a full DB dump nor a shared-hash object copy establishes safe
reactivation of Chat, HR approvals or their external effects.

## 2. Existing capture and restore paths

| ID / source boundary | Captures or consumes today | What it does not establish |
|---|---|---|
| BC01 — [ConfigBackupHandler.ExportConfig / ImportConfig](../../mailserver/internal/admin/admin_config_backup.go):23–100 | Exports `system_config` key/description/value, redacting encrypted or secret-classified values. Import accepts allowed string-valued entries and counts skipped entries. | Not an independently restorable full configuration package, key backup, app manifest inventory or business-data recovery. Export shape is different from BC02. |
| BC02 — [Engine.ExportConfig / processRun](../../mailserver/internal/backup/engine.go):277–292, :504–545 | Worker exports `system_config` as key → `{value,encrypted}` after the blob-copy stage. `SnapshotBlobs` at :198–205 selects `blobs WHERE ref_count>0`. `CopyNewBlobs` uses `blobs/<hash>` and verifies bytes. | No `drive_chunks` enumeration in this path; its blob snapshot and later configuration query are not one exported DB snapshot. Neither encrypted fields nor a ciphertext fingerprint supplies the recovery key. |
| BC03 — `Engine.writeManifests`, same file :317–377 | Writes `manifests/incr-<ts>.json`, `config-<ts>.json`, `config.json`, `backup-manifest-<ts>.json`, then `backup-manifest.json` as latest commit point. The blob manifest records hashes/count/total size; signing is conditional on configured signing-key length. | No Drive scope/stream/version inventory. Do not label every backup artifact independently trusted merely because an optional embedded signature is present. Partial copy fails before manifest publication in `processRun`. |
| BC04 — [captureSnapshotAndDump / pgDumpSnapshotArgs](../../mailctl/backup_recovery.go):435–583 | Direct-owner repeatable-read/read-only transaction exports a PostgreSQL snapshot; `pg_dump --format=custom --snapshot=...` has no table selector. Reads installation/timeline/schema, users/mailboxes counts, positive-ref Mail blobs, configuration and feature-toggle digest in that snapshot. | A complete dump is expected to contain accessible current Drive metadata; no retained dump was examined to prove actual rows/schema. Byte coverage remains Mail-blob-only. This is not a selected row export or identity-remapping plan. |
| BC05 — `runPreUpgradeBackupWithDependencies / compareBackupToSnapshot`, same file :195–265, :602–644 | Completes the gateway backup first, captures the DB snapshot afterward, and rejects mismatch in exact Mail blob set/count/bytes or configuration. Writes `recovery-sets/<id>/database.dump`, `database.list`; binds those with immutable blob/config artifacts, schema/release, timeline and external protected-key fingerprint. | Equality checks are not an all-domain consistency oracle. Missing Drive bytes can remain invisible to this comparison. Manifest verification is not a selected-app restore. |
| BC06 — [recoveryset.Coordinator.Commit / verifyBlobInventory](../../shared/recoveryset/coordinator.go):40–67, :117–184; [Manifest / Counts](../../shared/recoveryset/verify.go):39–63 | Verifies four artifacts, then re-reads/hashes each `blobs/<digest>` and checks counts. Writes `recovery-sets/<id>/manifest.json` last. Counts name blobs/bytes/users/mailboxes. | No Drive byte namespace or Drive graph/ACL oracle. `ValidateRestoreProof` at :162–169 validates supplied isolated/schema/login/mail/blob evidence fields; it does not execute a restore or test Drive. |
| BC07 — [restore.Engine](../../mailserver/internal/restore/engine.go):81–136, :185–211, :281–355 | `RestoreConfig` checks manifest/config integrity only when `HeadObject("backup-manifest.json")` succeeds; a missing manifest or other HEAD error skips that check before `restore_config_apply`. `VerifyIntegrity`, `RestoreFromManifest` and `RestoreMissingBlobs` use `blobs/<hash>`, with source/post-write verification. | Successful safe-key application does not prove manifest integrity was checked. No Drive-byte restore loop in those inspected functions. Configuration restore's safe-key policy is not proof that raw database restore performs the same filtering. |
| BC08 — [mailctl.orchestrateRestore / runRestore](../../mailctl/restore.go):265–290, :347–417; [pgDumpArgs](../../mailctl/backup_db.go):20–29 | Existing full restore restores blob content into the empty target first, rechecks/resets the schema, then loads the DB dump; config comes from DB replay. Standalone custom DB dump preserves database ownership/ACLs and needs standard roles at the target. | Not a selected inactive copy inside an active organization. Restoring a dump containing sessions, grants or job state does not itself prove clone remapping, effect suppression or safe activation. |

Configuration restoration already has a distinct authority: [V229](../../mailserver/sql/dbschema/V229__restore_config_policy.sql):49–79
defines `restore_config_disposition` and `restore_config_apply`. Encrypted entries
are classified `rotate`; unknown entries default to quarantine; only admitted
safe entries, or the separately conditioned operator-approved class, apply.
BC07 passes `p_source_verified=false`. Preserve that distinction between captured
material, integrity, source trust and permission to activate it. No credential or
key values belong in this inventory or a backup preview.

### Backup transport qualification amendment — 2026-09-08

The E0 census binds backup/restore calls
separately from their concrete transports. In the inspected engine, primary-copy
reuse verifies digest, but replica same-size reuse skips without that verification;
replica metadata copying continues after blob failures. Primary-run completion is
therefore not evidence of a complete, independently restorable replica.
RestoreConfig performs its manifest/config integrity comparison only after a
successful manifest HEAD. A HEAD failure must not silently choose a less verified
restore profile. ApplyRetention logs provider-delete errors and still attempts
backup_runs deletion; that is not confirmed physical cleanup.

For B0/B1, retain separate primary and replica outcomes. A qualified replica must
bind every selected exact object and metadata version to verified bytes before
publishing a complete restore-point receipt; size-only reuse and partial metadata
publication cannot satisfy this. Restore admission must distinguish proven absence,
access denial and unavailable observation. Any supported legacy/no-manifest profile
needs its own explicit authority and evidence contract, not automatic fallback on
an I/O error. This amendment does not authorize such a profile.

Bind historical-index retirement to the shared durable physical-deletion owner:
lost responses, failed deletes and DB-row removal must preserve an exact outstanding
obligation and truthful partial state. Preserve latest pointers, independent reader/
backup/migration/compliance protections and the existing domain retention selector;
do not create a second GC coordinator or infer blob deletion from index retirement.
These are planned corrections/oracles, not implemented fixes or new scan findings.

Root inspected backup/engine389–458,602–628 and restore/engine81–113. Their exact
whole-file hashes are bound in the census; no tests or live restore were performed.

## 3. Proposed preset classification — not existing selectors

Legend: **include** = required within the declared recoverable scope; **exclude** =
not business-data capture for that preset; **conditional/block** = the exact
dependency, safe handling or rebuild contract is unresolved and cannot be omitted
behind a success label. All rows below are B1 proposals implementing the accepted
categories, not deployed export SQL. Full is the accepted future default, not a
code/default change made here.

| Category | Configuration only | Selected apps/data | Full recovery |
|---|---|---|---|
| `system_config`; app manifest/config definitions | Include explicitly enumerated categories with redaction/key/restore disposition; generic app inventory mapping remains conditional. | Include selected app configuration and required dependencies. | Include declared configuration plus independently governed key requirements. |
| Users, credentials, keys, privileged policies | Conditional/block: enumerate separately; never silently bundle under “config.” | Conditional/block only necessary identity mapping/security dependencies; no blanket identity export. | Required declared recovery dependencies, with accepted protected-key handling and current-authority activation. Exact security inventory still needs owner review. |
| DI01–DI05 tree/files/retained versions/branches/content | Exclude; explicitly cannot recover business data. | Include exact selected objects plus required structural/version closure and their scoped chunks. | Include all in-scope captured Drive business objects and retained history, not only live Main heads. |
| DI06 ready preview streams | Exclude bytes. | Include by default in this proposed inventory; omission only under a tested rebuild profile and explicit recovery impact. | Same rule; “derived” alone is not evidence that omission is safe. |
| DI07–DI08 ACL, membership, principal and approval dependencies | Only explicitly chosen policy definitions; no implied content/identity restore. | Include necessary authority/provenance closure, or block when unauthorized/unrestorable. | Include declared authority dependencies; historical permissions are not automatic target activation. |
| DI09 audit and source sync state | Exclude business history; any configuration audit category must be separately named. | Conditional/block for chain-preserving, authorized scoped audit projection; capture required provenance without silently expanding unrelated history. | Include required retained audit/history and source cursor provenance; validate chains and reconcile target cursors. |
| DI10 transient claims, leases, tokens, queues; Office live sessions | Exclude executable state. | No replay as live authority. Capture only required historical evidence/accepted-work obligations with explicit terminal or inactive disposition. | DB capture may contain rows, but restore must separately fence/reconcile executable state before services or effects can run. |
| DI11 retained zero-ref bytes / rowless retained objects | Exclude bytes. | Conditional/block when retention obligations belong to the selected scope and cannot be independently enumerated. | Conditional/block until retained-byte completeness and destination enforcement are proven; zero reference count is not an automatic omission rule. |
| DI12 durable Office/app records | Configuration subset only; no save/history recovery claim. | Include selected structured state and version/provenance dependencies; retain runtime activation separately. | Include declared structured state. Generic app-managed DB/export formats still require per-app declarations. |
| Mail/Chat/Meet content referenced from selected Drive records | Exclude. | Mere reverse references do not pull in unrelated messages/recordings. Include only declared necessary dependencies after scope/authority checks, otherwise block or request an explicitly broader selection. | Governed by the explicitly declared full-domain inventory; this Drive-focused document does not establish all Mail/Chat/Meet coverage. |
| Declared Mail raw representations and accepted-work dependencies | Exclude business content; no mail-recovery claim. | Only for explicitly selected Mail scope or an approved necessary dependency; enumerate literals, exact keyed bytes and non-message owners. Unresolved representation/authority blocks completeness. | Include the declared Mail representation and accepted-work closure, independently of positive-ref attachment blobs. Restore obligations remain inactive until reconciliation; no automatic resend. |
| Declared Chat previews/attachments and HR receipts | Exclude business bytes and approval/message content. | Include only selected logical owners and approved necessary dependencies; keep shared blob and Drive chunk identities distinct. Omission needs qualified recovery/rebuild disposition. | Include declared domain closure with independent capture protection; source TTL or terminal approval status does not authorize dropping captured evidence. No automatic refetch or approval execution. |
| Scratch, canonical orphan candidates, cache, external vendor data | Exclude scratch; explicitly label external omissions. | Exclude uncommitted scratch; cache omission needs verified rebuild. External records require declared export/recovery or an explicit incomplete result. | Same rule; no promise that an unmanaged external system or every historical copy is captured. |

### Selected dependency closure, bound to current relationships

1. Start with authorized explicit app/file/space roots. Resolve app ownership using
   an approved mapping; do not infer it from the installer, directory name, Docker
   label or all rows in a shared `g` scope.
2. Add required node ancestors, space metadata, file rows, captured selected
   versions, Main/branch heads, fork bases, labels and their dependency reasons.
   Follow parent/conflict/merge references only under the declared history scope.
   An out-of-scope FK with no safe standalone representation blocks or requires
   a previewed broader selection; do not delete the edge to make import succeed.
3. Resolve ACL anchors, inheritance breaks, closure, mode/epoch and required
   principal/approval provenance. Effective permission is not a list of user IDs.
   Historical evidence may be retained without importing a live credential or
   reenabling a revoked identity. Unresolved mapping remains a blocker.
4. Join selected `drive_file_versions.id` to every required
   `drive_version_chunks(version_id,stream,ordinal)`, then to
   `drive_chunks(scope_key,sha256)`. Record each logical reference and each unique
   physical object, with size/digest and inclusion reason. Include ready previews
   unless their verified omission profile explicitly changes the effective scope.
5. Add declared durable app state, accepted-work receipts, audit proof and key
   dependencies. Compare the resulting requested/effective scope against the
   approved preview. No whole-database dump may masquerade as a selected export.

These steps are a logical algorithm, not permission to execute unscoped SQL.
No public app receives the existing backup worker/owner credentials.

## 4. GC and snapshot consistency: facts, failure, candidate protocol

Current deletion participants:

| Source participant | Actual predicate/effect | Snapshot implication |
|---|---|---|
| V114:416–443 reference triggers; `drive_maintenance_sweep`:53–65 | Version-ref deletion decrements counts/queues zero-ref chunks; unclaimed zero-ref chunks are also queued once no recent upload claim remains. | A chunk referenced in an earlier snapshot can become a current zero-ref candidate. MVCC preserves the old row view, not object-store bytes. |
| [Worker.gcDecide / gcDeleteOne](../../mailserver/internal/drive/worker.go):35–42, :240–329 | Batch classification checks reference count/retention; first transaction locks the chunk key, rechecks zero-ref plus queue and deletes the row. After commit, a second transaction takes the same lock, rechecks row absence and removes bytes. | Backup protection must cover both the DB-delete admission and the post-commit object-delete gap. This inspected path has no backup-pin predicate. Do not describe the batch retention check as a newly proven universal same-transaction retention guarantee. |
| `Worker.reapCanonicalOrphans`, same file :332–411 | Lists only `drive/`, checks exact key grammar and age, then takes the shared chunk lock and checks current DB absence before deletion. | Protecting only GC queue rows misses canonical orphans. A snapshot-referenced object whose current row disappeared can reach this path. |
| `Worker.reapTmp`, same file :45–63, :481–495 | Reaps stale `tmp/upload/` objects after the current 24-hour window; unknown age is not stale. | Temporary objects are not accepted business bytes. A backup must not depend on them without an explicit accepted-work staging contract. This is a source timer, not the future backup lease duration. |
| [Chunk producers](../../mailserver/internal/drive/chunks.go):329–395 | Trusted staged promotion and registration use `hashtextextended('drive-chunk:' || scope || ':' || sha,0)` transaction locks. | Existing serialization is reusable at the internal storage boundary, but does not by itself pin the entire captured set. |
| `PreviewWorker.render`:213–226 and `drive_preview_attach`:72–87 | Preview writes canonical objects directly, then registers/replaces preview references. No shared chunk-lock call appears in these inspected bodies. | Producer participation is a concrete coverage gap for the proposed protocol; do not claim every current producer already follows the staged-promotion lock rail. |
| `drive_version_prune`:21–54; `drive_node_destroy_hard`:55–100 | Prune preserves named version dependencies; hard destroy breaks branch/head/export FKs and cascades chunk-reference deletion. `Worker.tick`:163–165 does not schedule `drive_version_prune`. | Do not claim an active generic prune job. Snapshot protection must tolerate allowed concurrent metadata deletion and preserve its captured bytes independently of current references. |

Failure schedule to forbid: capture version V and chunk C in snapshot S → current
V is deleted → C becomes zero-ref → GC deletes C → backup copies remaining objects
and reports success. An exported snapshot and an object-list timestamp cannot
close this race.

The following is a **candidate B1 algorithm**, not a deployed lease/pin schema:

1. The existing backup owner requests a bounded deletion-admission barrier for
   the affected byte plane. Because regular chunks share `g`, a space-only prefix
   lock is insufficient. All relevant GC/removal participants acknowledge the
   barrier and settle pre-barrier deletes before snapshot S is established.
   This is coordination to design, not a request to stop services now.
2. While that barrier remains effective, create S and export/digest its authorized
   metadata and exact scoped reference inventory. A separate reducer-owned
   transaction records durable retention of those object identities for the
   capture operation. The read-only exported-snapshot transaction cannot perform
   these writes itself. Validate every protection acknowledgement before releasing
   the barrier; partial registration does not make a valid capture.
3. Both `gcDeleteOne` transactions and canonical orphan removal must consult the
   committed protection under the same object-lock/fence protocol. Producers,
   including preview, need an audited participation inventory and fixed lock order.
   Do not reuse `drive_upload_claims`, forge `ref_count`, or extend compliance
   `retain_until` to disguise a backup pin.
4. Copy each protected object to the independent backup domain; read/hash/size-check
   destination bytes. Reconstruct whole content/preview streams and compare their
   recorded hashes, order and lengths. A same-size object or successful upload
   acknowledgement alone is insufficient. Missing/ambiguous bytes fail the run.
5. Seal the metadata/ref inventory, actual copied objects, requested/effective scope,
   exclusions and key requirements together. Publish the complete immutable
   recovery point only after all checks. Release exact capture protections only
   after committed independent-copy evidence or explicit aborted-run reconciliation.
6. On crash, lease expiry fences the old executor but does not silently free still
   needed bytes. The backup owner reconciles durable copy/protection receipts;
   cleanup reports retained/unresolved work honestly. B1 must set numeric barrier,
   copy, retry and reconciliation deadlines plus storage-budget limits before
   implementation; indefinite invisible GC suspension is not an accepted outcome.

A storage snapshot/retention mechanism could replace steps 1–3 only with equivalent
independent byte-availability evidence and declared backend support. No storage
versioning, Object Lock, KMS or physical snapshot capability is assumed here.

## 5. Proposed logical inventory and independent restore oracles

These are record **roles** for a future versioned backup manifest, not tables or
wire fields claimed to exist:

| Logical record | Required binding to source facts |
|---|---|
| Capture envelope | Backup operation/idempotency scope, source installation/timeline, DB schema and release, snapshot identity, authorized requested/effective scope digest, actor/grant evidence without secrets. Request correlation ID remains separate from durable retry identity. |
| Metadata object | Source table/type + stable source identity, owner/scope, canonical record digest, included relationships and dependency reason; explicit source-to-target mapping on selected restore. |
| Version stream | Source version, stream, ordered ordinal refs, whole-stream digest/size, preview state and branch/parent/merge provenance. |
| Physical object | Exact source namespace/key (not a closed `blobs`/`drive` enum), source provider/placement identity and security scope, digest, verified length, independent backup reference, protection/copy-verification receipt and retention needs. Future encoding generations bind under Storage E3/E5; equal content hashes do not erase namespace/scope authority. |
| Database-held content and logical references | Explicit representation discriminator, owning source record/field or exact external-object reference, verified content digest/length and accepted-work dependency reason. Inline/literal bytes belong to metadata capture, not a fabricated S3 key; executable-state disposition remains separate. |
| Restore disposition | Included, excluded-with-reason, protected dependency, rebuild-required-with-tested-profile, inactive operational provenance, or incomplete/blocking. No missing category silently becomes empty. |

Selected restore remaps space/file/version/branch/principal/app identities; full
isolated recovery may retain source identities only under its separately approved
target model. Neither may import `s<old-space-id>` keys into a different target
scope by string substitution alone. Drive owns target storage-reference creation,
chunk registration, derived reference counts and quota. Preserve original audit
provenance/digests without rewriting history to fit new IDs; the cross-link/proof
representation remains a B2 gate.

| Proposed oracle | Concrete pass/fail condition |
|---|---|
| BI-T01 — exact metadata closure | Independent verifier enumerates restored roots, tree, Main/branch heads, fork/merge/parent edges and labels against the captured set. Missing FK, changed owner, extra unrelated file, or hidden scope expansion fails. |
| BI-T02 — bytes and empty streams | Read every destination object, verify scope/hash/length, assemble every content/preview stream by ordinal, compare whole hashes and size. Zero-byte content has an explicit empty manifest; missing/truncated bytes fail rather than becoming an empty file. |
| BI-T03 — quota and sharing | Two selected files share a regular chunk; an unselected file also references it. Restore logical version sizes and recompute destination counts from destination refs; neither copy unrelated file data nor inherit the source global reference count. |
| BI-T04 — ACL and identity | User/group allow/deny, inheritance break, revoked/expired grant, changed group generation and absent target principal produce the declared inactive/denied result. A reused numeric ID or installer departure cannot transfer authority. |
| BI-T05 — retention and history | Retained branch/preview/version survives; missing retained-byte category is incomplete. Destination retention is independently observed, not inferred from copied `worm_applied_until`. Audit proof checks the retained source chain/projection without fabricating pruned history. |
| BI-T06 — GC schedule | Inject capture-before-last-reference-delete, GC between its two transactions, canonical-orphan removal, concurrent reupload and preview attachment. Captured bytes remain available until independent verification; failure cannot publish a complete point. |
| BI-T07 — crash and replay | Crash before/after protection commit, object upload, manifest commit and pin release; stale executor fails, duplicate intent returns one logical operation, unfinished protection stays visible, and cleanup cannot delete another run's objects. |
| BI-T08 — no revived effects | Restore an isolated inactive copy containing watches, Office sessions/receipts, pending app work and expired grants. Observe zero mail/webhook/notification/job/provider effects and denied old tokens until separately authorized activation. UI hiding is not the oracle. |
| BI-T09 — preset honesty and key failure | Config-only contains no business-data recovery claim; selected does not bundle unrelated content; missing required permission, protected key, external export or Drive chunk blocks recoverability. Demonstrate recovery from a genuinely independent failure domain. |
| BI-T10 — Mail representation and obligation closure | Exercise inline, bare-hash, prefixed and APPEND literal/sentinel inputs plus source-bound held/outbound/scheduled owners. Restore exact bytes and declared inactive obligations without false empty-message success, key normalization or automatic delivery. Missing external raw bytes fail even when DB/attachment counts match; map to Storage E0-RM-01/03/04 rather than implementing a second resolver/pin authority. |
| BI-T11 — shared domain owners | Select one of Mail/Chat-preview/HR owners of the same blob and a Drive-backed Chat attachment. Restore only declared logical scope, exact namespaces and recomputed counts; preserve terminal HR receipt dependencies. Cache expiry during capture cannot delete independently protected bytes. Unselected content, automatic remote refetch or revived approval/Chat effects fails; bind CH/LP cases without duplicate evidence counting. |
| BI-T12 — independent replica qualification | Corrupt an existing replica object without changing its size; fail one copied blob or metadata object. No complete replica receipt/latest qualified restore point may advance until all selected exact bytes and metadata verify. Primary success remains separately reported. |
| BI-T13 — restore observation failures | Cross manifest present/absent, denied, timeout and malformed metadata with config integrity. Observation failure cannot bypass the required verification or select a legacy profile; no configuration is applied before its admitted profile checks pass. |
| BI-T14 — historical-index retirement | Inject denied deletion, lost provider response and crash around backup_runs removal. Exact pending cleanup remains durable and visible; no false physical-completion claim or release of another lifecycle's protection. Reuse LP/PD oracles instead of duplicating their authority. |

Existing test source anchors, **not fresh runs**: [blob_integrity_test.go](../../mailserver/internal/backup/blob_integrity_test.go):57–94
covers blob corruption/invalid inventory; [manifest_emit_test.go](../../mailserver/internal/backup/manifest_emit_test.go):256
has `TestWriteManifests_CommitPointNotWrittenOnFailure`;
[manifest_restore_test.go](../../mailserver/internal/restore/manifest_restore_test.go):260–297
covers corrupted blobs/count mismatch/post-write failure;
[worker_gc_race_live_test.go](../../mailserver/internal/drive/worker_gc_race_live_test.go):34
names the GC/reupload race; [worker_live_test.go](../../mailserver/internal/drive/worker_live_test.go):126,177
names canonical-orphan inventory/race cases. These do not prove BI-T01–BI-T14,
snapshot retention or generic selected/full Drive recovery.

## 6. Bounded gaps and ownership handoff

This inventory establishes concrete source roots for B0; it does not close B0 for
every app/domain. Remaining work is specifically bound to: later migration/foreign-key
coverage for the selected classes; app-space ownership mapping; cross-file merge
and audit-chain dependency projections; preview producer serialization; retention-only
and rowless object inventory; all GC/protection participants; safe configuration
versus raw-DB replay; target ID/key mapping; per-app structured/external state;
effect suppression; exact deadlines and independent restore evidence.

No new product decision is made. Existing accepted preset, retain-default and
inactive-copy rules stay fixed. If identity/policy-copy authority or an otherwise
unrestorable cross-domain selection needs a broader product/security choice, return
that concrete dependency and impact to its owner rather than authorizing it here.

## Source fingerprint appendix

SHA-256 of source bytes inspected on 2026-09-06. This list fingerprints the bounded
inputs, not proof of running binaries, applied schema or passing tests.

| Source | SHA-256 |
|---|---|
| `mailserver/sql/dbschema/V114__drive_core.sql` | `d771694ed844dfa6cbdcd087f4c7d3b5bfaecb5a1e75dcdd835be2f639a8daec` |
| `mailserver/sql/dbschema/V115__drive_versioning.sql` | `803503aaf8d95ecd6f97d8a953347625f07e5594299f47056fbe6f1a89619cf6` |
| `mailserver/sql/dbschema/V116__drive_compliance.sql` | `6a4f95a5282ee60e1756ca5b5963ae7bd9614f3919265c871028458a934f1040` |
| `mailserver/sql/dbschema/V184__drive_node_acl_foundation.sql` | `894c86854d3da6adfce1c99c7b0f64eb1577afd8529e1cc25ca2c31d6b77a7b8` |
| `mailserver/sql/dbschema/V186__directory_group_authority.sql` | `4791f84b0ccee6649cdd93dc5e5fa1b72eb26394572cdec9e853f4fd5915c87e` |
| `mailserver/sql/dbschema/V188__drive_acl_group_principals.sql` | `d81e5c3548e31137ac3bda6700fc108484a2ff9f6ca648c3f94ac5ed3145be20` |
| `mailserver/sql/dbschema/V189__drive_access_governance.sql` | `64bc0becb6886e8f3e32af6e6a445cbd187dd664bd1fc84b2b4395137d4967b3` |
| `mailserver/sql/dbschema/V190__drive_acl_upload_binding.sql` | `4dd7da4bcd1c7203731b1e9abf9fab92643c2efcfcb66ef139d492736cc61ced` |
| `mailserver/sql/dbschema/V220__office_foundation.sql` | `020f527e7560521c19e54bc2f3b7bb9f39513926a1f6df5979ae72edabd3174b` |
| `mailserver/sql/dbschema/V224__office_delivery_control.sql` | `7669db621406c723d765a83b01f57806ab59cf52c560aa8a2b7bf0ba46d24088` |
| `mailserver/sql/dbschema/V229__restore_config_policy.sql` | `99df727c4057fd19d1586e7ca5a19681461e6892cbbfdd44bd2902aafec38b0b` |
| `mailserver/internal/drive/chunks.go` | `29344aa56ac1ac0f0089151bc1e02db3c43b0d4ffca9ab76a39823adae273004` |
| `mailserver/internal/drive/worker.go` | `52cf26be3866dfcaf5195eb688e76f11ae039ed14e986582231bac79de82767b` |
| `mailserver/internal/drive/preview.go` | `3be2750d208f24f58e6ef0091900e93932f07399900726973579d327c35a0483` |
| `mailserver/sql/reducers/drive_preview_attach.sql` | `54451ba5fdbb90aa57448f4f1cf1f4fd3409cbedf5a0179cffeef2c4d791a73c` |
| `mailserver/sql/reducers/drive_version_prune.sql` | `1fe79b56dcbb218cfd50fcb95b7bda816905b89087bec824cdd4fd802a424465` |
| `mailserver/sql/reducers/drive_node_destroy_hard.sql` | `3e8ed063d3bcee79992ed0a2ca7b402ac5fa6828b531619124ccefe1f3023892` |
| `mailserver/sql/reducers/drive_maintenance_sweep.sql` | `589a22cc6da2b90f2ed0de6f28261c968a2dfaab8e8f99c3de842ac7e4935805` |
| `mailserver/internal/admin/admin_config_backup.go` | `6580a5e9da430e1f225cd1d8694fe754b8d68b60f28e1d9b4bf7e9efc68940f3` |
| `mailserver/internal/backup/engine.go` | `3e950f58b410f498006e79d4c9a59ddc74692ccd7d1fe52e66341498c89f0c80` |
| `mailserver/internal/restore/engine.go` | `d6ff4d8193510ecd8e4c5fb28afcc39c8ac8bd223185ad341389eba3528a98c7` |
| `mailctl/backup_db.go` | `7f109d93100f50391b0fd823fd1ac69f0e53ac9aa38b587a38ce95496ad5b2c9` |
| `mailctl/backup_recovery.go` | `a70f9d85bd8f933d1c1546586ed34453bc4b8fa01f719d29d2ffc97194e71ff5` |
| `mailctl/restore.go` | `10c317a0fc5b5d6343321de5a454a6d901d6a729d326ffaab69dbdde2e1e6c81` |
| `shared/recoveryset/coordinator.go` | `cdddd07871f7ccc9d69504eacd735a7656396ab3f64cf05bee2dad49d4fd3330` |
| `shared/recoveryset/verify.go` | `b236aef5868ccf4d8766667dd1c70a6a2b4241c3a32e9ef9252c257e894f9d09` |
