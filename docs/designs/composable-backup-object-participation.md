# Backup object participation: bounded source map

Date: 2026-09-07. Status: source-grounded reference and proposed RR2/RR3 + BS2 test packet, not implementation approval, a complete lock graph or executed evidence.

Owners remain Drive's data/reducer boundary and the existing backup/recovery coordinator. This sheet refines the CP0 finite slice, [B0 inventory](composable-backup-data-inventory.md), [B1 snapshot contract](composable-backup-snapshot-contract.md) and [recovery records](composable-recovery-records.md). It creates no permission, migration, store capability or alternate job engine. The accepted B0/B1 lifecycle scope remains unchanged.

## Evidence boundary

Current means inspected source, not deployed schema or runtime proof. Proposed means work before profile qualification. Graphify found 241 nodes and returned 37: navigation, not coverage. The register distinguishes full reads, ranges and matches. Root/docs instructions were fully read; complete source-owner DOX, callers, migrations and adapters remain implementation-freeze prerequisites.

No source bytes or tests were changed or executed. No database, object store, process, container, temporary directory or network service was created. Namespace: `sj-plan-backup-envelope-20260907`; root retains the execution ledger and owns integration/Graphify refresh.

## Current identities and participants

`drive_chunks` keys bytes by `(scope_key,sha256)`; `drive_version_chunks` keys ordered content/preview references by `(version_id,stream,ordinal)` ([V114:115–137](../../mailserver/sql/dbschema/V114__drive_core.sql:115)). Canonical keys are `drive/g/<sha>` (regular/shared) or `drive/s<spaceID>/<sha>`; BP07/BP08 use the backup convention `blobs/<sha>`, not a universal live Mail namespace. Neither hash nor folder/shared prefix is content authority. Store/generation binding is proposed, not deployed by V114.

The [2026-09-08 compatibility amendment](storage-e0-drive-mail-byte-map.md#e0-c3-proposed-compatibility-contract--2026-09-08)
supersedes the earlier unqualified Mail namespace statement: live attachment
writers use bare hashes, while raw messages also have prefixed objects and
database-held representations. Preserve exact class/source/backup/target mapping;
do not infer live keys from BP07's backup convention. This correction leaves the
original source-read/score attribution intact and does not qualify a round trip.

| ID / source entry | Observed acquisition, effect and failure boundary | Required participation, not implemented here |
|---|---|---|
| BP01 References | [V114:416–443](../../mailserver/sql/dbschema/V114__drive_core.sql:416): reference INSERT/DELETE triggers UPDATE exact chunk counts; zero enqueues GC. [maintenance:53–65](../../mailserver/sql/reducers/drive_maintenance_sweep.sql:53) queues zero-ref rows without a claim within seven days, then expires claims. | Snapshot references outlive current counts. Pins must not forge counts, claims or retention. Trash/alarm callees (:78/:82), other reference writes and trigger precedence remain unclosed. |
| BP02 Queue GC | [gcChunks:187–222](../../mailserver/internal/drive/worker.go:187) batch-checks count/retention. [gcDeleteOne:240–330](../../mailserver/internal/drive/worker.go:240): transaction A → chunk advisory → DELETE zero-ref chunk iff still queued → delete queue → COMMIT; return if no chunk deleted. Transaction B → same advisory → row-absence check → `RemoveObject(storage_ref)` under lock → COMMIT. Errors log/return, possibly after row deletion. | Fence both phases and the committed gap; a pre-barrier delete remains tracked after A commits. Batch retention classification is not a universal same-transaction retention proof. |
| BP03 Canonical orphans | [reapCanonicalOrphans:337–376](../../mailserver/internal/drive/worker.go:337) lists `drive/`, checks grammar/age; [reapCanonicalOrphan:379–412](../../mailserver/internal/drive/worker.go:379) takes transaction/chunk lock → DB absence → `RemoveObject` under lock → COMMIT. DB-check failure preserves bytes; deletion errors log for retry. | Row-absent objects need protection checks. Restarted sweepers must observe durable barrier/epoch; listing cursor is not acknowledgement. Backend retention/error semantics remain unqualified. |
| BP04 Scratch | [reapTmp:481–496](../../mailserver/internal/drive/worker.go:481) deletes stale `tmp/upload/` objects without DB/chunk lock; unknown age is not stale (:58–63). [Cleanup:292–294](../../mailserver/internal/drive/chunks.go:292) deletes its exact temp key best-effort; staging removes hash/size failures (:315/:319). | Scratch is not accepted recovery data. Recovery use requires protection-aware reaper and exact-key cleanup first; no timer-based guarantee. Preview filesystem cleanup is separate. |
| BP05 Promotion | [StageChunk:300–322](../../mailserver/internal/drive/chunks.go:300) stages random temp bytes and verifies hash/size. [CommitStagedChunk:346–358](../../mailserver/internal/drive/chunks.go:346): reauthorize → chunk lock → canonical CopyObject → registration within caller transaction. [Bound:373–387](../../mailserver/internal/drive/chunks.go:373) checks target/epoch → chunk lock → copy → bound registration. Rollback can leave canonical orphans. | Keep lock-through-copy until replacement qualification. Producer reservations must exclude pending/unknown same-key deletion before promotion/attachment. Staging alone is not accepted file content. |
| BP06 Preview | [tick/render:101–229](../../mailserver/internal/drive/preview.go:101) plain-select pending versions → assemble local source → renderer → read whole PDF/reject empty → direct canonical PUT → [attach:25–89](../../mailserver/sql/reducers/drive_preview_attach.sql:25). Attach inserts chunks, replaces preview refs by DELETE/INSERT, updates hash/status; failed/unsupported only updates status. | Neither inspected body acquires the chunk advisory. Both I/O and reference replacement must participate. Attach's later row locks cannot protect the earlier PUT. Gap identified, not runtime loss reproduced. |
| BP07 Gateway backup | [SnapshotBlobs:198–205](../../mailserver/internal/backup/engine.go:198) selects positive-ref Mail `blobs`; :210–274 copies `blobs/<hash>` and re-reads destination size/hash. `processRun` :515–545 snapshots → copies → separate config query → manifests; copy errors stop publication. [writeManifests:331–386](../../mailserver/internal/backup/engine.go:331) writes latest index last. | No Drive enumeration/pins in these bodies; config is not one exported snapshot. Preserve verification. Replica/retention (:565/:570) remain unclosed; current latest index is not the proposed seal protocol. |
| BP08 Snapshot/dump | [captureSnapshotAndDump:435–584](../../mailctl/backup_recovery.go:435): direct-owner repeatable-read/read-only S → Mail/config/toggle inventory → custom pg_dump with S → validate/list → COMMIT. [Caller:195–265](../../mailctl/backup_recovery.go:195) finishes gateway backup before S; [comparison:602–640](../../mailctl/backup_recovery.go:602) checks exact Mail hashes/count/size/config. | No table selector: Drive metadata expected, not artifact-proven. Mail-only byte comparison misses Drive coverage. Current S spans dump/list I/O; future pins require separate writable transactions, metadata persisted before closing S. |

## Lock edges that constrain the next change

The current explicit chunk primitive is exclusive `pg_advisory_xact_lock(hashtextextended('drive-chunk:' || scope || ':' || sha,0))` ([chunks:329–332](../../mailserver/internal/drive/chunks.go:329)). It is transaction-scoped; store/bucket is not part of this key. SQL registration takes the same advisory lock again; re-entry is not a lock upgrade. Preserve existing serialization rather than adding a second, incompatible chunk key.

| Call shape | Current order visible in read bodies | Freeze consequence |
|---|---|---|
| Unbound Go promotion and direct `drive_chunk_register` | `drive_chunk_upload_require` locks `drive_spaces` `FOR SHARE` ([register:26–30](../../mailserver/sql/reducers/drive_chunk_register.sql:26)) → chunk advisory → canonical copy in Go → SQL registration repeats space SHARE and advisory → chunk/claim writes → queue delete (:59–81). | Re-entered locks remain in the enclosing transaction. Domain locks acquired before this helper are unknown until caller closure. |
| Bound Go promotion versus direct `drive_chunk_register_bound` | Go's initial authorization query has no explicit row-lock clause (:361–370); Go takes chunk advisory and copies before bound SQL takes `FOR SHARE OF n,s,g` ([register:94–101](../../mailserver/sql/reducers/drive_chunk_register.sql:94)), then repeats chunk advisory (:115–116). Direct SQL begins with row SHARE then advisory. | Concrete opposite acquisition edges, not proof of a conflicting lock cycle: SHARE modes, FK/trigger locks, upstream exclusive holders and caller transaction order must be mapped. No caller mode, bulk ordering or lock upgrade is silently inferred. |
| GC/orphan I/O | BP02 transaction B and BP03 hold chunk advisory continuously across the final absence check and DELETE call. | Do not apply the proposed “short transaction/no network I/O” rule by merely dropping these locks. Error return/context cancellation alone is not a newly verified backend cessation proof. |

Current constants are separate facts: maintenance interval 5 minutes, GC/inventory batch 200, canonical/tmp age windows 24 hours ([worker:22–63](../../mailserver/internal/drive/worker.go:22), [:177–179](../../mailserver/internal/drive/worker.go:177)); chunk maximum 4 MiB ([chunks:23–26](../../mailserver/internal/drive/chunks.go:23)); preview tick 15 seconds, batch 5, command timeout 2 minutes ([preview:41–45](../../mailserver/internal/drive/preview.go:41), [:262–271](../../mailserver/internal/drive/preview.go:262)). These are not joint capacity, backup leases or authority to raise limits. The separately owned EN-T10 resource envelope must bind actual profiles, admission and measurements.

## Proposed participation protocol: preserve B1/RR ordering

1. Freeze producer/deleter capabilities and byte planes; shared `g` precludes folder-only barriers. Unknown participants block this profile, not unrelated accepted work. Domain reducers retain authorization, quota/count/retention and cleanup authority.
2. Proposed order: plane admission → stable operation order → canonical scoped-object order. Close this operation's deletion admission; settle all pre-admitted effects, including BP02's gap and rowless BP03. This is not yet a replacement lock proof.
3. After exact participant epoch acknowledgement and settlement, establish S, persist typed metadata/ordered references and digest/counts. Install pins in separate writable transactions; accept the complete inventory once. Partial pins never release the blocker; one operation cannot clear another's.
4. Source-capture pins protect S; destination-stage protections precede target promotion. Neither is a claim, live ref or WORM hold. Pending/unknown delete reservations block same-store/key promotion, attachment and new protection acceptance even without a current row.
5. Release deletion reservations only after proven request cessation and reconciled outcome. Expiry, restart, HEAD, response loss or worker stop are insufficient. Unqualified backends retain reviewed lock-through-I/O or block the new profile; this does not prove every old delayed-backend case safe.
6. After complete pins and durable metadata, release only this broad barrier and close S; do not hold S through byte copying. Exporter crash before complete metadata requires re-preview/new S. Mutations enforce current authority and post-lock database-time fencing; expiry never deletes pins.
7. Independently verify objects and assembled streams, then accept one immutable seal. Pre-seal cancel reconciles owned effects; post-seal interruption reconciles that publication. Release source pins only after publication evidence or reconciled pre-seal abort. Never target existing backups, shared/held objects or another operation's protections.

## Exact future schedules and independent oracles

All BP-T cases below are proposed, not present test names or passed evidence. Add them under the existing Drive/backup test owners with new fixture bindings at implementation freeze; no new runner is allocated here.

| Case / injection boundary | Required negative and positive oracle |
|---|---|
| BP-T01 Queue gap, BP02 A COMMIT (:266) / before B lock (:288) | Before A commit, active protection prevents destructive admission. After A commit, a pending ticket prevents barrier settlement and capture success. After proven deletion cessation/outcome, a fresh reupload may commit and its bytes/ref row survive. Snapshot-referenced bytes are never lost under a complete-capture receipt. |
| BP-T02 DELETE response loss, BP02 :305 and BP03 :401 | Crash before dispatch and after backend acceptance but before local receipt; delayed DELETE remains pending/unknown across executor expiry/restart. Same-key preview, upload and restore promotion plus protection acceptance remain refused while executable. Proven cessation + reconciled outcome permits safe retry/reuse; a mere HEAD must fail this oracle. |
| BP-T03 Partial pins and concurrent blockers | Crash immediately before/after each pin batch and complete-inventory acceptance. Incomplete count/digest keeps blocker or reconciles abort; no complete capture. Two operations block `g`: completing one cannot release the other. Complete pins permit ordinary writes and later independent byte verification without the broad barrier. |
| BP-T04 Preview publication gap, BP06 PUT :214 / attach :225 | Pause before canonical PUT, after PUT before attach, and after attach commit before response; race GC/orphan plus capture. Pending deletion prevents unsafe PUT/attachment; successful attachment leaves exact ready preview bytes/ordered refs and trigger-derived counts. Failed attachment cannot produce a ready/complete backup claim. |
| BP-T05 Snapshot/live reference drift, BP01/BP08 | Capture version V, then remove its last live ref, replace preview or reupload same regular key from an unselected file. Captured V and stream hashes reconstruct independently until pin release; unrelated file metadata is not included. ACL/selection change before capture invalidates preview. Exporter crash before durable metadata requires a new preview/S, never partial success. |
| BP-T06 Scratch ownership, BP04 | For current behavior verify unknown/fresh ages are not stale and exact-owned cleanup leaves other keys untouched. If recovery uses scratch, inject expiry while accepted stage is in flight: no reaper/cleanup deletion while its admitted protection applies; eventual reconciled cleanup removes only that operation's unreferenced scratch. Otherwise profile admission refuses that dependency. |
| BP-T07 Ordered lock acquisition | Exercise direct and Go-bound registration against row-exclusive mutation, same-key GC, and two keys requested in reverse input order; cover repeated advisory/row acquisition. Require a frozen trace of actual lock modes/order and successful permitted operations, not only a timeout. Resolve/exclude every observed inversion before adopting the common order; no deadlock-free claim from this documentary schedule. |
| BP-T08 Copy/seal/publication and empty sets | Empty authorized selection is explicitly empty; missing Drive content/preview, scan error, corrupt destination or unsupported retained-byte category cannot become empty/success. Crash before/after copy receipt, seal, final upload and pin release: one immutable result, same-intent replay, changed-intent refusal, no premature pin release. Independently read/hash/assemble the exact expected objects and streams. |
| BP-T09 Restarted or missing participant | Restart a deleter with stale capability epoch while blocker is active; omit one producer/deleter from the admitted registry. Neither can delete or report settled capture. Once the exact supported set reconciles, normal unrelated progress and permitted deletion resume without releasing another operation's protection. |

Existing source read, not execution: [TestWorkerGCChunksRaceAgainstConcurrentReupload](../../mailserver/internal/drive/worker_gc_race_live_test.go:34) uses the final-check hook and asserts canonical presence plus re-registered row. [TestWorkerCanonicalOrphanInventory](../../mailserver/internal/drive/worker_live_test.go:126) checks stale orphan removal and registered/fresh/malformed/locked survival; [:177](../../mailserver/internal/drive/worker_live_test.go:177) checks concurrent upload bytes and row. [TestWriteManifests_CommitPointNotWrittenOnFailure](../../mailserver/internal/backup/manifest_emit_test.go:256) asserts the latest pointer is absent after index-write failure. Their fake-store/live-DB source does not establish delayed backend cancellation, backup pins or BP-T01–09.

## Finite residual gates

This list records the original bounded checkpoint. Subsequent source closures
are tracked in the [current E0 work order](storage-specification-completion-map.md#e0-finite-closure--current-residual-work),
including Office/Meet, raw/held Mail, replicas and deletion tails. Reuse their
exact source-bound answers rather than restarting completed reads; integration,
concrete locks and runtime qualification remain separate open gates.

- Caller matches only: Office [handler:237–248](../../mailserver/internal/office/handler.go:237), Meet [worker_recordings:369–380](../../mailserver/internal/meet/worker_recordings.go:369). Their enclosing transactions, multi-chunk order, accepted-work obligations/cleanup remain unclosed. `putChunk` was read; `RunUserScoped` internals and capability/member helpers were not.
- Unclosed: trash/alarm callees, hard destroy/prune, other reference writes, later FK/trigger definitions; preview reads after :291; destination restore producers/cleanup. No source-wide absence claim follows.
- Unclosed: backup claim/replica/retention/store adapters, dump validation, artifact upload/coordinator/trust/restore. External/admin deletion, backend lifecycle/WORM, rowless retained inventory and delayed effects need qualification; no KMS policy changes.
- Freeze requires complete source DOX/caller matrix, resolved lock inversions, reducer-owned records/indexes/enrollment, exact fixtures and root's resource envelope. This sheet narrows BS2/RR2/RR3; it closes neither those gates nor Full recovery.

## Source hash and read register

Continuation: [restore, replica and retention tails](composable-restore-replica-retention-tails.md)
narrows BP07/BP08 with distinct empty-target/selected-copy authority, partial-result
ordering, replica verification and recovery-index deletion obligations. Its source
receipt is separate; this link does not broaden the original inspected ranges or
retroactively extend their review verdict. Remaining gates above stay open.

The [Drive deletion/reference continuation](composable-drive-deletion-reference-tails.md)
narrows BP01 through trash, purge, hard destroy, prune and age-sweep bodies plus
selected FK/trigger effects. Candidate inversions, cross-file retention failures
and six proposed schedules remain source-backed planning, not executed closure.

SHA-256 fingerprints whole file bytes; the range column alone states inspection coverage. A hash is not a full-read, deployed-schema or runtime receipt. Caller-match rows contain only returned search lines. Dates/hashes bind this authoring snapshot; later parent-only index links require a separate integration receipt.

| File | Read range (1-based, inclusive) | SHA-256 |
|---|---|---|
| `AGENTS.md` | full 1–311 | `7ff01755f4fda49eaa0f1b1a6f442a05e3355802d3e1aae9a0315c041985f329` |
| `docs/AGENTS.md` | full 1–252 | `2767f16c6b87ca244d5a28a29a9b4a572ec2424be2dbc8788126afb463c64919` |
| `docs/designs/composable-backup-data-inventory.md` | full 1–290 | `2988efda3c77bd71e5ae26f24647c36b4d2ef892346b7e242f8746226fa42fe6` |
| `docs/designs/composable-backup-snapshot-contract.md` | full 1–153 | `d082522ad2f42acaa7f3507e441b339d39c5f2f7243cc8cc06b4f7cc7f13a5c9` |
| `docs/designs/composable-recovery-records.md` | full 1–245 | `15e00fdfb04efe2d2d45900b1cddd95df1ecfb490a1ffd2a73807fa8fa559cc8` |
| `retired-docs:superpowers/plans/2026-09-06-composable-contract-freeze.md` | 218–250; heading matches only elsewhere | `e6143bc1847587c017a7df8def4070e272302d1e15bfcf9f4388a458e45821ee` |
| `retired-docs:superpowers/plans/2026-09-06-app-data-backup-lifecycle.md` | 1–154; heading matches elsewhere | `8c4e0fad03cc06710a0bb2265377a6e7b39d7f55c08b7aa9dcdb0778c1bbace0` |
| `mailserver/internal/drive/worker.go` | 1–90, 130–175, 177–414, 479–496 | `52cf26be3866dfcaf5195eb688e76f11ae039ed14e986582231bac79de82767b` |
| `mailserver/internal/drive/chunks.go` | 1–78, 181–396 | `29344aa56ac1ac0f0089151bc1e02db3c43b0d4ffca9ab76a39823adae273004` |
| `mailserver/internal/drive/preview.go` | 1–260, 262–291 | `3be2750d208f24f58e6ef0091900e93932f07399900726973579d327c35a0483` |
| `mailserver/sql/reducers/drive_chunk_register.sql` | full 1–137 | `e10199ed50e0a21ecfa136febcc873bec6a4447e2fb930c01fe8be81297dac0c` |
| `mailserver/sql/reducers/drive_preview_attach.sql` | full 1–89 | `54451ba5fdbb90aa57448f4f1cf1f4fd3409cbedf5a0179cffeef2c4d791a73c` |
| `mailserver/sql/reducers/drive_maintenance_sweep.sql` | full 1–90 | `589a22cc6da2b90f2ed0de6f28261c968a2dfaab8e8f99c3de842ac7e4935805` |
| `mailserver/sql/dbschema/V114__drive_core.sql` | 115–147, 414–445 | `d771694ed844dfa6cbdcd087f4c7d3b5bfaecb5a1e75dcdd835be2f639a8daec` |
| `mailserver/internal/backup/engine.go` | 138–391, 494–575 | `3e950f58b410f498006e79d4c9a59ddc74692ccd7d1fe52e66341498c89f0c80` |
| `mailctl/backup_recovery.go` | 72–97, 190–274, 435–644 | `a70f9d85bd8f933d1c1546586ed34453bc4b8fa01f719d29d2ffc97194e71ff5` |
| `mailserver/internal/office/handler.go` | matches 237, 245, 248 only | `b4b0a914e569f240e2971f817d71458b6f22093f2723f95dbeb9b88587292429` |
| `mailserver/internal/meet/worker_recordings.go` | matches 369, 380 only | `25e3ebb492b71fc6dc60fd39e46ddc5e9748252bf38b4a6ca47f1f39ca57332e` |
| `mailserver/internal/drive/worker_gc_race_live_test.go` | full 1–122 | `a8b57f5c09cb8e2b7353034b8de82c0697f8c9f292a555395ebaf01211b99580` |
| `mailserver/internal/drive/worker_live_test.go` | 126–223; test-name match 39 | `b0b9762b61f673530f25b66c65e84eddc1ec871bf9fab922e7c1be31fd4acfee` |
| `mailserver/internal/backup/manifest_emit_test.go` | 253–272; test-name matches elsewhere | `517f7d2e3fd7181ec66379358c7dc243fb7d992a4edc35a5016ffb4be7aec238` |
