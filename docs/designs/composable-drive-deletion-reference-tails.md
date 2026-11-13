# Drive deletion and reference tails

Date: 2026-09-07. Status: BP01 source continuation; authoring only. No implementation, privilege change, full-lock proof or executed test claim.

Continuation of [BP01/object participation](composable-backup-object-participation.md); its proposed BS2/RR2/RR3 byte protocol remains open. Root owns integration/ledger. Namespace `sj-plan-storage-tails-20260907`; only this document written, no resources/services/tests/Git/network actions.

## Current reducer boundaries

No COMMIT/object I/O in these bodies: effects and locks belong to the caller transaction. DELETE means metadata. Exact FK lock modes and row order remain unverified.

| ID / current source | Checks, acquisition and effects |
|---|---|
| DT01 [trash:14–32](../../mailserver/sql/reducers/drive_node_trash.sql:14) | Live root (`BZ139` if absent) → require `delete` → tree lock → root-only Chat/Meet record checks (`BZ175`) → UPDATE live closure-subtree `deleted_at` → audit → notify. Versions, refs and quota remain; root checks do not establish descendant checks. |
| DT02 [destroy:55–77](../../mailserver/sql/reducers/drive_node_destroy.sql:55) | `drive.manage`, otherwise both `delete`/`manage_acl`; require trashed root (`BZ141`) → tree lock → purge helper → audit → notify. Helper :33–46 marks subtree `purged_at/purged_by` without repeating authority. Content remains; [V117:15–21](../../mailserver/sql/dbschema/V117__drive_qol.sql:15) adds markers, not copied data. |
| DT03 [hard destroy:45–107](../../mailserver/sql/reducers/drive_node_destroy_hard.sql:45) | Purged root → tree lock → skip children, own retained GxP versions or recording ref. Sum bytes → DELETE Chat attachments/locks → NULL branch IDs → DELETE branches → NULL incoming cross-file merge links/Main head → DELETE export grants/versions → quota decrement → DELETE node. Named skips return false; SQL errors propagate. Grace age is **caller-only**. Header :2–7's worker-routing convention is not an EXECUTE-grant proof. |
| DT04 [prune:21–55](../../mailserver/sql/reducers/drive_version_prune.sql:21) | Missing/GxP returns 0. Rank newest IDs/file; beyond `p_keep` exclude branch-line, Main/branch-head/fork, merge, lock, Chat/Meet refs. Aggregate IDs/bytes → DELETE → actual row count → quota debit using earlier sum. No explicit tree/advisory/row-lock clause or `p_keep` validation in body. |
| DT05 [age sweep:23–49](../../mailserver/sql/reducers/drive_sweep_age_trash.sql:23) | Tier-1 older than 30d UPDATE → per-row notify; tier-2 older than 30d → repeated childless hard-destroy passes until no progress. No ORDER BY, batch cap, exception handler or inter-pass commit. False is a skip; exception is not. [maintenance:78](../../mailserver/sql/reducers/drive_maintenance_sweep.sql:78) supplies the broader transaction. |

## Reference and lock effects reached

- [V114:89–137](../../mailserver/sql/dbschema/V114__drive_core.sql:89): version DELETE cascades content **and preview** refs; [triggers:423–443](../../mailserver/sql/dbschema/V114__drive_core.sql:423) decrement exact `(scope_key,sha256)` and enqueue zero counts. BP02/BP03 later remove bytes; a surviving shared ref keeps its count positive.
- [V114:56–110,159–165](../../mailserver/sql/dbschema/V114__drive_core.sql:56), [V115:14–74](../../mailserver/sql/dbschema/V115__drive_versioning.sql:14): node/file/version/label/watch/folder-admin cascades coexist with parent/Main/branch/fork/lock/merge FKs needing unwind. Version parent/conflict edges SET NULL. [Quota:228–236](../../mailserver/sql/dbschema/V114__drive_core.sql:228) UPDATEs logical version bytes, clamped at zero, not physical dedup bytes.
- [V184:20–116](../../mailserver/sql/dbschema/V184__drive_node_acl_foundation.sql:20): node deletion cascades ACL grants/breaks/closure edges and nulls invalidation anchors. Capture must preserve its historical authority graph independently; later FK additions remain unclosed.
- [V114:493–494](../../mailserver/sql/dbschema/V114__drive_core.sql:493) binds WORM; [V115:115–145](../../mailserver/sql/dbschema/V115__drive_versioning.sql:115) also guards merge links. Hard destroy :90–92 can raise `BZ145` on a retained referencing version despite its own retention precheck. Possible source-backed failure, not reproduced incidence: verify whole-transaction rollback, not false/skip.
- [Tree:4–10](../../mailserver/sql/reducers/drive_tree_lock.sql:4): exclusive transaction advisory `hashtextextended('setjoin:drive-tree:'||space,0)`. [Closure:3–11](../../mailserver/sql/reducers/drive_closure_subtree.sql:3) depth/ID output order does not prove UPDATE lock order. [Audit:41–53](../../mailserver/sql/reducers/drive_access_audit.sql:41) takes `hashtext('drive_audit_'||space)` then inserts; [notify:14–21](../../mailserver/sql/reducers/drive_notify_change.sql:14) UPDATEs space, journals, calls `app_notify`.

Visible edges: trash/destroy **tree → nodes → audit → space**; hard destroy **tree → refs/versions/chunks → quota space → node DELETE**; prune **versions/refs/chunks → quota space**. Age sweep first acquires **nodes → notify space**, then hard-destroy tree locks. Tree/node and tree/space inversions are candidates, not deadlock proof. Multi-space/pass locks persist; sorted acquisition is not established.

Trash/destroy capability checks precede tree locks; [require:561–580](../../mailserver/sql/reducers/drive_effective_access.sql:561) delegates runtime resolution and emits `BZ140`/`BZ139`. Post-lock reauthorization, nested locks, helper EXECUTE and caller isolation remain unverified. Authority stays in reducers.

## Proposed backup acceptance cases

DT-T cases are proposed, not existing/passed tests. Bind Drive/backup fixtures at caller/schema freeze. Preserve byte lock-through-I/O until replacement qualification.

| Case | Positive/negative and crash oracle |
|---|---|
| DT-T01 Tiers | Trash/destroy changes markers, not version/preview refs or quota; captured tier stays exact. Untrashed destroy refuses. Rollback preserves markers/audit/journal. |
| DT-T02 Sharing | After S/pins, hard-delete/prune last live ref: counts/queue change but S's content/preview reconstruct. Unselected shared-`g` file survives without metadata export. Partial pins cannot succeed. |
| DT-T03 Unwind | Check branch/lock/label/export and both merge-deletion orders, FK graph/quota/counts. Own retained GxP/recording skips. Inject retained cross-file unlink/cascade failure: whole sweep rolls back. Unconstructible admitted edge is unsupported evidence, not pass. |
| DT-T04 Age | Before/after both 30d boundaries, parent/child and retained no-progress cases: allowed cleanup and blocked survival. Mid-pass crash rolls back; post-commit GC work stays reconcilable. Test direct hard-destroy caller authority; no assumed grace check. |
| DT-T05 Prune drift | Race candidate scan with new branch/lock/ref and deletion: preserve dependencies or atomically refuse; actual rows/bytes/counts agree, no debit for undeleted candidates. Characterize null/zero/negative `p_keep`; freeze allowed inputs before scheduling. |
| DT-T06 Ordering | Race age node/space locks against tree-first paths across spaces/reversed keys. Trace locks and permitted progress; timeout is not proof. Restart preserves proposed barrier/pins; no stale-worker or expiry release. |

Existing source, not runs: [trash tiers:37–100](../../mailserver/sql/tests/drive_trash_tiers.pg:37) covers purge/visibility/admin restore; [versioning:21–95](../../mailserver/sql/tests/drive_node_destroy_versioning.pg:21) covers unwind/merge orders/own-GxP skip. Neither establishes pin/backend/crash evidence.

## Residuals and documentary precedence

The previously uninspected [Chat caller:192](../../mailserver/sql/reducers/chat_purge_expired.sql:192) now has a separate [Chat purge continuation](composable-chat-drive-purge-boundary.md): immediate attachment reclamation, rollback/budget boundaries and six proposed cases. This does not expand the historical read register or verdict below. Omitted: remaining Go/admin callers, restore/move, other direct writes, later Chat/Office/approval constraints, auth internals, audit/notify tails, deployed schema/roles and storage/backup adapters. BP01/lock closure remains open; no new authority/retention choice.

Historical [README:532/536](../../mailserver/sql/reducers/README.md:532) describes old destroy effects/wrong prune parameter; use current bodies. Spec §3.5 distinguishes P6 marking. Parent edits are outside ownership.

## Hash/read register

Hashes cover whole bytes; inclusive ranges state reads. `R/` = `mailserver/sql/reducers/`, `S/` = `mailserver/sql/dbschema/`, `T/` = `mailserver/sql/tests/`. Reused session reads were hash-checked. Source DOX is sampled, not full; full owning instructions remain a freeze gate. Graphify returned 34/78 nodes; not coverage proof.

| File | Read lines | SHA-256 |
|---|---|---|
| `AGENTS.md` | full 1–311, reused | `7ff01755f4fda49eaa0f1b1a6f442a05e3355802d3e1aae9a0315c041985f329` |
| `docs/AGENTS.md` | full 1–252, reused | `2767f16c6b87ca244d5a28a29a9b4a572ec2424be2dbc8788126afb463c64919` |
| `mailserver/AGENTS.md` | 1–24, 890–947; heading matches | `28283ad1593f5bad385c8ac39cced4482689caffa35c8b20e6c73c2f3a508f70` |
| `mailserver/sql/AGENTS.md` | 1–98, 537–592; heading/matching lines | `e58eff6c923ed65fdffe299f5accf660afbf1daa8d8dbb07addbb0173f4c6801` |
| `docs/designs/composable-backup-object-participation.md` | full 1–101 | `9bcbe400d826b505969181b58147ccf8b782204671f126c4afc22c7fdeab65ca` |
| `retired-docs:superpowers/specs/2026-07-09-drive-v1-spec.md` | 509–552 | `e66138e5e7d63ea32e56367c117ea30f1588f95ebc040ace6e43181212b5bd95` |
| `R/drive_node_trash.sql` | full 1–34 | `37ecf5f2fa7e123d342159745b85804defa3b7ed288a5b81b406d47c8ac0a6b9` |
| `R/drive_node_destroy.sql` | full 1–79 | `fb9d8a17810a3166691fcae21fbef33f517fa353bca22dee12748e11a036ec8b` |
| `R/drive_node_destroy_hard.sql` | full 1–109 | `3e8ed063d3bcee79992ed0a2ca7b402ac5fa6828b531619124ccefe1f3023892` |
| `R/drive_version_prune.sql` | full 1–57 | `1fe79b56dcbb218cfd50fcb95b7bda816905b89087bec824cdd4fd802a424465` |
| `R/drive_sweep_age_trash.sql` | full 1–51 | `c7843743b750b7885e4e4f88b805207eda20bf8a81f2f3f52226b80388caa2f8` |
| `R/drive_tree_lock.sql` | full 1–11 | `cd2adf148aba030627d32e039badaaa1bab3c16731fbca48a2a010d10c478cda` |
| `R/drive_closure_subtree.sql` | full 1–12 | `6ddfa88e5daab1ab4f03bfe3bcc033cd265cf4b985dfa32af3000fc6a5407aeb` |
| `R/drive_effective_access.sql` | 540–610 | `626c550531c25cdf5825d0e323602dc3c5fc9b845c048944b8d7bd371c0b69d4` |
| `R/drive_notify_change.sql` | full 1–25 | `eb2c5ccb8dd9a81375b78ee234db56e5dd0ca7f4525e8cfb00f0b0e43c152b28` |
| `R/drive_access_audit.sql` | full 1–97 | `38f1551ec6669d983027044cd557a610d35fe2d1ef0bf369d13f25fa6a9f84d8` |
| `R/drive_maintenance_sweep.sql` | full 1–90, reused; fresh matches 14,76,78 | `589a22cc6da2b90f2ed0de6f28261c968a2dfaab8e8f99c3de842ac7e4935805` |
| `R/chat_purge_expired.sql` | match 192 only | `19398e5696e6bbe390bba8c95810160c964c4e049fdf2e15a59c2e0f4c14b250` |
| `R/README.md` | matches 532,536,537,576 only | `37078ce2b00aa0c1aa5c5a806b669d4d31ec6fac24f7550a8068e535768e09fd` |
| `S/V114__drive_core.sql` | 56–173, 225–249, 409–509 | `d771694ed844dfa6cbdcd087f4c7d3b5bfaecb5a1e75dcdd835be2f639a8daec` |
| `S/V115__drive_versioning.sql` | 14–74, 110–146; declaration matches | `803503aaf8d95ecd6f97d8a953347625f07e5594299f47056fbe6f1a89619cf6` |
| `S/V117__drive_qol.sql` | 1–22; declaration matches | `c150138a86b9357ebd19f4a7b9cb72950c041a1105b9e8ef69da24d0e5bd3403` |
| `S/V184__drive_node_acl_foundation.sql` | 20–124; declaration matches | `894c86854d3da6adfce1c99c7b0f64eb1577afd8529e1cc25ca2c31d6b77a7b8` |
| `T/drive_trash_tiers.pg` | full 1–103 | `6ab944227193ec74d755c28a7e24e244f311b653af5c871fc87ffe47270854ec` |
| `T/drive_node_destroy_versioning.pg` | full 1–98 | `316a49d6f4cbe8fc9a79eda61d9d8620e260f6f815a27f93ffa8ab1ab2c98c38` |
