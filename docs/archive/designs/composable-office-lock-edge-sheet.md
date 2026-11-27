# Office / Drive acquisition-edge sheet — OS-T07

Date: 2026-09-07. Status: source-grounded planning draft; graph closure incomplete.
Owner: Office + Drive + CP0; D5/updater consumes the resulting admission contract.
Authority: [Office session contract](composable-office-session-contract.md) and
CP0 freeze slice.

This sheet advances OS2/OS-T07, not implementation or a whole-plan 10/10 verdict.
Observed statement order is not a reproduced deadlock. No concurrency test ran.
Keep the existing reducers authoritative; do not introduce a gateway-only lock,
second Office version store, universal plugin mutex, or second updater coordinator.

## Reading convention and transaction boundary

`A → B` records acquisition/call order in the inspected path. A plain SELECT is
not FOR UPDATE. Updating an already-held row is reentry, not a new reverse edge.
INSERT/UPDATE/DELETE, foreign keys, unique indexes and triggers can add locks;
absence of an explicit locking clause is not absence of a lock.

The inspected Drive launch/revoke handlers in
[office.go](../../mailserver/internal/drive/office.go) use
[RunUserScoped](../../shared/dbscope/dbscope.go), whose transaction begins before
the reducer and commits after the callback. Admin handlers in
[admin_office.go](../../mailserver/internal/admin/admin_office.go) issue reducer
queries; qualification probing precedes its committing reducer call. These facts
do not close WOPI upload/staging/proof or all caller I/O spans. Transaction-scoped
advisory locks below last through the enclosing transaction, not just the helper.

## Current acquisition map

| ID / source | Observed path; scope and exceptions |
|---|---|
| OE01 [launch](../../mailserver/sql/reducers/office_launch_begin.sql) | ACL-mode generation row `FOR SHARE` through mutation guard → transaction advisory `hashtextextended('office-session:' + file + ':' + provider + ':' + cohort,0)` → matching session `FOR UPDATE` or INSERT → launch INSERT → per-space audit advisory → space-row UPDATE through notification. Provider eligibility is a read, not the proposed admission barrier. |
| OE02 [save](../../mailserver/sql/reducers/office_save_accept.sql) | Launch `FOR UPDATE` → session `FOR UPDATE` → live callback check → plain receipt/WOPI reads → existing-session UPDATE → **`drive_file_put_version`** → receipt INSERT → session reentry → audit. Exact receipt replay returns before the Drive call; it is a separate branch. |
| OE03 [WOPI lock](../../mailserver/sql/reducers/office_wopi_lock_apply.sql) | Launch `FOR UPDATE` → session `FOR UPDATE` → callback check → WOPI row `FOR UPDATE` → operation-specific writes. UNLOCK_AND_RELOCK's later session UPDATE is reentry. Missing/expired-row insert and unique conflicts still need graph coverage. |
| OE04 [Drive version](../../mailserver/sql/reducers/drive_file_put_version.sql) | ACL generation SHARE → branch ref or main file `FOR UPDATE` → matching other-user Drive lock `FOR UPDATE` → quota space UPDATE → version/chunk-link writes → optional conflict branch/audit/fan-out → optional retention and claim cleanup → audit → space notification reentry. Existing-version replay returns before quota and new-version writes. |
| OE05 [configure](../../mailserver/sql/reducers/office_provider_configure.sql) / [activate](../../mailserver/sql/reducers/office_provider_activate.sql) | Provider `FOR UPDATE` precedes configuration writes; activate additionally locks qualification `FOR UPDATE`. These are current row locks, not an immutable runtime-binding implementation. |
| OE06 [remove](../../mailserver/sql/reducers/office_provider_remove.sql) | Provider `FOR UPDATE` → matching sessions UPDATE → matching launches UPDATE → WOPI DELETE → provider reentry. Bulk row order is not explicitly canonicalized. |
| OE07 [revoke launch](../../mailserver/sql/reducers/office_launch_revoke.sql) / [finish cohort](../../mailserver/sql/reducers/office_cohort_finish.sql) | Revoke: launch `FOR UPDATE` → session UPDATE → WOPI DELETE → audit → space notification. Finish: session `FOR UPDATE` → plain actor-launch existence check → session reentry → WOPI DELETE → audit → notification. A plain actor lookup is not a launch-row lock. |
| OE08 [qualify](../../mailserver/sql/reducers/office_provider_qualify.sql) | Provider `FOR UPDATE` → managed app revision `FOR UPDATE` where applicable → qualification upsert → provider/revision writes → health/audit. Include FK/index effects before claiming a total order. |
| OE09 [app request](../../mailserver/sql/reducers/office_app_operation_request.sql) / [install commit](../../mailserver/sql/reducers/office_app_install_commit.sql) | Request locks provider before operation INSERT. Commit locks operation first, then its new-revision branch takes the `office_app_revisions:collabora-code` advisory and inserts a provider-referencing revision. No inferred runtime drain protocol; D5's proposed receipt handoff remains separate. |

The retired [policy-set shim](../../mailserver/sql/reducers/office_provider_policy_set.sql)
raises BZ324; do not count it as a live configuration writer.

The [ACL guard](../../mailserver/sql/reducers/drive_acl_mutation_guard.sql) takes
generation SHARE only in ACL mode, before capability evaluation; it does not take
the tree advisory itself. [Audit](../../mailserver/sql/reducers/drive_access_audit.sql)
takes `pg_advisory_xact_lock(hashtext('drive_audit_' || space_id))` before insertion.
[Notification](../../mailserver/sql/reducers/drive_notify_change.sql) UPDATEs the
space sequence. These helpers are part of the transaction, not harmless logging.

## Candidate inversions and required design disposition

| Candidate | Source-supported concern | Required disposition, not an implemented fix |
|---|---|---|
| OE-R1 remove / callback | Remove can hold a session while acquiring its launch; save/WOPI/revoke can hold the launch while acquiring its session. | Cover every participating entrypoint with a compatible admission boundary **before** lower locks; canonicalize bulk acquisition and recheck identity/authority after any preliminary lookup. Demonstrate the cycle is removed, rather than relying on retry. |
| OE-R2 launch / version save | Launch acquires per-space audit then space UPDATE; a new version save acquires quota space UPDATE then audit. Different files/sessions in the same space can participate. | Resolve the shared Drive audit/state order with its owning writers and triggers. A provider-shared admission barrier does **not** serialize two ordinary operations and cannot by itself fix this candidate. Preserve atomic quota, audit-chain and notification semantics. |
| OE-R3 ACL / Office | Launch's ACL SHARE precedes cohort/session, while save reaches it after launch/session. | Trace exclusive generation/tree/revoke writers and their downstream locks. Two SHARE holders alone are not a deadlock. Do not move authorization outside the mutation transaction to simplify the diagram. |
| OE-R4 implicit/transitive tails | Chunk trigger writes, FK checks, conflict notifications and managed revision/operation edges are not captured by a provider/session-only order. | Expand the finite tails below; explicitly exclude unreachable combinations with source proof. No global-lock workaround or assertion that Office → Drive terminates the graph. |

OS2's provider shared/exclusive barrier remains **proposed**. Freeze its exact
namespace, identity resolution/recheck, callers, lock mode, timeout and ordering
only after resolving OE-R1–R4. Place it before launch's ACL acquisition if claiming
provider-first order. No SQL helper name, new permission or numeric budget is
invented here. Keep config admission, accepted callbacks, revoke and D5 drain
semantically distinct; admission closure must not strand accepted saves.

## Finite next reads before freezing the graph

1. Expand all direct `drive_file_put_version` consumers, including restore-version
   and Chat writes; trace ACL grant/revoke/inheritance/expiry/migration, member and
   governance writers. Bind branch predicates and actual lock modes, not just names.
2. Expand quota/refcount/retention bodies in
   [V114](../../mailserver/sql/dbschema/V114__drive_core.sql), replacement triggers
   in [V115](../../mailserver/sql/dbschema/V115__drive_versioning.sql), and FK/unique
   constraints in [V220](../../mailserver/sql/dbschema/V220__office_foundation.sql)
   and [V225](../../mailserver/sql/dbschema/V225__office_architecture_deepening.sql).
   Schema-load precedence and actual installed definitions must match test inputs.
3. Expand [conflict fan-out](../../mailserver/sql/reducers/drive_notify_event.sql)
   through `deliver` and its triggers. The exception wrapper does not prove no
   waiting, deadlock, or latency effect; distinguish rolled-back subtransaction
   work from successful locks retained by the outer transaction.
4. Trace WOPI Go request → proof → staged bytes → scoped reducer → response and
   cancellation/cleanup. Record network/blob I/O spans and connection/transaction
   ownership. Do not hold new locks around editor network I/O by accident.
5. Reconcile every provider/session lifecycle writer, including expiry/recovery
   and the updater pre-stop receipt participants. Search absence is not proof that
   a reducer has no consumer. Bind read scope, source digests and unresolved edges.

## Proposed OS-T07 concurrency fixtures

These IDs are additions to the owning test plan, **not existing runnable selectors**.
Before execution, name the exact runner/test path and isolated database fixture.
Use controlled two-transaction rendezvous; no timing-only sleeps or production
debug hooks. Observe lock waits/outcomes and persisted state independently.

| Case | Controlled overlap | Required oracle |
|---|---|---|
| OS-T07a | Remove holds session while save/WOPI/revoke holds matching launch; each advances toward opposite row | Pre-change characterization records whether a cycle occurs; revised order terminates within the frozen bound with no deadlock-retry loop. Accepted save or denied/fenced result must agree with commit order and durable receipt/version/audit. |
| OS-T07b | Launch reaches audit while another new save in same space reaches quota; cover same/different file and provider | Independently observe audit and space waits. Revised path preserves one valid audit chain, quota and sequence; provider barrier alone is not accepted evidence. |
| OS-T07c | Launch/save versus ACL revoke/downgrade, both commit orders, ACL and legacy modes | A revoke committed before terminal authorization prevents mutation. A previously authorized in-flight transaction follows the defined serialization; no unauthorized version or disclosure. |
| OS-T07d | Main/branch saves, hard/soft Drive locks, exact receipt replay, conflict fan-out and repeated chunks | Correct unchanged head or conflict branch, no lost bytes, one quota/refcount effect per accepted new version; replay stays distinct. Check shared-chunk and Mail tail waits. |
| OS-T07e | Multi-session remove versus qualify/configure/install completion and D5 drain/restart | No lower-lock-first bypass, stale generation acceptance, arbitrary bulk-order dependency, or stranded accepted callback. Unresolved legacy sessions continue to block updater DDL. |

All cases need cancellation, rollback and timeout variants, paired positive cases,
bounded concurrency and evidence from the same source/schema/fixtures. Numeric
termination and load limits belong to the pending joint-resource sheet; existing
lease defaults are not a measured performance budget. Do not mark this sheet frozen
until test-location/oracle bindings and the transitive graph are reviewed. Runtime
qualification follows later implementation approval; it is not required to pretend
the present source-only review ran tests.

## Evidence boundary

Root read the full nine principal Office reducer groups above, Drive version,
ACL/audit/notification helpers and the two Go Office handler files; the dbscope
transaction body was read separately. The independent source researcher additionally
read conflict fan-out/tree helpers and selected V114/V115 bodies; its ACL consumers,
other Drive callers and schema-wide constraints were targeted inventory, not closure.
Source hashes are retained in the companion input receipt. Unread tails remain
explicit tasks. No product changes, new security-finding count, runtime result,
numeric score, or full Engineering/Fable gate is claimed by this draft.
