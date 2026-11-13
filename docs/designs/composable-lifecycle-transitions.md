# Composable lifecycle transitions — first contract packet

Date: 2026-09-06
Status: draft, source-inspected Office/Drive/backup subset; NOT frozen or implemented.
Owner: CP0.3 with Office, Drive, D5 and backup domain owners.
Authority: CP0 plan.
Sources: inventory.

## Interface and ownership

Retain the existing managed-app control module and shared recovery module. Their
interfaces should hide execution/receipt mechanics, not move business authorization
out of reducers. A generic public lifecycle interface is not justified by the one
installed CODE adapter. Paper references and additional callers must justify its
eventual shape. No public endpoint or error-code allocation is created here.

Keep release approval, admission, runtime observation, operation progress and data
disposition separate. An installed runtime is not an activated provider; healthy
transport is not current permission; stopped execution is not deleted data.

## Current interfaces inspected

| Interface | Input and authoritative result | Refusal / evidence limit |
|---|---|---|
| office_app_operation_request | Auth-derived actor, install kind, provider and expected generation, UUID idempotency key, bounded request and reason; reducer returns operationId/state/stateGeneration/phase/replayed | BZ323 permission; BZ322 shape; BZ324 provider state; BZ326 changed replay; BZ327 disabled/installed/busy. Only install admitted |
| appmarket.ControlPlane | Claim, Heartbeat, Advance, CommitInstall; operation generation/executor/lease identify execution ownership | Worker interface is not a public app-management contract; no work is nil, not failure |
| office_provider_accepts_new_launch | Provider/platform/family/classification checked against current qualification, health, scope and admission | Draining provider cannot admit new sessions |
| office_wopi_callback_allowed | Launch/token hash/capability checked against current fence, expiry, ACL, session and provider | SQL allows draining; gateway global OFF still rejects all callbacks |
| office_save_accept | Launch/token, operation key, base, hash/size/type/manifest/lock; authoritative Drive version/branch and replay result | BZ321 unavailable, BZ322 invalid, BZ323 authority, BZ324 stale session, BZ325 lock, BZ326 changed bytes. Existing authorization precedes replay |
| office_launch_revoke | Auth-derived actor, file and launch; increments fence, revokes launch, removes session lock and records audit | BZ321 masks unavailable/unauthorized launch; revocation is not planned drain |
| recovery coordinator | Existing artifact verification and manifest-last commit | Does not establish selected-app restore, Drive chunk-byte closure or safe activation |

Error codes above describe inspected reducers, not a new universal taxonomy or a
complete HTTP mapping. Preserve owning protocol mappings; transport shape review
remains a separate CP0 error packet.

## Proposed transitions and independent oracles

All rows below are requirements, not descriptions of already implemented behavior.
Lock order and numeric deadlines are intentionally open implementation-review gates.

| ID / command | Guard and committed facts | Executor / UI outcome | Recovery and oracle |
|---|---|---|---|
| LC01 Propose update | Bind immutable candidate, current release/config/grant revisions; wider permissions remain awaiting approval | Old approved release keeps its existing authority; candidate gets no route | Retry looks up operation; reject changed input. CP-T04 |
| LC02 Stage candidate | Approved exact inputs and current operation lease; no admission switch yet | Stage/probe only owned runtime resources; report installed versus qualified separately | Lost response reads receipt; failed probe leaves old admission unchanged. CP-T03/07 |
| LC03 Begin planned drain | Compare authoritative provider/session revisions; close new admission, persist accepted-session set and drain deadline | Existing permitted sessions may save against pinned qualified runtime/config; show count and deadline | Restart reconstructs obligations; new launch denied and late/stale save denied. CP-T05 |
| LC04 Save during drain | Recheck token/fence/ACL/lock and content identity in authoritative save transaction | Commit Drive version or conflict branch and receipt; do not clear draining intent | Response loss must not duplicate versions. Distinguish receipt recovery from authorization to write again. CP-T05/08 |
| LC05 Finish drain | All accepted obligations terminal; deadline with unresolved work instead enters postponed/blocked | Retire old runtime only after safe completion; timeout never automatically kills editors | Crash resumes receipt-led observation; explicit force-end requires owning policy's fresh permission, step-up, preview and audit. CP-T05/07 |
| LC06 Security revoke | Current authorization revokes immediately, including while draining | Fence callbacks; no final-save exception with revoked credentials | Any maintenance needs separate narrowly authorized identity; cannot revive old token. CP-T06 |
| LC07 Uninstall, keep data | Authorized exact preview; admission closed, approved dependent disposition and accepted-work disposition completed; route-revocation reconciliation confirmed | Only then stop/remove owned runtime; retain data by default with inspect/export access under current policy | Unknown route reconciliation remains pending; repeat exact cleanup safely, foreign resources untouched. AB-T06/09 |
| LC08 Uninstall, delete app data | Same LC07 lifecycle prerequisites and operation owner; additionally explicit delete selection and fresh scope/ownership/hold revisions, each mutation rechecks eligibility | Data-disposition branch of the same operation, not independent deletion; separate deleted-now, retained, untouched, pending reclamation and partial outcomes | Unknown lifecycle reconciliation blocks progression; new hold blocks affected deletion, backups/shared bytes retain independent owners. AB-T05/06/09 |
| LC09 Capture selected/full backup | Resolve restorable dependency closure and consistent metadata plus referenced bytes before commit | Show requested/effective scope and exclusions; commit recovery point last | Missing/corrupt Drive chunk prevents complete recovery claim. AB-T02/04/10 |
| LC10 Restore inactive copy | Verify coverage, remap identities, current restore authority and key availability | Isolated copy with outbound work authoritatively suppressed; inspect before activation | Restart must remain inactive; identity collision fails closed, never overwrites live state. AB-T07/09 |
| LC11 Activate restored app | Fresh authorization, compatibility, secrets/endpoints and dependency checks | Explicit activation distinct from successful restore; publish only authorized copy | Lost activation response resolves receipt; no duplicate outbound effects. AB-T07/09 |

## Source conflicts to resolve, not abstract away

1. office_save_accept currently returns session status to active after saving.
   Preserve planned drain intent separately or preserve its authoritative state;
   choose the concrete representation with the domain owner before schema freeze.
2. Session provider ID/base version does not establish pinning of qualified runtime,
   configuration and proof-key material. Specify immutable binding and key rotation
   semantics; a callback must not silently move to the candidate's configuration.
3. Global feature OFF is currently immediate callback denial. Do not reuse that
   switch as the ordinary drain command or weaken emergency revocation to save work.
4. Install request replay passes current state checks before receipt lookup. Specify
   a safe authorized operation-observation path for response-loss reconciliation;
   do not promise unlimited replay after completion or bypass current permission.
5. Backup engine and pre-upgrade snapshot inventory referenced blobs, whereas Drive
   has separate chunk objects. Define snapshot/GC protection through backup completion
   so a captured reference cannot disappear before bytes are copied and verified.
6. Legacy backup worker state uses direct SQL CAS. Do not describe it as already
   reducer-authoritative; any ownership migration needs a separately reviewed task.

Managed Dependency §25.4 already confirms default Office postponement on timeout.
Standalone lifecycle must preserve the no-automatic-kill rule; an ordinary timeout
is not a new destructive authorization. The owning updater's conditional compatible
Office deferral remains distinct from completing an Office update.

On postponement, release only this operation's temporary admission blocker after
durable reconciliation/audit, then recompute current qualification, health, scope
and permission. Never restore a captured grant, feature flag, provider choice or
security generation. A still-eligible old route may resume admission; an independently
revoked/unhealthy/changed route remains denied and an inactive route stays inactive.
Compatible deferral must be an already approved conditional branch, not a new worker
fallback. A later Office-only retry needs fresh approval.

## Resume / freeze gates

| Remaining packet | Required completion before implementation |
|---|---|
| LC-P1 Office identity | Exact session/runtime/config/proof binding, migration and lock order; qualification and security-rotation races |
| LC-P2 Timing | Numeric domain-specific drain/save/lease budgets, measurement basis, renewal rules and explicit deadline failure outcomes |
| LC-P3 Receipt recovery | Authenticated observation, idempotency scope/retention and response-loss mapping for every command |
| LC-P4 Backup closure | Actual Drive object enumeration, consistency/GC protection, independent restore and key-dependency oracle |
| LC-P5 Data deletion/clone | Exact ownership/remapping schema, retention/hold races, resumable mutation and outbound suppression |
| LC-P6 Other domains | Mail approval, Chat/Meet, native resources and updater transitions; no whole-project completion from this subset |

Existing tests to inspect/reuse, not a passing receipt: TestRunnerInstallLifecycle,
TestWOPIVerticalSaveToDriveHistory, TestDockerRollbackForeignResourceMakesZeroDeletes,
TestDockerRollbackReinspectsEveryExactResourceBeforeDelete and
TestWriteManifests_CommitPointNotWrittenOnFailure. Bind proposed cases in their
existing domain test files; no second test framework.

No new product decision is needed to write these packets. A proposed new privilege,
data-loss policy or timeout that forces destructive completion requires explicit
review, not an assumed default. Current plan status remains HOLD for implementation.
