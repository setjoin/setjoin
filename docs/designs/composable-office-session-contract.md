# Office session binding, drain and receipt contract

Date: 2026-09-06
Status: detailed proposal for LC-P1–P3; no schema/code changes or qualification claim.
Owner: Office/Drive and standalone D5; signed update execution remains updater-owned.
Parent: [lifecycle transitions](composable-lifecycle-transitions.md).

## Current source and constraints

| Source | Current fact relevant to the change |
|---|---|
| [office_launch_begin](../../mailserver/sql/reducers/office_launch_begin.sql) | Checks provider admission before the file/provider/cohort advisory lock; session stores provider ID and shares a lease with launches. Existing lease range is 60–28,800 seconds, default 28,800 |
| [session schema](../../mailserver/sql/dbschema/V220__office_foundation.sql) | Session stores base version, cohort, fence and status, but not immutable qualified runtime/config/proof binding |
| [office_provider_configure](../../mailserver/sql/reducers/office_provider_configure.sql) | Generation CAS, 64-KiB configuration limit; active/draining reconfiguration refused. This useful restriction does not itself supply an immutable session binding |
| [WOPI projection](../../mailserver/sql/reducers/office_wopi_file_query.sql) | Fetches proof discovery/public base URL from current provider configuration |
| [proof verifier](../../mailserver/internal/office/proof.go) | URL-keyed current/old public-key cache: 12 hours; discovery timeout 5 seconds; timestamp skew 20 minutes; these are existing constants, not independently qualified here |
| [save handler](../../mailserver/internal/office/handler.go) | 200-MiB body and 4-MiB chunks; explicit operation-key header or fallback derived from launch ID, projected base and content hash |
| [save reducer](../../mailserver/sql/reducers/office_save_accept.sql) | Current authority before receipt lookup; locks launch then session, delegates version mutation to Drive, then sets status active |
| [WOPI lock reducer](../../mailserver/sql/reducers/office_wopi_lock_apply.sql) | Default lock TTL 1,800 seconds; accepted 60–3,600; launch/session/WOPI-lock row locking |

This is a bounded source inspection, not a protocol conformance or concurrency test.
Changing production WOPI proof behavior requires the owning protocol references,
real-provider qualification and security review; constants are not new recommended
values simply because they exist.

## Proposed persistent binding

Create a domain-owned immutable binding record referenced by each session. This is
a proposed logical schema, not an allocated migration/table name or public DTO.

| Logical field | Proposed type / invariant |
|---|---|
| binding ID | Server UUID; immutable after creation |
| provider identity | Existing provider ID; never a request-owned substitute |
| qualified release | Content-immutable qualification evidence identity plus immutable managed app revision/digests, or explicit qualified existing-provider identity; current mutable qualification UUID alone is insufficient |
| configuration identity | Existing canonical configuration digest plus versioned configuration snapshot reference |
| endpoints | Qualified editor/discovery/public WOPI origins from that snapshot; no caller URL override |
| proof trust profile | Qualified verification mode and trust-profile revision; no raw signing/private key or bearer token |
| session relationship | Session references exactly one binding; cohort admission includes binding identity |
| security authority | Current fence/grants remain live domain facts, not immutable permissions copied into the binding |
| retention references | Binding retained while accepted sessions, required save receipts or promised recovery refer to it |

Do not mutate an old binding when staging a candidate or selecting a new default.
New sessions use the admitted binding; accepted sessions keep theirs. If a provider
cannot retain the old qualified runtime/configuration, ordinary update postpones
until its sessions finish. No seamless migration claim for that profile.

Proof trust is not “cache a public key forever.” Cache identity must include the
binding/trust revision, not just a reusable URL. Rotation acceptance comes from the
qualified verification policy for that binding; security withdrawal is checked as
current authority and may revoke previously cached keys. Do not fetch candidate
discovery to authorize an old session or retain a withdrawn key just to finish saves.
Exact key-refresh/rotation vectors remain a protocol qualification prerequisite.

## Admission and state

Represent maintenance admission intent separately from transient save progress.
Use an operation-owned admission blocker and accepted-session set; saving must not
clear that blocker when it returns a session to its ordinary active state.
UI derives “draining” from the authoritative blocker/obligations, not from a last
callback overwriting one overloaded status value.

Begin-drain transaction rechecks the expected provider/binding/policy identity,
closes new admission and records accepted sessions atomically. A launch must repeat
admission/binding checks at its serialization point, not rely on an earlier read.
Captured session membership does not capture eternal authority: every callback still
checks live token, fence, expiry, ACL, locks and the accepted binding.

Proposed serialization discipline, to audit against all direct callers:

1. Acquire a provider-scoped shared transaction barrier for launch/save/lock; acquire
   its exclusive form for admission switch, removal or security-fence transitions.
2. Acquire existing cohort advisory lock when creating/joining; then launch/session
   rows in the common Office order, followed by WOPI lock where needed.
3. Enter Drive's existing reference/lock/quota ordering only after Office authority
   has been established. No callback may acquire the provider barrier after holding
   a lower-level Office/Drive lock.
4. Hold neither network discovery nor byte upload nor runtime-stop work inside this
   barrier transaction. Stage outside; revalidate at the final short mutation.

This is a proposed ordering, not a proven deadlock-free implementation. Before
admission, enumerate configure/activate/remove/revoke, direct Drive/ACL callers and
triggers. If a reverse acquisition exists, resolve it in that same domain packet,
not by retrying deadlocks indefinitely or globally serializing all Drive traffic.
Concurrent revocation and save must have a defined commit order: revocation prevents
subsequent effects; it cannot retroactively uncommit an already accepted version.

## Timing profile and safe deadline behavior

Do not equate the eight-hour session ceiling, thirty-minute lock default, thirty-second
worker claim lease, five-second discovery timeout and maintenance deadline.

For a deterministic synthetic rehearsal, propose a **120-second drain observation
budget** with **two-second UI polling**, explicitly not a production promise.
The required timeout outcome is postponed/blocked, never forced termination.
Exercise saves completing just before the boundary and saves still unresolved at
it; neither lease renewal nor UI polling may silently extend approved maintenance.
Every run records actual elapsed time and configured profile; provider load/large-file
tests must qualify a production budget before a supported rollout.

Persist the drain deadline and operation identity server-side; restart does not reset
the clock. Session/token/lock expiry still applies independently. Postponement releases
only this operation's blocker after reconciliation and recomputes current admission.
Explicit force-end remains the existing permission/step-up/loss-warning/fresh-audit
policy. A timed-out save has unknown or failed outcome until its receipt is reconciled;
timeout does not mean bytes were never committed.

## Receipt and retry semantics

Keep authenticated observation separate from a mutating retry. An actor who loses
write permission must not regain it by replaying a key; a receipt may be disclosed
only under a specifically authorized current read projection, without content leaks.
Receipt retention follows the owning history/audit/recovery requirements; no short
generic cache eviction can erase an unresolved operation's outcome.

For an explicit stable operation key, bind receipt to provider session, canonical
accepted intent/content and result version/branch. Same key/same intent reconciles
one result; changed intent refuses. Correlation request IDs are not this key.

**No-header path needs its own contract.** Today the fallback includes the projected
base version. After a successful save advances that base, a transport retry may
calculate a different key. Do not claim this path has the same exact-once receipt
guarantee merely because the explicit-header test passes. Source inspection identifies
the changing identity basis; it is not a freshly executed duplicate-version finding.

Before freeze, qualify actual upstream behavior with and without a stable operation
identifier. A proposed bounded no-op for bytes already identical to the current
session head can prevent redundant versions in that case, but cannot distinguish all
delayed retries from intentional A→B→A edits after intervening writes. Do not silently
deduplicate by content forever or require an upstream custom header it does not send.
Unsupported exact-once cases need an explicit compatibility result and preserved
Drive conflict semantics, not a fabricated receipt. This is an engineering
qualification gate, not permission to modify the upstream editor.

## Candidate OS1/OS2 freeze-input register

OS1/OS2 is a bounded **candidate** for preparing the first freeze input, not a
selected implementation lane or acceptance of FG-CEO-01. A complete boundary must
include affected OS3 callback projections and OS4 migration/drain consumers, or
prove them unchanged. These are explicitly unsettled implementation bindings;
their honest presence in a work plan is not evidence of a contradictory safety
policy or a requirement to run future tests merely to assess planning quality.

| Binding / existing owner | Required before this candidate can freeze |
|---|---|
| Schema — OS1/Office | Allocate binding/session reference and operation-owned blocker/accepted-session records: keys, uniqueness, foreign keys/delete behavior, retention references, isolation and database roles. Logical records above are not production declarations |
| Fields — OS1/configuration/qualification | Freeze actual types, required/nullability rules, bounds, normalization, canonical bytes and authenticated source for qualification, provider identity, snapshot/digest, endpoints and trust revision; cohort equality includes binding identity. Live grants/fences are never immutable copied permission |
| Paths/generators — OS1 plus affected OS3 | Name normative production declarations and manual/generated projection owners. Record internal-only fields without inventing public OpenAPI/WIT. Bind affected SQL→Go/protocol projections and exposed unknown/version behavior |
| Callers — OS1/OS2/Drive | Close creators/joiners, binding/configuration/qualification writers, callbacks and barrier participants; classify each consumer retain/change/retire. Expiry/recovery, direct Drive/ACL/trigger and caller-I/O tails remain open in the acquisition sheet |
| Migration — OS1/LC-P1/OS4/D5/updater | Specify admitted profile, exact SQL and durable disposition fields: source-provable reconstruction or safe session completion/postponement; bind session/generation identity and updater recheck. No reconstruction from today's configuration or DDL with unresolved accepted sessions |
| Locks — OS2/OS-T07 | Freeze namespace/key resolution, shared/exclusive modes, timeout, provider-before-ACL placement and canonical bulk order. Resolve or prove unreachable OE-R1–R4, including FK/index/trigger edges; the provider barrier alone does not settle audit/space ordering |
| Resources — OS2/EN-T10/D5 | Bind selected-profile pool/backend/worker/stream inventory, reservation/helper owner, atomic admission/reconstruction and numeric wait/termination/resource bounds. Preserve accepted saves; existing TTLs and synthetic workload sizes are not capacity reservations |
| Recovery — OS1/OS2 with OS3/OS4 | Give blocker, binding retention, accepted-session set and observation/completion records exact identities/transitions; bind restart, stale generation, lost receipt, cancellation and only-owned-blocker release after reconciliation. Timeout never proves cleanup or restores authority |
| Test bindings — OS-T01–07 | Resolve foundation/handler/proof/browser families to exact paths/selectors/runners; bind isolated schema fixtures, two-transaction rendezvous, both commit orders, persisted independent outcomes and merge/release classification. OS-T07a–e remain proposed cases, not executable selectors |

The [acquisition sheet](composable-office-lock-edge-sheet.md) and
[resource envelope](composable-joint-resource-envelope.md) own their wider closure;
this register does not create another roadmap or resource coordinator. Real-provider
rotation/no-key replay, executed lock/pressure/timing tests and production capacity
remain later qualification. Their owner, protocol, location and acceptance must be
specified first; missing execution is distinct from missing specification.

### OS1 source-bound field and consumer closure

The finite creation→projection pass is recorded in the
OS1 source receipt, with
actual read ranges, hashes and instruction-coverage limits. These are observed
current shapes, not proposed production declarations or runtime qualification.

| Source field / owner | Current fact | Required design disposition |
|---|---|---|
| V220 session/cohort | UUID; non-null space/file/base/provider/cohort, nullable branch; active uniqueness is file/provider/cohort. Joining uses existing session base, not necessarily the requested base | Allocate binding relationship/retention constraints; include binding identity in cohort equality; distinguish requested and effective base |
| V220 launch identity | Gateway supplies authenticated actor and SHA-256 token hash; token-hash column permits NULL although inspected HTTP path supplies it | Freeze database requiredness explicitly, not by assuming every caller is this gateway; no bearer-token copy into binding |
| V224/V225 qualification | Generation/config/profile/status/checks/expiry required; fingerprint/build/receipt/app revision have nullable declarations. Qualification commit updates the same UUID on conflict | Preserve content-immutable evidence, not a pointer whose checked contents may change; separately specify each binding field's requiredness |
| Configuration | SHA-256 over PostgreSQL JSONB text; configure requires object and ≤65,536 serialized bytes | Version exact canonical bytes and snapshot source; do not assume cross-language canonicalization or reconstruct old settings from current config |
| Generations | Activation increments provider generation; launch eligibility matches qualification generation to provider generation minus one | Keep provider/qualification/route/app revisions distinct; migration and admission use exact relations |
| Launch/proof endpoints | Launch and callback project current provider config; callback proof cache is discovery-URL keyed | Pin accepted editor/discovery/public-WOPI settings and trust revision; change cache identity without freezing current revocation authority |
| Live file/permission state | Callback checks live expiry/fence/revocation/provider/node/capability; effective version comes from session and ACL/name from Drive | Retain live authority and Drive ownership; internal storage references are not editor authority |

Direct change seams are manual reducer JSON→Go map in Drive `officeLaunch` and
Office's private `fileProjection` decoded by `(*Handler).projection`; there is no observed generated DTO to update.
The struct currently permits missing-field zero values and ignores unknown fields;
OS1/OS3 must explicitly bind required/version behavior without inventing a public API.
CheckFileInfo/GetFile/PutFile/lock retain domain checks; PutFile keeps Drive promotion
and final reducer authority. Browser/native consumers downstream of launch HTTP
remain unread in this slice and need compatibility disposition before freeze.

The qualification writer's update-on-conflict means a UUID is **not sufficient
historical proof** for legacy-session reconstruction. OS-T01 must include a same-ID
qualification-content update after session acceptance: the old binding must not be
silently rewritten or redirected; current security withdrawal still applies. The
paired new-session fixture uses the newly admitted binding. OS-T06 covers proof
rotation separately. These are future tests, not executed findings or a schema choice.

The finite qualification producer tail is also closed in the source receipt.
Actor is authenticated; provider/generation/config hash come from the target reducer;
fingerprint/checks come from the server probe. Synthetic receipt, build digest and
route revision are caller-selected (nonpositive revision currently defaults to1).
The handler marks `wopiSave: pass` after receiving a positive receipt ID; the commit
checks receipt/provider/result class, not that receipt's exact config/generation,
app/route revision, session or observation time. Thus present receipt acceptance is
not evidence of saving against that exact probed runtime. OS1 qualification must
bind those relevant provenance facts before using evidence for immutable admission;
unknown/unprovable evidence must not be upgraded to qualified by copying its ID.

Stored `config.profile` is the qualification target's source; configure's separate
top-level profile argument does not inject it or establish equality in the inspected
bodies. Freeze one canonical profile source and explicit mismatch/default semantics
with compatibility disposition, rather than guessing from that earlier argument.
Target→network probe→commit is already split; preserve commit's generation/config
recheck. Extend planned OS-T01 with wrong-runtime/reused receipt, changed target
during probing and profile mismatch, each with an exact-runtime paired positive.
Detailed production selectors remain unallocated; no executed vulnerability claim.

Wider OS-T07 acquisition/trigger closure stays with its existing owner. New binding,
blocker, migration, resource and executable test identities remain unallocated;
this source closure does not approve FG-CEO-01, freeze or a numerical score.

## Implementation ordering and exact test obligations

| Slice | Change ownership / acceptance before proceeding |
|---|---|
| OS1 Binding model | Office schema/reducers, configuration and qualification projections; immutable binding, retained references and unsupported-old-session policy |
| OS2 Admission serialization | Enumerate all barrier callers and lock order; launch-versus-drain/configure/revoke race tests with independent transaction outcomes |
| OS3 Callback/save | Pinned projection/proof policy, live fences, state-preserving save and receipt observation; no gateway-only authorization |
| OS4 D5/updater/UI | Same operation-owned blocker and deadline; Office/D5 resolves accepted legacy sessions during updater pre-stop drain and returns its durable disposition; updater gates migration on that receipt and current recheck; restart/deferral/force-end projections, no second coordinator |
| OS5 Real-provider qualification | Two users, current/old runtime, explicit/no operation key, proof rotation, large save and timed interruption; actual Drive bytes/versions/audit |

Proposed additions to existing office_foundation.pg, Office handler/proof tests and
Office browser lanes:

- OS-T01: candidate config changes cannot redirect accepted callbacks or join an old
  cohort under a new binding; unsupported concurrent old runtime postpones.
- OS-T02: save during drain commits without reopening new admission; delayed launch
  cannot slip through an earlier eligibility read.
- OS-T03: revoke at projection/staging/commit boundaries; no unauthorized promotion;
  older still-authorized binding remains a paired positive case.
- OS-T04: exact-key response loss creates one receipt; no-header response loss and
  intervening edits are separate fixtures with honest compatibility outcomes.
- OS-T05: restart before/after deadline, before/after stop and during route
  reconciliation; no clock reset, stale-grant restoration or unknown-cleanup success.
- OS-T06: proof-key cache rotation/withdrawal, wrong binding/discovery and expiry;
  no candidate-key acceptance or indefinite revoked-key fallback.
- OS-T07: barrier ordering under concurrent direct Drive saves, ACL changes and
  provider operations; bounded termination without lost versions or deadlock loops.

The [OS-T07 acquisition sheet](composable-office-lock-edge-sheet.md) supplies a
source-grounded partial graph, two distinct inverse-order candidates and finite
next reads/tests. The provider admission barrier alone does not settle shared
Drive audit/state ordering. These are planning obligations, not executed failures
or an approved final lock order.

Current sessions without a binding are not silently backfilled from today's provider
configuration. Rehearsal may begin from a disposable baseline, but an eventual
upgrade needs either a source-provable binding reconstruction or explicit safe
session completion/postponement before migration. No installation or version reset
is performed by this document. Exact migration SQL, protocol vectors, production
budget and legacy no-key retry qualification remain implementation-review gates.

LC-P1/OS4 ordering is explicit: the updater requests domain drain while the old
business process and compatible provider can still service accepted callbacks.
Office/D5 owns session completion or source-provable binding reconstruction and
records the disposition against the update operation, session set and generations.
The updater stops the old process only after the required disposition is complete;
its migration preflight rechecks it under the same closed-admission/fence boundary.
If any unbound accepted session remains unresolved, the migration does not start.
If the old process is already unavailable, remain blocked or follow the existing
qualified recovery path; never use the new business process to migrate schema or
silently fabricate old bindings. Resume/restart cannot waive the guard.

Extend OS-T05 with old-process unavailable, lost drain receipt, a new/stale session
generation and restart just before migration: each unresolved case refuses DDL;
the source-proven completed case is its paired positive. These are proposed tests.
