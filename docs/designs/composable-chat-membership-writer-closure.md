# Membership writer closure: finite inventory and caller contracts

Date: 2026-09-07. Documentation-only continuation of the
[hold/writer contract](composable-chat-hold-writer-serialization.md). No implementation,
runtime concurrency result or complete security coverage is claimed.

## Fixed direct-write inventory

The source-bound inventory
records 20 direct-write matches in 11 reducer files: 12 INSERT, five UPDATE and
three DELETE sites. It searches rg-visible SQL/Go across the repository with explicit
exclusions. Counts describe the literal search, not all possible database mutations.
Quoted identifiers, dynamic SQL, generated/runtime SQL, cascades, triggers on other
tables, omitted languages and deployment-specific grants need separate closure.
An unchanged hash permits reuse of a prior read, not an upgrade from sampled to full
review. No owner may mark a row done merely because the search matched it.

| Slice | Fixed files/sites | Current review boundary and next proof |
|---|---|---|
| MW01 Ordinary Chat | `chat_channel.sql`: INSERT90/131/377/468, DELETE565, UPDATE595/620; `chat_read.sql`: UPDATE53 | Ordinary-add and sampled create/join/DM/remove were mapped previously. Complete outer guest helpers, role promotion, read/notif mutations and trigger effects before closing. |
| MW02 Defaults/provisioning | `chat_org_defaults.sql`: INSERT63/109 | Both default reducers and the complete `provision_account` body are mapped. Outer invite/directory/SCIM callers and multi-channel/target lock qualification remain open. |
| MW03 Guest lifecycle | `guest_account.sql`: DELETE395, INSERT699, UPDATE702; `guest_profile.sql`: UPDATE394 | Transfer, profile set/apply and bounded HTTP wrappers mapped below. Expiry/provisioning outer callers and authority-fence composition remain qualification obligations. |
| MW04 Meet bridge | `meeting_join.sql`: INSERT110; `meeting_lobby.sql`: INSERT361; `meeting_control.sql`: DELETE291 | Join/admit/kick bodies and bounded HTTP wrappers read here; projected ordering below. Transitive grant/authority/media-fence/notification helpers and loaded trigger graph remain open. |
| MW05 Federation | `federation_dm_ensure.sql`: INSERT97; `federation_apply_chat.sql`: INSERT276; `federation_apply_room.sql`: INSERT591 | Complete reducer/receiver reads and bounded stream/service context. Two concrete dispatch/poison defects have repair plans below; loaded-state and directly implicated effect tails remain qualification work. |

Implementation-review completion requires each row's initiating transaction,
authenticated authority, affected columns, FK/trigger effects, lock ordering and
independent test oracle. Freeze all five rows plus an **indirect-write appendix**
covering cascades, alternate SQL spellings/dynamic statements, migrations and
effective grants. Re-run the recorded search against implementation inputs; any
added/changed/unclassified site reopens its row. This is a finite closure checklist,
not a proposal for a new general plugin-write framework.

## Meet ordering and boundaries to preserve

- [meeting_join](../../mailserver/sql/reducers/meeting_join.sql:28): authenticated
  guests first call `guest_require_grantable`; participant UPSERT precedes the
  provisioned Chat channel row lock and membership INSERT. The hold AFTER INSERT
  trigger therefore runs after those outer writes/locks.
- [meeting_admit](../../mailserver/sql/reducers/meeting_lobby.sql:276): authority
  helper and request validation precede provisioned-channel locking, guest checks,
  participant UPSERT and membership INSERT. Anonymous requests have a separate
  meeting/recording guard and receive no Chat membership. Do not conflate anonymous
  meeting guests with authenticated guest accounts.
- [guest_require_grantable](../../mailserver/sql/reducers/guest_account.sql:147)
  takes a guest-row `FOR SHARE`; member targets without that row take no such lock.
  Thus join's guest→participant→channel projection differs from admission's
  channel→guest→participant projection. Even without a guest row, participant→channel
  versus channel→participant is a candidate inversion on the same meeting/user.
  Actual blocking modes, helper locks and reachable interleavings still need proof;
  this is not a demonstrated deadlock or a final replacement order.
- [meeting_kick](../../mailserver/sql/reducers/meeting_control.sql:224) bans the
  participant and removes authenticated-user Chat membership **only** for a
  meeting-provisioned channel. Existing huddle-channel membership is preserved.
  Removal is not hold release; retained coverage stays governed by explicit hold
  release. Preserve the symmetric provisioned-channel gate across join/admit/kick.
- [HTTP join](../../mailserver/internal/meet/meetings.go:245) runs join and get in
  one user-scoped transaction, then prepares the media room and mints the token.
  [HTTP kick](../../mailserver/internal/meet/meetings.go:387) commits its reducer
  before external eviction. A subsequent room/eviction failure cannot be reported
  as SQL rollback. Keep external calls outside lock-holding SQL transactions and
  preserve existing revocation/reconciliation behavior; do not infer media cessation
  from database membership deletion alone.

Resolve lock composition jointly with HW's custodian/channel/Drive graph, not by
moving guest checks later until they cease protecting grants. Re-read eligibility
under the agreed boundary and preserve authority, history-floor snapshots, guest
disable, ban/re-admit and recording exclusion. The `meeting_require_authority`
helper was read; its delegated role lookup is not full authority closure.

## Proposed qualification cases

MW-T IDs are future obligations, not executable selectors or passed tests. Use
actual reducers and user-scoped HTTP wrappers with deterministic barriers and
independent committed-state/audit checks. A lock timeout is not proof of rollback;
unknown outcomes follow HW's authoritative reconciliation rule.

| Case | Setup and required oracle |
|---|---|
| MW-T01 Join versus admit | Same meeting, user and provisioned channel; existing participant plus pending authenticated request. Pause join after participant write and admit after channel acquisition, then exercise both orders under the proposed protocol. No indefinite wait, lost committed membership, duplicate coverage or unintended role reset. Include member and authenticated-guest variants. |
| MW-T02 Hold versus bridge | Custodian hold overlaps actual join/admit, including authored-but-departed channel history. Both commit orders preserve active coverage. Kick removes only provisioned membership, never hold history; explicit release remains separate. |
| MW-T03 Boundary matrix | Provisioned versus existing huddle channel; ordinary member, authenticated guest and anonymous request; active/disabled guest, banned/re-admitted participant and recording state. Preserve each existing admission/denial contract and history-floor behavior. Do not grant Chat access solely because meeting access was granted. |
| MW-T04 Post-commit effects | After committed join, fail room preparation; after committed kick, fail media eviction. Assert actual DB outcome and truthful error, retained retry/reconciliation state and eventual qualified media behavior. Confirmed pre-commit failure leaves no partial SQL effects; lost response is reconciled before retry. |
| MW-T05 Transfer variants | Sponsor missing versus already holding membership. New INSERT materializes sponsor custodian coverage through V127; promotion-only UPDATE does not rerun the INSERT trigger. Preserve guest coverage, historical authorship and history floors; sponsorship, channel roles, Drive ownership and admin audit commit or roll back together. |
| MW-T06 Transfer interleavings | Authorized ordinary add versus transfer on a guest-owned channel, both acquisition orders with observed barriers. Separately trace the actual guest-reprovision outer caller before constructing its race. Assert bounded completion/cancellation and authoritative reconciliation; do not turn a candidate lock edge into a claim of an existing deadlock. |
| MW-T07 Profile composition | Extend existing profile apply/update/member-add fixtures with multiple assigned guests/channels, hold and disable. Profile changes do not rewrite `history_floor_seq` on retained memberships or alter hold coverage; current access follows current app entitlements and active/disabled state. Preserve disable's authorized membership deletion, not unchanged effective historical access. NULL profile remains restrictive. |
| MW-T08 Provisioning rollback | New member and re-provision, duplicate defaults, hold-set overlap, and injected failure after autojoin but before completion. User/mailbox/membership/hold/audit effects remain atomic; guest provisioning creates no default Chat membership. |
| MW-T09 Authority revocation | Transfer and profile mutations versus live permission/reach changes. Qualify the existing fence and same-assignment requirement; preserve domain/OU/set constraints, without inventing new permissions or assuming all SECURITY DEFINER calls are worker-only. |
| MW-T10 Poison isolation | Malformed invite's empty/oversized domain in first/middle/last roster element, new mirror and removed existing mirror, absent/present contact membership and active custodian hold. Consume/ACK poison with no new mirror/room/member/coverage/audit, no reactivation, and no roster/notification change. Follow with valid next sequence and same-sequence replay. |
| MW-T11 Explicit dispatch | Missing, JSON-null and unknown `op`, pre-existing peer-bound mirror, valid roster and DM-only peer. Poison consumes/ACKs without domain changes. Valid roster still needs room scope; only the explicitly named `room_revoked` exemption remains. Include nonstring operation values and a valid subsequent frame. |
| MW-T12 Federation replay/hold | All three writers versus hold-set; fresh/existing mirror and absent/present membership; lost ACK replay, reaped sequence, fresh-sequence duplicate DM content and re-invite with same/new contact/gap fields. Inspect independent membership/coverage/audit and sequence state, preserving existing replay contracts rather than asserting all fresh-sequence content is semantically idempotent. |

These extend existing Meet/Guest and HW tests; they do not replace them. Match-only
test searches are not an assertion that no equivalent test exists. Bind concrete
selectors and identify reusable fixtures during implementation review.

## Guest and provisioning composition

The full [transfer body](../../mailserver/sql/reducers/guest_account.sql:634)
locks the guest row, then ID-ordered guest/sponsor users, then channel-ordered
guest-owned membership rows. It UPSERTs the sponsor membership and demotes the
guest, then locks ID-ordered owned Drive spaces, transfers mutable ownership and
sponsorship, and writes the admin audit in the same transaction. The permission
helper requires **one live assignment** covering both guest and replacement
sponsor. The sponsor must be enabled, non-guest and in the immutable host domain.
An unchanged sponsor or unexpected personal Drive space is rejected. Historical
authorship is not transferred. Preserve these checks inside reducer authority.

Only transfer's actual INSERT invokes V127's membership AFTER INSERT trigger.
An existing sponsor's role promotion and the guest's demotion do not. Do not
delete or transplant the guest's retained custodian coverage because ownership
moved. Transfer's explicit audit is `guest.transfer`; absence of a direct Chat
audit/notification call in this body is not proof that no transitive effect exists.

[Profile apply](../../mailserver/sql/reducers/guest_profile.sql:323) takes a
selected profile `FOR SHARE` before guest `FOR UPDATE`, replaces exactly seven
app entitlements and updates existing membership `can_post`. It neither creates
membership nor rewrites the history floor. Profile set takes the profile
`FOR UPDATE`, then assigned guests without explicit ordering, and calls apply.
Keep domain-wide profile authority distinct from narrowed target-assignment reach.
The inspected profile-set HTTP path also reads the result before committing; a
failed result read rolls back its writes. Transfer and assignment use a single
pool reducer call, not separate handler-owned multi-step transactions.

[Provisioning](../../mailserver/sql/reducers/provision_account.sql:51) already
takes `admin_authority_fence` before account work. Member user and mailbox writes
precede `chat_autojoin_defaults`; email-policy/alias work can still follow it.
Autjoin therefore cannot be qualified as a standalone transaction. Its default
channel INSERT loop has no explicit channel order. Guest provisioning returns
without mailbox/autojoin; member/guest identity collisions remain refused.

Projected acquisition edges, **not reproduced deadlocks**:

```text
transfer:      guest G -> users -> membership rows -> new sponsor INSERT -> channel FK
ordinary add:  channel C -> guest G FOR SHARE -> membership INSERT / conflict
re-provision:  user -> guest satellite     [outer caller still needs tracing]
profile set:   profile -> assigned guests -> apply -> membership policy UPDATE
```

Resolve these with HW's one qualified lock graph, including loaded FK/trigger
modes. Preserve eligibility protection rather than moving the check outside the
transaction to avoid blocking. Transfer and profile bodies lack an explicit
authority-fence call, while their inspected permission helpers are STABLE reads;
this is a finite revocation qualification obligation, not a repository-wide absence
claim. Reuse the existing fence if its full protocol applies; do not add a competing
primitive from this partial map.

Existing tests to extend, **inspected but not run**: `guest_lifecycle.pg`201–226;
`TestGuestTransferAndDisableShareLifecycleLockOrder`; `guest_profiles.pg`156–250
and serial fixtures281–330; `TestGuestProfileApplyVsUpdateSerialization` and
`TestGuestProfileUpdateVsMemberAddSerialization`. None is being relabeled as a
transfer/new-membership/hold or full provisioning concurrency proof.

## Federation: repair rejected-frame isolation before extracting interfaces

Two source-derived findings are **P1 planning repair priorities**, not executed
exploits or an all-federation security verdict. Deduplicate them by source/symbol
against the security program before assigning occurrence IDs; do not alter the
scan's canonical counts from this review. Correct these local behavioral defects
with regression tests before the owning C2 path enters a structural extraction.
Current authorization, sequence consumption and retained-history policy are the
intended behavior; no new product policy is needed for these two corrections.

1. **MW-F01: invite poison can leave accepted business writes.** In
   [federation_apply_room](../../mailserver/sql/reducers/federation_apply_room.sql:572),
   mirror/room creation572–582, membership591–593 and reactivation598 precede
   roster-element rejection673–680. `RETURN 'poison'` is an ordinary return, not
   transaction rollback. [Receiver](../../mailserver/internal/federation/receiver.go:319)
   ACKs a successful reducer call including poison. Keep one shared roster-element
   validation pass: leave invite lookup/shape/cardinality checks in the invite arm,
   but move its mirror/setup/membership/reactivation writes (current572–598) after
   the shared element validation and before shared roster replacement, guarded by
   explicit `v_op = 'invite'`. Preserve both existing `v_channel_id` assignment
   paths inside that relocated block: INSERT/RETURNING with conflict lookup, or
   assignment from the existing binding. Establish the `federation_rooms` row
   before shared roster-member upserts, retaining its channel binding. Membership,
   reactivation, the later gap marker and final roster notification must use the
   same resolved channel. The roster arm retains its existing peer/mirror
   checks; remove/revocation return before this pass. Do not duplicate the domain
   predicate or introduce a new public helper. Retain intended inbox/cursor
   consumption. Reconcile the header and invite-arm “before any write” comments
   with this ordering: they mean domain writes, not required poison bookkeeping.
   MW-T10/11 include paired valid/invalid roster-operation cases to prove its
   outcomes and the remove/revocation exception did not change. Do not add
   compensating deletion of pre-existing
   membership or hold coverage. Existing `federation_room_control.pg`499–522 checks
   oversized elements/cardinality for **roster** operations; those sampled assertions
   do not prove invite isolation.
2. **MW-F02: NULL operation skips the dispatch and scope guards.** The exact guards
   at198–216 are `IF v_op NOT IN (...)` and `IF v_op <> 'room_revoked'`. A missing
   or JSON-null discriminator makes both conditions NULL. With a pre-existing
   spoke mirror bound to the peer, the later non-invite branch can reach roster
   mutation. Explicitly reject NULL before dispatch, validate the discriminator's
   type, and keep the named `room_revoked` exception exclusive. Do not rely on
   HTTP struct decoding as the reducer's authority check.

Implementation order: first add MW-T10/11 failures to
`mailserver/sql/tests/federation_room_control.pg` and proposed real-DB tests
`TestRoomApplyIntegration_PoisonInviteLeavesNoBusinessEffects` and
`TestRoomApplyIntegration_NullOpCannotBypassRoomScope` in
`mailserver/internal/federation/room_apply_integration_test.go`; then apply the
reducer validation changes; then test the real Receiver ACK/lost-ACK sequence and
MW-T12 composition. Names above are **proposed**, not existing runnable selectors.
Use the existing pgTAP/Go database lanes and their real fixtures; the pure-Go
`TestHandle_ToggleGateAppliesBeforeRoomDispatch` tests the feature gate only and
cannot prove SQL isolation. For poison, compare independently captured domain
before/after state while allowing only the contract's inbox/cursor bookkeeping;
for SQL/helper failure assert rollback/no ACK, not poison success.

Bind MW-T10's existing active-custodian-hold and removed-mirror variants to these
fixtures explicitly; they are not optional empty coverage/audit assertions.
Capture notification row/count deltas (`notify_count` or `_test_notify_log`),
not only `last_notify_event`: an identical extra event must fail isolation.
Keep transactional capture distinct from committed LISTEN evidence. Update the
pgTAP `plan(...)` count when adding assertions. Missing, skipped or unexecuted
required cases in either Go or pgTAP are not passing evidence.
The new Go cases are spoke-side, not the existing hub-ingest fixture. Use unique
per-run peer/room identities and point the existing lane's DSN at a disposable
task-owned PostgreSQL instance and database. Role provisioning changes
cluster-global roles, so an isolated database on a shared instance is insufficient;
never run this fixture's role provisioning against a shared instance.
Pass the loader's target-validation contract; when Architecture R2 test mode is
enabled, use its derived test database name and permitted local host/DSNs. That
validator does not establish instance ownership or validate the worker DSN/port:
bind setup and Receiver connections to the same task-owned instance and database
independently, never bypass its checks or infer isolation from a validator pass.
Setup/migration and Receiver credentials are separate.
Setup uses the existing test schema-loader and role-provisioning sequence against
that disposable target, including the current reducers and their ownership/grants,
before the Receiver fixture connects; require loader exit status zero plus the
identity/grant assertions below, rather than assuming an empty database already
has runtime roles. Loader exit zero alone does not prove pgTAP is available:
require the pgTAP lane to execute its declared assertions, not skip.
Use `fedConcPool(t, explicitWorkerDSN)` for the Receiver connection after setup,
not `fedConcDSN` or the hub-room setup helper. The
primary fixture requires an explicit worker DSN and fails immediately if absent;
it must not silently fall back or skip. Keep that credential out of test output.
Explicitly wire the Receiver's primary split-credential fixture as `setjoin_worker`;
the existing `fedConcDSN` reads `DB_DSN`, so setting `DB_WORKER_DSN` alone does
not configure that helper. Verify connected identity outside a SECURITY DEFINER
call, provisioned NOSUPERUSER/BYPASSRLS/NOCREATEDB/NOCREATEROLE attributes and
relevant schema/table/sequence/reducer grants; neither the WorkerPool wrapper nor
function ownership proves caller credentials. Never SET ROLE on a shared pool.
Preserve and restore any changed toggle/config presence and value,
including `feature.federation` and compliance setup, on every exit. Never copy
the existing helper's global-setting cleanup into a shared database. Qualify
lost-ACK replay separately from the ordinary Receiver-returned-ACK assertion.

Preserve the runtime's empty-worker-DSN → `DB_DSN` fallback. A separately labeled
pre-flip compatibility fixture freezes its actual base-login identity and grants
and verifies that the worker aliases that pool; do not assume the login is
`setjoin_owner` or count fallback as split-worker acceptance. These test contracts
do not authorize a deployment credential flip.

Writer composition to preserve:

```text
local DM: user-scoped transaction -> peer/guest checks -> channel ensure -> member -> V127
inbound:  authenticated stream peer -> per-call worker SQL
          -> cursor lock/bookkeeping -> trust/dispatch -> channel/member -> V127
          -> domain message/roster effects -> return/commit -> ACK
V127:     actual membership INSERT -> custodian advisory -> coverage -> Chat audit lock
```

Local DM uses authenticated `claims.UserID` and excludes guest senders. Inbound
peer comes from the authenticated stream, not the payload; inbound recipient
queries use enabled mailbox/user checks, which are not automatically the same
guest prohibition. Inbound DM lacks a per-message peer-authorize call; stream
reconciliation must not be described as an atomic per-message revocation fence.
Room scope is checked per payload except the named revocation advisory. Preserve
DES-012's hub/spoke origin rules; a relayed room sender is not a DM sender.

An existing DM channel conflict may return without membership repair. Inbound
fresh-sequence duplicate content can seed membership before content dedup. An
invite with a new contact may add another owner, but existing membership is left
unchanged, not promoted. Same sequence, duplicate content under a fresh sequence,
and re-invite are distinct retry cases. Remove/revoke mark the mirror removed;
they do not delete local membership/messages/hold history. The inspected hold and
coverage loops have no explicit sorting; qualify the outer cursor/channel/member,
FK, custodian and audit edges together rather than declaring a helper-only order
safe. Network ACK is outside SQL; lost ACK is reconciled by sequence replay.

## Read receipt and next unit

Full reads: `meeting_join.sql`1–171 and `meeting_require_authority.sql`1–42.
Sampled: `meeting_lobby.sql`241–412 (admit body276–391);
`meeting_control.sql`224–325; `guest_account.sql`140–172,277–336,371–411;
Meet `meetings.go`95–116,220–282,362–407; Meet `lobby.go`54–88.
Other inventory entries retain their stated prior-read/match-only status. Inventory
hashes bind all eleven direct-writer files; helper/HTTP inputs are bound in the
continuation ledger. Source-owner DOX and loaded isolation/grants remain incomplete.

MW03 adds complete transfer/helper, profile set/apply and `provision_account`
function reads, with bounded HTTP/test/helper samples; the autonomous continuation
ledger owns exact input hashes and read limits. Remaining outer provisioning,
audit/notification helper and loaded-state obligations stay explicit.

MW05 adds full reads of all three federation reducers, receiver, peer authorization,
V127, hold-set and Chat audit helpers, plus bounded stream/service/sender context.
Its exact hashes/ranges are retained in the autonomous continuation ledger. Root
also sampled room-control473–530 and read the pure-Go receiver-dispatch test.
No receiver SQL regression, concurrency fixture or loaded-state test ran.

The next work is finite integration, not another unconstrained source scan: reconcile
the five rows and indirect-write exclusions into the owning implementation packet,
bind the complete selected transaction boundary and qualification tests, then
review that packet. Remaining helper/loaded-state unknowns cannot support a safety
claim; their qualification is a named pre-implementation/rollout obligation rather
than fabricated evidence. No full Autoplan/numeric score or implementation
authorization follows from this documentary packet.
