<!-- Detailed DOX reference, moved from AGENTS.md on 2026-09-11. -->
This is a task-selected reference, not an always-loaded rail. Root and local
AGENTS.md govern agent workflows. Domain contracts below remain binding for their
scope; historical status is not permission to implement or enable flags.

# mailserver/internal/meet — Meet Pillars B1 + B2 + B3 (DOX child)

Parent: `mailserver/internal/AGENTS.md` → `mailserver/AGENTS.md` → root `AGENTS.md`.

## Purpose

Serves `/meet/*` (mounted at `/api/meet/*`, plus the ONE unauthenticated
guest-lobby surface at `/api/public/meet/*` and the loopback-only `/rtc`
signal proxy) — WebRTC conferencing on a self-hosted **LiveKit SFU sidecar**
(`setjoin-sfu.service`, v1.13.5, pinned + checksummed), with all business
logic (create/join/lock/roles/kick/end, guest lobby, attendance) in PL/pgSQL
reducers. A thin REST translator, mirroring `internal/chat/handler.go`'s
single-gate + internal-mux shape.

- **B1** (core conferencing) behind `feature.meet` (`toggle.FeatureMeet`,
  seeded OFF — V125); org-level guest-lobby kill switch `meet.guest_access`
  (seeded ON).
- **B2** (host-initiated recording → Drive) behind `feature.meet_recording`
  (`toggle.FeatureMeetRecording`, seeded OFF — V129; additionally requires
  `feature.meet`+`feature.drive`), via a self-hosted **LiveKit Egress**
  sidecar (`setjoin-egress.service`) + a loopback **Valkey** bus
  (`setjoin-valkey.service`, NOT Redis — RESP-compatible).
- **B3a** (breakout rooms; polls/Q&A/whiteboard ride existing chat/
  data-channel rails, no new toggle) behind `feature.meet_breakouts`
  (`toggle.FeatureMeetBreakouts`, seeded OFF — V130).
- **B3b** (live captions, SHIPPED end-to-end incl. the `asrbot/` Go sidecar
  module, the FunASR runtime container, and the live FunASR round-trip)
  behind `feature.meet_captions` (`toggle.FeatureMeetCaptions`, seeded
  OFF — V130).

All three programs are code-complete and gate-green. Spec/plan:
`retired-docs:superpowers/plans/archive/2026-07-12-meet-B1-core.md` (B1),
`retired-docs:superpowers/plans/archive/2026-07-15-meet-B2-recording.md` +
`retired-docs:superpowers/specs/2026-07-15-meet-B2-recording-design.md` (B2),
`retired-docs:superpowers/plans/archive/2026-07-15-meet-B3-qol.md` (B3). Authority model:
ADR `docs/adr/DES-011-sfu-peripheral-reducers-are-authority.md` (extended to
Egress in B2, to the ASR sidecar in B3b). LiveKit risk research:
`retired-docs:superpowers/research/2026-07-12-B1-livekit-C0-spike.md`. See "Honesty
ledger — flip status" below for what remains owed before each toggle flips
ON anywhere.

## Ownership

`Handler.registerRoutes(router)` is the single private authenticated-route
authority. `NewHandler` passes its production `*http.ServeMux`; the package-local
route-inventory test replays the same registrar and emits `meet.json`. The public
lobby routes and `/rtc` remain gateway-owned and are recorded by the six gateway
registrars; do not duplicate them in the private list.

This doc owns every `.go` file directly under `mailserver/internal/meet/`
(`handler.go`, `config.go`, `errors.go`, `livekit.go`, `meetings.go`,
`lobby.go`, `webhook.go`, `egress.go`/`recording.go` (B2), `breakouts.go`
(B3a), `captions.go` (B3b), + their tests).

**The `Worker` (worker.go) is split across four files, one per program (pure
file move, no worker-arm abstraction — five arms, five real shapes,
deliberate)**: `worker.go` (the `Worker` type, `NewWorker`, `Run`, `tick`'s
dispatcher, and the B1 lifecycle arm: `expireLobby`, `retryDeleteForRooms`,
`deleteEndedButLiveRooms`, `gcLostWebhooks`) · `worker_recordings.go` (B2 —
`reconcileRecordings{,DBOnly,Egress}`, `ingestRecordings`/`ingestOne`,
`reapStaging`) · `worker_breakouts.go` (B3a — `reconcileBreakouts`,
`gcClosedBreakoutRooms`, `reconcileBreakoutPresence` + its drain/
absence-grace helpers) · `worker_captions.go` (B3b —
`reconcileCaptions{Crashed,Orphaned}`). All four share one `Worker`
struct/receiver; `worker_test.go` (unsplit) covers all four arms.

**Two gating postures, stated once, load-bearing everywhere below:**
1. B2's recording drains (`reconcileRecordings`, `ingestRecordings`, the
   staging reaper) run **outside** the `feature.meet && Configured()` gate,
   unconditionally, gated only on their own runtime deps (`egress`/`store`
   non-nil) — a toggle gates new intent, never the draining of committed
   state (the `pushjobs`/`drive.NewWorker` precedent).
2. B3's breakout/captions healers run **inside** the `feature.meet &&
   Configured()` gate but are never additionally gated on
   `feature.meet_breakouts`/`feature.meet_captions` — a toggle flip must
   never strand someone in a breakout room or an orphaned captions session
   nobody can close.

**Recording-to-Drive chunk safety:** `ingestOne` stages each verified chunk
under `tmp/upload/`, then commits it through
`drive.CommitStagedChunk` in one short transaction per chunk. That shared path
rechecks the meeting owner's Drive authority, row-locks classification, and
holds the same transaction-scoped `(scope, sha256)` advisory lock used by
Drive GC/inventory across canonical `CopyObject` plus
`drive_chunk_register`. A classification upgrade between chunks makes the
final `drive_file_put_version` fail closed; the durable ingest retry converges
on the new scope, while old unreferenced claims follow the seven-day sweep/GC
rail. Do not restore a raw `PromoteChunk` then separate register sequence.

Does NOT own: the reducers (`mailserver/sql/reducers/meeting_*.sql`,
`notify_meet_state.sql` — `mailserver/sql/AGENTS.md`), the webmail Meet app
(`$lib/meet/`, `src/lib/components/meet/` — `mailserver/webmail/AGENTS.md`),
the `meet:{uid}` WS/SSE push wiring (`internal/ws/` —
`mailserver/internal/AGENTS.md`'s `ws` row), deploy-side SFU/Egress/Valkey/
ASR provisioning (`mailserver/AGENTS.md`'s deploy section), the admin
recordings registry (`internal/admin/admin_meet_recordings.go`), or
`cmd/mailserverd/main.go`'s wiring (mounts, worker start, `/rtc` proxy,
`apiPinnedPrefixes`, push leg, health probes — no separate
`cmd/mailserverd/AGENTS.md` exists). The captions ASR sidecar itself is
`asrbot/` (`asrbot/AGENTS.md`), a fifth top-level Go module outside
`go.work`.

## Architecture — the three spike laws, enforced not narrated

1. **Eviction, not TTL.** A LiveKit AccessToken's `exp` is admission control
   only — a connected participant outlives token expiry. Every revocation
   path terminates in a `RoomController` call: `kick` → `RemoveParticipant`,
   `end` → `DeleteRoom`, the reconcile worker's lost-webhook GC → a synthetic
   `room_finished` fact → `meeting_end`'s own projection.
   `TestEveryRevokePathEvicts` (`meetings_test.go`) is the machine-checked
   invariant — a future revoke route added without wiring an eviction call
   fails this test by omission, not by review comment. (B3a grew it four
   more cases: breakout move/close, end-with-breakouts-open, kick-in-
   breakout.)
2. **Webhooks are facts, never authorization.** Authorization truth flows
   reducers → LiveKit (mint/evict) only. Webhooks (retried, unordered, not
   guaranteed) flow back only as facts — `meeting_participant_event` is
   loss-tolerant + idempotent by construction: unknown room/identity, a
   banned identity, or an already-applied transition is a silent no-op, not
   an error (raising would 500 a retried webhook forever). `room.auto_create:
   false` in `livekit.yaml`; member/guest grant specs carry `roomJoin` only,
   **never** `roomCreate`/`recorder`/`roomAdmin`-for-guests (the `grantSpec`
   struct in `livekit.go` has no field to set them from —
   `TestMintTokenGuestGrantNeverAdmin` pins it by decoding the minted JWT).
3. **One secret, one generation step.** `LIVEKIT_API_KEY`/
   `LIVEKIT_API_SECRET`/`LIVEKIT_URL` live in `config.env`; `install.sh`
   generates the secret ONCE and writes it into both `config.env` and
   `livekit.yaml` in the same run; `Config.Configured()` is the runtime gate
   every route checks before touching `h.rooms`.

**FORCE-RLS (R4, W4 Go leg ACTIVE):** three `SECURITY DEFINER STABLE SET
search_path = public` scope helpers dodge the policy-recursion trap a
literal membership subquery would hit under FORCE (the V114/V119 pattern):
`meeting_member_role` (V125, filters `left_at IS NULL` — DEAD post-end),
`meeting_attendee_role` (V129, reads the historical participant row
instead — gates every post-end surface). App-level checks inside each
reducer stay PRIMARY (ARCH-006), but the RLS policy is no longer dormant:
every user-request-path DB call in this package runs inside
`dbscope.RunUserScoped(ctx, h.pool, claims.UserID, func(tx pgx.Tx) error
{...})` (`meetings.go`'s `execMeet`/`queryMeetJSON`/`roomNameForMeeting`/
`queryStringColumnScoped` choke points, or wrapped inline per multi-
statement route), setting `app.current_user_id` transaction-locally before
the reducer call — the V134 write policies actually evaluate and
actually admit/deny under the flipped `setjoin_app`/NOBYPASSRLS runtime.
Guarded by `scripts/check-rls-scope-wrap.sh`; live-proven by
`rls_scope_live_test.go`'s `TestRLSScopeWrapMeetingCreate`, which runs the
real `Handler` against a connection assuming the constrained `setjoin_app`
role. **Exempt by construction, not by gap:** the webhook receiver
(`webhook.go`) runs on the **APP pool with no caller GUC** — a webhook has
no user — which is exactly why V134 converted
`meeting_participant_event`/`meeting_recording_event` to `SECURITY DEFINER`
(it does NOT run on `workerPool`; only the four `worker*.go` reconcile files
do). All Meet tables carry `FORCE ROW LEVEL SECURITY` with a cross-tenant
denial proof in `mailserver/sql/tests/rls_meet.pg`
(`scripts/rls-denial-allowlist.txt`, all `COVERED`). The guest-lobby
reducers (`meeting_join_request_create`/`_poll`) are **worker-owned**
`SECURITY DEFINER` (the `chat_space_ensure` pattern) — the unauthenticated
surface (`lobby.go`'s `PublicHandler`) has no caller GUC either.

## Gate-ratified postures (user 2026-07-12)

**Member-join is org-open by design.** Any authenticated org user may join
(or knock at, when locked) any non-ended meeting **by id** — no invite/
participant precondition; the join upsert makes them a participant on first
call. Deliberately different from Chat's membership model (id-enumerable by
design, the Teams-like "anyone in the org" model); `locked` and `banned_at`
are the only member-side barriers. The slug/anti-oracle rigor (BZ185,
one-shot secret, IP+slug rate limits) exists for the PUBLIC/guest surface
only. Pinned by `TestFullMeetingArc` + `meet_join.pg`.

**Kick = ban-until-re-admit.** `meeting_kick` stamps
`meeting_participants.banned_at`; `meeting_join` rejects a banned identity
with BZ186 until the host clears it via `meeting_set_role` (any role
assignment on a banned identity clears the ban — re-assigning a role IS the
re-admit signal). **Guests are symmetric but sealed**: a guest kick flips
their `meeting_join_requests` row straight to `denied` — no guest re-admit
path, only a fresh join-request. Pinned by `meet_control.pg`/`meet_lobby.pg`
+ `TestKickBansAndReAdmitRoundTrip`/`TestGuestPollAfterKickDenied`.

## Grant spec — reducers COMPOSE, Go only TRANSLATES

```json
{"room":"<meetings.room_name>","identity":"u:42","name":"Alice Chen","role":"host",
 "canPublish":true,"canSubscribe":true,"canPublishData":true,
 "roomAdmin":true,"hidden":false,"external":false,"ttlSeconds":14400}
```

`livekit.go`'s unexported `grantSpec` struct mirrors this exactly;
`MintToken` maps it onto `protocol/auth.VideoGrant` + `SetValidFor` and
nothing else — the ONLY function in the codebase that builds a LiveKit
grant. `roomCreate`/`recorder` have no field, so a compromised or buggy
reducer literally cannot express them into a token. `ttlSeconds` is
admission-window sizing only (`LEAST(14400, …)`); eviction is the actual
enforcement (law 1).

## Authenticated guest accounts (Guest G3)

Guest accounts do not inherit B1's org-open member posture. Exact possession of
the high-entropy slug authorizes only the ordinary prejoin projection and an
authenticated knock; it never authorizes a LiveKit token. Numeric reads require
current bound-channel membership, ownership, an existing participant row, or a
join request belonging to the caller. Token minting is narrower: current
bound-channel membership, ownership, or an admitted authenticated knock through
`meeting_guest_join_allowed`. Direct join, public-poll completion, breakout
rejoin, role mutation, and create all reapply active-account and derived Meet
entitlement checks. Member behavior is unchanged.

Profile policy is authoritative: `allow_meet_create` gates creation,
`allow_meet_host` gates promotion to cohost. Meeting-attendance Drive scope is
independent of `allow_download`, so view-only guests retain preview authority;
the raw-content reducer gate owns original-byte access. Every authenticated guest-account grant carries
reducer-authored `external:true`; `MintToken` maps only that fact to the signed
LiveKit participant attribute `setjoin.external=true` and pins
`CanUpdateOwnMetadata=false`. Anonymous `g:` lobby identities remain Guest, not
External, and their BZ199 recording rules are unchanged. Recording consent for
authenticated guests is the existing in-progress interstitial plus persistent
live banner—no second opt-in and no `recordable` profile knob.

Mailbox-less guest web sessions consume named `meet` and `chat` EventSource
frames instead of the bidirectional JMAP WebSocket. `guest_set_status(...,
'disable')` expires pending/admitted authenticated requests and marks retained
participants left+banned, preventing enable from resurrecting a token or
recording-file grant. Guest G5 completes live eviction: `meeting_join`, admitted
`meeting_join_request_poll`, and `meeting_breakout_join` call
`guest_require_grantable` before returning a token, taking the same guest-row
share lock that lifecycle changes take exclusively. Disable/expiry therefore
cannot miss a concurrent grant. The transition records the guest identity for
the parent and every breakout room of every non-ended meeting in which the
guest has a participant row, including recently-left rows and prior breakout
rooms whose still-valid token may reconnect. The unconditional
`guestlifecycle` drain repeats `RemoveParticipant` through the 4h5m stale-token
horizon and is never gated on Meet or Guest feature toggles.

Guest credential recovery reuses the stable `u:<user_id>` identity and writes
separate `action='reinvite'` eviction intents. `meeting_join`, authenticated
admitted poll, and breakout re-mint call `guest_require_meet_ready` after the
lifecycle share lock and refuse new tokens while any such intent is incomplete.
Invite acceptance may restore other web apps immediately; Meet deliberately
waits for the stale-token horizon so the continuing eviction worker cannot kick
a recovered session or allow an old token to reconnect.

## Guest-poll envelope: passthrough + deny-list

`lobby.go`'s `PublicHandler.handlePoll` (the ONE unauthenticated poll route,
`GET /public/meet/{slug}/join-request/{id}`) decodes
`meeting_join_request_poll`'s jsonb into `map[string]json.RawMessage`,
deletes the ONE `"grant"` key (raw LiveKit grant material — consumed to
mint token/wsPath/expiresAt, never echoed back), and re-serializes
everything else unchanged (`stripAndMintPoll`). **Deny-list, not an
allowlist struct, because a decode-into-struct site silently drops any
undeclared reducer key with no compile error — this shipped that bug TWICE**
(`captionsOn`, then the room data-channel's `p` field — the sibling decode
site in `room.svelte.ts`, same root cause). A future reducer key on the
admitted arm now reaches the client with zero code change here. Every key
`meeting_join_request_poll` emits today is deliberately guest-visible per
DN3 (`state`, `recordingActive`, `captionsOn`/`ccIdentity`); if a future
change ever needs a host-only field on this specific envelope, add it to
the deny check — do not revert to an allowlist struct, and do not assume
blanket passthrough stays safe by default the way it already safely does on
`meeting_get`'s authed `json.RawMessage` passthrough. Tests:
`TestStripAndMintPollStripsGrant`, `TestPollPassthroughNewReducerKey` (a
simulated, never-seen reducer key flows through with zero code change),
`TestStripAndMintPollNonAdmittedPassesThrough`,
`TestGuestPollAfterAdmitMintsToken`/`TestMemberKnockRidesPublicPoll` (assert
the raw HTTP body never contains `"grant"`).

## The admitted re-mint fence: reducer-durable (primary) + in-process (second)

The public poll's admitted leg is a TIME-BOUNDED mint capability, enforced
at TWO layers, same horizon — 15 minutes past the FIRST admitted mint
(`admittedReMintWindow`, the V125 pending-expiry interval;
occ_bcdf321b15332f109a69e653):

1. **PRIMARY — the durable reducer fence (V270).**
   `meeting_lobby.sql`'s `meeting_lobby_mint_fence(p_request_id)` (the
   `identity_media_mint_fence` genre: SECURITY DEFINER, worker ownership,
   pinned search_path) records the first admitted mint per join request in
   `meeting_lobby_mint_fences` — ONE immutable row (join_request_id PK, the
   row-derived `g:`/`u:` identity, `first_mint_at`, `expires_at`, a CHECK
   pinning `expires_at = first_mint_at + interval '15 minutes'`: the horizon
   is a table constant, not a tunable) — and fails closed with **BZ329**
   (`stateMismatch` → 409; registered in `reducererr.codeClass`, the golden
   contract matrix, `docs/reducer-error-codes.md`, and this package's
   `bzSlug`) on any past-window mint. `meeting_join_request_poll` consults
   it immediately before BOTH admitted RETURNs — after every shape-deciding
   arm (toggle-off BZ185, meeting-ended, banned→denied, the member arm's
   `identity_media_mint_fence` gate), so wire priority is exactly what the
   Go fence produced when it was the only bound — and catches BZ329 to
   synthesize its OWN bare `{"state":"expired"}` shape: no grant, no riders,
   the persisted `'admitted'` row untouched. The window NEVER extends
   (INSERT … ON CONFLICT DO NOTHING + re-read: the first mint wins; a fast
   poller only accelerates the close for everyone) and an expired row is
   NEVER swept — it IS the durable CLOSED marker (sweeping it would reopen
   the window), cascading away with its join request. FORCE RLS with ZERO
   policies (the `identity_media_admissions` posture;
   `meeting_lobby_mint_fence_rls.pg` proves setjoin_app blind; the allow
   guard auto-excludes policy-less tables).
2. **SECOND — `lobby.go`'s in-process `admittedMintFence`** (kept, belt and
   braces): `stripAndMintPoll` consults it before any admitted-leg mint,
   a nil fence fails closed, the store is bounded (4096, fail-closed when
   full of unexpired entries), and a past-window poll answers the same bare
   `{"state":"expired"}`. It can only ever be stricter than the reducer's
   window (its clock opens no earlier than the reducer's first allowed
   mint; a restart only widens it) — the reducer's row is what a replica
   restart or a second gateway replica can no longer reopen.

The within-window wire is byte-identical to the pre-V270 behavior on both
arms. A mint the member arm's `identity_media_mint_fence` refuses never
burns window (our fence runs after it), and a BZ329 refusal rolls back the
nested block (the identity admission lease that arm just refreshed dies
with it — truthful for a poll that minted nothing). pgTAP:
`meet_lobby_mint_fence.pg` (32 — open/re-mint/refuse exact shape/
poll-row coherence/CHECK pin/cascade), `meet_lobby_mint_fence_rls.pg` (11
— the FORCE deny-all proof as setjoin_app). Go:
`TestReducerMintFenceOpensAndClosesWindow`/`TestReducerMintFenceMemberKnockArm`
(the primary layer, incl. the fresh-replica cannot-reopen proof),
`TestGuestPollReMintWindowClosesEndToEnd` (the second layer, end to end).

## BZ185–BZ190 (`errors.go`'s `bzSlug`/`writeMeetProblem`)

`writeMeetProblem` wraps the shared `reducererr.WriteProblem` kit
(`Namespace:"meet"`) — the projection mechanics live once in
`shared/reducererr/wire.go` (moved from `mailserver/internal/reducererr` by
arch #A8); `bzSlug` here only adds the RFC7807 `type`.

| Code | Class → HTTP | Meaning |
|---|---|---|
| BZ185 | NotFound → 404 | meeting/slug not found — anti-oracle: nonexistent, ended, guest-disallowed, and `meet.guest_access`-off all read identically on the public surface |
| BZ186 | Forbidden → 403 | host/cohost-only action by a lesser role, OR a banned participant rejoining before re-admit |
| BZ187 | Forbidden → 403 | meeting locked — join refused (knock instead) |
| BZ188 | Unprocessable → 422 | invalid arguments (title/window/role/flood-cap/foreign calendar event) |
| BZ189 | Unprocessable → 422 | join-request not decidable (not pending/expired/nonexistent — no oracle on which) |
| BZ190 | Conflict → 409 | mutation against an already-ended meeting |

`TestBZStatusMap`/`TestBZStatusMap_DefaultUnknownIs500` pin the table
verbatim, including that `code`/`type` survive the RFC7807 projection.

## Push (`meet:{uid}` self-channel, members only — guests poll)

`notify_meet_state` fires `meeting_created`/`meeting_state`(live/ended/
locked/unlocked/guest-allowed-changed)/`join_request_created`(hosts+cohosts
only)/`join_request_decided`/`participant_role`/`participant_kicked`/
`captions_state`, payload-shaped like `notify_chat_state`.
**Emission-ordering invariant**: `meeting_admit` inserts the participant row
BEFORE emitting `join_request_decided`; `meeting_end`/
`meeting_participant_event`'s `room_finished` arm both emit the terminal
`meeting_state` push BEFORE mass-stamping `left_at` (the fan-out filters
`WHERE left_at IS NULL`). A denied/expired guest knocker never becomes a
participant and never gets a push — the public poll is the sole completion
signal for that arm.

## The SFU test seam

`RoomController` (`handler.go`) is the interface every revocation path
calls through. `fake_rooms_test.go`'s `fakeRooms` is the hermetic double
every test in this package shares (records every call, `errs` injects a
failure for one named call, `sawCall` asserts a call fired). `livekit.go`'s
`lkRooms` is the real `server-sdk-go/v2` `RoomServiceClient` wrapper,
constructed only when `Config.Configured()`; a nil `RoomController` is
otherwise safe since an unconfigured `Handler` 503s first.

## Huddle chat-bridge membership (V131)

A meeting's chat IS a `chat_channels` row — `meeting_create` either binds a
PRE-EXISTING channel the creator already belongs to (a "huddle,"
`p_chat_channel_id` passed) or provisions a fresh private channel FOR the
meeting. `meetings.chat_channel_provisioned` (DEFAULT `true`) distinguishes
them: `true` = provisioned FOR the meeting (auto-membership on join/admit is
correct); `false` = bound to a pre-existing channel/DM (a joiner who is not
already a member gets the MEETING only, never the channel's history).
**Fixed a real DES-008 violation**: before this flag, org-open join
unconditionally inserted every joiner into `chat_channel_members` on either
path, so any org user joining a huddle launched from a private channel/DM
gained PERMANENT full-history read+write to it, surviving meeting end.
`meeting_join.sql` and `meeting_lobby.sql`'s `meeting_admit` gate their
INSERT on this flag; `meeting_kick`'s bridged-membership DELETE (D13, below)
gates on the SAME flag — insert and delete sides must stay symmetric, since
a provisioned-gated re-insert can never restore access an un-gated delete
stripped. `meeting_get` projects `chatChannelMember` (whether the caller is
actually a member of the bound channel).

**Audit-chain coverage:** `meeting_join`'s provisioned-channel insert,
`meeting_kick`'s D13 DELETE, and `meeting_admit`'s member-knock insert all
write `chat_access_audit` acts (`member.join`/`member.remove`) when
`feature.chat_compliance` is ON — these Meet-side mutations write
`chat_channel_members` directly rather than through
`chat_channel_join`/`chat_member_remove`, so they previously bypassed the
A4a chain entirely (see `mailserver/internal/chat/AGENTS.md`'s "Records
lifecycle (A4a)"). `meeting_admit`'s act uses the admitter as actor / the
admitted knocker as target, gated on `FOUND` so a re-admit writes no
duplicate act. pgTAP: `meet_lobby.pg`'s "meeting_admit audit residual".

## Recording (B2) — state machine, DES-011 extended to Egress

**State machine, reducer-owned** (`meeting_recordings.state`, V129):
`requested → active → stopping → pending_ingest → ready`, `failed`
reachable from anywhere. The reducer commits the fact FIRST — the row (+
`recording_state` banner push) exists BEFORE any Egress API call, so the
consent banner is server state ahead of a single captured frame. Go's
`EgressController` (`egress.go`, the `RoomController` genre) only
translates: `recording.go`'s `startRecording`/`stopRecording` routes are
claims → gates → parse → **reducer** (authority) → **ONE** controller call →
bind.

**Law 1 extended to Egress:** every path out of `active` ends in an Egress
API call — explicit stop → `StopEgress`; `meeting_end` → stop each active
recording then `DeleteRoom`; the `room_finished` webhook mirrors
`meeting_end`'s flip; `reconcileRecordings` belts an SFU-active egress whose
registry row has gone terminal. Machine-checked:
`TestEveryRecordingStopPathStopsEgress`. **Four wedge states**
`reconcileRecordings` sweeps: (1) a stale `requested` row never bound to an
egress (gateway crashed before `StartRoomComposite`) → `failed` after a
grace window; (2) an `active`/bound-`requested` row whose egress vanished
from `ListEgress` with no `egress_ended` fact → a synthetic `egress_ended`;
(3) a `stopping` row still `Active` at the SFU → retried `StopEgress`; (4) a
`stopping` row with `egress_id IS NULL` (three code paths could reach this
without a binding) → `failed` directly, fixed at the origin (`meeting_end`/
`room_finished` only flip BOUND rows to `stopping`) and belted in the
worker. `reconcileRecordings`'s `ListEgress` call runs before its registry
read, so wedge 3 and the belt both age-guard against `requestedGrace` so
neither destructive leg kills a healthy just-started recording.

**`egress_*` webhooks are facts, never authorization** (law 2 extended):
`meeting_recording_event` never raises — unknown room/egress id, a replayed
`egress_ended`, an out-of-order `egress_started` after `egress_ended` are
all silent no-ops. `webhook.go`'s `egressEvents` map forwards
`egress_started`/`egress_updated`/`egress_ended` the same way B1 forwards
`room_finished` — protojson `EgressInfo`, size/duration read from
`fileResults[0]` (int64s arrive as STRINGS).

**The two BZ199 arms + the row-lock law (spec §8.2, verbatim):** "Two
same-transaction reducer arms (D4), both opening with `SELECT … FROM
meetings WHERE id = $1 FOR UPDATE`: start blocked while any guest
**admission** exists (BZ199 — the admission fact, not the webhook-fed
`joined_at`); guest admit blocked while recording (BZ199). Invariant: **no
admitted guest is ever recorded**, fail-closed, race-free — an explicit row
lock, not look-then-act in Go." `FOR UPDATE` (not `FOR NO KEY UPDATE`)
deliberately: it also conflicts with the `FOR KEY SHARE` a participant-row
FK insert takes, so even a future admit path that forgot the explicit lock
still serializes against this. Arm 1: `meeting_recording_start`; arm 2:
`meeting_admit`. BZ200 covers every other recording state-machine conflict
(not live, already recording, none active to stop, bind/ingest against the
wrong state). **D4 — captions never trip BZ199**: captions retain no
content, so the guest⇄recording exclusion does not extend to them.

**Post-end reads use `meeting_attendee_role`, never `meeting_member_role`**
(the latter filters `left_at IS NULL`, and `meeting_end` mass-stamps
`left_at` — DEAD post-end). `meeting_attendee_role` reads the HISTORICAL
row: host/cohost count regardless of `joined_at`; a plain member counts
only with the webhook-fed `joined_at` stamp; `banned_at` excludes; no
`left_at` filter. Gates the `meeting_recordings` SELECT policy,
`recordings[]`/`attendance[]` in `meeting_get`, and the `drive_member_role`
v3 attendance-derivation arm. Guest G4 leaves that role derivation intact and
enforces `allow_download` only at the raw-content choke.

**`staging_key` is OURS** (spec §4): `recording.go`'s `stagingKeyFor`
composes `meet-egress/<recordingId>-<room>.<ext>` and `startRecording`
persists it via `meeting_recording_bind_egress` at bind time — NEVER
derived from `egress_ended`, whose payload only confirms size/duration.
**The ingest attributes to `meetings.owner_user_id`, not `started_by`**: a
cohost who started a recording and was later kicked (kick=ban) would
resolve NULL and strand the ingest in bounded retry → `failed`; the owner is
the stable Drive audit-chain actor. WHO pressed start stays in
`meeting_recordings.started_by`. `ingest_attempts` makes the bounded-retry
state durable across a worker restart (`failed` lands on tick 6). The Drive
node name is suffixed with the recording id (not just the minute-
granularity timestamp) so a same-meeting stop+restart inside the same
minute can't collide.

**The container reality — CORRECTED by the 2026-07-16 live gate, decision
RATIFIED same day and SHIPPED.** The plan's ".webm → VP8+Opus" claim was
disproved live: livekit-server's `fileTypeToOutputType` maps
`DEFAULT_FILETYPE` to `OutputTypeUnknownFile` and never reads the Filepath
extension; `updateOutputType` then resolves an audio+video encoded file
from `AudioVideoFileOutputTypes`, which is `[OutputTypeMP4]` only in v1.13.0
AND upstream `main` (`OutputTypeWebM` exists only for TRACK egress). A
RoomComposite file recording is therefore always **MP4 + H.264(Main) +
AAC** (ffprobe-verified live), and egress rewrites the object key's
extension to `.mp4` — breaking the persisted `.webm` `staging_key` and
404ing every ingest. **Decision: composite recordings ship as MP4/
H.264(Main)+AAC.** `egress.go`'s `buildRoomCompositeRequest` sets `FileType:
livekit.EncodedFileType_MP4` explicitly (never `DEFAULT_FILETYPE` —
`TestBuildRoomCompositeRequestPinsMP4` pins it), `stagingKeyFor` emits
`.mp4`, ingest writes `video/mp4` — live-proven key-stable end-to-end
(start→active→stop→`EGRESS_COMPLETE`→object at the exact staging key).
**D9's no-H.264 intent survives everywhere it was load-bearing: live
SFU-relayed meeting media stays VP9-SVC/VP8/Opus, untouched** — D9 never
governed the composite-file container, only the live media plane. Deferred
seam: a single-source/webinar recording mode via TrackComposite egress (one
video+one audio track, VP9/WebM, transcode-free) fits "record the
presentation," not "record the meeting" — not built.

**The egressBusy surface:** Egress has no `max_concurrent` knob; the real
mechanism is `cpu_cost.room_composite_cpu_cost` (egress.yaml, default 3)
against the container's `CPUQuota` — a second concurrent composite is
refused by egress's own admission control as a twirp
`ResourceExhausted`/`Unavailable`. `egress.go`'s `isEgressBusy` classifies
it; `startRecording` projects it as a distinguishable `egressBusy`
(`https://setjoin.com/problems/meet/egress-busy`) 503, and rolls the banner
back via `bindFailed` either way.

**D11 drain posture:** the three B2 worker legs run unconditionally, gated
only on `egress`/`store` non-nil — never on `feature.meet` or
`feature.meet_recording`. Only `startRecording` (`POST
/meet/{id}/recording`) is toggle-gated — 404 (toggle checked BEFORE the
path id parses) when `feature.meet_recording` OR `feature.drive` is OFF.
`stopRecording` (`DELETE /meet/{id}/recording`), the webhook leg, and all
three worker legs are unconditional.

**Routes:** `POST /meet/{id}/recording` (start, toggle-gated) · `DELETE
/meet/{id}/recording` (stop, unconditional) · `GET /admin/meet/recordings`
(`drive.view`-gated, no toggle — a findability surface regardless of
`feature.meet_recording`'s state). `meeting_get`'s `recordings[]`/
`attendance[]`/`banned[]` (the last one an A/B leftover, item 1 — the
durable re-admit list, same shape/gate as attendance[]) are populated only
for a `meeting_attendee_role` host/cohost.

**BZ199/BZ200 (this package's sole registration site):** BZ199
`recording-guest-exclusion` → 403; BZ200 `recording-conflict` → 409.

**The EgressController seam + fakeEgress:** `egress.go` declares
`EgressController` (`StartRoomComposite`/`StopEgress`/`ListEgress`) — the
`RoomController` genre. `fake_egress_test.go`'s `fakeEgress` mints a unique
egress id per `StartRoomComposite` call. `NewLKEgress` is constructed only
when `meetCfg.Configured() && meetCfg.EgressEnabled` — a nil
`EgressController` is safe since both recording routes 503 first.

## Breakouts (B3a)

**Schema (`V130__meet_qol.sql`):** `meeting_breakouts` (FORCE-RLS via
`meeting_member_role`) + `meeting_participants.breakout_id` (nullable FK,
`ON DELETE SET NULL` — a destroyed breakout row can never strand an
assignment) + `chat_messages.msg_type` widened to add `'question'`. BZ201
(`ClassUnprocessable` → 422) is the breakout anti-oracle lump — every
breakout-reducer failure (bad count, bad target, wrong role, foreign
meeting) raises through the ONE helper `raise_breakout_invalid()`, so every
BZ201 carries byte-identical message+HINT — a probe learns THAT an argument
was invalid, never WHICH one (pinned by `meet_breakouts.pg`).

**Assignment is truth.** `meeting_participants.breakout_id` is the single
source of truth for where a member belongs; LiveKit room membership and the
client's connected `Room` are expected to converge to it, never the
reverse.

**F1 — kick evicts from wherever the target actually is.** `meeting_kick`
returns the target's CURRENT room (main or child); `meetings.go`'s kick
route evicts from THAT room, not just the parent. `TestEveryRevokePathEvicts`
covers this.

**D10 — join always redirects to the live assignment.** `meeting_join.sql`'s
redirect arm names an assigned member's OPEN breakout room, never a
main-room bypass; return-to-main is only the host's act. `meetings.go`'s
join route pre-creates whatever room the grant names with breakout timeouts
(86400/86400, below) whenever it differs from the meeting's own room — a
D10-redirected grant must never get main-room timeouts (300/20), or a GC'd/
never-created child room could self-finish an open breakout out from under
the host.

**D12 — a child room's own `room_finished` is accept-as-close, never a
meeting-state event.** `meeting_participant_event.sql` closes THAT one
breakout row (idempotent) and clears its assignees to main, but never
touches `meetings.ended_at`. `CreateRoomWithTimeouts` params (86400/86400)
make the SFU self-finishing an open breakout a non-event in practice; a
replayed post-end child `room_finished` leaves `closed_at` unchanged
(`TestBreakoutTracerArc`).

**D13 — a kicked participant loses their bridged-chat seat too, but ONLY on
a channel `meeting_create` provisioned FOR the meeting** (gated on
`chat_channel_provisioned`, symmetric with the huddle-membership insert
paths above — see `meet_control.pg`'s huddle-kick block).

**§4.1 webhook rule — do not simplify this away.** A forced move's
`participant_left`/`participant_joined` webhooks can arrive in EITHER
order. `participant_left` stamps `meeting_participants.left_at` ONLY when
the leave event names the room the participant is CURRENTLY assigned to
(per `breakout_id`) — a leave-from-the-room-they-just-left-on-purpose is
silent expected churn, never a fact. Collapsing this to "stamp `left_at` on
any `participant_left`" reads simpler but falsely marks a mid-move
participant as gone. Both orderings are pinned in `meet_breakouts.pg` and
proven at the wire level in `TestBreakoutTracerArc`.

**E5 — one lock, no races (binding, do not simplify away).**
`meeting_breakout_open`/`_assign`/`_close` all open with `SELECT … FROM
meetings WHERE id = p_meeting_id FOR UPDATE` FIRST, serializing the three
per meeting — closes both the open-race on the partial-unique
`meeting_breakouts_open_idx` and the close-all ∥ assign hole. pgTAP proves
the `RowShareLock` still holds in `pg_locks` at transaction end.
**`meeting_captions_set` (below) carries the SAME lock** — without it, two
concurrent starts both read `captionsOn=false` before either writes, and
the caller `Start`s the sidecar twice; the lock serializes the second
caller behind the first's commit so it re-reads `true` and takes the
idempotent-204/NULL-grant path instead (`meet_captions.pg`'s `pg_locks`
proof).

**Go routes (`breakouts.go`) + `CreateRoomWithTimeouts`.** `POST
/meet/{id}/breakouts` (open, the ONLY toggle-gated route — `feature.
meet_breakouts` 404s before the path id parses) · `POST /breakouts/assign`
(evicts via `RemoveParticipant` from the target's CURRENT room, per F1) ·
`POST /breakouts/close` (204, idempotent — drains a `DeleteRoom` loop,
every room attempted even if an earlier one fails) · `POST /breakouts/join`
→ `{token, wsPath, expiresAt, recordingActive}` (**D11**:
`CreateRoomWithTimeouts` runs BEFORE `MintToken` on every call,
UNCONDITIONALLY — assign/close/join are never toggle-gated). `endMeeting`
drains EVERY `meeting_breakouts` row for the meeting and `DeleteRoom`s each
(law 1: ending drops everyone, every room) — belt only, since the reducer
already closed every open breakout in the same txn. `breakouts_test.go`
proves the toggle-gate, pre-create-every-child, both wire proofs (F1, D11
ordering), and a main-room breakout-join grant's `recordingActive` staying
hard `false` for a child grant (breakouts are never recorded).

**The two worker arms (`worker_breakouts.go`)**, both inside the D11/B3
gating posture (never gated on `feature.meet_breakouts` itself):
- **`gcClosedBreakoutRooms`** — a child room whose OWN row closed within
  24h, or whose PARENT meeting ended within 24h, and the SFU still lists
  it, gets `DeleteRoom` retried (the `deleteEndedButLiveRooms` shape one
  level down).
- **`reconcileBreakoutPresence`** — the assignment↔presence healer, scoped
  to live meetings with ≥1 open breakout and MEMBER-role participants only
  (host/cohost roam by design; guests are never assignable). Present in the
  wrong room → `RemoveParticipant`; present in the assigned room → no-op;
  absent from every room → a one-tick grace via an in-memory
  `absentSince` map (`// ponytail: in-memory — a worker restart extends the
  grace, never fires it early; move to a DB column if multi-instance
  workers ever exist`), second consecutive absent tick stamps `left_at`.
  **`sweepStaleAbsentEntries`** (called first, before the early return):
  every tick, any `absentSince` entry whose meeting fell out of the
  candidate set gets ONE parent-room `ListParticipants` check and is
  settled either way — closes the phantom-participant hole where a host
  closing breakouts before the grace's second tick used to leave an
  assignee's `left_at` unstamped forever, blocking `gcLostWebhooks`. A
  transient error on the settle-check RETAINS the entry for retry next tick
  (deleting on error would re-open the hole for that identity on every
  hiccup) — the one exception is `pgx.ErrNoRows` on the `meetings` lookup
  (definitively gone, nothing to retry against).

**Integration proof.** `TestBreakoutTracerArc` composes every piece above
into one realistic session: open at the wire → auto-assign with both
members' own pushes → a forced move evicting the RIGHT current room →
breakouts/join → both webhook orderings on two different members → mid-
assignment join redirect → kick-in-breakout (F1+D13+BZ186 refused rejoin) →
a guest-target BZ201 anti-oracle → Q&A through `internal/chat`'s real route
(`question` `msg_type` lands correctly; a bare `poll` send still 400s) →
close-all → reopen → end with breakouts still open (`DeleteRoom` parent AND
child) → a replayed post-end child `room_finished` no-op.

**Honesty note — B3a shipped a DORMANT captions rail before B3b existed.**
The `cc` data-channel envelope arm, `captionSegments`, and
`attestedCcIdentity` (the F8 attested-identity fail-closed contract — an
empty identity matches nothing, so captions fail closed) landed in
`$lib/meet/room.svelte.ts`, alongside the V130 `feature.meet_captions` seed
(OFF), with no producer until B3b's `asrbot/` sidecar existed.

Webmail-only Task 6–9 work (breakout store-layer plumbing, BreakoutsPanel +
forced-move choreography, the Poll button + Q&A tab riding the existing
bridged chat with zero new reducer/BZ/table, and the Excalidraw whiteboard —
client-only, no server/reducer/toggle surface, DN6) is documented in
`mailserver/webmail/AGENTS.md`'s Meet section, not here.

## Captions (B3b)

**`meeting_captions_set(p_user_id, p_meeting_id, p_on) RETURNS jsonb`**
(`meeting_control.sql`, the `meeting_set_guest_allowed` shape) — host/cohost
only (BZ186); an ended meeting (BZ190). **IDEMPOTENT (D8):** already in the
requested state is a silent no-op — no error, no push, `RETURNS NULL` — so a
flip-flop double-click never double-pushes or re-stamps `captionsSince`.

- **OFF→ON** stamps `captionsOn=true` AND `captionsSince=now()` (**F5** —
  the durable start-grace stamp the worker's reconcile arm reads so a
  restart can never mistake a Start still in flight for a crashed bot),
  pushes `captions_state {on:true, botIdentity:'cc:'||meetingId}`, and
  **RETURNS the bot's LiveKit grant spec** — the grant-composition monopoly
  stays reducer-side (**D6**, the same law `meeting_join.sql`/
  `meeting_recording.sql` follow):
  ```json
  {"room":"<meetings.room_name>","identity":"cc:42","name":"Captions","role":"bot",
   "canPublish":false,"canSubscribe":true,"canPublishData":true,
   "roomAdmin":false,"hidden":false,"ttlSeconds":14400,"recordingActive":false}
  ```
  The bot cannot publish audio/video, only listen + emit data.
  **`hidden:false` (2026-07-16, reverses the B3 plan's original `hidden:
  true`):** the live gate A/B-proved that livekit-server v1.13.3 forwards a
  HIDDEN participant's data packets with an EMPTY `participant_identity`
  (a visible sender's identity arrives intact, the hidden bot's arrives
  empty) — with `hidden:true`, webmail's F8 fail-closed attestation
  dropped every `cc` frame and captions rendered nowhere despite a fully
  working pipeline. The bot now joins **unhidden**; `cc:{meetingId}` stays
  the sole reducer/`MintToken`-minted identity (D6 unchanged — attestation
  security is unaffected, only the identity LiveKit now actually forwards),
  and webmail filters `cc:`-prefixed identities out of the
  roster/gallery/participant-count at the one choke point
  (`room.svelte.ts`'s `#syncParticipants`). Watch-item: if a future LiveKit
  upstream forwards a hidden participant's data-packet identity correctly,
  `hidden:true` + a server-side roster filter could replace this
  client-side one.
- **ON→OFF** clears `captionsOn` only (`captionsSince` is left as-is — the
  next OFF→ON flip overwrites it fresh), pushes
  `{on:false, botIdentity:'cc:'||meetingId}`, `RETURNS NULL`.
- **D4 — no BZ199 interaction.** Captions retain no content anywhere (no
  transcript persistence, no storage write), so the guest⇄recording
  exclusion invariant does not extend to them (`meet_captions.pg`).
- **`meeting_get` gains `captionsEnabled`** (the toggle) **and
  `captionsOn`** (the live flag). **`meeting_join_request_poll` gains
  `captionsOn` on BOTH admitted-grant returns** (guest `g:` and
  member-knock `u:`) — **DN3**: the indicator is visible to guests too, not
  gated behind membership. **Both admitted arms ALSO gain `ccIdentity:
  'cc:' || meetingId`**, unconditional on `captionsOn` — the guest/knock
  page can attest `cc` frames regardless of whether captions happen to be
  live at admit time; consumed webmail-side via `MeetRoom`'s
  `attestedCcIdentity` constructor arg (the guest captions attestation
  ceiling this fixes is closed end-to-end).
- **`notify_meet_state` gains `captions_state`** — an ordinary all-live-
  members fan-out, every member renders the identical chip.

pgTAP: `mailserver/sql/tests/meet_captions.pg` (33 assertions).

**`CaptionsController` (`captions.go`)** — the third seam of the
`RoomController`/`EgressController` family:

```go
type CaptionsController interface {
    Start(ctx context.Context, room, token string) error
    Stop(ctx context.Context, room string) error
    Status(ctx context.Context) ([]string, error)
}
```

- **`POST /meet/{id}/captions`** — `feature.meet_captions` 404s BEFORE the
  path id parses → `h.captions == nil` → 503 → the reducer commits the fact
  + push FIRST (the B2 recording-banner discipline extended to captions) →
  a `NULL` grant (D8: already on) → 204, zero `Start` calls → otherwise
  `MintToken` translates the reducer-composed bot grant and `captions.Start`
  binds the session. A `Start` failure **rolls the chip back**
  (`meeting_captions_set(uid, id, false)` — the chip must never lie about a
  session that never started) before responding: `errCaptionsBusy` (the
  real client's 409-from-asrbot mapping) projects as `captionsBusy` 503;
  any other error is a generic 502.
- **`DELETE /meet/{id}/captions`** — UNCONDITIONAL, no toggle gate (the
  `stopRecording` precedent: a session started before a toggle flip OFF
  must still be stoppable). **The reducer flip runs FIRST, unconditionally,
  BEFORE the `h.captions == nil` check** — idempotent either way (D8),
  always commits; only THEN does a nil controller short-circuit to 204.
  (Before this ordering fix, a box with `ASR_URL` deconfigured could never
  turn a `captionsOn=true` row off through this route at all — the same
  wedge class B2's `reconcileRecordingsDBOnly` fixed for recordings.) Not a
  member of `TestEveryRevokePathEvicts`'s table (a captions Stop is a
  sidecar instruction, not a `RoomController` eviction) — pinned directly
  by `TestStopCaptions`. Ending a meeting still evicts the bot with
  everyone else for free (same room, existing `DeleteRoom`/
  `RemoveParticipant` calls).
- **Join envelope**: `"captionsConfigured": h.captions != nil` rides beside
  `recordingActive` — distinct from `meeting_get`'s `captionsEnabled` (the
  toggle) and `captionsOn` (the live flag).
- **`reconcileCaptions` (`worker_captions.go`)**, inside the SAME
  `feature.meet && Configured()` gated section, never gated on
  `feature.meet_captions` — **bidirectional (F5)**. A nil controller no
  longer no-ops the whole function: leg (a) still runs with an empty `live`
  set (meaning "no session is live anywhere," true by construction with no
  controller), so a stale `captionsOn=true` row still converges to OFF on a
  box with no ASR sidecar at all; leg (b) is naturally a no-op there.
  - **Leg (a) `reconcileCaptionsCrashed`**: a `captionsOn=true` meeting
    whose room `Status()` no longer lists gets the flag flipped off
    directly (worker-plane) plus the same `captions_state{on:false}` push
    — but only once `captionsSince` is older than one worker interval
    (F5's grace, so a Start still racing this tick's snapshot isn't killed).
  - **Leg (b) `reconcileCaptionsOrphaned`**: every room `Status()` reports
    live whose meeting reads `captionsOn=false` or `state='ended'` gets a
    retried `Stop` unconditionally; an ended meeting also gets a
    `DeleteRoom` backstop (grace-guarded the same way).
- **`asr` health probe** — a round-trip through `Status()`, registered only
  when `ASR_URL` is set. Not a route.
- **The real `CaptionsController`** (`httpCaptionsClient`) is a ~40-line
  loopback `net/http` client to the asrbot control API (`ASR_URL`, default
  `http://127.0.0.1:7890`): `POST /start {room,token}` → 200/409→
  `errCaptionsBusy`; `POST /stop {room}` → 200 (idempotent); `GET /status`
  → `{"rooms":[...]}`. **Every request carries `Authorization: Bearer
  <token>`** — asrbot's control API requires it on all three routes, since
  loopback TCP alone carries no peer identity. Token comes from
  `Config.ASRToken` (env `ASR_TOKEN`, law-3'd alongside
  `LIVEKIT_API_SECRET`); an empty token sends no header rather than a
  malformed `Bearer ` (a deploy misconfiguration surfaces as asrbot's own
  401, never a Go panic). Proven hermetically:
  `internal/meet/captions_client_test.go` against a fake `httptest.Server`.

Coverage: `captions_test.go` (routes, DB-gated), `captions_client_test.go`
(bearer-token header, hermetic), `fake_captions_test.go` (the `fakeCaptions`
double), `worker_test.go`'s
`TestWorkerReconcileCaptions{CrashedBot,OrphanedSession,IgnoresToggleOff}`,
and `TestCaptionsTracerArc` (`tracer_integration_test.go`): one continuous
run over 5 meetings proving start (fact precedes sidecar call) → the push
carries the attested `cc:{meetingId}` botIdentity → a member join envelope
carries `captionsConfigured`+`captionsOn` → a guest knock/admit while
captions are on SUCCEEDS (DN3) and the admitted poll carries `captionsOn` →
busy on a second meeting → 503 + rollback push → explicit off → `Stop`
recorded → a third meeting ends with captions still on (`DeleteRoom` evicts
the bot for free; the worker's orphan leg then retries `Stop` for the
still-reported session) → D11-drain on a fourth meeting (toggle-off
Handler): `DELETE` still stops, `POST` now 404s, the reconcile arm
converges regardless → reconcile leg (a) on a fifth meeting: flag on, bot
silent, stale `captionsSince` → flag flips off + push.

**The live F14 arm** (`livekit_live_smoke_test.go`'s `TestLiveSFUSmoke`,
`MEET_LIVE_SFU=1`-gated): a second, adversarial re-verification that the
pinned self-hosted v1.13.3 server does NOT implement
`RoomService.MoveParticipant` (Cloud-only) — RUN live against the official
`livekit/livekit-server:v1.13.3` Docker image; `MoveParticipant` errored as
expected, confirming D1's premise the breakout evict+re-mint choreography
rests on.

Deploy-side wiring (`setjoin-asr-bot.service` + the pinned `setjoin-funasr`
runtime container, both `MEET_CAPTIONS_ENABLED`-conditional in
`install.sh`) is detailed in `mailserver/AGENTS.md`'s deploy section and
`asrbot/AGENTS.md`'s Ownership section.

## Presentation contracts (M0/M1, MEET plan)

`internal/meet/presentation` (new package) freezes the M0/M1 contract layer
of [the MEET plan](retired-docs:superpowers/plans/2026-08-25-meet-document-
presentation-semantic-recording.md): the `meet-pages-v1` protected
paged-rendition profile (tenant-scoped key tuple, bounded manifest, relative
short-lived asset refs only — no object-store URLs, presenter-gated notes),
the versioned `t:'presentation'` event envelope (14000-byte wire bound,
page-change <1KiB, closed kind vocabulary, receive-side
reject/noop/invalidate-hint classification), the durable checkpoint state
machine (ENDED/REVOKED→ACTIVE illegal by construction), the `.sjrec` logical
package layout with embedded/retained/absent/expired child states and the
ACTIVE→DELETE_PENDING→{HELD_COMPLETE,HELD_PARTIAL,DELETED} reducer-atomic
boundary (HELD_PARTIAL ineligible for restore in V1), the typed
recording-policy matrix (`local_preferred`/`server_only`/`local_only`/
`disabled` × surface), the closed named-failure-code registry, the qualified
provider identity pins with fail-closed evidence-bound admission and
explicit-rebind-only requalification (M1a — never a silent provider swap),
the stale-subscription cleanup contract whose only reaping scope is the
subscription itself — it cannot delete admitted recordings/rendition
references or strand accepted work (M1b), and the Drive-side source
boundary (SourceRef pins immutable Drive version identity; page capabilities
are view-only by construction with no original/notes/search/future-version
field; `ErrMeetNeverWopiHost`). All pure data and functions — no route,
worker, reducer, or table; behavior admits nothing until
`feature.meet_document_presentation`/`feature.meet_semantic_recording`/
`feature.meet_local_recording` (all DEFAULT OFF, V264 registry projection,
drain-on-disable operator semantics; presentation additionally requires
`feature.drive`). The webmail mirror of the envelope contract lives in
`webmail/src/lib/meet/presentation.ts` (+ the room.svelte.ts receive
switch/publish seam); deploycatalog gains the fail-closed qualified
rendition-artifact section (`rendition_artifact.go`, zero admitted, unit
inventory untouched — no second installer, no Manifest v2). M2+ wires the
gated start paths against these types.

**M0 producer/format corpus freeze (2026-09-19, branch `codex/old5-wave5`).**
`docs/verification/meet-m0-corpus.json` (corpusId `meet-m0-corpus`) freezes the
M0 corpus: 10 byte-deterministic synthetic-seed fixtures under
`internal/meet/presentation/testdata/corpus/` — small/medium/500-page decks
(manifest <256 KiB @500 pages cell), a 9×3 MiB asset-heavy deck whose 28.3 MiB
aggregate crosses the 24 MiB encoded-client-assets cap so prefetch bounding is
observable, a 20-page annotation-heavy reference-deck shape (800 annotations;
envelope/payload bounds), pptx/docx/xlsx/odp format-coverage seeds, and a
5000-cue caption track (semantic-replay streaming cell) — regenerated and
digest-verified by `scripts/gen-meet-m0-corpus.sh` (bash + python3 stdlib, no
network; `verify` mode re-derives every pinned sha256). Producer-pinned
entries (LibreOffice headless per owner decision D3) are acquisition-pending:
soffice is not installed on this Mac, no engine version is invented, and
`corpus_manifest.go` refuses any bytes parked under a pinned name before
acquisition (fabrication guard) while re-verifying digest/size/intrinsic
count for everything frozen. The manifest also carries the R2 measurement
protocol bindings (20 randomized pairs, attributed transfer accounting,
one-sided bounds; the ≥80% attributed-transfer-reduction GA cell) and the
qualification-readiness note — the §D3 qualification run consumes this
corpus, so the freeze precedes it. Verification: `go test
./internal/meet/presentation -run TestM0Corpus`.

## Presentation session (M2, MEET plan)

M2 wires the gated start paths against the frozen M0/M1 contracts — the
reducer-owned presentation session (V265 `sql/dbschema/V265__meet_presentation.sql`,
`sql/reducers/meeting_presentation.sql`; SQL-side contract detail lives in
`mailserver/sql/DOX.md`'s Meet section). The Go surface is deliberately thin
(`presentation.go`):

- **Routes.** `POST /meet/{id}/presentation` (prepare: nodeId+versionId+
  manifestDigest), then per-session verbs under
  `/meet/{id}/presentation/{pid}/…`: `ready`, `start`, `page`
  (presenterGeneration+checkpointSeq+pageIndex), `presenter`
  (targetParticipantId, `takeover` boolean), `source`, `degrade`, `recover`,
  `end`, `revoke`, and `GET …/checkpoint`. Every mutating response carries
  the committed fact plus the versioned `t:'presentation'` frame built
  THROUGH `internal/meet/presentation`'s `NewEnvelope`+`Encode` — the M0
  types are the only encoder; an over-budget/shape-invalid frame is a
  bounded diagnostic (field omitted, committed state stays committed,
  checkpoint refresh converges), never an error.
- **Flag posture (D11 genre).** New-intent verbs (prepare/ready/start/
  page/presenter/source/degrade/recover) require
  `feature.meet_document_presentation` AND `feature.drive` and 404
  otherwise — the surface is INERT when OFF. Drain verbs (end/revoke/
  checkpoint read) are never flag-gated: DisableDrain means a flip never
  strands an admitted session and clients keep converging onto committed
  checkpoints (recording's stop-route posture verbatim).
- **Authority & fences.** All four fence axes live in the reducer
  (participant / verb-specific authority incl. Drive `preview` via
  `drive_runtime_has_node_capability` / lifecycle / presenter-generation +
  checkpoint-sequence). BZ272–BZ277 are registered in `reducererr.codeClass`
  (contract matrix) and this package's `bzSlug` (BZ274 is deliberately its
  own `stale-presenter-generation` slug so clients branch to the
  refresh-checkpoint rescue without string-matching Detail). The
  annotation reservation (`meeting_presentation_annotation_commit`) fails
  closed BZ277 until M4 admission.
- **Checkpoint read.** `GET …/checkpoint` enforces the M1 CheckpointRefresher
  budget's server half — 5 refreshes/s sustained, burst 2, per user, in
  memory — refusing excess with 429 `checkpointRefreshThrottled` and a
  1–30s-clamped `Retry-After`, exactly what the client's
  `throttledRefreshBackoffMs` parses. The projection itself is
  `meeting_attendee_role`-scoped (historical attendees converge; absent
  callers get the indistinguishable BZ272).
- **Push facts.** `notify_meet_state('presentation_state', …)` fans the
  committed {presentationId, status, checkpointSeq, presenterGeneration,
  pageIndex, manifestGeneration} to every live member; a fresh checkpointSeq
  is exactly the bounded invalidation hint the client admits — never a state
  promotion (M0 receive contract; the webmail seam consumer is
  `webmail/src/lib/meet/presentationCheckpoint.ts`, M3 owns the UI wiring).
- **Out of scope here:** rendition production/worker (M1 wiring), page-asset
  serving and page capabilities at the HTTP layer (M3), durable annotation
  snapshots and `.sjrec` (M4+). Meet never becomes a WOPI host and never
  writes `blobs.ref_count`.

## Semantic recording (M4 slice 1, MEET plan)

The implementable CONTRACT + DRAIN slice of [M4](retired-docs:superpowers/
plans/2026-08-25-meet-document-presentation-semantic-recording.md): no HTTP
routes, no flag change (`feature.meet_semantic_recording` stays DEFAULT OFF,
V264), all new user-visible behavior OFF by default. Contract types in
`internal/meet/presentation/` (same package as M0/M1):

- **`sjrec.go`** — the versioned `.sjrec` logical manifest
  (`sjrec-v1`): package state CARRIES lifecycle.go's frozen machine (never
  restated); per-child stable references (`StableRef`: package-relative
  path + sha256 + size — retained recording children are NOT short-lived
  fetches but ALSO never object-store URLs); annotation snapshots bind to
  their exact presentation checkpoint, captions bind by language+reference
  (the captions.go genre); the optional `LegacyVideoRef` records — never
  copies — a retained B2 MP4 (a companion index, no second recorder, no
  combined export); `IntegrityIndex` (`integrity/sha256.json`) names EVERY
  missing/mismatched object (integrityMismatch). Lifecycle truth at the
  boundary: DELETED advertises no live children; HELD_PARTIAL requires a
  released required child; HELD_COMPLETE forbids one (V1 restore rule).
- **`timeline.go`** — the ordered event writer/parser (`sjrec-timeline-v1`
  NDJSON grammar): closed vocabulary, monotone sequences, undeclared holes
  fail closed, `timeline.gap` is the ONLY way sequences go missing and a
  declared gap can never be filled afterward (never-invent-events);
  16 KiB per-record and 100k-record bounds; `VerifyTimelineIntegrity` is
  the replay-side integrity gate. Reserved `annotation.*` kinds are NOT in
  the vocabulary — the BZ277 reservation holds at the timeline too.
- **`segment.go`** — the segment binding contract: verified REQUIRES
  digest+size+actual MIME/codec/container+acknowledgement; interrupted/
  failed name why they stopped and are truthful partials; duplicate acks
  are idempotent no-ops; lost acks never promote bytes; `ComputeCoverage`
  merges adjacent verified runs, fails closed on overlapping verified
  segments (duplicate media), and returns gaps as first-class facts.
- **`acquisition.go`** — the server-audio adapter, FAIL-CLOSED: the
  `AudioAcquirer` seam + typed `CaptureProfile` classification
  (qualified/evidence_pending/unsupported). The ONLY implementation is
  `FailClosedAcquirer` (Start always refuses with
  `ErrAudioPathEvidencePending`). The plan gates the public recording
  contract on real pinned service evidence (MP-AUDIO-001 unrun: current B2
  RoomComposite MP4 does not prove an audio-only/WebM path); the version-
  pin rule (`RequalificationRequired`/`AdmitCaptureProfile`) re-qualifies
  the pinned profile on ANY producer/Egress/container/codec change before
  new capture — no silent provider swap. Wave-1 B4 (test-contract row 32,
  2026-09-23): a qualified profile's `EvidenceRef` must be digest-bearing
  (`<record-path>#sha256=<64 hex>` of the exact receipt bytes; pending/
  unsupported profiles still carry NO evidence) — a plain-string reference
  is not a verifiable pin and fails closed. The receipt comes from
  `scripts/run-meet-audio-evidence-harness.sh` (receipt-only: it never
  promotes or pins a profile — no promotion path exists; missing pinned
  services exit non-zero with an `evidence_pending` receipt; never in a
  required CI lane). Qualification lands as an
  implementation of the seam (or `Worker.ExportComposer`), never a flag
  flip.
- **`export.go`** — idempotent MP4 export receipts: identity =
  (recording, generation); `PlanExport` computes confirmed bounds and
  explicit exclusions from verified coverage and REFUSES a pages-only
  package (no verified audio ⇒ nothing exportable — never a fabricated
  video); `ValidateComposePlan` refuses bounds drift with reselection
  (R5.4), never silent clipping; a ready receipt replays unchanged.
- **`indexing.go`** — policy-bounded text/event indexing bound to
  policy.go's matrix: disabled → nothing; local_only → no central index;
  note_text refused in EVERY policy (protected class); media transcripts
  admit only over verified segments; page/caption/event text requires the
  rendition-level policy-permitted text reference. Exclusions are named,
  not swallowed.
- **`replay.go`** — the deterministic replay model: entries from verified
  coverage + explicit gap stops (bounds announced; next-available offered
  only when one exists), named unavailable segments, visible presentation
  version links and caption tracks, `LocalOnlyProvenance`, fenced
  (delete/hold/deleted) packages replays nothing but explain themselves,
  `PositionAt`/`ErrSeekIntoGap`/`ErrSeekPastEnd` honest seek states.

SQL side (owned in `mailserver/sql/DOX.md`'s Meet section): V266 tables +
`meeting_semantic_recording.sql` reducers (BZ278–BZ281), the shared
`meeting_recording_active` predicate extended to count live semantic rows
(one banner truth, single-primary-mode both directions, BZ199 arm shared),
and `meeting_end`'s same-txn stop arm. Worker legs in
`worker_semantic.go`: `sweepSemanticPackages` (delete sweep through the
owning reducers — release receipts, hold fences, finalize requires the
exhausted set) and `drainSemanticExports` (bounded composition queue; the
`ExportComposer` seam is deliberately nil — every claimed export completes
`exportCompositionFailed` with the semantic source retained). Both legs
share the B2 D11 drain posture: pool-only, outside every feature gate.
Client mirror: `webmail/src/lib/meet/semanticReplay.ts` +
`components/meet/SemanticReplayPanel.svelte` (R5.4 honest states).
Named follow-ups: audio-path qualification (MP-AUDIO-001), export
composer + Drive ingest, Drive History events (see the completion-gates
section for the exact linkage point).

## Annotation admission + semantic read routes (M4 completion gates, MEET plan)

The M4 named gaps closed on top of slice 1: the durable annotation commit
(the BZ277 flip) and the replay/package read routes. No new feature toggle —
annotation commits are new-intent verbs riding
`feature.meet_document_presentation` (+`feature.drive`); every read is
committed-state drain (D11) and answers with any flag OFF.

- **V267** (`sql/dbschema/V267__meet_annotation_admission.sql`): widens the
  V265 events kind CHECK to admit exactly `annotation.committed`/
  `annotation.cleared` — a COMMITTED annotation is admitted; unknown
  annotation kinds still have no durable home (the reservation narrowed to
  admitted-path semantics, it was not removed) — and adds the
  `meeting_presentation_annotations` ledger: the exact serialized snapshot
  bytes bound to (presentation, checkpoint seq, presenter generation), the
  `.sjrec` StableRef path (`annotations/p<id>-s<seq>.json`) REDUCER-derived
  (never request-owned), and an in-database content-identity CHECK
  (`sha256`/`byte_size` are derived from the stored bytes via
  `sha256(convert_to(...))`, so a row can never claim a digest its bytes do
  not hash to). FORCE RLS: the read backstop scopes through
  `meeting_attendee_role` (retained material — the post-end gate), writes
  through the participant backstop (V265 posture); COVERED rows in both
  rls allowlists (`meet_annotation_rls.pg`).
- **Reducer** (`meeting_presentation.sql`):
  `meeting_presentation_annotation_commit` is the ONE admitting writer —
  the four-axis fence in the file's documented order (BZ272 anti-oracle →
  BZ273 presenter-scope: the plan's security table has no attendee durable
  verb and M3 attendee ink stays ephemeral → BZ274 generation+sequence →
  BZ275 ACTIVE-only), then the admitted-shape gate: a well-formed snapshot
  (1..16384 bytes — the stored-object bound; larger snapshots have no home
  and need the separately designed reference-storage contract, never
  fragmentation) whose digest+size are re-derived in-database, or a clear.
  Un-admitted shapes refuse BZ277. Commit is atomic: ledger row +
  `annotation_snapshot_ref` + the durable event (payload = the bounded
  reference triple) + state bump + push fact; the returned fact carries an
  `annotation` rider. `meeting_presentation_annotation_read` is the
  authorized bounded reference/read path (HISTORICAL attendee gate;
  truthful `snapshot: null` when none exists). The checkpoint read gains
  `annotationSnapshotRef`.
- **Contract layer** (`presentation/annotation.go` + `envelope.go` +
  `timeline.go`): `DurableCommittable` flips to true for the annotation
  kinds, and their payloads become closed contracts validated in BOTH
  directions (`validateAnnotationEvent`; commit = the bounded reference
  triple, clear = no payload). The envelope NEVER carries snapshot bytes —
  the 14000-byte wire bound holds by construction. The timeline vocabulary
  admits `annotation.*` ONLY as committed-binding records (presentation id
  + checkpoint seq +, for commits, the snapshot StableRef); anything else
  fails closed at writer and parser.
- **Routes** (`annotation.go`, `semantic.go`): `POST
  /meet/{id}/presentation/{pid}/annotation` (new-intent, flag-gated 404;
  derives sha256+size from the exact received bytes — the reducer
  re-derives them in-database and refuses a mismatch) and `GET …/annotation`
  (committed read, not flag-gated) · `GET /meet/{id}/semantic/{rid}/package`
  (the EXISTING `meeting_semantic_package_read`) and `GET
  …/semantic/{rid}/replay` (NEW `meeting_semantic_replay_read`: the package
  projection composed with presentation version links — never hidden, the
  session's own status, never a fabricated child-state claim — committed
  annotation references, the wall/media-aligned fact rail (`mediaMs`
  against the earliest verified segment's wall start; −1 ⇒ fact rail), and
  captions as an EXPLICITLY empty list until their binding producer lands).
  All reads: HISTORICAL-attendee scoped, stranger = the indistinguishable
  BZ278/409. openapi-pending entries + route-inventory pins added.
- **Webmail**: `presentation.ts` flips `RESERVED_UNCOMMITTABLE` and
  validates annotation payloads both directions (wire-byte semantics kept);
  `annotationSnapshots.ts` (canonical serialization + async sha256 +
  byte bound — identity derived, never claimed);
  `presentationApi.ts` standalone transports (deliberately NOT extending
  the M2/M3 `PresentationApi` interface — its fakes stay untouched);
  `semanticReplay.ts` gains the optional feed riders + the deterministic
  `replayFactRail`; the panel renders version links, annotation refs,
  captions and the fact rail with i18n keys in en/de/zh.

**Drive History events — named follow-up with its exact linkage point.**
The M4 "recording/rendition lifecycle history events" stay a follow-up:
the only Drive-side history surfaces are `drive_audit_log` (V114 §9.3 — a
per-space TAMPER-EVIDENT CHAIN with the checksum in `after_state`,
maintained exclusively by Drive's own reducers) and the `drive_changes`
feed. A meet-side writer would have to append into Drive's chain, which is
exactly the second-coordinator move the plan forbids, and the M1
rendition-pipeline "history facts" emitter (the plan's M1 bullet that owns
history facts) has not landed. When it lands, the recording lifecycle facts
(`recording.started/stopped/revoked`, rendition bound/expired) attach
THERE — Meet contributes ordered human events, Drive History stays the sole
timeline owner.

**Landed (V269, the Drive-lane shape):** the emitter is the DRIVE-side
ingest `drive_meet_history_emit` (reducers/drive_meet_history_emit.sql) —
it appends through `drive_access_audit` and records the idempotent receipt
in `drive_meet_history_events` (V269, FORCE RLS, member-scoped read,
reducer-only writes; UNIQUE (source_kind, source_id) is the
no-second-chain-entry belt). Meet's only involvement is the thin worker leg
(`internal/meet/drive_history_emitter.go`, `emitMeetDriveHistory` in the
shared Worker's drain posture): it drives exactly THREE lifecycle points —
package stopped (`recording.stopped`, attachable only through a ready
export; a package that never exported is receipted `absent`, never
synthesized), annotation committed (`annotation.committed`), presentation
pinned (`presentation.pinned`). Entries surface through the existing
`drive_file_history_query` audit source. Observational restraint: no M0–M4
state machine reads the receipts, no backfill, no second coordinator.
pgTAP: `drive_meet_history.pg` (chain order/verify, refusal codes BZ272/
BZ276, absent arm, cross-tenant RLS denial); Go:
`drive_history_emitter_test.go`. `recording.started`/`revoked` and
rendition-bound/expired facts beyond these three remain unemitted (the
frozen contract admits exactly the three points).

pgTAP: `meet_annotation_admission.pg` (fences → admission → commit/clear
arc → bounded read → lifecycle), `meet_annotation_rls.pg` (FORCE proof as
setjoin_app), §8 of `meet_presentation.pg` (the admitted CHECK widening),
§6 of `meet_semantic_recording.pg` (the annotations member seed + the
replay read). Go: `presentation/annotation_test.go`,
`annotation` cases in `presentation_test.go` (wire), `presentationApi.
annotation.test.ts` + panel/feed tests (webmail).

## Local capture lease + truthful registration (M5 slice 2, MEET plan)

The server half of the M5 slice-1 Electron substrate
(`clients/desktop/electron/src/meet/`, whose `localCapture.ts` composition
is the client wiring): the reducer capture lease, the heartbeats, the
revocation/meeting-end stop, expiry, and the truthful local-package
registration — `feature.meet_local_recording` stays DEFAULT OFF (V264);
every route 404s while it is OFF and the client substrate ships inert.

- **V268** (`sql/dbschema/V268__meet_local_capture.sql`):
  `meeting_local_capture_leases` — ONE live lease per (meeting, device)
  (partial unique belt) plus one live lease per recording; each lease binds
  the live `local_registered` `meeting_semantic_recordings` row (the
  reducer-commit-before-capture invariant: recording + banner commit BEFORE
  the lease exists), the version-pinned producer identity, the captured
  surfaces, and the client-proposed heartbeat cadence server-clamped to
  5..60 s with TTL = 3 × cadence (the server may tighten, never loosen the
  local stall stop). Lifecycle `live → stopped
  (user_stop|revoked|meeting_ended|device_stopped|recording_ended) |
  expired`; a terminal lease names WHY and WHEN. §B adds the local-
  registration receipt columns on `meeting_semantic_recordings`
  (`local_descriptor_digest` sha256-CHECKed + `registered_at`, refused on
  any non-local capture mode). §C FORCE RLS, the V266 §E posture verbatim;
  COVERED rows in both RLS allowlists.
- **Reducers** (`meeting_local_capture.sql`): USER plane
  `meeting_local_capture_lease_acquire` (the reused M4 start chain —
  BZ185/BZ186/BZ190/BZ199/BZ278 — then the lease; idempotent reattach for
  the same (meeting, device) whose recording still lives — crash recovery,
  never a twin — and a fresh generation after a stop so stale heartbeats
  fail closed), `_lease_heartbeat` (monotonic seq: exact replay refreshes
  as the lost-response retry, regression is BZ283; stale generation BZ282;
  a foreign caller gets the indistinguishable BZ282; the final
  `captureState:'stopped'` frame and the lazy expiry arm answer the typed
  stop FACT — revocation/meeting-end/expiry — never a refreshed deadline),
  `_lease_stop` (owner-or-host floor; lease + recording stop in the SAME
  txn so the lease and the banner truth can never disagree), and
  `meeting_local_capture_register` (post-stop by nature: the HISTORICAL
  attendee floor, anti-oracle authority BEFORE descriptor shape; the
  sealed `sjrec-local-v1` descriptor's segments bind through the EXISTING
  `meeting_semantic_segment_ingest` — the same truthful-promotion rules,
  the same BZ279 duplicate-media belt, the same idempotent re-entry, no
  second segment writer — and the receipt (sealed digest + registered_at)
  lands on the local_only row; the registration IS the acknowledgement,
  and a conflicting re-registration is BZ284 because settled history never
  rewrites). WORKER plane `_lease_expire` (SECURITY DEFINER +
  `apply_worker_ownership`, bounded, SKIP LOCKED — converges expired live
  leases and stops their recordings truthfully; unregistered segments stay
  unregistered, never synthesized). `meeting_control.sql`'s `meeting_end`
  gains the M5 same-txn arm: a live lease never outlives its meeting (the
  V266 arm's shape; the recording stop rides the existing M4 arm).
- **Routes** (`internal/meet/localcapture.go` — NEW file; lobby/annotation/
  presentation/semantic files untouched): `POST /meet/{id}/local/lease`,
  `POST /meet/{id}/local/{rid}/heartbeat|stop|register` — ALL new intent,
  flag-gated on `feature.meet_local_recording` (404 = inert). The
  registration route re-validates the descriptor with the SAME rules as
  `presentation/segment.go` — every segment routes through
  `presentation.MediaSegment.Validate`, coverage through
  `presentation.ComputeCoverage` (duplicate media and fabricated coverage
  fail closed server-side) — and re-derives the canonical-JSON seal
  byte-identically to the slice-1 TS `canonicalJson` (sorted keys, arrays
  in order, number literals preserved, ECMAScript JSON.stringify escaping;
  pinned against the shipped TS module by a cross-language known-answer
  digest in `localcapture_test.go`). The exact received bytes reach the
  reducer; Go owns admission, the SQL belt re-refuses what could not have
  passed it.
- **Codes** BZ282–BZ284 (`reducererr.codeClass` + `meet/errors.go` +
  `docs/reducer-error-codes.md`): BZ282 local-capture-lease-conflict
  (the plan's `captureLeaseExpired`), BZ283 local-capture-invalid,
  BZ284 local-package-not-admitted (the BZ277 admitted-path genre).
- **Truthful locality end to end**: a local_registered capture is
  local_only, its registered package exports nothing centrally (the
  existing BZ281 local_only arm), and registration stores a RECEIPT —
  never a claim of retained central bytes.
- Named follow-ups: the idle-time sweep leg wiring
  (`meeting_local_capture_lease_expire` exists and is pgTAP-proven; no
  worker.go leg calls it yet — lazy expiry arms make it non-urgent while
  the flag is OFF), the ArkTS `meet-capture:` denial twin, and the
  authorized Drive upload path (the plan's optional tail).
- pgTAP: `tests/meet_local_capture.pg` (75 — fences, reattach, heartbeat
  monotonicity + stop facts, stop/reacquire generations, meeting_end arm,
  expiry arms, registration truthfulness + idempotence + BZ279/BZ281
  locality) and `tests/meet_local_capture_rls.pg` (9 — the FORCE proof as
  setjoin_app). Go: `localcapture_test.go` (the descriptor contract +
  cross-language seal), `localcapture_integration_test.go` (the DB-gated
  wire arc: acquire → heartbeat fence/refusal surfaces → stop → truthful
  registration → idempotent replay → flag-OFF inertness) + the four new
  route pins in `route_inventory_test.go`.

## Document-mode fidelity contract (M6 slice 1, MEET plan)

Word/text pagination + spreadsheet static print pages under the SAME
`meet-pages-v1` manifest (plan M6 bullet 1: "Add Word/text pagination and
spreadsheet static print pages under the same manifest; retain explicit
fidelity warnings and fallback"). CONTRACT only — no route, worker, reducer,
table, or flag change; everything stays behind the existing OFF flags.

- **`presentation/docmode.go`** — the closed M6 mode vocabulary riding the
  existing manifest grammar, never a parallel manifest: the two-value
  `DocumentMode` set (`word_text_paginated` — docx/odt/txt pages by the
  PRODUCER'S OWN pagination, TXT under the producer's frozen UTF-8-pinned
  default theme; `spreadsheet_print_static` — xlsx/ods render the STATIC
  PRINT LAYOUT, print area/scale exactly as the producer resolves them,
  never an interactive-grid promise), each mode pinned by the audited mode
  gate table to an explicit pair of a `FidelityClass`
  (`producer_pagination` / `static_print_layout`) and a `FallbackRule`
  (`office_editor_or_screen_share` / `screen_share_or_office_editor` — the
  plan's fidelity escape hatches). `Manifest.DocumentMode` (rendition.go,
  optional section) carries the capability; `nil` = the launch vocabulary
  (pdf/pptx/odp) and implies nothing new. Fail-closed arms: unknown
  mode/class/rule, format⇄mode mismatch, non-canonical source format, and
  a capability whose class's MANDATED warning token
  (`producer_pagination` / `static_print_layout`, both new closed
  `RenditionWarning` values) is missing from the same manifest's Warnings —
  a capability without its warning is a silent fidelity promise. Zero-page
  and every other existing manifest rule still apply unchanged.
- **Producer conversion path** — `DocModeProducerEngineID` pins the D3
  one-suite engine (`libreoffice-headless-soffice`);
  `DocModeProducer.Validate`/`AdmitDocModeProducer` refuse anything but the
  evidence-backed pinned engine and require requalification on ANY
  engine/version change (the version-pinned lifecycle). Producer-absent is
  the EXPLICIT `FidelityUnavailable` (`rendition_unavailable`) state —
  `UnavailableAdmission(format)` names the mode + its real fallback while
  producing NO capability/manifest, never a silent substitute.
  `ProducerConversionRecipe`/`ConversionRecipeFor` are the committed,
  deterministic conversion recipes (isolated profile, `--norestore`,
  explicit export filter per mode family: `pdf:writer_pdf_Export` paginates
  by the producer's own print layout; `pdf:calc_pdf_Export` prints the
  document's print ranges/scale with NO single-page-sheet override; txt
  pins `--infilter=Text (encoded):UTF8`). The executable mirror is
  `scripts/meet-m6-convert-doc-modes.sh` (`recipe` prints the committed
  recipes; `convert` runs the pinned producer with a bounded per-file wait
  and fails closed with the rendition_unavailable state when the engine is
  absent; `verify` re-derives page counts — it counts BOTH the corpus
  measurer's spaced `/Type /Page` and LibreOffice's unspaced `/Type/Page`
  token — and requires the producer receipt; output may never land in the
  M0 corpus dir). Dev-side corroboration only (D3: qualification evidence
  comes from linux-ci-host); the corpus manifest is NOT touched by this slice.
- **Replay surfacing** — `replay.go`'s `PresentationVersionLink` gains the
  optional document-mode triple
  (`documentMode`/`fidelityClass`/`fallback`), attached ONLY by
  `AttachDocumentModeCapability` and only when the rendition manifest is
  the one the binding pinned (integrity-digest match) — one rendition's
  fidelity claims are never cross-attached to another binding, and launch
  links imply nothing. The webmail mirror (`webmail/src/lib/meet/
  semanticReplay.ts` `ReplayDocumentMode`/`ReplayFidelityClass`/
  `ReplayFallbackRule` + `replayFidelityNotice`, which surfaces nothing
  for launch links or partial triples) renders the notice honestly beside
  the version link in `SemanticReplayPanel.svelte`; i18n keys
  `meet.replay.fidelity*`/`meet.replay.fallback*` in en/de/zh.
- **M6 exit discipline** (`docmode_test.go`): a named positive, negative,
  and recovery matrix over every supported (mode, format) combination —
  positive: docx/odt/txt word combos + xlsx/ods validate under the
  SAME manifest with their mandated warnings and pinned pairs (incl. wire
  round-trip); negative: unknown mode, format⇄mode mismatch, non-canonical
  format, unadvertised formats refused everywhere (doc/rtf/md/csv/et stay
  OUT — unadvertised format support is a named plan anti-goal), pinned-pair
  mix-and-match, stripped warning, zero-page still refused; recovery:
  producer-absent → explicit rendition_unavailable (never a silent
  substitute), engine/version change → requalification, deterministic
  recipes, replay-link attach gated on the digest match.

## M6 cross-feature continuity proofs (M6 slice 2, MEET plan)

The M6 exit ("every supported document mode and cross-feature combination
has a named positive, negative, and recovery test") — slice 2 delivers the
cross-feature half as REAL tests in `presentation/m6_continuity_test.go`
(fake Drive boundary, always run) and
`presentation/m6_continuity_db_test.go` (real reducers, `DB_DSN`-gated —
the meet-package DB precedent; own disposable container per the RUNBOOK
recipe). The Office edit-save is simulated at the Drive version boundary
exactly as Drive records it — a NEW immutable `drive_file_versions` row on
the SAME node, advanced to head — never live Office, never network.
Test→bullet map:

- **Edit-save vs pinned presentation** (plan M6 bullet 3 + driveboundary.go's
  pin contract): positive `TestM6ContinuityEditSaveNewVersionLeavesActivePinnedContract`
  (contract: a new version identity never mutates the pinned SourceRef,
  manifest or capability binding) + `TestM6DBOfficeEditSaveCreatesNewVersionPresentationStaysPinned`
  (real reducers: save lands, checkpoint byte-stable — version, sha,
  digest, manifest generation, page, seq, for presenter AND attendee
  reads); positive, continued:
  `TestM6DBPresenterSwitchToSavedVersionRepinsExplicitly` (explicit switch
  to a branch-conflict head then the linear save: re-pins, page resets,
  manifest generation bumps, durable `source.switched` facts name the new
  identity); negative `TestM6ContinuityEditSaveNeverSilentlyAliasesThePinnedRendition`
  (dedup can never alias old/new renditions; an old-version+new-bytes
  manifest refuses the key-tuple binding) + `TestM6DBSilentRepageAttemptsRefused`
  (second prepare BZ275, non-presenter switch BZ273, stale generation and
  stale sequence BZ274, same-version switch BZ276 — the pin is untouched
  after every refusal); recovery `TestM6DBFailedSwitchLeavesPinnedSessionRecoverable`
  (a switch at a deleted source refuses BZ272 without disturbing the pin;
  the presenter's real switch then lands cleanly).
- **Guest roles**: positive `TestM6DBGuestPresenterTargetConfersPageOnlyAuthority`
  (an admitted guest is a legal presenter-grant TARGET — page verbs only;
  the fact records targetRole=guest); negative `TestM6DBGuestRoleHasNoDurableVerbs`
  (guest rows carry user_id NULL by construction, so no authenticated
  durable actor exists; recording with a guest admitted refuses BZ199);
  recovery `TestM6DBGuestDepartureAndTakeoverRestoreControl` (departure
  re-admits recording; host takeover restores control, the stale guest-era
  generation refuses BZ274, the checkpoint converges).
- **Captions**: positive/negative/recovery in ONE named test,
  `TestM6ContinuityCaptionBearingReplayBindsRefsAndStaysCoherent`: retained
  zh/en StableRef bindings validate and replay shows the tracks with the
  presentation links intact; duplicate language, retained-without-ref and
  over the 8-language cap all fail closed; a lapsed caption track replays
  truthfully expired — no path, no fabricated text, the rest of the
  package untouched.
- **Breakouts**: positive `TestM6DBBreakoutMovePreservesPresentationCheckpoint`
  (room facts never move the meeting-scoped session; the assigned
  presenter keeps their fences and pages from the child room); negative
  `TestM6DBBreakoutAssignmentGrantsNoPresentationAuthority` (an assigned
  member's page/annotation/switch all refuse BZ273 and the assignment
  commits no presentation fact); recovery
  `TestM6DBBreakoutCloseLeavesOpenPresentationCoherent` (close-all clears
  assignments, the open presentation continues, no breakout fact ever
  enters the presentation rail).
- **Whiteboard transitions**: positive `TestM6DBWhiteboardInterludeLeavesCheckpointReloadable`
  (the interlude is a client-stage no-op; return reloads the identical
  checkpoint and the next fenced page change is admitted) plus the contract
  arm `TestM6ContinuityWhiteboardTransitionsNeverEnterTheDurableRail`
  (whiteboard kinds refuse DurableCommittable/Encode/Classify; the state
  machine has no whiteboard arm); negative
  `TestM6DBWhiteboardInterludeConfersNoDurableAuthority` (ephemeral stage
  authority never promotes: member BZ273, stale annotation BZ274);
  recovery `TestM6DBWhiteboardReturnRecoversDegradedSession` (degrade →
  interlude → recover lands ACTIVE on the same page; the rail stays
  gapless).
- **Retention + legal hold**: positive `TestM6DBHeldPackageSurvivesRetentionSweep`
  (a hold on DELETE_PENDING classifies HELD_COMPLETE; every child release
  answers a heldBeforeRelease receipt; finalize stays suspended); negative
  `TestM6DBRetentionHoldRefusalsFailClosed` (stale-generation release,
  child outside the expected set, restore from HELD_PARTIAL, hold/restore
  against DELETED — all BZ280); recovery
  `TestM6DBHoldRestoreCompletesRetentionWithFreshGeneration` (restore bumps
  the deletion generation so stale receipts fail closed forever; hold
  lift, re-delete, and the sweep completes to DELETED).
- **History** (the meet-side facts the Drive History emitter consumes; the
  emitter file itself is a parallel worker's slice): positive
  `TestM6DBPresentationRailRecordsCoherentHistoryFacts` (rail kinds ordered
  and gapless, the `source.switched` payload names node/version/digest/
  manifestGeneration, the acting user is recorded); negative
  `TestM6DBRefusedMutationsEmitNoHistoryFacts` (refused switch/page emits
  nothing — no phantom version ever enters the timeline); recovery
  `TestM6DBHistoryRailStaysLinearAcrossRecovery` (after a refused attempt
  at a gone source, the accepted switch lands at exactly the next
  sequence).
- **Defect fixed by these proofs** — `_meeting_presentation_require_presenter`
  (`sql/reducers/meeting_presentation.sql`): an actor with NO live
  participant row (absent/departed) silently PASSED the presenter fence —
  `id <> NULL` yields NULL, never true — leaving only the guessable
  generation/sequence pair between a caller with no meeting position and
  the durable presenter verbs. The helper now refuses a NULL actor
  explicitly (BZ273); pgTAP regression case added in
  `sql/tests/meet_presentation.pg` (plan 89→90, suite green on the
  container) plus `TestM6DBGuestRoleHasNoDurableVerbs` at the Go layer.
- **Coordination note**: the parallel Drive-History emitter worker's
  `TestWorkerDriveHistoryEmitsLifecycleEvents` drains candidates globally
  and is not tolerant of another process committing meet facts to the same
  database concurrently: `go test ./internal/meet/...` is green with
  `-p 1` (and with per-worker containers per the RUNBOOK) but intermittent
  cross-package under shared-DB parallelism. Emitter owner's call.

## Honesty ledger — flip status

Full run-by-run detail lives in git history / the plans; this is the
current, load-bearing state of what's proven vs owed for each toggle.

### B1 (`feature.meet`)

**Proven:** the DB-gated tracer (`TestFullMeetingArc`) — create (huddle
bound to a real chat channel) → member join ×2 (org-open) → kick → BZ186
rejoin → role-route re-admit → rejoin succeeds → lock → stranger BZ187 →
knock → mid-arc `guestAllowed` flip → knock admit completing on the PUBLIC
poll → guest join-request → host admit → guest poll mints a `g:`-identity
token → guest kick → poll denied → end (`DeleteRoom` + a pending knock lands
`expired`) → a replayed `room_finished` webhook no-op → `feature.meet` OFF
404s a REAL registered route. The live SFU control plane (`TestLiveSFUSmoke`,
`MEET_LIVE_SFU=1`) against both the Docker image and the native pinned
Linux binary. The mailserverd boot smoke (found+fixed a real bug: `/rtc` was
missing from `apiPinnedPrefixes`, so every real LiveKit connection would
have silently 404'd — fixed, `check-api-namespace.sh` clean). The systemd
unit (`systemd-analyze verify`; found+fixed `StartLimitBurst`/
`StartLimitIntervalSec` silently ignored under `[Service]` — moved to
`[Unit]`). The raw-SDK two-browser media plane (real Chromium contexts, real
SFU, both peers publish+subscribe A/V through the SFU). **The full webmail-
UI authority flow ran 2026-07-16 on linux-ci-host, all legs green**: real login
→ create/join → org-open join-by-link → two-way video tiles relayed through
the SFU → lock/unlock → kick via the UI + BZ186 refused rejoin surfaced →
role-route re-admit → rejoin succeeds → guest-access toggle → public guest
knock → host admit → guest kick sealed → end-for-all. Reusable gated spec:
`mailserver/webmail/e2e/meet-live-ui.spec.ts` (`MEET_LIVE_UI=1`-gated).
**That run found + fixed 7 real product bugs** (each its own commit, the
class the raw-SDK smoke could never see because it never loads a
gateway-served page): a `Permissions-Policy` header denying getUserMedia/
autoplay to the Meet origin itself; the SPA static handler serving a
directory listing for `/meet` instead of falling through to `index.html`;
`room.svelte.ts` hard-coding `wss://` (breaks on non-TLS pages); the `/rtc`
reverse proxy forwarding paths verbatim so livekit-client's own `/rtc/v1`
suffix doubled to `/rtc/rtc/v1` and 404'd (the proxied media path had NEVER
actually worked); a Svelte 5 effect-dependency bug tearing down every
`?slug=` deep-link join on connect; MeetApp never unwrapping the
`{"@type":"MeetEvent",...}` push envelope (every live push silently
dropped); and authserver's CSRF check comparing `Origin` against the
proxy-rewritten `Host` instead of `X-Forwarded-Host` (403'd every real
cross-host login). Two sibling non-Meet bugs fixed in the same pass: a
threat-mirror INSERT silently dropped by a bad constraint value, and
`chat_channel_create`/`chat_dm_open` failing their own RETURNING policy
under live FORCE-RLS.

**Still owed before `feature.meet` flips ON:**
1. ~~The native-RLS W4 policy wave — a hard flip blocker, found live.~~
   **DONE.** SQL leg: V134 added the missing write policies
   (`meeting_participants`/`meeting_join_requests`/`meeting_breakouts`/
   `meeting_recordings` UPDATE, `meetings`/`chat_channels` UPDATE), proven as
   `setjoin_app` in pgTAP. Go leg: every Handler route in this package + chat
   now GUC-scopes its DB calls via `dbscope.RunUserScoped` — see this
   section's "FORCE-RLS (R4, W4 Go leg ACTIVE)" paragraph above,
   `scripts/check-rls-scope-wrap.sh`, and `rls_scope_live_test.go`. Both legs
   verified against the constrained `setjoin_app` role, not just pgTAP/the
   test suite's usual superuser DSN.
2. Real camera/mic/screenshare + blur on actual hardware (the headless
   codec probe falls back to VP8, `blurSupported` stays false, recorded not
   a crash) — needs human hands. **This is the ONLY B1 pre-flip item still
   owed** after the 2026-07-16 fresh-VM systemd gate.
3. ~~The systemd unit installed + running under `journalctl -u setjoin-sfu`
   on a fresh VM.~~ **DONE 2026-07-16 — the fresh-VM systemd install smoke
   RAN + GREEN.** The REAL `install.sh` (`NONINTERACTIVE=1`,
   `MEET_CAPTIONS_ENABLED=true`) on a fresh LXD VM (Ubuntu 26.04, own
   systemd/ports) brought ALL SEVEN units to `active`, `systemd-analyze
   verify` clean, journals crash-loop-free, install run with ZERO WARN/ERROR;
   then `meet-live-ui.spec.ts` drove all 10 authority-flow legs through the
   browser against the systemd deploy over self-signed HTTPS. **The install
   found + fixed FIVE never-before-caught deploy bugs** (each a labeled
   commit): `setjoin-sfu`/`setjoin-asr-bot` crash-looped on
   `RestrictAddressFamilies` blocking `AF_NETLINK` (pion/WebRTC ICE — the
   unit as shipped could NEVER start on a real host; `systemd-analyze verify`
   only parses); `/health`'s sfu/egress/asr probes could never report a
   healthy component (an `err==nil`→skip inversion + a `feature.meet`-gated
   sfu row the seeded-OFF toggle always suppressed); `StartLimit*` under
   `[Service]` (silently ignored) in the mailserver/authserver units; **the
   SFU webhook plane was DEAD on every self-signed install** (livekit verifies
   the gateway cert against the system trust store → meetings never flipped
   `live`, recording start 409'd BZ200 — `install.sh` now anchors the
   self-signed cert); and the gateway hung the full 90s stop timeout into
   SIGKILL on every restart + OOM-killed under the shipped 512M cap. Plus a
   reducer RLS bug (`meeting_end` expired knocks after the left_at mass-stamp
   → 0 rows under V134). The VM (`setjoin-gate`, stopped, on `ssh
   linux-ci-host`) is a reusable gate asset.

**UI gaps observed, ledgered not fixed (product decisions):** a kicked
MEMBER's UI stays frozen in-room (`notify_meet_state`'s fan-out excludes the
just-kicked identity itself by construction, so there is no push for their
OWN client to react to — only other live members get one); the leave
announcement falls back to the raw identity. **Fixed since:** a re-admit
affordance for banned members (5ae8e665), durable across a reload since A/B
leftover item 1 added `meeting_get`'s `banned[]` projection (see "Recording
(B2)"'s Routes paragraph above for the exact shape/gate); opening an ENDED
meeting via `?slug=` used to still render PreJoin (join then 409s BZ190) —
A/B leftover item 5 routes an `m.state === 'ended'` slug-open straight to
the ended/summary view instead, client-side only (the authed by-slug
resolve itself stays deliberately post-end capable — only the PUBLIC
surface is BZ185-sealed).

### B2 (`feature.meet_recording`)

**Proven:** the maximal fake-based tier (Task 11) — real reducers/routes/
Postgres, real minio-go wire protocol against an in-process S3 stub, fakes
only at the two network seams; a 105 MiB byte-identical ingest round-trip,
the live two-session guest⇄start race. **The live Valkey/Egress round-trip
RAN 2026-07-16** on linux-ci-host: livekit-server v1.13.3 + the digest-pinned
`livekit/egress:v1.13.0` ran a full RoomComposite lifecycle TWICE
coordinating over real Valkey 8.1.8 on loopback `:6390` with `requirepass`,
landing the recording in MinIO through the exact `EncodedFileOutput_S3`
shape `egress.go` sends — **the D7 Valkey question is a YES**.

**That run found two flip blockers:** (a) **FIXED same day, ratified** —
the container-reality MP4 pivot above (output was MP4, egress rewrote
`.webm`→`.mp4`, breaking the persisted staging key; fixed by pinning
`EncodedFileType_MP4`, live-proven key-stable before the fix landed). (b)
**FIXED same day, ratified (62243f05)** — `install.sh` left
`/etc/setjoin/egress.yaml` 0600 `setjoin:setjoin`, but the pinned image
runs `USER=egress` (uid 1001, gid 0) → permission denied →
`setjoin-egress.service` could never start as shipped. Fixed: `install.sh`
now chowns it `root:0` mode 0640 after the blanket chown (the image user
is in gid 0); `-u 0:0` is NOT a workaround (the entrypoint's pulseaudio
dies as root under `set -euo pipefail`).

**The full staging→ingest→Drive→browser-`<video>` leg RAN + GREEN
2026-07-16 on the fresh-VM systemd gate** (see the B1 section): under real
`setjoin-egress`/`setjoin-valkey` + the gateway worker, a host started
recording via the UI (consent banner asserted as SERVER state on BOTH
browsers before the first frame), published ≥35s of fake A/V, stopped, and
the worker drove `requested→active→stopping→pending_ingest→ready`; the
recording landed as a Drive node (`file_node_id` set, 4.1 MB) and
`RecordingsList`'s `<video>` played it back (`readyState=4`, `duration≈32s`,
`content-type: video/mp4`) — the NOW-FIXED MP4 path, under real systemd, end
to end. This run is what found the self-signed-webhook flip blocker (see the
B1 section: meetings never went `live` → recording start 409'd BZ200).
**Still owed before `feature.meet_recording` flips ON:** the `/health`
egress probe honest with the bus down; a live observation of the SFU's own
behavior with the bus down mid-meeting; multi-node egress (untested,
single-box only); the 信创 GA precondition (spec §1.3) — the compliance
owner's WRITTEN confirmation (at-rest SM4-via-Drive + outer-TLS suffices) is
due before ship, owner: user → compliance owner, a ledger line not a task.

### B3 (`feature.meet_breakouts` / `feature.meet_captions`)

**Proven:** the maximal fake-based tier — full breakout choreography +
captions lifecycle vs `fakeRooms`/`fakeCaptions`, the `TestBreakoutTracerArc`/
`TestCaptionsTracerArc` composites, `TestEveryRevokePathEvicts`'s four new
breakout cases, the asrbot module's hermetic slot/VAD/protocol suite. **The
live FunASR round-trip RAN 2026-07-16** on a 6-core CPU-only Linux box
against the real pinned FunASR image, real pinned livekit-server v1.13.3,
and the real cgo asrbot build: the full `/start`→speech→`cc:` partials +
punctuated finals + `hb` keepalives→`/stop` arc proven at the LiveKit/
data-channel tier (a known-transcript Mandarin sample came back verbatim;
zero transcript/token material in asrbot logs; all five models loaded from
the sha256-pinned dir). **Found + fixed two real shipped bugs**: the funasr
systemd unit's ExecStart ran the upstream wrapper, which backgrounds the
server and exits, killing the container at every boot — now direct-`exec`
with all five models named explicitly; the funasr client discarded the
`2pass-offline` final the server only emits after the closing frame, so no
`final:true` cc frame was ever published — now drained. **The Task-16
companion-model gap is CLOSED** — all five FunASR models (vad/offline/punc/
itn/online) are pinned; the optional ~960MB LM stays deliberately disabled,
not pinned. **The F8 attestation P0 this run also found is FIXED same day**
— see the `hidden:false` reversal in "Captions (B3b)" above; attestation is
no longer broken. `systemd-analyze verify` on both ASR units — DONE
2026-07-16 (systemd 259, zero diagnostics, re-verified clean after the
direct-exec rewrite). The live F14 `MoveParticipant`-unimplemented arm —
proven against the pinned v1.13.3 server (owed again at every SFU pin
bump).

### M2 (`feature.meet_document_presentation`)

**Proven (implementation-time, 2026-09-18):** the full pgTAP suite serially
green (527 files / 9290 tests) including the two new files —
`meet_presentation.pg` (87: the prepare→ready→start→page→handoff→switch→
degrade→recover→end/revoke arc with every fence, all refusal arms
BZ186/BZ272/BZ273/BZ274/BZ275/BZ276, terminal resurrection, the annotation
CHECK belt, `meeting_end`'s same-txn cancel, `meeting_get`'s
presentation/presentationEnabled keys) and `meet_presentation_rls.pg` (16:
participant-scoped FORCE-RLS denial + the real-reducer ALLOW flow as
`setjoin_app`, COVERED in both RLS allowlists). Go: the seven
`presentation_test.go` httptest suites (flag gates both directions, the
drain exemption with the flag OFF, the full lifecycle with frame assertions,
authority refusals incl. the no-Drive-right switch, lifecycle illegals,
meeting-end cancel, the deterministic 429 throttle with `Retry-After`, the
BZ277 annotation refusal), the whole `internal/meet` package green,
`shared` (reducererr contract matrix rows for BZ272–BZ277) green, webmail
vitest green (`presentationCheckpoint.test.ts`, 8). Guards:
`check-no-duplicate-version.sh`, `check-toggle-registry.sh`,
`check-rls-denial.sh`, `check-rls-allow.sh` all clean. **Flags stay OFF** —
behavior remains OFF; nothing above admits production presentation traffic.
**Owed:** M1-rendition-pipeline wiring for `ready` (M2 accepts host/cohost
confirmation only), M3 UI/E2E convergence, M4 annotation admission.
Live-SFU presentation E2E and the two-API-client
convergence proof remain M3 acceptance work.

**The D4 journald leg RAN + GREEN 2026-07-16 on the fresh-VM systemd gate,
and FOUND one more real leak.** Under real systemd (`setjoin-asr-bot` +
`setjoin-funasr` both `active`), captions were started in-browser and the
known Mandarin sample published as fake audio; `cc` frames rendered verbatim
in `CaptionsOverlay`. The FIRST journald pass showed funasr STILL leaked the
transcript: `StandardOutput=null` muted only stdout, but
funasr-wss-server-2pass's glog INFO writes recognition results to STDERR
("online_res :…"/"offline results :…"), journal-routed by the unit. Fixed
same day (`GLOG_minloglevel=2` in the unit's container env — ERROR/FATAL
still reach the journal, INFO/transcript lines don't); the POST-FIX windowed
grep across a full captions round-trip showed ZERO transcript text, ZERO
`ASR_TOKEN`/`LIVEKIT_API_SECRET`/`eyJ`-JWT material on BOTH ASR units.
**Still owed pre-flip:** GPU sizing (no GPU on the gate box); the
multi-meeting realtime factor behind `ASR_MAX_MEETINGS`; CI
runners need `libopus-dev`/`brew install opus` for the asrbot lane to stop
skipping (a provisioning line, not a code task — this box has it and built/
linted/tested asrbot for real); the B1 standing gate above (grows breakout-
move + captions steps when that run happens); the B2 live tier above,
unchanged.

**Manual smoke checklist for the fresh-VM residual:** fresh install on a VM
→ `systemctl status setjoin-sfu` + `journalctl -u setjoin-sfu` clean → flip
`feature.meet` → two-browser meeting on real cameras (video both ways,
screenshare, blur toggle) — the authority flow itself (lock, knock/admit,
kick/re-admit, end) is already covered by `e2e/meet-live-ui.spec.ts` and
need not be re-proven by hand.

## Deferrals (owners, not vague "later")

See root `TODOS.md` "Meet B1"/"Meet B2"/"Meet B3" sections for the
authoritative registry; summarized here:

- **Recording → SHIPPED (B2).** Host-initiated RoomComposite recording to a
  meeting-bound Drive space, consent banner + disable-recording-when-guest-
  present both delivered. Ships as **MP4/H.264+AAC**, not WebM/VP9 (ratified
  2026-07-16, see "Recording (B2)" above).
- **Single-source/webinar recording mode via TrackComposite egress → named
  seam, not built.** RoomComposite has no WebM/VP9 file-output path at all
  (upstream constraint); TrackComposite still offers `OutputTypeWebM`/
  VP9+Opus, transcode-free, but fits "record the presentation," not "record
  the meeting" — not a drop-in replacement.
- **Attendance report UI → SHIPPED (B2).** `meeting_get`'s `attendance[]`
  (host/cohost-only, post-end) + the webmail AttendancePanel/CSV export.
- **Breakouts/polls/Q&A/whiteboard → SHIPPED (B3a). Captions/transcription
  → SHIPPED end-to-end (B3b).** See the sections above.
- **B3's own §11 deferral registry (each with its seam, carried not
  dropped):** moderated/webinar Q&A module (the `msg_type='question'` rail
  already carries the data, a moderation UI is the seam) · transcript
  persistence (the B2 ingest pattern + an A4 compliance-owner treatment, a
  separate decision, never a captions rider) · breakout recording (per-room
  egress fan-out on the `EgressController` seam) · guest breakouts/polls/
  Q&A/whiteboard (the guest-accounts program — guests have no `users` row,
  the chat rail is member-only) · caption translation/meeting summaries
  (the `assist.Provider` seam — text→text) · whiteboard persistence/resume
  (a Drive-file snapshot on close — the "Export to chat" button is the
  seam) · timed breakouts (a `closes_at` column + a worker arm) · per-
  meeting caption language/additional ASR models (sidecar config, `lang` is
  additive on the asrbot control API) · per-breakout attendance reporting
  (a facts table on the §4.1 webhook resolution) · guest caption exclusion
  override (clone the BZ199 two-arm `FOR UPDATE` pattern).
- **SIP/PSTN, livestream, e2ee-mode → anti-scope** (spec §3.2).
- **:443-only TURN (SNI/coturn second-IP) → ledgered, not built.** The one
  case v1 doesn't cover — a customer whose egress firewall allows only
  443/tcp outbound. `SINGLE_NODE_SETUP.md`'s firewall section.
- **Native-client media permissions → the client-unification desktop/
  mobile wave.** B1 is web-browser only.
- **Guest in-meeting chat → the guest-accounts program.** Guests have no
  `users` row; get media + reactions only.
- **Forced re-auth on role demote → not built, by design.** A demote
  changes future grants, doesn't evict — kick exists for that.
- **Watermarking → spec's own cut.**
- **Join-request secret hashing → ledgered hardening, not a B1
  requirement** (plaintext accepted: host-visible by design, 15-min
  lifetime, grants only a host-approved admission).
- **Deep per-device HW-encode matrix → simple probe only** until the mobile
  WebView shells land.
- **Fresh-VM install smoke / B2 live Valkey+Egress remainder → open
  preconditions for flip.** See the honesty ledger above.
- **Guest recording access → the guest-accounts program.** `drive_member_
  role` v3 already keys on `users` rows; guests have none.
- **Series-level recording grouping/space → a UI query** over
  `calendar_event_id` — no schema owed.
- **Org retention/classification knob for recordings → one values-change**
  in `meeting_space_ensure` when a customer needs it.
- **Share-recording-beyond-attendees → the audited `drive.manage` admin
  override** DES-009 already names; never a host button.
- **Recording disposition/deletion → the A4 gxp-disposition pattern**
  (explicit, reviewed, approval-gated); nothing destructive ships in B2.
- **eDiscovery reader leg → one UNION** against `meeting_recordings` when a
  case demands it. Meeting attendance has no officer-grade export surface
  in v1 either — the same UNION seam covers both when a case demands it.
- **VP9 at rest → blocked upstream** (the protocol `VideoCodec` enum has no
  VP9 member; needs an upstream addition first).
- **Multi-node egress pool/autoscaling → the separate-host recipe**
  suffices until a real concurrency demand exists (the `cpu_cost` cap is a
  single-host ceiling of 1 concurrent composite by design).
- **RTMP/HLS livestream, track/participant egress, local-file egress → the
  `EgressController` seam** is where they would land; not built.
