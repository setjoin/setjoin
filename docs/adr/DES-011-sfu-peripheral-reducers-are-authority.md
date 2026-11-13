# ADR: DES-011 — The SFU Is a Peripheral; Reducers Are the Sole Meeting Authority

**Status:** Accepted
**Date:** 2026-07-12
**Source:** `retired-docs:superpowers/research/2026-07-12-B1-livekit-C0-spike.md` §2; `retired-docs:superpowers/plans/archive/2026-07-12-meet-B1-core.md` (autoplan gauntlet + gate decisions)

## Context

B1 embeds LiveKit as the media plane (sidecar `setjoin-sfu`). LiveKit has its own notions of rooms, participants, tokens, and webhooks — a second source of truth waiting to happen. Three of its behaviors actively invite authority leakage: (1) tokens are **refreshed for connected participants**, so token TTL cannot end a session; (2) webhooks are retried but **explicitly not guaranteed delivered**; (3) rooms **auto-create** on first join by default. A meeting layer that trusted any of these would split authorization between Postgres and the SFU — the exact split-brain the "logic where the data is" architecture exists to prevent.

## Decision

**Authorization truth flows one way: from reducers to LiveKit. Facts flow back the other way, loss-tolerantly.**

- **Every allow is a reducer decision materialized as a narrow mint.** `meeting_join` / the lobby poll compose a grant spec in SQL; Go only translates it to a VideoGrant and signs. Member and guest tokens carry `roomJoin` scoped to one room — never `roomCreate`, never `recorder`; guests additionally never `roomAdmin`.
- **Every revoke is an eviction call, never a TTL hope.** Kick, ban, lock-enforcement, guest-revocation, meeting-end → RoomService `RemoveParticipant`/`DeleteRoom`. Token expiry is admission control only. Machine-checked by `TestEveryRevokePathEvicts`.
- **Rooms are pre-created by the gateway** (`room.auto_create: false`); the room name is the meeting UUID. The SFU can never mint a meeting.
- **Webhooks are facts, never authorization.** `participant_joined/left`, `room_started/finished` feed a loss-tolerant, idempotent ingest reducer (attendance stamps, lifecycle GC) backed by a periodic RoomService reconcile — the system converges without any webhook arriving. No webhook handler may gate access.

## Consequences

- The meeting layer survives SFU restarts, webhook loss, and LiveKit version churn with no authorization drift; the SFU binary is swappable (the sidecar decision, spike §1) without touching authority logic.
- Cost: every revocation path must be wired to an eviction call (a forgotten path = a lingering participant — hence the machine check), and attendance/lifecycle need a reconcile sweep instead of trusting webhook completeness.
- Future features (recording consent, breakout moves, captions) inherit the rule: if it grants or revokes anything, it is a reducer decision + a mint or eviction — never a webhook reaction.

## Alternatives rejected

- **Token-TTL-as-session-control:** LiveKit refreshes connected participants' tokens; a "suppress refresh" knob does not exist. TTL enforcement is fiction for connected sessions.
- **Webhook-driven authorization** (e.g. admit-on-`participant_joined`): webhooks are best-effort; an authorization path that can silently not fire is not an authorization path.
- **Trusting SFU room state as the meeting registry** (auto-create, LiveKit-native metadata): puts the domain record in a process we deliberately treat as replaceable, and outside RLS/audit/backup.

## Extension — B2 recording (2026-07-15)

The rule extends to Egress unchanged: **"stop is an API call, never a TTL/room-death hope"** now covers every path out of `meeting_recordings.state = 'active'` — explicit stop, `meeting_end`, the `room_finished` webhook, and the worker's reconcile sweep all terminate in a `StopEgress`/belt call, machine-checked by `TestEveryRecordingStopPathStopsEgress` (`mailserver/internal/meet/recording_integration_test.go`). `egress_*` webhooks (`egress_started`/`egress_updated`/`egress_ended`) are facts only, ingested by the same loss-tolerant/idempotent contract `meeting_participant_event` established — `meeting_recording_event` never raises, and the system converges via `ListEgress` reconcile with zero webhooks delivered, exactly as B1 converges via `ListRooms`. The one new grant surface Egress adds (start-recording authorization) is still a reducer decision materialized as a Go translation, never the reverse: `meeting_recording_start` commits the state (and the consent-banner push) BEFORE Go ever calls `StartRoomComposite` — the SFU/Egress plane holds no authority over whether a recording is legitimate, only over whether the bytes get produced. Full detail: `mailserver/internal/meet/AGENTS.md`'s "Recording (B2)" section.

## Extension — B3 breakouts + captions (2026-07-16)

The rule extends to both of B3's new peripherals unchanged. **Breakout
child rooms**: `meeting_participants.breakout_id` is the single source of
truth for where a member belongs — a child room is a reducer-authorized,
gateway-pre-created LiveKit room exactly like the parent
(`CreateRoomWithTimeouts`, never `room.auto_create`), and every move is a
reducer decision (`meeting_breakout_assign`) materialized as an eviction
from the target's CURRENT room + a fresh mint for the new one — never a
LiveKit-side `MoveParticipant` (which the pinned self-hosted server doesn't
even implement, confirmed live). A child room's own `room_finished`
webhook is ingested as a fact that closes THAT breakout row, never meeting
state — the same loss-tolerant, idempotent contract
`meeting_participant_event` already applies to the parent room. **The
captions bot**: `setjoin-asr-bot` joins a meeting's room as an ordinary
participant, admitted through the exact same reducer-composed grant-spec
path every human participant uses (`meeting_captions_set` RETURNS the
bot's `VideoGrant` fields — `hidden:true`, `canPublish:false`,
`canPublishData:true` — Go only translates it via the same `MintToken`).
The bot holds **no authority and no secret beyond its own invited seat**:
no DB/S3 credential, no LiveKit API key, no ability to mint its own token
or create/admin a room — it is evicted for free by the SAME
`RemoveParticipant`/`DeleteRoom` calls that end a meeting or kick a human,
and its own `Stop` (a control-plane instruction to the bot process, not a
`RoomController` eviction) is idempotent and retried by the worker if
lost. Both peripherals are reducer-decided, gateway-translated, and hold
zero standing authority — the same law that already covered the SFU (B1)
and Egress (B2). Full detail: `mailserver/internal/meet/AGENTS.md`'s
"Breakouts (B3a)" + "Captions (B3b)" sections.
