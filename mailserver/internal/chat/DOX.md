<!-- Detailed DOX reference, moved from AGENTS.md on 2026-09-11. -->
This is a task-selected reference, not an always-loaded rail. Root and local
AGENTS.md govern agent workflows. Domain contracts below remain binding for their
scope; historical status is not permission to implement or enable flags.

# mailserver/internal/chat — Chat/IM Pillars A1–A4b (DOX child)

Parent: `mailserver/internal/AGENTS.md` → `mailserver/AGENTS.md` → root `AGENTS.md`.

## Purpose

Serves `/chat/*` (mounted at `/api/chat/*`) — channels, DMs, threaded
messages, reactions, mentions, read-state, typing, presence, roster,
attachments (A2, in an org-governed Drive space auto-provisioned per
channel), and records-lifecycle + eDiscovery oversight (A4a/A4b). A thin
REST translator over the `chat_*` PL/pgSQL reducers ("logic where the data
is"), mirroring `internal/drive/handler.go`'s single-gate + internal-mux
shape. Behind `feature.chat` (`toggle.FeatureChat`, seeded OFF — V119);
attachments additionally require `feature.drive`; records lifecycle +
oversight additionally require `feature.chat_compliance` (seeded OFF).
Plans: `retired-docs:superpowers/plans/archive/2026-07-11-chat-A1-core-messaging.md`,
`…-A2-storage-on-drive.md`, `…-A3-qol.md`, `…-A3.5-mobile-push.md`,
`2026-07-12-chat-A4a-records-lifecycle.md`,
`2026-07-15-chat-A4b-oversight.md`. Governance ADR: `docs/adr/DES-009-chat-bound-drive-space-governance.md`.
Visibility ADR: `docs/adr/DES-008-chat-visibility-discovery-not-access.md`.
Read-receipt ADR: `docs/adr/DES-010-chat-read-receipts-watermark-not-fact-table.md`.

## Ownership

`Handler.registerRoutes(router)` is the single private HTTP registration
authority. `NewHandler` passes its production `*http.ServeMux`; the package-local
route-inventory test passes a side-effect-free recorder and atomically emits
`chat.json`. Do not add routes directly to the constructor or a test-only list.

This doc owns every `.go` file directly under `mailserver/internal/chat/`
(`handler.go`, `channels.go`, `messages.go`, `presence.go`, `roster.go`,
`errors.go`, `translate.go`, `poll.go`, `search.go`, `threads.go`, + their
tests). It does NOT own the reducers (`mailserver/sql/reducers/chat_*.sql`,
`notify_chat_state.sql`, `chat_space_ensure.sql`, or the Drive-side V120
governance guards in `drive_member_grant.sql`/
`drive_node_{trash,move,rename}.sql`/`drive_file_put_version.sql` —
`mailserver/sql/AGENTS.md`), the webmail chat app (`$lib/chat/`,
`src/lib/components/chat/` — `mailserver/webmail/AGENTS.md`), the WS/SSE
push wiring the `chat:{uid}` channel rides (`internal/ws/handler.go` /
`eventsource.go` — documented in `mailserver/internal/AGENTS.md`'s `ws`
package entry), or the Drive-side membership/immutability machinery
(`drive_member_role` v2, `driveMemberScopeSQL`/`driveMemberScopeUnionSQL`,
`chatAttachmentLiveSQL` — `mailserver/internal/AGENTS.md`'s `drive` row; no
separate `internal/drive/AGENTS.md` exists).

## Architecture — membership-scoped, not mailbox-scoped

Chat is the first domain in this codebase where the account-scope currency
is a **channel membership row**, not a mailbox id (ARCH-003 governs
mail/calendar/contacts/tasks; chat is a deliberate exception). A channel has
N participants and is owned by no single mailbox. Every reducer takes
`p_user_id` (`users.id`, resolved from `claims.UserID` — never a
primary-mailbox lookup) and enforces membership itself, in the reducer body,
per call (R1). The Go layer never checks membership — it is a pure
translator: claims → path/body parse → `pool.QueryRow("SELECT chat_*($1,…)",
claims.UserID, …)` → map the error. `caller.UserID` never travels through the
request body (R2); ownership/membership is re-checked in the same statement
as any mutation (R3, e.g. edit/delete fold the archive-check into the same
`UPDATE … WHERE id=$1 AND NOT is_archived`).

**FORCE-RLS backstop (R4, W4 Go leg ACTIVE):** `chat_member_role(channel_id,
user_id)` is a `SECURITY DEFINER` scope helper (V119, the drive V114
pattern) — a literal membership subquery in a policy on
`chat_channel_members` would recurse onto its own table; the DEFINER helper
dodges that. App-level checks inside each reducer stay PRIMARY (ARCH-006),
but the RLS policy is no longer a dormant backstop: every user-request-path
DB call in this package runs inside `dbscope.RunUserScoped(ctx, h.pool,
claims.UserID, func(tx pgx.Tx) error {...})` (`handler.go`'s
`execChat`/`queryChatJSON` choke point, or wrapped inline per call site),
which sets `app.current_user_id` transaction-locally before the reducer
call — so the policy is actually evaluated and actually admits/denies under
the flipped `setjoin_app`/NOBYPASSRLS runtime, not just under the
pre-flip BYPASSRLS one. Guarded by `scripts/check-rls-scope-wrap.sh` (every
direct `h.pool.Query/QueryRow/Exec/Begin` call outside a scoped wrap or a
reasoned allowlist entry fails the build); live-proven end to end by
`rls_scope_live_test.go`'s `TestRLSScopeWrapChatMessageSend`, which runs the
real `Handler` against a connection assuming the constrained `setjoin_app`
role (not the test suite's usual superuser DSN, which bypasses RLS
entirely and would never catch a missing wrap). V134 additionally added the
write policies six FORCE'd tables were missing (`chat_channels` UPDATE,
`chat_channel_members`'s meet-bridge + public-read arms) and converted
`chat_dm_open`/`chat_member_remove` to `SECURITY DEFINER` for the
cross-member-row writes an invoker-rights policy can never admit. Six tables
carry `FORCE ROW LEVEL SECURITY`: `chat_channels`, `chat_channel_members`,
`chat_messages`, `chat_message_reactions`, `chat_mentions`,
`chat_message_revisions` — all six have a cross-tenant denial proof in
`mailserver/sql/tests/rls_chat.pg` (`scripts/rls-denial-allowlist.txt`, all
`COVERED`).

## The seq rail (the load-bearing invariant)

`chat_channels.change_seq` is a per-channel, commit-ordered mutation
counter. **Every** mutation — send, edit, delete — bumps it under the
channel row's own lock (`UPDATE chat_channels SET change_seq = change_seq +
1 WHERE id=$1 … RETURNING change_seq`) and stamps the mutated
`chat_messages` row's `seq` with the result, in the SAME reducer call. Two
consequences, both live-proven in
`mailserver/internal/chat/tracer_integration_test.go`:

- **`since(seq)` replay is gap-free under concurrent senders.** The row lock
  serializes concurrent `chat_message_send`/`edit`/`delete` calls on the same
  channel — commit order == seq order by construction, so a raw-identity
  cursor (`id > since`, which CAN commit out of order under concurrency) is
  provably wrong here and was never used.
  `TestConcurrentLateCommitterReplay` proves a second concurrent sender
  BLOCKS on the same lock and `since(0)` replays both in commit order with
  no gap after the first commits.
- **Edits and deletes are visible after reconnect, not just live push.**
  Because an edit/delete RE-STAMPS `seq` (not just `updated_at`), a client
  that missed the live `ChatEvent` still sees the change on its next
  `since(seq)` call — the row shows up again with `edited_at`/`body` updated
  or `deleted_at` set and `body` blanked (a tombstone).
  `TestEditRevisionRaceNoLostBody`/`TestSmokeReconnectOrdering` pin this.

**Soft-delete retains `body`.** `chat_message_delete` sets `deleted_at`
only; every READ path projects `body` to `''` when deleted — content is not
destroyed at user-delete time; real purge is A4a's job (see "Records
lifecycle" below). **Edits retain the pre-edit body too**, in
`chat_message_revisions` (write-only pre-A4b — the A4b eDiscovery reader is
the intended reader), captured AFTER the `change_seq` row lock is acquired
(never from a pre-lock variable, so a concurrent second editor's capture
can't silently lose an edit from the evidence chain —
`TestEditRevisionRaceNoLostBody` pins this race).

## Feature surface (A3 QoL) — one-line contracts

Each of these lives in its own reducer file; the BZ160–178 map below is the
authoritative error-code registry. Route files noted in parens.

- **Pin/Save** (`chat_pin.sql`/`chat_save.sql`, V122): pin is an org
  **curation act**, owner/admin-only in a `kind='channel'` conversation
  (BZ176) but any member in a DM/group-DM; unpin is collective (any current
  member may remove any pin — Slack semantics, no "only-the-pinner" guard).
  Pin/unpin re-stamp the message's `seq` under `change_seq` so the
  `'pinned'` field heals via ordinary `since(seq)` replay. Save is a
  **personal bookmark** (self-scoped RLS, no notify); `chat_saves_list`
  joins current membership IN-SQL so a save in a channel the user left is
  hidden (row retained) and reappears on rejoin. Routes: `POST
  /chat/messages/{id}/pin`, `GET /chat/channels/{id}/pins`, `POST
  /chat/messages/{id}/save`, `GET /chat/saves` (`messages.go`).
- **Read receipts (已读)** (DES-010, `chat_readers.sql`/`chat_read.sql`):
  "read by" is always a *derivation* over the per-member
  `chat_channel_members.last_read_seq` watermark — no per-message fact
  table, ever (avoids O(members × messages) write amplification).
  `chat_mark_read` fans out `member_read` live for DMs only (2 members,
  cheap); channel/group-DM refetch `chat_channel_readers` on
  open/focus/own-send instead. **No per-user opt-out, ever** — 已读 is
  org-governed workplace state, not a privacy-consent surface; a deferred
  **org-level** kill switch is registered for works-council jurisdictions
  (not built — when it lands the UI must degrade to nothing). Names are
  visible on "read by N" (watermark rows are member-readable under RLS
  regardless, so hiding names would be a curtain not a guarantee). Route:
  `GET /chat/channels/{id}/readers` (`presence.go`).
- **Translation** (`translate.go`): `POST /chat/messages/{id}/translate`
  `{targetLocale}` is a thin prompt over the SAME `shared/assist.Provider`
  `/assist/complete` already drives — no new reducer, no new membership
  logic (reuses `chat_thread_list`). `feature.assist` off → 503 (checked
  before touching the DB). Every successful translation emits a structured
  `slog.Info` (userId/messageId/targetLocale/provider, never key/URL) —
  chat content is leaving the DB through an external provider; A4a's audit
  chain records the act, no separate audit table.
- **Voice + msg_type/payload** (`chat_message.sql`): `chat_message_send`
  takes `p_msg_type`/`p_payload` (`'text'|'voice'|'poll'|'question'|'call'`).
  Voice = `msg_type='voice'` + `payload {durationMs}` + one `audio/*`
  attachment, capped at 300000ms/5min (BZ178). `POST
  /chat/channels/{id}/messages` allowlists exactly `text`/`voice`/`question`
  client-side (`poll` stays exclusive to `chat_poll_create`'s own atomic
  seam) — any other value 400s before reaching the reducer. Playback needs
  no new route: the A2 content route already serves Range-streamed audio.
- **`notif_level` + DND client surface**: purely a client-decision surface
  in A1–A3 — no server-side push filtering existed until A3.5 (below).
  `chat_member_set_notif` sets the CALLER's own per-channel mute
  (`'all'|'mentions'|'none'`, BZ162/BZ163). `chat_conversation_list` also
  projects `postPermission`/`broadcastPermission`/`meetingId` (the meeting,
  if any, whose `chat_channel_id` equals this channel — live over ended,
  most-recent wins). **Two different vocabularies, don't cross them**: the
  per-channel `notif_level` (`'all'|'mentions'|'none'`) vs the GLOBAL
  `user_notification_prefs.chat_notifications` (`'all'|'mentions'|'off'`,
  `internal/user/notification_prefs.go`) — deliberately different third
  value, not a copy-paste bug. Route: `PUT /chat/channels/{id}/notif`
  (`channels.go`).
- **Announcement/broadcast permission**: two independent owner/admin-settable
  gates on `chat_channel_update` (BZ161-gated, no separate reducer).
  `post_permission` (`'all'|'admins'`, default `'all'`) gates ordinary
  posting in an announcement channel (BZ164, pre-existing).
  `broadcast_permission` (`'admins'|'all'`, default `'admins'`) gates
  `@channel`/`@all` (BZ166) — flipping a channel to `'all'` opens broadcast
  to any member of THAT channel only. Route: `PATCH /chat/channels/{id}`
  (`channels.go`).
- **Polls** (`chat_poll.sql`, V122): a poll is anchored to its message —
  `chat_poll_create` posts THROUGH `chat_message_send`
  (`msg_type='poll'`), never a direct INSERT, so it rides the same
  membership/permission/seq/notify plumbing every message uses; the pollId
  is stamped into the message's `payload` in the same transaction.
  `chat_poll_vote`: `SELECT..FOR UPDATE` serializes concurrent votes;
  single-vote replaces, multi accumulates via `ON CONFLICT DO NOTHING`
  (idempotent). Votes do **NOT** bump `change_seq` (write-amplification
  ceiling) — fan-out is `poll_voted` only. `chat_poll_close`: creator OR
  channel owner/admin only (BZ161, reused); never re-opened. Results are
  **non-anonymous** (per-option voter lists — vote rows are member-readable
  under RLS regardless, so hiding voters would be a curtain). Poll rows are
  **never destroyed** on message soft-delete (implicitly closes the poll
  instead) — same never-destroy posture as body/revisions/attachments; no
  poll editing, ever (delete + recreate). **BZ177 vs BZ161 split**: BZ177
  covers poll/option-not-found/anchor-deleted/already-closed (one code, no
  oracle, 422); the manual-close wrong-actor case reuses BZ161 (403) rather
  than minting a second poll-specific forbidden code. Routes: `POST
  /chat/channels/{id}/polls`, `POST /chat/polls/{id}/vote`, `POST
  /chat/polls/{id}/close`, `GET /chat/polls/{id}/results` (`poll.go`).
- **Search** (`chat_search.sql`, `search.go`): `GET
  /chat/search?q=&in=&from=&before=&has=` scopes membership IN-SQL (a plain
  JOIN, not an error) — a non-member's query and a genuinely-empty result
  look identical, deliberately no BZ code (no membership oracle to
  protect). **CJK routing (CN-critical)**: `HasHanRune` routes a
  Han-containing query to the `pg_trgm` `body ILIKE` leg
  (`chat_messages_body_trgm_idx`) instead of the `'simple'`-config
  `tsquery` leg, which cannot tokenize Han text — without this, zh search
  returns nothing. Proper zh segmentation (zhparser/pg_jieba) stays
  deferred; substring match is the v1 floor. Cursor is the GLOBAL
  `chat_messages.id` (not `seq`, which is per-channel and can't keyset
  across channels). `has=attachment` is the only recognized filter; an
  unrecognized value matches nothing, never a 500. Attachment content
  search does not ride this rail (`body` only) — still open.
  `chat_messages_list` also gains `p_around_seq` (jump-to-message: target
  seq ± `p_limit` rows each side, ascending) wired as `?aroundSeq=` on `GET
  /chat/channels/{id}/messages`.
- **My-Threads inbox** (`chat_threads.sql`, `threads.go`): `GET
  /chat/my-threads?limit=` — a "thread" is a top-level message with ≥1 live
  reply; caller is "in" it if they authored the root/a reply or were
  `@mentioned`. Membership re-checked at QUERY time (removed-then-query
  drops it immediately). `unreadCount` reuses the DES-010 watermark (no new
  write path) — a channel-wide approximation, not a true per-thread cursor.
  No BZ code (no membership oracle).
- **Org-default channels** (`chat_org_defaults.sql`, V122 §G): backend-only,
  no admin console page. `org_default_channels` is the org catalog
  (org-admin-gated via `users.is_local_admin` — BZ161, a DIFFERENT
  authority axis than every other BZ161 raiser here, which are CHANNEL-admin
  gates). Marking default backfills membership for every enabled user in
  one INSERT…SELECT (one aggregate notify, not per-user).
  `chat_autojoin_defaults` is the provisioning hook off the ONE
  `provision_account` seam (admin-create/CSV/AD/LDAP/SCIM/JIT), idempotent
  (`ON CONFLICT DO NOTHING`). **Membership by policy, not by choice**:
  org-default membership is non-revocable by the member —
  `chat_member_remove` rejects a self-leave on an org-default channel
  (BZ163, reused) so an idempotent re-sync can't silently boomerang an
  intentional leave; admin-initiated removal is unaffected.
  `chat_channel_create` gates non-admin creation on `chat.channel_creation`
  (V122 seed, DEFAULT ON — `drive.space_creation`'s shape).

## BZ160–178 map (`errors.go`)

`writeChatProblem` wraps the shared `reducererr.WriteProblem(w, r, err,
ProblemOptions{Namespace:"chat", Slugs:bzSlug})` kit (whole-pipeline review
arch #3 — the projection mechanics live once in `shared/reducererr/wire.go`
(moved from `mailserver/internal/reducererr` by arch #A8); never a hand-rolled
`pgErr.Code` switch — `scripts/check-reducererr-contract.sh` forbids that
outside `shared/reducererr`). The wire STATUS comes from
`reducererr`'s shared `codeClass` table; `bzSlug` here only adds the
RFC7807 `type`/`code` fields on top:

| Code | Meaning | Status |
|---|---|---|
| BZ160 | `notify_chat_state`: NULL channel (internal-seam guard, not reachable from a real request) | 400 |
| BZ161 | not owner/admin (channel update incl. post/broadcast-permission flip, member add/remove, poll manual-close, org-default set) | 403 |
| BZ162 | invalid create/DM/notif-level/permission args | 422 |
| BZ163 | caller not a channel member (send, mark-read, typing, thread-list, roster, self-leave on an org-default channel) | 403 |
| BZ164 | announcement-channel post by a non-admin | 403 |
| BZ165 | thread parent missing / other channel / soft-deleted — one code, no oracle | 422 |
| BZ166 | `@channel`/`@all` broadcast by a non-owner/admin (gated by `broadcast_permission`) | 403 |
| BZ167 | edit/delete: not the author (delete also allows owner/admin) — one code covers not-author/not-a-member/already-deleted/doesn't-exist, no probe | 403 |
| BZ168 | message body empty or over the 64 KiB cap | 422 |
| BZ169 | reaction/pin/save target message not found/deleted | 404 |
| BZ170 | joining a private or nonexistent channel — anti-oracle leg, both read identically (drive's BZ139 posture); ALSO `chat_dm_open` naming a target member id that isn't an existing, enabled user — a nonexistent id and a disabled/offboarded one read identically, same anti-oracle posture | 404 |
| BZ171 | mutation attempted against an archived (read-only) channel | 403 |
| BZ172 | attachment payload invalid — >8 per message, or malformed `sha256`/`size`/`name`/`manifest` | 400 |
| BZ173 | attachments unavailable — non-empty `p_attachments` while `feature.drive` disabled (reducer-level belt) | 403 |
| BZ174 | *allocated, not raised* — reserved for an explicit attachment-not-found signal on a future read path | — |
| BZ175 | chat-bound-space governance violation (DES-009) — ad-hoc grant/revoke, or trash/move/rename/new-version on a node already referenced by `chat_message_attachments` | 403 |
| BZ176 | pin permission (channel-kind, not owner/admin) | 403 |
| BZ177 | poll invalid — not found/anchor deleted/already closed | 422 |
| BZ178 | voice message duration cap (300000ms/5min) | 422 |

## Attachments (A2) — files live in a chat-bound Drive space, never a personal one

**The bet:** every chat attachment — channel and DM alike — lands in a Drive
space auto-provisioned per channel (`chat_space_ensure`, worker-owned
`SECURITY DEFINER`), with file access a LIVE function of current channel
membership — never a frozen share-at-send grant, never the uploader's
personal space (the Teams storage flaw this pillar fixes). Full governance
model (derived membership, no ad-hoc grants, immutable attachment nodes,
hidden from `/drive`) is ADR **DES-009**; this doc covers only the
`internal/chat/` consumer surface.

- **`POST /chat/channels/{id}/space` → `{spaceId}`** (`channels.go`) calls
  `chat_space_ensure`, membership-gated (BZ163), idempotent.
- **`POST /chat/channels/{id}/messages` gains `attachments: []`**
  (`messages.go`) — `null`/empty normalized to `'[]'` BEFORE the
  drive-off gate check, so a plain send is unaffected by `feature.drive`'s
  state; non-empty with `feature.drive` OFF 404s (BZ173 reducer-side belt).
  Passed straight through as `p_attachments jsonb` — the Go layer never
  inspects/validates/transforms it; every decision (8-item cap, shape
  validation, node creation, `drive_file_put_version` quota/dedup/claims,
  name-collision suffix, link-row insert) happens atomically in the
  reducer, in the SAME transaction as the send — an unsent message never
  orphans a landed file.
- **Conversations envelope** gains `attachmentsEnabled: feature.chat AND
  feature.drive` (top-level; `feature.drive` OFF hides attachments but
  never affects plain messaging) and a nullable per-conversation `spaceId`.

**Deletion posture (matches A1's body-retention pin):** soft-deleting a
message projects `attachments: []` in every read path (link row + version +
bytes retained, never destroyed — A4a's job) AND revokes content access —
the Drive content route 404s a version whose ONLY
`chat_message_attachments` rows are all for soft-deleted messages
(`chatAttachmentLiveSQL`). The eDiscovery worker pool (BYPASSRLS) can still
read the row directly — deleted-for-members ≠ purged.

**The orphan-chunk reaper** (closes a pre-existing Drive bug, not just an A2
leak): a chunk registered but never referenced by a `put_version` call (an
abandoned composer) was never GC'd or quota-charged. `drive_maintenance_sweep`
now also enqueues any `ref_count=0` chunk whose only `drive_upload_claims`
row is past its 7-day TTL, and prunes the expired claim rows.

**Immutability (DES-009 D4):** a derived `editor` (any plain channel
member, zero `drive_space_members` rows) can ordinarily trash/rename/move/
re-version any node in a space they edit. A chat-attached node is the one
exception — BZ175 rejects all four mutations when the target node has a
`chat_message_attachments` row, keeping it a point-in-time record and out
of the trash→`destroy_hard` pipeline (whose un-handled FK would otherwise
abort the maintenance worker's sweep forever). Pinned live by
`TestA2DerivedEditorCannotMutateChatAttachment` and
`mailserver/sql/tests/chat_attachment_immutable.pg` (also proving a
non-attached file in the same space is unaffected).

## Push seam + `notify_decouple` recommendation + fan-out ceiling

Every mutating reducer calls `notify_chat_state(p_channel_id, p_event,
p_message_id, p_seq)` (never raw `pg_notify`) — fans out to **every
member's own** `chat:{user_id}` self-channel via `app_notify`, the same
drive-watch pattern `internal/ws/handler.go`/`eventsource.go` run.
Reactions carry the reacted-to message's CURRENT `seq` (they don't bump
`change_seq`); every other event carries the mutation's own new `seq`.

`ponytail:` the fan-out loop is `O(members)` **inside the write
transaction** — fine at low-hundreds-of-members scale, a real ceiling
above that. Two documented, unbuilt mitigations: (1) flip
`feature.notify_decouple` ON for chat-heavy orgs — moves fan-out into
`notify_intents` drained by `notifyjobs.NewWorker` (already wired,
config-only, do this first); (2) channel-scoped push subscriptions
(`chat:{channel_id}` instead of per-member) — needs the WS/SSE dispatcher
to manage dynamic per-channel subscription sets it doesn't have today, only
worth it if (1) alone isn't enough.

Typing has its own, tighter cap: `chat_typing_signal` silently no-ops (no
error, no notify) above 32 members — the worst NOTIFY-storm amplifier in
this package.

## Presence — deliberately not reducer-backed

`Presence` (`presence.go`) is a process-wide, in-memory connect-COUNT
registry (not a bool — multi-tab/device safe), maintained by
`ws/handler.go`'s WS Upgrade and `ws/eventsource.go`'s SSE handler
(`Connect`/deferred `Disconnect`) around their existing `chat:{uid}`
subscribe block. No DB row, no push — `GET /chat/presence?userIds=` is the
only reader, clients poll (≤1/60s, visible users only). `ponytail:`
process-local; a multi-node `mailserverd` deployment would need this
centralized (Redis/a shared table) — not built, not needed at current scale.

## DES-008 — discovery-not-access invariant

`chat_channels.visibility` (`public`/`private`) controls ONLY whether a
channel is **discoverable and self-joinable** (`chat_browse_channels` lists
public non-archived channels; `chat_channel_join` self-joins one).
Visibility never controls **content or membership-roster access** — every
read path (messages, roster, mention-search, thread-list) is gated on
actual membership, always, with no preview exception for a public
channel's content. This is why BZ170 (join) and the private-channel-hidden-
from-browse behavior exist as separate, deliberately identical-looking
failure modes: discovery is cheap and public-channel-scoped; access is
membership-scoped and uniform everywhere else.

## Mobile push (A3.5) — server-side `notif_level`/DND enforcement at push time

Plan: `retired-docs:superpowers/plans/archive/2026-07-12-chat-A3.5-mobile-push.md`. Closes
the gap left after A3: `notif_level`/`chat_notifications` were
readable/settable but nothing FILTERED a push on either value, and no
mobile-push leg existed. **The WS relay (`notify_chat_state`/
`forwardRawEvents`) stays byte-for-byte verbatim** — every A3.5 change
lives in a NEW layer (`chat_push_should_notify` + the pushjobs drain leg),
never in the mutating reducer's own fan-out.

- **Schema** (`V124__chat_push.sql`): `chat_push_intents` — ONE row per
  MESSAGE (`UNIQUE(message_id)`, idempotent enqueue), never per member;
  per-member fan-out is the worker's job. No RLS (worker-only table, the
  `push_intents`/`scheduled_actions` precedent). Toggle
  **`feature.chat_push`** (its own toggle, DEFAULT OFF) — does not ride
  `feature.mail_push`.
- **Enqueue**: `chat_message_send`, in-txn, O(1), toggle-gated.
- **Gate `chat_push_should_notify(user_id, channel_id, message_id)`** — the
  chat sibling of `push_should_notify`, same DND-window logic (tz/
  overnight-wrap/day-mask, resolved via the caller's PRIMARY mailbox).
  Decision order (first false wins): sender-is-self → **in-meeting
  suppression** (the recipient is PRESENTLY a participant, `left_at IS
  NULL`, of a LIVE meeting whose `meetings.chat_channel_id` binds this
  channel — scoped to the recipient's own live participation, never "a
  meeting exists"; a member who never joined the huddle, already left, or
  whose meeting ended is pushed normally) → per-channel `notif_level`
  (`'none'`→false, `'mentions'`→false unless mentioned/broadcast/DM) →
  global `chat_notifications` (`'off'`→false) → `push_enabled` false → DND
  window → soft-deleted message.
- **pushjobs second drain leg** — see `mailserver/internal/AGENTS.md`'s
  `pushjobs` row for the full worker contract. No-retry-after-fan-out
  (multi-recipient intent, unlike mail's single-recipient row);
  mention-safe coalescing; no-body payload built per member; a 7-day
  reaper for terminal rows.
- **Webmail service worker**: chat notifications — title = sender (mention
  → i18n prefix), body = channelName (DM → "Direct message"), `tag:
  dedupeTag` (per-channel replace), click → `/chat?channel={id}&seq={seq}`
  → `chatStore.openChannelAt` (deep-link).
- **HarmonyOS**: `PushService.initialize(context)` wired at
  `EntryAbility.onCreate` — Huawei/HarmonyOS fleet only; on-device
  verification pending (no device/emulator boot in this sandbox).

**Fleet coverage (the honest rollout claim):** `feature.chat` is flippable
for Huawei/HarmonyOS + desktop-browser + iOS-PWA fleets. iOS-native = nothing
until APNs un-stubs (client work, not server-closable). Non-Huawei CN
Android (~55%+ of CN handsets, 小米/OPPO/vivo) has no OEM channel — push =
wake hint via next-app-foreground, not a guarantee, a deliberate posture
(no OEM channel exists unless one is ever procured).

## A1/A2/A3/A3.5 deferrals (owners, not vague "later")

See root `TODOS.md` "Chat A1"/"Chat A2"/"Chat A3" sections for the
authoritative list; summarized here:

- **Attachment content/filename search → open, no owner.** `chat_search`
  matches `body` only (filenames are searchable via A4b's eDiscovery
  reader only, not the general search route).
- **Per-channel quota admin UI → open, no owner.** `chat_space_ensure` sets
  a default `upload_max_bytes` (capped, not unlimited) but no admin surface
  exists to view/adjust it per channel.
- **Guest file access tiers → shipped in Guest G4.** A guest-in-channel derives
  a live `viewer` role, never editor/manager; office-PDF preview remains
  membership/history-floor scoped, while original bytes require the guest
  profile's reducer-enforced `allow_download`. Viewer guests cannot upload:
  the conversations envelope reports `attachmentsEnabled:false`, and the
  chunk PUT rechecks editor authority before storage. No frozen share is
  materialized.
- **Rich presence → post-B backlog.** A1 ships polled online/offline dots
  only; push presence updates, away/custom-status text are not built.
- **Channel-scoped push subscriptions → documented alternative, not
  built.** See "Push seam" above.
- **A3's own NOT-in-scope items**: voice transcript (A4/later) ·
  translation streaming (`/assist/stream` 501, later) · unfurl on non-chat
  surfaces (later) · zh segmentation/stemming via zhparser/pg_jieba (later
  — pg_trgm substring is the shipped v1 floor) · scheduled-send
  edit/reschedule (later — cancel + recompose is v1) · ownership-transfer
  UI (A4) · thread-participant server-side notices (covered client-side by
  the My-Threads unread badge) · an org-level `chat.read_receipts` kill
  switch, default ON (later, for works-council jurisdictions).

## Records lifecycle (A4a) — audit chain, retention, legal hold, purge, gxp/WORM channels

Plan: `retired-docs:superpowers/plans/archive/2026-07-12-chat-A4a-records-lifecycle.md`
(migration V126, BZ191–196). Behind **`feature.chat_compliance`** (seeded
OFF), with ONE deliberate exception: the per-user send rate limit (below)
ships live to every deployment, gated on nothing.

**Ship posture (binding — repeat verbatim, do not soften):** A4a is
substrate, not a shippable compliance story. `feature.chat_compliance`
must not be flipped ON in a customer deployment until eDiscovery
reader/export exists. Retention destroys content that no shipped surface
can produce; a legal hold you cannot produce from is inert. **A4b (below)
shipped the eDiscovery reader/export — the flip blocker is satisfied;
`feature.chat_compliance` is now flippable (still seeded OFF).** The 会话存档
GTM claim rests on A4a+A4b together, never A4a alone.

**The chain records ACTS, never per-message sends** (the seq rail already
replays every message; a chain write per send would serialize the hottest
path). Acts = message edit/delete, pin/unpin, membership
add/remove/join/leave, hold set/release, classification change, retention
change, purge execution, chain anchor, translate egress — plus A4b's
writer-less catalog entries (`export.run`, `search.run`, `dlp.block`,
`barrier.change`, `membership.inherit`, `push.emission`, `role.change`,
`rescope.execute`). `chat_audit_log` is `(channel_id, id)`-keyed, FORCE-RLS
with **zero policies** (deny-all — a legal hold must be invisible to the
custodians it targets); every read is an admin route on `workerPool`
(BYPASSRLS); the writer is `chat_access_audit` (SECURITY DEFINER,
worker-owned, `pg_advisory_xact_lock`-serialized per channel — the
`drive_access_audit.sql` shape). `chat_audit_actions()` is the closed
catalog; an unrecognized `p_action` raises **BZ191**.

**What the anchor proves, and what it does not** (`chat_chain_anchor`/
`chat_chain_anchor_verify` — the plan's "What is and is not tamper-evident"
is the authoritative unabridged version):
- **Per anchored id-range:** no message was inserted, removed, or
  back-dated, and no message's ORIGINAL body was rewritten. The leaf hash
  is `sha256` of the first revision's `prior_body` (or the current `body`
  if never edited) — a later legitimate edit never falsifies a past anchor.
- **A lawful purge reconciles to a hard TRUE, never a benign excuse.**
  `purge.execute`'s `after_state` carries per-id `destroyedElems:
  {id: "id:author_id:epoch:sha256(original_body)"}`, and
  `chat_chain_anchor_verify` recomputes `H(surviving leaves ∪ destroyed
  leaves recovered from the chained purge acts)` — both acts live on the
  same HMAC chain, so recovered leaves are themselves unforgeable. (A prior
  scalar "purge_overlap" excuse-field design was rejected — it made
  tampering and lawful destruction indistinguishable; it does not exist.)
- **A fabricated `chat_message_revisions` row fails the verdict** — INSERT
  on that table is unrestricted by construction, so the verifier asserts
  every revision row in the range has a matching chained `message.edit`
  act, **scoped to the chained era** (`created_at >=
  chat.compliance_enabled_at`, a `system_config` row the anchor lazily
  stamps on its first run — without this floor every pre-flip edit would
  verify FALSE forever).
- **A tail-truncated chain is caught, never silently re-blessed.** A pure
  HMAC chain detects forgery/mid-chain deletion but not a contiguous TAIL
  delete. Closed with a **chain-head notary**: after its per-channel loop
  the anchor writes ONE row to the separate, append-only, HMAC-chained
  `admin_audit_log` (`action='chat.chain_notary'`), recording every
  channel's current chain head as `GREATEST(live head, prior notarized
  floor)` — non-regressing, so a truncated channel can never heal into a
  fresh baseline. The next anchor refuses to re-anchor (loud `RAISE
  WARNING`) any channel below/differing from its notarized floor;
  `VerifyAudit` reports **TRUNCATION DETECTED**, not a pass.
- **Residual (state to auditors, do not overclaim):** a superuser who
  coherently truncates BOTH chains (bypassing `chat_audit_log`'s deny-all
  via BYPASSRLS `setjoin_worker`, and `admin_audit_log`'s
  `trg_audit_append_only` via table ownership/superuser) AND forges any
  off-box copy is not caught by anything DB-resident — retain each
  `VerifyAudit`'s head id/checksum off-box. `destroyedElems` is **body-only**
  — poll options/votes, reactions, and an attachment's `sha256` are not
  individually digested into the purge act (they die by the same CASCADE,
  outside this specific digest).

**Retention:** `chat_effective_retention(channel_id)` resolves the
most-specific enabled `chat_retention_policies` row (kind-specific beats
`'all'`, shortest wins on a tie) OR the channel's own override
(`chat_channels.retention_days`, **BZ195** on invalid days/toggle-off/not-
found). Org policies carry `effective_at DEFAULT now() + 7 days` — a 7-day
undo window BY CONSTRUCTION. `UpdatePolicy` re-arms
(`GREATEST(effective_at, now()+7d)`) whenever the edit is MORE destructive.
`DeletePolicy`/a shielding-weakening update are gated by an
effective-retention-EXPOSURE check: a change that would shorten ANY
channel's effective retention refuses with `409 {code:"exposure",
exposedChannels}` unless `?confirm=DESTROY`. The **per-channel override is
disclosed as immediate-by-design**, not graced — one admin, one channel,
`chat.compliance_manage`-scoped, fronted by a typed-DESTROY confirm in the
channel sheet, not a week's delay.

**Legal hold beats retention/WORM by construction — a trigger, not a query
predicate.** `chat_hold_active(channel_id)` (SECURITY DEFINER,
worker-owned) is the **single-homed predicate** every consumer calls — the
`trg_chat_message_hold` BEFORE DELETE trigger (**BZ194**, HINT
`type:"litigation_hold"`), the purge sweep's channel selection, and the
admin channel list/tile/preview reads, and NOTHING else.
`scripts/check-chat-hold-truth.sh` machine-checks that no raw `legal_hold`
read exists outside the predicate's own plumbing. `chat_channel_set_hold`
manages the boolean arm's `legal_hold`/`legal_hold_reason` (**BZ195** on
toggle-off/not-found/conflicting-matter-SET/no-reason-RELEASE). **One
matter per channel** on the boolean arm: setting a second, different matter
on an already-held channel is rejected, not silently overwritten; release
is **reason-scoped** — a non-matching reason is a silent no-op, never
BZ195. `SELECT … FOR UPDATE` on the channel row serializes two admins
racing to first-hold the same channel for different matters. A held
channel's soft-delete (UPDATE) stays allowed — hold blocks destruction, not
tombstoning. (A4b's durable case-hold table dissolves the one-matter
ceiling via a second predicate arm — see "Oversight (A4b)" below.)

**The purge sweep — `chat_purge_expired`/`chat_purge_run`, the ONE place
chat content is ever truly destroyed:** selects `retention_days > 0`
regular (never `gxp`) channels not under hold, past their effective
retention; destroys messages, revisions (CASCADE), reactions, mentions,
pins, saves, poll rows, translations-in-payload, AND expired non-`pending`
`chat_send` `scheduled_actions` rows (an orphan `failed`/`done`/`processing`
row in a channel with zero expired *messages* still has its verbatim body
destroyed) — every destroyed message's leaf rides `purge.execute`'s
`destroyedElems` for the anchor to reconcile against.
`chat_purge_run()` **drains within a 90-second wall-clock budget** (cron
`50 2 * * *`, after the anchor's `40 2 * * *`), looping
`chat_purge_expired(5000)` until the backlog is empty or the budget is
spent — a large backlog takes several nights (the Overview tile/confirm
copy say so). **`last_purged_seq` is provenance ONLY** — never a replay
cursor (`seq` is re-stamped on every edit/delete, not contiguous over the
purged set). Attachments: `chat_purge_expired` **stages** the node
(`deleted_at`/`purged_at` direct UPDATE — the one deliberate, purge-only
lift of the chat-attachment never-trash posture, legal because BZ175 lives
in a reducer check, not a trigger) before `drive_node_destroy_hard`
reclaims bytes/refcount — see `internal/AGENTS.md`'s `drive` row for the
full staging contract. The scheduled-row destruction leg folds a
`scheduledDestroyedCount`/`scheduledDestroyedIds` array into the SAME
`purge.execute` act as the message stats (`scheduled_actions.id` is a
`uuid`, so the act carries the honest destroyed-id list, not a fabricated
range); a channel with ONLY expired scheduled rows and zero expired
messages still gets its own act (`purgedCount:0`, populated scheduled
fields) — an unrecorded-destruction gap this closed.

**gxp/WORM channels:** `chat_channel_set_classification` upgrades
`regular`→`gxp` only, never downgrades (`trg_chat_channel_no_downgrade_fn`,
**BZ192**), requiring `retention_days`/`worm_mode` already set (**BZ195**
otherwise). On a `gxp` channel, `trg_chat_message_worm_fn`/
`trg_chat_revision_worm_fn` block `body`/`deleted_at` changes inside the
retention window (**BZ193**) — NULL retention = infinite (fail-CLOSED).
`payload`/`seq`/`edited_at`-only changes (pin/poll curation) are EXEMPT —
which is why gxp channels **disable unfurl** (the unfurl-merged-preview
write into `payload` is content; widening the WORM exemption to cover it
would be the wrong fix). `chat_space_ensure` creates a gxp channel's bound
Drive space gxp-FROM-BIRTH and stamps
`drive_chunks_extend_retention('g', shas, until)` — the global-pool→
per-space chunk re-scope that would make S3 Object-Lock meaningful stays
**deferred to Drive P5** (a `'g'`-scoped chunk with a future `retain_until`
is already GC-proof; immutability comes from the DB triggers + BZ175, not
the scope key).

**Rate limit (live to every deployment, gated on nothing):**
`chat_message_send` raises **BZ196** (`ClassSendQuota`, HINT
`type:"sending_quota_exceeded"` + `retryAfterSeconds`) past
`system_config['chat.send_rate_per_minute']` (default **60**, `0`
disables) — a later `RAISE` in the same transaction rolls the counter back,
so a failed send consumes nothing. No admin UI — `system_config` only.
The counter table `chat_send_counters` (`user_id` PK) carries **FORCE RLS +
a self-scoped policy** (self-scoped, `user_id = current_setting(...)`, NOT
the `chat_audit_log` deny-all shape — the writer is an ordinary
non-`SECURITY DEFINER` reducer upserting the caller's own row; a deny-all
policy would make it permanently unwritable once native-RLS lands).

**BZ191–196:** BZ191 unknown chat audit action (`ClassUnprocessable`) ·
BZ192 compliance no-downgrade (`ClassConflict`) · BZ193 WORM
message/revision immutable inside retention (`ClassConflict`) · BZ194
legal hold blocks destruction (`ClassForbidden`, HINT
`type:"litigation_hold"`) · BZ195 invalid compliance arguments
(`ClassUnprocessable`) · BZ196 send rate limited (`ClassSendQuota`).

**Retention-label vocabulary (pinned, do not invent a fourth translation):**
a `regular` channel's `retention_days` is a **destroy ceiling** ("Permanently
delete messages older than {n} days" / 超过 {n} 天后永久销毁（不可恢复）);
a `gxp` channel's is a **WORM keep-floor** ("Messages cannot be edited or
deleted for {n} days" / {n} 天内不可编辑或删除（WORM 保存期限）). Never
"retain for {n} days" / 保留 N 天 / 保存期限 as a ceiling label — the CN
compliance reading of 保存期限 is a mandatory floor, the opposite of a
regular channel's knob, and a mistranslation here destroys customer data.

**Admin surface:** `internal/admin/admin_chat_compliance.go`
(`ChatComplianceHandler`) — see `internal/AGENTS.md`'s `admin` row. Webmail:
`admin/(access)/chat-compliance/` — see `mailserver/webmail/AGENTS.md`'s
Access console entry.

**End-user surface (deliberately minimal):** a channel-header WORM badge
when `classification==='gxp'`, and a retention indicator when
`retentionDays` is non-null — both wording single-homed in
`store.svelte.ts`'s `retentionNotice()` so the header tooltip and the
channel settings sheet's read-only Retention row can never diverge on the
ceiling-vs-floor wording. **`legalHold` is deliberately NEVER projected to
end users** (tipping-off) and **`last_purged_seq` is deliberately never
projected** (provenance, not a client-visible cursor) — both decisions, not
oversights.

### NOT in scope (A4a) — carried forward, not silently dropped

The `'g'`→`'s<space_id>'` chunk re-scope (→ Drive P5, gate 1) · disposition/
destruction of gxp channels past their WORM window (→ an explicit,
reviewed, approval-gated action when a customer's records schedule demands
it, never a cron) · a grace window on the per-channel retention override
(disclosed immediate-by-design) · per-channel quota admin UI · org-policy
priority/reorder UI (resolution is specificity+shortest, deterministic
without one) · a rate-limit admin UI (`system_config` only) · client-side
purge-floor refetch logic · link-preview cache pruning · a per-message
body-hash column (the last tamper-evidence gap — build only if a regulator
asks) · locales beyond en/de/zh.

## Oversight (A4b) — eDiscovery reader/export + durable case holds

Plan: `retired-docs:superpowers/plans/archive/2026-07-15-chat-A4b-oversight.md`
(migration **V127**, **BZ197/BZ198**). Spec:
`retired-docs:superpowers/specs/2026-07-15-chat-A4b-oversight-design.md`. Same
toggle as A4a — **`feature.chat_compliance`**, no new toggle: A4b is the
second half of one feature, and is what made flipping the toggle ON
**shippable** (see the A4a Ship-posture paragraph above). Every admin
route 404s live when the toggle is OFF (per-request `gate`, never cached).

**Substrate (V127):** three FORCE-RLS **deny-all** tables (zero policies —
holds and reader activity invisible to custodians, the A4a tipping-off
rule; `rls_chat_oversight.pg` proves the custodian themselves sees zero
rows): `chat_case_holds` (case_id FK → `ediscovery_cases`, EXACTLY ONE of
`custodian_user_id`/`channel_id` — CHECK; partial-UNIQUE dedups active
holds; channel FKs `ON DELETE RESTRICT` — coverage fails loudly, never
vanishes) · `chat_case_hold_channels` (materialized coverage,
`source IN ('snapshot','join')`) · `chat_ediscovery_searches` (the case
record of every reader invocation). Plus the `chat.ediscovery` permission
and the BZ197/198 `reducererr` classes.

**The two-arm hold predicate:** `chat_hold_active(bigint)` v2 = arm 1 (the
A4a `chat_channels.legal_hold` boolean) `OR` arm 2 (an active
`chat_case_holds` row covering the channel via `chat_case_hold_channels`).
The BZ194 trigger and the purge sweep call it unchanged — **the destruction
path gained zero writers**: no new writer to
`chat_purge_expired`/`chat_purge_run`, no new content-DELETE path anywhere
in A4b. A4a's BZ195 one-matter-per-channel ceiling and the reason-scoped
release workaround both dissolve: two cases hold one channel as two rows;
release is **case-scoped by construction** and writes a `hold.release` act
only for channels losing their LAST active case-hold coverage.
`scripts/check-chat-hold-truth.sh` machine-checks the predicate is the
ONLY hold-truth source — the admin list/tile/preview raw-boolean reads are
repointed onto it (`chat_hold_active(c.id) AS legal_hold`); any remaining
raw `legal_hold` read outside the arm's own plumbing fails the guard. (The
A4a snapshot-loop `chat_custodian_set_hold` was deleted, superseded by
`chat_case_hold_set` — the toggle has never been ON in a customer, no data
migration needed; dev/test boolean holds stay releasable via
`chat_channel_set_hold`.)

**Coverage law:** custodian-hold coverage is materialized at set time as
current memberships **∪ channels the custodian ever authored a message
in** (pre-hold departures/offboarding covered), grown by the V127
`trg_chat_member_case_hold` join trigger on `chat_channel_members` INSERT,
and **NEVER pruned on leave** — leave-can't-expose is the single property
this substrate stands on. The hold-set/join **both-miss race** is closed by
`pg_advisory_xact_lock(hashtext('chat_hold_user_' || uid))` taken by BOTH
sides (reducer before its snapshot, trigger before its hold lookup) —
proven live in `oversight_integration_test.go` (two real pgx conns, the A1
`TestConcurrentLateCommitterReplay` genre). The trigger is SECURITY
DEFINER + worker-owned (deny-all table — an invoker-rights lookup would see
0 rows and silently never materialize coverage, failing OPEN, the worst
direction for a hold).

**Reducers (all SECURITY DEFINER + `apply_worker_ownership`, called on
`workerPool`):** `chat_case_hold_set`/`chat_case_hold_release` (durable
holds; idempotent re-set returns the existing id with no new acts; second
release raises BZ197 with no state change) · `chat_ediscovery_search`
(case-scoped, **deliberately org-unscoped** — DES-008: a distinct,
permission-gated authority plane, not a membership bypass; NO membership
join, NO `deleted_at` filter; FOUR content legs: live+soft-deleted bodies,
revision `prior_body`, scheduled `chat_send` payload bodies
pending+failed, attachment FILENAMES; tsquery/trgm routing verbatim from
`chat_search`) · `chat_ediscovery_read` (one channel's full conversation
window: deleted included, revisions inline, scheduled rows, attachment
meta, `poll: {options[], votes[]}`, plus `last_purged_seq` + purge-act
id-ranges — the record-floor banner data; shares
`chat_ediscovery_message_json`, the canonical per-message JSON shape, with
export, so read and export can never diverge — projects `payload` too, so
retention can never destroy content export could never have produced) ·
`chat_ediscovery_export_begin` (export act writing + chain heads; the Go
handler streams). **Every reader access itself lands as a chained act**:
interactive search/read persist a `chat_ediscovery_searches` row AND write
a `search.run` act per hit channel in the same txn; export writes
`export.run` per included channel before the stream starts. These four act
writers are **writers only — the engine (`chat_access_audit`, anchor,
verifier, notary) is untouched, no catalog migration, no new act types**.
Search rows persist, result rows don't — results are re-runnable over
destruction-proof held scope; the export is the production artifact.

**The record floor (verbatim law):** reader and manifest surface
`last_purged_seq` + the `purge.execute` acts' id-ranges as an explicit
record floor ("this channel's record begins above a purge floor"), never a
replayable cursor, and neither surface ever claims the record "proves a
specific held message was not destroyed" — the digest proves what
`destroyedElems` leaves say and nothing more. The disclaimer sentence lands
verbatim in BOTH surfaces: console i18n
(`admin.chatCompliance.ediscovery.recordFloorDisclaimer`, en/de/zh) and the
manifest `disclaimers` block.

**Export artifact:** `GET /admin/chat-ediscovery/export` streams a ZIP
built inside **ONE REPEATABLE READ transaction**
(`admin_chat_ediscovery_export.go`): `messages.jsonl` (canonical
per-message JSON, polls intact) + attachment bytes (fetched by
`content_sha256` through the Drive chunk manifest on workerPool, never the
member content route — DES-009 D5) + `manifest.json` written **LAST**,
carrying counts computed in the same snapshot (can never diverge from the
streamed rows, by isolation), the whole-file `sha256` of `messages.jsonl`,
per-channel chain heads, the record floor, the `export.run` act ids, and
the `disclaimers` block. `lastPurgedSeq`/`purgeActs`/per-channel
`chainHead` are re-read INSIDE the RR transaction per channel (never
`export_begin`'s begin-time values, which only lower-bound the pin) so a
purge committing mid-export can't stamp the manifest with a floor the
streamed content already moved past. The attachment stream tees every
written byte through a `sha256` hasher and compares against the entry's
own sha-named path, abandoning (no manifest) on mismatch rather than
shipping silently-corrupted content under a false-hash filename. Custody
posture mirrors mail's `admin_ediscovery.go` (sha256 + disposition) into
manifest fields. `GET /admin/chat-ediscovery/export` is a state-writing GET
by design (it writes `export.run` acts) — the only CSRF surface it opens
is act/row spam, never disclosure, since the response still requires the
browser to read cross-origin content the attacker's page can't see.

**Permission split (SoD):** `chat.ediscovery` (V127, `is_privileged`/
sensitive, deliberately OUTSIDE the SoD class map — the `drive.manage`
precedent) gates search/read/export — NOT `compliance.write` (would
silently grant chat-content read to every existing holder the day the
toggle flips), NOT fused into `chat.compliance_manage` ("may destroy" ≠
"may read"). Holds stay under `chat.compliance_manage`; hold/case reads
under `chat.compliance_view`. `chat.ediscovery` deliberately carries NO
OU/domain reach scoping, unlike `chat.compliance_manage`'s custodian-hold
`admin_can_reach` check — org-wide read is the grant's meaning (grant it
explicitly; the Super-Admin V127 seed).

**Go surface** (`internal/admin/admin_chat_ediscovery.go` + `_export.go` —
split from `admin_chat_compliance.go`, one handler per authority plane):
`POST /admin/chat-ediscovery/holds` (custodian scope carries the
`admin_can_reach` OU-scope check) · `POST
/admin/chat-ediscovery/holds/{id}/release` · `GET
/admin/chat-ediscovery/holds` · `GET /admin/chat-ediscovery/cases` — all
four `chat.compliance_manage`/`_view`; `POST /admin/chat-ediscovery/search`
· `GET /admin/chat-ediscovery/channels/{id}/messages` · `GET
/admin/chat-ediscovery/export` — all three `chat.ediscovery`
(`requireChatEDiscovery`). The A4a `POST /admin/chat-holds/custodian` route
was deleted (superseded — the new reducer requires a `case_id` the old
wire shape lacked).

**Webmail:** the chat-compliance console has two oversight tabs
(`CaseHoldsPanel.svelte` — case picker + case/custodian hold CRUD;
`EDiscoveryPanel.svelte` — search → reader → export with the record-floor
banner + disclaimer verbatim, no ConfirmDestructive on export since an
export destroys nothing). i18n `admin.chatCompliance.holds.*`/
`.ediscovery.*` en/de/zh. `legal_hold`/case-hold state remains never
projected to end users.

**BZ197/198:** BZ197 invalid oversight arguments (bad scope/query/target,
hold not found or already released — `ClassUnprocessable`, 422) · BZ198
eDiscovery case not open (`ClassConflict`, 409). BZ180–184 stays the
unclaimed gap.

**Concurrency invariants (found in eng review, now load-bearing):**
`chat_case_hold_release`'s "last coverage" check takes
`pg_advisory_xact_lock(hashtext('chat_hold_chan_'||channel_id))` per
channel, in id order, BEFORE the NOT EXISTS check — without it, two
concurrent releases of a shared channel's last two holds could each see
the other as still-active and BOTH skip the `hold.release` act
(`TestConcurrentReleaseActLossRace`). `chat_ediscovery_searches.result_count`
is a PER-PAGE count, not a total across pages. The search excerpt's
`array_agg` is `ORDER BY matched_in` (deterministic leg on a multi-leg
match). Scheduled-hit legs in both search and read are clamped to the same
`v_lim` the message legs use.

### Deferred (A4b) — carried, not dropped (each with its seam)

DLP engine (seam: one PERFORM at the top of `chat_message_send` + the
catalogued `dlp.block` writer) · information barriers (seam: the FIVE
membership-creation paths — `chat_member_add`, `chat_channel_join`,
`chat_dm_open`, `chat_autojoin_defaults`, `chat_org_default_set`'s backfill
— enforce at the `chat_channel_members` trigger level or enumerate all
five) · departure/offboarding workflow + ownership-transfer UI (the
inheritance QUESTION is dissolved by the reader — a custodian hold covers
authored channels after departure; the workflow UI is what remains;
`membership.inherit` stays catalogued, writer-less) · approval-gated export
= approval-engine consumer #6 when a procurement demands it
(`drive_export_request.sql` is the fail-closed template) ·
`role.change`/`rescope.execute`/`push.emission`/`dlp.block`/
`barrier.change` writers (push-emission decided NOT chained, CLOSED — the
`pushjobs/worker.go` reap window stays 7 days; revisit trigger is a
procurement demanding 推送审计, then a nightly aggregate act, never
per-emission) · gxp disposition (never a cron) · attachment CONTENT search
(filenames shipped; content needs an org-wide text-extraction/indexing
program; seam: one extra UNION leg in `chat_ediscovery_search` against a
future extracted-text table) · per-channel quota admin UI (carried again) ·
unbounded link-preview-cache prune (carried again) · zh word-segmentation
for eDiscovery search (inherits `chat_search`'s trgm floor) ·
scheduled/async export jobs (v1 streams synchronously; add a job table only
if productions outgrow a request timeout) · a chat-side case UI beyond the
tab (mail's case console is the registry) · locales beyond en/de/zh.

## Federated rooms (C2) — the cross-org surface (DM + rooms), `feature.federation`

The chat rail's federation surface spans two channel shapes, both gated by the same toggle
(`feature.federation`, seeded OFF, `toggle.FeatureFederation`) and both owned by `mailserver/internal/federation`
for the wire/transport half — this section is the chat-side contract: what a channel row means, what
`chat_message_send` does with it, and the product surfaces (routes, webmail) built on top. Full transport/wire
contract (stream auth, ordered exactly-once delivery, the Q1/Q2/Q9 design record): `mailserver/internal/AGENTS.md`'s
`federation` package row. ADR: `docs/adr/DES-012-hub-relay-authority-and-room-residency.md` (rooms only; DMs
predate it and are unaffected — see below).

**Channel binding shapes (all on `chat_channels`, V139 DM columns + V140 room columns, kept structurally
disjoint by CHECK constraints):**
- **Federated DM (C1):** `kind='dm'`, `federated_peer_domain` + `federated_local_key` set, `federated_room_id`
  NULL. The local user is the channel's SOLE member; the remote party is identity metadata only — never a local
  account/directory row. Inbound rows carry `author_id NULL` + `federated_sender_addr` (honest eDiscovery
  attribution). See CONTEXT.md's [[Federated DM]] entry.
- **Hub room channel (C2):** `kind='channel'`, `federated_room_id` set, `federated_peer_domain IS NULL` — this
  IS the hub self-check (a reducer can't see process config; a row created only by `federation_room_create`
  proves hub-ness against the Go-passed local domain, so the shape carries the proof forward). Streams to N
  peers via the roster, never one.
- **Spoke mirror channel (C2):** `kind='channel'`, `federated_room_id` set, `federated_peer_domain` = the bound
  hub domain (the SAME V139 column DMs use, reused with the same meaning: "the one peer this channel streams
  through"), `federated_local_key`/`federated_remote_id`/`member_key` all NULL. Created ONLY by
  `federation_apply_room`'s `op:'invite'` arm, `visibility='private'` (pinned — never V119's `'public'` default,
  which DES-008 would make self-joinable before the contact-owner user acts). `federated_room_removed_at`
  non-NULL = kicked or scope-revoked — archive-read-only, banner state, see below.

See CONTEXT.md's [[Federated room]] entry for the hub/spoke/parked/revoked vocabulary this whole section uses.

**The three-way enqueue split in `chat_message_send` (`chat_message.sql`):** the existing federated read now also
selects `federated_room_id`/`federated_room_removed_at`. After the local `chat_messages` INSERT:
- **DM** (`federated_peer_domain` set, `federated_room_id` NULL — the pre-C2 condition, now explicit): one
  `federation_enqueue` to the peer, `content_type='application/x-setjoin-chat'`. Unchanged from C1.
- **Spoke** (both set): one `federation_enqueue` to the single bound hub, `content_type='application/x-setjoin-room'`,
  payload `{op:'message',roomId,fromAddr,body,sentAt,clientMsgId}` — deliberately carries NO `originDomain`; the
  hub stamps it (DES-012's hub-relay authority). `p_user_initiated=true` — BZ205 backpressure protects the human.
- **Hub** (`federated_room_id` set, `federated_peer_domain` NULL): the local land already happened;
  `federation_room_fanout` relays the same payload to every other active roster member in the same reducer call,
  stamping `originDomain` from the room's own `hub_domain`.

New send-path refusals (both shapes it applies to, this reducer's own site): **BZ212** (Q11 content scope — an
attachment or a non-`'text'` `msg_type` cannot propagate to a federated room, so it is refused rather than
silently desyncing every member org's copy) and **BZ213** (kicked/scope-revoked mirror — `federated_room_removed_at`
set — the archive-read-only law, enforced here, not just at the UI). Every channel, federated or not, also gains
one universal guard: `msg_type='system'` is refused as user input (BZ168, the reused invalid-arguments family) —
`'system'` is reserved for the applier-inserted federation gap marker (below); the CHECK constraint alone
cannot forbid a forged row (a constraint can't see call-site identity), so this reducer-level guard is the real
enforcement point.

**Guest obligation — DISCHARGED (Guest Accounts G0 Task 8):** this section's design record originally carried a
standing obligation for a future guest-accounts program to close the guest⇄federation exclusion. That program
shipped it: BZ216 refuses a guest account at all three reachable sites — `chat_member_add` (guest joining an
already-bound channel, under the channel row's `FOR UPDATE` lock), `federation_room_create` (binding a channel
that still has a guest member, under the SAME lock discipline), and `federation_dm_ensure` (a guest as the local
caller opening a federated DM) — proven live in `guest_federation_refusal.pg`. See "Guest doors (G0)" below for
the full guest-accounts contract this pillar now carries.

**BZ209–213 (`shared/reducererr`, this pillar's own federation-room codes — BZ202–208 are the C1 transport
codes, `internal/federation/AGENTS.md`'s row):**
- **BZ209** — the room-bind/archive/org-default refusal family (Q13/Q14): channel not eligible to become a room
  (not `kind='channel'` / already bound / archived / DM-shaped / an org-default channel), OR archiving a
  room-bound channel while the hub still has active member orgs / while a spoke mirror is still live.
- **BZ210** — gxp classification × room binding, both arms (Q7): a gxp channel cannot bind, and a room-bound
  channel cannot be gxp-classified (a WORM claim is unenforceable on a remote org's copy).
- **BZ211** — the room membership-authority family (Q3): owner/admin required, channel not hub-shaped, target
  is the room's own hub, `contactAddr` domain mismatch, peer not allow-listed/enabled at scope `'room'`, unknown
  or already-left member, an archived hub channel, or an unknown `roomId` reaching the fan-out (internal
  invariant).
- **BZ212** — outbound room-content-scope refusal (Q11), `chat_message_send`, above.
- **BZ213** — outbound send refused because the target room mirror was closed (kicked or scope-revoked),
  `chat_message_send`; the field it reads (`federated_room_removed_at`) is written by `federation_apply_room`'s
  `'remove'`/`'room_revoked'` op arms.

**The typing hook + debounce (`presence.go`'s `typingSignal`, "federated typing" — never "presence", Q5
ratified):** after the LOCAL `chat_typing_signal` succeeds (the local signal is always authoritative and
unaffected by any of this — a federation hiccup never changes the 204 already written), a channel bound to a
federation peer/room ALSO gets a best-effort `Service.SendTyping` call. Ordering is load-bearing: a per-channel
in-memory debounce (`h.typingDebounce`, ~1s floor matching the local typing cadence, bounded map with a lazy
sweep at `typingDebounceCap=4096` — `httputil.ParseIDPath` admits any int64 as a channel id, so an unbounded map
would grow forever under a client hammering bogus ids) is consulted BEFORE the federated-columns SELECT and
BEFORE any goroutine is spawned — a noisy client must never create local DB load even though the wire frame
would end up dropped anyway. The federation hook fires ONLY when `chat_typing_signal` itself SUCCEEDED
(app-level gate, PRIMARY per ARCH-006 — the RLS read inside the federated send path is a backstop only, and does
not even hold for a PUBLIC channel, since DES-008's discovery arm lets any org user SELECT a public channel's
federation columns whether or not they're a member). The call itself is fire-and-forget on a short-lived detached
context (not `r.Context()` — the outbound wire send must outlive the HTTP response). `chat_typing_signal`'s own
local 32-member cap (`chat_presence.sql`, a literal `> 32` guard) is LOCAL only — the federated relay leg
(`federation_typing_notify`'s hub-side fan-out) has no equivalent cap and notifies the full active roster
regardless of size; a large federated room's typing behaves inconsistently with a large local-only channel's
(TODOS.md "Federation C2", disclosed, not fixed). The "typing writes zero tables, ever" claim has one honest
carve-out: `notify_chat_state` (every typing NOTIFY funnels through it) writes a transient `notify_intents` row
instead of a direct `pg_notify` whenever `feature.notify_decouple` is ON — an org-level posture unrelated to
federation, drained by `notifyjobs.NewWorker`, never archived, never chat content, but a real row nonetheless.

**The federation surface routes (`internal/chat/federation_rooms.go`), all toggle-gated 404 while
`feature.federation` is OFF (the `openFederatedDM` pattern) — role authority lives entirely in the reducers
(R1), these handlers are thin callers:**
- `POST /chat/channels/{id}/federation` → `federation_room_create` (bind; ALSO 404s when this box has no
  `FederationLocalDomain` configured — a reducer can't see process config, so an unconfigured box refuses before
  ever calling the reducer with an empty string) → `{roomId}`.
- `POST /chat/channels/{id}/federation/invite` `{memberDomain,contactAddr}` → `federation_room_invite` (IS
  re-admit — Q9 — the same route re-admits a parked/revoked/removed member, no separate endpoint).
- `POST /chat/channels/{id}/federation/remove` `{memberDomain}` → `federation_room_remove` (the kick lever).
- `GET /chat/channels/{id}/federation` → `federation_room_roster` → `{roomId,hubDomain,isHub,removedAt,
  members:[{domain,state,invitedAt,parkedReason,depthWarn}]}` — any channel member may read (no min-role
  restriction); only the three mutating routes above are owner/admin-gated (in the reducers, not here).

**Webmail contract:**
- A persistent **"Federated · N orgs" badge** on a room-bound channel header, hub and spoke alike (the C1
  External-badge genre — a records-jurisdiction signal every member org's users must see). `N` counts sibling
  member orgs only — never the hub itself on a spoke's badge — and reads `0` for the moment between channel-open
  and the roster fetch resolving (the same "starts empty, fills in" posture as the local active-roster chip).
- A **roster sheet** (`FederationRosterSheet.svelte`): org chips in active / amber depth-warn / parked / revoked
  / left states; hub owner/admin sees invite `{memberDomain,contactAddr}` + remove + re-admit-via-re-invite
  affordances. `depthWarn` is a LIVE re-evaluated signal (always false on a spoke read — a spoke has no
  `federation_peers` row per member), distinct from the Task-2 audit act that already fired once.
- **Attach-intake honesty**: the composer's attach affordance derives from `!federatedRoomId` client-side
  (disabled + tooltip in a room-bound channel) — never the global `attachmentsEnabled` alone, which would let a
  user compose an attachment only to hit the BZ212 toast at send. The affordance is honesty; BZ212 remains the
  enforcement.
- **Divergence confirms**: the Q1 residency-divergence warning surfaces at INVITE time (not only in the export
  manifest) AND on both the edit affordance and the delete confirmation dialog in a federated room (the Q11
  disclosed-divergence posture made visible in-product, i18n en/de/zh) — edits/deletions stay local; other
  member orgs keep their own copy.
- **Gap markers**: a `msg_type='system'` row with a `{"kind":"federation_gap","from":...,"to":...}` body renders
  as a centered i18n'd system row ("messages were not delivered between {from} and {to}") — inserted only by
  `federation_apply_room`'s invite arm when a re-admit closes a coverage gap; `chat_message_send`'s BZ168 guard
  is what stops a user from forging one. (`V141__federation_room_gap_marker.sql` relaxes the V139
  `chat_messages_author_or_federated_ck` CHECK to permit this row's shape — neither a local author nor a remote
  sender — a same-day fix found while building this insert; the CHECK no longer double-enforces the forgery
  guard, so BZ168 is the sole enforcement point, not a belt-and-suspenders pair.)
- The **kicked/scope-revoked banner** is ONE string covering both causes — both arrive as the same
  `federation_removed` notify event (`federated_room_removed_at` set); composer disabled, mirroring BZ213.
- The **archive affordance** mirrors the BZ209 Q13 refusal (still enforced server-side, never just client-side):
  disabled on a hub while any member remains ("remove all member orgs first"), disabled on a live spoke mirror
  ("the hub org controls this room"), re-enabled once the roster is empty (hub) or the mirror is removed (spoke).

**Stale C1-era residue, fixed by this pass:** this file previously carried NO federation contract at all — an
agent walking the chat rail (`chat_message.sql`, `channels.go`) had no way to discover that `chat_message_send`
had a federated branch since C1 shipped, or that `chat_channels` carries federation columns. This section is
that missing contract, covering the C1 DM branch and the C2 room branch together, in one place.

## Guest doors (G0–G3) — the constrained-external-user surface, `feature.guest_accounts`

Guest Accounts G0 (spec `retired-docs:superpowers/specs/2026-07-18-guest-accounts-design.md`, plan
`retired-docs:superpowers/plans/archive/2026-07-18-guest-G0-substrate.md`, V143, BZ215/216/219/221) treats chat as the ONE app a
guest may use in G0 — every other app's routes are 404 to a guest claim at the `guestgate` allowlist (the
`guestgate` row in `mailserver/internal/AGENTS.md`'s package index — no separate `guestgate/AGENTS.md` file
exists, per the established `internal/drive/` convention). This section is the reducer/Go-side half of that
contract: what a guest may and may not do inside chat once the route surface admits them.

**The seven BZ215 doors** (`is_guest_account(p_user_id)` checked first, before any other validation, so a deny
here is never an oracle for anything else — `chat_channel.sql`/`chat_org_defaults.sql`):
1. `chat_channel_create` — a guest may never create a channel.
2. `chat_channel_join` — a guest may never self-join (org-open reach is a member-only affordance).
3. `chat_browse_channels` — a guest may never browse the org's public-channel list.
4. `chat_dm_open` — G2 narrows the former blanket refusal to one exception: a guest whose live profile has
   `can_initiate_dm=TRUE` may name exactly one enabled local non-guest target already visible through shared
   membership in an ordinary, non-archived channel. Memberless, guest, federated, nonexistent, inactive, and
   profile-false targets all remain the same BZ215 anti-oracle. A MEMBER may still open a DM TO a guest; that
   target-side reach is governed by door 7 below. The guest caller takes the same `guest_require_grantable`
   share lock before policy evaluation or any founding insert, serializing DM creation with disable and profile
   updates.
5. `chat_org_defaults`'s backfill arm — a guest is never auto-seeded into an org-default channel when one is
   created.
6. The org-default **autojoin** arm — a guest is excluded from the same backfill's per-user autojoin loop (a
   distinct code path from door 5's backfill-on-create; both were made regression-detectable after a Task-7
   follow-up found they were vacuous via an `ON CONFLICT` dodge).
7. `chat_member_add` — a guest may never be the CALLER (the adder); it is a valid ADDABLE TARGET (P15's
   asymmetry — a member with owner/admin rights may add a guest to an ordinary channel), gated instead by the
   BZ219 grantability belt (below) and the BZ216 federation exclusion.

**The BZ216 federated⇄guest exclusion, all three sites, one lock discipline:** a guest account and a federation
binding can never coexist on the same channel — the residency promise (spec §4A) that a guest's content must
never leave the tenant via a federation peer. Enforced at:
- `chat_member_add` — adding a guest to an already federation-bound channel (dm-shaped or room-shaped), checked
  under the SAME `SELECT ... FOR UPDATE` row lock on `chat_channels` that also serializes this reducer's
  dm/group_dm immutability check — a concurrent federation bind cannot race the add.
- `federation_room_create` — binding a channel that still has ANY guest member, checked under an equivalent row
  lock on the channel being bound (the mirror-image direction of the same invariant).
- `federation_dm_ensure` — a guest as the LOCAL caller opening a federated DM (denied twice over in practice: the
  P8 `chat_dm_open` door above AND this federation-side refusal, since the distinct `POST /chat/dm/federated`
  route reaches only this reducer).

Accepted residual (E-M3, Task 8 review-fold): because arm (4) in `chat_member_add` fires BEFORE the owner/admin
role check, an authed non-guest caller who already knows a channel id can distinguish "federation-bound AND
target-is-guest" (BZ216) from other outcomes without holding owner/admin rights on that channel — a narrow oracle
(channel-binding + target-guest-status only; no membership or content leak), accepted as the cost of enforcing
the residency refusal under the lock. Proven live: `guest_federation_refusal.pg` — see also this file's
"Federated rooms (C2)" section above, whose standing guest obligation this discharges.

**The BZ219 belts** (`guest_require_active(p_user_id)`, a no-op for a member — called from every mutating chat
reducer a guest can legally reach as a normal participant: `chat_message_send`, `chat_message_edit`,
`chat_message_delete`, `chat_read_mark`, `chat_reaction_add`): a guest whose satellite status has gone
`disabled`/`expired` since their token was minted is refused HERE, at the reducer, not just at the auth-chain
belt — defense in depth for any reducer reachable via a route the allowlist still admits post-disable (the JWT
itself may still be technically valid for its remaining TTL). **The C-5 grant-writer serialization**
(`guest_require_grantable(bigint)`, a `FOR SHARE` lock on the target's satellite row) is the belt's sibling for
the OTHER direction — a grant landing a guest into new membership: called in `chat_member_add` (position 6,
after the role check, immediately before the `INSERT`) and per-target in `chat_dm_open` (before its BZ170
anti-oracle check, so a disabled/expired guest DM target answers BZ219 "re-invite required" rather than the
generic BZ170). It conflicts correctly against `guest_set_status`'s `FOR UPDATE` on the same row: a grant either
lands before a disable's clean-slate sweep runs, or waits on the lock and is refused once the sweep commits — no
window where a membership row survives a disable. Task 5's real two-session tests cover member-add against a
profile update and guest DM-open against disable and profile updates. G2d adds the
true member-add versus disable proof with two independent pgx sessions in both
commit orders: grant-first is deleted by disable; disable-first makes the grant
return BZ219; both end with zero membership. The admin lifecycle tracer and the
independent real EventSource wire tracer form the composite release gate.

**G2 membership policy snapshot:** after the grantability lock,
`guest_chat_policy_snapshot` supplies explicit `can_post` and join-history
policy for every guest row created by either `chat_member_add` or
`chat_dm_open`; a NULL profile snapshots restrictive `FALSE` plus the current
channel `change_seq`. Non-guest membership rows remain NULL/NULL. The live
two-session proof in `tracer_integration_test.go` holds a profile edit
uncommitted, proves a concurrent apply blocks before reading it, and verifies
the committed restrictive entitlement and `can_post` win without deadlock. Its
member-add sibling holds an assigned guest's restrictive profile edit
uncommitted, proves `guest_require_grantable` blocks the add, then verifies the
new `can_post` and channel-sequence history floor are snapshotted after commit.

**G2 posting/history enforcement:** `chat_message_send` refuses an explicit
membership `can_post=FALSE` and also fails closed on a pre-V145 guest's
`can_post=NULL` with BZ220, before the rate counter, message, mention,
push/digest intent, sequence bump, or notify; only a non-guest legacy member's
NULL retains the historical allow behavior. Every member-facing message reader
(`chat_messages_list`/`since`, thread, search, conversation unread/mention/
preview, pins, saves, my-threads, readers) applies the caller's immutable
`history_floor_seq`, and also requires `created_at >= joined_at` whenever a
floor exists so a pre-join row cannot resurrect when pin/edit/delete re-stamps
its seq. V145 stamps `chat_messages.created_at` with insertion-time
`clock_timestamp()` through the table default, so a transaction opened before
join but inserting after join remains visible. Parent/reply references use the
same wall in both directions: send refuses a hidden parent with BZ165; edit,
delete, reaction, pin, fresh-save, and poll vote/close/results refuse a hidden
remembered id with their existing anti-oracle code. `chat_thread_list` gives a
hidden parent the same BZ165/not-found outcome as an absent id; edit/delete
perform that visibility decision before the archived-channel BZ171 check, so a
remembered hidden id cannot disclose its channel through error ordering. Their
final mutations retain the ownership/current-membership predicates. Unsave remains deliberately
ungated so an old personal bookmark is always dismissable. Replay is explicitly
gap-free: a post-floor reply to a hidden parent is returned as a detached row
(`parentMessageId:null`, `parentUnavailable:true`), exposing neither the parent
id nor thread. More generally, `GET .../messages/since` returns the unchanged
bare message array plus additive `X-Setjoin-Chat-Cursor` metadata from the SAME
MVCC snapshot. The header advances across a pre-floor row that a visible member
edits/deletes after join even though no safe message row can be returned; it
discloses no message id/content/type. Webmail stores this high-water mark
separately from rendered rows, never rewinds it, and starts the next backfill
after it. Every replay/backfill/reconcile request is issued through one
per-channel promise queue: the next request cannot reach the server until its
predecessor's response has been applied, making PostgreSQL snapshot order and
client application order the same total order. Invocation-generation filtering
is insufficient because HTTP/2 scheduling can invert server snapshot order and
reaction snapshots may share a message seq. The guest-allowlisted Drive chunk `HEAD`,
`GET /drive/nodes?ids=`, and version-content routes also require a live
attachment link above the caller's floor, so derived channel-space membership
cannot enumerate/download pre-floor attachments. Compliance/eDiscovery is
intentionally unfiltered. The exact 21-entry reader/mutation/Drive manifest is
machine-guarded by `scripts/check-guest-history-readers.sh` and its mutation
self-test; pgTAP plus the Drive live test prove deterministic remove/re-add with
remembered message, poll, node, and version ids. The member-add/disable lock
test observes the waiter backend PID in both `pg_stat_activity` and an ungranted
`pg_locks` row before releasing the holder; elapsed scheduler silence is not
accepted as serialization evidence.

**Exact-email member preview:** `POST
/chat/channels/{id}/members/guest-preview` strictly decodes `{email}`, rejects
a missing/null/blank value as 400 invalid-arguments, and calls
the owner/admin-gated `chat_guest_preview`. Only an active, same-host-domain
exact match returns `{kind:"activeGuest",userId,displayName,historyFromJoin}`;
missing, inactive, member-account, substring, and out-of-scope targets all
return exactly `{kind:"inviteRequired"}`. `chat_member_add` remains the sole
mutation authority and rechecks grantability/profile state under its lock.

**Presence co-membership scoping** (`presence.go`, Task 13): a guest caller's presence-by-ids query is restricted
to user ids that share a channel with the guest — every other id (a non-co-member or a nonexistent id) answers
uniformly `false`, never distinguishable from each other (an anti-oracle, the same posture BZ170 uses elsewhere).
Runs under `dbscope.RunUserScoped` (the guest's own GUC scope, not a raw BYPASSRLS read — a raw-pool read against
FORCE-RLS `chat_channel_members` would answer uniformly false for every id regardless of true co-membership,
silently returning a lie rather than an enforced deny) and fails closed (deny) on a scope-lookup error. Roster and
mention-search were AUDITED, not newly built, for this program: both already route through `chat_require_role`'s
membership check, so a guest's reach there was already choked to its own channels before G0 — four pgTAP asserts
in `guest_chat_doors.pg` pin the already-choked claim as a regression-detectable fact rather than an unverified
assumption.

**Guest G1 digest enqueue + render:** when `feature.guest_accounts` is ON,
`chat_message_send` enqueues `guest_notification_intents` for guest mentionees
(`mention`) and a non-sender guest DM recipient (`dm`) in the same transaction
as the message. Toggle OFF prevents new rows; it never stops the unconditional
worker drain. The drain re-resolves each message/channel reference under the
recipient guest's current authorization, omits unauthorized or missing refs,
and counts only the rendered lines in the digest subject.

**Server-derived identity lifecycle keys:** every roster and mention result
carries `external` plus `removed`; every message projection carries
`authorExternal` plus `authorRemoved`. External comes from the durable guest
satellite, so historical authors remain External after membership removal.
Removed is true for disabled/expired satellites and for effective expiry
(`expires_at <= now()`) before reconciliation. All reads route through the
worker-owned RLS-safe guest helper family—never email-domain inference and
never a raw FORCE-RLS satellite read from caller context.

**The conversation `hasExternalMembers` payload key** (`chat_read.sql`, Guest G2a): every
`chat_conversation_list` row derives this boolean with an `EXISTS` over current channel membership joined to an
unexpired guest in `invited` or `active` state. It is never persisted and never inferred from an email domain; the
shared conversation-row/header badge consumes this frozen server aggregate without a roster fan-out.

**Guest G3 interaction:** the gateway now enumerates scoped Meet routes. A
meeting provisioned by an admitted authenticated knock may add the guest to its
provisioned Chat channel using the same grantability lock, profile `can_post`,
and immutable history-floor snapshot as an ordinary member add. A huddle bound
to a pre-existing channel never auto-grants that channel. Mailbox-less in-room
Chat consumes the same named `chat` EventSource rail as the constrained Chat
app; members retain the JMAP WebSocket.

**Deferred to later guest-accounts phases** (owners named, not vague "later" — see `TODOS.md`): guest credential recovery and lifecycle/eviction/sponsor/离职继承 → G5. G2 console, G3 scoped Meet, and G4 Drive tiers are shipped.
