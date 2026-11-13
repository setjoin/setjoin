// Chat A1 client transport — typed fetch wrappers over every /api/chat/*
// route (Tasks 9-11, locked shapes). Reuses $lib/http's timeout/auth/DPoP
// machinery (httpRequest/typedFetch) rather than re-implementing it.
import { problemFetch, ProblemError } from '$lib/http';

const BASE = '/api/chat';

// ── ChatError ────────────────────────────────────────────────────────────
//
// Arch review #A1: ChatError/MeetError/DriveError were three verbatim copies
// of the same RFC-7807-via-encoded-message transport (`$lib/http.ts`'s
// problemFetch). ChatError is now a plain alias onto the one shared
// `ProblemError` class — every existing call site (`instanceof ChatError`,
// `.status`/`.code`/`.detail`) keeps working unchanged, since it IS that
// class, not a copy of it.
export const ChatError = ProblemError;
export type ChatError = ProblemError;

const { fetch: chatFetch, fetchVoid: chatFetchVoid, fetchResponse: chatFetchResponse } = problemFetch(BASE);

const JSON_HEADERS = { 'Content-Type': 'application/json' };

// ── wire types (mirrors mailserver/internal/chat/*.go response + chat_message_to_json/chat_conversation_list) ──

export interface ChatReaction {
	emoji: string;
	count: number;
	mine: boolean;
}

/** chat_message_to_json's `attachments[]` shape (Chat A2 Task 3) — hidden
 *  ([]) by the server projection once the message is soft-deleted (C1). */
export interface ChatAttachment {
	id: number;
	fileNodeId: number;
	filename: string;
	contentType: string | null;
	sizeBytes: number;
}

export interface ChatMessage {
	messageId: number;
	channelId: number;
	seq: number;
	/** Pillar C1 Task 3 — nullable since V139: a federated inbound message
	 *  (Task 4) has no local author, only `federatedSenderAddr`. Every reader
	 *  of this field must treat `null` as "not a local user", never coerce it. */
	authorId: number | null;
	/** Guest G2: server-owned identity classification. This remains true for
	 *  guest-account authors after channel removal; clients must never infer it
	 *  from an email address or current roster membership. */
	authorExternal: boolean;
	/** Guest G2 lifecycle projection. True only once the author is disabled or
	 *  expired; authorship remains visible alongside the Removed badge. */
	authorRemoved: boolean;
	parentMessageId: number | null;
	msgType: string;
	broadcast: string | null;
	/** Blanked to '' by the server projection once deletedAt is set (C1 — body is RETAINED in the row, never here). */
	body: string;
	editedAt: string | null;
	deletedAt: string | null;
	createdAt: string;
	reactions: ChatReaction[];
	mentionsMe: boolean;
	replyCount: number;
	lastReplyAt: string | null;
	/** Pillar C1 Task 3 — the remote sender's bare address (present only when
	 *  `authorId` is null, i.e. a federated inbound message). */
	federatedSenderAddr?: string | null;
	/** Pillar C1 Task 6's ack-as-receipt tick, projected starting Task 3 (null
	 *  until the peer org acks — "delivered to the peer org", not "read by
	 *  the recipient user", see the plan's own semantic note). Absent/null
	 *  for a non-federated message. */
	deliveredAt?: string | null;
	/** Pillar C1 Task 4B's quarantine-on-apply flag, projected starting Task 3
	 *  (always false for a non-federated message). */
	spamQuarantined?: boolean;
	// Optional, not required: chat_message_to_json always sends this array, but
	// several pre-existing (Chat A1) test fixtures build a ChatMessage literal
	// without it — making it required would force edits across files outside
	// this task's scope. Store code treats an absent array as `[]` (see
	// store.svelte.ts's `msg.attachments ?? []` reads).
	attachments?: ChatAttachment[];
	/** A3 QoL Task 6 — voice `{durationMs}` / poll `{pollId}` / unfurl preview
	 *  fields; NULLed by the projection on soft-delete, same as body. Optional
	 *  for the same pre-existing-fixture reason as `attachments` above — most
	 *  callers never set it. */
	payload?: Record<string, unknown> | null;
	/** A3 QoL Task 3 — current-state channel-curation pin flag
	 *  (chat_message_pins). Optional for the same pre-existing-fixture reason
	 *  as `attachments`/`payload` above. */
	pinned?: boolean;
}

// ── attachments (Chat A2 Task 7) ─────────────────────────────────────────

/** One manifest chunk reference — mirrors $lib/drive/upload.ts's ChunkRef,
 *  restated here so chat/api.ts has no compile-time dependency on the drive
 *  wire types (only the store composes the two). */
export interface AttachmentManifestChunk {
	sha256: string;
	size: number;
}

/** The wire shape chat_message_send's p_attachments expects per item (plan
 *  §Data model / BZ172's shape check): sha256/size/name/manifest required,
 *  contentType optional. Built by the store from a fully-uploaded
 *  PendingAttachment once its chunks are HEAD-skipped/PUT. */
export interface AttachmentPayload {
	sha256: string;
	size: number;
	name: string;
	contentType?: string | null;
	manifest: AttachmentManifestChunk[];
}

export interface ConversationPreview {
	authorId: number;
	snippet: string;
	createdAt: string;
	/** whole-pipeline review UX #16 — lets the client map a voice message's
	 *  empty `snippet` to a "Voice message" label (PinsPanel/SavedView/
	 *  SearchView's existing mapping). Optional for the same pre-existing-
	 *  fixture reason as `notifLevel`/`pinned` elsewhere in this file. */
	msgType?: string;
}

export interface Conversation {
	channelId: number;
	kind: 'channel' | 'dm' | 'group_dm';
	name: string | null;
	topic: string | null;
	changeSeq: number;
	lastReadSeq: number;
	unreadCount: number;
	hasMention: boolean;
	/** Server-derived: an active guest account is currently a channel member. */
	hasExternalMembers: boolean;
	lastMessagePreview: ConversationPreview | null;
	/** DM/group_dm carry no name — the client resolves a title from these ids. */
	memberIds: number[];
	/** A3 QoL Task 7 — the CALLER's own per-channel mute preference
	 *  ('all'|'mentions'|'none', chat_channel_members.notif_level). Optional
	 *  for the same pre-existing-fixture reason as `pinned`/`payload` above
	 *  — chat_conversation_list has sent this since Task 7, but no client
	 *  type declared it until Task 16's channel-settings/mute surface needed
	 *  to read it. NOT the same vocabulary as the global
	 *  user_notification_prefs.chat_notifications ('all'|'mentions'|'off') —
	 *  see chat/AGENTS.md's "two different vocabularies" note. */
	notifLevel?: 'all' | 'mentions' | 'none';
	/** Channel-wide (Task 8): who may post at all. Always 'all' in practice
	 *  for dm/group_dm (no route ever sets it there). */
	postPermission?: 'all' | 'admins';
	/** Channel-wide (Task 8): who may @channel/@all. */
	broadcastPermission?: 'admins' | 'all';
	/** Chat A4a Task 8 — 'gxp' means WORM: messages/revisions cannot be edited
	 *  or deleted for retentionDays, even by admins. `legalHold` is
	 *  deliberately NEVER projected here (design review #11 — a hold must
	 *  stay invisible to the custodians it targets). */
	classification?: 'regular' | 'gxp';
	/** Same knob under TWO different client-side labels depending on
	 *  `classification` — a destroy ceiling for 'regular', a WORM keep-floor
	 *  for 'gxp' (see $lib/chat/store.svelte's retentionNotice). Null/absent
	 *  when no org policy or per-channel override applies. */
	retentionDays?: number | null;
	/** Pipeline-review fix: the `meetings.id` this channel is bridged to (a
	 *  meeting-provisioned channel or a huddle bound to a pre-existing
	 *  channel), or `null`/absent for an ordinary channel — lets the chat
	 *  rail mark meeting-bridged conversations. `chat_conversation_list` has
	 *  sent this since backend V131; optional for the same
	 *  pre-existing-fixture reason as the other fields above. */
	meetingId?: number | null;
	/** Pillar C1 Task 3 — non-null marks this conversation as a federated DM
	 *  (V139's `chat_channels.federated_peer_domain`/`federated_remote_id`).
	 *  A federated channel's ONLY member row is the local user (the remote
	 *  party is identity metadata, never a member) — the client must use
	 *  `federatedRemoteId` as the title instead of the normal roster
	 *  resolution, and render the persistent External badge. */
	federatedPeerDomain?: string | null;
	federatedRemoteId?: string | null;
	/** Pillar C2 Task 7 — room-federation binding markers (V140). Non-null on
	 *  BOTH the hub channel and every spoke mirror of a federated room (a
	 *  federated DM's `federatedPeerDomain` above stays a DIFFERENT signal —
	 *  a room's `federatedRoomId` renders the "Federated · N orgs" badge +
	 *  the roster-sheet entry point; `isFederatedRoomHub` picks which shape
	 *  this org holds; `federatedRoomRemoved` is the kicked/scope-revoked
	 *  read-only marker — BZ213 remains the send-time enforcement, this is
	 *  the client-side honesty signal for the banner/composer-disable). */
	federatedRoomId?: string | null;
	isFederatedRoomHub?: boolean;
	federatedRoomRemoved?: boolean;
}

export interface BrowseChannel {
	channelId: number;
	name: string;
	topic: string | null;
	memberCount: number;
	joined: boolean;
}

export interface RosterMember {
	userId: number;
	displayName: string;
	avatarSha256: string | null;
	role: string;
	/** Server-derived guest-account marker — never inferred from email/domain. */
	external: boolean;
	/** Server-derived disabled/expired lifecycle marker. */
	removed: boolean;
}

/** Exact-email guest lookup deliberately returns only a safe union: callers
 *  may add an already-active guest by id, or must start an invitation. */
export type GuestPreview =
	| { kind: 'activeGuest'; userId: number; displayName: string; historyFromJoin: boolean }
	| { kind: 'inviteRequired' };

/** The inner payload of a `{"@type":"ChatEvent","event":{...}}` WS/SSE frame
 *  (notify_chat_state's shape) — subscribeType('ChatEvent', cb) hands the
 *  OUTER envelope to cb; callers pass `payload.event` to ChatStore.applyEvent. */
export interface ChatWireEvent {
	/** A3 QoL Task 14: typed as a literal union (with an open string escape
	 *  hatch) rather than a bare `string` — every event applyEvent actually
	 *  switches on is named here for autocomplete/typo-safety, while
	 *  channel-level events this store doesn't yet act on (member_added,
	 *  owner_changed, …) still type-check and fall through applyEvent's
	 *  default no-op arm. Not a full discriminated union of distinct object
	 *  shapes — every event already shares the same {channelId, messageId,
	 *  seq, userId?} shape (userId is optional everywhere it's unused), so a
	 *  richer union would add structure nothing here needs. */
	event:
		| 'message_created'
		| 'message_edited'
		| 'message_deleted'
		| 'reaction_added'
		| 'reaction_removed'
		| 'message_pinned'
		| 'poll_voted'
		| 'typing'
		| 'read'
		| 'member_read'
		| 'member_added'
		| 'member_removed'
		| 'owner_changed'
		| 'channel_updated'
		| 'federation_removed'
		| 'federation_roster'
		| (string & {});
	channelId: number;
	messageId: number | null;
	seq: number | null;
	/** Present on 'read' (chat_mark_read's self-notify) and 'member_read'
	 *  (the DM peer's own userId, A3 QoL Task 4). Typing carries none today —
	 *  chat_presence.sql's notify_chat_state call passes no actor id, a gap
	 *  in the already-shipped Task 7 reducer (see chat/AGENTS.md TODO). */
	userId?: number;
}

// ── conversations / channels / DMs ───────────────────────────────────────

/** GET /chat/conversations returns an envelope (T5): the list plus the
 *  attachmentsEnabled capability (feature.chat && feature.drive). */
export const listConversations = () =>
	chatFetch<{ conversations: Conversation[]; attachmentsEnabled: boolean }>('/conversations');

export const createChannel = (body: { name: string; topic?: string; visibility?: 'public' | 'private' }) =>
	chatFetch<{ channelId: number }>('/channels', {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify(body),
	});

export const openDM = (userIds: number[]) =>
	chatFetch<{ channelId: number }>('/dm', {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ userIds }),
	});

/** POST /chat/dm/federated {remoteAddr} -> {channelId}. Pillar C1 Task 3 —
 *  the ONLY user path that starts a federated DM. 404s (via ChatError) while
 *  `feature.federation` is off; a peer domain that isn't locally allow-
 *  listed/enabled surfaces as a 403 (BZ204). */
export const openFederatedDM = (remoteAddr: string) =>
	chatFetch<{ channelId: number }>('/dm/federated', {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ remoteAddr }),
	});

// ── room federation (Pillar C2 Task 7) ───────────────────────────────────

/** federation_room_roster's wire shape (GET /chat/channels/{id}/federation).
 *  `state` mirrors the Q9-split roster: 'revoked' is a scope-downgrade
 *  (visible, not silent), 'left' is a plain kick, 'parked' is a backpressure
 *  pause, 'active' is live. `depthWarn` is hub-only (always false on a
 *  spoke read) — the live, re-evaluated-per-read amber-chip signal,
 *  distinct from the one-shot admin audit act the reducer also writes. */
export interface FederationRoomMember {
	domain: string;
	state: 'active' | 'parked' | 'revoked' | 'left';
	invitedAt: string;
	parkedReason: string | null;
	depthWarn: boolean;
}

export interface FederationRoomRoster {
	roomId: string;
	hubDomain: string;
	isHub: boolean;
	removedAt: string | null;
	members: FederationRoomMember[];
}

/** POST /chat/channels/{id}/federation -> {roomId}. Owner/admin only
 *  (federation_room_create's own BZ163/BZ209 gate); 404s while
 *  `feature.federation` is off OR this box has no federation local domain
 *  configured (the static-gate posture, same as federation.Service). */
export const bindFederationRoom = (channelId: number) =>
	chatFetch<{ roomId: string }>(`/channels/${channelId}/federation`, { method: 'POST' });

/** POST /chat/channels/{id}/federation/invite {memberDomain, contactAddr} ->
 *  204. federation_room_invite IS re-admit (Q9) — the SAME call re-admits a
 *  parked/revoked/removed member, no separate endpoint. */
export const inviteFederationMember = (channelId: number, memberDomain: string, contactAddr: string) =>
	chatFetchVoid(`/channels/${channelId}/federation/invite`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ memberDomain, contactAddr }),
	});

/** POST /chat/channels/{id}/federation/remove {memberDomain} -> 204 (the
 *  kick lever, Q3). */
export const removeFederationMember = (channelId: number, memberDomain: string) =>
	chatFetchVoid(`/channels/${channelId}/federation/remove`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ memberDomain }),
	});

/** GET /chat/channels/{id}/federation -> the roster envelope. Any channel
 *  member may read (federation_room_roster's own R1 proof, no min-role
 *  restriction) — only the three mutating calls above are owner/admin
 *  gated. */
export const getFederationRoomRoster = (channelId: number) =>
	chatFetch<FederationRoomRoster>(`/channels/${channelId}/federation`);

export const browseChannels = () => chatFetch<BrowseChannel[]>('/channels/browse');

export const joinChannel = (channelId: number) => chatFetchVoid(`/channels/${channelId}/join`, { method: 'POST' });

/** `postPermission`/`broadcastPermission` (A3 QoL Task 8) ride the SAME PATCH
 *  route as name/topic/archived (channels.go's updateChannel, extended, not a
 *  new route) — owner/admin-gated server-side (BZ161). The client type only
 *  gained these two fields in Task 16, when the channel-settings sheet became
 *  the first caller that needed to set them. */
export const updateChannel = (
	channelId: number,
	fields: {
		name?: string;
		topic?: string;
		archived?: boolean;
		postPermission?: 'all' | 'admins';
		broadcastPermission?: 'admins' | 'all';
	},
) => chatFetchVoid(`/channels/${channelId}`, { method: 'PATCH', headers: JSON_HEADERS, body: JSON.stringify(fields) });

export const addMember = (channelId: number, userId: number) =>
	chatFetchVoid(`/channels/${channelId}/members`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ userId }),
	});

export const previewGuest = (channelId: number, email: string) =>
	chatFetch<GuestPreview>(`/channels/${channelId}/members/guest-preview`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ email }),
	});

export const removeMember = (channelId: number, userId: number) =>
	chatFetchVoid(`/channels/${channelId}/members/${userId}`, { method: 'DELETE' });

// ── roster (Task 11) ─────────────────────────────────────────────────────

export const listMembers = (channelId: number) => chatFetch<RosterMember[]>(`/channels/${channelId}/members`);

export const searchMembers = (channelId: number, q: string) =>
	chatFetch<RosterMember[]>(`/channels/${channelId}/members/search?q=${encodeURIComponent(q)}`);

// ── messages ──────────────────────────────────────────────────────────────

/** `msgType`/`payload` (A3 QoL Task 15) are the client-facing half of Task
 *  6's msg_type/payload send seam — voice is the only kind a plain send may
 *  originate ('poll' stays exclusive to chatApi.createPoll's own route; the
 *  server route rejects any other value with 400). Absent for a normal text
 *  send, which is why every existing call site keeps working untouched. */
export const sendMessage = (
	channelId: number,
	body: string,
	parentId?: number | null,
	mentions?: number[],
	broadcast?: string | null,
	attachments?: AttachmentPayload[],
	msgType?: string,
	payload?: Record<string, unknown> | null,
) =>
	chatFetch<{ messageId: number; seq: number }>(`/channels/${channelId}/messages`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({
			body,
			parentId: parentId ?? null,
			mentions: mentions ?? [],
			broadcast: broadcast ?? null,
			attachments: attachments ?? [],
			msgType: msgType ?? undefined,
			payload: payload ?? undefined,
		}),
	});

/** POST /chat/channels/{id}/space -> {spaceId}. The composer calls this
 *  before the chunk-upload rail so it has a space to upload into;
 *  chat_space_ensure lazily provisions (or returns the existing) org-governed
 *  Drive space bound to the channel. 404s when feature.drive is off (one of
 *  the two attachment surfaces — messages.go). */
export const ensureSpace = (channelId: number) =>
	chatFetch<{ spaceId: number }>(`/channels/${channelId}/space`, { method: 'POST' });

/** Newest-first keyset page (chat_messages_list) — beforeSeq/limit both
 *  optional. `aroundSeq` (A3 QoL Task 10) switches the reducer into its
 *  jump-to-message mode instead (target row + up to `limit` per side,
 *  ASCENDING — NOT the normal DESC page); ChatStore.openChannelAt is the
 *  only caller that passes it. */
export const listMessages = (channelId: number, opts: { beforeSeq?: number; limit?: number; aroundSeq?: number } = {}) => {
	const params = new URLSearchParams();
	if (opts.beforeSeq != null) params.set('beforeSeq', String(opts.beforeSeq));
	if (opts.limit != null) params.set('limit', String(opts.limit));
	if (opts.aroundSeq != null) params.set('aroundSeq', String(opts.aroundSeq));
	const qs = params.toString();
	return chatFetch<ChatMessage[]>(`/channels/${channelId}/messages${qs ? '?' + qs : ''}`);
};

export interface ChatReplay {
	messages: ChatMessage[];
	/** Snapshot high-water mark from X-Setjoin-Chat-Cursor. It may exceed every
	 *  returned row when the intervening mutations are hidden by a guest's
	 *  immutable history floor. */
	cursor: number;
}

/** Ascending replay since `seq` (exclusive) — the reconnect/backfill path
 *  (H2). The HTTP body remains the established bare ChatMessage[] wire; the
 *  additive cursor header is lifted into this client-only envelope. Missing
 *  headers fall back to the largest safe row/request cursor for rolling
 *  compatibility and can never rewind. */
export const sinceMessages = async (channelId: number, seq: number): Promise<ChatReplay> => {
	const res = await chatFetchResponse(`/channels/${channelId}/messages/since?seq=${seq}`);
	const messages = (await res.json()) as ChatMessage[];
	const rawCursor = res.headers.get('X-Setjoin-Chat-Cursor');
	const parsedCursor = rawCursor == null ? Number.NaN : Number(rawCursor);
	const rowCursor = messages.reduce((max, message) => Math.max(max, message.seq), seq);
	return {
		messages,
		cursor: Number.isSafeInteger(parsedCursor) && parsedCursor >= 0 ? Math.max(seq, parsedCursor) : rowCursor,
	};
};

/** Root + replies ascending (chat_thread_list) — ThreadPane's read path (Task 15).
 *  `parentId` is the ROOT message id; membership is resolved off the parent's
 *  own channel server-side, so no channel id travels on this route. */
export const threadMessages = (parentId: number) => chatFetch<ChatMessage[]>(`/messages/${parentId}/thread`);

export const editMessage = (messageId: number, body: string) =>
	chatFetch<{ seq: number }>(`/messages/${messageId}`, {
		method: 'PATCH',
		headers: JSON_HEADERS,
		body: JSON.stringify({ body }),
	});

export const deleteMessage = (messageId: number) => chatFetch<{ seq: number }>(`/messages/${messageId}`, { method: 'DELETE' });

export const toggleReaction = (messageId: number, emoji: string) =>
	chatFetch<{ present: boolean }>(`/messages/${messageId}/reactions`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ emoji }),
	});

// ── read / typing / presence ─────────────────────────────────────────────

export const markRead = (channelId: number, seq: number) =>
	chatFetchVoid(`/channels/${channelId}/read`, { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ seq }) });

export const sendTyping = (channelId: number) => chatFetchVoid(`/channels/${channelId}/typing`, { method: 'POST' });

/** Polled online/offline map (grill Q2) — callers should poll <=1/60s for VISIBLE users only. */
export const getPresence = (userIds: number[]) =>
	chatFetch<Record<string, boolean>>(`/presence?userIds=${userIds.join(',')}`);

// ── pin (channel curation) + save (personal bookmark) — A3 QoL Task 3 ────

export const togglePin = (messageId: number) => chatFetch<{ pinned: boolean }>(`/messages/${messageId}/pin`, { method: 'POST' });

export const listPins = (channelId: number) => chatFetch<ChatMessage[]>(`/channels/${channelId}/pins`);

export const toggleSave = (messageId: number) => chatFetch<{ saved: boolean }>(`/messages/${messageId}/save`, { method: 'POST' });

export const listSaves = () => chatFetch<ChatMessage[]>('/saves');

// ── read receipts (已读 watermark projection, ADR DES-010) — A3 QoL Task 4 ─

export interface ChannelReader {
	userId: number;
	lastReadSeq: number;
}

export const getChannelReaders = (channelId: number) => chatFetch<ChannelReader[]>(`/channels/${channelId}/readers`);

// ── translate (reuse /assist) — A3 QoL Task 5 ─────────────────────────────

export const translateMessage = (messageId: number, targetLocale: string) =>
	chatFetch<{ translated: string }>(`/messages/${messageId}/translate`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ targetLocale }),
	});

// ── scheduled-send (ScheduledAction rail) — A3 QoL Task 2 ─────────────────

/** chat_scheduled_list's wire shape — a pending OR failed row (failed rows
 *  stay visible, grill-decided: silent content loss is the wrong brand for a
 *  compliance product). Dismiss = cancelScheduled on a failed row. */
export interface ScheduledChatMessage {
	actionId: string;
	channelId: number;
	body: string;
	fireAt: string;
	status: string;
	failureCode: string | null;
	lastError: string | null;
}

export const scheduleMessage = (
	channelId: number,
	body: string,
	opts: { parentId?: number | null; mentions?: number[]; broadcast?: string | null; fireAt: string },
) =>
	chatFetch<{ actionId: string }>(`/channels/${channelId}/messages/schedule`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({
			body,
			parentId: opts.parentId ?? null,
			mentions: opts.mentions ?? [],
			broadcast: opts.broadcast ?? null,
			fireAt: opts.fireAt,
		}),
	});

/** The caller's own pending + failed chat_send rows, mine-only. */
export const listScheduled = () => chatFetch<ScheduledChatMessage[]>('/scheduled');

export const cancelScheduled = (actionId: string) =>
	chatFetchVoid(`/scheduled/${encodeURIComponent(actionId)}`, { method: 'DELETE' });

// ── polls — A3 QoL Task 9 ──────────────────────────────────────────────────

export interface ChatPollOption {
	optionId: number;
	ordinal: number;
	label: string;
	count: number;
	/** Non-anonymous by product decision — per-voter user ids, not just counts. */
	voters: number[];
}

export interface ChatPollResults {
	pollId: number;
	question: string;
	multi: boolean;
	closesAt: string | null;
	closed: boolean;
	options: ChatPollOption[];
}

/** Posts THROUGH chat_message_send (Task 6's seam) — returns the anchor
 *  message's id alongside the poll id. */
export const createPoll = (channelId: number, question: string, options: string[], multi = false, closesAt?: string | null) =>
	chatFetch<{ messageId: number; pollId: number; seq: number }>(`/channels/${channelId}/polls`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ question, options, multi, closesAt: closesAt ?? null }),
	});

export const votePoll = (pollId: number, optionId: number) =>
	chatFetchVoid(`/polls/${pollId}/vote`, { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ optionId }) });

/** Creator or channel owner/admin only (BZ161 otherwise); a poll is never re-opened. */
export const closePoll = (pollId: number) => chatFetchVoid(`/polls/${pollId}/close`, { method: 'POST' });

export const pollResults = (pollId: number) => chatFetch<ChatPollResults>(`/polls/${pollId}/results`);

// ── search (CJK-capable, jump-to-message substrate) — A3 QoL Task 10 ─────

export interface ChatSearchFilters {
	/** `in:` — restrict to one channel. */
	in?: number;
	/** `from:` — restrict to one author. */
	from?: number;
	/** Global `chat_messages.id` keyset cursor (seq is per-channel and cannot
	 *  keyset a cross-channel result set). */
	before?: number;
	/** Only `'attachment'` is recognized server-side today; anything else
	 *  degrades to "no results", never a 500. */
	has?: string;
}

export const searchMessages = (q: string, filters: ChatSearchFilters = {}) => {
	const params = new URLSearchParams({ q });
	if (filters.in != null) params.set('in', String(filters.in));
	if (filters.from != null) params.set('from', String(filters.from));
	if (filters.before != null) params.set('before', String(filters.before));
	if (filters.has) params.set('has', filters.has);
	return chatFetch<ChatMessage[]>(`/search?${params.toString()}`);
};

// ── My-Threads inbox — A3 QoL Task 11 ─────────────────────────────────────

export interface ChatThread {
	messageId: number;
	channelId: number;
	seq: number;
	authorId: number;
	body: string;
	createdAt: string;
	replyCount: number;
	lastReplyAt: string | null;
	unreadCount: number;
}

export const listMyThreads = (limit?: number) => chatFetch<ChatThread[]>(`/my-threads${limit != null ? '?limit=' + limit : ''}`);

// ── notif_level / DND client surface — A3 QoL Task 7 ──────────────────────

export const setChannelNotif = (channelId: number, level: 'all' | 'mentions' | 'none') =>
	chatFetchVoid(`/channels/${channelId}/notif`, { method: 'PUT', headers: JSON_HEADERS, body: JSON.stringify({ level }) });

// ── unfurl (link preview images) — A3 QoL Task 13 ─────────────────────────

/** Cookie-authed, chat-capability-gated image content route — used directly
 *  as an `<img src>`, not fetched through chatFetch (it serves raw bytes,
 *  not JSON). The sha256 is percent-encoded at this boundary: the route pattern
 *  is single-segment, so encoding pins the value to that segment no matter what
 *  the caller passes. */
export const unfurlImageUrl = (sha256: string) => `${BASE}/unfurl/image/${encodeURIComponent(sha256)}`;
