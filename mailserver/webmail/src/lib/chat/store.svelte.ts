// store.svelte.ts — Chat A1 Task 12 runes store: conversations + the active
// channel's message timeline, optimistic send/retry, reconnect backfill,
// scroll/watermark state, and typing expiry. Mirrors drive/locks.svelte.ts's
// singleton-class shape (private `#field`s, a plain `new ChatStore()` for
// tests, one shared instance exported for the app).
//
// Read path: every message-mutating WS/SSE push (`message_created` /
// `message_edited` / `message_deleted` / `reaction_added` / `reaction_removed`)
// carries only {channelId, messageId, seq} (notify_chat_state's payload has no
// room for a full row) — applyEvent re-fetches via chatApi.sinceMessages
// (chat_messages_since, seq > since ASC) rather than trying to patch fields
// from the push itself. Passing `seq-1` as the cursor pulls exactly the
// changed row (and, for free, anything else this client is behind on — the
// commit-ordered seq rail plus the response's explicit high-water cursor
// guarantees no gap even when every intervening row is hidden by a guest
// history floor). #upsertMessage is keyed on
// messageId, so replaying the same event twice (or a reconcile racing an
// already-applied optimistic-send ack) is a no-op merge, never a duplicate row.
import * as chatApi from './api';
import type {
	AttachmentPayload,
	ChatMessage,
	ChatPollResults,
	ChatReaction,
	ChatReplay,
	ChatWireEvent,
	Conversation,
	ScheduledChatMessage,
} from './api';
import { splitManifest, type ChunkRef } from '$lib/drive/upload';
import { headChunk, putChunk } from '$lib/drive/api';
import { driveErrorMessage } from '$lib/drive/errors';
import { t } from '$lib/i18n';
import { registerAuthSessionTeardown } from '$lib/stores/auth';

/** Composer-scoped key: a channel's root composer and its ThreadPane composer
 *  (same channel, different parentId) never share a pending-attachment list
 *  (Design H8 — pending state survives navigation, keyed off the SAME pair
 *  the messages themselves are keyed off, not a component instance).
 *  Exported (Chat A2 Task 8) so Composer.svelte can index its own slice of
 *  `pendingAttachments` without duplicating the key format. */
export function pendingKey(channelId: number, parentId: number | null | undefined): string {
	return `${channelId}:${parentId ?? 'root'}`;
}

/** Pure flip helper for the optimistic reaction toggle (Task 15): adds a new
 *  pill at count 1/mine when the emoji is unreacted; increments/decrements an
 *  existing one; drops the pill entirely once its count reaches 0. */
function flipReaction(reactions: ChatReaction[], emoji: string): ChatReaction[] {
	const idx = reactions.findIndex((r) => r.emoji === emoji);
	if (idx === -1) return [...reactions, { emoji, count: 1, mine: true }];
	const r = reactions[idx];
	if (!r.mine) return reactions.map((x, i) => (i === idx ? { ...x, count: x.count + 1, mine: true } : x));
	const nextCount = r.count - 1;
	if (nextCount <= 0) return reactions.filter((_, i) => i !== idx);
	return reactions.map((x, i) => (i === idx ? { ...x, count: nextCount, mine: false } : x));
}

// A4a Task 13 — bespoke copy for the two BZ codes an end user can actually
// hit (BZ192/BZ194/BZ195 are admin-console-only, Task 12's own error
// handling). Deliberately a small map keyed on the wire `code`, not a
// driveErrorMessage-style `chat.error.BZ<nnn>` convention — the plan pins
// these two semantic key names explicitly.
const errorKeyByCode: Record<string, string> = {
	BZ193: 'chat.error.wormImmutable',
	BZ196: 'chat.error.rateLimited',
	// Pillar C2 Task 7 — the stale-hub surface: a federated spoke send (DM or
	// room) refused by federation_enqueue's user-initiated backpressure/
	// stale-peer check (BZ205) renders here, through the EXISTING failed-row
	// Retry path (MessageRow's failedReason) — never a bespoke banner/queue
	// illusion.
	BZ205: 'chat.federation.staleHub',
	// Pillar C2 Task 7 review (M1): a straggler send that lands after the
	// mirror was kicked/scope-revoked (federated_room_removed_at set mid-flight)
	// hits BZ213 — same failed-row Retry path as BZ205, same reason to give
	// this its own copy rather than the raw English server detail.
	BZ213: 'chat.federation.removed.sendFailed',
};

/** BZ code -> bespoke translated copy, or undefined for a code with no
 *  chat-specific string (caller falls back to the server's raw `detail`).
 *  Exported so MessageRow can render the SAME reason next to a failed send's
 *  Retry button from just the stamped `errorCode` string (no full ChatError
 *  instance available at render time).
 *
 *  Deviation from the plan: BZ196's copy does NOT interpolate
 *  `retryAfterSeconds` — Task 10 (already merged) deliberately left that HINT
 *  a raw pgErr fact, never wired onto the wire Problem body
 *  (reducererr/contract_test.go's BZ196 row is class-fallback-only, `detail`
 *  is the fixed string "overQuota"), so there is no `{n}` to read client-side. */
export function chatErrorReason(code: string | undefined): string | undefined {
	if (!code) return undefined;
	const key = errorKeyByCode[code];
	return key ? t(key) : undefined;
}

/** Toast copy for a caught chat API error — bespoke string for BZ193/BZ196,
 *  else the server's own `detail`, else a generic fallback for a non-ChatError
 *  throw (network/timeout/abort). */
export function chatErrorMessage(err: unknown): string {
	if (err instanceof chatApi.ChatError) {
		return chatErrorReason(err.code) ?? err.detail;
	}
	return t('common.error');
}

// A4a Task 13 — the retention-days knob is TWO DIFFERENT LABELS depending on
// classification (Global Constraints vocabulary block, binding: a
// mistranslation here reads as the opposite of what the knob does and
// destroys customer data). 'regular' = a destroy CEILING; 'gxp' = a WORM
// keep-FLOOR. `classification` itself is never rendered raw. Single-homed so
// ChatApp's header tooltip and ChannelSettingsSheet's retention row can never
// diverge on wording.
export function retentionNotice(
	classification: 'regular' | 'gxp' | undefined,
	retentionDays: number | null | undefined,
): string | null {
	if (retentionDays == null) return null;
	const key = classification === 'gxp' ? 'chat.compliance.retentionFloor' : 'chat.compliance.retentionCeiling';
	return t(key, { n: String(retentionDays) });
}

export type SendStatus = 'sending' | 'sent' | 'failed';

export interface StoreMessage extends ChatMessage {
	/** Present only on a row this session originated, until the server ack lands. */
	clientId?: string;
	status: SendStatus;
	/** Retained on optimistic rows only, so retry() can re-POST the same mention set. */
	pendingMentions?: number[];
	/** Retained on optimistic rows only (Design C3) — a failed send keeps the
	 *  fully-hashed/uploaded attachment payload so retry() re-posts it as-is
	 *  (chunks are already claimed server-side; a retry costs zero re-upload). */
	pendingAttachmentPayload?: AttachmentPayload[];
	/** A4a Task 13 — the BZ code that failed the send (e.g. 'BZ196' — rate
	 *  limited), stamped by #doSend's catch so MessageRow's failed-row block
	 *  can render a reason next to Retry instead of just a bare button —
	 *  without this a rate-limited user has no signal not to hammer Retry. */
	errorCode?: string;
}

export type AttachmentStatus = 'hashing' | 'uploading' | 'ready' | 'failed';

/** One composer chip's client-side state (Chat A2 Task 7). `progress` is
 *  cumulative bytes hashed/uploaded out of `size` — the same cumulative
 *  shape splitManifest/uploadFile already report, so a progress bar just
 *  reads `progress / size`. */
export interface PendingAttachment {
	clientId: string;
	file: File;
	status: AttachmentStatus;
	progress: number;
	size: number;
	name: string;
	contentType: string;
	sha256?: string;
	manifest?: ChunkRef[];
	/** Localized (driveErrorMessage) reason, set only when status === 'failed'. */
	error?: string;
}

const TYPING_TTL_MS = 4000; // Design F13 — typing rows auto-clear after 4s of silence
// ponytail: one literal debounce window, not a configurable prop — no caller needs a
// different cadence today; promote to a constructor param if one does.
const MARK_READ_DEBOUNCE_MS = 500;

export interface ChatEventOutcome {
	refreshFederationRosterChannelId: number | null;
}

interface ConversationReconcileCycle {
	generation: number;
	dirty: boolean;
	promise: Promise<void>;
}

export class ChatStore {
	conversations = $state<Conversation[]>([]);
	/** feature.chat && feature.drive (T5 envelope). When false, the composer
	 *  attachment surface is absent (Task 8 gates on this). Optimistic true so
	 *  the UI doesn't flash the attach button off before the first load. */
	attachmentsEnabled = $state(true);
	activeChannelId = $state<number | null>(null);
	/** Ascending (oldest→newest) per channel — server list/since endpoints use two
	 *  different orders (list = DESC page, since = ASC replay); the store normalizes
	 *  to ASC once, here, so every consumer reads one direction. */
	messagesByChannel = $state<Record<number, StoreMessage[]>>({});
	/** Set by the MessageList scroll handler (Task 14) — gates autoscroll vs. the jump pill. */
	atBottom = $state(true);
	/** Count behind the "New messages ↓" jump pill while scrolled up (Design F2). */
	unseenBelow = $state(0);
	/** channelId-scoped (Task 14 — MessageList renders only its own channel's
	 *  typers; without channelId a signal from a background channel would show
	 *  up as a ghost typing row in whichever channel happens to be open). */
	typingUsers = $state<{ channelId: number; userId: number; expiresAt: number }[]>([]);
	/** The caller's own numeric user id — unknown (null) until the host app sets it;
	 *  used only to stamp optimistic rows and to filter self out of typingUsers/read echoes. */
	selfUserId = $state<number | null>(null);

	/** Keyed by pendingKey(channelId, parentId) — Design H8: survives a
	 *  channel switch and back (A1's Composer hard-resets on channel change;
	 *  ThreadPane is a second composer keyed by its own parentId). Cleared for
	 *  a key's 'ready' entries the moment send() consumes them; 'failed'
	 *  entries are left behind as removable/retryable chips. */
	pendingAttachments = $state<Record<string, PendingAttachment[]>>({});

	// ── A3 QoL Task 14 additions ─────────────────────────────────────────────

	/** Set by openChannelAt() (Task 10's jump-to-message substrate — search
	 *  hits/pins/saves/My-Threads click-throughs); the messageId the UI
	 *  (Task 15's MessageList/MessageRow) should apply its `ml__row--focused`
	 *  style to and scroll into view. Cleared by clearFocusedMessage(). */
	focusedMessageId = $state<number | null>(null);

	/** Poll tallies cache (Task 15's poll render reads this), keyed by
	 *  pollId — populated by loadPollResults() on render. applyEvent's
	 *  'poll_voted' arm only refetches an ALREADY-cached (i.e., currently
	 *  rendered) poll in the active channel; an uncached poll_voted is a
	 *  no-op — tallies for a poll nobody has opened heal on next render
	 *  (same no-live-fetch-for-invisible-state posture DES-010 read
	 *  receipts already accept). */
	pollResultsByPollId = $state<Record<number, ChatPollResults>>({});

	/** DM read-tick (ADR DES-010, A3 QoL Task 4) — the OTHER member's own
	 *  last_read_seq for a DM channel, pushed live via 'member_read' only
	 *  for kind='dm' (chat_mark_read never fans this out for channel/
	 *  group_dm — see chat_read.sql). Monotonic, same non-rewind guarantee
	 *  as #syncReadWatermark. MessageRow (Task 15) reads this for the DM
	 *  read tick off the peer's watermark. */
	peerReadSeq = $state<Record<number, number>>({});

	/** `${messageId}:${targetLocale}` -> translated text (Task 15's "Show
	 *  original" toggle reads this — re-toggling is free, no repeat API call
	 *  for the same message+locale pair). */
	translationsByKey = $state<Record<string, string>>({});

	/** The caller's own pending + failed chat_send rows (Task 2's ScheduledAction
	 *  rail) — Task 16's queue view/chip renders this; populated by
	 *  loadScheduled() and refreshed by scheduleSend()/cancelScheduled(). */
	scheduled = $state<ScheduledChatMessage[]>([]);

	#typingTimers = new Map<string, ReturnType<typeof setTimeout>>();
	#markReadTimer: ReturnType<typeof setTimeout> | null = null;
	/** One ensureSpace() call per channel, however many files get attached. */
	#spaceIdByChannel = new Map<number, Promise<number>>();
	/** Lets send() await an in-flight upload before deciding ready-vs-not,
	 *  and lets removeAttachment() cancel one still in flight. */
	#uploadTasks = new Map<string, Promise<void>>();
	#uploadAborts = new Map<string, AbortController>();
	/** Server-supplied replay high-water mark, deliberately independent of
	 *  rendered rows. A guest can have a hidden pre-floor edit/delete between
	 *  visible rows; deriving the cursor only from rows would poll that gap
	 *  forever. Monotonic per channel, never rewound by a stale response. */
	#replayCursorByChannel = new Map<number, number>();
	/** One promise tail per channel. `since` requests must be issued serially,
	 *  not merely applied by invocation generation: PostgreSQL snapshot order
	 *  follows server execution, which HTTP/2 may schedule differently from
	 *  browser invocation order. This queue makes request/snapshot/application
	 *  order one total order, including same-seq reaction snapshots. */
	#replayQueueByChannel = new Map<number, Promise<void>>();
	/** One in-flight metadata refresh plus one dirty-bit rerun per auth
	 * generation. Per-message replay remains channel-serialized separately. */
	#conversationReconcile: ConversationReconcileCycle | null = null;
	/** Session-local terminal revocations. A stale/in-flight conversation response
	 * may not reopen compose after the event has arrived. */
	#federationRevokedChannels = new Set<number>();
	#conversationLoadGeneration = 0;
	/** Monotonic browser-session generation. reset() increments it so an
	 *  unresolved request from the prior identity can never populate state for
	 *  the next one, even when numeric channel/message ids are reused. */
	#sessionGeneration = 0;

	/** Design F14 — total unread across every conversation + whether any of them mentions me.
	 *  Mirrors ChannelList.svelte's showBadge() mute rules (whole-pipeline review UX #6): a
	 *  'none'-muted conversation never contributes, and a 'mentions'-muted one contributes only
	 *  when it actually has a mention — otherwise a fully-muted channel would still light the rail. */
	railBadge = $derived.by(() => {
		let count = 0;
		let hasMention = false;
		for (const c of this.conversations) {
			if (c.notifLevel === 'none') continue;
			if (c.notifLevel === 'mentions' && !c.hasMention) continue;
			count += c.unreadCount;
			if (c.hasMention) hasMention = true;
		}
		return { count, hasMention };
	});

	/** Clears every user-scoped public and private slice. Auth invokes this on
	 *  logout/reset and before an identity/impersonation switch. In-flight HTTP
	 *  cannot be cancelled universally, so #sessionGeneration makes their late
	 *  continuations inert; upload work has AbortControllers and is cancelled. */
	reset(): void {
		this.#sessionGeneration += 1;
		for (const timer of this.#typingTimers.values()) clearTimeout(timer);
		this.#typingTimers.clear();
		if (this.#markReadTimer) clearTimeout(this.#markReadTimer);
		this.#markReadTimer = null;
		for (const controller of this.#uploadAborts.values()) controller.abort();
		this.#uploadAborts.clear();
		this.#uploadTasks.clear();
		this.#spaceIdByChannel.clear();
		this.#replayCursorByChannel.clear();
		this.#replayQueueByChannel.clear();
		this.#conversationReconcile = null;
		this.#federationRevokedChannels.clear();
		this.#conversationLoadGeneration += 1;

		this.conversations = [];
		this.attachmentsEnabled = true;
		this.activeChannelId = null;
		this.messagesByChannel = {};
		this.atBottom = true;
		this.unseenBelow = 0;
		this.typingUsers = [];
		this.selfUserId = null;
		this.pendingAttachments = {};
		this.focusedMessageId = null;
		this.pollResultsByPollId = {};
		this.peerReadSeq = {};
		this.translationsByKey = {};
		this.scheduled = [];
	}

	async loadConversations(): Promise<void> {
		const generation = this.#sessionGeneration;
		const loadGeneration = ++this.#conversationLoadGeneration;
		const env = await chatApi.listConversations();
		if (generation !== this.#sessionGeneration || loadGeneration !== this.#conversationLoadGeneration) return;
		for (const conversation of env.conversations) {
			if (this.#federationRevokedChannels.has(conversation.channelId)) {
				conversation.federatedRoomRemoved = true;
			}
		}
		this.conversations = env.conversations;
		this.attachmentsEnabled = env.attachmentsEnabled;
	}

	async openChannel(channelId: number): Promise<void> {
		const generation = this.#sessionGeneration;
		this.activeChannelId = channelId;
		this.atBottom = true;
		this.unseenBelow = 0;
		const rows = await chatApi.listMessages(channelId);
		if (generation !== this.#sessionGeneration) return;
		// chat_messages_list is newest-first; reverse once here so every reader sees ASC.
		this.messagesByChannel[channelId] = rows
			.slice()
			.reverse()
			.map((m) => ({ ...m, status: 'sent' as const }));
	}

	/** MessageList calls this on every scroll tick (Task 14); entering "at bottom" clears the pill. */
	setAtBottom(atBottom: boolean): void {
		this.atBottom = atBottom;
		if (atBottom) this.unseenBelow = 0;
	}

	/** Jump-to-message substrate (Task 10's `aroundSeq` window) — the
	 *  click-through for search hits, pins, saves, and My-Threads. Always
	 *  REPLACES the channel's loaded rows: a jump can land far from whatever
	 *  was previously loaded, and merging two non-contiguous windows would
	 *  silently fabricate a bogus ordering. Records the target row so the UI
	 *  (Task 15's MessageList/MessageRow) can apply its focus style and
	 *  scroll it into view. Scrolling past either edge of the loaded window
	 *  "stitches" forward/backward via the EXISTING loadOlderMessages()/
	 *  backfillSince() — both are already idempotent-merge on messageId, so
	 *  no separate stitch method is needed here. */
	async openChannelAt(channelId: number, seq: number): Promise<void> {
		const generation = this.#sessionGeneration;
		this.activeChannelId = channelId;
		this.atBottom = false;
		this.unseenBelow = 0;
		const rows = await chatApi.listMessages(channelId, { aroundSeq: seq });
		if (generation !== this.#sessionGeneration) return;
		// aroundSeq mode returns ascending already (chat_messages_list) —
		// unlike the normal DESC page openChannel() reverses, no reverse here.
		this.messagesByChannel[channelId] = rows.map((m) => ({ ...m, status: 'sent' as const }));
		const target = rows.find((m) => m.seq === seq);
		this.focusedMessageId = target ? target.messageId : null;
	}

	/** Clears the jump-to-message highlight (Task 15 calls this once the
	 *  focused row has scrolled out of view, or the user navigates away). */
	clearFocusedMessage(): void {
		this.focusedMessageId = null;
	}

	/** Sends to the currently open channel. Pushes an optimistic row immediately;
	 *  on failure the row's status flips to 'failed' and its body is left in place
	 *  (the row itself IS the "restored buffer" — MessageRow's Retry/Discard read it). */
	async send(body: string, parentId?: number | null, mentions?: number[], broadcast?: string | null): Promise<void> {
		const generation = this.#sessionGeneration;
		const channelId = this.activeChannelId;
		if (channelId == null) return;
		const key = pendingKey(channelId, parentId);
		// Ternary, not an `if`/early-`await` — when nothing is pending for this
		// composer the right side is a plain `[]`, no `await` is ever reached,
		// and this whole function runs synchronously up to the push below
		// (Design C3's "never blocks text-only send", and the pre-existing
		// "optimistic row is visible synchronously" contract both rely on this).
		const attachmentPayload = this.pendingAttachments[key]?.length
			? await this.#collectReadyAttachments(key, generation)
			: [];
		if (generation !== this.#sessionGeneration) return;
		const clientId = crypto.randomUUID();
		// Never mutate the right side of a `??=`-style assignment directly — the
		// assignment expression evaluates to the plain value assigned, not the
		// reactive proxy Svelte wraps it in once it lands in $state. Assign first,
		// then re-read from the proxy so `rows` is the live, tracked array.
		if (!this.messagesByChannel[channelId]) this.messagesByChannel[channelId] = [];
		const rows = this.messagesByChannel[channelId];
		rows.push({
			// ponytail: negative synthetic id — real chat_messages ids are positive
			// bigints, so this can never collide; replaced with the server id on ack.
			messageId: -Date.now(),
			channelId,
			// pins the optimistic row at the tail of the ascending list until reconciled.
			seq: Number.MAX_SAFE_INTEGER,
			authorId: this.selfUserId ?? 0,
			authorExternal: false,
			authorRemoved: false,
			parentMessageId: parentId ?? null,
			msgType: 'text',
			broadcast: broadcast ?? null,
			body,
			editedAt: null,
			deletedAt: null,
			createdAt: new Date().toISOString(),
			reactions: [],
			mentionsMe: false,
			replyCount: 0,
			lastReplyAt: null,
			// Placeholder rows (Design "optimistic message carries attachment
			// placeholders reconciled from the projection") — fileNodeId 0 / a
			// non-positive id is never a real drive_nodes id, so a naive render
			// can't mistake this for a live deep-link; the next reconcile
			// (applyEvent's #reconcileSince / #upsertMessage) overwrites this
			// array with the server's real ids in place.
			attachments: attachmentPayload.map((a, i) => ({
				id: -(i + 1),
				fileNodeId: 0,
				filename: a.name,
				contentType: a.contentType ?? null,
				sizeBytes: a.size,
			})),
			clientId,
			status: 'sending',
			pendingMentions: mentions ?? [],
			pendingAttachmentPayload: attachmentPayload,
		});
		await this.#doSend(channelId, clientId, generation);
	}

	/** Composer's voice-recording send (A3 QoL Task 15) — the store-level half
	 *  of Task 6's msg_type/payload send seam, which shipped with no send
	 *  path to reach it (chat_poll_create, Task 9, is the only other caller,
	 *  through its own separate route). Mirrors send()'s optimistic-row shape
	 *  exactly, but the row is ALWAYS attachment-only (empty body, msgType
	 *  'voice', payload {durationMs}) — the recording IS the message, there
	 *  is no accompanying caption in v1. Reuses the SAME pending-attachment
	 *  key/collection machinery send() does (the recorded clip rides the A2
	 *  chunk-upload rail exactly like any other composer attachment). */
	async sendVoice(durationMs: number, parentId?: number | null): Promise<void> {
		const generation = this.#sessionGeneration;
		const channelId = this.activeChannelId;
		if (channelId == null) return;
		const key = pendingKey(channelId, parentId);
		const attachmentPayload = this.pendingAttachments[key]?.length
			? await this.#collectReadyAttachments(key, generation)
			: [];
		if (generation !== this.#sessionGeneration) return;
		const clientId = crypto.randomUUID();
		if (!this.messagesByChannel[channelId]) this.messagesByChannel[channelId] = [];
		const rows = this.messagesByChannel[channelId];
		rows.push({
			messageId: -Date.now(),
			channelId,
			seq: Number.MAX_SAFE_INTEGER,
			authorId: this.selfUserId ?? 0,
			authorExternal: false,
			authorRemoved: false,
			parentMessageId: parentId ?? null,
			msgType: 'voice',
			broadcast: null,
			body: '',
			editedAt: null,
			deletedAt: null,
			createdAt: new Date().toISOString(),
			reactions: [],
			mentionsMe: false,
			replyCount: 0,
			lastReplyAt: null,
			payload: { durationMs },
			attachments: attachmentPayload.map((a, i) => ({
				id: -(i + 1),
				fileNodeId: 0,
				filename: a.name,
				contentType: a.contentType ?? null,
				sizeBytes: a.size,
			})),
			clientId,
			status: 'sending',
			pendingMentions: [],
			pendingAttachmentPayload: attachmentPayload,
		});
		await this.#doSend(channelId, clientId, generation);
	}

	// ── attachments (Chat A2 Task 7) ────────────────────────────────────────

	/** Kicks off hash+upload for each file against the given composer
	 *  (channelId, parentId) — fire-and-forget from the caller's point of
	 *  view (the UI polls `pendingAttachments[key]`, reactive $state, for
	 *  progress); returns the underlying per-file promises so a test (or a
	 *  caller that wants to know when a batch has settled) can await them.
	 *  Reuses $lib/drive/upload.ts's splitManifest + drive/api.ts's
	 *  headChunk/putChunk — never re-implements the chunk rail. */
	addAttachments(channelId: number, parentId: number | null | undefined, files: File[]): Promise<void>[] {
		const generation = this.#sessionGeneration;
		const key = pendingKey(channelId, parentId);
		if (!this.pendingAttachments[key]) this.pendingAttachments[key] = [];
		const rows = this.pendingAttachments[key];
		const tasks: Promise<void>[] = [];
		for (const file of files) {
			const clientId = crypto.randomUUID();
			rows.push({
				clientId,
				file,
				status: 'hashing',
				progress: 0,
				size: file.size,
				name: file.name,
				// M17 (edge case): an empty File.type (e.g. some OS file pickers
				// for unrecognized extensions) falls back to a generic binary type.
				contentType: file.type || 'application/octet-stream',
			});
			const controller = new AbortController();
			this.#uploadAborts.set(clientId, controller);
			const task = this.#uploadAttachment(channelId, key, clientId, controller.signal, generation);
			this.#uploadTasks.set(clientId, task);
			tasks.push(task);
		}
		return tasks;
	}

	/** Removes a chip outright — cancels its upload in flight, if any (the
	 *  counterpart to retryAttachment for a permanently-unwanted attachment). */
	removeAttachment(channelId: number, parentId: number | null | undefined, clientId: string): void {
		const key = pendingKey(channelId, parentId);
		const rows = this.pendingAttachments[key];
		if (!rows) return;
		this.#uploadAborts.get(clientId)?.abort();
		const next = rows.filter((r) => r.clientId !== clientId);
		if (next.length > 0) this.pendingAttachments[key] = next;
		else delete this.pendingAttachments[key];
	}

	/** Re-attempts a 'failed' chip in place, same clientId — mirrors retry()'s
	 *  message-level shape. Returns the new attempt's promise (test/await
	 *  convenience, same as addAttachments). */
	retryAttachment(channelId: number, parentId: number | null | undefined, clientId: string): Promise<void> | undefined {
		const generation = this.#sessionGeneration;
		const key = pendingKey(channelId, parentId);
		const rows = this.pendingAttachments[key];
		if (!rows) return undefined;
		const idx = rows.findIndex((r) => r.clientId === clientId);
		if (idx === -1 || rows[idx].status !== 'failed') return undefined;
		rows[idx] = { ...rows[idx], status: 'hashing', progress: 0, error: undefined };
		const controller = new AbortController();
		this.#uploadAborts.set(clientId, controller);
		const task = this.#uploadAttachment(channelId, key, clientId, controller.signal, generation);
		this.#uploadTasks.set(clientId, task);
		return task;
	}

	/** One chunked-upload run for a single chip. HEAD-skip dedup (I-4) means a
	 *  re-shared file that's already on the server flips straight to 'ready'
	 *  without ever PUTting a byte — the instant-ready case the plan calls out. */
	async #uploadAttachment(channelId: number, key: string, clientId: string, signal: AbortSignal, generation: number): Promise<void> {
		const setEntry = (patch: Partial<PendingAttachment>) => {
			if (generation !== this.#sessionGeneration) return;
			const rows = this.pendingAttachments[key];
			if (!rows) return;
			const idx = rows.findIndex((r) => r.clientId === clientId);
			if (idx >= 0) rows[idx] = { ...rows[idx], ...patch };
		};
		try {
			const rows = this.pendingAttachments[key];
			const entry = rows?.find((r) => r.clientId === clientId);
			if (!entry) return;
			const spaceId = await this.#ensureSpaceId(channelId, generation);
			if (generation !== this.#sessionGeneration) return;
			const manifest = await splitManifest(entry.file, (done) => setEntry({ progress: done }), signal);
			setEntry({ status: 'uploading', sha256: manifest.contentSha256, manifest: manifest.chunks, progress: 0 });
			let off = 0;
			for (const chunk of manifest.chunks) {
				if (signal.aborted) return;
				const already = await headChunk(spaceId, chunk.sha256);
				if (!already) {
					const bytes: Uint8Array<ArrayBuffer> = new Uint8Array(await entry.file.slice(off, off + chunk.size).arrayBuffer());
					await putChunk(spaceId, chunk.sha256, bytes);
				}
				off += chunk.size;
				setEntry({ progress: off });
			}
			if (signal.aborted) return;
			setEntry({ status: 'ready', progress: entry.size });
		} catch (err) {
			// An abort (removeAttachment mid-flight) is not a failure to surface
			// — the chip is either already gone or about to be replaced by retry.
			if (err instanceof Error && err.name === 'UploadAbortedError') return;
			setEntry({ status: 'failed', error: driveErrorMessage(err) });
		} finally {
			if (generation === this.#sessionGeneration) this.#uploadAborts.delete(clientId);
		}
	}

	/** One ensureSpace() round trip per channel, cached across every file a
	 *  composer attaches (M18: this is also what lazily provisions the chat
	 *  space on first attach-intent, even if the composer is later abandoned). */
	#ensureSpaceId(channelId: number, generation: number): Promise<number> {
		let p = this.#spaceIdByChannel.get(channelId);
		if (!p) {
			p = chatApi.ensureSpace(channelId).then((r) => r.spaceId);
			// A rejected ensureSpace() must not poison the channel forever — evict
			// so the next addAttachments/retryAttachment gets a fresh call instead
			// of replaying the same stale rejection until page reload.
			p.catch(() => {
				if (generation === this.#sessionGeneration) this.#spaceIdByChannel.delete(channelId);
			});
			this.#spaceIdByChannel.set(channelId, p);
		}
		return p;
	}

	/** Awaits every chip's in-flight upload, then hands back the wire payload
	 *  for the 'ready' ones (send() awaits this only when something is
	 *  pending — see the ternary there). 'failed' chips are left in
	 *  pendingAttachments as removable/retryable, not silently dropped. */
	async #collectReadyAttachments(key: string, generation: number): Promise<AttachmentPayload[]> {
		const rows = this.pendingAttachments[key] ?? [];
		await Promise.allSettled(rows.map((r) => this.#uploadTasks.get(r.clientId)));
		// reset() replaces the public map and advances the session generation.
		// Both checks matter: generation rejects an old identity outright; array
		// identity prevents an older collector in the SAME generation from
		// deleting/replacing a newer composer-owned list at the reused key.
		if (generation !== this.#sessionGeneration || this.pendingAttachments[key] !== rows) return [];
		const ready = rows.filter((r) => r.status === 'ready');
		const remaining = rows.filter((r) => r.status !== 'ready');
		if (remaining.length > 0) this.pendingAttachments[key] = remaining;
		else delete this.pendingAttachments[key];
		return ready.map((r) => ({
			sha256: r.sha256!,
			size: r.size,
			name: r.name,
			contentType: r.contentType,
			manifest: (r.manifest ?? []).map((c) => ({ sha256: c.sha256, size: c.size })),
		}));
	}

	/** Re-attempts a 'failed' optimistic row in place, same clientId. */
	async retry(clientId: string): Promise<void> {
		const generation = this.#sessionGeneration;
		for (const key of Object.keys(this.messagesByChannel)) {
			const channelId = Number(key);
			const row = this.messagesByChannel[channelId].find((r) => r.clientId === clientId);
			if (!row) continue;
			if (row.status !== 'failed') return;
			row.status = 'sending';
			await this.#doSend(channelId, clientId, generation);
			return;
		}
	}

	/** Gives up on a permanently-failed send (MessageRow's Discard action) —
	 *  removes the row outright, the counterpart to retry()'s re-attempt. */
	discard(clientId: string): void {
		for (const key of Object.keys(this.messagesByChannel)) {
			const channelId = Number(key);
			const rows = this.messagesByChannel[channelId];
			const idx = rows.findIndex((r) => r.clientId === clientId);
			if (idx >= 0) {
				this.messagesByChannel[channelId] = [...rows.slice(0, idx), ...rows.slice(idx + 1)];
				return;
			}
		}
	}

	/** Optimistic reaction toggle (MessageRow's pills, Design F1): flips the
	 *  pill in this store's row BEFORE the API call resolves, so the acting
	 *  user sees their own click instantly. Reverted on failure. A later
	 *  reaction_added/removed push (fanned out to every member incl. the
	 *  actor) re-syncs the authoritative count via applyEvent regardless. */
	async toggleReaction(channelId: number, messageId: number, emoji: string): Promise<void> {
		const generation = this.#sessionGeneration;
		const rows = this.messagesByChannel[channelId];
		if (!rows) return;
		const idx = rows.findIndex((r) => r.messageId === messageId);
		if (idx === -1) return;
		const before = rows[idx].reactions;
		rows[idx] = { ...rows[idx], reactions: flipReaction(before, emoji) };
		try {
			await chatApi.toggleReaction(messageId, emoji);
		} catch (err) {
			if (generation !== this.#sessionGeneration) throw err;
			const cur = rows.findIndex((r) => r.messageId === messageId);
			if (cur >= 0) rows[cur] = { ...rows[cur], reactions: before };
			throw err;
		}
	}

	/** Author-only edit (BZ167 enforced server-side) — updates body/seq/editedAt
	 *  in place on success; the reducer captures the PRIOR body into
	 *  chat_message_revisions before this ever resolves (grill Q3). */
	async editMessage(channelId: number, messageId: number, body: string): Promise<void> {
		const generation = this.#sessionGeneration;
		const res = await chatApi.editMessage(messageId, body);
		if (generation !== this.#sessionGeneration) return;
		const rows = this.messagesByChannel[channelId];
		if (!rows) return;
		const idx = rows.findIndex((r) => r.messageId === messageId);
		if (idx >= 0) rows[idx] = { ...rows[idx], body, seq: res.seq, editedAt: new Date().toISOString() };
	}

	/** Author or channel owner/admin (BZ167). Blanks the row's body client-side
	 *  to mirror the server projection — the row itself RETAINS body server-side
	 *  (C1, compliance); this store never sees that retained value. */
	async deleteMessage(channelId: number, messageId: number): Promise<void> {
		const generation = this.#sessionGeneration;
		const res = await chatApi.deleteMessage(messageId);
		if (generation !== this.#sessionGeneration) return;
		const rows = this.messagesByChannel[channelId];
		if (!rows) return;
		const idx = rows.findIndex((r) => r.messageId === messageId);
		if (idx >= 0) rows[idx] = { ...rows[idx], body: '', seq: res.seq, deletedAt: new Date().toISOString() };
	}

	async #doSend(channelId: number, clientId: string, generation: number): Promise<void> {
		if (generation !== this.#sessionGeneration) return;
		const rows = this.messagesByChannel[channelId];
		const row = rows.find((r) => r.clientId === clientId);
		if (!row) return;
		try {
			const res = await chatApi.sendMessage(
				channelId,
				row.body,
				row.parentMessageId,
				row.pendingMentions,
				row.broadcast,
				row.pendingAttachmentPayload,
				// A3 QoL Task 15: 'text' is the server's own default — omitted
				// here so a plain send()'s wire call stays byte-identical to
				// before this task (no msgType/payload key at all).
				row.msgType !== 'text' ? row.msgType : undefined,
				row.payload ?? undefined,
			);
			if (generation !== this.#sessionGeneration) return;
			// Known race, not fixed here (ponytail): if a `message_created` push for this
			// same send arrives BEFORE this response, applyEvent's reconcile will have
			// already appended a second, non-clientId row for the real messageId (the
			// event payload carries no clientId to correlate against) — a duplicate that
			// self-heals on the next full reload/backfillSince. Fixing it needs the server
			// to echo clientId back, which is a wire-contract change outside Task 12.
			const i = rows.findIndex((r) => r.clientId === clientId);
			if (i >= 0) rows[i] = { ...rows[i], messageId: res.messageId, seq: res.seq, status: 'sent' };
		} catch (err) {
			if (generation !== this.#sessionGeneration) throw err;
			const i = rows.findIndex((r) => r.clientId === clientId);
			if (i >= 0) {
				rows[i] = { ...rows[i], status: 'failed', errorCode: err instanceof chatApi.ChatError ? err.code : undefined };
			}
			throw err;
		}
	}

	/** Idempotent on messageId — a replayed or duplicate event for a row already
	 *  present merges in place instead of appending a second copy. */
	#upsertMessage(channelId: number, msg: ChatMessage): void {
		if (!this.messagesByChannel[channelId]) this.messagesByChannel[channelId] = [];
		const rows = this.messagesByChannel[channelId];
		const idx = rows.findIndex((r) => r.messageId === msg.messageId);
		if (idx >= 0) {
			rows[idx] = { ...rows[idx], ...msg, status: 'sent' };
			return;
		}
		const insertAt = rows.findIndex((r) => r.status === 'sent' && r.seq > msg.seq);
		const stored: StoreMessage = { ...msg, status: 'sent' };
		if (insertAt === -1) rows.push(stored);
		else rows.splice(insertAt, 0, stored);
		if (channelId === this.activeChannelId && !this.atBottom) this.unseenBelow++;
	}

	/** Highest CONFIRMED seq this store has seen for a channel — optimistic
	 *  ('sending'/'failed') rows carry a synthetic seq and are excluded, or every
	 *  backfill/reconcile while a send is in flight would ask the server for
	 *  "since Number.MAX_SAFE_INTEGER" and get nothing back. */
	#maxSeqFor(channelId: number): number {
		const rows = this.messagesByChannel[channelId];
		const rowMax = rows?.reduce((max, m) => (m.status === 'sent' && m.seq > max ? m.seq : max), 0) ?? 0;
		return Math.max(rowMax, this.#replayCursorByChannel.get(channelId) ?? 0);
	}

	#applyReplay(channelId: number, replay: ChatReplay): void {
		const current = this.#replayCursorByChannel.get(channelId) ?? 0;
		this.#replayCursorByChannel.set(channelId, Math.max(current, replay.cursor));
		for (const row of replay.messages) this.#upsertMessage(channelId, row);
	}

	#serializeReplay(channelId: number, request: () => Promise<ChatReplay>): Promise<void> {
		const generation = this.#sessionGeneration;
		const execute = async () => {
			if (generation !== this.#sessionGeneration) return;
			let replay: ChatReplay;
			try {
				replay = await request();
			} catch (err) {
				// A late failure belongs to the identity that issued the request;
				// after reset it must not surface in the next session either.
				if (generation !== this.#sessionGeneration) return;
				throw err;
			}
			if (generation !== this.#sessionGeneration) return;
			this.#applyReplay(channelId, replay);
		};
		const previous = this.#replayQueueByChannel.get(channelId);
		const run = previous ? previous.catch(() => undefined).then(execute) : execute();
		this.#replayQueueByChannel.set(channelId, run);
		const clear = () => {
			if (this.#replayQueueByChannel.get(channelId) === run) {
				this.#replayQueueByChannel.delete(channelId);
			}
		};
		void run.then(clear, clear);
		return run;
	}

	#reconcileSince(channelId: number, seq: number | null): Promise<void> {
		return this.#serializeReplay(channelId, () =>
			chatApi.sinceMessages(channelId, seq != null ? seq - 1 : this.#maxSeqFor(channelId))
		);
	}

	/** Reconnect replay path (Design F5): pulls everything since the last
	 *  confirmed seq this store holds for the channel. */
	backfillSince(channelId: number): Promise<void> {
		return this.#serializeReplay(channelId, () =>
			chatApi.sinceMessages(channelId, this.#maxSeqFor(channelId))
		);
	}

	/** History-prepend page (Task 14 — MessageList's infinite-scroll-up): the
	 *  prior keyset page before `beforeSeq`, reversed to ASC and spliced ahead
	 *  of whatever's already loaded. Skips any messageId already present, so a
	 *  duplicate prepend (e.g. two scroll-triggered calls racing) is a no-op
	 *  merge rather than a second copy. Returns the count actually added —
	 *  0 tells the caller there is no older page left to fetch. */
	async loadOlderMessages(channelId: number, beforeSeq: number, limit = 50): Promise<number> {
		const generation = this.#sessionGeneration;
		const page = await chatApi.listMessages(channelId, { beforeSeq, limit });
		if (generation !== this.#sessionGeneration) return 0;
		if (page.length === 0) return 0;
		const rows = this.messagesByChannel[channelId] ?? (this.messagesByChannel[channelId] = []);
		const existing = new Set(rows.map((r) => r.messageId));
		const toPrepend = page
			.slice()
			.reverse()
			.filter((m) => !existing.has(m.messageId))
			.map((m) => ({ ...m, status: 'sent' as const }));
		this.messagesByChannel[channelId] = [...toPrepend, ...rows];
		return toPrepend.length;
	}

	/** Wire this to the transport's reconnect signal (Task 13) — never loses
	 *  messages sent while this client was offline. */
	async onSocketOpen(): Promise<void> {
		const generation = this.#sessionGeneration;
		if (this.activeChannelId != null) await this.backfillSince(this.activeChannelId);
		if (generation !== this.#sessionGeneration) return;
		await this.#reconcileConversations();
	}

	#addTypingUser(channelId: number, userId: number | undefined): void {
		// chat_presence.sql's notify_chat_state call carries no actor id today (a gap
		// in the already-shipped Task 7 reducer, tracked as a TODO, not fixed here —
		// out of Task 12's file scope) — this is a no-op until userId is present.
		if (userId == null || userId === this.selfUserId) return;
		const expiresAt = Date.now() + TYPING_TTL_MS;
		const generation = this.#sessionGeneration;
		const key = `${channelId}:${userId}`;
		const existing = this.typingUsers.find((t) => t.channelId === channelId && t.userId === userId);
		if (existing) existing.expiresAt = expiresAt;
		else this.typingUsers.push({ channelId, userId, expiresAt });
		const prior = this.#typingTimers.get(key);
		if (prior) clearTimeout(prior);
		this.#typingTimers.set(
			key,
			setTimeout(() => {
				if (generation === this.#sessionGeneration) this.#expireTypingUser(channelId, userId);
			}, TYPING_TTL_MS),
		);
	}

	#expireTypingUser(channelId: number, userId: number): void {
		this.typingUsers = this.typingUsers.filter((t) => !(t.channelId === channelId && t.userId === userId));
		this.#typingTimers.delete(`${channelId}:${userId}`);
	}

	#syncReadWatermark(channelId: number, seq: number | null, userId: number | undefined): void {
		if (seq == null) return;
		// Defensive self-scope check (chat_mark_read's own comment: the self-channel
		// already guarantees only the caller's own acks arrive here, but carries
		// userId so a client can defend even if it ever listens broader than that).
		if (userId != null && this.selfUserId != null && userId !== this.selfUserId) return;
		const conv = this.conversations.find((c) => c.channelId === channelId);
		if (!conv) return;
		conv.lastReadSeq = Math.max(conv.lastReadSeq, seq);
		if (conv.lastReadSeq >= conv.changeSeq) conv.unreadCount = 0;
	}

	/** Idempotent event owner. Message replay, conversation metadata refresh and
	 * immediate federation revocation live here; the view receives only the
	 * narrow federation-roster invalidation it owns. */
	async applyEvent(evt: ChatWireEvent): Promise<ChatEventOutcome> {
		let refreshConversations = false;
		let refreshFederationRosterChannelId: number | null = null;
		switch (evt.event) {
			case 'message_created':
			case 'message_edited':
			case 'message_deleted':
				await this.#reconcileSince(evt.channelId, evt.seq);
				refreshConversations = true;
				break;
			case 'reaction_added':
			case 'reaction_removed':
			// A3 QoL Task 3: pin/unpin re-stamp the message's seq under the
			// channel's change_seq lock (same rail as edit/delete), so the
			// EXISTING reconcile heals the fresh 'pinned' flag chat_message_to_json
			// projects — no separate patch logic needed.
			// falls through
			case 'message_pinned':
				await this.#reconcileSince(evt.channelId, evt.seq);
				break;
			// A3 QoL Task 9: votes never bump change_seq (write-amplification
			// ceiling) — refetch tallies directly instead of via the seq rail,
			// and only for a poll something has actually rendered (cached).
			case 'poll_voted':
				await this.#maybeRefetchPollResults(evt.channelId, evt.messageId);
				break;
			case 'typing':
				this.#addTypingUser(evt.channelId, evt.userId);
				break;
			case 'read':
				// Defensive event-shape check: 'read' is only ever meaningful when
				// attributed to self (chat_mark_read's self-notify). A frame with
				// no actor id is treated as non-self — an actor-less fanout must
				// never clear unread badges. (The local-echo caller
				// markReadDebounced syncs via #syncReadWatermark directly.)
				if (evt.userId == null || evt.userId !== this.selfUserId) break;
				this.#syncReadWatermark(evt.channelId, evt.seq, evt.userId);
				break;
			// A3 QoL Task 4 (DES-010): DM-only live tick — chat_mark_read never
			// fans this out for channel/group_dm (see chat_read.sql).
			case 'member_read':
				// Same attribution defense: a 'member_read' frame with no actor
				// id is unattributable and must never forge the peer's read tick.
				if (evt.userId == null) break;
				this.#syncPeerReadTick(evt.channelId, evt.seq, evt.userId);
				break;
			case 'federation_removed': {
				// Revocation is fail-closed immediately; it must not wait behind the
				// ordinary metadata fetch or be erased if that fetch fails.
				const conversation = this.conversations.find((c) => c.channelId === evt.channelId);
				this.#federationRevokedChannels.add(evt.channelId);
				if (conversation) conversation.federatedRoomRemoved = true;
				refreshConversations = true;
				refreshFederationRosterChannelId = evt.channelId;
				break;
			}
			case 'federation_roster':
				refreshConversations = true;
				refreshFederationRosterChannelId = evt.channelId;
				break;
			case 'member_added':
			case 'member_removed':
			case 'owner_changed':
			case 'channel_updated':
				refreshConversations = true;
				break;
			default:
				break;
		}
		if (refreshConversations) await this.#reconcileConversations();
		return { refreshFederationRosterChannelId };
	}

	async #reconcileConversations(): Promise<void> {
		const generation = this.#sessionGeneration;
		const current = this.#conversationReconcile;
		if (current?.generation === generation) {
			current.dirty = true;
			return current.promise;
		}

		const cycle: ConversationReconcileCycle = {
			generation,
			dirty: false,
			promise: Promise.resolve(),
		};
		this.#conversationReconcile = cycle;
		cycle.promise = (async () => {
			do {
				cycle.dirty = false;
				try {
					await this.loadConversations();
				} catch {
					// Preserve the last readable projection. A dirty invalidation retries
					// once after this attempt; otherwise the next event/socket-open retries.
				}
				if (cycle.generation !== this.#sessionGeneration) return;
			} while (cycle.dirty);
		})().finally(() => {
			if (this.#conversationReconcile === cycle) this.#conversationReconcile = null;
		});
		return cycle.promise;
	}

	/** Refetches chat_poll_results for the poll anchored to messageId, but
	 *  ONLY when the caller is currently looking at that channel AND has
	 *  already rendered that poll at least once (i.e., it's cached) — an
	 *  uncached poll_voted for a background poll is a no-op; it heals on the
	 *  next render via loadPollResults(), matching the "no live fetch for
	 *  invisible state" posture DES-010 already accepts for read receipts. */
	async #maybeRefetchPollResults(channelId: number, messageId: number | null): Promise<void> {
		if (channelId !== this.activeChannelId || messageId == null) return;
		const row = this.messagesByChannel[channelId]?.find((r) => r.messageId === messageId);
		const pollId = (row?.payload as { pollId?: number } | null | undefined)?.pollId;
		if (pollId == null || !(pollId in this.pollResultsByPollId)) return;
		await this.loadPollResults(pollId);
	}

	/** Loads (or refreshes) one poll's tally/voter cache — Task 15's poll
	 *  render calls this; applyEvent's 'poll_voted' arm calls it again only
	 *  for an already-cached, currently-active-channel poll. */
	async loadPollResults(pollId: number): Promise<void> {
		const generation = this.#sessionGeneration;
		const results = await chatApi.pollResults(pollId);
		if (generation === this.#sessionGeneration) this.pollResultsByPollId[pollId] = results;
	}

	/** Monotonic, same non-rewind guarantee as #syncReadWatermark — a stale/
	 *  out-of-order 'member_read' ack can never move the peer's tick backward. */
	#syncPeerReadTick(channelId: number, seq: number | null, userId: number | undefined): void {
		if (seq == null) return;
		// Defensive self-scope check (mirrors #syncReadWatermark's own comment):
		// the server only ever sends 'member_read' to the OTHER DM member, but
		// defend anyway in case a client ever listens broader than its own
		// self-channel.
		if (userId != null && this.selfUserId != null && userId === this.selfUserId) return;
		const cur = this.peerReadSeq[channelId] ?? 0;
		if (seq > cur) this.peerReadSeq[channelId] = seq;
	}

	/** Translated text for (messageId, targetLocale), cached — re-toggling
	 *  "Show original"/"Show translation" in the UI costs zero extra API
	 *  calls for the same pair. */
	async translateMessage(messageId: number, targetLocale: string): Promise<string> {
		const key = `${messageId}:${targetLocale}`;
		const cached = this.translationsByKey[key];
		if (cached != null) return cached;
		const generation = this.#sessionGeneration;
		const { translated } = await chatApi.translateMessage(messageId, targetLocale);
		if (generation === this.#sessionGeneration) this.translationsByKey[key] = translated;
		return translated;
	}

	/** Composer's "send later" (Task 2's ScheduledAction rail) — deliberately
	 *  does NOT push an optimistic timeline row the way send() does: the
	 *  message doesn't exist until fire time, and a placeholder in the live
	 *  timeline would misrepresent a queued send as already delivered. The
	 *  scheduled-queue view (Task 16) is the only pre-fire surface. */
	async scheduleSend(
		channelId: number,
		body: string,
		fireAt: string,
		parentId?: number | null,
		mentions?: number[],
		broadcast?: string | null,
	): Promise<void> {
		const generation = this.#sessionGeneration;
		await chatApi.scheduleMessage(channelId, body, {
			parentId: parentId ?? null,
			mentions: mentions ?? [],
			broadcast: broadcast ?? null,
			fireAt,
		});
		if (generation === this.#sessionGeneration) await this.loadScheduled();
	}

	/** Populates the scheduled-queue view (Task 16) with the caller's own
	 *  pending + failed chat_send rows. */
	async loadScheduled(): Promise<void> {
		const generation = this.#sessionGeneration;
		const rows = await chatApi.listScheduled();
		if (generation === this.#sessionGeneration) this.scheduled = rows;
	}

	/** Dismiss (works on a pending OR failed row) — removes it from the local
	 *  queue once the server confirms. */
	async cancelScheduled(actionId: string): Promise<void> {
		const generation = this.#sessionGeneration;
		await chatApi.cancelScheduled(actionId);
		if (generation === this.#sessionGeneration) {
			this.scheduled = this.scheduled.filter((s) => s.actionId !== actionId);
		}
	}

	/** Visibility-gated (Design F3): only marks read while the tab is visible
	 *  AND the viewport is at/below the bottom — never while backgrounded or scrolled up. */
	markReadDebounced(channelId: number, seq: number): void {
		if (!this.#canMarkRead()) return;
		if (this.#markReadTimer) clearTimeout(this.#markReadTimer);
		const generation = this.#sessionGeneration;
		this.#markReadTimer = setTimeout(() => {
			if (generation !== this.#sessionGeneration) return;
			this.#markReadTimer = null;
			if (!this.#canMarkRead()) return;
			const selfId = this.selfUserId ?? undefined;
			void chatApi.markRead(channelId, seq).then(() => {
				if (generation === this.#sessionGeneration) this.#syncReadWatermark(channelId, seq, selfId);
			});
		}, MARK_READ_DEBOUNCE_MS);
	}

	#canMarkRead(): boolean {
		if (typeof document !== 'undefined' && document.visibilityState === 'hidden') return false;
		return this.atBottom;
	}
}

/** Shared process-wide instance — mirrors drive/locks.svelte.ts's singleton pattern. */
export const chatStore = new ChatStore();
registerAuthSessionTeardown(() => chatStore.reset());
