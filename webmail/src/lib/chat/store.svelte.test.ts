import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { ChatStore, chatStore, chatErrorMessage, chatErrorReason, retentionNotice } from './store.svelte';
import { ChatError } from './api';
import type { ChatMessage, ChatReplay, Conversation } from './api';

// ChatStore only needs the teardown registration seam. Keep this unit suite
// isolated from auth.ts's browser-startup checkAuth() side effect; auth's own
// tests cover registration and page-load restoration independently.
vi.mock('$lib/stores/auth', () => ({
	registerAuthSessionTeardown: vi.fn(() => vi.fn()),
}));

const listConversations = vi.fn();
const listMessages = vi.fn();
const sinceMessages = vi.fn();
const sendMessage = vi.fn();
const markRead = vi.fn();
const editMessage = vi.fn();
const deleteMessage = vi.fn();
const toggleReaction = vi.fn();
const ensureSpace = vi.fn();
const pollResults = vi.fn();
const translateMessage = vi.fn();
const scheduleMessage = vi.fn();
const listScheduled = vi.fn();
const cancelScheduled = vi.fn();

vi.mock('./api', async () => {
	const actual = await vi.importActual<typeof import('./api')>('./api');
	return {
		...actual,
		listConversations: (...a: unknown[]) => listConversations(...a),
		listMessages: (...a: unknown[]) => listMessages(...a),
		sinceMessages: (...a: unknown[]) => sinceMessages(...a),
		sendMessage: (...a: unknown[]) => sendMessage(...a),
		markRead: (...a: unknown[]) => markRead(...a),
		editMessage: (...a: unknown[]) => editMessage(...a),
		deleteMessage: (...a: unknown[]) => deleteMessage(...a),
		toggleReaction: (...a: unknown[]) => toggleReaction(...a),
		ensureSpace: (...a: unknown[]) => ensureSpace(...a),
		pollResults: (...a: unknown[]) => pollResults(...a),
		translateMessage: (...a: unknown[]) => translateMessage(...a),
		scheduleMessage: (...a: unknown[]) => scheduleMessage(...a),
		listScheduled: (...a: unknown[]) => listScheduled(...a),
		cancelScheduled: (...a: unknown[]) => cancelScheduled(...a),
	};
});

// The chunk rail itself ($lib/drive/api's headChunk/putChunk) is mocked —
// only the store's own hash/dedup/collect logic is under test here;
// $lib/drive/upload.ts's splitManifest runs FOR REAL (real crypto.subtle),
// same as its own upload.test.ts, so the sha256 the store produces is a
// real hash of the test file's bytes, not a stub.
const headChunk = vi.fn();
const putChunk = vi.fn();

vi.mock('$lib/drive/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/drive/api')>('$lib/drive/api');
	return {
		...actual,
		headChunk: (...a: unknown[]) => headChunk(...a),
		putChunk: (...a: unknown[]) => putChunk(...a),
	};
});

function msg(over: Partial<ChatMessage> = {}): ChatMessage {
	return {
		messageId: 1,
		channelId: 10,
		seq: 1,
		authorId: 99,
		authorExternal: false,
		authorRemoved: false,
		parentMessageId: null,
		msgType: 'text',
		broadcast: null,
		body: 'hello',
		editedAt: null,
		deletedAt: null,
		createdAt: '2026-07-11T00:00:00Z',
		reactions: [],
		mentionsMe: false,
		replyCount: 0,
		lastReplyAt: null,
		attachments: [],
		...over,
	};
}

function replay(messages: ChatMessage[], cursor = messages.reduce((max, message) => Math.max(max, message.seq), 0)) {
	return { messages, cursor };
}

function deferred<T>() {
	let resolve!: (value: T) => void;
	let reject!: (reason?: unknown) => void;
	const promise = new Promise<T>((done, fail) => {
		resolve = done;
		reject = fail;
	});
	return { promise, resolve, reject };
}

async function flushPromises(): Promise<void> {
	await Promise.resolve();
	await Promise.resolve();
}

function file(name: string, contents = 'hello world', type = 'text/plain'): File {
	return new File([contents], name, { type });
}

function conv(over: Partial<Conversation> = {}): Conversation {
	return {
		channelId: 10,
		kind: 'channel',
		name: 'eng',
		topic: null,
		changeSeq: 5,
		lastReadSeq: 0,
		unreadCount: 3,
		hasMention: false,
		hasExternalMembers: false,
		lastMessagePreview: null,
		memberIds: [1, 2],
		...over,
	};
}

describe('ChatStore', () => {
	beforeEach(() => {
		listConversations.mockReset();
		listMessages.mockReset();
		sinceMessages.mockReset();
		sendMessage.mockReset();
		markRead.mockReset();
		ensureSpace.mockReset();
		headChunk.mockReset();
		putChunk.mockReset();
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it('exports a shared singleton instance', () => {
		expect(chatStore).toBeInstanceOf(ChatStore);
	});

	it('loadConversations() populates conversations and railBadge aggregates unread/mention', async () => {
		listConversations.mockResolvedValue({
			conversations: [conv({ unreadCount: 3, hasMention: false }), conv({ channelId: 11, unreadCount: 2, hasMention: true })],
			attachmentsEnabled: true,
		});
		const store = new ChatStore();

		await store.loadConversations();

		expect(store.conversations).toHaveLength(2);
		expect(store.railBadge.count).toBe(5);
		expect(store.railBadge.hasMention).toBe(true);
	});

	// Whole-pipeline review UX #6: railBadge must respect per-channel mute the
	// same way ChannelList's showBadge() does — a 'none'-muted channel's
	// unread must not light the rail at all, and a 'mentions'-muted channel
	// only contributes when it actually has a mention.
	it('railBadge excludes a muted (notifLevel=none) channel entirely', async () => {
		listConversations.mockResolvedValue({
			conversations: [
				conv({ unreadCount: 3, hasMention: false, notifLevel: 'none' }),
				conv({ channelId: 11, unreadCount: 2, hasMention: false, notifLevel: 'all' }),
			],
			attachmentsEnabled: true,
		});
		const store = new ChatStore();

		await store.loadConversations();

		expect(store.railBadge.count).toBe(2);
		expect(store.railBadge.hasMention).toBe(false);
	});

	it('railBadge only counts a mentions-muted channel when it has a mention', async () => {
		listConversations.mockResolvedValue({
			conversations: [
				conv({ unreadCount: 4, hasMention: false, notifLevel: 'mentions' }),
				conv({ channelId: 11, unreadCount: 1, hasMention: true, notifLevel: 'mentions' }),
			],
			attachmentsEnabled: true,
		});
		const store = new ChatStore();

		await store.loadConversations();

		expect(store.railBadge.count).toBe(1);
		expect(store.railBadge.hasMention).toBe(true);
	});

	it('loadConversations() parses the {conversations, attachmentsEnabled} envelope (T5 wire shape)', async () => {
		// Pins the envelope: a bare array here would make store.conversations the
		// envelope object and throw in railBadge's iteration (the T7 review catch).
		listConversations.mockResolvedValue({ conversations: [conv()], attachmentsEnabled: false });
		const store = new ChatStore();

		await store.loadConversations();

		expect(Array.isArray(store.conversations)).toBe(true);
		expect(store.conversations).toHaveLength(1);
		expect(store.attachmentsEnabled).toBe(false);
		expect(() => store.railBadge.count).not.toThrow();
	});

	it('openChannel() reverses the newest-first page into ascending order', async () => {
		listMessages.mockResolvedValue([msg({ messageId: 3, seq: 3 }), msg({ messageId: 2, seq: 2 }), msg({ messageId: 1, seq: 1 })]);
		const store = new ChatStore();

		await store.openChannel(10);

		expect(store.messagesByChannel[10].map((m) => m.seq)).toEqual([1, 2, 3]);
		expect(store.messagesByChannel[10].every((m) => m.status === 'sent')).toBe(true);
		expect(store.activeChannelId).toBe(10);
	});

	// Design F2/F13: a duplicate/replayed message_created must never double-insert.
	it('applyEvent(message_created) is idempotent on messageId', async () => {
		sinceMessages.mockResolvedValue(replay([msg({ messageId: 5, seq: 5 })]));
		const store = new ChatStore();
		store.activeChannelId = 10;

		await store.applyEvent({ event: 'message_created', channelId: 10, messageId: 5, seq: 5 });
		await store.applyEvent({ event: 'message_created', channelId: 10, messageId: 5, seq: 5 });

		expect(store.messagesByChannel[10]).toHaveLength(1);
		expect(sinceMessages).toHaveBeenCalledWith(10, 4); // seq-1
	});

	it('applyEvent reconciles message_edited/message_deleted/reaction_* the same way (refetch + merge)', async () => {
		sinceMessages.mockResolvedValue(replay([msg({ messageId: 5, seq: 6, body: 'edited' })]));
		const store = new ChatStore();
		store.messagesByChannel[10] = [{ ...msg({ messageId: 5, seq: 5 }), status: 'sent' }];

		await store.applyEvent({ event: 'message_edited', channelId: 10, messageId: 5, seq: 6 });

		expect(store.messagesByChannel[10]).toHaveLength(1);
		expect(store.messagesByChannel[10][0].body).toBe('edited');
	});

	it('send() reconciles the optimistic row on success (real messageId/seq, status sent)', async () => {
		sendMessage.mockResolvedValue({ messageId: 42, seq: 7 });
		const store = new ChatStore();
		store.activeChannelId = 10;
		store.selfUserId = 99;

		const p = store.send('hi there');
		// optimistic row is visible synchronously, before the send() promise resolves
		expect(store.messagesByChannel[10]).toHaveLength(1);
		expect(store.messagesByChannel[10][0].status).toBe('sending');
		expect(store.messagesByChannel[10][0].body).toBe('hi there');
		await p;

		expect(store.messagesByChannel[10]).toHaveLength(1);
		expect(store.messagesByChannel[10][0].status).toBe('sent');
		expect(store.messagesByChannel[10][0].messageId).toBe(42);
		expect(store.messagesByChannel[10][0].seq).toBe(7);

		// A later duplicate push for the now-confirmed messageId must not double-insert.
		sinceMessages.mockResolvedValue(replay([msg({ messageId: 42, seq: 7 })]));
		await store.applyEvent({ event: 'message_created', channelId: 10, messageId: 42, seq: 7 });
		expect(store.messagesByChannel[10]).toHaveLength(1);
	});

	// Design F4/F13: a failed send keeps status='failed' and the composed body is
	// retained on the row itself (the "restored buffer") for Retry/Discard.
	it('a failed send() sets status=failed and preserves the body', async () => {
		sendMessage.mockRejectedValue(new Error('network down'));
		const store = new ChatStore();
		store.activeChannelId = 10;

		await expect(store.send('important text')).rejects.toThrow('network down');

		expect(store.messagesByChannel[10]).toHaveLength(1);
		expect(store.messagesByChannel[10][0].status).toBe('failed');
		expect(store.messagesByChannel[10][0].body).toBe('important text');
	});

	// A4a Task 13: a rate-limited (BZ196) send used to become a failed row
	// with NO reason at all — the user just hammered Retry, burning more of
	// the same per-minute budget. #doSend now stamps errorCode from a
	// ChatError so MessageRow can render the reason next to Retry.
	it('a failed send() stamps errorCode from a ChatError', async () => {
		sendMessage.mockRejectedValue(new ChatError({ status: 507, code: 'BZ196', detail: 'overQuota' }));
		const store = new ChatStore();
		store.activeChannelId = 10;

		await expect(store.send('too fast')).rejects.toThrow();

		expect(store.messagesByChannel[10][0].status).toBe('failed');
		expect(store.messagesByChannel[10][0].errorCode).toBe('BZ196');
	});

	it('a failed send() from a non-ChatError (network/timeout) leaves errorCode undefined', async () => {
		sendMessage.mockRejectedValue(new Error('network down'));
		const store = new ChatStore();
		store.activeChannelId = 10;

		await expect(store.send('x')).rejects.toThrow();

		expect(store.messagesByChannel[10][0].errorCode).toBeUndefined();
	});

	it('retry() re-sends a failed row in place under the same clientId', async () => {
		sendMessage.mockRejectedValueOnce(new Error('boom')).mockResolvedValueOnce({ messageId: 9, seq: 1 });
		const store = new ChatStore();
		store.activeChannelId = 10;
		await expect(store.send('retry me')).rejects.toThrow();
		const clientId = store.messagesByChannel[10][0].clientId!;

		await store.retry(clientId);

		expect(store.messagesByChannel[10]).toHaveLength(1);
		expect(store.messagesByChannel[10][0].status).toBe('sent');
		expect(store.messagesByChannel[10][0].messageId).toBe(9);
	});

	// Design F5: reconnect must never lose messages — backfill the active channel
	// from its highest confirmed seq, then refresh the conversation list.
	it('onSocketOpen() backfills the active channel and reloads conversations', async () => {
		sinceMessages.mockResolvedValue(replay([msg({ messageId: 2, seq: 2 })]));
		listConversations.mockResolvedValue({ conversations: [conv()], attachmentsEnabled: true });
		const store = new ChatStore();
		store.activeChannelId = 10;
		store.messagesByChannel[10] = [{ ...msg({ messageId: 1, seq: 1 }), status: 'sent' }];

		await store.onSocketOpen();

		expect(sinceMessages).toHaveBeenCalledWith(10, 1);
		expect(store.messagesByChannel[10].map((m) => m.messageId)).toEqual([1, 2]);
		expect(listConversations).toHaveBeenCalledTimes(1);
	});

	it('advances an explicit replay cursor across an empty hidden mutation gap, then delivers the next visible row once', async () => {
		// seq 6 is an edit/delete of a pre-floor row: the server must not return
		// that row, but its cursor header advances. The following fetch therefore
		// starts at 6, receives visible seq 7 once, and the next starts at 7.
		sinceMessages
			.mockResolvedValueOnce(replay([], 6))
			.mockResolvedValueOnce(replay([msg({ messageId: 7, seq: 7, body: 'visible after gap' })], 7))
			.mockResolvedValueOnce(replay([], 7));
		const store = new ChatStore();
		store.messagesByChannel[10] = [{ ...msg({ messageId: 5, seq: 5 }), status: 'sent' }];

		await store.backfillSince(10);
		expect(sinceMessages).toHaveBeenNthCalledWith(1, 10, 5);
		expect(store.messagesByChannel[10].map((m) => m.messageId)).toEqual([5]);

		await store.backfillSince(10);
		expect(sinceMessages).toHaveBeenNthCalledWith(2, 10, 6);
		expect(store.messagesByChannel[10].filter((m) => m.messageId === 7)).toHaveLength(1);

		await store.backfillSince(10);
		expect(sinceMessages).toHaveBeenNthCalledWith(3, 10, 7);
		expect(store.messagesByChannel[10].filter((m) => m.messageId === 7)).toHaveLength(1);
	});

	it('reset clears every public user-scoped state slice', async () => {
		vi.useFakeTimers();
		const store = new ChatStore();
		store.conversations = [conv()];
		store.attachmentsEnabled = false;
		store.activeChannelId = 10;
		store.messagesByChannel = { 10: [{ ...msg(), status: 'sent' }] };
		store.atBottom = false;
		store.unseenBelow = 4;
		store.selfUserId = 99;
		store.pendingAttachments = { '10:root': [] };
		store.focusedMessageId = 1;
		store.pollResultsByPollId = { 5: {} as never };
		store.peerReadSeq = { 10: 9 };
		store.translationsByKey = { '1:de': 'Hallo' };
		store.scheduled = [{} as never];
		await store.applyEvent({ event: 'typing', channelId: 10, messageId: null, seq: null, userId: 7 });

		store.reset();

		expect(store.conversations).toEqual([]);
		expect(store.attachmentsEnabled).toBe(true);
		expect(store.activeChannelId).toBeNull();
		expect(store.messagesByChannel).toEqual({});
		expect(store.atBottom).toBe(true);
		expect(store.unseenBelow).toBe(0);
		expect(store.typingUsers).toEqual([]);
		expect(store.selfUserId).toBeNull();
		expect(store.pendingAttachments).toEqual({});
		expect(store.focusedMessageId).toBeNull();
		expect(store.pollResultsByPollId).toEqual({});
		expect(store.peerReadSeq).toEqual({});
		expect(store.translationsByKey).toEqual({});
		expect(store.scheduled).toEqual([]);
		vi.advanceTimersByTime(5000);
		expect(store.typingUsers).toEqual([]);
	});

	it('reset drops in-flight and queued old-session replay, then a reused channel starts from cursor zero', async () => {
		const oldReplay = deferred<ChatReplay>();
		sinceMessages.mockReturnValueOnce(oldReplay.promise);
		const store = new ChatStore();

		const inFlight = store.backfillSince(10);
		const queued = store.backfillSince(10);
		await Promise.resolve();
		expect(sinceMessages).toHaveBeenCalledTimes(1);

		store.reset();
		oldReplay.resolve(replay([msg({ messageId: 90, channelId: 10, seq: 9, body: 'old user' })], 9));
		await Promise.all([inFlight, queued]);
		expect(store.messagesByChannel[10]).toBeUndefined();
		expect(sinceMessages).toHaveBeenCalledTimes(1); // queued old request was never issued

		sinceMessages.mockResolvedValueOnce(replay([], 0));
		await store.backfillSince(10);
		expect(sinceMessages).toHaveBeenNthCalledWith(2, 10, 0);
	});

	it('serializes overlapping backfills before issuing the second API call', async () => {
		const first = deferred<ChatReplay>();
		const second = deferred<ChatReplay>();
		sinceMessages.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
		const store = new ChatStore();
		store.messagesByChannel[10] = [{ ...msg({ messageId: 5, seq: 5, body: 'original' }), status: 'sent' }];

		const editReplay = store.backfillSince(10);
		const deleteReplay = store.backfillSince(10);
		await Promise.resolve();
		expect(sinceMessages).toHaveBeenCalledTimes(1);

		first.resolve(replay([msg({ messageId: 5, seq: 6, body: 'edit' })], 6));
		await editReplay;
		expect(sinceMessages).toHaveBeenCalledTimes(2);
		expect(sinceMessages).toHaveBeenNthCalledWith(2, 10, 6);

		second.resolve(replay([msg({ messageId: 5, seq: 7, body: '', deletedAt: '2026-07-20T00:01:00Z' })], 7));
		await deleteReplay;

		expect(store.messagesByChannel[10][0].seq).toBe(7);
		expect(store.messagesByChannel[10][0].deletedAt).toBe('2026-07-20T00:01:00Z');
		expect(store.messagesByChannel[10][0].body).toBe('');
	});

	it('serializes same-seq reaction reconciles and finishes with the second response', async () => {
		const first = deferred<ChatReplay>();
		const second = deferred<ChatReplay>();
		sinceMessages.mockReturnValueOnce(first.promise).mockReturnValueOnce(second.promise);
		const reacted = { emoji: 'thumbsup', count: 1, mine: true };
		const store = new ChatStore();
		store.messagesByChannel[10] = [{ ...msg({ messageId: 5, seq: 5, reactions: [] }), status: 'sent' }];

		const addReplay = store.applyEvent({ event: 'reaction_added', channelId: 10, messageId: 5, seq: 5 });
		const removeReplay = store.applyEvent({ event: 'reaction_removed', channelId: 10, messageId: 5, seq: 5 });
		await Promise.resolve();
		expect(sinceMessages).toHaveBeenCalledTimes(1);

		first.resolve(replay([msg({ messageId: 5, seq: 5, reactions: [reacted] })], 5));
		await addReplay;
		expect(store.messagesByChannel[10][0].reactions).toEqual([reacted]);
		expect(sinceMessages).toHaveBeenCalledTimes(2);

		second.resolve(replay([msg({ messageId: 5, seq: 5, reactions: [] })], 5));
		await removeReplay;

		expect(store.messagesByChannel[10][0].seq).toBe(5);
		expect(store.messagesByChannel[10][0].reactions).toEqual([]);
	});

	it('onSocketOpen() with no active channel only reloads conversations', async () => {
		listConversations.mockResolvedValue({ conversations: [conv()], attachmentsEnabled: true });
		const store = new ChatStore();

		await store.onSocketOpen();

		expect(sinceMessages).not.toHaveBeenCalled();
		expect(listConversations).toHaveBeenCalledTimes(1);
	});

	// Design F13: typing rows auto-clear after 4s without a fresh signal.
	it('typing users expire after 4s', async () => {
		vi.useFakeTimers();
		const store = new ChatStore();

		await store.applyEvent({ event: 'typing', channelId: 10, messageId: null, seq: null, userId: 7 });
		expect(store.typingUsers.map((t) => t.userId)).toEqual([7]);

		vi.advanceTimersByTime(3999);
		expect(store.typingUsers).toHaveLength(1);

		vi.advanceTimersByTime(2);
		expect(store.typingUsers).toHaveLength(0);
	});

	it('a fresh typing signal for the same user resets the 4s window instead of stacking', async () => {
		vi.useFakeTimers();
		const store = new ChatStore();

		await store.applyEvent({ event: 'typing', channelId: 10, messageId: null, seq: null, userId: 7 });
		vi.advanceTimersByTime(3000);
		await store.applyEvent({ event: 'typing', channelId: 10, messageId: null, seq: null, userId: 7 });
		vi.advanceTimersByTime(3000); // 3s past the SECOND signal, only 6s past the first

		expect(store.typingUsers).toHaveLength(1);
	});

	it('the typing signal never lists the store\'s own selfUserId', async () => {
		const store = new ChatStore();
		store.selfUserId = 7;

		await store.applyEvent({ event: 'typing', channelId: 10, messageId: null, seq: null, userId: 7 });

		expect(store.typingUsers).toHaveLength(0);
	});

	// Design F3: markReadDebounced only fires while the tab is visible AND scrolled to bottom.
	it('markReadDebounced does not fire while the document is hidden', async () => {
		vi.useFakeTimers();
		Object.defineProperty(document, 'visibilityState', { value: 'hidden', configurable: true });
		const store = new ChatStore();
		store.atBottom = true;

		store.markReadDebounced(10, 5);
		await vi.advanceTimersByTimeAsync(1000);

		expect(markRead).not.toHaveBeenCalled();
		Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });
	});

	it('markReadDebounced does not fire while scrolled away from the bottom', async () => {
		vi.useFakeTimers();
		Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });
		const store = new ChatStore();
		store.atBottom = false;

		store.markReadDebounced(10, 5);
		await vi.advanceTimersByTimeAsync(1000);

		expect(markRead).not.toHaveBeenCalled();
	});

	it('markReadDebounced fires once after the debounce window when visible + at bottom, coalescing repeats', async () => {
		vi.useFakeTimers();
		Object.defineProperty(document, 'visibilityState', { value: 'visible', configurable: true });
		markRead.mockResolvedValue(undefined);
		const store = new ChatStore();
		store.atBottom = true;
		store.conversations = [conv({ channelId: 10, lastReadSeq: 0, changeSeq: 5 })];

		store.markReadDebounced(10, 3);
		store.markReadDebounced(10, 5); // supersedes the first before it fires
		await vi.advanceTimersByTimeAsync(1000);

		expect(markRead).toHaveBeenCalledTimes(1);
		expect(markRead).toHaveBeenCalledWith(10, 5);
		expect(store.conversations[0].lastReadSeq).toBe(5);
		expect(store.conversations[0].unreadCount).toBe(0); // caught up to changeSeq
	});

	it('applyEvent(read) syncs the conversation watermark monotonically for self-attributed frames', async () => {
		const store = new ChatStore();
		store.selfUserId = 7;
		store.conversations = [conv({ channelId: 10, lastReadSeq: 2, changeSeq: 10, unreadCount: 8 })];

		await store.applyEvent({ event: 'read', channelId: 10, messageId: null, seq: 5, userId: 7 });
		expect(store.conversations[0].lastReadSeq).toBe(5);

		// An out-of-order older ack never rewinds the watermark.
		await store.applyEvent({ event: 'read', channelId: 10, messageId: null, seq: 1, userId: 7 });
		expect(store.conversations[0].lastReadSeq).toBe(5);
	});

	it('applyEvent(read) treats an actor-less frame as non-self (never clears unread badges)', async () => {
		const store = new ChatStore();
		store.selfUserId = 7;
		store.conversations = [conv({ channelId: 10, lastReadSeq: 2, changeSeq: 10, unreadCount: 8 })];

		await store.applyEvent({ event: 'read', channelId: 10, messageId: null, seq: 5 });
		expect(store.conversations[0].lastReadSeq).toBe(2);
		expect(store.conversations[0].unreadCount).toBe(8);
	});

	it('setAtBottom(true) clears unseenBelow, and a background append while scrolled up increments it', async () => {
		sinceMessages.mockResolvedValue(replay([msg({ messageId: 2, seq: 2 })]));
		const store = new ChatStore();
		store.activeChannelId = 10;
		store.messagesByChannel[10] = [{ ...msg({ messageId: 1, seq: 1 }), status: 'sent' }];
		store.setAtBottom(false);

		await store.applyEvent({ event: 'message_created', channelId: 10, messageId: 2, seq: 2 });
		expect(store.unseenBelow).toBe(1);

		store.setAtBottom(true);
		expect(store.unseenBelow).toBe(0);
	});

	// Task 14 (MessageList): a typing signal is scoped to ITS channel — a
	// background channel's typer must never bleed into whichever channel's
	// MessageList happens to be open.
	it('typingUsers carries channelId so a signal from one channel never leaks into another', async () => {
		const store = new ChatStore();

		await store.applyEvent({ event: 'typing', channelId: 10, messageId: null, seq: null, userId: 7 });
		await store.applyEvent({ event: 'typing', channelId: 11, messageId: null, seq: null, userId: 8 });

		expect(store.typingUsers.filter((t) => t.channelId === 10).map((t) => t.userId)).toEqual([7]);
		expect(store.typingUsers.filter((t) => t.channelId === 11).map((t) => t.userId)).toEqual([8]);
	});

	it('the same userId typing in two different channels expires independently', async () => {
		vi.useFakeTimers();
		const store = new ChatStore();

		await store.applyEvent({ event: 'typing', channelId: 10, messageId: null, seq: null, userId: 7 });
		vi.advanceTimersByTime(2000);
		await store.applyEvent({ event: 'typing', channelId: 11, messageId: null, seq: null, userId: 7 });
		vi.advanceTimersByTime(2001); // 4001ms since channel 10's signal, 2001ms since channel 11's

		expect(store.typingUsers.filter((t) => t.channelId === 10)).toHaveLength(0);
		expect(store.typingUsers.filter((t) => t.channelId === 11)).toHaveLength(1);
	});

	// Task 14: prepend history page — reversed to ASC, spliced ahead of the
	// existing rows, idempotent on messageId.
	it('loadOlderMessages() prepends a reversed page ahead of existing rows', async () => {
		listMessages.mockResolvedValue([msg({ messageId: 2, seq: 2 }), msg({ messageId: 1, seq: 1 })]);
		const store = new ChatStore();
		store.messagesByChannel[10] = [{ ...msg({ messageId: 3, seq: 3 }), status: 'sent' }];

		const added = await store.loadOlderMessages(10, 3);

		expect(added).toBe(2);
		expect(listMessages).toHaveBeenCalledWith(10, { beforeSeq: 3, limit: 50 });
		expect(store.messagesByChannel[10].map((m) => m.seq)).toEqual([1, 2, 3]);
	});

	it('loadOlderMessages() returns 0 and leaves rows untouched when there is no older page', async () => {
		listMessages.mockResolvedValue([]);
		const store = new ChatStore();
		store.messagesByChannel[10] = [{ ...msg({ messageId: 3, seq: 3 }), status: 'sent' }];

		const added = await store.loadOlderMessages(10, 3);

		expect(added).toBe(0);
		expect(store.messagesByChannel[10]).toHaveLength(1);
	});

	it('loadOlderMessages() skips any messageId already present (idempotent re-fetch)', async () => {
		listMessages.mockResolvedValue([msg({ messageId: 3, seq: 3 }), msg({ messageId: 2, seq: 2 })]);
		const store = new ChatStore();
		store.messagesByChannel[10] = [{ ...msg({ messageId: 3, seq: 3 }), status: 'sent' }];

		const added = await store.loadOlderMessages(10, 4);

		expect(added).toBe(1);
		expect(store.messagesByChannel[10].map((m) => m.messageId)).toEqual([2, 3]);
	});

	// Task 15 (MessageRow): discard() removes a failed optimistic row outright —
	// the only way to make a permanently-failed send disappear (Retry re-attempts
	// in place; Discard gives up on it).
	it('discard() removes a failed row by clientId', async () => {
		sendMessage.mockRejectedValue(new Error('boom'));
		const store = new ChatStore();
		store.activeChannelId = 10;
		await expect(store.send('doomed')).rejects.toThrow();
		const clientId = store.messagesByChannel[10][0].clientId!;

		store.discard(clientId);

		expect(store.messagesByChannel[10]).toHaveLength(0);
	});

	// Task 15 (MessageRow reaction pills): the initiating client sees the flip
	// immediately, before the server round trip resolves.
	it('toggleReaction() flips the pill optimistically, before the API call resolves', async () => {
		let resolveApi!: (v: { present: boolean }) => void;
		toggleReaction.mockReturnValue(new Promise((r) => (resolveApi = r)));
		const store = new ChatStore();
		store.messagesByChannel[10] = [{ ...msg({ messageId: 5, reactions: [] }), status: 'sent' }];

		const p = store.toggleReaction(10, 5, '👍');
		expect(store.messagesByChannel[10][0].reactions).toEqual([{ emoji: '👍', count: 1, mine: true }]);
		resolveApi({ present: true });
		await p;
		expect(toggleReaction).toHaveBeenCalledWith(5, '👍');
	});

	it('toggleReaction() removes mine when already reacted, decrementing count (or dropping the pill at 0)', async () => {
		toggleReaction.mockResolvedValue({ present: false });
		const store = new ChatStore();
		store.messagesByChannel[10] = [
			{ ...msg({ messageId: 5, reactions: [{ emoji: '👍', count: 1, mine: true }] }), status: 'sent' },
		];

		await store.toggleReaction(10, 5, '👍');

		expect(store.messagesByChannel[10][0].reactions).toEqual([]);
	});

	it('toggleReaction() reverts the optimistic flip if the API call fails', async () => {
		toggleReaction.mockRejectedValue(new Error('network down'));
		const store = new ChatStore();
		store.messagesByChannel[10] = [{ ...msg({ messageId: 5, reactions: [] }), status: 'sent' }];

		await expect(store.toggleReaction(10, 5, '👍')).rejects.toThrow('network down');

		expect(store.messagesByChannel[10][0].reactions).toEqual([]);
	});

	it('editMessage() updates the row body/seq/editedAt in place on success', async () => {
		editMessage.mockResolvedValue({ seq: 9 });
		const store = new ChatStore();
		store.messagesByChannel[10] = [{ ...msg({ messageId: 5, seq: 5, body: 'v0' }), status: 'sent' }];

		await store.editMessage(10, 5, 'v1');

		expect(editMessage).toHaveBeenCalledWith(5, 'v1');
		expect(store.messagesByChannel[10][0].body).toBe('v1');
		expect(store.messagesByChannel[10][0].seq).toBe(9);
		expect(store.messagesByChannel[10][0].editedAt).not.toBeNull();
	});

	it('deleteMessage() blanks the body and sets deletedAt in place on success (body RETAINED server-side, C1)', async () => {
		deleteMessage.mockResolvedValue({ seq: 9 });
		const store = new ChatStore();
		store.messagesByChannel[10] = [{ ...msg({ messageId: 5, seq: 5, body: 'gone soon' }), status: 'sent' }];

		await store.deleteMessage(10, 5);

		expect(deleteMessage).toHaveBeenCalledWith(5);
		expect(store.messagesByChannel[10][0].body).toBe('');
		expect(store.messagesByChannel[10][0].deletedAt).not.toBeNull();
	});
});

// Chat A2 Task 7 — webmail attach pipeline: ensureSpace + hash/upload/ready,
// HEAD-skip dedup, cancel, and send() blocking/payload-shape/retry.
describe('ChatStore attachments', () => {
	beforeEach(() => {
		ensureSpace.mockReset();
		headChunk.mockReset();
		putChunk.mockReset();
		sendMessage.mockReset();
		ensureSpace.mockResolvedValue({ spaceId: 500 });
	});

	it('addAttachments hashes then uploads a new (HEAD-miss) chunk, flipping to ready', async () => {
		putChunk.mockResolvedValue(undefined);
		headChunk.mockResolvedValue(false); // not yet on the server
		const store = new ChatStore();

		const [task] = store.addAttachments(10, null, [file('report.pdf')]);
		expect(store.pendingAttachments['10:root']).toHaveLength(1);
		expect(store.pendingAttachments['10:root'][0].status).toBe('hashing');
		await task;

		const entry = store.pendingAttachments['10:root'][0];
		expect(entry.status).toBe('ready');
		expect(entry.sha256).toMatch(/^[0-9a-f]{64}$/);
		expect(ensureSpace).toHaveBeenCalledWith(10);
		expect(headChunk).toHaveBeenCalledWith(500, entry.sha256);
		expect(putChunk).toHaveBeenCalledTimes(1);
	});

	it('HEAD-skip dedup: an already-present chunk uploads zero bytes, showing instant-ready', async () => {
		headChunk.mockResolvedValue(true); // already on the server (re-shared file)
		const store = new ChatStore();

		const [task] = store.addAttachments(10, null, [file('shared.pdf')]);
		await task;

		expect(store.pendingAttachments['10:root'][0].status).toBe('ready');
		expect(putChunk).not.toHaveBeenCalled();
	});

	it('one ensureSpace() call is cached across multiple files attached to the same channel', async () => {
		headChunk.mockResolvedValue(true);
		const store = new ChatStore();

		await Promise.all(store.addAttachments(10, null, [file('a.txt', 'a'), file('b.txt', 'b')]));

		expect(ensureSpace).toHaveBeenCalledTimes(1);
	});

	it('a chunk-upload failure flips the chip to failed with a readable reason; removeAttachment drops it', async () => {
		headChunk.mockResolvedValue(false);
		putChunk.mockRejectedValue(new Error('network down'));
		const store = new ChatStore();

		const [task] = store.addAttachments(10, null, [file('doomed.pdf')]);
		await task;

		expect(store.pendingAttachments['10:root'][0].status).toBe('failed');
		expect(store.pendingAttachments['10:root'][0].error).toBeTruthy();

		store.removeAttachment(10, null, store.pendingAttachments['10:root'][0].clientId);
		expect(store.pendingAttachments['10:root']).toBeUndefined();
	});

	it('retryAttachment() re-attempts a failed chip in place under the same clientId', async () => {
		headChunk.mockResolvedValue(false);
		putChunk.mockRejectedValueOnce(new Error('boom')).mockResolvedValueOnce(undefined);
		const store = new ChatStore();
		const [task] = store.addAttachments(10, null, [file('retry-me.pdf')]);
		await task;
		const clientId = store.pendingAttachments['10:root'][0].clientId;
		expect(store.pendingAttachments['10:root'][0].status).toBe('failed');

		await store.retryAttachment(10, null, clientId);

		expect(store.pendingAttachments['10:root'][0].status).toBe('ready');
		expect(store.pendingAttachments['10:root'][0].clientId).toBe(clientId);
	});

	it('a transient ensureSpace() rejection does not poison the channel — retryAttachment succeeds once it recovers', async () => {
		headChunk.mockResolvedValue(false);
		putChunk.mockResolvedValue(undefined);
		ensureSpace.mockRejectedValueOnce(new Error('space provision down')).mockResolvedValueOnce({ spaceId: 500 });
		const store = new ChatStore();

		const [task] = store.addAttachments(10, null, [file('retry-me.pdf')]);
		await task;
		const clientId = store.pendingAttachments['10:root'][0].clientId;
		expect(store.pendingAttachments['10:root'][0].status).toBe('failed');

		await store.retryAttachment(10, null, clientId);

		expect(store.pendingAttachments['10:root'][0].status).toBe('ready');
		expect(ensureSpace).toHaveBeenCalledTimes(2);
	});

	it('removeAttachment cancels an in-flight multi-chunk upload (AbortSignal) — the 2nd chunk never uploads', async () => {
		headChunk.mockResolvedValue(false);
		let releaseFirstPut!: () => void;
		putChunk.mockImplementationOnce(() => new Promise<void>((resolve) => (releaseFirstPut = resolve)));
		putChunk.mockResolvedValueOnce(undefined); // the would-be 2nd (1 MiB remainder) chunk — must never be reached
		// 5 MiB -> splitManifest yields two chunks (4 MiB + 1 MiB remainder),
		// same math as upload.test.ts's own chunk-boundary assertions.
		const bigFile = new File([new Uint8Array(5 * 1024 * 1024)], 'big.bin', { type: 'application/octet-stream' });
		const store = new ChatStore();

		const [task] = store.addAttachments(10, null, [bigFile]);
		// Synchronize on the first PUT rather than wall-clock ticks. Coverage
		// instrumentation makes the real 5 MiB SHA-256 path exceed Vitest's
		// 1 s waitFor default on slower runners; this is not a product SLA.
		await vi.waitFor(() => expect(putChunk).toHaveBeenCalledTimes(1), { timeout: 4_000 });
		const clientId = store.pendingAttachments['10:root'][0].clientId;

		store.removeAttachment(10, null, clientId);
		releaseFirstPut();
		await task;

		// The per-chunk `signal.aborted` check stops the loop before chunk 2 —
		// not just removeAttachment's own array splice (which alone can't prove
		// the abort wiring, since the chip is gone either way once removed).
		expect(putChunk).toHaveBeenCalledTimes(1);
		// The chip is gone outright — cancel never resurrects it as 'failed'.
		expect(store.pendingAttachments['10:root']).toBeUndefined();
	});

	it("pendingAttachments keys the channel's root composer separately from a ThreadPane reply composer", () => {
		headChunk.mockResolvedValue(true);
		const store = new ChatStore();

		store.addAttachments(10, null, [file('root.txt')]);
		store.addAttachments(10, 77, [file('reply.txt')]);

		expect(store.pendingAttachments['10:root']).toHaveLength(1);
		expect(store.pendingAttachments['10:77']).toHaveLength(1);
	});

	it('send() blocks until a pending attachment is ready, then posts the wire payload shape', async () => {
		headChunk.mockResolvedValue(false);
		putChunk.mockResolvedValue(undefined);
		sendMessage.mockResolvedValue({ messageId: 42, seq: 1 });
		const store = new ChatStore();
		store.activeChannelId = 10;
		store.addAttachments(10, null, [file('brief.pdf', 'contents', 'application/pdf')]);
		// Not yet ready — send() must not resolve (or post) before the upload does.
		let sent = false;
		const p = store.send('see attached').then(() => {
			sent = true;
		});
		await Promise.resolve(); // let any spurious microtask settle
		expect(sent).toBe(false);
		await p;

		expect(sent).toBe(true);
		expect(sendMessage).toHaveBeenCalledTimes(1);
		const [, , , , , attachments] = sendMessage.mock.calls[0];
		expect(attachments).toHaveLength(1);
		expect(attachments[0]).toMatchObject({ name: 'brief.pdf', size: 8, contentType: 'application/pdf' });
		expect(attachments[0].sha256).toMatch(/^[0-9a-f]{64}$/);
		expect(attachments[0].manifest).toEqual([{ sha256: attachments[0].sha256, size: 8 }]);
		// The composer's pending list is cleared once consumed by send().
		expect(store.pendingAttachments['10:root']).toBeUndefined();
	});

	it('reset during a deferred upload prevents the old collector from resurrecting its chip or file', async () => {
		const space = deferred<{ spaceId: number }>();
		ensureSpace.mockReturnValue(space.promise);
		const store = new ChatStore();
		store.activeChannelId = 10;
		const [upload] = store.addAttachments(10, null, [file('old-session.pdf')]);
		const send = store.send('old session attachment');
		await Promise.resolve();
		expect(ensureSpace).toHaveBeenCalledWith(10);

		// reset aborts the upload and replaces pendingAttachments while both the
		// upload task and #collectReadyAttachments are suspended on old-session work.
		store.reset();
		space.resolve({ spaceId: 500 });
		await Promise.all([upload, send]);

		expect(store.pendingAttachments).toEqual({});
		expect(store.messagesByChannel).toEqual({});
		expect(sendMessage).not.toHaveBeenCalled();
		expect(headChunk).not.toHaveBeenCalled();
		expect(putChunk).not.toHaveBeenCalled();
	});

	it('text-only send() is completely unaffected by attachments and stays synchronous', async () => {
		sendMessage.mockResolvedValue({ messageId: 1, seq: 1 });
		const store = new ChatStore();
		store.activeChannelId = 10;

		const p = store.send('just text');
		// No pending attachments for this key -> the optimistic row is pushed
		// synchronously, same guarantee as the pre-existing text-only test.
		expect(store.messagesByChannel[10]).toHaveLength(1);
		expect(store.messagesByChannel[10][0].attachments).toEqual([]);
		await p;
		expect(ensureSpace).not.toHaveBeenCalled();
	});

	it('a failed attachment chip never blocks send() — text-only send proceeds without it', async () => {
		headChunk.mockResolvedValue(false);
		putChunk.mockRejectedValue(new Error('network down'));
		sendMessage.mockResolvedValue({ messageId: 7, seq: 1 });
		const store = new ChatStore();
		store.activeChannelId = 10;
		const [task] = store.addAttachments(10, null, [file('doomed.pdf')]);
		await task;
		expect(store.pendingAttachments['10:root'][0].status).toBe('failed');

		await store.send('sent without the doomed attachment');

		expect(sendMessage).toHaveBeenCalledTimes(1);
		const [, , , , , attachments] = sendMessage.mock.calls[0];
		expect(attachments).toEqual([]);
		// The failed chip is left behind as a removable/retryable chip, not swept.
		expect(store.pendingAttachments['10:root']).toHaveLength(1);
		expect(store.pendingAttachments['10:root'][0].status).toBe('failed');
	});

	it('a failed send() retains the resolved attachment payload on the row for retry() (no re-upload)', async () => {
		headChunk.mockResolvedValue(false);
		putChunk.mockResolvedValue(undefined);
		sendMessage.mockRejectedValueOnce(new Error('server exploded')).mockResolvedValueOnce({ messageId: 9, seq: 2 });
		const store = new ChatStore();
		store.activeChannelId = 10;
		const [task] = store.addAttachments(10, null, [file('important.pdf')]);
		await task;

		await expect(store.send('please attach')).rejects.toThrow('server exploded');
		expect(store.messagesByChannel[10][0].status).toBe('failed');
		const clientId = store.messagesByChannel[10][0].clientId!;

		await store.retry(clientId);

		expect(store.messagesByChannel[10][0].status).toBe('sent');
		expect(putChunk).toHaveBeenCalledTimes(1); // retry re-posts, it never re-uploads
		expect(sendMessage).toHaveBeenCalledTimes(2);
		const firstCallAttachments = sendMessage.mock.calls[0][5];
		const secondCallAttachments = sendMessage.mock.calls[1][5];
		expect(secondCallAttachments).toEqual(firstCallAttachments);
	});
});

// Chat A3 QoL Task 14 — store + api: openChannelAt, the new applyEvent arms
// (message_pinned/poll_voted/member_read), translate caching, and the
// scheduled-send store surface's non-optimistic contract.
describe('ChatStore A3 QoL', () => {
	beforeEach(() => {
		listMessages.mockReset();
		sinceMessages.mockReset();
		pollResults.mockReset();
		translateMessage.mockReset();
		scheduleMessage.mockReset();
		listScheduled.mockReset();
		cancelScheduled.mockReset();
	});

	// ── openChannelAt (jump-to-message substrate) ──────────────────────────

	it('openChannelAt() loads the aroundSeq window verbatim (already ascending, no reverse) and focuses the target row', async () => {
		listMessages.mockResolvedValue([msg({ messageId: 4, seq: 4 }), msg({ messageId: 5, seq: 5 }), msg({ messageId: 6, seq: 6 })]);
		const store = new ChatStore();

		await store.openChannelAt(10, 5);

		expect(listMessages).toHaveBeenCalledWith(10, { aroundSeq: 5 });
		expect(store.messagesByChannel[10].map((m) => m.seq)).toEqual([4, 5, 6]);
		expect(store.activeChannelId).toBe(10);
		expect(store.focusedMessageId).toBe(5);
	});

	it('openChannelAt() discards whatever was previously loaded for the channel (a jump can land far away)', async () => {
		listMessages.mockResolvedValue([msg({ messageId: 100, seq: 100 })]);
		const store = new ChatStore();
		store.messagesByChannel[10] = [{ ...msg({ messageId: 1, seq: 1 }), status: 'sent' }];

		await store.openChannelAt(10, 100);

		expect(store.messagesByChannel[10].map((m) => m.messageId)).toEqual([100]);
	});

	it('clearFocusedMessage() clears the jump-to-message highlight', async () => {
		listMessages.mockResolvedValue([msg({ messageId: 5, seq: 5 })]);
		const store = new ChatStore();
		await store.openChannelAt(10, 5);
		expect(store.focusedMessageId).toBe(5);

		store.clearFocusedMessage();

		expect(store.focusedMessageId).toBeNull();
	});

	// ── applyEvent: message_pinned ─────────────────────────────────────────

	it('applyEvent(message_pinned) reconciles via since(seq-1), same as message_edited (chat_message_to_json carries the fresh pinned flag)', async () => {
		sinceMessages.mockResolvedValue(replay([msg({ messageId: 5, seq: 6, pinned: true })]));
		const store = new ChatStore();
		store.messagesByChannel[10] = [{ ...msg({ messageId: 5, seq: 5, pinned: false }), status: 'sent' }];

		await store.applyEvent({ event: 'message_pinned', channelId: 10, messageId: 5, seq: 6 });

		expect(sinceMessages).toHaveBeenCalledWith(10, 5); // seq-1
		expect(store.messagesByChannel[10][0].pinned).toBe(true);
	});

	// ── applyEvent: poll_voted ──────────────────────────────────────────────

	it('applyEvent(poll_voted) refetches results for an ALREADY-cached poll in the ACTIVE channel', async () => {
		pollResults.mockResolvedValue({ pollId: 7, question: 'q', multi: false, closesAt: null, closed: false, options: [] });
		const store = new ChatStore();
		store.activeChannelId = 10;
		store.messagesByChannel[10] = [{ ...msg({ messageId: 50, seq: 5, payload: { pollId: 7 } }), status: 'sent' }];
		store.pollResultsByPollId[7] = { pollId: 7, question: 'q', multi: false, closesAt: null, closed: false, options: [] };

		await store.applyEvent({ event: 'poll_voted', channelId: 10, messageId: 50, seq: null });

		expect(pollResults).toHaveBeenCalledWith(7);
	});

	it('applyEvent(poll_voted) does NOT refetch when the poll is not currently cached/visible', async () => {
		const store = new ChatStore();
		store.activeChannelId = 10;
		store.messagesByChannel[10] = [{ ...msg({ messageId: 50, seq: 5, payload: { pollId: 7 } }), status: 'sent' }];
		// pollResultsByPollId is empty — nobody has rendered this poll yet.

		await store.applyEvent({ event: 'poll_voted', channelId: 10, messageId: 50, seq: null });

		expect(pollResults).not.toHaveBeenCalled();
	});

	it('applyEvent(poll_voted) does NOT refetch for a background (non-active) channel', async () => {
		const store = new ChatStore();
		store.activeChannelId = 99;
		store.messagesByChannel[10] = [{ ...msg({ messageId: 50, seq: 5, payload: { pollId: 7 } }), status: 'sent' }];
		store.pollResultsByPollId[7] = { pollId: 7, question: 'q', multi: false, closesAt: null, closed: false, options: [] };

		await store.applyEvent({ event: 'poll_voted', channelId: 10, messageId: 50, seq: null });

		expect(pollResults).not.toHaveBeenCalled();
	});

	it('loadPollResults() populates pollResultsByPollId', async () => {
		pollResults.mockResolvedValue({ pollId: 7, question: 'q', multi: true, closesAt: null, closed: false, options: [] });
		const store = new ChatStore();

		await store.loadPollResults(7);

		expect(store.pollResultsByPollId[7].multi).toBe(true);
	});

	// ── applyEvent: member_read (DM tick) ───────────────────────────────────

	it('applyEvent(member_read) sets the peer read-tick for a DM channel', async () => {
		const store = new ChatStore();

		await store.applyEvent({ event: 'member_read', channelId: 10, messageId: null, seq: 5, userId: 2 });

		expect(store.peerReadSeq[10]).toBe(5);
	});

	it('applyEvent(member_read) never rewinds the peer read-tick on a stale/out-of-order ack', async () => {
		const store = new ChatStore();
		store.peerReadSeq[10] = 5;

		await store.applyEvent({ event: 'member_read', channelId: 10, messageId: null, seq: 2, userId: 2 });

		expect(store.peerReadSeq[10]).toBe(5);
	});

	// ── translate caching ────────────────────────────────────────────────────

	it('translateMessage() caches per message+locale — a second call for the same pair is free', async () => {
		translateMessage.mockResolvedValue({ translated: 'hola' });
		const store = new ChatStore();

		const first = await store.translateMessage(5, 'es');
		const second = await store.translateMessage(5, 'es');

		expect(first).toBe('hola');
		expect(second).toBe('hola');
		expect(translateMessage).toHaveBeenCalledTimes(1);
	});

	it('translateMessage() keys the cache by locale too — a different target locale re-fetches', async () => {
		translateMessage.mockResolvedValueOnce({ translated: 'hola' }).mockResolvedValueOnce({ translated: 'bonjour' });
		const store = new ChatStore();

		await store.translateMessage(5, 'es');
		await store.translateMessage(5, 'fr');

		expect(translateMessage).toHaveBeenCalledTimes(2);
	});

	// ── scheduled-send store surface ─────────────────────────────────────────

	it('scheduleSend() never inserts an optimistic timeline row (the message only exists at fire time)', async () => {
		scheduleMessage.mockResolvedValue({ actionId: 'abc' });
		listScheduled.mockResolvedValue([]);
		const store = new ChatStore();
		store.activeChannelId = 10;

		await store.scheduleSend(10, 'later text', '2026-08-01T00:00:00Z');

		expect(store.messagesByChannel[10]).toBeUndefined();
		expect(scheduleMessage).toHaveBeenCalledWith(10, 'later text', {
			parentId: null,
			mentions: [],
			broadcast: null,
			fireAt: '2026-08-01T00:00:00Z',
		});
	});

	it('scheduleSend() reloads the scheduled queue afterward', async () => {
		scheduleMessage.mockResolvedValue({ actionId: 'abc' });
		listScheduled.mockResolvedValue([
			{ actionId: 'abc', channelId: 10, body: 'later text', fireAt: '2026-08-01T00:00:00Z', status: 'pending', failureCode: null, lastError: null },
		]);
		const store = new ChatStore();

		await store.scheduleSend(10, 'later text', '2026-08-01T00:00:00Z');

		expect(store.scheduled).toHaveLength(1);
		expect(store.scheduled[0].actionId).toBe('abc');
	});

	it('cancelScheduled() removes the row from the local queue after the API call', async () => {
		cancelScheduled.mockResolvedValue(undefined);
		const store = new ChatStore();
		store.scheduled = [
			{ actionId: 'abc', channelId: 10, body: 'x', fireAt: '2026-08-01T00:00:00Z', status: 'pending', failureCode: null, lastError: null },
		];

		await store.cancelScheduled('abc');

		expect(cancelScheduled).toHaveBeenCalledWith('abc');
		expect(store.scheduled).toHaveLength(0);
	});
});

// Chat A3 QoL Task 15 — the composer's voice-recording send path. Task 6
// widened chat_message_send/chat_message_to_json with msg_type/payload but
// left no store-level send path to reach it (only Task 9's poll wrapper did,
// through its own separate route) — sendVoice() + #doSend's now-widened
// chatApi.sendMessage call are the substrate this task needs to actually
// ship voice messages, mirroring send()'s own optimistic-row shape.
describe('ChatStore A3 QoL Task 15 — sendVoice', () => {
	beforeEach(() => {
		sendMessage.mockReset();
		headChunk.mockReset();
		putChunk.mockReset();
	});

	it('pushes an optimistic voice row (msgType/payload set, empty body) and reconciles on success', async () => {
		headChunk.mockResolvedValue(false);
		putChunk.mockResolvedValue(undefined);
		sendMessage.mockResolvedValue({ messageId: 55, seq: 3 });
		const store = new ChatStore();
		store.activeChannelId = 10;
		store.selfUserId = 99;
		const [uploadTask] = store.addAttachments(10, null, [file('clip.webm', 'aa', 'audio/webm')]);
		await uploadTask; // let the recorded clip finish uploading (ready) first

		await store.sendVoice(4200);

		const row = store.messagesByChannel[10][0];
		expect(row.status).toBe('sent');
		expect(row.msgType).toBe('voice');
		expect(row.body).toBe('');
		expect(row.payload).toEqual({ durationMs: 4200 });
		expect(store.messagesByChannel[10][0].messageId).toBe(55);
		expect(sendMessage).toHaveBeenCalledTimes(1);
		const call = sendMessage.mock.calls[0];
		expect(call[6]).toBe('voice'); // msgType
		expect(call[7]).toEqual({ durationMs: 4200 }); // payload
		expect(call[5]).toHaveLength(1); // the recorded attachment
	});

	it('a plain text send() never carries msgType/payload (still defaults server-side)', async () => {
		sendMessage.mockResolvedValue({ messageId: 1, seq: 1 });
		const store = new ChatStore();
		store.activeChannelId = 10;

		await store.send('just text');

		const call = sendMessage.mock.calls[0];
		expect(call[6]).toBeUndefined();
		expect(call[7]).toBeUndefined();
	});

	it('retry() on a failed voice row re-posts with the SAME msgType/payload', async () => {
		headChunk.mockResolvedValue(false);
		putChunk.mockResolvedValue(undefined);
		sendMessage.mockRejectedValueOnce(new Error('boom')).mockResolvedValueOnce({ messageId: 8, seq: 1 });
		const store = new ChatStore();
		store.activeChannelId = 10;
		store.addAttachments(10, null, [file('clip.webm', 'aa', 'audio/webm')]);
		await expect(store.sendVoice(1000)).rejects.toThrow('boom');
		const clientId = store.messagesByChannel[10][0].clientId!;

		await store.retry(clientId);

		expect(store.messagesByChannel[10][0].status).toBe('sent');
		const secondCall = sendMessage.mock.calls[1];
		expect(secondCall[6]).toBe('voice');
		expect(secondCall[7]).toEqual({ durationMs: 1000 });
	});

	it('no channel open -> sendVoice() is a no-op', async () => {
		const store = new ChatStore();
		store.activeChannelId = null;
		await store.sendVoice(1000);
		expect(sendMessage).not.toHaveBeenCalled();
	});
});

describe('ChatStore generation fences and no-op guards', () => {
	beforeEach(() => {
		listConversations.mockReset().mockResolvedValue({ conversations: [], attachmentsEnabled: true });
		listMessages.mockReset().mockResolvedValue([]);
		sinceMessages.mockReset().mockResolvedValue(replay([]));
		sendMessage.mockReset().mockResolvedValue({ messageId: 1, seq: 1 });
		editMessage.mockReset().mockResolvedValue({ seq: 2 });
		deleteMessage.mockReset().mockResolvedValue({ seq: 2 });
		toggleReaction.mockReset().mockResolvedValue(undefined);
		pollResults.mockReset().mockResolvedValue([]);
		translateMessage.mockReset().mockResolvedValue({ translated: 'hola' });
		scheduleMessage.mockReset().mockResolvedValue(undefined);
		listScheduled.mockReset().mockResolvedValue([]);
		cancelScheduled.mockReset().mockResolvedValue(undefined);
	});

	it('drops late conversation, normal-open, and jump-open results after reset', async () => {
		const convWait = deferred<{ conversations: Conversation[]; attachmentsEnabled: boolean }>();
		listConversations.mockReturnValueOnce(convWait.promise);
		const store = new ChatStore();
		const load = store.loadConversations();
		store.reset();
		convWait.resolve({ conversations: [conv()], attachmentsEnabled: false });
		await load;
		expect(store.conversations).toEqual([]);

		const pageWait = deferred<ChatMessage[]>();
		listMessages.mockReturnValueOnce(pageWait.promise);
		const open = store.openChannel(10);
		store.reset();
		pageWait.resolve([msg()]);
		await open;
		expect(store.messagesByChannel).toEqual({});

		const jumpWait = deferred<ChatMessage[]>();
		listMessages.mockReturnValueOnce(jumpWait.promise);
		const jump = store.openChannelAt(10, 9);
		store.reset();
		jumpWait.resolve([msg({ messageId: 9, seq: 9 })]);
		await jump;
		expect(store.focusedMessageId).toBeNull();
	});

	it('sets a null jump focus when the requested seq is outside the returned window', async () => {
		listMessages.mockResolvedValueOnce([msg({ messageId: 1, seq: 1 })]);
		const store = new ChatStore();
		await store.openChannelAt(10, 99);
		expect(store.focusedMessageId).toBeNull();
	});

	it('returns safely for missing attachment, retry, discard, and reaction targets', async () => {
		const store = new ChatStore();
		store.removeAttachment(10, null, 'missing');
		expect(store.retryAttachment(10, null, 'missing')).toBeUndefined();
		store.pendingAttachments['10:root'] = [{ clientId: 'ready', file: file('a'), status: 'ready', progress: 1, size: 1, name: 'a', contentType: 'text/plain' }] as never;
		expect(store.retryAttachment(10, null, 'absent')).toBeUndefined();
		expect(store.retryAttachment(10, null, 'ready')).toBeUndefined();
		await store.retry('missing');
		store.messagesByChannel[10] = [{ ...msg(), status: 'sent', clientId: 'sent' }];
		await store.retry('sent');
		store.discard('missing');
		await store.toggleReaction(11, 1, '👍');
		await store.toggleReaction(10, 999, '👍');
		expect(toggleReaction).not.toHaveBeenCalled();
	});

	it('keeps reaction state untouched by a failure from a reset identity', async () => {
		const wait = deferred<void>();
		toggleReaction.mockImplementationOnce(async () => { await wait.promise; throw new Error('old failure'); });
		const store = new ChatStore();
		store.messagesByChannel[10] = [{ ...msg({ reactions: [] }), status: 'sent' }];
		const pending = store.toggleReaction(10, 1, '👍');
		store.reset();
		wait.resolve(undefined);
		await expect(pending).rejects.toThrow('old failure');
		expect(store.messagesByChannel).toEqual({});
	});

	it('ignores successful edit/delete results after reset or when rows/messages vanished', async () => {
		const store = new ChatStore();
		await store.editMessage(10, 1, 'new');
		await store.deleteMessage(10, 1);
		store.messagesByChannel[10] = [{ ...msg({ messageId: 2 }), status: 'sent' }];
		await store.editMessage(10, 1, 'new');
		await store.deleteMessage(10, 1);

		const editWait = deferred<{ seq: number }>();
		editMessage.mockReturnValueOnce(editWait.promise);
		const pendingEdit = store.editMessage(10, 2, 'late');
		store.reset();
		editWait.resolve({ seq: 3 });
		await pendingEdit;
		expect(store.messagesByChannel).toEqual({});
	});

	it('orders replay inserts, accepts null-seq reconciliation, and swallows old-session failures', async () => {
		const store = new ChatStore();
		store.activeChannelId = 10;
		store.messagesByChannel[10] = [{ ...msg({ messageId: 3, seq: 3 }), status: 'sent' }];
		sinceMessages.mockResolvedValueOnce(replay([
			msg({ messageId: 2, seq: 2 }),
			msg({ messageId: 4, seq: 4 }),
		], 4));
		await store.applyEvent({ event: 'message_edited', channelId: 10, messageId: 2, seq: null } as never);
		expect(store.messagesByChannel[10].map((m) => m.seq)).toEqual([2, 3, 4]);

		const wait = deferred<never>();
		sinceMessages.mockReturnValueOnce(wait.promise);
		const backfill = store.backfillSince(10);
		store.reset();
		wait.resolve(Promise.reject(new Error('old')) as never);
		await expect(backfill).resolves.toBeUndefined();
	});

	it('drops older-page and socket-open continuations after reset', async () => {
		const pageWait = deferred<ChatMessage[]>();
		listMessages.mockReturnValueOnce(pageWait.promise);
		const store = new ChatStore();
		const older = store.loadOlderMessages(10, 5);
		store.reset();
		pageWait.resolve([msg()]);
		await expect(older).resolves.toBe(0);

		const replayWait = deferred<ChatReplay>();
		sinceMessages.mockReturnValueOnce(replayWait.promise);
		store.activeChannelId = 10;
		const reconnect = store.onSocketOpen();
		store.reset();
		replayWait.resolve(replay([]));
		await reconnect;
		expect(listConversations).not.toHaveBeenCalled();
	});

	it('defensively ignores invalid read and peer-read events', async () => {
		const store = new ChatStore();
		store.selfUserId = 7;
		store.conversations = [conv({ channelId: 10, lastReadSeq: 1, changeSeq: 5, unreadCount: 4 })];
		for (const event of [
			{ event: 'read', channelId: 10, seq: null, userId: 7 },
			{ event: 'read', channelId: 10, seq: 4, userId: 8 },
			{ event: 'read', channelId: 99, seq: 4, userId: 7 },
			{ event: 'read', channelId: 10, seq: 4 },
			{ event: 'member_read', channelId: 10, seq: null, userId: 8 },
			{ event: 'member_read', channelId: 10, seq: 4 },
			{ event: 'member_read', channelId: 10, seq: 4, userId: 7 },
			{ event: 'unknown', channelId: 10 },
		]) await store.applyEvent(event as never);
		expect(store.conversations[0].lastReadSeq).toBe(1);
		expect(store.peerReadSeq).toEqual({});
	});

	it('coalesces a burst to one in-flight refresh plus exactly one dirty-bit rerun', async () => {
		const first = deferred<{ conversations: Conversation[]; attachmentsEnabled: boolean }>();
		const trailing = deferred<{ conversations: Conversation[]; attachmentsEnabled: boolean }>();
		listConversations.mockReturnValueOnce(first.promise).mockReturnValueOnce(trailing.promise);
		const store = new ChatStore();
		const firstEvent = store.applyEvent({ event: 'member_added', channelId: 10, messageId: null, seq: null });
		const secondEvent = store.applyEvent({ event: 'federation_roster', channelId: 10, messageId: null, seq: null });
		const thirdEvent = store.applyEvent({ event: 'channel_updated', channelId: 10, messageId: null, seq: null });
		expect(listConversations).toHaveBeenCalledTimes(1);

		first.resolve({ conversations: [conv({ name: 'stale' })], attachmentsEnabled: true });
		await flushPromises();
		expect(listConversations).toHaveBeenCalledTimes(2);
		trailing.resolve({ conversations: [conv({ name: 'fresh' })], attachmentsEnabled: true });

		expect(await firstEvent).toEqual({ refreshFederationRosterChannelId: null });
		expect(await secondEvent).toEqual({ refreshFederationRosterChannelId: 10 });
		expect(await thirdEvent).toEqual({ refreshFederationRosterChannelId: null });
		expect(store.conversations[0].name).toBe('fresh');
		expect(listConversations).toHaveBeenCalledTimes(2);
	});

	it('bounds multiple invalidation bursts to one trailing rerun per in-flight attempt', async () => {
		const first = deferred<{ conversations: Conversation[]; attachmentsEnabled: boolean }>();
		const second = deferred<{ conversations: Conversation[]; attachmentsEnabled: boolean }>();
		const third = deferred<{ conversations: Conversation[]; attachmentsEnabled: boolean }>();
		listConversations
			.mockReturnValueOnce(first.promise)
			.mockReturnValueOnce(second.promise)
			.mockReturnValueOnce(third.promise);
		const store = new ChatStore();
		const events = [
			store.applyEvent({ event: 'member_added', channelId: 10, messageId: null, seq: null }),
			store.applyEvent({ event: 'member_removed', channelId: 10, messageId: null, seq: null }),
			store.applyEvent({ event: 'owner_changed', channelId: 10, messageId: null, seq: null }),
		];
		expect(listConversations).toHaveBeenCalledTimes(1);

		first.resolve({ conversations: [conv({ name: 'first' })], attachmentsEnabled: true });
		await flushPromises();
		expect(listConversations).toHaveBeenCalledTimes(2);
		events.push(
			store.applyEvent({ event: 'channel_updated', channelId: 10, messageId: null, seq: null }),
			store.applyEvent({ event: 'member_added', channelId: 11, messageId: null, seq: null }),
			store.applyEvent({ event: 'member_removed', channelId: 12, messageId: null, seq: null }),
		);
		expect(listConversations).toHaveBeenCalledTimes(2);

		second.resolve({ conversations: [conv({ name: 'second' })], attachmentsEnabled: true });
		await flushPromises();
		expect(listConversations).toHaveBeenCalledTimes(3);
		third.resolve({ conversations: [conv({ name: 'third' })], attachmentsEnabled: true });
		await Promise.all(events);
		expect(store.conversations[0].name).toBe('third');
		expect(listConversations).toHaveBeenCalledTimes(3);
	});

	it('runs the dirty-bit retry after a failed in-flight metadata refresh', async () => {
		const first = deferred<{ conversations: Conversation[]; attachmentsEnabled: boolean }>();
		listConversations
			.mockReturnValueOnce(first.promise)
			.mockResolvedValueOnce({ conversations: [conv({ name: 'recovered' })], attachmentsEnabled: false });
		const store = new ChatStore();
		store.conversations = [conv({ name: 'readable' })];

		const initial = store.applyEvent({ event: 'member_added', channelId: 10, messageId: null, seq: null });
		const dirty = store.applyEvent({ event: 'channel_updated', channelId: 10, messageId: null, seq: null });
		first.reject(new Error('offline'));
		await Promise.all([initial, dirty]);

		expect(listConversations).toHaveBeenCalledTimes(2);
		expect(store.conversations[0].name).toBe('recovered');
		expect(store.attachmentsEnabled).toBe(false);
	});

	it('reset drops an old auth generation and its dirty rerun without polluting the new session', async () => {
		const old = deferred<{ conversations: Conversation[]; attachmentsEnabled: boolean }>();
		listConversations
			.mockReturnValueOnce(old.promise)
			.mockResolvedValueOnce({ conversations: [conv({ channelId: 20, name: 'new-session' })], attachmentsEnabled: true });
		const store = new ChatStore();
		const oldInitial = store.applyEvent({ event: 'member_added', channelId: 10, messageId: null, seq: null });
		const oldDirty = store.applyEvent({ event: 'channel_updated', channelId: 10, messageId: null, seq: null });

		store.reset();
		await store.applyEvent({ event: 'member_added', channelId: 20, messageId: null, seq: null });
		expect(listConversations).toHaveBeenCalledTimes(2);
		expect(store.conversations.map((conversation) => conversation.channelId)).toEqual([20]);

		old.resolve({ conversations: [conv({ channelId: 10, name: 'old-session' })], attachmentsEnabled: false });
		await Promise.all([oldInitial, oldDirty]);
		expect(listConversations).toHaveBeenCalledTimes(2);
		expect(store.conversations.map((conversation) => conversation.channelId)).toEqual([20]);
		expect(store.attachmentsEnabled).toBe(true);
	});

	it('applies federation removal fail-closed immediately before an in-flight and trailing failed refresh', async () => {
		const wait = deferred<{ conversations: Conversation[]; attachmentsEnabled: boolean }>();
		listConversations.mockReturnValueOnce(wait.promise).mockRejectedValueOnce(new Error('still offline'));
		const store = new ChatStore();
		store.conversations = [conv({ federatedRoomRemoved: false })];
		const ordinary = store.applyEvent({ event: 'member_added', channelId: 10, messageId: null, seq: null });

		const removal = store.applyEvent({
			event: 'federation_removed', channelId: 10, messageId: null, seq: null
		});
		expect(store.conversations[0].federatedRoomRemoved).toBe(true);
		expect(listConversations).toHaveBeenCalledTimes(1);
		wait.reject(new Error('offline'));
		const [, outcome] = await Promise.all([ordinary, removal]);
		expect(listConversations).toHaveBeenCalledTimes(2);
		expect(store.conversations[0].federatedRoomRemoved).toBe(true);
		expect(outcome).toEqual({ refreshFederationRosterChannelId: 10 });
	});

	it('does not let an older conversation response reopen a revoked federation room', async () => {
		const stale = deferred<{ conversations: Conversation[]; attachmentsEnabled: boolean }>();
		listConversations
			.mockReturnValueOnce(stale.promise)
			.mockResolvedValueOnce({ conversations: [conv({ federatedRoomRemoved: false })], attachmentsEnabled: true });
		const store = new ChatStore();
		store.conversations = [conv({ federatedRoomRemoved: false })];
		const oldLoad = store.loadConversations();
		await store.applyEvent({ event: 'federation_removed', channelId: 10, messageId: null, seq: null });
		stale.resolve({ conversations: [conv({ federatedRoomRemoved: false })], attachmentsEnabled: true });
		await oldLoad;
		expect(store.conversations[0].federatedRoomRemoved).toBe(true);
	});

	it('does not publish poll, translation, or scheduled results from a reset session', async () => {
		const store = new ChatStore();
		const pollWait = deferred<never[]>();
		pollResults.mockReturnValueOnce(pollWait.promise);
		const poll = store.loadPollResults(1);
		store.reset();
		pollWait.resolve([]);
		await poll;
		expect(store.pollResultsByPollId).toEqual({});

		const transWait = deferred<{ translated: string }>();
		translateMessage.mockReturnValueOnce(transWait.promise);
		const translation = store.translateMessage(1, 'es');
		store.reset();
		transWait.resolve({ translated: 'hola' });
		expect(await translation).toBe('hola');
		expect(store.translationsByKey).toEqual({});

		const listWait = deferred<never[]>();
		listScheduled.mockReturnValueOnce(listWait.promise);
		const list = store.loadScheduled();
		store.reset();
		listWait.resolve([]);
		await list;
		expect(store.scheduled).toEqual([]);
	});

	it('does not mutate a new scheduled queue when an old schedule/cancel resolves', async () => {
		const scheduleWait = deferred<void>();
		scheduleMessage.mockReturnValueOnce(scheduleWait.promise);
		const store = new ChatStore();
		const schedule = store.scheduleSend(10, 'later', '2030-01-01T00:00:00Z');
		store.reset();
		scheduleWait.resolve(undefined);
		await schedule;
		expect(listScheduled).not.toHaveBeenCalled();

		store.scheduled = [{ actionId: 'a1' }] as never;
		const cancelWait = deferred<void>();
		cancelScheduled.mockReturnValueOnce(cancelWait.promise);
		const cancel = store.cancelScheduled('a1');
		store.reset();
		cancelWait.resolve(undefined);
		await cancel;
		expect(store.scheduled).toEqual([]);
	});
});

// A4a Task 13 — the webmail end-user minimum's pure helpers: BZ error copy
// (chatErrorMessage/chatErrorReason) and the two-different-labels retention
// notice (retentionNotice). Component-level rendering is covered by
// MessageRow.test.ts / ChatApp.test.ts / ChannelSettingsSheet.test.ts.
describe('chatErrorReason / chatErrorMessage', () => {
	it('BZ193 -> the WORM-specific chat copy, not the raw server detail', () => {
		expect(chatErrorReason('BZ193')).toBe("This channel keeps records — messages can't be edited or deleted");
		expect(chatErrorMessage(new ChatError({ status: 409, code: 'BZ193', detail: 'conflict' }))).toBe(
			"This channel keeps records — messages can't be edited or deleted",
		);
	});

	it('BZ196 -> the rate-limit copy (no {n} — Task 10 never wired retryAfterSeconds onto the wire body)', () => {
		expect(chatErrorReason('BZ196')).toBe("You're sending too fast — try again shortly");
	});

	// Pillar C2 Task 7 review (M1): a straggler send landing after the
	// mirror was kicked/scope-revoked used to fall back to the raw English
	// server detail (never localized) — same failed-row Retry path as BZ205.
	it('BZ213 -> the federated-room-removed copy, not the raw server detail', () => {
		expect(chatErrorReason('BZ213')).toBe('You were removed from this federated room — message not sent');
		expect(
			chatErrorMessage(
				new ChatError({ status: 403, code: 'BZ213', detail: 'this federated room was closed (kicked or revoked) — archive-read-only' }),
			),
		).toBe('You were removed from this federated room — message not sent');
	});

	it('an unmapped BZ code falls back to the ChatError\'s own detail', () => {
		expect(chatErrorReason('BZ161')).toBeUndefined();
		expect(chatErrorMessage(new ChatError({ status: 403, code: 'BZ161', detail: 'access denied' }))).toBe(
			'access denied',
		);
	});

	it('a non-ChatError throw (network/abort) falls back to the generic error string', () => {
		expect(chatErrorMessage(new Error('network down'))).toBe('An error occurred');
	});

	it('chatErrorReason(undefined) -> undefined (no errorCode stamped on the row)', () => {
		expect(chatErrorReason(undefined)).toBeUndefined();
	});
});

describe('retentionNotice', () => {
	it('null/undefined retentionDays -> no notice, regardless of classification', () => {
		expect(retentionNotice('regular', null)).toBeNull();
		expect(retentionNotice('gxp', undefined)).toBeNull();
	});

	it("a 'regular' channel gets the destroy-CEILING wording", () => {
		expect(retentionNotice('regular', 30)).toBe('Permanently delete messages older than 30 days');
	});

	it("a 'gxp' channel gets the WORM keep-FLOOR wording — the OPPOSITE meaning, never the ceiling copy", () => {
		expect(retentionNotice('gxp', 90)).toBe('Messages cannot be edited or deleted for 90 days');
	});

	it('undefined classification (a pre-A4a conversation payload) defaults to the regular/ceiling wording', () => {
		expect(retentionNotice(undefined, 14)).toBe('Permanently delete messages older than 14 days');
	});
});
