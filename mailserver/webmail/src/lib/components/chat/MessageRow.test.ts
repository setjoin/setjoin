import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import MessageRow, { sameGroup } from './MessageRow.svelte';
import { chatStore, type StoreMessage } from '$lib/chat/store.svelte';
import type { ChatAttachment, ChatMessage } from '$lib/chat/api';
import * as chatApi from '$lib/chat/api';
import { toasts, clearToasts } from '$lib/components/ui';
import { jmapSession } from '$lib/stores/session';

vi.mock('$lib/chat/api');

const resolveSlug = vi.fn();
vi.mock('$lib/meet/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/meet/api')>('$lib/meet/api');
	return { ...actual, resolveSlug: (...a: unknown[]) => resolveSlug(...a) };
});

const typedFetch = vi.fn();
vi.mock('$lib/http', async () => {
	const actual = await vi.importActual<typeof import('$lib/http')>('$lib/http');
	return { ...actual, typedFetch: (...a: unknown[]) => typedFetch(...a) };
});

const fetchVersionContent = vi.fn();
vi.mock('$lib/drive/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/drive/api')>('$lib/drive/api');
	return { ...actual, fetchVersionContent: (...a: unknown[]) => fetchVersionContent(...a) };
});

function attachment(over: Partial<ChatAttachment> = {}): ChatAttachment {
	return { id: 1, fileNodeId: 5, filename: 'pic.png', contentType: 'image/png', sizeBytes: 2048, ...over };
}

// $lib/chat/api is bare-automocked in this file (line above) — vitest keeps
// the ChatError prototype chain (so `instanceof` still works, which is all
// chatErrorMessage/chatErrorReason rely on) but does NOT run the real
// constructor body, so `code`/`detail` land undefined unless stamped back on
// afterward. Verified empirically before writing this helper.
function chatError(code: string, detail: string): chatApi.ChatError {
	return Object.assign(new chatApi.ChatError({ status: 409, code, detail }), { code, detail });
}

function msg(over: Partial<StoreMessage> = {}): StoreMessage {
	return {
		messageId: 1,
		channelId: 1,
		seq: 1,
		authorId: 99,
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
		authorExternal: false,
		authorRemoved: false,
		status: 'sent',
		...over,
	};
}

const baseProps = {
	channelId: 1,
	showHeader: true,
	focused: false,
	authorName: 'Alice',
	isMine: false,
	canModerate: false,
	onOpenThread: vi.fn(),
};

beforeEach(() => {
	chatStore.messagesByChannel = {};
	chatStore.conversations = [];
	chatStore.selfUserId = null;
	chatStore.peerReadSeq = {};
	chatStore.pollResultsByPollId = {};
	chatStore.translationsByKey = {};
	jmapSession.set(null);
});

afterEach(() => {
	vi.clearAllMocks();
});

const createObjectURL = vi.fn(() => 'blob:mock-url');
const revokeObjectURL = vi.fn();

beforeEach(() => {
	typedFetch.mockReset();
	fetchVersionContent.mockReset();
	createObjectURL.mockClear();
	revokeObjectURL.mockClear();
	URL.createObjectURL = createObjectURL as unknown as typeof URL.createObjectURL;
	URL.revokeObjectURL = revokeObjectURL;
});

describe('sameGroup (5-minute same-author grouping boundary)', () => {
	// literal 5 minutes, not the imported GROUP_WINDOW_MS — must stay independent
	// of the constant under test so a mutated window value fails these.
	const FIVE_MIN_MS = 5 * 60 * 1000;
	const base = { authorId: 1, createdAt: '2026-07-11T00:00:00Z' };

	it('same author within 5 min -> true', () => {
		const cur = { authorId: 1, createdAt: new Date(new Date(base.createdAt).getTime() + FIVE_MIN_MS - 1).toISOString() };
		expect(sameGroup(base, cur)).toBe(true);
	});

	it('same author at 5min+1ms -> false', () => {
		const cur = { authorId: 1, createdAt: new Date(new Date(base.createdAt).getTime() + FIVE_MIN_MS + 1).toISOString() };
		expect(sameGroup(base, cur)).toBe(false);
	});

	it('different author within window -> false', () => {
		const cur = { authorId: 2, createdAt: new Date(new Date(base.createdAt).getTime() + 1000).toISOString() };
		expect(sameGroup(base, cur)).toBe(false);
	});
});

describe('MessageRow', () => {
	it('shows author name + avatar when showHeader, hides them when grouped (showHeader=false)', () => {
		const { rerender } = render(MessageRow, { ...baseProps, message: msg(), showHeader: true });
		expect(screen.getByText('Alice')).toBeTruthy();

		vi.clearAllMocks();
		return rerender({ ...baseProps, message: msg(), showHeader: false }).then(() => {
			expect(screen.queryByText('Alice')).toBeNull();
		});
	});

	it('renders External from authorExternal without inferring from the author name', () => {
		const { rerender } = render(MessageRow, {
			...baseProps,
			authorName: 'Pat from Finance',
			message: msg({ authorExternal: true }),
		});
		expect(screen.getByText('External')).toBeTruthy();
		return rerender({
			...baseProps,
			authorName: 'external@example.com',
			message: msg({ authorExternal: false }),
		}).then(() => expect(screen.queryByText('External')).toBeNull());
	});

	it('keeps historical authorship and renders Removed from authorRemoved', () => {
		render(MessageRow, {
			...baseProps,
			authorName: 'Pat',
			message: msg({ authorExternal: true, authorRemoved: true }),
		});
		expect(screen.getByText('Pat')).toBeTruthy();
		expect(screen.getByText('External')).toBeTruthy();
		expect(screen.getByText('Removed')).toBeTruthy();
	});

	it('renders the body through renderChatMarkdown (bold survives as <strong>)', () => {
		const { container } = render(MessageRow, { ...baseProps, message: msg({ body: '**bold**' }) });
		expect(container.querySelector('strong')?.textContent).toBe('bold');
	});

	it('deleted messages show an italic placeholder, never the body', () => {
		render(MessageRow, { ...baseProps, message: msg({ deletedAt: '2026-07-11T00:05:00Z', body: 'gone' }) });
		expect(screen.getByText('Message deleted')).toBeTruthy();
		expect(screen.queryByText('gone')).toBeNull();
	});

	it('an edited (not deleted) message shows the "(edited)" suffix', () => {
		render(MessageRow, { ...baseProps, message: msg({ editedAt: '2026-07-11T00:05:00Z' }) });
		expect(screen.getByText('(edited)')).toBeTruthy();
	});

	it('reaction pills show emoji/count and highlight mine; clicking toggles via the store (whose own optimistic flip is pinned in store.svelte.test.ts)', async () => {
		chatStore.toggleReaction = vi.fn().mockResolvedValue(undefined);
		render(MessageRow, {
			...baseProps,
			channelId: 1,
			message: msg({ messageId: 1, reactions: [{ emoji: '👍', count: 2, mine: true }] }),
		});
		const pill = screen.getByRole('button', { name: /👍/ });
		expect(pill.textContent).toContain('2');
		expect(pill.className).toContain('mine');

		await fireEvent.click(pill);
		expect(chatStore.toggleReaction).toHaveBeenCalledWith(1, 1, '👍');
	});

	it('hover actions: reply is always offered; edit/delete (now in the ⋯ overflow menu) only for the author or a moderator', async () => {
		const { rerender } = render(MessageRow, { ...baseProps, message: msg(), isMine: false, canModerate: false });
		expect(screen.getByLabelText('Reply in thread')).toBeTruthy();
		await fireEvent.click(screen.getByLabelText('More actions'));
		expect(screen.queryByText('Edit')).toBeNull();
		expect(screen.queryByText('Delete')).toBeNull();

		// The overflow menu is already open (still true across the rerender —
		// same component instance) so this rerender alone reveals Edit/Delete;
		// clicking the trigger again would TOGGLE it back closed.
		await rerender({ ...baseProps, message: msg(), isMine: true, canModerate: false });
		expect(screen.getByText('Edit')).toBeTruthy();
		expect(screen.getByText('Delete')).toBeTruthy();
	});

	it('a non-author moderator (owner/admin) can still delete, but not edit, from the overflow menu', async () => {
		render(MessageRow, { ...baseProps, message: msg(), isMine: false, canModerate: true });
		await fireEvent.click(screen.getByLabelText('More actions'));
		expect(screen.queryByText('Edit')).toBeNull();
		expect(screen.getByText('Delete')).toBeTruthy();
	});

	it('reply chip opens the thread pane via onOpenThread (existing MessageList contract preserved)', async () => {
		const onOpenThread = vi.fn();
		render(MessageRow, { ...baseProps, message: msg({ messageId: 7, replyCount: 2 }), onOpenThread });
		await fireEvent.click(screen.getByText('2 replies'));
		expect(onOpenThread).toHaveBeenCalledWith(7);
	});

	it('a failed row renders red with Retry/Discard, wired to the store', async () => {
		chatStore.retry = vi.fn();
		chatStore.discard = vi.fn();
		const { container } = render(MessageRow, {
			...baseProps,
			isMine: true,
			message: msg({ status: 'failed', clientId: 'c1', body: 'oops' }),
		});
		expect(container.querySelector('.mrow--failed')).toBeTruthy();
		expect(container.querySelector('.mrow__failed-reason')).toBeNull();
		await fireEvent.click(screen.getByLabelText('Retry'));
		expect(chatStore.retry).toHaveBeenCalledWith('c1');
		await fireEvent.click(screen.getByLabelText('Discard'));
		expect(chatStore.discard).toHaveBeenCalledWith('c1');
	});

	// A4a Task 13: a rate-limited (BZ196) send used to become a failed row
	// with a bare Retry button and NO reason — the user just hammered Retry,
	// burning more of the same per-minute budget. #doSend (store.svelte.test.ts)
	// stamps errorCode; this proves the row actually renders it.
	it('a rate-limited failed send (errorCode BZ196) renders the reason next to Retry', () => {
		render(MessageRow, {
			...baseProps,
			isMine: true,
			message: msg({ status: 'failed', clientId: 'c2', body: 'go go go', errorCode: 'BZ196' }),
		});
		expect(screen.getByText("You're sending too fast — try again shortly")).toBeTruthy();
		expect(screen.getByLabelText('Retry')).toBeTruthy();
	});

	// A4a Task 13: MessageRow.saveEdit/doDelete used to await the store with
	// NO try/catch — a gxp channel's BZ193 left the edit box just sitting
	// there with no signal, and a rejected delete raised silently.
	describe('A4a Task 13 — BZ error copy on edit/delete', () => {
		afterEach(() => {
			clearToasts();
			// Bug fix (found while adding Pillar C2 Task 7 tests): the two `it`s
			// below reassign chatStore.editMessage/deleteMessage directly on the
			// shared chatStore SINGLETON (not a fresh instance per test) and
			// never restored them — every test running LATER in this same file
			// that calls the real chatStore.editMessage/deleteMessage silently
			// hit these leftover rejecting mocks instead, with zero signal (a
			// message never reaches chatApi.deleteMessage/editMessage at all).
			// Reflect.deleteProperty removes the own-property shadow so the
			// next lookup falls through to the real ChatStore.prototype method
			// again — `delete chatStore.editMessage` directly is a TS error
			// (the operand of `delete` must be optional; these are required
			// methods on the class).
			Reflect.deleteProperty(chatStore, 'editMessage');
			Reflect.deleteProperty(chatStore, 'deleteMessage');
		});

		it('an edit rejected with BZ193 keeps the edit box open and toasts the WORM-specific reason', async () => {
			chatStore.editMessage = vi.fn().mockRejectedValue(chatError('BZ193', 'conflict'));
			render(MessageRow, { ...baseProps, isMine: true, message: msg({ body: 'hello' }) });
			await fireEvent.click(screen.getByLabelText('More actions'));
			await fireEvent.click(screen.getByText('Edit'));
			expect(screen.getByText('Save')).toBeTruthy(); // now editing

			await fireEvent.click(screen.getByText('Save'));
			await waitFor(() => expect(chatStore.editMessage).toHaveBeenCalled());
			await waitFor(() =>
				expect(toasts.at(-1)?.message).toBe("This channel keeps records — messages can't be edited or deleted"),
			);
			expect(toasts.at(-1)?.variant).toBe('danger');
			// the edit box is STILL open — editing is only cleared on success.
			expect(screen.getByText('Save')).toBeTruthy();
			expect(screen.queryByText('Edit')).toBeNull();
		});

		it('a delete rejected with an unmapped code toasts the server detail verbatim', async () => {
			chatStore.deleteMessage = vi.fn().mockRejectedValue(chatError('BZ161', 'access denied'));
			render(MessageRow, { ...baseProps, isMine: true, message: msg() });
			await fireEvent.click(screen.getByLabelText('More actions'));
			await fireEvent.click(screen.getByText('Delete'));
			await waitFor(() => expect(chatStore.deleteMessage).toHaveBeenCalled());
			await waitFor(() => expect(toasts.at(-1)?.message).toBe('access denied'));
			expect(toasts.at(-1)?.variant).toBe('danger');
		});
	});

	it('a sending row is dimmed and offers no hover actions', () => {
		const { container } = render(MessageRow, {
			...baseProps,
			isMine: true,
			message: msg({ status: 'sending' }),
		});
		expect(container.querySelector('.mrow--sending')).toBeTruthy();
		expect(screen.queryByLabelText('Edit')).toBeNull();
		expect(screen.queryByLabelText('Delete')).toBeNull();
	});

	it('root element keeps data-testid + ml__row/--focused contract (MessageList Task 14 tests)', () => {
		const { container } = render(MessageRow, { ...baseProps, message: msg({ messageId: 3 }), focused: true });
		const root = container.querySelector('[data-testid="msg-3"]');
		expect(root).toBeTruthy();
		expect(root?.classList.contains('ml__row')).toBe(true);
		expect(root?.classList.contains('ml__row--focused')).toBe(true);
	});
});

describe('MessageRow — Task 16 locale-aware relative timestamps', () => {
	const NOW = new Date('2026-07-11T12:00:00Z').getTime();

	beforeEach(() => {
		vi.useFakeTimers();
		vi.setSystemTime(NOW);
	});

	afterEach(() => {
		vi.useRealTimers();
	});

	it('< 60s -> "just now"', () => {
		render(MessageRow, { ...baseProps, message: msg({ createdAt: new Date(NOW - 30_000).toISOString() }) });
		expect(screen.getByText('just now')).toBeTruthy();
	});

	it('< 60min -> locale-aware "N minutes ago" via Intl.RelativeTimeFormat', () => {
		render(MessageRow, { ...baseProps, message: msg({ createdAt: new Date(NOW - 2 * 60_000).toISOString() }) });
		expect(screen.getByText('2 minutes ago')).toBeTruthy();
	});

	it('< 24h -> locale-aware "N hours ago"', () => {
		render(MessageRow, { ...baseProps, message: msg({ createdAt: new Date(NOW - 3 * 3_600_000).toISOString() }) });
		expect(screen.getByText('3 hours ago')).toBeTruthy();
	});

	it('>= 24h falls back to a clock time, not a relative phrase', () => {
		const { container } = render(MessageRow, {
			...baseProps,
			message: msg({ createdAt: new Date(NOW - 2 * 86_400_000).toISOString() }),
		});
		const time = container.querySelector('.ml__time');
		expect(time?.textContent).not.toMatch(/ago/);
		expect(time?.textContent?.length).toBeGreaterThan(0);
	});
});

// The full voice/image/file attachment behavior (Chat A2 Task 8 + A3 QoL
// Task 15's voice player) now lives in MessageAttachments.test.ts
// (whole-pipeline review arch #9 — MessageRow's per-genre body renderers
// moved to their own components). This smoke test proves MessageRow still
// mounts MessageAttachments for a real attachment.
describe('MessageRow — attachments (wiring smoke test; see MessageAttachments.test.ts)', () => {
	it('an image attachment resolves and renders a thumbnail through the mounted MessageAttachments child', async () => {
		typedFetch.mockResolvedValue([{ nodeId: 5, headVersionId: 9, deletedAt: null }]);
		fetchVersionContent.mockResolvedValue({ blob: async () => new Blob(['x'], { type: 'image/png' }) });
		render(MessageRow, { ...baseProps, message: msg({ attachments: [attachment()] }) });
		await waitFor(() => expect(screen.getByAltText('pic.png')).toBeTruthy());
	});

	it('no attachments -> no attachment markup at all', () => {
		const { container } = render(MessageRow, { ...baseProps, message: msg({ attachments: [] }) });
		expect(container.querySelector('.mrow__attachments')).toBeNull();
	});
});

describe('MessageRow — A3 QoL Task 15: overflow menu (pin/save/translate)', () => {
	it('pin is offered to any member in a DM, but only a moderator in a channel (no BZ176 toast bait)', async () => {
		chatStore.conversations = [{ channelId: 1, kind: 'dm', name: null, topic: null, changeSeq: 1, lastReadSeq: 0, unreadCount: 0, hasMention: false, hasExternalMembers: false, lastMessagePreview: null, memberIds: [1, 2] }];
		render(MessageRow, { ...baseProps, message: msg(), isMine: false, canModerate: false });
		await fireEvent.click(screen.getByLabelText('More actions'));
		expect(screen.getByText('Pin message')).toBeTruthy();
	});

	it('a non-admin member sees no Pin action in a regular channel', async () => {
		chatStore.conversations = [{ channelId: 1, kind: 'channel', name: 'eng', topic: null, changeSeq: 1, lastReadSeq: 0, unreadCount: 0, hasMention: false, hasExternalMembers: false, lastMessagePreview: null, memberIds: [1, 2] }];
		render(MessageRow, { ...baseProps, message: msg(), isMine: false, canModerate: false });
		await fireEvent.click(screen.getByLabelText('More actions'));
		expect(screen.queryByText('Pin message')).toBeNull();
	});

	it('a channel admin sees Pin, and toggling it flips message.pinned optimistically via chatApi.togglePin', async () => {
		chatStore.conversations = [{ channelId: 1, kind: 'channel', name: 'eng', topic: null, changeSeq: 1, lastReadSeq: 0, unreadCount: 0, hasMention: false, hasExternalMembers: false, lastMessagePreview: null, memberIds: [1, 2] }];
		chatStore.messagesByChannel = { 1: [msg({ messageId: 5, pinned: false }) as StoreMessage] };
		vi.mocked(chatApi.togglePin).mockResolvedValue({ pinned: true });
		render(MessageRow, { ...baseProps, message: msg({ messageId: 5, pinned: false }), isMine: false, canModerate: true });
		await fireEvent.click(screen.getByLabelText('More actions'));
		await fireEvent.click(screen.getByText('Pin message'));
		expect(chatApi.togglePin).toHaveBeenCalledWith(5);
		await waitFor(() => expect(chatStore.messagesByChannel[1][0].pinned).toBe(true));
	});

	// [UX #7/#14, whole-pipeline review] pin/translate/vote/closePoll used to
	// fail silently (or, for pin, re-throw into an unhandled onclick rejection).
	describe('UX #7/#14 — pin/translate/vote/closePoll toast on failure', () => {
		afterEach(() => {
			clearToasts();
		});

		it('a rejected togglePin toasts and reverts the optimistic pinned flip (no unhandled rejection)', async () => {
			chatStore.conversations = [{ channelId: 1, kind: 'channel', name: 'eng', topic: null, changeSeq: 1, lastReadSeq: 0, unreadCount: 0, hasMention: false, hasExternalMembers: false, lastMessagePreview: null, memberIds: [1, 2] }];
			chatStore.messagesByChannel = { 1: [msg({ messageId: 5, pinned: false }) as StoreMessage] };
			vi.mocked(chatApi.togglePin).mockRejectedValue(chatError('BZ161', 'access denied'));
			render(MessageRow, { ...baseProps, message: msg({ messageId: 5, pinned: false }), isMine: false, canModerate: true });
			await fireEvent.click(screen.getByLabelText('More actions'));
			await fireEvent.click(screen.getByText('Pin message'));
			await waitFor(() => expect(toasts.at(-1)?.message).toBe('access denied'));
			expect(toasts.at(-1)?.variant).toBe('danger');
			expect(chatStore.messagesByChannel[1][0].pinned).toBe(false);
		});

		it('a rejected translate toasts instead of silently leaving the body unchanged', async () => {
			jmapSession.set({ effectiveCapabilities: { features: { assist: true } } } as never);
			vi.mocked(chatApi.translateMessage).mockRejectedValue(chatError('BZ163', 'not a member'));
			render(MessageRow, { ...baseProps, message: msg({ messageId: 9, body: 'hello' }), isMine: false });
			await fireEvent.click(screen.getByLabelText('More actions'));
			await fireEvent.click(screen.getByText('Translate'));
			await waitFor(() => expect(toasts.at(-1)?.message).toBe('not a member'));
			expect(toasts.at(-1)?.variant).toBe('danger');
		});
	});

	it('save is offered to every member and calls chatApi.toggleSave, flipping the label', async () => {
		vi.mocked(chatApi.toggleSave).mockResolvedValue({ saved: true });
		render(MessageRow, { ...baseProps, message: msg({ messageId: 3 }), isMine: false, canModerate: false });
		await fireEvent.click(screen.getByLabelText('More actions'));
		expect(screen.getByText('Save message')).toBeTruthy();
		await fireEvent.click(screen.getByText('Save message'));
		expect(chatApi.toggleSave).toHaveBeenCalledWith(3);
		await fireEvent.click(screen.getByLabelText('More actions'));
		expect(screen.getByText('Remove from saved')).toBeTruthy();
	});

	it('translate is absent when feature.assist is off', async () => {
		render(MessageRow, { ...baseProps, message: msg({ messageId: 9, body: 'hello' }), isMine: false });
		await fireEvent.click(screen.getByLabelText('More actions'));
		expect(screen.queryByText('Translate')).toBeNull();
	});

	it('with feature.assist on, Translate renders the translation inline with a Show original toggle (never replacing the body)', async () => {
		jmapSession.set({ effectiveCapabilities: { features: { assist: true } } } as never);
		vi.mocked(chatApi.translateMessage).mockResolvedValue({ translated: 'bonjour' });
		render(MessageRow, { ...baseProps, message: msg({ messageId: 9, body: 'hello' }), isMine: false });
		await fireEvent.click(screen.getByLabelText('More actions'));
		await fireEvent.click(screen.getByText('Translate'));
		await waitFor(() => expect(screen.getByText('bonjour')).toBeTruthy());
		expect(screen.getByText('hello')).toBeTruthy(); // original still shown, never replaced
		await fireEvent.click(screen.getByText('Show original'));
		expect(screen.queryByText('bonjour')).toBeNull();
	});

	it('an already-deleted message offers no overflow menu at all', () => {
		render(MessageRow, { ...baseProps, message: msg({ deletedAt: '2026-07-11T00:00:00Z' }), isMine: true, canModerate: true });
		expect(screen.queryByLabelText('More actions')).toBeNull();
	});

	it('the overflow menu is keyboard-operable (Escape closes it, focus returns to the trigger)', async () => {
		render(MessageRow, { ...baseProps, message: msg({ messageId: 4 }), isMine: true });
		const trigger = screen.getByLabelText('More actions');
		await fireEvent.click(trigger);
		expect(screen.getByRole('menu')).toBeTruthy();
		await fireEvent.keyDown(document, { key: 'Escape' });
		expect(screen.queryByRole('menu')).toBeNull();
	});
});

describe('MessageRow — A3 QoL Task 15: read receipts (DES-010)', () => {
	it('a DM tick shows "Read" on my own latest message once the peer watermark has passed its seq', () => {
		chatStore.selfUserId = 1;
		chatStore.conversations = [{ channelId: 1, kind: 'dm', name: null, topic: null, changeSeq: 5, lastReadSeq: 0, unreadCount: 0, hasMention: false, hasExternalMembers: false, lastMessagePreview: null, memberIds: [1, 2] }];
		const m = msg({ messageId: 8, authorId: 1, seq: 5 });
		chatStore.messagesByChannel = { 1: [m as StoreMessage] };
		chatStore.peerReadSeq = { 1: 5 };
		render(MessageRow, { ...baseProps, message: m, isMine: true });
		expect(screen.getByText('Read')).toBeTruthy();
	});

	it('no DM tick before the peer has read that far', () => {
		chatStore.selfUserId = 1;
		chatStore.conversations = [{ channelId: 1, kind: 'dm', name: null, topic: null, changeSeq: 5, lastReadSeq: 0, unreadCount: 0, hasMention: false, hasExternalMembers: false, lastMessagePreview: null, memberIds: [1, 2] }];
		const m = msg({ messageId: 8, authorId: 1, seq: 5 });
		chatStore.messagesByChannel = { 1: [m as StoreMessage] };
		chatStore.peerReadSeq = { 1: 2 };
		render(MessageRow, { ...baseProps, message: m, isMine: true });
		expect(screen.queryByText('Read')).toBeNull();
	});

	it('a channel caption shows "Read by N" on my own latest message, fetched via chatApi.getChannelReaders', async () => {
		chatStore.selfUserId = 1;
		chatStore.conversations = [{ channelId: 1, kind: 'channel', name: 'eng', topic: null, changeSeq: 5, lastReadSeq: 0, unreadCount: 0, hasMention: false, hasExternalMembers: false, lastMessagePreview: null, memberIds: [1, 2, 3] }];
		const m = msg({ messageId: 8, authorId: 1, seq: 5 });
		chatStore.messagesByChannel = { 1: [m as StoreMessage] };
		vi.mocked(chatApi.getChannelReaders).mockResolvedValue([
			{ userId: 1, lastReadSeq: 5 },
			{ userId: 2, lastReadSeq: 5 },
			{ userId: 3, lastReadSeq: 1 },
		]);
		render(MessageRow, { ...baseProps, message: m, isMine: true });
		await waitFor(() => expect(chatApi.getChannelReaders).toHaveBeenCalledWith(1));
		await waitFor(() => expect(screen.getByText('Read by 1')).toBeTruthy()); // self excluded, only user 2 caught up
	});

	it('no read-receipt UI on a message that is not my own latest', () => {
		chatStore.selfUserId = 1;
		chatStore.conversations = [{ channelId: 1, kind: 'dm', name: null, topic: null, changeSeq: 5, lastReadSeq: 0, unreadCount: 0, hasMention: false, hasExternalMembers: false, lastMessagePreview: null, memberIds: [1, 2] }];
		const older = msg({ messageId: 7, authorId: 1, seq: 4 });
		const newer = msg({ messageId: 8, authorId: 1, seq: 5 });
		chatStore.messagesByChannel = { 1: [older as StoreMessage, newer as StoreMessage] };
		chatStore.peerReadSeq = { 1: 5 };
		render(MessageRow, { ...baseProps, message: older, isMine: true });
		expect(screen.queryByText('Read')).toBeNull();
	});
});

// The full voice-player behavior now lives in MessageAttachments.test.ts —
// this smoke test proves MessageRow still mounts it for a voice message.
describe('MessageRow — voice messages (wiring smoke test; see MessageAttachments.test.ts)', () => {
	it('a ready voice attachment renders a native <audio> player through the mounted MessageAttachments child', async () => {
		typedFetch.mockResolvedValue([{ nodeId: 5, headVersionId: 9, deletedAt: null }]);
		const voiceMsg = msg({
			messageId: 20,
			msgType: 'voice',
			body: '',
			payload: { durationMs: 4200 },
			attachments: [{ id: 1, fileNodeId: 5, filename: 'clip.webm', contentType: 'audio/webm', sizeBytes: 900 }],
		}) as StoreMessage;
		render(MessageRow, { ...baseProps, message: voiceMsg });
		await waitFor(() => expect(screen.getByTestId('voice-player')).toBeTruthy());
	});
});

// The full poll render/vote/close behavior now lives in
// MessageBodyPoll.test.ts — this smoke test proves MessageRow still mounts
// it for a poll message.
describe('MessageRow — polls (wiring smoke test; see MessageBodyPoll.test.ts)', () => {
	it('renders the poll question as an accessible radiogroup through the mounted MessageBodyPoll child', async () => {
		vi.mocked(chatApi.pollResults).mockResolvedValue({
			pollId: 77,
			question: 'Pick one',
			multi: false,
			closesAt: null,
			closed: false,
			options: [{ optionId: 1, ordinal: 0, label: 'Tea', count: 0, voters: [] }],
		});
		const pollMsg = msg({ messageId: 30, msgType: 'poll', body: 'Pick one', payload: { pollId: 77 } }) as StoreMessage;
		render(MessageRow, { ...baseProps, message: pollMsg });
		await waitFor(() => expect(screen.getByRole('radiogroup')).toBeTruthy());
	});
});

// The full call-card behavior (Join/BZ190-ended/feature.meet-off) now lives
// in MessageBodyCall.test.ts — MessageRow.test.ts keeps only the
// dispatch-chain-specific behavior (soft-delete blanking, which happens in
// MessageRow's own isDeleted branch, before the call genre is ever reached)
// plus one smoke test proving the row still mounts MessageBodyCall.
describe('MessageRow — Meet B1 Task 16: the `call` msg_type arm', () => {
	function callMsg(over: Partial<ChatMessage> = {}): StoreMessage {
		return msg({
			messageId: 40,
			msgType: 'call',
			body: 'Standup',
			payload: { meetingId: 9, slug: 'abc123', title: 'Standup' },
			...over,
		}) as StoreMessage;
	}

	afterEach(() => vi.clearAllMocks());

	it('renders the meeting title through the mounted MessageBodyCall child (wiring smoke test)', async () => {
		resolveSlug.mockResolvedValue({ meetingId: 9, state: 'live' });
		render(MessageRow, { ...baseProps, message: callMsg() });
		expect(screen.getByText('Standup')).toBeTruthy();
		expect(screen.getByTestId('call-card')).toBeTruthy();
	});

	it('a soft-deleted call message blanks like every other payload type', () => {
		render(MessageRow, { ...baseProps, message: callMsg({ deletedAt: '2026-07-12T00:00:00Z' }) });
		expect(screen.queryByText('Standup')).toBeNull();
		expect(screen.getByText('Message deleted')).toBeTruthy();
	});
});

// UX #15 (whole-pipeline review): a msg_type='question' row (B3 Task 3's
// widening — Q&A rides ordinary chat messages) had no identity outside
// MeetChatPanel's own Q&A tab; it rendered as bare text everywhere else
// (the meet Chat tab, and the standalone chat app browsing a meeting's
// bound channel post-meeting). Additive chip, the voice/call precedent.
describe('MessageRow — question msg_type chip (whole-pipeline review UX #15)', () => {
	function questionMsg(over: Partial<ChatMessage> = {}): StoreMessage {
		return msg({
			messageId: 41,
			msgType: 'question',
			body: 'What time is the deploy?',
			...over,
		}) as StoreMessage;
	}

	it('renders a "Question" chip alongside the ordinary body text', () => {
		render(MessageRow, { ...baseProps, message: questionMsg() });
		expect(screen.getByTestId('question-chip')).toBeTruthy();
		expect(screen.getByText('Question')).toBeTruthy();
		// the body still renders normally — the chip is additive, not a replacement.
		expect(screen.getByText('What time is the deploy?')).toBeTruthy();
	});

	it('an ordinary text message renders no question chip', () => {
		render(MessageRow, { ...baseProps, message: msg({ body: 'not a question' }) });
		expect(screen.queryByTestId('question-chip')).toBeNull();
	});

	it('a soft-deleted question message blanks like every other payload type — no chip', () => {
		render(MessageRow, { ...baseProps, message: questionMsg({ deletedAt: '2026-07-12T00:00:00Z' }) });
		expect(screen.queryByTestId('question-chip')).toBeNull();
		expect(screen.getByText('Message deleted')).toBeTruthy();
	});
});

describe('MessageRow — A3 QoL Task 15: link unfurl card', () => {
	// med-chat-unfurl-href-001 r2 — the marker chat_message_unfurl_apply stamps
	// onto every reducer-written preview (chat_unfurl.sql); the render gate
	// below requires it.
	const UNFURL_APPLY_MARKER = 'chat_message_unfurl_apply';
	function unfurlMsg(over: Partial<ChatMessage> = {}): StoreMessage {
		return msg({
			messageId: 40,
			body: 'check this out https://example.com',
			payload: { preview: { url: 'https://example.com', title: 'Example', description: 'An example site', imageSha256: 'ff00'.repeat(16), appliedBy: UNFURL_APPLY_MARKER } },
			...over,
		}) as StoreMessage;
	}

	it('renders a fixed-height card with title/description/thumbnail', () => {
		vi.mocked(chatApi.unfurlImageUrl).mockImplementation((sha) => `/api/chat/unfurl/image/${sha}`);
		const { container } = render(MessageRow, { ...baseProps, message: unfurlMsg() });
		expect(screen.getByText('Example')).toBeTruthy();
		expect(screen.getByText('An example site')).toBeTruthy();
		const card = container.querySelector('.mrow__unfurl') as HTMLElement;
		expect(card).toBeTruthy();
		expect(getComputedStyle(card).minHeight).toBe('88px');
		const img = container.querySelector('.mrow__unfurl-thumb img') as HTMLImageElement;
		expect(img.src).toContain('/api/chat/unfurl/image/');
	});

	it('a preview with no image renders no thumbnail box', () => {
		const { container } = render(MessageRow, {
			...baseProps,
			message: unfurlMsg({ payload: { preview: { url: 'https://example.com', title: 'Example', description: null, imageSha256: null, appliedBy: UNFURL_APPLY_MARKER } } }),
		});
		expect(container.querySelector('.mrow__unfurl-thumb')).toBeNull();
	});

	it('the collapse chevron toggles the card body without removing the card itself', async () => {
		render(MessageRow, { ...baseProps, message: unfurlMsg() });
		expect(screen.getByText('Example')).toBeTruthy();
		await fireEvent.click(screen.getByLabelText('Collapse preview'));
		expect(screen.queryByText('Example')).toBeNull();
		await fireEvent.click(screen.getByLabelText('Expand preview'));
		expect(screen.getByText('Example')).toBeTruthy();
	});

	it('no preview payload -> no unfurl card at all', () => {
		const { container } = render(MessageRow, { ...baseProps, message: msg({ messageId: 41 }) });
		expect(container.querySelector('.mrow__unfurl')).toBeNull();
	});

	// med-chat-unfurl-href-001 — render-time re-validation (supporting check
	// behind the reducer's send-time preview strip + apply-time http(s)
	// allowlist): a payload.preview whose url is not an absolute http(s) URL
	// renders NO card at all — no anchor, and no attacker-authored
	// title/description in trusted enrichment chrome either (the whole block
	// gates on the URL, not just the href). These rows carry the reducer's
	// marker so the scheme checks below are exercised on their own.
	describe('unfurl url scheme re-validation', () => {
		const cases: Array<[string, unknown]> = [
			['javascript:', 'javascript:alert(1)'],
			['data:', 'data:text/html,<script>alert(1)</script>'],
			['vbscript:', 'vbscript:msgbox(1)'],
			['relative', '/relative/path'],
			['scheme-less', 'example.com/phish'],
			['non-string url', 12345],
		];

		for (const [label, url] of cases) {
			it(`a ${label} preview url renders no card and no anchor`, () => {
				const { container } = render(MessageRow, {
					...baseProps,
					message: unfurlMsg({ payload: { preview: { url, title: 'Forged', description: 'Forged', imageSha256: null, appliedBy: UNFURL_APPLY_MARKER } } }),
				});
				expect(container.querySelector('.mrow__unfurl')).toBeNull();
				expect(container.querySelector('a.mrow__unfurl-body')).toBeNull();
				expect(screen.queryByText('Forged')).toBeNull();
			});
		}

		it('a malformed url (unparseable) renders no card', () => {
			const { container } = render(MessageRow, {
				...baseProps,
				message: unfurlMsg({ payload: { preview: { url: 'ht!tp://bad', title: 'Forged', description: null, imageSha256: null, appliedBy: UNFURL_APPLY_MARKER } } }),
			});
			expect(container.querySelector('.mrow__unfurl')).toBeNull();
		});

		it('a valid https preview still renders its anchor with the exact href (valid previews unchanged)', () => {
			vi.mocked(chatApi.unfurlImageUrl).mockImplementation((sha) => `/api/chat/unfurl/image/${sha}`);
			const { container } = render(MessageRow, { ...baseProps, message: unfurlMsg() });
			const anchor = container.querySelector('a.mrow__unfurl-body') as HTMLAnchorElement;
			expect(anchor).toBeTruthy();
			expect(anchor.href).toBe('https://example.com/');
			expect(anchor.rel).toContain('noopener');
		});
	});

	// med-chat-unfurl-href-001 r2 — provenance epoch marker gate. The scheme
	// check alone admits an already-stored FORGED HTTPS card: send-time
	// stripping protects new messages but cannot establish legacy provenance.
	// Only a preview carrying chat_message_unfurl_apply's 'appliedBy' marker
	// renders; every pre-marker row — forged AND genuine legacy reducer output
	// alike — fails closed to no card.
	describe('unfurl provenance marker gate (legacy/forged previews fail closed)', () => {
		it('an already-stored forged HTTPS preview with no provenance marker renders no card and no anchor', () => {
			const { container } = render(MessageRow, {
				...baseProps,
				message: unfurlMsg({
					payload: { preview: { url: 'https://evil.example/phish', title: 'Forged title', description: 'Forged description', imageSha256: null } },
				}),
			});
			expect(container.querySelector('.mrow__unfurl')).toBeNull();
			expect(container.querySelector('a.mrow__unfurl-body')).toBeNull();
			expect(screen.queryByText('Forged title')).toBeNull();
			expect(screen.queryByText('Forged description')).toBeNull();
			expect(screen.queryByText('https://evil.example/phish')).toBeNull();
		});

		it('a preview carrying a wrong appliedBy value renders no card', () => {
			const { container } = render(MessageRow, {
				...baseProps,
				message: unfurlMsg({
					payload: { preview: { url: 'https://example.com', title: 'Example', description: null, imageSha256: null, appliedBy: 'sender' } },
				}),
			});
			expect(container.querySelector('.mrow__unfurl')).toBeNull();
		});

		// med-chat-unfurl-href-001 r4 — the HONEST RESIDUAL, pinned explicitly
		// per Astra's "explicitly retain as unresolved" arm. The appliedBy marker
		// is a PUBLIC constant, so a row written AFTER V252 carrying a FORGED
		// marker is client-side indistinguishable from a reducer-written one and
		// renders (below). V252 itself emptied the ENTIRE at-migration population
		// server-side — every preview stripped regardless of marker, because the
		// marker's only writer (chat_message_unfurl_apply) is installed by that
		// same delta and migrations run before the new code serves traffic, so an
		// at-migration marker proves nothing — and post-migration no reducer path
		// writes payload.preview except chat_message_unfurl_apply. A forged-marker
		// row therefore requires a future reducer hole or direct DB access;
		// closing even that case needs sender/worker signing (owner decision).
		// This test documents that the client cannot, and does not claim to,
		// provide it.
		it('RESIDUAL: a forged HTTPS preview carrying the public marker still renders — indistinguishable from reducer output without sender signing', () => {
			vi.mocked(chatApi.unfurlImageUrl).mockImplementation((sha) => `/api/chat/unfurl/image/${sha}`);
			const { container } = render(MessageRow, {
				...baseProps,
				message: unfurlMsg({
					payload: { preview: { url: 'https://evil.example/phish', title: 'Forged title', description: 'Forged description', imageSha256: null, appliedBy: UNFURL_APPLY_MARKER } },
				}),
			});
			const anchor = container.querySelector('a.mrow__unfurl-body') as HTMLAnchorElement;
			expect(anchor).toBeTruthy();
			expect(anchor.href).toBe('https://evil.example/phish');
			expect(screen.getByText('Forged title')).toBeTruthy();
			expect(screen.getByText('Forged description')).toBeTruthy();
		});

		it('a non-object preview payload (arbitrary stored shape) renders no card', () => {
			const { container } = render(MessageRow, {
				...baseProps,
				message: unfurlMsg({ payload: { preview: 'https://evil.example/phish' } }),
			});
			expect(container.querySelector('.mrow__unfurl')).toBeNull();
			expect(container.querySelector('a.mrow__unfurl-body')).toBeNull();
		});
	});
});

describe('MessageRow — Pillar C1 Task 4B: spam-quarantine collapse + reveal', () => {
	function quarantinedMsg(over: Partial<ChatMessage> = {}): StoreMessage {
		return msg({
			messageId: 50,
			authorId: null,
			federatedSenderAddr: 'bob@bravo.test',
			spamQuarantined: true,
			body: 'urgent click now',
			...over,
		}) as StoreMessage;
	}

	it('renders collapsed behind a warning + reveal control, hiding the body', () => {
		const { container } = render(MessageRow, { ...baseProps, message: quarantinedMsg() });
		expect(container.querySelector('[data-testid="quarantine-banner"]')).toBeTruthy();
		expect(screen.getByText('Possible spam — from bravo.test')).toBeTruthy();
		expect(screen.queryByText('urgent click now')).toBeNull();
	});

	it('"Show anyway" reveals the ordinary body and removes the banner', async () => {
		render(MessageRow, { ...baseProps, message: quarantinedMsg() });
		await fireEvent.click(screen.getByTestId('quarantine-reveal'));
		expect(screen.queryByTestId('quarantine-banner')).toBeNull();
		expect(screen.getByText('urgent click now')).toBeTruthy();
	});

	it('a non-quarantined federated message renders normally, with no banner', () => {
		const { container } = render(MessageRow, {
			...baseProps,
			message: quarantinedMsg({ spamQuarantined: false }),
		});
		expect(container.querySelector('[data-testid="quarantine-banner"]')).toBeNull();
		expect(screen.getByText('urgent click now')).toBeTruthy();
	});
});

describe('MessageRow — Pillar C1 Task 6: federated delivery tick (ack-as-receipt)', () => {
	it('an own message with deliveredAt set renders the delivered tick', () => {
		const { container } = render(MessageRow, {
			...baseProps,
			isMine: true,
			message: msg({ messageId: 60, deliveredAt: '2026-07-17T00:00:00Z' }),
		});
		expect(container.querySelector('.mrow__delivered-tick')).toBeTruthy();
		expect(screen.getByText('Delivered')).toBeTruthy();
	});

	it('an own message with no deliveredAt (ordinary local send) renders no tick', () => {
		const { container } = render(MessageRow, {
			...baseProps,
			isMine: true,
			message: msg({ messageId: 61, deliveredAt: null }),
		});
		expect(container.querySelector('.mrow__delivered-tick')).toBeNull();
	});

	it("deliveredAt on SOMEONE ELSE's message (isMine false) never renders a tick", () => {
		const { container } = render(MessageRow, {
			...baseProps,
			isMine: false,
			message: msg({ messageId: 62, deliveredAt: '2026-07-17T00:00:00Z' }),
		});
		expect(container.querySelector('.mrow__delivered-tick')).toBeNull();
	});
});

describe('MessageRow — Pillar C2 Task 7: federation gap marker + divergence warnings', () => {
	it("a 'system' row with a valid federation_gap body renders the gap marker, never an authored row", () => {
		const { container } = render(MessageRow, {
			...baseProps,
			message: msg({
				messageId: 70,
				authorId: null,
				msgType: 'system',
				body: JSON.stringify({ kind: 'federation_gap', from: '2026-07-01T00:00:00Z', to: '2026-07-02T00:00:00Z' }),
			}),
		});
		expect(container.querySelector('.mrow__gap-marker')).toBeTruthy();
		expect(container.querySelector('.ml__row')).toBeNull();
	});

	it("a 'system' row with a malformed/foreign body renders nothing — never the raw JSON, never an authored row", () => {
		const { container } = render(MessageRow, {
			...baseProps,
			message: msg({ messageId: 71, authorId: null, msgType: 'system', body: '{"kind":"something_else"}' }),
		});
		expect(container.querySelector('.mrow__gap-marker')).toBeNull();
		expect(container.querySelector('.ml__row')).toBeNull();
		expect(screen.queryByText(/something_else/)).toBeNull();
	});

	it('editing in a federated room shows the Q1 divergence warning; editing elsewhere does not', async () => {
		const { rerender } = render(MessageRow, {
			...baseProps,
			isMine: true,
			isFederatedRoom: false,
			message: msg({ messageId: 72 }),
		});
		await fireEvent.click(screen.getByLabelText('More actions'));
		await fireEvent.click(screen.getByText('Edit'));
		expect(screen.queryByText(/other member organizations keep the original message/)).toBeNull();

		await rerender({ ...baseProps, isMine: true, isFederatedRoom: true, message: msg({ messageId: 72 }) });
		expect(screen.getByText(/other member organizations keep the original message/)).toBeTruthy();
	});

	it('deleting in a federated room opens a confirm dialog with the divergence warning (no immediate delete)', async () => {
		vi.mocked(chatApi.deleteMessage).mockResolvedValue({ seq: 9 });
		render(MessageRow, {
			...baseProps,
			isMine: true,
			isFederatedRoom: true,
			message: msg({ messageId: 73 }),
		});
		await fireEvent.click(screen.getByLabelText('More actions'));
		await fireEvent.click(screen.getByText('Delete'));

		expect(screen.getByText('Delete this message?')).toBeTruthy();
		expect(screen.getByText(/other member organizations keep the original message/)).toBeTruthy();
		expect(chatApi.deleteMessage).not.toHaveBeenCalled();

		await fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
		await waitFor(() => expect(chatApi.deleteMessage).toHaveBeenCalledWith(73));
	});

	it('deleting OUTSIDE a federated room deletes immediately — no confirm dialog (unchanged pre-C2 behavior)', async () => {
		vi.mocked(chatApi.deleteMessage).mockResolvedValue({ seq: 10 });
		render(MessageRow, {
			...baseProps,
			isMine: true,
			isFederatedRoom: false,
			message: msg({ messageId: 74 }),
		});
		await fireEvent.click(screen.getByLabelText('More actions'));
		await fireEvent.click(screen.getByText('Delete'));
		await waitFor(() => expect(chatApi.deleteMessage).toHaveBeenCalledWith(74));
		expect(screen.queryByText('Delete this message?')).toBeNull();
	});
});
