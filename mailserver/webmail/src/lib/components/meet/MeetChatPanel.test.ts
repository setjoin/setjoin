// MeetChatPanel.test.ts — Meet B1 Task 16 named test: mounts the chat
// composer with the meeting's channel id, and shows the guest-visibility
// note when a `g:` participant is present. B3 Task 8 adds the Q&A tab
// (client-side filter over the same messagesByChannel data) + the
// openPollDialog pass-through.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import MeetChatPanel from './MeetChatPanel.svelte';
import { chatStore } from '$lib/chat/store.svelte';
import type { ChatMessage, RosterMember } from '$lib/chat/api';
import { user } from '$lib/stores/auth';
import { jmapSession } from '$lib/stores/session';

const listMembers = vi.fn();
const listMessages = vi.fn();
const listScheduled = vi.fn();
const sendMessage = vi.fn();
const threadMessages = vi.fn();
const toggleReaction = vi.fn();
const listConversations = vi.fn();

vi.mock('$lib/chat/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/chat/api')>('$lib/chat/api');
	return {
		...actual,
		listMembers: (...a: unknown[]) => listMembers(...a),
		listMessages: (...a: unknown[]) => listMessages(...a),
		listScheduled: (...a: unknown[]) => listScheduled(...a),
		sendMessage: (...a: unknown[]) => sendMessage(...a),
		threadMessages: (...a: unknown[]) => threadMessages(...a),
		toggleReaction: (...a: unknown[]) => toggleReaction(...a),
		listConversations: (...a: unknown[]) => listConversations(...a),
	};
});

let websocketSubscribeCalls = 0;
vi.mock('$lib/jmap/websocket', () => ({
	subscribeEvent: () => {
		websocketSubscribeCalls += 1;
		return () => {};
	},
}));

let capturedGuestChatHandler: ((event: Record<string, unknown>) => void) | null = null;
let capturedGuestChatOpen: (() => void) | null = null;
let guestChatSubscribeCalls = 0;
vi.mock('$lib/chat/guestEventSource', () => ({
	subscribeGuestChatEvents: (handler: (event: Record<string, unknown>) => void, onOpen?: () => void) => {
		guestChatSubscribeCalls += 1;
		capturedGuestChatHandler = handler;
		capturedGuestChatOpen = onOpen ?? null;
		return () => {
			capturedGuestChatHandler = null;
			capturedGuestChatOpen = null;
		};
	},
}));

function fixtureMessage(over: Partial<ChatMessage> & { messageId: number; seq: number }): ChatMessage {
	return {
		channelId: 501,
		authorId: 1,
		authorExternal: false,
		authorRemoved: false,
		parentMessageId: null,
		msgType: 'text',
		broadcast: null,
		body: 'hi',
		editedAt: null,
		deletedAt: null,
		createdAt: '2026-07-15T00:00:00.000Z',
		reactions: [],
		mentionsMe: false,
		replyCount: 0,
		lastReplyAt: null,
		...over,
	};
}

const HOST: RosterMember = { userId: 1, displayName: 'Host Hank', avatarSha256: null, role: 'owner', external: false, removed: false };
const MEMBER: RosterMember = { userId: 2, displayName: 'Mem Mary', avatarSha256: null, role: 'member', external: false, removed: false };

beforeEach(() => {
	user.set(null);
	jmapSession.set(null);
	websocketSubscribeCalls = 0;
	guestChatSubscribeCalls = 0;
	capturedGuestChatHandler = null;
	capturedGuestChatOpen = null;
	listMembers.mockResolvedValue([]);
	listMessages.mockResolvedValue([]);
	listScheduled.mockResolvedValue([]);
	sendMessage.mockResolvedValue({ messageId: 999, seq: 99 });
	threadMessages.mockResolvedValue([]);
	toggleReaction.mockResolvedValue(undefined);
	listConversations.mockResolvedValue({ conversations: [], attachmentsEnabled: false });
	chatStore.messagesByChannel = {};
	chatStore.activeChannelId = null;
	chatStore.conversations = [];
});

afterEach(() => {
	vi.clearAllMocks();
	user.set(null);
	jmapSession.set(null);
});

describe('MeetChatPanel', () => {
	it('uses the guest Chat EventSource rail and reconciles on every open', async () => {
		user.set({ email: 'guest@partner.example', isAdmin: false, hasMailbox: false, accountType: 'guest' });
		const applyEvent = vi.spyOn(chatStore, 'applyEvent').mockResolvedValue({ refreshFederationRosterChannelId: null });
		const onSocketOpen = vi.spyOn(chatStore, 'onSocketOpen').mockResolvedValue();
		render(MeetChatPanel, { channelId: 501 });

		await vi.waitFor(() => expect(guestChatSubscribeCalls).toBe(1));
		expect(websocketSubscribeCalls).toBe(0);
		const event = { event: 'message_created', channelId: 501, messageId: 9, seq: 3 };
		capturedGuestChatHandler!(event);
		await vi.waitFor(() => expect(applyEvent).toHaveBeenCalledWith(event));
		capturedGuestChatOpen!();
		capturedGuestChatOpen!();
		await vi.waitFor(() => expect(onSocketOpen).toHaveBeenCalledTimes(2));
		applyEvent.mockRestore();
		onSocketOpen.mockRestore();
	});
	it('mounts the chat Composer bound to the meeting channel id', async () => {
		render(MeetChatPanel, { channelId: 501 });
		await vi.waitFor(() => expect(listMembers).toHaveBeenCalledWith(501));
		expect(listMessages).toHaveBeenCalled();
		expect(listMessages.mock.calls[0][0]).toBe(501);
		// Composer's send button/textarea rendered (real Composer, no mock needed).
		expect(screen.getByRole('textbox')).toBeTruthy();
	});

	it('shows the guest-visibility note only when hasGuestParticipant is true', () => {
		const { rerender } = render(MeetChatPanel, { channelId: 501, hasGuestParticipant: false });
		expect(screen.queryByTestId('meet-chat-guest-notice')).toBeNull();
	});

	it('shows the guest-visibility note when a guest participant is present', () => {
		render(MeetChatPanel, { channelId: 501, hasGuestParticipant: true });
		expect(screen.getByTestId('meet-chat-guest-notice')).toBeTruthy();
	});

	// [UX #2b, pipeline review] this panel never called
	// chatStore.loadConversations() — MessageList's markReadIfEligible looks
	// the channel up in chatStore.conversations before marking anything read,
	// and openChannel() alone never populates that array — so a message read
	// live in-meeting was never actually marked read, leaving a phantom
	// unread once the meeting ended.
	it('calls chatStore.loadConversations() on mount so mark-read works for the bridged channel', async () => {
		render(MeetChatPanel, { channelId: 501 });
		await vi.waitFor(() => expect(listConversations).toHaveBeenCalled());
	});
});

// B3 Task 8 — Q&A tab: a client-side filter over the same messagesByChannel
// data MessageList reads (spec §4.2 zero-new-plumbing verdict).
describe('MeetChatPanel — Q&A tab (Meet B3 Task 8)', () => {
	it('lists only msgType=question rows, sorted by upvote count desc, tie-broken by seq', async () => {
		listMessages.mockResolvedValue([
			fixtureMessage({ messageId: 1, seq: 1, msgType: 'text', body: 'hello' }),
			fixtureMessage({ messageId: 2, seq: 2, msgType: 'question', body: 'low votes', reactions: [{ emoji: '👍', count: 1, mine: false }] }),
			fixtureMessage({ messageId: 3, seq: 3, msgType: 'question', body: 'high votes', reactions: [{ emoji: '👍', count: 5, mine: false }] }),
			fixtureMessage({ messageId: 4, seq: 4, msgType: 'question', body: 'no votes' }),
			fixtureMessage({ messageId: 5, seq: 5, msgType: 'question', body: 'also no votes' }),
		]);
		render(MeetChatPanel, { channelId: 501 });
		await vi.waitFor(() => expect(listMessages).toHaveBeenCalled());
		await fireEvent.click(screen.getByRole('tab', { name: 'Q&A' }));

		const rows = screen.getAllByTestId(/^qa-item-\d+$/);
		expect(rows.map((r) => r.getAttribute('data-testid'))).toEqual([
			'qa-item-3', // 5 upvotes
			'qa-item-2', // 1 upvote
			'qa-item-4', // 0 upvotes, seq 4 before seq 5
			'qa-item-5',
		]);
		expect(screen.queryByText('hello')).toBeNull(); // plain text message excluded
	});

	it('shows the empty state when there are no questions', async () => {
		listMessages.mockResolvedValue([]);
		render(MeetChatPanel, { channelId: 501 });
		await vi.waitFor(() => expect(listMessages).toHaveBeenCalled());
		await fireEvent.click(screen.getByRole('tab', { name: 'Q&A' }));
		expect(screen.getByText('No questions yet')).toBeTruthy();
	});

	it('"Ask a question" is a real form — Enter/native submit calls sendMessage with msgType question', async () => {
		listMessages.mockResolvedValue([]);
		render(MeetChatPanel, { channelId: 501 });
		await vi.waitFor(() => expect(listMessages).toHaveBeenCalled());
		await fireEvent.click(screen.getByRole('tab', { name: 'Q&A' }));

		const input = screen.getByPlaceholderText('Ask a question') as HTMLInputElement;
		await fireEvent.input(input, { target: { value: 'What is the roadmap?' } });
		const form = input.closest('form');
		expect(form).toBeTruthy();
		await fireEvent.submit(form as HTMLFormElement);

		await vi.waitFor(() => expect(sendMessage).toHaveBeenCalled());
		const call = sendMessage.mock.calls[0];
		expect(call[0]).toBe(501);
		expect(call[1]).toBe('What is the roadmap?');
		expect(call[6]).toBe('question');
	});

	it('renders the Answered badge only once the expanded thread contains an owner/admin roster reply', async () => {
		listMembers.mockResolvedValue([HOST, MEMBER]);
		listMessages.mockResolvedValue([
			fixtureMessage({ messageId: 10, seq: 10, msgType: 'question', authorId: 2, body: 'unanswered?' }),
			fixtureMessage({ messageId: 20, seq: 20, msgType: 'question', authorId: 2, body: 'answered?' }),
		]);
		threadMessages.mockImplementation(async (parentId: number) => {
			if (parentId === 10) {
				return [
					fixtureMessage({ messageId: 10, seq: 10, msgType: 'question', authorId: 2, body: 'unanswered?' }),
					fixtureMessage({ messageId: 11, seq: 11, parentMessageId: 10, authorId: 2, body: 'me too' }),
				];
			}
			return [
				fixtureMessage({ messageId: 20, seq: 20, msgType: 'question', authorId: 2, body: 'answered?' }),
				fixtureMessage({ messageId: 21, seq: 21, parentMessageId: 20, authorId: 1, body: 'here is the answer' }),
			];
		});
		render(MeetChatPanel, { channelId: 501 });
		await vi.waitFor(() => expect(listMessages).toHaveBeenCalled());
		await fireEvent.click(screen.getByRole('tab', { name: 'Q&A' }));

		expect(screen.queryByText('Answered')).toBeNull(); // nothing expanded yet — D9 "on expand"

		await fireEvent.click(screen.getByTestId('qa-item-10-toggle'));
		await vi.waitFor(() => expect(threadMessages).toHaveBeenCalledWith(10));
		expect(screen.queryByText('Answered')).toBeNull(); // reply author (userId 2) is a plain member

		await fireEvent.click(screen.getByTestId('qa-item-20-toggle'));
		await vi.waitFor(() => expect(threadMessages).toHaveBeenCalledWith(20));
		expect(screen.getByText('Answered')).toBeTruthy(); // reply author (userId 1) is roster role 'owner'
	});

	it('upvote calls the existing reaction-toggle route', async () => {
		listMessages.mockResolvedValue([fixtureMessage({ messageId: 30, seq: 30, msgType: 'question', body: 'q' })]);
		render(MeetChatPanel, { channelId: 501 });
		await vi.waitFor(() => expect(listMessages).toHaveBeenCalled());
		await fireEvent.click(screen.getByRole('tab', { name: 'Q&A' }));

		await fireEvent.click(screen.getByTestId('qa-item-30-upvote'));
		expect(toggleReaction).toHaveBeenCalledWith(30, '👍');
		const rows = chatStore.messagesByChannel[501] ?? [];
		const row = rows.find((r) => r.messageId === 30);
		expect(row?.reactions.find((r) => r.emoji === '👍')?.count).toBe(1);
	});
});

describe('MeetChatPanel — openPollDialog pass-through (Meet B3 Task 8)', () => {
	it('exposes openPollDialog(): switches to the chat tab and opens the EXISTING Composer poll dialog', async () => {
		const { component } = render(MeetChatPanel, { channelId: 501 });
		await vi.waitFor(() => expect(listMembers).toHaveBeenCalled());
		// Start on the Q&A tab — the pass-through must switch back to chat
		// (Composer is unmounted while the Q&A tab is active).
		await fireEvent.click(screen.getByRole('tab', { name: 'Q&A' }));
		expect(screen.queryByPlaceholderText('Message…')).toBeNull(); // Composer unmounted, only the Q&A "Ask" input remains

		await (component as unknown as { openPollDialog: () => Promise<void> }).openPollDialog();

		expect(screen.getByRole('tab', { name: 'Chat', selected: true })).toBeTruthy();
		expect(screen.getByText('Create a poll')).toBeTruthy();
	});
});
