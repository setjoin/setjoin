import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import ChatApp from './ChatApp.svelte';
import { chatStore } from '$lib/chat/store.svelte';
import type { Conversation } from '$lib/chat/api';
import { jmapSession } from '$lib/stores/session';
import { user } from '$lib/stores/auth';
import { goto } from '$app/navigation';

const createMeeting = vi.fn();
vi.mock('$lib/meet/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/meet/api')>('$lib/meet/api');
	return { ...actual, createMeeting: (...a: unknown[]) => createMeeting(...a) };
});

const listConversations = vi.fn();
const listMembers = vi.fn();
const getPresence = vi.fn();
const createChannel = vi.fn();
const browseChannels = vi.fn();
const joinChannel = vi.fn();
const openDM = vi.fn();
const listMessages = vi.fn();
const sinceMessages = vi.fn();
// A3 QoL Task 15: Composer's onMount now calls chatStore.loadScheduled() (the
// "N scheduled" chip), which reaches this route whenever ChatApp mounts a
// real Composer for an open channel — stub it so that path never fires an
// unstubbed network call in this suite (the chip/queue UI itself is
// Composer.test.ts's own concern, not ChatApp's).
const listScheduled = vi.fn();
// Pillar C2 Task 7 review (M1) — ChatApp's own roster fetch for the
// header badge / roster sheet (refreshFedRoom).
const getFederationRoomRoster = vi.fn();

vi.mock('$lib/chat/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/chat/api')>('$lib/chat/api');
	return {
		...actual,
		listConversations: (...a: unknown[]) => listConversations(...a),
		listMembers: (...a: unknown[]) => listMembers(...a),
		getPresence: (...a: unknown[]) => getPresence(...a),
		createChannel: (...a: unknown[]) => createChannel(...a),
		browseChannels: (...a: unknown[]) => browseChannels(...a),
		joinChannel: (...a: unknown[]) => joinChannel(...a),
		openDM: (...a: unknown[]) => openDM(...a),
		listMessages: (...a: unknown[]) => listMessages(...a),
		sinceMessages: (...a: unknown[]) => sinceMessages(...a),
		listScheduled: (...a: unknown[]) => listScheduled(...a),
		getFederationRoomRoster: (...a: unknown[]) => getFederationRoomRoster(...a),
	};
});

// capturedHandler keeps the ENVELOPE shape ({'@type', event: {...}}) —
// mirrors the MeetApp.test.ts/locks.test.ts convention: the mock's
// subscribeEvent unwraps `event` itself (the real jmap/websocket.ts hub-level
// unwrap) before forwarding to the handler ChatApp.svelte registers, so a
// test fires the same envelope shape the WS layer actually delivers.
let capturedHandler: ((envelope: Record<string, unknown>) => void) | null = null;
let websocketSubscribeCalls = 0;
vi.mock('$lib/jmap/websocket', () => ({
	subscribeEvent: (_type: string, handler: (event: Record<string, unknown>) => void) => {
		websocketSubscribeCalls += 1;
		capturedHandler = (envelope: Record<string, unknown>) => {
			const event = (envelope as { event?: unknown }).event;
			if (event && typeof event === 'object') handler(event as Record<string, unknown>);
		};
		return () => {
			capturedHandler = null;
		};
	},
}));

let capturedGuestHandler: ((event: Record<string, unknown>) => void) | null = null;
let capturedGuestOpen: (() => void) | null = null;
let guestEventSourceSubscribeCalls = 0;
vi.mock('$lib/chat/guestEventSource', () => ({
	subscribeGuestChatEvents: (handler: (event: Record<string, unknown>) => void, onOpen?: () => void) => {
		guestEventSourceSubscribeCalls += 1;
		capturedGuestHandler = handler;
		capturedGuestOpen = onOpen ?? null;
		return () => {
			capturedGuestHandler = null;
			capturedGuestOpen = null;
		};
	},
}));

function conv(over: Partial<Conversation> = {}): Conversation {
	return {
		channelId: 1,
		kind: 'channel',
		name: 'eng',
		topic: null,
		changeSeq: 5,
		lastReadSeq: 5,
		unreadCount: 0,
		hasMention: false,
		hasExternalMembers: false,
		lastMessagePreview: null,
		memberIds: [],
		...over,
	};
}

beforeEach(() => {
	capturedHandler = null;
	capturedGuestHandler = null;
	capturedGuestOpen = null;
	websocketSubscribeCalls = 0;
	guestEventSourceSubscribeCalls = 0;
	getPresence.mockResolvedValue({});
	listMembers.mockResolvedValue([]);
	listMessages.mockResolvedValue([]);
	sinceMessages.mockReset();
	listScheduled.mockResolvedValue([]);
	getFederationRoomRoster.mockResolvedValue({ roomId: 'room@hub.test', hubDomain: 'hub.test', isHub: true, removedAt: null, members: [] });
	jmapSession.set(null); // FALLBACK_CAPS — every app, incl. 'meet', enabled by default
});

afterEach(() => {
	vi.clearAllMocks();
	vi.restoreAllMocks();
	chatStore.reset();
	delete (chatStore as unknown as { addAttachments?: unknown }).addAttachments;
	capturedHandler = null;
	capturedGuestHandler = null;
	capturedGuestOpen = null;
	websocketSubscribeCalls = 0;
	guestEventSourceSubscribeCalls = 0;
	jmapSession.set(null);
	user.set(null);
});

describe('ChatApp', () => {
	it('renders the first-run empty state with Create / New-DM / Browse CTAs when there are no channels', async () => {
		listConversations.mockResolvedValue({ conversations: [], attachmentsEnabled: true });
		render(ChatApp);
		await waitFor(() => expect(screen.getByText('No channels yet')).toBeTruthy());
		expect(screen.getByText('Create a channel')).toBeTruthy();
		expect(screen.getByText('Start a direct message')).toBeTruthy();
		expect(screen.getByText('Browse channels')).toBeTruthy();
	});

	it('renders Waiting for access without member creation actions for a guest with zero memberships', async () => {
		jmapSession.set({
			isGuest: true,
			effectiveCapabilities: { apps: { chat: true, drive: false, meet: false }, features: { assist: false, bundles: false } },
		} as never);
		listConversations.mockResolvedValue({ conversations: [], attachmentsEnabled: true });
		render(ChatApp);
		await waitFor(() => expect(screen.getByText('Waiting for access')).toBeTruthy());
		expect(screen.queryByText('Create a channel')).toBeNull();
		expect(screen.queryByText('Start a direct message')).toBeNull();
		expect(screen.queryByText('Browse channels')).toBeNull();
	});

	it('uses the read-only EventSource rail for a guest and feeds its Chat events into ChatStore', async () => {
		user.set({ email: 'guest@partner.example', isAdmin: false, hasMailbox: false, accountType: 'guest' });
		jmapSession.set({
			isGuest: true,
			effectiveCapabilities: { apps: { chat: true }, features: { assist: false, bundles: false } },
		} as never);
		listConversations.mockResolvedValue({ conversations: [], attachmentsEnabled: true });
		const applyEvent = vi.spyOn(chatStore, 'applyEvent').mockResolvedValue({ refreshFederationRosterChannelId: null });
		const view = render(ChatApp);

		await waitFor(() => expect(guestEventSourceSubscribeCalls).toBe(1));
		expect(websocketSubscribeCalls).toBe(0);
		expect(capturedGuestHandler).not.toBeNull();
		expect(capturedGuestOpen).not.toBeNull();
		const event = { event: 'message_created', channelId: 7, messageId: 9, seq: 3 };
		capturedGuestHandler!(event);
		await waitFor(() => expect(applyEvent).toHaveBeenCalledWith(event));

		view.unmount();
		expect(capturedGuestHandler).toBeNull();
		applyEvent.mockRestore();
	});

	it('backfills missed guest messages and refreshes conversations on the initial EventSource open and every reopen', async () => {
		user.set({ email: 'guest@partner.example', isAdmin: false, hasMailbox: false, accountType: 'guest' });
		jmapSession.set({
			isGuest: true,
			effectiveCapabilities: { apps: { chat: true }, features: { assist: false, bundles: false } },
		} as never);
		listConversations.mockResolvedValue({ conversations: [], attachmentsEnabled: true });
		sinceMessages
			.mockResolvedValueOnce({
				messages: [{
					messageId: 2, channelId: 7, seq: 2, authorId: 9,
					authorExternal: true, authorRemoved: false, parentMessageId: null,
					msgType: 'text', broadcast: null, body: 'missed while offline',
					editedAt: null, deletedAt: null, createdAt: '2026-07-20T00:00:00Z',
					reactions: [], mentionsMe: false, replyCount: 0, lastReplyAt: null, attachments: [],
				}],
				cursor: 2,
			})
			.mockResolvedValueOnce({ messages: [], cursor: 2 });
		render(ChatApp);

		await waitFor(() => expect(capturedGuestOpen).not.toBeNull());
		chatStore.activeChannelId = 7;
		chatStore.messagesByChannel[7] = [{
			messageId: 1, channelId: 7, seq: 1, authorId: 9,
			authorExternal: true, authorRemoved: false, parentMessageId: null,
			msgType: 'text', broadcast: null, body: 'already loaded', editedAt: null,
			deletedAt: null, createdAt: '2026-07-19T00:00:00Z', reactions: [],
			mentionsMe: false, replyCount: 0, lastReplyAt: null, attachments: [], status: 'sent',
		}];
		listConversations.mockClear();

		capturedGuestOpen!();
		await waitFor(() => expect(chatStore.messagesByChannel[7]?.map((row) => row.messageId)).toEqual([1, 2]));
		capturedGuestOpen!();
		await waitFor(() => expect(listConversations).toHaveBeenCalledTimes(2));

		expect(sinceMessages).toHaveBeenNthCalledWith(1, 7, 1);
		expect(sinceMessages).toHaveBeenNthCalledWith(2, 7, 2);
	});

	it('keeps member Chat push on the existing WebSocket subscribeEvent hub', async () => {
		user.set({ email: 'member@example.com', isAdmin: false, hasMailbox: true, accountType: 'member' });
		listConversations.mockResolvedValue({ conversations: [], attachmentsEnabled: true });
		render(ChatApp);

		await waitFor(() => expect(websocketSubscribeCalls).toBeGreaterThan(0));
		expect(guestEventSourceSubscribeCalls).toBe(0);
		expect(capturedHandler).not.toBeNull();
	});

	it('keeps member affordances hidden for a guest with an existing conversation even when fallback caps enable Meet', async () => {
		user.set({ email: 'pat@example.com', isAdmin: false, hasMailbox: false, accountType: 'guest' });
		jmapSession.set(null);
		listConversations.mockResolvedValue({ conversations: [conv({ kind: 'dm', name: 'Partner chat' })], attachmentsEnabled: true });
		render(ChatApp);
		await waitFor(() => expect(screen.getByText('Partner chat')).toBeTruthy());
		expect(screen.queryByRole('button', { name: 'New channel' })).toBeNull();
		expect(screen.queryByRole('button', { name: 'New direct message' })).toBeNull();
		expect(screen.queryByRole('button', { name: 'Browse channels' })).toBeNull();

		await fireEvent.click(screen.getByText('Partner chat'));
		await waitFor(() => expect(screen.getByTestId('composer-input')).toBeTruthy());
		expect(screen.queryByRole('button', { name: 'Add people…' })).toBeNull();
		expect(screen.queryByRole('button', { name: 'Start call' })).toBeNull();
	});

	it('renders the channel list once conversations load, with a placeholder main pane', async () => {
		listConversations.mockResolvedValue({ conversations: [conv()], attachmentsEnabled: true });
		render(ChatApp);
		await waitFor(() => expect(screen.getByText('eng')).toBeTruthy());
		expect(screen.getByText('Select a conversation')).toBeTruthy();
	});

	it('creates a channel defaulting to public visibility', async () => {
		listConversations.mockResolvedValue({ conversations: [], attachmentsEnabled: true });
		createChannel.mockResolvedValue({ channelId: 9 });
		render(ChatApp);
		await waitFor(() => expect(screen.getByText('No channels yet')).toBeTruthy());
		await fireEvent.click(screen.getByText('Create a channel'));
		const nameInput = await screen.findByLabelText('Name');
		await fireEvent.input(nameInput, { target: { value: 'general' } });
		await fireEvent.click(screen.getByText('Create channel'));
		await waitFor(() => expect(createChannel).toHaveBeenCalledWith({ name: 'general', topic: '', visibility: 'public' }));
	});

	it('browse-channels dialog lists public channels and joins one', async () => {
		listConversations.mockResolvedValue({ conversations: [], attachmentsEnabled: true });
		browseChannels.mockResolvedValue([{ channelId: 5, name: 'random', topic: null, memberCount: 3, joined: false }]);
		joinChannel.mockResolvedValue(undefined);
		render(ChatApp);
		await waitFor(() => expect(screen.getByText('No channels yet')).toBeTruthy());
		await fireEvent.click(screen.getAllByText('Browse channels')[0]);
		await waitFor(() => expect(screen.getByText('random')).toBeTruthy());
		await fireEvent.click(screen.getByText('Join'));
		await waitFor(() => expect(joinChannel).toHaveBeenCalledWith(5));
	});

	it('opens a DM from numeric user ids', async () => {
		listConversations.mockResolvedValue({ conversations: [], attachmentsEnabled: true });
		openDM.mockResolvedValue({ channelId: 3 });
		render(ChatApp);
		await waitFor(() => expect(screen.getByText('No channels yet')).toBeTruthy());
		await fireEvent.click(screen.getByText('Start a direct message'));
		const idInput = await screen.findByLabelText('User ID(s)');
		await fireEvent.input(idInput, { target: { value: '43' } });
		await fireEvent.click(screen.getByText('Start conversation'));
		await waitFor(() => expect(openDM).toHaveBeenCalledWith([43]));
	});

	// Task 15: opening a conversation mounts MessageList + Composer in the
	// main pane (replacing the Task 13 placeholder) and fetches that
	// channel's roster exactly once.
	it('opening a conversation mounts MessageList + Composer and fetches the channel roster', async () => {
		listConversations.mockResolvedValue({ conversations: [conv({ channelId: 1, name: 'eng' })], attachmentsEnabled: true });
		render(ChatApp);
		await waitFor(() => expect(screen.getByText('eng')).toBeTruthy());

		await fireEvent.click(screen.getByText('eng'));

		await waitFor(() => expect(listMembers).toHaveBeenCalledWith(1));
		await waitFor(() => expect(screen.getByTestId('composer-input')).toBeTruthy());
		expect(screen.queryByText('Select a conversation')).toBeNull();
	});

	// grill Q5: a DM's header offers "Add people…"; a channel's never does.
	it('a DM conversation header offers "Add people…"; a channel does not', async () => {
		listConversations.mockResolvedValue({
			conversations: [
				conv({ channelId: 1, kind: 'channel', name: 'eng' }),
				conv({ channelId: 2, kind: 'dm', name: null, memberIds: [42, 43] }),
			],
			attachmentsEnabled: true,
		});
		listMembers.mockResolvedValue([
			{ userId: 42, displayName: 'Me', avatarSha256: null, role: 'member' },
			{ userId: 43, displayName: 'Bob', avatarSha256: null, role: 'member' },
		]);
		render(ChatApp);
		await waitFor(() => expect(screen.getByText('eng')).toBeTruthy());

		await fireEvent.click(screen.getByText('eng'));
		await waitFor(() => expect(screen.getByTestId('composer-input')).toBeTruthy());
		expect(screen.queryByText('Add people…')).toBeNull();
	});

	it('shows the header External badge from hasExternalMembers even when the fetched roster has no external row', async () => {
		listConversations.mockResolvedValue({ conversations: [conv({ channelId: 1, name: 'eng', hasExternalMembers: true })], attachmentsEnabled: true });
		listMembers.mockResolvedValue([
			{ userId: 1, displayName: 'Me', avatarSha256: null, role: 'member', external: false, removed: false },
		]);
		const { container } = render(ChatApp);
		await waitFor(() => expect(screen.getByText('eng')).toBeTruthy());

		await fireEvent.click(screen.getByText('eng'));
		await waitFor(() => expect(screen.getByTestId('composer-input')).toBeTruthy());
		expect(container.querySelector('.chat-app__conv-header')?.textContent).toContain('External');
	});

	it('shows no header External badge when hasExternalMembers is false even if a roster row is external', async () => {
		listConversations.mockResolvedValue({ conversations: [conv({ channelId: 1, name: 'eng' })], attachmentsEnabled: true });
		listMembers.mockResolvedValue([
			{ userId: 1, displayName: 'Pat', avatarSha256: null, role: 'member', external: true, removed: false },
		]);
		render(ChatApp);
		await waitFor(() => expect(screen.getByText('eng')).toBeTruthy());

		await fireEvent.click(screen.getByText('eng'));
		await waitFor(() => expect(screen.getByTestId('composer-input')).toBeTruthy());
		expect(screen.queryByText('External')).toBeNull();
	});

	it('"Add people…" on a DM calls chat_dm_open with the enlarged member set and navigates there (original DM untouched)', async () => {
		listConversations.mockResolvedValue({ conversations: [conv({ channelId: 2, kind: 'dm', name: null, memberIds: [42, 43] })], attachmentsEnabled: true });
		listMembers.mockResolvedValue([
			{ userId: 42, displayName: 'Me', avatarSha256: null, role: 'member' },
			{ userId: 43, displayName: 'Bob', avatarSha256: null, role: 'member' },
		]);
		openDM.mockResolvedValue({ channelId: 9 });
		render(ChatApp);
		// ChatApp's selfUserId resolution is best-effort (no numeric-id route
		// exists — see resolveSelfUserId's own comment) and stays unresolved
		// here (no $lib/stores/auth mock), so the DM title includes every
		// member, not just the counterpart; match on the substring instead.
		await waitFor(() => expect(screen.getByText(/Bob/)).toBeTruthy());

		await fireEvent.click(screen.getByText(/Bob/));
		await waitFor(() => expect(screen.getByText('Add people…')).toBeTruthy());

		await fireEvent.click(screen.getByText('Add people…'));
		const idInput = await screen.findByLabelText('User ID(s)');
		await fireEvent.input(idInput, { target: { value: '44' } });
		await fireEvent.click(screen.getByText('Start conversation'));

		await waitFor(() => expect(openDM).toHaveBeenCalledWith([42, 43, 44]));
	});

	// [UX #17, whole-pipeline review] selfUserId used to be resolved by
	// matching displayName against a fetched DM roster — wrong in
	// duplicate-displayName orgs. It now reads /auth/me's own `user_id`
	// (surfaced on the $lib/stores/auth `user` store as `userId`) directly.
	describe('selfUserId resolution (UX #17)', () => {
		it('resolves chatStore.selfUserId straight from $user.userId, with no roster fetch at all', async () => {
			user.set({ email: 'me@example.com', displayName: 'Me', isAdmin: false, hasMailbox: true, userId: 42 });
			listConversations.mockResolvedValue({ conversations: [conv({ channelId: 2, kind: 'dm', name: null, memberIds: [42, 43] })], attachmentsEnabled: true });
			render(ChatApp);

			await waitFor(() => expect(chatStore.selfUserId).toBe(42));
			expect(listMembers).not.toHaveBeenCalled();
		});

		it('a duplicate displayName in the roster never causes a wrong match once userId is known', async () => {
			// Two roster members share the SAME displayName as the caller — the
			// old displayName-matching hack would have had a 50/50 chance of
			// picking the wrong one. With userId present the roster is never
			// even consulted for self-resolution.
			user.set({ email: 'me@example.com', displayName: 'Alex', isAdmin: false, hasMailbox: true, userId: 42 });
			listConversations.mockResolvedValue({ conversations: [conv({ channelId: 2, kind: 'dm', name: null, memberIds: [42, 99] })], attachmentsEnabled: true });
			listMembers.mockResolvedValue([
				{ userId: 42, displayName: 'Alex', avatarSha256: null, role: 'member' },
				{ userId: 99, displayName: 'Alex', avatarSha256: null, role: 'member' },
			]);
			render(ChatApp);

			await waitFor(() => expect(chatStore.selfUserId).toBe(42));
		});

		it('falls back to the displayName match only when $user.userId is absent (old-gateway compatibility)', async () => {
			user.set({ email: 'me@example.com', displayName: 'Me', isAdmin: false, hasMailbox: true });
			listConversations.mockResolvedValue({ conversations: [conv({ channelId: 2, kind: 'dm', name: null, memberIds: [42, 43] })], attachmentsEnabled: true });
			listMembers.mockResolvedValue([
				{ userId: 42, displayName: 'Me', avatarSha256: null, role: 'member' },
				{ userId: 43, displayName: 'Bob', avatarSha256: null, role: 'member' },
			]);
			render(ChatApp);

			await waitFor(() => expect(chatStore.selfUserId).toBe(42));
			expect(listMembers).toHaveBeenCalledWith(2);
		});
	});

	// A3.5 Task 4: the deep-link props +page.svelte resolves from
	// ?channel=&seq= (a chat push notification's click-through) jump straight
	// to the target conversation via the same openChannelAt substrate
	// pin/save/search/My-Threads click-throughs already use.
	it('deepLinkChannel/deepLinkSeq props jump to the target conversation on mount', async () => {
		listConversations.mockResolvedValue({ conversations: [conv({ channelId: 7, name: 'eng' })], attachmentsEnabled: true });
		const openChannelAt = vi.spyOn(chatStore, 'openChannelAt').mockResolvedValue(undefined);
		render(ChatApp, { props: { deepLinkChannel: 7, deepLinkSeq: 42 } });
		await waitFor(() => expect(openChannelAt).toHaveBeenCalledWith(7, 42));
		openChannelAt.mockRestore();
	});

	it('without deep-link props, no jump happens (plain mount is unaffected)', async () => {
		listConversations.mockResolvedValue({ conversations: [conv({ channelId: 1, name: 'eng' })], attachmentsEnabled: true });
		const openChannelAt = vi.spyOn(chatStore, 'openChannelAt').mockResolvedValue(undefined);
		render(ChatApp);
		await waitFor(() => expect(screen.getByText('eng')).toBeTruthy());
		expect(openChannelAt).not.toHaveBeenCalled();
		openChannelAt.mockRestore();
	});

	// T8 review blocker: drag-drop must be whole-pane, not composer-only — a
	// drop over MessageList (never touching the composer strip) must still
	// preventDefault (no browser navigation) and route into the active
	// composer's intake via composerRef.acceptDroppedFiles.
	it('dropping a file over the message-list region (not the composer) routes to the composer intake and prevents the browser navigating', async () => {
		chatStore.addAttachments = vi.fn().mockReturnValue([]);
		listConversations.mockResolvedValue({ conversations: [conv({ channelId: 1, name: 'eng' })], attachmentsEnabled: true });
		const { container } = render(ChatApp);
		await waitFor(() => expect(screen.getByText('eng')).toBeTruthy());

		await fireEvent.click(screen.getByText('eng'));
		await waitFor(() => expect(screen.getByTestId('composer-input')).toBeTruthy());

		const messageListRegion = container.querySelector('.ml') as HTMLElement;
		expect(messageListRegion).toBeTruthy();
		const file = new File(['x'], 'dropped.png', { type: 'image/png' });
		const dispatched = await fireEvent.drop(messageListRegion, { dataTransfer: { types: ['Files'], files: [file] } });

		// dispatchEvent returns false when preventDefault was called on a
		// cancelable event — proof the browser did NOT navigate to the file.
		expect(dispatched).toBe(false);
		expect(chatStore.addAttachments).toHaveBeenCalledWith(1, null, [file]);
	});

	// A4a Task 13 — deliberately minimal end-user compliance surface: a WORM
	// badge for a gxp channel, a separate retention indicator whenever a
	// retention knob applies, and legalHold NEVER rendered (design review
	// #11 — not even a projected field to check here, see api.ts's Conversation).
	describe('A4a Task 13 — WORM badge + retention indicator', () => {
		it('a gxp channel header shows the WORM badge; a regular channel does not', async () => {
			listConversations.mockResolvedValue({
				conversations: [conv({ channelId: 1, name: 'records', classification: 'gxp', retentionDays: 90 })],
				attachmentsEnabled: true,
			});
			render(ChatApp);
			await waitFor(() => expect(screen.getByText('records')).toBeTruthy());
			await fireEvent.click(screen.getByText('records'));
			await waitFor(() => expect(screen.getByTestId('composer-input')).toBeTruthy());

			expect(screen.getByTitle('Compliance channel — messages cannot be edited or deleted')).toBeTruthy();
		});

		it('a regular channel with no retentionDays shows neither badge', async () => {
			listConversations.mockResolvedValue({
				conversations: [conv({ channelId: 1, name: 'eng' })],
				attachmentsEnabled: true,
			});
			render(ChatApp);
			await waitFor(() => expect(screen.getByText('eng')).toBeTruthy());
			await fireEvent.click(screen.getByText('eng'));
			await waitFor(() => expect(screen.getByTestId('composer-input')).toBeTruthy());

			expect(screen.queryByTitle('Compliance channel — messages cannot be edited or deleted')).toBeNull();
			expect(screen.queryByTitle(/Permanently delete messages older than/)).toBeNull();
		});

		it('a regular channel with an org retention policy shows the destroy-ceiling tooltip, not the WORM one', async () => {
			listConversations.mockResolvedValue({
				conversations: [conv({ channelId: 1, name: 'eng', retentionDays: 30 })],
				attachmentsEnabled: true,
			});
			render(ChatApp);
			await waitFor(() => expect(screen.getByText('eng')).toBeTruthy());
			await fireEvent.click(screen.getByText('eng'));
			await waitFor(() => expect(screen.getByTestId('composer-input')).toBeTruthy());

			expect(screen.getByTitle('Permanently delete messages older than 30 days')).toBeTruthy();
			expect(screen.queryByTitle('Compliance channel — messages cannot be edited or deleted')).toBeNull();
		});
	});

	// [UX #3, pipeline review] the chat→meet huddle bridge (spec §3.3's
	// "no-ring launch") had no SENDER anywhere in webmail — meeting_create
	// accepts chatChannelId and MessageRow already renders the receiver-side
	// call card, but nothing ever posted one. This is the sender.
	describe('Start call (UX #3 — the chat→meet huddle bridge sender)', () => {
		it('shows the Start call button in the conversation header once a channel is open (meet enabled by default)', async () => {
			listConversations.mockResolvedValue({ conversations: [conv({ channelId: 1, name: 'eng' })], attachmentsEnabled: true });
			render(ChatApp);
			await waitFor(() => expect(screen.getByText('eng')).toBeTruthy());
			expect(screen.queryByLabelText('Start call')).toBeNull(); // no channel open yet

			await fireEvent.click(screen.getByText('eng'));
			await waitFor(() => expect(screen.getByTestId('composer-input')).toBeTruthy());
			expect(screen.getByLabelText('Start call')).toBeTruthy();
		});

		it('hides the Start call button entirely when feature.meet is OFF', async () => {
			jmapSession.set({ effectiveCapabilities: { apps: { meet: false }, features: { assist: false, bundles: false } } } as never);
			listConversations.mockResolvedValue({ conversations: [conv({ channelId: 1, name: 'eng' })], attachmentsEnabled: true });
			render(ChatApp);
			await waitFor(() => expect(screen.getByText('eng')).toBeTruthy());
			await fireEvent.click(screen.getByText('eng'));
			await waitFor(() => expect(screen.getByTestId('composer-input')).toBeTruthy());
			expect(screen.queryByLabelText('Start call')).toBeNull();
		});

		it('clicking Start call creates a meeting bound to the open channel and navigates into it', async () => {
			listConversations.mockResolvedValue({ conversations: [conv({ channelId: 1, name: 'eng' })], attachmentsEnabled: true });
			createMeeting.mockResolvedValue({ meetingId: 5, slug: 'huddle-abc', roomName: 'room-5', chatChannelId: 1 });
			render(ChatApp);
			await waitFor(() => expect(screen.getByText('eng')).toBeTruthy());
			await fireEvent.click(screen.getByText('eng'));
			await waitFor(() => expect(screen.getByTestId('composer-input')).toBeTruthy());

			await fireEvent.click(screen.getByLabelText('Start call'));

			await waitFor(() => expect(createMeeting).toHaveBeenCalledWith({ title: 'eng', chatChannelId: 1 }));
			await waitFor(() => expect(goto).toHaveBeenCalledWith('/meet?slug=huddle-abc'));
		});
	});

	// Pillar C2 Task 7 review (M1) — the server emits 'federation_removed'/
	// 'federation_roster' (notify_chat_state, no row of their own) but nothing
	// consumed them client-side: a kicked spoke's banner/composer-disable
	// never appeared live, and the roster/depth-warn badge never updated
	// live. This is the regression proof — reverting the ChatApp.svelte
	// subscription fix (the two event names added to the reload trigger +
	// the channel-scoped refreshFedRoom() call) makes both tests below fail.
	describe('Pillar C2 Task 7 review (M1) — live federation_removed/roster events', () => {
		it('a federation_removed event for the OPEN channel reloads conversations (banner appears) and refetches that channel’s roster', async () => {
			listConversations
				.mockResolvedValueOnce({
					conversations: [conv({ channelId: 1, name: 'room', federatedRoomId: 'room@hub.test', isFederatedRoomHub: true })],
					attachmentsEnabled: true,
				})
				.mockResolvedValueOnce({
					conversations: [
						conv({
							channelId: 1,
							name: 'room',
							federatedRoomId: 'room@hub.test',
							isFederatedRoomHub: true,
							federatedRoomRemoved: true,
						}),
					],
					attachmentsEnabled: true,
				});
			render(ChatApp);
			await waitFor(() => expect(screen.getByText('room')).toBeTruthy());
			await fireEvent.click(screen.getByText('room'));
			await waitFor(() => expect(screen.getByTestId('composer-input')).toBeTruthy());
			await waitFor(() => expect(getFederationRoomRoster).toHaveBeenCalledTimes(1));
			expect(screen.queryByText('This room was closed for your organization — it is now archive-only')).toBeNull();

			await vi.waitFor(() => expect(capturedHandler).not.toBeNull());
			capturedHandler!({ '@type': 'ChatEvent', event: { event: 'federation_removed', channelId: 1, messageId: null, seq: null } });

			await waitFor(() => expect(listConversations).toHaveBeenCalledTimes(2));
			await waitFor(() =>
				expect(screen.getByText('This room was closed for your organization — it is now archive-only')).toBeTruthy(),
			);
			await waitFor(() => expect(getFederationRoomRoster).toHaveBeenCalledTimes(2));
		});

		it('a federation_roster event for a BACKGROUND channel reloads conversations but does not refetch a roster for the currently-open channel', async () => {
			listConversations.mockResolvedValue({
				conversations: [
					conv({ channelId: 1, name: 'eng' }),
					conv({ channelId: 2, name: 'room', federatedRoomId: 'other-room@hub.test', isFederatedRoomHub: true }),
				],
				attachmentsEnabled: true,
			});
			render(ChatApp);
			await waitFor(() => expect(screen.getByText('eng')).toBeTruthy());
			await fireEvent.click(screen.getByText('eng'));
			await waitFor(() => expect(screen.getByTestId('composer-input')).toBeTruthy());
			// channel 1 (open) has no federatedRoomId -> no roster fetch on open.
			expect(getFederationRoomRoster).not.toHaveBeenCalled();

			await vi.waitFor(() => expect(capturedHandler).not.toBeNull());
			capturedHandler!({ '@type': 'ChatEvent', event: { event: 'federation_roster', channelId: 2, messageId: null, seq: null } });

			await waitFor(() => expect(listConversations).toHaveBeenCalledTimes(2));
			// the event named channel 2, not the active channel (1) -> no roster
			// fetch fired for it (the stale-response/wrong-channel guard).
			expect(getFederationRoomRoster).not.toHaveBeenCalled();
		});
	});
});
