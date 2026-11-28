import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import ChannelList from './ChannelList.svelte';
import type { Conversation, RosterMember } from '$lib/chat/api';

const listMembers = vi.fn();
const getPresence = vi.fn();
const listMyThreads = vi.fn();

vi.mock('$lib/chat/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/chat/api')>('$lib/chat/api');
	return {
		...actual,
		listMembers: (...a: unknown[]) => listMembers(...a),
		getPresence: (...a: unknown[]) => getPresence(...a),
		listMyThreads: (...a: unknown[]) => listMyThreads(...a),
	};
});

beforeEach(() => {
	listMyThreads.mockResolvedValue([]);
});

function conv(over: Partial<Conversation> = {}): Conversation {
	return {
		channelId: 10,
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

function member(over: Partial<RosterMember> = {}): RosterMember {
	return { userId: 43, displayName: 'Bob', avatarSha256: null, role: 'member', external: false, removed: false, ...over };
}

const noop = vi.fn();

afterEach(() => {
	vi.clearAllMocks();
});

describe('ChannelList', () => {
	it('renders channel rows with name and preview', () => {
		render(ChannelList, {
			conversations: [
				conv({
					channelId: 1,
					name: 'eng',
					lastMessagePreview: { authorId: 2, snippet: 'ship it', createdAt: '2026-07-11T00:00:00Z' },
				}),
			],
			activeChannelId: null,
			selfUserId: 42,
			onSelect: noop,
			onNewChannel: noop,
			onNewDM: noop,
			onBrowse: noop,
		});
		expect(screen.getByText('eng')).toBeTruthy();
		expect(screen.getByText(/ship it/)).toBeTruthy();
	});

	it('renders the container External badge from hasExternalMembers without fetching a channel roster', async () => {
		render(ChannelList, {
			conversations: [conv({ channelId: 1, hasExternalMembers: true })],
			activeChannelId: null,
			selfUserId: 42,
			onSelect: noop,
			onNewChannel: noop,
			onNewDM: noop,
			onBrowse: noop,
		});
		expect(screen.getByText('External')).toBeTruthy();
		await Promise.resolve();
		expect(listMembers).not.toHaveBeenCalled();
	});

	// whole-pipeline review UX #16: a voice message's empty snippet used to
	// render as a blank preview; msgType now maps it to a label instead.
	it('renders a "Voice message" preview label for a voice message (empty snippet)', () => {
		render(ChannelList, {
			conversations: [
				conv({
					channelId: 1,
					name: 'eng',
					lastMessagePreview: { authorId: 2, snippet: '', createdAt: '2026-07-11T00:00:00Z', msgType: 'voice' },
				}),
			],
			activeChannelId: null,
			selfUserId: 42,
			onSelect: noop,
			onNewChannel: noop,
			onNewDM: noop,
			onBrowse: noop,
		});
		expect(screen.getByText('Voice message')).toBeTruthy();
	});

	it('shows an unread badge capped at 99+', () => {
		render(ChannelList, {
			conversations: [conv({ channelId: 1, unreadCount: 150 })],
			activeChannelId: null,
			selfUserId: 42,
			onSelect: noop,
			onNewChannel: noop,
			onNewDM: noop,
			onBrowse: noop,
		});
		expect(screen.getByText('99+')).toBeTruthy();
	});

	it('gives a mentioned conversation distinct styling from a plain-unread one', () => {
		render(ChannelList, {
			conversations: [conv({ channelId: 1, unreadCount: 3, hasMention: true })],
			activeChannelId: null,
			selfUserId: 42,
			onSelect: noop,
			onNewChannel: noop,
			onNewDM: noop,
			onBrowse: noop,
		});
		const badge = screen.getByText('3');
		expect(badge.className).toContain('mention');
	});

	// [UX #2a, pipeline review] a meeting-bridged channel used to render as an
	// unlabeled ghost channel (the generic MessageCircle icon) — consumes the
	// new `meetingId` envelope key to render a distinct meeting affordance.
	it('shows a meeting affordance for a channel bridged to a meeting (meetingId != null)', () => {
		render(ChannelList, {
			conversations: [conv({ channelId: 1, meetingId: 42 })],
			activeChannelId: null,
			selfUserId: 42,
			onSelect: noop,
			onNewChannel: noop,
			onNewDM: noop,
			onBrowse: noop,
		});
		expect(screen.getByLabelText('Meeting chat')).toBeTruthy();
		expect(document.querySelector('.cl__icon--meeting')).toBeTruthy();
	});

	it('renders the plain channel icon (no meeting affordance) when meetingId is null/absent', () => {
		render(ChannelList, {
			conversations: [conv({ channelId: 1 })],
			activeChannelId: null,
			selfUserId: 42,
			onSelect: noop,
			onNewChannel: noop,
			onNewDM: noop,
			onBrowse: noop,
		});
		expect(screen.queryByLabelText('Meeting chat')).toBeNull();
		expect(document.querySelector('.cl__icon--meeting')).toBeNull();
	});

	it('resolves a DM title from the roster (memberIds minus self)', async () => {
		listMembers.mockResolvedValue([member({ userId: 42, displayName: 'Me' }), member({ userId: 43, displayName: 'Bob' })]);
		getPresence.mockResolvedValue({});
		render(ChannelList, {
			conversations: [conv({ channelId: 2, kind: 'dm', name: null, memberIds: [42, 43] })],
			activeChannelId: null,
			selfUserId: 42,
			onSelect: noop,
			onNewChannel: noop,
			onNewDM: noop,
			onBrowse: noop,
		});
		await waitFor(() => expect(screen.getByText('Bob')).toBeTruthy());
		expect(listMembers).toHaveBeenCalledWith(2);
	});

	it('shows a presence dot for an online DM counterpart', async () => {
		listMembers.mockResolvedValue([member({ userId: 42, displayName: 'Me' }), member({ userId: 43, displayName: 'Bob' })]);
		getPresence.mockResolvedValue({ '43': true });
		render(ChannelList, {
			conversations: [conv({ channelId: 2, kind: 'dm', name: null, memberIds: [42, 43] })],
			activeChannelId: null,
			selfUserId: 42,
			onSelect: noop,
			onNewChannel: noop,
			onNewDM: noop,
			onBrowse: noop,
		});
		await waitFor(() => expect(screen.getByLabelText('Online')).toBeTruthy());
	});

	it('calls onSelect with the channel id when a row is clicked', async () => {
		const onSelect = vi.fn();
		render(ChannelList, {
			conversations: [conv({ channelId: 7 })],
			activeChannelId: null,
			selfUserId: 42,
			onSelect,
			onNewChannel: noop,
			onNewDM: noop,
			onBrowse: noop,
		});
		await fireEvent.click(screen.getByText('eng'));
		expect(onSelect).toHaveBeenCalledWith(7);
	});

	it('wires the header New channel / New DM / Browse buttons', async () => {
		const onNewChannel = vi.fn();
		const onNewDM = vi.fn();
		const onBrowse = vi.fn();
		render(ChannelList, {
			conversations: [],
			activeChannelId: null,
			selfUserId: 42,
			onSelect: noop,
			onNewChannel,
			onNewDM,
			onBrowse,
		});
		await fireEvent.click(screen.getByLabelText('New channel'));
		await fireEvent.click(screen.getByLabelText('New direct message'));
		await fireEvent.click(screen.getByLabelText('Browse channels'));
		expect(onNewChannel).toHaveBeenCalled();
		expect(onNewDM).toHaveBeenCalled();
		expect(onBrowse).toHaveBeenCalled();
	});

	// A3 QoL Task 16 — fixed Saved/My-Threads entries (Slack's "Later"/"Threads" placement).
	describe('fixed Saved / My-Threads rows', () => {
		it('renders Saved and Threads above the conversation list and wires their callbacks', async () => {
			const onSelectSaved = vi.fn();
			const onSelectThreads = vi.fn();
			render(ChannelList, {
				conversations: [conv({ channelId: 1 })],
				activeChannelId: null,
				selfUserId: 42,
				onSelect: noop,
				onNewChannel: noop,
				onNewDM: noop,
				onBrowse: noop,
				onSelectSaved,
				onSelectThreads,
			});
			await fireEvent.click(screen.getByText('Saved'));
			expect(onSelectSaved).toHaveBeenCalled();
			await fireEvent.click(screen.getByText('Threads'));
			expect(onSelectThreads).toHaveBeenCalled();
		});

		it('shows an aggregate unread badge on the Threads row derived from chat_my_threads', async () => {
			listMyThreads.mockResolvedValue([
				{ messageId: 1, channelId: 1, seq: 1, authorId: 2, body: 'a', createdAt: '2026-07-11T00:00:00Z', replyCount: 2, lastReplyAt: null, unreadCount: 3 },
				{ messageId: 2, channelId: 1, seq: 2, authorId: 2, body: 'b', createdAt: '2026-07-11T00:00:00Z', replyCount: 1, lastReplyAt: null, unreadCount: 4 },
			]);
			render(ChannelList, {
				conversations: [conv({ channelId: 1 })],
				activeChannelId: null,
				selfUserId: 42,
				onSelect: noop,
				onNewChannel: noop,
				onNewDM: noop,
				onBrowse: noop,
			});
			await waitFor(() => expect(screen.getByText('7')).toBeTruthy());
		});

		it('submits a global search query from the header input on Enter', async () => {
			const onSearch = vi.fn();
			render(ChannelList, {
				conversations: [],
				activeChannelId: null,
				selfUserId: 42,
				onSelect: noop,
				onNewChannel: noop,
				onNewDM: noop,
				onBrowse: noop,
				onSearch,
			});
			const input = screen.getByPlaceholderText('Search messages');
			await fireEvent.input(input, { target: { value: 'deploy' } });
			await fireEvent.keyDown(input, { key: 'Enter' });
			expect(onSearch).toHaveBeenCalledWith('deploy');
		});

		it('highlights the Saved row as selected when activeView is saved', () => {
			render(ChannelList, {
				conversations: [],
				activeChannelId: null,
				selfUserId: 42,
				onSelect: noop,
				onNewChannel: noop,
				onNewDM: noop,
				onBrowse: noop,
				activeView: 'saved',
			});
			expect(screen.getByText('Saved').closest('button')?.className).toContain('selected');
		});
	});

	// A3 QoL Task 16 — mute consequence rendering (per-channel notifLevel).
	describe('mute rendering', () => {
		it('suppresses the unread badge and shows a mute glyph for notifLevel "none"', () => {
			render(ChannelList, {
				conversations: [conv({ channelId: 1, unreadCount: 5, notifLevel: 'none' })],
				activeChannelId: null,
				selfUserId: 42,
				onSelect: noop,
				onNewChannel: noop,
				onNewDM: noop,
				onBrowse: noop,
			});
			expect(screen.queryByText('5')).toBeNull();
			expect(screen.getByLabelText('Muted')).toBeTruthy();
		});

		it('shows the badge only for a mention when notifLevel is "mentions"', () => {
			render(ChannelList, {
				conversations: [conv({ channelId: 1, unreadCount: 5, hasMention: false, notifLevel: 'mentions' })],
				activeChannelId: null,
				selfUserId: 42,
				onSelect: noop,
				onNewChannel: noop,
				onNewDM: noop,
				onBrowse: noop,
			});
			expect(screen.queryByText('5')).toBeNull();
		});

		it('still shows the badge for a mention conversation muted to "mentions"', () => {
			render(ChannelList, {
				conversations: [conv({ channelId: 1, unreadCount: 5, hasMention: true, notifLevel: 'mentions' })],
				activeChannelId: null,
				selfUserId: 42,
				onSelect: noop,
				onNewChannel: noop,
				onNewDM: noop,
				onBrowse: noop,
			});
			expect(screen.getByText('5')).toBeTruthy();
		});

		it('shows the badge as normal when notifLevel is "all" (or absent, pre-Task-7 fixtures)', () => {
			render(ChannelList, {
				conversations: [conv({ channelId: 1, unreadCount: 5 })],
				activeChannelId: null,
				selfUserId: 42,
				onSelect: noop,
				onNewChannel: noop,
				onNewDM: noop,
				onBrowse: noop,
			});
			expect(screen.getByText('5')).toBeTruthy();
		});
	});
});
