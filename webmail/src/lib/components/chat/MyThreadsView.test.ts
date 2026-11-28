import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import MyThreadsView from './MyThreadsView.svelte';
import { chatStore } from '$lib/chat/store.svelte';
import type { ChatThread, Conversation } from '$lib/chat/api';

const listMyThreads = vi.fn();

vi.mock('$lib/chat/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/chat/api')>('$lib/chat/api');
	return {
		...actual,
		listMyThreads: (...a: unknown[]) => listMyThreads(...a),
	};
});

function thread(over: Partial<ChatThread> = {}): ChatThread {
	return {
		messageId: 1,
		channelId: 5,
		seq: 10,
		authorId: 2,
		body: 'kick off the thread',
		createdAt: '2026-07-12T00:00:00Z',
		replyCount: 3,
		lastReplyAt: '2026-07-12T01:00:00Z',
		unreadCount: 2,
		...over,
	};
}

function conv(over: Partial<Conversation> = {}): Conversation {
	return {
		channelId: 5,
		kind: 'channel',
		name: 'eng',
		topic: null,
		changeSeq: 1,
		lastReadSeq: 1,
		unreadCount: 0,
		hasMention: false,
		hasExternalMembers: false,
		lastMessagePreview: null,
		memberIds: [],
		...over,
	};
}

const noop = vi.fn();

afterEach(() => {
	vi.clearAllMocks();
	chatStore.conversations = [];
});

describe('MyThreadsView', () => {
	it('loads and renders threads with channel name, reply count and unread badge', async () => {
		chatStore.conversations = [conv()];
		listMyThreads.mockResolvedValue([thread()]);
		render(MyThreadsView, { onJump: noop });
		await waitFor(() => expect(screen.getByText('kick off the thread')).toBeTruthy());
		expect(screen.getByText('eng')).toBeTruthy();
		expect(screen.getByText('2')).toBeTruthy(); // unread badge
	});

	it('shows an empty state when there are no threads', async () => {
		listMyThreads.mockResolvedValue([]);
		render(MyThreadsView, { onJump: noop });
		await waitFor(() => expect(screen.getByText('No threads yet')).toBeTruthy());
	});

	// [UX #7/#14, whole-pipeline review] a fetch failure used to render
	// identically to "no threads" — distinguish the two, with a retry.
	it('shows a distinct error state (not the empty state) when the fetch fails, and Retry re-fetches', async () => {
		listMyThreads.mockRejectedValueOnce(new Error('network'));
		render(MyThreadsView, { onJump: noop });
		await waitFor(() => expect(screen.getByText("Couldn't load threads")).toBeTruthy());
		expect(screen.queryByText('No threads yet')).toBeNull();

		listMyThreads.mockResolvedValueOnce([thread()]);
		await fireEvent.click(screen.getByText('Retry'));
		await waitFor(() => expect(screen.getByText('kick off the thread')).toBeTruthy());
	});

	it('clicking a thread jumps to its channel + seq', async () => {
		chatStore.conversations = [conv()];
		listMyThreads.mockResolvedValue([thread({ channelId: 5, seq: 88 })]);
		const onJump = vi.fn();
		render(MyThreadsView, { onJump });
		await waitFor(() => expect(screen.getByText('kick off the thread')).toBeTruthy());
		await fireEvent.click(screen.getByText('kick off the thread'));
		expect(onJump).toHaveBeenCalledWith(5, 88);
	});

	it('omits the unread badge for a read thread', async () => {
		listMyThreads.mockResolvedValue([thread({ unreadCount: 0 })]);
		render(MyThreadsView, { onJump: noop });
		await waitFor(() => expect(screen.getByText('kick off the thread')).toBeTruthy());
		expect(screen.queryByText('0')).toBeNull();
	});
});
