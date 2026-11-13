import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import SearchView from './SearchView.svelte';
import { chatStore } from '$lib/chat/store.svelte';
import { toasts, clearToasts } from '$lib/components/ui';
import type { ChatMessage, Conversation } from '$lib/chat/api';

const searchMessages = vi.fn();

vi.mock('$lib/chat/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/chat/api')>('$lib/chat/api');
	return {
		...actual,
		searchMessages: (...a: unknown[]) => searchMessages(...a),
	};
});

function msg(over: Partial<ChatMessage> = {}): ChatMessage {
	return {
		messageId: 1,
		channelId: 5,
		seq: 10,
		authorId: 2,
		authorExternal: false,
		authorRemoved: false,
		parentMessageId: null,
		msgType: 'text',
		broadcast: null,
		body: 'deploy the change',
		editedAt: null,
		deletedAt: null,
		createdAt: '2026-07-12T00:00:00Z',
		reactions: [],
		mentionsMe: false,
		replyCount: 0,
		lastReplyAt: null,
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
	clearToasts();
});

describe('SearchView', () => {
	it('shows a prompt before any search has run', () => {
		render(SearchView, { onJump: noop });
		expect(screen.getByText('Search across your channels and direct messages')).toBeTruthy();
	});

	it('submits the query on Enter and renders results grouped by channel', async () => {
		chatStore.conversations = [conv({ channelId: 5, name: 'eng' })];
		searchMessages.mockResolvedValue([msg({ channelId: 5, body: 'deploy the change' })]);
		render(SearchView, { onJump: noop });
		const input = screen.getByPlaceholderText('Search messages');
		await fireEvent.input(input, { target: { value: 'deploy' } });
		await fireEvent.keyDown(input, { key: 'Enter' });
		await waitFor(() => expect(searchMessages).toHaveBeenCalledWith('deploy', {}));
		await waitFor(() => expect(screen.getByText('deploy the change')).toBeTruthy());
		expect(screen.getByText('eng')).toBeTruthy();
	});

	it('shows an empty state for zero results', async () => {
		searchMessages.mockResolvedValue([]);
		render(SearchView, { onJump: noop });
		const input = screen.getByPlaceholderText('Search messages');
		await fireEvent.input(input, { target: { value: 'nothing' } });
		await fireEvent.keyDown(input, { key: 'Enter' });
		await waitFor(() => expect(screen.getByText('No results')).toBeTruthy());
	});

	// [UX #7/#14, whole-pipeline review] a fetch failure used to render
	// identically to "zero results" — distinguish the two, with a retry.
	it('shows a distinct error state (not the empty state) when the search fails, and Retry re-runs it', async () => {
		searchMessages.mockRejectedValueOnce(new Error('network'));
		render(SearchView, { onJump: noop });
		const input = screen.getByPlaceholderText('Search messages');
		await fireEvent.input(input, { target: { value: 'deploy' } });
		await fireEvent.keyDown(input, { key: 'Enter' });
		await waitFor(() => expect(screen.getByText('Search failed')).toBeTruthy());
		expect(screen.queryByText('No results')).toBeNull();

		searchMessages.mockResolvedValueOnce([msg({ body: 'deploy the change' })]);
		await fireEvent.click(screen.getByText('Retry'));
		await waitFor(() => expect(screen.getByText('deploy the change')).toBeTruthy());
	});

	it('a failed load-more toasts instead of blowing away the already-visible results', async () => {
		const page = Array.from({ length: 50 }, (_, i) => msg({ messageId: i + 1, body: `hit ${i}` }));
		searchMessages.mockResolvedValueOnce(page);
		render(SearchView, { onJump: noop });
		const input = screen.getByPlaceholderText('Search messages');
		await fireEvent.input(input, { target: { value: 'deploy' } });
		await fireEvent.keyDown(input, { key: 'Enter' });
		await waitFor(() => expect(screen.getByText('Load more')).toBeTruthy());

		searchMessages.mockRejectedValueOnce(new Error('network'));
		await fireEvent.click(screen.getByText('Load more'));
		await waitFor(() => expect(toasts.at(-1)?.message).toBe('Search failed'));
		expect(toasts.at(-1)?.variant).toBe('danger');
		expect(screen.getByText('hit 0')).toBeTruthy(); // existing results untouched
	});

	it('clicking a result jumps to its channel + seq', async () => {
		chatStore.conversations = [conv({ channelId: 5, name: 'eng' })];
		searchMessages.mockResolvedValue([msg({ channelId: 5, seq: 55, body: 'deploy the change' })]);
		const onJump = vi.fn();
		render(SearchView, { onJump });
		const input = screen.getByPlaceholderText('Search messages');
		await fireEvent.input(input, { target: { value: 'deploy' } });
		await fireEvent.keyDown(input, { key: 'Enter' });
		await waitFor(() => expect(screen.getByText('deploy the change')).toBeTruthy());
		await fireEvent.click(screen.getByText('deploy the change'));
		expect(onJump).toHaveBeenCalledWith(5, 55);
	});

	it('pre-scopes to a channel when initialChannelId is provided, with a checkbox to broaden', async () => {
		chatStore.conversations = [conv({ channelId: 5, name: 'eng' })];
		searchMessages.mockResolvedValue([]);
		render(SearchView, { onJump: noop, initialChannelId: 5 });
		const input = screen.getByPlaceholderText('Search messages');
		await fireEvent.input(input, { target: { value: 'deploy' } });
		await fireEvent.keyDown(input, { key: 'Enter' });
		await waitFor(() => expect(searchMessages).toHaveBeenCalledWith('deploy', { in: 5 }));

		await fireEvent.click(screen.getByLabelText('This channel only'));
		await fireEvent.keyDown(input, { key: 'Enter' });
		await waitFor(() => expect(searchMessages).toHaveBeenLastCalledWith('deploy', {}));
	});

	it('an initialQuery pre-fills and auto-runs the search', async () => {
		chatStore.conversations = [conv({ channelId: 5, name: 'eng' })];
		searchMessages.mockResolvedValue([msg({ channelId: 5, body: 'deploy the change' })]);
		render(SearchView, { onJump: noop, initialQuery: 'deploy' });
		await waitFor(() => expect(searchMessages).toHaveBeenCalledWith('deploy', {}));
		await waitFor(() => expect(screen.getByText('deploy the change')).toBeTruthy());
	});
});
