import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import { tick } from 'svelte';
import ThreadPane from './ThreadPane.svelte';
import { chatStore, type StoreMessage } from '$lib/chat/store.svelte';
import type { ChatMessage } from '$lib/chat/api';

const threadMessages = vi.fn();
// A3 QoL Task 15: ThreadPane's own Composer instance calls
// chatStore.loadScheduled() on mount (the "N scheduled" chip) — stub it so
// that never fires an unstubbed network call in this suite.
const listScheduled = vi.fn();

vi.mock('$lib/chat/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/chat/api')>('$lib/chat/api');
	return {
		...actual,
		threadMessages: (...a: unknown[]) => threadMessages(...a),
		listScheduled: (...a: unknown[]) => listScheduled(...a),
	};
});

function msg(over: Partial<ChatMessage> = {}): StoreMessage {
	return {
		messageId: 1,
		channelId: 1,
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
		status: 'sent',
		...over,
	};
}

beforeEach(() => {
	threadMessages.mockReset();
	threadMessages.mockResolvedValue([]);
	listScheduled.mockReset();
	listScheduled.mockResolvedValue([]);
	chatStore.messagesByChannel = {};
	chatStore.activeChannelId = 1;
});

afterEach(() => {
	vi.clearAllMocks();
});

describe('ThreadPane', () => {
	it('fetches and renders root + replies ascending; the close button calls onClose', async () => {
		threadMessages.mockResolvedValue([msg({ messageId: 1, seq: 1, body: 'root' }), msg({ messageId: 2, seq: 2, body: 'a reply', parentMessageId: 1 })]);
		const onClose = vi.fn();
		render(ThreadPane, { parentId: 1, channelId: 1, onClose });

		await waitFor(() => expect(threadMessages).toHaveBeenCalledWith(1));
		await waitFor(() => expect(screen.getByText('root')).toBeTruthy());
		expect(screen.getByText('a reply')).toBeTruthy();

		await fireEvent.click(screen.getByLabelText('Close thread'));
		expect(onClose).toHaveBeenCalled();
	});

	it('renders its own composer defaulting parentId (thread placeholder text)', async () => {
		render(ThreadPane, { parentId: 1, channelId: 1, onClose: vi.fn() });
		await waitFor(() => expect(threadMessages).toHaveBeenCalled());
		expect(screen.getByPlaceholderText('Reply in thread…')).toBeTruthy();
	});

	it('a new reply landing in the store (live push) appears without a re-fetch', async () => {
		threadMessages.mockResolvedValue([msg({ messageId: 1, seq: 1, body: 'root' })]);
		render(ThreadPane, { parentId: 1, channelId: 1, onClose: vi.fn() });
		await waitFor(() => expect(screen.getByText('root')).toBeTruthy());
		expect(threadMessages).toHaveBeenCalledTimes(1);

		chatStore.messagesByChannel[1] = [
			{ ...msg({ messageId: 1, seq: 1, body: 'root' }), status: 'sent' },
			{ ...msg({ messageId: 2, seq: 2, body: 'live reply', parentMessageId: 1 }), status: 'sent' },
		];
		await tick();

		expect(screen.getByText('live reply')).toBeTruthy();
		expect(threadMessages).toHaveBeenCalledTimes(1);
	});

	it('Chat A2 Task 8 parity: a reply carrying an attachment renders through MessageRow unmodified (no ThreadPane-side wiring needed)', async () => {
		threadMessages.mockResolvedValue([
			msg({ messageId: 1, seq: 1, body: 'root' }),
			msg({
				messageId: 2,
				seq: 2,
				body: 'see attached',
				parentMessageId: 1,
				attachments: [{ id: 1, fileNodeId: 5, filename: 'notes.pdf', contentType: 'application/pdf', sizeBytes: 1024 }],
			}),
		]);
		render(ThreadPane, { parentId: 1, channelId: 1, onClose: vi.fn() });
		await waitFor(() => expect(screen.getByText('notes.pdf')).toBeTruthy());
	});

	it('re-fetches when parentId changes', async () => {
		threadMessages.mockResolvedValue([msg({ messageId: 1, seq: 1, body: 'root one' })]);
		const { rerender } = render(ThreadPane, { parentId: 1, channelId: 1, onClose: vi.fn() });
		await waitFor(() => expect(screen.getByText('root one')).toBeTruthy());

		threadMessages.mockResolvedValue([msg({ messageId: 5, seq: 5, body: 'root two' })]);
		await rerender({ parentId: 5, channelId: 1, onClose: vi.fn() });

		await waitFor(() => expect(threadMessages).toHaveBeenCalledWith(5));
		await waitFor(() => expect(screen.getByText('root two')).toBeTruthy());
	});
});
