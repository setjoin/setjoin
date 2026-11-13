import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import SavedView from './SavedView.svelte';
import { chatStore } from '$lib/chat/store.svelte';
import type { ChatMessage, Conversation } from '$lib/chat/api';

const listSaves = vi.fn();
const toggleSave = vi.fn();

vi.mock('$lib/chat/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/chat/api')>('$lib/chat/api');
	return {
		...actual,
		listSaves: (...a: unknown[]) => listSaves(...a),
		toggleSave: (...a: unknown[]) => toggleSave(...a),
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
		body: 'remember this',
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
});

beforeEach(() => {
	toggleSave.mockResolvedValue({ saved: false });
});

describe('SavedView', () => {
	it('loads and renders saved messages with their channel name', async () => {
		chatStore.conversations = [conv()];
		listSaves.mockResolvedValue([msg({ channelId: 5, body: 'remember this' })]);
		render(SavedView, { onJump: noop });
		await waitFor(() => expect(screen.getByText('remember this')).toBeTruthy());
		expect(screen.getByText('eng')).toBeTruthy();
	});

	it('shows an empty state when nothing is saved', async () => {
		listSaves.mockResolvedValue([]);
		render(SavedView, { onJump: noop });
		await waitFor(() => expect(screen.getByText('No saved messages yet')).toBeTruthy());
	});

	// [UX #7/#14, whole-pipeline review] a fetch failure used to render
	// identically to "nothing saved" — distinguish the two, with a retry.
	it('shows a distinct error state (not the empty state) when the fetch fails, and Retry re-fetches', async () => {
		listSaves.mockRejectedValueOnce(new Error('network'));
		render(SavedView, { onJump: noop });
		await waitFor(() => expect(screen.getByText("Couldn't load saved messages")).toBeTruthy());
		expect(screen.queryByText('No saved messages yet')).toBeNull();

		listSaves.mockResolvedValueOnce([msg({ body: 'remember this' })]);
		await fireEvent.click(screen.getByText('Retry'));
		await waitFor(() => expect(screen.getByText('remember this')).toBeTruthy());
	});

	it('clicking a row jumps to its channel + seq', async () => {
		chatStore.conversations = [conv()];
		listSaves.mockResolvedValue([msg({ channelId: 5, seq: 77, body: 'remember this' })]);
		const onJump = vi.fn();
		render(SavedView, { onJump });
		await waitFor(() => expect(screen.getByText('remember this')).toBeTruthy());
		await fireEvent.click(screen.getByText('remember this'));
		expect(onJump).toHaveBeenCalledWith(5, 77);
	});

	it('unsaves a row via the row action', async () => {
		listSaves.mockResolvedValue([msg({ messageId: 9, body: 'remember this' })]);
		toggleSave.mockResolvedValue({ saved: false });
		render(SavedView, { onJump: noop });
		await waitFor(() => expect(screen.getByText('remember this')).toBeTruthy());
		await fireEvent.click(screen.getByLabelText('Remove from saved'));
		await waitFor(() => expect(toggleSave).toHaveBeenCalledWith(9));
		await waitFor(() => expect(screen.queryByText('remember this')).toBeNull());
	});
});
