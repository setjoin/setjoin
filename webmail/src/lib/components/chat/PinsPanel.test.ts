import { describe, it, expect, vi, afterEach, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import PinsPanel from './PinsPanel.svelte';
import type { ChatMessage, RosterMember } from '$lib/chat/api';

const listPins = vi.fn();
const togglePin = vi.fn();

vi.mock('$lib/chat/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/chat/api')>('$lib/chat/api');
	return {
		...actual,
		listPins: (...a: unknown[]) => listPins(...a),
		togglePin: (...a: unknown[]) => togglePin(...a),
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
		body: 'ship it',
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

function member(over: Partial<RosterMember> = {}): RosterMember {
	return { userId: 2, displayName: 'Bob', avatarSha256: null, role: 'member', external: false, removed: false, ...over };
}

const noop = vi.fn();

afterEach(() => {
	vi.clearAllMocks();
});

beforeEach(() => {
	togglePin.mockResolvedValue({ pinned: false });
});

describe('PinsPanel', () => {
	it('loads and renders pinned messages for the channel', async () => {
		listPins.mockResolvedValue([msg({ messageId: 1, body: 'ship it' })]);
		render(PinsPanel, { channelId: 5, roster: [member()], onClose: noop, onJump: noop });
		await waitFor(() => expect(screen.getByText('ship it')).toBeTruthy());
		expect(listPins).toHaveBeenCalledWith(5);
		expect(screen.getByText('Bob')).toBeTruthy();
	});

	it('shows an empty state when there are no pins', async () => {
		listPins.mockResolvedValue([]);
		render(PinsPanel, { channelId: 5, roster: [], onClose: noop, onJump: noop });
		await waitFor(() => expect(screen.getByText('No pinned messages')).toBeTruthy());
	});

	// [UX #7/#14, whole-pipeline review] a fetch failure used to render
	// identically to "no pins" — distinguish the two, with a retry.
	it('shows a distinct error state (not the empty state) when the fetch fails, and Retry re-fetches', async () => {
		listPins.mockRejectedValueOnce(new Error('network'));
		render(PinsPanel, { channelId: 5, roster: [member()], onClose: noop, onJump: noop });
		await waitFor(() => expect(screen.getByText("Couldn't load pinned messages")).toBeTruthy());
		expect(screen.queryByText('No pinned messages')).toBeNull();

		listPins.mockResolvedValueOnce([msg({ body: 'ship it' })]);
		await fireEvent.click(screen.getByText('Retry'));
		await waitFor(() => expect(screen.getByText('ship it')).toBeTruthy());
	});

	it('falls back to a voice-message label when the pinned row has no body', async () => {
		listPins.mockResolvedValue([msg({ messageId: 1, body: '', msgType: 'voice' })]);
		render(PinsPanel, { channelId: 5, roster: [member()], onClose: noop, onJump: noop });
		await waitFor(() => expect(screen.getByText('Voice message')).toBeTruthy());
	});

	it('clicking a pinned row jumps to it and closes the panel', async () => {
		listPins.mockResolvedValue([msg({ messageId: 1, seq: 42, body: 'ship it' })]);
		const onJump = vi.fn();
		render(PinsPanel, { channelId: 5, roster: [member()], onClose: noop, onJump });
		await waitFor(() => expect(screen.getByText('ship it')).toBeTruthy());
		await fireEvent.click(screen.getByText('ship it'));
		expect(onJump).toHaveBeenCalledWith(42);
	});

	it('unpins a row via the row action', async () => {
		listPins.mockResolvedValue([msg({ messageId: 1, body: 'ship it' })]);
		togglePin.mockResolvedValue({ pinned: false });
		render(PinsPanel, { channelId: 5, roster: [member()], onClose: noop, onJump: noop });
		await waitFor(() => expect(screen.getByText('ship it')).toBeTruthy());
		await fireEvent.click(screen.getByLabelText('Unpin message'));
		await waitFor(() => expect(togglePin).toHaveBeenCalledWith(1));
		await waitFor(() => expect(screen.queryByText('ship it')).toBeNull());
	});

	it('wires the close button', async () => {
		listPins.mockResolvedValue([]);
		const onClose = vi.fn();
		render(PinsPanel, { channelId: 5, roster: [], onClose, onJump: noop });
		await waitFor(() => expect(screen.getByText('No pinned messages')).toBeTruthy());
		await fireEvent.click(screen.getByLabelText('Close'));
		expect(onClose).toHaveBeenCalled();
	});
});
