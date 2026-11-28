// MessageBodyCall.test.ts — the `call` msg_type genre (Meet B1 Task 16),
// split out of MessageRow.test.ts (whole-pipeline review arch #9).
// MessageRow.test.ts keeps a couple of thin smoke tests (dispatch-chain
// mount + the deleted-message blanking, which is dispatch-chain behavior,
// not this genre's own) — every other call-card behavior lives here.
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import MessageBodyCall from './MessageBodyCall.svelte';
import { jmapSession } from '$lib/stores/session';
import { goto } from '$app/navigation';
import type { StoreMessage } from '$lib/chat/store.svelte';
import type { ChatMessage } from '$lib/chat/api';

const resolveSlug = vi.fn();
vi.mock('$lib/meet/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/meet/api')>('$lib/meet/api');
	return { ...actual, resolveSlug: (...a: unknown[]) => resolveSlug(...a) };
});

function msg(over: Partial<StoreMessage> = {}): StoreMessage {
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
	} as StoreMessage;
}

function callMsg(over: Partial<ChatMessage> = {}): StoreMessage {
	return msg({
		messageId: 40,
		msgType: 'call',
		body: 'Standup',
		payload: { meetingId: 9, slug: 'abc123', title: 'Standup' },
		...over,
	}) as StoreMessage;
}

afterEach(() => {
	vi.clearAllMocks();
	jmapSession.set(null);
});

describe('MessageBodyCall', () => {
	it('renders the meeting title and a Join button for a live meeting, which deep-links via /meet?slug=…', async () => {
		resolveSlug.mockResolvedValue({ meetingId: 9, state: 'live' });
		render(MessageBodyCall, { message: callMsg() });
		expect(screen.getByText('Standup')).toBeTruthy();
		await fireEvent.click(screen.getByText('Join'));
		expect(resolveSlug).toHaveBeenCalledWith('abc123');
		await waitFor(() => expect(goto).toHaveBeenCalledWith('/meet?slug=abc123'));
	});

	it('swaps the card to "Meeting ended" on a BZ190 resolve result instead of navigating into a dead join', async () => {
		const { MeetError } = await vi.importActual<typeof import('$lib/meet/api')>('$lib/meet/api');
		resolveSlug.mockRejectedValue(new MeetError({ status: 409, code: 'BZ190', detail: 'ended' }));
		render(MessageBodyCall, { message: callMsg() });
		await fireEvent.click(screen.getByText('Join'));
		await waitFor(() => expect(screen.getByText('The meeting has ended.')).toBeTruthy());
		expect(screen.queryByText('Join')).toBeNull();
		expect(goto).not.toHaveBeenCalled();
	});

	// [UX #4, pipeline review] with feature.meet OFF, Join used to dead-end
	// into the Mail app (a code-less 404 on /api/meet/*, then the layout
	// guard silently bouncing to $firstEnabledApp) — no explanation offered.
	// Fixed by hiding Join (and never resolving/navigating) whenever 'meet'
	// is absent from $effectiveCaps.enabledApps, the same signal MeetApp
	// itself gates on.
	it('hides the Join button and shows "Meeting unavailable" when feature.meet is OFF (meet absent from enabledApps)', async () => {
		jmapSession.set({ effectiveCapabilities: { apps: { meet: false }, features: { assist: false, bundles: false } } } as never);
		render(MessageBodyCall, { message: callMsg() });
		expect(screen.getByText('Standup')).toBeTruthy();
		expect(screen.queryByText('Join')).toBeNull();
		expect(screen.getByText('Meeting unavailable')).toBeTruthy();
		expect(resolveSlug).not.toHaveBeenCalled();
	});
});
