// MessageBodyPoll.test.ts — the poll msg_type genre, split out of
// MessageRow.test.ts (whole-pipeline review arch #9: MessageRow's per-genre
// body renderers moved to their own components). MessageRow.test.ts keeps
// one thin smoke test proving the dispatch chain still mounts this
// component for a poll message; every other poll behavior lives here.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import MessageBodyPoll from './MessageBodyPoll.svelte';
import { chatStore, type StoreMessage } from '$lib/chat/store.svelte';
import type { ChatMessage, ChatPollResults } from '$lib/chat/api';
import * as chatApi from '$lib/chat/api';
import { toasts, clearToasts } from '$lib/components/ui';

vi.mock('$lib/chat/api');

// $lib/chat/api is bare-automocked — vitest keeps the ChatError prototype
// chain (so `instanceof` still works, which is all chatErrorMessage relies
// on) but does NOT run the real constructor body, so `code`/`detail` land
// undefined unless stamped back on afterward (verified empirically in
// MessageRow.test.ts, the precedent this file was split from).
function chatError(code: string, detail: string): chatApi.ChatError {
	return Object.assign(new chatApi.ChatError({ status: 409, code, detail }), { code, detail });
}

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
	};
}

function pollMsg(over: Partial<ChatMessage> = {}): StoreMessage {
	return msg({ messageId: 30, msgType: 'poll', body: 'Pick one', payload: { pollId: 77 }, ...over }) as StoreMessage;
}
function results(over: Partial<ChatPollResults> = {}): ChatPollResults {
	return {
		pollId: 77,
		question: 'Pick one',
		multi: false,
		closesAt: null,
		closed: false,
		options: [
			{ optionId: 1, ordinal: 0, label: 'Tea', count: 2, voters: [1, 2] },
			{ optionId: 2, ordinal: 1, label: 'Coffee', count: 0, voters: [] },
		],
		...over,
	};
}

const baseProps = { isMine: false, canModerate: false };

beforeEach(() => {
	chatStore.pollResultsByPollId = {};
	chatStore.selfUserId = null;
});

afterEach(() => {
	vi.clearAllMocks();
});

describe('MessageBodyPoll', () => {
	it('loads results on render and renders question/options as an accessible radiogroup with tallies', async () => {
		vi.mocked(chatApi.pollResults).mockResolvedValue(results());
		render(MessageBodyPoll, { ...baseProps, message: pollMsg() });
		await waitFor(() => expect(chatApi.pollResults).toHaveBeenCalledWith(77));
		await waitFor(() => expect(screen.getByText('Pick one')).toBeTruthy());
		expect(screen.getByRole('radiogroup')).toBeTruthy();
		expect(screen.getByLabelText('Tea')).toBeTruthy();
		expect(screen.getByLabelText('Coffee')).toBeTruthy();
		expect(screen.getByText('2 votes')).toBeTruthy();
		// fixed row footprint: the zero-vote option still renders its count row (no
		// conditional DOM add/remove as tallies change), never a vacuous height jump.
		expect(screen.getAllByText(/vote/).length).toBe(2);
	});

	it('voting calls chatApi.votePoll then reloads results', async () => {
		vi.mocked(chatApi.pollResults).mockResolvedValue(results());
		vi.mocked(chatApi.votePoll).mockResolvedValue(undefined);
		render(MessageBodyPoll, { ...baseProps, message: pollMsg() });
		await waitFor(() => expect(screen.getByLabelText('Coffee')).toBeTruthy());
		await fireEvent.click(screen.getByLabelText('Coffee'));
		expect(chatApi.votePoll).toHaveBeenCalledWith(77, 2);
		await waitFor(() => expect(chatApi.pollResults).toHaveBeenCalledTimes(2));
	});

	// [UX #7/#14, whole-pipeline review] both used to fail silently/unhandled.
	it('a rejected votePoll toasts instead of failing silently', async () => {
		vi.mocked(chatApi.pollResults).mockResolvedValue(results());
		vi.mocked(chatApi.votePoll).mockRejectedValue(chatError('BZ161', 'access denied'));
		render(MessageBodyPoll, { ...baseProps, message: pollMsg() });
		await waitFor(() => expect(screen.getByLabelText('Coffee')).toBeTruthy());
		await fireEvent.click(screen.getByLabelText('Coffee'));
		await waitFor(() => expect(toasts.at(-1)?.message).toBe('access denied'));
		expect(toasts.at(-1)?.variant).toBe('danger');
		clearToasts();
	});

	it('a rejected closePoll toasts instead of throwing an unhandled rejection', async () => {
		vi.mocked(chatApi.pollResults).mockResolvedValue(results());
		vi.mocked(chatApi.closePoll).mockRejectedValue(chatError('BZ161', 'access denied'));
		render(MessageBodyPoll, { message: pollMsg({ authorId: 1 }), isMine: true, canModerate: false });
		await waitFor(() => expect(screen.getByText('Close poll')).toBeTruthy());
		await fireEvent.click(screen.getByText('Close poll'));
		await waitFor(() => expect(toasts.at(-1)?.message).toBe('access denied'));
		expect(toasts.at(-1)?.variant).toBe('danger');
		clearToasts();
	});

	it('a closed poll shows "Final results" and disables every option', async () => {
		vi.mocked(chatApi.pollResults).mockResolvedValue(results({ closed: true }));
		render(MessageBodyPoll, { ...baseProps, message: pollMsg() });
		await waitFor(() => expect(screen.getByText('Final results')).toBeTruthy());
		expect((screen.getByLabelText('Tea') as HTMLInputElement).disabled).toBe(true);
	});

	it('the poll creator (isMine) can close an open poll even without canModerate', async () => {
		vi.mocked(chatApi.pollResults).mockResolvedValue(results());
		vi.mocked(chatApi.closePoll).mockResolvedValue(undefined);
		render(MessageBodyPoll, { message: pollMsg({ authorId: 1 }), isMine: true, canModerate: false });
		await waitFor(() => expect(screen.getByText('Close poll')).toBeTruthy());
		await fireEvent.click(screen.getByText('Close poll'));
		expect(chatApi.closePoll).toHaveBeenCalledWith(77);
	});

	it('a non-creator, non-admin member sees no Close action', async () => {
		vi.mocked(chatApi.pollResults).mockResolvedValue(results());
		render(MessageBodyPoll, { message: pollMsg({ authorId: 99 }), isMine: false, canModerate: false });
		await waitFor(() => expect(screen.getByText('Pick one')).toBeTruthy());
		expect(screen.queryByText('Close poll')).toBeNull();
	});

	it('multi-select polls render checkboxes, not radios', async () => {
		vi.mocked(chatApi.pollResults).mockResolvedValue(results({ multi: true }));
		render(MessageBodyPoll, { ...baseProps, message: pollMsg() });
		await waitFor(() => expect(screen.getByLabelText('Tea')).toBeTruthy());
		expect((screen.getByLabelText('Tea') as HTMLInputElement).type).toBe('checkbox');
	});
});
