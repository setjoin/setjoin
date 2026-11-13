import { afterEach, describe, expect, it, vi } from 'vitest';
import { sinceMessages, type ChatMessage } from './api';

function message(seq: number): ChatMessage {
	return {
		messageId: seq,
		channelId: 10,
		seq,
		authorId: 1,
		authorExternal: false,
		authorRemoved: false,
		parentMessageId: null,
		msgType: 'text',
		broadcast: null,
		body: `message ${seq}`,
		editedAt: null,
		deletedAt: null,
		createdAt: '2026-07-20T00:00:00Z',
		reactions: [],
		mentionsMe: false,
		replyCount: 0,
		lastReplyAt: null,
	};
}

describe('chat replay cursor', () => {
	afterEach(() => vi.unstubAllGlobals());

	it('keeps the message-array HTTP body internal while lifting the cursor header into the client envelope', async () => {
		const fetchMock = vi.fn().mockResolvedValue(
			new Response(JSON.stringify([]), {
				status: 200,
				headers: { 'Content-Type': 'application/json', 'X-Setjoin-Chat-Cursor': '6' },
			}),
		);
		vi.stubGlobal('fetch', fetchMock);

		await expect(sinceMessages(10, 5)).resolves.toEqual({ messages: [], cursor: 6 });
		expect(fetchMock).toHaveBeenCalledWith('/api/chat/channels/10/messages/since?seq=5', expect.any(Object));
	});

	it('falls back monotonically to the largest safe row cursor when an older gateway omits the header', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn().mockResolvedValue(
				new Response(JSON.stringify([message(7)]), {
					status: 200,
					headers: { 'Content-Type': 'application/json' },
				}),
			),
		);

		await expect(sinceMessages(10, 5)).resolves.toEqual({ messages: [message(7)], cursor: 7 });
	});
});
