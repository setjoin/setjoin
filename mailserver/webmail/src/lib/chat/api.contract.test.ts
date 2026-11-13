import { beforeEach, describe, expect, it, vi } from 'vitest';

const transport = vi.hoisted(() => vi.fn().mockResolvedValue({}));
const responseTransport = vi.hoisted(() => vi.fn());

vi.mock('$lib/http', () => {
	class ProblemError extends Error {}
	return {
		ProblemError,
		problemFetch: () => ({ fetch: transport, fetchVoid: transport, fetchResponse: responseTransport }),
	};
});

import * as chat from './api';

type Contract = [name: keyof typeof chat, args: unknown[], path: string, method?: string];

const contracts: Contract[] = [
	['listConversations', [], '/conversations'],
	['createChannel', [{ name: 'Ops', visibility: 'private' }], '/channels', 'POST'],
	['openDM', [[7, 8]], '/dm', 'POST'],
	['openFederatedDM', ['user@peer.test'], '/dm/federated', 'POST'],
	['bindFederationRoom', [3], '/channels/3/federation', 'POST'],
	['inviteFederationMember', [3, 'peer.test', 'admin@peer.test'], '/channels/3/federation/invite', 'POST'],
	['removeFederationMember', [3, 'peer.test'], '/channels/3/federation/remove', 'POST'],
	['getFederationRoomRoster', [3], '/channels/3/federation'],
	['browseChannels', [], '/channels/browse'],
	['joinChannel', [3], '/channels/3/join', 'POST'],
	['updateChannel', [3, { topic: 'Launch' }], '/channels/3', 'PATCH'],
	['addMember', [3, 7], '/channels/3/members', 'POST'],
	['previewGuest', [3, 'guest@example.test'], '/channels/3/members/guest-preview', 'POST'],
	['removeMember', [3, 7], '/channels/3/members/7', 'DELETE'],
	['listMembers', [3], '/channels/3/members'],
	['searchMembers', [3, 'Ada & Bob'], '/channels/3/members/search?q=Ada%20%26%20Bob'],
	['sendMessage', [3, 'hello'], '/channels/3/messages', 'POST'],
	['sendMessage', [3, 'voice', 9, [7], 'all', [], 'voice', { durationMs: 12 }], '/channels/3/messages', 'POST'],
	['ensureSpace', [3], '/channels/3/space', 'POST'],
	['listMessages', [3], '/channels/3/messages'],
	['listMessages', [3, { beforeSeq: 8, limit: 20, aroundSeq: 4 }], '/channels/3/messages?beforeSeq=8&limit=20&aroundSeq=4'],
	['threadMessages', [9], '/messages/9/thread'],
	['editMessage', [9, 'updated'], '/messages/9', 'PATCH'],
	['deleteMessage', [9], '/messages/9', 'DELETE'],
	['toggleReaction', [9, '👍'], '/messages/9/reactions', 'POST'],
	['markRead', [3, 12], '/channels/3/read', 'POST'],
	['sendTyping', [3], '/channels/3/typing', 'POST'],
	['getPresence', [[7, 8]], '/presence?userIds=7,8'],
	['togglePin', [9], '/messages/9/pin', 'POST'],
	['listPins', [3], '/channels/3/pins'],
	['toggleSave', [9], '/messages/9/save', 'POST'],
	['listSaves', [], '/saves'],
	['getChannelReaders', [3], '/channels/3/readers'],
	['translateMessage', [9, 'zh-CN'], '/messages/9/translate', 'POST'],
	['scheduleMessage', [3, 'later', { fireAt: '2026-01-01T00:00:00Z' }], '/channels/3/messages/schedule', 'POST'],
	['scheduleMessage', [3, 'reply', { parentId: 9, mentions: [7], broadcast: 'all', fireAt: '2026-01-01T00:00:00Z' }], '/channels/3/messages/schedule', 'POST'],
	['listScheduled', [], '/scheduled'],
	['cancelScheduled', ['job/1'], '/scheduled/job%2F1', 'DELETE'],
	['createPoll', [3, 'Lunch?', ['A', 'B']], '/channels/3/polls', 'POST'],
	['createPoll', [3, 'Lunch?', ['A', 'B'], true, '2026-01-01T00:00:00Z'], '/channels/3/polls', 'POST'],
	['votePoll', [4, 2], '/polls/4/vote', 'POST'],
	['closePoll', [4], '/polls/4/close', 'POST'],
	['pollResults', [4], '/polls/4/results'],
	['searchMessages', ['launch'], '/search?q=launch'],
	['searchMessages', ['launch', { in: 3, from: 7, before: 9, has: 'attachment' }], '/search?q=launch&in=3&from=7&before=9&has=attachment'],
	['listMyThreads', [], '/my-threads'],
	['listMyThreads', [10], '/my-threads?limit=10'],
	['setChannelNotif', [3, 'mentions'], '/channels/3/notif', 'PUT'],
];

describe('Chat REST helper endpoint contracts', () => {
	beforeEach(() => {
		transport.mockClear();
		responseTransport.mockReset();
	});

	it.each(contracts)('%s preserves its endpoint and HTTP method', async (name, args, path, method = 'GET') => {
		const invoke = chat[name] as unknown as (...values: unknown[]) => Promise<unknown>;
		await invoke(...args);
		expect(transport).toHaveBeenCalledTimes(1);
		const [actualPath, options = {}] = transport.mock.calls[0] as [string, RequestInit?];
		expect(actualPath).toBe(path);
		expect(options.method ?? 'GET').toBe(method);
	});

	it('encodes the unfurl image URL', () => {
		expect(chat.unfurlImageUrl('abc')).toBe('/api/chat/unfurl/image/abc');
		expect(chat.unfurlImageUrl('../../secret')).toBe('/api/chat/unfurl/image/..%2F..%2Fsecret');
	});

	it.each([
		[null, [{ seq: 11 }, { seq: 14 }], 14],
		['18', [{ seq: 14 }], 18],
		['bad', [{ seq: 14 }], 14],
		['-1', [], 10],
	])('uses a safe replay cursor for header %s', async (header, messages, expected) => {
		responseTransport.mockResolvedValue({
			json: async () => messages,
			headers: { get: () => header },
		});
		await expect(chat.sinceMessages(3, 10)).resolves.toEqual({ messages, cursor: expected });
		expect(responseTransport).toHaveBeenCalledWith('/channels/3/messages/since?seq=10');
	});
});
