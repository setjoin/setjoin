import { describe, it, expect, beforeEach, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { join as joinPath } from 'node:path';
import { stubFetchRoutes } from '$lib/test-utils';
import {
	createMeeting,
	listMeetings,
	getMeeting,
	resolveSlug,
	join,
	lock,
	setGuestAllowed,
	setRole,
	kick,
	end,
	decideRequest,
	knock,
	guestJoinRequest,
	guestPoll,
	MeetError,
	openBreakouts,
	assignBreakout,
	closeBreakouts,
	joinBreakout,
} from './api';

vi.mock('$lib/auth/dpop', () => ({
	peekDpopKey: vi.fn(),
	peekDpopKeySync: vi.fn(() => null),
	accessTokenForProofs: vi.fn(() => null),
	// stores/auth.ts (r4) registers its auth-generation bump on this at import
	// time — the partial mock must export it or the suite fails to even load.
	onRecoveredAccessTokenRotation: vi.fn(() => () => {})
}));

beforeEach(() => {
	vi.unstubAllGlobals();
});

describe('meet/api.ts — authed routes', () => {
	it('createMeeting POSTs to /api/meet with the body and returns the create-shape', async () => {
		const fetchMock = stubFetchRoutes([
			['/api/meet', { meetingId: 1, slug: 'abc123xyz01', roomName: 'room-uuid', chatChannelId: null }],
		]);
		const result = await createMeeting({ title: 'Standup' });
		expect(result).toEqual({ meetingId: 1, slug: 'abc123xyz01', roomName: 'room-uuid', chatChannelId: null });

		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe('/api/meet');
		expect(init.method).toBe('POST');
		expect(JSON.parse(init.body as string)).toEqual({ title: 'Standup' });
	});

	it('listMeetings GETs /api/meet with no trailing slash', async () => {
		const fetchMock = stubFetchRoutes([['/api/meet', []]]);
		await listMeetings();
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe('/api/meet');
		expect(init.method ?? 'GET').toBe('GET');
	});

	it('getMeeting GETs /api/meet/{id}', async () => {
		stubFetchRoutes([['/api/meet/42', { meetingId: 42 }]]);
		const m = await getMeeting(42);
		expect(m.meetingId).toBe(42);
	});

	it('getMeeting defaults the B3 breakout/captions keys when a pre-Task-7 server response omits them', async () => {
		stubFetchRoutes([['/api/meet/42', { meetingId: 42 }]]);
		const m = await getMeeting(42);
		expect(m.breakoutsEnabled).toBe(false);
		expect(m.breakouts).toEqual([]);
		expect(m.myBreakoutId).toBeNull();
		expect(m.captionsEnabled).toBe(false);
		expect(m.captionsOn).toBe(false);
	});

	// [pipeline review, V131] chatChannelMember defaults true when a pre-V131
	// server response omits it — every bound channel WAS auto-join before
	// this fix, so a provisioned meeting must behave identically for an old
	// server. Passes through a real `false` unchanged for the huddle case.
	it('getMeeting defaults chatChannelMember to true when a pre-V131 server response omits it', async () => {
		stubFetchRoutes([['/api/meet/42', { meetingId: 42, chatChannelId: 5 }]]);
		const m = await getMeeting(42);
		expect(m.chatChannelMember).toBe(true);
	});

	it('getMeeting passes through a real chatChannelMember:false (a huddle-bound channel the caller never joined)', async () => {
		stubFetchRoutes([['/api/meet/42', { meetingId: 42, chatChannelId: 5, chatChannelMember: false }]]);
		const m = await getMeeting(42);
		expect(m.chatChannelMember).toBe(false);
	});

	it('getMeeting passes through real B3 keys when the server already sends them', async () => {
		stubFetchRoutes([
			[
				'/api/meet/42',
				{
					meetingId: 42,
					breakoutsEnabled: true,
					breakouts: [{ breakoutId: 1, idx: 1, title: null }],
					myBreakoutId: 1,
					captionsEnabled: true,
					captionsOn: true,
				},
			],
		]);
		const m = await getMeeting(42);
		expect(m.breakoutsEnabled).toBe(true);
		expect(m.breakouts).toEqual([{ breakoutId: 1, idx: 1, title: null }]);
		expect(m.myBreakoutId).toBe(1);
		expect(m.captionsOn).toBe(true);
	});

	it('resolveSlug GETs /api/meet/by-slug/{slug}, URL-encoded', async () => {
		const fetchMock = stubFetchRoutes([['/api/meet/by-slug/', { meetingId: 9, slug: 'a b' }]]);
		await resolveSlug('a b');
		const [url] = fetchMock.mock.calls[0] as [string];
		expect(url).toBe('/api/meet/by-slug/a%20b');
	});

	it('join POSTs to /api/meet/{id}/join and returns the token envelope', async () => {
		stubFetchRoutes([
			['/api/meet/7/join', { token: 't', wsPath: '/rtc', expiresAt: '2026-01-01T00:00:00Z', meeting: { meetingId: 7 } }],
		]);
		const result = await join(7);
		expect(result.token).toBe('t');
		expect(result.meeting.meetingId).toBe(7);
	});

	it('lock POSTs {locked} and resolves on a 204 (no json parse)', async () => {
		const fetchMock = stubFetchRoutes([['/api/meet/5/lock', { ok: true, status: 204, json: async () => { throw new Error('no body'); }, text: async () => '' }]]);
		await expect(lock(5, true)).resolves.toBeUndefined();
		const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(JSON.parse(init.body as string)).toEqual({ locked: true });
	});

	it('setGuestAllowed POSTs {guestAllowed} to the settings route', async () => {
		const fetchMock = stubFetchRoutes([['/api/meet/5/settings', {}]]);
		await setGuestAllowed(5, false);
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe('/api/meet/5/settings');
		expect(JSON.parse(init.body as string)).toEqual({ guestAllowed: false });
	});

	it('setRole POSTs {identity, role}', async () => {
		const fetchMock = stubFetchRoutes([['/api/meet/5/role', {}]]);
		await setRole(5, 'u:9', 'cohost');
		const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(JSON.parse(init.body as string)).toEqual({ identity: 'u:9', role: 'cohost' });
	});

	it('kick POSTs {identity}', async () => {
		const fetchMock = stubFetchRoutes([['/api/meet/5/kick', {}]]);
		await kick(5, 'g:3');
		const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(JSON.parse(init.body as string)).toEqual({ identity: 'g:3' });
	});

	it('end POSTs with no body', async () => {
		const fetchMock = stubFetchRoutes([['/api/meet/5/end', {}]]);
		await end(5);
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe('/api/meet/5/end');
		expect(init.method).toBe('POST');
	});

	it('decideRequest POSTs {action} to /requests/{reqId}', async () => {
		const fetchMock = stubFetchRoutes([['/api/meet/5/requests/9', {}]]);
		await decideRequest(5, 9, 'admit');
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe('/api/meet/5/requests/9');
		expect(JSON.parse(init.body as string)).toEqual({ action: 'admit' });
	});

	it('knock POSTs the high-entropy slug to /api/meet/{id}/knock', async () => {
		const fetchMock = stubFetchRoutes([['/api/meet/5/knock', { requestId: 11, secret: 'sekret' }]]);
		const result = await knock(5, 'abc123');
		expect(result).toEqual({ requestId: 11, secret: 'sekret' });
		const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(JSON.parse(init.body as string)).toEqual({ slug: 'abc123' });
	});
});

describe('meet/api.ts — public lobby routes', () => {
	it('guestJoinRequest POSTs {displayName} to /api/public/meet/{slug}/join-request', async () => {
		const fetchMock = stubFetchRoutes([
			['/api/public/meet/abc/join-request', { requestId: 3, secret: 's' }],
		]);
		const result = await guestJoinRequest('abc', 'Alice');
		expect(result).toEqual({ requestId: 3, secret: 's' });
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe('/api/public/meet/abc/join-request');
		expect(JSON.parse(init.body as string)).toEqual({ displayName: 'Alice' });
	});

	// MEET-002 (CWE-598): the secret rides the X-Meet-Lobby-Secret request
	// header — the URL carries requestId in the path and NOTHING else; a
	// query-string secret would leak into access logs, proxies and referrers.
	it('guestPoll GETs with the secret on the X-Meet-Lobby-Secret header and never in the URL', async () => {
		const fetchMock = stubFetchRoutes([
			['/api/public/meet/abc/join-request/3', { state: 'pending' }],
		]);
		const result = await guestPoll('abc', 3, 'top secret');
		expect(result).toEqual({ state: 'pending' });
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe('/api/public/meet/abc/join-request/3');
		expect(new Headers(init.headers).get('X-Meet-Lobby-Secret')).toBe('top secret');
	});

	it('guestPoll returns the admitted+token shape', async () => {
		stubFetchRoutes([
			[
				'/api/public/meet/abc/join-request/3',
				{ state: 'admitted', token: 't', wsPath: '/rtc', expiresAt: '2026-01-01T00:00:00Z' },
			],
		]);
		const result = await guestPoll('abc', 3, 's');
		expect(result.state).toBe('admitted');
	});

	// MEET-002 (CWE-598) grep belt: no file on the guest-lobby client surface
	// may construct a URL carrying the lobby secret — the header is the only
	// ride (pins the clean cut against a future query-param regression at the
	// source level, not just the runtime shape above).
	it('no guest-lobby client file builds a URL carrying the secret', () => {
		const sources = [
			'src/lib/meet/api.ts',
			'src/lib/meet/guestReconnect.ts',
			'src/lib/components/meet/LobbyWaiting.svelte',
			'src/routes/meet/join/[slug]/+page.svelte',
		].map((p) => readFileSync(joinPath(process.cwd(), p), 'utf8'));
		for (const src of sources) {
			expect(src).not.toMatch(/\?secret=/);
			expect(src).not.toMatch(/&secret=/);
			expect(src).not.toMatch(/secret=\$\{/);
		}
	});
});

describe('meet/api.ts — breakouts (Task 6)', () => {
	it('openBreakouts POSTs {count, titles, autoAssign} and returns {breakouts}', async () => {
		const fetchMock = stubFetchRoutes([
			['/api/meet/5/breakouts', { breakouts: [{ breakoutId: 1, idx: 1, title: null, roomName: 'r1' }] }],
		]);
		const result = await openBreakouts(5, 3, ['A', 'B', 'C'], true);
		expect(result.breakouts).toEqual([{ breakoutId: 1, idx: 1, title: null, roomName: 'r1' }]);
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe('/api/meet/5/breakouts');
		expect(init.method).toBe('POST');
		expect(JSON.parse(init.body as string)).toEqual({ count: 3, titles: ['A', 'B', 'C'], autoAssign: true });
	});

	it('assignBreakout POSTs {targetUserId, breakoutId} and resolves on 204; null returns to main', async () => {
		const fetchMock = stubFetchRoutes([['/api/meet/5/breakouts/assign', {}]]);
		await assignBreakout(5, 9, null);
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe('/api/meet/5/breakouts/assign');
		expect(JSON.parse(init.body as string)).toEqual({ targetUserId: 9, breakoutId: null });
	});

	it('closeBreakouts POSTs with no body and resolves on 204', async () => {
		const fetchMock = stubFetchRoutes([['/api/meet/5/breakouts/close', {}]]);
		await closeBreakouts(5);
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe('/api/meet/5/breakouts/close');
		expect(init.method).toBe('POST');
	});

	it('joinBreakout POSTs {breakoutId} and returns {token, wsPath, expiresAt, recordingActive}', async () => {
		const fetchMock = stubFetchRoutes([
			['/api/meet/5/breakouts/join', { token: 't', wsPath: '/rtc', expiresAt: '2026-01-01T00:00:00Z', recordingActive: false }],
		]);
		const result = await joinBreakout(5, 2);
		expect(result).toEqual({ token: 't', wsPath: '/rtc', expiresAt: '2026-01-01T00:00:00Z', recordingActive: false });
		const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(JSON.parse(init.body as string)).toEqual({ breakoutId: 2 });
	});

	it('joinBreakout with no breakoutId sends {breakoutId: null} (own assignment / roam main)', async () => {
		const fetchMock = stubFetchRoutes([
			['/api/meet/5/breakouts/join', { token: 't', wsPath: '/rtc', expiresAt: '2026-01-01T00:00:00Z', recordingActive: false }],
		]);
		await joinBreakout(5);
		const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(JSON.parse(init.body as string)).toEqual({ breakoutId: null });
	});
});

describe('meet/api.ts — MeetError decoding', () => {
	it('decodes an RFC7807 problem body into a MeetError with status/code/detail', async () => {
		stubFetchRoutes([
			[
				'/api/meet/5/kick',
				{ ok: false, status: 403, json: async () => ({ code: 'BZ186', detail: 'not authorized' }), text: async () => '' },
			],
		]);
		await expect(kick(5, 'u:1')).rejects.toMatchObject({
			status: 403,
			code: 'BZ186',
			detail: 'not authorized',
		});
		await expect(kick(5, 'u:1')).rejects.toBeInstanceOf(MeetError);
	});
});
