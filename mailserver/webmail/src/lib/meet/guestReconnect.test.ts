// guestReconnect.test.ts — Meet B1 Task 17, design #7's classification
// table: a plain unit test (no component mount) over classifyPostDisconnect.
import { describe, it, expect, vi } from 'vitest';

const guestPoll = vi.fn();
vi.mock('./api', async () => {
	const actual = await vi.importActual<typeof import('./api')>('./api');
	return { ...actual, guestPoll: (...a: unknown[]) => guestPoll(...a) };
});

const { classifyPostDisconnect } = await import('./guestReconnect');
const { MeetError } = await import('./api');

describe('classifyPostDisconnect', () => {
	it('a denied poll (kicked) classifies as removed', async () => {
		guestPoll.mockResolvedValue({ state: 'denied' });
		expect(await classifyPostDisconnect('s1', 7, 'sec')).toEqual({ kind: 'removed' });
	});

	it('an expired poll (meeting ended, admitted-row synthesized) classifies as ended', async () => {
		guestPoll.mockResolvedValue({ state: 'expired' });
		expect(await classifyPostDisconnect('s1', 7, 'sec')).toEqual({ kind: 'ended' });
	});

	it('a 404-class MeetError (nonexistent slug) classifies as ended, same as expired', async () => {
		guestPoll.mockRejectedValue(new MeetError({ status: 404, code: 'BZ185', detail: 'meeting not found' }));
		expect(await classifyPostDisconnect('s1', 7, 'sec')).toEqual({ kind: 'ended' });
	});

	it('a re-admitted poll (transient disconnect, same grant still live) classifies as admitted with the fresh token', async () => {
		guestPoll.mockResolvedValue({ state: 'admitted', token: 'tok2', wsPath: '/rtc', expiresAt: 'later' });
		expect(await classifyPostDisconnect('s1', 7, 'sec')).toEqual({
			kind: 'admitted',
			token: { token: 'tok2', wsPath: '/rtc', expiresAt: 'later' },
			// med-shard3-021: absent flag reads as not-recording — a
			// non-recording reconnect stays frictionless.
			recordingActive: false,
		});
	});

	// med-shard3-021 (CWE-359): the poll's recordingActive admission fact
	// rides the admitted arm — surfaced, not discarded, so the caller can
	// re-run the recording consent gate before reconnecting.
	it('a re-admitted poll carrying recordingActive surfaces the admission fact for the consent gate', async () => {
		guestPoll.mockResolvedValue({ state: 'admitted', token: 'tok2', wsPath: '/rtc', expiresAt: 'later', recordingActive: true });
		expect(await classifyPostDisconnect('s1', 7, 'sec')).toEqual({
			kind: 'admitted',
			token: { token: 'tok2', wsPath: '/rtc', expiresAt: 'later' },
			recordingActive: true,
		});
	});

	it('an unexpected pending result is never treated as a revocation — falls to reconnect', async () => {
		guestPoll.mockResolvedValue({ state: 'pending' });
		expect(await classifyPostDisconnect('s1', 7, 'sec')).toEqual({ kind: 'reconnect' });
	});

	it('a non-404 transport error also falls to reconnect, never guessed as a revocation', async () => {
		guestPoll.mockRejectedValue(new Error('network blip'));
		expect(await classifyPostDisconnect('s1', 7, 'sec')).toEqual({ kind: 'reconnect' });
	});
});
