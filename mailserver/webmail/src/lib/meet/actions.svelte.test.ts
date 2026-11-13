// actions.svelte.test.ts — unit tests for MeetActions (the in-meeting
// host-control dispatch layer extracted from MeetApp.svelte, whole-pipeline
// review arch #9). Mirrors calendarActionStore.svelte.test.ts's shape: a
// plain mutable object satisfies MeetActionHost (no Svelte reactivity
// needed off-component — MeetApp.svelte itself supplies the real
// accessor-backed host; see MeetApp.test.ts for the behavioral/integration
// coverage of the wiring). $lib/meet/api is mocked; showToast/toasts are
// the REAL implementation (the MeetApp.test.ts precedent) so toast
// assertions read the same `toasts` array the app renders from.
import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { Meeting } from '$lib/meet/api';
import { MeetError } from '$lib/meet/api';
import type { MeetRoom } from '$lib/meet/room.svelte';
import { toasts, clearToasts } from '$lib/components/ui';

const startRecordingApi = vi.fn();
const stopRecordingApi = vi.fn();
const startCaptionsApi = vi.fn();
const stopCaptionsApi = vi.fn();
const endApi = vi.fn();
const lockApi = vi.fn();
const kickApi = vi.fn();
const setRoleApi = vi.fn();
const joinBreakoutApi = vi.fn();
const joinApi = vi.fn();

vi.mock('$lib/meet/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/meet/api')>('$lib/meet/api');
	return {
		...actual,
		startRecording: (...a: unknown[]) => startRecordingApi(...a),
		stopRecording: (...a: unknown[]) => stopRecordingApi(...a),
		startCaptions: (...a: unknown[]) => startCaptionsApi(...a),
		stopCaptions: (...a: unknown[]) => stopCaptionsApi(...a),
		end: (...a: unknown[]) => endApi(...a),
		lock: (...a: unknown[]) => lockApi(...a),
		kick: (...a: unknown[]) => kickApi(...a),
		setRole: (...a: unknown[]) => setRoleApi(...a),
		joinBreakout: (...a: unknown[]) => joinBreakoutApi(...a),
		join: (...a: unknown[]) => joinApi(...a),
	};
});

import { MeetActions, type MeetActionHost } from './actions.svelte';

function meeting(over: Partial<Meeting> = {}): Meeting {
	return {
		meetingId: 9,
		slug: 'abc123',
		title: 'Standup',
		roomName: 'room-uuid',
		state: 'live',
		locked: false,
		guestAllowed: false,
		scheduledStart: null,
		scheduledEnd: null,
		chatChannelId: null,
		chatChannelMember: true,
		calendarEventId: null,
		ownerUserId: 1,
		createdAt: '',
		endedAt: null,
		myRole: 'host',
		pendingJoinRequests: [],
		recordingActive: false,
		recordingEnabled: false,
		recordings: [],
		attendance: [],
		banned: [],
		breakoutsEnabled: false,
		breakouts: [],
		myBreakoutId: null,
		captionsEnabled: false,
		captionsOn: false,
		...over,
	};
}

function fakeRoom(): MeetRoom {
	return {
		moveTo: vi.fn().mockResolvedValue(undefined),
		disconnect: vi.fn(),
	} as unknown as MeetRoom;
}

/** A minimal MeetActionHost-like plain object — mirrors emailActionStore's
 *  ActionHost / calendarActionStore's CalendarActionHost testing shape.
 *  MeetApp.svelte itself supplies a get/set-accessor-backed host over its
 *  own $state; here plain mutable fields are enough. */
function makeHost(over: Partial<MeetActionHost> = {}): MeetActionHost {
	return {
		meeting: meeting(),
		room: fakeRoom(),
		view: 'in-room',
		errorMessage: '',
		openGeneration: 0,
		recordingSeededByPush: false,
		recordingActive: false,
		recordingStopping: false,
		recordingRequested: false,
		captionsOn: false,
		currentBreakoutId: null,
		moveInterstitial: null,
		whiteboardOpen: false,
		...over,
	};
}

beforeEach(() => {
	vi.clearAllMocks();
	clearToasts();
});

describe('MeetActions.startRecording', () => {
	it('no-ops when there is no meeting', async () => {
		const actions = new MeetActions(makeHost({ meeting: null }));
		await actions.startRecording();
		expect(startRecordingApi).not.toHaveBeenCalled();
	});

	it('calls the API with the meeting id', async () => {
		const actions = new MeetActions(makeHost({ meeting: meeting({ meetingId: 42 }) }));
		await actions.startRecording();
		expect(startRecordingApi).toHaveBeenCalledWith(42);
	});

	it('egressBusy shows its own distinguishable toast', async () => {
		startRecordingApi.mockRejectedValue(new MeetError({ status: 503, code: 'egressBusy', detail: 'busy' }));
		const actions = new MeetActions(makeHost());
		await actions.startRecording();
		expect(toasts.some((tst) => tst.message === 'Recording capacity is in use; try again shortly')).toBe(true);
	});

	it('BZ199 (guest⇄recording exclusion) shows its own distinguishable toast', async () => {
		startRecordingApi.mockRejectedValue(new MeetError({ status: 403, code: 'BZ199', detail: 'no' }));
		const actions = new MeetActions(makeHost());
		await actions.startRecording();
		expect(toasts.some((tst) => tst.message === 'Guests are in the meeting. Remove guests before starting a recording.')).toBe(true);
	});

	it('any other failure falls back to errText(e)', async () => {
		startRecordingApi.mockRejectedValue(new MeetError({ status: 500, code: '', detail: 'Something broke' }));
		const actions = new MeetActions(makeHost());
		await actions.startRecording();
		expect(toasts.some((tst) => tst.message === 'Something broke')).toBe(true);
	});
});

describe('MeetActions.stopRecording', () => {
	it('the stopBusy guard fires exactly one DELETE for two synchronous calls', async () => {
		const actions = new MeetActions(makeHost());
		void actions.stopRecording();
		void actions.stopRecording();
		await vi.waitFor(() => expect(stopRecordingApi).toHaveBeenCalledTimes(1));
	});

	it('resets stopBusy after completion (a later call fires again)', async () => {
		const actions = new MeetActions(makeHost());
		await actions.stopRecording();
		expect(actions.stopBusy).toBe(false);
		await actions.stopRecording();
		expect(stopRecordingApi).toHaveBeenCalledTimes(2);
	});

	it('BZ200 (state conflict) shows its own distinguishable toast', async () => {
		stopRecordingApi.mockRejectedValue(new MeetError({ status: 409, code: 'BZ200', detail: 'no' }));
		const actions = new MeetActions(makeHost());
		await actions.stopRecording();
		expect(toasts.some((tst) => tst.message === 'Recording state changed — refresh and try again.')).toBe(true);
	});
});

describe('MeetActions.startCaptions / stopCaptions', () => {
	it('captionsBusy shows its own distinguishable toast', async () => {
		startCaptionsApi.mockRejectedValue(new MeetError({ status: 503, code: 'captionsBusy', detail: 'busy' }));
		const actions = new MeetActions(makeHost());
		await actions.startCaptions();
		expect(toasts.some((tst) => tst.message === 'Caption capacity is in use — try again shortly')).toBe(true);
	});

	it('the captionsStopBusy guard fires exactly one DELETE for two synchronous calls', async () => {
		const actions = new MeetActions(makeHost());
		void actions.stopCaptions();
		void actions.stopCaptions();
		await vi.waitFor(() => expect(stopCaptionsApi).toHaveBeenCalledTimes(1));
	});

	it('stopCaptions has no distinguishable-error branch — any failure just toasts errText(e)', async () => {
		stopCaptionsApi.mockRejectedValue(new MeetError({ status: 500, code: '', detail: 'nope' }));
		const actions = new MeetActions(makeHost());
		await actions.stopCaptions();
		expect(toasts.some((tst) => tst.message === 'nope')).toBe(true);
	});
});

describe('MeetActions.end / kick / setRole (generic showToast(errText(e)) failures)', () => {
	it('end calls the API and toasts on failure', async () => {
		endApi.mockRejectedValue(new MeetError({ status: 500, code: '', detail: 'Could not end the meeting' }));
		const actions = new MeetActions(makeHost({ meeting: meeting({ meetingId: 7 }) }));
		await actions.end();
		expect(endApi).toHaveBeenCalledWith(7);
		expect(toasts.some((tst) => tst.message === 'Could not end the meeting')).toBe(true);
	});

	it('kick calls the API with meetingId + identity and toasts on failure', async () => {
		kickApi.mockRejectedValue(new MeetError({ status: 500, code: '', detail: 'Could not remove Alice' }));
		const actions = new MeetActions(makeHost({ meeting: meeting({ meetingId: 7 }) }));
		await actions.kick('u:2');
		expect(kickApi).toHaveBeenCalledWith(7, 'u:2');
		expect(toasts.some((tst) => tst.message === 'Could not remove Alice')).toBe(true);
	});

	it('setRole calls the API with meetingId + identity + role and toasts on failure', async () => {
		setRoleApi.mockRejectedValue(new MeetError({ status: 500, code: '', detail: 'nope' }));
		const actions = new MeetActions(makeHost({ meeting: meeting({ meetingId: 7 }) }));
		await actions.setRole('u:2', 'cohost');
		expect(setRoleApi).toHaveBeenCalledWith(7, 'u:2', 'cohost');
		expect(toasts.some((tst) => tst.message === 'nope')).toBe(true);
	});
});

describe('MeetActions.lock', () => {
	it('on success, patches host.meeting.locked (merge, not replace)', async () => {
		const host = makeHost({ meeting: meeting({ meetingId: 7, locked: false, title: 'Standup' }) });
		const actions = new MeetActions(host);
		await actions.lock(true);
		expect(lockApi).toHaveBeenCalledWith(7, true);
		expect(host.meeting).toEqual(meeting({ meetingId: 7, locked: true, title: 'Standup' }));
	});

	it('on failure, leaves host.meeting untouched and toasts', async () => {
		lockApi.mockRejectedValue(new MeetError({ status: 422, code: 'BZ188', detail: 'Could not lock the meeting' }));
		const host = makeHost({ meeting: meeting({ meetingId: 7, locked: false }) });
		const actions = new MeetActions(host);
		await actions.lock(true);
		expect(host.meeting?.locked).toBe(false);
		expect(toasts.some((tst) => tst.message === 'Could not lock the meeting')).toBe(true);
	});
});

describe('MeetActions.moveToBreakout', () => {
	it('no-ops without a meeting or room', async () => {
		const actions = new MeetActions(makeHost({ meeting: null }));
		await actions.moveToBreakout(10);
		expect(joinBreakoutApi).not.toHaveBeenCalled();
	});

	it('happy path: sets the moving interstitial, closes the whiteboard, moves the room, lands currentBreakoutId', async () => {
		const room = fakeRoom();
		const host = makeHost({
			meeting: meeting({ meetingId: 9, breakouts: [{ breakoutId: 10, idx: 1, title: 'Room A' }] }),
			room,
			whiteboardOpen: true,
		});
		joinBreakoutApi.mockResolvedValue({ token: 'tok2', wsPath: '/rtc', expiresAt: 'later', recordingActive: false });
		const actions = new MeetActions(host);

		await actions.moveToBreakout(10);

		expect(joinBreakoutApi).toHaveBeenCalledWith(9, 10);
		expect(room.moveTo).toHaveBeenCalledWith('tok2', '/rtc');
		expect(host.currentBreakoutId).toBe(10);
		expect(host.moveInterstitial).toBeNull();
		expect(host.whiteboardOpen).toBe(false);
	});

	it('falls back to the generic "moving…" label when the target breakout is not (yet) in meeting.breakouts', async () => {
		const host = makeHost({ meeting: meeting({ meetingId: 9, breakouts: [] }) });
		let resolveJoin: (v: unknown) => void = () => {};
		joinBreakoutApi.mockReturnValue(new Promise((resolve) => (resolveJoin = resolve)));
		const actions = new MeetActions(host);

		const p = actions.moveToBreakout(10);
		expect(host.moveInterstitial).toEqual({ kind: 'moving', roomLabel: null });
		resolveJoin({ token: 'tok2', wsPath: '/rtc', expiresAt: 'later', recordingActive: false });
		await p;
	});

	it('retries once on failure, then falls back to rejoinMain and toasts moveFailed if the target was not reached', async () => {
		const host = makeHost({
			meeting: meeting({ meetingId: 9, breakouts: [{ breakoutId: 10, idx: 1, title: 'Room A' }] }),
		});
		joinBreakoutApi.mockRejectedValue(new MeetError({ status: 502, code: '', detail: 'evict failed' }));
		joinApi.mockResolvedValue({ token: 'tokM', wsPath: '/rtc', expiresAt: 'later', meeting: host.meeting, recordingActive: false });
		const actions = new MeetActions(host);

		await actions.moveToBreakout(10);

		expect(joinBreakoutApi).toHaveBeenCalledTimes(2); // one automatic retry
		expect(joinApi).toHaveBeenCalledTimes(1); // the D1 rejoinMain fallback
		expect(toasts.some((tst) => tst.message === 'Could not move you — returning to the main room')).toBe(true);
	});

	it('a stale generation (superseded by a newer meeting switch) drops the response — no state mutated', async () => {
		let gen = 0;
		const host: MeetActionHost = {
			...makeHost({ meeting: meeting({ meetingId: 9, breakouts: [{ breakoutId: 10, idx: 1, title: 'Room A' }] }) }),
			get openGeneration() {
				return gen;
			},
		};
		let resolveJoinBreakout: (v: unknown) => void = () => {};
		joinBreakoutApi.mockReturnValue(new Promise((resolve) => (resolveJoinBreakout = resolve)));
		const actions = new MeetActions(host);

		const p = actions.moveToBreakout(10);
		gen = 1; // a newer openMeeting/openBySlug call landed mid-move
		resolveJoinBreakout({ token: 'tok2', wsPath: '/rtc', expiresAt: 'later', recordingActive: false });
		await p;

		expect(host.currentBreakoutId).toBeNull(); // never set — the stale response was dropped
	});
});

describe('MeetActions.rejoinMain', () => {
	it('no-ops without a meeting or room', async () => {
		const actions = new MeetActions(makeHost({ room: null }));
		await actions.rejoinMain();
		expect(joinApi).not.toHaveBeenCalled();
	});

	it('happy path: reseeds recording/captions from the fresh join response and lands currentBreakoutId', async () => {
		const room = fakeRoom();
		const m = meeting({ meetingId: 9, myBreakoutId: null, captionsOn: true });
		joinApi.mockResolvedValue({ token: 'tokM', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: true });
		const host = makeHost({ meeting: m, room, whiteboardOpen: true });
		const actions = new MeetActions(host);

		await actions.rejoinMain();

		expect(room.moveTo).toHaveBeenCalledWith('tokM', '/rtc');
		expect(host.recordingActive).toBe(true);
		expect(host.recordingStopping).toBe(false);
		expect(host.recordingRequested).toBe(false);
		expect(host.captionsOn).toBe(true);
		expect(host.currentBreakoutId).toBeNull();
		expect(host.moveInterstitial).toBeNull();
		expect(host.whiteboardOpen).toBe(false);
	});

	it('D10 redirect: a still-live server-side assignment redirects back into the child room', async () => {
		const m = meeting({ meetingId: 9, myBreakoutId: 10 });
		joinApi.mockResolvedValue({ token: 'tokM', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });
		const host = makeHost({ meeting: m });
		const actions = new MeetActions(host);

		await actions.rejoinMain();

		expect(host.currentBreakoutId).toBe(10);
	});

	it('F2a push-wins: recordingSeededByPush=true means the join response never overwrites recording state', async () => {
		const m = meeting({ meetingId: 9 });
		joinApi.mockResolvedValue({ token: 'tokM', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: true });
		const host = makeHost({ meeting: m, recordingSeededByPush: true, recordingActive: false });
		const actions = new MeetActions(host);

		await actions.rejoinMain();

		expect(host.recordingActive).toBe(false); // untouched — the push already won
	});

	it('BZ190 (mutation against an already-ended meeting) is a silent no-op, not an error screen', async () => {
		joinApi.mockRejectedValue(new MeetError({ status: 409, code: 'BZ190', detail: 'meeting has ended' }));
		const host = makeHost({ view: 'in-room', currentBreakoutId: 10 });
		const actions = new MeetActions(host);

		await actions.rejoinMain();

		expect(host.view).toBe('in-room'); // untouched — the ended push owns the transition
		expect(host.errorMessage).toBe('');
		expect(host.moveInterstitial).toBeNull();
		// the eng NEW-1 fix: currentBreakoutId is ALSO cleared on BZ190, or the
		// disconnect $effect's guard (currentBreakoutId !== null) never breaks
		// and loops one POST /join per iteration.
		expect(host.currentBreakoutId).toBeNull();
	});

	it('any other failure disconnects the room, sets errorMessage, and flips view to error', async () => {
		const room = fakeRoom();
		joinApi.mockRejectedValue(new MeetError({ status: 500, code: '', detail: 'boom' }));
		const host = makeHost({ room });
		const actions = new MeetActions(host);

		await actions.rejoinMain();

		expect(room.disconnect).toHaveBeenCalled();
		expect(host.errorMessage).toBe('boom');
		expect(host.view).toBe('error');
	});

	it('a stale generation drops the response — no state mutated', async () => {
		let gen = 0;
		const host: MeetActionHost = {
			...makeHost(),
			get openGeneration() {
				return gen;
			},
		};
		let resolveJoin: (v: unknown) => void = () => {};
		joinApi.mockReturnValue(new Promise((resolve) => (resolveJoin = resolve)));
		const actions = new MeetActions(host);

		const p = actions.rejoinMain();
		gen = 1;
		resolveJoin({ token: 'tokM', wsPath: '/rtc', expiresAt: 'later', meeting: meeting(), recordingActive: true });
		await p;

		expect(host.recordingActive).toBe(false); // never applied — the stale response was dropped
	});
});

// [whole-pipeline review arch #9, structural] mirrors MeetApp.test.ts's own
// structural pin (pre-extraction, it covered doEnd/doLock/doKick/doSetRole
// inline) — end/lock/kick/setRole all showToast(errText(e)) on failure, the
// SAME generic pattern; startRecording/stopRecording/startCaptions have
// their own distinguishable-error branches instead, covered behaviorally
// above.
describe('MeetActions — structural', () => {
	it('end/lock/kick/setRole all showToast(errText(e)) on a generic failure', async () => {
		const mod = (await import('./actions.svelte.ts?raw')) as unknown as { default: string };
		const src = mod.default;
		for (const fn of ['end', 'lock', 'kick', 'setRole']) {
			const re = new RegExp(`async ${fn}\\([^)]*\\)\\s*:\\s*Promise<void>\\s*\\{[\\s\\S]*?catch \\(e\\) \\{\\s*showToast\\(errText\\(e\\)\\);`);
			expect(src, `${fn} should showToast(errText(e)) on failure`).toMatch(re);
		}
	});
});
