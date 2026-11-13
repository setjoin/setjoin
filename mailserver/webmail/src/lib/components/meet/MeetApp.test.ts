// MeetApp.test.ts — Meet B1 Task 16 named test (meeting_state:ended) plus the
// Meet B2 retro design review's own MeetApp-level pins (F1/F2a/F3/F5): the
// knock-admitted consent gate, push-wins recording seeding, the meeting-
// switch room teardown, and the starting/stopBusy guards. Mirrors
// routes/meet/join/join.test.ts's livekit-client fake — this file also
// reaches real MeetRoom.connect via PreJoin → handlePreJoin → connectRoom,
// so the same SFU test seam applies (the SFU is NOT run in unit tests).
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import MeetApp from './MeetApp.svelte';
import { MeetError, type Meeting } from '$lib/meet/api';
import { toasts, clearToasts } from '$lib/components/ui';
import { user } from '$lib/stores/auth';
import { jmapSession } from '$lib/stores/session';

const listMeetings = vi.fn();
const getMeeting = vi.fn();
const resolveSlug = vi.fn();
const decideRequest = vi.fn();
const join = vi.fn();
const knock = vi.fn();
const guestPoll = vi.fn();
const startRecording = vi.fn();
const stopRecording = vi.fn();
const joinBreakout = vi.fn();
const startCaptions = vi.fn();
const stopCaptions = vi.fn();
// [UX #1, pipeline review] doEnd/doLock/doKick/doSetRole/createMeeting all
// need their own mocks (not just the actual fetch-backed impl) so a
// rejection test can drive them without a phantom-fetch guard failure.
const lock = vi.fn();
const end = vi.fn();
const kick = vi.fn();
const setRole = vi.fn();
const createMeeting = vi.fn();

vi.mock('$lib/meet/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/meet/api')>('$lib/meet/api');
	return {
		...actual,
		listMeetings: (...a: unknown[]) => listMeetings(...a),
		getMeeting: (...a: unknown[]) => getMeeting(...a),
		resolveSlug: (...a: unknown[]) => resolveSlug(...a),
		decideRequest: (...a: unknown[]) => decideRequest(...a),
		join: (...a: unknown[]) => join(...a),
		knock: (...a: unknown[]) => knock(...a),
		guestPoll: (...a: unknown[]) => guestPoll(...a),
		startRecording: (...a: unknown[]) => startRecording(...a),
		stopRecording: (...a: unknown[]) => stopRecording(...a),
		joinBreakout: (...a: unknown[]) => joinBreakout(...a),
		startCaptions: (...a: unknown[]) => startCaptions(...a),
		stopCaptions: (...a: unknown[]) => stopCaptions(...a),
		lock: (...a: unknown[]) => lock(...a),
		end: (...a: unknown[]) => end(...a),
		kick: (...a: unknown[]) => kick(...a),
		setRole: (...a: unknown[]) => setRole(...a),
		createMeeting: (...a: unknown[]) => createMeeting(...a),
	};
});

// capturedHandler keeps the ENVELOPE shape ({'@type', event: {...}}) every
// test call site already used pre-#A2 — the mock's subscribeEvent unwraps
// `event` itself (mirroring the real jmap/websocket.ts hub-level unwrap)
// before forwarding to the handler MeetApp.svelte registers, so no test
// call site needed to change when MeetApp moved off subscribeType.
let capturedHandler: ((envelope: Record<string, unknown>) => void) | null = null;
let capturedGuestMeetHandler: ((event: Record<string, unknown>) => void) | null = null;
let capturedGuestMeetOpen: (() => void) | null = null;
let guestMeetSubscribeCalls = 0;
vi.mock('$lib/jmap/websocket', () => ({
	subscribeEvent: (_type: string, handler: (event: Record<string, unknown>) => void) => {
		capturedHandler = (envelope: Record<string, unknown>) => {
			const event = (envelope as { event?: unknown }).event;
			if (event && typeof event === 'object') handler(event as Record<string, unknown>);
		};
		return () => {
			capturedHandler = null;
		};
	},
}));

vi.mock('$lib/chat/guestEventSource', () => ({
	subscribeGuestMeetEvents: (handler: (event: Record<string, unknown>) => void, onOpen?: () => void) => {
		guestMeetSubscribeCalls += 1;
		capturedGuestMeetHandler = handler;
		capturedGuestMeetOpen = onOpen ?? null;
		return () => {
			capturedGuestMeetHandler = null;
			capturedGuestMeetOpen = null;
		};
	},
}));

const pickVideoCodec = vi.fn(async () => 'vp8' as const);
vi.mock('$lib/meet/codecProbe', () => ({ pickVideoCodec: () => pickVideoCodec() }));

vi.mock('$lib/meet/blur', () => ({
	isBlurAvailable: () => false,
	loadBlurPref: () => false,
	saveBlurPref: () => undefined,
	setBlur: async () => true,
}));

// B3 Task 9: WhiteboardPanel itself dynamically imports the real
// @excalidraw/excalidraw (a canvas-feature-detecting package jsdom can't
// import at all, no `canvas` npm package installed) — its own wiring is
// WhiteboardPanel.test.ts's job. Stubbed here (the directory/OrgChart.svelte
// genre) so MeetApp's own open/close toggle is what's under test.
vi.mock('./WhiteboardPanel.svelte', () => ({ default: () => null }));

// vi.mock factories are hoisted above every import (incl. MeetApp's own
// static import chain through PreJoin/MeetingRoom/room.svelte, which all
// reach 'livekit-client') — same dodge join.test.ts documents: the fake
// classes must live inside vi.hoisted or the factory runs before they exist.
type Handler = (...args: unknown[]) => void;

const { FakeRoomInner, roomState } = vi.hoisted(() => {
	class FakeLocalParticipant {
		identity = 'u:1';
		name = 'Alice Host';
		isCameraEnabled = false;
		isMicrophoneEnabled = false;
		isScreenShareEnabled = false;
		videoTrackPublications = new Map<string, unknown>();
		audioTrackPublications = new Map<string, unknown>();
		setMicrophoneEnabled = vi.fn(async () => undefined);
		setCameraEnabled = vi.fn(async () => undefined);
		setScreenShareEnabled = vi.fn(async () => undefined);
		publishData = vi.fn(async () => undefined);
		getTrackPublication = vi.fn(() => undefined as { videoTrack?: unknown } | undefined);
	}
	class FakeRoomInner {
		handlers = new Map<string, Handler[]>();
		localParticipant = new FakeLocalParticipant();
		remoteParticipants = new Map<string, unknown>();
		connect = vi.fn(async () => undefined);
		disconnect = vi.fn(async () => undefined);
		removeAllListeners = vi.fn(() => {
			this.handlers.clear();
		});
		constructor(public opts: unknown) {}
		on(event: string, handler: Handler) {
			const list = this.handlers.get(event) ?? [];
			list.push(handler);
			this.handlers.set(event, list);
			return this;
		}
		emit(event: string, ...args: unknown[]) {
			for (const h of this.handlers.get(event) ?? []) h(...args);
		}
	}
	const roomState: { lastRoom?: InstanceType<typeof FakeRoomInner> } = {};
	return { FakeRoomInner, roomState };
});

vi.mock('livekit-client', () => {
	class RoomCtor extends FakeRoomInner {
		static getLocalDevices = vi.fn(async () => [] as MediaDeviceInfo[]);
		constructor(opts: unknown) {
			super(opts);
			roomState.lastRoom = this;
		}
	}
	class FakeLocalVideoTrack {
		attach = vi.fn();
		detach = vi.fn();
		constructor(public mediaStreamTrack: unknown) {}
	}
	return {
		Room: RoomCtor,
		LocalVideoTrack: FakeLocalVideoTrack,
		RoomEvent: {
			Connected: 'connected',
			Reconnecting: 'reconnecting',
			Reconnected: 'reconnected',
			Disconnected: 'disconnected',
			ParticipantConnected: 'participantConnected',
			ParticipantDisconnected: 'participantDisconnected',
			ConnectionQualityChanged: 'connectionQualityChanged',
			ActiveSpeakersChanged: 'activeSpeakersChanged',
			DataReceived: 'dataReceived',
		},
		ConnectionQuality: { Excellent: 'excellent', Good: 'good', Poor: 'poor', Lost: 'lost', Unknown: 'unknown' },
		Track: { Source: { Camera: 'camera', Microphone: 'microphone', ScreenShare: 'screen_share' } },
		ScreenSharePresets: { h1080fps15: { encoding: {} } },
		// B1 live-gate ledger fix 1: the real @livekit/protocol enum value
		// (PARTICIPANT_REMOVED = 4) — MeetApp's kicked-detection $effect
		// compares room.disconnectReason (room.svelte.ts's String(reason))
		// against String(DisconnectReason.PARTICIPANT_REMOVED).
		DisconnectReason: {
			UNKNOWN_REASON: 0,
			CLIENT_INITIATED: 1,
			DUPLICATE_IDENTITY: 2,
			SERVER_SHUTDOWN: 3,
			PARTICIPANT_REMOVED: 4,
			ROOM_DELETED: 5,
		},
	};
});

function fakeStream(): MediaStream {
	const videoTrack = { kind: 'video', enabled: true, stop: vi.fn() };
	const audioTrack = { kind: 'audio', enabled: true, stop: vi.fn() };
	return {
		getAudioTracks: () => [audioTrack],
		getVideoTracks: () => [videoTrack],
		getTracks: () => [audioTrack, videoTrack],
	} as unknown as MediaStream;
}

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
		// V131 default (mirrors api.ts's normalizeMeeting, which every REAL
		// join/getMeeting/resolveSlug response goes through — this fixture
		// bypasses that via the module mock, so it defaults the same way here).
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
		// B3 Task 6: additive-safe keys (Task 2/7/13/14 land the real server
		// values) — default to the toggle-off/unassigned shape here.
		breakoutsEnabled: false,
		breakouts: [],
		myBreakoutId: null,
		captionsEnabled: false,
		captionsOn: false,
		...over,
	};
}

function setGuestMeetSession(allowMeetCreate = false, allowMeetHost = false): void {
	user.set({ email: 'pat@partner.example', isAdmin: false, hasMailbox: false, accountType: 'guest' });
	jmapSession.set({
		isGuest: true,
		effectiveCapabilities: {
			apps: { mail: false, calendar: false, contacts: false, tasks: false, approvals: false, drive: false, chat: true, meet: true },
			features: { assist: false, bundles: false },
			guest: { allowMeetCreate, allowMeetHost },
		},
	} as never);
}

/** Drives landing -> "Join by link" -> prejoin for the given meeting (reused
 *  by every test below that needs to reach PreJoin). */
async function toPreJoin(m: Meeting): Promise<void> {
	resolveSlug.mockResolvedValue(m);
	render(MeetApp);
	await vi.waitFor(() => expect(listMeetings).toHaveBeenCalled());
	const joinLinkInput = screen.getByPlaceholderText('Paste a meeting link or code');
	await fireEvent.input(joinLinkInput, { target: { value: m.slug } });
	await fireEvent.click(screen.getByText('Join by link'));
	await vi.waitFor(() => expect(resolveSlug).toHaveBeenCalledWith(m.slug));
}

/** Clicks PreJoin's own "Join" button (fires handlePreJoin -> meetApi.join). */
async function clickPreJoinJoin(): Promise<void> {
	await vi.waitFor(() => expect(screen.getByText('Join')).toBeTruthy());
	await fireEvent.click(screen.getByText('Join'));
}

beforeEach(() => {
	listMeetings.mockResolvedValue([]);
	user.set(null);
	jmapSession.set(null);
	roomState.lastRoom = undefined;
	capturedGuestMeetHandler = null;
	capturedGuestMeetOpen = null;
	guestMeetSubscribeCalls = 0;
	vi.stubGlobal('navigator', { ...navigator, mediaDevices: { getUserMedia: async () => fakeStream() } });
});

afterEach(() => {
	vi.clearAllMocks();
	vi.unstubAllGlobals();
	capturedHandler = null;
	roomState.lastRoom = undefined;
	user.set(null);
	jmapSession.set(null);
	clearToasts();
});

describe('MeetApp', () => {
	it('uses the read-only named Meet EventSource rail for a guest account', async () => {
		setGuestMeetSession();
		const m = meeting({ meetingId: 40, slug: 'guest-live' });
		await toPreJoin(m);
		await vi.waitFor(() => expect(guestMeetSubscribeCalls).toBe(1));
		expect(capturedGuestMeetHandler).not.toBeNull();
		expect(capturedGuestMeetOpen).not.toBeNull();
		getMeeting.mockResolvedValue({ ...m, recordingActive: true });
		capturedGuestMeetOpen!();
		await vi.waitFor(() => expect(getMeeting).toHaveBeenCalledWith(40));
		await vi.waitFor(() => expect(screen.getByText('This meeting is being recorded. If you join, your voice and video will be part of the recording.')).toBeTruthy());

		capturedGuestMeetHandler!({ event: 'meeting_state', meetingId: 40, payload: { state: 'ended' } });
		await vi.waitFor(() => expect(screen.getByText('This meeting has ended')).toBeTruthy());
	});
	it('hides meeting creation for a guest unless its session policy permits it', async () => {
		setGuestMeetSession(false);
		const { unmount } = render(MeetApp);
		await vi.waitFor(() => expect(listMeetings).toHaveBeenCalled());
		expect(screen.queryByText('New meeting')).toBeNull();
		expect(screen.getByText('Join by link')).toBeTruthy();
		expect(screen.getByText('No meetings yet — paste a join link')).toBeTruthy();
		expect(screen.queryByText('No meetings yet — start one or paste a join link')).toBeNull();
		unmount();

		setGuestMeetSession(true);
		render(MeetApp);
		await vi.waitFor(() => expect(screen.getByText('New meeting')).toBeTruthy());
		expect(screen.getByText('No meetings yet — start one or paste a join link')).toBeTruthy();
	});

	it('treats BZ215 as knock-needed only for an authenticated guest and includes the meeting slug', async () => {
		setGuestMeetSession();
		const m = meeting({ meetingId: 41, slug: 'high-entropy-slug', myRole: null });
		join.mockRejectedValue(new MeetError({ status: 403, code: 'BZ215', detail: 'Knock required' }));
		knock.mockResolvedValue({ requestId: 8, secret: 'sek' });

		await toPreJoin(m);
		await clickPreJoinJoin();

		await vi.waitFor(() => expect(knock).toHaveBeenCalledWith(41, 'high-entropy-slug'));
		expect(screen.getByTestId('lobby-waiting')).toBeTruthy();
	});

	it('gates a guest admitted during recording before connecting, then shows the live banner', async () => {
		setGuestMeetSession();
		const m = meeting({ meetingId: 44, slug: 'guest-knock-recording', myRole: null, recordingActive: false });
		join.mockRejectedValue(new MeetError({ status: 403, code: 'BZ215', detail: 'Knock required' }));
		knock.mockResolvedValue({ requestId: 9, secret: 'sek' });
		guestPoll.mockResolvedValue({ state: 'admitted', token: 'tok', wsPath: '/rtc', expiresAt: 'later', recordingActive: true });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(knock).toHaveBeenCalledWith(44, 'guest-knock-recording'));
		await vi.waitFor(() => expect(screen.getByText('This meeting is being recorded. If you join, your voice and video will be part of the recording.')).toBeTruthy());
		expect(roomState.lastRoom).toBeUndefined();

		await fireEvent.click(screen.getByText('Join'));
		await vi.waitFor(() => expect(document.querySelector('.recording-banner--active')).toBeTruthy());
	});

	it('does not reinterpret a member BZ215 as a knock', async () => {
		const m = meeting({ meetingId: 42, slug: 'member-slug', myRole: 'member' });
		join.mockRejectedValue(new MeetError({ status: 403, code: 'BZ215', detail: 'Not allowed' }));

		await toPreJoin(m);
		await clickPreJoinJoin();

		await vi.waitFor(() => expect(screen.getByText('Not allowed')).toBeTruthy());
		expect(knock).not.toHaveBeenCalled();
	});

	it('shows the recording interstitial and live banner for an authenticated guest account', async () => {
		setGuestMeetSession();
		const m = meeting({ meetingId: 43, slug: 'guest-recording', myRole: 'member', recordingActive: true });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: true });

		await toPreJoin(m);
		expect(screen.getByText('This meeting is being recorded. If you join, your voice and video will be part of the recording.')).toBeTruthy();
		expect(roomState.lastRoom).toBeUndefined();

		await fireEvent.click(screen.getByText('Join'));
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.recording-banner--active')).toBeTruthy());
	});

	it('shows the ended state when a meeting_state:ended event arrives for the current meeting', async () => {
		getMeeting.mockResolvedValue(meeting());
		render(MeetApp);

		// Land on the create/join screen first, then open a meeting (the PreJoin
		// step) so `meeting` is populated with meetingId 9.
		await vi.waitFor(() => expect(listMeetings).toHaveBeenCalled());
		const joinLinkInput = screen.getByPlaceholderText('Paste a meeting link or code');
		await fireEvent.input(joinLinkInput, { target: { value: '9' } });
		// join-by-link resolves via slug, not a numeric id — use resolveSlug instead
		resolveSlug.mockResolvedValue(meeting());
		await fireEvent.click(screen.getByText('Join by link'));

		await vi.waitFor(() => expect(resolveSlug).toHaveBeenCalledWith('9'));
		await vi.waitFor(() => expect(capturedHandler).not.toBeNull());

		capturedHandler!({ '@type': 'MeetEvent', event: { event: 'meeting_state', meetingId: 9, payload: { state: 'ended' } } });

		await vi.waitFor(() => expect(screen.getByText('This meeting has ended')).toBeTruthy());
	});

	// A/B leftover item 5: an authed ?slug= / "Join by link" open of an
	// ALREADY-ended meeting used to still render PreJoin (join then 409s
	// BZ190) — resolveSlug's own m.state='ended' now routes straight to the
	// ended view, no PreJoin frame ever mounts, and Join is never clickable.
	it('routes a slug-open of an already-ended meeting straight to the ended view, never PreJoin', async () => {
		resolveSlug.mockResolvedValue(meeting({ meetingId: 40, slug: 'already-ended', state: 'ended' }));
		render(MeetApp);
		await vi.waitFor(() => expect(listMeetings).toHaveBeenCalled());
		const joinLinkInput = screen.getByPlaceholderText('Paste a meeting link or code');
		await fireEvent.input(joinLinkInput, { target: { value: 'already-ended' } });
		await fireEvent.click(screen.getByText('Join by link'));

		await vi.waitFor(() => expect(resolveSlug).toHaveBeenCalledWith('already-ended'));
		await vi.waitFor(() => expect(screen.getByText('This meeting has ended')).toBeTruthy());
		expect(screen.queryByText('Join')).toBeNull();
		expect(join).not.toHaveBeenCalled();
	});

	it('ignores a meeting_state:ended event for a DIFFERENT meeting', async () => {
		resolveSlug.mockResolvedValue(meeting({ meetingId: 9 }));
		render(MeetApp);
		await vi.waitFor(() => expect(listMeetings).toHaveBeenCalled());
		const joinLinkInput = screen.getByPlaceholderText('Paste a meeting link or code');
		await fireEvent.input(joinLinkInput, { target: { value: '9' } });
		await fireEvent.click(screen.getByText('Join by link'));
		await vi.waitFor(() => expect(capturedHandler).not.toBeNull());

		capturedHandler!({ '@type': 'MeetEvent', event: { event: 'meeting_state', meetingId: 999, payload: { state: 'ended' } } });
		expect(screen.queryByText('This meeting has ended')).toBeNull();
	});

	// ── B2 retro F1: knock-admitted consent + banner ──────────────────────
	it('F1: a knock-admitted grant carrying recordingActive routes through the consent gate before connecting, then seeds the banner', async () => {
		const m = meeting({ meetingId: 30, slug: 'locked-rec', myRole: 'member', locked: true, recordingActive: false });
		join.mockRejectedValue(new MeetError({ status: 403, code: 'BZ187', detail: 'Meeting is locked' }));
		knock.mockResolvedValue({ requestId: 5, secret: 'sek' });
		guestPoll.mockResolvedValue({ state: 'admitted', token: 'tok', wsPath: '/rtc', expiresAt: 'later', recordingActive: true });

		await toPreJoin(m);
		await clickPreJoinJoin();

		await vi.waitFor(() => expect(knock).toHaveBeenCalledWith(30));
		await vi.waitFor(() => expect(screen.getByTestId('lobby-waiting')).toBeTruthy());

		// admitted with recordingActive:true -> the consent gate, NOT an instant connect
		await vi.waitFor(() =>
			expect(
				screen.getByText('This meeting is being recorded. If you join, your voice and video will be part of the recording.'),
			).toBeTruthy(),
		);
		expect(roomState.lastRoom).toBeUndefined();

		await fireEvent.click(screen.getByText('Join'));
		await vi.waitFor(() => expect(roomState.lastRoom).toBeDefined());
		// the in-room banner is seeded active from the admitted grant.
		await vi.waitFor(() => expect(document.querySelector('.recording-banner--active')).toBeTruthy());
	});

	// ── B2 retro F2a: push-wins seeding ────────────────────────────────────
	it('F2a: a recording_state push landing before the join envelope wins over it (push wins)', async () => {
		const m = meeting({ meetingId: 31, slug: 'push-wins', myRole: 'host', locked: false, recordingActive: false });
		// the join envelope itself says recordingActive:false (stale relative
		// to the push) — if the fix regresses, the banner would be OFF in-room.
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await vi.waitFor(() => expect(capturedHandler).not.toBeNull());
		capturedHandler!({ '@type': 'MeetEvent', event: { event: 'recording_state', meetingId: 31, payload: { state: 'active' } } });

		await clickPreJoinJoin();

		await vi.waitFor(() => expect(roomState.lastRoom).toBeDefined());
		await vi.waitFor(() => expect(document.querySelector('.recording-banner--active')).toBeTruthy());
	});

	// ── B2 retro F3: meeting-switch room teardown ──────────────────────────
	it('F3 (runtime): Leave disconnects the live room and resets recording state back to idle (teardownLiveRoom)', async () => {
		const m = meeting({ meetingId: 32, slug: 'leave-1', myRole: 'cohost', locked: false, recordingEnabled: true });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: true });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(roomState.lastRoom).toBeDefined());
		await vi.waitFor(() => expect(document.querySelector('.recording-banner--active')).toBeTruthy());

		await fireEvent.click(screen.getByTestId('leave'));

		expect(roomState.lastRoom!.disconnect).toHaveBeenCalled();
		await vi.waitFor(() => expect(document.querySelector('.recording-banner--active')).toBeNull());
		await vi.waitFor(() => expect(screen.getByPlaceholderText('Paste a meeting link or code')).toBeTruthy());
	});

	// F3 (structural): moved to $lib/meet/store.svelte.test.ts (arch review
	// #A12) — openMeeting/openBySlug now live on MeetStore, not MeetApp.

	// ── B2 retro F5: the 'starting' guard + stopBusy ───────────────────────
	it('F5: a `requested` recording_state push renders the disabled "starting" state', async () => {
		const m = meeting({ meetingId: 33, slug: 'starting-1', myRole: 'host', locked: false, recordingEnabled: true });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(roomState.lastRoom).toBeDefined());

		capturedHandler!({ '@type': 'MeetEvent', event: { event: 'recording_state', meetingId: 33, payload: { state: 'requested' } } });

		await vi.waitFor(() => expect(screen.getByLabelText('Start recording')).toBeTruthy());
		expect(screen.getByLabelText('Start recording')).toBeDisabled();
	});

	it('F5: a double-click Stop fires exactly one DELETE (the stopBusy guard)', async () => {
		const m = meeting({ meetingId: 34, slug: 'stop-1', myRole: 'host', locked: false, recordingEnabled: true });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: true });
		stopRecording.mockResolvedValue(undefined);

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(roomState.lastRoom).toBeDefined());
		await vi.waitFor(() => expect(document.querySelector('.recording-banner--active')).toBeTruthy());

		const stopBtn = screen.getByLabelText('Stop recording');
		// Two synchronous dispatches, NOT individually awaited — doStopRecording
		// sets stopBusy=true before its first await, so the second dispatch
		// (still within the same tick) must see the guard and no-op.
		fireEvent.click(stopBtn);
		fireEvent.click(stopBtn);

		await vi.waitFor(() => expect(stopRecording).toHaveBeenCalledTimes(1));
	});

	// ── pipeline review UX #1: MeetApp silently swallowed host-control
	// failures — errorMessage only ever rendered on view==='error', but
	// doEnd/doLock/doKick/doSetRole/createMeeting/loadMeetings never set that
	// view, so a failure vanished with zero UI feedback. Fixed by routing all
	// six through the SAME showToast(errText(e)) idiom the recording/
	// captions handlers already use. ──────────────────────────────────────
	it('[UX #1] a failing doLock surfaces a toast and stays in the room (no dead-end error screen)', async () => {
		const m = meeting({ meetingId: 171, slug: 'lock-fail', myRole: 'host', locked: false });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });
		lock.mockRejectedValue(new MeetError({ status: 422, code: 'BZ188', detail: 'Could not lock the meeting' }));

		await toPreJoin(m);
		await clickPreJoinJoin();
		// vi.waitFor's own retry loop is load-bearing here — roomState.lastRoom
		// is set the instant `new MeetRoom()` constructs (synchronous, well
		// before the view actually flips to 'in-room'), so a bare assertion
		// right after it races the render; polling for the in-room control
		// itself is what the F5 tests above already do.
		await vi.waitFor(() => expect(screen.getByLabelText('Lock meeting')).toBeTruthy());

		await fireEvent.click(screen.getByLabelText('Lock meeting'));

		await vi.waitFor(() => expect(toasts.some((tst) => tst.message === 'Could not lock the meeting')).toBe(true));
		// still in-room: the Lock control (only rendered in-room) is still there.
		expect(screen.getByLabelText('Lock meeting')).toBeTruthy();
	});

	it('[UX #1] a failing doEnd surfaces a toast and stays in the room', async () => {
		const m = meeting({ meetingId: 172, slug: 'end-fail', myRole: 'host', locked: false });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });
		end.mockRejectedValue(new MeetError({ status: 500, code: 'BZ190', detail: 'Could not end the meeting' }));

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(screen.getByTestId('end-for-all')).toBeTruthy());

		await fireEvent.click(screen.getByTestId('end-for-all'));
		await fireEvent.click(screen.getByTestId('end-for-all-confirm'));

		await vi.waitFor(() => expect(toasts.some((tst) => tst.message === 'Could not end the meeting')).toBe(true));
		expect(screen.getByTestId('end-for-all')).toBeTruthy();
	});

	it('[UX #1] a failing createMeeting (landing view) surfaces a toast instead of vanishing silently', async () => {
		createMeeting.mockRejectedValue(new MeetError({ status: 422, code: 'BZ188', detail: 'Could not create the meeting' }));
		render(MeetApp);
		await vi.waitFor(() => expect(listMeetings).toHaveBeenCalled());

		await fireEvent.click(screen.getByText('New meeting'));

		await vi.waitFor(() => expect(toasts.some((tst) => tst.message === 'Could not create the meeting')).toBe(true));
		// still on the landing view (never transitioned to view==='error').
		expect(screen.getByPlaceholderText('Paste a meeting link or code')).toBeTruthy();
	});

	// UX #13 (whole-pipeline review): kick used to fire instantly with no
	// confirmation and no explanation that it's a ban-until-re-admit, not a
	// soft "leave". Confirm-then-kick + the failure toast (doKick's existing
	// showToast(errText(e)) idiom, proven live here rather than just
	// structurally as the [UX #1, structural] test above does).
	it('[UX #13] kick requires confirmation naming the ban-until-re-admit semantics, then calls kick — and a failure toasts', async () => {
		const m = meeting({ meetingId: 173, slug: 'kick-1', myRole: 'host' });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });
		kick.mockRejectedValue(new MeetError({ status: 500, code: '', detail: 'Could not remove Alice' }));

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		roomState.lastRoom!.remoteParticipants.set('u:2', {
			identity: 'u:2',
			name: 'Alice',
			videoTrackPublications: new Map(),
			audioTrackPublications: new Map(),
		});
		roomState.lastRoom!.emit('participantConnected');

		await fireEvent.click(screen.getByLabelText('Participants'));
		await fireEvent.click(screen.getByText('Remove'));

		// the confirm dialog explains the ban-until-re-admit semantics —
		// kick has NOT fired yet.
		expect(
			screen.getByText("They'll be removed from the meeting immediately and won't be able to rejoin until you re-admit them."),
		).toBeTruthy();
		expect(kick).not.toHaveBeenCalled();

		await fireEvent.click(screen.getByTestId('kick-confirm'));
		await vi.waitFor(() => expect(kick).toHaveBeenCalledWith(173, 'u:2'));
		await vi.waitFor(() => expect(toasts.some((tst) => tst.message === 'Could not remove Alice')).toBe(true));
	});

	it('[UX #13] cancelling the kick confirm dialog never calls kick', async () => {
		const m = meeting({ meetingId: 174, slug: 'kick-2', myRole: 'host' });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		roomState.lastRoom!.remoteParticipants.set('u:3', {
			identity: 'u:3',
			name: 'Bob',
			videoTrackPublications: new Map(),
			audioTrackPublications: new Map(),
		});
		roomState.lastRoom!.emit('participantConnected');

		await fireEvent.click(screen.getByLabelText('Participants'));
		await fireEvent.click(screen.getByText('Remove'));
		await fireEvent.click(screen.getByText('Cancel'));

		expect(kick).not.toHaveBeenCalled();
	});

	// doEnd/doLock/doKick/doSetRole moved to MeetActions ($lib/meet/
	// actions.svelte.ts, the whole-pipeline-review arch #9 extraction) — each
	// is now a one-line call-through onto `actions.X()`; their own
	// showToast(errText(e))-on-failure structural pin lives in
	// actions.svelte.test.ts instead. createMeeting stayed in MeetApp
	// (landing-page create-then-navigate form glue, not part of the meeting/
	// view/push slice — arch review #A12) and keeps its pin here; loadMeetings
	// moved onto MeetStore along with the rest of that slice (its own copy of
	// this pin moved to $lib/meet/store.svelte.test.ts).
	it('[UX #1, structural] createMeeting showToast(errText(e)) on failure, never the dead errorMessage assignment', async () => {
		const mod = (await import('./MeetApp.svelte?raw')) as unknown as { default: string };
		const src = mod.default;
		const re = /async function createMeeting\([^)]*\)\s*:\s*Promise<void>\s*\{[\s\S]*?catch \(e\) \{\s*showToast\(errText\(e\)\);/;
		expect(src, 'createMeeting should showToast(errText(e)) on failure').toMatch(re);
	});

	// The four moved handlers are still thin call-through wiring onto
	// `store.actions` (MeetActions, now reached via the MeetStore instance —
	// arch review #A12) — pinned structurally so a future edit can't quietly
	// re-inline dispatch logic here instead of in the action store.
	it('[whole-pipeline review arch #9, structural] doEnd/doLock/doKick/doSetRole are thin call-throughs onto store.actions.*', async () => {
		const mod = (await import('./MeetApp.svelte?raw')) as unknown as { default: string };
		const src = mod.default;
		const pins: Record<string, RegExp> = {
			doEnd: /async function doEnd\(\): Promise<void> \{\s*await store\.actions\.end\(\);\s*\}/,
			doLock: /async function doLock\(locked: boolean\): Promise<void> \{\s*await store\.actions\.lock\(locked\);\s*\}/,
			doKick: /async function doKick\(identity: string\): Promise<void> \{\s*await store\.actions\.kick\(identity\);\s*\}/,
			doSetRole:
				/async function doSetRole\(identity: string, role: 'cohost' \| 'member'\): Promise<void> \{\s*await store\.actions\.setRole\(identity, role\);\s*\}/,
		};
		for (const [fn, re] of Object.entries(pins)) {
			expect(src, `${fn} should be a thin call-through onto MeetActions`).toMatch(re);
		}
	});
});

// ── B3 Task 15: captions toggle + server-state chip (DN3) + captions_state
// push arm. ──────────────────────────────────────────────────────────────
describe('MeetApp — captions (Meet B3 Task 15)', () => {
	it('seeds captionsOn/captionsConfigured from the join envelope; the toggle renders for a host when both signals are true', async () => {
		const m = meeting({ meetingId: 60, slug: 'captions-1', myRole: 'host', captionsEnabled: true, captionsOn: true });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false, captionsConfigured: true });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(roomState.lastRoom).toBeDefined());

		// captionsOn:true seeds the chip (server state, not local optimism).
		await vi.waitFor(() => expect(screen.getByText('Live captions on')).toBeTruthy());
		// captionsEnabled && captionsConfigured -> the host's toggle button.
		expect(screen.getByLabelText('Turn off live captions')).toBeTruthy();
	});

	it('the toggle is hidden when captionsConfigured is false (no ASR sidecar deployed), even for a host with captionsEnabled', async () => {
		const m = meeting({ meetingId: 61, slug: 'captions-2', myRole: 'host', captionsEnabled: true, captionsOn: false });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false, captionsConfigured: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(roomState.lastRoom).toBeDefined());
		await vi.waitFor(() => expect(document.querySelector('.meeting-room')).toBeTruthy()); // settle into in-room

		expect(screen.queryByLabelText('Turn on live captions')).toBeNull();
	});

	it('a captions_state push flips the chip live (server truth, never local optimism)', async () => {
		const m = meeting({ meetingId: 62, slug: 'captions-3', myRole: 'member', captionsEnabled: false, captionsOn: false });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false, captionsConfigured: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(roomState.lastRoom).toBeDefined());
		expect(screen.queryByText('Live captions on')).toBeNull();

		capturedHandler!({ '@type': 'MeetEvent', event: { event: 'captions_state', meetingId: 62, payload: { on: true, botIdentity: 'cc:62' } } });
		await vi.waitFor(() => expect(screen.getByText('Live captions on')).toBeTruthy());

		capturedHandler!({ '@type': 'MeetEvent', event: { event: 'captions_state', meetingId: 62, payload: { on: false, botIdentity: 'cc:62' } } });
		await vi.waitFor(() => expect(screen.queryByText('Live captions on')).toBeNull());
	});

	it('ignores a captions_state push for a DIFFERENT meeting', async () => {
		const m = meeting({ meetingId: 63, slug: 'captions-4', myRole: 'member', captionsEnabled: false, captionsOn: false });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false, captionsConfigured: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(roomState.lastRoom).toBeDefined());

		capturedHandler!({ '@type': 'MeetEvent', event: { event: 'captions_state', meetingId: 999, payload: { on: true } } });
		expect(screen.queryByText('Live captions on')).toBeNull();
	});

	it('clicking the toggle calls startCaptions; a captionsBusy failure shows its own distinguishable toast', async () => {
		const m = meeting({ meetingId: 64, slug: 'captions-5', myRole: 'host', captionsEnabled: true, captionsOn: false });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false, captionsConfigured: true });
		startCaptions.mockRejectedValue(
			new MeetError({ status: 503, code: 'captionsBusy', detail: 'caption capacity is in use; try again shortly' }),
		);

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(roomState.lastRoom).toBeDefined());
		await vi.waitFor(() => expect(screen.getByLabelText('Turn on live captions')).toBeTruthy());

		await fireEvent.click(screen.getByLabelText('Turn on live captions'));
		await vi.waitFor(() => expect(startCaptions).toHaveBeenCalledWith(64));
		await vi.waitFor(() =>
			expect(toasts.some((t) => t.message === 'Caption capacity is in use — try again shortly')).toBe(true),
		);
	});

	it('clicking the toggle while ON calls stopCaptions; a double-click fires exactly one DELETE (stopBusy guard)', async () => {
		const m = meeting({ meetingId: 65, slug: 'captions-6', myRole: 'host', captionsEnabled: true, captionsOn: true });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false, captionsConfigured: true });
		stopCaptions.mockResolvedValue(undefined);

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(roomState.lastRoom).toBeDefined());
		await vi.waitFor(() => expect(screen.getByLabelText('Turn off live captions')).toBeTruthy());

		const btn = screen.getByLabelText('Turn off live captions');
		fireEvent.click(btn);
		fireEvent.click(btn);
		await vi.waitFor(() => expect(stopCaptions).toHaveBeenCalledTimes(1));
	});

	it('Leave resets the captions chip/toggle (teardownLiveRoom)', async () => {
		// cohost, not host — the ControlsBar `leave` testid only renders for a
		// NON-host role (host gets end-for-all instead, the F3 test precedent).
		const m = meeting({ meetingId: 66, slug: 'captions-7', myRole: 'cohost', captionsEnabled: true, captionsOn: true });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false, captionsConfigured: true });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(roomState.lastRoom).toBeDefined());
		await vi.waitFor(() => expect(screen.getByText('Live captions on')).toBeTruthy());

		await fireEvent.click(screen.getByTestId('leave'));
		await vi.waitFor(() => expect(screen.getByPlaceholderText('Paste a meeting link or code')).toBeTruthy());
		expect(screen.queryByText('Live captions on')).toBeNull();
	});
});

// ── B3 Task 7: breakouts — the move/auto-return choreography, the "not
// recorded" banner swap, and the D4 teardown discipline. ──────────────────
describe('MeetApp — breakouts (Meet B3 Task 7)', () => {
	it('D1/a11y: a self-targeted breakout_assigned push shows the focus-managed interstitial, then joins via room.moveTo', async () => {
		const m = meeting({
			meetingId: 50,
			slug: 'bo-1',
			myRole: 'member',
			breakoutsEnabled: true,
			breakouts: [{ breakoutId: 10, idx: 1, title: 'Room A' }],
		});
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });
		let resolveJoinBreakout: (v: unknown) => void = () => {};
		joinBreakout.mockReturnValue(
			new Promise((resolve) => {
				resolveJoinBreakout = resolve;
			}),
		);

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		capturedHandler!({ '@type': 'MeetEvent', event: { event: 'breakout_assigned', meetingId: 50, payload: { identity: 'u:1', breakoutId: 10 } } });

		// the interstitial renders and takes focus (the B2 D-5 a11y lesson).
		await vi.waitFor(() => expect(screen.getByText('Moving you to Room A…')).toBeTruthy());
		await vi.waitFor(() => expect(document.activeElement?.className).toContain('meet-app__move-interstitial-body'));

		resolveJoinBreakout({ token: 'tok2', wsPath: '/rtc', expiresAt: 'later', recordingActive: false });
		await vi.waitFor(() => expect(joinBreakout).toHaveBeenCalledWith(50, 10));
		await vi.waitFor(() => expect(screen.queryByText('Moving you to Room A…')).toBeNull());
	});

	it('a breakout_assigned push for a DIFFERENT identity only updates the panel map — no move, no interstitial', async () => {
		const m = meeting({
			meetingId: 58,
			slug: 'bo-9',
			myRole: 'host',
			breakoutsEnabled: true,
			breakouts: [{ breakoutId: 10, idx: 1, title: 'Room A' }],
		});
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		capturedHandler!({ '@type': 'MeetEvent', event: { event: 'breakout_assigned', meetingId: 58, payload: { identity: 'u:2', breakoutId: 10 } } });

		expect(joinBreakout).not.toHaveBeenCalled();
		expect(screen.queryByText('Moving you to Room A…')).toBeNull();
	});

	it('D1: a move failure retries once, then falls back to rejoining the main room and toasts moveFailed', async () => {
		const m = meeting({
			meetingId: 51,
			slug: 'bo-2',
			myRole: 'member',
			breakoutsEnabled: true,
			breakouts: [{ breakoutId: 10, idx: 1, title: 'Room A' }],
		});
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });
		joinBreakout.mockRejectedValue(new MeetError({ status: 502, code: '', detail: 'evict failed' }));

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		capturedHandler!({ '@type': 'MeetEvent', event: { event: 'breakout_assigned', meetingId: 51, payload: { identity: 'u:1', breakoutId: 10 } } });

		await vi.waitFor(() => expect(joinBreakout).toHaveBeenCalledTimes(2)); // one automatic retry
		await vi.waitFor(() => expect(join).toHaveBeenCalledTimes(2)); // the initial connect + the D1 fallback rejoin
		await vi.waitFor(() => expect(toasts.some((t) => t.message === 'Could not move you — returning to the main room')).toBe(true));
		await vi.waitFor(() => expect(screen.queryByText('Moving you to Room A…')).toBeNull());
	});

	it('breakout_closed: a member in a breakout auto-rejoins main via api.join, seeding the recording banner from the fresh fact (D3)', async () => {
		const m = meeting({
			meetingId: 52,
			slug: 'bo-3',
			myRole: 'member',
			breakoutsEnabled: true,
			breakouts: [{ breakoutId: 10, idx: 1, title: 'Room A' }],
			myBreakoutId: 10, // D10: already assigned — connectRoom seeds currentBreakoutId from this.
		});
		join.mockResolvedValueOnce({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());
		await vi.waitFor(() => expect(screen.getByText('Breakout rooms are not recorded')).toBeTruthy());

		// the server has closed the breakout and cleared the assignment —
		// the rejoin's own join() response reflects that (myBreakoutId: null),
		// which is what currentBreakoutId now seeds from (retro fix #1, D10).
		join.mockResolvedValueOnce({
			token: 'tok2',
			wsPath: '/rtc',
			expiresAt: 'later',
			meeting: { ...m, myBreakoutId: null },
			recordingActive: true,
		});
		capturedHandler!({ '@type': 'MeetEvent', event: { event: 'breakout_closed', meetingId: 52, payload: null } });

		await vi.waitFor(() => expect(join).toHaveBeenCalledTimes(2));
		// D3: the rejoin's OWN recordingActive fact seeds the banner — asserted,
		// not assumed.
		await vi.waitFor(() => expect(document.querySelector('.recording-banner--active')).toBeTruthy());
		await vi.waitFor(() => expect(screen.queryByText('Breakout rooms are not recorded')).toBeNull());
	});

	it('an unexpected Disconnected while assigned to a breakout triggers the same auto-rejoin choreography', async () => {
		const m = meeting({
			meetingId: 53,
			slug: 'bo-4',
			myRole: 'member',
			breakoutsEnabled: true,
			breakouts: [{ breakoutId: 10, idx: 1, title: 'Room A' }],
			myBreakoutId: 10,
		});
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		roomState.lastRoom!.emit('disconnected'); // RoomEvent.Disconnected's fake-mapped literal
		await vi.waitFor(() => expect(join).toHaveBeenCalledTimes(2));
	});

	it('while connected to a breakout room, the "not recorded" line renders instead of the recording banner', async () => {
		const m = meeting({
			meetingId: 54,
			slug: 'bo-5',
			myRole: 'member',
			myBreakoutId: 10,
			breakouts: [{ breakoutId: 10, idx: 1, title: 'Room A' }],
		});
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: true });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		await vi.waitFor(() => expect(screen.getByText('Breakout rooms are not recorded')).toBeTruthy());
		expect(document.querySelector('.recording-banner--active')).toBeNull();
	});

	// D4 (structural): moved to $lib/meet/store.svelte.test.ts (arch review
	// #A12) — teardownLiveRoom now lives on MeetStore, not MeetApp.

	it('D4 (runtime): leaving mid-breakout tears down the interstitial and the breakout banner — nothing lingers', async () => {
		const m = meeting({
			meetingId: 59,
			slug: 'bo-10',
			myRole: 'member',
			myBreakoutId: 10,
			breakouts: [{ breakoutId: 10, idx: 1, title: 'Room A' }],
		});
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());
		await vi.waitFor(() => expect(screen.getByText('Breakout rooms are not recorded')).toBeTruthy());

		await fireEvent.click(screen.getByTestId('leave'));

		await vi.waitFor(() => expect(screen.queryByText('Breakout rooms are not recorded')).toBeNull());
		expect(document.querySelector('.meet-app__move-interstitial')).toBeNull();
	});
});

// ── B3 retro fixes (post-Task-18 two-reviewer retrospective). ────────────────
describe('MeetApp — breakout retro fixes', () => {
	// HIGH eng finding #1, the D10-redirect bug.
	it('rejoin-while-assigned records the CHILD room id (D10) — captions stay suppressed, "not recorded" banner shows; a later breakout_closed still returns to main', async () => {
		const m = meeting({
			meetingId: 90,
			slug: 'bo-d10',
			myRole: 'member',
			myBreakoutId: 10,
			breakouts: [{ breakoutId: 10, idx: 1, title: 'Room A' }],
		});
		// initial connect: D10 redirect already lands the member in the child room.
		join.mockResolvedValueOnce({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());
		await vi.waitFor(() => expect(screen.getByText('Breakout rooms are not recorded')).toBeTruthy());

		// a mid-breakout Disconnected races a rejoin — the server still
		// reports the SAME live assignment (D10): the plain `join` route
		// redirects back to the child room grant, never main.
		join.mockResolvedValueOnce({ token: 'tok2', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });
		roomState.lastRoom!.emit('disconnected');

		await vi.waitFor(() => expect(join).toHaveBeenCalledTimes(2));
		// still suppressed/not-recorded — currentBreakoutId must be 10, not null.
		await vi.waitFor(() => expect(screen.getByText('Breakout rooms are not recorded')).toBeTruthy());
		expect(document.querySelector('.recording-banner--active')).toBeNull();

		// NOW the host actually closes all breakouts — with currentBreakoutId
		// correctly still 10 (not wrongly stranded at null already), the
		// breakout_closed guard still fires the real return-to-main rejoin.
		join.mockResolvedValueOnce({
			token: 'tok3',
			wsPath: '/rtc',
			expiresAt: 'later',
			meeting: { ...m, myBreakoutId: null },
			recordingActive: true,
		});
		capturedHandler!({ '@type': 'MeetEvent', event: { event: 'breakout_closed', meetingId: 90, payload: null } });

		await vi.waitFor(() => expect(join).toHaveBeenCalledTimes(3));
		await vi.waitFor(() => expect(screen.queryByText('Breakout rooms are not recorded')).toBeNull());
		await vi.waitFor(() => expect(document.querySelector('.recording-banner--active')).toBeTruthy());
	});

	// LOW eng finding #12: a rejoin racing the meeting's own end must not
	// error-screen — the ended push owns that transition.
	it('rejoinMain at an ended meeting (BZ190) leaves the view untouched, not an error screen', async () => {
		const m = meeting({
			meetingId: 91,
			slug: 'bo-bz190',
			myRole: 'member',
			myBreakoutId: 10,
			breakouts: [{ breakoutId: 10, idx: 1, title: 'Room A' }],
		});
		join.mockResolvedValueOnce({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		join.mockRejectedValueOnce(new MeetError({ status: 409, code: 'BZ190', detail: 'meeting has ended' }));
		capturedHandler!({ '@type': 'MeetEvent', event: { event: 'breakout_closed', meetingId: 91, payload: null } });

		await vi.waitFor(() => expect(join).toHaveBeenCalledTimes(2));
		// still in-room (not the generic error screen) — no error message rendered.
		expect(document.querySelector('.controls-bar')).toBeTruthy();
		expect(screen.queryByText('meeting has ended')).toBeNull();
	});

	// B3 confirm-pass fix (eng NEW-1): the SFU eviction that accompanies a
	// meeting end can land BEFORE the meeting_state:ended push. Without also
	// clearing currentBreakoutId in the BZ190 catch, the disconnect $effect's
	// guard never breaks and rejoinMain loops, one POST /join per iteration,
	// until the (loss-tolerant, possibly never-arriving) ended push shows up.
	// Assert exactly ONE rejoin attempt and no loop; a later ended push still
	// lands view='ended'.
	it('eviction-before-ended-push: a disconnect while assigned does not loop rejoinMain when join keeps rejecting BZ190', async () => {
		const m = meeting({
			meetingId: 93,
			slug: 'bo-evict',
			myRole: 'member',
			myBreakoutId: 10,
			breakouts: [{ breakoutId: 10, idx: 1, title: 'Room A' }],
		});
		join.mockResolvedValueOnce({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		// every subsequent join() call rejects BZ190 (the meeting has, in fact,
		// already ended server-side) -- a looping bug would call this
		// unboundedly.
		join.mockRejectedValue(new MeetError({ status: 409, code: 'BZ190', detail: 'meeting has ended' }));

		// the SFU eviction: the room drops out from under the client.
		roomState.lastRoom!.emit('disconnected');

		// the initial connect join() plus exactly ONE rejoin attempt -- never a
		// second, looping one.
		await vi.waitFor(() => expect(join).toHaveBeenCalledTimes(2));
		// give any runaway microtask loop a chance to surface before asserting
		// the count stays put.
		await new Promise((r) => setTimeout(r, 20));
		expect(join).toHaveBeenCalledTimes(2);
		expect(document.querySelector('.controls-bar')).toBeTruthy();

		// the ended push (possibly delayed, per the loss-tolerant push design)
		// still lands the terminal view once it arrives.
		getMeeting.mockResolvedValue(m);
		capturedHandler!({ '@type': 'MeetEvent', event: { event: 'meeting_state', meetingId: 93, payload: { state: 'ended' } } });
		await vi.waitFor(() => expect(screen.getByText('This meeting has ended')).toBeTruthy());
	});

	// design finding #3: a scene left open from the room just vacated must
	// never answer the NEW room's wb_req with the OLD room's scene.
	it('a forced breakout move closes an open whiteboard', async () => {
		const m = meeting({
			meetingId: 92,
			slug: 'bo-wb',
			myRole: 'member',
			breakoutsEnabled: true,
			breakouts: [{ breakoutId: 10, idx: 1, title: 'Room A' }],
		});
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });
		joinBreakout.mockResolvedValue({ token: 'tok2', wsPath: '/rtc', expiresAt: 'later', recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		await fireEvent.click(screen.getByLabelText('Whiteboard'));
		expect(document.querySelector('.meet-app__whiteboard-stage')).toBeTruthy();

		capturedHandler!({ '@type': 'MeetEvent', event: { event: 'breakout_assigned', meetingId: 92, payload: { identity: 'u:1', breakoutId: 10 } } });

		await vi.waitFor(() => expect(joinBreakout).toHaveBeenCalledWith(92, 10));
		await vi.waitFor(() => expect(document.querySelector('.meet-app__whiteboard-stage')).toBeNull());
	});

	it('rejoinMain (the breakout_closed genre) also closes an open whiteboard', async () => {
		const m = meeting({
			meetingId: 93,
			slug: 'bo-wb2',
			myRole: 'member',
			myBreakoutId: 10,
			breakouts: [{ breakoutId: 10, idx: 1, title: 'Room A' }],
		});
		join.mockResolvedValueOnce({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		await fireEvent.click(screen.getByLabelText('Whiteboard'));
		expect(document.querySelector('.meet-app__whiteboard-stage')).toBeTruthy();

		join.mockResolvedValueOnce({
			token: 'tok2',
			wsPath: '/rtc',
			expiresAt: 'later',
			meeting: { ...m, myBreakoutId: null },
			recordingActive: false,
		});
		capturedHandler!({ '@type': 'MeetEvent', event: { event: 'breakout_closed', meetingId: 93, payload: null } });

		await vi.waitFor(() => expect(join).toHaveBeenCalledTimes(2));
		expect(document.querySelector('.meet-app__whiteboard-stage')).toBeNull();
	});

	// design finding #9: a race with the breakout_opened refetch can leave the
	// target room unresolved on the COMMON auto-assign path.
	it('the interstitial falls back to the generic "moving…" copy when the target room is not yet in meeting.breakouts', async () => {
		const m = meeting({
			meetingId: 94,
			slug: 'bo-label-race',
			myRole: 'member',
			breakoutsEnabled: true,
			breakouts: [], // the breakout_opened refetch has not landed yet
		});
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });
		let resolveJoinBreakout: (v: unknown) => void = () => {};
		joinBreakout.mockReturnValue(
			new Promise((resolve) => {
				resolveJoinBreakout = resolve;
			}),
		);

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		capturedHandler!({ '@type': 'MeetEvent', event: { event: 'breakout_assigned', meetingId: 94, payload: { identity: 'u:1', breakoutId: 10 } } });

		await vi.waitFor(() => expect(screen.getByText('Moving you to a breakout room…')).toBeTruthy());
		expect(screen.queryByText(/Moving you to Breakout /)).toBeNull();
		expect(screen.queryByText('Moving you to undefined…')).toBeNull();

		resolveJoinBreakout({ token: 'tok2', wsPath: '/rtc', expiresAt: 'later', recordingActive: false });
		await vi.waitFor(() => expect(screen.queryByText('Moving you to a breakout room…')).toBeNull());
	});

	// design finding #10: a push for a meeting the caller isn't even looking
	// at must not touch this component's local panel map at all.
	it('a breakout_closed push for a FOREIGN meeting leaves the local panel map intact', async () => {
		const m = meeting({
			meetingId: 95,
			slug: 'bo-foreign',
			myRole: 'host',
			breakoutsEnabled: true,
			breakouts: [
				{ breakoutId: 10, idx: 1, title: 'Room A', assignees: [{ identity: 'u:2', displayName: 'Alice' }] },
			],
		});
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		// the assign select is keyed off the LIVE roster (sheetParticipants),
		// not the breakouts[].assignees snapshot — a remote participant must
		// actually be connected for a row to render.
		roomState.lastRoom!.remoteParticipants.set('u:2', {
			identity: 'u:2',
			name: 'Alice',
			videoTrackPublications: new Map(),
			audioTrackPublications: new Map(),
		});
		roomState.lastRoom!.emit('participantConnected');

		await fireEvent.click(screen.getByLabelText('Breakout rooms'));
		await vi.waitFor(() => expect(screen.getByTestId('breakouts-assign-u:2')).toBeTruthy());
		expect((screen.getByTestId('breakouts-assign-u:2') as HTMLSelectElement).value).toBe('10');

		capturedHandler!({ '@type': 'MeetEvent', event: { event: 'breakout_closed', meetingId: 999, payload: null } });

		// the panel map (and the select's own reflection of it) is untouched.
		expect((screen.getByTestId('breakouts-assign-u:2') as HTMLSelectElement).value).toBe('10');
		expect(join).toHaveBeenCalledTimes(1); // no rejoin fired for a foreign meeting
	});

	// eng finding #7/#11: currentBreakoutId must seed from the FRESH join
	// response, not the stale pre-join snapshot fetched before PreJoin dwell.
	it('an assignment made during the PreJoin dwell yields the correct currentBreakoutId after connect (fresh join response, not the stale snapshot)', async () => {
		const preJoinMeeting = meeting({
			meetingId: 96,
			slug: 'bo-fresh',
			myRole: 'member',
			myBreakoutId: null,
			breakouts: [{ breakoutId: 10, idx: 1, title: 'Room A' }],
		});
		// the pre-join fetch (resolveSlug) sees the OLD, unassigned snapshot...
		resolveSlug.mockResolvedValue(preJoinMeeting);
		// ...but by the time PreJoin's Join button is clicked, the host has
		// already assigned this caller — join()'s OWN response is fresher.
		join.mockResolvedValue({
			token: 'tok',
			wsPath: '/rtc',
			expiresAt: 'later',
			meeting: { ...preJoinMeeting, myBreakoutId: 10 },
			recordingActive: false,
		});

		render(MeetApp);
		await vi.waitFor(() => expect(listMeetings).toHaveBeenCalled());
		const joinLinkInput = screen.getByPlaceholderText('Paste a meeting link or code');
		await fireEvent.input(joinLinkInput, { target: { value: preJoinMeeting.slug } });
		await fireEvent.click(screen.getByText('Join by link'));
		await vi.waitFor(() => expect(resolveSlug).toHaveBeenCalledWith(preJoinMeeting.slug));

		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		// currentBreakoutId=10 -> the "not recorded" breakout banner, not the
		// ordinary recording banner — the fresh join response won the race.
		await vi.waitFor(() => expect(screen.getByText('Breakout rooms are not recorded')).toBeTruthy());
	});

	// design finding #11: focus moves INTO the interstitial on mount but used
	// to drop to <body> on exit.
	it('focus returns to the room-main region once the move interstitial unmounts', async () => {
		const m = meeting({
			meetingId: 97,
			slug: 'bo-focus',
			myRole: 'member',
			breakoutsEnabled: true,
			breakouts: [{ breakoutId: 10, idx: 1, title: 'Room A' }],
		});
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });
		// a manually-resolved promise (the D1/a11y test's own pattern) so the
		// interstitial stays open long enough to assert focus moved INTO it,
		// before resolving to assert focus moves back OUT.
		let resolveJoinBreakout: (v: unknown) => void = () => {};
		joinBreakout.mockReturnValue(
			new Promise((resolve) => {
				resolveJoinBreakout = resolve;
			}),
		);

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		capturedHandler!({ '@type': 'MeetEvent', event: { event: 'breakout_assigned', meetingId: 97, payload: { identity: 'u:1', breakoutId: 10 } } });
		await vi.waitFor(() => expect(document.activeElement?.className).toContain('meet-app__move-interstitial-body'));

		resolveJoinBreakout({ token: 'tok2', wsPath: '/rtc', expiresAt: 'later', recordingActive: false });
		await vi.waitFor(() => expect(document.querySelector('.meet-app__move-interstitial')).toBeNull());
		await vi.waitFor(() => expect(document.activeElement?.className).toContain('meet-app__room-main'));
	});
});

// B3 retro fix (design finding #1 — host roaming): the reducer/route layer
// already supported a host/cohost joining/leaving a breakout room; this
// wires the BreakoutsPanel UI entry point through MeetApp's own choreography.
describe('MeetApp — host/cohost breakout roaming (retro fix)', () => {
	it('a host clicking Join in BreakoutsPanel calls joinBreakout and moves into the room', async () => {
		const m = meeting({
			meetingId: 98,
			slug: 'bo-roam',
			myRole: 'host',
			breakoutsEnabled: true,
			breakouts: [{ breakoutId: 10, idx: 1, title: 'Room A' }],
		});
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });
		joinBreakout.mockResolvedValue({ token: 'tok2', wsPath: '/rtc', expiresAt: 'later', recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		await fireEvent.click(screen.getByLabelText('Breakout rooms'));
		await vi.waitFor(() => expect(screen.getByTestId('breakouts-join-10')).toBeTruthy());
		await fireEvent.click(screen.getByTestId('breakouts-join-10'));

		await vi.waitFor(() => expect(joinBreakout).toHaveBeenCalledWith(98, 10));
		await vi.waitFor(() => expect(screen.getByText('Breakout rooms are not recorded')).toBeTruthy());
	});

	it('"Return to main" while roaming calls the plain join route and lands back in main', async () => {
		const m = meeting({
			meetingId: 99,
			slug: 'bo-roam-return',
			myRole: 'host',
			breakoutsEnabled: true,
			breakouts: [{ breakoutId: 10, idx: 1, title: 'Room A' }],
		});
		join.mockResolvedValueOnce({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });
		joinBreakout.mockResolvedValue({ token: 'tok2', wsPath: '/rtc', expiresAt: 'later', recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		await fireEvent.click(screen.getByLabelText('Breakout rooms'));
		await fireEvent.click(screen.getByTestId('breakouts-join-10'));
		await vi.waitFor(() => expect(screen.getByText('Breakout rooms are not recorded')).toBeTruthy());

		join.mockResolvedValueOnce({ token: 'tok3', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });
		await vi.waitFor(() => expect(screen.getByTestId('breakouts-return-main')).toBeTruthy());
		await fireEvent.click(screen.getByTestId('breakouts-return-main'));

		await vi.waitFor(() => expect(join).toHaveBeenCalledTimes(2));
		await vi.waitFor(() => expect(screen.queryByText('Breakout rooms are not recorded')).toBeNull());
	});

	// D3's filter posture — a plain member never gets roaming affordances.
	it('a plain member does not see Join buttons in the breakouts panel (no BreakoutsPanel access at all — host/cohost only)', async () => {
		const m = meeting({
			meetingId: 100,
			slug: 'bo-roam-member',
			myRole: 'member',
			breakoutsEnabled: true,
			breakouts: [{ breakoutId: 10, idx: 1, title: 'Room A' }],
		});
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		// the breakouts icon itself is host/cohost-only (ControlsBar), so a
		// member never reaches the panel — the strongest form of D3's filter.
		expect(screen.queryByLabelText('Breakout rooms')).toBeNull();
	});
});

// UX #9 (whole-pipeline review): LobbyPanel used to be unconditionally
// docked whenever host/cohost — on a narrow viewport that crushed the video
// region. It now joins the sidePanel exclusive slot (same toggle mechanism
// as chat/breakouts) and `.meet-app__side` gets the MeetChatPanel mobile-
// overlay treatment (CSS-only, asserted separately at the stylesheet level
// is impractical in jsdom — these tests instead pin the toggle/close
// behavior and the notification fallback that toggle needed).
describe('MeetApp — LobbyPanel toggle (whole-pipeline review UX #9)', () => {
	it('LobbyPanel is not rendered until the host opens it via ControlsBar, and its own close button hides it again', async () => {
		const m = meeting({
			meetingId: 200,
			slug: 'lobby-1',
			myRole: 'host',
			pendingJoinRequests: [{ requestId: 1, displayName: 'Alice', isMemberKnock: false, createdAt: '', expiresAt: '' }],
		});
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		// not docked by default (the crushed-video bug this fixes)
		expect(document.querySelector('.lobby-panel')).toBeNull();

		await fireEvent.click(screen.getByLabelText('Waiting to join (1)'));
		await vi.waitFor(() => expect(document.querySelector('.lobby-panel')).toBeTruthy());
		expect(screen.getByText('Alice')).toBeTruthy();

		await fireEvent.click(screen.getByLabelText('Close'));
		await vi.waitFor(() => expect(document.querySelector('.lobby-panel')).toBeNull());
	});

	it('a plain member never sees the Lobby toggle (host/cohost only, the breakouts-button precedent)', async () => {
		const m = meeting({ meetingId: 201, slug: 'lobby-2', myRole: 'member' });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		expect(screen.queryByLabelText('Waiting to join')).toBeNull();
	});

	it('a knock while the Lobby panel is closed shows a toast whose action opens it (bug fix: the panel used to silently miss live knocks while open, too — this also refreshes meeting on every same-room event)', async () => {
		const m = meeting({ meetingId: 202, slug: 'lobby-3', myRole: 'host', pendingJoinRequests: [] });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });
		getMeeting.mockResolvedValue({
			...m,
			pendingJoinRequests: [{ requestId: 5, displayName: 'Bob', isMemberKnock: false, createdAt: '', expiresAt: '' }],
		});

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());
		clearToasts();

		capturedHandler!({ '@type': 'MeetEvent', event: { event: 'join_request_created', meetingId: 202 } });
		await vi.waitFor(() => expect(toasts.length).toBeGreaterThan(0));
		expect(toasts[0]?.message).toContain('Bob');

		// the toast's action opens the panel directly (no page nav — the
		// caller is already in this exact room)
		toasts[0]?.onAction?.();
		await vi.waitFor(() => expect(document.querySelector('.lobby-panel')).toBeTruthy());
		expect(screen.getByText('Bob')).toBeTruthy(); // refreshed meeting flowed into the panel
	});

	it('a knock while the Lobby panel is open refreshes the list silently (no duplicate toast)', async () => {
		const m = meeting({ meetingId: 203, slug: 'lobby-4', myRole: 'host', pendingJoinRequests: [] });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });
		getMeeting.mockResolvedValue({
			...m,
			pendingJoinRequests: [{ requestId: 6, displayName: 'Carol', isMemberKnock: false, createdAt: '', expiresAt: '' }],
		});

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());
		await fireEvent.click(screen.getByLabelText('Waiting to join'));
		await vi.waitFor(() => expect(document.querySelector('.lobby-panel')).toBeTruthy());
		clearToasts();

		capturedHandler!({ '@type': 'MeetEvent', event: { event: 'join_request_created', meetingId: 203 } });
		await vi.waitFor(() => expect(screen.getByText('Carol')).toBeTruthy());
		expect(toasts.length).toBe(0);
	});
});

describe('MeetApp — whiteboard (Meet B3 Task 9)', () => {
	it('the Whiteboard button mounts the panel on the main stage; clicking again closes it', async () => {
		const m = meeting({ meetingId: 70, slug: 'wb-1', myRole: 'member' });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		expect(document.querySelector('.meet-app__whiteboard-stage')).toBeNull();
		expect(document.querySelector('.meet-app__video-region--collapsed')).toBeNull();

		await fireEvent.click(screen.getByLabelText('Whiteboard'));
		expect(document.querySelector('.meet-app__whiteboard-stage')).toBeTruthy();
		expect(document.querySelector('.meet-app__video-region--collapsed')).toBeTruthy();

		await fireEvent.click(screen.getByLabelText('Whiteboard'));
		expect(document.querySelector('.meet-app__whiteboard-stage')).toBeNull();
		expect(document.querySelector('.meet-app__video-region--collapsed')).toBeNull();
	});

	it('is available to a plain member (unconditional, no server toggle — DN6)', async () => {
		const m = meeting({ meetingId: 71, slug: 'wb-2', myRole: 'member' });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		expect(screen.getByLabelText('Whiteboard')).not.toBeDisabled();
	});
});

// [Slack-semantics client consequence, pipeline review] a huddle bound to a
// pre-existing private channel/DM no longer auto-joins a non-member joiner
// into the channel's history (V131, backend fix) — meeting_get's envelope
// carries chatChannelMember so the client can hide the bridged chat/Poll/Q&A
// entry points for a participant who is genuinely not a channel member,
// rather than opening an empty/erroring panel.
describe('MeetApp — huddle chat-bridge membership (V131 chatChannelMember)', () => {
	it('hides the chat + poll entry points when chatChannelMember is false, even though chatChannelId is set', async () => {
		const m = meeting({ meetingId: 180, slug: 'huddle-nonmember', myRole: 'member', chatChannelId: 5, chatChannelMember: false });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		expect(screen.queryByLabelText('Chat')).toBeNull();
		expect(screen.queryByLabelText('Poll')).toBeNull();
	});

	it('shows the chat + poll entry points when chatChannelMember is true (the default provisioned-huddle/regular-meeting shape)', async () => {
		const m = meeting({ meetingId: 181, slug: 'huddle-member', myRole: 'member', chatChannelId: 5, chatChannelMember: true });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		expect(screen.getByLabelText('Chat')).toBeTruthy();
		expect(screen.getByLabelText('Poll')).toBeTruthy();
	});
});

// B1 live-gate ledger fix 1: a kicked MEMBER's browser used to have no
// handler at all for the eviction — frozen in-room forever (the ledger's own
// wording). notify_meet_state's fan-out excludes the just-kicked identity
// (left_at is stamped before the PERFORM runs), so the ONLY signal the
// kicked caller's own client ever gets is LiveKit's Disconnected event with
// reason PARTICIPANT_REMOVED — room.svelte.ts's disconnectReason field
// (added, but never consumed, before this fix).
describe('MeetApp — kicked (B1 live-gate ledger fix 1)', () => {
	it('a Disconnected with reason PARTICIPANT_REMOVED shows the removed view, stops media, and never auto-rejoins', async () => {
		const m = meeting({ meetingId: 300, slug: 'kicked-1', myRole: 'member' });
		join.mockResolvedValueOnce({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());
		expect(join).toHaveBeenCalledTimes(1);

		roomState.lastRoom!.emit('disconnected', 4); // DisconnectReason.PARTICIPANT_REMOVED

		await vi.waitFor(() => expect(screen.getByText('You were removed from this meeting')).toBeTruthy());
		expect(screen.getByText(/The host removed you/)).toBeTruthy();
		expect(document.querySelector('.controls-bar')).toBeNull();
		// teardownLiveRoom() actually disconnected the underlying Room (stops
		// local media) rather than merely swapping the view over a live room.
		expect(roomState.lastRoom!.disconnect).toHaveBeenCalled();

		// idempotent, no retry loop (the fc7672f8 bug class): give any runaway
		// microtask a chance to surface, then confirm join() never fires again.
		await new Promise((r) => setTimeout(r, 20));
		expect(join).toHaveBeenCalledTimes(1);
	});

	it('a kick landing mid-breakout shows the removed view instead of the breakout auto-return effect racing a doomed rejoinMain', async () => {
		const m = meeting({
			meetingId: 301,
			slug: 'kicked-2',
			myRole: 'member',
			myBreakoutId: 10,
			breakouts: [{ breakoutId: 10, idx: 1, title: 'Room A' }],
		});
		join.mockResolvedValueOnce({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());
		expect(join).toHaveBeenCalledTimes(1);

		roomState.lastRoom!.emit('disconnected', 4);

		await vi.waitFor(() => expect(screen.getByText('You were removed from this meeting')).toBeTruthy());
		// rejoinMain (the breakout auto-return branch) must never have fired —
		// join() stays at its one initial call, not a second doomed attempt.
		expect(join).toHaveBeenCalledTimes(1);
	});

	it('a plain reconnect (no PARTICIPANT_REMOVED reason) does not show the removed view', async () => {
		const m = meeting({ meetingId: 302, slug: 'kicked-3', myRole: 'member' });
		join.mockResolvedValueOnce({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		roomState.lastRoom!.emit('disconnected', 1); // DisconnectReason.CLIENT_INITIATED
		await new Promise((r) => setTimeout(r, 20));
		expect(screen.queryByText('You were removed from this meeting')).toBeNull();
	});

	it('Close on the removed view returns to the landing screen', async () => {
		const m = meeting({ meetingId: 303, slug: 'kicked-4', myRole: 'member' });
		join.mockResolvedValueOnce({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		roomState.lastRoom!.emit('disconnected', 4);
		await vi.waitFor(() => expect(screen.getByText('You were removed from this meeting')).toBeTruthy());

		await fireEvent.click(screen.getByText('Close'));
		await vi.waitFor(() => expect(screen.getByPlaceholderText('Meeting title')).toBeTruthy());
	});
});

// B1 live-gate ledger fix 2: the ban-until-re-admit posture had no UI
// affordance to clear a ban — meeting_set_role IS the re-admit path
// (assigning a role to a banned identity clears banned_at server-side,
// meeting_control.sql's own comment), so this wires the SAME setRole call
// the "Make co-host" button already uses, surfaced via the participant_kicked
// push (the one live signal available — meeting_get projects no bannedAt).
describe('MeetApp — banned/re-admit (B1 live-gate ledger fix 2)', () => {
	it('a participant_kicked push adds a Re-admit row (resolved name, never the raw identity), and Re-admit calls setRole', async () => {
		const m = meeting({ meetingId: 310, slug: 'readmit-1', myRole: 'host' });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });
		setRole.mockResolvedValue(undefined);

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		roomState.lastRoom!.remoteParticipants.set('u:2', {
			identity: 'u:2',
			name: 'Bob',
			videoTrackPublications: new Map(),
			audioTrackPublications: new Map(),
		});
		roomState.lastRoom!.emit('participantConnected');

		capturedHandler!({
			'@type': 'MeetEvent',
			event: { event: 'participant_kicked', meetingId: 310, payload: { identity: 'u:2' } },
		});

		await fireEvent.click(screen.getByLabelText('Participants'));
		await vi.waitFor(() => expect(screen.getByText('Removed from this meeting')).toBeTruthy());
		// resolved display name renders (never the raw 'u:2' identity) — Bob
		// appears both in the live roster row above and the new banned row.
		expect(screen.getAllByText('Bob').length).toBeGreaterThanOrEqual(1);
		expect(screen.queryByText('u:2')).toBeNull();

		await fireEvent.click(screen.getByText('Re-admit'));
		await vi.waitFor(() => expect(setRole).toHaveBeenCalledWith(310, 'u:2', 'member'));
	});

	// A/B leftover item 1: meeting_get now projects a durable banned[] —
	// bannedMembers is seeded from it on load, not just built live off a
	// participant_kicked push, so a host who reloads mid-meeting still sees
	// everyone kicked before the reload.
	it('seeds the Re-admit list from meeting.banned[] on load, with no participant_kicked push at all', async () => {
		const m = meeting({
			meetingId: 313,
			slug: 'readmit-durable',
			myRole: 'host',
			banned: [{ identity: 'u:9', displayName: 'Zoe', bannedAt: '2026-07-16T00:00:00Z' }],
		});
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });
		setRole.mockResolvedValue(undefined);

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		await fireEvent.click(screen.getByLabelText('Participants'));
		await vi.waitFor(() => expect(screen.getByText('Removed from this meeting')).toBeTruthy());
		expect(screen.getByText('Zoe')).toBeTruthy();

		await fireEvent.click(screen.getByText('Re-admit'));
		await vi.waitFor(() => expect(setRole).toHaveBeenCalledWith(313, 'u:9', 'member'));
	});

	it('a participant_role push for a banned identity clears it from the list (push-is-truth, never optimistic)', async () => {
		const m = meeting({ meetingId: 311, slug: 'readmit-2', myRole: 'host' });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		capturedHandler!({
			'@type': 'MeetEvent',
			event: { event: 'participant_kicked', meetingId: 311, payload: { identity: 'u:2' } },
		});
		await fireEvent.click(screen.getByLabelText('Participants'));
		await vi.waitFor(() => expect(screen.getByText('Removed from this meeting')).toBeTruthy());

		capturedHandler!({
			'@type': 'MeetEvent',
			event: { event: 'participant_role', meetingId: 311, payload: { identity: 'u:2', role: 'member' } },
		});
		await vi.waitFor(() => expect(screen.queryByText('Removed from this meeting')).toBeNull());
	});

	it('a participant_kicked push for a DIFFERENT meeting is ignored', async () => {
		const m = meeting({ meetingId: 312, slug: 'readmit-3', myRole: 'host' });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });

		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(document.querySelector('.controls-bar')).toBeTruthy());

		capturedHandler!({
			'@type': 'MeetEvent',
			event: { event: 'participant_kicked', meetingId: 999, payload: { identity: 'u:2' } },
		});
		await fireEvent.click(screen.getByLabelText('Participants'));
		expect(screen.queryByText('Removed from this meeting')).toBeNull();
	});
});

describe('MEET-DP1 actionable departed-presentation cleanup', () => {
	it('keeps a cleanup Retry toast and retries original IDs after rebind', async () => {
		const { MeetStore } = await import('$lib/meet/store.svelte');
		const { httpPresentationApi } = await import('$lib/meet/presentationApi');
		const { tick } = await import('svelte');
		let owner!: InstanceType<typeof MeetStore>;
		const load = MeetStore.prototype.loadMeetings;
		const capture = vi.spyOn(MeetStore.prototype, 'loadMeetings').mockImplementation(function (this: InstanceType<typeof MeetStore>) {
			owner = this;
			return load.call(this);
		});
		let accept!: (value: { presentationId: number; status: 'READY'; checkpointSeq: number }) => void;
		const prepare = vi.spyOn(httpPresentationApi, 'prepare').mockReturnValue(new Promise((resolve) => { accept = resolve; }));
		const drain = vi.spyOn(httpPresentationApi, 'end').mockRejectedValueOnce(new Error('offline')).mockResolvedValue(undefined);
		const { unmount } = render(MeetApp);
		try {
			await tick();
			owner.presentation.bind(42, () => null);
			const work = owner.presentation.prepare(7, 9);
			owner.presentation.cancelPrepare();
			owner.presentation.bind(84, () => null);
			accept({ presentationId: 19, status: 'READY', checkpointSeq: 1 });
			await work;
			await tick();
			const notice = toasts.find((notice) => notice.message.includes('cancelled presentation'));
			expect(notice?.message).toContain('meeting 42');
			expect(notice?.actionLabel).toBe('Retry');
			expect(notice?.durationMs).toBe(0);
			await notice?.onAction?.();
			await tick();
			expect(drain.mock.calls).toEqual([[42, 19], [42, 19]]);
			expect(owner.presentation.cleanupFailures).toEqual([]);
			expect(toasts.some((notice) => notice.message.includes('cancelled presentation'))).toBe(false);
		} finally {
			unmount();
			capture.mockRestore();
			prepare.mockRestore();
			drain.mockRestore();
		}
	});
});

describe('MEET-DP1 presentation caller lifetimes', () => {
	afterEach(() => vi.restoreAllMocks());

	async function connectedPresentationApp() {
		const { MeetStore } = await import('$lib/meet/store.svelte');
		const { httpPresentationApi } = await import('$lib/meet/presentationApi');
		const driveApi = await import('$lib/drive/api');
		let owner!: InstanceType<typeof MeetStore>;
		const load = MeetStore.prototype.loadMeetings;
		vi.spyOn(MeetStore.prototype, 'loadMeetings').mockImplementation(function (this: InstanceType<typeof MeetStore>) {
			owner = this;
			return load.call(this);
		});
		vi.spyOn(driveApi, 'listSpaces').mockResolvedValue([{ id: 1, name: 'Documents' }] as never);
		vi.spyOn(driveApi, 'tree').mockResolvedValue([{ id: 12, kind: 'file', name: 'launch.pdf', headVersionId: 3 }] as never);
		vi.spyOn(driveApi, 'listVersions').mockResolvedValue([{ id: 3, createdAt: '2026-09-22T00:00:00Z' }] as never);
		const checkpoint = vi.spyOn(httpPresentationApi, 'getCheckpoint').mockResolvedValue({
			presentationId: 19, status: 'READY', checkpointSeq: 1,
			presenterGeneration: 1, presenterParticipantId: 7, pageIndex: 0,
			manifestGeneration: 1, manifestDigest: 'digest', driveNodeId: 12,
			driveVersionId: 3, myParticipantId: 7, amPresenter: true,
		});
		vi.spyOn(httpPresentationApi, 'getManifest').mockRejectedValue(new Error('unavailable manifest route'));
		const drain = vi.spyOn(httpPresentationApi, 'end').mockResolvedValue(undefined);
		const m = meeting({ meetingId: 42, slug: 'presentation-lifetime', presentationEnabled: true, presentation: null,
			breakoutsEnabled: true, breakouts: [{ breakoutId: 10, idx: 1, title: 'Room A' }] });
		join.mockResolvedValue({ token: 'tok', wsPath: '/rtc', expiresAt: 'later', meeting: m, recordingActive: false });
		await toPreJoin(m);
		await clickPreJoinJoin();
		await vi.waitFor(() => expect(screen.getByTestId('present-document')).toBeTruthy());
		// The shared LiveKit fake resolves connect but does not emit its event.
		// Drive the real room connection lifecycle before testing reauthorization.
		roomState.lastRoom!.emit('connected');
		const { tick } = await import('svelte');
		await tick();
		return { owner, api: httpPresentationApi, checkpoint, drain };
	}

	async function pickDocument() {
		await fireEvent.click(screen.getByTestId('present-document'));
		await fireEvent.click(await screen.findByTestId('picker-file-12'));
		await fireEvent.click(await screen.findByTestId('picker-prepare'));
	}

	it('whiteboard return permits the first preparation and retains its READY preview', async () => {
		const { owner, api } = await connectedPresentationApp();
		const prepare = vi.spyOn(api, 'prepare').mockResolvedValue({ presentationId: 19, status: 'READY', checkpointSeq: 1 });
		await fireEvent.click(screen.getByLabelText('Whiteboard'));
		await owner.presentation.prepare(12, 3);
		expect(prepare).not.toHaveBeenCalled();
		await fireEvent.click(screen.getByLabelText('Whiteboard'));
		expect(owner.presentation.isLive).toBe(false);
		await pickDocument();
		expect(prepare).toHaveBeenCalledExactlyOnceWith(42, { nodeId: 12, versionId: 3, manifestDigest: '' });
		await vi.waitFor(() => expect(owner.presentation.isPreviewing).toBe(true));
		await fireEvent.click(screen.getByRole('button', { name: 'Close' }));
	});

	it('whiteboard and breakout suspension deny preparation across reconnect and whiteboard close', async () => {
		const { owner, api } = await connectedPresentationApp();
		const prepare = vi.spyOn(api, 'prepare').mockRejectedValue({ code: 'documentProtected' });
		const { tick } = await import('svelte');
		owner.room!.connectionState = 'reconnecting';
		await fireEvent.click(screen.getByLabelText('Whiteboard'));
		await owner.presentation.prepare(12, 3);
		expect(prepare).not.toHaveBeenCalled();
		owner.room!.connectionState = 'connected';
		await tick();
		await owner.presentation.prepare(12, 3);
		expect(prepare).not.toHaveBeenCalled();
		await fireEvent.click(screen.getByLabelText('Whiteboard'));
		owner.currentBreakoutId = 10;
		await tick();
		await fireEvent.click(screen.getByLabelText('Whiteboard'));
		await fireEvent.click(screen.getByLabelText('Whiteboard'));
		await owner.presentation.prepare(12, 3);
		expect(prepare).not.toHaveBeenCalled();
		expect(screen.queryByTestId('present-document')).toBeNull();
	});

	for (const dismissal of ['Close', 'Escape'] as const) {
		it(`${dismissal} during pending prepare drains late acceptance without reopening the picker`, async () => {
			const { owner, api, checkpoint, drain } = await connectedPresentationApp();
			let accept!: (value: Awaited<ReturnType<typeof api.prepare>>) => void;
			const prepare = vi.spyOn(api, 'prepare').mockReturnValue(new Promise((resolve) => { accept = resolve; }));
			if (dismissal === 'Escape') drain.mockRejectedValueOnce(new Error('offline'));
			await pickDocument();
			expect(prepare).toHaveBeenCalledTimes(1);
			if (dismissal === 'Close') await fireEvent.click(screen.getByRole('button', { name: 'Close' }));
			else await fireEvent.keyDown(screen.getByRole('dialog'), { key: 'Escape' });
			expect(screen.queryByTestId('presentation-picker')).toBeNull();
			accept({ presentationId: 19, status: 'READY', checkpointSeq: 1 });
			await vi.waitFor(() => expect(drain).toHaveBeenCalledExactlyOnceWith(42, 19));
			expect(checkpoint).not.toHaveBeenCalled();
			expect(owner.presentation.pickerOpen).toBe(false);
			expect(screen.queryByTestId('presentation-picker')).toBeNull();
			if (dismissal === 'Escape') {
				await vi.waitFor(() => expect(toasts.some((notice) => notice.message.includes('cancelled presentation'))).toBe(true));
				const notice = toasts.find((notice) => notice.message.includes('cancelled presentation'))!;
				expect(notice.actionLabel).toBe('Retry');
				expect(notice.durationMs).toBe(0);
				owner.presentation.bind(84, () => null);
				await notice.onAction?.();
				expect(drain.mock.calls).toEqual([[42, 19], [42, 19]]);
				expect(owner.presentation.cleanupFailures).toEqual([]);
			}
		});
	}
});
