// join.test.ts — Meet B1 Task 17 named tests: the guest lobby page's own
// state machine, on top of what LobbyWaiting.test.ts / guestReconnect.test.ts
// / PreJoin.test.ts / MeetingRoom.test.ts / ControlsBar.test.ts already cover
// in isolation. Mirrors booking.test.ts's convention for testing a
// `[slug]/+page.svelte` from a sibling file, and room.svelte.test.ts's
// livekit-client fake (this page reaches real MeetRoom.connect, so the SFU
// test seam applies here too — the plan's "SFU is NOT run in unit tests").
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import { page } from '$app/state';
import GuestJoinPage from './[slug]/+page.svelte';
import { authenticated, authInitializing } from '$lib/stores/auth';

const guestJoinRequest = vi.fn();
const guestPoll = vi.fn();
vi.mock('$lib/meet/api', async () => {
	const actual = await vi.importActual<typeof import('$lib/meet/api')>('$lib/meet/api');
	return {
		...actual,
		guestJoinRequest: (...a: unknown[]) => guestJoinRequest(...a),
		guestPoll: (...a: unknown[]) => guestPoll(...a),
	};
});

const gotoMock = vi.fn();
vi.mock('$app/navigation', () => ({ goto: (...a: unknown[]) => gotoMock(...a) }));

const pickVideoCodec = vi.fn(async () => 'vp8' as const);
vi.mock('$lib/meet/codecProbe', () => ({ pickVideoCodec: () => pickVideoCodec() }));

vi.mock('$lib/meet/blur', () => ({
	isBlurAvailable: () => false,
	loadBlurPref: () => false,
	saveBlurPref: () => undefined,
	setBlur: async () => true,
}));

// vi.mock factories are hoisted above every import (incl. the static import
// of GuestJoinPage below, which transitively imports 'livekit-client' via
// $lib/meet/room.svelte and $lib/components/meet/PreJoin.svelte) — so the
// fake classes the factory closes over must themselves be defined inside
// vi.hoisted, or the factory runs before they exist (room.svelte.test.ts
// dodges this by never statically importing ./room.svelte; this file can't
// avoid it, since it imports the +page.svelte that does).
type Handler = (...args: unknown[]) => void;

const { FakeRoomInner, roomState } = vi.hoisted(() => {
	class FakeLocalParticipant {
		identity = 'g:1';
		name = 'Alex Guest';
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

async function fillNameAndSubmit(name = 'Alex Guest'): Promise<void> {
	const input = screen.getByLabelText('Your name') as HTMLInputElement;
	await fireEvent.input(input, { target: { value: name } });
	await fireEvent.click(screen.getByText('Ask to join'));
}

beforeEach(() => {
	(page as unknown as { params: Record<string, string> }).params = { slug: 'meet-slug-1' };
	authenticated.set(false);
	authInitializing.set(false);
	roomState.lastRoom = undefined;
	// mockResolvedValueOnce queues survive vi.clearAllMocks() (it only clears
	// calls/instances, not queued implementations) — an unconsumed queue
	// entry from one multi-step test would otherwise leak into the next.
	guestJoinRequest.mockReset();
	guestPoll.mockReset();
	vi.stubGlobal('navigator', { ...navigator, mediaDevices: { getUserMedia: async () => fakeStream() } });
});

afterEach(() => {
	vi.clearAllMocks();
	vi.unstubAllGlobals();
	(page as unknown as { params: Record<string, string> }).params = {};
	authenticated.set(false);
	authInitializing.set(true);
});

describe('/meet/join/[slug] (guest lobby page)', () => {
	it('an authenticated visitor is redirected into the app instead of seeing the guest form', async () => {
		authenticated.set(true);
		render(GuestJoinPage);
		await vi.waitFor(() => expect(gotoMock).toHaveBeenCalledWith('/meet?slug=meet-slug-1', { replaceState: true }));
	});

	it('submits the display-name form via guestJoinRequest and shows the shared waiting screen', async () => {
		guestJoinRequest.mockResolvedValue({ requestId: 7, secret: 'sec' });
		guestPoll.mockReturnValue(new Promise(() => {})); // stays pending
		render(GuestJoinPage);

		await fillNameAndSubmit();
		expect(guestJoinRequest).toHaveBeenCalledWith('meet-slug-1', 'Alex Guest');
		await vi.waitFor(() => expect(screen.getByTestId('lobby-waiting')).toBeTruthy());
	});

	it('admits the guest, connects the room, and mounts the in-room chrome with the guest chat notice', async () => {
		guestJoinRequest.mockResolvedValue({ requestId: 7, secret: 'sec' });
		guestPoll.mockResolvedValue({ state: 'admitted', token: 'tok', wsPath: '/rtc', expiresAt: 'later' });
		render(GuestJoinPage);

		await fillNameAndSubmit();
		await vi.waitFor(() => expect(roomState.lastRoom).toBeDefined());
		expect(roomState.lastRoom!.connect).toHaveBeenCalledWith(`ws://${location.host}/rtc`, 'tok');
		await vi.waitFor(() => expect(screen.getByText("Guests in this meeting can't see chat")).toBeTruthy());
		// no host controls for a guest: no lock/end-for-all surface
		expect(screen.queryByText('Lock meeting')).toBeNull();
		expect(screen.queryByText('End meeting for all')).toBeNull();
	});

	it('a Disconnected classified as denied (kicked) shows the removed terminal state', async () => {
		guestJoinRequest.mockResolvedValue({ requestId: 7, secret: 'sec' });
		guestPoll
			.mockResolvedValueOnce({ state: 'admitted', token: 'tok', wsPath: '/rtc', expiresAt: 'later' })
			.mockResolvedValueOnce({ state: 'denied' });
		render(GuestJoinPage);

		await fillNameAndSubmit();
		// roomState.lastRoom is set the instant `new Room()` runs (inside
		// MeetRoom's constructor), which is BEFORE the awaited connect()
		// resolves and view actually flips to 'in-room' — wait for the
		// in-room marker itself so the listener connectRoom attaches is
		// guaranteed live and `view === 'in-room'` really holds.
		await vi.waitFor(() => expect(screen.getByText("Guests in this meeting can't see chat")).toBeTruthy());
		roomState.lastRoom!.emit('disconnected', 'PARTICIPANT_REMOVED');

		await vi.waitFor(() => expect(screen.getByText('You were removed from the meeting.')).toBeTruthy());
	});

	it('a Disconnected classified as expired (meeting ended) shows the ended terminal state', async () => {
		guestJoinRequest.mockResolvedValue({ requestId: 7, secret: 'sec' });
		guestPoll
			.mockResolvedValueOnce({ state: 'admitted', token: 'tok', wsPath: '/rtc', expiresAt: 'later' })
			.mockResolvedValueOnce({ state: 'expired' });
		render(GuestJoinPage);

		await fillNameAndSubmit();
		await vi.waitFor(() => expect(screen.getByText("Guests in this meeting can't see chat")).toBeTruthy());
		roomState.lastRoom!.emit('disconnected', 'ROOM_DELETED');

		await vi.waitFor(() => expect(screen.getByText('The meeting has ended.')).toBeTruthy());
	});

	// med-shard3-021 (CWE-359): a post-disconnect reconnect poll carries the
	// same recordingActive admission fact as the original admit — a recording
	// that started mid-call must re-present RecordingConsentGate before the
	// guest rejoins, through the same gate evaluation as the first admission.
	it('a reconnect after disconnect while recording re-presents the consent gate before joining', async () => {
		guestJoinRequest.mockResolvedValue({ requestId: 7, secret: 'sec' });
		guestPoll
			.mockResolvedValueOnce({ state: 'admitted', token: 'tok', wsPath: '/rtc', expiresAt: 'later' })
			.mockResolvedValueOnce({ state: 'admitted', token: 'tok2', wsPath: '/rtc', expiresAt: 'later2', recordingActive: true });
		render(GuestJoinPage);

		await fillNameAndSubmit();
		await vi.waitFor(() => expect(screen.getByText("Guests in this meeting can't see chat")).toBeTruthy());
		roomState.lastRoom!.emit('disconnected', 'SERVER_SHUTDOWN');

		await vi.waitFor(() =>
			expect(
				screen.getByText('This meeting is being recorded. If you join, your voice and video will be part of the recording.'),
			).toBeTruthy(),
		);
		// the gate sits BEFORE the reconnect's MeetRoom.connect — exactly one
		// connect so far (the original admission), none since the disconnect.
		expect(roomState.lastRoom!.connect).toHaveBeenCalledTimes(1);

		await fireEvent.click(screen.getByText('Join'));
		await vi.waitFor(() => expect(screen.getByText("Guests in this meeting can't see chat")).toBeTruthy());
		expect(roomState.lastRoom!.connect).toHaveBeenLastCalledWith(`ws://${location.host}/rtc`, 'tok2');
	});

	it('declining the reconnect consent gate returns to the join form without reconnecting', async () => {
		guestJoinRequest.mockResolvedValue({ requestId: 7, secret: 'sec' });
		guestPoll
			.mockResolvedValueOnce({ state: 'admitted', token: 'tok', wsPath: '/rtc', expiresAt: 'later' })
			.mockResolvedValueOnce({ state: 'admitted', token: 'tok2', wsPath: '/rtc', expiresAt: 'later2', recordingActive: true });
		render(GuestJoinPage);

		await fillNameAndSubmit();
		await vi.waitFor(() => expect(screen.getByText("Guests in this meeting can't see chat")).toBeTruthy());
		roomState.lastRoom!.emit('disconnected', 'SERVER_SHUTDOWN');

		await vi.waitFor(() =>
			expect(
				screen.getByText('This meeting is being recorded. If you join, your voice and video will be part of the recording.'),
			).toBeTruthy(),
		);
		await fireEvent.click(screen.getByText("Don't join"));

		await vi.waitFor(() => expect(screen.getByText('Ask to join')).toBeTruthy()); // back at the form
		expect(roomState.lastRoom!.connect).toHaveBeenCalledTimes(1); // the pre-disconnect connect only
		expect(
			screen.queryByText('This meeting is being recorded. If you join, your voice and video will be part of the recording.'),
		).toBeNull();
	});

	// Regression: a reconnect whose poll carries NO recordingActive flag stays
	// frictionless — direct reconnection, no interstitial (pre-existing design
	// #7 behavior, now pinned).
	it('a non-recording reconnect stays frictionless — no consent gate, direct reconnection', async () => {
		guestJoinRequest.mockResolvedValue({ requestId: 7, secret: 'sec' });
		guestPoll
			.mockResolvedValueOnce({ state: 'admitted', token: 'tok', wsPath: '/rtc', expiresAt: 'later' })
			.mockResolvedValueOnce({ state: 'admitted', token: 'tok2', wsPath: '/rtc', expiresAt: 'later2' });
		render(GuestJoinPage);

		await fillNameAndSubmit();
		await vi.waitFor(() => expect(screen.getByText("Guests in this meeting can't see chat")).toBeTruthy());
		roomState.lastRoom!.emit('disconnected', 'SERVER_SHUTDOWN');

		await vi.waitFor(() => expect(roomState.lastRoom!.connect).toHaveBeenLastCalledWith(`ws://${location.host}/rtc`, 'tok2'));
		await vi.waitFor(() => expect(screen.getByText("Guests in this meeting can't see chat")).toBeTruthy());
		expect(screen.queryByText('This meeting is being recorded')).toBeNull();
	});

	// Meet B2 Task 10, D5's flicker-window belt.
	it('a pending poll response carrying recordingActive renders the consent text on the waiting screen', async () => {
		guestJoinRequest.mockResolvedValue({ requestId: 7, secret: 'sec' });
		guestPoll.mockResolvedValue({ state: 'pending', recordingActive: true });
		render(GuestJoinPage);

		await fillNameAndSubmit();
		await vi.waitFor(() => expect(screen.getByText('This meeting is being recorded')).toBeTruthy());
	});

	it('an admitted grant carrying recordingActive shows the interstitial before connecting', async () => {
		guestJoinRequest.mockResolvedValue({ requestId: 7, secret: 'sec' });
		guestPoll.mockResolvedValue({ state: 'admitted', token: 'tok', wsPath: '/rtc', expiresAt: 'later', recordingActive: true });
		render(GuestJoinPage);

		await fillNameAndSubmit();
		await vi.waitFor(() =>
			expect(
				screen.getByText('This meeting is being recorded. If you join, your voice and video will be part of the recording.'),
			).toBeTruthy(),
		);
		// not connected yet — the gate sits BEFORE MeetRoom.connect.
		expect(roomState.lastRoom).toBeUndefined();

		await fireEvent.click(screen.getByText('Join'));
		await vi.waitFor(() => expect(roomState.lastRoom).toBeDefined());
		expect(roomState.lastRoom!.connect).toHaveBeenCalledWith(`ws://${location.host}/rtc`, 'tok');
	});

	// B3 retro fix (design findings #4/#5): the admitted grant's ccIdentity
	// dissolves the guest-captions attestation ceiling — a guest now attests
	// real cc frames from the bot exactly like a member does, and a spoofed
	// sender is still dropped.
	it('the admitted grant\'s ccIdentity attests the guest MeetRoom for captions', async () => {
		guestJoinRequest.mockResolvedValue({ requestId: 7, secret: 'sec' });
		guestPoll.mockResolvedValue({
			state: 'admitted',
			token: 'tok',
			wsPath: '/rtc',
			expiresAt: 'later',
			captionsOn: true,
			ccIdentity: 'cc:42',
		});
		render(GuestJoinPage);

		await fillNameAndSubmit();
		await vi.waitFor(() => expect(roomState.lastRoom).toBeDefined());

		// a real cc frame from the attested bot identity renders...
		roomState.lastRoom!.emit(
			'dataReceived',
			new TextEncoder().encode(JSON.stringify({ t: 'cc', sid: 's1', p: 'g:1', text: 'hi', final: true })),
			{ identity: 'cc:42' },
		);
		await vi.waitFor(() => expect(screen.getByText('hi')).toBeTruthy());

		// ...but a SPOOFED sender (not the attested bot identity) is still dropped.
		roomState.lastRoom!.emit(
			'dataReceived',
			new TextEncoder().encode(JSON.stringify({ t: 'cc', sid: 's2', p: 'g:1', text: 'spoofed', final: true })),
			{ identity: 'g:99' },
		);
		expect(screen.queryByText('spoofed')).toBeNull();
	});

	it('a denied/expired poll response renders no consent line (the flag is absent)', async () => {
		guestJoinRequest.mockResolvedValue({ requestId: 7, secret: 'sec' });
		guestPoll.mockResolvedValue({ state: 'denied' });
		render(GuestJoinPage);

		await fillNameAndSubmit();
		await vi.waitFor(() => expect(screen.getByText('Your request to join was declined.')).toBeTruthy());
		expect(screen.queryByText('This meeting is being recorded')).toBeNull();
	});

	it('expired pre-admission renders "Ask again", which requests a fresh join-request and returns to pending', async () => {
		guestJoinRequest
			.mockResolvedValueOnce({ requestId: 7, secret: 'sec' })
			.mockResolvedValueOnce({ requestId: 8, secret: 'sec2' });
		guestPoll.mockResolvedValueOnce({ state: 'expired' }).mockReturnValue(new Promise(() => {}));
		render(GuestJoinPage);

		await fillNameAndSubmit();
		await vi.waitFor(() => expect(screen.getByText('Your request has expired.')).toBeTruthy());

		await fireEvent.click(screen.getByText('Ask again'));
		await vi.waitFor(() => expect(guestJoinRequest).toHaveBeenCalledTimes(2));
		expect(guestJoinRequest).toHaveBeenLastCalledWith('meet-slug-1', 'Alex Guest');
		await vi.waitFor(() => expect(screen.getByTestId('lobby-waiting').dataset.state).toBe('pending'));
	});
});
