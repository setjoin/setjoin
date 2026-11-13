/**
 * MeetRoom edge branches (coverage round r2).
 *
 * Complementary real-behavior tests over the same faked livekit seam: the
 * participant-roster resync events, tear-down via disconnect(), screen-share
 * success and user-cancelled failure, raise-hand publication, the wb_sync
 * newer-seq supersede / straggler-drop rules, camera-on blur re-application,
 * the disconnected publish gate, and a rejecting publishData on the
 * presentation send path.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';

type Handler = (...args: unknown[]) => void;

class FakeLocalParticipant {
	setMicrophoneEnabled = vi.fn(async () => undefined);
	setCameraEnabled = vi.fn(async () => undefined);
	setScreenShareEnabled = vi.fn(async () => undefined);
	publishData = vi.fn(async (_data: Uint8Array, _opts?: unknown) => undefined);
	getTrackPublication = vi.fn((_source: string) => undefined as { videoTrack?: unknown } | undefined);
}

class FakeRoom {
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

let lastRoom: FakeRoom | undefined;

vi.mock('livekit-client', () => {
	class RoomCtor extends FakeRoom {
		constructor(opts: unknown) {
			super(opts);
			lastRoom = this;
		}
	}
	return {
		Room: RoomCtor,
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

const setBlur = vi.fn(async (_track: unknown, _enabled: boolean) => true);
vi.mock('./blur', () => ({
	isBlurAvailable: (codec: string) => codec !== 'vp8',
	setBlur: (track: unknown, enabled: boolean) => setBlur(track, enabled),
}));

const { MeetRoom } = await import('./room.svelte');

beforeEach(() => {
	lastRoom = undefined;
});

function encode(payload: Record<string, unknown>): Uint8Array {
	return new TextEncoder().encode(JSON.stringify(payload));
}

describe('MeetRoom roster and teardown edges', () => {
	it('participant connect/disconnect events re-sync the filtered roster', () => {
		const mr = new MeetRoom('vp8');
		lastRoom!.emit('connected');
		// The captions bot is filtered from the roster, a human stays.
		lastRoom!.remoteParticipants.set('cc:bot', { identity: 'cc:bot' });
		lastRoom!.remoteParticipants.set('u:1', { identity: 'u:1' });
		lastRoom!.emit('participantConnected');
		expect(mr.participants.map((p) => (p as { identity: string }).identity)).toEqual(['u:1']);
		// A departure re-syncs too.
		lastRoom!.remoteParticipants.delete('u:1');
		lastRoom!.emit('participantDisconnected');
		expect(mr.participants).toEqual([]);
	});

	it('disconnect tears the room down without throwing', () => {
		vi.useFakeTimers();
		const mr = new MeetRoom('vp8');
		mr.connect('tok');
		lastRoom!.emit('connected');
		mr.sendReaction('🎉'); // arms a reaction-expiry timer
		mr.disconnect();
		expect(lastRoom!.disconnect).toHaveBeenCalled();
		vi.advanceTimersByTime(6_000);
		vi.useRealTimers();
	});
});

describe('MeetRoom device toggles', () => {
	it('toggleScreenShare flips on success', async () => {
		const mr = new MeetRoom('vp8');
		expect(mr.screenSharing).toBe(false);
		await mr.toggleScreenShare();
		expect(mr.screenSharing).toBe(true);
		expect(lastRoom!.localParticipant.setScreenShareEnabled).toHaveBeenLastCalledWith(true);
		await mr.toggleScreenShare();
		expect(mr.screenSharing).toBe(false);
	});

	it('a cancelled screen-share (OS picker dismissal) leaves the state as-is', async () => {
		const mr = new MeetRoom('vp8');
		lastRoom!.localParticipant.setScreenShareEnabled = vi.fn(async () => {
			throw new Error('NotAllowedError');
		});
		await mr.toggleScreenShare();
		expect(mr.screenSharing).toBe(false);
	});

	it('turning the camera on re-applies a sticky blur preference to the fresh track', async () => {
		const mr = new MeetRoom('vp9');
		// The preference is recorded while no camera track exists yet.
		await mr.toggleBlur(true);
		expect(mr.blurEnabled).toBe(true);
		// A camera track is published; unmuting the camera must carry blur over.
		lastRoom!.localParticipant.getTrackPublication = vi.fn(() => ({ videoTrack: { fake: true } }));
		await mr.toggleCamera();
		expect(mr.localCameraOff).toBe(false);
		expect(setBlur).toHaveBeenCalledWith({ fake: true }, true);
	});
});

describe('MeetRoom raise hand', () => {
	it('toggleRaiseHand flips the local flag and publishes the hand envelope', () => {
		const mr = new MeetRoom('vp8');
		mr.connect('tok');
		lastRoom!.emit('connected');
		mr.toggleRaiseHand();
		expect(mr.raisedHandSelf).toBe(true);
		const sent = lastRoom!.localParticipant.publishData.mock.calls.at(-1);
		expect(JSON.parse(new TextDecoder().decode(sent![0] as Uint8Array))).toEqual({ t: 'hand', v: true });
		mr.toggleRaiseHand();
		expect(mr.raisedHandSelf).toBe(false);
	});

	it('a hand envelope with a non-boolean value is ignored', () => {
		const mr = new MeetRoom('vp8');
		lastRoom!.emit('dataReceived', encode({ t: 'hand', v: 'yes' }), { identity: 'u:2' });
		expect(mr.raisedHands.size).toBe(0);
	});
});

describe('MeetRoom wb_sync sequencing', () => {
	it('a NEWER seq discards the in-flight reassembly buffer; an OLDER straggler is dropped', () => {
		const mr = new MeetRoom('vp8');
		const seen: unknown[][] = [];
		mr.onWhiteboard((elements) => seen.push(elements as unknown[]));
		const peer = { identity: 'u:1' };
		// Part of seq 1 arrives (buffer opened).
		lastRoom!.emit('dataReceived', encode({ t: 'wb_sync', seq: 1, part: 1, of: 2, elements: [{ id: 'a' }] }), peer);
		// Seq 2 starts: the stale seq-1 buffer is discarded.
		lastRoom!.emit('dataReceived', encode({ t: 'wb_sync', seq: 2, part: 1, of: 2, elements: [{ id: 'new' }] }), peer);
		// A seq-1 straggler must NOT complete the stale buffer.
		lastRoom!.emit('dataReceived', encode({ t: 'wb_sync', seq: 1, part: 2, of: 2, elements: [{ id: 'old' }] }), peer);
		expect(seen).toHaveLength(0);
		// Seq 2 completes with exactly its own parts.
		lastRoom!.emit('dataReceived', encode({ t: 'wb_sync', seq: 2, part: 2, of: 2, elements: [{ id: 'b' }] }), peer);
		expect(seen).toEqual([[{ id: 'new' }, { id: 'b' }]]);
	});

	it('same-seq duplicates overwrite their part slot instead of double-merging', () => {
		const mr = new MeetRoom('vp8');
		const seen: unknown[][] = [];
		mr.onWhiteboard((elements) => seen.push(elements as unknown[]));
		const peer = { identity: 'u:1' };
		lastRoom!.emit('dataReceived', encode({ t: 'wb_sync', seq: 5, part: 1, of: 1, elements: [{ id: 'first' }] }), peer);
		lastRoom!.emit('dataReceived', encode({ t: 'wb_sync', seq: 5, part: 1, of: 1, elements: [{ id: 'second' }] }), peer);
		expect(seen).toEqual([[{ id: 'first' }], [{ id: 'second' }]]);
	});
});

describe('MeetRoom publish gating', () => {
	it('a reaction while NOT connected echoes locally but publishes nothing', () => {
		const mr = new MeetRoom('vp8');
		mr.sendReaction('🎉');
		expect(mr.reactions).toHaveLength(1);
		expect(lastRoom!.localParticipant.publishData).not.toHaveBeenCalled();
	});

	it('a rejecting publishData on the presentation send path never throws', async () => {
		vi.stubGlobal('location', { host: 'mail.example.com', protocol: 'https:' });
		const mr = new MeetRoom('vp8');
		await mr.connect('tok');
		lastRoom!.emit('connected');
		lastRoom!.localParticipant.publishData = vi.fn(async () => {
			throw new Error('dc closed');
		});
		const ok = mr.sendPresentationFrame({
			v: 1,
			presentationId: 'p-1',
			checkpointSeq: 1,
			presenterGeneration: 1,
			kind: 'page.changed',
			payload: { pageIndex: 0 },
			sentAt: '2026-09-18T00:00:00Z',
		});
		expect(ok).toBe(true); // publication is fire-and-forget: the frame was handed off
		await new Promise<void>((resolve) => setTimeout(resolve, 0));
		vi.unstubAllGlobals();
	});
});
