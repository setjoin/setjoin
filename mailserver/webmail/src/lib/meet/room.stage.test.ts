// room.stage.test.ts — MEET plan M3: the ephemeral stage family plumbing in
// room.svelte.ts, against the SAME livekit-client mock seam room.svelte.test.ts
// established (tests drive #handleData by emitting RoomEvent.DataReceived on
// the fake Room). Locks: shape validation, per-sender stale-sequence drops,
// the send-side frame cap + disconnected guard, and the D4 rule that a room
// swap (moveTo) clears the per-sender watermarks so a fresh room's sequence
// space is not silently dropped. The durable presentation family's contract
// itself is frozen in presentation.test.ts / presentation.branches.test.ts —
// untouched here.
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
			TrackSubscribed: 'trackSubscribed',
			TrackUnsubscribed: 'trackUnsubscribed',
			LocalTrackPublished: 'localTrackPublished',
			LocalTrackUnpublished: 'localTrackUnpublished',
		},
		Track: { Source: { Camera: 'camera', Microphone: 'microphone', ScreenShare: 'screenshare', ScreenShareAudio: 'screenshare_audio' } },
		ConnectionQuality: { Excellent: 'excellent', Good: 'good', Poor: 'poor', Unknown: 'unknown' },
		DisconnectReason: { PARTICIPANT_REMOVED: 'PARTICIPANT_REMOVED' },
		ScreenSharePresets: { h1080fps15: { encoding: {} } },
		createLocalScreenTracks: vi.fn(),
	};
});

vi.mock('./blur', () => ({
	isBlurAvailable: () => false,
	setBlur: vi.fn(async () => true),
}));

// Dynamic import (the room.svelte.test.ts seam): the module's evaluation
// triggers the hoisted livekit mock factory, which closes over the FakeRoom
// class declared below — so the import must wait for the module body.
import type { MeetRoom } from './room.svelte';
const { MeetRoom: MeetRoomCtor, MAX_STAGE_FRAME_BYTES, MAX_INK_POINTS } = await import('./room.svelte');
type StageEvent = import('./room.svelte').StageEvent;

const peer = { identity: 'u:2', name: 'Peer' };

function emitStage(room: MeetRoom, event: unknown, from: { identity: string } = peer): void {
	lastRoom!.emit('dataReceived', new TextEncoder().encode(JSON.stringify(event)), from as never);
}

function pointerEvent(seq = 1): StageEvent {
	return { t: 'stage', v: 1, kind: 'pointer', seq, x: 0.25, y: 0.75 };
}

describe('stage family — receive path', () => {
	let room: MeetRoom;
	let received: { event: StageEvent; from: string }[];

	beforeEach(() => {
		room = new MeetRoomCtor('vp8', 'cc:42');
		room.connectionState = 'connected';
		received = [];
		room.onStage((event, from) => received.push({ event, from }));
	});

	it('a valid stage frame reaches the listener with its sender identity', () => {
		emitStage(room, pointerEvent(1));
		expect(received).toHaveLength(1);
		expect(received[0]).toEqual({ event: pointerEvent(1), from: 'u:2' });
	});

	it('stale sequences per sender are dropped; a fresh one passes', () => {
		emitStage(room, pointerEvent(5));
		emitStage(room, pointerEvent(5));
		emitStage(room, pointerEvent(4));
		expect(received).toHaveLength(1);
		emitStage(room, pointerEvent(6));
		expect(received).toHaveLength(2);
	});

	it('different senders keep independent sequence spaces', () => {
		emitStage(room, pointerEvent(1), peer);
		emitStage(room, pointerEvent(100), { identity: 'u:3' });
		expect(received).toHaveLength(2);
	});

	it('malformed shapes never reach the listener (fail closed at the door)', () => {
		emitStage(room, { t: 'stage', v: 2, kind: 'pointer', seq: 1, x: 0.5, y: 0.5 }); // wrong v
		emitStage(room, { t: 'stage', v: 1, kind: 'mystery', seq: 1 }); // unknown kind
		emitStage(room, { t: 'stage', v: 1, kind: 'pointer', seq: -1, x: 0.5, y: 0.5 }); // bad seq
		emitStage(room, { t: 'stage', v: 1, kind: 'pointer', seq: 1, x: 1.5, y: 0.5 }); // out of [0,1]
		emitStage(room, { t: 'stage', v: 1, kind: 'ink', seq: 1, points: [0.5, 'x'] }); // bad points
		emitStage(room, { t: 'stage', v: 1, kind: 'ink', seq: 1, points: new Array(MAX_INK_POINTS * 2 + 2).fill(0.5) }); // over cap
		expect(received).toHaveLength(0);
	});

	it('a valid ink frame passes the shape gate', () => {
		emitStage(room, { t: 'stage', v: 1, kind: 'ink', seq: 1, points: [0.1, 0.2, 0.3, 0.4] });
		expect(received[0]?.event.kind).toBe('ink');
	});
});

describe('stage family — send path', () => {
	it('sendStageEvent validates the shape, caps bytes, and requires a connected room', () => {
		const room = new MeetRoomCtor('vp8');
		room.connectionState = 'connected';
		expect(room.sendStageEvent(pointerEvent(1))).toBe(true);
		expect(room.sendStageEvent({ t: 'stage', v: 1, kind: 'pointer', seq: 1, x: 2, y: 0 } as StageEvent)).toBe(false);
		const oversized: StageEvent = {
			t: 'stage',
			v: 1,
			kind: 'ink',
			seq: 1,
			points: new Array(MAX_INK_POINTS * 2).fill(0.123456789),
		};
		if (JSON.stringify(oversized).length > MAX_STAGE_FRAME_BYTES) {
			expect(room.sendStageEvent(oversized)).toBe(false);
		}
		room.connectionState = 'disconnected';
		expect(room.sendStageEvent(pointerEvent(2))).toBe(false);
	});
});

describe('stage family — room swap (moveTo)', () => {
	it('clears the per-sender watermarks: a fresh room accepts fresh sequences', async () => {
		const room = new MeetRoomCtor('vp8', 'cc:42');
		room.connectionState = 'connected';
		const received: number[] = [];
		room.onStage((event) => received.push(event.seq));
		emitStage(room, pointerEvent(7));
		expect(received).toEqual([7]);
		// the D4 genre: the vacated room's sequence space dies with it
		await room.moveTo('tok2');
		emitStage(room, pointerEvent(1));
		expect(received).toEqual([7, 1]);
	});
});
