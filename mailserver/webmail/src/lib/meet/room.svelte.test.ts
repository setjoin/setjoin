// room.svelte.test.ts — Meet B1 Task 16. livekit-client's real Room opens a
// real WebSocket/WebRTC stack, so the whole module is mocked (the same seam
// the plan's "SFU is NOT run in unit tests" constraint calls for) with a
// fake EventEmitter that lets tests fire the exact RoomEvent callbacks
// #wireEvents() registers.
import { describe, it, expect, vi, beforeEach } from 'vitest';

type Handler = (...args: unknown[]) => void;

class FakeLocalParticipant {
	setMicrophoneEnabled = vi.fn(async () => undefined);
	setCameraEnabled = vi.fn(async () => undefined);
	setScreenShareEnabled = vi.fn(async () => undefined);
	publishData = vi.fn(async (_data: Uint8Array, _opts?: unknown) => undefined);
	/** Task 16b: returns undefined by default (no camera track) — tests that
	 *  need a live track override this per-case. */
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
	// Mirrors blur.ts's own gate (vp8 = hidden) without pulling in the real
	// @livekit/track-processors/mediapipe WASM stack into a unit test.
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

describe('MeetRoom', () => {
	it('connects to wss://<host>/rtc with the given token and applies the default-muted local media state', async () => {
		// scheme follows the page (B1 gate fix): https page -> wss, http -> ws
		vi.stubGlobal('location', { host: 'mail.example.com', protocol: 'https:' });
		const mr = new MeetRoom('vp9');
		await mr.connect('tok123');
		expect(lastRoom!.connect).toHaveBeenCalledWith('wss://mail.example.com/rtc', 'tok123');
		// design #11: mic/camera default MUTED — both toggles start true (off)
		expect(lastRoom!.localParticipant.setMicrophoneEnabled).toHaveBeenCalledWith(false);
		expect(lastRoom!.localParticipant.setCameraEnabled).toHaveBeenCalledWith(false);
		vi.unstubAllGlobals();
	});

	it('uses ws:// (not wss://) when the page itself is served over http (B1 gate fix)', async () => {
		vi.stubGlobal('location', { host: '127.0.0.1:18080', protocol: 'http:' });
		const mr = new MeetRoom('vp8');
		await mr.connect('tok-http');
		expect(lastRoom!.connect).toHaveBeenCalledWith('ws://127.0.0.1:18080/rtc', 'tok-http');
		vi.unstubAllGlobals();
	});

	it('Connected sets connectionState to connected and Disconnected resets it + records the reason', () => {
		const mr = new MeetRoom('vp8');
		lastRoom!.emit('connected');
		expect(mr.connectionState).toBe('connected');
		lastRoom!.emit('disconnected', 'PARTICIPANT_REMOVED');
		expect(mr.connectionState).toBe('disconnected');
		expect(mr.disconnectReason).toBe('PARTICIPANT_REMOVED');
	});

	it('toggleMic flips localMuted optimistically and calls setMicrophoneEnabled with the new state', async () => {
		const mr = new MeetRoom('vp8');
		expect(mr.localMuted).toBe(true);
		await mr.toggleMic();
		expect(mr.localMuted).toBe(false);
		expect(lastRoom!.localParticipant.setMicrophoneEnabled).toHaveBeenLastCalledWith(true);
	});

	it('reverts the optimistic flip when the device call rejects', async () => {
		const mr = new MeetRoom('vp8');
		lastRoom!.localParticipant.setMicrophoneEnabled = vi.fn(async () => {
			throw new Error('NotAllowedError');
		});
		await mr.toggleMic();
		expect(mr.localMuted).toBe(true); // reverted, not stuck showing "unmuted"
	});

	it('a reaction data packet from a remote participant adds a floating reaction that expires', () => {
		vi.useFakeTimers();
		const mr = new MeetRoom('vp8');
		const remote = { identity: 'u:7' };
		lastRoom!.emit('dataReceived', encode({ t: 'reaction', v: '🎉' }), remote);
		expect(mr.reactions).toHaveLength(1);
		expect(mr.reactions[0]).toMatchObject({ identity: 'u:7', emoji: '🎉' });
		vi.advanceTimersByTime(5000);
		expect(mr.reactions).toHaveLength(0);
		vi.useRealTimers();
	});

	it('a hand-raise data packet toggles the identity in raisedHands', () => {
		const mr = new MeetRoom('vp8');
		const remote = { identity: 'u:7' };
		lastRoom!.emit('dataReceived', encode({ t: 'hand', v: true }), remote);
		expect(mr.raisedHands.has('u:7')).toBe(true);
		lastRoom!.emit('dataReceived', encode({ t: 'hand', v: false }), remote);
		expect(mr.raisedHands.has('u:7')).toBe(false);
	});

	it('sendReaction adds an optimistic local echo and publishes the data envelope', () => {
		const mr = new MeetRoom('vp8');
		lastRoom!.emit('connected');
		mr.sendReaction('👍');
		expect(mr.reactions.some((r) => r.identity === 'local' && r.emoji === '👍')).toBe(true);
		expect(lastRoom!.localParticipant.publishData).toHaveBeenCalled();
	});

	it('participantConnected/Disconnected keeps `participants` in sync with room.remoteParticipants', () => {
		const mr = new MeetRoom('vp8');
		lastRoom!.remoteParticipants.set('u:9', { identity: 'u:9' });
		lastRoom!.emit('participantConnected');
		expect(mr.participants).toHaveLength(1);
		lastRoom!.remoteParticipants.delete('u:9');
		lastRoom!.emit('participantDisconnected');
		expect(mr.participants).toHaveLength(0);
	});

	// 2026-07-16 (B3b live-gate P0 1b): the captions bot now joins UNHIDDEN
	// (livekit strips a hidden participant's data-packet sender identity,
	// which killed F8 attestation), so it appears in room.remoteParticipants
	// like any other participant — webmail must filter it client-side.
	it('a cc:-identity participant is filtered out of `participants` (the roster/gallery choke point)', () => {
		const mr = new MeetRoom('vp8');
		lastRoom!.remoteParticipants.set('u:9', { identity: 'u:9' });
		lastRoom!.remoteParticipants.set('cc:42', { identity: 'cc:42' });
		lastRoom!.emit('participantConnected');
		expect(mr.participants).toHaveLength(1);
		expect(mr.participants[0]).toMatchObject({ identity: 'u:9' });
	});

	it('a cc:-identity bot still delivers data frames — the filter only touches the roster list, not #handleData', () => {
		const mr = new MeetRoom('vp9', 'cc:42');
		lastRoom!.remoteParticipants.set('cc:42', { identity: 'cc:42' });
		lastRoom!.emit('participantConnected');
		expect(mr.participants).toHaveLength(0); // filtered from the roster
		const bot = { identity: 'cc:42' };
		lastRoom!.emit(
			'dataReceived',
			encode({ t: 'cc', sid: 's1', p: 'u:9', text: 'hello', final: true }),
			bot,
		);
		expect(mr.captionSegments).toHaveLength(1); // but its cc frames still render
	});

	// ── Task 16b: background blur ──────────────────────────────────────
	describe('background blur', () => {
		beforeEach(() => setBlur.mockClear());

		it('blurSupported mirrors isBlurAvailable(codec) — hidden for the vp8 weak-hardware signal', () => {
			expect(new MeetRoom('vp9').blurSupported).toBe(true);
			expect(new MeetRoom('vp8').blurSupported).toBe(false);
		});

		it('toggleBlur attaches the processor to the live camera track and flips blurEnabled on success', async () => {
			const mr = new MeetRoom('vp9');
			const track = { id: 'fake-video-track' };
			lastRoom!.localParticipant.getTrackPublication = vi.fn(() => ({ videoTrack: track }));
			await mr.toggleBlur(true);
			expect(setBlur).toHaveBeenCalledWith(track, true);
			expect(mr.blurEnabled).toBe(true);
		});

		it('toggleBlur does NOT flip blurEnabled when the processor attach fails', async () => {
			setBlur.mockResolvedValueOnce(false);
			const mr = new MeetRoom('vp9');
			lastRoom!.localParticipant.getTrackPublication = vi.fn(() => ({ videoTrack: {} }));
			await mr.toggleBlur(true);
			expect(mr.blurEnabled).toBe(false);
		});

		it('toggleBlur is a no-op when the codec/browser gate says unsupported', async () => {
			const mr = new MeetRoom('vp8');
			await mr.toggleBlur(true);
			expect(setBlur).not.toHaveBeenCalled();
			expect(mr.blurEnabled).toBe(false);
		});

		it('toggleBlur with no live camera track yet records a sticky preference (no setBlur call)', async () => {
			const mr = new MeetRoom('vp9');
			await mr.toggleBlur(true);
			expect(setBlur).not.toHaveBeenCalled();
			expect(mr.blurEnabled).toBe(true);
		});

		it('connect() applies a carried-over blur preference once the camera track exists', async () => {
			const mr = new MeetRoom('vp9');
			const track = { id: 'fake-video-track' };
			lastRoom!.localParticipant.getTrackPublication = vi.fn(() => ({ videoTrack: track }));
			mr.localCameraOff = false;
			await mr.connect('tok', '/rtc', { blurEnabled: true });
			expect(setBlur).toHaveBeenCalledWith(track, true);
			expect(mr.blurEnabled).toBe(true);
		});

		it('toggleCamera re-applies blur on the fresh track once the camera turns back on', async () => {
			const mr = new MeetRoom('vp9');
			// Sticky preference recorded while there is no track yet:
			await mr.toggleBlur(true);
			expect(mr.blurEnabled).toBe(true);
			expect(setBlur).not.toHaveBeenCalled();

			const track = { id: 'fresh-video-track' };
			lastRoom!.localParticipant.getTrackPublication = vi.fn(() => ({ videoTrack: track }));
			mr.localCameraOff = true; // camera currently off; toggling turns it on
			await mr.toggleCamera();
			expect(setBlur).toHaveBeenCalledWith(track, true);
		});
	});
});

// ── B3 Task 6: live captions (F8 attested identity) ─────────────────────────
describe('MeetRoom — live captions (F8 attested-sender rule)', () => {
	it('renders a cc frame from the attested bot identity; the SAME frame from a spoofed identity is dropped', () => {
		const mr = new MeetRoom('vp8', 'cc:42');
		const bot = { identity: 'cc:42' };
		const spoofer = { identity: 'u:99' };
		lastRoom!.emit('dataReceived', encode({ t: 'cc', sid: 's1', p: 'u:7', text: 'Hello', final: false }), bot);
		expect(mr.captionSegments).toHaveLength(1);
		// identity is the SPEAKER (msg.p), not the sender (the bot) — a real
		// bug fixed ahead of Task 15's per-speaker attribution overlay.
		expect(mr.captionSegments[0]).toMatchObject({ sid: 's1', identity: 'u:7', text: 'Hello', final: false });

		lastRoom!.emit('dataReceived', encode({ t: 'cc', sid: 's2', p: 'u:7', text: 'spoofed', final: false }), spoofer);
		expect(mr.captionSegments).toHaveLength(1); // unchanged — dropped
	});

	it('with no attestedCcIdentity configured (default), every cc frame is dropped (fail closed)', () => {
		const mr = new MeetRoom('vp8');
		lastRoom!.emit(
			'dataReceived',
			encode({ t: 'cc', sid: 's1', p: 'u:7', text: 'Hello', final: false }),
			{ identity: 'cc:42' },
		);
		expect(mr.captionSegments).toHaveLength(0);
	});

	it('a cc frame missing the speaker identity (p) is dropped, not rendered with a bogus attribution', () => {
		const mr = new MeetRoom('vp8', 'cc:42');
		lastRoom!.emit('dataReceived', encode({ t: 'cc', sid: 's1', text: 'Hello', final: false }), { identity: 'cc:42' });
		expect(mr.captionSegments).toHaveLength(0);
	});

	it('interim (final:false) segments replace by sid; a final segment always appends', () => {
		const mr = new MeetRoom('vp8', 'cc:42');
		const bot = { identity: 'cc:42' };
		lastRoom!.emit('dataReceived', encode({ t: 'cc', sid: 's1', p: 'u:7', text: 'Hel', final: false }), bot);
		lastRoom!.emit('dataReceived', encode({ t: 'cc', sid: 's1', p: 'u:7', text: 'Hello', final: false }), bot);
		expect(mr.captionSegments).toHaveLength(1);
		expect(mr.captionSegments[0].text).toBe('Hello');

		lastRoom!.emit('dataReceived', encode({ t: 'cc', sid: 's1', p: 'u:7', text: 'Hello world', final: true }), bot);
		expect(mr.captionSegments).toHaveLength(2);
		expect(mr.captionSegments[1]).toMatchObject({ text: 'Hello world', final: true, identity: 'u:7' });
	});

	it('caps the ring at 6 segments, dropping the oldest', () => {
		const mr = new MeetRoom('vp8', 'cc:42');
		const bot = { identity: 'cc:42' };
		for (let i = 0; i < 8; i++) {
			lastRoom!.emit('dataReceived', encode({ t: 'cc', sid: `s${i}`, p: 'u:7', text: `t${i}`, final: true }), bot);
		}
		expect(mr.captionSegments).toHaveLength(6);
		expect(mr.captionSegments[0].sid).toBe('s2');
		expect(mr.captionSegments[5].sid).toBe('s7');
	});

	// B3 retro fix (eng #13 / design D7-break): finalsLog is a SEPARATE,
	// append-only log the sr-only region reads from — it must NOT shrink when
	// the small captionSegments ring evicts on an unrelated append.
	it('finalsLog retains every final past the 6-entry visual ring cap — the sr-only region never shrinks on ring eviction', () => {
		const mr = new MeetRoom('vp8', 'cc:42');
		const bot = { identity: 'cc:42' };
		for (let i = 0; i < 8; i++) {
			lastRoom!.emit('dataReceived', encode({ t: 'cc', sid: `s${i}`, p: 'u:7', text: `t${i}`, final: true }), bot);
		}
		expect(mr.captionSegments).toHaveLength(6); // the visual ring, unchanged
		expect(mr.finalsLog).toHaveLength(8); // the sr-only log, all retained
		expect(mr.finalsLog[0].sid).toBe('s0');
		expect(mr.finalsLog[7].sid).toBe('s7');
	});

	it('finalsLog only grows on a final — an interim update never appends to it', () => {
		const mr = new MeetRoom('vp8', 'cc:42');
		const bot = { identity: 'cc:42' };
		lastRoom!.emit('dataReceived', encode({ t: 'cc', sid: 's1', p: 'u:7', text: 'Hel', final: false }), bot);
		lastRoom!.emit('dataReceived', encode({ t: 'cc', sid: 's1', p: 'u:7', text: 'Hello', final: false }), bot);
		expect(mr.finalsLog).toHaveLength(0);
		lastRoom!.emit('dataReceived', encode({ t: 'cc', sid: 's1', p: 'u:7', text: 'Hello world', final: true }), bot);
		expect(mr.finalsLog).toHaveLength(1);
	});

	// B3 retro fix (design finding #5a): asrbot's 5s heartbeat frame.
	it('an attested hb frame resets lastAttestedCcAt without creating a caption segment', () => {
		const mr = new MeetRoom('vp8', 'cc:42');
		const bot = { identity: 'cc:42' };
		expect(mr.lastAttestedCcAt).toBe(0);
		lastRoom!.emit('dataReceived', encode({ t: 'cc', hb: true }), bot);
		expect(mr.lastAttestedCcAt).toBeGreaterThan(0);
		expect(mr.captionSegments).toHaveLength(0);
		expect(mr.finalsLog).toHaveLength(0);
	});

	it('a spoofed hb frame (wrong sender) does not update lastAttestedCcAt', () => {
		const mr = new MeetRoom('vp8', 'cc:42');
		const spoofer = { identity: 'u:99' };
		lastRoom!.emit('dataReceived', encode({ t: 'cc', hb: true }), spoofer);
		expect(mr.lastAttestedCcAt).toBe(0);
	});

	it('a real cc frame also bumps lastAttestedCcAt (a single "still alive" signal for both shapes)', () => {
		const mr = new MeetRoom('vp8', 'cc:42');
		const bot = { identity: 'cc:42' };
		lastRoom!.emit('dataReceived', encode({ t: 'cc', sid: 's1', p: 'u:7', text: 'hi', final: true }), bot);
		expect(mr.lastAttestedCcAt).toBeGreaterThan(0);
	});
});

// ── B3 Task 6: whiteboard data channel (F15 wb_sync chunking) ───────────────
describe('MeetRoom — whiteboard data channel (F15 wb_sync chunking)', () => {
	it('sendWhiteboard publishes a single unchunked wb envelope', () => {
		const mr = new MeetRoom('vp8');
		lastRoom!.emit('connected');
		mr.sendWhiteboard([{ id: 'a' }]);
		expect(lastRoom!.localParticipant.publishData).toHaveBeenCalledTimes(1);
		const [bytes] = lastRoom!.localParticipant.publishData.mock.calls[0];
		expect(JSON.parse(new TextDecoder().decode(bytes))).toEqual({ t: 'wb', elements: [{ id: 'a' }] });
	});

	it('requestWhiteboardSync publishes a bare wb_req envelope', () => {
		const mr = new MeetRoom('vp8');
		lastRoom!.emit('connected');
		mr.requestWhiteboardSync();
		const [bytes] = lastRoom!.localParticipant.publishData.mock.calls[0];
		expect(JSON.parse(new TextDecoder().decode(bytes))).toEqual({ t: 'wb_req' });
	});

	it('a wb_req from a remote participant fires the onWhiteboardRequest listener', () => {
		const mr = new MeetRoom('vp8');
		const cb = vi.fn();
		mr.onWhiteboardRequest(cb);
		lastRoom!.emit('dataReceived', encode({ t: 'wb_req' }), { identity: 'u:5' });
		expect(cb).toHaveBeenCalledTimes(1);
	});

	// B3 retro fix (design finding #9-nit / #9): WhiteboardPanel's onDestroy
	// calls these with null to unregister — a frame arriving after that must
	// be a silent no-op, never a call into a dead handle.
	it('onWhiteboard(null) unregisters the listener — a later wb frame is a silent no-op', () => {
		const mr = new MeetRoom('vp8');
		const cb = vi.fn();
		mr.onWhiteboard(cb);
		mr.onWhiteboard(null);
		lastRoom!.emit('dataReceived', encode({ t: 'wb', elements: [{ id: 'x' }] }), { identity: 'u:5' });
		expect(cb).not.toHaveBeenCalled();
	});

	it('onWhiteboardRequest(null) unregisters the listener — a later wb_req frame is a silent no-op', () => {
		const mr = new MeetRoom('vp8');
		const cb = vi.fn();
		mr.onWhiteboardRequest(cb);
		mr.onWhiteboardRequest(null);
		lastRoom!.emit('dataReceived', encode({ t: 'wb_req' }), { identity: 'u:5' });
		expect(cb).not.toHaveBeenCalled();
	});

	it('sendWhiteboardSync chunks a >15KiB element set into N wb_sync parts sharing one seq', () => {
		const mr = new MeetRoom('vp8');
		lastRoom!.emit('connected');
		const big = Array.from({ length: 2000 }, (_, i) => ({ id: `el-${i}`, text: 'x'.repeat(20) }));
		mr.sendWhiteboardSync(big);
		const calls = lastRoom!.localParticipant.publishData.mock.calls;
		expect(calls.length).toBeGreaterThan(1);
		const decoded = calls.map(([bytes]) => JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>);
		expect(decoded.every((d) => d.t === 'wb_sync')).toBe(true);
		const seqs = new Set(decoded.map((d) => d.seq));
		expect(seqs.size).toBe(1);
		expect(decoded[0].of).toBe(calls.length);
		const parts = decoded.map((d) => d.part as number).sort((a, b) => a - b);
		expect(parts).toEqual(Array.from({ length: calls.length }, (_, i) => i + 1));
		// every byte-encoded part stays under the 15KiB LiveKit reliable-data cap
		for (const bytes of calls.map(([b]) => b)) expect(bytes.length).toBeLessThan(15 * 1024);
	});

	it('reassembles wb_sync parts only once ALL parts arrive, tolerating out-of-order delivery', () => {
		const mr = new MeetRoom('vp8');
		const received: unknown[] = [];
		mr.onWhiteboard((elements) => received.push(elements));
		const peer = { identity: 'u:5' };
		lastRoom!.emit('dataReceived', encode({ t: 'wb_sync', seq: 1, part: 2, of: 2, elements: [{ id: 'b' }] }), peer);
		expect(received).toHaveLength(0); // incomplete — only part 2 of 2 has arrived
		lastRoom!.emit('dataReceived', encode({ t: 'wb_sync', seq: 1, part: 1, of: 2, elements: [{ id: 'a' }] }), peer);
		expect(received).toHaveLength(1);
		expect(received[0]).toEqual([{ id: 'a' }, { id: 'b' }]);
	});

	it('discards a stale seq once a newer sync supersedes it', () => {
		const mr = new MeetRoom('vp8');
		const received: unknown[] = [];
		mr.onWhiteboard((elements) => received.push(elements));
		const peer = { identity: 'u:5' };
		lastRoom!.emit('dataReceived', encode({ t: 'wb_sync', seq: 1, part: 1, of: 2, elements: [{ id: 'old' }] }), peer);
		lastRoom!.emit('dataReceived', encode({ t: 'wb_sync', seq: 2, part: 1, of: 1, elements: [{ id: 'new' }] }), peer);
		expect(received).toHaveLength(1);
		expect(received[0]).toEqual([{ id: 'new' }]);
		// the stale seq 1's remaining part arrives late — must not complete/deliver
		lastRoom!.emit('dataReceived', encode({ t: 'wb_sync', seq: 1, part: 2, of: 2, elements: [{ id: 'stale' }] }), peer);
		expect(received).toHaveLength(1); // unchanged
	});
});

// ── B3 Task 6: moveTo (breakout forced-move choreography) ───────────────────
describe('MeetRoom — moveTo (breakout move choreography)', () => {
	it('disconnects the old room, connects the new token, and preserves mute/camera/blur state across the gap', async () => {
		vi.stubGlobal('location', { host: 'mail.example.com', protocol: 'https:' });
		const mr = new MeetRoom('vp9');
		await mr.connect('main-token');
		const oldRoom = lastRoom!;
		lastRoom!.localParticipant.getTrackPublication = vi.fn(() => ({ videoTrack: { id: 't' } }));
		mr.localCameraOff = false;
		await mr.toggleBlur(true);
		mr.localMuted = false;

		await mr.moveTo('child-token', '/rtc');

		expect(oldRoom.disconnect).toHaveBeenCalled();
		const newRoom = lastRoom!;
		expect(newRoom).not.toBe(oldRoom);
		expect(newRoom.connect).toHaveBeenCalledWith('wss://mail.example.com/rtc', 'child-token');
		expect(mr.localMuted).toBe(false);
		expect(mr.localCameraOff).toBe(false);
		expect(mr.blurEnabled).toBe(true); // preserved (sticky — no track on the fresh fake room)
		vi.unstubAllGlobals();
	});

	it('clears captionSegments + in-flight wb reassembly buffers, and re-sends wb_req on the new room (D4)', async () => {
		vi.stubGlobal('location', { host: 'mail.example.com' });
		const mr = new MeetRoom('vp9', 'cc:42');
		await mr.connect('main-token');
		lastRoom!.emit('dataReceived', encode({ t: 'cc', sid: 's1', p: 'u:7', text: 'hi', final: false }), { identity: 'cc:42' });
		expect(mr.captionSegments).toHaveLength(1);
		// an in-flight (incomplete) wb_sync reassembly buffer from the OLD room
		lastRoom!.emit('dataReceived', encode({ t: 'wb_sync', seq: 1, part: 1, of: 2, elements: [{ id: 'a' }] }), {
			identity: 'u:5',
		});

		await mr.moveTo('child-token');

		expect(mr.captionSegments).toHaveLength(0);
		const newRoom = lastRoom!;
		const calls = newRoom.localParticipant.publishData.mock.calls;
		const decoded = calls.map(([bytes]) => JSON.parse(new TextDecoder().decode(bytes)) as Record<string, unknown>);
		expect(decoded.some((d) => d.t === 'wb_req')).toBe(true);

		// the pre-move seq=1/part=1 buffer must have been dropped: a lone
		// late part 2 for that same seq must NOT complete anything post-move.
		const received: unknown[] = [];
		mr.onWhiteboard((elements) => received.push(elements));
		newRoom.emit('dataReceived', encode({ t: 'wb_sync', seq: 1, part: 2, of: 2, elements: [{ id: 'b' }] }), {
			identity: 'u:5',
		});
		expect(received).toHaveLength(0);
		vi.unstubAllGlobals();
	});

	// B3 retro fix (eng #13): finalsLog is a room-scoped log too — it must not
	// survive a move any more than captionSegments does (D4).
	it('clears finalsLog on move too', async () => {
		vi.stubGlobal('location', { host: 'mail.example.com' });
		const mr = new MeetRoom('vp9', 'cc:42');
		await mr.connect('main-token');
		lastRoom!.emit('dataReceived', encode({ t: 'cc', sid: 's1', p: 'u:7', text: 'hi', final: true }), { identity: 'cc:42' });
		expect(mr.finalsLog).toHaveLength(1);
		await mr.moveTo('child-token');
		expect(mr.finalsLog).toHaveLength(0);
		vi.unstubAllGlobals();
	});

	// B3 retro fix (eng finding #9-nit / eng #9): every OTHER room-scoped bit
	// of state resets too, and the OLD room's handlers are neutralized so a
	// stray in-flight event can't mutate state through a dead closure.
	it('resets raisedHands/reactions/dominantSpeakerId/connectionQuality/disconnectReason/screenSharing, and neutralizes the OLD room (removeAllListeners)', async () => {
		vi.stubGlobal('location', { host: 'mail.example.com' });
		const mr = new MeetRoom('vp9');
		await mr.connect('main-token');
		const oldRoom = lastRoom!;

		oldRoom.emit('dataReceived', encode({ t: 'hand', v: true }), { identity: 'u:9' });
		oldRoom.emit('activeSpeakersChanged', [{ identity: 'u:9' }]);
		oldRoom.emit('connectionQualityChanged', 'poor', { identity: 'u:9' });
		oldRoom.emit('disconnected', 'PARTICIPANT_REMOVED');
		mr.screenSharing = true;
		expect(mr.raisedHands.size).toBe(1);
		expect(mr.dominantSpeakerId).toBe('u:9');
		expect(Object.keys(mr.connectionQuality)).toContain('u:9');
		expect(mr.disconnectReason).toBe('PARTICIPANT_REMOVED');

		await mr.moveTo('child-token');

		expect(mr.raisedHands.size).toBe(0);
		expect(mr.reactions).toHaveLength(0);
		expect(mr.dominantSpeakerId).toBeNull();
		expect(mr.connectionQuality).toEqual({});
		expect(mr.disconnectReason).toBeNull();
		expect(mr.screenSharing).toBe(false);
		expect(oldRoom.removeAllListeners).toHaveBeenCalled();

		// the neutralized old room's handlers are gone — a stray late event on
		// it must not resurrect state on the (now-swapped) MeetRoom instance.
		oldRoom.emit('activeSpeakersChanged', [{ identity: 'u:stale' }]);
		expect(mr.dominantSpeakerId).toBeNull();
		vi.unstubAllGlobals();
	});

	// ── MEET plan M0: t:'presentation' family (inert until M2/M3) ─────────

	it('a presentation frame with no live presentation session is dropped (fail closed)', () => {
		const mr = new MeetRoom('vp8');
		const listener = vi.fn();
		mr.onPresentation(listener);
		lastRoom!.emit(
			'dataReceived',
			encode({ t: 'presentation', v: 1, presentationId: 'p-1', checkpointSeq: 9, presenterGeneration: 1, kind: 'page.changed', payload: { pageIndex: 2 }, sentAt: '2026-09-18T00:00:00Z' }),
			{ identity: 'u:9' },
		);
		expect(listener).not.toHaveBeenCalled();
	});

	it('a fresh presentation sequence only notifies the listener — it never advances state itself', () => {
		const mr = new MeetRoom('vp8');
		const listener = vi.fn();
		mr.onPresentation(listener);
		mr.setPresentationContext({ presentationId: 'p-1', confirmedSeq: 5, knownGeneration: 2 });
		const frame = { t: 'presentation', v: 1, presentationId: 'p-1', checkpointSeq: 6, presenterGeneration: 2, kind: 'page.changed', payload: { pageIndex: 3 }, sentAt: '2026-09-18T00:00:00Z' };
		lastRoom!.emit('dataReceived', encode(frame), { identity: 'u:9' });
		expect(listener).toHaveBeenCalledTimes(1);
		expect(listener).toHaveBeenCalledWith(6);
		// Durable frames are untrusted hints: the room carries NO promoted
		// presentation state that the frame could have advanced.
		expect(mr.raisedHands.size).toBe(0);
		expect(mr.reactions).toHaveLength(0);
	});

	it('stale-generation, wrong-id, unknown-version, duplicate-seq and unknown-kind frames never reach the listener', () => {
		const mr = new MeetRoom('vp8');
		const listener = vi.fn();
		mr.onPresentation(listener);
		mr.setPresentationContext({ presentationId: 'p-1', confirmedSeq: 5, knownGeneration: 2 });
		const base = { t: 'presentation', v: 1, presentationId: 'p-1', checkpointSeq: 9, presenterGeneration: 2, kind: 'page.changed', payload: { pageIndex: 0 }, sentAt: '2026-09-18T00:00:00Z' };
		lastRoom!.emit('dataReceived', encode({ ...base, presenterGeneration: 1 }), { identity: 'u:9' }); // stale generation
		lastRoom!.emit('dataReceived', encode({ ...base, presentationId: 'other' }), { identity: 'u:9' }); // wrong id
		lastRoom!.emit('dataReceived', encode({ ...base, v: 2 }), { identity: 'u:9' }); // unknown version
		lastRoom!.emit('dataReceived', encode({ ...base, checkpointSeq: 5 }), { identity: 'u:9' }); // duplicate seq
		lastRoom!.emit('dataReceived', encode({ ...base, kind: 'brand.new' }), { identity: 'u:9' }); // unknown kind
		expect(listener).not.toHaveBeenCalled();
	});

	it('sendPresentationFrame byte-checks BEFORE publication and returns false when dropped', () => {
		const mr = new MeetRoom('vp8');
		const fat = { t: 'presentation' as const, v: 1, presentationId: 'p-1', checkpointSeq: 1, presenterGeneration: 1, kind: 'ready' as const, payload: { pad: 'x'.repeat(20000) }, sentAt: '2026-09-18T00:00:00Z' };
		expect(mr.sendPresentationFrame(fat)).toBe(false);
		// Not connected (no Connected event yet): dropped even when valid.
		expect(mr.sendPresentationFrame({ v: 1, presentationId: 'p-1', checkpointSeq: 1, presenterGeneration: 1, kind: 'ready', sentAt: '2026-09-18T00:00:00Z' })).toBe(false);
		expect(lastRoom!.localParticipant.publishData).not.toHaveBeenCalled();
	});

	it('sendPresentationFrame publishes a valid frame only while connected', () => {
		const mr = new MeetRoom('vp8');
		lastRoom!.emit('connected');
		const ok = mr.sendPresentationFrame({ v: 1, presentationId: 'p-1', checkpointSeq: 1, presenterGeneration: 1, kind: 'page.changed', payload: { pageIndex: 0 }, sentAt: '2026-09-18T00:00:00Z' });
		expect(ok).toBe(true);
		expect(lastRoom!.localParticipant.publishData).toHaveBeenCalledTimes(1);
		const bytes = lastRoom!.localParticipant.publishData.mock.calls[0][0] as Uint8Array;
		expect(new TextDecoder().decode(bytes)).toContain('"t":"presentation"');
	});

	it('moveTo resets the presentation session context with the other room-scoped state', async () => {
		vi.stubGlobal('location', { host: 'mail.example.com' });
		const mr = new MeetRoom('vp9');
		await mr.connect('main-token');
		mr.setPresentationContext({ presentationId: 'p-1', confirmedSeq: 5, knownGeneration: 2 });
		await mr.moveTo('child-token');
		// The child room has no live presentation session: frames fail closed.
		const listener = vi.fn();
		mr.onPresentation(listener);
		lastRoom!.emit(
			'dataReceived',
			encode({ t: 'presentation', v: 1, presentationId: 'p-1', checkpointSeq: 9, presenterGeneration: 2, kind: 'page.changed', payload: { pageIndex: 0 }, sentAt: '2026-09-18T00:00:00Z' }),
			{ identity: 'u:9' },
		);
		expect(listener).not.toHaveBeenCalled();
		vi.unstubAllGlobals();
	});

	it('an oversized ORIGINAL wire frame never reaches the listener, even though its re-serialization fits the bound', () => {
		// M0/M1 review regression: the receive path measured the byte bound on
		// JSON.stringify of the PARSED frame. A frame padded with `\u0041`
		// escapes is ~24KB on the wire but re-serializes to ~4KB, so the old
		// check let it through to checkpoint invalidation. The room now hands
		// the classifier the original bytes it received.
		const mr = new MeetRoom('vp8');
		const listener = vi.fn();
		mr.onPresentation(listener);
		mr.setPresentationContext({ presentationId: 'p-1', confirmedSeq: 5, knownGeneration: 2 });
		const raw =
			'{"t":"presentation","v":1,"presentationId":"p-1","checkpointSeq":9,"presenterGeneration":2,"kind":"ready","payload":{"pad":"' +
			'\\u0041'.repeat(4000) +
			'"}}';
		const wire = new TextEncoder().encode(raw);
		expect(wire.length).toBeGreaterThan(14000);
		const parsed: unknown = JSON.parse(raw);
		// Prove the shrinkage the old check trusted: the parsed frame
		// re-serializes under the bound.
		expect(new TextEncoder().encode(JSON.stringify(parsed)).length).toBeLessThanOrEqual(14000);
		lastRoom!.emit('dataReceived', wire, { identity: 'u:9' });
		expect(listener).not.toHaveBeenCalled();
		// A genuinely in-bound frame on the same session still hints.
		lastRoom!.emit(
			'dataReceived',
			encode({ t: 'presentation', v: 1, presentationId: 'p-1', checkpointSeq: 9, presenterGeneration: 2, kind: 'ready', sentAt: '2026-09-18T00:00:00Z' }),
			{ identity: 'u:9' },
		);
		expect(listener).toHaveBeenCalledTimes(1);
	});
});
