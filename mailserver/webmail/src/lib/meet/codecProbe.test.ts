// codecProbe.test.ts — spec §3.4: "never trust getCapabilities()". These mock
// RTCPeerConnection/navigator.mediaCapabilities directly (there is no
// existing in-repo mock for either — this is the first probe of its kind)
// rather than trusting whatever jsdom happens to expose.
import { describe, it, expect, afterEach, vi } from 'vitest';
import { pickVideoCodec } from './codecProbe';

function stubMediaCapabilities(powerEfficient: boolean | 'throw') {
	Object.defineProperty(navigator, 'mediaCapabilities', {
		value: {
			encodingInfo: async () => {
				if (powerEfficient === 'throw') throw new Error('unsupported');
				return { supported: true, powerEfficient, smooth: true };
			},
		},
		configurable: true,
		enumerable: true,
	});
}

/** A fake RTCPeerConnection whose senders report a getStats() the probe reads
 *  for outbound-rtp.framesEncoded. `encodedFrames` controls whether the
 *  try-encode "succeeds" (VP9 provable) or not. */
function stubRTCPeerConnection(encodedFrames: number) {
	class FakeSender {
		getParameters() {
			return { encodings: [{}] };
		}
		setParameters() {
			return Promise.resolve();
		}
		async getStats() {
			return new Map([['outbound-1', { type: 'outbound-rtp', framesEncoded: encodedFrames }]]);
		}
	}
	class FakeTrack {
		kind = 'video';
		stop() {}
	}
	class FakePC {
		private senders: FakeSender[] = [];
		addTransceiver() {
			const sender = new FakeSender();
			this.senders.push(sender);
			return { sender, setCodecPreferences: () => {} };
		}
		createOffer() {
			return Promise.resolve({ type: 'offer', sdp: 'v=0' });
		}
		createAnswer() {
			return Promise.resolve({ type: 'answer', sdp: 'v=0' });
		}
		setLocalDescription() {
			return Promise.resolve();
		}
		setRemoteDescription() {
			return Promise.resolve();
		}
		close() {}
		getSenders() {
			return this.senders;
		}
	}
	vi.stubGlobal('RTCPeerConnection', FakePC as unknown as typeof RTCPeerConnection);
	vi.stubGlobal(
		'MediaStreamTrack',
		class {} as unknown as typeof MediaStreamTrack,
	);
	vi.stubGlobal('navigator', {
		...navigator,
		mediaDevices: {
			getUserMedia: async () => ({
				getVideoTracks: () => [new FakeTrack()],
				getTracks: () => [new FakeTrack()],
			}),
		},
	});
}

afterEach(() => {
	vi.unstubAllGlobals();
});

describe('pickVideoCodec', () => {
	it('picks av1 when mediaCapabilities reports powerEfficient for AV1', async () => {
		stubMediaCapabilities(true);
		stubRTCPeerConnection(5);
		await expect(pickVideoCodec()).resolves.toBe('av1');
	});

	it('picks vp9 when AV1 is not power-efficient but the VP9 try-encode succeeds', async () => {
		stubMediaCapabilities(false);
		stubRTCPeerConnection(5);
		await expect(pickVideoCodec()).resolves.toBe('vp9');
	});

	it('falls back to vp8 when both AV1 power-efficiency and the VP9 try-encode fail', async () => {
		stubMediaCapabilities(false);
		stubRTCPeerConnection(0);
		await expect(pickVideoCodec()).resolves.toBe('vp8');
	});

	it('falls back to vp8 when the probe throws (a probe crash must never block joining)', async () => {
		stubMediaCapabilities('throw');
		vi.stubGlobal('RTCPeerConnection', class {
			constructor() {
				throw new Error('boom');
			}
		} as unknown as typeof RTCPeerConnection);
		await expect(pickVideoCodec()).resolves.toBe('vp8');
	});
});
