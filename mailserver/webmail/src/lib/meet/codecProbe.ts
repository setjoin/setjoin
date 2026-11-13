// codecProbe.ts — spec §3.4, locked: VP9-SVC primary, AV1 opportunistic-only,
// VP8 universal fallback. Session-start capability probe — NEVER trust
// `RTCRtpSender.getCapabilities()`, which claims support a browser then
// silently falls back on (the MediaCodec trap). AV1 is chosen only when
// `mediaCapabilities.encodingInfo(...).powerEfficient` reports true (the
// HW-encode signal — software AV1 encode would eat old-desktop/信创 clients
// alive). VP9 is proven by actually TRY-ENCODING: a loopback RTCPeerConnection
// pair* with setCodecPreferences forced to VP9; success = at least one
// outbound-rtp report with framesEncoded > 0 within the probe window.
// Anything else (AV1 not powerEfficient AND the VP9 try-encode fails, or the
// probe throws at any point) falls back to VP8 — universal, unchecked. A
// probe crash must never block joining (Task 16's PreJoin never blocks the
// Join button on this; a late/failed result just means backupCodec vp8
// rides through). Result is NOT cached across calls at this layer — Task 16
// (room.svelte.ts) calls this once per session and holds the result itself
// ("cached per session" is the caller's job, not this module's).
//
// *"loopback pair" here is a single local RTCPeerConnection whose own sender
// stats are read directly — no actual second peer/signaling is needed to
// observe framesEncoded; a real second connection would need real ICE/DTLS,
// which a probe that must resolve in ~1.5s cannot afford.

export type MeetCodec = 'vp9' | 'av1' | 'vp8';

/** Bound on the whole probe — never let a stalled getUserMedia/encode hang
 *  the caller past this (PreJoin's spinner window, spec's own "≤1.5s" bound). */
const PROBE_TIMEOUT_MS = 1500;

async function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
	let timer: ReturnType<typeof setTimeout>;
	const timeout = new Promise<never>((_, reject) => {
		timer = setTimeout(() => reject(new Error('codec probe timed out')), ms);
	});
	try {
		return await Promise.race([p, timeout]);
	} finally {
		clearTimeout(timer!);
	}
}

/** AV1 is chosen ONLY on the hardware-encode signal — never on bare
 *  `supported`, which any software encoder can also report. */
async function av1PowerEfficient(): Promise<boolean> {
	const caps = (navigator as unknown as { mediaCapabilities?: MediaCapabilities }).mediaCapabilities;
	if (!caps?.encodingInfo) return false;
	const info = await caps.encodingInfo({
		type: 'webrtc',
		video: {
			contentType: 'video/av1',
			width: 1280,
			height: 720,
			bitrate: 1_000_000,
			framerate: 30,
		},
	} as MediaEncodingConfiguration);
	return info.powerEfficient === true;
}

/** Proves VP9 by actually encoding a frame or two, not by asking the browser
 *  what it claims to support. Returns false on ANY failure along the way
 *  (no getUserMedia, no RTCPeerConnection, setCodecPreferences throws,
 *  zero frames encoded in the window) — every failure mode collapses to
 *  "VP9 not proven", never a thrown error out of this function. */
async function vp9TryEncode(): Promise<boolean> {
	let pc: RTCPeerConnection | undefined;
	let stream: MediaStream | undefined;
	try {
		stream = await navigator.mediaDevices.getUserMedia({ video: true });
		const track = stream.getVideoTracks()[0];
		if (!track) return false;

		pc = new RTCPeerConnection();
		const transceiver = pc.addTransceiver(track, { direction: 'sendonly' });
		const RTCRtpSenderCtor = (globalThis as { RTCRtpSender?: { getCapabilities?: (kind: string) => RTCRtpCapabilities | null } }).RTCRtpSender;
		const capabilities = RTCRtpSenderCtor?.getCapabilities?.('video');
		const vp9Codecs = capabilities?.codecs.filter((c) => /VP9/i.test(c.mimeType)) ?? [];
		if (vp9Codecs.length > 0 && transceiver.setCodecPreferences) {
			transceiver.setCodecPreferences(vp9Codecs);
		}

		const offer = await pc.createOffer();
		await pc.setLocalDescription(offer);
		// No real remote peer: read the sender's own outbound-rtp stats after a
		// short encode window — enough for a local encoder to have produced at
		// least one frame if VP9 encoding actually works on this hardware.
		await new Promise((resolve) => setTimeout(resolve, 250));

		for (const sender of pc.getSenders()) {
			const stats = await sender.getStats();
			for (const report of stats.values()) {
				if (report.type === 'outbound-rtp' && (report as { framesEncoded?: number }).framesEncoded) {
					if ((report as { framesEncoded: number }).framesEncoded > 0) return true;
				}
			}
		}
		return false;
	} catch {
		return false;
	} finally {
		pc?.close();
		stream?.getTracks().forEach((t) => t.stop());
	}
}

/** Session-start capability probe (spec §3.4). Never throws — any internal
 *  failure degrades to 'vp8'. Callers (PreJoin) must never block the Join
 *  button on this resolving; a late result just updates publishDefaults. */
export async function pickVideoCodec(): Promise<MeetCodec> {
	try {
		return await withTimeout(pickVideoCodecInner(), PROBE_TIMEOUT_MS);
	} catch {
		return 'vp8';
	}
}

async function pickVideoCodecInner(): Promise<MeetCodec> {
	try {
		if (await av1PowerEfficient()) return 'av1';
	} catch {
		/* fall through to the VP9 try-encode */
	}
	try {
		if (await vp9TryEncode()) return 'vp9';
	} catch {
		/* fall through to vp8 */
	}
	return 'vp8';
}
