// room.svelte.ts — Meet B1 Task 16: the one stateful piece MeetApp/MeetingRoom
// render off. Wraps a single livekit-client Room for the DURATION of one
// meeting attendance (a fresh instance per join — this is not a
// process-wide singleton the way chatStore/driveLocks are, because a user
// attends at most one meeting's media session at a time and a stale Room
// from a prior meeting must never leak into a new one).
//
// Reactions and raise-hand ride the LiveKit data channel (publishData with a
// small JSON envelope {t:'reaction'|'hand', v}) — spec/plan: "no server
// surface at all" for these, so there is no api.ts call here for either.
//
// B3 Task 6 grows the data channel with three more envelope families:
//   - {t:'cc', sid, p, text, final} — live captions from the bot (F8:
//     rendered ONLY from the server-attested `cc:{meetingId}` SENDER,
//     dropped from everyone else — any participant can publish arbitrary
//     data, so the defense is sender identity, never payload trust). `p` is
//     a SEPARATE field: the identity of the human who actually SPOKE the
//     line (asrbot's ccPayload, internal/bot/session.go) — distinct from the
//     frame's sender (always the bot's own `cc:{meetingId}` identity, the
//     thing F8 checks). B3 Task 15 fixed a real bug here: this file used to
//     have no `p` field at all and stamped `CaptionSegment.identity` from
//     the SENDER (`participant.identity`, i.e. the bot on every line) —
//     harmless while nothing rendered per-speaker attribution (Task 6
//     shipped dormant, ahead of asrbot's Task 12 wire contract), but wrong
//     the moment Task 15's overlay needed to show WHO said each line.
//   - {t:'wb', elements} / {t:'wb_req'} / {t:'wb_sync', part, of, seq,
//     elements} — the whiteboard data plane (spec §4.4). `wb` is an
//     unchunked live delta; a `wb_req` late-join request is answered with
//     one or more `wb_sync` parts (F15: LiveKit reliable data caps ~15KiB,
//     so a full-board answer must chunk).
// `moveTo` is the breakout forced-move choreography (D1): the SFU has no
// MoveParticipant, so a move is disconnect-old-room + connect-new-room with
// a freshly minted child-room token, preserving local device state across
// the ~1-2s gap. Room-scoped state (D4) never survives a move: captions are
// main-room-only (the bot never joins a child room) and the whiteboard is
// per-room, so both reset and the new room re-requests a fresh wb sync.
//
// codecProbe.ts's result is NOT re-probed here — the caller (PreJoin) awaits
// pickVideoCodec() once per session and passes the winner into the
// constructor; this class only ever composes RoomOptions from it.
import {
	Room,
	RoomEvent,
	ConnectionQuality,
	Track,
	ScreenSharePresets,
	type RemoteParticipant,
	type Participant,
	type DisconnectReason,
	type ScalabilityMode,
	type VideoCodec,
} from 'livekit-client';
import type { MeetCodec } from './codecProbe';
import { isBlurAvailable, setBlur } from './blur';
// MEET plan M0: the frozen `t:'presentation'` family contract — validation,
// byte budget and receive-side classification live there, never inline here.
import {
	classifyPresentationFrame,
	encodePresentationEnvelope,
	PRESENTATION_TOPIC,
	type PresentationEnvelope,
	type PresentationFrameContext,
} from './presentation';

/** Ephemeral floating reaction (design: reactions are a UI toast, not
 *  persisted state) — auto-expires client-side after REACTION_TTL_MS. */
export interface FloatingReaction {
	id: string;
	identity: string;
	emoji: string;
	expiresAt: number;
}
const REACTION_TTL_MS = 4000;

/** B3 Task 6: a single caption line. `sid` is the ASR engine's per-utterance
 *  segment id — interim updates for the same sid replace in place; a final
 *  update always appends (see #addCaption). `identity` is the SPEAKING
 *  participant's LiveKit identity (asrbot's wire `p` field) — for per-
 *  speaker attribution, NOT the data-channel sender (always the bot). */
export interface CaptionSegment {
	sid: string;
	identity: string;
	text: string;
	final: boolean;
}
/** captionSegments is a capped ring — only the most recent CAPTION_RING
 *  entries are kept (spec: "capped ring of 6"). */
const CAPTION_RING = 6;

/** B3 retro fix (eng #13 / design D7-break): finalsLog is a SEPARATE,
 *  append-only log of finalized lines the sr-only role="log" region reads
 *  from — decoupled from captionSegments' small 6-entry VISUAL ring, whose
 *  eviction on an unrelated INTERIM append was mutating the a11y region (a
 *  final scrolling out of the ring rewrote every remaining row, since the
 *  region used to key by array index). Capped generously, far past the
 *  visual ring, so a long meeting doesn't grow it without bound. */
const FINALS_LOG_CAP = 50;

/** F15: LiveKit reliable data messages cap at ~15KiB. Pinned below the real
 *  ceiling (not at it) so per-part JSON envelope overhead (t/part/of/seq
 *  keys) never pushes an individual wire frame over the real limit. */
export const WB_CHUNK_BYTES = 14000;

interface ReactionEnvelope {
	t: 'reaction';
	v: string;
}
interface HandEnvelope {
	t: 'hand';
	v: boolean;
}
/** Only ever RECEIVED (the bot sends these, never this client). `p` is the
 *  speaking participant's identity (asrbot's ccPayload) — distinct from the
 *  frame's SENDER, which F8's attestedCcIdentity check validates separately
 *  in #handleData. B3 retro fix (design finding #5a): asrbot also publishes
 *  a heartbeat frame every 5s on this SAME `t:'cc'` channel — exactly
 *  `{t:'cc', hb:true}`, with none of sid/p/text/final — that must reset the
 *  degrade signal without ever rendering as a transcript segment; `hb` and
 *  the real-frame fields are all optional here so ONE interface covers both
 *  shapes, discriminated by #handleData at runtime. */
interface CaptionEnvelope {
	t: 'cc';
	hb?: boolean;
	sid?: string;
	p?: string;
	text?: string;
	final?: boolean;
}
interface WhiteboardEnvelope {
	t: 'wb';
	elements: unknown;
}
interface WhiteboardRequestEnvelope {
	t: 'wb_req';
}
interface WhiteboardSyncEnvelope {
	t: 'wb_sync';
	part: number;
	of: number;
	seq: number;
	elements: unknown;
}

type DataEnvelope =
	| ReactionEnvelope
	| HandEnvelope
	| CaptionEnvelope
	| WhiteboardEnvelope
	| WhiteboardRequestEnvelope
	| WhiteboardSyncEnvelope
	| PresentationEnvelope
	| StageEvent;

function isDataEnvelope(x: unknown): x is DataEnvelope {
	return !!x && typeof x === 'object' && 't' in x && (x as { t: unknown }).t !== undefined;
}

// ── MEET plan M3: ephemeral stage events (pointer motion + in-progress ink).
// Deliberately NOT `t:'presentation'` kinds: presentation.ts freezes pointer/
// ink OUT of the durable family (they can neither advance a checkpoint nor be
// durably committed, and a separately-fenced ephemeral frame can never
// impersonate a durable kind). They ride their OWN tiny envelope family here
// so a malformed or oversized stage frame can never be confused with a
// durable one. Frames carry per-sender monotonic `seq` numbers; the receiver
// drops stale ones. Coordinates are normalized [0,1] pairs — never device
// pixels, so a frame leaks nothing about the sender's window.
export const STAGE_EVENT_VERSION = 1;
/** Stage frames are tiny by construction; a hard cap well under the durable
 *  envelope's 14000-byte bound keeps the ephemeral plane from sneaking bulk
 *  payloads onto the wire. */
export const MAX_STAGE_FRAME_BYTES = 2048;
/** One ink stroke carries at most MAX_INK_POINTS normalized coordinates
 *  (flat x,y pairs), so a stroke always fits the frame cap. */
export const MAX_INK_POINTS = 512;

export interface StagePointerEvent {
	t: 'stage';
	v: typeof STAGE_EVENT_VERSION;
	kind: 'pointer';
	seq: number;
	x: number;
	y: number;
}
export interface StageInkEvent {
	t: 'stage';
	v: typeof STAGE_EVENT_VERSION;
	kind: 'ink';
	seq: number;
	points: number[];
}
export interface StageInkClearEvent {
	t: 'stage';
	v: typeof STAGE_EVENT_VERSION;
	kind: 'ink_clear';
	seq: number;
}
export type StageEvent = StagePointerEvent | StageInkEvent | StageInkClearEvent;

function isFiniteUnit(n: unknown): n is number {
	return typeof n === 'number' && Number.isFinite(n) && n >= 0 && n <= 1;
}

function isStageEvent(x: unknown): x is StageEvent {
	if (!x || typeof x !== 'object') return false;
	const e = x as Record<string, unknown>;
	if (e.t !== 'stage' || e.v !== STAGE_EVENT_VERSION) return false;
	if (!Number.isInteger(e.seq) || (e.seq as number) < 0) return false;
	switch (e.kind) {
		case 'pointer':
			return isFiniteUnit(e.x) && isFiniteUnit(e.y);
		case 'ink':
			return (
				Array.isArray(e.points) &&
				e.points.length > 0 &&
				e.points.length <= MAX_INK_POINTS * 2 &&
				e.points.every((p) => typeof p === 'number' && Number.isFinite(p))
			);
		case 'ink_clear':
			return true;
		default:
			return false;
	}
}

/** Ring-caps an array to its most recent `max` entries. */
function capRing<T>(arr: T[], max: number): T[] {
	return arr.length > max ? arr.slice(arr.length - max) : arr;
}

/** Greedily groups `items` into JSON-byte-bounded chunks (each chunk's
 *  stringified size stays under `maxBytes`) — the wb_sync chunker. A single
 *  item larger than maxBytes on its own still gets its own chunk (no
 *  further splitting below the element granularity; ponytail: the board is
 *  capped ~1000 elements client-side per spec §4.4, so a pathological
 *  single-element case is not a real-world path). */
function chunkByBytes(items: unknown[], maxBytes: number): unknown[][] {
	if (items.length === 0) return [[]];
	const chunks: unknown[][] = [];
	let current: unknown[] = [];
	let bytes = 2; // "[]"
	for (const item of items) {
		const itemBytes = new TextEncoder().encode(JSON.stringify(item)).length + 1; // +1 separator
		if (current.length > 0 && bytes + itemBytes > maxBytes) {
			chunks.push(current);
			current = [];
			bytes = 2;
		}
		current.push(item);
		bytes += itemBytes;
	}
	chunks.push(current);
	return chunks;
}

const codecPublishDefaults: Record<MeetCodec, { videoCodec: VideoCodec; scalabilityMode?: ScalabilityMode }> = {
	vp9: { videoCodec: 'vp9', scalabilityMode: 'L3T3_KEY' },
	av1: { videoCodec: 'av1', scalabilityMode: 'L3T3_KEY' },
	// VP8 rides plain simulcast (spec §3.4) — no SVC scalabilityMode.
	vp8: { videoCodec: 'vp8' },
};

export type MeetConnectionState = 'disconnected' | 'connecting' | 'connected' | 'reconnecting';

export class MeetRoom {
	room: Room;
	/** The codec this session's constructor was built with (Task 15's probe
	 *  result) — Task 16b's weak-hardware guard reads it via blurSupported. */
	codec: MeetCodec;
	/** Probe- and browser-capability-gated (Task 16b): ControlsBar hides its
	 *  blur toggle entirely when this is false, rather than offering a
	 *  switch that can't work (spec's own "graceful absence" posture). */
	blurSupported: boolean;
	/** B3 Task 6 / F8: the server-attested `cc:{meetingId}` bot identity for
	 *  THIS meeting. A `{t:'cc'}` frame is rendered only when the sender's
	 *  identity equals this value — everyone else's `cc` frames are dropped,
	 *  a spoof defense (any participant can publish arbitrary data). Default
	 *  `''` fails closed: pre-Task-7 callers that still construct with only
	 *  a codec arg get zero captions rendered, never a wildcard match. */
	attestedCcIdentity: string;

	connectionState = $state<MeetConnectionState>('disconnected');
	participants = $state<RemoteParticipant[]>([]);
	localMuted = $state(true); // design #11: mic/camera default MUTED
	localCameraOff = $state(true);
	screenSharing = $state(false);
	/** identity -> ConnectionQuality, INCLUDING the local participant under 'local'. */
	connectionQuality = $state<Record<string, ConnectionQuality>>({});
	/** design #4: dominant/active speaker (gallery never reshuffles on this;
	 *  only speaker/screenshare layout reads it — MeetingRoom's own concern). */
	dominantSpeakerId = $state<string | null>(null);
	raisedHands = $state<Set<string>>(new Set());
	reactions = $state<FloatingReaction[]>([]);
	/** Task 16b: whether the local camera track currently has the
	 *  background-blur processor attached. Only ever flips on a SUCCESSFUL
	 *  attach/detach (toggleBlur) — never claims a state the processor
	 *  didn't actually reach. */
	blurEnabled = $state(false);
	/** Set once, from the very first Disconnected event — MeetApp/MeetingRoom
	 *  read this to decide whether to show a "you were removed" vs "left"
	 *  vs "connection lost" banner. LiveKit's own DisconnectReason string. */
	disconnectReason = $state<string | null>(null);
	/** B3 Task 6: the caption overlay's data (F8-filtered, ring-capped). */
	captionSegments = $state<CaptionSegment[]>([]);
	/** B3 retro fix (eng #13 / D7-break): the sr-only role="log" region's OWN
	 *  append-only source — see FINALS_LOG_CAP above. Never evicted by the
	 *  small visual ring's own turnover. */
	finalsLog = $state<CaptionSegment[]>([]);
	/** B3 retro fix (design finding #5a): epoch-ms timestamp of the last
	 *  ATTESTED `cc` frame of any kind — a real segment OR the bot's 5s
	 *  heartbeat (`{t:'cc', hb:true}`). CaptionsOverlay's degrade timer keys
	 *  off this (in addition to the `captionSegments` array reference) so a
	 *  heartbeat-only tick resets the "still alive" signal without ever
	 *  creating a transcript entry. */
	lastAttestedCcAt = $state(0);

	#reactionTimers = new Map<string, ReturnType<typeof setTimeout>>();
	#wbListener: ((elements: unknown) => void) | null = null;
	#wbRequestListener: (() => void) | null = null;
	/** MEET plan M0: presentation-family seam. `#presentationContext` is the
	 *  locally validated session truth frames are classified against (null
	 *  presentationId fails closed — no live session, every frame drops);
	 *  `#presentationListener` receives only fresh-sequence hints. Both sit
	 *  inert until M2/M3 wire a gated start path. */
	#presentationListener: ((checkpointSeq: number) => void) | null = null;
	#presentationContext: PresentationFrameContext = { presentationId: null, confirmedSeq: 0, knownGeneration: 0 };
	/** MEET plan M3: the ephemeral stage-plane listener (pointer/ink) and the
	 *  per-sender last-seen sequence numbers used to drop stale frames. The
	 *  map is keyed by identity and cleared on a room swap (a new room is a
	 *  fresh sequence space — carrying old watermarks would drop every fresh
	 *  frame in the new room). */
	#stageListener: ((event: StageEvent, from: string) => void) | null = null;
	#stageSeqBySender = new Map<string, number>();
	/** In-flight wb_sync reassembly, at most one outstanding at a time — a
	 *  higher seq always supersedes and drops whatever was in progress. */
	#wbReassembly: { seq: number; of: number; parts: Map<number, unknown[]> } | null = null;
	#wbSendSeq = 0;

	constructor(codec: MeetCodec, attestedCcIdentity = '') {
		this.codec = codec;
		this.attestedCcIdentity = attestedCcIdentity;
		this.blurSupported = isBlurAvailable(codec);
		this.room = this.#buildRoom();
		this.#wireEvents();
	}

	#buildRoom(): Room {
		const codecDefaults = codecPublishDefaults[this.codec];
		return new Room({
			adaptiveStream: true,
			dynacast: true,
			publishDefaults: {
				...codecDefaults,
				// VP8 has no separate backup — it IS the universal fallback (spec §3.4).
				backupCodec: this.codec === 'vp8' ? undefined : { codec: 'vp8' },
				screenShareEncoding: ScreenSharePresets.h1080fps15.encoding,
			},
		});
	}

	#wireEvents(): void {
		this.room
			.on(RoomEvent.Connected, () => {
				this.connectionState = 'connected';
				this.#syncParticipants();
			})
			.on(RoomEvent.Reconnecting, () => {
				this.connectionState = 'reconnecting';
			})
			.on(RoomEvent.Reconnected, () => {
				this.connectionState = 'connected';
			})
			.on(RoomEvent.Disconnected, (reason?: DisconnectReason) => {
				this.connectionState = 'disconnected';
				this.disconnectReason = reason != null ? String(reason) : null;
				this.participants = [];
			})
			.on(RoomEvent.ParticipantConnected, () => this.#syncParticipants())
			.on(RoomEvent.ParticipantDisconnected, () => this.#syncParticipants())
			.on(RoomEvent.ConnectionQualityChanged, (quality: ConnectionQuality, participant?: Participant) => {
				const identity = participant?.identity ?? 'local';
				this.connectionQuality = { ...this.connectionQuality, [identity]: quality };
			})
			.on(RoomEvent.ActiveSpeakersChanged, (speakers: Participant[]) => {
				this.dominantSpeakerId = speakers[0]?.identity ?? null;
			})
			.on(RoomEvent.DataReceived, (payload: Uint8Array, participant?: RemoteParticipant) => {
				this.#handleData(payload, participant);
			});
	}

	/** 2026-07-16 (B3b live-gate P0 1b): the captions bot joins UNHIDDEN
	 *  (livekit-server v1.13.3 strips a HIDDEN participant's data-packet
	 *  sender identity, which killed F8 attestation — see
	 *  meeting_control.sql's meeting_captions_set) — so it now appears in
	 *  room.remoteParticipants like anyone else. Filtered out HERE, the one
	 *  choke point every gallery tile / participant sheet / count reads
	 *  (`participants`), so the bot never renders a row anywhere. Its data
	 *  frames are unaffected — #handleData reads straight off the
	 *  RoomEvent.DataReceived callback, not off this filtered list. */
	#syncParticipants(): void {
		this.participants = Array.from(this.room.remoteParticipants.values()).filter(
			(p) => !p.identity.startsWith('cc:'),
		);
	}

	#handleData(payload: Uint8Array, participant?: RemoteParticipant): void {
		if (!participant) return;
		let msg: unknown;
		try {
			msg = JSON.parse(new TextDecoder().decode(payload));
		} catch {
			return; // ponytail: a malformed data packet is silently dropped, never crashes the room
		}
		if (!isDataEnvelope(msg)) return;
		switch (msg.t) {
			case 'reaction':
				if (typeof msg.v === 'string') this.#addReaction(participant.identity, msg.v);
				break;
			case 'hand': {
				if (typeof msg.v !== 'boolean') break;
				const next = new Set(this.raisedHands);
				if (msg.v) next.add(participant.identity);
				else next.delete(participant.identity);
				this.raisedHands = next;
				break;
			}
			case 'cc': {
				// F8: dropped unless the SENDER is the server-attested bot identity
				// (an empty attestedCcIdentity — the pre-Task-7 default — matches
				// nothing, so captions fail closed rather than open).
				if (this.attestedCcIdentity === '' || participant.identity !== this.attestedCcIdentity) break;
				// B3 retro fix (design finding #5a): the heartbeat frame — no
				// sid/p/text/final — resets the "still alive" signal WITHOUT
				// ever rendering as a transcript segment.
				if (msg.hb === true) {
					this.lastAttestedCcAt = Date.now();
					break;
				}
				// `msg.p` (the SPEAKING participant, not the sender) is what
				// gets recorded as the segment's identity — attribution, not
				// authentication.
				if (
					typeof msg.sid === 'string' &&
					typeof msg.p === 'string' &&
					typeof msg.text === 'string' &&
					typeof msg.final === 'boolean'
				) {
					this.lastAttestedCcAt = Date.now();
					this.#addCaption({ sid: msg.sid, identity: msg.p, text: msg.text, final: msg.final });
				}
				break;
			}
			case 'wb':
				this.#wbListener?.(msg.elements);
				break;
			case 'wb_req':
				this.#wbRequestListener?.();
				break;
			case 'wb_sync':
				if (typeof msg.part === 'number' && typeof msg.of === 'number' && typeof msg.seq === 'number') {
					this.#handleWbSync(msg);
				}
				break;
			case PRESENTATION_TOPIC: {
				// MEET plan M0: durable presentation frames are UNTRUSTED
				// checkpoint-invalidation hints, even from the current
				// presenter. Reject/no-op per the frozen contract; only a
				// fresh sequence reaches the listener, and the listener (M2+
				// store) still promotes state only from an authorized
				// reducer response / checkpoint read — never from a frame.
				// The ORIGINAL wire bytes travel with the frame: the byte
				// bound is measured against what actually arrived, not a
				// re-serialization of the parsed object.
				const verdict = classifyPresentationFrame(msg, this.#presentationContext, payload);
				if (verdict === 'invalidate-checkpoint') {
					this.#presentationListener?.(msg.checkpointSeq);
				}
				break;
			}
			case 'stage': {
				// MEET plan M3: the ephemeral stage plane. Shape-validated
				// (isStageEvent), sequence-deduped per sender, and handed to
				// the listener with the sender identity — the store layers
				// the liveness/presenter gates on top. Never touches
				// presentation durable state (the families are disjoint by
				// construction).
				if (!participant || !isStageEvent(msg)) break;
				const last = this.#stageSeqBySender.get(participant.identity);
				if (last !== undefined && msg.seq <= last) break;
				this.#stageSeqBySender.set(participant.identity, msg.seq);
				this.#stageListener?.(msg, participant.identity);
				break;
			}
		}
	}

	#addReaction(identity: string, emoji: string): void {
		const id = `${identity}-${Date.now()}-${Math.random()}`;
		this.reactions = [...this.reactions, { id, identity, emoji, expiresAt: Date.now() + REACTION_TTL_MS }];
		const timer = setTimeout(() => {
			this.reactions = this.reactions.filter((r) => r.id !== id);
			this.#reactionTimers.delete(id);
		}, REACTION_TTL_MS);
		this.#reactionTimers.set(id, timer);
	}

	/** Interim (final:false) segments replace the existing entry with the
	 *  same sid, or append if this sid is new. A final segment always
	 *  appends a fresh entry (the finalized line joins the transcript log;
	 *  it does not retroactively collapse its own interim history). Ring
	 *  capped at CAPTION_RING regardless of which branch fired.
	 *
	 *  B3 retro fix (eng #13 / D7-break): a final ALSO appends to finalsLog
	 *  (capped separately, far higher — FINALS_LOG_CAP) so the sr-only
	 *  region has its own append-only source, immune to the visual ring's
	 *  own turnover on a later INTERIM append. */
	#addCaption(seg: CaptionSegment): void {
		if (seg.final) {
			this.finalsLog = capRing([...this.finalsLog, seg], FINALS_LOG_CAP);
		} else {
			const idx = this.captionSegments.findIndex((s) => s.sid === seg.sid);
			if (idx >= 0) {
				const next = [...this.captionSegments];
				next[idx] = seg;
				this.captionSegments = capRing(next, CAPTION_RING);
				return;
			}
		}
		this.captionSegments = capRing([...this.captionSegments, seg], CAPTION_RING);
	}

	/** Reassembles a chunked wb_sync answer. Tolerates out-of-order parts
	 *  (keyed by part number in a Map, delivered regardless of arrival
	 *  order) and discards a stale in-flight buffer the moment a NEWER seq
	 *  starts arriving; a straggling part from an already-superseded seq is
	 *  dropped on arrival rather than silently reviving a stale buffer. */
	#handleWbSync(msg: WhiteboardSyncEnvelope): void {
		if (this.#wbReassembly && msg.seq > this.#wbReassembly.seq) {
			this.#wbReassembly = null;
		}
		if (this.#wbReassembly && msg.seq < this.#wbReassembly.seq) {
			return; // a newer sync already superseded this one — drop the straggler
		}
		if (!this.#wbReassembly) {
			this.#wbReassembly = { seq: msg.seq, of: msg.of, parts: new Map() };
		}
		this.#wbReassembly.parts.set(msg.part, (msg.elements as unknown[]) ?? []);
		if (this.#wbReassembly.parts.size >= this.#wbReassembly.of) {
			const merged: unknown[] = [];
			for (let i = 1; i <= this.#wbReassembly.of; i++) {
				merged.push(...(this.#wbReassembly.parts.get(i) ?? []));
			}
			this.#wbReassembly = null;
			this.#wbListener?.(merged);
		}
	}

	async connect(token: string, wsPath = '/rtc', opts?: { blurEnabled?: boolean }): Promise<void> {
		this.connectionState = 'connecting';
		// Scheme follows the page: a hard-coded wss:// on an http-served page
		// (dev stack, non-TLS install) hits ERR_SSL_PROTOCOL_ERROR and the
		// join dies before the signal handshake (B1 webmail-UI gate finding).
		// Production is TLS-only and stays wss.
		const proto = location.protocol === 'https:' ? 'wss' : 'ws';
		const url = `${proto}://${location.host}${wsPath}`;
		await this.room.connect(url, token);
		// Local media defaults MUTED (design #11) — publish nothing until the
		// user explicitly unmutes via toggleMic()/toggleCamera() (or PreJoin
		// already unmuted before connect, in which case these are no-ops).
		await this.room.localParticipant.setMicrophoneEnabled(!this.localMuted).catch(() => undefined);
		await this.room.localParticipant.setCameraEnabled(!this.localCameraOff).catch(() => undefined);
		// Carry PreJoin's blur preference into the real published track (a
		// fresh MediaStreamTrack — the preview's processor, if any, doesn't
		// travel with it).
		if (opts?.blurEnabled && this.blurSupported && !this.localCameraOff) {
			await this.toggleBlur(true);
		}
	}

	/** Attaches/detaches background blur on the LIVE camera track (Task
	 *  16b). No-op if unsupported (blurSupported gate). If there is no
	 *  camera track yet (camera currently off), the preference is recorded
	 *  as sticky and applied by toggleCamera() the next time the camera
	 *  turns on — it never claims success it didn't reach. */
	async toggleBlur(enabled: boolean): Promise<void> {
		if (!this.blurSupported) return;
		const track = this.room.localParticipant.getTrackPublication(Track.Source.Camera)?.videoTrack;
		if (!track) {
			this.blurEnabled = enabled;
			return;
		}
		const ok = await setBlur(track, enabled);
		if (ok) this.blurEnabled = enabled;
	}

	/** Clears reaction timers and disconnects the CURRENT `this.room`.
	 *  Shared by the plain leave-the-meeting `disconnect()` (fire-and-forget)
	 *  and `moveTo` (which awaits it before building the replacement room). */
	#teardownRoom(): Promise<void> {
		for (const timer of this.#reactionTimers.values()) clearTimeout(timer);
		this.#reactionTimers.clear();
		return this.room.disconnect();
	}

	disconnect(): void {
		void this.#teardownRoom();
	}

	/** B3 Task 6 (design D1): the SFU has no native MoveParticipant, so a
	 *  forced breakout move is disconnect-old-room + connect-new-room with a
	 *  freshly minted child-room token. Device state (mute/camera/blur)
	 *  survives the ~1-2s gap; room-scoped state does NOT (D4): captions are
	 *  main-room-only (the bot never joins a child room) and the whiteboard
	 *  is per-room, so both reset here and the new room re-requests a fresh
	 *  wb sync the moment it's live. */
	async moveTo(token: string, wsPath = '/rtc'): Promise<void> {
		this.captionSegments = [];
		this.finalsLog = [];
		this.#wbReassembly = null;

		const preservedMuted = this.localMuted;
		const preservedCameraOff = this.localCameraOff;
		const preservedBlur = this.blurEnabled;

		const oldRoom = this.room;
		await this.#teardownRoom();
		// B3 retro fix (eng #9): neutralize the OLD room's handlers BEFORE
		// `this.room` is reassigned below — every #wireEvents() handler closes
		// over `this`, not the specific Room instance, so a stray event still
		// in flight on the old (disconnected) Room would otherwise mutate this
		// object's state as if it were the live room.
		oldRoom.removeAllListeners();

		this.room = this.#buildRoom();
		this.#wireEvents();
		this.blurEnabled = false; // re-carried by connect()'s opts.blurEnabled below, only on real success
		this.localMuted = preservedMuted;
		this.localCameraOff = preservedCameraOff;
		// B3 retro fix (eng #9, the D4 room-scoped-state genre): every other
		// bit of state that describes the room just vacated — a stale raised
		// hand, a floating reaction, the dominant speaker, per-identity
		// connection quality, the last disconnect reason, an active
		// screenshare flag — must never render as if it belonged to the new
		// room.
		this.raisedHands = new Set();
		this.reactions = [];
		this.dominantSpeakerId = null;
		this.connectionQuality = {};
		this.disconnectReason = null;
		this.screenSharing = false;
	// D4 room-scoped-state genre: the vacated room's presentation-family
	// session truth must never classify frames for the new room.
	this.#presentationContext = { presentationId: null, confirmedSeq: 0, knownGeneration: 0 };
	// D4 genre (M3): the stage plane's per-sender watermarks die with the
	// room too — a new room is a fresh sequence space, and a stale watermark
	// would silently drop every fresh pointer/ink frame after a move.
	this.#stageSeqBySender.clear();

		await this.connect(token, wsPath, { blurEnabled: preservedBlur });
		// connect() only returns once room.connect() has resolved, i.e. the
		// new room is live — set explicitly rather than relying on the
		// Connected event's dispatch timing relative to that resolution.
		this.connectionState = 'connected';
		this.requestWhiteboardSync();
	}

	async toggleMic(): Promise<void> {
		this.localMuted = !this.localMuted;
		await this.room.localParticipant.setMicrophoneEnabled(!this.localMuted).catch(() => {
			// revert optimistic flip on a real device failure so the UI never
			// claims "unmuted" when the browser refused the request
			this.localMuted = !this.localMuted;
		});
	}

	async toggleCamera(): Promise<void> {
		this.localCameraOff = !this.localCameraOff;
		await this.room.localParticipant.setCameraEnabled(!this.localCameraOff).catch(() => {
			this.localCameraOff = !this.localCameraOff;
		});
		// A fresh camera track needs blur re-applied — it doesn't inherit the
		// prior track's processor. The preference itself (blurEnabled) is a
		// session-level sticky setting that survives a mute/unmute cycle.
		if (!this.localCameraOff && this.blurEnabled) await this.toggleBlur(true);
	}

	async toggleScreenShare(): Promise<void> {
		const next = !this.screenSharing;
		try {
			await this.room.localParticipant.setScreenShareEnabled(next);
			this.screenSharing = next;
		} catch {
			// user cancelled the OS picker, or permission denied — stay as-is
		}
	}

	#publish(envelope: DataEnvelope): void {
		if (this.connectionState !== 'connected') return;
		const bytes = new TextEncoder().encode(JSON.stringify(envelope));
		void this.room.localParticipant.publishData(bytes, { reliable: true });
	}

	sendReaction(emoji: string): void {
		this.#addReaction('local', emoji); // optimistic local echo — no round trip needed to see your own reaction
		this.#publish({ t: 'reaction', v: emoji });
	}

	raisedHandSelf = $state(false);
	toggleRaiseHand(): void {
		this.raisedHandSelf = !this.raisedHandSelf;
		this.#publish({ t: 'hand', v: this.raisedHandSelf });
	}

	// ── B3 Task 6: whiteboard (spec §4.4) ──────────────────────────────────

	/** Registers the callback that receives whiteboard element updates —
	 *  both live `wb` deltas and a fully-reassembled `wb_sync` answer land
	 *  here uniformly (Excalidraw's own reconcileElements decides how to
	 *  merge either shape; this store doesn't distinguish them). One
	 *  listener at a time (a single WhiteboardPanel mounts per room). Pass
	 *  `null` to unregister (B3 retro fix, design #9) — WhiteboardPanel's
	 *  onDestroy does this so a `wb` frame arriving after the panel unmounts
	 *  never calls into a dead Excalidraw handle. */
	onWhiteboard(cb: ((elements: unknown) => void) | null): void {
		this.#wbListener = cb;
	}

	/** Registers the callback that fires when a peer asks for the current
	 *  full board (a `wb_req` frame) — the owning component answers via
	 *  `sendWhiteboardSync(currentElements)`. `null` unregisters, the
	 *  onWhiteboard genre. */
	onWhiteboardRequest(cb: (() => void) | null): void {
		this.#wbRequestListener = cb;
	}

	/** A live, small element delta — unchunked `{t:'wb', elements}`. */
	sendWhiteboard(elements: unknown): void {
		this.#publish({ t: 'wb', elements });
	}

	/** Asks any peer to answer with the current full board state. */
	requestWhiteboardSync(): void {
		this.#publish({ t: 'wb_req' });
	}

	/** Answers a `wb_req` with the full board, chunked at WB_CHUNK_BYTES
	 *  (F15) into sequence-numbered `wb_sync` parts sharing one `seq` so the
	 *  receiver can detect + discard a superseded in-flight sync. */
	sendWhiteboardSync(elements: unknown): void {
		const seq = ++this.#wbSendSeq;
		const list = Array.isArray(elements) ? elements : [elements];
		const chunks = chunkByBytes(list, WB_CHUNK_BYTES);
		const of = chunks.length;
		chunks.forEach((chunk, i) => {
			this.#publish({ t: 'wb_sync', part: i + 1, of, seq, elements: chunk });
		});
	}

	// ── MEET plan M0: presentation family (inert until M2 wires a start path)

	/** Sets the locally validated session truth received presentation frames
	 *  are classified against. `presentationId: null` (the default) fails
	 *  closed. `confirmedSeq`/`knownGeneration` move only on authorized
	 *  reads — never from a received frame. */
	setPresentationContext(ctx: PresentationFrameContext): void {
		this.#presentationContext = ctx;
	}

	/** Registers the callback that receives fresh-sequence checkpoint
	 *  invalidation hints. Rejects and duplicates never reach it. `null`
	 *  unregisters (the onWhiteboard genre). */
	onPresentation(cb: ((checkpointSeq: number) => void) | null): void {
		this.#presentationListener = cb;
	}

	/** Publishes one durable presentation frame. The frozen byte budget is
	 *  checked BEFORE publication; a dropped frame is a bounded diagnostic —
	 *  already-committed state stays committed and checkpoint recovery
	 *  converges (never an infinite retry). Returns false when the frame was
	 *  not published (disconnected, shape-invalid, reserved kind, or over
	 *  the 14000-byte wire bound). */
	sendPresentationFrame(
		envelope: Omit<PresentationEnvelope, 't'> & { t?: typeof PRESENTATION_TOPIC },
	): boolean {
		const result = encodePresentationEnvelope({ t: PRESENTATION_TOPIC, ...envelope } as PresentationEnvelope);
		if (!result.ok) return false;
		if (this.connectionState !== 'connected') return false;
		void this.room.localParticipant.publishData(result.bytes, { reliable: true }).catch(() => undefined);
		return true;
	}

	// ── MEET plan M3: ephemeral stage plane (pointer motion, in-progress ink)

	/** Registers the ephemeral stage-frame listener. Receives only
	 *  shape-valid, sequence-fresh frames plus the sender identity. `null`
	 *  unregisters (the onWhiteboard genre). */
	onStage(cb: ((event: StageEvent, from: string) => void) | null): void {
		this.#stageListener = cb;
	}

	/** Publishes one ephemeral stage frame. The stage frame cap is checked
	 *  BEFORE publication; a dropped frame is a bounded diagnostic on an
	 *  ephemeral plane — the next pointer move or stroke supersedes it, and
	 *  nothing durable is ever lost (there is nothing durable here). Returns
	 *  false when the frame was not published (disconnected, shape-invalid,
	 *  or over the stage wire cap). */
	sendStageEvent(event: StageEvent): boolean {
		if (!isStageEvent(event)) return false;
		const bytes = new TextEncoder().encode(JSON.stringify(event));
		if (bytes.length > MAX_STAGE_FRAME_BYTES) return false;
		if (this.connectionState !== 'connected') return false;
		void this.room.localParticipant.publishData(bytes, { reliable: true }).catch(() => undefined);
		return true;
	}
}

export { Track };
