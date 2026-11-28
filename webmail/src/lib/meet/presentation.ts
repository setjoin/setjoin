// presentation.ts — MEET plan M0: the frozen client-side contract for the
// `t:'presentation'` data-channel family
// (retired-docs:superpowers/plans/2026-08-25-meet-document-presentation-semantic-
// recording.md, "Event envelope"). Presentation preserves the existing
// room.svelte.ts top-level `t` discriminator; `v` and `kind` apply only
// inside this family.
//
// Contract limits frozen here (plan "Performance budgets"):
//   - A complete serialized UTF-8 presentation envelope, including all
//     fields, is at most MAX_ENVELOPE_BYTES (14000) on LiveKit — the
//     API/stored-object 16 KiB limit is NOT the wire allowance.
//   - A page-change payload targets under 1 KiB; larger durable snapshots
//     use an authorized bounded reference/read path, never implicit
//     fragmentation.
//   - Manifests bound at 500 pages; page indexes live in [0, 500).
//
// Durable presentation frames are UNTRUSTED checkpoint-invalidation hints,
// even from the current presenter: nothing in this module advances canvas,
// checkpoint sequence, manifest generation, source identity or any retained
// timeline directly. State is promoted only from an authenticated reducer
// response or an authorized checkpoint read (the M2/M3 surfaces). Pointer
// motion and in-progress ink are ephemeral — deliberately not kinds here.

export const PRESENTATION_TOPIC = 'presentation' as const;

/** Unknown versions fail closed — clients reject them. */
export const PRESENTATION_VERSION = 1 as const;

/** The wire byte budget checked BEFORE publication. */
export const MAX_ENVELOPE_BYTES = 14000;

/** Manifest page bound: [0, MAX_PAGE_INDEX]. */
export const MAX_PAGE_INDEX = 499;

/** Page-change payloads target under 1 KiB. */
export const TARGET_PAGE_CHANGE_PAYLOAD_BYTES = 1024;

/** Durable presentation events. The annotation kinds were RESERVED at
 *  M0/M2; M4 admitted them through the reducer's admitted-shape commit path
 *  (a well-formed snapshot commit or a clear) — their payloads are validated
 *  closed in both directions below, and every other annotation shape stays
 *  refused (BZ277 admitted-path semantics). */
export type PresentationKind =
	| 'start'
	| 'ready'
	| 'page.changed'
	| 'presenter.granted'
	| 'presenter.takeover'
	| 'annotation.cleared'
	| 'annotation.committed'
	| 'source.switched'
	| 'fallback.changed'
	| 'end';

const KNOWN_KINDS: readonly PresentationKind[] = [
	'start',
	'ready',
	'page.changed',
	'presenter.granted',
	'presenter.takeover',
	'annotation.cleared',
	'annotation.committed',
	'source.switched',
	'fallback.changed',
	'end',
];

/** The versioned presentation envelope (`t:'presentation'`, v:1). */
export interface PresentationEnvelope {
	t: typeof PRESENTATION_TOPIC;
	v: number;
	presentationId: string;
	checkpointSeq: number;
	presenterGeneration: number;
	kind: PresentationKind;
	payload?: unknown;
	sentAt: string;
}

export type EncodeResult =
	| { ok: true; bytes: Uint8Array<ArrayBuffer> }
	| { ok: false; error: string };

/** Validates the frame shape, enforces the byte budget, and serializes. A
 *  failed encode is a bounded diagnostic: the caller drops the ephemeral
 *  output while already-committed state stays committed and checkpoint
 *  recovery converges — never an infinite retry or reconnect replay. */
/** UTF-8 is the wire encoding: byte budgets are measured with
 *  TextEncoder byte lengths, never JS string lengths (a string of n
 *  UTF-16 units can be up to 3n UTF-8 bytes on the wire). */
const utf8Encoder = new TextEncoder();
const utf8ByteLength = (s: string): number => utf8Encoder.encode(s).length;

export function encodePresentationEnvelope(envelope: PresentationEnvelope): EncodeResult {
	const error = validateShape(envelope);
	if (error !== null) return { ok: false, error };
	const bytes = utf8Encoder.encode(JSON.stringify(envelope));
	if (bytes.length > MAX_ENVELOPE_BYTES) {
		return {
			ok: false,
			error: `presentation envelope is ${bytes.length} bytes; complete serialized frames are at most ${MAX_ENVELOPE_BYTES} — use an authorized bounded reference/read path`,
		};
	}
	return { ok: true, bytes };
}

/** The page.changed payload admission shared by BOTH directions: the send
 *  path (encodePresentationEnvelope) and the receive path
 *  (classifyPresentationFrame) enforce the identical integer-pageIndex and
 *  1 KiB wire-byte payload target, so a payload one side would reject can
 *  neither be published nor ride a received frame into checkpoint
 *  invalidation.
 *
 *  `rawWireBytes` is the payload member's size in its ORIGINAL wire encoding
 *  within the received frame (the TS mirror of Go's `json.RawMessage`
 *  length). Measuring the RE-SERIALIZED parsed payload instead launders the
 *  check through JSON escapes: a 1,225-byte raw payload collapses to 225
 *  bytes after parse+stringify and would slip under the target. It is
 *  omitted only where the original encoding is unknowable — on the send
 *  path, whose JSON.stringify serialization IS the wire encoding, and on a
 *  receive path that was handed no frame bytes. */
function validatePageChangedPayload(payload: unknown, rawWireBytes?: number): string | null {
	const p = payload as { pageIndex?: unknown } | undefined;
	if (!p || typeof p !== 'object' || typeof p.pageIndex !== 'number' || !Number.isInteger(p.pageIndex)) {
		return 'page.changed payload missing integer pageIndex';
	}
	if (p.pageIndex < 0 || p.pageIndex > MAX_PAGE_INDEX) {
		return `page index ${p.pageIndex} outside [0,${MAX_PAGE_INDEX}]`;
	}
	const wireBytes = rawWireBytes ?? utf8ByteLength(JSON.stringify(p) ?? '');
	if (wireBytes > TARGET_PAGE_CHANGE_PAYLOAD_BYTES) {
		return `page-change payload of ${wireBytes} bytes exceeds the ${TARGET_PAGE_CHANGE_PAYLOAD_BYTES}-byte target`;
	}
	return null;
}

/** The annotation kinds' closed payload admission (the M4 flip's wire
 *  guard, the mirror of the Go validateAnnotationEvent): a committed
 *  snapshot carries exactly the bounded reference triple; a clear carries
 *  no payload. Anything else fails closed on BOTH the send and receive
 *  paths — the admitted-path semantics, never a silent demotion. */
export const MAX_ANNOTATION_SNAPSHOT_BYTES = 16384;
export const TARGET_ANNOTATION_PAYLOAD_BYTES = 1024;
const ANNOTATION_REF_RE = /^annotations\/p[0-9]+-s[0-9]+\.json$/;
const SHA256_RE = /^[0-9a-f]{64}$/;

export interface AnnotationPayload {
	snapshotRef: string;
	sha256: string;
	byteSize: number;
}

function validateAnnotationPayload(payload: unknown, rawWireBytes?: number): string | null {
	const p = payload as Partial<AnnotationPayload> | undefined | null;
	if (
		!p ||
		typeof p !== 'object' ||
		typeof p.snapshotRef !== 'string' ||
		!ANNOTATION_REF_RE.test(p.snapshotRef) ||
		typeof p.sha256 !== 'string' ||
		!SHA256_RE.test(p.sha256) ||
		typeof p.byteSize !== 'number' ||
		!Number.isInteger(p.byteSize) ||
		p.byteSize < 1 ||
		p.byteSize > MAX_ANNOTATION_SNAPSHOT_BYTES
	) {
		return 'annotation.committed payload is not a typed annotation payload';
	}
	const wireBytes = rawWireBytes ?? utf8ByteLength(JSON.stringify(p) ?? '');
	if (wireBytes > TARGET_ANNOTATION_PAYLOAD_BYTES) {
		return `annotation payload of ${wireBytes} bytes exceeds the ${TARGET_ANNOTATION_PAYLOAD_BYTES}-byte target`;
	}
	return null;
}

function validateShape(envelope: PresentationEnvelope): string | null {
	if (envelope.t !== PRESENTATION_TOPIC) return `envelope topic must be ${PRESENTATION_TOPIC}`;
	if (envelope.v !== PRESENTATION_VERSION) return `unknown presentation version ${envelope.v} fails closed`;
	if (!KNOWN_KINDS.includes(envelope.kind)) return `unknown kind fails closed`;
	if (typeof envelope.presentationId !== 'string' || envelope.presentationId === '') {
		return 'envelope missing presentation id';
	}
	if (!Number.isInteger(envelope.checkpointSeq) || envelope.checkpointSeq < 0) {
		return 'checkpointSeq must be a non-negative integer';
	}
	if (!Number.isInteger(envelope.presenterGeneration) || envelope.presenterGeneration < 0) {
		return 'presenterGeneration must be a non-negative integer';
	}
	if (typeof envelope.sentAt !== 'string' || envelope.sentAt === '') return 'envelope missing sentAt';
	if (envelope.kind === 'page.changed') {
		const error = validatePageChangedPayload(envelope.payload);
		if (error !== null) return error;
	}
	if (envelope.kind === 'annotation.committed') {
		const error = validateAnnotationPayload(envelope.payload);
		if (error !== null) return error;
	}
	if (envelope.kind === 'annotation.cleared' && envelope.payload !== undefined && envelope.payload !== null) {
		return 'annotation.cleared carries no payload';
	}
	return null;
}

/** The locally validated session truth a received frame is judged against.
 *  `presentationId === null` means no live presentation family session:
 *  every frame rejects (fail closed). `confirmedSeq` only ever moves on an
 *  AUTHORIZED checkpoint read — an advertised peer sequence is not a
 *  trusted watermark. */
export interface PresentationFrameContext {
	presentationId: string | null;
	confirmedSeq: number;
	knownGeneration: number;
}

export type FrameVerdict = 'reject' | 'noop' | 'invalidate-checkpoint';

/** The wire text a received frame's raw payload member is measured in: the
 *  same non-fatal UTF-8 decode the room applies before `JSON.parse`, so the
 *  extracted substring is byte-for-byte what the sender encoded. */
const wireTextDecoder = new TextDecoder('utf-8');

/** Scans a JSON string literal starting at `start` (at `"`) and returns the
 *  decoded text plus the index just past the closing quote, or null on
 *  malformed input. Used for MEMBER KEYS only — values are measured raw. */
function scanJsonKey(doc: string, start: number): { key: string; end: number } | null {
	let i = start + 1;
	let key = '';
	for (;;) {
		if (i >= doc.length) return null;
		const c = doc[i];
		if (c === '"') return { key, end: i + 1 };
		if (c === '\\') {
			const esc = doc[i + 1];
			i += 2;
			if (esc === 'u') {
				const hex = doc.slice(i, i + 4);
				if (!/^[0-9a-fA-F]{4}$/.test(hex)) return null;
				key += String.fromCharCode(parseInt(hex, 16));
				i += 4;
			} else if (esc === '"' || esc === '\\' || esc === '/') {
				key += esc;
			} else if (esc === 'b') {
				key += '\b';
			} else if (esc === 'f') {
				key += '\f';
			} else if (esc === 'n') {
				key += '\n';
			} else if (esc === 'r') {
				key += '\r';
			} else if (esc === 't') {
				key += '\t';
			} else {
				return null;
			}
			continue;
		}
		key += c;
		i++;
	}
}

/** Returns the index just past one complete JSON value starting at `start`,
 *  or null on malformed input. String literals are skipped escape-aware so
 *  braces and brackets inside them never affect nesting depth. */
function scanRawJsonValueEnd(doc: string, start: number): number | null {
	let i = start;
	let depth = 0;
	for (;;) {
		if (i >= doc.length) return null;
		const c = doc[i];
		if (c === '"') {
			i++;
			for (;;) {
				if (i >= doc.length) return null;
				const ch = doc[i];
				if (ch === '\\') i += 2;
				else if (ch === '"') {
					i++;
					break;
				} else i++;
			}
			continue;
		}
		if (c === '{' || c === '[') {
			depth++;
			i++;
			continue;
		}
		if (depth > 0 && (c === '}' || c === ']')) {
			depth--;
			i++;
			if (depth === 0) return i;
			continue;
		}
		// Depth 0: a bare literal (number/true/false/null) ends at the
		// enclosing object's `,` or `}`.
		if (depth === 0 && (c === ',' || c === '}')) return i;
		i++;
	}
}

/** Extracts the RAW source text of the LAST top-level `payload` member of a
 *  JSON object document — escapes and internal whitespace included, exactly
 *  as the sender encoded it (the TS mirror of Go's `json.RawMessage`).
 *  Duplicate keys follow JSON.parse semantics: last wins. Returns null when
 *  the document is not a JSON object or carries no such member. */
function rawPayloadMemberText(doc: string): string | null {
	let i = 0;
	const n = doc.length;
	const skipWs = (): void => {
		while (i < n && (doc[i] === ' ' || doc[i] === '\t' || doc[i] === '\n' || doc[i] === '\r')) i++;
	};
	skipWs();
	if (i >= n || doc[i] !== '{') return null;
	i++;
	skipWs();
	let found: string | null = null;
	if (i < n && doc[i] === '}') return found;
	for (;;) {
		if (i >= n || doc[i] !== '"') return null;
		const key = scanJsonKey(doc, i);
		if (key === null) return null;
		i = key.end;
		skipWs();
		if (i >= n || doc[i] !== ':') return null;
		i++;
		skipWs();
		const valueStart = i;
		const valueEnd = scanRawJsonValueEnd(doc, i);
		if (valueEnd === null) return null;
		if (key.key === 'payload') found = doc.slice(valueStart, valueEnd);
		i = valueEnd;
		skipWs();
		if (i >= n) return null;
		if (doc[i] === ',') {
			i++;
			skipWs();
			continue;
		}
		return doc[i] === '}' ? found : null;
	}
}

/** Receive-side classification: clients reject unknown versions, wrong
 *  presentation IDs, stale generations, oversized payloads, invalid page
 *  indexes and non-presenter mutations; duplicate or old events are no-ops;
 *  a fresh sequence is a bounded checkpoint-invalidation hint (coalesced
 *  refresh — never direct promotion of the frame's contents).
 *
 *  ORDERING CONTRACT: wire-byte and payload validation run BEFORE the
 *  sequence-based dedup. An oversized or malformed frame rejects at the
 *  door even when its sequence is a duplicate or stale — the `noop`
 *  classification is for well-formed frames only and must never launder a
 *  frame the wire/payload bounds reject into a harmless no-op.
 *
 *  `wireBytes` is the ORIGINAL UTF-8 frame exactly as received, when the
 *  caller has it (the room's data-channel payload). The wire bound is
 *  measured against THOSE bytes: re-serializing a parsed frame is not the
 *  frame the peer sent (key order, whitespace, `\uXXXX` escapes all
 *  collapse), so an oversized frame could otherwise shrink below the bound
 *  and slip through to checkpoint invalidation. The page.changed payload is
 *  likewise measured in its raw wire encoding WITHIN those bytes — its
 *  source substring, escapes intact — mirroring the Go receiver's
 *  json.RawMessage length; the re-serialized parsed payload is only the
 *  fallback when no wire bytes were supplied. */
export function classifyPresentationFrame(frame: unknown, ctx: PresentationFrameContext, wireBytes?: Uint8Array): FrameVerdict {
	if (ctx.presentationId === null) return 'reject';
	if (typeof frame !== 'object' || frame === null) return 'reject';
	const e = frame as Record<string, unknown>;
	if (e.t !== PRESENTATION_TOPIC) return 'reject';
	if (e.v !== PRESENTATION_VERSION) return 'reject';
	if (typeof e.kind !== 'string' || !KNOWN_KINDS.includes(e.kind as PresentationKind)) return 'reject';
	if (e.presentationId !== ctx.presentationId) return 'reject';
	if (typeof e.presenterGeneration !== 'number' || e.presenterGeneration < ctx.knownGeneration) return 'reject';
	if (typeof e.checkpointSeq !== 'number' || !Number.isInteger(e.checkpointSeq) || e.checkpointSeq < 0) {
		return 'reject';
	}
	// Door checks first: wire bytes, then the page.changed payload (mirrors
	// the Go Classify order) — only then may a sequence be deduped.
	if (wireBytes !== undefined) {
		if (wireBytes.length > MAX_ENVELOPE_BYTES) return 'reject';
	} else if (utf8ByteLength(JSON.stringify(frame)) > MAX_ENVELOPE_BYTES) {
		return 'reject';
	}
	if (e.kind === 'page.changed') {
		// Measure the payload member in its ORIGINAL wire encoding within the
		// received frame, not a re-serialization of the parsed payload:
		// `\uXXXX` escapes collapse on parse+stringify and would launder an
		// over-target payload under the 1 KiB target (the Go mirror rejects
		// on the raw json.RawMessage length). The parse+stringify measure
		// remains only where no frame bytes exist to extract the member from.
		let rawWireBytes: number | undefined;
		if (wireBytes !== undefined) {
			const raw = rawPayloadMemberText(wireTextDecoder.decode(wireBytes));
			if (raw !== null) rawWireBytes = utf8ByteLength(raw);
		}
		const error = validatePageChangedPayload(e.payload, rawWireBytes);
		if (error !== null) return 'reject';
	}
	if (e.kind === 'annotation.committed') {
		// The same door for annotation frames (the admitted-path guard at
		// the wire layer): an untyped or oversized annotation payload
		// rejects outright, never demoted to a hint or a no-op.
		let rawWireBytes: number | undefined;
		if (wireBytes !== undefined) {
			const raw = rawPayloadMemberText(wireTextDecoder.decode(wireBytes));
			if (raw !== null) rawWireBytes = utf8ByteLength(raw);
		}
		const error = validateAnnotationPayload(e.payload, rawWireBytes);
		if (error !== null) return 'reject';
	}
	if (e.kind === 'annotation.cleared' && e.payload !== undefined && e.payload !== null) {
		return 'reject';
	}
	if (e.checkpointSeq <= ctx.confirmedSeq) return 'noop';
	return 'invalidate-checkpoint';
}

/** Checkpoint-refresh admission (plan "Performance budgets"): ONE refresh
 *  in flight plus ONE pending, at most CHECKPOINT_REFRESH_PER_SECOND per
 *  client sustained with a CHECKPOINT_REFRESH_BURST allowance, and a bounded
 *  Retry-After backoff after a `checkpointRefreshThrottled` (429) rejection
 *  (Retry-After 1–30s; jittered default when the problem carries none). */
export const CHECKPOINT_REFRESH_PER_SECOND = 5;
export const CHECKPOINT_REFRESH_BURST = 2;
export const MIN_RETRY_AFTER_MS = 1_000;
export const MAX_RETRY_AFTER_MS = 30_000;
/** Default jittered backoff when a throttle carries no parsable
 *  Retry-After: 1s plus up to 20% jitter, never implying renewal. */
export const DEFAULT_REFRESH_BACKOFF_MS = 1_000;

/** The throttled-refresh error contract: the authorized checkpoint read
 *  rejects `checkpointRefreshThrottled` with an optional numeric
 *  `retryAfterMs` from the 429's Retry-After header. Returns the bounded
 *  backoff the refresher must honor, or null for non-throttled failures
 *  (which recover immediately — the pending slot still drains). A throttle
 *  without a parsable Retry-After gets the bounded default plus up to 20%
 *  jitter; a numeric Retry-After is clamped into the 1–30s window. */
export function throttledRefreshBackoffMs(err: unknown, jitter: () => number = Math.random): number | null {
	if (typeof err !== 'object' || err === null) return null;
	const e = err as { retryAfterMs?: unknown; problem?: unknown; name?: unknown };
	const retryAfter = typeof e.retryAfterMs === 'number' && Number.isFinite(e.retryAfterMs) ? e.retryAfterMs : null;
	if (retryAfter === null && e.problem !== 'checkpointRefreshThrottled' && e.name !== 'checkpointRefreshThrottled') {
		return null;
	}
	if (retryAfter !== null) return Math.min(MAX_RETRY_AFTER_MS, Math.max(MIN_RETRY_AFTER_MS, retryAfter));
	return DEFAULT_REFRESH_BACKOFF_MS + Math.floor(jitter() * DEFAULT_REFRESH_BACKOFF_MS * 0.2);
}

/** Injectable clock so the admission bounds are deterministically testable.
 *  `schedule` returns a cancel function. */
export interface CheckpointRefresherClock {
	now?: () => number;
	schedule?: (ms: number, fn: () => void) => () => void;
}

/** Coalesces checkpoint-invalidation hints into ONE in-flight refresh plus
 *  ONE pending refresh, and ADMIITS refreshes through the plan's budget:
 *  a token bucket capped at CHECKPOINT_REFRESH_BURST refilling at
 *  CHECKPOINT_REFRESH_PER_SECOND/s bounds the sustained rate, and a
 *  Retry-After backoff parks hints after throttling. A burst of hints (or
 *  an attacker spraying fresh sequences) can never queue an unbounded
 *  catch-up loop: while a refresh runs, further hints collapse into the
 *  single pending slot; while rate-limited or in backoff, the pending slot
 *  parks until the next admission.
 *
 *  The pending slot is OWNED by the newest hint, not by the timer that
 *  serves it: a parked wakeup fires into an admission attempt and never
 *  erases the slot. A hint that lands behind an in-flight refresh — or
 *  behind a wakeup that fires while that refresh is still running — is
 *  preserved, and the in-flight refresh's completion drains the slot into
 *  the required follow-up refresh. A refresh only ever starts to SERVE a
 *  hint, so the slot clears exactly when that refresh starts. */
export class CheckpointRefresher {
	#refresh: () => Promise<void>;
	#now: () => number;
	#schedule: (ms: number, fn: () => void) => () => void;
	#inFlight = false;
	#pending = false;
	#tokens = CHECKPOINT_REFRESH_BURST;
	#lastRefill: number;
	#backoffUntil = 0;
	#wakeup: (() => void) | null = null;

	constructor(refresh: () => Promise<void>, clock: CheckpointRefresherClock = {}) {
		this.#refresh = refresh;
		this.#now = clock.now ?? (() => Date.now());
		this.#schedule =
			clock.schedule ??
			((ms, fn) => {
				const t = setTimeout(fn, ms);
				return () => clearTimeout(t);
			});
		this.#lastRefill = this.#now();
	}

	hint(): void {
		if (this.#inFlight) {
			this.#pending = true;
			return;
		}
		this.#admit();
	}

	#admit(): void {
		const t = this.#now();
		if (t < this.#backoffUntil) {
			this.#park(this.#backoffUntil - t);
			return;
		}
		this.#refill(t);
		if (this.#tokens < 1) {
			// Sustained-rate cap: park the single pending slot until the next
			// token (epsilon avoids float-shortfall busy-parking).
			this.#park(((1 - this.#tokens) / CHECKPOINT_REFRESH_PER_SECOND) * 1000 + 1);
			return;
		}
		this.#tokens -= 1;
		// The starting refresh serves every hint parked in the slot; clear
		// it here (never in the parked timer) so refreshes only ever run
		// for hints that have actually arrived.
		this.#pending = false;
		this.#inFlight = true;
		void this.#refresh()
			.catch((err: unknown) => {
				const backoff = throttledRefreshBackoffMs(err);
				if (backoff !== null) this.#backoffUntil = this.#now() + backoff;
			})
			.finally(() => {
				this.#inFlight = false;
				// The slot is still owned by the hint that arrived mid-refresh:
				// admit it WITHOUT clearing — the follow-up refresh's own start
				// (this.#admit's clear above) is the only place the slot clears.
				if (this.#pending) this.#admit();
			});
	}

	#refill(t: number): void {
		const elapsed = t - this.#lastRefill;
		if (elapsed <= 0) return;
		this.#tokens = Math.min(CHECKPOINT_REFRESH_BURST, this.#tokens + (elapsed / 1000) * CHECKPOINT_REFRESH_PER_SECOND);
		this.#lastRefill = t;
	}

	#park(ms: number): void {
		this.#pending = true;
		if (this.#wakeup !== null) return; // one parked wakeup at a time
		this.#wakeup = this.#schedule(Math.max(1, ms), () => {
			this.#wakeup = null;
			// The wakeup never erases the pending slot: a hint parked behind
			// an in-flight refresh (this timer may fire while it runs) must
			// survive so the follow-up refresh still happens. Admit only
			// when a hint is actually waiting — never a hintless refresh.
			if (!this.#inFlight && this.#pending) this.#admit();
		});
	}

	get inFlight(): boolean {
		return this.#inFlight;
	}

	get pending(): boolean {
		return this.#pending;
	}
}
