//! Truthful local-package descriptor for Electron local capture (M5 slice 1).
//!
//! The typed descriptor the client will eventually REGISTER for a locally
//! captured package — the client-side mirror of the wave-4 `.sjrec` segment
//! truthfulness contract (`mailserver/internal/meet/presentation/segment.go`
//! + `sjrec.go`; the server lease/registration endpoints are the named M5
//! slice-2 follow-up and are NOT called here — there is no upload path).
//!
//! Ported invariants (enforced identically, in TypeScript):
//!   - A verified segment requires digest + byte size + ACTUAL MIME/codec/
//!     container + a positive interval + wall anchors. No completeness claim
//!     exists without them.
//!   - A capturing segment carries NO completeness claim at all.
//!   - interrupted/failed segments keep their slot, name WHY they stopped,
//!     stay out of coverage forever, and are never acknowledged into truth.
//!   - A verified segment is never demoted (its bytes are real).
//!   - Overlapping verified segments are duplicate media — fail closed.
//!   - Gaps are first-class facts: coverage lists them, nothing synthesizes
//!     silence (MR-01 source completeness).
//!
//! Truthfulness of the descriptor itself: `recordingId` is null until the
//! server assigns one, `uploadedToDrive` is `false` by construction (slice 1
//! cannot upload and the descriptor can never claim it), and the integrity
//! digest is sha256 over the canonical JSON with the digest field cleared
//! (the `sjrec` Seal() genre).

import { createHash } from 'node:crypto';

import type { CaptureIdentity, CaptureSurfaceId } from './preflight';

/** Frozen descriptor schema. Consumers reject other versions fail-closed. */
export const LOCAL_PACKAGE_SCHEMA = 'sjrec-local-v1';

/** Segment cap mirrors the server's MaxSJRecSegments. */
export const MAX_LOCAL_SEGMENTS = 10_000;

/** The typed recording-policy snapshot at start (the policy.go matrix). */
export type PolicyModeSnapshot = 'local_preferred' | 'server_only' | 'local_only' | 'disabled';

/** Segment truth states — the segment.go vocabulary. There is deliberately
 *  no "complete" state a byte stream can be promoted into without a verified
 *  content digest. */
export type LocalSegmentState = 'capturing' | 'verified' | 'interrupted' | 'failed';

export interface LocalSegmentInterval {
	/** Half-open [startMs, endMs) on the recording's media timeline (ms since
	 *  the capture started; wall anchors bind it to real time). */
	startMs: number;
	endMs: number;
}

export interface LocalPackageSegment {
	seq: number;
	state: LocalSegmentState;
	/** Observed content identity — null while capturing; mandatory once
	 *  verified; optional-but-honest for interrupted/failed partial bytes. */
	contentSha256: string | null;
	byteSize: number | null;
	/** What the bytes ARE, never what was requested. */
	mimeType: string | null;
	codec: string | null;
	container: string | null;
	interval: LocalSegmentInterval;
	wallStartUnixMs: number;
	wallEndUnixMs: number;
	/** Mandatory for interrupted/failed (the truthful partial result). */
	interruptReason: string | null;
}

export type LocalPackageState = 'recording' | 'finalized' | 'interrupted' | 'registered';

export interface LocalPackageDescriptor {
	schema: typeof LOCAL_PACKAGE_SCHEMA;
	meetingId: number;
	/** Server-assigned recording id; null until slice 2's registration exists
	 *  (honest null — never a locally invented id). */
	recordingId: number | null;
	packageState: LocalPackageState;
	/** The .sjrec captureMode vocabulary's local truth: a locally captured,
	 *  truthfully registered package. */
	captureMode: 'local_registered';
	/** The typed recording-policy snapshot at capture start. */
	policyMode: PolicyModeSnapshot;
	/** Surfaces actually captured. */
	surfaces: CaptureSurfaceId[];
	/** The version-pinned producer identity the capture ran under (a platform
	 *  or provider version change re-qualifies the profile before new
	 *  capture — an existing descriptor keeps the identity it ran with). */
	producer: CaptureIdentity;
	startedAtUnixMs: number;
	endedAtUnixMs: number | null;
	registeredAtUnixMs: number | null;
	segments: LocalPackageSegment[];
	/** Slice 1 has NO upload path; the descriptor structurally cannot claim
	 *  uploaded bytes (the plan's "never claims unuploaded bytes are
	 *  retained"). */
	uploadedToDrive: false;
	/** Truthful availability map over [0, mediaDuration): verified segments
	 *  merged; every hole is a listed gap, never synthesized media. */
	coverage: { available: LocalSegmentInterval[]; gaps: LocalSegmentInterval[] };
	/** sha256 over the canonical JSON with this field cleared (Seal genre). */
	integrityDigest: string | null;
}

// ── Validation (the ported segment.go rules) ──────────────────────────────

const SHA256_RE = /^[0-9a-f]{64}$/;

export function isValidSHA256(value: string): boolean {
	return SHA256_RE.test(value);
}

/** Validate one segment. Returns the named problem instead of throwing so
 *  builders and tests can pin each rule. */
export function validateSegment(segment: LocalPackageSegment): string | null {
	if (!Number.isInteger(segment.seq) || segment.seq < 1) {
		return `segment sequence numbers from 1 (got ${segment.seq})`;
	}
	if (segment.interval.endMs <= segment.interval.startMs) {
		return `segment ${segment.seq} interval [${segment.interval.startMs},${segment.interval.endMs}) is not a positive interval`;
	}
	if (segment.wallEndUnixMs < segment.wallStartUnixMs) {
		return `segment ${segment.seq} wall-clock anchors run backwards`;
	}
	switch (segment.state) {
		case 'capturing':
			if (segment.contentSha256 !== null || segment.byteSize !== null) {
				return `segment ${segment.seq} is capturing and carries a completeness claim`;
			}
			break;
		case 'verified':
			if (segment.contentSha256 === null || !isValidSHA256(segment.contentSha256)) {
				return `segment ${segment.seq} is verified without a valid sha256 digest`;
			}
			if (segment.byteSize === null || segment.byteSize <= 0) {
				return `segment ${segment.seq} is verified and carries no byte size`;
			}
			if (
				segment.mimeType === null || segment.mimeType === '' ||
				segment.codec === null || segment.codec === '' ||
				segment.container === null || segment.container === ''
			) {
				return `segment ${segment.seq} is verified and missing actual MIME/codec/container`;
			}
			break;
		case 'interrupted':
		case 'failed':
			if (segment.interruptReason === null || segment.interruptReason === '') {
				return `segment ${segment.seq} is ${segment.state} and must name why it stopped (truthful partial result)`;
			}
			if (segment.contentSha256 !== null && !isValidSHA256(segment.contentSha256)) {
				return `segment ${segment.seq} observed digest is not a valid sha256`;
			}
			break;
		default:
			return `unknown segment state fails closed`;
	}
	return null;
}

export function validateDescriptor(descriptor: LocalPackageDescriptor): string | null {
	if (descriptor.schema !== LOCAL_PACKAGE_SCHEMA) {
		return `descriptor schema ${descriptor.schema} is not ${LOCAL_PACKAGE_SCHEMA}`;
	}
	if (!Number.isInteger(descriptor.meetingId) || descriptor.meetingId <= 0) {
		return 'descriptor missing meeting identity';
	}
	const policies: PolicyModeSnapshot[] = ['local_preferred', 'server_only', 'local_only', 'disabled'];
	if (!policies.includes(descriptor.policyMode)) {
		return `unknown policy mode fails closed`;
	}
	if (descriptor.uploadedToDrive !== false) {
		return 'descriptor claims an upload path that does not exist';
	}
	if (!Number.isInteger(descriptor.startedAtUnixMs) || descriptor.startedAtUnixMs <= 0) {
		return 'descriptor missing start time';
	}
	if (descriptor.endedAtUnixMs !== null && descriptor.endedAtUnixMs < descriptor.startedAtUnixMs) {
		return 'descriptor ends before it starts';
	}
	if (descriptor.registeredAtUnixMs !== null && descriptor.packageState !== 'registered') {
		return 'descriptor claims registration while not in the registered state';
	}
	if (descriptor.segments.length > MAX_LOCAL_SEGMENTS) {
		return `descriptor binds ${descriptor.segments.length} segments over the ${MAX_LOCAL_SEGMENTS} cap`;
	}
	const seen = new Set<number>();
	for (const segment of descriptor.segments) {
		if (seen.has(segment.seq)) return `duplicate segment seq ${segment.seq}`;
		seen.add(segment.seq);
		const problem = validateSegment(segment);
		if (problem !== null) return problem;
	}
	for (const segment of descriptor.segments) {
		if (segment.state !== 'verified') continue;
		for (const prior of descriptor.segments) {
			if (prior.state !== 'verified' || prior.seq >= segment.seq) continue;
			if (segment.interval.startMs < prior.interval.endMs && prior.interval.startMs < segment.interval.endMs) {
				return `verified segments ${prior.seq} and ${segment.seq} overlap — duplicate media fails closed`;
			}
		}
	}
	if (descriptor.packageState === 'recording' && descriptor.endedAtUnixMs !== null) {
		return 'a recording descriptor cannot carry an end time';
	}
	if ((descriptor.packageState === 'finalized' || descriptor.packageState === 'registered') &&
		descriptor.endedAtUnixMs === null) {
		return `a ${descriptor.packageState} descriptor must carry its end time`;
	}
	if (descriptor.integrityDigest !== null && !isValidSHA256(descriptor.integrityDigest)) {
		return 'descriptor integrity digest is not a valid sha256';
	}
	return null;
}

/** Truthful coverage: verified segments merge into available runs; every
 *  other segment state leaves a listed gap. Mirrors ComputeCoverage. */
export function computeCoverage(
	segments: LocalPackageSegment[],
	mediaDurationMs: number,
): { available: LocalSegmentInterval[]; gaps: LocalSegmentInterval[] } {
	const verified = segments
		.filter((s) => s.state === 'verified')
		.sort((a, b) => a.interval.startMs - b.interval.startMs);
	const available: LocalSegmentInterval[] = [];
	for (const s of verified) {
		const inWindow: LocalSegmentInterval = {
			startMs: Math.max(0, s.interval.startMs),
			endMs: Math.min(mediaDurationMs, s.interval.endMs),
		};
		if (inWindow.endMs <= inWindow.startMs) continue;
		const last = available[available.length - 1];
		if (last && last.endMs === inWindow.startMs) {
			last.endMs = inWindow.endMs; // adjacent runs merge
			continue;
		}
		available.push({ ...inWindow });
	}
	const gaps: LocalSegmentInterval[] = [];
	let cursor = 0;
	for (const a of available) {
		if (a.startMs > cursor) gaps.push({ startMs: cursor, endMs: a.startMs });
		if (a.endMs > cursor) cursor = a.endMs;
	}
	if (cursor < mediaDurationMs) gaps.push({ startMs: cursor, endMs: mediaDurationMs });
	return { available, gaps };
}

// ── Canonical JSON + digest (the Seal genre) ──────────────────────────────

/** Deterministic JSON: object keys sorted recursively, arrays in order. */
export function canonicalJson(value: unknown): string {
	if (value === null || typeof value !== 'object') return JSON.stringify(value);
	if (Array.isArray(value)) return `[${value.map((v) => canonicalJson(v)).join(',')}]`;
	const entries = Object.entries(value as Record<string, unknown>)
		.filter(([, v]) => v !== undefined)
		.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
	return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalJson(v)}`).join(',')}}`;
}

/** sha256 over the canonical JSON with `integrityDigest` cleared, so the
 *  digest pins everything else. */
export function descriptorDigest(descriptor: LocalPackageDescriptor): string {
	const cleared: LocalPackageDescriptor = { ...descriptor, integrityDigest: null };
	return createHash('sha256').update(canonicalJson(cleared), 'utf8').digest('hex');
}

// ── Builder ───────────────────────────────────────────────────────────────

export interface LocalPackageStart {
	meetingId: number;
	policyMode: PolicyModeSnapshot;
	surfaces: CaptureSurfaceId[];
	producer: CaptureIdentity;
}

export interface ObservedSegment {
	contentSha256: string;
	byteSize: number;
	mimeType: string;
	codec: string;
	container: string;
}

/** Named builder failure (tests pin these; callers surface them verbatim). */
export class LocalPackageBuilderError extends Error {}

/** Builds one local package truthfully. Slice 1 is offline-only: nothing
 *  here performs I/O, upload, or server calls — the descriptor is the
 *  client's local truth, ready for slice 2's truthful registration. */
export class LocalPackageBuilder {
	#segments: LocalPackageSegment[] = [];
	#nextSeq = 1;
	#startedAtUnixMs: number;
	#endedAtUnixMs: number | null = null;
	#packageState: LocalPackageState = 'recording';
	#registeredAtUnixMs: number | null = null;

	constructor(
		private readonly start: LocalPackageStart,
		nowMs: number,
	) {
		this.#startedAtUnixMs = nowMs;
	}

	/** Open a capturing segment at `nowMs` (wall) / the current media clock. */
	openSegment(mediaClockMs: number, wallNowUnixMs: number): number {
		this.#assertState(['recording'], 'openSegment');
		if (this.#segments.length >= MAX_LOCAL_SEGMENTS) {
			throw new LocalPackageBuilderError(`segment cap ${MAX_LOCAL_SEGMENTS} reached`);
		}
		const seq = this.#nextSeq++;
		this.#segments.push({
			seq,
			state: 'capturing',
			contentSha256: null,
			byteSize: null,
			mimeType: null,
			codec: null,
			container: null,
			interval: { startMs: mediaClockMs, endMs: mediaClockMs },
			wallStartUnixMs: wallNowUnixMs,
			wallEndUnixMs: wallNowUnixMs,
			interruptReason: null,
		});
		return seq;
	}

	/** Close a capturing segment as VERIFIED with the actual observed bytes
	 *  identity. Any mismatch with what was requested is the caller's problem
	 *  to surface — this records what the bytes ARE. */
	confirmSegment(
		seq: number,
		observed: ObservedSegment,
		mediaClockEndMs: number,
		wallEndUnixMs: number,
	): LocalPackageSegment {
		this.#assertState(['recording'], 'confirmSegment');
		const segment = this.#segment(seq);
		if (segment.state !== 'capturing') {
			throw new LocalPackageBuilderError(`segment ${seq} is ${segment.state}; only a capturing segment confirms`);
		}
		if (mediaClockEndMs <= segment.interval.startMs) {
			throw new LocalPackageBuilderError(`segment ${seq} end is not after its start`);
		}
		segment.state = 'verified';
		segment.contentSha256 = observed.contentSha256;
		segment.byteSize = observed.byteSize;
		segment.mimeType = observed.mimeType;
		segment.codec = observed.codec;
		segment.container = observed.container;
		segment.interval = { startMs: segment.interval.startMs, endMs: mediaClockEndMs };
		segment.wallEndUnixMs = wallEndUnixMs;
		const problem = validateSegment(segment);
		if (problem !== null) {
			// Never leave a mutated lie behind: roll the promotion back.
			segment.state = 'capturing';
			segment.contentSha256 = null;
			segment.byteSize = null;
			segment.mimeType = null;
			segment.codec = null;
			segment.container = null;
			segment.interval = { startMs: segment.interval.startMs, endMs: segment.interval.startMs };
			segment.wallEndUnixMs = segment.wallStartUnixMs;
			throw new LocalPackageBuilderError(problem);
		}
		return { ...segment };
	}

	/** Truthfully stop a capturing segment as interrupted/failed (reason is
	 *  mandatory). A verified segment is never demoted. */
	markSegmentNotCompleted(
		seq: number,
		state: Extract<LocalSegmentState, 'interrupted' | 'failed'>,
		reason: string,
		mediaClockEndMs: number,
		wallEndUnixMs: number,
	): LocalPackageSegment {
		this.#assertState(['recording'], 'markSegmentNotCompleted');
		const segment = this.#segment(seq);
		if (segment.state === 'verified') {
			throw new LocalPackageBuilderError(`segment ${seq} is verified; a verified segment is never demoted (its bytes are real)`);
		}
		if (segment.state !== 'capturing') {
			throw new LocalPackageBuilderError(`segment ${seq} is already ${segment.state}`);
		}
		if (reason === '') throw new LocalPackageBuilderError('an interrupted/failed segment must name why it stopped');
		segment.state = state;
		segment.interruptReason = reason;
		segment.interval = { startMs: segment.interval.startMs, endMs: Math.max(mediaClockEndMs, segment.interval.startMs) };
		segment.wallEndUnixMs = Math.max(wallEndUnixMs, segment.wallStartUnixMs);
		return { ...segment };
	}

	/** The stop path for revocation/meeting-end/crash-adjacent stops: every
	 *  still-capturing segment truthfully becomes `interrupted` with the named
	 *  reason, then the package finalizes into the `interrupted` state. */
	stopWithInterrupt(reason: string, mediaClockMs: number, nowMs: number): LocalPackageDescriptor {
		for (const segment of this.#segments) {
			if (segment.state !== 'capturing') continue;
			this.markSegmentNotCompleted(segment.seq, 'interrupted', reason, mediaClockMs, nowMs);
		}
		return this.finalize(mediaClockMs, nowMs, 'interrupted');
	}

	/** Finalize the package: refuses while any segment is still capturing
	 *  (they must be confirmed or truthfully stopped first). Computes
	 *  coverage over the recorded media window and seals the digest. */
	finalize(
		mediaClockMs: number,
		nowMs: number,
		state: Extract<LocalPackageState, 'finalized' | 'interrupted'> = 'finalized',
	): LocalPackageDescriptor {
		this.#assertState(['recording'], 'finalize');
		const open = this.#segments.filter((s) => s.state === 'capturing');
		if (open.length > 0) {
			throw new LocalPackageBuilderError(
				`cannot finalize: ${open.length} segment(s) still capturing (seq ${open.map((s) => s.seq).join(', ')})`,
			);
		}
		this.#endedAtUnixMs = nowMs;
		this.#packageState = state;
		const descriptor = this.#descriptor(mediaClockMs);
		const problem = validateDescriptor(descriptor);
		if (problem !== null) {
			this.#endedAtUnixMs = null;
			this.#packageState = 'recording';
			throw new LocalPackageBuilderError(problem);
		}
		return descriptor;
	}

	/** Truthful registration flip (slice 2 performs the server-side call;
	 *  this records that the descriptor WAS registered). */
	markRegistered(mediaClockMs: number, nowMs: number): LocalPackageDescriptor {
		this.#assertState(['finalized'], 'markRegistered');
		this.#registeredAtUnixMs = nowMs;
		this.#packageState = 'registered';
		const descriptor = this.#descriptor(mediaClockMs);
		const problem = validateDescriptor(descriptor);
		if (problem !== null) {
			this.#registeredAtUnixMs = null;
			this.#packageState = 'finalized';
			throw new LocalPackageBuilderError(problem);
		}
		return descriptor;
	}

	/** Current honest snapshot ('recording' descriptors carry no digest —
	 *  an in-flight package has no sealed truth yet). */
	snapshot(mediaClockMs: number): LocalPackageDescriptor {
		return this.#descriptor(mediaClockMs);
	}

	#descriptor(mediaClockMs: number): LocalPackageDescriptor {
		const recording = this.#packageState === 'recording';
		const mediaDurationMs = recording
			? Math.max(0, mediaClockMs)
			: this.#segments.reduce((max, s) => Math.max(max, s.interval.endMs), 0);
		const descriptor: LocalPackageDescriptor = {
			schema: LOCAL_PACKAGE_SCHEMA,
			meetingId: this.start.meetingId,
			recordingId: null,
			packageState: this.#packageState,
			captureMode: 'local_registered',
			policyMode: this.start.policyMode,
			surfaces: [...this.start.surfaces],
			producer: { ...this.start.producer },
			startedAtUnixMs: this.#startedAtUnixMs,
			endedAtUnixMs: this.#endedAtUnixMs,
			registeredAtUnixMs: this.#registeredAtUnixMs,
			segments: this.#segments.map((s) => ({ ...s, interval: { ...s.interval } })),
			uploadedToDrive: false,
			coverage: computeCoverage(this.#segments, mediaDurationMs),
			integrityDigest: null,
		};
		// A sealed state carries the integrity digest; a recording snapshot
		// stays digest-free (nothing is sealed while bytes still grow).
		descriptor.integrityDigest = recording ? null : descriptorDigest(descriptor);
		return descriptor;
	}

	#segment(seq: number): LocalPackageSegment {
		const segment = this.#segments.find((s) => s.seq === seq);
		if (!segment) throw new LocalPackageBuilderError(`no segment with seq ${seq}`);
		return segment;
	}

	#assertState(allowed: LocalPackageState[], what: string): void {
		if (!allowed.includes(this.#packageState)) {
			throw new LocalPackageBuilderError(`${what} is not allowed in package state '${this.#packageState}'`);
		}
	}
}
