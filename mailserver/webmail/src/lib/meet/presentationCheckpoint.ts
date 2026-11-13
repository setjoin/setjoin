// presentationCheckpoint.ts — MEET plan M2: the client-side envelope SEAM
// between the M2 authorized HTTP surface and the M0 frozen contract in
// presentation.ts (retired-docs:superpowers/plans/2026-08-25-meet-document-
// presentation-semantic-recording.md, M2 "Push facts and versioned LiveKit
// envelopes with checkpoint refresh"). Pure data-in/data-out — no LiveKit,
// no store, no UI: the M3 presentation UX consumes these helpers.
//
// Two directions, one rule (the M0 receive contract, preserved verbatim):
// a received frame or a push fact NEVER advances local truth. Only an
// AUTHORIZED read — the checkpoint endpoint this module parses — moves
// confirmedSeq, and only a COMMITTED reducer response (the mutation
// response's fact + frame pair) mints a publishable envelope.
import {
	PRESENTATION_TOPIC,
	PRESENTATION_VERSION,
	MAX_RETRY_AFTER_MS,
	MIN_RETRY_AFTER_MS,
	encodePresentationEnvelope,
	throttledRefreshBackoffMs,
	type PresentationEnvelope,
	type PresentationFrameContext,
} from './presentation';

/** The committed status vocabulary (the M0 lifecycle states the checkpoint
 *  read projects). Terminal statuses end the client's presentation family:
 *  the context collapses to `presentationId: null` so every late frame
 *  fails closed instead of steering a dead session. */
const TERMINAL_STATUSES: readonly string[] = ['FAILED', 'CANCELLED', 'ENDED', 'REVOKED'];

/** The shape of `GET /meet/{id}/presentation/{pid}/checkpoint` — the
 *  authorized read (meeting_presentation_checkpoint) the coalesced
 *  CheckpointRefresher converges on. */
export interface PresentationCheckpoint {
	presentationId: number;
	status: string;
	checkpointSeq: number;
	presenterGeneration: number;
	presenterParticipantId: number | null;
	pageIndex: number;
	manifestGeneration: number;
	manifestDigest: string;
	driveNodeId: number;
	driveVersionId: number;
	myParticipantId: number | null;
	amPresenter: boolean;
}

/** Maps an authorized checkpoint read onto the locally validated session
 *  truth received frames are classified against. Terminal sessions (and a
 *  non-participant read) yield `presentationId: null` — every subsequent
 *  frame rejects, exactly the fail-closed posture of a sessionless room. */
export function presentationFrameContextFromCheckpoint(
	cp: PresentationCheckpoint,
): PresentationFrameContext {
	if (TERMINAL_STATUSES.includes(cp.status)) {
		return { presentationId: null, confirmedSeq: 0, knownGeneration: 0 };
	}
	return {
		presentationId: String(cp.presentationId),
		confirmedSeq: cp.checkpointSeq,
		knownGeneration: cp.presenterGeneration,
	};
}

/** The shape of a committed mutation response (`POST .../{verb}`): the
 *  reducer fact the server committed, plus the canonical versioned frame
 *  the server already encoded (omitted when the frame was dropped as a
 *  bounded diagnostic). The client RE-ENCODES from the fact — never
 *  forwards untrusted bytes — and the frozen budget still applies here. */
export interface PresentationMutationResponse {
	presentationId: number;
	status: string;
	checkpointSeq: number;
	presenterGeneration: number;
	pageIndex: number;
	manifestGeneration: number;
}

/** The durable kinds a CLIENT legitimately publishes after its own
 *  committed mutation. Presenter grant/takeover and end are server-authority
 *  events here (granted to another participant, revoked) — a client that
 *  just won those verbs may relay the committed frame; everyone else
 *  refreshes. `annotation.*` is deliberately unreachable: the reserved
 *  kinds are not committable and encodePresentationEnvelope refuses them. */
export type PublishableClientKind = 'page.changed' | 'source.switched';

/** Builds the versioned envelope a presenter publishes after a committed
 *  page change or source switch. Returns the encode verdict verbatim: a
 *  failed encode is a bounded diagnostic — the mutation is already
 *  committed and checkpoint recovery converges — never a retry. */
export function frameFromCommittedFact(
	fact: PresentationMutationResponse,
	kind: PublishableClientKind,
	sentAt: string,
): ReturnType<typeof encodePresentationEnvelope> {
	const envelope: PresentationEnvelope = {
		t: PRESENTATION_TOPIC,
		v: PRESENTATION_VERSION,
		presentationId: String(fact.presentationId),
		checkpointSeq: fact.checkpointSeq,
		presenterGeneration: fact.presenterGeneration,
		kind,
		payload: kind === 'page.changed' ? { pageIndex: fact.pageIndex } : undefined,
		sentAt,
	};
	return encodePresentationEnvelope(envelope);
}

/** A throttled checkpoint read's problem body: 429 + code
 *  `checkpointRefreshThrottled` + a clamped numeric `retryAfterMs` the
 *  server derives from its Retry-After header. */
export interface CheckpointThrottleProblem {
	status?: number;
	code?: string;
	retryAfterMs?: number;
}

/** Parses a checkpoint-read failure into the bounded backoff
 *  throttledRefreshBackoffMs honors (null for non-throttled failures —
 *  those recover immediately; the pending slot still drains). The raw
 *  Retry-After header is the wire source: seconds, clamped 1–30s, never
 *  implying renewal. */
export function backoffFromCheckpointProblem(
	problem: CheckpointThrottleProblem,
	retryAfterHeader: string | null,
	jitter: () => number = Math.random,
): number | null {
	if (problem.code !== 'checkpointRefreshThrottled' && problem.status !== 429) {
		return null;
	}
	let retryAfterMs: number | undefined = problem.retryAfterMs;
	if (retryAfterMs === undefined) {
		const seconds = Number(retryAfterHeader);
		retryAfterMs = Number.isFinite(seconds) && seconds > 0 ? seconds * 1000 : undefined;
	}
	if (retryAfterMs === undefined) {
		// The throttle contract with no parsable window: the bounded default
		// plus up to 20% jitter (throttledRefreshBackoffMs's own default).
		return throttledRefreshBackoffMs(
			{ problem: 'checkpointRefreshThrottled', name: 'checkpointRefreshThrottled' },
			jitter,
		);
	}
	return Math.min(MAX_RETRY_AFTER_MS, Math.max(MIN_RETRY_AFTER_MS, retryAfterMs));
}
