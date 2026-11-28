// presentationCheckpoint.test.ts — MEET plan M2 contract tests for the
// checkpoint/envelope SEAM between the authorized HTTP surface and the M0
// frozen presentation contract. Pure data-in/data-out.
import { describe, it, expect } from 'vitest';
import {
	MAX_RETRY_AFTER_MS,
	MIN_RETRY_AFTER_MS,
	classifyPresentationFrame,
} from './presentation';
import {
	backoffFromCheckpointProblem,
	frameFromCommittedFact,
	presentationFrameContextFromCheckpoint,
	type PresentationCheckpoint,
	type PresentationMutationResponse,
} from './presentationCheckpoint';

const liveCheckpoint: PresentationCheckpoint = {
	presentationId: 41,
	status: 'ACTIVE',
	checkpointSeq: 7,
	presenterGeneration: 3,
	presenterParticipantId: 9,
	pageIndex: 2,
	manifestGeneration: 1,
	manifestDigest: 'a'.repeat(64),
	driveNodeId: 12,
	driveVersionId: 34,
	myParticipantId: 9,
	amPresenter: true,
};

describe('presentationFrameContextFromCheckpoint', () => {
	it('maps an authorized live read onto the frame context', () => {
		expect(presentationFrameContextFromCheckpoint(liveCheckpoint)).toEqual({
			presentationId: '41',
			confirmedSeq: 7,
			knownGeneration: 3,
		});
	});

	it('collapses a terminal read to the fail-closed sessionless context', () => {
		for (const status of ['FAILED', 'CANCELLED', 'ENDED', 'REVOKED']) {
			const ctx = presentationFrameContextFromCheckpoint({ ...liveCheckpoint, status });
			expect(ctx).toEqual({ presentationId: null, confirmedSeq: 0, knownGeneration: 0 });
		}
	});
});

describe('frameFromCommittedFact', () => {
	const fact: PresentationMutationResponse = {
		presentationId: 41,
		status: 'ACTIVE',
		checkpointSeq: 8,
		presenterGeneration: 3,
		pageIndex: 5,
		manifestGeneration: 2,
	};

	it('encodes a page.changed frame the M0 classifier admits as fresh', () => {
		const result = frameFromCommittedFact(fact, 'page.changed', '2026-09-18T00:00:00Z');
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		const verdict = classifyPresentationFrame(
			JSON.parse(new TextDecoder().decode(result.bytes)),
			{
				presentationId: '41',
				confirmedSeq: 7,
				knownGeneration: 3,
			},
			result.bytes,
		);
		expect(verdict).toBe('invalidate-checkpoint');
	});

	it('encodes a source.switched frame without a page payload', () => {
		const result = frameFromCommittedFact(fact, 'source.switched', '2026-09-18T00:00:00Z');
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		const parsed = JSON.parse(new TextDecoder().decode(result.bytes));
		expect(parsed.kind).toBe('source.switched');
		expect(parsed.payload).toBeUndefined();
		expect(parsed.manifestGeneration ?? undefined).toBeUndefined();
	});

	it('refuses a stale sequence as a noop — never a state promotion', () => {
		const result = frameFromCommittedFact(fact, 'page.changed', '2026-09-18T00:00:00Z');
		expect(result.ok).toBe(true);
		if (!result.ok) return;
		const verdict = classifyPresentationFrame(
			JSON.parse(new TextDecoder().decode(result.bytes)),
			{
				presentationId: '41',
				confirmedSeq: 8,
				knownGeneration: 3,
			},
			result.bytes,
		);
		expect(verdict).toBe('noop');
	});
});

describe('backoffFromCheckpointProblem', () => {
	it('returns null for a non-throttled failure', () => {
		expect(backoffFromCheckpointProblem({ status: 404, code: 'BZ272' }, null)).toBeNull();
	});

	it('clamps the server Retry-After header into the 1-30s window', () => {
		expect(backoffFromCheckpointProblem({ status: 429 }, '0', () => 0)).toBe(MIN_RETRY_AFTER_MS);
		expect(backoffFromCheckpointProblem({ status: 429 }, '120', () => 0)).toBe(MAX_RETRY_AFTER_MS);
		expect(backoffFromCheckpointProblem({ status: 429, code: 'checkpointRefreshThrottled' }, '5', () => 0)).toBe(5000);
	});

	it('falls back to the bounded jittered default when no window is parsable', () => {
		const backoff = backoffFromCheckpointProblem(
			{ status: 429, code: 'checkpointRefreshThrottled' },
			null,
			() => 0,
		);
		expect(backoff).toBe(1000);
	});
});
