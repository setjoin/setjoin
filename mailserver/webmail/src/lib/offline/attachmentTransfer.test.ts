import { describe, expect, it } from 'vitest';

import {
	MAX_ATTACHMENT_SIZE_BYTES,
	classifyAttachmentFailure,
	createAttachmentTransferCheckpoint,
	finalizeAttachmentTransfer,
	validateAttachmentRangeResponse,
	validateAttachmentTransferCheckpoint,
	type AttachmentRangeResponse,
	type AttachmentTransferCheckpoint,
} from './attachmentTransfer';

const HASH = 'a'.repeat(64);
const OTHER_HASH = 'b'.repeat(64);
const EMPTY_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
const ETAG = `"${HASH}"`;
const NOW = '2026-08-11T00:00:00.000Z';
const BEFORE_DEADLINE = '2026-08-11T00:00:01.000Z';
const DEADLINE = '2026-08-11T00:00:10.000Z';
const AFTER_DEADLINE = '2026-08-11T00:00:10.000Z';

function makeCheckpoint(
	size = 100,
	overrides: Partial<AttachmentTransferCheckpoint> = {},
): AttachmentTransferCheckpoint {
	const result = createAttachmentTransferCheckpoint({
		accountId: 'account-1',
		jobId: 'job-1',
		blobId: 'blob-1',
		expectedSize: size,
		expectedSha256: HASH,
		deadlineUtc: DEADLINE,
	});
	expect(result.kind).toBe('ready');
	if (result.kind !== 'ready') throw new Error('test checkpoint construction failed');
	return { ...result.checkpoint, ...overrides };
}

function rangeResponse(
	checkpoint: AttachmentTransferCheckpoint,
	start: number,
	end: number,
	overrides: Partial<AttachmentRangeResponse> = {},
): AttachmentRangeResponse {
	return {
		requestStart: start,
		status: 206,
		etag: checkpoint.etag,
		contentRange: `bytes ${start}-${end}/${checkpoint.expectedSize}`,
		contentEncoding: undefined,
		bodyByteCount: end - start + 1,
		expectedTotal: checkpoint.expectedSize,
		expectedValidator: checkpoint.etag,
		nowUtc: NOW,
		...overrides,
	};
}

describe('E3 attachment transfer checkpoint', () => {
	it('constructs an account/job/blob-bound checkpoint with a strong hash ETag', () => {
		const result = createAttachmentTransferCheckpoint({
			accountId: 'account-1',
			jobId: 'job-1',
			blobId: 'blob-1',
			expectedSize: 100,
			expectedSha256: HASH,
			deadlineUtc: DEADLINE,
		});

		expect(result).toMatchObject({ kind: 'ready', purgePartial: false, promote: false, writeBody: false });
		if (result.kind !== 'ready') return;
		expect(result.checkpoint).toMatchObject({
			accountId: 'account-1',
			jobId: 'job-1',
			blobId: 'blob-1',
			etag: ETAG,
			expectedSize: 100,
			expectedSha256: HASH,
			committedBytes: 0,
			attempts: 0,
			state: 'queued',
		});
	});

	it('rejects a zero-byte terminal value whose claimed SHA-256 is not the empty digest', () => {
		const result = createAttachmentTransferCheckpoint({
			accountId: 'account-1', jobId: 'job-1', blobId: 'blob-1',
			expectedSize: 0, expectedSha256: HASH, deadlineUtc: DEADLINE,
		});
		expect(result).toMatchObject({ kind: 'invalid-checkpoint', reason: 'invalid-hash', promote: false });
	});

	it('returns an explicit terminal-empty result without a sink write for zero bytes', () => {
		const result = createAttachmentTransferCheckpoint({
			accountId: 'account-1',
			jobId: 'job-1',
			blobId: 'blob-1',
			expectedSize: 0,
			expectedSha256: EMPTY_HASH,
			deadlineUtc: DEADLINE,
		});

		expect(result).toEqual({
			kind: 'terminal-empty',
			state: 'complete',
			checkpoint: null,
			purgePartial: false,
			promote: true,
			writeBody: false,
		});
	});

	it.each([-1, Number.MAX_SAFE_INTEGER + 1, 1.5, Number.NaN, Number.POSITIVE_INFINITY])(
		'rejects invalid expected size %s',
		(expectedSize) => {
			const result = createAttachmentTransferCheckpoint({
				accountId: 'account-1', jobId: 'job-1', blobId: 'blob-1', expectedSize,
				expectedSha256: HASH, deadlineUtc: DEADLINE,
			});
			expect(result.kind).toBe('invalid-checkpoint');
		},
	);

	it('accepts exactly the 8 GiB ceiling and rejects one byte above it', () => {
		const atCeiling = createAttachmentTransferCheckpoint({
			accountId: 'account-1', jobId: 'job-1', blobId: 'blob-1',
			expectedSize: MAX_ATTACHMENT_SIZE_BYTES, expectedSha256: HASH, deadlineUtc: DEADLINE,
		});
		const aboveCeiling = createAttachmentTransferCheckpoint({
			accountId: 'account-1', jobId: 'job-1', blobId: 'blob-1',
			expectedSize: MAX_ATTACHMENT_SIZE_BYTES + 1, expectedSha256: HASH, deadlineUtc: DEADLINE,
		});

		expect(atCeiling.kind).toBe('ready');
		expect(aboveCeiling.kind).toBe('invalid-checkpoint');
	});

	it('rejects extra persisted fields, including bearer and URL-shaped fields', () => {
		const checkpoint = makeCheckpoint();
		expect(validateAttachmentTransferCheckpoint({ ...checkpoint, bearerToken: 'secret' }).kind).toBe('invalid-checkpoint');
		expect(validateAttachmentTransferCheckpoint({ ...checkpoint, url: 'https://example.test/blob' }).kind).toBe('invalid-checkpoint');
		expect(Object.keys(checkpoint).some((key) => /bearer|token|url/i.test(key))).toBe(false);
	});
});

describe('E3 attachment range validation', () => {
	it('accepts a valid continuation and only advances contiguous bytes', () => {
		const initial = makeCheckpoint();
		const first = validateAttachmentRangeResponse(initial, rangeResponse(initial, 0, 59));
		expect(first).toMatchObject({ kind: 'accepted', writeBody: true, promote: false, purgePartial: false });
		if (first.kind !== 'accepted') return;
		expect(first.nextCheckpoint.committedBytes).toBe(60);

		const finalChunk = validateAttachmentRangeResponse(first.nextCheckpoint, rangeResponse(first.nextCheckpoint, 60, 99));
		expect(finalChunk).toMatchObject({ kind: 'accepted', writeBody: true, promote: false, purgePartial: false });
		if (finalChunk.kind !== 'accepted') return;
		expect(finalChunk.nextCheckpoint.committedBytes).toBe(100);
		expect(finalChunk.nextCheckpoint.state).toBe('verifying');

		const promoted = finalizeAttachmentTransfer(finalChunk.nextCheckpoint, HASH);
		expect(promoted).toMatchObject({ kind: 'promoted', promote: true, writeBody: false, purgePartial: false });
	});

	it('rejects a 200 full response to a Range request and discards the partial', () => {
		const checkpoint = makeCheckpoint(100, { committedBytes: 40, state: 'transferring' });
		const result = validateAttachmentRangeResponse(checkpoint, rangeResponse(checkpoint, 40, 99, { status: 200 }));
		expect(result).toMatchObject({
			kind: 'safe-restart', reason: 'full-response-to-range', purgePartial: true,
			checkpoint: null, writeBody: false, deadlineUtc: DEADLINE, attempts: 0,
		});
	});

	it.each([
		[undefined, 'missing-etag'],
		[`W/${ETAG}`, 'weak-etag'],
		[`"${OTHER_HASH}"`, 'changed-etag'],
	] as const)('rejects %s ETag safely', (etag, reason) => {
		const checkpoint = makeCheckpoint();
		const result = validateAttachmentRangeResponse(checkpoint, rangeResponse(checkpoint, 0, 9, { etag }));
		expect(result).toMatchObject({ kind: 'safe-restart', reason, purgePartial: true, writeBody: false });
	});

	it('rejects compressed partial bodies even when the byte count matches', () => {
		const checkpoint = makeCheckpoint();
		const result = validateAttachmentRangeResponse(checkpoint, rangeResponse(checkpoint, 0, 9, { contentEncoding: 'gzip' }));
		expect(result).toMatchObject({ kind: 'safe-restart', reason: 'compressed-partial', purgePartial: true, writeBody: false });
	});

	it('rejects missing, malformed, multiple, and mismatched Content-Range metadata', () => {
		const checkpoint = makeCheckpoint();
		const cases: Array<[AttachmentRangeResponse, string]> = [
			[rangeResponse(checkpoint, 0, 9, { contentRange: undefined }), 'missing-content-range'],
			[rangeResponse(checkpoint, 0, 9, { contentRange: 'bytes 0-9/*' }), 'malformed-content-range'],
			[rangeResponse(checkpoint, 0, 9, { contentRange: ['bytes 0-9/100', 'bytes 10-19/100'] }), 'multiple-content-range'],
			[rangeResponse(checkpoint, 0, 9, { expectedTotal: 101 }), 'expected-total-mismatch'],
			[rangeResponse(checkpoint, 0, 9, { expectedValidator: `"${OTHER_HASH}"` }), 'changed-expected-validator'],
		];
		for (const [response, reason] of cases) {
			expect(validateAttachmentRangeResponse(checkpoint, response)).toMatchObject({ kind: 'safe-restart', reason, purgePartial: true });
		}
	});

	it('rejects overlap, gap, out-of-bounds, request-start, and body-length ambiguity', () => {
		const checkpoint = makeCheckpoint(100, { committedBytes: 40, state: 'transferring' });
		expect(validateAttachmentRangeResponse(checkpoint, rangeResponse(checkpoint, 40, 49, {
			contentRange: 'bytes 0-9/100',
		}))).toMatchObject({ kind: 'safe-restart', reason: 'content-range-overlap' });
		expect(validateAttachmentRangeResponse(checkpoint, rangeResponse(checkpoint, 40, 49, {
			contentRange: 'bytes 50-59/100',
		}))).toMatchObject({ kind: 'safe-restart', reason: 'content-range-gap' });
		expect(validateAttachmentRangeResponse(checkpoint, rangeResponse(checkpoint, 40, 100, {
			contentRange: 'bytes 40-100/100', bodyByteCount: 61,
		}))).toMatchObject({ kind: 'safe-restart', reason: 'content-range-out-of-bounds' });
		expect(validateAttachmentRangeResponse(checkpoint, rangeResponse(checkpoint, 41, 49))).toMatchObject({ kind: 'safe-restart', reason: 'request-start-mismatch' });
		expect(validateAttachmentRangeResponse(checkpoint, rangeResponse(checkpoint, 40, 49, { bodyByteCount: 9 }))).toMatchObject({ kind: 'safe-restart', reason: 'body-length-mismatch' });
	});

	it('rejects 416 without retry or appending any bytes', () => {
		const checkpoint = makeCheckpoint(100, { committedBytes: 40, state: 'transferring' });
		const result = validateAttachmentRangeResponse(checkpoint, rangeResponse(checkpoint, 40, 49, { status: 416 }));
		expect(result).toMatchObject({ kind: 'safe-restart', reason: 'range-not-satisfiable', purgePartial: true, writeBody: false });
	});
});

describe('E3 attachment failure and finalization actions', () => {
	it.each([404, 410] as const)('purges an authorized %s as terminal-unavailable', (status) => {
		const checkpoint = makeCheckpoint(100, { committedBytes: 40, state: 'transferring' });
		const result = validateAttachmentRangeResponse(checkpoint, rangeResponse(checkpoint, 40, 49, { status, authorized: true }));
		expect(result).toMatchObject({ kind: 'terminal-unavailable', status, purgePartial: true, checkpoint: null, writeBody: false, promote: false });
	});

	it('does not claim an unauthorized 404 is unavailable', () => {
		const checkpoint = makeCheckpoint();
		const result = validateAttachmentRangeResponse(checkpoint, rangeResponse(checkpoint, 0, 9, { status: 404, authorized: false }));
		expect(result).toMatchObject({ kind: 'terminal-failure', status: 404, reason: 'not-authorized', retryable: false, purgePartial: false });
	});

	it.each([
		[401, 'token-or-session-expired'],
		[403, 'policy-or-device-changed'],
		[409, 'policy-or-device-changed'],
	] as const)('preserves verified bytes and requires a fresh authorization on %s', (status, reason) => {
		const checkpoint = makeCheckpoint(100, { committedBytes: 40, state: 'transferring' });
		const result = validateAttachmentRangeResponse(checkpoint, rangeResponse(checkpoint, 40, 49, { status }));
		expect(result).toMatchObject({
			kind: 'reauthorize',
			status,
			reason,
			requiresTokenMint: true,
			retryable: false,
			purgePartial: false,
			writeBody: false,
			checkpoint: { committedBytes: 40, state: 'retry' },
		});
	});

	it('retries 429, 5xx, and transport failure only before the deadline', () => {
		const checkpoint = makeCheckpoint(100, { committedBytes: 40, attempts: 2, state: 'transferring' });
		const retry = validateAttachmentRangeResponse(checkpoint, rangeResponse(checkpoint, 40, 49, {
			status: 429, nowUtc: BEFORE_DEADLINE, retryAfterMs: 250,
		}));
		expect(retry).toMatchObject({ kind: 'retry', retryable: true, retryAfterMs: 250, purgePartial: false, writeBody: false });
		if (retry.kind === 'retry') expect(retry.checkpoint.attempts).toBe(3);

		const serverRetry = classifyAttachmentFailure(checkpoint, { kind: 'http', status: 503, nowUtc: BEFORE_DEADLINE });
		expect(serverRetry.kind).toBe('retry');
		const transportRetry = classifyAttachmentFailure(checkpoint, { kind: 'transport', nowUtc: BEFORE_DEADLINE });
		expect(transportRetry.kind).toBe('retry');

		const expiredHttp = classifyAttachmentFailure(checkpoint, { kind: 'http', status: 500, nowUtc: AFTER_DEADLINE });
		const expiredTransport = classifyAttachmentFailure(checkpoint, { kind: 'transport', nowUtc: AFTER_DEADLINE });
		expect(expiredHttp).toMatchObject({ kind: 'terminal-expired', retryable: false, writeBody: false });
		expect(expiredTransport).toMatchObject({ kind: 'terminal-expired', retryable: false, writeBody: false });
	});

	it('emits Retry-After only when finite, non-negative, and within the deadline', () => {
		const checkpoint = makeCheckpoint();
		const valid = classifyAttachmentFailure(checkpoint, { kind: 'http', status: 429, nowUtc: BEFORE_DEADLINE, retryAfterMs: 5000 });
		expect(valid).toMatchObject({ kind: 'retry', retryAfterMs: 5000 });
		const tooLong = classifyAttachmentFailure(checkpoint, { kind: 'http', status: 429, nowUtc: BEFORE_DEADLINE, retryAfterMs: 10000 });
		const negative = classifyAttachmentFailure(checkpoint, { kind: 'http', status: 429, nowUtc: BEFORE_DEADLINE, retryAfterMs: -1 });
		const infinite = classifyAttachmentFailure(checkpoint, { kind: 'http', status: 429, nowUtc: BEFORE_DEADLINE, retryAfterMs: Number.POSITIVE_INFINITY });
		for (const result of [tooLong, negative, infinite]) {
			expect(result.kind).toBe('retry');
			if (result.kind === 'retry') expect(result.retryAfterMs).toBeUndefined();
		}
	});

	it('promotes only an exact complete lowercase SHA-256 match', () => {
		const complete = makeCheckpoint(100, { committedBytes: 100, state: 'verifying' });
		const mismatch = finalizeAttachmentTransfer(complete, OTHER_HASH);
		const uppercase = finalizeAttachmentTransfer(complete, HASH.toUpperCase());
		const short = finalizeAttachmentTransfer(complete, HASH.slice(0, -1));
		const incomplete = finalizeAttachmentTransfer(makeCheckpoint(99, { committedBytes: 98, state: 'transferring' }), HASH);

		for (const result of [mismatch, uppercase, short, incomplete]) {
			expect(result).toMatchObject({ kind: 'safe-restart', purgePartial: true, checkpoint: null, promote: false, writeBody: false });
		}
		const promoted = finalizeAttachmentTransfer(complete, HASH);
		expect(promoted).toMatchObject({ kind: 'promoted', promote: true, writeBody: false, purgePartial: false });
		if (promoted.kind === 'promoted') expect(promoted.checkpoint.state).toBe('complete');
	});
});
