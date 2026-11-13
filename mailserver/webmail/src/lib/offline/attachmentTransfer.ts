/**
 * Pure E3 attachment-transfer contract.
 *
 * This module only validates coordinator inputs and returns the next explicit
 * action. It never performs I/O, writes a sink, retains a URL, or carries a
 * bearer token. The coordinator owns those effects after checking `writeBody`
 * and the returned checkpoint.
 */

export const ATTACHMENT_TRANSFER_CHECKPOINT_VERSION = 1 as const;

/** The generic encrypted native blob sink's current documented ceiling. */
export const MAX_ATTACHMENT_SIZE_BYTES = 8_589_934_592 as const;

const SHA256_RE = /^[0-9a-f]{64}$/;
const STRONG_SHA256_ETAG_RE = /^"([0-9a-f]{64})"$/;
const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

export const ATTACHMENT_TRANSFER_STATES = [
	'queued',
	'transferring',
	'retry',
	'verifying',
	'complete',
	'failed',
	'expired',
] as const;
export type AttachmentTransferState = (typeof ATTACHMENT_TRANSFER_STATES)[number];

export interface AttachmentTransferCheckpoint {
	version: typeof ATTACHMENT_TRANSFER_CHECKPOINT_VERSION;
	accountId: string;
	jobId: string;
	blobId: string;
	etag: string;
	expectedSize: number;
	expectedSha256: string;
	committedBytes: number;
	deadlineUtc: string;
	attempts: number;
	state: AttachmentTransferState;
}

/** Input for a new transfer. The ETag defaults to the immutable SHA-256 ETag. */
export interface AttachmentTransferStart {
	accountId: string;
	jobId: string;
	blobId: string;
	expectedSize: number;
	expectedSha256: string;
	deadlineUtc: string;
	etag?: string;
}

export const CHECKPOINT_INVALID_REASONS = [
	'invalid-shape',
	'invalid-version',
	'invalid-identity',
	'invalid-size',
	'invalid-hash',
	'invalid-etag',
	'invalid-committed-bytes',
	'invalid-deadline',
	'invalid-attempts',
	'invalid-state',
	'invalid-state-progress',
] as const;
export type CheckpointInvalidReason = (typeof CHECKPOINT_INVALID_REASONS)[number];

export const SAFE_RESTART_REASONS = [
	'invalid-checkpoint',
	'invalid-response',
	'full-response-to-range',
	'missing-etag',
	'weak-etag',
	'invalid-etag',
	'changed-etag',
	'invalid-expected-validator',
	'changed-expected-validator',
	'compressed-partial',
	'missing-content-range',
	'multiple-content-range',
	'malformed-content-range',
	'expected-total-mismatch',
	'request-start-mismatch',
	'content-range-overlap',
	'content-range-gap',
	'content-range-reversed',
	'content-range-out-of-bounds',
	'body-length-mismatch',
	'invalid-body-length',
	'range-not-satisfiable',
	'zero-size-range-request',
	'size-mismatch',
	'hash-mismatch',
	'invalid-failure',
	// E4 Astra correction: V1 native transfers reject redirects instead of
	// forwarding credentials to any redirected destination (including
	// same-origin redirects). Route relocation needs a new approved
	// token/contract, never redirect-following.
	'redirect-rejected',
] as const;
export type SafeRestartReason = (typeof SAFE_RESTART_REASONS)[number];

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function hasExactKeys(
	value: Record<string, unknown>,
	required: readonly string[],
	optional: readonly string[] = [],
): boolean {
	const allowed = new Set([...required, ...optional]);
	const keys = Object.keys(value);
	return required.every((key) => Object.prototype.hasOwnProperty.call(value, key)) &&
		keys.every((key) => allowed.has(key));
}

function isSafeNonNegativeInteger(value: unknown): value is number {
	return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

function isOpaqueId(value: unknown): value is string {
	return typeof value === 'string' && value.length > 0 && value.trim() === value && !value.includes('://');
}

function parseUtc(value: unknown): number | null {
	if (typeof value !== 'string' || value.length === 0 || !/[zZ]$/.test(value)) return null;
	const parsed = Date.parse(value);
	return Number.isFinite(parsed) && parsed >= 0 ? parsed : null;
}

function isSha256(value: unknown): value is string {
	return typeof value === 'string' && SHA256_RE.test(value);
}

function strongSha256EtagHash(value: unknown): string | null {
	if (typeof value !== 'string') return null;
	const match = STRONG_SHA256_ETAG_RE.exec(value);
	return match?.[1] ?? null;
}

function cloneCheckpoint(checkpoint: AttachmentTransferCheckpoint): AttachmentTransferCheckpoint {
	return { ...checkpoint };
}

function invalidCheckpointAction(reason: CheckpointInvalidReason): InvalidCheckpointAction {
	return {
		kind: 'invalid-checkpoint',
		action: 'safe-restart',
		reason,
		checkpoint: null,
		purgePartial: true,
		promote: false,
		writeBody: false,
	};
}

function safeRestart(
	reason: SafeRestartReason,
	checkpoint: AttachmentTransferCheckpoint,
): SafeRestartAction {
	return {
		kind: 'safe-restart',
		action: 'safe-restart',
		reason,
		checkpoint: null,
		deadlineUtc: checkpoint.deadlineUtc,
		attempts: checkpoint.attempts,
		purgePartial: true,
		promote: false,
		writeBody: false,
	};
}

export type CheckpointValidation =
	| { kind: 'valid'; checkpoint: AttachmentTransferCheckpoint }
	| InvalidCheckpointAction;

/** Parse a persisted checkpoint without allowing fields to be silently added. */
export function validateAttachmentTransferCheckpoint(value: unknown): CheckpointValidation {
	if (!isRecord(value) || !hasExactKeys(value, [
		'accountId',
		'attempts',
		'blobId',
		'committedBytes',
		'deadlineUtc',
		'etag',
		'expectedSha256',
		'expectedSize',
		'jobId',
		'state',
		'version',
	])) return invalidCheckpointAction('invalid-shape');

	if (value.version !== ATTACHMENT_TRANSFER_CHECKPOINT_VERSION) {
		return invalidCheckpointAction('invalid-version');
	}
	if (!isOpaqueId(value.accountId) || !isOpaqueId(value.jobId) || !isOpaqueId(value.blobId)) {
		return invalidCheckpointAction('invalid-identity');
	}
	if (!isSafeNonNegativeInteger(value.expectedSize) || value.expectedSize > MAX_ATTACHMENT_SIZE_BYTES) {
		return invalidCheckpointAction('invalid-size');
	}
	if (!isSha256(value.expectedSha256)) return invalidCheckpointAction('invalid-hash');
	if (typeof value.etag !== 'string' || strongSha256EtagHash(value.etag) !== value.expectedSha256) {
		return invalidCheckpointAction('invalid-etag');
	}
	if (!isSafeNonNegativeInteger(value.committedBytes) || value.committedBytes > value.expectedSize) {
		return invalidCheckpointAction('invalid-committed-bytes');
	}
	if (typeof value.deadlineUtc !== 'string' || parseUtc(value.deadlineUtc) === null) {
		return invalidCheckpointAction('invalid-deadline');
	}
	if (!isSafeNonNegativeInteger(value.attempts)) return invalidCheckpointAction('invalid-attempts');
	if (
		typeof value.state !== 'string' ||
		!(ATTACHMENT_TRANSFER_STATES as readonly string[]).includes(value.state)
	) return invalidCheckpointAction('invalid-state');

	const state = value.state as AttachmentTransferState;
	if (
		(state === 'complete' || state === 'verifying') &&
		value.committedBytes !== value.expectedSize
	) return invalidCheckpointAction('invalid-state-progress');
	if (value.expectedSize === 0 && (state !== 'complete' || value.committedBytes !== 0)) {
		return invalidCheckpointAction('invalid-state-progress');
	}

	return {
		kind: 'valid',
		checkpoint: {
			version: ATTACHMENT_TRANSFER_CHECKPOINT_VERSION,
			accountId: value.accountId,
			jobId: value.jobId,
			blobId: value.blobId,
			etag: value.etag,
			expectedSize: value.expectedSize,
			expectedSha256: value.expectedSha256,
			committedBytes: value.committedBytes,
			deadlineUtc: value.deadlineUtc,
			attempts: value.attempts,
			state,
		},
	};
}

export function isAttachmentTransferCheckpoint(value: unknown): value is AttachmentTransferCheckpoint {
	return validateAttachmentTransferCheckpoint(value).kind === 'valid';
}

export function parseAttachmentTransferCheckpoint(
	value: unknown,
): AttachmentTransferCheckpoint | null {
	const result = validateAttachmentTransferCheckpoint(value);
	return result.kind === 'valid' ? result.checkpoint : null;
}

export type AttachmentCheckpointConstructionResult =
	| {
			kind: 'ready';
			checkpoint: AttachmentTransferCheckpoint;
			purgePartial: false;
			promote: false;
			writeBody: false;
		}
	| {
			kind: 'terminal-empty';
			state: 'complete';
			checkpoint: null;
			purgePartial: false;
			promote: true;
			writeBody: false;
		}
	| InvalidCheckpointAction;

/** Construct the initial checkpoint, or the explicit no-write zero-byte result. */
export function createAttachmentTransferCheckpoint(
	value: unknown,
): AttachmentCheckpointConstructionResult {
	if (!isRecord(value) || !hasExactKeys(value,
		['accountId', 'blobId', 'deadlineUtc', 'expectedSha256', 'expectedSize', 'jobId'],
		['etag'])) return invalidCheckpointAction('invalid-shape');
	if (!isOpaqueId(value.accountId) || !isOpaqueId(value.jobId) || !isOpaqueId(value.blobId)) {
		return invalidCheckpointAction('invalid-identity');
	}
	if (!isSafeNonNegativeInteger(value.expectedSize) || value.expectedSize > MAX_ATTACHMENT_SIZE_BYTES) {
		return invalidCheckpointAction('invalid-size');
	}
	if (!isSha256(value.expectedSha256)) return invalidCheckpointAction('invalid-hash');
	if (typeof value.deadlineUtc !== 'string' || parseUtc(value.deadlineUtc) === null) {
		return invalidCheckpointAction('invalid-deadline');
	}

	const etag: string = value.etag === undefined ? `"${value.expectedSha256}"` :
		(typeof value.etag === 'string' ? value.etag : '');
	if (strongSha256EtagHash(etag) !== value.expectedSha256) {
		return invalidCheckpointAction('invalid-etag');
	}

	if (value.expectedSize === 0) {
		if (value.expectedSha256 !== EMPTY_SHA256) {
			return invalidCheckpointAction('invalid-hash');
		}
		return {
			kind: 'terminal-empty',
			state: 'complete',
			checkpoint: null,
			purgePartial: false,
			promote: true,
			writeBody: false,
		};
	}

	return {
		kind: 'ready',
		checkpoint: {
			version: ATTACHMENT_TRANSFER_CHECKPOINT_VERSION,
			accountId: value.accountId,
			jobId: value.jobId,
			blobId: value.blobId,
			etag,
			expectedSize: value.expectedSize,
			expectedSha256: value.expectedSha256,
			committedBytes: 0,
			deadlineUtc: value.deadlineUtc,
			attempts: 0,
			state: 'queued',
		},
		purgePartial: false,
		promote: false,
		writeBody: false,
	};
}

export interface AttachmentRangeResponse {
	requestStart: number;
	status: number;
	etag?: string | null;
	contentRange?: string | readonly string[] | null;
	contentEncoding?: string | null;
	bodyByteCount: number;
	expectedTotal?: number;
	expectedValidator?: string | null;
	nowUtc?: string;
	authorized?: boolean;
	retryAfterMs?: number;
}

interface ParsedRangeResponse extends AttachmentRangeResponse {
	requestStart: number;
	status: number;
	bodyByteCount: number;
}

function parseRangeResponse(value: unknown): ParsedRangeResponse | null {
	if (!isRecord(value) || !hasExactKeys(value,
		['status'],
		['authorized', 'bodyByteCount', 'contentEncoding', 'contentRange', 'etag', 'expectedTotal', 'expectedValidator', 'nowUtc', 'requestStart', 'retryAfterMs'])) {
		return null;
	}
	if (typeof value.status !== 'number' || !Number.isSafeInteger(value.status) || value.status < 100 || value.status > 599) return null;
	if (value.requestStart !== undefined && !isSafeNonNegativeInteger(value.requestStart)) return null;
	if (value.bodyByteCount !== undefined && !isSafeNonNegativeInteger(value.bodyByteCount)) return null;
	if (value.authorized !== undefined && typeof value.authorized !== 'boolean') return null;
	if (value.nowUtc !== undefined && typeof value.nowUtc !== 'string') return null;
	return value as unknown as ParsedRangeResponse;
}

interface ParsedContentRange {
	start: number;
	end: number;
	total: number;
}

type ContentRangeParse =
	| { kind: 'missing' }
	| { kind: 'multiple' }
	| { kind: 'malformed' }
	| { kind: 'valid'; range: ParsedContentRange };

function parseContentRange(value: unknown): ContentRangeParse {
	let text: string;
	if (Array.isArray(value)) {
		if (value.length !== 1) return { kind: 'multiple' };
		if (typeof value[0] !== 'string') return { kind: 'malformed' };
		text = value[0];
	} else if (value === undefined || value === null) {
		return { kind: 'missing' };
	} else if (typeof value === 'string') {
		text = value;
	} else {
		return { kind: 'malformed' };
	}

	if (text.includes(',')) return { kind: 'multiple' };
	const match = /^bytes ([0-9]+)-([0-9]+)\/([0-9]+)$/.exec(text);
	if (!match) return { kind: 'malformed' };
	const start = Number(match[1]);
	const end = Number(match[2]);
	const total = Number(match[3]);
	if (![start, end, total].every((part) => Number.isSafeInteger(part) && part >= 0)) {
		return { kind: 'malformed' };
	}
	return { kind: 'valid', range: { start, end, total } };
}

function expectedValidatorMatches(
	checkpoint: AttachmentTransferCheckpoint,
	value: unknown,
): boolean {
	return value === undefined ? true : value === checkpoint.etag;
}

function boundedRetryAfter(
	value: unknown,
	nowMs: number,
	deadlineMs: number,
): number | undefined {
	if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return undefined;
	return value <= deadlineMs - nowMs ? value : undefined;
}

export type AttachmentTransferAction =
	| SafeRestartAction
	| InvalidCheckpointAction
	| AcceptedRangeAction
	| RetryAction
	| ReauthorizeAction
	| TerminalExpiredAction
	| TerminalUnavailableAction
	| TerminalFailureAction
	| PromotedAction;

export interface SafeRestartAction {
	kind: 'safe-restart';
	action: 'safe-restart';
	reason: SafeRestartReason;
	checkpoint: null;
	/** Job-envelope retry budget retained even though unsafe partial bytes purge. */
	deadlineUtc: string;
	attempts: number;
	purgePartial: true;
	promote: false;
	writeBody: false;
}

export interface InvalidCheckpointAction {
	kind: 'invalid-checkpoint';
	action: 'safe-restart';
	reason: CheckpointInvalidReason;
	checkpoint: null;
	purgePartial: true;
	promote: false;
	writeBody: false;
}

export interface AcceptedRangeAction {
	kind: 'accepted';
	action: 'append-contiguous-range';
	range: ParsedContentRange;
	checkpoint: AttachmentTransferCheckpoint;
	nextCheckpoint: AttachmentTransferCheckpoint;
	purgePartial: false;
	promote: false;
	writeBody: true;
}

export interface RetryAction {
	kind: 'retry';
	action: 'retry';
	retryable: true;
	checkpoint: AttachmentTransferCheckpoint;
	purgePartial: false;
	promote: false;
	writeBody: false;
	retryAfterMs?: number;
}

/**
 * The current bearer or effective authorization changed. Keep already verified
 * bytes, but do not retry this response or persist the bearer; the coordinator
 * must re-evaluate policy and mint a fresh short-lived token.
 */
export interface ReauthorizeAction {
	kind: 'reauthorize';
	action: 'reauthorize';
	retryable: false;
	requiresTokenMint: true;
	status: 401 | 403 | 409;
	reason: 'token-or-session-expired' | 'policy-or-device-changed';
	checkpoint: AttachmentTransferCheckpoint;
	purgePartial: false;
	promote: false;
	writeBody: false;
}

export interface TerminalExpiredAction {
	kind: 'terminal-expired';
	action: 'terminal-expired';
	retryable: false;
	checkpoint: AttachmentTransferCheckpoint;
	purgePartial: false;
	promote: false;
	writeBody: false;
}

export interface TerminalUnavailableAction {
	kind: 'terminal-unavailable';
	action: 'terminal-unavailable';
	status: 404 | 410;
	checkpoint: null;
	purgePartial: true;
	promote: false;
	writeBody: false;
}

export interface TerminalFailureAction {
	kind: 'terminal-failure';
	action: 'terminal-failure';
	retryable: false;
	status: number;
	reason: 'not-authorized' | 'http';
	checkpoint: AttachmentTransferCheckpoint;
	purgePartial: false;
	promote: false;
	writeBody: false;
}

export interface PromotedAction {
	kind: 'promoted';
	action: 'promote';
	checkpoint: AttachmentTransferCheckpoint;
	nextCheckpoint: AttachmentTransferCheckpoint;
	purgePartial: false;
	promote: true;
	writeBody: false;
}

function retryAction(
	checkpoint: AttachmentTransferCheckpoint,
	nowMs: number,
	retryAfterMs: unknown,
): RetryAction | TerminalExpiredAction {
	const deadlineMs = parseUtc(checkpoint.deadlineUtc);
	if (deadlineMs === null || nowMs >= deadlineMs) {
		const expired = {
			...cloneCheckpoint(checkpoint),
			state: 'expired' as const,
		};
		return {
			kind: 'terminal-expired',
			action: 'terminal-expired',
			retryable: false,
			checkpoint: expired,
			purgePartial: false,
			promote: false,
			writeBody: false,
		};
	}

	const nextCheckpoint = {
		...cloneCheckpoint(checkpoint),
		attempts: checkpoint.attempts < Number.MAX_SAFE_INTEGER
			? checkpoint.attempts + 1
			: checkpoint.attempts,
		state: 'retry' as const,
	};
	const retry: RetryAction = {
		kind: 'retry',
		action: 'retry',
		retryable: true,
		checkpoint: nextCheckpoint,
		purgePartial: false,
		promote: false,
		writeBody: false,
	};
	const hint = boundedRetryAfter(retryAfterMs, nowMs, deadlineMs);
	if (hint !== undefined) retry.retryAfterMs = hint;
	return retry;
}

type AttachmentFailure =
	| { kind: 'transport'; nowUtc: string; retryAfterMs?: number }
	| { kind: 'http'; status: number; nowUtc: string; authorized?: boolean; retryAfterMs?: number };

function parseAttachmentFailure(value: unknown): AttachmentFailure | null {
	if (!isRecord(value) || typeof value.kind !== 'string' || typeof value.nowUtc !== 'string') return null;
	if (value.kind === 'transport') {
		return hasExactKeys(value, ['kind', 'nowUtc'], ['retryAfterMs'])
			? value as AttachmentFailure
			: null;
	}
	if (value.kind === 'http' && hasExactKeys(value, ['kind', 'nowUtc', 'status'], ['authorized', 'retryAfterMs'])) {
		if (typeof value.status === 'number' && Number.isSafeInteger(value.status) && value.status >= 100 && value.status <= 599) {
			if (value.authorized === undefined || typeof value.authorized === 'boolean') {
				return value as AttachmentFailure;
			}
		}
	}
	return null;
}

/** Classify a transport or HTTP failure without performing a retry. */
export function classifyAttachmentFailure(
	checkpointValue: unknown,
	failureValue: unknown,
): AttachmentTransferAction {
	const checkpointResult = validateAttachmentTransferCheckpoint(checkpointValue);
	if (checkpointResult.kind !== 'valid') return checkpointResult;
	const checkpoint = checkpointResult.checkpoint;
	const failure = parseAttachmentFailure(failureValue);
	if (!failure) return safeRestart('invalid-failure', checkpoint);
	const nowMs = parseUtc(failure.nowUtc);
	if (nowMs === null) return safeRestart('invalid-failure', checkpoint);

	if (failure.kind === 'transport') {
		return retryAction(checkpointResult.checkpoint, nowMs, failure.retryAfterMs);
	}

	if ((failure.status === 404 || failure.status === 410) && failure.authorized === true) {
		return {
			kind: 'terminal-unavailable',
			action: 'terminal-unavailable',
			status: failure.status,
			checkpoint: null,
			purgePartial: true,
			promote: false,
			writeBody: false,
		};
	}

	if (failure.status === 429 || (failure.status >= 500 && failure.status <= 599)) {
		return retryAction(checkpointResult.checkpoint, nowMs, failure.retryAfterMs);
	}
	if (failure.status === 401 || failure.status === 403 || failure.status === 409) {
		return {
			kind: 'reauthorize',
			action: 'reauthorize',
			retryable: false,
			requiresTokenMint: true,
			status: failure.status,
			reason: failure.status === 401
				? 'token-or-session-expired'
				: 'policy-or-device-changed',
			checkpoint: { ...cloneCheckpoint(checkpointResult.checkpoint), state: 'retry' },
			purgePartial: false,
			promote: false,
			writeBody: false,
		};
	}

	const reason: TerminalFailureAction['reason'] = failure.status === 404 || failure.status === 410
		? 'not-authorized'
		: 'http';
	const failedCheckpoint = {
		...cloneCheckpoint(checkpointResult.checkpoint),
		state: 'failed' as const,
	};
	return {
		kind: 'terminal-failure',
		action: 'terminal-failure',
		retryable: false,
		status: failure.status,
		reason,
		checkpoint: failedCheckpoint,
		purgePartial: false,
		promote: false,
		writeBody: false,
	};
}

/**
 * Validate one response to a Range request. A 206 can advance only from the
 * persisted contiguous offset; every other ambiguous byte disposition is a
 * safe restart with the partial/checkpoint discarded.
 */
export function validateAttachmentRangeResponse(
	checkpointValue: unknown,
	responseValue: unknown,
	nowUtcOverride?: string,
): AttachmentTransferAction {
	const checkpointResult = validateAttachmentTransferCheckpoint(checkpointValue);
	if (checkpointResult.kind !== 'valid') return checkpointResult;
	const checkpoint = checkpointResult.checkpoint;
	const response = parseRangeResponse(responseValue);
	if (!response) return safeRestart('invalid-response', checkpoint);
	const nowUtc = nowUtcOverride ?? response.nowUtc;
	const nowMs = parseUtc(nowUtc);
	if (nowMs === null) return safeRestart('invalid-response', checkpoint);

	if (response.status === 404 || response.status === 410 || response.status === 429 || response.status >= 500) {
		return classifyAttachmentFailure(checkpointResult.checkpoint, {
			kind: 'http',
			status: response.status,
			nowUtc,
			authorized: response.authorized,
			retryAfterMs: response.retryAfterMs,
		});
	}
	if (response.status === 200) return safeRestart('full-response-to-range', checkpoint);
	if (response.status === 416) return safeRestart('range-not-satisfiable', checkpoint);
	if (response.status !== 206) {
		return classifyAttachmentFailure(checkpointResult.checkpoint, {
			kind: 'http',
			status: response.status,
			nowUtc,
			authorized: response.authorized,
			retryAfterMs: response.retryAfterMs,
		});
	}

	if (response.expectedTotal !== undefined &&
		(!isSafeNonNegativeInteger(response.expectedTotal) || response.expectedTotal !== checkpoint.expectedSize)) {
		return safeRestart('expected-total-mismatch', checkpoint);
	}
	if (!expectedValidatorMatches(checkpoint, response.expectedValidator)) {
		return safeRestart(response.expectedValidator === null || response.expectedValidator === undefined
			? 'invalid-expected-validator'
			: 'changed-expected-validator', checkpoint);
	}
	if (response.contentEncoding !== undefined && response.contentEncoding !== null && response.contentEncoding !== 'identity') {
		return safeRestart('compressed-partial', checkpoint);
	}

	if (typeof response.etag !== 'string' || response.etag.length === 0) return safeRestart('missing-etag', checkpoint);
	if (/^W\//i.test(response.etag)) return safeRestart('weak-etag', checkpoint);
	if (strongSha256EtagHash(response.etag) === null) return safeRestart('invalid-etag', checkpoint);
	if (response.etag !== checkpoint.etag) return safeRestart('changed-etag', checkpoint);
	if (!isSafeNonNegativeInteger(response.requestStart) || !isSafeNonNegativeInteger(response.bodyByteCount)) {
		return safeRestart('invalid-response', checkpoint);
	}

	if (response.requestStart !== checkpoint.committedBytes) return safeRestart('request-start-mismatch', checkpoint);
	const contentRange = parseContentRange(response.contentRange);
	if (contentRange.kind === 'missing') return safeRestart('missing-content-range', checkpoint);
	if (contentRange.kind === 'multiple') return safeRestart('multiple-content-range', checkpoint);
	if (contentRange.kind === 'malformed') return safeRestart('malformed-content-range', checkpoint);

	const range = contentRange.range;
	if (range.total !== checkpoint.expectedSize) return safeRestart('expected-total-mismatch', checkpoint);
	if (range.start < checkpoint.committedBytes) return safeRestart('content-range-overlap', checkpoint);
	if (range.start > checkpoint.committedBytes) return safeRestart('content-range-gap', checkpoint);
	if (range.end < range.start) return safeRestart('content-range-reversed', checkpoint);
	if (range.end >= range.total) return safeRestart('content-range-out-of-bounds', checkpoint);
	const expectedBodyLength = range.end - range.start + 1;
	if (!Number.isSafeInteger(expectedBodyLength) || expectedBodyLength < 1) {
		return safeRestart('invalid-body-length', checkpoint);
	}
	if (response.bodyByteCount !== expectedBodyLength) return safeRestart('body-length-mismatch', checkpoint);

	const nextCheckpoint = {
		...cloneCheckpoint(checkpoint),
		committedBytes: range.end + 1,
		state: (range.end + 1 === checkpoint.expectedSize ? 'verifying' : 'transferring') as AttachmentTransferState,
	};
	return {
		kind: 'accepted',
		action: 'append-contiguous-range',
		range,
		checkpoint: nextCheckpoint,
		nextCheckpoint,
		purgePartial: false,
		promote: false,
		writeBody: true,
	};
}

/**
 * E4 Astra correction: classify any redirect observation (3xx) as a safe
 * restart with the partial discarded. The bearer is never forwarded, the
 * redirect target is never followed, and no existence claim is recorded.
 * The coordinator's job envelope (deadline/attempts) is preserved exactly as
 * for every other safe restart.
 */
export function rejectAttachmentRedirect(
	checkpointValue: unknown,
): SafeRestartAction | InvalidCheckpointAction {
	const checkpointResult = validateAttachmentTransferCheckpoint(checkpointValue);
	if (checkpointResult.kind !== 'valid') return checkpointResult;
	return safeRestart('redirect-rejected', checkpointResult.checkpoint);
}

/** Promote only a complete, exactly hashed transfer. */
export function finalizeAttachmentTransfer(
	checkpointValue: unknown,
	observedSha256: unknown,
): AttachmentTransferAction {
	const checkpointResult = validateAttachmentTransferCheckpoint(checkpointValue);
	if (checkpointResult.kind !== 'valid') return checkpointResult;
	const checkpoint = checkpointResult.checkpoint;
	if (checkpoint.state === 'failed' || checkpoint.state === 'expired') {
		return safeRestart('invalid-checkpoint', checkpoint);
	}
	if (checkpoint.committedBytes !== checkpoint.expectedSize) return safeRestart('size-mismatch', checkpoint);
	if (!isSha256(observedSha256) || observedSha256 !== checkpoint.expectedSha256) {
		return safeRestart('hash-mismatch', checkpoint);
	}

	const completeCheckpoint = {
		...cloneCheckpoint(checkpoint),
		state: 'complete' as const,
	};
	return {
		kind: 'promoted',
		action: 'promote',
		checkpoint: completeCheckpoint,
		nextCheckpoint: completeCheckpoint,
		purgePartial: false,
		promote: true,
		writeBody: false,
	};
}
