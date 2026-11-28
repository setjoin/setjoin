/**
 * E4-I transfer-effect executor: the ONLY wiring between the pure E3
 * controller decisions (`attachmentTransfer.ts`) and real effects — native
 * sink writes, scoped range requests, checkpoint persistence and cleanup.
 *
 * Frozen invariants (plan §5 + E4 Astra corrections + B62):
 * - The bearer is memory-only: it exists as a local variable for the lifetime
 *   of one request and is never persisted, logged, or carried in a checkpoint.
 *   Restart/expiry remints under CURRENT authorization.
 * - The destination is constructed from the approved origin; caller URL input
 *   is validated against the canonical destination before any bearer is
 *   attached (`transferDestination.ts`). Redirects are rejected, never
 *   followed (`rejectAttachmentRedirect`).
 * - Adapters supply observations, not authority: a 404/410 purges the partial
 *   ONLY when the observation provably came from an authenticated result
 *   under current authorization (confirmed content-unavailable). Mint facts
 *   alone NEVER authorize a purge: a raw/hidden/ambiguous 404/410 preserves
 *   valid encrypted state and pauses admission. A stale-generation
 *   observation is ignored without purging.
 * - Native security work is never delayed waiting for optional admission: the
 *   executor refuses to start or continue while a Critical scope is active,
 *   composes its lifecycle through balanced begin/end handles, and SUBSCRIBES
 *   to Critical transitions so security work beginning mid-flight aborts the
 *   transfer immediately.
 * - Cancellation is armed BEFORE the token mint and ownership is held for the
 *   WHOLE cycle — postflight authorization, sink writes, digest verification
 *   and promotion — with re-checks at every await boundary, so revoked or
 *   changed authorization can never resurrect in-flight work into committed
 *   effects. The window between the awaited promote and the completion persist
 *   is closed too: a revoke observed there PURGES instead of persisting the
 *   completed checkpoint.
 * - The retained deadline bounds every terminal path: a fresh expired start,
 *   a deadline crossed during fetch, a deadline crossed during
 *   verification, and a deadline crossed during promotion all terminate as
 *   expired, never as completions.
 * - An UNPROVEN 404/410 preserves the resumable checkpoint unchanged (no
 *   failed row is persisted), so a later authorized admission remints and
 *   resumes; only an adapter-proven authenticated 404/410 purges.
 * - Account change / revocation cancels account-scoped work, drops the
 *   bearer, and purges through the existing paths with zero cross-account
 *   reuse. Account identity is validated BEFORE every terminal path —
 *   including completed-checkpoint replay and the zero-length completion.
 * - Terminal/transport classifications reuse the E3 controller: fetch
 *   exceptions are transport failures (bounded retry with the retained
 *   deadline/attempt envelope), never a bypass into auth-expiry; expired
 *   checkpoints and fully-downloaded `verifying` transfers are handled by
 *   lifecycle state without any network effect.
 */

import {
	classifyAttachmentFailure,
	createAttachmentTransferCheckpoint,
	finalizeAttachmentTransfer,
	rejectAttachmentRedirect,
	validateAttachmentRangeResponse,
	type AttachmentTransferCheckpoint,
	type AttachmentTransferStart,
} from './attachmentTransfer';
import {
	buildAttachmentTransferUrl,
	isRedirectStatus,
	validateAttachmentTransferUrl,
	type TransferDestinationRejectionReason,
} from './transferDestination';
import type { CriticalActivityCounter } from './criticalScope';

/** Observation of one native range request; adapters supply facts only. */
export interface RangeObservation {
	status: number;
	etag?: string | null;
	contentRange?: string | readonly string[] | null;
	contentEncoding?: string | null;
	bodyByteCount: number;
	/** Bytes for 206 responses; only read when the controller says writeBody. */
	bodyBytes?: Uint8Array;
	/** The policy/device generation the request's token was minted under. */
	mintGeneration: number;
	/** True only when the minted token was current at request time. */
	mintWasCurrent: boolean;
	/**
	 * True ONLY when the adapter proves this response came from an
	 * authenticated evaluation under current authorization (e.g. an
	 * authenticated upstream status confirmation). Mint timing facts supplied
	 * by the executor itself never set this; a raw 404/410 without it can
	 * never confirm content-unavailable.
	 */
	authenticatedResult?: boolean;
}

export interface TransferAuthorizationContext {
	accountId: string;
	deviceId: string;
	policyGeneration: number;
}

export interface TransferSinkPort {
	openPartial(transferId: string, expectedSize: number): Promise<void>;
	write(transferId: string, offset: number, bytes: Uint8Array): Promise<void>;
	committedDigest(transferId: string): Promise<string>;
	promote(transferId: string): Promise<void>;
	purge(transferId: string): Promise<void>;
}

export interface TransferExecutorPorts {
	/** Approved HTTPS server origin (trusted configuration, never caller input). */
	approvedOrigin: string;
	authorization(): Promise<TransferAuthorizationContext | null>;
	/** Subscribe to authorization/account changes; returns an unsubscribe. */
	onAuthorizationChange(listener: () => void): () => void;
	/** Mint a short-lived scoped transfer token under CURRENT authorization. */
	mintTransferToken(ctx: {
		accountId: string;
		blobSha256: string;
		jobId: string;
		generation: number;
	}): Promise<string>;
	fetchRange(args: {
		url: string;
		bearer: string;
		requestStart: number;
		expectedValidator: string;
		mintGeneration: number;
		signal: AbortSignal;
	}): Promise<RangeObservation>;
	sink: TransferSinkPort;
	persist: {
		upsertCheckpoint(checkpoint: {
			jobId: string;
			accountId: string;
			blobSha256: string;
			etag: string;
			expectedSize: number;
			expectedSha256: string;
			committedBytes: number;
			state: string;
			deadlineUtc: string;
			attempts: number;
		}): Promise<void>;
		loadCheckpoint(jobId: string): Promise<{
			jobId: string;
			accountId: string;
			blobSha256: string;
			etag: string;
			expectedSize: number;
			expectedSha256: string;
			committedBytes: number;
			state: string;
			deadlineUtc: string;
			attempts: number;
		} | null>;
		purgeCheckpoint(jobId: string): Promise<void>;
	};
	/** Critical counter: the executor refuses to run while security work is active. */
	critical: CriticalActivityCounter;
	nowUtc(): string;
	/** Injected randomness (unused in v1; reserved for bounded backoff). */
	random?: () => number;
}

export type TransferExecutorOutcome =
	| { kind: 'promoted'; checkpoint: AttachmentTransferCheckpoint }
	| { kind: 'safe-restart'; reason: string; purged: boolean; /** Retained job envelope (E3 safe-restart). */ deadlineUtc?: string; attempts?: number }
	| { kind: 'retry'; checkpoint: AttachmentTransferCheckpoint; retryAfterMs?: number }
	| { kind: 'reauthorize'; checkpoint: AttachmentTransferCheckpoint }
	| { kind: 'terminal-unavailable'; purged: boolean }
	| { kind: 'terminal-expired'; checkpoint: AttachmentTransferCheckpoint }
	| { kind: 'terminal-failure'; checkpoint: AttachmentTransferCheckpoint; reason: string }
	/** Hidden/ambiguous observation: valid encrypted state preserved. */
	| { kind: 'paused-admission'; reason: 'authExpired' | 'criticalActivity' }
	| { kind: 'destination-rejected'; reason: TransferDestinationRejectionReason }
	/** Observation from a superseded generation: ignored without purging. */
	| { kind: 'stale-result' }
	| { kind: 'disposed' };

export interface TransferExecutor {
	startTransfer(start: AttachmentTransferStart): Promise<TransferExecutorOutcome>;
	runTransfer(jobId: string): Promise<TransferExecutorOutcome>;
	cancelTransfer(jobId: string, reason: 'account-change' | 'revoked' | 'user'): Promise<void>;
	dispose(): void;
	readonly disposed: boolean;
}

function toPersisted(checkpoint: AttachmentTransferCheckpoint) {
	return {
		jobId: checkpoint.jobId,
		accountId: checkpoint.accountId,
		blobSha256: checkpoint.blobId,
		etag: checkpoint.etag,
		expectedSize: checkpoint.expectedSize,
		expectedSha256: checkpoint.expectedSha256,
		committedBytes: checkpoint.committedBytes,
		state: checkpoint.state,
		deadlineUtc: checkpoint.deadlineUtc,
		attempts: checkpoint.attempts,
	};
}

interface PersistedTransferRow {
	jobId: string;
	accountId: string;
	blobSha256: string;
	etag: string;
	expectedSize: number;
	expectedSha256: string;
	committedBytes: number;
	state: string;
	deadlineUtc: string;
	attempts: number;
}

function rowToCheckpoint(row: PersistedTransferRow): AttachmentTransferCheckpoint | null {
	const candidate: AttachmentTransferCheckpoint = {
		version: 1,
		accountId: row.accountId,
		jobId: row.jobId,
		blobId: row.blobSha256,
		etag: row.etag,
		expectedSize: row.expectedSize,
		expectedSha256: row.expectedSha256,
		committedBytes: row.committedBytes,
		deadlineUtc: row.deadlineUtc,
		attempts: row.attempts,
		state: row.state as AttachmentTransferCheckpoint['state'],
	};
	// Cheap structural re-check (the full frozen E3 validation runs inside the
	// controller functions on the next decision); guards against corrupt rows.
	if (
		candidate.version !== 1 ||
		candidate.accountId.length === 0 ||
		candidate.jobId.length === 0 ||
		candidate.blobId.length === 0 ||
		typeof candidate.etag !== 'string' ||
		candidate.committedBytes < 0 ||
		candidate.committedBytes > candidate.expectedSize
	) return null;
	return candidate;
}

export function createTransferExecutor(ports: TransferExecutorPorts): TransferExecutor {
	let disposed = false;
	const controllers = new Map<string, AbortController>();
	const unsubscribe = ports.onAuthorizationChange(() => {
		// Authorization changed mid-flight: abort in-flight requests, drop
		// bearers (they are locals anyway) and cancel/purge account-scoped
		// work through the existing paths. Stale results never purge.
		for (const controller of controllers.values()) controller.abort();
		controllers.clear();
	});
	// E4-I Astra correction: Critical work beginning mid-flight aborts the
	// transfer immediately — not only at the next cycle boundary.
	const unsubscribeCritical = ports.critical.subscribe((count) => {
		if (count > 0) {
			for (const controller of controllers.values()) controller.abort();
		}
	});

	async function purgePartial(jobId: string): Promise<void> {
		await ports.sink.purge(jobId);
		await ports.persist.purgeCheckpoint(jobId);
	}

	/** True when the checkpoint's retained deadline has passed: never download, verify or promote past it. */
	function deadlinePassed(checkpoint: AttachmentTransferCheckpoint): boolean {
		const deadline = Date.parse(checkpoint.deadlineUtc);
		const now = Date.parse(ports.nowUtc());
		return Number.isFinite(deadline) && Number.isFinite(now) && now >= deadline;
	}

	/** Persist the expired terminal shape and surface it (envelope retained). */
	async function expireNow(checkpoint: AttachmentTransferCheckpoint): Promise<TransferExecutorOutcome> {
		const expired = classifyAttachmentFailure(checkpoint, { kind: 'transport', nowUtc: ports.nowUtc() });
		if (expired.kind === 'terminal-expired') {
			await ports.persist.upsertCheckpoint(toPersisted(expired.checkpoint));
			return { kind: 'terminal-expired', checkpoint: expired.checkpoint };
		}
		// classify is deadline-authoritative; this shadow only guards its contract.
		return { kind: 'terminal-expired', checkpoint };
	}

	async function runCycle(start: AttachmentTransferStart | null, jobId: string): Promise<TransferExecutorOutcome> {
		if (disposed) return { kind: 'disposed' };
		if (ports.critical.isActive()) {
			// Native security work suppresses optional I/O even before any
			// renderer hint is processed; never delay security work.
			return { kind: 'paused-admission', reason: 'criticalActivity' };
		}
		const authorization = await ports.authorization();
		if (!authorization) return { kind: 'paused-admission', reason: 'authExpired' };

		// Cancellation ownership is ARMED for the ENTIRE cycle — mint, fetch,
		// postflight authorization, digest verification and every sink/persist
		// effect — and released only when the cycle settles (E4-I Astra
		// correction: the controller used to be removed right after the fetch,
		// so a revoke during openPartial/verify/promote could not abort the
		// cycle and its effects resurrected committed state after the purge).
		const controller = new AbortController();
		controllers.set(jobId, controller);
		// An abort or a 0→1 Critical transition observed at ANY checkpoint
		// between awaits yields the cycle: no further effect runs.
		const interrupted = (): boolean => controller.signal.aborted || ports.critical.isActive();
		const interruption = (): TransferExecutorOutcome => ({
			kind: 'paused-admission',
			reason: ports.critical.isActive() ? 'criticalActivity' : 'authExpired',
		});
		try {
			let checkpoint: AttachmentTransferCheckpoint;
			if (start) {
				// Account identity is validated BEFORE any terminal path — including
				// the zero-length completion below (E4-I Astra correction).
				if (start.accountId !== authorization.accountId) {
					return { kind: 'paused-admission', reason: 'authExpired' };
				}
				// A fresh start whose retained deadline has ALREADY passed expires
				// instead of completing — expiry is checked on every terminal path,
				// not only for loaded checkpoints (E4-I Astra correction).
				const construction = createAttachmentTransferCheckpoint(start);
				if (construction.kind !== 'ready') {
					if (construction.kind === 'terminal-empty') {
						const freshEmpty: AttachmentTransferCheckpoint = {
							version: 1,
							accountId: start.accountId,
							jobId: start.jobId,
							blobId: start.blobId,
							etag: `"${start.expectedSha256}"`,
							expectedSize: 0,
							expectedSha256: start.expectedSha256,
							committedBytes: 0,
							deadlineUtc: start.deadlineUtc,
							attempts: 0,
							state: 'complete',
						};
						if (deadlinePassed(freshEmpty)) {
							await ports.persist.purgeCheckpoint(jobId);
							return await expireNow({ ...freshEmpty, state: 'queued' });
						}
						// Zero-length attachments complete as an explicit terminal empty
						// value without entering the sink's non-empty write path.
						await ports.persist.purgeCheckpoint(jobId);
						return { kind: 'promoted', checkpoint: freshEmpty };
					}
					return { kind: 'safe-restart', reason: 'invalid-checkpoint', purged: false };
				}
				checkpoint = construction.checkpoint;
				if (deadlinePassed(checkpoint)) {
					return await expireNow(checkpoint);
				}
				await ports.persist.upsertCheckpoint(toPersisted(checkpoint));
			} else {
				const row = await ports.persist.loadCheckpoint(jobId);
				const loaded = row ? rowToCheckpoint(row) : null;
				if (!loaded) return { kind: 'safe-restart', reason: 'invalid-checkpoint', purged: false };
				if (loaded.accountId !== authorization.accountId) {
					// Cross-account reuse attempt: refuse WITHOUT replaying or
					// promoting anything, then purge through the existing path.
					await purgePartial(jobId);
					return { kind: 'paused-admission', reason: 'authExpired' };
				}
				// Lifecycle-aware restart (E4-I Astra correction): terminal states
				// replay without any network effect, and the account check above
				// always runs first.
				if (loaded.state === 'complete') {
					// Restart of an already promoted transfer: committed success is
					// replayed from persistence without any network effect.
					return { kind: 'promoted', checkpoint: loaded };
				}
				if (loaded.state === 'failed') {
					return { kind: 'terminal-failure', checkpoint: loaded, reason: 'already-failed' };
				}
				if (loaded.state === 'expired') {
					return { kind: 'terminal-expired', checkpoint: loaded };
				}
				// An expired checkpoint never downloads: the E3 controller expires
				// it with its envelope retained, and no range request is sent.
				const expiry = classifyAttachmentFailure(loaded, { kind: 'transport', nowUtc: ports.nowUtc() });
				if (expiry.kind === 'terminal-expired') {
					await ports.persist.upsertCheckpoint(toPersisted(expiry.checkpoint));
					return { kind: 'terminal-expired', checkpoint: expiry.checkpoint };
				}
				if (loaded.state === 'verifying') {
					// Fully downloaded under a prior cycle: verification only — never
					// another range request (which would request EOF and purge on a
					// 416). The digest await runs under the cycle controller, and
					// cancellation/expiry is re-checked before the promotion effects
					// (E4-I Astra correction: a revoke racing the digest used to
					// promote + persist a completion the revoke had already purged).
					if (interrupted()) return interruption();
					if (deadlinePassed(loaded)) return await expireNow(loaded);
					const observedSha256 = await ports.sink.committedDigest(jobId);
					if (interrupted()) return interruption();
					if (deadlinePassed(loaded)) return await expireNow(loaded);
					const finalization = finalizeAttachmentTransfer(loaded, observedSha256);
					if (finalization.kind === 'promoted') {
						await ports.sink.promote(jobId);
						// The revoke may land DURING promote (its purge runs
						// concurrently): re-verify in the same critical section as the
						// completion persist — a revoked cycle PURGES instead of
						// resurrecting the completed checkpoint behind the concurrent
						// purge (E4-I r5 Astra correction; the persist used to follow
						// promotion with no new interruption check).
						if (interrupted()) {
							await purgePartial(jobId);
							return interruption();
						}
						// The retained deadline is re-checked in the SAME post-promote
						// critical section: an expiry crossing during the awaited
						// promote expires the transfer instead of persisting the
						// completed checkpoint (E4-I r6 Astra correction).
						if (deadlinePassed(loaded)) return await expireNow(loaded);
						await ports.persist.upsertCheckpoint(toPersisted(finalization.nextCheckpoint));
						return { kind: 'promoted', checkpoint: finalization.nextCheckpoint };
					}
					await purgePartial(jobId);
					return {
						kind: 'safe-restart',
						reason: finalization.kind === 'safe-restart' ? finalization.reason : 'invalid-checkpoint',
						purged: true,
						deadlineUtc: loaded.deadlineUtc,
						attempts: loaded.attempts,
					};
				}
				checkpoint = loaded;
			}

			const destination = buildAttachmentTransferUrl({
				approvedOrigin: ports.approvedOrigin,
				blobSha256: checkpoint.blobId,
			});
			if (destination.kind === 'rejected') {
				return { kind: 'destination-rejected', reason: destination.reason };
			}

			{
				// Mint under CURRENT authorization; generation binds the observation.
				// Memory-only: the bearer lives in this frame's local only, for one
				// request — never persisted, logged, or placed in a checkpoint.
				const mintGeneration = authorization.policyGeneration;
				let bearer: string;
				try {
					bearer = await ports.mintTransferToken({
						accountId: checkpoint.accountId,
						blobSha256: checkpoint.blobId,
						jobId: checkpoint.jobId,
						generation: mintGeneration,
					});
				} catch {
					return { kind: 'paused-admission', reason: 'authExpired' };
				}
				// The world may have moved on while the mint was pending.
				if (interrupted()) return interruption();
				const preflight = await ports.authorization();
				if (!preflight || preflight.accountId !== authorization.accountId || preflight.policyGeneration !== mintGeneration) {
					return { kind: 'stale-result' };
				}

				let observation: RangeObservation;
				try {
					observation = await ports.fetchRange({
						url: destination.url,
						bearer,
						requestStart: checkpoint.committedBytes,
						expectedValidator: checkpoint.etag,
						mintGeneration,
						signal: controller.signal,
					});
				} catch {
					// Cancellation/Critical is a yield, never a retry increment.
					if (interrupted()) return interruption();
					// E4-I Astra correction: a fetch exception is a TRANSPORT failure
					// classified by the E3 controller — attempts increment and the
					// retained deadline/attempt envelope is persisted — never an
					// auth-expiry bypass that skips E3 transport retries.
					const transport = classifyAttachmentFailure(checkpoint, { kind: 'transport', nowUtc: ports.nowUtc() });
					if (transport.kind === 'retry') {
						await ports.persist.upsertCheckpoint(toPersisted(transport.checkpoint));
						const outcome: TransferExecutorOutcome = { kind: 'retry', checkpoint: transport.checkpoint };
						if (transport.retryAfterMs !== undefined) outcome.retryAfterMs = transport.retryAfterMs;
						return outcome;
					}
					if (transport.kind === 'terminal-expired') {
						await ports.persist.upsertCheckpoint(toPersisted(transport.checkpoint));
						return { kind: 'terminal-expired', checkpoint: transport.checkpoint };
					}
					return { kind: 'safe-restart', reason: 'invalid-failure', purged: false };
				}

				// Re-verify the world AFTER the fetch and BEFORE any effect: an
				// aborted, Critical, revoked or rotated observation is never allowed
				// to resurrect into write/promote/persist. Critical takes precedence
				// so security work beginning mid-flight is reported as such.
				if (interrupted()) return interruption();
				// The deadline may have crossed while the range request was in
				// flight: a crossed deadline never promotes (E4-I Astra correction).
				if (deadlinePassed(checkpoint)) return await expireNow(checkpoint);
				// Stale-generation observation: the world moved on; ignore without any
				// state change or purge. A fresh cycle remints under the new generation.
				if (observation.mintGeneration !== mintGeneration || !observation.mintWasCurrent) {
					return { kind: 'stale-result' };
				}
				const postflight = await ports.authorization();
				if (!postflight || postflight.accountId !== authorization.accountId || postflight.policyGeneration !== mintGeneration) {
					return { kind: 'stale-result' };
				}

				if (isRedirectStatus(observation.status)) {
					const action = rejectAttachmentRedirect(checkpoint);
					await purgePartial(jobId);
					return {
						kind: 'safe-restart',
						reason: action.kind === 'safe-restart' ? action.reason : 'invalid-checkpoint',
						purged: true,
						deadlineUtc: checkpoint.deadlineUtc,
						attempts: checkpoint.attempts,
					};
				}

				if (observation.status === 404 || observation.status === 410) {
					// E4-I Astra correction: mint facts are NOT authorization. Only an
					// adapter-proven authenticated result can confirm
					// content-unavailable; a raw 404/410 with a current mint preserves
					// valid partial state and pauses admission.
					const action = classifyAttachmentFailure(checkpoint, {
						kind: 'http',
						status: observation.status,
						nowUtc: ports.nowUtc(),
						authorized: observation.authenticatedResult === true,
					});
					if (action.kind === 'terminal-unavailable') {
						await purgePartial(jobId);
						return { kind: 'terminal-unavailable', purged: true };
					}
					if (action.kind === 'terminal-failure') {
						// An UNPROVEN 404/410 never persists a failed state: the valid
						// checkpoint survives untouched so a later authorized admission
						// remints and resumes (persisting `failed` used to disable
						// recovery forever — the terminal replay then answered
						// already-failed without reminting; E4-I Astra correction).
						return { kind: 'paused-admission', reason: 'authExpired' };
					}
					// Deadline raced the classification: persist the terminal shape.
					if (action.kind === 'terminal-expired') {
						await ports.persist.upsertCheckpoint(toPersisted(action.checkpoint));
						return { kind: 'terminal-expired', checkpoint: action.checkpoint };
					}
					return { kind: 'terminal-failure', checkpoint, reason: 'not-authorized' };
				}

				const action = validateAttachmentRangeResponse(checkpoint, {
					status: observation.status,
					etag: observation.etag,
					contentRange: observation.contentRange,
					contentEncoding: observation.contentEncoding,
					bodyByteCount: observation.bodyByteCount,
					requestStart: checkpoint.committedBytes,
					expectedValidator: checkpoint.etag,
					nowUtc: ports.nowUtc(),
				});

				switch (action.kind) {
					case 'accepted': {
						if (action.writeBody) {
							if (!observation.bodyBytes || observation.bodyBytes.byteLength === 0) {
								await purgePartial(jobId);
								return {
									kind: 'safe-restart', reason: 'body-length-mismatch', purged: true,
									deadlineUtc: checkpoint.deadlineUtc, attempts: checkpoint.attempts,
								};
							}
							// Cancellation is re-checked immediately before the sink
							// effects: a revoke observed during the awaited postflight can
							// never be outrun by openPartial/write (E4-I Astra correction).
							if (interrupted()) return interruption();
							await ports.sink.openPartial(jobId, checkpoint.expectedSize);
							// The revoke may land DURING openPartial (the purge runs
							// concurrently): no byte is written after it.
							if (interrupted()) return interruption();
							await ports.sink.write(jobId, action.range.start, observation.bodyBytes);
							// And no checkpoint is persisted behind a write that raced a
							// revoke — the purged state is never resurrected.
							if (interrupted()) return interruption();
						}
						await ports.persist.upsertCheckpoint(toPersisted(action.nextCheckpoint));
						if (action.nextCheckpoint.state === 'verifying') {
							// The digest await is an interruption window: re-check before
							// verifying AND before the promotion effects.
							if (interrupted()) return interruption();
							const observedSha256 = await ports.sink.committedDigest(jobId);
							if (interrupted()) return interruption();
							if (deadlinePassed(action.nextCheckpoint)) return await expireNow(action.nextCheckpoint);
							const finalization = finalizeAttachmentTransfer(action.nextCheckpoint, observedSha256);
							if (finalization.kind === 'promoted') {
								await ports.sink.promote(jobId);
								// Same critical-section re-verification as the restart
								// path: a revoke landing during the awaited promote must
								// purge, never persist the completed state over its purge
								// (E4-I r5 Astra correction) — and an expiry crossing the
								// same window expires instead of persisting the completion
								// (E4-I r6 Astra correction).
								if (interrupted()) {
									await purgePartial(jobId);
									return interruption();
								}
								if (deadlinePassed(action.nextCheckpoint)) return await expireNow(action.nextCheckpoint);
								await ports.persist.upsertCheckpoint(toPersisted(finalization.nextCheckpoint));
								return { kind: 'promoted', checkpoint: finalization.nextCheckpoint };
							}
							await purgePartial(jobId);
							return {
								kind: 'safe-restart',
								reason: finalization.kind === 'safe-restart' ? finalization.reason : 'invalid-checkpoint',
								purged: true,
								deadlineUtc: checkpoint.deadlineUtc,
								attempts: checkpoint.attempts,
							};
						}
						return { kind: 'retry', checkpoint: action.nextCheckpoint };
					}
					case 'safe-restart':
					case 'invalid-checkpoint': {
						await purgePartial(jobId);
						const outcome: TransferExecutorOutcome = { kind: 'safe-restart', reason: action.reason, purged: true };
						if (action.kind === 'safe-restart') {
							// The retained job envelope survives the purge: deadline and
							// attempts stay with the outcome for the next scheduling
							// decision (E4-I Astra correction).
							outcome.deadlineUtc = action.deadlineUtc;
							outcome.attempts = action.attempts;
						}
						return outcome;
					}
					case 'retry': {
						await ports.persist.upsertCheckpoint(toPersisted(action.checkpoint));
						const outcome: TransferExecutorOutcome = { kind: 'retry', checkpoint: action.checkpoint };
						if (action.retryAfterMs !== undefined) outcome.retryAfterMs = action.retryAfterMs;
						return outcome;
					}
					case 'reauthorize': {
						// Keep already verified bytes; never persist the bearer. The next
						// cycle remints under current authorization.
						await ports.persist.upsertCheckpoint(toPersisted(action.checkpoint));
						return { kind: 'reauthorize', checkpoint: action.checkpoint };
					}
					case 'terminal-expired': {
						await ports.persist.upsertCheckpoint(toPersisted(action.checkpoint));
						return { kind: 'terminal-expired', checkpoint: action.checkpoint };
					}
					case 'terminal-unavailable': {
						await purgePartial(jobId);
						return { kind: 'terminal-unavailable', purged: true };
					}
					case 'terminal-failure': {
						// A raw unproven 404/410 (not-authorized) preserves valid
						// encrypted state UNCHANGED and pauses optional admission instead
						// of claiming deletion: no failed checkpoint is persisted, so
						// authorization recovery can remint and resume (E4-I Astra
						// correction — persisting `failed` permanently disabled
						// recovery). Other HTTP terminal failures record as-is.
						if (action.reason === 'not-authorized') {
							return { kind: 'paused-admission', reason: 'authExpired' };
						}
						await ports.persist.upsertCheckpoint(toPersisted(action.checkpoint));
						return { kind: 'terminal-failure', checkpoint: action.checkpoint, reason: action.reason };
					}
					default:
						return { kind: 'safe-restart', reason: 'invalid-response', purged: false };
				}
			}
		} finally {
			// Cancellation ownership is released only when the whole cycle has
			// settled — every effect included.
			controllers.delete(jobId);
		}
	}

	return {
		async startTransfer(start): Promise<TransferExecutorOutcome> {
			return runCycle(start, start.jobId);
		},
		async runTransfer(jobId): Promise<TransferExecutorOutcome> {
			return runCycle(null, jobId);
		},
		async cancelTransfer(jobId, reason): Promise<void> {
			const controller = controllers.get(jobId);
			if (controller) controller.abort();
			if (reason === 'account-change' || reason === 'revoked') {
				// Account-scoped cancellation: bytes and checkpoint purge; zero
				// cross-account reuse is possible because rows are account-bound.
				await purgePartial(jobId);
			}
		},
		dispose(): void {
			if (disposed) return;
			disposed = true;
			unsubscribe();
			unsubscribeCritical();
			for (const controller of controllers.values()) controller.abort();
			controllers.clear();
		},
		get disposed(): boolean {
			return disposed;
		},
	};
}

export { validateAttachmentTransferUrl };
