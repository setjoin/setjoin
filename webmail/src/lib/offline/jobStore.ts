/**
 * E4-I versioned encrypted-store job/transfer persistence.
 *
 * Implements plan §4's local-only `optional_jobs` and `attachment_transfers`
 * tables (created by migration `mail-v2-optional-work` in `migrations.ts`) with
 * CAS lease/reclaim, committed checkpoints and duplicate-effect rejection.
 * Rows carry opaque account/blob/job identity, class, state, trigger
 * generation, unique coalescing key, lease owner/expiry, attempts, deadlines,
 * the versioned content-minimal checkpoint and the committed result — never a
 * bearer token, subject, sender, filename, body or network-location history.
 *
 * The durable implementation REQUIRES the E4-I native atomic batch entry
 * (`transactionBatch`) and refuses to persist without it. Production mail page
 * and checkpoint atomicity is composed by `mailPagePersistence.ts` in that same
 * native transaction; the legacy callback composition below is a compensation
 * model, not a native crash guarantee. An in-memory implementation exists for plain shells and tests;
 * both share one pure core so admission semantics cannot drift.
 */

import {
	JOB_RESULT_STATES,
	SYNC_CHECKPOINT_VERSION,
	isJobResultState,
	isPauseReason,
	validateSyncCheckpoint,
	type JobResult,
	type OptionalJobState,
	type OptionalWorkClass,
	type PauseReason,
	type SyncCheckpoint,
} from './work-contract';
import {
	ATTACHMENT_TRANSFER_CHECKPOINT_VERSION,
	parseAttachmentTransferCheckpoint,
} from './attachmentTransfer';
import type { NativeBatchStatement, OfflineDbBridge } from '$lib/native/types';
import { admitBatch, DEFAULT_BATCH_BUDGET } from './nativeBatch';

/** CAS lease time-to-live. Reclaim happens only after expiry. */
export const LEASE_TTL_MS = 60_000;
/** Terminal jobs are garbage-collected after this retention. */
export const TERMINAL_RETENTION_MS = 24 * 60 * 60 * 1000;

export type JobStepKind = 'delta' | 'window';

export interface OptionalJobRecord {
	jobId: string;
	accountId: string;
	workClass: OptionalWorkClass;
	state: OptionalJobState;
	triggerGeneration: number;
	/** Unique per semantic work item; duplicate triggers coalesce onto it. */
	coalescingKey: string;
	attempts: number;
	deadlineUtc: string;
	queuedAtUtcMs: number;
	retryAtUtcMs: number | null;
	stepKind: JobStepKind;
	checkpoint: SyncCheckpoint | null;
	leaseOwner: string | null;
	leaseExpiresAtMs: number | null;
}

export interface StoredJobResult {
	resultState: (typeof JOB_RESULT_STATES)[number];
	result: JobResult;
	triggerGeneration: number;
}

export interface EnqueueOutcome {
	kind: 'enqueued' | 'coalesced' | 'rejected-stale-generation';
	job: OptionalJobRecord;
}

export interface CheckpointCommitOutcome {
	kind: 'committed' | 'stale-generation' | 'unknown-job';
}

/**
 * Lease fencing (E4-I Astra correction): a writer that claimed a lease must
 * prove it still holds THAT lease when it commits. Trigger generation alone
 * does not fence — after A's lease expires and B claims the same job at the
 * same generation, A must not be able to commit a checkpoint or result.
 * The fence is the (owner, expiry) pair stamped by the winning claim, which
 * stays unchanged until that lease is released or reclaimed.
 */
export interface LeaseFence {
	owner: string;
	leaseExpiresAtMs: number;
}

/**
 * Compatibility composition for the memory/legacy staged-page model. The native
 * production path uses `mailPagePersistence.ts`; these callbacks do not establish
 * native crash atomicity. `applyPage` must be
 * an all-or-nothing flush — a failure inside it exposes neither the page nor
 * the checkpoint — and `rollbackPage` must undo an ALREADY-APPLIED page when
 * the checkpoint half of the composition fails or turns out stale, so a
 * checkpoint failure can never leave the page visible under the old cursor.
 */
export interface ComposedPageCommit {
	applyPage(): Promise<void>;
	/** Undo an applied page after the checkpoint half failed (idempotent). */
	rollbackPage(): Promise<void>;
}

export interface CommitGuard {
	/** Lease fencing for a writer acting under a claim. */
	fence?: LeaseFence;
	/** Staged page applied atomically with the checkpoint. */
	compose?: ComposedPageCommit;
}

/** Job states a released/reclaimed lease can never leave the queue with. */
const TERMINAL_JOB_STATES: ReadonlySet<string> = new Set(['complete', 'failed', 'expired', 'cancelled']);

function stateIsTerminal(state: string): boolean {
	return TERMINAL_JOB_STATES.has(state);
}

function fenceHolds(job: OptionalJobRecord, fence: LeaseFence | undefined): boolean {
	if (!fence) return true;
	return job.leaseOwner === fence.owner
		&& job.leaseExpiresAtMs !== null
		&& job.leaseExpiresAtMs === fence.leaseExpiresAtMs;
}

export interface JobPersistence {
	enqueueJob(record: OptionalJobRecord): Promise<EnqueueOutcome>;
	listDue(nowUtcMs: number): Promise<OptionalJobRecord[]>;
	/**
	 * CAS claim: succeeds only for a due job with no live lease. The winner
	 * receives the stamped (owner, expiry) lease fence — the ONLY commit
	 * credential this claimant holds (E4-I Astra correction: every later
	 * checkpoint/result commit must present it verbatim, and a claimant that
	 * cannot present its fence never commits at all — an absent fence never
	 * means "unfenced").
	 */
	claimLease(jobId: string, owner: string, nowUtcMs: number): Promise<LeaseFence | null>;
	releaseLease(jobId: string, owner: string, options?: { backoff?: boolean; retryAtUtcMs?: number | null; attempts?: number }): Promise<void>;
	/** Reclaim every lease whose TTL expired; returns the reclaimed job ids. */
	reclaimExpiredLeases(nowUtcMs: number): Promise<string[]>;
	/**
	 * CAS-committed checkpoint: accepted only while the persisted trigger
	 * generation equals `expectedGeneration` and, when a lease fence is
	 * supplied, only while THAT lease is still the live one. The optional
	 * staged page is applied atomically with the checkpoint — never before
	 * the fence passes. A stale writer is a no-op.
	 */
	commitCheckpoint(
		jobId: string,
		expectedGeneration: number,
		checkpoint: SyncCheckpoint | null,
		guard?: CommitGuard,
	): Promise<CheckpointCommitOutcome>;
	/** Terminal result, generation- and lease-guarded (duplicate-effect rejection). */
	recordResult(
		jobId: string,
		expectedGeneration: number,
		result: JobResult,
		fence?: LeaseFence,
	): Promise<CheckpointCommitOutcome>;
	readJobResult(jobId: string): Promise<StoredJobResult | null>;
	readJob(jobId: string): Promise<OptionalJobRecord | null>;
	listByAccount(accountId: string): Promise<OptionalJobRecord[]>;
	/** Account-scoped cancellation (sign-out/wipe): terminal for every job. */
	cancelAccountJobs(accountId: string, nowUtcMs: number): Promise<string[]>;
	/** Bounded GC of terminal jobs past retention. */
	purgeTerminalBefore(nowUtcMs: number): Promise<number>;
}

export interface AttachmentTransferPersistence {
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
	listByAccount(accountId: string): Promise<Array<{ jobId: string; state: string }>>;
}

// ── shared pure core ─────────────────────────────────────────────────────────

function isDueJob(job: OptionalJobRecord, nowUtcMs: number): boolean {
	// E4-I Astra correction: a backoff job is due again once its retry
	// deadline passes — it was never excluded forever.
	if (job.state !== 'queued' && job.state !== 'backoff') return false;
	if (job.leaseOwner !== null && job.leaseExpiresAtMs !== null && job.leaseExpiresAtMs > nowUtcMs) return false;
	if (job.retryAtUtcMs !== null && job.retryAtUtcMs > nowUtcMs) return false;
	return true;
}

function mergeEnqueue(
	existing: OptionalJobRecord | null,
	record: OptionalJobRecord,
): EnqueueOutcome {
	if (existing) {
		if (record.triggerGeneration > existing.triggerGeneration) {
			// A materially newer authenticated trigger re-opens admission —
			// INCLUDING over a terminal job (E4-I Astra correction: the r1
			// "terminal stays terminal" rule is a lease-release/duplicate-result
			// rule, not a trigger rule; a fresh generation is fresh work). The
			// new generation becomes runnable while the previous generation's
			// terminal result is superseded (never mutated to look like the new
			// run's own result). Queue age stays with the original enqueue (no
			// retry-storm reset), and the fresh attempt envelope resets. A
			// RUNNING job keeps its running state: the coalesce never clobbers a
			// concurrent lease — the superseded writer stays running (its commits
			// are generation-guarded) until it releases or its lease is reclaimed.
			const merged: OptionalJobRecord = {
				...existing,
				triggerGeneration: record.triggerGeneration,
				state: existing.state === 'running' ? 'running' : 'queued',
				retryAtUtcMs: null,
				attempts: 0,
			};
			return { kind: 'coalesced', job: merged };
		}
		return { kind: 'rejected-stale-generation', job: existing };
	}
	return { kind: 'enqueued', job: { ...record } };
}

function applyRelease(
	job: OptionalJobRecord | null,
	owner: string,
	options: { backoff?: boolean; retryAtUtcMs?: number | null; attempts?: number } | undefined,
): OptionalJobRecord | null {
	if (!job || job.leaseOwner !== owner) return job;
	// E4-I Astra correction: a terminal job never re-enters the queue. The
	// lease release that follows a committed terminal result only clears the
	// lease — releasing a completed job back to `queued` made it replay.
	if (stateIsTerminal(job.state)) {
		return { ...job, leaseOwner: null, leaseExpiresAtMs: null };
	}
	return {
		...job,
		leaseOwner: null,
		leaseExpiresAtMs: null,
		state: options?.backoff ? 'backoff' : 'queued',
		retryAtUtcMs: options?.retryAtUtcMs ?? null,
		attempts: options?.attempts ?? job.attempts,
	};
}

/** Terminal result states: once recorded, a same-or-older generation cannot overwrite. */
const TERMINAL_RESULT_STATES: ReadonlySet<string> = new Set(['complete', 'failed', 'expired', 'cancelled']);

function resultIsTerminal(state: string): boolean {
	return TERMINAL_RESULT_STATES.has(state);
}

function claimable(job: OptionalJobRecord | null, jobId: string, nowUtcMs: number): boolean {
	if (!job || job.jobId !== jobId) return false;
	if (!isDueJob(job, nowUtcMs)) return false;
	return true;
}

// ── in-memory persistence ────────────────────────────────────────────────────

export function createMemoryJobPersistence(): JobPersistence & { snapshotJobs(): OptionalJobRecord[]; snapshotResults(): Map<string, StoredJobResult> } {
	const jobs = new Map<string, OptionalJobRecord>();
	const results = new Map<string, StoredJobResult>();
	const store = {
		async enqueueJob(record: OptionalJobRecord): Promise<EnqueueOutcome> {
			const existing = jobs.get(record.coalescingKey) ?? null;
			const outcome = mergeEnqueue(existing, record);
	if (outcome.kind !== 'rejected-stale-generation') jobs.set(record.coalescingKey, outcome.job);
	if (outcome.kind === 'coalesced') {
		// The superseded generation's TERMINAL result no longer describes this
		// job: a newer trigger reopened it, so a complete/failed/expired result
		// is cleared rather than mistaken for the fresh generation's own. A
		// non-terminal (paused) result survives the coalesce — it is durable
		// pause state, never a dropped column.
		const superseded = results.get(record.jobId);
		if (superseded && resultIsTerminal(superseded.resultState)) results.delete(record.jobId);
	}
	return outcome;
},
		async listDue(nowUtcMs: number): Promise<OptionalJobRecord[]> {
			return [...jobs.values()]
				.filter((job) => isDueJob(job, nowUtcMs))
				.sort((a, b) => a.queuedAtUtcMs - b.queuedAtUtcMs || a.jobId.localeCompare(b.jobId));
		},
		async claimLease(jobId: string, owner: string, nowUtcMs: number): Promise<LeaseFence | null> {
			for (const [key, job] of jobs) {
				if (job.jobId !== jobId) continue;
				if (!claimable(job, jobId, nowUtcMs)) return null;
				const leaseExpiresAtMs = nowUtcMs + LEASE_TTL_MS;
				jobs.set(key, {
					...job,
					leaseOwner: owner,
					leaseExpiresAtMs,
					state: 'running',
				});
				// The winner's commit credential: present this verbatim on every
				// checkpoint/result commit.
				return { owner, leaseExpiresAtMs };
			}
			return null;
		},
		async releaseLease(jobId: string, owner: string, options?: { backoff?: boolean; retryAtUtcMs?: number | null; attempts?: number }): Promise<void> {
			for (const [key, job] of jobs) {
				if (job.jobId !== jobId) continue;
				const released = applyRelease(job, owner, options);
				if (released) jobs.set(key, released);
				return;
			}
		},
		async reclaimExpiredLeases(nowUtcMs: number): Promise<string[]> {
			const reclaimed: string[] = [];
			for (const [key, job] of jobs) {
				if (
					job.leaseOwner !== null &&
					job.leaseExpiresAtMs !== null &&
					job.leaseExpiresAtMs <= nowUtcMs
				) {
					// A terminal job whose lease outlived its commit stays terminal —
					// reclaim only returns runnable work to the queue.
					jobs.set(key, {
						...job,
						leaseOwner: null,
						leaseExpiresAtMs: null,
						state: stateIsTerminal(job.state) ? job.state : 'queued',
					});
					reclaimed.push(job.jobId);
				}
			}
			return reclaimed;
		},
		async commitCheckpoint(jobId: string, expectedGeneration: number, checkpoint: SyncCheckpoint | null, guard?: CommitGuard): Promise<CheckpointCommitOutcome> {
			for (const [key, job] of jobs) {
				if (job.jobId !== jobId) continue;
				if (job.triggerGeneration !== expectedGeneration) return { kind: 'stale-generation' };
				// Lease fencing: a claimant that lost its lease (expired and
				// reclaimed, or re-claimed by another owner) can no longer commit.
				if (!fenceHolds(job, guard?.fence)) return { kind: 'stale-generation' };
				// The staged page and the checkpoint commit as ONE unit: applyPage
				// runs only after the fence passed, and the checkpoint write
				// follows with no intervening await; a failure in the checkpoint
				// half rolls the applied page back so neither side is exposed.
				if (guard?.compose) {
					try {
						await guard.compose.applyPage();
					} catch (error) {
						await guard.compose.rollbackPage?.();
						throw error;
					}
					// E4-I r5 Astra correction: the fence is re-verified AFTER the
					// async page application, before the checkpoint write. The apply
					// await is an interleaving window — an account cancellation, a
					// lease reclaim/re-claim or a superseding trigger recorded during
					// it must never be overwritten by this composition's stale
					// snapshot (the write used to restore the pre-await running job,
					// resurrecting work a cancellation had already terminalized). A
					// lost race rolls the applied page back: it belongs to a commit
					// that never was.
					const current = jobs.get(key);
					if (!current || current.triggerGeneration !== expectedGeneration || !fenceHolds(current, guard.fence)) {
						await guard.compose.rollbackPage?.();
						return { kind: 'stale-generation' };
					}
					try {
						jobs.set(key, { ...current, checkpoint });
					} catch (error) {
						await guard.compose.rollbackPage?.();
						throw error;
					}
					return { kind: 'committed' };
				}
				jobs.set(key, { ...job, checkpoint });
				return { kind: 'committed' };
			}
			return { kind: 'unknown-job' };
		},
		async recordResult(jobId: string, expectedGeneration: number, result: JobResult, fence?: LeaseFence): Promise<CheckpointCommitOutcome> {
			for (const [key, job] of jobs) {
				if (job.jobId !== jobId) continue;
				if (job.triggerGeneration !== expectedGeneration) return { kind: 'stale-generation' };
				if (!fenceHolds(job, fence)) return { kind: 'stale-generation' };
				const existing = results.get(jobId);
				if (existing && (existing.triggerGeneration > expectedGeneration ||
					(resultIsTerminal(existing.resultState) && existing.triggerGeneration === expectedGeneration))) {
					// Duplicate-effect rejection: a terminal result is immutable at
					// its generation; a newer generation already superseded this one.
					return { kind: 'stale-generation' };
				}
				results.set(jobId, { resultState: result.state, result, triggerGeneration: expectedGeneration });
				jobs.set(key, { ...job, state: result.state, checkpoint: result.checkpoint });
				return { kind: 'committed' };
			}
			return { kind: 'unknown-job' };
		},
		async readJobResult(jobId: string): Promise<StoredJobResult | null> {
			return results.get(jobId) ?? null;
		},
		async readJob(jobId: string): Promise<OptionalJobRecord | null> {
			for (const job of jobs.values()) if (job.jobId === jobId) return { ...job };
			return null;
		},
		async listByAccount(accountId: string): Promise<OptionalJobRecord[]> {
			return [...jobs.values()].filter((job) => job.accountId === accountId).map((job) => ({ ...job }));
		},
		async cancelAccountJobs(accountId: string, nowUtcMs: number): Promise<string[]> {
			const cancelled: string[] = [];
			for (const [key, job] of jobs) {
				if (job.accountId !== accountId || job.state === 'complete' || job.state === 'cancelled' || job.state === 'expired' || job.state === 'failed') continue;
				jobs.set(key, { ...job, state: 'cancelled', leaseOwner: null, leaseExpiresAtMs: null });
				results.set(job.jobId, {
					resultState: 'cancelled',
					triggerGeneration: job.triggerGeneration,
					result: {
						state: 'cancelled',
						checkpoint: job.checkpoint ?? { version: SYNC_CHECKPOINT_VERSION, cursor: null },
						progress: { done: 0, chargedUnits: 0 },
						reason: 'cancelled',
					},
				});
				cancelled.push(job.jobId);
			}
			void nowUtcMs;
			return cancelled;
		},
		async purgeTerminalBefore(nowMs: number): Promise<number> {
			let purged = 0;
			for (const [key, job] of jobs) {
				const settled = results.get(job.jobId);
				if (!settled || !resultIsTerminal(settled.resultState)) continue;
				if (job.queuedAtUtcMs + TERMINAL_RETENTION_MS < nowMs) {
					jobs.delete(key);
					purged += 1;
				}
			}
			return purged;
		},
		snapshotJobs(): OptionalJobRecord[] {
			return [...jobs.values()].map((job) => ({ ...job }));
		},
		snapshotResults(): Map<string, StoredJobResult> {
			return new Map(results);
		},
	};
	return store;
}

type MemoryJobPersistence = ReturnType<typeof createMemoryJobPersistence>;

// ── durable persistence over the native atomic batch ─────────────────────────

const JOB_ROW_COLUMNS = [
	'job_id',
	'account_id',
	'work_class',
	'state',
	'trigger_generation',
	'coalescing_key',
	'attempts',
	'deadline_utc',
	'queued_at_utc_ms',
	'retry_at_utc_ms',
	'step_kind',
	'checkpoint_version',
	'checkpoint_cursor',
	'lease_owner',
	'lease_expires_at_ms',
] as const;

interface JobRow {
	job_id: string;
	account_id: string;
	work_class: OptionalWorkClass;
	state: OptionalJobState;
	trigger_generation: number;
	coalescing_key: string;
	attempts: number;
	deadline_utc: string;
	queued_at_utc_ms: number;
	retry_at_utc_ms: number | null;
	step_kind: JobStepKind;
	checkpoint_version: number | null;
	checkpoint_cursor: string | null;
	lease_owner: string | null;
	lease_expires_at_ms: number | null;
}

function rowToJob(row: JobRow): OptionalJobRecord {
	const checkpoint = validateSyncCheckpoint({
		version: row.checkpoint_version ?? SYNC_CHECKPOINT_VERSION,
		cursor: row.checkpoint_cursor ?? null,
	});
	return {
		jobId: row.job_id,
		accountId: row.account_id,
		workClass: row.work_class,
		state: row.state,
		triggerGeneration: row.trigger_generation,
		coalescingKey: row.coalescing_key,
		attempts: row.attempts,
		deadlineUtc: row.deadline_utc,
		queuedAtUtcMs: row.queued_at_utc_ms,
		retryAtUtcMs: row.retry_at_utc_ms,
		stepKind: row.step_kind === 'window' ? 'window' : 'delta',
		checkpoint,
		leaseOwner: row.lease_owner,
		leaseExpiresAtMs: row.lease_expires_at_ms,
	};
}

function jobToRowParams(job: OptionalJobRecord): unknown[] {
	return [
		job.jobId,
		job.accountId,
		job.workClass,
		job.state,
		job.triggerGeneration,
		job.coalescingKey,
		job.attempts,
		job.deadlineUtc,
		job.queuedAtUtcMs,
		job.retryAtUtcMs,
		job.stepKind,
		job.checkpoint?.version ?? null,
		job.checkpoint?.cursor ?? null,
		job.leaseOwner,
		job.leaseExpiresAtMs,
	];
}

/** True only when the bridge exposes the E4-I native atomic batch entry. */
export function durableJobPersistenceAvailable(db: OfflineDbBridge): boolean {
	return typeof db.transactionBatch === 'function';
}

interface DurableOptions {
	/** Injected for deterministic tests; defaults to Date.now(). */
	nowUtcMs?: () => number;
}

/**
 * Durable persistence over the native atomic batch. Every mutation is one
 * validated `transactionBatch` — crash/failure exposes neither partial page
 * nor checkpoint; success exposes both. Construction fails closed when the
 * entry is absent: use `durableJobPersistenceAvailable` first.
 */
export function createDurableJobPersistence(
	db: OfflineDbBridge,
	options: DurableOptions = {},
): JobPersistence {
	if (typeof db.transactionBatch !== 'function') {
		throw new Error(
			'durable job store: this shell does not expose the E4-I native atomic batch ' +
				'(db.transactionBatch); durable job persistence refuses non-atomic storage. ' +
				'Use the in-memory persistence or ship the native batch entry.',
		);
	}
	const runBatch = async (statements: NativeBatchStatement[]): Promise<number> => {
		const decision = admitBatch('mail', 'mail', DEFAULT_BATCH_BUDGET, statements);
		if (decision.kind === 'refused') {
			throw new Error(`durable job store: batch refused ${decision.reason} (${decision.detail})`);
		}
		return db.transactionBatch!('mail', statements, DEFAULT_BATCH_BUDGET);
	};
	const nowUtcMs = options.nowUtcMs ?? (() => Date.now());

	async function queryJobs(sql: string, params: unknown[]): Promise<JobRow[]> {
		return db.query<JobRow>('mail', sql, params);
	}

	return {
		async enqueueJob(record): Promise<EnqueueOutcome> {
			// E4-I Astra correction: coalescing never rewrites the whole row.
			// A plain INSERT claims new identities; a conflicting row is updated
			// IN PLACE with targeted SETs guarded by the prior generation, so a
			// racing claim's lease/state can never be overwritten by a stale
			// read-modify-replace and an existing row's result columns are never
			// dropped (INSERT OR REPLACE nulls every column it omits).
			const inserted = await runBatch([
				{
					sql: `INSERT INTO optional_jobs (${JOB_ROW_COLUMNS.join(', ')})
						VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
						ON CONFLICT (coalescing_key) DO NOTHING`,
					params: jobToRowParams(record),
				},
			]);
			if (inserted > 0) return { kind: 'enqueued', job: { ...record } };
			// E4-I Astra correction (trigger lifecycle): a materially newer
			// authenticated trigger RE-OPENS the job — including over a terminal
			// state — as fresh runnable work at the new generation. The prior
			// generation's TERMINAL result is superseded (its columns are cleared
			// in the SAME atomic update, so it can never be mistaken for the new
			// run's own result; a non-terminal paused result survives as durable
			// pause state), the attempt envelope resets, a RUNNING job keeps its
			// running state (the coalesce never clobbers a concurrent lease), and
			// the live lease of a superseded older-generation writer is preserved
			// untouched.
			const merged = await runBatch([
				{
					sql: `UPDATE optional_jobs SET
						trigger_generation = ?,
						state = CASE WHEN state = 'running' THEN 'running' ELSE 'queued' END,
						retry_at_utc_ms = NULL,
						attempts = 0,
						result_state = CASE
							WHEN result_state IN ('complete','failed','expired','cancelled') THEN NULL
							ELSE result_state END,
						result_json = CASE
							WHEN result_state IN ('complete','failed','expired','cancelled') THEN NULL
							ELSE result_json END
						WHERE coalescing_key = ? AND trigger_generation < ?`,
					params: [record.triggerGeneration, record.coalescingKey, record.triggerGeneration],
				},
			]);
			const existing = await queryJobs(
				`SELECT ${JOB_ROW_COLUMNS.join(', ')} FROM optional_jobs WHERE coalescing_key = ?`,
				[record.coalescingKey],
			);
			if (merged === 0 || existing.length === 0) {
				return { kind: 'rejected-stale-generation', job: existing.length ? rowToJob(existing[0]) : record };
			}
			return { kind: 'coalesced', job: rowToJob(existing[0]) };
		},

		async listDue(nowMs): Promise<OptionalJobRecord[]> {
			const rows = await queryJobs(
				`SELECT ${JOB_ROW_COLUMNS.join(', ')} FROM optional_jobs ORDER BY queued_at_utc_ms, job_id`,
				[],
			);
			return rows.map(rowToJob).filter((job) => isDueJob(job, nowMs));
		},

		async claimLease(jobId, owner, nowMs): Promise<LeaseFence | null> {
			// CAS claim in one atomic batch: only an unleased/expired due job
			// (queued, or backoff whose retry deadline has passed) transitions to
			// running; changedRows===1 proves this owner won. The stamped
			// (owner, expiry) pair is returned as the winner's commit fence — it
			// is exactly the value this UPDATE wrote, so no post-claim read (and
			// its TOCTOU window) participates in fencing.
			const leaseExpiresAtMs = nowMs + LEASE_TTL_MS;
			const changed = await runBatch([
				{
					sql: `UPDATE optional_jobs SET state = 'running', lease_owner = ?, lease_expires_at_ms = ?
						WHERE job_id = ?
						AND state IN ('queued','backoff')
						AND (retry_at_utc_ms IS NULL OR retry_at_utc_ms <= ?)
						AND (lease_owner IS NULL OR lease_expires_at_ms IS NULL OR lease_expires_at_ms <= ?)`,
					params: [owner, leaseExpiresAtMs, jobId, nowMs, nowMs],
				},
			]);
			return changed > 0 ? { owner, leaseExpiresAtMs } : null;
		},

		async releaseLease(jobId, owner, opts): Promise<void> {
			await runBatch([
				{
					sql: `UPDATE optional_jobs SET
						lease_owner = NULL, lease_expires_at_ms = NULL,
						state = CASE WHEN state IN ('complete','failed','expired','cancelled') THEN state ELSE ? END,
						retry_at_utc_ms = CASE WHEN state IN ('complete','failed','expired','cancelled') THEN retry_at_utc_ms ELSE ? END,
						attempts = COALESCE(?, attempts)
						WHERE job_id = ? AND lease_owner = ?`,
					params: [
						opts?.backoff ? 'backoff' : 'queued',
						opts?.retryAtUtcMs ?? null,
						opts?.attempts ?? null,
						jobId,
						owner,
					],
				},
			]);
		},

		async reclaimExpiredLeases(nowMs): Promise<string[]> {
			const expired = await queryJobs(
				`SELECT job_id FROM optional_jobs WHERE lease_owner IS NOT NULL AND lease_expires_at_ms IS NOT NULL AND lease_expires_at_ms <= ?`,
				[nowMs],
			);
			if (expired.length === 0) return [];
			await runBatch([
				{
					sql: `UPDATE optional_jobs SET lease_owner = NULL, lease_expires_at_ms = NULL,
						state = CASE WHEN state IN ('complete','failed','expired','cancelled') THEN state ELSE 'queued' END
						WHERE lease_owner IS NOT NULL AND lease_expires_at_ms IS NOT NULL AND lease_expires_at_ms <= ?`,
					params: [nowMs],
				},
			]);
			return expired.map((row) => row.job_id);
		},

		async commitCheckpoint(jobId: string, expectedGeneration: number, checkpoint: SyncCheckpoint | null, guard?: CommitGuard): Promise<CheckpointCommitOutcome> {
			const fenceClause = guard?.fence ? 'AND lease_owner = ? AND lease_expires_at_ms = ?' : '';
			const guardedParams: unknown[] = guard?.fence
				? [guard.fence.owner, guard.fence.leaseExpiresAtMs]
				: [];
			const checkpointBatch = async (): Promise<number> => runBatch([
				{
					sql: `UPDATE optional_jobs
						SET checkpoint_version = ?, checkpoint_cursor = ?
						WHERE job_id = ? AND trigger_generation = ? ${fenceClause}`,
					params: [
						checkpoint?.version ?? SYNC_CHECKPOINT_VERSION,
						checkpoint?.cursor ?? null,
						jobId,
						expectedGeneration,
						...guardedParams,
					],
				},
			]);
			if (guard?.compose) {
				// The staged page and the checkpoint commit as ONE unit at the TS
				// integration layer: the generation/lease fence is verified FIRST
				// (a stale writer applies no page effect at all), then the page
				// flush runs, then the fence-guarded checkpoint batch — and when
				// the checkpoint half fails OR turns out stale, the already-applied
				// page is rolled back, so a checkpoint failure can never leave the
				// page visible under the old cursor (E4-I Astra correction: the
				// page used to stay applied when the batch failed afterwards).
				const rows = await queryJobs(
					`SELECT ${JOB_ROW_COLUMNS.join(', ')} FROM optional_jobs WHERE job_id = ?`,
					[jobId],
				);
				if (!rows.length) return { kind: 'unknown-job' };
				const current = rowToJob(rows[0]);
				if (current.triggerGeneration !== expectedGeneration) return { kind: 'stale-generation' };
				if (!fenceHolds(current, guard.fence)) return { kind: 'stale-generation' };
				await guard.compose.applyPage();
				try {
					const changed = await checkpointBatch();
					if (changed === 0) {
						// Stale between the fence read and the write (the lease moved
						// on): undo the page — it belongs to a commit that never was.
						await guard.compose.rollbackPage();
						return { kind: 'stale-generation' };
					}
					return { kind: 'committed' };
				} catch (error) {
					await guard.compose.rollbackPage();
					throw error;
				}
			}
			// CAS + checkpoint write in one atomic batch: a stale generation (a
			// superseded trigger or a reclaimed lease) changes nothing.
			const changed = await checkpointBatch();
			return changed > 0 ? { kind: 'committed' } : { kind: 'stale-generation' };
		},

		async recordResult(jobId: string, expectedGeneration: number, result: JobResult, fence?: LeaseFence): Promise<CheckpointCommitOutcome> {
			if (!isJobResultState(result.state)) throw new Error('durable job store: invalid result state');
			const reason = 'reason' in result && typeof result.reason === 'string' && isPauseReason(result.reason)
				? result.reason
				: null;
			// Result + job state + checkpoint land in ONE atomic batch, generation-
			// and lease-guarded: a duplicate/stale effect application — including a
			// claimant that lost its lease to reclaim or re-claim — is a no-op.
			const changed = await runBatch([
				{
					sql: `UPDATE optional_jobs
						SET state = ?, result_state = ?, result_json = ?, checkpoint_version = ?, checkpoint_cursor = ?
						WHERE job_id = ? AND trigger_generation = ?
						AND (result_state IS NULL OR result_state IN ('queued','running','paused','backoff'))
						${fence ? 'AND lease_owner = ? AND lease_expires_at_ms = ?' : ''}`,
					params: [
						result.state,
						result.state,
						JSON.stringify({ ...result, reason }),
						result.checkpoint?.version ?? SYNC_CHECKPOINT_VERSION,
						result.checkpoint?.cursor ?? null,
						jobId,
						expectedGeneration,
						...(fence ? [fence.owner, fence.leaseExpiresAtMs] : []),
					],
				},
			]);
			return changed > 0 ? { kind: 'committed' } : { kind: 'stale-generation' };
		},

		async readJobResult(jobId: string): Promise<StoredJobResult | null> {
			const rows = await db.query<{
				result_state: string | null;
				result_json: string | null;
				trigger_generation: number;
				checkpoint_version: number | null;
				checkpoint_cursor: string | null;
			}>(
				'mail',
				`SELECT result_state, result_json, trigger_generation, checkpoint_version, checkpoint_cursor FROM optional_jobs WHERE job_id = ?`,
				[jobId],
			);
			const row = rows[0];
			if (!row || row.result_state === null) return null;
			if (!isJobResultState(row.result_state)) return null;
			// E4-I r5 Astra correction: the durable account-scoped cancellation
			// terminalizes rows WITHOUT a per-row JSON payload (one batched UPDATE
			// cannot fabricate each row's stored checkpoint). A `cancelled`
			// result_state with no result_json is that durable terminal state, not
			// a missing result: the reader synthesizes the same canonical result
			// the in-memory cancellation records. Every other state without JSON
			// stays unreadable (fail closed).
			if (row.result_json === null) {
				if (row.result_state !== 'cancelled') return null;
				const checkpoint = validateSyncCheckpoint({
					version: row.checkpoint_version ?? SYNC_CHECKPOINT_VERSION,
					cursor: row.checkpoint_cursor ?? null,
				}) ?? { version: SYNC_CHECKPOINT_VERSION, cursor: null };
				return {
					resultState: 'cancelled',
					triggerGeneration: row.trigger_generation,
					result: {
						state: 'cancelled',
						checkpoint,
						progress: { done: 0, chargedUnits: 0 },
						reason: 'cancelled',
					},
				};
			}
			try {
				const parsed = JSON.parse(row.result_json) as JobResult;
				if (parsed.state !== row.result_state) return null;
				const checkpoint = validateSyncCheckpoint(parsed.checkpoint);
				if (!checkpoint) return null;
				return {
					resultState: row.result_state,
					result: { ...parsed, checkpoint } as JobResult,
					triggerGeneration: row.trigger_generation,
				};
			} catch {
				return null;
			}
		},

		async readJob(jobId: string): Promise<OptionalJobRecord | null> {
			const rows = await queryJobs(
				`SELECT ${JOB_ROW_COLUMNS.join(', ')} FROM optional_jobs WHERE job_id = ?`,
				[jobId],
			);
			return rows.length ? rowToJob(rows[0]) : null;
		},

		async listByAccount(accountId: string): Promise<OptionalJobRecord[]> {
			const rows = await queryJobs(
				`SELECT ${JOB_ROW_COLUMNS.join(', ')} FROM optional_jobs WHERE account_id = ? ORDER BY queued_at_utc_ms, job_id`,
				[accountId],
			);
			return rows.map(rowToJob);
		},

		async cancelAccountJobs(accountId): Promise<string[]> {
			const open = await queryJobs(
				`SELECT job_id, trigger_generation FROM optional_jobs
				WHERE account_id = ? AND state NOT IN ('complete','failed','expired','cancelled')`,
				[accountId],
			);
			if (open.length === 0) return [];
			await runBatch([
				{
					// E4-I r6 Astra correction: the cancellation also clears any
					// stale non-cancelled result_json (e.g. a paused payload left by
					// an earlier result). A cancelled row with a stale JSON payload
					// was unreachable-but-readable-as-nothing: the strict reader
					// rejected the parsed paused state against the cancelled
					// result_state. NULL is THE durable cancelled shape — the reader
					// synthesizes the same canonical cancelled result the in-memory
					// cancellation records, from the row's own committed checkpoint.
					sql: `UPDATE optional_jobs SET state = 'cancelled', lease_owner = NULL, lease_expires_at_ms = NULL,
						result_state = 'cancelled', result_json = NULL
						WHERE account_id = ? AND state NOT IN ('complete','failed','expired','cancelled')`,
					params: [accountId],
				},
			]);
			return open.map((row) => row.job_id);
		},

		async purgeTerminalBefore(nowMs: number): Promise<number> {
			const rows = await queryJobs(
				`SELECT job_id FROM optional_jobs
				WHERE state IN ('complete','failed','expired','cancelled')
				AND result_state IS NOT NULL
				AND queued_at_utc_ms + ? < ?`,
				[TERMINAL_RETENTION_MS, nowMs],
			);
			if (rows.length === 0) return 0;
			await runBatch([
				{
					sql: `DELETE FROM optional_jobs
						WHERE state IN ('complete','failed','expired','cancelled')
						AND result_state IS NOT NULL
						AND queued_at_utc_ms + ? < ?`,
					params: [TERMINAL_RETENTION_MS, nowMs],
				},
			]);
			return rows.length;
		},
	};
}

// ── transfer persistence ─────────────────────────────────────────────────────

interface TransferRow {
	job_id: string;
	account_id: string;
	blob_sha256: string;
	etag: string;
	expected_size: number;
	expected_sha256: string;
	committed_bytes: number;
	state: string;
	deadline_utc: string;
	attempts: number;
}

export interface PersistedTransferRecord {
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

export function createMemoryTransferPersistence(): AttachmentTransferPersistence & { snapshot(): PersistedTransferRecord[] } {
	const rows = new Map<string, PersistedTransferRecord>();
	return {
		async upsertCheckpoint(checkpoint): Promise<void> {
			rows.set(checkpoint.jobId, { ...checkpoint });
		},
		async loadCheckpoint(jobId): Promise<PersistedTransferRecord | null> {
			const row = rows.get(jobId);
			return row ? { ...row } : null;
		},
		async purgeCheckpoint(jobId): Promise<void> {
			rows.delete(jobId);
		},
		async listByAccount(accountId) {
			return [...rows.values()]
				.filter((row) => row.accountId === accountId)
				.map((row) => ({ jobId: row.jobId, state: row.state }));
		},
		snapshot() {
			return [...rows.values()].map((row) => ({ ...row }));
		},
	};
}

export function createDurableTransferPersistence(db: OfflineDbBridge): AttachmentTransferPersistence {
	if (typeof db.transactionBatch !== 'function') {
		throw new Error(
			'durable transfer store: this shell does not expose the E4-I native atomic batch ' +
				'(db.transactionBatch); refusing non-atomic transfer persistence.',
		);
	}
	const runBatch = async (statements: NativeBatchStatement[]): Promise<number> => {
		const decision = admitBatch('mail', 'mail', DEFAULT_BATCH_BUDGET, statements);
		if (decision.kind === 'refused') {
			throw new Error(`durable transfer store: batch refused ${decision.reason} (${decision.detail})`);
		}
		return db.transactionBatch!('mail', statements, DEFAULT_BATCH_BUDGET);
	};
	return {
		async upsertCheckpoint(checkpoint): Promise<void> {
			await runBatch([
				{
					sql: `INSERT OR REPLACE INTO attachment_transfers
						(job_id, account_id, blob_sha256, etag, expected_size, expected_sha256, committed_bytes, state, deadline_utc, attempts, checkpoint_version)
						VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
					params: [
						checkpoint.jobId,
						checkpoint.accountId,
						checkpoint.blobSha256,
						checkpoint.etag,
						checkpoint.expectedSize,
						checkpoint.expectedSha256,
						checkpoint.committedBytes,
						checkpoint.state,
						checkpoint.deadlineUtc,
						checkpoint.attempts,
						ATTACHMENT_TRANSFER_CHECKPOINT_VERSION,
					],
				},
			]);
		},
		async loadCheckpoint(jobId) {
			const rows = await db.query<TransferRow>(
				'mail',
				`SELECT job_id, account_id, blob_sha256, etag, expected_size, expected_sha256, committed_bytes, state, deadline_utc, attempts
				FROM attachment_transfers WHERE job_id = ?`,
				[jobId],
			);
			const row = rows[0];
			if (!row) return null;
			return {
				jobId: row.job_id,
				accountId: row.account_id,
				blobSha256: row.blob_sha256,
				etag: row.etag,
				expectedSize: row.expected_size,
				expectedSha256: row.expected_sha256,
				committedBytes: row.committed_bytes,
				state: row.state,
				deadlineUtc: row.deadline_utc,
				attempts: row.attempts,
			};
		},
		async purgeCheckpoint(jobId): Promise<void> {
			await runBatch([
				{ sql: 'DELETE FROM attachment_transfers WHERE job_id = ?', params: [jobId] },
			]);
		},
		async listByAccount(accountId) {
			const rows = await db.query<TransferRow>(
				'mail',
				`SELECT job_id, state, account_id, blob_sha256, etag, expected_size, expected_sha256, committed_bytes, deadline_utc, attempts
				FROM attachment_transfers WHERE account_id = ?`,
				[accountId],
			);
			return rows.map((row) => ({ jobId: row.job_id, state: row.state }));
		},
	};
}

/**
 * Map a persisted transfer record onto the E3 checkpoint contract and parse it
 * strictly; a row that fails the frozen E3 validation is reported as invalid
 * instead of being silently trusted.
 */
export function parsePersistedTransferCheckpoint(record: PersistedTransferRecord | null) {
	if (!record) return null;
	return parseAttachmentTransferCheckpoint({
		version: ATTACHMENT_TRANSFER_CHECKPOINT_VERSION,
		accountId: record.accountId,
		jobId: record.jobId,
		blobId: record.blobSha256,
		etag: record.etag,
		expectedSize: record.expectedSize,
		expectedSha256: record.expectedSha256,
		committedBytes: record.committedBytes,
		deadlineUtc: record.deadlineUtc,
		attempts: record.attempts,
		state: record.state,
	});
}
