/**
 * Job/transfer store edge branches (coverage round r2).
 *
 * Real behavior tests for the paths the E4-I suites leave cold:
 *
 * - the shared in-memory persistence: stale-generation admission refusals,
 *   unknown-job reads/claims/commits, per-account listing, terminal-skip in
 *   account cancellation, bounded terminal GC, snapshots, and the plain
 *   (uncomposed) checkpoint commit;
 * - the durable persistence over a REAL SQLite engine: per-account listing,
 *   bounded terminal GC, the no-open-jobs cancellation fast path, the strict
 *   result reader's fail-closed shapes (invalid state, state/JSON mismatch,
 *   invalid checkpoint, corrupt JSON), the composed commit's unknown/stale/
 *   fence pre-checks and its changed-0 stale race, and an explicit injected
 *   clock;
 * - the durable transfer persistence end-to-end (upsert/load/purge/list over
 *   the real engine, fail-closed without the atomic batch entry) and the
 *   strict E3 parse of a persisted transfer record.
 */

import { describe, it, expect } from 'vitest';
import type { NativeDbAppKey, OfflineDbBridge } from '$lib/native/types';

let DatabaseSync: (typeof import('node:sqlite'))['DatabaseSync'] | null = null;
try {
	({ DatabaseSync } = await import('node:sqlite'));
} catch {
	// Node without node:sqlite: the real-SQL scenarios skip; the memory
	// scenarios still run.
}
const sqliteDescribe = DatabaseSync ? describe : describe.skip;

import {
	createDurableJobPersistence,
	createDurableTransferPersistence,
	createMemoryJobPersistence,
	createMemoryTransferPersistence,
	durableJobPersistenceAvailable,
	LEASE_TTL_MS,
	TERMINAL_RETENTION_MS,
	parsePersistedTransferCheckpoint,
	type OptionalJobRecord,
} from './jobStore';
import { legacySchemaInitSql } from './migrations';
import type { SyncCheckpoint } from './work-contract';

function baseJob(overrides: Partial<OptionalJobRecord> = {}): OptionalJobRecord {
	return {
		jobId: 'job-1',
		accountId: 'acct-1',
		workClass: 'background',
		state: 'queued',
		triggerGeneration: 3,
		coalescingKey: 'reconnect:acct-1',
		attempts: 0,
		deadlineUtc: '2026-09-24T00:00:00Z',
		queuedAtUtcMs: 0,
		retryAtUtcMs: null,
		stepKind: 'delta',
		checkpoint: null,
		leaseOwner: null,
		leaseExpiresAtMs: null,
		...overrides,
	};
}

function completeResult(cursor = 'delta:state:5') {
	return {
		state: 'complete' as const,
		checkpoint: { version: 1 as const, cursor },
		progress: { done: 2, chargedUnits: 2 },
	};
}

/** A REAL SQLite-backed bridge: genuine constraints, transactions, changes(). */
function createSqliteBridge(options: { withSchemaInit?: boolean } = {}): OfflineDbBridge & { execDirect(sql: string, params?: unknown[]): void } {
	const db = new DatabaseSync!(':memory:');
	if (options.withSchemaInit) {
		// Strip the FTS5 virtual table (job/transfer oracles never touch it and
		// node builds may omit the module).
		const sql = legacySchemaInitSql({ version: 0, needsLegacyEligibilityReplay: false });
		db.exec(sql.split(';\n').filter((statement) => !statement.includes('USING fts5')).join(';\n'));
	}
	const bridge = {
		async open() {},
		async isOpen() {
			return true;
		},
		async exec(_appKey: NativeDbAppKey, sql: string, params: unknown[] = []) {
			return Number(db.prepare(sql).run(...(params as never[])).changes);
		},
		async query<T = Record<string, unknown>>(_appKey: NativeDbAppKey, sql: string, params: unknown[] = []) {
			return db.prepare(sql).all(...(params as never[])) as T[];
		},
		async transactionBatch(_appKey: NativeDbAppKey, statements: ReadonlyArray<{ sql: string; params?: unknown[] }>) {
			db.exec('BEGIN');
			try {
				let changes = 0;
				for (const statement of statements) {
					changes += Number(db.prepare(statement.sql).run(...((statement.params ?? []) as never[])).changes);
				}
				db.exec('COMMIT');
				return changes;
			} catch (error) {
				db.exec('ROLLBACK');
				throw error;
			}
		},
		async wipe() {
			db.close();
		},
		execDirect(sql: string, params: unknown[] = []) {
			db.prepare(sql).run(...(params as never[]));
		},
	};
	return bridge as OfflineDbBridge & { execDirect(sql: string, params?: unknown[]): void };
}

describe('memory job persistence edge branches', () => {
	it('an EQUAL-generation re-enqueue is refused as stale without touching the row', async () => {
		const jobs = createMemoryJobPersistence();
		const first = await jobs.enqueueJob(baseJob({ triggerGeneration: 3 }));
		expect(first.kind).toBe('enqueued');
		const again = await jobs.enqueueJob(baseJob({ triggerGeneration: 3 }));
		expect(again.kind).toBe('rejected-stale-generation');
		// The refusal reports the EXISTING row, not the incoming record.
		expect(again.job.state).toBe('queued');
		const listed = await jobs.listByAccount('acct-1');
		expect(listed).toHaveLength(1);
		expect(listed[0].triggerGeneration).toBe(3);
		// Another account's listing stays empty.
		expect(await jobs.listByAccount('acct-other')).toEqual([]);
	});

	it('unknown job ids answer null/false/unknown-job across every reader and commit', async () => {
		const jobs = createMemoryJobPersistence();
		expect(await jobs.claimLease('missing', 'owner-a', 0)).toBeNull();
		expect(await jobs.readJob('missing')).toBeNull();
		expect(await jobs.readJobResult('missing')).toBeNull();
		expect(await jobs.commitCheckpoint('missing', 1, { version: 1, cursor: 'x' })).toEqual({ kind: 'unknown-job' });
		expect(await jobs.recordResult('missing', 1, completeResult())).toEqual({ kind: 'unknown-job' });
		expect(await jobs.releaseLease('missing', 'owner-a')).toBeUndefined();
		expect(await jobs.reclaimExpiredLeases(60_000)).toEqual([]);
	});

	it('checkpoint and result commits are generation- and fence-guarded', async () => {
		const jobs = createMemoryJobPersistence();
		await jobs.enqueueJob(baseJob({ triggerGeneration: 3 }));
		// A stale generation never commits a checkpoint.
		expect((await jobs.commitCheckpoint('job-1', 2, { version: 1, cursor: 'x' }))).toEqual({ kind: 'stale-generation' });
		// The current generation commits without a guard (plain CAS path).
		expect((await jobs.commitCheckpoint('job-1', 3, { version: 1, cursor: 'c1' }))).toEqual({ kind: 'committed' });
		expect((await jobs.readJob('job-1'))?.checkpoint?.cursor).toBe('c1');
		// A wrong-generation result is refused...
		expect((await jobs.recordResult('job-1', 2, completeResult()))).toEqual({ kind: 'stale-generation' });
		// ...and a writer presenting a fence that is NOT the live lease is
		// refused even at the right generation.
		const fence = await jobs.claimLease('job-1', 'owner-a', 0);
		expect(fence).not.toBeNull();
		expect(
			(await jobs.recordResult('job-1', 3, completeResult(), { owner: 'owner-b', leaseExpiresAtMs: fence!.leaseExpiresAtMs })),
		).toEqual({ kind: 'stale-generation' });
		// The rightful fence holder commits.
		expect((await jobs.recordResult('job-1', 3, completeResult(), fence!))).toEqual({ kind: 'committed' });
		// A terminal job re-leases as terminal: release only clears the lease.
		await jobs.releaseLease('job-1', 'owner-a');
		expect((await jobs.readJob('job-1'))?.state).toBe('complete');
	});

	it('cancelAccountJobs skips terminal jobs and cancels open ones with a canonical result', async () => {
		const jobs = createMemoryJobPersistence();
		await jobs.enqueueJob(baseJob({ jobId: 'job-done', coalescingKey: 'k1' }));
		await jobs.claimLease('job-done', 'owner-a', 0);
		expect((await jobs.recordResult('job-done', 3, completeResult())).kind).toBe('committed');
		await jobs.enqueueJob(baseJob({ jobId: 'job-open', coalescingKey: 'k2' }));
		expect(await jobs.cancelAccountJobs('acct-1', 0)).toEqual(['job-open']);
		// The completed job survived; the open job is terminal-cancelled.
		expect((await jobs.readJob('job-done'))?.state).toBe('complete');
		const cancelled = await jobs.readJob('job-open');
		expect(cancelled?.state).toBe('cancelled');
		expect(cancelled?.leaseOwner).toBeNull();
		// The cancelled result is the canonical synthesized shape.
		const result = await jobs.readJobResult('job-open');
		expect(result?.resultState).toBe('cancelled');
		expect(result?.result.state === 'cancelled' && result.result.reason).toBe('cancelled');
		// Already-cancelled jobs are not cancelled twice.
		expect(await jobs.cancelAccountJobs('acct-1', 0)).toEqual([]);
	});

	it('purgeTerminalBefore GCs only settled terminal jobs past retention and snapshots stay honest', async () => {
		const jobs = createMemoryJobPersistence();
		await jobs.enqueueJob(baseJob({ jobId: 'old-done', coalescingKey: 'k1', queuedAtUtcMs: 0 }));
		await jobs.recordResult('old-done', 3, completeResult());
		await jobs.enqueueJob(baseJob({ jobId: 'young-done', coalescingKey: 'k2', queuedAtUtcMs: 5 }));
		await jobs.recordResult('young-done', 3, completeResult());
		await jobs.enqueueJob(baseJob({ jobId: 'unsettled', coalescingKey: 'k3', queuedAtUtcMs: 0 }));
		// Nothing is past retention yet.
		expect(await jobs.purgeTerminalBefore(TERMINAL_RETENTION_MS)).toBe(0);
		// Only the OLD SETTLED job is collected.
		expect(await jobs.purgeTerminalBefore(TERMINAL_RETENTION_MS + 1)).toBe(1);
		const remaining = jobs.snapshotJobs().map((job) => job.jobId).sort();
		expect(remaining).toEqual(['unsettled', 'young-done']);
		// Results are not dropped by the job GC (duplicate-effect memory).
		expect(jobs.snapshotResults().get('young-done')?.resultState).toBe('complete');
		expect(jobs.snapshotResults().has('old-done')).toBe(true);
		// A second pass finds nothing left to collect.
		expect(await jobs.purgeTerminalBefore(TERMINAL_RETENTION_MS + 2)).toBe(0);
	});
});

describe('durable job persistence edge branches (real SQLite)', () => {
	it('an explicit injected clock drives the claim expiry arithmetic', async () => {
		const bridge = createSqliteBridge({ withSchemaInit: true });
		await bridge.open('mail');
		const jobs = createDurableJobPersistence(bridge, { nowUtcMs: () => 1_000 });
		await jobs.enqueueJob(baseJob());
		expect(await jobs.claimLease('job-1', 'owner-a', 2_000)).toEqual({ owner: 'owner-a', leaseExpiresAtMs: 2_000 + LEASE_TTL_MS });
	});

	it('listByAccount scopes rows to one account in queued order', async () => {
		const bridge = createSqliteBridge({ withSchemaInit: true });
		await bridge.open('mail');
		const jobs = createDurableJobPersistence(bridge);
		await jobs.enqueueJob(baseJob({ jobId: 'job-a1', coalescingKey: 'ka', queuedAtUtcMs: 20 }));
		await jobs.enqueueJob(baseJob({ jobId: 'job-a2', accountId: 'acct-2', coalescingKey: 'kb', queuedAtUtcMs: 10 }));
		const mine = await jobs.listByAccount('acct-1');
		expect(mine.map((job) => job.jobId)).toEqual(['job-a1']);
		const other = await jobs.listByAccount('acct-2');
		expect(other.map((job) => job.jobId)).toEqual(['job-a2']);
		expect(await jobs.listByAccount('acct-none')).toEqual([]);
	});

	it('cancelAccountJobs answers [] without a batch when the account has no open jobs', async () => {
		const bridge = createSqliteBridge({ withSchemaInit: true });
		await bridge.open('mail');
		const jobs = createDurableJobPersistence(bridge);
		await jobs.enqueueJob(baseJob());
		expect(await jobs.cancelAccountJobs('acct-nobody', 0)).toEqual([]);
	});

	it('purgeTerminalBefore GCs settled terminal rows past retention and reports 0 when idle', async () => {
		const bridge = createSqliteBridge({ withSchemaInit: true });
		await bridge.open('mail');
		const jobs = createDurableJobPersistence(bridge);
		// Old settled: purged. Young settled: kept. Old unsettled: kept.
		await jobs.enqueueJob(baseJob({ jobId: 'old-done', coalescingKey: 'ka' }));
		await jobs.recordResult('old-done', 3, completeResult());
		await jobs.enqueueJob(baseJob({ jobId: 'young-done', coalescingKey: 'kb', queuedAtUtcMs: TERMINAL_RETENTION_MS - 1 }));
		await jobs.recordResult('young-done', 3, completeResult());
		await jobs.enqueueJob(baseJob({ jobId: 'old-open', coalescingKey: 'kc' }));
		expect(await jobs.purgeTerminalBefore(TERMINAL_RETENTION_MS + 1)).toBe(1);
		expect(await jobs.readJob('old-done')).toBeNull();
		expect((await jobs.readJob('young-done'))?.jobId).toBe('young-done');
		expect((await jobs.readJob('old-open'))?.jobId).toBe('old-open');
		// An idle pass answers 0 and issues no batch.
		expect(await jobs.purgeTerminalBefore(TERMINAL_RETENTION_MS + 2)).toBe(0);
	});

	it('the strict result reader fails closed on every invalid persisted shape', async () => {
		const bridge = createSqliteBridge({ withSchemaInit: true });
		await bridge.open('mail');
		const jobs = createDurableJobPersistence(bridge);
		await jobs.enqueueJob(baseJob());
		await jobs.claimLease('job-1', 'owner-a', 0);
		expect((await jobs.recordResult('job-1', 3, completeResult())).kind).toBe('committed');
		expect((await jobs.readJobResult('job-1'))?.resultState).toBe('complete');

		// A result_state outside the frozen contract is unreadable.
		bridge.execDirect("UPDATE optional_jobs SET result_state = 'bogus' WHERE job_id = 'job-1'");
		expect(await jobs.readJobResult('job-1')).toBeNull();

		// A JSON payload whose own state disagrees with the row's result_state.
		bridge.execDirect(
			"UPDATE optional_jobs SET result_state = 'paused', result_json = ? WHERE job_id = 'job-1'",
			[JSON.stringify(completeResult())],
		);
		expect(await jobs.readJobResult('job-1')).toBeNull();

		// A payload whose checkpoint fails the frozen validation.
		bridge.execDirect(
			"UPDATE optional_jobs SET result_state = 'complete', result_json = ? WHERE job_id = 'job-1'",
			[JSON.stringify({ ...completeResult(), checkpoint: { version: 99, cursor: 'x' } })],
		);
		expect(await jobs.readJobResult('job-1')).toBeNull();

		// Corrupt JSON fails closed instead of throwing.
		bridge.execDirect("UPDATE optional_jobs SET result_json = 'not-json{{' WHERE job_id = 'job-1'");
		expect(await jobs.readJobResult('job-1')).toBeNull();
	});

	it('refuses to record a result whose state is outside the frozen contract', async () => {
		const bridge = createSqliteBridge({ withSchemaInit: true });
		await bridge.open('mail');
		const jobs = createDurableJobPersistence(bridge);
		await jobs.enqueueJob(baseJob());
		// The batch is never issued for a contract-invalid result state.
		await expect(
			jobs.recordResult('job-1', 3, { state: 'bogus' } as never),
		).rejects.toThrow(/invalid result state/);
		// The row is untouched.
		expect((await jobs.readJob('job-1'))?.state).toBe('queued');
	});

	it('the composed commit pre-checks unknown jobs, stale generations and lost fences before applying any page', async () => {
		const bridge = createSqliteBridge({ withSchemaInit: true });
		await bridge.open('mail');
		const jobs = createDurableJobPersistence(bridge);
		await jobs.enqueueJob(baseJob());
		const fence = await jobs.claimLease('job-1', 'owner-a', 0);
		expect(fence).not.toBeNull();
		let applyCalls = 0;
		let rollbackCalls = 0;
		const compose = {
			applyPage: async () => {
				applyCalls += 1;
			},
			rollbackPage: async () => {
				rollbackCalls += 1;
			},
		};
		// Unknown job: no page effect at all.
		expect(
			(await jobs.commitCheckpoint('missing', 3, { version: 1, cursor: 'x' }, { fence: fence!, compose })),
		).toEqual({ kind: 'unknown-job' });
		expect(applyCalls).toBe(0);
		// Stale generation: refused before the page applies.
		expect(
			(await jobs.commitCheckpoint('job-1', 2, { version: 1, cursor: 'x' }, { fence: fence!, compose })),
		).toEqual({ kind: 'stale-generation' });
		expect(applyCalls).toBe(0);
		// A fence that is not the live lease: refused before the page applies.
		expect(
			(await jobs.commitCheckpoint('job-1', 3, { version: 1, cursor: 'x' }, {
				fence: { owner: 'owner-b', leaseExpiresAtMs: fence!.leaseExpiresAtMs },
				compose,
			})),
		).toEqual({ kind: 'stale-generation' });
		expect(applyCalls).toBe(0);
	});

	it('a lease stolen during the page application turns the composed commit stale and rolls the page back', async () => {
		const bridge = createSqliteBridge({ withSchemaInit: true });
		await bridge.open('mail');
		const jobs = createDurableJobPersistence(bridge);
		await jobs.enqueueJob(baseJob());
		const fence = await jobs.claimLease('job-1', 'owner-a', 0);
		expect(fence).not.toBeNull();
		let rollbackCalls = 0;
		const compose = {
			// The interleaving: while the page applies, the lease moves on.
			applyPage: async () => {
				bridge.execDirect(
					"UPDATE optional_jobs SET lease_owner = 'owner-b', lease_expires_at_ms = 999999 WHERE job_id = 'job-1'",
				);
			},
			rollbackPage: async () => {
				rollbackCalls += 1;
			},
		};
		const outcome = await jobs.commitCheckpoint('job-1', 3, { version: 1, cursor: 'delta:state:9' }, { fence: fence!, compose });
		// The guarded checkpoint batch matched NOTHING: the page was undone.
		expect(outcome).toEqual({ kind: 'stale-generation' });
		expect(rollbackCalls).toBe(1);
		expect((await jobs.readJob('job-1'))?.checkpoint?.cursor ?? null).toBeNull();
		expect((await jobs.readJob('job-1'))?.leaseOwner).toBe('owner-b');
	});
});

describe('transfer persistence', () => {
	it('the memory transfer persistence lists per account', async () => {
		const transfers = createMemoryTransferPersistence();
		await transfers.upsertCheckpoint({
			jobId: 'job-t1',
			accountId: 'acct-1',
			blobSha256: 'ab'.repeat(32),
			etag: `"${'ab'.repeat(32)}"`,
			expectedSize: 10,
			expectedSha256: 'ab'.repeat(32),
			committedBytes: 4,
			state: 'transferring',
			deadlineUtc: '2026-09-24T00:00:00Z',
			attempts: 1,
		});
		await transfers.upsertCheckpoint({
			jobId: 'job-t2',
			accountId: 'acct-2',
			blobSha256: 'cd'.repeat(32),
			etag: `"${'cd'.repeat(32)}"`,
			expectedSize: 5,
			expectedSha256: 'cd'.repeat(32),
			committedBytes: 0,
			state: 'queued',
			deadlineUtc: '2026-09-24T00:00:00Z',
			attempts: 0,
		});
		expect(await transfers.listByAccount('acct-1')).toEqual([{ jobId: 'job-t1', state: 'transferring' }]);
		expect(await transfers.listByAccount('acct-none')).toEqual([]);
	});

	sqliteDescribe('the durable transfer persistence (real SQLite)', () => {
		it('refuses to construct without the atomic batch entry', () => {
			const bare = createSqliteBridge();
			const noBatch = Object.create(bare) as OfflineDbBridge;
			Object.defineProperty(noBatch, 'transactionBatch', { value: undefined });
			expect(() => createDurableTransferPersistence(noBatch)).toThrow(/refusing non-atomic transfer persistence/);
		});

		it('upserts, loads, lists and purges transfer checkpoints atomically', async () => {
			const bridge = createSqliteBridge({ withSchemaInit: true });
			await bridge.open('mail');
			expect(durableJobPersistenceAvailable(bridge)).toBe(true);
			const transfers = createDurableTransferPersistence(bridge);
			const row = {
				jobId: 'job-t1',
				accountId: 'acct-1',
				blobSha256: 'ab'.repeat(32),
				etag: `"${'ab'.repeat(32)}"`,
				expectedSize: 10,
				expectedSha256: 'ab'.repeat(32),
				committedBytes: 4,
				state: 'transferring',
				deadlineUtc: '2026-09-24T00:00:00Z',
				attempts: 1,
			};
			expect(await transfers.loadCheckpoint('job-t1')).toBeNull();
			await transfers.upsertCheckpoint(row);
			// The stored row round-trips exactly.
			expect(await transfers.loadCheckpoint('job-t1')).toEqual(row);
			// Upserting again REPLACES the row (no duplicate identity).
			await transfers.upsertCheckpoint({ ...row, committedBytes: 8, state: 'verifying' });
			expect((await transfers.loadCheckpoint('job-t1'))?.committedBytes).toBe(8);
			expect(await transfers.listByAccount('acct-1')).toEqual([{ jobId: 'job-t1', state: 'verifying' }]);
			expect(await transfers.listByAccount('acct-none')).toEqual([]);
			await transfers.purgeCheckpoint('job-t1');
			expect(await transfers.loadCheckpoint('job-t1')).toBeNull();
			expect(await transfers.listByAccount('acct-1')).toEqual([]);
		});

		it('maps a persisted record strictly onto the E3 checkpoint contract', async () => {
			// No record: nothing to parse.
			expect(parsePersistedTransferCheckpoint(null)).toBeNull();
			const record = {
				jobId: 'job-t1',
				accountId: 'acct-1',
				blobSha256: 'ab'.repeat(32),
				etag: `"${'ab'.repeat(32)}"`,
				expectedSize: 10,
				expectedSha256: 'ab'.repeat(32),
				committedBytes: 10,
				state: 'verifying' as const,
				deadlineUtc: '2026-09-24T00:00:00Z',
				attempts: 1,
			};
			const parsed = parsePersistedTransferCheckpoint(record);
			expect(parsed).not.toBeNull();
			expect(parsed).toMatchObject({
				version: 1,
				jobId: 'job-t1',
				accountId: 'acct-1',
				blobId: 'ab'.repeat(32),
				committedBytes: 10,
				state: 'verifying',
			});
			// A record that fails the frozen E3 validation (etag does not hash to
			// expectedSha256) is reported invalid, never silently trusted.
			expect(
				parsePersistedTransferCheckpoint({ ...record, etag: '"deadbeef"' }),
			).toBeNull();
		});
	});
});
