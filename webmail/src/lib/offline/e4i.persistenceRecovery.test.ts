/**
 * CAS-E4I-PERSISTENCE-RECOVERY — E4-I verification binding (core lane).
 *
 * Native-transaction-freeze oracles against the N66 contract bridge:
 * migration interruption/retry/version skew, atomic page/checkpoint commit
 * (crash between writes exposes neither; after commit both), lease
 * reclaim/duplicate-effect rejection, and admission refusals for cross-app
 * handles, ordinary DDL, bare/nested transaction control through every entry,
 * and forged/untrusted migration registration.
 *
 * E4-I Astra corrections under test:
 * - The atomicity oracle composes the PRODUCTION page/checkpoint path
 *   (bounded step → staged page → job-store commit), not hand-built inserts.
 * - The durable store's lease semantics run against a REAL SQLite engine
 *   (node:sqlite): the NOT NULL release failure, the completed-job replay,
 *   the forever-stranded backoff, the unfenced stale writer and the
 *   lease-clobbering coalesce are reproduced exactly as reported and proven
 *   fixed under real constraint enforcement.
 * - The retained receipt is written ONCE, after every scenario finishes,
 *   from the ACTUAL auditor verdict over actually observed denials.
 *
 * The core-lane fake bridge proves the TS-side admission contract and the
 * atomic visibility model; real SQLCipher durability stays with the native
 * owner's crash harness (native lane), which cannot be certified by a mock.
 */

import { describe, it, expect, afterAll, afterEach } from 'vitest';
import { getCurrentTest } from 'vitest/suite';
import type { NativeDbAppKey, OfflineDbBridge } from '$lib/native/types';

let DatabaseSync: (typeof import('node:sqlite'))['DatabaseSync'] | null = null;
try {
	({ DatabaseSync } = await import('node:sqlite'));
} catch {
	// Node without node:sqlite: the real-SQL regressions skip; the TS oracles
	// still run. The retained receipt then honestly reports the gap.
}
const sqliteDescribe = DatabaseSync ? describe : describe.skip;

import {
	auditPersistenceRecovery,
	createContractBridge,
	createHarnessCoordinator,
	e4iFailure,
	gateVerdictOnScenarios,
	scenarioFailed,
	writeCaseResult,
	type ContractBridge,
} from '$lib/native/testing/backgroundWorkHarness';
import {
	applyMailMigrations,
	detectMailSchemaVersion,
	legacySchemaInitSql,
	MAIL_MIGRATION_MANIFEST,
	migrationManifestDigest,
	planMigration,
} from './migrations';
import { admitOrdinaryStatement, executeBatch } from './nativeBatch';
import { createStagedStore } from './stagedPage';
import { makeNativeStore, PageRollbackUnavailableError, RestoreAtomicityUnavailableError } from './store-native';
import {
	createDurableJobPersistence,
	createMemoryJobPersistence,
	durableJobPersistenceAvailable,
	LEASE_TTL_MS,
	type OptionalJobRecord,
} from './jobStore';
import type { Email } from '$lib/types/jmap';

const BUDGET = { maxStatements: 64, maxParamBytes: 1_048_576 };

// Real observations feed the auditor — never manufactured values.
const facts = {
	crashBeforeCommitExposedNothing: false,
	commitExposedBoth: false,
	leaseReclaimedOnce: false,
	duplicateEffectRejected: false,
	positiveOracleDemonstrated: false,
};
const collectedDenials: Array<{ entry: string; reason: string }> = [];

/** E4-I Astra correction (finding 14): every scenario's ACTUAL verdict gates
 * the retained receipt — a test that fails without flipping an auditor fact
 * can never hide behind a PASS verdict in afterAll. */
const scenarioFailures: string[] = [];
afterEach(() => {
	const task = getCurrentTest();
	const failure = scenarioFailed(task, task?.name ?? '');
	if (failure) scenarioFailures.push(failure);
});

function collectDenials(bridge: ContractBridge): void {
	for (const entry of bridge.log) {
		if (entry.disposition === 'refused' && entry.reason) {
			collectedDenials.push({ entry: entry.entry, reason: entry.reason });
		}
	}
}

/** Strip the FTS5 virtual table for the embedded engine (test-only scope:
 *  job/transfer oracles do not touch FTS and node builds may omit it). The
 *  production-composition oracle drives the REAL store (makeNativeStore),
 *  whose writes recompute FTS — pass `withFts` to keep the virtual table. */
function embeddedInitSql(options: { withFts?: boolean } = {}): string {
	const sql = legacySchemaInitSql({ version: 0, needsLegacyEligibilityReplay: false });
	const statements = sql.split(';\n');
	const filtered = options.withFts
		? statements
		: statements.filter((statement) => !statement.includes('USING fts5'));
	return filtered.join(';\n');
}

/** A REAL SQLite-backed bridge: genuine constraints, transactions, changes(). */
function createSqliteBridge(options: { withSchemaInit?: boolean; withFts?: boolean } = {}): OfflineDbBridge & { execSchemaInitCalls(): number } {
	const db = new DatabaseSync!(':memory:');
	let schemaInitCalls = 0;
	const bridge: OfflineDbBridge & { execSchemaInitCalls(): number } = {
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
			// Real atomicity: the whole batch commits or nothing does.
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
		async execSchemaInit(_appKey: NativeDbAppKey, sql: string) {
			schemaInitCalls += 1;
			db.exec(sql);
			return 0;
		},
		async wipe() {
			db.close();
		},
		execSchemaInitCalls() {
			return schemaInitCalls;
		},
	};
	if (options.withSchemaInit) {
		// Apply the real mail schema through the authorized one-shot seam.
		db.exec(embeddedInitSql({ withFts: options.withFts }));
	}
	return bridge;
}

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

function completeResult() {
	return {
		state: 'complete' as const,
		checkpoint: { version: 1 as const, cursor: 'delta:state:5' },
		progress: { done: 2, chargedUnits: 2 },
	};
}

function testEmail(id: string): Email {
	return {
		id,
		threadId: 't',
		mailboxIds: { Inbox: true },
		keywords: { $seen: true },
		receivedAt: '2026-09-01T00:00:00Z',
		hasAttachment: false,
		preview: '',
		subject: '',
	} as unknown as Email;
}

function storedSeed(id: string) {
	return {
		id,
		threadId: 't',
		receivedAt: Date.parse('2026-09-01T00:00:00Z'),
		flags: [],
		hasAttachment: false,
		cacheState: 'full' as const,
		syncedAt: 0,
		from: '',
		to: '',
		cc: '',
		bcc: '',
		subject: '',
		preview: '',
		tagIds: ['Inbox'],
		version: 0,
		dirtyFields: [],
	};
}

describe('CAS-E4I-PERSISTENCE-RECOVERY', () => {
	it('positive oracle: a committed batch exposes page and checkpoint together after reopen', async () => {
		const bridge = createContractBridge();
		await bridge.open('mail');
		// One atomic batch: the page write and the checkpoint write.
		const changed = await executeBatch(bridge, 'mail', [
			{ sql: 'INSERT OR REPLACE INTO meta_mail (key, value) VALUES (?, ?)', params: ['page:1', 'applied'] },
			{ sql: 'INSERT OR REPLACE INTO meta_mail (key, value) VALUES (?, ?)', params: ['checkpoint:job-1', 'cursor-state-5'] },
		], BUDGET);
		expect(changed).toBe(2);
		const page = await bridge.query('mail', 'SELECT value FROM meta_mail WHERE key = ?', ['page:1']);
		const checkpoint = await bridge.query('mail', 'SELECT value FROM meta_mail WHERE key = ?', ['checkpoint:job-1']);
		expect(page).toHaveLength(1);
		expect(checkpoint).toHaveLength(1);
		// A valid committed batch plus a bundled-migration success were shown.
		const migrate = createContractBridge();
		await migrate.open('mail');
		await applyMailMigrations(migrate);
		facts.positiveOracleDemonstrated = true;
	});

	it('production composition, crash case: a page failure exposes NEITHER the page nor the checkpoint', async () => {
		// Astra finding 18: the atomicity oracle must exercise the production
		// page/checkpoint composition, not two hand-built inserts.
		const store = createHarnessCoordinator({}).store;
		// Seed the row so the page STAGES a merge (which then fails at flush).
		await store.upsertMessage(storedSeed('1'));
		store.failNextMerge(new Error('simulated native page failure'));
		const coordinator = createHarnessCoordinator({
			store,
			pages: [{
				newState: '7', hasMoreChanges: false, created: ['1'], updated: [], destroyed: [],
				emails: [testEmail('1')],
			}],
		});
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await coordinator.runDueWork();
		const job = await coordinator.jobs.readJob('opt-reconnect-acct-1');
		// Neither the staged page nor the checkpoint is visible after the crash:
		// the seeded row is untouched and the cursor never advanced.
		const surviving = await store.getMessage('1');
		expect(surviving?.version ?? 0).toBe(0);
		expect(surviving?.flags ?? []).toEqual([]);
		expect(job?.checkpoint?.cursor ?? null).not.toBe('delta:state:7');
		facts.crashBeforeCommitExposedNothing = true;
	});

	it('production composition, success case: after commit the page and the checkpoint are BOTH visible', async () => {
		const store = createHarnessCoordinator({}).store;
		await store.upsertMessage(storedSeed('1'));
		const coordinator = createHarnessCoordinator({
			store,
			pages: [{
				newState: '7', hasMoreChanges: false, created: ['1'], updated: [], destroyed: [],
				emails: [testEmail('1')],
			}],
		});
		await coordinator.ingestTrigger({ kind: 'reconnect', accountId: 'acct-1', generation: 1 });
		await coordinator.runDueWork();
		const job = await coordinator.jobs.readJob('opt-reconnect-acct-1');
		const merged = await store.getMessage('1');
		// The committed page applied the merge (watermark advanced) AND the
		// durable checkpoint advanced with it — one atomic unit.
		expect((merged?.version ?? 0)).toBe(7);
		expect(job?.checkpoint?.cursor ?? null).toBe('delta:state:7');
		const read = await coordinator.readJobResult('opt-reconnect-acct-1');
		expect(read.kind === 'committed' && read.result.state).toBe('complete');
		facts.commitExposedBoth = true;
	});

	it('crash between writes exposes neither the page nor the checkpoint; after commit both', async () => {
		const crashed = createContractBridge({ fault: { crashBatchAtStatement: 1 } });
		await crashed.open('mail');
		await expect(executeBatch(crashed, 'mail', [
			{ sql: 'INSERT OR REPLACE INTO meta_mail (key, value) VALUES (?, ?)', params: ['page:2', 'applied'] },
			{ sql: 'INSERT OR REPLACE INTO meta_mail (key, value) VALUES (?, ?)', params: ['checkpoint:job-2', 'cursor-state-7'] },
		], BUDGET)).rejects.toThrow(/crashed before commit/);
		expect(await crashed.query('mail', 'SELECT value FROM meta_mail WHERE key = ?', ['page:2'])).toHaveLength(0);
		expect(await crashed.query('mail', 'SELECT value FROM meta_mail WHERE key = ?', ['checkpoint:job-2'])).toHaveLength(0);
	});

	it('migration interruption rolls back the interrupted step and retries cleanly', async () => {
		const bridge = createContractBridge({ fault: { crashAfterMigrationVersion: 1 } });
		const migrateStore = bridge.migrateStore!.bind(bridge) as NonNullable<typeof bridge.migrateStore>;
		await bridge.open('mail');
		await expect(migrateStore('mail', 2)).rejects.toThrow(/crashed between steps/);
		// v1 committed; v2 did not interleave.
		const detected = await detectMailSchemaVersion(bridge);
		expect(detected.version).toBe(1);
		// Retry completes the remaining step under the same serialization.
		const result = await migrateStore('mail', 2);
		expect(result.version).toBe(2);
		const after = await detectMailSchemaVersion(bridge);
		expect(after.version).toBe(2);
	});

	it('version skew: unknown, ahead, and downgrade targets are refused before mutation', async () => {
		const bridge = createContractBridge();
		const migrateStore = bridge.migrateStore!.bind(bridge) as NonNullable<typeof bridge.migrateStore>;
		await bridge.open('mail');
		await expect(migrateStore('mail', 99)).rejects.toThrow(/ahead-version/);
		await expect(migrateStore('mail', Number.NaN)).rejects.toThrow(/unknown-version/);
		await migrateStore('mail', 2);
		await expect(migrateStore('mail', 1)).rejects.toThrow(/downgrade/);
	});

	it('cross-app handles are refused through every entry', async () => {
		const bridge = createContractBridge({ authorizedAppKeys: ['mail'] });
		await expect(bridge.transactionBatch!('drive', [
			{ sql: 'INSERT OR REPLACE INTO meta_mail (key, value) VALUES (?, ?)', params: ['k', 'v'] },
		], BUDGET)).rejects.toThrow(/foreign-app-handle/);
		await expect(bridge.migrateStore!('drive', 1)).rejects.toThrow(/foreign-app-handle/);
		await expect(bridge.exec('drive', 'SELECT 1')).rejects.toThrow(/foreign-app-handle/);
		await expect(bridge.query('drive', 'SELECT 1')).rejects.toThrow(/foreign-app-handle/);
		collectDenials(bridge);
	});

	it('bare and nested transaction control is refused through every entry (parsed, not prefix-matched)', async () => {
		const bridge = createContractBridge();
		await bridge.open('mail');
		for (const [entry, attempt] of [
			['exec', () => bridge.exec('mail', 'BEGIN')],
			['exec', () => bridge.exec('mail', 'COMMIT')],
			['exec', () => bridge.exec('mail', 'ROLLBACK TRANSACTION')],
			['exec', () => bridge.exec('mail', 'END')],
			['exec', () => bridge.exec('mail', 'SAVEPOINT s1')],
			['exec', () => bridge.exec('mail', 'RELEASE SAVEPOINT s1')],
			['query', () => bridge.query('mail', 'BEGIN')],
			['batch', () => executeBatch(bridge, 'mail', [
				{ sql: "INSERT OR REPLACE INTO meta_mail (key, value) VALUES ('a', 'b')" },
				{ sql: 'BEGIN' },
			], BUDGET)],
			['batch-nested', () => executeBatch(bridge, 'mail', [
				{ sql: 'SAVEPOINT sp' },
				{ sql: 'SELECT 1' },
			], BUDGET)],
			['migrate-schema-init', () => bridge.execSchemaInit!('mail', 'CREATE TABLE t (x); BEGIN;')],
		] as const) {
			await expect(attempt()).rejects.toThrow(/transaction-control|refused/);
			void entry;
		}
		// Comments/strings carrying transaction keywords are NOT refused —
		// parsed authorization, never string-prefix matching.
		await bridge.exec('mail', "SELECT '-- not a BEGIN' AS note");
		await bridge.exec('mail', 'SELECT 1 -- BEGIN commentary');
		collectDenials(bridge);
	});

	it('ordinary DDL and pragmas are refused in job batches but allowed in the authorized init seam', async () => {
		const bridge = createContractBridge();
		await bridge.open('mail');
		await expect(executeBatch(bridge, 'mail', [
			{ sql: 'CREATE TABLE evil (x)' },
		], BUDGET)).rejects.toThrow(/forbidden-keyword|create/);
		await expect(bridge.exec('mail', 'PRAGMA bogus')).rejects.toThrow(/forbidden-keyword/);
		await expect(bridge.exec('mail', 'ATTACH DATABASE ? AS x')).rejects.toThrow(/forbidden-keyword/);
		// The authorized one-shot init seam is the ONLY DDL path (consumed once).
		await bridge.execSchemaInit!('mail', 'CREATE TABLE IF NOT EXISTS meta_mail (key TEXT);');
		await expect(bridge.execSchemaInit!('mail', 'CREATE TABLE another (x);')).rejects.toThrow(/one-shot-consumed/);
		collectDenials(bridge);
	});

	it('forged/untrusted migration registration is refused: only the bundled manifest binds', () => {
		// No runtime register entry exists at all; a caller-supplied manifest
		// with a different digest is refused before any statement is produced.
		const forged = { ...MAIL_MIGRATION_MANIFEST, steps: [] };
		expect(migrationManifestDigest(forged)).not.toBe(migrationManifestDigest(MAIL_MIGRATION_MANIFEST));
		expect(planMigration({ version: 0, needsLegacyEligibilityReplay: false }, 2, forged)).toEqual({
			kind: 'refused',
			reason: 'digest-mismatch',
		});
		expect(planMigration({ version: 0, needsLegacyEligibilityReplay: false }, 2, MAIL_MIGRATION_MANIFEST, 'drive')).toEqual({
			kind: 'refused',
			reason: 'foreign-app',
		});
		// The bundled manifest applies through both authorized paths.
		expect(planMigration({ version: 1, needsLegacyEligibilityReplay: false }, 2)).toEqual({
			kind: 'ok',
			steps: [MAIL_MIGRATION_MANIFEST.steps[1]],
			legacyReplays: [],
		});
	});

	it('CAS lease reclaim happens once after expiry and duplicate effects are rejected (memory model)', async () => {
		const jobs = createMemoryJobPersistence();
		await jobs.enqueueJob(baseJob());
		// The winner receives its stamped (owner, expiry) commit fence.
		expect(await jobs.claimLease('job-1', 'owner-a', 0)).toEqual({ owner: 'owner-a', leaseExpiresAtMs: LEASE_TTL_MS });
		// A second claim while leased fails; after expiry reclaim succeeds once.
		expect(await jobs.claimLease('job-1', 'owner-b', 1)).toBeNull();
		expect(await jobs.reclaimExpiredLeases(60_000)).toEqual(['job-1']);
		expect(await jobs.reclaimExpiredLeases(61_000)).toEqual([]);
		expect(await jobs.claimLease('job-1', 'owner-b', 61_000)).toEqual({ owner: 'owner-b', leaseExpiresAtMs: 61_000 + LEASE_TTL_MS });
		// Duplicate-effect rejection: the committed result is immutable at its
		// generation; a stale generation cannot overwrite it either.
		const result = completeResult();
		expect((await jobs.recordResult('job-1', 3, result)).kind).toBe('committed');
		expect((await jobs.recordResult('job-1', 3, result)).kind).toBe('stale-generation');
		facts.leaseReclaimedOnce = true;
		facts.duplicateEffectRejected = true;
	});

	it('a newer authenticated trigger restarts a completed job (memory model too)', async () => {
		// The pure core and the durable store share the trigger lifecycle: a
		// newer generation re-opens a terminal job as fresh runnable work.
		const jobs = createMemoryJobPersistence();
		await jobs.enqueueJob(baseJob({ triggerGeneration: 1 }));
		expect(await jobs.claimLease('job-1', 'owner-a', 0)).not.toBeNull();
		expect((await jobs.recordResult('job-1', 1, completeResult())).kind).toBe('committed');
		const outcome = await jobs.enqueueJob(baseJob({ triggerGeneration: 2 }));
		expect(outcome.kind).toBe('coalesced');
		const restarted = await jobs.readJob('job-1');
		expect(restarted?.state).toBe('queued');
		expect(restarted?.triggerGeneration).toBe(2);
		expect(await jobs.readJobResult('job-1')).toBeNull();
		// After the superseded writer's lease clears, the fresh generation is due.
		await jobs.reclaimExpiredLeases(60_000);
		expect((await jobs.listDue(60_000)).map((job) => job.jobId)).toEqual(['job-1']);
	});

	it('a merge that fails mid-application is fully rolled back: the undo precedes the apply (r5)', async () => {
		// Astra r5 finding 2 reproduction: the undo entry was registered only
		// AFTER the awaited apply returned, but the native merge updates the
		// message row BEFORE its FTS work — a failure inside that call left the
		// mutated row exposed with no undo for it (subject changed while the
		// checkpoint stayed uncommitted).
		const underlying = createHarnessCoordinator({}).store;
		await underlying.upsertMessage(storedSeed('1'));
		const originalMerge = underlying.mergeServerDelta.bind(underlying);
		underlying.mergeServerDelta = async (id, changed, serverVersion) => {
			// The real native merge shape: mutate the row FIRST, then fail.
			await originalMerge(id, changed, serverVersion);
			throw new Error('fts write failed after the row was updated');
		};
		const staged = createStagedStore(underlying);
		await staged.mergeServerDelta('1', { subject: 'changed-in-page' }, 9);
		await expect(staged.flushAllOrNothing()).rejects.toThrow(/fts write failed/);
		// The undo ran for the FAILED operation too: the row is exactly its
		// prior self — neither the staged subject nor the watermark survived.
		const row = await underlying.getMessage('1');
		expect(row?.subject).not.toBe('changed-in-page');
		expect(row?.subject ?? '').toBe('');
		expect(row?.version ?? 0).toBe(0);
		// After the rollback nothing is retained: a later flush is a no-op.
		expect(staged.stagedCount).toBe(0);
	});

	it('a concurrent local edit on a field the page did not stage survives the rollback (r6)', async () => {
		// Astra r6 finding 2 reproduction: the rollback restored the full
		// pre-page row through the whole-row native upsert, clobbering a
		// concurrent local edit that landed on the SAME row between the
		// page's apply and its rollback.
		const underlying = createHarnessCoordinator({}).store;
		const seed = storedSeed('1');
		await underlying.upsertMessage(seed);
		const staged = createStagedStore(underlying);
		// The staged page touches ONLY the subject.
		await staged.mergeServerDelta('1', { subject: 'server-subject' }, 9);
		await staged.flushAllOrNothing();
		// A concurrent local edit lands on the UNDERLYING store (the
		// optimistic-edit passthrough writes there by design): it changes
		// flags — a field the page never staged — and bumps the local
		// watermark, exactly the row shape the native optimistic write leaves.
		const applied = await underlying.getMessage('1');
		await underlying.upsertMessage({
			...applied!,
			flags: ['$flagged'],
			version: 10,
			dirtyFields: ['flags'],
		});
		// The checkpoint half of the composition fails: the page rolls back.
		await staged.rollbackAppliedPage();
		const row = await underlying.getMessage('1');
		// The staged field returned to its prior value...
		expect(row?.subject).toBe('');
		// ...while the concurrent local edit SURVIVED (flags AND watermark).
		expect(row?.flags).toEqual(['$flagged']);
		expect(row?.version).toBe(10);
		expect(row?.dirtyFields).toEqual(['flags']);
	});

	it('a concurrent local edit on a staged field wins the rollback (r6)', async () => {
		// The same trace with the edit landing on a field the page DID stage:
		// the rewrite is no longer the staged value, so the rollback preserves
		// the edit instead of restoring the pre-page content over it.
		const underlying = createHarnessCoordinator({}).store;
		await underlying.upsertMessage(storedSeed('1'));
		const staged = createStagedStore(underlying);
		await staged.mergeServerDelta('1', { subject: 'server-subject' }, 9);
		await staged.flushAllOrNothing();
		// The concurrent local edit rewrites the STAGED field itself.
		const applied = await underlying.getMessage('1');
		await underlying.upsertMessage({
			...applied!,
			subject: 'local-edit-subject',
			version: 10,
			dirtyFields: ['subject'],
		});
		await staged.rollbackAppliedPage();
		const row = await underlying.getMessage('1');
		// The un-acked local edit wins (F1): the staged value is not restored.
		expect(row?.subject).toBe('local-edit-subject');
		expect(row?.dirtyFields).toEqual(['subject']);
	});

	it('a concurrent local edit rewriting a staged field to the SAME value survives the rollback (r9)', async () => {
		// Astra r8 P1 reproduction: the rollback compared only the staged
		// post-image VALUE, so a concurrent local edit that rewrote a staged
		// field to exactly the staged value passed the comparison and was
		// clobbered back to the pre-page content. Comparison-by-value cannot
		// distinguish "untouched" from "rewritten to the same value" — the
		// current row's dirty generation (and bumped watermark) is the
		// ownership record for that ABA case.
		const underlying = createHarnessCoordinator({}).store;
		await underlying.upsertMessage(storedSeed('1'));
		const staged = createStagedStore(underlying);
		await staged.mergeServerDelta('1', { subject: 'server-subject' }, 9);
		await staged.flushAllOrNothing();
		// The concurrent local edit rewrites the staged field to the SAME
		// value and bumps the local watermark — exactly the row shape the
		// native optimistic write leaves (version +1, dirtyFields claimed).
		const applied = await underlying.getMessage('1');
		await underlying.upsertMessage({
			...applied!,
			subject: 'server-subject',
			version: 10,
			dirtyFields: ['subject'],
		});
		await staged.rollbackAppliedPage();
		const row = await underlying.getMessage('1');
		// The same-value local edit SURVIVES (F1): the field was claimed by
		// the row's dirty generation, so value equality alone does not own it.
		expect(row?.subject).toBe('server-subject');
		expect(row?.version).toBe(10);
		expect(row?.dirtyFields).toEqual(['subject']);
	});

	it('an untouched row (same version) still rolls back fully (r9)', async () => {
		// The r9 dirty-generation guard must not weaken the r6 contract:
		// a row NO concurrent writer touched rolls its staged fields AND its
		// watermark back completely.
		const underlying = createHarnessCoordinator({}).store;
		await underlying.upsertMessage(storedSeed('1'));
		const staged = createStagedStore(underlying);
		await staged.mergeServerDelta('1', { subject: 'server-subject' }, 9);
		await staged.flushAllOrNothing();
		await staged.rollbackAppliedPage();
		const row = await underlying.getMessage('1');
		expect(row?.subject).toBe('');
		expect(row?.version ?? 0).toBe(0);
		expect(row?.dirtyFields ?? []).toEqual([]);
	});

	it('a local edit landing between the rollback snapshot and its restore survives (r11)', async () => {
		// Astra r10 P1 reproduction: restoreRow snapshotted the current row and
		// then wrote a WHOLE merged row through the whole-row `upsertMessage`.
		// A local optimistic edit committing between that snapshot and the
		// restore write was still clobbered by the whole-row replace — the r9
		// tests land their edits BEFORE the rollback begins, so they never
		// exercised the interleaving. The restore now runs through the store
		// seam's atomic per-field conditional primitive, which re-compares
		// every field's CURRENT value INSIDE the write operation.
		const underlying = createHarnessCoordinator({}).store;
		await underlying.upsertMessage(storedSeed('1'));
		const staged = createStagedStore(underlying);
		// The staged page touches the subject AND the preview.
		await staged.mergeServerDelta('1', { subject: 'server-subject', preview: 'server-preview' }, 9);
		await staged.flushAllOrNothing();
		// Store seam hook: the concurrent optimistic edit commits right AFTER
		// the rollback's snapshot read returns the pre-edit row but BEFORE the
		// restore executes — exactly the window the old read-then-write
		// rollback left open. The edit rewrites the SUBJECT, bumps the local
		// watermark and claims the field, exactly the native optimistic shape.
		const originalGet = underlying.getMessage.bind(underlying);
		let editLanded = false;
		underlying.getMessage = async (id: string) => {
			const row = await originalGet(id);
			if (row && !editLanded && row.subject === 'server-subject') {
				editLanded = true;
				const applied = await originalGet(id);
				await underlying.upsertMessage({
					...applied!,
					subject: 'local-edit-subject',
					version: 11,
					dirtyFields: ['subject'],
				});
			}
			return row;
		};
		await staged.rollbackAppliedPage();
		underlying.getMessage = originalGet;
		const row = await underlying.getMessage('1');
		// The concurrent edit SURVIVED: the primitive's per-field comparison
		// ran against the post-edit row, so the rewritten subject (differing
		// value AND dirty claim) and the bumped watermark failed their
		// predicates and were skipped.
		expect(editLanded).toBe(true);
		expect(row?.subject).toBe('local-edit-subject');
		expect(row?.version).toBe(11);
		expect(row?.dirtyFields).toEqual(['subject']);
		// ...while the staged field the edit did not touch still rolled back.
		expect(row?.preview).toBe('');
	});

	it('the restore primitive restores unchanged fields and refuses a missing row (r11)', async () => {
		// The primitive itself, pinned at the store boundary: clean restore
		// path and the absent-row contract the rollback's guards rely on.
		const underlying = createHarnessCoordinator({}).store;
		await underlying.upsertMessage({ ...storedSeed('1'), subject: 'staged-subject', version: 9 });
		expect(
			await underlying.restoreFieldsIfUnchanged('1', { subject: 'staged-subject', version: 9 }, { subject: 'prior-subject', version: 0 }),
		).toBe(true);
		const row = await underlying.getMessage('1');
		expect(row?.subject).toBe('prior-subject');
		expect(row?.version).toBe(0);
		expect(await underlying.restoreFieldsIfUnchanged('missing', { subject: 'x' }, { subject: 'y' })).toBe(false);
	});

	it('the composed commit re-verifies the fence after its async page application (r5)', async () => {
		// Astra r5 finding 3 reproduction: the fence/generation check ran only
		// BEFORE applyPage; the checkpoint write then restored the pre-await
		// snapshot, overwriting a cancellation recorded during the page's await.
		const jobs = createMemoryJobPersistence();
		await jobs.enqueueJob(baseJob());
		const fence = await jobs.claimLease('job-1', 'owner-a', 0);
		expect(fence).not.toBeNull();
		let pageFlushStarted: (() => void) | null = null;
		const flushStarted = new Promise<void>((resolve) => {
			pageFlushStarted = resolve;
		});
		let releaseApplication: (() => void) | null = null;
		const applicationGate = new Promise<void>((resolve) => {
			releaseApplication = resolve;
		});
		let rollbackCalls = 0;
		const compose = {
			applyPage: async () => {
				// The staged flush is async: it opens the interleaving window and
				// only resolves once the cancellation has landed inside it.
				pageFlushStarted!();
				await applicationGate;
			},
			rollbackPage: () => {
				rollbackCalls += 1;
				return Promise.resolve();
			},
		};
		const commit = jobs.commitCheckpoint('job-1', 3, { version: 1, cursor: 'delta:state:9' }, { fence: fence!, compose });
		await flushStarted;
		// The durable account cancellation lands DURING the page application.
		expect(await jobs.cancelAccountJobs('acct-1', 1)).toEqual(['job-1']);
		releaseApplication!();
		// The composition lost the race: no checkpoint commit, and the applied
		// page was rolled back — the cancellation is not overwritten.
		expect((await commit).kind).toBe('stale-generation');
		expect(rollbackCalls).toBe(1);
		const job = await jobs.readJob('job-1');
		expect(job?.state).toBe('cancelled');
		expect(job?.checkpoint?.cursor ?? null).toBeNull();
		const result = await jobs.readJobResult('job-1');
		expect(result?.resultState).toBe('cancelled');
	});

	it('durable persistence fails closed without the native batch entry and admits with it', async () => {
		const bare = createContractBridge();
		// Simulate a shell without the E4-I entries by hiding the symbols.
		const noBatch = Object.create(bare) as typeof bare;
		Object.defineProperty(noBatch, 'transactionBatch', { value: undefined });
		Object.defineProperty(noBatch, 'migrateStore', { value: undefined });
		expect(durableJobPersistenceAvailable(noBatch)).toBe(false);
		expect(() => createDurableJobPersistence(noBatch)).toThrow(/refuses non-atomic storage/);
		const durable = createDurableJobPersistence(createContractBridge());
		expect(durable).toBeTruthy();
	});

	it('legacy composition preserves the historical one-shot SQL contract', async () => {
		const fresh = legacySchemaInitSql({ version: 0, needsLegacyEligibilityReplay: false });
		expect(fresh).toContain('CREATE TABLE IF NOT EXISTS messages');
		expect(fresh).toContain('CREATE TABLE IF NOT EXISTS optional_jobs');
		expect(fresh).not.toContain('ALTER TABLE');
		const legacyDev = legacySchemaInitSql({ version: 0, needsLegacyEligibilityReplay: true });
		expect(legacyDev).toContain("ALTER TABLE recovery_artifacts ADD COLUMN eligibility");
		const current = legacySchemaInitSql({ version: 2, needsLegacyEligibilityReplay: false });
		expect(current).toBe('');
		// The execSchemaInit path applies the composed SQL through the seam on a
		// shell that lacks the E4-I native entries.
		const bareBridge = createContractBridge();
		const legacyShell = Object.create(bareBridge) as typeof bareBridge;
		Object.defineProperty(legacyShell, 'transactionBatch', { value: undefined });
		Object.defineProperty(legacyShell, 'migrateStore', { value: undefined });
		await legacyShell.open('mail');
		const result = await applyMailMigrations(legacyShell);
		expect(result.via).toBe('execSchemaInit');
		const detected = await detectMailSchemaVersion(legacyShell);
		expect(detected.version).toBe(2);
	});

	it('planted faults produce the pinned FAIL text with distinct finite causes', () => {
		const pinned = e4iFailure('CAS-E4I-PERSISTENCE-RECOVERY', 'probe');
		expect(pinned.fail).toBe(
			'FAIL CAS-E4I-PERSISTENCE-RECOVERY: page/checkpoint atomicity or bridge admission contract failed',
		);
		const verdict = auditPersistenceRecovery({
			denials: [
				{ entry: 'exec', reason: 'transaction-control' },
				{ entry: 'transactionBatch', reason: 'transaction-control' },
				{ entry: 'migrateStore', reason: 'downgrade' },
			],
			crashBeforeCommitExposedNothing: false,
			commitExposedBoth: true,
			leaseReclaimedOnce: true,
			duplicateEffectRejected: true,
			positiveOracleDemonstrated: true,
		});
		expect(verdict.ok).toBe(false);
		expect(verdict.fail).toBe(pinned.fail);
		expect(verdict.cause).toBe('subOracleId=crash-before-commit-exposed-state lane=core');

		const duplicate = auditPersistenceRecovery({
			denials: [
				{ entry: 'exec', reason: 'transaction-control' },
				{ entry: 'exec', reason: 'transaction-control' },
			],
			crashBeforeCommitExposedNothing: true,
			commitExposedBoth: true,
			leaseReclaimedOnce: true,
			duplicateEffectRejected: false,
			positiveOracleDemonstrated: true,
		});
		expect(duplicate.cause).toBe('subOracleId=duplicate-effect-accepted lane=core');
		expect(duplicate.cause).not.toBe(verdict.cause);

		const indistinct = auditPersistenceRecovery({
			denials: [
				{ entry: 'exec', reason: 'transaction-control' },
				{ entry: 'exec', reason: 'transaction-control' },
			],
			crashBeforeCommitExposedNothing: true,
			commitExposedBoth: true,
			leaseReclaimedOnce: true,
			duplicateEffectRejected: true,
			positiveOracleDemonstrated: true,
		});
		expect(indistinct.cause).toBe('subOracleId=denial-cause-not-distinct lane=core');
	});

	it('ordinary exec/query admission parity rejects transaction control before any bridge call', () => {
		expect(admitOrdinaryStatement('BEGIN')).toEqual({ kind: 'refused', reason: 'transaction-control', detail: 'keyword=begin' });
		expect(admitOrdinaryStatement('commit; SELECT 1')).toEqual({ kind: 'refused', reason: 'multi-statement', detail: 'statement-separator' });
		expect(admitOrdinaryStatement('SELECT 1')).toEqual({ kind: 'ok' });
	});
});

// ── real-SQL durable lease regressions (Astra findings 3-6) ─────────────────

sqliteDescribe('CAS-E4I-PERSISTENCE-RECOVERY: durable store over real SQLite', () => {
	it('a normal options-free lease release succeeds and preserves attempts (NOT NULL holds)', async () => {
		// Astra finding 3 reproduction: omitted options used to write NULL into
		// the NOT NULL attempts column — "NOT NULL constraint failed".
		const bridge = createSqliteBridge({ withSchemaInit: true });
		await bridge.open('mail');
		const jobs = createDurableJobPersistence(bridge);
		await jobs.enqueueJob(baseJob());
		// The claim returns the winner's (owner, expiry) commit fence — exactly
		// the values the winning UPDATE wrote, with no post-claim read.
		expect(await jobs.claimLease('job-1', 'owner-a', 0)).toEqual({ owner: 'owner-a', leaseExpiresAtMs: LEASE_TTL_MS });
		await expect(jobs.releaseLease('job-1', 'owner-a')).resolves.toBeUndefined();
		const afterRelease = await jobs.readJob('job-1');
		expect(afterRelease?.state).toBe('queued');
		expect(afterRelease?.attempts).toBe(0);
		// An explicit attempts update still lands.
		expect(await jobs.claimLease('job-1', 'owner-a', 1)).toEqual({ owner: 'owner-a', leaseExpiresAtMs: 1 + LEASE_TTL_MS });
		await jobs.releaseLease('job-1', 'owner-a', { backoff: true, retryAtUtcMs: 6, attempts: 2 });
		const afterBackoff = await jobs.readJob('job-1');
		expect(afterBackoff?.attempts).toBe(2);
		expect(afterBackoff?.state).toBe('backoff');
	});

	it('a completed job never replays after its lease release', async () => {
		// Astra finding 4a reproduction: the post-completion release reset the
		// job to `queued`, so the completed work ran again forever.
		const bridge = createSqliteBridge({ withSchemaInit: true });
		await bridge.open('mail');
		const jobs = createDurableJobPersistence(bridge);
		await jobs.enqueueJob(baseJob());
		expect(await jobs.claimLease('job-1', 'owner-a', 0)).toEqual({ owner: 'owner-a', leaseExpiresAtMs: LEASE_TTL_MS });
		expect((await jobs.recordResult('job-1', 3, completeResult())).kind).toBe('committed');
		await jobs.releaseLease('job-1', 'owner-a');
		const after = await jobs.readJob('job-1');
		expect(after?.state).toBe('complete');
		expect(await jobs.listDue(60_000)).toEqual([]);
		expect(await jobs.claimLease('job-1', 'owner-b', 60_000)).toBeNull();
	});

	it('a newer authenticated trigger restarts a completed job as fresh runnable work', async () => {
		// Astra r2 finding 3 reproduction (regression from finding 4): the
		// coalesce advanced the generation but left the terminal state, so a
		// completed job accepted the newer trigger and the due queue stayed
		// empty — new triggers could never restart completed work.
		const bridge = createSqliteBridge({ withSchemaInit: true });
		await bridge.open('mail');
		const jobs = createDurableJobPersistence(bridge);
		await jobs.enqueueJob(baseJob({ triggerGeneration: 1 }));
		expect(await jobs.claimLease('job-1', 'owner-a', 0)).not.toBeNull();
		expect((await jobs.recordResult('job-1', 1, completeResult())).kind).toBe('committed');
		expect(await jobs.readJobResult('job-1')).not.toBeNull();
		expect(await jobs.listDue(60_000)).toEqual([]);
		// A materially newer trigger re-opens the job as RUNNABLE work.
		const outcome = await jobs.enqueueJob(baseJob({ triggerGeneration: 2 }));
		expect(outcome.kind).toBe('coalesced');
		const restarted = await jobs.readJob('job-1');
		expect(restarted?.triggerGeneration).toBe(2);
		expect(restarted?.state).toBe('queued');
		expect(restarted?.attempts).toBe(0);
		// The superseded result is no longer readable as the new run's own.
		expect(await jobs.readJobResult('job-1')).toBeNull();
		// The superseded writer's live lease is preserved untouched: the job
		// becomes due the moment that lease clears (release or expiry).
		expect(await jobs.listDue(0)).toEqual([]);
		expect(await jobs.reclaimExpiredLeases(60_000)).toEqual(['job-1']);
		const due = await jobs.listDue(60_000);
		expect(due.map((job) => job.jobId)).toEqual(['job-1']);
	});

	it('reclaiming the lease of a completed job keeps it terminal', async () => {
		// A crash between recordResult(complete) and the lease release leaves a
		// terminal job leased; the reclaim must clear the lease WITHOUT
		// returning the completed job to the queue.
		const bridge = createSqliteBridge({ withSchemaInit: true });
		await bridge.open('mail');
		const jobs = createDurableJobPersistence(bridge);
		await jobs.enqueueJob(baseJob());
		expect(await jobs.claimLease('job-1', 'owner-a', 0)).not.toBeNull();
		expect((await jobs.recordResult('job-1', 3, completeResult())).kind).toBe('committed');
		// The lease is still held; after expiry the reclaim picks it up.
		expect(await jobs.reclaimExpiredLeases(60_000)).toEqual(['job-1']);
		expect(await jobs.reclaimExpiredLeases(61_000)).toEqual([]);
		const after = await jobs.readJob('job-1');
		expect(after?.state).toBe('complete');
		expect(after?.leaseOwner).toBeNull();
		expect(await jobs.claimLease('job-1', 'owner-b', 61_000)).toBeNull();
	});

	it('a backoff job becomes due again once its retry deadline passes', async () => {
		// Astra finding 4b reproduction: backoff jobs were excluded from listDue
		// forever, stranding the retry even after its deadline.
		const bridge = createSqliteBridge({ withSchemaInit: true });
		await bridge.open('mail');
		const jobs = createDurableJobPersistence(bridge);
		await jobs.enqueueJob(baseJob());
		expect(await jobs.claimLease('job-1', 'owner-a', 0)).not.toBeNull();
		await jobs.releaseLease('job-1', 'owner-a', { backoff: true, retryAtUtcMs: 100, attempts: 1 });
		expect((await jobs.readJob('job-1'))?.state).toBe('backoff');
		// Before the deadline: not due.
		expect(await jobs.listDue(99)).toEqual([]);
		expect(await jobs.claimLease('job-1', 'owner-b', 99)).toBeNull();
		// After the deadline: due again, claimable.
		const due = await jobs.listDue(100);
		expect(due.map((job) => job.jobId)).toEqual(['job-1']);
		expect(await jobs.claimLease('job-1', 'owner-b', 100)).toEqual({ owner: 'owner-b', leaseExpiresAtMs: 100 + LEASE_TTL_MS });
		expect((await jobs.readJob('job-1'))?.state).toBe('running');
	});

	it('reclaim fences the expired writer: a stale claimant cannot commit checkpoints or results', async () => {
		// Astra finding 5 reproduction: checkpoint/result writes were guarded
		// only by trigger generation, so after A expired and B claimed the same
		// generation, A could still commit.
		const bridge = createSqliteBridge({ withSchemaInit: true });
		await bridge.open('mail');
		const jobs = createDurableJobPersistence(bridge);
		await jobs.enqueueJob(baseJob());
		const fenceA = await jobs.claimLease('job-1', 'owner-a', 0);
		expect(fenceA).toEqual({ owner: 'owner-a', leaseExpiresAtMs: LEASE_TTL_MS });
		// A's lease expires; B claims the SAME job at the SAME generation.
		expect(await jobs.reclaimExpiredLeases(60_000)).toEqual(['job-1']);
		const fenceB = await jobs.claimLease('job-1', 'owner-b', 60_000);
		expect(fenceB).toEqual({ owner: 'owner-b', leaseExpiresAtMs: 60_000 + LEASE_TTL_MS });
		expect(
			(await jobs.commitCheckpoint('job-1', 3, { version: 1, cursor: 'delta:state:9' }, { fence: fenceA! })).kind,
		).toBe('stale-generation');
		expect(
			(await jobs.recordResult('job-1', 3, completeResult(), fenceA!)).kind,
		).toBe('stale-generation');
		// The stale writer left NO trace.
		const untouched = await jobs.readJob('job-1');
		expect(untouched?.checkpoint?.cursor ?? null).toBeNull();
		expect(await jobs.readJobResult('job-1')).toBeNull();
		// The live claimant commits normally under its own fence.
		expect(
			(await jobs.commitCheckpoint('job-1', 3, { version: 1, cursor: 'delta:state:5' }, { fence: fenceB! })).kind,
		).toBe('committed');
		expect(
			(await jobs.recordResult('job-1', 3, completeResult(), fenceB!)).kind,
		).toBe('committed');
		expect((await jobs.readJob('job-1'))?.checkpoint?.cursor ?? null).toBe('delta:state:5');
		facts.leaseReclaimedOnce = true;
	});

	it('coalescing never clobbers a concurrent lease and never drops result columns', async () => {
		// Astra finding 6 reproduction: read-then-INSERT OR REPLACE restored a
		// previously read unleased row over a racing claim, and replaced rows
		// lost every omitted column (result_state/result_json went NULL).
		const bridge = createSqliteBridge({ withSchemaInit: true });
		await bridge.open('mail');
		const jobs = createDurableJobPersistence(bridge);
		await jobs.enqueueJob(baseJob({ triggerGeneration: 1 }));
		expect(await jobs.claimLease('job-1', 'owner-a', 0)).not.toBeNull();
		// A duplicate trigger coalesces WHILE the lease is live.
		const outcome = await jobs.enqueueJob(baseJob({ triggerGeneration: 2 }));
		expect(outcome.kind).toBe('coalesced');
		const afterCoalesce = await jobs.readJob('job-1');
		// The live lease survived the coalesce.
		expect(afterCoalesce?.leaseOwner).toBe('owner-a');
		expect(afterCoalesce?.state).toBe('running');
		// A recorded result survives a later coalesce: no column is dropped.
		expect(
			(await jobs.recordResult('job-1', 2, {
				state: 'paused',
				reason: 'networkUnavailable',
				checkpoint: { version: 1, cursor: 'delta:state:2' },
				progress: { done: 1, chargedUnits: 1 },
			})).kind,
		).toBe('committed');
		const reopened = await jobs.enqueueJob(baseJob({ triggerGeneration: 5 }));
		expect(reopened.kind).toBe('coalesced');
		const result = await jobs.readJobResult('job-1');
		expect(result?.resultState).toBe('paused');
		expect(result?.result.state === 'paused' && result.result.reason).toBe('networkUnavailable');
		// A stale trigger is still refused without touching the row.
		const stale = await jobs.enqueueJob(baseJob({ triggerGeneration: 4 }));
		expect(stale.kind).toBe('rejected-stale-generation');
	});

	it('an already-current durable store re-opens without re-issuing the one-shot init', async () => {
		// Astra finding 1: reopen used to submit an empty execSchemaInit batch.
		const bridge = createSqliteBridge();
		await bridge.open('mail');
		const first = await applyMailMigrations(bridge);
		expect(first.via).toBe('execSchemaInit');
		const reopen = await applyMailMigrations(bridge);
		expect(reopen).toEqual({ version: 2, via: 'current' });
		// The one-shot seam was consumed EXACTLY once across both opens.
		expect(bridge.execSchemaInitCalls()).toBe(1);
		expect((await detectMailSchemaVersion(bridge)).version).toBe(2);
	});

	it('an interrupted legacy init is never mistaken for a current store', async () => {
		// Astra r2 finding 10 reproduction: the legacy eligibility replay is
		// composed AFTER both optional tables, so an interrupted init can leave
		// optional_jobs/attachment_transfers present with the replay missing.
		// Detection used to report a plain-current store; the replay was lost.
		const bridge = createSqliteBridge();
		await bridge.open('mail');
		// Model the interrupted legacy state EXACTLY: the historical
		// pre-versioning recovery_artifacts DDL (NO eligibility column — the
		// replay had not run yet), then both v2 optional tables.
		const v1 = MAIL_MIGRATION_MANIFEST.steps.find((step) => step.targetVersion === 1)!.statements;
		const v2 = MAIL_MIGRATION_MANIFEST.steps.find((step) => step.targetVersion === 2)!.statements;
		const legacyRecoveryDdl = v1
			.find((sql) => sql.includes('CREATE TABLE IF NOT EXISTS recovery_artifacts'))!
			.split('\n')
			.filter((line) => !/^\s*eligibility\b/.test(line))
			.join('\n');
		const interruptedLegacySql = v1
			.map((sql) => (sql.includes('CREATE TABLE IF NOT EXISTS recovery_artifacts') ? legacyRecoveryDdl : sql))
			.concat(v2)
			.filter((sql) => !sql.includes('USING fts5'))
			.map((sql) => `${sql};`)
			.join('\n');
		await bridge.execSchemaInit!('mail', interruptedLegacySql);
		// Sanity: the interrupted shape has optional tables but no eligibility.
		const detected = await detectMailSchemaVersion(bridge);
		expect(detected.version).toBe(2);
		expect(detected.needsLegacyEligibilityReplay).toBe(true);
		// Initialization does NOT report a current store: it applies the replay.
		const applied = await applyMailMigrations(bridge);
		expect(applied.via).toBe('execSchemaInit');
		// The eligibility column now exists.
		await bridge.exec(
			'mail',
			"INSERT INTO recovery_artifacts (artifact_identity, message_id, account_id, mailbox_id, installation_id, raw_sha256, raw_size, received_at, timeline_generation, boot_epoch, state_watermark, receipt, eligibility, verified_at) VALUES ('a', 'm', 'acc', 'mb', 'inst', ?, 1, 0, 't', 'b', 'w', 'r', 'received', 0)",
			['aa'.repeat(32)],
		);
		const after = await detectMailSchemaVersion(bridge);
		expect(after).toEqual({ version: 2, needsLegacyEligibilityReplay: false });
	});

	it('the composed commit is failure-atomic: an injected checkpoint failure exposes neither page nor checkpoint', async () => {
		// Astra r2 finding 1 reproduction: the page used to stay applied with the
		// OLD checkpoint when the checkpoint half of the composition failed.
		const bridge = createSqliteBridge({ withSchemaInit: true, withFts: true });
		await bridge.open('mail');
		const nativeStore = makeNativeStore(bridge);
		await nativeStore.upsertMessage(storedSeed('1'));
		const staged = createStagedStore(nativeStore);
		let failCheckpointBatches = false;
		const flakyBridge: OfflineDbBridge = Object.create(bridge);
		Object.defineProperty(flakyBridge, 'transactionBatch', {
			value: async (appKey: NativeDbAppKey, statements: Parameters<NonNullable<OfflineDbBridge['transactionBatch']>>[1], budget: Parameters<NonNullable<OfflineDbBridge['transactionBatch']>>[2]) => {
				if (failCheckpointBatches) throw new Error('injected checkpoint failure');
				return bridge.transactionBatch!(appKey, statements, budget);
			},
		});
		const jobs = createDurableJobPersistence(flakyBridge);
		await jobs.enqueueJob(baseJob());
		const fence = await jobs.claimLease('job-1', 'owner-a', 0);
		expect(fence).not.toBeNull();
		await staged.mergeServerDelta('1', { flags: ['$seen'] }, 9);
		const compose = {
			applyPage: () => staged.flushAllOrNothing(),
			rollbackPage: () => staged.rollbackAppliedPage(),
		};
		failCheckpointBatches = true;
		await expect(
			jobs.commitCheckpoint('job-1', 3, { version: 1, cursor: 'delta:state:9' }, { fence: fence!, compose }),
		).rejects.toThrow(/injected checkpoint failure/);
		// NEITHER side of the composition is visible: the applied page rolled
		// back and the checkpoint never advanced.
		const surviving = await nativeStore.getMessage('1');
		expect(surviving?.flags ?? []).toEqual([]);
		expect((await jobs.readJob('job-1'))?.checkpoint?.cursor ?? null).toBeNull();
		// The success path commits BOTH sides together: the retry re-runs the
		// step, which re-stages the page before the composed commit.
		failCheckpointBatches = false;
		await staged.mergeServerDelta('1', { flags: ['$seen'] }, 9);
		const committed = await jobs.commitCheckpoint('job-1', 3, { version: 1, cursor: 'delta:state:9' }, { fence: fence!, compose });
		expect(committed.kind).toBe('committed');
		expect((await nativeStore.getMessage('1'))?.flags ?? []).toEqual(['$seen']);
		expect((await jobs.readJob('job-1'))?.checkpoint?.cursor ?? null).toBe('delta:state:9');
		facts.crashBeforeCommitExposedNothing = true;
	});

	it('a durable account cancellation is readable as a cancelled terminal result (r5)', async () => {
		// Astra r5 finding 5 reproduction: cancelAccountJobs terminalized rows
		// with result_state='cancelled' but no result_json (one batched UPDATE
		// cannot fabricate each row's payload), and the terminal-replay reader
		// treated the missing JSON as no result — the durable cancellation could
		// never be read as a cancelled result.
		const bridge = createSqliteBridge({ withSchemaInit: true });
		await bridge.open('mail');
		const jobs = createDurableJobPersistence(bridge);
		await jobs.enqueueJob(baseJob());
		expect(await jobs.claimLease('job-1', 'owner-a', 0)).not.toBeNull();
		expect((await jobs.commitCheckpoint('job-1', 3, { version: 1, cursor: 'delta:state:4' })).kind).toBe('committed');
		expect(await jobs.cancelAccountJobs('acct-1', 1)).toEqual(['job-1']);
		// The state-only cancellation READS as a terminal cancelled result.
		const stored = await jobs.readJobResult('job-1');
		expect(stored?.resultState).toBe('cancelled');
		expect(stored?.result.state).toBe('cancelled');
		expect(stored?.result.state === 'cancelled' && stored.result.reason).toBe('cancelled');
		expect(stored?.result.checkpoint?.cursor ?? null).toBe('delta:state:4');
		expect(stored?.triggerGeneration).toBe(3);
		expect((await jobs.readJob('job-1'))?.state).toBe('cancelled');
		// The terminal result keeps its duplicate-effect rejection: a same-
		// generation completion can no longer overwrite the cancellation.
		expect((await jobs.recordResult('job-1', 3, completeResult())).kind).toBe('stale-generation');
		// A non-cancelled state without JSON stays unreadable (fail closed).
		await bridge.exec(
			'mail',
			"UPDATE optional_jobs SET state = 'complete', result_state = 'complete', result_json = NULL WHERE job_id = 'job-1'",
		);
		expect(await jobs.readJobResult('job-1')).toBeNull();
	});

	it('cancelling a paused job with a stored result payload reads as cancelled (r6)', async () => {
		// Astra r6 finding 3 reproduction: cancelAccountJobs set
		// result_state='cancelled' but left the paused job's existing
		// result_json in place; the strict reader rejected the parsed paused
		// payload against the cancelled result_state, so the reachable
		// cancelled-with-stale-paused-payload row read as NO result at all.
		const bridge = createSqliteBridge({ withSchemaInit: true });
		await bridge.open('mail');
		const jobs = createDurableJobPersistence(bridge);
		await jobs.enqueueJob(baseJob());
		expect(await jobs.claimLease('job-1', 'owner-a', 0)).not.toBeNull();
		// The job pauses WITH a stored non-null result payload (the reachable
		// paused shape).
		expect(
			(await jobs.recordResult('job-1', 3, {
				state: 'paused',
				reason: 'networkUnavailable',
				checkpoint: { version: 1, cursor: 'delta:state:2' },
				progress: { done: 1, chargedUnits: 1 },
			})).kind,
		).toBe('committed');
		expect((await jobs.readJobResult('job-1'))?.resultState).toBe('paused');
		// The account-scoped cancellation lands over the paused result.
		expect(await jobs.cancelAccountJobs('acct-1', 1)).toEqual(['job-1']);
		// The stale paused payload no longer masks the cancellation: the row
		// reads as the canonical cancelled terminal result with the committed
		// checkpoint retained.
		const stored = await jobs.readJobResult('job-1');
		expect(stored?.resultState).toBe('cancelled');
		expect(stored?.result.state).toBe('cancelled');
		expect(stored?.result.state === 'cancelled' && stored.result.reason).toBe('cancelled');
		expect(stored?.result.checkpoint?.cursor ?? null).toBe('delta:state:2');
		expect(stored?.triggerGeneration).toBe(3);
		expect((await jobs.readJob('job-1'))?.state).toBe('cancelled');
		// The cancellation stays terminal: a same-generation completion cannot
		// overwrite it.
		expect((await jobs.recordResult('job-1', 3, completeResult())).kind).toBe('stale-generation');
	});

	it('the restore primitive restores per field against a real SQLite row (r11)', async () => {
		const bridge = createSqliteBridge({ withSchemaInit: true, withFts: true });
		await bridge.open('mail');
		const store = makeNativeStore(bridge);
		await store.upsertMessage({ ...storedSeed('1'), tagIds: ['Inbox', 'Work'] });
		// The page applied its staged shape, then a concurrent optimistic edit
		// rewrote the subject (bumping the watermark and claiming the field) —
		// the transactional outbox shape.
		await store.upsertMessage({ ...storedSeed('1'), subject: 'server-subject', preview: 'server-preview', version: 9, tagIds: ['Inbox', 'Work'] });
		await store.enqueueOptimisticEdit('1', { subject: 'local-edit-subject' }, { type: 'mark-read', payload: { id: '1' } });
		// Stale staged expectations: the rewritten subject must survive, the
		// untouched preview rolls back, the watermark comparison skips the
		// edit's bump, and the unchanged tag set restores to the prior tags.
		const restored = await store.restoreFieldsIfUnchanged(
			'1',
			{ subject: 'server-subject', preview: 'server-preview', version: 9, tagIds: ['Inbox', 'Work'] },
			{ subject: '', preview: '', version: 0, tagIds: ['Inbox'] },
		);
		expect(restored).toBe(true);
		const row = await store.getMessage('1');
		expect(row?.subject).toBe('local-edit-subject');
		expect(row?.dirtyFields).toEqual(['subject']);
		expect(row?.version).toBe(10);
		expect(row?.preview).toBe('');
		expect(row?.tagIds).toEqual(['Inbox']);
		// The derived FTS index followed the restored content: the staged
		// subject no longer matches, the same effect the whole-row write had.
		expect(await store.searchBody('server')).toEqual([]);
		expect(await store.searchBody('local')).toEqual(['1']);
	});

	it('the restore primitive skips a same-value rewrite claimed dirty (r9 at the boundary, r11)', async () => {
		const bridge = createSqliteBridge({ withSchemaInit: true, withFts: true });
		await bridge.open('mail');
		const store = makeNativeStore(bridge);
		await store.upsertMessage(storedSeed('1'));
		// The staged value applied, then a concurrent edit rewrote the field
		// to the SAME value under a dirty claim — the ABA case the r9 contract
		// resolves by ownership, now enforced INSIDE the restore statement.
		await store.upsertMessage({ ...storedSeed('1'), subject: 'server-subject', version: 9 });
		await store.enqueueOptimisticEdit('1', { subject: 'server-subject' }, { type: 'mark-read', payload: { id: '1' } });
		await store.restoreFieldsIfUnchanged('1', { subject: 'server-subject' }, { subject: '' });
		const row = await store.getMessage('1');
		expect(row?.subject).toBe('server-subject');
		expect(row?.dirtyFields).toEqual(['subject']);
	});

	it('a rolled-back staged upsert restores prior tags through the atomic primitive (r11)', async () => {
		const bridge = createSqliteBridge({ withSchemaInit: true, withFts: true });
		await bridge.open('mail');
		const store = makeNativeStore(bridge);
		await store.upsertMessage({ ...storedSeed('1'), tagIds: ['Inbox'] });
		const staged = createStagedStore(store);
		await staged.upsertMessage({ ...storedSeed('1'), subject: 'page-subject', tagIds: ['Inbox', 'Work'], version: 9 });
		await staged.flushAllOrNothing();
		// Clean rollback: columns AND the tag set return to the prior shape.
		await staged.rollbackAppliedPage();
		const row = await store.getMessage('1');
		expect(row?.subject).toBe('');
		expect(row?.tagIds).toEqual(['Inbox']);
		expect(row?.version ?? 0).toBe(0);
	});

	it('a rolled-back staged upsert keeps a concurrent tag rewrite (r11)', async () => {
		const bridge = createSqliteBridge({ withSchemaInit: true, withFts: true });
		await bridge.open('mail');
		const store = makeNativeStore(bridge);
		await store.upsertMessage({ ...storedSeed('1'), tagIds: ['Inbox'] });
		const staged = createStagedStore(store);
		await staged.upsertMessage({ ...storedSeed('1'), tagIds: ['Inbox', 'Work'], version: 9 });
		await staged.flushAllOrNothing();
		// A concurrent writer rewrites the tag set after the page applied; the
		// rollback's conditional tag restore must leave it untouched (the
		// staged expectation no longer matches the current set).
		await store.upsertMessage({ ...storedSeed('1'), tagIds: ['Inbox', 'Other'], version: 12 });
		await staged.rollbackAppliedPage();
		const row = await store.getMessage('1');
		expect(row?.tagIds).toEqual(['Inbox', 'Other']);
		expect(row?.version).toBe(12);
	});

	it('a rolled-back staged upsert never resurrects a concurrently removed tag (r16)', async () => {
		// Astra r16 P1 reproduction (strict subset): the expected ⊆ current
		// plant guard built its VALUES table as ONE N-column row but read only
		// `column1`, so it validated only the FIRST expected tag. With the
		// staged set {Inbox, Work} and a concurrent removal of Work (current
		// {Inbox}), the guard passed on Inbox alone, the marker planted, and
		// the restore half re-inserted the stale prior set — resurrecting
		// Work. The rollback of the remaining tags must NOT bring it back.
		const bridge = createSqliteBridge({ withSchemaInit: true, withFts: true });
		await bridge.open('mail');
		const store = makeNativeStore(bridge);
		await store.upsertMessage({ ...storedSeed('1'), tagIds: ['Inbox', 'Work'] });
		const staged = createStagedStore(store);
		await staged.upsertMessage({ ...storedSeed('1'), tagIds: ['Inbox', 'Work'], version: 9 });
		await staged.flushAllOrNothing();
		// A concurrent writer REMOVES one of the previously staged tags
		// (a strict subset of the staged expectation remains).
		await store.upsertMessage({ ...storedSeed('1'), tagIds: ['Inbox'], version: 12 });
		await staged.rollbackAppliedPage();
		// The staged expectation no longer matches the current set, so the
		// rollback restores NOTHING: the removed tag stays removed.
		const row = await store.getMessage('1');
		expect(row?.tagIds).toEqual(['Inbox']);
		expect(row?.version).toBe(12);
	});

	it('a rolled-back staged upsert fully restores the prior multi-tag set (r16)', async () => {
		// Happy path is unchanged by the r16 row-per-tag fix: with no
		// concurrent writer, the clean rollback still restores the FULL prior
		// tag set through the same conditional marker-guarded swap.
		const bridge = createSqliteBridge({ withSchemaInit: true, withFts: true });
		await bridge.open('mail');
		const store = makeNativeStore(bridge);
		await store.upsertMessage({ ...storedSeed('1'), tagIds: ['Inbox', 'Work'] });
		const staged = createStagedStore(store);
		await staged.upsertMessage({ ...storedSeed('1'), subject: 'page-subject', tagIds: ['Inbox', 'Work'], version: 9 });
		await staged.flushAllOrNothing();
		await staged.rollbackAppliedPage();
		const row = await store.getMessage('1');
		expect(row?.tagIds).toEqual(['Inbox', 'Work']);
		expect(row?.subject).toBe('');
		expect(row?.version ?? 0).toBe(0);
	});

	it('the restore primitive fails closed when the bridge lacks transactionBatch (r12)', async () => {
		// Astra r12 P1 reproduction: the no-batch fallback replayed the
		// multi-statement restore (column CASE-WHEN + FTS recompute + tag
		// swap) through individually awaited exec calls, so a failure or a
		// concurrent operation between statements could expose a PARTIAL
		// restore. The primitive must refuse BEFORE issuing any statement.
		const bridge = createSqliteBridge({ withSchemaInit: true, withFts: true });
		await bridge.open('mail');
		// Simulate a legacy shell that never projected the atomic batch entry.
		const noBatch: OfflineDbBridge = Object.create(bridge);
		Object.defineProperty(noBatch, 'transactionBatch', { value: undefined });
		// Count every statement the store tries to send through exec.
		let execStatements = 0;
		const seedExec = bridge.exec.bind(bridge);
		Object.defineProperty(noBatch, 'exec', {
			value: async (...args: Parameters<OfflineDbBridge['exec']>) => {
				execStatements += 1;
				return seedExec(...args);
			},
		});
		const store = makeNativeStore(noBatch);
		await store.upsertMessage({ ...storedSeed('1'), subject: 'server-subject', preview: 'server-preview', version: 9, tagIds: ['Inbox', 'Work'] });
		const statementsAfterSeeding = execStatements;
		// A full multi-statement restore fails closed with the typed error.
		await expect(
			store.restoreFieldsIfUnchanged(
				'1',
				{ subject: 'server-subject', preview: 'server-preview', version: 9, tagIds: ['Inbox', 'Work'] },
				{ subject: '', preview: '', version: 0, tagIds: ['Inbox'] },
			),
		).rejects.toBeInstanceOf(RestoreAtomicityUnavailableError);
		// The error names the missing seam for shell diagnostics.
		await expect(
			store.restoreFieldsIfUnchanged('1', { subject: 'server-subject' }, { subject: '' }),
		).rejects.toThrow(/transactionBatch/);
		// Not a single statement of the would-be sequence reached the bridge
		// after seeding — the fault cannot expose a partial restore.
		expect(execStatements).toBe(statementsAfterSeeding);
		// The row is exactly as the page applied it: state untouched.
		const row = await store.getMessage('1');
		expect(row?.subject).toBe('server-subject');
		expect(row?.preview).toBe('server-preview');
		expect(row?.version).toBe(9);
		expect(row?.tagIds).toEqual(['Inbox', 'Work']);
		// A no-op restore (nothing to write) still succeeds without the seam.
		expect(await store.restoreFieldsIfUnchanged('1', {}, {})).toBe(true);
	});

	it('a flush on a batch-less shell refuses BEFORE any page statement (r15)', async () => {
		// Supersedes the r12 caller contract (apply, then leave-state-alone on
		// a refused rollback): applying the page first and discovering "no
		// undo" only when the checkpoint half failed left the page exposed
		// under the old cursor. The flush now gates on the store's rollback
		// capability UP FRONT — never apply-then-discover-no-undo.
		const bridge = createSqliteBridge({ withSchemaInit: true, withFts: true });
		await bridge.open('mail');
		// Simulate a legacy shell that never projected the atomic batch entry.
		const noBatch: OfflineDbBridge = Object.create(bridge);
		Object.defineProperty(noBatch, 'transactionBatch', { value: undefined });
		// Count every statement the store tries to send through exec.
		let execStatements = 0;
		const seedExec = bridge.exec.bind(bridge);
		Object.defineProperty(noBatch, 'exec', {
			value: async (...args: Parameters<OfflineDbBridge['exec']>) => {
				execStatements += 1;
				return seedExec(...args);
			},
		});
		const store = makeNativeStore(noBatch);
		await store.upsertMessage({ ...storedSeed('1') });
		const statementsAfterSeeding = execStatements;
		// The store reports the missing capability; the staged page inherits it.
		expect(store.hasAtomicRestore()).toBe(false);
		const staged = createStagedStore(store);
		expect(staged.hasAtomicRestore()).toBe(false);
		await staged.upsertMessage({ ...storedSeed('1'), subject: 'page-subject', preview: 'page-preview', tagIds: ['Inbox', 'Work'], version: 9 });
		await expect(staged.flushAllOrNothing()).rejects.toBeInstanceOf(RestoreAtomicityUnavailableError);
		await expect(staged.flushAllOrNothing()).rejects.toThrow(/BEFORE any page statement/);
		await expect(staged.flushAllOrNothing()).rejects.toBeInstanceOf(PageRollbackUnavailableError);
		// Not a single page statement reached the bridge after seeding and the
		// row is byte-for-byte the seed: the page was NEVER applied.
		expect(execStatements).toBe(statementsAfterSeeding);
		const row = await store.getMessage('1');
		expect(row?.subject).toBe('');
		expect(row?.preview).toBe('');
		expect(row?.tagIds).toEqual(['Inbox']);
		expect(row?.version ?? 0).toBe(0);
		// The staged page is retained (nothing lost) and discards cleanly.
		expect(staged.stagedCount).toBe(1);
		staged.discard();
		expect(staged.stagedCount).toBe(0);
	});

	it('a refused rollback propagates and RETAINS the undo for a later capable attempt (r15)', async () => {
		// The undoApplied companion of the r15 gate: a restore the store
		// refuses for missing atomic capability is never swallowed into a fake
		// "rolled back", and the undo log is never cleared — a later attempt
		// on a capable store can still undo the applied page.
		const bridge = createSqliteBridge({ withSchemaInit: true, withFts: true });
		await bridge.open('mail');
		// The seam starts PRESENT (the page applies atomically), then the
		// shell "loses" it before the rollback — the sequence the up-front
		// gate now prevents for fresh pages.
		const mutable: OfflineDbBridge = Object.create(bridge);
		Object.defineProperty(mutable, 'transactionBatch', { value: bridge.transactionBatch?.bind(bridge), configurable: true });
		const store = makeNativeStore(mutable);
		await store.upsertMessage({ ...storedSeed('1') });
		const staged = createStagedStore(store);
		await staged.upsertMessage({ ...storedSeed('1'), subject: 'page-subject', preview: 'page-preview', tagIds: ['Inbox', 'Work'], version: 9 });
		await staged.flushAllOrNothing();
		// The checkpoint half failed elsewhere; the rollback's restore
		// primitive is now refused (no seam) — the refusal PROPAGATES...
		Object.defineProperty(mutable, 'transactionBatch', { value: undefined, configurable: true });
		await expect(staged.rollbackAppliedPage()).rejects.toBeInstanceOf(RestoreAtomicityUnavailableError);
		// ...the applied page is left EXACTLY as applied (no partial undo)...
		let row = await store.getMessage('1');
		expect(row?.subject).toBe('page-subject');
		expect(row?.preview).toBe('page-preview');
		expect(row?.tagIds).toEqual(['Inbox', 'Work']);
		expect(row?.version).toBe(9);
		// ...and the undo log is RETAINED, not swallowed-and-cleared: a second
		// attempt refuses again instead of silently reporting success.
		await expect(staged.rollbackAppliedPage()).rejects.toBeInstanceOf(RestoreAtomicityUnavailableError);
		// When the seam returns, the RETAINED undo still undoes the page.
		Object.defineProperty(mutable, 'transactionBatch', { value: bridge.transactionBatch?.bind(bridge), configurable: true });
		await staged.rollbackAppliedPage();
		row = await store.getMessage('1');
		expect(row?.subject).toBe('');
		expect(row?.preview).toBe('');
		expect(row?.tagIds).toEqual(['Inbox']);
		expect(row?.version ?? 0).toBe(0);
	});

	it('a checkpoint failure on a batch-less shell never applies the page (r15)', async () => {
		// Astra r14 P1 regression: flushAllOrNothing used to WRITE the page
		// first, and undoApplied swallowed the capability refusal while
		// clearing the undo — a failed checkpoint half left the applied page
		// exposed under the old cursor with no rollback capability. The
		// composed commit now fails BEFORE any page statement: the typed
		// error surfaces, zero page statements execute, and the prior
		// checkpoint stays intact.
		const bridge = createSqliteBridge({ withSchemaInit: true, withFts: true });
		await bridge.open('mail');
		// The page side runs on the batch-less shadow of the real engine.
		const noBatch: OfflineDbBridge = Object.create(bridge);
		Object.defineProperty(noBatch, 'transactionBatch', { value: undefined });
		let execStatements = 0;
		const seedExec = bridge.exec.bind(bridge);
		Object.defineProperty(noBatch, 'exec', {
			value: async (...args: Parameters<OfflineDbBridge['exec']>) => {
				execStatements += 1;
				return seedExec(...args);
			},
		});
		const store = makeNativeStore(noBatch);
		await store.upsertMessage({ ...storedSeed('1') });
		const statementsAfterSeeding = execStatements;
		const staged = createStagedStore(store);
		// The job side runs on the CAPABLE engine: a prior checkpoint commits
		// first, so "intact" means exactly that cursor afterwards.
		const jobs = createDurableJobPersistence(bridge);
		await jobs.enqueueJob(baseJob());
		const fence = await jobs.claimLease('job-1', 'owner-a', 0);
		expect(fence).not.toBeNull();
		expect(
			(await jobs.commitCheckpoint('job-1', 3, { version: 1, cursor: 'delta:state:old' })).kind,
		).toBe('committed');
		await staged.mergeServerDelta('1', { flags: ['$seen'] }, 9);
		// The composed commit refuses UP FRONT: the page's store cannot roll
		// the page back, so no page statement is applied ahead of the
		// checkpoint — and the typed error names the missing seam.
		await expect(
			jobs.commitCheckpoint('job-1', 3, { version: 1, cursor: 'delta:state:9' }, {
				fence: fence!,
				compose: {
					applyPage: () => staged.flushAllOrNothing(),
					rollbackPage: () => staged.rollbackAppliedPage(),
				},
			}),
		).rejects.toBeInstanceOf(PageRollbackUnavailableError);
		await expect(
			jobs.commitCheckpoint('job-1', 3, { version: 1, cursor: 'delta:state:9' }, {
				fence: fence!,
				compose: {
					applyPage: () => staged.flushAllOrNothing(),
					rollbackPage: () => staged.rollbackAppliedPage(),
				},
			}),
		).rejects.toThrow(/transactionBatch/);
		// Zero page statements executed after seeding; no rows written.
		expect(execStatements).toBe(statementsAfterSeeding);
		const row = await store.getMessage('1');
		expect(row?.flags ?? []).toEqual([]);
		expect(row?.version ?? 0).toBe(0);
		// The PRIOR checkpoint is intact — the composition wrote neither side.
		expect((await jobs.readJob('job-1'))?.checkpoint?.cursor ?? null).toBe('delta:state:old');
		// The staged page is still staged and discards without durable trace.
		expect(staged.stagedCount).toBe(1);
		staged.discard();
		expect(staged.stagedCount).toBe(0);
	});
});

// The retained receipt is written ONCE, after every scenario finished, from
// the ACTUAL verdict (Astra finding 18: the old artifact recorded a FAIL the
// suite never asserted) AND gated on every scenario's actual verdict (Astra
// finding 14, r2).
afterAll(async () => {
	const distinct = new Map<string, { entry: string; reason: string }>();
	for (const denial of collectedDenials) {
		distinct.set(`${denial.entry}:${denial.reason}`, denial);
	}
	const verdict = auditPersistenceRecovery({
		denials: [...distinct.values()],
		crashBeforeCommitExposedNothing: facts.crashBeforeCommitExposedNothing,
		commitExposedBoth: facts.commitExposedBoth,
		leaseReclaimedOnce: facts.leaseReclaimedOnce,
		duplicateEffectRejected: facts.duplicateEffectRejected,
		positiveOracleDemonstrated: facts.positiveOracleDemonstrated,
	});
	const final = gateVerdictOnScenarios(verdict, scenarioFailures);
	expect(final.ok, JSON.stringify({ final, scenarioFailures })).toBe(true);
	writeCaseResult(final);
});
