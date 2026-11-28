/** Real SQLite composition tests. These are NOT SQLCipher/shell crash qualification. */
import { DatabaseSync } from 'node:sqlite';
import { writeFileSync } from 'node:fs';
import { afterEach, describe, expect, it } from 'vitest';
import type { OfflineDbBridge, NativeBatchStatement } from '$lib/native/types';
import type { Email } from '$lib/types/jmap';
import { MAIL_MIGRATION_MANIFEST } from './migrations';
import { makeNativeStore } from './store-native';
import { createDurableJobPersistence, type OptionalJobRecord } from './jobStore';
import { createMailPagePersistence, mailPageStatements, MailPageCapacityError } from './mailPagePersistence';
import { createSyncDeltaStep, createSyncWindowStep } from './steps';
import { admitBatch, DEFAULT_BATCH_BUDGET } from './nativeBatch';
import type { SyncCheckpoint } from './work-contract';
import { createCoordinator } from './coordinator';
import { HARNESS_EXECUTE_POLICY, HARNESS_NOMINAL_SNAPSHOT } from '$lib/native/testing/backgroundWorkHarness';

const databases: DatabaseSync[] = [];
afterEach(() => { for (const db of databases.splice(0)) db.close(); });
const job: OptionalJobRecord = {
	jobId: 'job-1', accountId: 'account-1', workClass: 'background', state: 'queued',
	triggerGeneration: 1, coalescingKey: 'window:account-1', attempts: 0,
	deadlineUtc: '2099-01-01T00:00:00Z', queuedAtUtcMs: 0, retryAtUtcMs: null,
	stepKind: 'window', checkpoint: null, leaseOwner: null, leaseExpiresAtMs: null,
};
function email(id: string, tags = ['inbox']): Email {
	return { id, threadId: `thread-${id}`, receivedAt: '2026-09-01T00:00:00Z',
		mailboxIds: Object.fromEntries(tags.map((tag) => [tag, true])), keywords: {}, size: 1,
		hasAttachment: false, subject: `subject-${id}`, preview: `preview-${id}`,
		from: [{ email: 'sender@example.test' }], to: [], cc: [], bcc: [],
	} as Email;
}
async function fixture() {
	const sqlite = new DatabaseSync(':memory:');
	databases.push(sqlite);
	for (const step of MAIL_MIGRATION_MANIFEST.steps) for (const sql of step.statements) sqlite.exec(sql);
	const controls: { before?: () => void; failStatement?: number; failCommit?: boolean } = {};
	const batches: NativeBatchStatement[][] = [];
	const bridge = {
		query: async (_app: string, sql: string, params: unknown[] = []) => sqlite.prepare(sql).all(...params as never[]),
		exec: async (_app: string, sql: string, params: unknown[] = []) => Number(sqlite.prepare(sql).run(...params as never[]).changes),
		transactionBatch: async (_app: string, statements: readonly NativeBatchStatement[]) => {
			controls.before?.();
			batches.push([...statements]);
			sqlite.exec('BEGIN IMMEDIATE');
			try {
				let changed = 0;
				for (const [index, statement] of statements.entries()) {
					if (controls.failStatement === index) sqlite.exec('INSERT INTO nonexistent_table VALUES (1)');
					changed += Number(sqlite.prepare(statement.sql).run(...(statement.params ?? []) as never[]).changes);
				}
				if (controls.failCommit) throw new Error('injected commit failure');
				sqlite.exec('COMMIT');
				return changed;
			} catch (error) { sqlite.exec('ROLLBACK'); throw error; }
		},
	} as unknown as OfflineDbBridge;
	const store = makeNativeStore(bridge);
	const jobs = createDurableJobPersistence(bridge, { nowUtcMs: () => 1_000 });
	await jobs.enqueueJob({ ...job });
	const fence = (await jobs.claimLease(job.jobId, 'owner', 1_000))!;
	const page = createMailPagePersistence(store, jobs, job, fence, () => 1_001);
	const runWindow = (items: Email[], checkpoint: SyncCheckpoint | null = null) => createSyncWindowStep({
		emailQuery: async (_f, _s, limit, position = 0) => ({ ids: items.slice(position, position + limit).map((e) => e.id) }),
		// Deliberately reversed: Email/get order is not a query-position cursor.
		emailGet: async ({ ids }) => ({ list: items.filter((e) => ids.includes(e.id)).reverse(), state: '9' }),
	}, { windowCutoffMs: null, nowMonoMs: () => 0 })({ store: page.store, accountId: job.accountId,
		signal: new AbortController().signal, budget: { maxRecords: 64, maxBytes: 2 * 1024 * 1024, deadlineMonoMs: 5_000 }, checkpoint });
	return { sqlite, bridge, store, jobs, fence, page, controls, batches, runWindow };
}

describe('CQ-DP1 native page/checkpoint composition on real SQLite', () => {
	it('commits page, tags, FTS and checkpoint in exactly one native batch', async () => {
		const f = await fixture();
		const result = await f.runWindow([email('1', ['a', 'b'])]);
		expect(await f.store.getMessage('1')).toBeNull();
		const previous = f.batches.length;
		expect(await f.page.commit(result.checkpoint)).toEqual({ kind: 'committed' });
		expect(f.batches).toHaveLength(previous + 1);
		expect((await f.store.getMessage('1'))?.tagIds).toEqual(['a', 'b']);
		expect(f.sqlite.prepare('SELECT subject FROM messages_fts').get()).toEqual({ subject: 'subject-1' });
		expect((await f.jobs.readJob(job.jobId))?.checkpoint).toEqual(result.checkpoint);
		// Optional retained input for the separately run SQLCipher process-termination proof.
		// It contains fixture data and the exact production-generated statements, never a pass.
		if (process.env.CQ_NATIVE_FIXTURE_PATH) writeFileSync(process.env.CQ_NATIVE_FIXTURE_PATH, JSON.stringify({
			schema: MAIL_MIGRATION_MANIFEST.steps.flatMap((step) => step.statements),
			seed: f.batches.slice(0, previous).flat(), page: f.batches.at(-1), budget: DEFAULT_BATCH_BUDGET,
			checkpoint: result.checkpoint,
		}, null, 2));
		// Unchanged checkpoint still matches one SQLite UPDATE; page effects are not the oracle.
		expect(await f.page.commit(result.checkpoint)).toEqual({ kind: 'committed' });
	});

	it.each(['generation', 'lease', 'expiry', 'account', 'terminal'] as const)('refuses all effects if %s moves at the commit seam', async (change) => {
		const f = await fixture();
		const result = await f.runWindow([email('1')]);
		f.controls.before = () => {
			const set = { generation: 'trigger_generation = 2', lease: "lease_owner = 'other'", expiry: 'lease_expires_at_ms = 1',
				account: "account_id = 'other'", terminal: "state = 'cancelled'" }[change];
			f.sqlite.exec(`UPDATE optional_jobs SET ${set}`);
		};
		expect(await f.page.commit(result.checkpoint)).toEqual({ kind: 'stale-generation' });
		for (const table of ['messages', 'message_tags', 'messages_fts', 'bodies']) {
			expect(f.sqlite.prepare(`SELECT count(*) AS n FROM ${table}`).get()).toEqual({ n: 0 });
		}
		expect(f.sqlite.prepare('SELECT checkpoint_cursor FROM optional_jobs').get()).toEqual({ checkpoint_cursor: null });
	});

	it.each([0, 2, 4, 5, 'commit'] as const)('rolls back a failure at %s and reuses the connection', async (point) => {
		const f = await fixture();
		const result = await f.runWindow([email('1')]);
		if (point === 'commit') f.controls.failCommit = true; else f.controls.failStatement = point;
		await expect(f.page.commit(result.checkpoint)).rejects.toThrow();
		expect(await f.store.getMessage('1')).toBeNull();
		expect((await f.jobs.readJob(job.jobId))?.checkpoint?.cursor).toBeNull();
		delete f.controls.failStatement; delete f.controls.failCommit;
		expect(await f.page.commit(result.checkpoint)).toEqual({ kind: 'committed' });
		expect(await f.store.getMessage('1')).not.toBeNull();
	});

	it('preserves a local row created after staging and derives FTS from protected fields', async () => {
		const f = await fixture();
		const result = await f.runWindow([email('1', ['server-tag'])]);
		f.sqlite.exec(`INSERT INTO messages (id, subject, version, dirty_fields) VALUES ('1', 'local subject', 0, '["subject","tagIds"]');
			INSERT INTO message_tags VALUES ('1','local-tag',0)`);
		await f.page.commit(result.checkpoint);
		expect((await f.store.getMessage('1'))?.subject).toBe('local subject');
		expect((await f.store.getMessage('1'))?.tagIds).toEqual(['local-tag']);
		expect(f.sqlite.prepare('SELECT subject FROM messages_fts').get()).toEqual({ subject: 'local subject' });
	});

	it('rechecks local watermark and queued edits inside the transaction', async () => {
		const f = await fixture();
		let result = await f.runWindow([email('1')]); await f.page.commit(result.checkpoint);
		result = await f.runWindow([{ ...email('1'), subject: 'server replacement' }]);
		const localVersion = (await f.store.getMessage('1'))!.version! + 1;
		f.sqlite.prepare(`UPDATE messages SET subject = 'local replacement', version = ?, dirty_fields = '["subject"]'`).run(localVersion);
		f.sqlite.exec(`
			DELETE FROM messages_fts; INSERT INTO messages_fts (id,subject) VALUES ('1','local replacement')`);
		await f.page.commit(result.checkpoint);
		expect((await f.store.getMessage('1'))?.version).toBe(localVersion);
		expect((await f.store.getMessage('1'))?.subject).toBe('local replacement');
		result = await f.runWindow([email('2')]);
		f.sqlite.exec(`INSERT INTO action_queue (type,payload,status) VALUES ('edit','{"id":"2"}','pending')`);
		await f.page.commit(result.checkpoint);
		expect(await f.store.getMessage('2')).toBeNull();
	});

	it('fits a 64-record query into advancing prefixes without skipping unordered get results', async () => {
		const f = await fixture();
		const items = Array.from({ length: 64 }, (_, i) => email(String(i)));
		let checkpoint: SyncCheckpoint | null = null;
		let count = 0;
		for (let turn = 0; turn < 8; turn++) {
			const result = await f.runWindow(items, checkpoint);
			expect(result.progress.done).toBeGreaterThan(0);
			expect(result.progress.done).toBeLessThanOrEqual(12);
			await f.page.commit(result.checkpoint);
			count += result.progress.done;
			expect(JSON.parse(result.checkpoint.cursor!.slice('window:page:'.length)).position).toBe(count);
			checkpoint = result.checkpoint;
			if (count === 64) break;
		}
		expect(count).toBe(64);
		expect(f.sqlite.prepare('SELECT count(*) AS n FROM messages').get()).toEqual({ n: 64 });
		for (const batch of f.batches) expect(admitBatch('mail', 'mail', DEFAULT_BATCH_BUDGET, batch).kind).toBe('admitted');
	});

	it('resumes a fitting delta prefix without advancing the terminal state early', async () => {
		const f = await fixture();
		const items = Array.from({ length: 64 }, (_, i) => email(String(i)));
		let changesCalls = 0;
		const step = createSyncDeltaStep({
			emailChanges: async () => { changesCalls++; return { newState: '9', hasMoreChanges: false, created: items.map((e) => e.id), updated: [], destroyed: [] }; },
			emailGet: async ({ ids }) => ({ list: items.filter((e) => ids.includes(e.id)), state: '9' }),
		}, { nowMonoMs: () => 0 });
		let checkpoint: SyncCheckpoint = { version: 1, cursor: 'delta:state:8' };
		for (let turn = 0; turn < 8; turn++) {
			const result = await step({ store: f.page.store, accountId: job.accountId, signal: new AbortController().signal,
				budget: { maxRecords: 64, maxBytes: 2 * 1024 * 1024, deadlineMonoMs: 5_000 }, checkpoint });
			expect(result.progress.done).toBeGreaterThan(0);
			if (result.outcome !== 'complete') expect(result.checkpoint.cursor).toMatch(/^delta:page:/);
			await f.page.commit(result.checkpoint); checkpoint = result.checkpoint;
			if (result.outcome === 'complete') break;
		}
		expect(checkpoint.cursor).toBe('delta:state:9'); expect(changesCalls).toBe(1);
		expect(f.sqlite.prepare('SELECT count(*) AS n FROM messages').get()).toEqual({ n: 64 });
	});

	it('counts repeated guards and serialized UTF-8 bytes; refuses a single oversized record before effects', async () => {
		const f = await fixture();
		await expect(f.runWindow([{ ...email('huge'), subject: '界'.repeat(360_000) }])).rejects.toBeInstanceOf(MailPageCapacityError);
		expect(await f.store.getMessage('huge')).toBeNull();
		expect((await f.jobs.readJob(job.jobId))?.checkpoint?.cursor).toBeNull();
		const statements = mailPageStatements([], { jobId: job.jobId, accountId: job.accountId, generation: 1, fence: f.fence, nowUtcMs: 1_001 }, { version: 1, cursor: '界' });
		const bytes = statements.reduce((n, s) => n + new TextEncoder().encode(s.sql).length + new TextEncoder().encode(JSON.stringify(s.params ?? [])).length, 0);
		expect(admitBatch('mail', 'mail', { maxStatements: 64, maxParamBytes: bytes }, statements).kind).toBe('admitted');
		expect(admitBatch('mail', 'mail', { maxStatements: 64, maxParamBytes: bytes - 1 }, statements).kind).toBe('refused');
	});

	it('chunks tag parameters and rejects a tag set that cannot fit one bounded batch', async () => {
		const f = await fixture();
		const result = await f.runWindow([email('tags', Array.from({ length: 800 }, (_, i) => `tag-${i}`))]);
		await f.page.commit(result.checkpoint);
		expect((await f.store.getMessage('tags'))?.tagIds).toHaveLength(800);
		expect(Math.max(...f.batches.at(-1)!.map((s) => s.params?.length ?? 0))).toBeLessThan(300);
		await expect(f.runWindow([email('too-many-tags', Array.from({ length: 16_000 }, (_, i) => `tag-${i}`))])).rejects.toBeInstanceOf(MailPageCapacityError);
	});

	it('refuses batch-less shells before staging any nonempty page', async () => {
		const f = await fixture();
		delete f.bridge.transactionBatch;
		await expect(f.runWindow([email('1')])).rejects.toThrow(/transactionBatch/);
		expect(await f.store.getMessage('1')).toBeNull();
	});

	it('protects a concurrent local edit from a staged deletion and otherwise deletes all projections', async () => {
		const f = await fixture();
		const first = await f.runWindow([email('1')]); await f.page.commit(first.checkpoint);
		f.sqlite.exec(`INSERT INTO bodies (id,text_body) VALUES ('1','body')`);
		await f.page.store.deleteMessage('1');
		f.sqlite.exec('UPDATE messages SET version = version + 1');
		await f.page.commit({ version: 1, cursor: 'delta:state:10' });
		for (const table of ['messages', 'message_tags', 'messages_fts', 'bodies'])
			expect(f.sqlite.prepare(`SELECT count(*) AS n FROM ${table}`).get()).toEqual({ n: 1 });
		await f.page.store.deleteMessage('1');
		await f.page.commit({ version: 1, cursor: 'delta:state:11' });
		for (const table of ['messages', 'message_tags', 'messages_fts', 'bodies'])
			expect(f.sqlite.prepare(`SELECT count(*) AS n FROM ${table}`).get()).toEqual({ n: 0 });
	});

	it('preserves the previous checkpoint when a mixed merge/delete/upsert page fails', async () => {
		const f = await fixture();
		const first = await f.runWindow([email('merge'), email('delete')]); await f.page.commit(first.checkpoint);
		await f.page.store.mergeServerDelta('merge', { subject: 'next' }, Number.MAX_SAFE_INTEGER);
		await f.page.store.deleteMessage('delete');
		await f.page.store.upsertMessage({ ...(await f.store.getMessage('merge'))!, id: 'new' });
		f.controls.failCommit = true;
		await expect(f.page.commit({ version: 1, cursor: 'delta:state:next' })).rejects.toThrow();
		expect((await f.store.getMessage('merge'))?.subject).toBe('subject-merge');
		expect(await f.store.getMessage('delete')).not.toBeNull();
		expect(await f.store.getMessage('new')).toBeNull();
		expect((await f.jobs.readJob(job.jobId))?.checkpoint).toEqual(first.checkpoint);
	});

	it('does not delete a watermark-zero row created after an absent deletion snapshot', async () => {
		const f = await fixture();
		await f.page.store.deleteMessage('new-local');
		f.sqlite.exec(`INSERT INTO messages (id,version) VALUES ('new-local',0);
			INSERT INTO message_tags VALUES ('new-local','local',0)`);
		await f.page.commit({ version: 1, cursor: 'delta:state:10' });
		expect((await f.store.getMessage('new-local'))?.tagIds).toEqual(['local']);
	});

	it('records one finite nonretryable storage refusal through the actual coordinator', async () => {
		const f = await fixture();
		let fetched = 0;
		const step = createSyncDeltaStep({
			emailChanges: async () => { fetched++; return { newState: '1', hasMoreChanges: false, created: ['huge'], updated: [], destroyed: [] }; },
			emailGet: async ({ ids }) => ({ list: ids.length ? [{ ...email('huge'), subject: '界'.repeat(360_000) }] : [], state: '0' }),
		}, { nowMonoMs: () => 10_000 });
		const coordinator = createCoordinator({
			clock: { nowMonoMs: () => 10_000, nowUtcMs: () => 1_001 }, random: () => 0.5,
			policy: { readPolicy: async () => HARNESS_EXECUTE_POLICY },
			capability: { readCapability: async () => ({ snapshot: HARNESS_NOMINAL_SNAPSHOT, epoch: 0, receivedMonoMs: 10_000 }) },
			store: f.store, jobs: f.jobs, deltaStep: step, windowStep: step,
		});
		try {
			await coordinator.ingestTrigger({ kind: 'reconnect', accountId: job.accountId, generation: 1 });
			await coordinator.runDueWork(); await coordinator.runDueWork();
			expect(await coordinator.readJobResult('opt-reconnect-account-1')).toMatchObject({ kind: 'committed',
				result: { state: 'failed', error: { code: 'storage', retryable: false } } });
			expect(fetched).toBe(1);
			expect(await f.store.getMessage('huge')).toBeNull();
		} finally { coordinator.dispose(); }
	});
});
