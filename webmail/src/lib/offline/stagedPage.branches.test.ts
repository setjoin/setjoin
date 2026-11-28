/**
 * Staged-page edge branches (coverage round r2).
 *
 * Real behavior tests for the staged overlay and rollback edges the main
 * suites leave cold: overlay-honest reads (staged rows, staged deletes,
 * merged listings), the passthrough surface, merge-delta refusal outcomes,
 * the F1 dirty-field barrier inside a staged merge, the rollback's structural
 * guards (recreated row, vanished row, page-created row, undefined prior
 * fields), the r15 best-effort rule for non-capability rollback failures,
 * and the shared array-aware field equality.
 */

import { describe, it, expect } from 'vitest';

import { createStagedStore, fieldValueEqual } from './stagedPage';
import { createMemoryOfflineStore } from '$lib/native/testing/backgroundWorkHarness';
import type { OfflineStore, StoredMessage } from './store';

function seed(id: string, overrides: Partial<StoredMessage> = {}): StoredMessage {
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
		...overrides,
	};
}

describe('fieldValueEqual (shared by both store layers)', () => {
	it('compares arrays by content, not identity', () => {
		expect(fieldValueEqual(['a', 'b'], ['a', 'b'])).toBe(true);
		expect(fieldValueEqual(['a', 'b'], ['b', 'a'])).toBe(false);
		expect(fieldValueEqual(['a'], ['a', 'a'])).toBe(false);
		expect(fieldValueEqual([], [])).toBe(true);
		expect(fieldValueEqual(['a'], 'a')).toBe(false);
		expect(fieldValueEqual('a', 'a')).toBe(true);
		expect(fieldValueEqual(1, 2)).toBe(false);
		expect(fieldValueEqual(null, undefined)).toBe(false);
	});
});

describe('staged overlay reads', () => {
	it('init and isOpen delegate to the underlying store', async () => {
		const underlying = createMemoryOfflineStore();
		const staged = createStagedStore(underlying);
		await staged.init();
		expect(await staged.isOpen()).toBe(true);
	});

	it('getMessage reads staged writes and staged deletes without touching the durable store', async () => {
		const underlying = createMemoryOfflineStore();
		await underlying.upsertMessage(seed('1', { subject: 'durable' }));
		const staged = createStagedStore(underlying);
		// Staged upsert of a NEW row is visible before any flush.
		await staged.upsertMessage(seed('2', { subject: 'staged' }));
		expect((await staged.getMessage('2'))?.subject).toBe('staged');
		// Staged delete hides the durable row.
		await staged.deleteMessage('1');
		expect(await staged.getMessage('1')).toBeNull();
		// A row with no overlay entry still reads through.
		await staged.discard();
		expect((await staged.getMessage('1'))?.subject).toBe('durable');
		expect(await staged.getMessage('missing')).toBeNull();
	});

	it('listByReceivedDesc merges the overlay over the durable listing with offset paging', async () => {
		const underlying = createMemoryOfflineStore();
		await underlying.upsertMessage(seed('a', { receivedAt: 100 }));
		await underlying.upsertMessage(seed('b', { receivedAt: 200 }));
		await underlying.upsertMessage(seed('c', { receivedAt: 300 }));
		const staged = createStagedStore(underlying);
		// Staged: a newer row appears, an older row is deleted.
		await staged.upsertMessage(seed('d', { receivedAt: 400 }));
		await staged.deleteMessage('b');
		// Default offset is 0.
		expect((await staged.listByReceivedDesc(2)).map((row) => row.id)).toEqual(['d', 'c']);
		expect((await staged.listByReceivedDesc(2, 2)).map((row) => row.id)).toEqual(['a']);
		// Discard restores the durable listing.
		staged.discard();
		expect((await staged.listByReceivedDesc(10)).map((row) => row.id)).toEqual(['c', 'b', 'a']);
	});

	it('deleteOutOfWindow delegates to the underlying store (retention is never staged)', async () => {
		const underlying = createMemoryOfflineStore();
		let calls = 0;
		const original = underlying.deleteOutOfWindow.bind(underlying);
		underlying.deleteOutOfWindow = async (cutoffMs: number) => {
			calls += 1;
			return original(cutoffMs);
		};
		const staged = createStagedStore(underlying);
		expect(await staged.deleteOutOfWindow(1234)).toBe(0);
		expect(calls).toBe(1);
	});

	it('getVersion reads the staged watermark and returns 0 for absent rows', async () => {
		const underlying = createMemoryOfflineStore();
		await underlying.upsertMessage(seed('1'));
		const staged = createStagedStore(underlying);
		expect(await staged.getVersion('1')).toBe(0);
		await staged.mergeServerDelta('1', { subject: 'next' }, 7);
		expect(await staged.getVersion('1')).toBe(7);
		expect(await staged.getVersion('missing')).toBe(0);
	});

	it('the atomic restore passthrough writes behind the staged overlay', async () => {
		const underlying = createMemoryOfflineStore();
		await underlying.upsertMessage(seed('1', { subject: 'applied' }));
		const staged = createStagedStore(underlying);
		// The passthrough reaches the underlying row even while an unrelated
		// staged entry exists for another row.
		await staged.upsertMessage(seed('2'));
		expect(await staged.restoreFieldsIfUnchanged(
			'1',
			{ subject: 'applied' },
			{ subject: 'prior' },
		)).toBe(true);
		expect((await underlying.getMessage('1'))?.subject).toBe('prior');
	});
});

describe('the passthrough surface delegates every non-page operation', () => {
	it('bookkeeping, outbox, search, meta and sync-issue calls reach the underlying store', async () => {
		const underlying = createMemoryOfflineStore();
		const calls: string[] = [];
		const record = <Args extends unknown[], R>(name: string, fn: (...args: Args) => Promise<R>) =>
			async (...args: Args): Promise<R> => {
				calls.push(name);
				return fn(...args);
			};
		const wrapped: OfflineStore = Object.create(underlying);
		wrapped.bumpLocalVersion = record('bumpLocalVersion', underlying.bumpLocalVersion.bind(underlying));
		wrapped.clearDirty = record('clearDirty', underlying.clearDirty.bind(underlying));
		wrapped.enqueueOptimisticEdit = record('enqueueOptimisticEdit', underlying.enqueueOptimisticEdit.bind(underlying));
		wrapped.pendingMessageIds = record('pendingMessageIds', underlying.pendingMessageIds.bind(underlying));
		wrapped.listPendingOps = record('listPendingOps', underlying.listPendingOps.bind(underlying));
		wrapped.ackOp = record('ackOp', underlying.ackOp.bind(underlying));
		wrapped.failOp = record('failOp', underlying.failOp.bind(underlying));
		wrapped.searchBody = record('searchBody', underlying.searchBody.bind(underlying));
		wrapped.getMeta = record('getMeta', underlying.getMeta.bind(underlying));
		wrapped.setMeta = record('setMeta', underlying.setMeta.bind(underlying));
		wrapped.recordSyncIssue = record('recordSyncIssue', underlying.recordSyncIssue.bind(underlying));
		wrapped.listSyncIssues = record('listSyncIssues', underlying.listSyncIssues.bind(underlying));
		wrapped.clearSyncIssue = record('clearSyncIssue', underlying.clearSyncIssue.bind(underlying));
		wrapped.wipe = record('wipe', underlying.wipe.bind(underlying));
		const staged = createStagedStore(wrapped);
		await staged.upsertMessage(seed('1'));
		await staged.bumpLocalVersion('1', ['subject']);
		await staged.clearDirty('1');
		await staged.enqueueOptimisticEdit('1', { subject: 'x' }, { type: 'mark-read', payload: { id: '1' } });
		await staged.pendingMessageIds();
		await staged.listPendingOps();
		await staged.ackOp(1);
		await staged.failOp(1, 'boom');
		await staged.searchBody('needle', 5);
		await staged.getMeta('emailState');
		await staged.setMeta('emailState', '9');
		await staged.recordSyncIssue({ kind: 'stale', actionType: 'mark-read', payload: {}, error: 'e' });
		await staged.listSyncIssues();
		await staged.clearSyncIssue(1);
		await staged.wipe();
		expect(calls).toEqual([
			'bumpLocalVersion',
			'clearDirty',
			'enqueueOptimisticEdit',
			'pendingMessageIds',
			'listPendingOps',
			'ackOp',
			'failOp',
			'searchBody',
			'getMeta',
			'setMeta',
			'recordSyncIssue',
			'listSyncIssues',
			'clearSyncIssue',
			'wipe',
		]);
	});
});

describe('staged mergeServerDelta refusals and barriers', () => {
	it('reports absent for a row the store never held', async () => {
		const underlying = createMemoryOfflineStore();
		const staged = createStagedStore(underlying);
		expect(await staged.mergeServerDelta('missing', { subject: 'x' }, 5)).toBe('absent');
		expect(staged.stagedCount).toBe(0);
	});

	it('skips a delta older than the row watermark', async () => {
		const underlying = createMemoryOfflineStore();
		await underlying.upsertMessage(seed('1', { version: 9 }));
		const staged = createStagedStore(underlying);
		expect(await staged.mergeServerDelta('1', { subject: 'older' }, 8)).toBe('skipped');
		expect(staged.stagedCount).toBe(0);
	});

	it('ignores bookkeeping keys and dirty-claimed fields inside a staged merge', async () => {
		const underlying = createMemoryOfflineStore();
		await underlying.upsertMessage(seed('1', { subject: 'local-edit', dirtyFields: ['subject'] }));
		const staged = createStagedStore(underlying);
		// The changed map carries bookkeeping keys and a dirty-claimed field.
		const outcome = await staged.mergeServerDelta(
			'1',
			{ subject: 'server', preview: 'server-preview', version: 99, dirtyFields: [], tagIds: ['X'] } as never,
			5,
		);
		expect(outcome).toBe('merged');
		const row = await staged.getMessage('1');
		// F1: the un-acked local edit wins; bookkeeping keys never apply.
		expect(row?.subject).toBe('local-edit');
		expect(row?.dirtyFields).toEqual(['subject']);
		expect(row?.tagIds).toEqual(['Inbox']);
		// The non-claimed field applied and the watermark moved.
		expect(row?.preview).toBe('server-preview');
		expect(row?.version).toBe(5);
	});
});

describe('rollback structural guards', () => {
	it('restores a deleted row into a still-vacant slot, and never deletes a concurrently recreated row', async () => {
		const underlying = createMemoryOfflineStore();
		await underlying.upsertMessage(seed('1', { subject: 'prior' }));
		const staged = createStagedStore(underlying);
		staged.deleteMessage('1');
		await staged.flushAllOrNothing();
		expect(await underlying.getMessage('1')).toBeNull();
		// Vacant slot: the prior row returns.
		await staged.rollbackAppliedPage();
		expect((await underlying.getMessage('1'))?.subject).toBe('prior');

		// Same page, but a concurrent writer recreated the row: the rollback
		// must leave that row alone.
		const staged2 = createStagedStore(underlying);
		staged2.deleteMessage('1');
		await staged2.flushAllOrNothing();
		await underlying.upsertMessage(seed('1', { subject: 'recreated' }));
		await staged2.rollbackAppliedPage();
		expect((await underlying.getMessage('1'))?.subject).toBe('recreated');
	});

	it('restores a row wholesale when it vanished after the page applied', async () => {
		const underlying = createMemoryOfflineStore();
		await underlying.upsertMessage(seed('1', { subject: 'prior', preview: 'prior-preview' }));
		const staged = createStagedStore(underlying);
		await staged.mergeServerDelta('1', { subject: 'applied', preview: 'applied-preview' }, 5);
		await staged.flushAllOrNothing();
		// A concurrent writer REMOVED the row after the page applied.
		await underlying.deleteMessage('1');
		await staged.rollbackAppliedPage();
		const row = await underlying.getMessage('1');
		expect(row?.subject).toBe('prior');
		expect(row?.version ?? 0).toBe(0);
	});

	it('keeps a page-created row that a concurrent writer has edited', async () => {
		const underlying = createMemoryOfflineStore();
		const staged = createStagedStore(underlying);
		await staged.upsertMessage(seed('2', { subject: 'page-created' }));
		await staged.flushAllOrNothing();
		// A concurrent edit lands on the created row.
		await underlying.upsertMessage(seed('2', { subject: 'concurrent-edit' }));
		await staged.rollbackAppliedPage();
		expect((await underlying.getMessage('2'))?.subject).toBe('concurrent-edit');
	});

	it('skips restoring fields whose prior value was never recorded (pre-watermark rows)', async () => {
		const underlying = createMemoryOfflineStore();
		// A row written before the watermark feature: `version` is undefined.
		const legacy = seed('1');
		delete (legacy as { version?: number }).version;
		await underlying.upsertMessage(legacy);
		const staged = createStagedStore(underlying);
		await staged.mergeServerDelta('1', { subject: 'applied' }, 5);
		await staged.flushAllOrNothing();
		expect((await underlying.getMessage('1'))?.version).toBe(5);
		await staged.rollbackAppliedPage();
		const row = await underlying.getMessage('1');
		// The staged FIELD rolled back; the undefined-prior watermark was left
		// at its applied value instead of being restored to undefined.
		expect(row?.subject).toBe('');
		expect(row?.version).toBe(5);
	});

	it('treats a non-capability rollback failure as best-effort and clears the undo log', async () => {
		const underlying = createMemoryOfflineStore();
		await underlying.upsertMessage(seed('1', { subject: 'prior' }));
		const staged = createStagedStore(underlying);
		await staged.mergeServerDelta('1', { subject: 'applied' }, 5);
		await staged.flushAllOrNothing();
		// A plain store failure (NOT the typed capability refusal) during the
		// rollback is best-effort: it never surfaces as a thrown rollback.
		const originalGet = underlying.getMessage.bind(underlying);
		let failedOnce = false;
		underlying.getMessage = async (id: string) => {
			if (!failedOnce) {
				failedOnce = true;
				throw new Error('transient store read failure');
			}
			return originalGet(id);
		};
		await expect(staged.rollbackAppliedPage()).resolves.toBeUndefined();
		underlying.getMessage = originalGet;
		// The undo log was cleared: a second rollback is a no-op.
		await expect(staged.rollbackAppliedPage()).resolves.toBeUndefined();
	});
});
