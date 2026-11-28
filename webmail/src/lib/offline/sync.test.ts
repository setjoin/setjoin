import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('$lib/jmap/client', () => ({
	emailQuery: vi.fn(),
	emailGet: vi.fn(),
	getAccountId: vi.fn(async () => null),
}));
vi.mock('./leader', () => ({ withSyncOwnership: (fn: () => Promise<unknown>) => fn() }));
vi.mock('./reconcile', () => ({ resolveId: vi.fn(async (id: string) => id) }));
vi.mock('$lib/db/offline', () => ({
	getPendingActions: vi.fn(async () => []),
	isOnline: vi.fn(() => true),
	onNetworkChange: vi.fn(() => () => {})
}));

function fakeDb() {
	// Full row persisted so getMessage's dirty_fields pre-check works in applyRecord.
	const messages = new Map<string, Record<string, unknown>>();
	return {
		open: vi.fn(async (_a: string) => {}), isOpen: vi.fn(async (_a: string) => true), wipe: vi.fn(async (_a: string) => {}),
		// r3 sql guard: MAIL_SCHEMA runs only through the authorized one-shot seam.
		execSchemaInit: vi.fn(async (_appKey: string, _schema: string) => 0),
		exec: vi.fn(async (_appKey: string, sql: string, p: unknown[] = []) => {
			if (/^\s*CREATE/i.test(sql)) return 0;
			// upsertMessage passes: id[0], threadId[1], receivedAt[2], flags[3], hasAttachment[4],
			// cacheState[5], syncedAt[6], from[7], to[8], cc[9], bcc[10], subject[11],
			// preview[12], version[13], dirty_fields[14]
			if (/INSERT OR REPLACE INTO messages\b/i.test(sql)) messages.set(p[0] as string, { id: p[0], thread_id: p[1], received_at: p[2], flags: p[3] ?? '[]', has_attachment: p[4] ?? 0, cache_state: p[5] ?? 'meta', synced_at: p[6] ?? 0, from_: p[7] ?? '', to_: p[8] ?? '', cc: p[9] ?? '', bcc: p[10] ?? '', subject: p[11] ?? '', preview: p[12] ?? '', version: p[13] ?? 0, dirty_fields: p[14] ?? '[]' });
			else if (/DELETE FROM messages WHERE received_at </i.test(sql)) { for (const [id, m] of messages) if ((m.received_at as number) < (p[0] as number)) messages.delete(id); }
			return 1;
		}),
		query: vi.fn(async (_appKey: string, sql: string, p: unknown[] = []) => {
			if (/COUNT\(\*\).*received_at </i.test(sql)) { let n = 0; for (const m of messages.values()) if ((m.received_at as number) < (p[0] as number)) n++; return [{ n }]; }
			if (/ORDER BY received_at/i.test(sql)) return [...messages.values()].map((m) => ({ ...m, tag_ids: '' }));
			// getMessage: WHERE m.id = ? (also covers mergeServerDelta's SELECT * FROM messages WHERE id = ?)
			if (/WHERE m?\.?id\s*=\s*\?/i.test(sql) && p.length === 1) { const m = messages.get(p[0] as string); return m ? [{ ...m, tag_ids: '' }] : []; }
			// mergeServerDelta's SELECT version, dirty_fields FROM messages WHERE id = ?
			if (/SELECT.*version.*dirty_fields.*FROM messages WHERE id/i.test(sql) && p.length === 1) { const m = messages.get(p[0] as string); return m ? [{ version: m.version ?? 0, dirty_fields: m.dirty_fields ?? '[]' }] : []; }
			return [];
		}),
	};
}

import { emailQuery, emailGet } from '$lib/jmap/client';

describe('windowed sync', () => {
	let sync: typeof import('./sync');
	beforeEach(async () => {
		vi.resetModules();
		(window as never as { setjoinNative: { db: ReturnType<typeof fakeDb> } }).setjoinNative = { db: fakeDb() };
		vi.mocked(emailQuery).mockResolvedValue({ ids: ['10'], total: 1 } as never);
		vi.mocked(emailGet).mockResolvedValue([
			{ id: '10', threadId: 't', mailboxIds: { Inbox: true }, keywords: { $seen: true }, receivedAt: '2026-06-20T00:00:00Z', hasAttachment: false, preview: 'p', subject: 'S', from: [{ email: 'a@x' }], to: [{ email: 'b@y' }] }
		] as never);
		sync = await import('./sync');
	});

	it('queries with the window cutoff and metadata props', async () => {
		await sync.syncWindow({ window: '30d', now: Date.parse('2026-06-23T00:00:00Z') });
		expect(emailGet).toHaveBeenCalledWith(['10'], sync.METADATA_PROPS, undefined);
		const filter = vi.mocked(emailQuery).mock.calls[0][0] as { after?: string };
		expect(filter.after).toBeDefined();
	});

	it('evicts rows older than the window', async () => {
		const store = (await import('./store')).getStore()!;
		await store.upsertMessage({ id: 'old', threadId: 't', receivedAt: Date.parse('2020-01-01T00:00:00Z'), flags: [], hasAttachment: false, cacheState: 'meta', syncedAt: 0, from: '', to: '', cc: '', bcc: '', subject: 'o', preview: '', tagIds: [] });
		const res = await sync.syncWindow({ window: '30d', now: Date.parse('2026-06-23T00:00:00Z') });
		expect(res!.evicted).toBeGreaterThanOrEqual(1);
	});

	it('F2 barrier: a mid-replay StateChange does not clobber an optimistic row', async () => {
		// '10' has an un-acked offline edit in the SQLCipher action_queue; the resync
		// returns a server delta for it. The barrier must SKIP it (no merge/upsert).
		const store = (await import('./store')).getStore()!;
		vi.spyOn(store, 'pendingMessageIds').mockResolvedValueOnce(new Set(['10']));
		const mergeSpy = vi.spyOn(store, 'mergeServerDelta');
		const upsertSpy = vi.spyOn(store, 'upsertMessage');
		await sync.syncWindow({ window: '30d', now: Date.parse('2026-06-23T00:00:00Z') });
		// id '10' is pending → neither merged nor upserted this pass (held behind
		// the drained-queue checkpoint; it resyncs after ack).
		expect(mergeSpy).not.toHaveBeenCalledWith('10', expect.anything(), expect.anything());
		expect(upsertSpy).not.toHaveBeenCalledWith(expect.objectContaining({ id: '10' }));
	});

	it('UI-UX-PRO-MAX: tallies auto-merged flag/keyword/mailbox conflicts and confirms once', async () => {
		// '10' is cached with an un-acked offline flag edit (dirtyFields includes 'flags');
		// the resync returns a server delta for it that mergeServerDelta auto-reconciles.
		const store = (await import('./store')).getStore()!;
		await store.upsertMessage({ id: '10', threadId: 't', receivedAt: Date.now(), flags: ['\\Seen'], hasAttachment: false, cacheState: 'full', syncedAt: 0, from: '', to: '', cc: '', bcc: '', subject: 'S', preview: '', tagIds: [], version: 1, dirtyFields: ['flags'] } as never);
		vi.spyOn(store, 'mergeServerDelta').mockResolvedValue('merged');
		const { offline } = await import('./state.svelte');
		const notifySpy = vi.spyOn(offline, 'notifyAutoMerged');
		const res = await sync.syncWindow({ window: '30d', now: Date.parse('2026-06-23T00:00:00Z') });
		expect(res!.autoMerged).toBe(1);
		// ONE aggregate confirmation, not per-item.
		expect(notifySpy).toHaveBeenCalledTimes(1);
		expect(notifySpy).toHaveBeenCalledWith(1);
	});

	it('UI-UX-PRO-MAX: no auto-merge confirmation when nothing was dirty (notify(0) is a no-op)', async () => {
		const { offline } = await import('./state.svelte');
		offline.autoMergedCount = 0;
		await sync.syncWindow({ window: '30d', now: Date.parse('2026-06-23T00:00:00Z') });
		// a clean pass (no dirty flag/keyword/mailbox edits) leaves autoMergedCount at 0.
		expect(offline.autoMergedCount).toBe(0);
	});

	it('Fix 1: invalidates the delta watermark (sets emailState="") so syncDelta re-anchors', async () => {
		// syncWindow uses a receivedAt epoch cursor; syncDelta uses a JMAP state token.
		// The two domains are incomparable — after a windowed resync, emailState must be
		// cleared so syncDelta never treats a receivedAt value as a valid sinceState.
		const store = (await import('./store')).getStore()!;
		const spy = vi.spyOn(store, 'setMeta');
		await sync.syncWindow({ window: '30d', now: Date.parse('2026-06-23T00:00:00Z') });
		expect(spy).toHaveBeenCalledWith('emailState', '');
	});
});

// ── incremental delta apply (offline #3 §8.5) ────────────────────────────────

import { syncDelta } from './sync';

function mockClient(pages: { newState: string; hasMoreChanges: boolean; created: string[]; updated: string[]; destroyed: string[] }[], getResult: { list: { id: string; subject?: string; receivedAt?: string; [k: string]: unknown }[]; state?: string }) {
	let i = 0;
	return {
		emailChanges: vi.fn(async () => pages[i++]),
		// state must be present: JmapClient.emailGet returns { list, state } per JMAP spec.
		emailGet: vi.fn(async () => ({ state: '0', ...getResult })),
	};
}

// A minimal OfflineStore stub exposing the #1a F1/F4 seam. mergeServerDelta is
// spied; getMeta/setMeta back emailState; deleteMessage evicts destroyed ids.
function storeStub(meta: Record<string, string> = { emailState: '3' }) {
	return {
		mergeServerDelta: vi.fn(async () => 'merged' as const),
		upsertMessage: vi.fn(async () => {}),
		deleteMessage: vi.fn(async () => {}),
		getMeta: vi.fn(async (k: string) => meta[k] ?? null),
		setMeta: vi.fn(async (k: string, v: string) => { meta[k] = v; }),
		pendingMessageIds: vi.fn(async () => new Set<string>()),
		_meta: meta,
	};
}

describe('incremental delta apply (F1 per-field merge)', () => {
	it('MERGES created/updated per-field (never whole-record), evicts destroyed, loops, stores newState', async () => {
		const client = mockClient([
			{ newState: '5', hasMoreChanges: true,  created: ['1'], updated: [], destroyed: ['9'] },
			{ newState: '7', hasMoreChanges: false, created: [],    updated: ['2'], destroyed: [] },
		], { list: [{ id: '1', subject: 'A', receivedAt: '2026-06-01T00:00:00Z' }, { id: '2', subject: 'B', receivedAt: '2026-06-02T00:00:00Z' }] });
		const store = storeStub();
		await syncDelta(client as never, store as never);
		expect(store.deleteMessage).toHaveBeenCalledWith('9');       // destroyed evicted
		// F1: per-field merge with the journal state_seq as the watermark, NOT a
		// whole-record put. The `changed` arg is a Partial<StoredMessage>, never the
		// raw email object, and serverVersion = Number(newState).
		expect(store.mergeServerDelta).toHaveBeenCalledWith('1', expect.objectContaining({ subject: 'A' }), 5);
		expect(store.mergeServerDelta).toHaveBeenCalledWith('2', expect.objectContaining({ subject: 'B' }), 7);
		expect(store._meta.emailState).toBe('7');                    // final newState
		expect(client.emailChanges).toHaveBeenCalledTimes(2);        // looped
	});

	it('F2: a delta for an id with an un-acked outbound op is held (not merged)', async () => {
		const client = mockClient(
			[{ newState: '5', hasMoreChanges: false, created: [], updated: ['10'], destroyed: [] }],
			{ list: [{ id: '10', subject: 'X', receivedAt: '2026-06-01T00:00:00Z' }] }
		);
		const store = storeStub();
		// F2: id '10' has an un-acked op in the SQLCipher action_queue — store.pendingMessageIds()
		// is the correct seam (covers native; was broken when syncDelta used getPendingActions only).
		store.pendingMessageIds.mockResolvedValueOnce(new Set(['10']));
		await syncDelta(client as never, store as never);
		expect(store.mergeServerDelta).not.toHaveBeenCalledWith('10', expect.anything(), expect.anything());
	});

	it('absent row → full upsert with the journal watermark', async () => {
		const client = mockClient(
			[{ newState: '9', hasMoreChanges: false, created: ['3'], updated: [], destroyed: [] }],
			{ list: [{ id: '3', subject: 'C', receivedAt: '2026-06-03T00:00:00Z' }] }
		);
		const store = storeStub();
		store.mergeServerDelta.mockResolvedValueOnce('absent' as never);
		await syncDelta(client as never, store as never);
		expect(store.upsertMessage).toHaveBeenCalledWith(expect.objectContaining({ id: '3', version: 9 }));
	});

	it('falls back to full resync on cannotCalculateChanges', async () => {
		const err = Object.assign(new Error('x'), { jmapType: 'cannotCalculateChanges' });
		const client = { emailChanges: vi.fn(async () => { throw err; }), emailGet: vi.fn(async () => ({ list: [], state: '42' })) };
		const store = storeStub();
		// syncWindow is the #1a full-resync fallback; spy on the module export.
		const syncMod = await import('./sync');
		const spy = vi.spyOn(syncMod, 'syncWindow').mockResolvedValue(null as never);
		await syncDelta(client as never, store as never);
		expect(spy).toHaveBeenCalled();
	});

	it('Fix 2: BZ011 re-anchors emailState after fallback so next sync is incremental', async () => {
		// Without this fix: every subsequent syncDelta uses the same pruned sinceState
		// → permanent full-resync loop. Fix: after the windowed fallback, query the
		// server's current Email state and store it as the new delta watermark.
		const err = Object.assign(new Error('x'), { jmapType: 'cannotCalculateChanges' });
		const client = {
			emailChanges: vi.fn(async () => { throw err; }),
			emailGet: vi.fn(async () => ({ list: [], state: '99' })),
		};
		const store = storeStub({ emailState: 'old-pruned' });
		const syncMod = await import('./sync');
		vi.spyOn(syncMod, 'syncWindow').mockResolvedValue(null as never);
		await syncDelta(client as never, store as never);
		// emailState must be the server's current state, not the pruned token.
		expect(store._meta.emailState).toBe('99');
	});

	it('Fix 1+2: re-anchors at start when emailState is absent (first run) or empty (post-windowed-resync)', async () => {
		// Empty/absent emailState = no valid delta anchor. syncDelta must fetch the current
		// server state via emailGet(ids=[]) before entering the changes loop, so the first
		// emailChanges call starts from a correct base — never from '0'/pruned.
		const client = mockClient(
			[{ newState: '11', hasMoreChanges: false, created: [], updated: [], destroyed: [] }],
			{ list: [], state: '11' }
		);
		// Simulate post-windowed-resync: emailState cleared to ''.
		const store = storeStub({ emailState: '' });
		await syncDelta(client as never, store as never);
		// emailGet called once to re-anchor, then the loop used '11' as sinceState.
		expect(client.emailGet).toHaveBeenCalledWith({ ids: [], properties: [] });
		expect(store._meta.emailState).toBe('11');
	});
});
