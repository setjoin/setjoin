import { describe, it, expect, vi, beforeEach } from 'vitest';

// b1r2-011 r3: the REAL JmapMethodError class rides along (importActual) so the
// structured-classification tests below throw exactly what client.ts throws —
// no mocked-class drift.
vi.mock('./client', async () => {
	const actual = await vi.importActual<typeof import('./client')>('./client');
	return {
		emailSet: vi.fn(),
		emailSubmissionSet: vi.fn(),
		loadSession: vi.fn(),
		JmapMethodError: actual.JmapMethodError
	};
});

// ponytail: db/offline kept only for isOnline/onNetworkChange; the offline
// action_queue now routes through the SQLCipher store (native path, always active
// in these tests because window.setjoinNative.db is set in beforeEach).
vi.mock('$lib/db/offline', () => ({
	queueAction: vi.fn(),
	getPendingActions: vi.fn(async () => []),
	markActionDone: vi.fn(),
	markActionFailed: vi.fn(),
	isOnline: vi.fn(() => false),
	onNetworkChange: vi.fn(() => () => {}),
}));

// Full in-memory fake of the SQLCipher bridge. Handles messages + action_queue +
// meta_mail + sync_issues. BEGIN/COMMIT/ROLLBACK are no-ops (the fake is
// synchronous so atomicity is trivially maintained — the tx intercept test below
// overrides exec to simulate a mid-tx crash).
function fakeDb() {
	const messages = new Map<string, Record<string, unknown>>();
	const meta = new Map<string, string>();
	const issues: Record<string, unknown>[] = [];
	const actionQueue: Array<{ id: number; type: string; payload: string; status: string; attempts: number }> = [];
	let aqSeq = 1;
	let issueSeq = 1;

	return {
		open: vi.fn(async (_a: string) => {}),
		isOpen: vi.fn(async (_a: string) => true),
		wipe: vi.fn(async (_a: string) => {
			messages.clear(); meta.clear(); issues.length = 0; actionQueue.length = 0;
		}),
		// store-native init (r3 sql guard) applies MAIL_SCHEMA only through the
		// authorized one-shot seam; ordinary exec refuses multi-statement batches.
		execSchemaInit: vi.fn(async (_appKey: string, _schema: string) => {}),
		exec: vi.fn(async (_appKey: string, sql: string, params: unknown[] = []) => {
			if (/^\s*CREATE/i.test(sql)) return 0;
			if (/^\s*BEGIN\s*$/i.test(sql)) return 0;
			if (/^\s*COMMIT\s*$/i.test(sql)) return 0;
			if (/^\s*ROLLBACK\s*$/i.test(sql)) return 0;
			if (/INSERT.*INTO action_queue/i.test(sql)) {
				actionQueue.push({ id: aqSeq++, type: params[0] as string, payload: params[1] as string, status: 'pending', attempts: 0 });
			} else if (/DELETE FROM action_queue WHERE id/i.test(sql)) {
				const idx = actionQueue.findIndex((r) => r.id === params[0]);
				if (idx !== -1) actionQueue.splice(idx, 1);
			} else if (/UPDATE action_queue SET/i.test(sql)) {
				// failOp: UPDATE action_queue SET attempts = attempts + 1, last_error = ?, status = CASE ... WHERE id = ?
				const row = actionQueue.find((r) => r.id === params[params.length - 1]);
				if (row) {
					row.attempts += 1;
					row.status = row.attempts >= 3 ? 'failed' : 'pending';
				}
			} else if (/INSERT.*INTO meta_mail/i.test(sql)) {
				meta.set(params[0] as string, params[1] as string);
			} else if (/INSERT.*INTO sync_issues/i.test(sql)) {
				issues.push({ id: issueSeq++, kind: params[0], action_type: params[1], payload: params[2], error: params[3], created_at: params[4] });
			} else if (/UPDATE messages SET/i.test(sql)) {
				// enqueueOptimisticEdit cache UPDATE (patch={} → no-op; patch with fields → update row)
				// The id is always the last param in the WHERE clause.
				const id = params[params.length - 1] as string;
				const row = messages.get(id);
				if (row) {
					// simple: mark version bump (sufficient for the tx intercept test)
					row.version = ((row.version as number) ?? 0) + 1;
				}
			} else if (/INSERT OR REPLACE INTO messages\b/i.test(sql) && !/message_tags|fts/i.test(sql)) {
				const [id, threadId, receivedAt, flags, hasAtt, cacheState, syncedAt, from_, to_, cc, bcc, subject, preview, version, dirtyFields] = params as never[];
				messages.set(id as string, { id, thread_id: threadId, received_at: receivedAt, flags, has_attachment: hasAtt ? 1 : 0, cache_state: cacheState, synced_at: syncedAt, from_: from_, to_, cc, bcc, subject, preview, version: version ?? 0, dirty_fields: dirtyFields ?? '[]' });
			} else if (/DELETE FROM message_tags WHERE message_id/i.test(sql)) {
				/* no-op: tag tracking not needed here */
			} else if (/INSERT.*INTO message_tags/i.test(sql)) {
				/* no-op */
			} else if (/INSERT.*messages_fts/i.test(sql)) {
				/* no-op */
			} else if (/DELETE FROM messages_fts WHERE id/i.test(sql)) {
				/* no-op */
			} else if (/DELETE FROM messages WHERE id\s*=\s*\?/i.test(sql)) {
				messages.delete(params[0] as string);
			}
			return 1;
		}),
		query: vi.fn(async (_appKey: string, sql: string, params: unknown[] = []) => {
			if (/FROM action_queue WHERE status\s*=\s*'pending'/i.test(sql)) {
				// listPendingOps and pendingMessageIds both match; return full rows
				return actionQueue.filter((r) => r.status === 'pending');
			}
			if (/SELECT value FROM meta_mail WHERE key/i.test(sql)) {
				const v = meta.get(params[0] as string);
				return v !== undefined ? [{ value: v }] : [];
			}
			if (/FROM sync_issues/i.test(sql)) {
				return issues.map((i) => ({ ...i }));
			}
			if (/FROM messages WHERE id\s*=\s*\?/i.test(sql)) {
				const m = messages.get(params[0] as string);
				return m ? [{ ...m, dirty_fields: m.dirty_fields ?? '[]' }] : [];
			}
			return [];
		}),
		// expose for test assertions
		_actionQueue: actionQueue,
		_messages: messages,
		_issues: issues,
	};
}

describe('native outbox wiring', () => {
	let offlineClient: typeof import('./offline-client');
	let reconcile: typeof import('$lib/offline/reconcile');
	let client: typeof import('./client');
	let db: ReturnType<typeof fakeDb>;

	beforeEach(async () => {
		vi.resetAllMocks(); // clear persisted mock state (isOnline, client.emailSet, etc.) from prior test
		vi.resetModules();
		db = fakeDb();
		(window as never as { setjoinNative: { db: ReturnType<typeof fakeDb> } }).setjoinNative = { db };
		client = await import('./client');
		reconcile = await import('$lib/offline/reconcile');
		offlineClient = await import('./offline-client');
	});

	it('offline emailSet routes through enqueueOptimisticEdit (SQLCipher), not IndexedDB', async () => {
		const { queueAction } = await import('$lib/db/offline');
		await offlineClient.emailSet(null, { 'msg-1': { 'keywords/$seen': true } }, null);
		// Native path: IndexedDB queueAction is never called
		expect(queueAction).not.toHaveBeenCalled();
		// Action is in the SQLCipher action_queue
		expect(db._actionQueue).toHaveLength(1);
		expect(db._actionQueue[0].type).toBe('emailSetUpdate');
		expect(JSON.parse(db._actionQueue[0].payload)).toMatchObject({ id: 'msg-1' });
	});

	it('ATOMICITY: if enqueueOptimisticEdit fails, no partial state (wired path rolls back)', async () => {
		// Insert a message row so the cache UPDATE has something to act on.
		const { getStore } = await import('$lib/offline/store');
		const store = getStore()!;
		await store.init();
		await store.upsertMessage({
			id: 'msg-a', threadId: 't', receivedAt: 1, flags: [], hasAttachment: false,
			cacheState: 'full', syncedAt: 0, from: '', to: '', cc: '', bcc: '',
			subject: 'S', preview: 'p', tagIds: []
		});
		// Capture the real exec impl, then intercept to throw on the action_queue INSERT.
		const realImpl = db.exec.getMockImplementation()!;
		db.exec.mockImplementation(async (appKey: string, sql: string, params?: unknown[]) => {
			if (/INSERT INTO action_queue/i.test(sql)) throw new Error('simulated crash before COMMIT');
			return realImpl(appKey, sql, params);
		});
		// The wired path (emailSet → store.enqueueOptimisticEdit → ROLLBACK) should throw.
		await expect(offlineClient.emailSet(null, { 'msg-a': { flags: ['$seen'] } }, null)).rejects.toThrow();
		// No partial state: action_queue is empty (ROLLBACK).
		expect(db._actionQueue).toHaveLength(0);
	});

	it('rewrites a temp-id to the server id before replaying an update', async () => {
		const tmp = reconcile.newTempId();
		await reconcile.mapTempId(tmp, 'srv-77');
		// Enqueue directly via the offline path (uses SQLCipher action_queue).
		await offlineClient.emailSet(null, { [tmp]: { 'keywords/$seen': true } }, null);
		vi.mocked(client.emailSet).mockResolvedValue({} as never);
		// Make isOnline return true so replayPendingActions goes online.
		const { isOnline } = await import('$lib/db/offline');
		vi.mocked(isOnline).mockReturnValue(true);
		await offlineClient.replayPendingActions();
		expect(client.emailSet).toHaveBeenCalledWith(null, { 'srv-77': { 'keywords/$seen': true } }, null, null);
	});

	it('routes a stale-state rejection to sync_issues (SQLCipher), not silent loss', async () => {
		await offlineClient.emailSet(null, { 'msg-5': {} }, null);
		vi.mocked(client.emailSet).mockRejectedValue(new Error('stateMismatch'));
		const { isOnline } = await import('$lib/db/offline');
		vi.mocked(isOnline).mockReturnValue(true);

		await offlineClient.replayPendingActions();

		// recordSyncIssue must have inserted a row — not silent loss.
		expect(db._issues).toHaveLength(1);
		// Op is drained from the queue.
		expect(db._actionQueue.filter((r) => r.status === 'pending')).toHaveLength(0);
	});

	it('replay reads from SQLCipher action_queue, not IndexedDB', async () => {
		const { getPendingActions } = await import('$lib/db/offline');
		// Ensure client.emailSet resolves (not mocked to reject from prior test state).
		vi.mocked(client.emailSet).mockResolvedValue({} as never);
		await offlineClient.emailSet(null, { 'msg-x': {} }, null);
		const { isOnline } = await import('$lib/db/offline');
		vi.mocked(isOnline).mockReturnValue(true);
		await offlineClient.replayPendingActions();
		// IndexedDB getPendingActions is never consulted for replay on native.
		expect(getPendingActions).not.toHaveBeenCalled();
		// The op was replayed and removed from the SQLCipher queue.
		expect(db._actionQueue).toHaveLength(0);
	});
});

// b1r2-011: offline queue must carry the originating account override (acct) so
// replay re-issues each op against the account that created it — never the
// module-singleton primary account. Pre-fix legacy rows (no serialized acct) are
// quarantined to sync_issues as non-executable.
describe('b1r2-011 offline account persistence', () => {
	let offlineClient: typeof import('./offline-client');
	let reconcile: typeof import('$lib/offline/reconcile');
	let client: typeof import('./client');
	let db: ReturnType<typeof fakeDb>;

	beforeEach(async () => {
		vi.resetAllMocks();
		vi.resetModules();
		db = fakeDb();
		(window as never as { setjoinNative: { db: ReturnType<typeof fakeDb> } }).setjoinNative = { db };
		client = await import('./client');
		reconcile = await import('$lib/offline/reconcile');
		offlineClient = await import('./offline-client');
	});

	it('every fresh enqueue path persists the account (delegate and explicit null)', async () => {
		await offlineClient.emailSet(
			{ 'k1': { subject: 'd' } },
			{ 'msg-1': { 'keywords/$seen': true } },
			['msg-2'],
			'acct-delegate'
		);
		await offlineClient.emailSubmissionSet({ 'k2': { identityId: 'i1' } }, 'acct-delegate');
		// Explicit null (primary) still persists the key — presence distinguishes
		// fresh rows from legacy pre-fix rows.
		await offlineClient.emailSet(null, { 'msg-3': {} }, null, null);

		const rows = db._actionQueue.map((r) => ({ type: r.type, payload: JSON.parse(r.payload) }));
		expect(rows.map((r) => r.type)).toEqual([
			'emailSetUpdate', 'emailSetDestroy', 'emailSetCreate', 'emailSubmissionSet', 'emailSetUpdate'
		]);
		expect(rows[0].payload).toMatchObject({ id: 'msg-1', acct: 'acct-delegate' });
		expect(rows[1].payload).toMatchObject({ id: 'msg-2', acct: 'acct-delegate' });
		expect(rows[2].payload).toMatchObject({ key: 'k1', acct: 'acct-delegate' });
		expect(rows[3].payload).toMatchObject({ key: 'k2', acct: 'acct-delegate' });
		expect('acct' in rows[4].payload).toBe(true);
		expect(rows[4].payload.acct).toBeNull();
	});

	it('delegate-queued ops replay with the delegate account, not the primary', async () => {
		vi.mocked(client.emailSet).mockResolvedValue({} as never);
		vi.mocked(client.emailSubmissionSet).mockResolvedValue({} as never);
		await offlineClient.emailSet({ 'k1': { subject: 'd' } }, null, null, 'acct-delegate');
		await offlineClient.emailSubmissionSet({ 'k2': { identityId: 'i1' } }, 'acct-delegate');
		await offlineClient.replayPendingActions();

		expect(client.emailSet).toHaveBeenCalledWith(
			{ 'k1': { subject: 'd' } }, null, null, 'acct-delegate'
		);
		expect(client.emailSubmissionSet).toHaveBeenCalledWith(
			expect.objectContaining({ 'k2': expect.objectContaining({ identityId: 'i1' }) }),
			'acct-delegate'
		);
		// Both acked out of the queue.
		expect(db._actionQueue.filter((r) => r.status === 'pending')).toHaveLength(0);
	});

	it('a pre-fix legacy queue row with no serialized account is NOT replayed against the primary and lands in sync_issues', async () => {
		vi.mocked(client.emailSet).mockResolvedValue({} as never);
		// Legacy fixture: pre-fix row shape (no acct key in the payload).
		db._actionQueue.push({
			id: 901, type: 'emailSetCreate',
			payload: JSON.stringify({ key: 'k-legacy', msg: { subject: 'old' } }),
			status: 'pending', attempts: 0
		});
		await offlineClient.replayPendingActions();

		// Never issued against any account — non-executable at replay.
		expect(client.emailSet).not.toHaveBeenCalled();
		expect(db._issues).toHaveLength(1);
		expect(db._issues[0].kind).toBe('rejected');
		expect(db._issues[0].action_type).toBe('emailSetCreate');
		expect(JSON.parse(db._issues[0].payload as string)).toMatchObject({ key: 'k-legacy' });
		// Drained from the queue; user re-confirms or discards via sync_issues.
		expect(db._actionQueue.filter((r) => r.status === 'pending')).toHaveLength(0);
	});

	it('a per-item notUpdated failure in a RESOLVED setResponse routes to sync_issues before ack', async () => {
		// Real response path (the old test mocked `new Error('serverNotFound')`,
		// bypassing the bucket inspection): the gateway folds an updated-already-
		// gone id into notUpdated and RESOLVES — there is no throw to catch.
		vi.mocked(client.emailSet).mockResolvedValue({
			notUpdated: { 'msg-9': { type: 'notFound', description: 'Email not found' } }
		} as never);
		await offlineClient.emailSet(null, { 'msg-9': {} }, null, 'acct-delegate');
		await offlineClient.replayPendingActions();

		// Recorded, not silently acked: kind/classification comes from the
		// STRUCTURED type field, not the description prose.
		expect(db._issues).toHaveLength(1);
		expect(db._issues[0].kind).toBe('rejected');
		expect(db._issues[0].action_type).toBe('emailSetUpdate');
		expect(db._issues[0].error).toContain('notUpdated[msg-9]');
		expect(db._issues[0].error).toContain('notFound');
		// Drained from the queue like the method-level rejection path.
		expect(db._actionQueue.filter((r) => r.status === 'pending')).toHaveLength(0);
	});

	it('a per-item notDestroyed failure in a RESOLVED setResponse routes to sync_issues before ack', async () => {
		// The gateway folds destroyed-already-gone ids into notDestroyed as
		// {"type":"notFound"} and still resolves (internal/jmap parse.go:108).
		vi.mocked(client.emailSet).mockResolvedValue({
			notDestroyed: { 'msg-7': { type: 'notFound' } }
		} as never);
		await offlineClient.emailSet(null, null, ['msg-7'], 'acct-delegate');
		await offlineClient.replayPendingActions();

		expect(db._issues).toHaveLength(1);
		expect(db._issues[0].kind).toBe('rejected');
		expect(db._issues[0].action_type).toBe('emailSetDestroy');
		expect(db._issues[0].error).toContain('notDestroyed[msg-7]');
		expect(db._actionQueue.filter((r) => r.status === 'pending')).toHaveLength(0);
	});

	it('a method-level notFound with an innocent description routes to sync_issues (structured type, not prose)', async () => {
		// The r3 HOLD scenario, fixed at the source: client.ts now throws
		// JmapMethodError carrying the STRUCTURED type, so a notFound whose
		// description contains NO vocabulary token ("Message was deleted") still
		// classifies from err.jmapType — it can no longer reach the retry path
		// via description matching, because none happens.
		vi.mocked(client.emailSet).mockRejectedValue(
			new client.JmapMethodError('notFound', 'Message was deleted')
		);
		await offlineClient.emailSet(null, { 'msg-9': {} }, null, 'acct-delegate');
		await offlineClient.replayPendingActions();

		expect(db._issues).toHaveLength(1);
		expect(db._issues[0].kind).toBe('rejected');
		expect(db._issues[0].error).toBe('Message was deleted');
		expect(db._actionQueue.filter((r) => r.status === 'pending')).toHaveLength(0);
	});

	it('a method-level error whose description OMITS the token still classifies from its structured type (r2 ceiling closed)', async () => {
		// The r2 flagged ceiling: 'forbidden' → description 'fixed:access denied'
		// carries no vocabulary token, so prose matching could never recover the
		// type. With JmapMethodError the classification reads jmapType directly.
		vi.mocked(client.emailSet).mockRejectedValue(
			new client.JmapMethodError('forbidden', 'fixed:access denied')
		);
		await offlineClient.emailSet(null, { 'msg-9': {} }, null, 'acct-delegate');
		await offlineClient.replayPendingActions();

		expect(db._issues).toHaveLength(1);
		expect(db._issues[0].kind).toBe('rejected');
		expect(db._actionQueue.filter((r) => r.status === 'pending')).toHaveLength(0);
	});

	it('a method-level error with no description classifies from the type alone', async () => {
		// `description || type` fallback: the message IS the type; classification
		// reads jmapType either way.
		vi.mocked(client.emailSet).mockRejectedValue(new client.JmapMethodError('stateMismatch'));
		await offlineClient.emailSet(null, { 'msg-9': {} }, null, 'acct-delegate');
		await offlineClient.replayPendingActions();

		expect(db._issues).toHaveLength(1);
		expect(db._issues[0].kind).toBe('stale');
		expect(db._issues[0].error).toBe('stateMismatch');
		expect(db._actionQueue.filter((r) => r.status === 'pending')).toHaveLength(0);
	});

	it('an unknown method-level structured type stays transient (retry), like unknown prose', async () => {
		// A novel gateway type outside the closed vocabulary → null = retry,
		// unchanged from the r2 posture for unclassifiable failures.
		vi.mocked(client.emailSet).mockRejectedValue(
			new client.JmapMethodError('novelFutureType', 'something new')
		);
		await offlineClient.emailSet(null, { 'msg-9': {} }, null, 'acct-delegate');
		await offlineClient.replayPendingActions();

		expect(db._issues).toHaveLength(0);
		expect(db._actionQueue).toHaveLength(1);
		expect(db._actionQueue[0].attempts).toBe(1);
	});

	it('a transport failure with spaced vocabulary prose still routes to sync_issues (structured token fallback)', async () => {
		// Transport errors carry no structured type: the closed-vocabulary token
		// match over the message remains the fallback (not the old open prose
		// regex, which missed the spaced token and retried a permanent rejection).
		vi.mocked(client.emailSet).mockRejectedValue(new Error('Email not found'));
		await offlineClient.emailSet(null, { 'msg-9': {} }, null, 'acct-delegate');
		await offlineClient.replayPendingActions();

		expect(db._issues).toHaveLength(1);
		expect(db._issues[0].kind).toBe('rejected');
		expect(db._issues[0].error).toBe('Email not found');
		expect(db._actionQueue.filter((r) => r.status === 'pending')).toHaveLength(0);
	});

	it('unstructured transient failures still take the retry path, not sync_issues', async () => {
		// Transport prose carries no structured type token — must stay retryable.
		vi.mocked(client.emailSet).mockRejectedValue(new Error('JMAP error: 500'));
		await offlineClient.emailSet(null, { 'msg-9': {} }, null, 'acct-delegate');
		await offlineClient.replayPendingActions();

		expect(db._issues).toHaveLength(0);
		expect(db._actionQueue).toHaveLength(1);
		expect(db._actionQueue[0].status).toBe('pending'); // failOp bumped attempts, still retryable
		expect(db._actionQueue[0].attempts).toBe(1);
	});
});

// A8: the drain is INVOKED at the lifecycle seams the owner chose — app
// bootstrap after the first successful JMAP Session acquisition and each
// reconnect transition (browser online/offline + the JMAP push websocket
// reconnection, tested in websocket.test.ts). There is no manual-UI replay.
// The identity-generation fence is replay-internal (acct passthrough,
// b1r2-011): these tests pin that triggers firing under a freshly acquired
// session never double-drain or retarget a queued op.
describe('A8 drain wiring (bootstrap + reconnect)', () => {
	let offlineClient: typeof import('./offline-client');
	let client: typeof import('./client');
	let db: ReturnType<typeof fakeDb>;

	beforeEach(async () => {
		vi.resetAllMocks(); // clear persisted mock state (isOnline, client.emailSet, etc.) from prior test
		vi.resetModules();
		db = fakeDb();
		(window as never as { setjoinNative: { db: ReturnType<typeof fakeDb> } }).setjoinNative = { db };
		client = await import('./client');
		offlineClient = await import('./offline-client');
	});

	it('a reconnect transition invokes the drain through the registered online/offline listener', async () => {
		const { onNetworkChange } = await import('$lib/db/offline');
		vi.mocked(client.emailSet).mockResolvedValue({} as never);
		await offlineClient.emailSet(null, { 'msg-r': {} }, null, 'acct-1');

		// Module init registered exactly one reconnect handler on the existing seam.
		expect(onNetworkChange).toHaveBeenCalledTimes(1);
		const onNetwork = vi.mocked(onNetworkChange).mock.calls[0][0];
		onNetwork(true); // reconnect transition
		await vi.waitFor(() => expect(client.emailSet).toHaveBeenCalled());
		expect(client.emailSet).toHaveBeenCalledWith(null, { 'msg-r': {} }, null, 'acct-1');
		expect(db._actionQueue.filter((r) => r.status === 'pending')).toHaveLength(0);

		// The offline transition never drains.
		onNetwork(false);
		expect(client.emailSet).toHaveBeenCalledTimes(1);
	});

	it('a drain failure is contained (fire-and-forget), not an unhandled rejection', async () => {
		const { onNetworkChange } = await import('$lib/db/offline');
		vi.mocked(client.loadSession).mockRejectedValue(new Error('JMAP error: 503'));
		await offlineClient.emailSet(null, { 'msg-f': {} }, null, 'acct-1');
		const onNetwork = vi.mocked(onNetworkChange).mock.calls[0][0];
		// The trigger never surfaces the failure (no throw, no unhandled rejection).
		expect(() => onNetwork(true)).not.toThrow();
		await new Promise((resolve) => setTimeout(resolve, 0)); // flush the rejection path
		// The op stays queued for the next trigger — the failed drain lost nothing.
		expect(db._actionQueue.filter((r) => r.status === 'pending')).toHaveLength(1);
	});

	it('bootstrap: the first Session acquisition drains, once per page lifetime', async () => {
		const { isOnline } = await import('$lib/db/offline');
		const { jmapSession } = await import('$lib/stores/session');
		// Queue while offline (default isOnline → undefined = falsy), with a
		// transient failure so the op stays queued and a second drain would be
		// observable.
		vi.mocked(client.emailSet).mockRejectedValue(new Error('JMAP error: 503'));
		await offlineClient.emailSet(null, { 'msg-b': {} }, null, 'acct-1');
		vi.mocked(isOnline).mockReturnValue(true);

		jmapSession.set({} as never); // first successful Session acquisition at app bootstrap
		await vi.waitFor(() => expect(client.emailSet).toHaveBeenCalledTimes(1));
		expect(db._actionQueue[0].attempts).toBe(1); // drained, transiently failed, still queued

		// A later acquisition (token refresh re-loads caps) must NOT re-drain:
		// the bootstrap trigger is once per lifetime; reconnect seams own the rest.
		jmapSession.set({} as never);
		await new Promise((resolve) => setTimeout(resolve, 0));
		expect(client.emailSet).toHaveBeenCalledTimes(1);
	});

	it('bootstrap stays quiet while offline (the reconnect seam owns the later drain)', async () => {
		const { isOnline } = await import('$lib/db/offline');
		const { jmapSession } = await import('$lib/stores/session');
		vi.mocked(isOnline).mockReturnValue(false);
		await offlineClient.emailSet(null, { 'msg-c': {} }, null, 'acct-1');

		jmapSession.set({} as never);
		await new Promise((resolve) => setTimeout(resolve, 0));
		expect(client.emailSet).not.toHaveBeenCalled();
		expect(db._actionQueue.filter((r) => r.status === 'pending')).toHaveLength(1);
	});

	it('overlapping triggers collapse on the in-flight guard (no double replay)', async () => {
		const { onNetworkChange } = await import('$lib/db/offline');
		let release!: () => void;
		vi.mocked(client.loadSession).mockReturnValue(
			new Promise<void>((resolve) => (release = resolve)) as never
		);
		vi.mocked(client.emailSet).mockResolvedValue({} as never);
		await offlineClient.emailSet(null, { 'msg-o': {} }, null, 'acct-1');

		const onNetwork = vi.mocked(onNetworkChange).mock.calls[0][0];
		onNetwork(true);
		onNetwork(true); // second trigger while the first drain is mid-flight
		release();
		await vi.waitFor(() => expect(client.emailSet).toHaveBeenCalledTimes(1));
		expect(client.emailSet).toHaveBeenCalledTimes(1); // exactly one drain issued the op
	});

	it('a bootstrap trigger during an in-flight reconnect drain neither double-replays nor re-targets the op (identity fence)', async () => {
		const { onNetworkChange, isOnline } = await import('$lib/db/offline');
		const { jmapSession } = await import('$lib/stores/session');
		vi.mocked(isOnline).mockReturnValue(true);
		let release!: () => void;
		vi.mocked(client.loadSession).mockReturnValue(
			new Promise<void>((resolve) => (release = resolve)) as never
		);
		vi.mocked(client.emailSet).mockResolvedValue({} as never);
		await offlineClient.emailSet(null, { 'msg-x': {} }, null, 'acct-delegate');

		const onNetwork = vi.mocked(onNetworkChange).mock.calls[0][0];
		onNetwork(true); // reconnect drain starts (gated inside loadSession)
		jmapSession.set({} as never); // bootstrap trigger arrives mid-flight — guard must absorb it
		release();
		await vi.waitFor(() => expect(client.emailSet).toHaveBeenCalledTimes(1));
		// The op replayed under the identity that queued it — the mid-flight
		// session acquisition never re-targeted or duplicated it.
		expect(client.emailSet).toHaveBeenCalledWith(null, { 'msg-x': {} }, null, 'acct-delegate');
	});
});
