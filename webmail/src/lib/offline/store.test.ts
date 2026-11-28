import { describe, it, expect, beforeEach, vi } from 'vitest';
import { isOfflineAvailable, getStore, type StoredMessage } from './store';

// Stub fetch for profile.ts (fetchCryptoProfile). Tests that don't care about
// the profile get 'standard' (AES default); the profile-open test overrides it.
// ponytail: global stub here — profile.ts defers to 'standard' on any fetch
// failure, so tests that don't stub fetch also get 'standard' safely.
vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({}), { status: 200 })));

// A tiny in-memory fake of the GENERIC window.setjoinNative.db (every method
// takes appKey first) backed by a Map. We don't run real SQL in unit tests; we
// assert the store issues the right calls (with appKey='mail') and round-trips
// rows. The Rust store_test covers actual SQLCipher/FTS behaviour. CREATE DDL
// from the TS migration is a no-op here.
function fakeDb() {
	// Row shape matches MsgRow (snake_case) + version/dirty_fields for F1/F4.
	const messages = new Map<string, Record<string, unknown>>();
	const fts = new Map<string, string>(); // id -> "subject body addrs"
	const meta = new Map<string, string>();
	// message_tags: message_id -> Set<tag_id>
	const messageTags = new Map<string, Set<string>>();
	// action_queue: id -> { type, payload, status, attempts }
	const actionQueue: Array<{ id: number; type: string; payload: string; status: string; attempts: number }> = [];
	let aqSeq = 1;
	// r4: init() probes sqlite_master for the stored recovery_artifacts DDL (U6
	// upgrade check). null = fresh store (no row yet); a string = stored DDL.
	let recoveryDdl: string | null = null;

	// Parse "SET col = ?, col2 = ?" from an UPDATE statement and apply to row.
	// Also parses "version = version + 1" (increment) and "dirty_fields = ?".
	function applyUpdate(sql: string, params: unknown[], row: Record<string, unknown>): void {
		// Extract the SET clause (between SET and WHERE)
		const setMatch = sql.match(/SET\s+(.+?)\s+WHERE\s+/is);
		if (!setMatch) return;
		const setClause = setMatch[1];
		// Split on commas (not inside parens) — simple split works for our DDL
		const assignments = setClause.split(',').map((s) => s.trim());
		let paramIdx = 0;
		for (const assign of assignments) {
			// "version = version + 1" — increment
			if (/^version\s*=\s*version\s*\+\s*1$/i.test(assign)) {
				row['version'] = ((row['version'] as number) ?? 0) + 1;
				continue;
			}
			// "col = ?" — take next param
			const colMatch = assign.match(/^(\w+)\s*=\s*\?$/);
			if (colMatch) {
				row[colMatch[1]] = params[paramIdx++];
			}
		}
	}

	return {
		open: vi.fn(async (_appKey: string) => {}),
		isOpen: vi.fn(async (_appKey: string) => false), // force init() to open + migrate
		// r3 sql guard: MAIL_SCHEMA is applied only through the authorized
		// one-shot schema-init seam; the fake applies nothing (real DDL/FTS
		// behaviour is covered by offline-core's store_test).
		execSchemaInit: vi.fn(async (_appKey: string, _schema: string) => 0),
		exec: vi.fn(async (_appKey: string, sql: string, params: unknown[] = []) => {
			if (/^\s*CREATE/i.test(sql)) return 0; // TS schema migration — no-op in the fake
			if (/^\s*BEGIN\s*$/i.test(sql)) return 0;
			if (/^\s*COMMIT\s*$/i.test(sql)) return 0;
			if (/^\s*ROLLBACK\s*$/i.test(sql)) return 0;
			if (/INSERT.*INTO messages\b/i.test(sql) && !/fts|message_tags|action_queue/i.test(sql)) {
				// INSERT OR REPLACE INTO messages (...) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
				const [id, threadId, receivedAt, flags, hasAtt, cacheState, syncedAt, from_, to_, cc, bcc, subject, preview, version, dirtyFields] = params as never[];
				messages.set(id as string, {
					id, thread_id: threadId, received_at: receivedAt, flags, has_attachment: hasAtt ? 1 : 0,
					cache_state: cacheState, synced_at: syncedAt, from_: from_, to_: to_, cc, bcc,
					subject, preview, version: version ?? 0, dirty_fields: dirtyFields ?? '[]'
				});
			} else if (/INSERT.*messages_fts/i.test(sql)) {
				const [id, subject, body, addrs] = params as string[];
				fts.set(id, `${subject} ${body} ${addrs}`.toLowerCase());
			} else if (/DELETE FROM messages_fts WHERE id/i.test(sql)) {
				fts.delete(params[0] as string);
			} else if (/DELETE FROM messages WHERE id/i.test(sql)) {
				messages.delete(params[0] as string);
			} else if (/DELETE FROM message_tags WHERE message_id/i.test(sql)) {
				messageTags.delete(params[0] as string);
			} else if (/INSERT.*INTO message_tags/i.test(sql)) {
				const msgId = params[0] as string;
				const tagId = params[1] as string;
				if (!messageTags.has(msgId)) messageTags.set(msgId, new Set());
				messageTags.get(msgId)!.add(tagId);
			} else if (/INSERT.*INTO action_queue/i.test(sql)) {
				// action_queue INSERT — used in F5 transactional outbox test
				// The test may mock this to throw; if not intercepted, store it
				actionQueue.push({ id: aqSeq++, type: params[0] as string, payload: params[1] as string, status: 'pending', attempts: 0 });
			} else if (/DELETE FROM action_queue WHERE id/i.test(sql)) {
				const idx = actionQueue.findIndex((r) => r.id === (params[0] as number));
				if (idx !== -1) actionQueue.splice(idx, 1);
			} else if (/UPDATE action_queue SET/i.test(sql)) {
				// failOp: increment attempts, flip to 'failed' at ≥3
				const row = actionQueue.find((r) => r.id === (params[params.length - 1] as number));
				if (row) { row.attempts += 1; row.status = row.attempts >= 3 ? 'failed' : 'pending'; }
			} else if (/INSERT.*INTO meta_mail/i.test(sql)) {
				meta.set(params[0] as string, params[1] as string);
			} else if (/DELETE FROM messages WHERE received_at <\s*\?/i.test(sql)) {
				const cutoff = params[0] as number;
				for (const [id, m] of messages) if ((m.received_at as number) < cutoff) messages.delete(id);
			} else if (/UPDATE messages SET/i.test(sql)) {
				// F1/F4 UPDATE — parse SET clause and apply to row (id is last param)
				const id = params[params.length - 1] as string;
				const row = messages.get(id);
				if (row) applyUpdate(sql, params as unknown[], row);
			}
			return 1;
		}),
		query: vi.fn(async (_appKey: string, sql: string, params: unknown[] = []) => {
			// listByReceivedDesc: LEFT JOIN with GROUP_CONCAT + ORDER BY m.received_at
			if (/ORDER BY m\.received_at/i.test(sql)) {
				return [...messages.values()]
					.sort((a, b) => (b.received_at as number) - (a.received_at as number))
					.map((m) => ({ ...m, tag_ids: [...(messageTags.get(m.id as string) ?? [])].join(',') }));
			}
			if (/messages_fts MATCH/i.test(sql)) {
				const q = (params[0] as string).toLowerCase();
				return [...fts.entries()].filter(([, t]) => t.includes(q)).map(([id]) => ({ id }));
			}
			// getMessage: WHERE m.id = ? (with table alias)
			if (/WHERE m\.id\s*=\s*\?/i.test(sql)) {
				const m = messages.get(params[0] as string);
				if (!m) return [];
				return [{ ...m, tag_ids: [...(messageTags.get(m.id as string) ?? [])].join(',') }];
			}
			// getVersion / bumpLocalVersion (no alias)
			if (/FROM messages WHERE id\s*=\s*\?/i.test(sql)) {
				const m = messages.get(params[0] as string);
				return m ? [{ ...m, tag_ids: [...(messageTags.get(m.id as string) ?? [])].join(',') }] : [];
			}
			if (/SELECT version.*FROM messages WHERE id/i.test(sql)) {
				const m = messages.get(params[0] as string);
				return m ? [{ version: m.version ?? 0, dirty_fields: m.dirty_fields ?? '[]' }] : [];
			}
			if (/SELECT value FROM meta_mail WHERE key/i.test(sql)) {
				const v = meta.get(params[0] as string);
				return v !== undefined ? [{ value: v }] : [];
			}
			if (/SELECT COUNT\(\*\)/i.test(sql)) {
				if (/received_at </i.test(sql)) {
					const cutoff = params[0] as number;
					const n = [...messages.values()].filter((m) => (m.received_at as number) < cutoff).length;
					return [{ n }];
				}
			}
			// pendingMessageIds + listPendingOps: action_queue pending (return full rows)
			if (/FROM action_queue WHERE status\s*=\s*'pending'/i.test(sql)) {
				return actionQueue.filter((r) => r.status === 'pending');
			}
			// init()'s schema-detection probe (r4 + E4-I versioned migrations):
			// plain SELECT over the schema metadata. Rows carry {name, sql} so
			// the E4-I detector can distinguish recovery_artifacts DDL from the
			// optional_jobs/attachment_transfers tables in one probe.
			if (/FROM sqlite_master/i.test(sql)) {
				return recoveryDdl === null ? [] : [{ name: 'recovery_artifacts', sql: recoveryDdl }];
			}
			// r4: NO catch-all. An unrecognized statement must fail loudly so this
			// suite catches any SQL the store issues that the fake (and the real
			// bridge allowlists) have not vetted — the old `return []` here masked
			// init()'s PRAGMA table_info probe being rejected by every real shell
			// (med-offcore-sqlguard-001 r4).
			throw new Error(`fake db: unmatched query: ${sql}`);
		}),
		// Test hook for the U6-probe state (see recoveryDdl above).
		setRecoveryDdl: (ddl: string | null) => {
			recoveryDdl = ddl;
		},
		wipe: vi.fn(async (_appKey: string) => { messages.clear(); fts.clear(); meta.clear(); messageTags.clear(); actionQueue.length = 0; }),
	};
}

describe('offline store interface', () => {
	beforeEach(() => {
		// Reset cached store singleton between tests
		(globalThis as Record<string, unknown>)['__offline_store_cache_reset__'] = true;
		delete (window as never as { setjoinNative?: unknown }).setjoinNative;
		// Reset the module-level cached singleton — re-import forces it
		vi.resetModules();
	});

	it('isOfflineAvailable is false with no native db bridge', async () => {
		const { isOfflineAvailable: check, getStore: gs } = await import('./store');
		expect(check()).toBe(false);
		expect(gs()).toBeNull();
	});

	it('native store upserts, lists, and body-searches', async () => {
		(window as never as { setjoinNative: { db: ReturnType<typeof fakeDb> } }).setjoinNative = { db: fakeDb() };
		const { isOfflineAvailable: check, getStore: gs } = await import('./store');
		expect(check()).toBe(true);
		const store = gs()!;
		await store.init();
		await store.upsertMessage({
			id: 'm1', threadId: 't', receivedAt: 100, flags: [], hasAttachment: false,
			cacheState: 'full', syncedAt: 0, from: 'alice@corp', to: 'b@y', cc: '', bcc: '',
			subject: 'Quarterly Report', preview: 'p', tagIds: ['Inbox']
		});
		const list = await store.listByReceivedDesc(10);
		expect(list.map((m) => m.id)).toContain('m1');
		const hits = await store.searchBody('quarterly');
		expect(hits).toContain('m1');
	});

	// F1 + F4: column-level LWW merge. The merge/version path issues real
	// UPDATE/SELECT SQL, so this arm uses a SQL-faithful fake (parses the
	// `SET col = ?` list + WHERE version) — the canonical regression is the
	// mark-read-offline-while-tag-added case: neither change is lost.
	it('mergeServerDelta merges only changed columns, never whole-record (F1)', async () => {
		(window as never as { setjoinNative: { db: ReturnType<typeof fakeDb> } }).setjoinNative = { db: fakeDb() };
		const { getStore: gs } = await import('./store');
		const store = gs()!;
		await store.init();
		await store.upsertMessage({
			id: 'm9', threadId: 't', receivedAt: 100, flags: [], hasAttachment: false,
			cacheState: 'full', syncedAt: 0, from: 'a@x', to: '', cc: '', bcc: '',
			subject: 'S', preview: 'p', tagIds: ['Inbox']
		});
		// Optimistic offline mark-read: bumps watermark + marks `flags` dirty.
		await store.bumpLocalVersion('m9', ['flags']);
		// A server delta trying to write `flags` at version 0 — lower than bumped watermark, SKIPPED.
		await store.mergeServerDelta('m9', { flags: ['$seen'] }, 0);
		// A server delta that moved the message (threadId) at a higher version:
		const res = await store.mergeServerDelta('m9', { threadId: 't2' }, 5);
		expect(res).toBe('merged');
		const m = await store.getMessage('m9');
		// F1: the offline mark-read survived AND the server move applied.
		expect(m!.dirtyFields).toContain('flags'); // local edit retained (not acked yet)
		expect(m!.threadId).toBe('t2');            // server field merged
		expect(m!.version).toBeGreaterThanOrEqual(5);
	});

	it('mergeServerDelta skips a stale (lower-version) delta and reports absent (F4)', async () => {
		(window as never as { setjoinNative: { db: ReturnType<typeof fakeDb> } }).setjoinNative = { db: fakeDb() };
		const { getStore: gs } = await import('./store');
		const store = gs()!;
		await store.init();
		expect(await store.mergeServerDelta('nope', { subject: 'x' }, 1)).toBe('absent');
		await store.upsertMessage({
			id: 'm10', threadId: 't', receivedAt: 1, flags: [], hasAttachment: false,
			cacheState: 'full', syncedAt: 0, from: '', to: '', cc: '', bcc: '',
			subject: 'S', preview: 'p', tagIds: [], version: 9
		});
		expect(await store.mergeServerDelta('m10', { subject: 'old' }, 3)).toBe('skipped'); // 3 < 9
	});

	it('pendingMessageIds returns ids from action_queue (F2 seam)', async () => {
		(window as never as { setjoinNative: { db: ReturnType<typeof fakeDb> } }).setjoinNative = { db: fakeDb() };
		const { getStore: gs } = await import('./store');
		const store = gs()!;
		await store.init();
		// No ops yet — set is empty.
		expect((await store.pendingMessageIds()).size).toBe(0);
		// Enqueue an optimistic edit — puts an action_queue row with payload.id = 'pm1'.
		await store.upsertMessage({ id: 'pm1', threadId: 't', receivedAt: 1, flags: [], hasAttachment: false, cacheState: 'full', syncedAt: 0, from: '', to: '', cc: '', bcc: '', subject: 'S', preview: 'p', tagIds: [] });
		await store.enqueueOptimisticEdit('pm1', { flags: ['$seen'] }, { type: 'emailSetUpdate', payload: { id: 'pm1' } });
		const pending = await store.pendingMessageIds();
		expect(pending.has('pm1')).toBe(true);
	});

	it('listPendingOps returns full action objects; ackOp removes them; failOp increments attempts', async () => {
		(window as never as { setjoinNative: { db: ReturnType<typeof fakeDb> } }).setjoinNative = { db: fakeDb() };
		const { getStore: gs } = await import('./store');
		const store = gs()!;
		await store.init();
		await store.upsertMessage({ id: 'q1', threadId: 't', receivedAt: 1, flags: [], hasAttachment: false, cacheState: 'full', syncedAt: 0, from: '', to: '', cc: '', bcc: '', subject: 'S', preview: '', tagIds: [] });
		await store.enqueueOptimisticEdit('q1', {}, { type: 'emailSetUpdate', payload: { id: 'q1' } });
		const ops = await store.listPendingOps();
		expect(ops).toHaveLength(1);
		expect(ops[0].type).toBe('emailSetUpdate');
		expect((ops[0].payload as { id: string }).id).toBe('q1');
		// ackOp removes the op
		await store.ackOp(ops[0].id);
		expect(await store.listPendingOps()).toHaveLength(0);
		// failOp increments attempts and keeps 'pending' until ≥3
		await store.enqueueOptimisticEdit('q1', {}, { type: 'emailSetUpdate', payload: { id: 'q1' } });
		const op2 = (await store.listPendingOps())[0];
		await store.failOp(op2.id, 'transient');
		await store.failOp(op2.id, 'transient');
		// 2 attempts — still pending
		expect(await store.listPendingOps()).toHaveLength(1);
		await store.failOp(op2.id, 'transient');
		// 3 attempts — dropped to 'failed', no longer in pending list
		expect(await store.listPendingOps()).toHaveLength(0);
	});

	it('init() passes a crypto profile as the second arg to db.open (A4 delta)', async () => {
		// Default stub returns empty JSON → fetchCryptoProfile yields 'standard'.
		const fake = fakeDb();
		(window as never as { setjoinNative: { db: ReturnType<typeof fakeDb> } }).setjoinNative = { db: fake };
		const { getStore: gs } = await import('./store');
		await gs()!.init();
		// db.open is called with (appKey, profile) — profile must be 'standard' or 'SMx'.
		const openCalls = fake.open.mock.calls as unknown[][];
		expect(openCalls).toHaveLength(1);
		expect(['standard', 'SMx']).toContain(openCalls[0][1]);
	});

	it('init() applies MAIL_SCHEMA through the authorized execSchemaInit seam, never exec (r3 sql guard)', async () => {
		const fake = fakeDb();
		(window as never as { setjoinNative: { db: ReturnType<typeof fakeDb> } }).setjoinNative = { db: fake };
		const { getStore: gs } = await import('./store');
		await gs()!.init();
		// Exactly one schema-init call carrying the multi-statement DDL…
		const initCalls = fake.execSchemaInit.mock.calls as unknown[][];
		expect(initCalls).toHaveLength(1);
		expect(initCalls[0][0]).toBe('mail');
		expect(String(initCalls[0][1])).toContain('CREATE TABLE IF NOT EXISTS messages');
		// …and ordinary exec must never see a multi-statement payload.
		for (const [sql] of fake.exec.mock.calls as unknown[][]) {
			expect(String(sql).split(';').filter((part) => part.trim().length > 0)).toHaveLength(1);
		}
	});

	it('init() probes sqlite_master via a plain SELECT and never issues PRAGMA (r4)', async () => {
		const fake = fakeDb();
		(window as never as { setjoinNative: { db: ReturnType<typeof fakeDb> } }).setjoinNative = { db: fake };
		const { getStore: gs } = await import('./store');
		await gs()!.init();
		// The ONLY query init() issues is the sqlite_master probe — the old
		// `PRAGMA table_info(recovery_artifacts)` read was rejected by every
		// shell gate (Electron db_query allowlist, offline-core allowlist) and
		// made every real initialization fail (med-offcore-sqlguard-001 r4).
		const queryCalls = fake.query.mock.calls as unknown[][];
		expect(queryCalls).toHaveLength(1);
		expect(String(queryCalls[0][1])).toMatch(/FROM sqlite_master/);
		// Fresh store: the authorized batch carries NO upgrade ALTER.
		const initCalls = fake.execSchemaInit.mock.calls as unknown[][];
		expect(initCalls).toHaveLength(1);
		expect(String(initCalls[0][1])).not.toContain('ALTER TABLE');
		// No PRAGMA anywhere, on any bridge call init() makes.
		const allSql = [
			...queryCalls.map((c) => c[1]),
			...initCalls.map((c) => c[1]),
			...(fake.exec.mock.calls as unknown[][]).map((c) => c[1]),
		];
		for (const sql of allSql) {
			expect(String(sql)).not.toMatch(/PRAGMA/i);
		}
	});

	it('init() upgrades a pre-U6 recovery_artifacts store through the authorized batch (r4)', async () => {
		const fake = fakeDb();
		// Pre-release U6 shape: the first recovery table (no `eligibility` column)
		// — the stored DDL the probe reads back from sqlite_master.
		fake.setRecoveryDdl(
			"CREATE TABLE recovery_artifacts (artifact_identity TEXT PRIMARY KEY, message_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'covered')",
		);
		(window as never as { setjoinNative: { db: ReturnType<typeof fakeDb> } }).setjoinNative = { db: fake };
		const { getStore: gs } = await import('./store');
		await gs()!.init();
		// The upgrade rides the ONE authorized batch (ALTER is batch-valid)…
		const initCalls = fake.execSchemaInit.mock.calls as unknown[][];
		expect(initCalls).toHaveLength(1);
		expect(String(initCalls[0][1])).toContain(
			'ALTER TABLE recovery_artifacts ADD COLUMN eligibility',
		);
		// …never through ordinary exec, and never via PRAGMA.
		for (const [sql] of fake.exec.mock.calls as unknown[][]) {
			expect(String(sql)).not.toMatch(/ALTER|PRAGMA/i);
		}
	});

	it('fake db rejects unmatched queries instead of masking them (r4)', async () => {
		const fake = fakeDb();
		await expect(
			fake.query('mail', 'PRAGMA table_info(recovery_artifacts)'),
		).rejects.toThrow(/unmatched query/);
	});

	it('init() fails closed when a shell lacks the authorized schema-init seam', async () => {
		const fake = fakeDb();
		delete (fake as Partial<{ execSchemaInit: unknown }>).execSchemaInit;
		(window as never as { setjoinNative: { db: ReturnType<typeof fakeDb> } }).setjoinNative = { db: fake };
		const { getStore: gs } = await import('./store');
		await expect(gs()!.init()).rejects.toThrow(/execSchemaInit/);
		// Fail-closed: the multi-statement batch never went through ordinary exec.
		for (const [sql] of fake.exec.mock.calls as unknown[][]) {
			expect(String(sql)).not.toContain(';');
		}
	});

	it('F5 transactional outbox: a crash between cache-write and queue-write rolls back (atomic)', async () => {
		// Simulate a crash AFTER the cache UPDATE but BEFORE the action_queue INSERT
		// commits: make the INSERT throw. enqueueOptimisticEdit must issue ROLLBACK,
		// so neither the optimistic edit nor a dangling op survives — all-or-nothing.
		const fake = fakeDb();
		(window as never as { setjoinNative: { db: ReturnType<typeof fakeDb> } }).setjoinNative = { db: fake };
		const { getStore: gs } = await import('./store');
		const store = gs()!;
		await store.init();
		await store.upsertMessage({
			id: 'mt', threadId: 't', receivedAt: 1, flags: [], hasAttachment: false,
			cacheState: 'full', syncedAt: 0, from: '', to: '', cc: '', bcc: '',
			subject: 'S', preview: 'p', tagIds: []
		});
		const calls: string[] = [];
		// Capture the ORIGINAL implementation before replacing it — vi.fn() stores it
		// separately from the mock wrapper so calling it won't re-enter the interceptor.
		const realImpl = fake.exec.getMockImplementation()!;
		fake.exec.mockImplementation(async (appKey: string, sql: string, params?: unknown[]) => {
			calls.push(sql.trim().split(/\s+/).slice(0, 2).join(' ').toUpperCase());
			if (/INSERT INTO action_queue/i.test(sql)) throw new Error('crash before queue commit');
			return realImpl(appKey, sql, params);
		});
		await expect(
			store.enqueueOptimisticEdit('mt', { flags: ['$seen'] }, { type: 'emailSetUpdate', payload: { id: 'mt' } })
		).rejects.toThrow();
		// The transaction was opened and rolled back (never committed).
		expect(calls).toContain('BEGIN');
		expect(calls).toContain('ROLLBACK');
		expect(calls).not.toContain('COMMIT');
	});
});
