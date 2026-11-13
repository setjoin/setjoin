// med-shard2-004: account scoping + auth-teardown purge for the IndexedDB
// offline queue (D-MAILSERVER-WEBMAIL-SRC-LIB-DB-001/-002 isolation half).
//
// Covers the package's proposed tests:
// - logout / impersonation end / account switch evict queued actions;
// - getPendingActions never returns records scoped to a prior account
//   (including legacy untagged rows);
// - queueing fails closed with no authenticated identity (no un-attributable
//   residue can be recreated).
//
// jsdom has no IndexedDB and the project carries no fake-indexeddb dependency,
// so a minimal in-memory IndexedDB stub covers exactly the surface offline.ts
// uses (open/upgrade, add/get/put/delete/clear, index getAll + openCursor).
import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
	queueAction,
	getPendingActions,
	markActionDone,
	markActionFailed,
	clearFailedActions,
	purgeOfflineQueue
} from './offline';
import { user, registerAuthSessionTeardown } from '$lib/stores/auth';

vi.mock('$lib/stores/auth', async () => {
	const { writable } = await import('svelte/store');
	return {
		user: writable(null),
		registerAuthSessionTeardown: vi.fn(() => vi.fn())
	};
});

// --- minimal IndexedDB stub ---------------------------------------------------

type StubRecord = { id?: number; accountId?: string; status?: string;[k: string]: unknown };
interface StubStore {
	records: Map<number, StubRecord>;
	autoInc: number;
	indexes: Map<string, { keyPath: string }>;
}
interface StubDB {
	name: string;
	version: number;
	stores: Map<string, StubStore>;
}

class StubRequest {
	result: unknown = undefined;
	error: Error | null = null;
	transaction: { objectStore: (name: string) => unknown } | null = null;
	onsuccess: ((ev: { target: StubRequest }) => void) | null = null;
	onerror: ((ev: { target: StubRequest }) => void) | null = null;
	onupgradeneeded: ((ev: { target: StubRequest }) => void) | null = null;
	fire(): void {
		queueMicrotask(() => this.onsuccess?.({ target: this }));
	}
}

// Delayed-completion gate: when set, index getAll completions wait for it —
// simulating an IDB event landing after an identity switch (identity fence test).
let getAllGate: Promise<void> | null = null;

function makeIDBStub() {
	const dbs = new Map<string, StubDB>();

	const storeApi = (db: StubDB, name: string) => {
		const store = db.stores.get(name)!;
		return {
			indexNames: { contains: (n: string) => store.indexes.has(n) },
			createIndex(idx: string, keyPath: string) {
				store.indexes.set(idx, { keyPath });
			},
				index(idx: string) {
					const meta = store.indexes.get(idx)!;
					return {
						getAll(value?: unknown) {
							const req = new StubRequest();
							const finish = () => {
								req.result = [...store.records.values()].filter((r) => r[meta.keyPath] === value);
								req.fire();
							};
							if (getAllGate) getAllGate.then(finish);
							else finish();
							return req;
						},
					openCursor(value?: unknown) {
						const req = new StubRequest();
						let lastId = 0;
						const step = () => {
							const next = [...store.records.values()]
								.filter((r) => r[meta.keyPath] === value && (r.id as number) > lastId)
								.sort((a, b) => (a.id as number) - (b.id as number))[0];
							if (next) {
								lastId = next.id as number;
								req.result = {
									value: next,
									delete: () => store.records.delete(next.id as number),
									continue: () => queueMicrotask(step)
								};
							} else {
								req.result = null;
							}
							queueMicrotask(() => req.onsuccess?.({ target: req }));
						};
						queueMicrotask(step);
						return req;
					}
				};
			},
			add(rec: StubRecord) {
				const id = ++store.autoInc;
				rec.id = id;
				store.records.set(id, rec);
				const req = new StubRequest();
				req.result = id;
				req.fire();
				return req;
			},
			get(key: number) {
				const req = new StubRequest();
				req.result = store.records.get(key);
				req.fire();
				return req;
			},
			put(rec: StubRecord) {
				const id = (rec.id as number) ?? ++store.autoInc;
				rec.id = id;
				store.records.set(id, rec);
				const req = new StubRequest();
				req.result = id;
				req.fire();
				return req;
			},
			delete(key: number) {
				store.records.delete(key);
				const req = new StubRequest();
				req.fire();
				return req;
			},
			clear() {
				store.records.clear();
				const req = new StubRequest();
				req.fire();
				return req;
			}
		};
	};

	const dbProxy = (db: StubDB) => ({
		objectStoreNames: { contains: (n: string) => db.stores.has(n) },
		createObjectStore(n: string) {
			db.stores.set(n, { records: new Map(), autoInc: 0, indexes: new Map() });
			return storeApi(db, n);
		},
		transaction(_n: string, _mode?: string) {
			return { objectStore: (n: string) => storeApi(db, n) };
		},
		close() {}
	});

	const ensureDB = (dbName: string, storeName: string, version = 2, indexNames: string[] = ['status', 'type', 'accountId']) => {
		let db = dbs.get(dbName);
		if (!db) {
			db = { name: dbName, version, stores: new Map() };
			dbs.set(dbName, db);
		}
		if (!db.stores.has(storeName)) {
			db.stores.set(storeName, {
				records: new Map(),
				autoInc: 0,
				indexes: new Map(indexNames.map((n) => [n, { keyPath: n }]))
			});
		}
		return db;
	};

	const factory = {
		open(name: string, version?: number) {
			const req = new StubRequest();
			queueMicrotask(() => {
				let db = dbs.get(name);
				const target = version ?? 1;
				if (!db) {
					db = { name, version: 0, stores: new Map() };
					dbs.set(name, db);
				}
				if (target > db.version) {
					db.version = target;
					req.transaction = { objectStore: (n: string) => storeApi(db!, n) };
					req.result = dbProxy(db);
					req.onupgradeneeded?.({ target: req });
				}
				req.transaction = null;
				req.result = dbProxy(db);
				req.fire();
			});
			return req;
		}
	};

	return { dbs, ensureDB, factory: factory as unknown as IDBFactory };
}

const DB_NAME = 'mailserver_offline';
const STORE = 'action_queue';

// One stub for the file's lifetime: offline.ts caches its IDBDatabase connection,
// so the shared StubDB object identity must never change — only its records reset.
const stub = makeIDBStub();
vi.stubGlobal('indexedDB', stub.factory);
const sharedDB = stub.ensureDB(DB_NAME, STORE, 2);

const seed = (rec: StubRecord) => {
	const store = sharedDB.stores.get(STORE)!;
	const id = (rec.id as number) ?? ++store.autoInc;
	rec.id = id;
	store.records.set(id, rec);
	return rec;
};
const dump = (): StubRecord[] => [...sharedDB.stores.get(STORE)!.records.values()];
const resetRecords = () => sharedDB.stores.get(STORE)!.records.clear();

let accountSeq = 0;
const currentAccountId = () => `email:acct${accountSeq}@x.test`;
const loginAs = () => user.set({ email: `acct${++accountSeq}@x.test`, isAdmin: false, hasMailbox: true });
const ownRecord = (): StubRecord => ({
	type: 'email.send',
	payload: { body: 'draft text' },
	status: 'pending',
	createdAt: Date.now(),
	retries: 0,
	accountId: currentAccountId()
});
const foreignRecord = (): StubRecord => ({ ...ownRecord(), accountId: 'email:foreign@x.test' });
const legacyRecord = (): StubRecord => {
	const { accountId: _accountId, ...rest } = ownRecord();
	return rest; // pre-scoping row: no accountId
};

const flush = () => new Promise((r) => setTimeout(r, 0));

beforeEach(async () => {
	resetRecords();
	user.set(null);
	await flush();
	await flush();
});

describe('account scoping of the offline queue', () => {
	it('tags queued actions with the authenticated account identity', async () => {
		loginAs();
		const id = await queueAction('email.send', { body: 'draft text' });
		const rows = dump();
		expect(rows).toHaveLength(1);
		expect(rows[0].id).toBe(id);
		expect(rows[0].accountId).toBe(currentAccountId());
	});

	it('fails closed with no authenticated identity and persists nothing', async () => {
		await expect(queueAction('email.send', { body: 'x' })).rejects.toThrow(/no authenticated identity/);
		expect(dump()).toHaveLength(0);
	});

	it('getPendingActions returns only the current identity pending rows', async () => {
		loginAs(); // acquisition purge runs against the (empty) store first
		await flush();
		seed(ownRecord());
		seed({ ...foreignRecord(), status: 'pending' });
		seed({ ...ownRecord(), status: 'failed' });

		const pending = await getPendingActions();
		expect(pending).toHaveLength(1);
		expect(pending[0].accountId).toBe(currentAccountId());
	});

	it('getPendingActions returns nothing without an authenticated identity', async () => {
		seed(ownRecord());
		expect(await getPendingActions()).toEqual([]);
	});

	it('legacy untagged rows are never returned even before the purge lands', async () => {
		loginAs();
		await flush();
		seed(legacyRecord());
		expect(await getPendingActions()).toEqual([]);
	});

	it('logout (identity to null) evicts all queued actions', async () => {
		loginAs();
		await queueAction('email.send', { body: 'draft' });
		expect(dump()).toHaveLength(1);

		user.set(null); // logout resets identity
		await flush();

		expect(dump()).toHaveLength(0);
		expect(await getPendingActions()).toEqual([]);
	});

	it('account switch (impersonation end / different user) evicts the prior identity actions', async () => {
		loginAs();
		await queueAction('email.send', { body: 'admin session draft' });

		loginAs(); // different account
		await flush();

		expect(dump()).toHaveLength(0);
		// the new session can queue and read its own actions again
		await queueAction('email.send', { body: 'new session draft' });
		const pending = await getPendingActions();
		expect(pending).toHaveLength(1);
		expect(pending[0].accountId).toBe(currentAccountId());
	});

	it('the registered auth teardown purges the whole queue', async () => {
		expect(registerAuthSessionTeardown).toHaveBeenCalled();
		const teardown = vi.mocked(registerAuthSessionTeardown).mock.calls[0][0];

		loginAs();
		await queueAction('email.send', { body: 'draft' });

		teardown();
		await flush();

		expect(dump()).toHaveLength(0);
	});

	it('purgeOfflineQueue clears everything directly', async () => {
		loginAs();
		await queueAction('email.send', { body: 'x' });
		await purgeOfflineQueue();
		expect(dump()).toHaveLength(0);
	});
});

describe('ownership-checked mutations', () => {
	it('markActionDone deletes own records and ignores foreign-identity ids', async () => {
		loginAs();
		await flush();
		const foreign = seed(foreignRecord());
		const own = await queueAction('email.send', { body: 'mine' });

		await markActionDone((foreign.id as number) + 100000); // unknown id → no-op
		await markActionDone(foreign.id as number); // foreign → ignored
		expect(dump().map((r) => r.id)).toContain(foreign.id);

		await markActionDone(own);
		expect(dump().map((r) => r.id)).toEqual([foreign.id]);
	});

	it('markActionFailed mutates only own records and keeps the retry ladder', async () => {
		loginAs();
		await flush();
		const foreign = seed(foreignRecord());
		const own = await queueAction('email.send', { body: 'mine' });

		await markActionFailed(foreign.id as number, 'boom');
		expect(foreign.status).toBe('pending');
		expect(foreign.error).toBeUndefined();

		// retry ladder: pending again under 3 retries, terminal failed from the 3rd
		await markActionFailed(own, 'boom');
		let row = dump().find((r) => r.id === own)!;
		expect(row.status).toBe('pending'); // retries 1 < 3 — retry later
		await markActionFailed(own, 'boom');
		await markActionFailed(own, 'boom');
		row = dump().find((r) => r.id === own)!;
		expect(row.status).toBe('failed');
		expect(row.error).toBe('boom');
		expect(row.retries).toBe(3);
	});

	it('clearFailedActions clears only the current identity failed records', async () => {
		loginAs();
		await flush();
		const foreign = seed({ ...foreignRecord(), status: 'failed', error: 'old', retries: 3 });
		const own = await queueAction('email.send', { body: 'mine' });
		// drive the own record to terminal failed so it is cursor-visible
		await markActionFailed(own, 'boom');
		await markActionFailed(own, 'boom');
		await markActionFailed(own, 'boom');

		await clearFailedActions();

		const rows = dump();
		expect(rows).toHaveLength(1);
		expect(rows[0].id).toBe(foreign.id);
		expect(rows[0].accountId).toBe('email:foreign@x.test');
	});
});

// DB-001 encryption-or-exclusion (adjudication A3): body-bearing payload
// members never reach IndexedDB — only a body REFERENCE marker does; the
// plaintext lives in the session-volatile vault and is re-hydrated on read.
describe('body exclusion (DB-001 encryption-or-exclusion, A3)', () => {
	it('persists a body REFERENCE, never the plaintext, and re-hydrates in-session', async () => {
		loginAs();
		await flush();
		const id = await queueAction('email.send', { body: 'SECRET-DRAFT-TEXT', subject: 'hello' });

		const [row] = dump();
		expect(row.id).toBe(id);
		// IndexedDB record: no plaintext body — only the reference marker.
		expect(JSON.stringify(row)).not.toContain('SECRET-DRAFT-TEXT');
		const marker = (row.payload as Record<string, Record<string, string>>).body;
		expect(typeof marker?.__bodyRef).toBe('string');
		// Non-body members persist untouched.
		expect(row.payload).toMatchObject({ subject: 'hello' });

		// Same-session read: the body is re-hydrated from the session vault.
		const pending = await getPendingActions();
		expect(pending).toHaveLength(1);
		expect(pending[0].payload).toMatchObject({ body: 'SECRET-DRAFT-TEXT', subject: 'hello' });
	});

	it('redacts nested body members recursively and keeps non-body structure', async () => {
		loginAs();
		await flush();
		await queueAction('email.send', {
			msg: {
				subject: 'visible subject',
				preview: 'SECRET-PREVIEW',
				bodyValues: { v1: { value: 'SECRET-BODYVALUE' } },
				keywords: { $seen: true }
			}
		});

		const stored = JSON.stringify(dump());
		expect(stored).not.toContain('SECRET-PREVIEW');
		expect(stored).not.toContain('SECRET-BODYVALUE');
		expect(stored).toContain('visible subject');
		expect(stored).toContain('keywords');

		// In-session read re-hydrates the nested bodies.
		const pending = await getPendingActions();
		const msg = pending[0].payload.msg as Record<string, unknown>;
		expect(msg.preview).toBe('SECRET-PREVIEW');
		expect(msg.bodyValues).toEqual({ v1: { value: 'SECRET-BODYVALUE' } });
	});

	it('markActionDone drains the record and walks its persisted body references', async () => {
		loginAs();
		await flush();
		const id = await queueAction('email.send', { body: 'transient-body' });
		const pending = await getPendingActions();
		expect((pending[0].payload as Record<string, unknown>).body).toBe('transient-body');

		await markActionDone(id);
		expect(dump().map((r) => r.id)).not.toContain(id);
	});
});

// Depth-bound exclusion (med-shard2-004 r3): the redaction walk is depth-
// bounded, but the bound is never an exemption — a subtree beyond MAX_WALK_DEPTH
// (10) cannot be inspected, so it is excluded WHOLESALE with the same explicit
// __bodyRef/marker treatment, never silently passed through. The old
// `if (depth > MAX_WALK_DEPTH) return value` let a deeply nested body-bearing
// object persist plaintext past the redaction contract.
describe('depth-bound exclusion (med-shard2-004 r3)', () => {
	// Wraps `leaf` in `levels` single-key containers under 'chain'; the leaf is
	// reached by the redaction walk at entry depth `levels` (payload = depth 0).
	function chain(levels: number, leaf: Record<string, unknown>): Record<string, unknown> {
		let node = leaf;
		for (let i = 0; i < levels; i++) node = { chain: node };
		return node;
	}

	it('a body container just INSIDE the bound (depth 10) is redacted via the normal key path and re-hydrates', async () => {
		loginAs();
		await flush();
		await queueAction('email.send', chain(10, { body: 'BOUNDARY-INSIDE-SECRET', subject: 's' }));

		const stored = JSON.stringify(dump());
		expect(stored).not.toContain('BOUNDARY-INSIDE-SECRET');
		// The marker sits one container deeper than the deepest walked container —
		// still within hydration reach.
		const pending = await getPendingActions();
		let node = pending[0].payload as Record<string, unknown>;
		for (let i = 0; i < 10; i++) node = node.chain as Record<string, unknown>;
		expect(node).toMatchObject({ body: 'BOUNDARY-INSIDE-SECRET', subject: 's' });
	});

	it('a body nested just BEYOND the bound (depth 11) never persists raw — the subtree is excluded wholesale with a reference marker', async () => {
		loginAs();
		await flush();
		await queueAction('email.send', chain(11, { body: 'BOUNDARY-BEYOND-SECRET', subject: 's' }));

		// Nothing plaintext reaches IndexedDB…
		const stored = JSON.stringify(dump());
		expect(stored).not.toContain('BOUNDARY-BEYOND-SECRET');
		// …and the un-inspectable subtree is replaced by the SAME explicit marker
		// treatment, not dropped and not passed through: ten 'chain' hops reach
		// the deepest walked container, whose 'chain' value IS the marker.
		let node = (dump()[0].payload as Record<string, unknown>).chain as Record<string, unknown>;
		for (let i = 0; i < 9; i++) node = node.chain as Record<string, unknown>;
		expect(typeof (node.chain as Record<string, string>).__bodyRef).toBe('string');

		// Same-session read re-hydrates the vaulted subtree (in memory only).
		const pending = await getPendingActions();
		let h = pending[0].payload as Record<string, unknown>;
		for (let i = 0; i < 11; i++) h = h.chain as Record<string, unknown>;
		expect(h).toMatchObject({ body: 'BOUNDARY-BEYOND-SECRET', subject: 's' });
	});

	it('an arbitrarily deep body-bearing payload (depth 40) is still fully excluded', async () => {
		loginAs();
		await flush();
		await queueAction('email.send', chain(40, { bodyValues: { v: 'ABYSS-SECRET' } }));

		expect(JSON.stringify(dump())).not.toContain('ABYSS-SECRET');
	});

	it('a deep NON-body subtree beyond the bound is also excluded (never silent pass-through), and markActionDone still drains it', async () => {
		loginAs();
		await flush();
		const id = await queueAction('email.send', chain(15, { keywords: { $seen: true }, note: 'DEEP-PLAIN-NOTE' }));

		// The subtree was not body-bearing, but beyond the bound it cannot be
		// inspected — it must be vaulted + marked, not persisted as-is.
		const persisted = JSON.stringify(dump());
		expect(persisted).not.toContain('DEEP-PLAIN-NOTE');
		expect(persisted).toContain('__bodyRef');
		// The vaulted original re-hydrates on the same-session read…
		const pending = await getPendingActions();
		let h = pending[0].payload as Record<string, unknown>;
		for (let i = 0; i < 15; i++) h = h.chain as Record<string, unknown>;
		expect(h).toMatchObject({ keywords: { $seen: true }, note: 'DEEP-PLAIN-NOTE' });
		// …and the drain reaches the marker at the walk boundary (no throw, record gone).
		await markActionDone(id);
		expect(dump().map((r) => r.id)).not.toContain(id);
	});
});

// Identity fence (med-shard2-004 r2): a pending read started under A must not
// deliver A's records after a transition to B — the purge cannot retract an
// already-delivered result, so the completion re-checks the identity generation.
describe('identity fence on pending reads', () => {
	it('a read started under A delivers nothing when the identity switches before completion', async () => {
		loginAs(); // identity A
		await flush();
		await queueAction('email.send', { body: 'a-draft' });

		// Hold the IDB getAll completion so it lands AFTER the switch.
		let releaseGate!: () => void;
		getAllGate = new Promise<void>((r) => (releaseGate = r));
		try {
			const read = getPendingActions();
			await flush(); // the read captured identity A and issued getAll (now held)
			loginAs(); // identity B — synchronous transition: fence bump + purge
			releaseGate();

			// Fenced completion: no A records leak into B's session.
			await expect(read).resolves.toEqual([]);
		} finally {
			getAllGate = null;
		}

		// Control: the transition purged the queue; B reads its own (empty) set.
		await flush();
		expect(await getPendingActions()).toEqual([]);
	});
});

// Runs after the file-instance describes: resets the module registry to exercise
// the v1→v2 upgrade path on a fresh offline.ts instance (the file's shared
// connection above is untouched).
describe('legacy v1 database upgrade', () => {
	it('adds the accountId index, purges legacy rows on identity acquisition, then scopes new rows', async () => {
		vi.resetModules();
		const upgradeStub = makeIDBStub();
		vi.stubGlobal('indexedDB', upgradeStub.factory);
		try {
			// Pre-existing v1 database: accountId index absent, rows written pre-scoping.
			const v1db = upgradeStub.ensureDB(DB_NAME, STORE, 1, ['status', 'type']);
			v1db.stores.get(STORE)!.records.set(1, {
				id: 1,
				type: 'email.send',
				payload: { body: 'legacy draft' },
				status: 'pending',
				createdAt: Date.now(),
				retries: 0
			});

			const auth = await import('$lib/stores/auth');
			const offline = await import('./offline');
			const email = 'up@x.test';
			auth.user.set({ email, isAdmin: false, hasMailbox: true });
			await flush();

			// v1→v2 upgrade ran; the legacy row is evicted as prior-identity residue.
			expect(v1db.version).toBe(2);
			expect([...v1db.stores.get(STORE)!.records.values()]).toHaveLength(0);

			await offline.queueAction('email.send', { body: 'fresh' });
			const pending = await offline.getPendingActions();
			expect(pending).toHaveLength(1);
			expect(pending[0].accountId).toBe(`email:${email}`);
		} finally {
			// Restore the file's stub (the shared connection above stays authoritative
			// for any later test imported into this registry).
			vi.stubGlobal('indexedDB', stub.factory);
		}
	});
});

// Runs after the module-resetting upgrade describe: a fresh offline.ts instance
// means a fresh session vault — the reload case for body exclusion.
describe('body reference survives a reload (re-fetch handle for replay)', () => {
	it('a marker with no in-session body is delivered un-hydrated, never as plaintext', async () => {
		vi.resetModules();
		const reloadStub = makeIDBStub();
		vi.stubGlobal('indexedDB', reloadStub.factory);
		try {
			const auth = await import('$lib/stores/auth');
			const offline = await import('./offline');
			const email = 'reload@x.test';
			auth.user.set({ email, isAdmin: false, hasMailbox: true });
			await flush();
			await flush(); // acquisition purge lands before seeding

			// Pre-reload record: the body was excluded at write time, so only the
			// reference marker exists on disk.
			const store = reloadStub.ensureDB(DB_NAME, STORE, 2).stores.get(STORE)!;
			store.records.set(1, {
				id: 1,
				type: 'email.send',
				payload: { body: { __bodyRef: 'bodyref:pre-reload' }, subject: 'kept' },
				status: 'pending',
				createdAt: Date.now(),
				retries: 0,
				accountId: `email:${email}`
			});

			const pending = await offline.getPendingActions();
			expect(pending).toHaveLength(1);
			// No in-session body for the ref: the marker stays as the re-fetch
			// handle — it never fabricates plaintext.
			expect(pending[0].payload).toEqual({
				body: { __bodyRef: 'bodyref:pre-reload' },
				subject: 'kept'
			});
		} finally {
			// Restore the file's stub (the shared connection above stays
			// authoritative for any later test imported into this registry).
			vi.stubGlobal('indexedDB', stub.factory);
		}
	});
});
