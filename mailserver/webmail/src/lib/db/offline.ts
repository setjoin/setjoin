// IndexedDB offline queue for webmail actions.
// Queues mutations when the browser is offline and replays them when connectivity returns.
//
// Account scoping: every queued record is tagged with the authenticated account
// identity captured at enqueue time; readers only ever return records tagged for
// the CURRENT identity; and the whole queue is purged on auth teardown (logout,
// impersonation end, account switch) via registerAuthSessionTeardown plus the
// user-store transition watcher below. Legacy rows written before scoping carry
// no accountId: the accountId index skips them, so they are never readable, and
// the next identity transition purges them as prior-identity residue.
//
// Body exclusion (DB-001, adjudication A3): body-bearing payload members are
// NEVER persisted — they are replaced by a body REFERENCE at enqueue, held in a
// session-volatile map, and re-hydrated on read (see "body exclusion" below).
//
// Identity fence (med-shard2-004 r2): pending reads capture the identity AND a
// generation counter before the IDB read and re-check both at completion, so a
// read started under A cannot deliver A's records after a transition to B.

import { user, registerAuthSessionTeardown, type AuthUser } from '$lib/stores/auth';
import { logger } from '$lib/logger';

const DB_NAME = 'mailserver_offline';
// v2: adds the accountId index for per-identity scoping (v1 rows predate scoping).
const DB_VERSION = 2;
const STORE_NAME = 'action_queue';

export interface QueuedAction {
	id?: number;
	/** Owning account identity ('user:<id>' | 'email:<email>'), captured from the
	 *  authenticated session at enqueue time. Absent only on legacy pre-scoping
	 *  rows, which are treated as prior-identity residue (never readable). */
	accountId?: string;
	type: string;
	payload: Record<string, unknown>;
	status: 'pending' | 'failed';
	createdAt: number;
	retries: number;
	error?: string;
}

let dbCache: IDBDatabase | null = null;

function openDB(): Promise<IDBDatabase> {
	return new Promise((resolve, reject) => {
		const req = indexedDB.open(DB_NAME, DB_VERSION);
		req.onerror = () => reject(req.error);
		req.onsuccess = () => {
			dbCache = req.result;
			resolve(req.result);
		};
		req.onupgradeneeded = (e) => {
			const openReq = e.target as IDBOpenDBRequest;
			const db = openReq.result;
			let store: IDBObjectStore;
			if (!db.objectStoreNames.contains(STORE_NAME)) {
				store = db.createObjectStore(STORE_NAME, {
					keyPath: 'id',
					autoIncrement: true
				});
			} else {
				// v1 → v2 upgrade: the store already exists; open it on the upgrade
				// transaction to attach the new accountId index.
				store = openReq.transaction!.objectStore(STORE_NAME);
			}
			if (!store.indexNames.contains('status')) {
				store.createIndex('status', 'status', { unique: false });
			}
			if (!store.indexNames.contains('type')) {
				store.createIndex('type', 'type', { unique: false });
			}
			if (!store.indexNames.contains('accountId')) {
				store.createIndex('accountId', 'accountId', { unique: false });
			}
		};
	});
}

async function getDB(): Promise<IDBDatabase> {
	if (dbCache) return dbCache;
	return openDB();
}

// --- account identity --------------------------------------------------------

// Mirrors auth.ts authIdentity() (not exported there; kept in sync). Exported
// for the E4-I boot composition (lib/offline/boot.ts), whose trigger/job
// identity must be THIS app identity so offline store rows and coordinator
// jobs never disagree about whose account they belong to.
export function accountIdentity(u: AuthUser | null): string | null {
	if (!u) return null;
	return u.userId != null ? `user:${u.userId}` : `email:${u.email.toLowerCase()}`;
}

let currentAccountId: string | null = null;
// Bumped on EVERY identity transition and every purge. Pending reads capture it
// before issuing the IDB read and re-check it at completion (fence below).
let identityGeneration = 0;

// --- body exclusion (DB-001: encryption-or-exclusion, adjudication A3) -------
//
// A3 binds the approved requirement: draft/submission bodies must not persist
// plaintext in IndexedDB, and the manifest's "DB-001 … open by design" note does
// not override it. Webmail src/lib has NO established browser-side crypto
// primitive to reuse (the P3 vault is native SQLCipher/Rust; inventing browser
// crypto is not an option), so the EXCLUSION arm is implemented: body-bearing
// payload members are stripped at enqueue and replaced by a body REFERENCE
// marker. The original value lives only in this session-volatile map and is
// re-hydrated on read; after a reload the marker survives in the persisted
// record as the re-fetch handle for replay.
//
// Depth bound (med-shard2-004 r3): the redaction walk is depth-bounded, but a
// bound is never an exemption — a subtree beyond MAX_WALK_DEPTH cannot be
// inspected, so it is excluded WHOLESALE (vaulted + reference marker, exactly
// like a body key) instead of silently passing through to IndexedDB.

const BODY_REF_KEY = '__bodyRef';
// Draft/submission body surfaces: body, textBody, htmlBody, bodyValues and
// preview (the first N chars of the body). Case-insensitive substring match so
// vendor extensions (mailBody etc.) are covered without a per-call registry.
const BODY_KEY_PATTERN = /body|preview/i;
const MAX_WALK_DEPTH = 10;
// Markers are placed inside containers the walk actually reached (entry depth
// ≤ MAX_WALK_DEPTH); hydration and reference collection visit a marker one
// container deeper than the object holding it, so their bound is +1 — a marker
// at the walk boundary must still re-hydrate and still be collected on drain.
const MAX_MARKER_DEPTH = MAX_WALK_DEPTH + 1;

const bodyVault = new Map<string, unknown>();

interface BodyRefMarker {
	__bodyRef: string;
}

function isBodyRefMarker(v: unknown): v is BodyRefMarker {
	return (
		typeof v === 'object' &&
		v !== null &&
		typeof (v as Record<string, unknown>).__bodyRef === 'string'
	);
}

/** Replace every body-bearing member with a reference marker, collecting the
 *  originals for the session vault. Builds fresh containers — the caller's
 *  payload object is never mutated (SyncIssuesInspector re-queues it verbatim).
 *
 *  Depth bound (med-shard2-004 r3): the bound is never an exemption. A subtree
 *  beyond MAX_WALK_DEPTH cannot be inspected, so it is excluded WHOLESALE —
 *  vaulted and replaced by the same explicit reference marker as any body key —
 *  never silently passed through: the old `return value` here let a deeply
 *  nested body-bearing object persist plaintext past the redaction contract. */
function redactBodies(value: unknown, depth: number, bodies: Map<string, unknown>): unknown {
	if (depth > MAX_WALK_DEPTH) {
		// Un-inspectable subtree: same explicit __bodyRef/marker treatment as a
		// body member. The vault holds the whole original; on read it re-hydrates
		// (same session) or stays a re-fetch handle (reload), like any marker.
		const ref = `bodyref:${crypto.randomUUID()}`;
		bodies.set(ref, value);
		return { [BODY_REF_KEY]: ref };
	}
	if (Array.isArray(value)) return value.map((v) => redactBodies(v, depth + 1, bodies));
	if (typeof value !== 'object' || value === null) return value;
	const out: Record<string, unknown> = {};
	for (const [key, member] of Object.entries(value as Record<string, unknown>)) {
		if (BODY_KEY_PATTERN.test(key)) {
			const ref = `bodyref:${crypto.randomUUID()}`;
			bodies.set(ref, member);
			out[key] = { [BODY_REF_KEY]: ref };
		} else {
			out[key] = redactBodies(member, depth + 1, bodies);
		}
	}
	return out;
}

/** Re-hydrate body references from the session vault (same-session read).
 *  Markers whose body is gone (reload) stay in place as the re-fetch handle.
 *  Bound is MAX_MARKER_DEPTH: a marker may sit one container deeper than the
 *  deepest walked container (including the r3 beyond-the-bound strip). */
function hydrateBodies(value: unknown, depth: number): unknown {
	if (depth > MAX_MARKER_DEPTH) return value;
	if (Array.isArray(value)) return value.map((v) => hydrateBodies(v, depth + 1));
	if (typeof value !== 'object' || value === null) return value;
	if (isBodyRefMarker(value)) {
		const body = bodyVault.get(value.__bodyRef);
		return body === undefined ? value : body;
	}
	const out: Record<string, unknown> = {};
	for (const [key, member] of Object.entries(value)) {
		out[key] = hydrateBodies(member, depth + 1);
	}
	return out;
}

/** Body reference markers present in a (persisted) payload. Same +1 bound as
 *  hydration so markActionDone drains every marker the writer could place. */
function collectBodyRefs(value: unknown, depth: number, into: string[] = []): string[] {
	if (depth > MAX_MARKER_DEPTH) return into;
	if (Array.isArray(value)) {
		for (const v of value) collectBodyRefs(v, depth + 1, into);
		return into;
	}
	if (typeof value !== 'object' || value === null) return into;
	if (isBodyRefMarker(value)) {
		into.push(value.__bodyRef);
		return into;
	}
	for (const v of Object.values(value)) collectBodyRefs(v, depth + 1, into);
	return into;
}

/**
 * Delete EVERY queued record — the auth-teardown contract (logout, impersonation
 * end, account switch): nothing persisted under a previous identity outlives it.
 */
export async function purgeOfflineQueue(): Promise<void> {
	if (typeof indexedDB === 'undefined') return; // SSR / non-browser environments
	// Any purge invalidates in-flight pending reads (fence below): a completion
	// landing after the purge started must not deliver soon-to-vanish records.
	identityGeneration++;
	bodyVault.clear(); // records are gone; the session-held bodies go with them
	const db = await getDB();
	return new Promise((resolve, reject) => {
		const tx = db.transaction(STORE_NAME, 'readwrite');
		const store = tx.objectStore(STORE_NAME);
		const req = store.clear();
		req.onsuccess = () => resolve();
		req.onerror = () => reject(req.error);
	});
}

export async function queueAction(type: string, payload: Record<string, unknown>): Promise<number> {
	const db = await getDB();
	// Captured after the open await and re-checked against the live identity: an
	// un-attributable record is exactly the cross-identity residue this queue must
	// never persist, so queueing fails closed when no identity is known.
	const accountId = currentAccountId;
	if (!accountId) {
		throw new Error('offline queue: no authenticated identity; action not queued');
	}
	// DB-001 (A3): bodies are excluded from the persisted record — only the
	// reference marker reaches IndexedDB; the plaintext stays session-volatile.
	const bodies = new Map<string, unknown>();
	const redacted = redactBodies(payload, 0, bodies) as Record<string, unknown>;
	return new Promise((resolve, reject) => {
		const tx = db.transaction(STORE_NAME, 'readwrite');
		const store = tx.objectStore(STORE_NAME);
		const req = store.add({ accountId, type, payload: redacted, status: 'pending', createdAt: Date.now(), retries: 0 });
		req.onsuccess = () => {
			// The record is durably queued: only now does the vault become its
			// in-session body source (a failed add leaves no vault residue).
			for (const [ref, body] of bodies) bodyVault.set(ref, body);
			resolve(req.result as number);
		};
		req.onerror = () => reject(req.error);
	});
}

export async function getPendingActions(): Promise<QueuedAction[]> {
	const db = await getDB();
	// Fence (med-shard2-004): capture the identity AND its generation BEFORE the
	// read. A read started under A must never deliver A's records after a
	// transition to B — the subsequent purge cannot retract an already-delivered
	// result — so the completion re-checks both and yields nothing on change.
	const readGeneration = identityGeneration;
	const accountId = currentAccountId;
	if (!accountId) return [];
	return new Promise((resolve, reject) => {
		const tx = db.transaction(STORE_NAME, 'readonly');
		const store = tx.objectStore(STORE_NAME);
		// Identity-scoped read: rows tagged for another account can never be
		// returned or replayed; the accountId index also skips legacy untagged rows.
		const req = store.index('accountId').getAll(accountId);
		req.onsuccess = () => {
			// Fenced completion: identity changed (or a purge ran) between read
			// start and resolution — deliver nothing rather than stale records.
			if (readGeneration !== identityGeneration || currentAccountId !== accountId) {
				resolve([]);
				return;
			}
			resolve(
				(req.result as QueuedAction[])
					.filter((a) => a.status === 'pending')
					.map((a) => ({
						...a,
						// Re-hydrate bodies from the session vault; markers whose body is
						// gone (reload) stay in place as the re-fetch handle for replay.
						// The JSON round trip detaches the read record from IndexedDB
						// (hydration must never write back into the store).
						payload: a.payload
							? (hydrateBodies(JSON.parse(JSON.stringify(a.payload)), 0) as Record<string, unknown>)
							: a.payload
					}))
			);
		};
		req.onerror = () => reject(req.error);
	});
}

export async function markActionDone(id: number): Promise<void> {
	const db = await getDB();
	const accountId = currentAccountId;
	return new Promise((resolve, reject) => {
		const tx = db.transaction(STORE_NAME, 'readwrite');
		const store = tx.objectStore(STORE_NAME);
		const getReq = store.get(id);
		getReq.onsuccess = () => {
			const item = getReq.result as QueuedAction | undefined;
			if (!item) return resolve();
			// Ownership checked in the same transaction: a foreign or prior-identity
			// id is never deleted by this session.
			if (!accountId || item.accountId !== accountId) {
				logger.warn('offline queue: ignoring mutation of a record not owned by the current identity');
				return resolve();
			}
			// The record leaves the queue: drop its session-held bodies with it.
			for (const ref of collectBodyRefs(item.payload, 0)) bodyVault.delete(ref);
			const req = store.delete(id);
			req.onsuccess = () => resolve();
			req.onerror = () => reject(req.error);
		};
		getReq.onerror = () => reject(getReq.error);
	});
}

export async function markActionFailed(id: number, error: string): Promise<void> {
	const db = await getDB();
	const accountId = currentAccountId;
	return new Promise((resolve, reject) => {
		const tx = db.transaction(STORE_NAME, 'readwrite');
		const store = tx.objectStore(STORE_NAME);
		const getReq = store.get(id);
		getReq.onsuccess = () => {
			const item = getReq.result as QueuedAction | undefined;
			if (!item) return resolve();
			// Ownership checked in the same transaction, as in markActionDone.
			if (!accountId || item.accountId !== accountId) {
				logger.warn('offline queue: ignoring mutation of a record not owned by the current identity');
				return resolve();
			}
			item.status = 'failed';
			item.error = error;
			item.retries += 1;
			if (item.retries < 3) {
				item.status = 'pending'; // retry later
			}
			const putReq = store.put(item);
			putReq.onsuccess = () => resolve();
			putReq.onerror = () => reject(putReq.error);
		};
		getReq.onerror = () => reject(getReq.error);
	});
}

export async function clearFailedActions(): Promise<void> {
	const db = await getDB();
	const accountId = currentAccountId;
	if (!accountId) return;
	return new Promise((resolve, reject) => {
		const tx = db.transaction(STORE_NAME, 'readwrite');
		const store = tx.objectStore(STORE_NAME);
		const idx = store.index('status');
		const req = idx.openCursor('failed');
		req.onsuccess = (e) => {
			const cursor = (e.target as IDBRequest).result as IDBCursorWithValue | null;
			if (cursor) {
				// Only the current identity's failed records are cleared.
				if ((cursor.value as QueuedAction).accountId === accountId) cursor.delete();
				cursor.continue();
			} else {
				resolve();
			}
		};
		req.onerror = () => reject(req.error);
	});
}

// --- auth teardown wiring ----------------------------------------------------

registerAuthSessionTeardown(() => {
	void purgeOfflineQueue().catch((err) => logger.error('offline queue: teardown purge failed', err));
});

user.subscribe((u) => {
	const next = accountIdentity(u);
	if (next === currentAccountId) return;
	currentAccountId = next;
	// Fence: in-flight pending reads captured the PRIOR generation; their
	// completions below re-check and deliver nothing across the transition.
	identityGeneration++;
	// Any identity transition — session acquisition, logout, impersonation start/
	// end, account switch — is teardown semantics for persisted queue state: the
	// queue is purged in full. On first acquisition this also evicts legacy
	// untagged rows and any residue a crashed prior session left behind.
	void purgeOfflineQueue().catch((err) => logger.error('offline queue: identity-change purge failed', err));
});

// Online/offline detection
export function isOnline(): boolean {
	return navigator.onLine;
}

export function onNetworkChange(callback: (online: boolean) => void): () => void {
	const onOnline = () => callback(true);
	const onOffline = () => callback(false);
	window.addEventListener('online', onOnline);
	window.addEventListener('offline', onOffline);
	return () => {
		window.removeEventListener('online', onOnline);
		window.removeEventListener('offline', onOffline);
	};
}
