// Reconcile: temp-id map + send idempotency + sync-issues over the store.
// All functions early-return inertly when getStore() is null (browser, no native
// store) — the import is safe in any bundle. Consumed by offline-client (Task 14)
// and the sync-issues UI (Task 15).
import { getStore, type SyncIssue } from './store';

export type { SyncIssue };

export function newTempId(): string { return 'tmp_' + crypto.randomUUID(); }
export function isTempId(id: string): boolean { return id.startsWith('tmp_'); }
export function newIdempotencyKey(): string { return crypto.randomUUID(); }

/** Persist a temp→server mapping so resolveId works after a reload.
 *  ponytail: one meta_mail row per temp-id (key='idmap:'+tempId) — each write is
 *  an independent INSERT OR REPLACE, so concurrent sends can't race-drop each other's
 *  entry (the old single-JSON-blob read-modify-write was not atomic). Ceiling:
 *  unbounded rows if server never acks; add a TTL sweep at the Task 14 ack point. */
export async function mapTempId(tempId: string, serverId: string): Promise<void> {
	const store = getStore();
	if (!store) return;
	await store.setMeta('idmap:' + tempId, serverId);
}

/** Return the server id for a temp id, or the id unchanged (already real). */
export async function resolveId(id: string): Promise<string> {
	if (!isTempId(id)) return id;
	const store = getStore();
	if (!store) return id;
	return (await store.getMeta('idmap:' + id)) ?? id; // unresolved temp id falls through unchanged (caller retries)
}

export async function recordSyncIssue(issue: Omit<SyncIssue, 'id' | 'at'>): Promise<void> {
	const store = getStore();
	if (!store) return;
	await store.recordSyncIssue(issue);
}

export async function listSyncIssues(): Promise<SyncIssue[]> {
	const store = getStore();
	if (!store) return [];
	return store.listSyncIssues();
}

export async function clearSyncIssue(id: number): Promise<void> {
	const store = getStore();
	if (!store) return;
	await store.clearSyncIssue(id);
}
