import { offline } from './state.svelte';
import { getStore } from './store';
import { searchOffline } from './search';
import { emailQuery, emailGet } from '$lib/jmap/client';
import { METADATA_PROPS } from './sync';
import type { Email } from '$lib/types/jmap';

export interface ListRow { id: string; receivedAt: number; subject?: string; from?: string; }

// ponytail: simple online/offline branch — no caching layer, just two code
// paths behind the same interface. Ceiling: add a stale-while-revalidate layer
// (serve cache, refresh in background) if perceived latency becomes a concern.
export async function loadList(opts: { limit: number; offset?: number }): Promise<ListRow[]> {
	const store = getStore();
	if (offline.effectiveOffline && store) {
		// §19 P1: SQL ORDER BY received_at + LIMIT/OFFSET — page only, no full scan.
		const rows = await store.listByReceivedDesc(opts.limit, opts.offset ?? 0);
		return rows.map((r) => ({ id: r.id, receivedAt: r.receivedAt, subject: r.subject, from: r.from }));
	}
	const { ids } = await emailQuery({}, [{ property: 'receivedAt', isAscending: false }], opts.limit, opts.offset);
	const emails = await emailGet(ids, METADATA_PROPS, undefined);
	return emails.map((e: Email) => ({
		id: e.id,
		receivedAt: e.receivedAt ? Date.parse(e.receivedAt) : 0,
		subject: e.subject ?? undefined,
		from: (e.from ?? []).map((a) => a.email).join(', ')
	}));
}

// ponytail: returns ListRow[] (same shape as loadList) so the caller never touches
// the network for search results — one swap point, seam closed. Ceiling: offline
// FTS returns only messages_fts-indexed rows; add attachment/sender ranking in #1b.
export async function searchList(query: string, limit = 100): Promise<ListRow[]> {
	const store = getStore();
	if (offline.effectiveOffline && store) {
		const ids = await searchOffline(query, limit);
		// Hydrate from the SQLCipher cache — NOT from the network.
		const rows = await Promise.all(ids.map((id) => store.getMessage(id)));
		return rows
			.filter((m): m is NonNullable<typeof m> => m !== null)
			.map((m) => ({ id: m.id, receivedAt: m.receivedAt, subject: m.subject, from: m.from }));
	}
	// Online: server-side search; hydrate metadata via emailGet (same as loadList).
	const { ids } = await emailQuery({ text: query }, [{ property: 'receivedAt', isAscending: false }], limit);
	if (ids.length === 0) return [];
	const emails = await emailGet(ids, METADATA_PROPS, undefined);
	return emails.map((e: Email) => ({
		id: e.id,
		receivedAt: e.receivedAt ? Date.parse(e.receivedAt) : 0,
		subject: e.subject ?? undefined,
		from: (e.from ?? []).map((a) => a.email).join(', '),
	}));
}
