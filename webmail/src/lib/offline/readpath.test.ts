import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('$lib/jmap/client', () => ({ emailQuery: vi.fn(), emailGet: vi.fn() }));

function fakeDb() {
	const messages = new Map<string, Record<string, unknown>>();
	return {
		open: vi.fn(async (_a: string) => {}), isOpen: vi.fn(async (_a: string) => true), wipe: vi.fn(async (_a: string) => {}),
		exec: vi.fn(async (_appKey: string, sql: string, p: unknown[] = []) => {
			if (/^\s*CREATE/i.test(sql)) return 0;
			if (/INSERT OR REPLACE INTO messages\b/i.test(sql)) messages.set(p[0] as string, { id: p[0], thread_id: p[1], received_at: p[2], flags: p[3], has_attachment: 0, cache_state: p[5], synced_at: 0, from_: p[7], to_: p[8], cc: p[9], bcc: p[10], subject: p[11], preview: p[12], version: 0, dirty_fields: '[]' });
			// message_tags / fts inserts — silently accepted
			return 1;
		}),
		query: vi.fn(async (_appKey: string, sql: string, p: unknown[] = []) => {
			// listByReceivedDesc uses "ORDER BY m.received_at" (table alias)
			if (/ORDER BY m\.received_at/i.test(sql) || /ORDER BY received_at/i.test(sql)) return [...messages.values()];
			// getMessage: single-row lookup by id (WHERE m.id = ?)
			if (/WHERE m\.id = \?/i.test(sql) && p.length > 0) {
				const row = messages.get(p[0] as string);
				return row ? [row] : [];
			}
			// searchBody: FTS MATCH — return all message ids for test simplicity
			if (/messages_fts MATCH/i.test(sql)) return [...messages.keys()].map((id) => ({ id }));
			return [];
		}),
	};
}

describe('read path selector', () => {
	let readpath: typeof import('./readpath');
	let offline: typeof import('./state.svelte');
	beforeEach(async () => {
		vi.resetModules();
		(window as never as { setjoinNative: { db: ReturnType<typeof fakeDb> } }).setjoinNative = { db: fakeDb() };
		const store = (await import('./store')).getStore()!;
		await store.upsertMessage({ id: '1', threadId: 't', receivedAt: 5, flags: [], hasAttachment: false, cacheState: 'full', syncedAt: 0, from: 'a@x', to: 'b@y', cc: '', bcc: '', subject: 'Cached', preview: 'p', tagIds: ['Inbox'] });
		offline = await import('./state.svelte');
		offline.offline.workOffline = true; // force offline
		readpath = await import('./readpath');
	});

	it('reads from cache when offline', async () => {
		const list = await readpath.loadList({ limit: 10 });
		expect(list.map((m) => m.id)).toContain('1');
		expect(list.find((m) => m.id === '1')?.subject).toBe('Cached');
	});

	it('searchList returns cache rows offline — never calls emailGet', async () => {
		const { emailGet } = await import('$lib/jmap/client');
		const rows = await readpath.searchList('Cached', 10);
		// Must return the cached row's metadata
		expect(rows.map((r) => r.id)).toContain('1');
		expect(rows.find((r) => r.id === '1')?.subject).toBe('Cached');
		// Must NOT call emailGet (the network) when offline
		expect(emailGet).not.toHaveBeenCalled();
	});
});
