import { describe, it, expect, beforeEach, vi } from 'vitest';

function fakeDb() {
	const fts = new Map<string, string>();
	return {
		open: vi.fn(async (_a: string) => {}), isOpen: vi.fn(async (_a: string) => true), wipe: vi.fn(async (_a: string) => {}),
		exec: vi.fn(async (_appKey: string, sql: string, p: unknown[] = []) => {
			if (/^\s*CREATE/i.test(sql)) return 0;
			if (/INSERT INTO messages_fts/i.test(sql)) fts.set(p[0] as string, `${p[1]} ${p[2]} ${p[3]}`.toLowerCase());
			else if (/DELETE FROM messages_fts WHERE id/i.test(sql)) fts.delete(p[0] as string);
			return 1;
		}),
		query: vi.fn(async (_appKey: string, sql: string, p: unknown[] = []) => {
			if (/messages_fts MATCH/i.test(sql)) {
				const q = (p[0] as string).toLowerCase();
				return [...fts.entries()].filter(([, t]) => t.includes(q)).map(([id]) => ({ id }));
			}
			return [];
		}),
	};
}

describe('offline FTS body search', () => {
	let search: typeof import('./search');
	let store: typeof import('./store');
	beforeEach(async () => {
		vi.resetModules();
		(window as never as { setjoinNative: { db: ReturnType<typeof fakeDb> } }).setjoinNative = { db: fakeDb() };
		store = await import('./store');
		search = await import('./search');
		const s = store.getStore()!;
		await s.upsertMessage({ id: '1', threadId: 't', receivedAt: 1, flags: [], hasAttachment: false, cacheState: 'full', syncedAt: 0, from: 'alice@corp', to: '', cc: '', bcc: '', subject: 'Quarterly Report', preview: 'revenue grew', tagIds: [] });
		await s.upsertMessage({ id: '2', threadId: 't', receivedAt: 1, flags: [], hasAttachment: false, cacheState: 'full', syncedAt: 0, from: 'bob@home', to: '', cc: '', bcc: '', subject: 'Lunch', preview: 'plans', tagIds: [] });
	});

	it('matches by body/subject/from token', async () => {
		expect(await search.searchOffline('quarterly')).toEqual(['1']);
		expect(await search.searchOffline('revenue')).toEqual(['1']);
		expect(await search.searchOffline('bob')).toEqual(['2']);
	});

	it('empty query returns nothing', async () => {
		expect(await search.searchOffline('   ')).toEqual([]);
	});
});
