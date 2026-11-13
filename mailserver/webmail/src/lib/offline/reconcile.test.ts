import { describe, it, expect, beforeEach, vi } from 'vitest';

function fakeDb() {
	const meta = new Map<string, string>();
	const issues: Record<string, unknown>[] = [];
	let nextId = 1;
	return {
		open: vi.fn(async (_a: string) => {}),
		isOpen: vi.fn(async (_a: string) => true),
		wipe: vi.fn(async (_a: string) => {}),
		exec: vi.fn(async (_appKey: string, sql: string, p: unknown[] = []) => {
			if (/^\s*CREATE/i.test(sql)) return 0;
			if (/INSERT OR REPLACE INTO meta_mail/i.test(sql)) meta.set(p[0] as string, p[1] as string);
			else if (/INSERT INTO sync_issues/i.test(sql)) issues.push({ id: nextId++, kind: p[0], action_type: p[1], payload: p[2], error: p[3], created_at: p[4] });
			return 1;
		}),
		query: vi.fn(async (_appKey: string, sql: string, p: unknown[] = []) => {
			if (/FROM meta_mail WHERE key/i.test(sql)) { const v = meta.get(p[0] as string); return v === undefined ? [] : [{ value: v }]; }
			if (/FROM sync_issues/i.test(sql)) return issues.map((i) => ({ ...i }));
			return [];
		}),
	};
}

describe('reconcile (over the store)', () => {
	let mod: typeof import('./reconcile');
	let getStoreModule: typeof import('./store');

	beforeEach(async () => {
		vi.resetModules();
		(window as never as { setjoinNative: { db: ReturnType<typeof fakeDb> } }).setjoinNative = { db: fakeDb() };
		getStoreModule = await import('./store');
		mod = await import('./reconcile');
	});

	it('mints and recognizes temp ids', () => {
		const t = mod.newTempId();
		expect(mod.isTempId(t)).toBe(true);
		expect(mod.isTempId('42')).toBe(false);
	});

	it('maps a temp id to a server id', async () => {
		const t = mod.newTempId();
		await mod.mapTempId(t, 'srv-9');
		expect(await mod.resolveId(t)).toBe('srv-9');
		expect(await mod.resolveId('plain')).toBe('plain');
	});

	it('idempotency keys are unique', () => {
		expect(mod.newIdempotencyKey()).not.toBe(mod.newIdempotencyKey());
	});

	it('concurrent mapTempId calls do not drop each other (race fix)', async () => {
		// Old single-blob read-modify-write would silently drop whichever entry lost
		// the race; per-key rows make each INSERT OR REPLACE independent.
		const t1 = mod.newTempId();
		const t2 = mod.newTempId();
		await Promise.all([mod.mapTempId(t1, 'srv-1'), mod.mapTempId(t2, 'srv-2')]);
		expect(await mod.resolveId(t1)).toBe('srv-1');
		expect(await mod.resolveId(t2)).toBe('srv-2');
	});

	it('records and lists sync issues (never silently dropped)', async () => {
		await mod.recordSyncIssue({ kind: 'stale', actionType: 'emailSetUpdate', payload: { id: '1' }, error: 'stateMismatch' });
		const issues = await mod.listSyncIssues();
		expect(issues).toHaveLength(1);
		expect(issues[0].kind).toBe('stale');
	});

	it('early-returns inertly when no native store (browser)', async () => {
		vi.resetModules();
		delete (window as never as { setjoinNative?: unknown }).setjoinNative;
		const m = await import('./reconcile');
		// No store — all ops should be no-ops, not throw
		expect(m.isTempId('tmp_x')).toBe(true);
		await expect(m.mapTempId('tmp_x', 'srv-1')).resolves.toBeUndefined();
		expect(await m.resolveId('tmp_x')).toBe('tmp_x'); // unresolvable without store
		await expect(m.recordSyncIssue({ kind: 'stale', actionType: 'a', payload: {}, error: 'e' })).resolves.toBeUndefined();
		expect(await m.listSyncIssues()).toEqual([]);
		await expect(m.clearSyncIssue(1)).resolves.toBeUndefined();
	});

	// suppress unused-import warning — getStoreModule is imported for side effects
	it('getStoreModule is accessible', () => { expect(getStoreModule).toBeDefined(); });
});
