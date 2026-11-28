import { describe, it, expect, vi, afterEach } from 'vitest';
import { withSyncOwnership } from './leader';

afterEach(() => vi.unstubAllGlobals());

describe('leader election', () => {
	it('runs fn while holding the lock', async () => {
		const request = vi.fn(async (_n, _o, cb) => cb({ name: 'offline-sync' }));
		vi.stubGlobal('navigator', { locks: { request } });
		const r = await withSyncOwnership(async () => 42);
		expect(r).toBe(42);
		expect(request).toHaveBeenCalledWith('offline-sync', { mode: 'exclusive', ifAvailable: true }, expect.any(Function));
	});

	it('returns null when lock is unavailable (another window owns it)', async () => {
		const request = vi.fn(async (_n, _o, cb) => cb(null));
		vi.stubGlobal('navigator', { locks: { request } });
		const r = await withSyncOwnership(async () => 42);
		expect(r).toBeNull();
	});
});
