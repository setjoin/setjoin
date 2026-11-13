import { describe, it, expect, vi, beforeEach } from 'vitest';

const typedFetch = vi.fn();
vi.mock('$lib/http', () => ({
	typedFetch: (...a: unknown[]) => typedFetch(...a),
}));

// Capture the session-teardown registry so tests can fire auth teardowns the
// way logout/impersonation-end/account-switch do.
const authTeardowns = new Set<() => void>();
vi.mock('$lib/stores/auth', () => ({
	registerAuthSessionTeardown: (fn: () => void) => {
		authTeardowns.add(fn);
		return () => authTeardowns.delete(fn);
	},
}));

// Drive P3 (batch-3 #1(b) — the P1 native-token bridge's SPA-side mint/cache).
// Only the renderer holds the SPA's cookie session, so it is the only place
// that can mint POST /api/drive/native-token; VaultStore/SecureViewer consume
// the cached token instead of minting on every chunk fetch.
describe('getNativeToken', () => {
	beforeEach(async () => {
		vi.resetModules();
		authTeardowns.clear();
		typedFetch.mockReset();
	});

	it('mints once and caches until near expiry', async () => {
		typedFetch.mockResolvedValue({ token: 'tok-1', expiresAt: new Date(Date.now() + 3_600_000).toISOString() });
		const { getNativeToken } = await import('./nativeToken');
		const a = await getNativeToken();
		const b = await getNativeToken();
		expect(a).toBe('tok-1');
		expect(b).toBe('tok-1');
		expect(typedFetch).toHaveBeenCalledTimes(1);
		expect(typedFetch).toHaveBeenCalledWith('/api/drive/native-token', { method: 'POST' });
	});

	it('re-mints once the cached token is within 60s of expiry', async () => {
		typedFetch
			.mockResolvedValueOnce({ token: 'tok-1', expiresAt: new Date(Date.now() + 30_000).toISOString() })
			.mockResolvedValueOnce({ token: 'tok-2', expiresAt: new Date(Date.now() + 3_600_000).toISOString() });
		const { getNativeToken } = await import('./nativeToken');
		expect(await getNativeToken()).toBe('tok-1');
		expect(await getNativeToken()).toBe('tok-2');
		expect(typedFetch).toHaveBeenCalledTimes(2);
	});

	it('resetNativeTokenCache forces the next call to re-mint', async () => {
		typedFetch
			.mockResolvedValueOnce({ token: 'tok-1', expiresAt: new Date(Date.now() + 3_600_000).toISOString() })
			.mockResolvedValueOnce({ token: 'tok-2', expiresAt: new Date(Date.now() + 3_600_000).toISOString() });
		const { getNativeToken, resetNativeTokenCache } = await import('./nativeToken');
		expect(await getNativeToken()).toBe('tok-1');
		resetNativeTokenCache();
		expect(await getNativeToken()).toBe('tok-2');
		expect(typedFetch).toHaveBeenCalledTimes(2);
	});

	it('the logout hook is wired: an auth session teardown drops the cached bearer', async () => {
		typedFetch
			.mockResolvedValueOnce({ token: 'tok-1', expiresAt: new Date(Date.now() + 3_600_000).toISOString() })
			.mockResolvedValueOnce({ token: 'tok-2', expiresAt: new Date(Date.now() + 3_600_000).toISOString() });
		const { getNativeToken } = await import('./nativeToken');
		expect(await getNativeToken()).toBe('tok-1');

		// Module import must have registered exactly one teardown hook.
		expect(authTeardowns.size).toBe(1);
		for (const teardown of authTeardowns) teardown();

		// The in-memory bearer is gone — the next call re-mints.
		expect(await getNativeToken()).toBe('tok-2');
		expect(typedFetch).toHaveBeenCalledTimes(2);
	});
});
