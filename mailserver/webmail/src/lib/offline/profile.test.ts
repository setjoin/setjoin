import { describe, it, expect, vi } from 'vitest';
import { fetchCryptoProfile } from './profile';

describe('crypto profile discovery', () => {
	it('reads crypto_profile from /.well-known/setjoin', async () => {
		vi.stubGlobal('fetch', vi.fn(async () =>
			new Response(JSON.stringify({ crypto_profile: 'smx', crypto_algorithm: 'SM4-GCM' }), { status: 200 })));
		expect(await fetchCryptoProfile()).toBe('SMx');
	});
	it('defaults to standard when unset or fetch fails', async () => {
		vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('offline'); }));
		expect(await fetchCryptoProfile()).toBe('standard');
	});
});
