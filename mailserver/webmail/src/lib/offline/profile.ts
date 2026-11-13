export type CryptoProfile = 'standard' | 'SMx';

// fetchCryptoProfile reads the server's crypto_profile from the
// unauthenticated /.well-known/setjoin doc. The client does NOT choose the
// cipher — only passes it to db.open() so the store opens under the right
// SQLCipher cipher. Defaults to 'standard' (AES) on any error so an
// unreachable well-known never blocks the offline bootstrap.
export async function fetchCryptoProfile(): Promise<CryptoProfile> {
	try {
		const res = await fetch('/.well-known/setjoin', { credentials: 'same-origin' });
		if (!res.ok) return 'standard';
		const doc = await res.json();
		const p = (doc?.crypto_profile ?? '').toString().toLowerCase();
		return p === 'smx' ? 'SMx' : 'standard';
	} catch {
		return 'standard';
	}
}
