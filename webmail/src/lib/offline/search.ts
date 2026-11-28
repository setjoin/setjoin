import { getStore } from './store';

/**
 * Offline full-text BODY search over the SQLCipher messages_fts (FTS5) index.
 * Un-deferred by the native-offline pivot: the whole DB is page-encrypted, so
 * the FTS index is encrypted at rest automatically (§13). Returns matching
 * message ids; empty/locked store => []. Online search is unchanged.
 */
export async function searchOffline(query: string, limit = 100): Promise<string[]> {
	const store = getStore();
	if (!store) return [];
	const q = query.trim();
	if (!q) return [];
	return store.searchBody(q, limit);
}
