export type Strategy = 'cache-first' | 'network-only' | 'passthrough';

const SENSITIVE_PREFIXES = [
	'/api/',
	'/jmap',
	'/.well-known/jmap',
	'/.well-known/setjoin',
	'/auth/',
	'/updates/',
	'/terms/',
	'/blobs/',
	// Same-origin attachment content route — kept in lockstep with the service
	// worker's navigation-shell ban list (service-worker.ts) so the two lists
	// cannot drift: user attachment bytes are never cacheable, exactly as they
	// are never shell-servable.
	'/mail-attachment',
];

function normalizeAssetPath(path: string): string {
	return path.startsWith('/') ? path : `/${path}`;
}

function matchesPrefix(pathname: string, prefix: string): boolean {
	const root = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
	return pathname === root || pathname.startsWith(`${root}/`);
}

/**
 * Decide how the service worker should handle a request.
 *
 * Cacheability is allowlist-only: a GET is cache-first only when its exact
 * pathname is present in the current build's public-asset manifest. Unknown,
 * query-bearing, credential-bearing, and user-data paths are network-only.
 */
export function chooseStrategy(url: URL, method: string, publicAssets: ReadonlySet<string> = new Set()): Strategy {
	if (method !== 'GET') return 'passthrough';
	if (url.username || url.password || url.search) return 'network-only';
	if (SENSITIVE_PREFIXES.some((prefix) => matchesPrefix(url.pathname, prefix))) return 'network-only';
	return publicAssets.has(normalizeAssetPath(url.pathname)) ? 'cache-first' : 'network-only';
}
