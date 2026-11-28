import { httpRequest, type HttpOptions } from '$lib/http';

// All admin paths are app JSON served below the gateway's canonical /api mux.
const API_BASE = '/api';

// Deliberately not async: preserve the direct Promise returned by httpRequest
// and avoid an extra thenable-resolution microtask in component tests.
export function adminFetch(path: string, opts: HttpOptions = {}): Promise<Response> {
	const headers: Record<string, string> = {};
	const hasExplicitCT =
		opts.headers &&
		typeof opts.headers === 'object' &&
		'Content-Type' in (opts.headers as Record<string, string>);
	if (!hasExplicitCT && !(opts.body instanceof FormData)) {
		headers['Content-Type'] = 'application/json';
	}
	if (opts.headers) {
		const callerHeaders = opts.headers as Record<string, string>;
		for (const key of Object.keys(callerHeaders)) {
			headers[key] = callerHeaders[key];
		}
	}
	return httpRequest(API_BASE + path, {
		...opts,
		headers,
		cache: 'no-store',
		loginRedirect: '/login',
		forbiddenMessage: 'Admin access required'
	});
}
