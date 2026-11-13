import { httpRequest } from '$lib/http';
import type { Trace } from '$lib/types/delivery';

export async function messageTrace(id: string, signal?: AbortSignal): Promise<Trace> {
	// The id is interpolated into the request path, so it is percent-encoded at
	// this boundary — a malformed id can shape the path (e.g. add segments) but
	// never escape the /api/messages/ prefix. Server-issued ids (hex/UUID) are
	// unaffected; anything else fails closed with a scoped 404/401 at the
	// gateway rather than a differently-shaped route.
	const res = await httpRequest(`/api/messages/${encodeURIComponent(id)}/trace`, {
		method: 'GET',
		signal,
		onError: (r) => `Trace error: ${r.status}`
	});
	return (await res.json()) as Trace;
}
