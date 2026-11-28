import { createEdgeClient } from '$lib/edge/client';
import type { Trace } from '$lib/types/delivery';

const deliveryEdgeClient = createEdgeClient({
	onError: (r) => `Trace error: ${r.status}`
});

export async function messageTrace(id: string, signal?: AbortSignal): Promise<Trace> {
	// openapi-fetch percent-encodes path parameters via encodeURIComponent at this
	// boundary — a malformed id cannot escape the /api/messages/ prefix; anything
	// else fails closed with a scoped 404/401 at the gateway.
	const { data, error, response } = await deliveryEdgeClient.GET('/api/messages/{emailId}/trace', {
		params: { path: { emailId: id } },
		signal
	});
	if (!response.ok || error !== undefined || data === undefined) {
		throw new Error(`Trace error: ${response.status}`);
	}
	return data as Trace;
}
