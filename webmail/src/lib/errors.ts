// Structured error parsing for user-facing error messages.
//
// Every catch block should use parseError() instead of exposing raw
// exceptions to the UI — see docs/specs/LOADING_STATES.md for the
// combined loading + error pattern.

export interface ParsedError {
	/** User-facing message safe for display in the UI. */
	message: string;
	/** Original technical detail, suitable for console.error but never shown to users. */
	technical?: string;
}

/**
 * Convert any thrown value into a user-safe {@link ParsedError}.
 *
 * - DOMException/AbortError  → "Request cancelled" (intentional abort — not an error)
 * - TypeError                → network-friendly message (fetch throws TypeError on connection failure)
 * - Error                    → passes our own authored message through
 * - string                   → returned as-is
 * - everything else          → generic fallback "Something went wrong"
 */
export function parseError(err: unknown): ParsedError {
	// AbortError — intentional cancellation by AbortController, not a real error
	if (err instanceof DOMException && err.name === 'AbortError') {
		return { message: 'Request cancelled' };
	}

	// TypeError — fetch() throws TypeError for network failures (e.g. "Failed to fetch")
	if (err instanceof TypeError) {
		return {
			message: 'Network error — please check your connection',
			technical: err.message
		};
	}

	// Regular Error — our own errors carry authored messages safe for display
	if (err instanceof Error) {
		return { message: err.message, technical: err.message };
	}

	// Plain string thrown
	if (typeof err === 'string') {
		return { message: err };
	}

	// null, undefined, number, object — nothing meaningful for the user
	return { message: 'Something went wrong' };
}

/**
 * Read the RFC 7807 problem+json `detail` from an httpRequest/adminFetch
 * onError callback's Response — the gateway emits problem+json for every
 * app-JSON-API error, so this is the one shape any onError that needs the
 * server's actionable message (not just a generic status string) should read.
 * Falls back to `title`, then the caller-supplied fallback.
 */
export async function problemDetail(res: Response, fallback = 'Request failed'): Promise<string> {
	const body = (await res.json().catch(() => null)) as { detail?: unknown; title?: unknown } | null;
	if (body && typeof body.detail === 'string') return body.detail;
	if (body && typeof body.title === 'string') return body.title;
	return fallback;
}
