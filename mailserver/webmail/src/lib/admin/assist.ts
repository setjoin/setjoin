// AdminAssist helpers: asRich renderer and POST /assist/complete client.
// Reference: admin-kit §6.5 (message rendering & behavior).

import { httpRequest } from '$lib/http';

/** Encoding boundary for the only {@html} sink this module feeds: raw `<`/`>`
 *  in message content is entity-escaped HERE, at the builder, so a future
 *  caller cannot silently turn asRich output into live markup. Output that
 *  already contains entities (the AssistDrawer convention escapes `& < >`
 *  before calling) passes through unchanged — no double-escaping — because
 *  entity text carries no raw angle brackets.
 */
function escapeMarkup(s: string): string {
	return s.replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/** Minimal rich-text renderer per admin-kit §6.5.
 *  Renders `**bold**` → `<strong>` and `` `code` `` → inline code chip only.
 *  No headings, lists, links, tables, or emoji. Content is entity-escaped at
 *  this boundary (see escapeMarkup) — the result is safe for {@html} as-is.
 */
export function asRich(text: string): string {
	const parts = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g);
	return parts
		.map((part) => {
			if (part.startsWith('**') && part.endsWith('**')) {
				const inner = escapeMarkup(part.slice(2, -2));
				return `<strong>${inner}</strong>`;
			}
			if (part.startsWith('`') && part.endsWith('`')) {
				const inner = escapeMarkup(part.slice(1, -1));
				return `<code class="sj-code-chip">${inner}</code>`;
			}
			return escapeMarkup(part);
		})
		.join('');
}

export interface AssistMessage {
	role: 'system' | 'user' | 'assistant';
	content: string;
}

export interface AssistCompleteRequest {
	messages: AssistMessage[];
	context?: string;
	locale?: string;
}

export interface AssistCompleteResponse {
	content: string;
}

/** Call POST /assist/complete (backend-wave2 B4).
 *  Returns the response content on success (200).
 *  Throws on 403/422/502/503 with user-facing problem detail.
 *  Routes through httpRequest (shared timeout/abort/auth) but reads the
 *  problem-JSON body in the onError callback so each non-ok status maps to calm
 *  user copy — a bare adminFetch() throws before the detail can be read, which
 *  would leak raw JSON to the user. 401 redirects to /login (the standard
 *  httpRequest behavior) instead of flowing through onError.
 */
export async function assistComplete(req: AssistCompleteRequest): Promise<AssistCompleteResponse> {
	const res = await httpRequest('/api/assist/complete', {
		method: 'POST',
		headers: { 'Content-Type': 'application/json' },
		body: JSON.stringify(req),
		loginRedirect: '/login',
		unauthorizedMessage: 'Session expired — please log in again',
		onError: async (r) => {
			// Parse problem-JSON detail for user-facing copy.
			let detail = '';
			try {
				const body = await r.json();
				if (body?.detail) detail = body.detail;
				if (!detail && body?.title) detail = body.title;
			} catch { /* use status-specific fallback */ }

			if (r.status === 403) return 'Assist is not available for your account.';
			if (r.status === 422) return detail || 'Assist request could not be processed.';
			if (r.status === 502) return 'Assist backend is not reachable. Try again soon.';
			if (r.status === 503) return 'Assist is temporarily unavailable.';
			return detail || 'Assist request failed. Try again.';
		},
	});
	return (await res.json()) as AssistCompleteResponse;
}
