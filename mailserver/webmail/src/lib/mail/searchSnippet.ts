// Strict allow-list sanitizer for search snippets (SearchSnippet/get).
//
// The server returns HTML (ts_headline — plain GIN + tsquery, 2026-07-04
// queue-B #2 revert; not ParadeDB/BM25) that wraps otherwise-UNTRUSTED
// message text in <mark>…</mark> highlight tags. It must never be {@html}'d raw
// — a message body/subject can contain arbitrary attacker markup. The strict
// approach: HTML-escape EVERYTHING first (so <script>, attributes, stray tags
// all become inert text), then re-allow ONLY the two literal highlight tags by
// turning their escaped forms back into real <mark>/</mark>. Nothing else — an
// injected `<mark onclick=…>` escapes to `&lt;mark onclick=…&gt;`, which does
// not match the exact `&lt;mark&gt;` literal and so stays inert.
export function sanitizeSnippet(html: string): string {
	const escaped = html
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;');
	return escaped.replace(/&lt;mark&gt;/g, '<mark>').replace(/&lt;\/mark&gt;/g, '</mark>');
}
