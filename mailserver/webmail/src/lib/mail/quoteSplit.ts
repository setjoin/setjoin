// Quoted-text collapse (WAVE-5 #6) — split a message body into the fresh part
// and the trailing quoted reply chain, so the reading pane can collapse the
// quote behind a "Show quoted text" pill.
//
// splitQuotedHTML runs on the SANITIZED html AFTER the cid rewrite (the
// renderEmailBodyHTML output) — both halves therefore stay sanitized; the split
// only partitions top-level nodes, it never rewrites markup.
//
// Boundary vocabulary (first TOP-LEVEL match wins):
//   · <blockquote>            — the universal quote container
//   · .gmail_quote            — Gmail's wrapper div
//   · div[type=cite]          — Thunderbird's wrapper
//   · an "On … wrote:" line   — the bare attribution Gmail/Apple Mail emit
//     (ENGLISH-ONLY heuristic: localized attributions — "Am … schrieb:",
//     "在…写道：" — are not matched in v1, so those quotes simply stay visible;
//     a miss is cosmetic, never data loss).
//
// A body that IS entirely quote (no fresh content before the boundary), or has
// no boundary, returns quoted:null — the caller renders no pill.

export interface QuoteSplit {
	/** The fresh (pre-quote) part. Equals the input when quoted is null. */
	main: string;
	/** The quoted tail, or null when there is nothing to collapse. */
	quoted: string | null;
}

// Bare attribution line: "On Tue, Jul 1, 2025 at 9:00 AM Ada <a@x> wrote:".
// Bounded length so a paragraph that merely starts with "On" cannot match.
const ATTRIBUTION_RE = /^On .{1,300} wrote:\s*$/s;

function isBoundaryElement(el: Element): boolean {
	if (el.tagName === 'BLOCKQUOTE') return true;
	if (el.classList.contains('gmail_quote')) return true;
	if (el.tagName === 'DIV' && el.getAttribute('type') === 'cite') return true;
	return ATTRIBUTION_RE.test(el.textContent ?? '');
}

/** Split sanitized HTML at the first top-level quote boundary. */
export function splitQuotedHTML(html: string): QuoteSplit {
	const none: QuoteSplit = { main: html, quoted: null };
	if (!html || typeof DOMParser === 'undefined') return none;

	let doc: Document;
	try {
		doc = new DOMParser().parseFromString(html, 'text/html');
	} catch {
		return none;
	}
	const nodes = Array.from(doc.body.childNodes);

	let boundary = -1;
	let hasContentBefore = false;
	for (let i = 0; i < nodes.length; i++) {
		const n = nodes[i];
		if (n.nodeType === Node.ELEMENT_NODE && isBoundaryElement(n as Element)) {
			boundary = i;
			break;
		}
		if ((n.textContent ?? '').trim() !== '') hasContentBefore = true;
	}
	// No boundary, or whole-body quote (nothing fresh before it) → nothing to collapse.
	if (boundary < 0 || !hasContentBefore) return none;

	const ser = (list: Node[]) => {
		const div = doc.createElement('div');
		for (const n of list) div.appendChild(n);
		return div.innerHTML;
	};
	return { main: ser(nodes.slice(0, boundary)), quoted: ser(nodes.slice(boundary)) };
}

/**
 * Split a plain-text body at its trailing `> `-quote run. v1 is the trivial
 * prefix-run splitter (not exclusion): find the first `>`-prefixed line and
 * split there ONLY when every following line is quoted or blank — an
 * interleaved reply (fresh text below a quote) is left unsplit rather than
 * hiding the sender's own words. An immediately-preceding "On … wrote:"
 * attribution line joins the quoted tail.
 */
export function splitQuotedText(text: string): QuoteSplit {
	const none: QuoteSplit = { main: text, quoted: null };
	if (!text) return none;

	const lines = text.split('\n');
	const q = lines.findIndex((l) => l.startsWith('>'));
	if (q < 0) return none;
	if (!lines.slice(q).every((l) => l.trim() === '' || l.startsWith('>'))) return none;

	let start = q;
	if (start > 0 && ATTRIBUTION_RE.test(lines[start - 1].trim())) start -= 1;
	// Whole-body quote → nothing to collapse.
	if (lines.slice(0, start).every((l) => l.trim() === '')) return none;

	return {
		main: lines.slice(0, start).join('\n').replace(/\n+$/, ''),
		quoted: lines.slice(start).join('\n')
	};
}
