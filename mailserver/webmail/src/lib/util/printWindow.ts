// Shared print-window harness for the mail and calendar print paths.
// Both callers build their own HTML template (heads/titles/styles legitimately
// differ) but share the XSS-escaping primitive and the popup DOM harness.

// Escape a plain-text value for safe interpolation into a print document's HTML.
// This is the XSS-prevention primitive for every interpolated field on both print
// paths — keep it a pure 5-replace chain (matching chat/markdown.ts), never write
// user text raw. The single-quote replace keeps the primitive correct even where
// an attribute is (or becomes) single-quoted.
export function escapeHtml(s: string): string {
	return s
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;')
		.replace(/"/g, '&quot;')
		.replace(/'/g, '&#39;');
}

/**
 * Open a bare browser window, write `doc`, and print it. Must be called
 * synchronously from a user click so the popup blocker allows window.open.
 *
 * ponytail: print from the opener once the popup loads. Opener-driven print()
 * avoids an inline <script> the app CSP would block. Ceiling: if 'load' never
 * fires (rare), the window stays open for a manual print.
 */
export function openPrintWindow(doc: string): void {
	const win = window.open('', '_blank');
	if (!win) return; // popup blocked — nothing we can do without a user gesture window
	win.document.write(doc);
	win.document.close();
	win.addEventListener('load', () => {
		win.focus();
		win.print();
	}, { once: true });
}
