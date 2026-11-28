import { renderEmailBodyHTML } from '$lib/sanitize';
import { escapeHtml, openPrintWindow } from '$lib/util/printWindow';
import type { Email } from '$lib/types/jmap';

// Header fields + the plain-text body fallback are escaped via escapeHtml. The HTML
// body itself is already script-free via renderEmailBodyHTML → sanitizeHTML, so it
// is written as-is — and the popup document below carries its own restrictive CSP
// as SECONDARY containment (S20): the print surface renders sanitized attacker
// HTML in a same-origin window, so even an independent sanitizer/allowlist escape
// must not gain script execution, remote loads, or framing there. Printing itself
// is opener-driven (util/printWindow), so the popup needs no script of its own.

/**
 * Open a bare browser window and print a single message. Must be called
 * synchronously from a user click so the popup blocker allows window.open.
 *
 * Body is the sanitized HTML when present, else the plain text. Remote images are
 * NOT loaded (renderEmailBodyHTML defaults allowRemoteImages=false) — the print
 * view never fetches trackers the reading pane blocked, and the CSP below backs
 * that up at the document level.
 */
export function printMessage(email: Email): void {
	const from = email.from?.[0];
	const fromName = from?.name || from?.email || '';
	const fromEmail = from?.email || '';
	const date = email.receivedAt ? new Date(email.receivedAt).toLocaleString() : '';
	const subject = email.subject || '(no subject)';

	const bodyHTML = renderEmailBodyHTML(email);
	const body = bodyHTML || `<pre class="sj-print-text">${escapeHtml(email.bodyText || email.preview || '')}</pre>`;

	const fromLine = fromEmail && fromEmail !== fromName
		? `${escapeHtml(fromName)} &lt;${escapeHtml(fromEmail)}&gt;`
		: escapeHtml(fromName);

	const doc = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data: blob:">
<title>${escapeHtml(subject)}</title>
<style>
  body { font-family: system-ui, sans-serif; color: #111; margin: 24px; }
  .sj-print-head { border-bottom: 1px solid #ccc; padding-bottom: 12px; margin-bottom: 16px; }
  .sj-print-subject { font-size: 18px; font-weight: 600; margin: 0 0 6px; }
  .sj-print-meta { font-size: 13px; color: #555; }
  .sj-print-text { white-space: pre-wrap; font-family: inherit; font-size: 14px; }
  img { max-width: 100%; }
</style>
</head>
<body>
<div class="sj-print-head">
  <p class="sj-print-subject">${escapeHtml(subject)}</p>
  <div class="sj-print-meta">${fromLine}</div>
  <div class="sj-print-meta">${escapeHtml(date)}</div>
</div>
${body}
</body>
</html>`;

	openPrintWindow(doc);
}
