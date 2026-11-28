import { localeCode } from '$lib/i18n';
import { escapeHtml, openPrintWindow } from '$lib/util/printWindow';
import type { CalendarEvent } from '$lib/types/jmap';

// EVERY event field (title/location/description/attendee names) is user- or
// shared-calendar-controlled, so nothing is ever written raw — escapeHtml escapes
// every interpolated field.

function fmtDate(iso: string | undefined): string {
	if (!iso) return '';
	return new Date(iso).toLocaleDateString(localeCode(), {
		weekday: 'short', month: 'short', day: 'numeric', year: 'numeric'
	});
}

function fmtTime(iso: string | undefined): string {
	if (!iso) return '';
	return new Date(iso).toLocaleTimeString(localeCode(), { hour: 'numeric', minute: '2-digit', hour12: true });
}

function whenLabel(ev: CalendarEvent): string {
	if (ev.isAllDay) return `${fmtDate(ev.start)} (all day)`;
	const end = ev.end ? ` – ${fmtTime(ev.end)}` : '';
	return `${fmtDate(ev.start)}, ${fmtTime(ev.start)}${end}`;
}

/**
 * Open a bare browser window and print an agenda of the given events. Must be
 * called synchronously from a user click so the popup blocker allows window.open.
 *
 * Pure client-side: `events` is already in memory (RLS-gated at JMAP) and should be
 * pre-filtered to the visible calendars + current view range by the caller. Every
 * field is escaped — no event text is ever written raw into the document.
 */
export function printAgenda(events: CalendarEvent[], title: string): void {
	const rows = events
		.slice()
		.sort((a, b) => new Date(a.start).getTime() - new Date(b.start).getTime())
		.map((ev) => {
			const attendees = (ev.attendees ?? [])
				.map((a) => a.name || a.email || '')
				.filter(Boolean)
				.join(', ');
			return `<tr>
  <td class="sj-agenda-when">${escapeHtml(whenLabel(ev))}</td>
  <td>
    <div class="sj-agenda-title">${escapeHtml(ev.title || '(no title)')}</div>
    ${ev.location ? `<div class="sj-agenda-loc">${escapeHtml(ev.location)}</div>` : ''}
    ${ev.description ? `<div class="sj-agenda-desc">${escapeHtml(ev.description)}</div>` : ''}
    ${attendees ? `<div class="sj-agenda-att">${escapeHtml(attendees)}</div>` : ''}
  </td>
</tr>`;
		})
		.join('\n');

	const body = rows
		? `<table class="sj-agenda">${rows}</table>`
		: `<p class="sj-agenda-empty">No events in this range.</p>`;

	const doc = `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>${escapeHtml(title)}</title>
<style>
  body { font-family: system-ui, sans-serif; color: #111; margin: 24px; }
  h1 { font-size: 18px; margin: 0 0 16px; }
  table.sj-agenda { width: 100%; border-collapse: collapse; }
  table.sj-agenda td { border-bottom: 1px solid #ccc; padding: 8px 10px; vertical-align: top; font-size: 13px; }
  .sj-agenda-when { white-space: nowrap; color: #555; width: 220px; }
  .sj-agenda-title { font-weight: 600; }
  .sj-agenda-loc, .sj-agenda-att { font-size: 12px; color: #555; }
  .sj-agenda-desc { font-size: 12px; color: #333; white-space: pre-wrap; margin-top: 2px; }
  .sj-agenda-empty { color: #555; }
</style>
</head>
<body>
<h1>${escapeHtml(title)}</h1>
${body}
</body>
</html>`;

	openPrintWindow(doc);
}
