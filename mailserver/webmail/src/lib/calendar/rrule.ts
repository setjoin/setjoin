// rrule.ts — pure RFC 5545 RRULE compose/parse helpers for the recurrence editor.
// The single home for RRULE string logic (no RRULE assembly lives in components).

export type Freq = 'DAILY' | 'WEEKLY' | 'MONTHLY' | 'YEARLY';

export type RecurrenceEnd =
	| { type: 'never' }
	| { type: 'count'; count: number }
	| { type: 'until'; until: string };

export interface RecurrenceParts {
	freq: Freq;
	interval: number;
	byDay?: string[];
	end: RecurrenceEnd;
}

// Format an ISO date (YYYY-MM-DD) as an RFC 5545 UTC UNTIL value (YYYYMMDDT000000Z).
function formatUntil(isoDate: string): string {
	const compact = isoDate.replaceAll('-', '');
	return `${compact}T000000Z`;
}

// Parse an RFC 5545 UTC date-time (YYYYMMDDT000000Z) back to an ISO date (YYYY-MM-DD).
function parseUntil(value: string): string {
	const m = /^(\d{4})(\d{2})(\d{2})T/.exec(value);
	if (!m) return value;
	return `${m[1]}-${m[2]}-${m[3]}`;
}

// buildRrule composes a verbatim RRULE string from structured parts.
// INTERVAL=1 is omitted; BYDAY is emitted only when byDay is non-empty.
export function buildRrule(parts: RecurrenceParts): string {
	const segments: string[] = [`FREQ=${parts.freq}`];

	if (parts.interval && parts.interval > 1) {
		segments.push(`INTERVAL=${parts.interval}`);
	}

	if (parts.byDay && parts.byDay.length > 0) {
		segments.push(`BYDAY=${parts.byDay.join(',')}`);
	}

	if (parts.end.type === 'count') {
		segments.push(`COUNT=${parts.end.count}`);
	} else if (parts.end.type === 'until') {
		segments.push(`UNTIL=${formatUntil(parts.end.until)}`);
	}

	return segments.join(';');
}

// parseRrule decomposes an RRULE string into structured parts. Returns null for empty,
// 'none', or null input (the "does not repeat" sentinel).
export function parseRrule(rrule: string | null | undefined): RecurrenceParts | null {
	if (!rrule || rrule === 'none') return null;

	const map = new Map<string, string>();
	for (const segment of rrule.split(';')) {
		const [key, value] = segment.split('=');
		if (key && value !== undefined) map.set(key.toUpperCase(), value);
	}

	const freq = map.get('FREQ') as Freq | undefined;
	if (!freq) return null;

	const interval = map.has('INTERVAL') ? parseInt(map.get('INTERVAL')!, 10) || 1 : 1;

	let end: RecurrenceEnd = { type: 'never' };
	if (map.has('COUNT')) {
		end = { type: 'count', count: parseInt(map.get('COUNT')!, 10) || 1 };
	} else if (map.has('UNTIL')) {
		end = { type: 'until', until: parseUntil(map.get('UNTIL')!) };
	}

	const parts: RecurrenceParts = { freq, interval, end };

	if (map.has('BYDAY')) {
		const byDay = map
			.get('BYDAY')!
			.split(',')
			.map((d) => d.trim())
			.filter(Boolean);
		if (byDay.length > 0) parts.byDay = byDay;
	}

	return parts;
}

// Weekday tokens in RFC 5545 order (Sunday-first to match the calendar grid).
export const WEEKDAYS: { token: string; labelKey: string }[] = [
	{ token: 'SU', labelKey: 'calendar.recurrence.day.su' },
	{ token: 'MO', labelKey: 'calendar.recurrence.day.mo' },
	{ token: 'TU', labelKey: 'calendar.recurrence.day.tu' },
	{ token: 'WE', labelKey: 'calendar.recurrence.day.we' },
	{ token: 'TH', labelKey: 'calendar.recurrence.day.th' },
	{ token: 'FR', labelKey: 'calendar.recurrence.day.fr' },
	{ token: 'SA', labelKey: 'calendar.recurrence.day.sa' }
];
