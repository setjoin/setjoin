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

const SUPPORTED_FREQS = new Set<string>(['DAILY', 'WEEKLY', 'MONTHLY', 'YEARLY']);
const UNSUPPORTED_PARTS = new Set<string>(['BYHOUR', 'BYMINUTE', 'BYSECOND', 'BYEASTER']);

// Format an ISO date (YYYY-MM-DD) as an RFC 5545 UTC UNTIL value (YYYYMMDDT000000Z).
function formatUntil(isoDate: string): string {
	const compact = isoDate.replaceAll('-', '');
	return `${compact}T000000Z`;
}

// Parse an RFC 5545 DATE (YYYYMMDD) or UTC date-time (YYYYMMDDTHHMMSS[Z]) back to YYYY-MM-DD.
function parseUntil(value: string): string {
	const m = /^(\d{4})(\d{2})(\d{2})(?:T|$)/.exec(value);
	if (!m) return value;
	return `${m[1]}-${m[2]}-${m[3]}`;
}

function stripRrulePrefix(trimmed: string): string {
	return trimmed.slice(0, 6).toUpperCase() === 'RRULE:' ? trimmed.slice(6).trim() : trimmed;
}

// Validate an RFC 5545 RRULE string against the supported date-level subset.
// Returns null when empty/valid, or a human-readable error message when unsupported.
export function validateRrule(rrule: string | null | undefined): string | null {
	if (!rrule) return null;
	const initial = rrule.trim();
	if (initial === '') return null;
	const trimmed = stripRrulePrefix(initial);

	let freq: string | undefined;
	for (const rawSegment of trimmed.split(';')) {
		const segment = rawSegment.trim();
		if (!segment) continue;
		const eqIdx = segment.indexOf('=');
		const key = (eqIdx >= 0 ? segment.slice(0, eqIdx) : segment).trim().toUpperCase();
		const value = (eqIdx >= 0 ? segment.slice(eqIdx + 1) : '').trim().toUpperCase();
		if (key === 'FREQ') {
			if (freq !== undefined) {
				return 'Duplicate FREQ part in RRULE';
			}
			freq = value;
		} else if (UNSUPPORTED_PARTS.has(key)) {
			return `Unsupported RRULE part: ${key} (only DAILY, WEEKLY, MONTHLY, YEARLY date-level rules are supported)`;
		}
	}

	if (!freq) {
		return 'RRULE missing required FREQ part';
	}
	if (!SUPPORTED_FREQS.has(freq)) {
		return `Unsupported RRULE frequency: ${freq} (supported: DAILY, WEEKLY, MONTHLY, YEARLY)`;
	}
	return null;
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
// 'none', null, or unsupported RRULE input (e.g. FREQ=HOURLY, BYHOUR/BYMINUTE/BYSECOND/BYEASTER).
export function parseRrule(rrule: string | null | undefined): RecurrenceParts | null {
	if (!rrule || rrule === 'none') return null;
	if (validateRrule(rrule) !== null) return null;

	const normalized = stripRrulePrefix(rrule.trim());
	const map = new Map<string, string>();
	for (const segment of normalized.split(';')) {
		const eqIdx = segment.indexOf('=');
		if (eqIdx < 0) continue;
		const key = segment.slice(0, eqIdx).trim().toUpperCase();
		const value = segment.slice(eqIdx + 1).trim();
		if (key) map.set(key, value);
	}

	const freq = map.get('FREQ')?.toUpperCase() as Freq | undefined;
	if (!freq || !SUPPORTED_FREQS.has(freq)) return null;

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
