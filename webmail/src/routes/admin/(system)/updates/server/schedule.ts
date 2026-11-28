export type ScheduleErrorCode = 'incomplete' | 'nonexistent' | 'ambiguous' | 'past';

export class ScheduleTimeError extends Error {
	constructor(readonly code: ScheduleErrorCode) {
		super(code);
		this.name = 'ScheduleTimeError';
	}
}

function hasLocalParts(candidate: Date, parts: number[]): boolean {
	return candidate.getFullYear() === parts[0]
		&& candidate.getMonth() === parts[1] - 1
		&& candidate.getDate() === parts[2]
		&& candidate.getHours() === parts[3]
		&& candidate.getMinutes() === parts[4];
}

// Resolve the browser's local wall-clock selection to one unambiguous instant.
// Searching the surrounding three hours minute-by-minute catches both common
// one-hour DST folds and non-hour transitions without relying on one locale.
export function resolveLocalSchedule(value: string, nowMs = Date.now()): string | null {
	if (!value) return null;
	const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(value);
	if (!match) throw new ScheduleTimeError('incomplete');
	const parts = match.slice(1).map(Number);
	const date = new Date(parts[0], parts[1] - 1, parts[2], parts[3], parts[4]);
	if (!hasLocalParts(date, parts)) throw new ScheduleTimeError('nonexistent');

	for (let deltaMinutes = -180; deltaMinutes <= 180; deltaMinutes += 1) {
		if (deltaMinutes === 0) continue;
		const candidate = new Date(date.getTime() + deltaMinutes * 60_000);
		if (hasLocalParts(candidate, parts)) throw new ScheduleTimeError('ambiguous');
	}
	if (date.getTime() <= nowMs) throw new ScheduleTimeError('past');
	return date.toISOString();
}
