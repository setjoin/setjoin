// Date/time helpers for DateTimePicker — plain module so the validation
// and slot math are unit-testable without the DOM.

export interface TimeSlot {
	value: string;
	label: string;
}

/** 48 half-hour slots: 00:00, 00:30, …, 23:30. */
export function buildTimeSlots(): TimeSlot[] {
	const slots: TimeSlot[] = [];
	for (let h = 0; h < 24; h++) {
		for (const m of [0, 30]) {
			const v = `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}`;
			slots.push({ value: v, label: v });
		}
	}
	return slots;
}

/**
 * Combine "YYYY-MM-DD" + "HH:MM" into a local Date.
 * Returns null on malformed input or calendar rollover (e.g. Feb 31).
 */
export function combineDateTime(dateStr: string, timeStr: string): Date | null {
	const dm = /^(\d{4})-(\d{2})-(\d{2})$/.exec(dateStr);
	const tm = /^(\d{2}):(\d{2})$/.exec(timeStr);
	if (!dm || !tm) return null;
	const year = Number(dm[1]);
	const month = Number(dm[2]);
	const day = Number(dm[3]);
	const hour = Number(tm[1]);
	const minute = Number(tm[2]);
	if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || minute > 59) return null;
	const d = new Date(year, month - 1, day, hour, minute, 0, 0);
	if (d.getFullYear() !== year || d.getMonth() !== month - 1 || d.getDate() !== day) return null;
	return d;
}

/** Strictly after `now`. */
export function isFuture(d: Date, now: Date = new Date()): boolean {
	return d.getTime() > now.getTime();
}

/** Local date as "YYYY-MM-DD" (for <input type="date"> values). */
export function toDateStr(d: Date): string {
	const m = String(d.getMonth() + 1).padStart(2, '0');
	const day = String(d.getDate()).padStart(2, '0');
	return `${d.getFullYear()}-${m}-${day}`;
}

/** Nearest half-hour slot at or before the given time, e.g. 09:43 → "09:30". */
export function toTimeSlot(d: Date): string {
	const h = String(d.getHours()).padStart(2, '0');
	return `${h}:${d.getMinutes() < 30 ? '00' : '30'}`;
}
