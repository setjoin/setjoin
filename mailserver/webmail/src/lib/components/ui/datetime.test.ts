import { describe, it, expect } from 'vitest';
import { buildTimeSlots, combineDateTime, isFuture, toDateStr, toTimeSlot } from './datetime';

describe('buildTimeSlots', () => {
	it('returns 48 half-hour slots from 00:00 to 23:30', () => {
		const slots = buildTimeSlots();
		expect(slots.length).toBe(48);
		expect(slots[0].value).toBe('00:00');
		expect(slots[1].value).toBe('00:30');
		expect(slots[47].value).toBe('23:30');
	});
});

describe('combineDateTime', () => {
	it('combines a date string and time string into a local Date', () => {
		const d = combineDateTime('2099-01-15', '08:30');
		expect(d).not.toBeNull();
		expect(d!.getFullYear()).toBe(2099);
		expect(d!.getMonth()).toBe(0);
		expect(d!.getDate()).toBe(15);
		expect(d!.getHours()).toBe(8);
		expect(d!.getMinutes()).toBe(30);
	});

	it('rejects calendar rollover like Feb 31', () => {
		expect(combineDateTime('2099-02-31', '08:00')).toBeNull();
	});

	it('rejects malformed input', () => {
		expect(combineDateTime('', '08:00')).toBeNull();
		expect(combineDateTime('2099-01-15', '8:00')).toBeNull();
		expect(combineDateTime('2099-01-15', '25:00')).toBeNull();
		expect(combineDateTime('not-a-date', '08:00')).toBeNull();
	});
});

describe('isFuture', () => {
	it('compares strictly against the provided now', () => {
		const now = new Date(2026, 5, 1, 12, 0);
		expect(isFuture(new Date(2026, 5, 1, 12, 1), now)).toBe(true);
		expect(isFuture(new Date(2026, 5, 1, 12, 0), now)).toBe(false);
		expect(isFuture(new Date(2026, 4, 30, 12, 0), now)).toBe(false);
	});
});

describe('toDateStr / toTimeSlot', () => {
	it('formats a local date as YYYY-MM-DD with zero padding', () => {
		expect(toDateStr(new Date(2026, 0, 5))).toBe('2026-01-05');
	});

	it('rounds down to the nearest 30-minute slot', () => {
		expect(toTimeSlot(new Date(2026, 0, 5, 9, 0))).toBe('09:00');
		expect(toTimeSlot(new Date(2026, 0, 5, 9, 29))).toBe('09:00');
		expect(toTimeSlot(new Date(2026, 0, 5, 9, 30))).toBe('09:30');
		expect(toTimeSlot(new Date(2026, 0, 5, 9, 59))).toBe('09:30');
	});
});
