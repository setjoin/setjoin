import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { resolveLocalSchedule, ScheduleTimeError } from './schedule';

const originalTZ = process.env.TZ;

describe('server-update local schedule', () => {
	beforeEach(() => { process.env.TZ = 'America/New_York'; });
	afterEach(() => {
		if (originalTZ === undefined) delete process.env.TZ;
		else process.env.TZ = originalTZ;
	});

	it('returns one ISO instant for an ordinary future wall-clock time', () => {
		expect(resolveLocalSchedule('2099-01-02T03:04', 0)).toBe(new Date(2099, 0, 2, 3, 4).toISOString());
	});

	it.each([
		['2026-03-08T02:30', 'nonexistent'],
		['2026-11-01T01:30', 'ambiguous'],
		['2020-01-02T03:04', 'past'],
	] as const)('rejects %s as %s', (value, code) => {
		expect(() => resolveLocalSchedule(value, new Date('2026-01-01T00:00:00Z').getTime()))
			.toThrowError(expect.objectContaining<Partial<ScheduleTimeError>>({ code }));
	});

	it('rejects partial or browser-normalized input', () => {
		expect(() => resolveLocalSchedule('2026-01-02T03', 0))
			.toThrowError(expect.objectContaining<Partial<ScheduleTimeError>>({ code: 'incomplete' }));
		expect(() => resolveLocalSchedule('2026-02-30T03:00', 0))
			.toThrowError(expect.objectContaining<Partial<ScheduleTimeError>>({ code: 'nonexistent' }));
	});
});
