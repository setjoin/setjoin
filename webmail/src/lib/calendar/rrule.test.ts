import { describe, it, expect } from 'vitest';
import { buildRrule, parseRrule, validateRrule } from './rrule';

describe('buildRrule', () => {
	it('weekly every 2 weeks on Mon/Wed until a date', () => {
		expect(
			buildRrule({
				freq: 'WEEKLY',
				interval: 2,
				byDay: ['MO', 'WE'],
				end: { type: 'until', until: '2026-12-31' }
			})
		).toBe('FREQ=WEEKLY;INTERVAL=2;BYDAY=MO,WE;UNTIL=20261231T000000Z');
	});

	it('daily for 10 occurrences', () => {
		expect(buildRrule({ freq: 'DAILY', interval: 1, end: { type: 'count', count: 10 } })).toBe(
			'FREQ=DAILY;COUNT=10'
		);
	});

	it('omits INTERVAL=1 and never emits BYDAY for non-weekly without byDay', () => {
		expect(buildRrule({ freq: 'MONTHLY', interval: 1, end: { type: 'never' } })).toBe(
			'FREQ=MONTHLY'
		);
	});

	it('round-trips through parseRrule', () => {
		const parts = {
			freq: 'WEEKLY' as const,
			interval: 3,
			byDay: ['FR'],
			end: { type: 'count' as const, count: 5 }
		};
		expect(parseRrule(buildRrule(parts))).toEqual(parts);
	});

	it('round-trips a never-ending monthly with no byDay', () => {
		const parts = { freq: 'MONTHLY' as const, interval: 1, end: { type: 'never' as const } };
		expect(parseRrule(buildRrule(parts))).toEqual(parts);
	});

	it('round-trips a weekly until with byDay', () => {
		const parts = {
			freq: 'WEEKLY' as const,
			interval: 2,
			byDay: ['MO', 'WE'],
			end: { type: 'until' as const, until: '2026-12-31' }
		};
		expect(parseRrule(buildRrule(parts))).toEqual(parts);
	});
});

describe('parseRrule', () => {
	it('returns null for empty / none', () => {
		expect(parseRrule('')).toBeNull();
		expect(parseRrule('none')).toBeNull();
		expect(parseRrule(null)).toBeNull();
	});

	it('parses INTERVAL absent as 1', () => {
		const p = parseRrule('FREQ=DAILY');
		expect(p?.interval).toBe(1);
		expect(p?.freq).toBe('DAILY');
		expect(p?.end).toEqual({ type: 'never' });
	});

	it('parses DATE-form UNTIL=YYYYMMDD as YYYY-MM-DD', () => {
		expect(parseRrule('FREQ=DAILY;UNTIL=19970905')).toEqual({
			freq: 'DAILY',
			interval: 1,
			end: { type: 'until', until: '1997-09-05' }
		});
		expect(parseRrule('FREQ=DAILY;UNTIL=19970905T090000Z')).toEqual({
			freq: 'DAILY',
			interval: 1,
			end: { type: 'until', until: '1997-09-05' }
		});
	});

	it('parses leading case-insensitive RRULE: prefix', () => {
		expect(parseRrule('RRULE:FREQ=DAILY;COUNT=3')).toEqual({
			freq: 'DAILY',
			interval: 1,
			end: { type: 'count', count: 3 }
		});
		expect(parseRrule('rrule:FREQ=DAILY;COUNT=3')).toEqual({
			freq: 'DAILY',
			interval: 1,
			end: { type: 'count', count: 3 }
		});
	});

	it('returns null for unsupported FREQ, duplicate FREQ, bare RRULE:, and sub-day / Easter BY* parts', () => {
		expect(parseRrule('FREQ=HOURLY;COUNT=3')).toBeNull();
		expect(parseRrule('FREQ=MINUTELY;INTERVAL=15')).toBeNull();
		expect(parseRrule('FREQ=SECONDLY;COUNT=5')).toBeNull();
		expect(parseRrule('freq=hourly;count=2')).toBeNull();
		expect(parseRrule('FREQ=HOURLY;FREQ=DAILY;COUNT=3')).toBeNull();
		expect(parseRrule('FREQ=DAILY;FREQ=WEEKLY')).toBeNull();
		expect(parseRrule('RRULE:')).toBeNull();
		expect(parseRrule('RRULE:BYHOUR=9;FREQ=DAILY')).toBeNull();
		expect(parseRrule('rrule:BYHOUR=9;FREQ=DAILY')).toBeNull();
		expect(parseRrule('FREQ=DAILY;BYHOUR=9,17')).toBeNull();
		expect(parseRrule('FREQ=DAILY;BYMINUTE=30')).toBeNull();
		expect(parseRrule('FREQ=DAILY;BYSECOND=0')).toBeNull();
		expect(parseRrule('FREQ=YEARLY;BYEASTER=1')).toBeNull();
	});
});

describe('validateRrule', () => {
	it('returns null for null, empty, and supported rules (including RRULE: prefix)', () => {
		expect(validateRrule(null)).toBeNull();
		expect(validateRrule(undefined)).toBeNull();
		expect(validateRrule('')).toBeNull();
		expect(validateRrule('   \t\r\n')).toBeNull();
		expect(validateRrule('RRULE:FREQ=DAILY;COUNT=3')).toBeNull();
		expect(validateRrule('rrule:FREQ=DAILY;COUNT=3')).toBeNull();
		expect(validateRrule('FREQ=DAILY;UNTIL=19970905')).toBeNull();
		expect(validateRrule('FREQ=WEEKLY;INTERVAL=2;BYDAY=TU,SU;WKST=SU;COUNT=3')).toBeNull();
		expect(validateRrule('freq=monthly;byday=3tu,-3th;count=3')).toBeNull();
		expect(validateRrule('FREQ=YEARLY;BYYEARDAY=1,-1')).toBeNull();
	});

	it('rejects missing, duplicate, bare RRULE:, or unsupported FREQ', () => {
		expect(validateRrule('INTERVAL=2;COUNT=3')).toMatch(/FREQ/i);
		expect(validateRrule('RRULE:')).toBe('RRULE missing required FREQ part');
		expect(validateRrule('rrule:   ')).toBe('RRULE missing required FREQ part');
		expect(validateRrule('FREQ=HOURLY;FREQ=DAILY;COUNT=3')).toBe('Duplicate FREQ part in RRULE');
		expect(validateRrule('FREQ=DAILY;FREQ=WEEKLY')).toBe('Duplicate FREQ part in RRULE');
		expect(validateRrule('FREQ=HOURLY;COUNT=3')).toMatch(/HOURLY/);
		expect(validateRrule('FREQ=MINUTELY')).toMatch(/MINUTELY/);
		expect(validateRrule('FREQ=SECONDLY')).toMatch(/SECONDLY/);
	});

	it('rejects BYHOUR, BYMINUTE, BYSECOND, and BYEASTER (case-insensitive, with or without RRULE:)', () => {
		expect(validateRrule('FREQ=DAILY;BYHOUR=9')).toMatch(/BYHOUR/);
		expect(validateRrule('RRULE:BYHOUR=9;FREQ=DAILY')).toMatch(/BYHOUR/);
		expect(validateRrule('rrule:BYHOUR=9;FREQ=DAILY')).toMatch(/BYHOUR/);
		expect(validateRrule('FREQ=DAILY;byminute=15')).toMatch(/BYMINUTE/);
		expect(validateRrule('FREQ=DAILY;BYSECOND=30')).toMatch(/BYSECOND/);
		expect(validateRrule('FREQ=YEARLY;byeaster=1')).toMatch(/BYEASTER/);
	});
});

// Adapted from https://github.com/jkbrzt/rrule, commit 9f2061febeeb, test/rrule.test.ts.
// BSD-3-style license. See sql/tests/THIRD_PARTY-calendar_rrule_vectors.md.
// Copyright 2010, Jakub Roztocil <jakub@roztocil.name> and Lars Schöning
// rrule.ts only builds and parses RRULE strings; occurrence semantics are covered by sql/tests/calendar_rrule_vectors.pg.
describe('rrule.js rule strings: build/parse round-trip', () => {
	const cases: {
		name: string;
		rule: string;
		parts: Parameters<typeof buildRrule>[0];
	}[] = [
		{
			name: 'testBefore',
			rule: 'FREQ=DAILY',
			parts: { freq: 'DAILY', interval: 1, end: { type: 'never' } }
		},
		{
			name: 'testDaily',
			rule: 'FREQ=DAILY;COUNT=3',
			parts: { freq: 'DAILY', interval: 1, end: { type: 'count', count: 3 } }
		},
		{
			name: 'testDailyInterval',
			rule: 'FREQ=DAILY;INTERVAL=2;COUNT=3',
			parts: { freq: 'DAILY', interval: 2, end: { type: 'count', count: 3 } }
		},
		{
			name: 'testDailyIntervalLarge',
			rule: 'FREQ=DAILY;INTERVAL=92;COUNT=3',
			parts: { freq: 'DAILY', interval: 92, end: { type: 'count', count: 3 } }
		},
		{
			name: 'testWeekly',
			rule: 'FREQ=WEEKLY;COUNT=3',
			parts: { freq: 'WEEKLY', interval: 1, end: { type: 'count', count: 3 } }
		},
		{
			name: 'testWeeklyInterval',
			rule: 'FREQ=WEEKLY;INTERVAL=2;COUNT=3',
			parts: { freq: 'WEEKLY', interval: 2, end: { type: 'count', count: 3 } }
		},
		{
			name: 'testWeeklyByWeekDay',
			rule: 'FREQ=WEEKLY;BYDAY=TU,TH;COUNT=3',
			parts: { freq: 'WEEKLY', interval: 1, byDay: ['TU', 'TH'], end: { type: 'count', count: 3 } }
		},
		{
			name: 'testMonthly',
			rule: 'FREQ=MONTHLY;COUNT=3',
			parts: { freq: 'MONTHLY', interval: 1, end: { type: 'count', count: 3 } }
		},
		{
			name: 'testMonthlyIntervalLarge',
			rule: 'FREQ=MONTHLY;INTERVAL=18;COUNT=3',
			parts: { freq: 'MONTHLY', interval: 18, end: { type: 'count', count: 3 } }
		},
		{
			name: 'testMonthlyByNWeekDay',
			rule: 'FREQ=MONTHLY;BYDAY=1TU,-1TH;COUNT=3',
			parts: {
				freq: 'MONTHLY',
				interval: 1,
				byDay: ['1TU', '-1TH'],
				end: { type: 'count', count: 3 }
			}
		},
		{
			name: 'testYearly',
			rule: 'FREQ=YEARLY;COUNT=3',
			parts: { freq: 'YEARLY', interval: 1, end: { type: 'count', count: 3 } }
		},
		{
			name: 'testYearlyIntervalLarge',
			rule: 'FREQ=YEARLY;INTERVAL=100;COUNT=3',
			parts: { freq: 'YEARLY', interval: 100, end: { type: 'count', count: 3 } }
		},
		{
			name: 'testYearlyByNWeekDay',
			rule: 'FREQ=YEARLY;BYDAY=1TU,-1TH;COUNT=3',
			parts: {
				freq: 'YEARLY',
				interval: 1,
				byDay: ['1TU', '-1TH'],
				end: { type: 'count', count: 3 }
			}
		}
	];

	it.each(cases)('$name', ({ rule, parts }) => {
		expect(parseRrule(rule)).toEqual(parts);

		const rebuilt = buildRrule(parts);
		expect(rebuilt).toBe(rule);
		expect(parseRrule(rebuilt)).toEqual(parts);
	});
});
