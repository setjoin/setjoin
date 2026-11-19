import { describe, it, expect } from 'vitest';
import { buildRrule, parseRrule } from './rrule';

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
});

// Adapted from https://github.com/jkbrzt/rrule, commit 9f2061febeeb, test/rrule.test.ts.
// BSD-3-style license. See mailserver/sql/tests/THIRD_PARTY-calendar_rrule_vectors.md.
// Copyright 2010, Jakub Roztocil <jakub@roztocil.name> and Lars Schöning
// rrule.ts only builds and parses RRULE strings; occurrence semantics are covered by mailserver/sql/tests/calendar_rrule_vectors.pg.
describe('rrule.js rule strings: build/parse round-trip', () => {
	const cases: {
		name: string;
		rule: string;
		parts: Parameters<typeof buildRrule>[0];
		canonicalRule?: string;
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
		},
		// The date-only editor composes UNTIL at midnight UTC.
		{
			name: 'daily UNTIL date from the upstream DST case',
			rule: 'UNTIL=20181106T110000Z;FREQ=DAILY',
			parts: { freq: 'DAILY', interval: 1, end: { type: 'until', until: '2018-11-06' } },
			canonicalRule: 'FREQ=DAILY;UNTIL=20181106T000000Z'
		},
		{
			name: 'weekly UNTIL date from the upstream DST case',
			rule: 'FREQ=WEEKLY;UNTIL=20181115T050000Z',
			parts: { freq: 'WEEKLY', interval: 1, end: { type: 'until', until: '2018-11-15' } },
			canonicalRule: 'FREQ=WEEKLY;UNTIL=20181115T000000Z'
		}
	];

	it.each(cases)('$name', ({ rule, parts, canonicalRule }) => {
		expect(parseRrule(rule)).toEqual(parts);

		const rebuilt = buildRrule(parts);
		expect(rebuilt).toBe(canonicalRule ?? rule);
		expect(parseRrule(rebuilt)).toEqual(parts);
	});
});
