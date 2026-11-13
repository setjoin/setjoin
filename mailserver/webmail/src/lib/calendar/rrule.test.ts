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
