import { describe, it, expect } from 'vitest';
import { formatMessage } from './icu';

// Regression: `#` inside a plural clause is ICU shorthand for the formatted
// count and must be substituted — found while wiring U3's 'inbox.trackers_blocked'
// (the placeholder was rendering literally as "#" for every existing
// {count, plural, ...} string in the app).
describe('formatMessage plural `#` substitution', () => {
	it('substitutes # with the count in the "other" clause', () => {
		expect(formatMessage('{count, plural, one{# tracker blocked} other{# trackers blocked}}', { count: 3 }))
			.toBe('3 trackers blocked');
	});

	it('substitutes # with the count in the "one" clause', () => {
		expect(formatMessage('{count, plural, one{# tracker blocked} other{# trackers blocked}}', { count: 1 }))
			.toBe('1 tracker blocked');
	});

	it('substitutes # in an exact-match (=0) clause', () => {
		expect(formatMessage('{count, plural, =0{no items} one{# item} other{# items}}', { count: 0 }))
			.toBe('no items');
		expect(formatMessage('{count, plural, =0{no items} one{# item} other{# items}}', { count: 5 }))
			.toBe('5 items');
	});
});
