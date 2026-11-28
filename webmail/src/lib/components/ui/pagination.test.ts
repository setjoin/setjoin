import { describe, it, expect } from 'vitest';
import { formatRange, pageCount } from './pagination';

describe('formatRange', () => {
	it('formats a full first page', () => {
		expect(formatRange(1, 50, 1283)).toBe('1–50 of 1,283');
	});

	it('formats a partial last page with locale separators', () => {
		expect(formatRange(26, 50, 1283)).toBe('1,251–1,283 of 1,283');
	});

	it('caps the end at the total', () => {
		expect(formatRange(1, 50, 30)).toBe('1–30 of 30');
	});

	it('handles an empty result set', () => {
		expect(formatRange(1, 50, 0)).toBe('0 of 0');
	});
});

describe('pageCount', () => {
	it('rounds up and never returns less than 1', () => {
		expect(pageCount(1283, 50)).toBe(26);
		expect(pageCount(100, 50)).toBe(2);
		expect(pageCount(101, 50)).toBe(3);
		expect(pageCount(0, 50)).toBe(1);
		expect(pageCount(10, 0)).toBe(1);
	});
});
