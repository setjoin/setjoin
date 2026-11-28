import { describe, it, expect } from 'vitest';
import { safeColor, localDayKey } from './format';

describe('safeColor — CSS-injection guard', () => {
	it('passes valid #hex colors through unchanged', () => {
		expect(safeColor('#4A90D9')).toBe('#4A90D9');
		expect(safeColor('#abc')).toBe('#abc');
		expect(safeColor('#11223344')).toBe('#11223344');
		expect(safeColor('  #fff  ')).toBe('#fff');
	});

	it('rejects a CSS-injection payload and falls back to the token', () => {
		expect(safeColor('red;position:fixed;inset:0;width:100vw;height:100vh')).toBe('var(--app-calendar)');
		expect(safeColor('url(https://evil.example/pixel.png)')).toBe('var(--app-calendar)');
		expect(safeColor('#fff;background:url(//evil)')).toBe('var(--app-calendar)');
	});

	it('rejects non-hex names and empty/nullish values', () => {
		expect(safeColor('red')).toBe('var(--app-calendar)');
		expect(safeColor('')).toBe('var(--app-calendar)');
		expect(safeColor(undefined)).toBe('var(--app-calendar)');
		expect(safeColor(null)).toBe('var(--app-calendar)');
	});
});

describe('localDayKey — timezone-stable day key', () => {
	it('uses local date parts, not the UTC slice', () => {
		// An evening event in a negative-UTC-offset zone whose UTC time has rolled
		// to the next day must still key to the LOCAL day.
		const d = new Date(2026, 5, 15, 22, 30); // local 2026-06-15 22:30
		expect(localDayKey(d)).toBe('2026-06-15');
	});

	it('zero-pads month and day', () => {
		expect(localDayKey(new Date(2026, 0, 3))).toBe('2026-01-03');
	});
});
