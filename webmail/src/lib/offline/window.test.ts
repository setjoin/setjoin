import { describe, it, expect } from 'vitest';
import { OFFLINE_WINDOWS, DEFAULT_OFFLINE_WINDOW, windowDays, windowLabelKey, cutoffMillis } from './window';

describe('offline window enum', () => {
	it('lists the six windows in ascending order', () => {
		expect(OFFLINE_WINDOWS).toEqual(['7d', '30d', '90d', '180d', '365d', 'all']);
	});
	it('defaults to 30d', () => {
		expect(DEFAULT_OFFLINE_WINDOW).toBe('30d');
	});
	it('maps windows to days, all → null', () => {
		expect(windowDays('7d')).toBe(7);
		expect(windowDays('365d')).toBe(365);
		expect(windowDays('all')).toBeNull();
	});
	it('exposes an i18n label key per window', () => {
		expect(windowLabelKey('30d')).toBe('settings.storage.window.30d');
	});
	it('cutoffMillis returns null for all, and now-N*86400000 for a day window', () => {
		expect(cutoffMillis('all', 1_000_000)).toBeNull();
		const now = Date.now();
		expect(cutoffMillis('7d', now)).toBe(now - 7 * 86_400_000);
	});
});
