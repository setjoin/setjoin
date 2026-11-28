import { describe, it, expect } from 'vitest';
import { bytesForWindow, fitWindowToSpace, formatBytes, type SizeEstimate } from './sizeFit';

const est: SizeEstimate = {
	buckets: [
		{ window: '7d', messageCount: 10, bodyBytes: 1_000_000 },
		{ window: '30d', messageCount: 40, bodyBytes: 5_000_000 },
		{ window: '90d', messageCount: 100, bodyBytes: 20_000_000 },
		{ window: '180d', messageCount: 200, bodyBytes: 50_000_000 },
		{ window: '365d', messageCount: 400, bodyBytes: 120_000_000 },
		{ window: 'all', messageCount: 600, bodyBytes: 300_000_000 }
	]
};

describe('sizeFit', () => {
	it('reads cumulative bytes for a window', () => {
		expect(bytesForWindow(est, '30d')).toBe(5_000_000);
		expect(bytesForWindow(est, 'all')).toBe(300_000_000);
	});
	it('returns 0 for a window missing from the estimate', () => {
		expect(bytesForWindow({ buckets: [] }, '30d')).toBe(0);
	});
	it('fits the largest window that stays under free space', () => {
		// 60 MB free → 180d (50 MB) fits, 365d (120 MB) does not.
		expect(fitWindowToSpace(est, 60_000_000)).toBe('180d');
	});
	it('falls back to 7d when even the smallest window overflows', () => {
		expect(fitWindowToSpace(est, 500_000)).toBe('7d');
	});
	it('formats bytes human-readably', () => {
		expect(formatBytes(5_000_000)).toBe('4.8 MB');
		expect(formatBytes(1024)).toBe('1.0 KB');
		expect(formatBytes(1024 ** 3)).toBe('1.0 GB');
		expect(formatBytes(1024 ** 5)).toBe('1.0 PB');
		expect(formatBytes(0)).toBe('0 B');
	});
	it('formatBytes returns 0 B for NaN', () => {
		expect(formatBytes(NaN)).toBe('0 B');
	});
	it('fitWindowToSpace skips windows absent from the estimate (sparse bucket list)', () => {
		// Only '7d' is present — 'all' is absent so the missing-bucket guard must not
		// return 'all' (which would expand to 0 bytes and always "fit").
		const sparse: SizeEstimate = {
			buckets: [{ window: '7d', messageCount: 5, bodyBytes: 500_000 }]
		};
		// 10 MB free: only '7d' is present + fits → must return '7d', not a larger absent window.
		expect(fitWindowToSpace(sparse, 10_000_000)).toBe('7d');
	});
});
