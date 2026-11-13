import { describe, it, expect } from 'vitest';
import { computeReorderSortOrder } from './tasks';

// QoL #20: the drag/reorder fractional-key math, unit-tested without DragEvents.
describe('computeReorderSortOrder', () => {
	it('returns the midpoint between two neighbours', () => {
		expect(computeReorderSortOrder(2, 4)).toBe(3);
		expect(computeReorderSortOrder(1, 2)).toBe(1.5);
	});

	it('drops at the top (only a next neighbour) → next - 1', () => {
		expect(computeReorderSortOrder(undefined, 5)).toBe(4);
	});

	it('drops at the bottom (only a prev neighbour) → prev + 1', () => {
		expect(computeReorderSortOrder(3, undefined)).toBe(4);
	});

	it('empty list (no neighbours) → 0', () => {
		expect(computeReorderSortOrder(undefined, undefined)).toBe(0);
	});

	it('preserves strict ordering after a midpoint insert', () => {
		const mid = computeReorderSortOrder(1, 2);
		expect(mid).toBeGreaterThan(1);
		expect(mid).toBeLessThan(2);
	});
});
