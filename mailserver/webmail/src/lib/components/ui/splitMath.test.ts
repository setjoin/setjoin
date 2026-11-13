// mailserver/webmail/src/lib/components/ui/splitMath.test.ts
import { describe, it, expect } from 'vitest';
import {
	KEYBOARD_STEP_PX,
	DIVIDER_PX,
	clamp,
	paneLimits,
	resolveSplit,
	stepSize,
	dragSize,
	ratioFor
} from './splitMath';

describe('constants', () => {
	it('exports the kit constants', () => {
		expect(KEYBOARD_STEP_PX).toBe(16);
		expect(DIVIDER_PX).toBe(1);
	});
});

describe('clamp', () => {
	it('passes through in-range values', () => {
		expect(clamp(5, 0, 10)).toBe(5);
	});
	it('clamps below', () => {
		expect(clamp(-3, 0, 10)).toBe(0);
	});
	it('clamps above', () => {
		expect(clamp(42, 0, 10)).toBe(10);
	});
	it('returns min when the range is inverted (over-constrained)', () => {
		expect(clamp(5, 8, 2)).toBe(8);
	});
});

describe('paneLimits', () => {
	it('derives usable width and min/max for pane A', () => {
		expect(paneLimits({ total: 1000, minA: 200, minB: 360 })).toEqual({
			min: 200,
			max: 639, // 999 usable - 360 minB
			usable: 999
		});
	});
	it('caps max at maxA when given', () => {
		expect(paneLimits({ total: 1000, minA: 200, minB: 360, maxA: 320 }).max).toBe(320);
	});
	it('raises min when maxB constrains pane B', () => {
		// pane B may not exceed 600, so pane A must be at least 999 - 600 = 399
		expect(paneLimits({ total: 1000, minA: 200, minB: 360, maxB: 600 }).min).toBe(399);
	});
	it('honors a custom divider width', () => {
		expect(paneLimits({ total: 1000, minA: 200, minB: 360, dividerWidth: 7 }).usable).toBe(993);
	});
});

describe('resolveSplit', () => {
	it('splits by ratio when unconstrained', () => {
		expect(resolveSplit({ total: 1000, ratio: 0.3, minA: 200, minB: 360 })).toEqual({
			a: 300, // round(0.3 * 999) = 300
			b: 699,
			collapsed: false
		});
	});
	it('clamps a tiny ratio up to minA', () => {
		expect(resolveSplit({ total: 1000, ratio: 0.05, minA: 200, minB: 360 })).toEqual({
			a: 200, // round(0.05 * 999) = 50 → clamped to 200
			b: 799,
			collapsed: false
		});
	});
	it('clamps a huge ratio down to preserve minB', () => {
		expect(resolveSplit({ total: 1000, ratio: 0.95, minA: 200, minB: 360 })).toEqual({
			a: 639, // round(0.95 * 999) = 949 → clamped to 999 - 360
			b: 360,
			collapsed: false
		});
	});
	it('respects maxA', () => {
		expect(resolveSplit({ total: 1000, ratio: 0.5, minA: 200, minB: 280, maxA: 320 })).toEqual({
			a: 320, // round(0.5 * 999) = 500 → capped at maxA
			b: 679,
			collapsed: false
		});
	});
	it('respects maxB by raising pane A', () => {
		expect(resolveSplit({ total: 1000, ratio: 0.2, minA: 200, minB: 360, maxB: 600 })).toEqual({
			a: 399, // round(0.2 * 999) = 200 → raised so b ≤ 600
			b: 600,
			collapsed: false
		});
	});
	it('handles an exact-fit container', () => {
		// usable = 680 = 360 + 320: exactly one legal layout
		expect(resolveSplit({ total: 681, ratio: 0.5, minA: 360, minB: 320 })).toEqual({
			a: 360,
			b: 320,
			collapsed: false
		});
	});
	it('collapses when both minimums cannot fit', () => {
		// usable = 599 < 360 + 320 = 680
		expect(resolveSplit({ total: 600, ratio: 0.5, minA: 360, minB: 320 })).toEqual({
			a: 600, // pane A takes the whole container
			b: 0,
			collapsed: true
		});
	});
	it('collapses (without negative sizes) for an unmeasured 0-width container', () => {
		expect(resolveSplit({ total: 0, ratio: 0.5, minA: 200, minB: 200 })).toEqual({
			a: 0,
			b: 0,
			collapsed: true
		});
	});
});

describe('stepSize', () => {
	it('steps by the delta', () => {
		expect(stepSize(300, 16, 200, 639)).toBe(316);
	});
	it('clamps at min', () => {
		expect(stepSize(208, -16, 200, 639)).toBe(200);
	});
	it('clamps at max', () => {
		expect(stepSize(632, 16, 200, 639)).toBe(639);
	});
});

describe('dragSize', () => {
	it('offsets the start size by pointer travel', () => {
		expect(dragSize(300, 500, 572, 200, 639)).toBe(372);
	});
	it('clamps a leftward overshoot at min', () => {
		expect(dragSize(300, 500, 150, 200, 639)).toBe(200);
	});
	it('works with a zero start coordinate (delta-style input)', () => {
		expect(dragSize(300, 0, 50, 200, 639)).toBe(350);
	});
});

describe('ratioFor', () => {
	it('computes the proportional share', () => {
		expect(ratioFor(300, 999)).toBeCloseTo(0.3003, 4);
	});
	it('clamps to [0, 1]', () => {
		expect(ratioFor(-5, 999)).toBe(0);
		expect(ratioFor(1500, 999)).toBe(1);
	});
	it('falls back to 0.5 for a non-positive usable width', () => {
		expect(ratioFor(300, 0)).toBe(0.5);
		expect(ratioFor(300, -5)).toBe(0.5);
	});
});
