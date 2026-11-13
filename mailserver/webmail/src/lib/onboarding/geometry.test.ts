import { describe, expect, it } from 'vitest';
import {
	isSoftwareKeyboardOpen,
	positionCoachmark,
	visualViewportRect,
	type RectLike,
} from './geometry';

const target: RectLike = {
	top: 300,
	right: 460,
	bottom: 340,
	left: 360,
	width: 100,
	height: 40,
};
const card = { width: 300, height: 180 };
const viewport = { top: 0, left: 0, width: 1024, height: 768 };

describe('positionCoachmark', () => {
	it('uses the preferred side when it fits', () => {
		expect(positionCoachmark(target, card, viewport, { preferred: 'right' })).toMatchObject({
			placement: 'right',
			left: 474,
		});
	});

	it('chooses a side with more usable area when the preferred side overflows', () => {
		const edge = { ...target, left: 920, right: 1000 };
		expect(positionCoachmark(edge, card, viewport, { preferred: 'right' }).placement).toBe('left');
	});

	it('clamps the card inside an offset visual viewport', () => {
		const result = positionCoachmark(
			{ ...target, top: 12, bottom: 52, left: 110, right: 210 },
			card,
			{ top: 80, left: 40, width: 390, height: 500 },
			{ preferred: 'top' },
		);
		expect(result.left).toBeGreaterThanOrEqual(48);
		expect(result.top).toBeGreaterThanOrEqual(88);
		expect(result.left + card.width).toBeLessThanOrEqual(422);
		expect(result.top + card.height).toBeLessThanOrEqual(572);
	});

	it('keeps the card separated from the target', () => {
		const result = positionCoachmark(target, card, viewport, { preferred: 'bottom', gap: 14 });
		if (result.placement === 'bottom') expect(result.top).toBeGreaterThanOrEqual(target.bottom + 14);
		if (result.placement === 'top') expect(result.top + card.height).toBeLessThanOrEqual(target.top - 14);
		if (result.placement === 'left') expect(result.left + card.width).toBeLessThanOrEqual(target.left - 14);
		if (result.placement === 'right') expect(result.left).toBeGreaterThanOrEqual(target.right + 14);
	});
});

describe('visualViewportRect', () => {
	it('uses offsets from the visual viewport', () => {
		expect(
			visualViewportRect(
				{ offsetLeft: 11, offsetTop: 22, width: 333, height: 444 } as VisualViewport,
				{ width: 1000, height: 800 },
			),
		).toEqual({ left: 11, top: 22, width: 333, height: 444 });
	});

	it('falls back to the layout viewport', () => {
		expect(visualViewportRect(undefined, { width: 1000, height: 800 })).toEqual({
			left: 0,
			top: 0,
			width: 1000,
			height: 800,
		});
	});
});

describe('isSoftwareKeyboardOpen', () => {
	it('requires a focused editable control and a substantial viewport loss', () => {
		expect(isSoftwareKeyboardOpen({ layoutHeight: 800, visualHeight: 500, editableFocused: true })).toBe(true);
		expect(isSoftwareKeyboardOpen({ layoutHeight: 800, visualHeight: 700, editableFocused: true })).toBe(false);
		expect(isSoftwareKeyboardOpen({ layoutHeight: 800, visualHeight: 500, editableFocused: false })).toBe(false);
	});
});
