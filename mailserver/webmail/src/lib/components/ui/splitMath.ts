// mailserver/webmail/src/lib/components/ui/splitMath.ts
/**
 * Pure geometry for the SplitPane/Resizer primitives (S8).
 *
 * Model: a container `total` px wide holds pane A, a divider, and pane B.
 * `usable = total - dividerWidth` is divided between the panes.
 * The persisted value is `ratio = a / usable` in (0, 1), so window resizes
 * re-layout both panes proportionally. When `usable < minA + minB`, the
 * layout is "collapsed": pane A takes the full container and pane B gets 0
 * (the caller keeps pane B mounted but hidden — keep-alive).
 */

/** Arrow-key resize step in px (spec S8). */
export const KEYBOARD_STEP_PX = 16;

/** Layout width of the divider hairline in px (its 6px hit area overhangs). */
export const DIVIDER_PX = 1;

export interface PaneConstraints {
	/** Container width in px, divider included. */
	total: number;
	/** Minimum pane A width in px. */
	minA: number;
	/** Minimum pane B width in px. */
	minB: number;
	/** Optional maximum pane A width in px. */
	maxA?: number;
	/** Optional maximum pane B width in px. */
	maxB?: number;
	/** Divider layout width in px; defaults to DIVIDER_PX. */
	dividerWidth?: number;
}

export interface SplitInput extends PaneConstraints {
	/** Pane A share of the usable width, 0..1. */
	ratio: number;
}

export interface PaneLimits {
	min: number;
	max: number;
	usable: number;
}

export interface SplitResult {
	a: number;
	b: number;
	collapsed: boolean;
}

export function clamp(value: number, min: number, max: number): number {
	if (max < min) return min; // over-constrained: min wins
	if (value < min) return min;
	if (value > max) return max;
	return value;
}

/** Pane A's legal [min, max] range plus the usable width. */
export function paneLimits(c: PaneConstraints): PaneLimits {
	const usable = c.total - (c.dividerWidth ?? DIVIDER_PX);
	const min = Math.max(c.minA, c.maxB != null ? usable - c.maxB : c.minA);
	const max = Math.min(c.maxA ?? usable - c.minB, usable - c.minB);
	return { min, max, usable };
}

/** Resolve a stored ratio into concrete pane sizes, or a collapsed layout. */
export function resolveSplit(input: SplitInput): SplitResult {
	const { min, max, usable } = paneLimits(input);
	if (usable < input.minA + input.minB) {
		return { a: Math.max(input.total, 0), b: 0, collapsed: true };
	}
	const a = clamp(Math.round(input.ratio * usable), min, max);
	return { a, b: usable - a, collapsed: false };
}

/** Keyboard resize: current size plus a (signed) step, clamped. */
export function stepSize(current: number, delta: number, min: number, max: number): number {
	return clamp(current + delta, min, max);
}

/** Pointer resize: size at drag start plus pointer travel, clamped. */
export function dragSize(
	startSize: number,
	startX: number,
	currentX: number,
	min: number,
	max: number
): number {
	return clamp(startSize + (currentX - startX), min, max);
}

/** Pane A share for persistence; 0.5 fallback guards divide-by-zero. */
export function ratioFor(a: number, usable: number): number {
	if (usable <= 0) return 0.5;
	return clamp(a / usable, 0, 1);
}
