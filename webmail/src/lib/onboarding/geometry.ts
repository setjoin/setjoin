export type CoachmarkPlacement = 'top' | 'bottom' | 'left' | 'right';

export interface RectLike {
	top: number;
	right: number;
	bottom: number;
	left: number;
	width: number;
	height: number;
}

export interface Size {
	width: number;
	height: number;
}

export interface ViewportRect {
	top: number;
	left: number;
	width: number;
	height: number;
}

export interface CoachmarkPosition {
	placement: CoachmarkPlacement;
	top: number;
	left: number;
}

const DEFAULT_ORDER: CoachmarkPlacement[] = ['bottom', 'top', 'right', 'left'];

function clamp(value: number, min: number, max: number): number {
	return Math.max(min, Math.min(value, max));
}

function candidate(
	placement: CoachmarkPlacement,
	target: RectLike,
	card: Size,
	gap: number,
): { top: number; left: number } {
	switch (placement) {
		case 'top':
			return {
				top: target.top - gap - card.height,
				left: target.left + target.width / 2 - card.width / 2,
			};
		case 'left':
			return {
				top: target.top + target.height / 2 - card.height / 2,
				left: target.left - gap - card.width,
			};
		case 'right':
			return {
				top: target.top + target.height / 2 - card.height / 2,
				left: target.right + gap,
			};
		default:
			return {
				top: target.bottom + gap,
				left: target.left + target.width / 2 - card.width / 2,
			};
	}
}

function overflowArea(
	top: number,
	left: number,
	card: Size,
	viewport: ViewportRect,
	margin: number,
): number {
	const minLeft = viewport.left + margin;
	const minTop = viewport.top + margin;
	const maxRight = viewport.left + viewport.width - margin;
	const maxBottom = viewport.top + viewport.height - margin;
	const overflowX = Math.max(0, minLeft - left) + Math.max(0, left + card.width - maxRight);
	const overflowY = Math.max(0, minTop - top) + Math.max(0, top + card.height - maxBottom);
	return overflowX * card.height + overflowY * card.width;
}

function availableDepth(
	placement: CoachmarkPlacement,
	target: RectLike,
	viewport: ViewportRect,
	margin: number,
): number {
	switch (placement) {
		case 'top':
			return target.top - (viewport.top + margin);
		case 'left':
			return target.left - (viewport.left + margin);
		case 'right':
			return viewport.left + viewport.width - margin - target.right;
		default:
			return viewport.top + viewport.height - margin - target.bottom;
	}
}

/**
 * Choose the side with the most usable visual-viewport space, then clamp the
 * card to the viewport. The gap keeps the final card from covering its target.
 */
export function positionCoachmark(
	target: RectLike,
	card: Size,
	viewport: ViewportRect,
	options: {
		preferred?: CoachmarkPlacement;
		allowed?: CoachmarkPlacement[];
		gap?: number;
		margin?: number;
	} = {},
): CoachmarkPosition {
	const gap = options.gap ?? 14;
	const margin = options.margin ?? 8;
	const allowed = options.allowed ?? DEFAULT_ORDER;
	const ordered = options.preferred
		? [options.preferred, ...allowed.filter((side) => side !== options.preferred)]
		: allowed;

	let best = ordered[0] ?? 'bottom';
	let bestScore = Number.NEGATIVE_INFINITY;
	for (const placement of ordered) {
		const pos = candidate(placement, target, card, gap);
		const depth = availableDepth(placement, target, viewport, margin);
		const overflow = overflowArea(pos.top, pos.left, card, viewport, margin);
		const score = depth * 1000 - overflow;
		if (score > bestScore) {
			best = placement;
			bestScore = score;
		}
	}

	const raw = candidate(best, target, card, gap);
	const minLeft = viewport.left + margin;
	const minTop = viewport.top + margin;
	const maxLeft = Math.max(minLeft, viewport.left + viewport.width - card.width - margin);
	const maxTop = Math.max(minTop, viewport.top + viewport.height - card.height - margin);
	return {
		placement: best,
		left: clamp(raw.left, minLeft, maxLeft),
		top: clamp(raw.top, minTop, maxTop),
	};
}

export function visualViewportRect(
	viewport: Pick<VisualViewport, 'offsetLeft' | 'offsetTop' | 'width' | 'height'> | null | undefined,
	fallback: { width: number; height: number },
): ViewportRect {
	return viewport
		? {
				left: viewport.offsetLeft,
				top: viewport.offsetTop,
				width: viewport.width,
				height: viewport.height,
			}
		: { left: 0, top: 0, width: fallback.width, height: fallback.height };
}

export function isEditableElement(value: Element | null): boolean {
	if (!(value instanceof HTMLElement)) return false;
	return value.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(value.tagName);
}

export function isSoftwareKeyboardOpen(input: {
	layoutHeight: number;
	visualHeight: number;
	editableFocused: boolean;
}): boolean {
	if (!input.editableFocused || input.layoutHeight <= 0) return false;
	const lost = input.layoutHeight - input.visualHeight;
	return lost >= 160 && input.visualHeight / input.layoutHeight <= 0.78;
}
