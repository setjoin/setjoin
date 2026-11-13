// Welcome-tour step configuration + DOM target resolution.
// Pure data + small DOM helpers; no Svelte runes here.

export interface TourStep {
	id: 'apps' | 'compose' | 'search' | 'organize';
	/** Stable semantic selector. Responsive variants intentionally share it. */
	target: string;
	placement: 'top' | 'bottom' | 'left' | 'right';
	titleKey: string;
	bodyKey: string;
	hintKey?: string;
	forwardKey?: string;
}

export const TOUR_STEPS: TourStep[] = [
	{ id: 'apps', target: '[data-tour="apps"]', placement: 'right', titleKey: 'onboarding.apps.title', bodyKey: 'onboarding.apps.body' },
	{ id: 'compose', target: '[data-tour="compose"]', placement: 'right', titleKey: 'onboarding.compose.title', bodyKey: 'onboarding.compose.body', hintKey: 'onboarding.compose.hint', forwardKey: 'onboarding.next_instead' },
	{ id: 'search', target: '[data-tour="search"]', placement: 'bottom', titleKey: 'onboarding.search.title', bodyKey: 'onboarding.search.body', hintKey: 'onboarding.search.hint' },
	{ id: 'organize', target: '[data-tour="organize"]', placement: 'left', titleKey: 'onboarding.organize.title', bodyKey: 'onboarding.organize.body' },
];

function isVisible(el: HTMLElement): boolean {
	// Non-zero box AND (in real browsers) checkVisibility — catches collapsed-but-
	// sized / visibility:hidden / content-visibility containers per spec §4.4.
	// In jsdom `checkVisibility` is undefined → `?? true` falls back to the rect
	// check, so unit tests still pass. The desktop rail is hidden via display:none
	// (→ 0×0 rect) below the shell breakpoint, so the burger's [data-tour="apps"]
	// wins on narrow viewports; document order returns the visible one in the
	// rail+burger overlap band (≈768–1024px).
	const r = el.getBoundingClientRect();
	const disabled =
		(el instanceof HTMLButtonElement ||
			el instanceof HTMLInputElement ||
			el instanceof HTMLSelectElement ||
			el instanceof HTMLTextAreaElement) &&
		el.disabled;
	const hiddenFromUsers =
		el.hidden ||
		el.getAttribute('aria-hidden') === 'true' ||
		el.closest('[aria-hidden="true"], [hidden]') !== null;
	return (
		!disabled &&
		!hiddenFromUsers &&
		r.width > 0 &&
		r.height > 0 &&
		(el.checkVisibility?.() ?? true)
	);
}

/** First *visible* element matching the selector (so rail vs burger resolves by viewport). */
export function resolveTarget(selector: string, doc: Document = document): HTMLElement | null {
	const els = Array.from(doc.querySelectorAll<HTMLElement>(selector));
	return els.find(isVisible) ?? null;
}

/** TOUR_STEPS minus any step whose actionable anchor is absent/hidden right now. */
export function resolveVisibleSteps(doc: Document = document): TourStep[] {
	return TOUR_STEPS.filter((s) => resolveTarget(s.target, doc) !== null);
}
