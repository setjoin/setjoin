import { describe, it, expect, beforeEach, vi } from 'vitest';
import { TOUR_STEPS, resolveTarget, resolveVisibleSteps } from './steps';

function makeVisible() {
	// jsdom returns a 0-size rect by default; force a non-zero box.
	Element.prototype.getBoundingClientRect = vi.fn(
		() => ({ x: 10, y: 10, top: 10, left: 10, right: 110, bottom: 50, width: 100, height: 40, toJSON() {} }) as DOMRect,
	);
}

describe('steps', () => {
	beforeEach(() => {
		document.body.innerHTML = '';
		makeVisible();
	});

	it('TOUR_STEPS has the four expected anchored ids in order', () => {
		expect(TOUR_STEPS.map((s) => s.id)).toEqual(['apps', 'compose', 'search', 'organize']);
	});

	it('resolveTarget returns the first visible match, null when absent', () => {
		expect(resolveTarget('[data-tour="apps"]')).toBeNull();
		const el = document.createElement('div');
		el.setAttribute('data-tour', 'apps');
		document.body.appendChild(el);
		expect(resolveTarget('[data-tour="apps"]')).toBe(el);
	});

	it('resolveVisibleSteps keeps present targets and drops absent ones', () => {
		for (const id of ['apps', 'compose', 'search']) {
			const el = document.createElement('div');
			el.setAttribute('data-tour', id);
			document.body.appendChild(el);
		}
		// 'organize' is absent (empty inbox).
		const ids = resolveVisibleSteps().map((s) => s.id);
		expect(ids).toEqual(['apps', 'compose', 'search']);
	});

	it('rejects disabled and aria-hidden targets as non-actionable', () => {
		const disabled = document.createElement('button');
		disabled.dataset.tour = 'compose';
		disabled.disabled = true;
		document.body.appendChild(disabled);
		const hidden = document.createElement('div');
		hidden.setAttribute('aria-hidden', 'true');
		const nested = document.createElement('button');
		nested.dataset.tour = 'search';
		hidden.appendChild(nested);
		document.body.appendChild(hidden);

		expect(resolveTarget('[data-tour="compose"]')).toBeNull();
		expect(resolveTarget('[data-tour="search"]')).toBeNull();
	});
});
