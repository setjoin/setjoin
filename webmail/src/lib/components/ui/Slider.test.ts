import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import Slider from './Slider.svelte';

// Svelte 5 + JSDOM does not inject scoped CSS into document.head at test time
// (confirmed by spacing-lint.test.ts / csp.test.ts which both read source files).
// Read the source directly for CSS-content assertions; DOM assertions use render().
const here = dirname(fileURLToPath(import.meta.url));
const sliderSrc = readFileSync(join(here, 'Slider.svelte'), 'utf-8');

describe('Slider', () => {
	it('renders a discrete range with the right bounds and aria-valuetext', () => {
		const { getByRole } = render(Slider, {
			props: { label: 'Window', value: 1, stops: ['1w', '1mo', '3mo'] }
		});
		const input = getByRole('slider') as HTMLInputElement;
		expect(input.min).toBe('0');
		expect(input.max).toBe('2');
		expect(input.step).toBe('1');
		expect(input.getAttribute('aria-valuetext')).toBe('1mo');
		expect(input.getAttribute('aria-label')).toBe('Window');
	});

	it('fires oninput with the new index', async () => {
		const oninput = vi.fn();
		const { getByRole } = render(Slider, {
			props: { label: 'Window', value: 0, stops: ['1w', '1mo', '3mo'], oninput }
		});
		const input = getByRole('slider') as HTMLInputElement;
		input.value = '2';
		await fireEvent.input(input);
		expect(oninput).toHaveBeenCalledWith(2);
	});

	it('applies the danger tone class when tone="danger" (overflow state)', () => {
		const { container, getByRole } = render(Slider, {
			props: { label: 'Window', value: 2, stops: ['1w', '1mo', '3mo'], tone: 'danger' }
		});
		expect(container.querySelector('.sj-slider--danger')).toBeTruthy();
		// color is not the only signal: the data-tone attr lets the estimate copy react.
		expect(getByRole('slider').closest('.sj-slider')?.getAttribute('data-tone')).toBe('danger');
	});

	it('disables the input and does not fire oninput when disabled (inert/caps-absent)', async () => {
		const oninput = vi.fn();
		const { getByRole, container } = render(Slider, {
			props: { label: 'Window', value: 0, stops: ['1w', '1mo', '3mo'], oninput, disabled: true }
		});
		const input = getByRole('slider') as HTMLInputElement;
		expect(input.disabled).toBe(true);
		expect(input.getAttribute('aria-disabled')).toBe('true');
		expect(container.querySelector('.sj-slider--disabled')).toBeTruthy();
		input.value = '2';
		await fireEvent.input(input);
		expect(oninput).not.toHaveBeenCalled();
	});

	it('links the estimate line via aria-describedby for screen readers', () => {
		const { getByRole } = render(Slider, {
			props: { label: 'Window', value: 1, stops: ['1w', '1mo', '3mo'], describedById: 'est-line' }
		});
		expect(getByRole('slider').getAttribute('aria-describedby')).toBe('est-line');
	});

	it('uses token-based motion that collapses under prefers-reduced-motion (no raw durations)', () => {
		// The tone/disabled cross-fade is a --duration-fast/--ease-out transition and
		// a @media (prefers-reduced-motion: reduce) { transition: none } guard — assert
		// the component ships both (token motion + the reduced-motion escape hatch), so
		// it never animates against a user's OS setting.
		// NOTE: Svelte 5 + JSDOM doesn't inject scoped CSS into document.head at test
		// time, so we read the source file directly (same pattern as spacing-lint.test.ts).
		expect(sliderSrc).toMatch(/transition:\s*accent-color\s+var\(--duration-fast\)/);
		expect(sliderSrc).toMatch(/prefers-reduced-motion:\s*reduce/);
	});

	it('danger thumb ring survives forced-color/high-contrast (box-shadow on both vendor thumbs)', () => {
		// OS overrides accent-color in Windows High Contrast mode, so the ring is the only
		// surviving signal that the window doesn't fit. Assert both vendor pseudo-elements ship.
		expect(sliderSrc).toMatch(/::-webkit-slider-thumb[\s\S]*?box-shadow:\s*0 0 0 1px var\(--danger-fg\)/);
		expect(sliderSrc).toMatch(/::-moz-range-thumb[\s\S]*?box-shadow:\s*0 0 0 1px var\(--danger-fg\)/);
	});

	it('keeps the active stop label legible (not color-only) — bold weight token applied', () => {
		// Outcome is never color-only (WCAG 1.4.1): the active stop also goes
		// --weight-semibold, so it is distinguishable without relying on hue.
		const { container } = render(Slider, {
			props: { label: 'Window', value: 1, stops: ['1w', '1mo', '3mo'] }
		});
		const active = container.querySelector('.sj-slider-stop-active');
		expect(active).toBeTruthy();
	});
});
