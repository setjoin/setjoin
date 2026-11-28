import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte/svelte5';
import Progress from './Progress.svelte';

describe('Progress', () => {
	it('exposes progressbar semantics', () => {
		render(Progress, { value: 40, label: 'Upload progress' });
		const bar = screen.getByRole('progressbar');
		expect(bar.getAttribute('aria-valuemin')).toBe('0');
		expect(bar.getAttribute('aria-valuemax')).toBe('100');
		expect(bar.getAttribute('aria-valuenow')).toBe('40');
		expect(bar.getAttribute('aria-label')).toBe('Upload progress');
	});

	it('sets the fill width from value', () => {
		const { container } = render(Progress, { value: 40, label: 'Upload progress' });
		const fill = container.querySelector('.sj-progress__fill') as HTMLElement;
		expect(fill.style.width).toBe('40%');
	});

	it('clamps values above max', () => {
		render(Progress, { value: 150, label: 'x' });
		expect(screen.getByRole('progressbar').getAttribute('aria-valuenow')).toBe('100');
	});

	it('clamps negative values to zero', () => {
		render(Progress, { value: -5, label: 'x' });
		expect(screen.getByRole('progressbar').getAttribute('aria-valuenow')).toBe('0');
	});

	it('respects a custom max', () => {
		render(Progress, { value: 30, max: 60, label: 'x' });
		const bar = screen.getByRole('progressbar');
		expect(bar.getAttribute('aria-valuemax')).toBe('60');
		expect(bar.getAttribute('aria-valuenow')).toBe('30');
	});
});
