import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte/svelte5';
import Spinner from './Spinner.svelte';

describe('Spinner', () => {
	it('renders a status element with default size 20 and default label', () => {
		render(Spinner);
		const el = screen.getByRole('status');
		expect(el.getAttribute('aria-label')).toBe('Loading');
		expect(el.classList.contains('sj-spinner--20')).toBe(true);
	});

	it('applies the requested size class', () => {
		render(Spinner, { size: 28 });
		expect(screen.getByRole('status').classList.contains('sj-spinner--28')).toBe(true);
	});

	it('accepts a custom label', () => {
		render(Spinner, { label: 'Sending' });
		expect(screen.getByRole('status').getAttribute('aria-label')).toBe('Sending');
	});
});
