import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte/svelte5';
import Badge from './Badge.svelte';

describe('Badge', () => {
	it('renders the label', () => {
		render(Badge, { label: 'Active' });
		expect(screen.getByText('Active')).toBeTruthy();
	});

	it('applies the variant token colors inline', () => {
		render(Badge, { label: 'Active', variant: 'success' });
		const el = screen.getByText('Active');
		expect(el.getAttribute('style')).toContain('var(--success-bg)');
		expect(el.getAttribute('style')).toContain('var(--success-fg)');
	});

	it('defaults to the neutral variant', () => {
		render(Badge, { label: 'Pending' });
		expect(screen.getByText('Pending').getAttribute('style')).toContain('var(--gray-100)');
	});

	it('renders the status dot only when dot is set', () => {
		const { container } = render(Badge, { label: 'Locked', variant: 'danger', dot: true });
		const dotEl = container.querySelector('.badge__dot');
		expect(dotEl).not.toBeNull();
		expect(dotEl?.getAttribute('style')).toContain('var(--danger-solid)');
	});

	it('renders no dot by default', () => {
		const { container } = render(Badge, { label: 'Locked' });
		expect(container.querySelector('.badge__dot')).toBeNull();
	});

	it('renders count mode as a count pill', () => {
		render(Badge, { count: 24 });
		const el = screen.getByText('24');
		expect(el.classList.contains('badge--count')).toBe(true);
	});

	it('caps count display at 99+', () => {
		render(Badge, { count: 100 });
		expect(screen.getByText('99+')).toBeTruthy();
	});

	it('shows 99 without overflow at exactly 99', () => {
		render(Badge, { count: 99 });
		expect(screen.getByText('99')).toBeTruthy();
	});
});
