import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent, screen } from '@testing-library/svelte/svelte5';
import { createRawSnippet } from 'svelte';
import Button from './Button.svelte';

const label = (text: string) =>
	createRawSnippet(() => ({ render: () => `<span>${text}</span>` }));

describe('Button', () => {
	it('renders children inside a native button', () => {
		render(Button, { props: { children: label('Save changes') } });
		const btn = screen.getByRole('button', { name: 'Save changes' });
		expect(btn.tagName).toBe('BUTTON');
	});

	it('defaults to primary md with type=button', () => {
		render(Button, { props: { children: label('Save changes') } });
		const btn = screen.getByRole('button');
		expect(btn.classList.contains('sj-btn--primary')).toBe(true);
		expect(btn.classList.contains('sj-btn--md')).toBe(true);
		expect(btn).toHaveAttribute('type', 'button');
	});

	it('applies variant and size classes', () => {
		render(Button, {
			props: { variant: 'danger', size: 'lg', children: label('Delete domain') }
		});
		const btn = screen.getByRole('button');
		expect(btn.classList.contains('sj-btn--danger')).toBe(true);
		expect(btn.classList.contains('sj-btn--lg')).toBe(true);
		expect(btn.classList.contains('sj-btn--primary')).toBe(false);
	});

	it('calls onclick when clicked', async () => {
		const onclick = vi.fn();
		render(Button, { props: { onclick, children: label('Save changes') } });
		await fireEvent.click(screen.getByRole('button'));
		expect(onclick).toHaveBeenCalledTimes(1);
	});

	it('does not call onclick when disabled', async () => {
		const onclick = vi.fn();
		render(Button, { props: { onclick, disabled: true, children: label('Save changes') } });
		const btn = screen.getByRole('button');
		expect(btn).toBeDisabled();
		await fireEvent.click(btn);
		expect(onclick).not.toHaveBeenCalled();
	});

	it('renders the icon snippet before the label', () => {
		const icon = createRawSnippet(() => ({ render: () => `<svg data-icon="archive"></svg>` }));
		const { container } = render(Button, { props: { icon, children: label('Archive') } });
		const span = container.querySelector('.sj-btn__icon');
		expect(span).not.toBeNull();
		expect(span!.querySelector('svg')).not.toBeNull();
	});
});
