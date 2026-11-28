import { describe, it, expect, vi } from 'vitest';
import { render, fireEvent, screen } from '@testing-library/svelte/svelte5';
import { createRawSnippet } from 'svelte';
import IconButton from './IconButton.svelte';

const icon = createRawSnippet(() => ({ render: () => `<svg data-icon="archive"></svg>` }));

describe('IconButton', () => {
	it('exposes label as accessible name and tooltip', () => {
		render(IconButton, { props: { label: 'Archive', children: icon } });
		const btn = screen.getByRole('button', { name: 'Archive' });
		expect(btn).toHaveAttribute('aria-label', 'Archive');
		expect(btn).toHaveAttribute('title', 'Archive');
		expect(btn).toHaveAttribute('type', 'button');
	});

	it('allows the tooltip to differ without changing the accessible name', () => {
		render(IconButton, {
			props: { label: 'Compose', tooltip: 'Read-only mailbox', children: icon }
		});
		const btn = screen.getByRole('button', { name: 'Compose' });
		expect(btn).toHaveAttribute('aria-label', 'Compose');
		expect(btn).toHaveAttribute('title', 'Read-only mailbox');
	});

	it('defaults to ghost md', () => {
		render(IconButton, { props: { label: 'Archive', children: icon } });
		const btn = screen.getByRole('button');
		expect(btn.classList.contains('sj-iconbtn--md')).toBe(true);
		expect(btn.classList.contains('sj-iconbtn--outline')).toBe(false);
		expect(btn.classList.contains('sj-iconbtn--active')).toBe(false);
	});

	it('applies outline variant, sm size, and active state', () => {
		render(IconButton, {
			props: { label: 'Snooze', variant: 'outline', size: 'sm', active: true, children: icon }
		});
		const btn = screen.getByRole('button');
		expect(btn.classList.contains('sj-iconbtn--outline')).toBe(true);
		expect(btn.classList.contains('sj-iconbtn--sm')).toBe(true);
		expect(btn.classList.contains('sj-iconbtn--active')).toBe(true);
	});

	it('renders the icon snippet', () => {
		const { container } = render(IconButton, { props: { label: 'Archive', children: icon } });
		expect(container.querySelector('svg[data-icon="archive"]')).not.toBeNull();
	});

	it('calls onclick when clicked and not when disabled', async () => {
		const onclick = vi.fn();
		const first = render(IconButton, { props: { label: 'Archive', onclick, children: icon } });
		await fireEvent.click(first.getByRole('button'));
		expect(onclick).toHaveBeenCalledTimes(1);
		first.unmount();

		const onclickDisabled = vi.fn();
		const second = render(IconButton, {
			props: { label: 'Archive', onclick: onclickDisabled, disabled: true, children: icon }
		});
		const btn = second.getByRole('button');
		expect(btn).toBeDisabled();
		await fireEvent.click(btn);
		expect(onclickDisabled).not.toHaveBeenCalled();
	});
});
