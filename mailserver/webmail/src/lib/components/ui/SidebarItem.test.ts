// mailserver/webmail/src/lib/components/ui/SidebarItem.test.ts
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import { createRawSnippet } from 'svelte';
import SidebarItem from './SidebarItem.svelte';

describe('SidebarItem', () => {
	it('renders a button row with the label', () => {
		render(SidebarItem, { label: 'Inbox' });
		expect(screen.getByRole('button', { name: 'Inbox' })).toBeInTheDocument();
	});

	it('defaults to 8px left padding at depth 0', () => {
		render(SidebarItem, { label: 'Inbox' });
		expect(screen.getByRole('button').style.paddingLeft).toBe('8px');
	});

	it('indents by 8 + depth * 16 px', () => {
		render(SidebarItem, { label: 'Nested tag', depth: 2 });
		expect(screen.getByRole('button').style.paddingLeft).toBe('40px');
	});

	it('shows the count when positive', () => {
		render(SidebarItem, { label: 'Inbox', count: 12 });
		expect(screen.getByText('12')).toBeInTheDocument();
	});

	it('hides the count when 0', () => {
		render(SidebarItem, { label: 'Inbox', count: 0 });
		expect(screen.queryByText('0')).toBeNull();
	});

	it('hides the count when null', () => {
		render(SidebarItem, { label: 'Inbox', count: null });
		expect(screen.getByRole('button').querySelector('.sbitem__count')).toBeNull();
	});

	it('marks the active row with the active class and aria-current', () => {
		render(SidebarItem, { label: 'Inbox', active: true });
		const btn = screen.getByRole('button');
		expect(btn.className).toContain('sbitem--active');
		expect(btn).toHaveAttribute('aria-current', 'true');
	});

	it('omits aria-current when inactive', () => {
		render(SidebarItem, { label: 'Inbox' });
		expect(screen.getByRole('button')).not.toHaveAttribute('aria-current');
	});

	it('renders a tag-hue dot when dotColor is set', () => {
		render(SidebarItem, { label: 'Finance', dotColor: 'rose' });
		const dot = screen.getByRole('button').querySelector('.sbitem__dot');
		expect(dot).not.toBeNull();
		expect(dot?.getAttribute('style')).toContain('var(--tag-rose-dot)');
	});

	it('renders an icon snippet when no dotColor is set', () => {
		const icon = createRawSnippet(() => ({
			render: () => '<svg data-testid="custom-icon"></svg>'
		}));
		render(SidebarItem, { label: 'Inbox', icon });
		expect(screen.getByTestId('custom-icon')).toBeInTheDocument();
	});

	it('calls onclick when clicked', async () => {
		const onclick = vi.fn();
		render(SidebarItem, { label: 'Inbox', onclick });
		await fireEvent.click(screen.getByRole('button'));
		expect(onclick).toHaveBeenCalledTimes(1);
	});
});
