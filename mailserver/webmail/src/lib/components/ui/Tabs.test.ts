// mailserver/webmail/src/lib/components/ui/Tabs.test.ts
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import Tabs from './Tabs.svelte';

const items = [
	{ id: 'rules', label: 'Rules', count: 4 },
	{ id: 'history', label: 'History', count: 0 },
	{ id: 'settings', label: 'Settings' }
];

describe('Tabs', () => {
	it('renders a tablist with one tab per item', () => {
		render(Tabs, { items, active: 'rules' });
		expect(screen.getByRole('tablist')).toBeInTheDocument();
		expect(screen.getAllByRole('tab')).toHaveLength(3);
	});

	it('marks only the active tab as selected', () => {
		render(Tabs, { items, active: 'history' });
		const tabs = screen.getAllByRole('tab');
		expect(tabs[0]).toHaveAttribute('aria-selected', 'false');
		expect(tabs[1]).toHaveAttribute('aria-selected', 'true');
		expect(tabs[2]).toHaveAttribute('aria-selected', 'false');
	});

	it('applies the active class to the active tab only', () => {
		render(Tabs, { items, active: 'rules' });
		const tabs = screen.getAllByRole('tab');
		expect(tabs[0].className).toContain('tab--active');
		expect(tabs[1].className).not.toContain('tab--active');
	});

	it('shows a count pill for numeric counts, including 0', () => {
		render(Tabs, { items, active: 'rules' });
		expect(screen.getByText('4')).toBeInTheDocument();
		expect(screen.getByText('0')).toBeInTheDocument();
	});

	it('omits the count pill when count is not provided', () => {
		render(Tabs, { items, active: 'rules' });
		const settings = screen.getByRole('tab', { name: 'Settings' });
		expect(settings.querySelector('.tab__count')).toBeNull();
	});

	it('calls onChange with the tab id on click', async () => {
		const onChange = vi.fn();
		render(Tabs, { items, active: 'rules', onChange });
		await fireEvent.click(screen.getByRole('tab', { name: /History/ }));
		expect(onChange).toHaveBeenCalledTimes(1);
		expect(onChange).toHaveBeenCalledWith('history');
	});

	it('does not throw when onChange is omitted', async () => {
		render(Tabs, { items, active: 'rules' });
		await fireEvent.click(screen.getByRole('tab', { name: /History/ }));
		expect(screen.getByRole('tablist')).toBeInTheDocument();
	});
});
