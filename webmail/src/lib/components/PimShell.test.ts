import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/svelte/svelte5';
import { createRawSnippet } from 'svelte';
import PimShell from './PimShell.svelte';

const snippet = (text: string) =>
	createRawSnippet(() => ({ render: () => `<div>${text}</div>` }));

describe('PimShell', () => {
	it('renders the root element with data-pim-shell attribute', () => {
		render(PimShell, {
			props: {
				title: 'Calendar',
				sidebar: snippet('sidebar content'),
				main: snippet('main content')
			}
		});
		const root = screen.getByText('Calendar').closest('[data-pim-shell]');
		expect(root).not.toBeNull();
		expect(root!.tagName).toBe('DIV');
	});

	it('renders a topbar containing the title text', () => {
		render(PimShell, {
			props: {
				title: 'Calendar',
				sidebar: snippet('sidebar content'),
				main: snippet('main content')
			}
		});
		const topbar = screen.getByText('Calendar').closest('.pim-topbar');
		expect(topbar).not.toBeNull();
		expect(topbar!.querySelector('.pim-topbar__title')?.textContent).toBe('Calendar');
	});

	it('renders sidebar and main sections', () => {
		render(PimShell, {
			props: {
				title: 'Calendar',
				sidebar: snippet('sidebar content'),
				main: snippet('main content')
			}
		});
		const sidebar = screen.getByText('sidebar content');
		expect(sidebar.closest('.pim-sidebar')).not.toBeNull();
		const main = screen.getByText('main content');
		expect(main.closest('.pim-main')).not.toBeNull();
	});

	it('renders topbar actions when provided', () => {
		render(PimShell, {
			props: {
				title: 'Calendar',
				sidebar: snippet('sidebar content'),
				main: snippet('main content'),
				topbarActions: snippet('actions content')
			}
		});
		const actions = screen.getByText('actions content');
		expect(actions.closest('.pim-topbar__actions')).not.toBeNull();
	});

	it('does not render topbar actions container when not provided', () => {
		const { container } = render(PimShell, {
			props: {
				title: 'Calendar',
				sidebar: snippet('sidebar content'),
				main: snippet('main content')
			}
		});
		expect(container.querySelector('.pim-topbar__actions')).toBeNull();
	});

	it('has container-type inline-size on the root', () => {
		const { container } = render(PimShell, {
			props: {
				title: 'Calendar',
				sidebar: snippet('sidebar content'),
				main: snippet('main content')
			}
		});
		const root = container.querySelector('[data-pim-shell]');
		expect(root).not.toBeNull();
		expect(root!.getAttribute('style')).toContain('container-type: inline-size');
	});
});
