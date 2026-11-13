import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import AppearancePage from './+page.svelte';

function stubMatchMedia(matches: boolean) {
	vi.stubGlobal(
		'matchMedia',
		vi.fn().mockReturnValue({
			matches,
			addEventListener: vi.fn(),
			removeEventListener: vi.fn()
		})
	);
}

beforeEach(() => {
	localStorage.clear();
	delete document.documentElement.dataset.theme;
	delete document.documentElement.dataset.density;
	document.documentElement.classList.remove('dark', 'light');
	stubMatchMedia(false);
});

describe('appearance settings — theme', () => {
	it('Dark sets data-theme="dark", persists, and never uses classes', async () => {
		render(AppearancePage);
		await fireEvent.click(screen.getByText('Dark'));
		expect(document.documentElement.dataset.theme).toBe('dark');
		expect(localStorage.getItem('sj-theme')).toBe('dark');
		expect(document.documentElement.classList.contains('dark')).toBe(false);
		expect(document.documentElement.classList.contains('light')).toBe(false);
	});

	it('Light removes data-theme and persists', async () => {
		document.documentElement.dataset.theme = 'dark';
		render(AppearancePage);
		await fireEvent.click(screen.getByText('Light'));
		expect(document.documentElement.dataset.theme).toBeUndefined();
		expect(localStorage.getItem('sj-theme')).toBe('light');
	});

	it('System resolves via matchMedia — dark OS gives data-theme="dark"', async () => {
		stubMatchMedia(true);
		render(AppearancePage);
		await fireEvent.click(screen.getByText('System'));
		expect(document.documentElement.dataset.theme).toBe('dark');
		expect(localStorage.getItem('sj-theme')).toBe('system');
	});

	it('System with light OS removes data-theme', async () => {
		document.documentElement.dataset.theme = 'dark';
		stubMatchMedia(false);
		render(AppearancePage);
		await fireEvent.click(screen.getByText('System'));
		expect(document.documentElement.dataset.theme).toBeUndefined();
	});
});

describe('appearance settings — structural (Task 9)', () => {
	it('renders three theme buttons with data-value attributes', () => {
		const { container } = render(AppearancePage);
		const themeButtons = container.querySelectorAll('button[data-value]');
		expect(themeButtons.length).toBeGreaterThanOrEqual(3);
		const values = Array.from(themeButtons).map((b) => b.getAttribute('data-value'));
		expect(values).toContain('system');
		expect(values).toContain('dark');
		expect(values).toContain('light');
	});

	it('has no glass-pane class anywhere', () => {
		const { container } = render(AppearancePage);
		expect(container.querySelectorAll('.glass-pane').length).toBe(0);
	});

	it('has no glass-modal class anywhere', () => {
		const { container } = render(AppearancePage);
		expect(container.querySelectorAll('.glass-modal').length).toBe(0);
	});
});

describe('appearance settings — density', () => {
	it('Compact sets data-density="compact" and persists', async () => {
		render(AppearancePage);
		await fireEvent.click(screen.getByText('Compact'));
		expect(document.documentElement.dataset.density).toBe('compact');
		expect(localStorage.getItem('density')).toBe('compact');
	});

	it('Comfortable removes data-density and persists', async () => {
		document.documentElement.dataset.density = 'compact';
		render(AppearancePage);
		await fireEvent.click(screen.getByText('Comfortable'));
		expect(document.documentElement.dataset.density).toBeUndefined();
		expect(localStorage.getItem('density')).toBe('comfortable');
	});
});
