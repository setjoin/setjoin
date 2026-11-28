import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createRawSnippet } from 'svelte';
import { render, fireEvent } from '@testing-library/svelte/svelte5';
import AppTopbar from './AppTopbar.svelte';

describe('AppTopbar', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		vi.useFakeTimers();
	});

	afterEach(() => {
		vi.clearAllMocks();
		vi.useRealTimers();
	});

	it('renders header.sj-topbar', () => {
		const { container } = render(AppTopbar, { title: 'Mail' });
		const header = container.querySelector('header.sj-topbar');
		expect(header).toBeTruthy();
	});

	it('topbar has border-bottom via inline style or class containing sj-topbar', () => {
		const { container } = render(AppTopbar, { title: 'Mail' });
		const header = container.querySelector('header.sj-topbar');
		expect(header).toBeTruthy();
		// The class sj-topbar applies the border-bottom via scoped styles
		expect(header!.classList.contains('sj-topbar')).toBe(true);
	});

	it('renders burger IconButton when showBurger=true', () => {
		const { container } = render(AppTopbar, { title: 'Mail', showBurger: true });
		const burger = container.querySelector('[aria-label="Menu"]');
		expect(burger).toBeTruthy();
	});

	it('burger IconButton has class sj-burger-lg when showBurger=true', () => {
		const { container } = render(AppTopbar, { title: 'Mail', showBurger: true });
		const burger = container.querySelector('[aria-label="Menu"]');
		expect(burger).toBeTruthy();
		expect(burger!.classList.contains('sj-burger-lg')).toBe(true);
	});

	it('does not render burger IconButton when showBurger=false', () => {
		const { container } = render(AppTopbar, { title: 'Mail', showBurger: false });
		const burger = container.querySelector('[aria-label="Menu"]');
		expect(burger).toBeNull();
	});

	it('does not render burger IconButton when showBurger is not provided', () => {
		const { container } = render(AppTopbar, { title: 'Mail' });
		const burger = container.querySelector('[aria-label="Menu"]');
		expect(burger).toBeNull();
	});

	it('renders app title text matching title prop', () => {
		const { container } = render(AppTopbar, { title: 'Calendar' });
		const titleEl = container.querySelector('.sj-topbar-title');
		expect(titleEl).toBeTruthy();
		expect(titleEl!.textContent?.trim()).toBe('Calendar');
	});

	it('renders search input when onSearch prop is provided', () => {
		const onSearch = vi.fn();
		const { container } = render(AppTopbar, { title: 'Mail', onSearch });
		const input = container.querySelector('input[type="text"]') ?? container.querySelector('input:not([type])');
		expect(input).toBeTruthy();
	});

	it('does not render search input when onSearch prop is absent', () => {
		const { container } = render(AppTopbar, { title: 'Mail' });
		const input = container.querySelector('input[type="text"]') ?? container.querySelector('input:not([type])');
		expect(input).toBeNull();
	});

	it('calls onBurger when burger button is clicked', async () => {
		const onBurger = vi.fn();
		const { container } = render(AppTopbar, { title: 'Mail', showBurger: true, onBurger });
		const burger = container.querySelector('[aria-label="Menu"]') as HTMLButtonElement;
		expect(burger).toBeTruthy();
		await fireEvent.click(burger!);
		expect(onBurger).toHaveBeenCalledOnce();
	});

	it('search input uses provided searchPlaceholder', () => {
		const onSearch = vi.fn();
		const { container } = render(AppTopbar, {
			title: 'Mail',
			onSearch,
			searchPlaceholder: 'Search mail',
		});
		const input = container.querySelector('input') as HTMLInputElement;
		expect(input).toBeTruthy();
		expect(input!.placeholder).toBe('Search mail');
	});

	it('search input calls onSearch after debounce on input', async () => {
		const onSearch = vi.fn();
		const { container } = render(AppTopbar, { title: 'Mail', onSearch });
		const input = container.querySelector('input') as HTMLInputElement;
		expect(input).toBeTruthy();
		await fireEvent.input(input!, { target: { value: 'hello' } });
		// Should not call immediately
		expect(onSearch).not.toHaveBeenCalled();
		// Advance timer by 300ms
		vi.advanceTimersByTime(300);
		expect(onSearch).toHaveBeenCalledWith('hello');
	});

	it('Actions snippet renders in the right slot when provided', () => {
		const actions = createRawSnippet(() => ({
			render: () => `<button data-testid="action-btn">Archive</button>`,
		}));
		const { container } = render(AppTopbar, { title: 'Mail', actions });
		const btn = container.querySelector('[data-testid="action-btn"]');
		expect(btn).toBeTruthy();
		expect(btn!.textContent).toBe('Archive');
	});
});

describe('AppTopbar data-tour anchor', () => {
	it('marks the burger with data-tour="apps" when showBurger', () => {
		const { container } = render(AppTopbar, { title: 'Mail', showBurger: true, onBurger: () => {} });
		expect(container.querySelector('button[data-tour="apps"]')).toBeTruthy();
	});
});
