import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/svelte/svelte5';
import GlobalDrawer from './GlobalDrawer.svelte';
import type { AppId } from '$lib/types/jmap';
import type { AdminConsoleId } from '$lib/nav/navConfig';
import { user } from '$lib/stores/auth';

const ALL_APPS: AppId[] = ['mail', 'calendar', 'contacts', 'tasks'];

const defaultProps = {
	open: true,
	enabledApps: ALL_APPS,
	activeApp: 'mail',
	adminConsoles: [] as AdminConsoleId[],
	theme: 'light' as const,
	userName: 'Alice Smith',
	userEmail: 'user@example.com',
	onNavigate: vi.fn(),
	onSignOut: vi.fn(),
	onClose: vi.fn(),
};

describe('GlobalDrawer', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		user.set(null);
	});

	afterEach(() => {
		vi.clearAllMocks();
		user.set(null);
	});

	it('renders nothing when open=false', () => {
		const { container } = render(GlobalDrawer, { ...defaultProps, open: false });
		const backdrop = container.querySelector('.sj-drawer-backdrop');
		const drawer = container.querySelector('.sj-drawer');
		expect(backdrop).toBeNull();
		expect(drawer).toBeNull();
	});

	it('renders backdrop and drawer when open=true', () => {
		const { container } = render(GlobalDrawer, { ...defaultProps, open: true });
		const backdrop = container.querySelector('.sj-drawer-backdrop');
		const drawer = container.querySelector('.sj-drawer');
		expect(backdrop).toBeTruthy();
		expect(drawer).toBeTruthy();
	});

	it('drawer has role="dialog" and aria-modal="true"', () => {
		const { container } = render(GlobalDrawer, { ...defaultProps, open: true });
		const drawer = container.querySelector('.sj-drawer');
		expect(drawer).toBeTruthy();
		expect(drawer!.getAttribute('role')).toBe('dialog');
		expect(drawer!.getAttribute('aria-modal')).toBe('true');
	});

	it('backdrop click calls onClose', async () => {
		const onClose = vi.fn();
		const { container } = render(GlobalDrawer, { ...defaultProps, open: true, onClose });
		const backdrop = container.querySelector('.sj-drawer-backdrop');
		expect(backdrop).toBeTruthy();
		await fireEvent.click(backdrop!);
		expect(onClose).toHaveBeenCalledOnce();
	});

	it('Escape key on document calls onClose', async () => {
		const onClose = vi.fn();
		render(GlobalDrawer, { ...defaultProps, open: true, onClose });
		await fireEvent.keyDown(document, { key: 'Escape' });
		expect(onClose).toHaveBeenCalledOnce();
	});

	it('renders app rows for each id in enabledApps', () => {
		const { container } = render(GlobalDrawer, {
			...defaultProps,
			open: true,
			enabledApps: ['mail', 'tasks'] as AppId[],
		});
		// Should have rows for mail and tasks, not calendar or contacts
		const allBtns = Array.from(container.querySelectorAll('.sj-drawer-row'));
		const labels = allBtns.map((b) => b.textContent?.trim());
		const hasMailRow = labels.some((l) => l?.includes('Mail'));
		const hasTasksRow = labels.some((l) => l?.includes('Tasks'));
		const hasCalRow = labels.some((l) => l?.includes('Calendar'));
		const hasContactsRow = labels.some((l) => l?.includes('Contacts'));
		expect(hasMailRow).toBe(true);
		expect(hasTasksRow).toBe(true);
		expect(hasCalRow).toBe(false);
		expect(hasContactsRow).toBe(false);
	});

	it('projects a guest drawer to enabled Chat and Meet, theme, and sign-out only', () => {
		user.set({ email: 'pat@example.com', isAdmin: false, hasMailbox: false, accountType: 'guest' });
		render(GlobalDrawer, {
			...defaultProps,
			enabledApps: ['mail', 'calendar', 'chat', 'drive', 'meet'] as AppId[],
			adminConsoles: ['mail'] as AdminConsoleId[],
			onToggleTheme: vi.fn(),
		});
		expect(screen.getByRole('button', { name: 'Chat' })).toBeInTheDocument();
		expect(screen.getByRole('button', { name: 'Meet' })).toBeInTheDocument();
		expect(screen.getByRole('button', { name: 'Dark mode' })).toBeInTheDocument();
		expect(screen.getByRole('button', { name: 'Sign out' })).toBeInTheDocument();
		expect(screen.queryByRole('button', { name: 'Mail' })).not.toBeInTheDocument();
		expect(screen.queryByRole('button', { name: 'Drive' })).not.toBeInTheDocument();
		expect(screen.queryByRole('button', { name: 'Settings' })).not.toBeInTheDocument();
		expect(screen.queryByRole('button', { name: 'Mail admin' })).not.toBeInTheDocument();
	});

	it('active app row has aria-current="page"', () => {
		const { container } = render(GlobalDrawer, {
			...defaultProps,
			open: true,
			activeApp: 'mail',
		});
		const mailRow = Array.from(container.querySelectorAll('.sj-drawer-row')).find(
			(btn) => btn.getAttribute('aria-current') === 'page'
		);
		expect(mailRow).toBeTruthy();
		expect(mailRow!.textContent?.trim()).toContain('Mail');
	});

	it('non-active app row does not have aria-current="page"', () => {
		const { container } = render(GlobalDrawer, {
			...defaultProps,
			open: true,
			activeApp: 'mail',
		});
		const calRow = Array.from(container.querySelectorAll('.sj-drawer-row')).find((btn) =>
			btn.textContent?.includes('Calendar')
		);
		expect(calRow).toBeTruthy();
		expect(calRow!.getAttribute('aria-current')).toBeNull();
	});

	it('renders admin rows when adminConsoles is non-empty', () => {
		const { container } = render(GlobalDrawer, {
			...defaultProps,
			open: true,
			adminConsoles: ['mail', 'auth'] as AdminConsoleId[],
		});
		const allBtns = Array.from(container.querySelectorAll('.sj-drawer-row'));
		const labels = allBtns.map((b) => b.textContent?.trim());
		const hasAdminMail = labels.some((l) => l?.includes('Mail admin'));
		const hasAdminAuth = labels.some((l) => l?.includes('Auth admin'));
		expect(hasAdminMail).toBe(true);
		expect(hasAdminAuth).toBe(true);
	});

	it('does not render admin rows when adminConsoles is empty', () => {
		const { container } = render(GlobalDrawer, {
			...defaultProps,
			open: true,
			adminConsoles: [],
		});
		const allBtns = Array.from(container.querySelectorAll('.sj-drawer-row'));
		const labels = allBtns.map((b) => b.textContent?.trim());
		const hasAdminMail = labels.some((l) => l?.includes('Mail admin'));
		expect(hasAdminMail).toBe(false);
	});

	it('renders theme row when onToggleTheme is provided', () => {
		const onToggleTheme = vi.fn();
		const { container } = render(GlobalDrawer, {
			...defaultProps,
			open: true,
			theme: 'light',
			onToggleTheme,
		});
		const allBtns = Array.from(container.querySelectorAll('.sj-drawer-row'));
		const labels = allBtns.map((b) => b.textContent?.trim());
		const hasThemeRow = labels.some((l) => l?.includes('Dark mode') || l?.includes('Light mode'));
		expect(hasThemeRow).toBe(true);
	});

	it('does not render theme row when onToggleTheme is not provided', () => {
		const { container } = render(GlobalDrawer, {
			...defaultProps,
			open: true,
			onToggleTheme: undefined,
		});
		const allBtns = Array.from(container.querySelectorAll('.sj-drawer-row'));
		const labels = allBtns.map((b) => b.textContent?.trim());
		const hasThemeRow = labels.some((l) => l?.includes('Dark mode') || l?.includes('Light mode'));
		expect(hasThemeRow).toBe(false);
	});

	it('sign-out row always renders', () => {
		const { container } = render(GlobalDrawer, { ...defaultProps, open: true });
		const allBtns = Array.from(container.querySelectorAll('.sj-drawer-row'));
		const labels = allBtns.map((b) => b.textContent?.trim());
		const hasSignOut = labels.some((l) => l?.includes('Sign out'));
		expect(hasSignOut).toBe(true);
	});

	it('user email footer renders with userEmail', () => {
		const { container } = render(GlobalDrawer, {
			...defaultProps,
			open: true,
			userEmail: 'user@example.com',
		});
		const footer = container.querySelector('.sj-drawer-footer');
		expect(footer).toBeTruthy();
		expect(footer!.textContent?.trim()).toBe('user@example.com');
	});

	// Focus trap tests
	it('drawer panel has tabindex="-1" when open', () => {
		const { container } = render(GlobalDrawer, { ...defaultProps, open: true });
		const drawer = container.querySelector('.sj-drawer');
		expect(drawer).toBeTruthy();
		expect(drawer!.getAttribute('tabindex')).toBe('-1');
	});

	it('Tab key traps focus within drawer — wraps from last to first focusable', async () => {
		const { container } = render(GlobalDrawer, { ...defaultProps, open: true });
		const drawer = container.querySelector('.sj-drawer') as HTMLElement;
		expect(drawer).toBeTruthy();

		// Get all focusable buttons in the drawer
		const focusables = Array.from(
			drawer.querySelectorAll<HTMLElement>('button:not([disabled])')
		);
		expect(focusables.length).toBeGreaterThan(0);

		// Focus the last focusable element, then Tab — should wrap to first
		const last = focusables[focusables.length - 1];
		last.focus();
		expect(document.activeElement).toBe(last);

		// Dispatch Tab from document — our keydown handler should prevent default and move to first
		await fireEvent.keyDown(document, { key: 'Tab', shiftKey: false });

		// After Tab from last element, focus should be on first focusable
		expect(document.activeElement).toBe(focusables[0]);
	});

	it('Shift+Tab traps focus within drawer — wraps from first to last focusable', async () => {
		const { container } = render(GlobalDrawer, { ...defaultProps, open: true });
		const drawer = container.querySelector('.sj-drawer') as HTMLElement;
		expect(drawer).toBeTruthy();

		const focusables = Array.from(
			drawer.querySelectorAll<HTMLElement>('button:not([disabled])')
		);
		expect(focusables.length).toBeGreaterThan(0);

		// Focus the first focusable element, then Shift+Tab — should wrap to last
		const first = focusables[0];
		first.focus();
		expect(document.activeElement).toBe(first);

		await fireEvent.keyDown(document, { key: 'Tab', shiftKey: true });

		// After Shift+Tab from first element, focus should be on last focusable
		expect(document.activeElement).toBe(focusables[focusables.length - 1]);
	});

	it('drawer panel receives focus on open (auto-focus)', () => {
		const { container } = render(GlobalDrawer, { ...defaultProps, open: true });
		const drawer = container.querySelector('.sj-drawer') as HTMLElement;
		expect(drawer).toBeTruthy();
		// After mounting with open=true, the drawer itself should have focus
		// (or a focusable child — the $effect calls drawer.focus())
		expect(document.activeElement).toBe(drawer);
	});
});
