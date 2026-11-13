import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen } from '@testing-library/svelte/svelte5';
import AppRail from './AppRail.svelte';
import type { AppId } from '$lib/types/jmap';
import type { AdminConsoleId } from '$lib/nav/navConfig';
import { user } from '$lib/stores/auth';

// All four enabled apps (default test case)
const ALL_APPS: AppId[] = ['mail', 'calendar', 'contacts', 'tasks'];

// Minimal default props
const defaultProps = {
	enabledApps: ALL_APPS,
	activeApp: 'mail',
	adminConsoles: [] as AdminConsoleId[],
	theme: 'light' as const,
	userName: 'Alice Smith',
	userEmail: 'user@example.com',
	onNavigate: vi.fn(),
	onSignOut: vi.fn(),
};

describe('AppRail', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		user.set(null);
	});

	afterEach(() => {
		vi.clearAllMocks();
		user.set(null);
	});

	it('renders nav.sj-rail with aria-label="Main navigation"', () => {
		const { container } = render(AppRail, defaultProps);
		const nav = container.querySelector('nav.sj-rail');
		expect(nav).toBeTruthy();
		expect(nav!.getAttribute('aria-label')).toBe('Main navigation');
	});

	it('renders logomark img with class="sj-ink", alt="SetJoin", width="26", height="26"', () => {
		const { container } = render(AppRail, defaultProps);
		const img = container.querySelector('img.sj-ink');
		expect(img).toBeTruthy();
		expect(img!.getAttribute('alt')).toBe('SetJoin');
		expect(img!.getAttribute('width')).toBe('26');
		expect(img!.getAttribute('height')).toBe('26');
	});

	it('renders four app rail buttons when enabledApps contains all four ids', () => {
		const { container } = render(AppRail, defaultProps);
		// App buttons have aria-label matching app names
		const mailBtn = container.querySelector('[aria-label="Mail"]');
		const calBtn = container.querySelector('[aria-label="Calendar"]');
		const contactsBtn = container.querySelector('[aria-label="Contacts"]');
		const tasksBtn = container.querySelector('[aria-label="Tasks"]');
		expect(mailBtn).toBeTruthy();
		expect(calBtn).toBeTruthy();
		expect(contactsBtn).toBeTruthy();
		expect(tasksBtn).toBeTruthy();
	});

	it('renders only two app rail buttons when enabledApps is [mail, tasks]', () => {
		const { container } = render(AppRail, { ...defaultProps, enabledApps: ['mail', 'tasks'] as AppId[] });
		const mailBtn = container.querySelector('[aria-label="Mail"]');
		const calBtn = container.querySelector('[aria-label="Calendar"]');
		const contactsBtn = container.querySelector('[aria-label="Contacts"]');
		const tasksBtn = container.querySelector('[aria-label="Tasks"]');
		expect(mailBtn).toBeTruthy();
		expect(tasksBtn).toBeTruthy();
		expect(calBtn).toBeNull();
		expect(contactsBtn).toBeNull();
	});

	it('shows only enabled Chat and Meet apps on the guest rail', () => {
		user.set({ email: 'pat@example.com', isAdmin: false, hasMailbox: false, accountType: 'guest' });
		const { container } = render(AppRail, {
			...defaultProps,
			enabledApps: ['mail', 'drive', 'chat', 'meet'] as AppId[],
			adminConsoles: ['mail'] as AdminConsoleId[],
			activeApp: 'chat',
			onToggleTheme: vi.fn(),
		});
		expect(container.querySelector('[aria-label="Chat"]')).toBeTruthy();
		expect(container.querySelector('[aria-label="Mail"]')).toBeNull();
		expect(container.querySelector('[aria-label="Drive"]')).toBeNull();
		expect(container.querySelector('[aria-label="Meet"]')).toBeTruthy();
		expect(container.querySelector('[aria-label="Settings"]')).toBeNull();
		expect(container.querySelector('[aria-label="Mail admin"]')).toBeNull();
		expect(container.querySelector('[aria-label="Dark mode"]')).toBeTruthy();
		expect(container.querySelector('[aria-label="Sign out"]')).toBeTruthy();
	});

	it('active app button has aria-current="page"', () => {
		const { container } = render(AppRail, { ...defaultProps, activeApp: 'mail' });
		const mailBtn = container.querySelector('[aria-label="Mail"]');
		expect(mailBtn).toBeTruthy();
		expect(mailBtn!.getAttribute('aria-current')).toBe('page');
	});

	it('non-active app button does not have aria-current="page"', () => {
		const { container } = render(AppRail, { ...defaultProps, activeApp: 'mail' });
		const calBtn = container.querySelector('[aria-label="Calendar"]');
		expect(calBtn).toBeTruthy();
		expect(calBtn!.getAttribute('aria-current')).toBeNull();
	});

	it('renders admin divider and admin console buttons when adminConsoles is non-empty', () => {
		const adminConsoles: AdminConsoleId[] = ['mail', 'logs'];
		const { container } = render(AppRail, { ...defaultProps, adminConsoles });
		const divider = container.querySelector('.sj-rail-divider');
		expect(divider).toBeTruthy();
		const adminMailBtn = container.querySelector('[aria-label="Mail admin"]');
		expect(adminMailBtn).toBeTruthy();
		// Find "Logs & threats" button by iterating (& in CSS attr selector doesn't work in jsdom)
		const allBtns = Array.from(container.querySelectorAll('button'));
		const adminLogsBtn = allBtns.find((b) => b.getAttribute('aria-label') === 'Logs & threats');
		expect(adminLogsBtn).toBeTruthy();
	});

	it('does not render admin divider when adminConsoles is empty', () => {
		const { container } = render(AppRail, { ...defaultProps, adminConsoles: [] });
		const divider = container.querySelector('.sj-rail-divider');
		expect(divider).toBeNull();
	});

	it('renders theme toggle button when onToggleTheme prop is provided', () => {
		const onToggleTheme = vi.fn();
		const { container } = render(AppRail, { ...defaultProps, onToggleTheme });
		// Theme toggle has aria-label for dark/light mode
		const themeBtn = container.querySelector('[aria-label="Dark mode"]') ?? container.querySelector('[aria-label="Light mode"]');
		expect(themeBtn).toBeTruthy();
	});

	it('does not render theme toggle button when onToggleTheme is not provided', () => {
		const { container } = render(AppRail, { ...defaultProps });
		const darkBtn = container.querySelector('[aria-label="Dark mode"]');
		const lightBtn = container.querySelector('[aria-label="Light mode"]');
		expect(darkBtn).toBeNull();
		expect(lightBtn).toBeNull();
	});

	it('always renders settings button', () => {
		const { container } = render(AppRail, defaultProps);
		const settingsBtn = container.querySelector('[aria-label="Settings"]');
		expect(settingsBtn).toBeTruthy();
	});

	it('avatar button has aria-label="Sign out"', () => {
		const { container } = render(AppRail, defaultProps);
		const avatarBtn = container.querySelector('[aria-label="Sign out"]');
		expect(avatarBtn).toBeTruthy();
	});

	it('avatar button has correct title with email and "— sign out"', () => {
		const { container } = render(AppRail, { ...defaultProps, userEmail: 'user@example.com' });
		const avatarBtn = container.querySelector('[aria-label="Sign out"]');
		expect(avatarBtn).toBeTruthy();
		expect(avatarBtn!.getAttribute('title')).toBe('user@example.com — sign out');
	});

	it('rail has CSS class that hides it below 768px (display:none in style)', () => {
		const { container } = render(AppRail, defaultProps);
		const nav = container.querySelector('nav.sj-rail');
		expect(nav).toBeTruthy();
		// The sj-rail class controls display via CSS (display: none default, flex at >=768px)
		// We verify the class is present, which applies the responsive CSS rule
		expect(nav!.classList.contains('sj-rail')).toBe(true);
	});
});

describe('AppRail data-tour anchor', () => {
	it('marks the nav with data-tour="apps"', () => {
		const { container } = render(AppRail, defaultProps);
		expect(container.querySelector('nav[data-tour="apps"]')).toBeTruthy();
	});
});
