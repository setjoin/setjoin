import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte/svelte5';
import NotificationsPage from './+page.svelte';

describe('Notifications Page — Task 12 restyle', () => {
	beforeEach(() => {
		vi.stubGlobal('fetch', vi.fn(() =>
			Promise.resolve({
				ok: true,
				status: 200,
				json: async () => ({
					preferences: [],
				}),
				text: async () => '',
			})
		));
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('has no glass-pane class anywhere', async () => {
		const { container } = render(NotificationsPage);
		await waitFor(() => {
			expect(container.querySelector('.sj-notif-page')).toBeTruthy();
		});
		expect(container.querySelectorAll('.glass-pane').length).toBe(0);
	});

	it('has no glass-modal class anywhere', async () => {
		const { container } = render(NotificationsPage);
		await waitFor(() => {
			expect(container.querySelector('.sj-notif-page')).toBeTruthy();
		});
		expect(container.querySelectorAll('.glass-modal').length).toBe(0);
	});

	it('wraps sections in Card components (renders .card class)', async () => {
		const { container } = render(NotificationsPage);
		await waitFor(() => {
			const cards = container.querySelectorAll('.card');
			expect(cards.length).toBeGreaterThanOrEqual(3);
		});
	});

	it('renders Switch components from M1 for notification toggles', async () => {
		const { container } = render(NotificationsPage);
		await waitFor(() => {
			const switches = container.querySelectorAll('input[role="switch"]');
			expect(switches.length).toBeGreaterThanOrEqual(4);
		});
	});

	it('renders an enable push notifications Switch with label', async () => {
		render(NotificationsPage);
		await waitFor(() => {
			expect(screen.getByText('Enable push notifications')).toBeTruthy();
		});
	});

	it('renders a stop push when desktop online Switch', async () => {
		render(NotificationsPage);
		await waitFor(() => {
			expect(screen.getByText('Stop push when desktop is online')).toBeTruthy();
		});
	});

	it('renders calendar event reminders Switch', async () => {
		render(NotificationsPage);
		await waitFor(() => {
			expect(screen.getByText('Calendar event reminders')).toBeTruthy();
		});
	});

	it('renders task due date reminders Switch', async () => {
		render(NotificationsPage);
		await waitFor(() => {
			expect(screen.getByText('Task due date reminders')).toBeTruthy();
		});
	});

	it('renders DND card section title (sentence case, i18n)', async () => {
		render(NotificationsPage);
		await waitFor(() => {
			expect(screen.getByText('Do not disturb')).toBeTruthy();
		});
	});
});

describe('Notifications Page — push subscribe (QoL #9)', () => {
	beforeEach(() => {
		vi.stubGlobal('fetch', vi.fn(() =>
			Promise.resolve({ ok: true, status: 200, json: async () => ({ preferences: [] }), text: async () => '' })
		));
	});

	afterEach(() => {
		vi.unstubAllGlobals();
		vi.restoreAllMocks();
	});

	it('shows "unsupported" when the browser has no PushManager/Notification', async () => {
		// jsdom by default has neither — the H5-binding-critical assertion is that
		// this NEVER touches Notification.requestPermission on load.
		const requestPermission = vi.fn();
		vi.stubGlobal('Notification', { permission: 'default', requestPermission });
		render(NotificationsPage);
		await waitFor(() => {
			expect(screen.getByText("Push notifications aren't supported in this browser.")).toBeTruthy();
		});
		expect(requestPermission).not.toHaveBeenCalled();
	});

	it('shows the Enable button (not-asked) and never prompts on load when push IS supported', async () => {
		const requestPermission = vi.fn().mockResolvedValue('granted');
		vi.stubGlobal('Notification', { permission: 'default', requestPermission });
		vi.stubGlobal('navigator', {
			...navigator,
			serviceWorker: { ready: Promise.resolve({ pushManager: { getSubscription: async () => null, subscribe: async () => ({}) } }) },
			userAgent: 'test-agent',
		});
		vi.stubGlobal('PushManager', class {});

		render(NotificationsPage);
		await waitFor(() => {
			expect(screen.getByText('Enable mail notifications')).toBeTruthy();
		});
		expect(requestPermission).not.toHaveBeenCalled();
	});

	it('shows the granted state when permission is already granted', async () => {
		vi.stubGlobal('Notification', { permission: 'granted', requestPermission: vi.fn() });
		vi.stubGlobal('PushManager', class {});
		vi.stubGlobal('navigator', { ...navigator, serviceWorker: {} });
		render(NotificationsPage);
		await waitFor(() => {
			expect(screen.getByText('Notifications are enabled on this device.')).toBeTruthy();
		});
	});

	it('shows the quiet denied instruction when permission is denied', async () => {
		vi.stubGlobal('Notification', { permission: 'denied', requestPermission: vi.fn() });
		vi.stubGlobal('PushManager', class {});
		vi.stubGlobal('navigator', { ...navigator, serviceWorker: {} });
		render(NotificationsPage);
		await waitFor(() => {
			expect(screen.getByText(/Notifications are blocked/)).toBeTruthy();
		});
	});
});
