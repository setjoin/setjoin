import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';

describe('Settings Page — Task 6 four-card layout', () => {
	let SettingsPage: any;

	beforeEach(async () => {
		// Mock fetch with a flexible implementation
		const mockFetch = vi.fn(() =>
			Promise.resolve({
				ok: true,
				status: 200,
				json: async () => ({}),
				text: async () => ''
			})
		);
		vi.stubGlobal('fetch', mockFetch);

		Object.defineProperty(window, 'location', {
			value: { hostname: 'mail.acme.com' },
			writable: true
		});
		vi.stubGlobal('localStorage', {
			getItem: vi.fn().mockReturnValue(null),
			setItem: vi.fn(),
			removeItem: vi.fn()
		});

		// Dynamic import so mocks are in place before module loads
		SettingsPage = (await import('./+page.svelte')).default;
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('renders a page title heading', () => {
		render(SettingsPage);
		expect(screen.getByRole('heading', { level: 1 })).toBeTruthy();
	});

	it('renders subtitle text', () => {
		render(SettingsPage);
		expect(screen.getByText(/Your preferences/)).toBeTruthy();
	});

	it('page root has sj-settings-page class', () => {
		const { container } = render(SettingsPage);
		expect(container.querySelector('.sj-settings-page')).toBeTruthy();
	});

	it('renders Profile card title', () => {
		render(SettingsPage);
		expect(screen.getAllByText(/Profile/).length).toBeGreaterThanOrEqual(1);
	});

	it('renders Appearance & language card title', () => {
		render(SettingsPage);
		expect(screen.getAllByText(/Appearance/).length).toBeGreaterThanOrEqual(1);
	});

	it('renders Mail card title', () => {
		render(SettingsPage);
		expect(screen.getAllByText(/Mail/).length).toBeGreaterThanOrEqual(1);
	});

	it('renders Security card title', () => {
		render(SettingsPage);
		const matches = screen.getAllByText(/Security/);
		expect(matches.length).toBeGreaterThanOrEqual(1);
	});

	it('has no glass-pane class', () => {
		const { container } = render(SettingsPage);
		expect(container.querySelectorAll('.glass-pane').length).toBe(0);
	});

	it('has no glass-modal class', () => {
		const { container } = render(SettingsPage);
		expect(container.querySelectorAll('.glass-modal').length).toBe(0);
	});
});

// ── Parity-audit remediation: saveProfile must surface server failures ──
describe('Settings Page — profile save error handling', () => {
	let SettingsPage: any;

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('surfaces an error alert when POST /user/profile fails (does not falsely confirm)', async () => {
		vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input :
				input instanceof URL ? input.href : (input as Request).url;
			if (String(url).includes('/user/profile') && init?.method === 'POST') {
				return {
					ok: false,
					status: 500,
					json: async () => ({ error: 'Server is unavailable' }),
					text: async () => ''
				};
			}
			return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
		}));
		Object.defineProperty(window, 'location', { value: { hostname: 'mail.acme.com' }, writable: true });
		vi.stubGlobal('localStorage', {
			getItem: vi.fn().mockReturnValue(null),
			setItem: vi.fn(),
			removeItem: vi.fn()
		});

		SettingsPage = (await import('./+page.svelte')).default;
		render(SettingsPage);

		const saveBtn = screen.getByRole('button', { name: /Save changes/ });
		await fireEvent.click(saveBtn);

		await waitFor(() => {
			const alert = screen.getByRole('alert');
			expect(alert.textContent).toContain('Server is unavailable');
		});
	});
});
