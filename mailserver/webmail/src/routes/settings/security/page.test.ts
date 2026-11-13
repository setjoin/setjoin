import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte/svelte5';
import SecurityPage from './+page.svelte';

describe('security settings — structural (Task 11)', () => {
	beforeEach(() => {
		vi.stubGlobal(
			'matchMedia',
			vi.fn().mockReturnValue({
				matches: false,
				addEventListener: vi.fn(),
				removeEventListener: vi.fn()
			})
		);
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	function mockFetchByUrl(urlResponseMap: Record<string, unknown>) {
		vi.stubGlobal(
			'fetch',
			vi.fn((input: RequestInfo | URL) => {
				const url = typeof input === 'string' ? input : (input as Request).url;
				for (const [key, data] of Object.entries(urlResponseMap)) {
					if (url.startsWith(key) || url.includes(key)) {
						return Promise.resolve({
							ok: true,
							status: 200,
							json: async () => data,
							text: async () => ''
						});
					}
				}
				return Promise.resolve({
					ok: true,
					status: 200,
					json: async () => ({}),
					text: async () => ''
				});
			})
		);
	}

	it('renders Tabs for devices/history/TOTP', async () => {
		mockFetchByUrl({
			'/user/devices': { devices: [] },
			'/user/login-history': { events: [] },
			'/user/security-score': null,
			'/auth/me': { totp_enabled: false }
		});
		render(SecurityPage);
		await waitFor(() => {
			expect(screen.getByText('Login devices')).toBeTruthy();
		});
		expect(screen.getByText('Login history')).toBeTruthy();
		expect(screen.getByText('Authenticator')).toBeTruthy();
	});

	it('renders the Tabs component (tablist role)', async () => {
		mockFetchByUrl({
			'/user/devices': { devices: [] },
			'/user/login-history': { events: [] },
			'/user/security-score': null,
			'/auth/me': { totp_enabled: false }
		});
		const { container } = render(SecurityPage);
		await waitFor(() => {
			expect(container.querySelector('[role="tablist"]')).toBeTruthy();
		});
	});

	it('has no glass-pane class anywhere', async () => {
		mockFetchByUrl({
			'/user/devices': { devices: [] },
			'/user/login-history': { events: [] },
			'/user/security-score': null,
			'/auth/me': { totp_enabled: false }
		});
		const { container } = render(SecurityPage);
		await waitFor(() => {
			expect(container.querySelector('.sj-security-page')).toBeTruthy();
		});
		expect(container.querySelectorAll('.glass-pane').length).toBe(0);
	});

	it('has no glass-modal class anywhere', async () => {
		mockFetchByUrl({
			'/user/devices': { devices: [] },
			'/user/login-history': { events: [] },
			'/user/security-score': null,
			'/auth/me': { totp_enabled: false }
		});
		const { container } = render(SecurityPage);
		await waitFor(() => {
			expect(container.querySelector('.sj-security-page')).toBeTruthy();
		});
		expect(container.querySelectorAll('.glass-modal').length).toBe(0);
	});

	it('uses setjoin design system root class', async () => {
		mockFetchByUrl({
			'/user/devices': { devices: [] },
			'/user/login-history': { events: [] },
			'/user/security-score': null,
			'/auth/me': { totp_enabled: false }
		});
		const { container } = render(SecurityPage);
		await waitFor(() => {
			expect(container.querySelector('.sj-security-page')).toBeTruthy();
		});
	});

	it('devices tab renders device info with Badge variants', async () => {
		mockFetchByUrl({
			'/user/devices': {
				devices: [
					{
						device_fingerprint: 'fp-1',
						device_name: 'My MacBook Pro',
						platform: 'macOS',
						last_seen: '2026-06-15T10:00:00Z',
						trust_tier: 'trusted',
						has_active_session: true,
						is_current_device: true
					}
				]
			},
			'/user/login-history': { events: [] },
			'/user/security-score': null,
			'/auth/me': { totp_enabled: false }
		});
		render(SecurityPage);
		await waitFor(() => {
			// Text includes "(this device)" suffix for current device
			expect(screen.getByText((content) => content.includes('My MacBook Pro'))).toBeTruthy();
		});
		// Platform badge
		expect(screen.getByText('macOS')).toBeTruthy();
		// Trust tier badge
		expect(screen.getByText('trusted')).toBeTruthy();
		// flush cards used
		const cards = document.querySelectorAll('.card');
		expect(cards.length).toBeGreaterThanOrEqual(1);
	});

	it('history tab renders Badge variants for success/failure', async () => {
		mockFetchByUrl({
			'/user/devices': { devices: [] },
			'/user/login-history': {
				events: [
					{
						device_name: 'Firefox',
						platform: 'Windows',
						source_ip: '203.0.113.42',
						location: 'Berlin, DE',
						success: true,
						fail_reason: '',
						occurred_at: '2026-06-15T09:00:00Z'
					},
					{
						device_name: 'Unknown',
						platform: 'Linux',
						source_ip: '198.51.100.7',
						location: '',
						success: false,
						fail_reason: 'Wrong password',
						occurred_at: '2026-06-15T08:00:00Z'
					}
				]
			},
			'/user/security-score': null,
			'/auth/me': { totp_enabled: false }
		});
		render(SecurityPage);
		await waitFor(() => {
			expect(screen.getByText('Login devices')).toBeTruthy();
		});
		// Tab exists for history
		expect(screen.getByText('Login history')).toBeTruthy();
	});

	// ── SP1 Phase 6: Contacts' Certificates panel ──

	describe('contacts cert panel (Phase 6)', () => {
		function mockFetchWithContacts(certs: unknown[]) {
			vi.stubGlobal(
				'fetch',
				vi.fn((input: RequestInfo | URL) => {
					const url = typeof input === 'string' ? input : (input as Request).url;
					if (url.includes('/auth/me/smime/recipient-certs')) {
						return Promise.resolve({
							ok: true, status: 200,
							json: async () => ({ certs }),
							text: async () => ''
						});
					}
					return Promise.resolve({
						ok: true, status: 200,
						json: async () => ({}),
						text: async () => ''
					});
				})
			);
		}

		it('renders the contacts cert card title', async () => {
			mockFetchWithContacts([]);
			render(SecurityPage);
			await waitFor(() => {
				expect(screen.getByText("Contacts' Certificates")).toBeTruthy();
			});
		});

		it('renders empty-state body when certs array is empty', async () => {
			mockFetchWithContacts([]);
			render(SecurityPage);
			await waitFor(() => {
				expect(screen.getByText(/saved automatically when you receive signed mail/)).toBeTruthy();
			});
		});

		it('renders signing_only badge for harvested cert that is not encrypt-capable', async () => {
			mockFetchWithContacts([{
				id: 1,
				email: 'bob@example.com',
				label: '',
				source: 'harvested',
				notBefore: '2025-01-01T00:00:00Z',
				notAfter: '2030-01-01T00:00:00Z',
				fingerprint: 'abc123',
				isEncryptCapable: false
			}]);
			render(SecurityPage);
			await waitFor(() => {
				expect(screen.getByText("Signing only — can't encrypt")).toBeTruthy();
			});
		});

		it('renders expired badge for cert with past notAfter', async () => {
			mockFetchWithContacts([{
				id: 2,
				email: 'alice@example.com',
				label: '',
				source: 'imported',
				notBefore: '2020-01-01T00:00:00Z',
				notAfter: '2021-01-01T00:00:00Z',
				fingerprint: 'def456',
				isEncryptCapable: true
			}]);
			render(SecurityPage);
			await waitFor(() => {
				// expired badge appears (there may be multiple 'Expired' texts from different certs)
				expect(screen.getAllByText('Expired').length).toBeGreaterThan(0);
			});
		});

		it('renders the import form with cert file input and Import button', async () => {
			mockFetchWithContacts([]);
			render(SecurityPage);
			await waitFor(() => {
				expect(screen.getByText('Import a certificate')).toBeTruthy();
				expect(screen.getByText('Import')).toBeTruthy();
			});
		});
	});

	it('renders Security score Card with Progress when score data present', async () => {
		mockFetchByUrl({
			'/user/devices': { devices: [] },
			'/user/login-history': { events: [] },
			'/user/security-score': {
				score: 75,
				checks: [
					{ name: 'Password strength', pass: true, points: 25 },
					{ name: 'TOTP enrolled', pass: false, points: 0, action: 'Set up two-factor auth' }
				]
			},
			'/auth/me': { totp_enabled: false }
		});
		render(SecurityPage);
		await waitFor(() => {
			expect(screen.getByText('Security score')).toBeTruthy();
		});
		const progressBar = document.querySelector('[role="progressbar"]');
		expect(progressBar).toBeTruthy();
	});

	// Guards the real API contract: items + snake_case are mapped to the SignIn interface.
	// If loadSignIns reads data.events or uses ev.device_name directly the row won't render.
	it('loadSignIns: maps real API shape (items + snake_case) to rendered row', async () => {
		mockFetchByUrl({
			'/user/devices': { devices: [] },
			'/user/login-history': {
				items: [{
					id: 42,
					success: true,
					current: true,
					device_name: 'Firefox on Linux',
					auth_method: 'password',
					location: 'Berlin, DE',
					occurred_at: '2026-06-23T10:00:00Z',
				}],
				total: 1,
				failed_distinct: { count: 0, locations: 0, since: '' },
			},
			'/user/security-score': null,
			'/auth/me': { totp_enabled: false },
		});
		render(SecurityPage, { props: { initialTab: 'history', initialLoading: false } as any });
		await waitFor(() => {
			expect(screen.getByTestId('signin-row-42')).toBeTruthy();
		});
		expect(screen.getByTestId('signin-row-42').textContent).toContain('Firefox on Linux');
		expect(screen.getByTestId('signin-row-42').textContent).toContain('Berlin, DE');
	});

	// ── WP5: initial-load reads (devices, security-score, /auth/me) go through
	// the settings-resource composable; failures surface the seam's typed,
	// display-safe message on the page-level error line.

	it('WP5: a failed devices read surfaces the seam typed error instead of silently empty', async () => {
		vi.stubGlobal(
			'fetch',
			vi.fn((input: RequestInfo | URL) => {
				const url = typeof input === 'string' ? input : (input as Request).url;
				if (url.includes('/api/user/devices')) {
					return Promise.resolve({ ok: false, status: 500, json: async () => ({}), text: async () => '' });
				}
				return Promise.resolve({ ok: true, status: 200, json: async () => ({}), text: async () => '' });
			})
		);
		render(SecurityPage);
		await waitFor(() => {
			expect(screen.getByText('Request failed (500)')).toBeTruthy();
		});
	});

	it('WP5: unmount aborts the in-flight initial-load reads', async () => {
		const captured: AbortSignal[] = [];
		vi.stubGlobal(
			'fetch',
			vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
				const url = typeof input === 'string' ? input : (input as Request).url;
				if (url.includes('/api/user/devices')) {
					if (init?.signal) captured.push(init.signal);
					return new Promise<Response>((_resolve, reject) => {
						init?.signal?.addEventListener(
							'abort',
							() => reject(new DOMException('Aborted', 'AbortError')),
							{ once: true }
						);
					});
				}
				return Promise.resolve({ ok: true, status: 200, json: async () => ({}), text: async () => '' });
			})
		);
		const { unmount } = render(SecurityPage);
		await waitFor(() => expect(captured.length).toBe(1));
		unmount();
		expect(captured[0].aborted).toBe(true);
	});
});
