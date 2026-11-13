import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/svelte/svelte5';
import AboutPage from './+page.svelte';

describe('About Page — Task 12 restyle', () => {
	beforeEach(() => {
		vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL) => {
			const url = typeof input === 'string' ? input : (input as Request).url;
			if (url === '/health') {
				return Promise.resolve({
					ok: true,
					status: 200,
					json: async () => ({
						status: 'healthy',
						version: '0.1.0',
						uptime: '3d 14h',
						go_version: 'go1.25.0',
						db_status: 'ok',
						s3_status: 'ok',
					}),
					text: async () => '',
				});
			}
			return Promise.resolve({
				ok: true,
				status: 200,
				json: async () => ({}),
				text: async () => '',
			});
		}));
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('has no glass-pane class anywhere', async () => {
		const { container } = render(AboutPage);
		await waitFor(() => {
			expect(container.querySelector('.sj-about-page')).toBeTruthy();
		});
		expect(container.querySelectorAll('.glass-pane').length).toBe(0);
	});

	it('has no glass-modal class anywhere', async () => {
		const { container } = render(AboutPage);
		await waitFor(() => {
			expect(container.querySelector('.sj-about-page')).toBeTruthy();
		});
		expect(container.querySelectorAll('.glass-modal').length).toBe(0);
	});

	it('renders the version string in code with sj-version-code class', async () => {
		const { container } = render(AboutPage);
		await waitFor(() => {
			const versionCode = container.querySelector('code.sj-version-code');
			expect(versionCode).toBeTruthy();
			expect(versionCode?.textContent).toContain('0.1.0');
		});
	});

	it('wraps system info in Card components (renders .card class)', async () => {
		const { container } = render(AboutPage);
		await waitFor(() => {
			const cards = container.querySelectorAll('.card');
			expect(cards.length).toBeGreaterThanOrEqual(2);
		});
	});

	it('renders System Status Card title', async () => {
		render(AboutPage);
		await waitFor(() => {
			expect(screen.getByText('System Status')).toBeTruthy();
		});
	});

	it('renders Account Card with email in mono code', async () => {
		render(AboutPage);
		await waitFor(() => {
			expect(screen.getByText('Account')).toBeTruthy();
		});
	});

	it('renders database status indicator', async () => {
		render(AboutPage);
		await waitFor(() => {
			expect(screen.getByText('Database')).toBeTruthy();
		});
	});

	it('renders blob storage status indicator', async () => {
		render(AboutPage);
		await waitFor(() => {
			expect(screen.getByText('Blob Storage')).toBeTruthy();
		});
	});

	it('renders the hero logomark image (design ref §16, not the "SJ" placeholder)', async () => {
		render(AboutPage);
		await waitFor(() => {
			const logo = screen.getByAltText('SetJoin') as HTMLImageElement;
			expect(logo).toBeTruthy();
			expect(logo.tagName).toBe('IMG');
			expect(logo.getAttribute('src')).toContain('logo-mark.svg');
		});
		expect(screen.queryByText('SJ')).toBeNull();
	});
});
