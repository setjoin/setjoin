import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { screen } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';

const api = vi.hoisted(() => ({ fetch: vi.fn() }));
vi.mock('$lib/admin/client', () => ({ adminFetch: api.fetch }));

import Page from './+page.svelte';

function response(data: unknown) {
	return { ok: true, json: vi.fn().mockResolvedValue(data) };
}

describe('client updates page', () => {
	beforeEach(() => { resetStores(); vi.clearAllMocks(); });
	afterEach(() => resetStores());

	it('renders summaries, distributions, and all device badge variants', async () => {
		api.fetch.mockImplementation(async (path: string) => path.endsWith('/summary')
			? response({ total_devices: 5, up_to_date: 1, outdated: 2, critical: 2, by_version: [{ version: '2.0', count: 3 }], by_platform: [
				{ platform: 'iOS', count: 1 }, { platform: 'Android', count: 1 }, { platform: 'macOS', count: 1 },
				{ platform: 'Windows', count: 1 }, { platform: 'Linux', count: 1 },
			] })
			: response({ devices: [
				{ id: 1, name: 'Phone', platform: 'iOS', os_version: '18', app_version: '2.0', last_seen: '2026-07-23T01:00:00Z', status: 'up to date' },
				{ id: 2, name: '', platform: 'Android', os_version: '15', app_version: '', last_seen: '', status: 'outdated' },
				{ id: 3, name: 'Mac', platform: 'macOS', os_version: '15', app_version: '1.0', last_seen: '', status: 'critical' },
				{ id: 4, name: 'Linux', platform: 'Linux', os_version: '1', app_version: '1.0', last_seen: '', status: 'unknown' },
			] }));
		await renderAsUser(Page, {}, { isAdmin: true });
		expect(await screen.findByText('Phone')).toBeInTheDocument();
		expect(screen.getByText('Device #2')).toBeInTheDocument();
		expect(screen.getAllByText('2.0')).not.toHaveLength(0);
		expect(screen.getByText('Version Distribution')).toBeInTheDocument();
		expect(screen.getByText('Platform Distribution')).toBeInTheDocument();
	});

	it('renders an empty device state', async () => {
		api.fetch.mockImplementation(async (path: string) => path.endsWith('/summary')
			? response({ total_devices: 0, up_to_date: 0, outdated: 0, critical: 0, by_version: [], by_platform: [] })
			: response({}));
		await renderAsUser(Page, {}, { isAdmin: true });
		expect(await screen.findByText('No devices registered.')).toBeInTheDocument();
	});

	it('surfaces load failures', async () => {
		api.fetch.mockRejectedValue(new Error('offline'));
		await renderAsUser(Page, {}, { isAdmin: true });
		expect(await screen.findByRole('alert')).toHaveTextContent('Could not load version data.');
	});
});
