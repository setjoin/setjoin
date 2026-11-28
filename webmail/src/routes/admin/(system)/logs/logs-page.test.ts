import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';

const api = vi.hoisted(() => ({ fetch: vi.fn(), download: vi.fn() }));
vi.mock('$lib/admin/client', () => ({ adminFetch: api.fetch }));
vi.mock('$lib/utils/downloadBlob', () => ({ downloadBlob: api.download }));

import Page from './+page.svelte';

function response(data: unknown, ok = true) {
	return { ok, json: vi.fn().mockResolvedValue(data) };
}

describe('admin logs workflows', () => {
	beforeEach(() => {
		resetStores();
		vi.clearAllMocks();
		api.fetch.mockImplementation(async (path: string) => {
			if (path.startsWith('/admin/system/logs')) return response([
				{ timestamp: '2026-07-23T01:02:03Z', level: 'error', message: 'disk warning' },
				{ timestamp: '', level: '', message: '' },
			]);
			if (path.startsWith('/admin/auth-log')) return response([
				{ timestamp: '2026-07-23T01:02:03Z', email: 'alice@example.test', provider: 'webauthn', event: 'login', ip: '203.0.113.4' },
				{ timestamp: '', email: '', provider: '', event: 'login_failed', ip: '' },
			]);
			return response([]);
		});
	});
	afterEach(() => resetStores());

	it('loads, filters, and exports system logs', async () => {
		await renderAsUser(Page, {}, { isAdmin: true });
		expect(await screen.findByText('disk warning')).toBeInTheDocument();
		expect(screen.getAllByText('error')).not.toHaveLength(0);

		await fireEvent.change(screen.getByLabelText('Level'), { target: { value: 'error' } });
		await fireEvent.change(screen.getByLabelText('Time range'), { target: { value: '6h' } });
		await fireEvent.input(screen.getByLabelText('Search'), { target: { value: 'disk' } });
		await waitFor(() => expect(api.fetch).toHaveBeenCalledWith(expect.stringContaining('level=error')));
		await fireEvent.click(screen.getByRole('button', { name: 'Export' }));
		await waitFor(() => expect(api.download).toHaveBeenCalledWith(expect.any(Blob), expect.stringMatching(/^logs-.*\.txt$/)));
	});

	it('switches to auth logs and applies auth filters', async () => {
		await renderAsUser(Page, {}, { isAdmin: true });
		await screen.findByText('disk warning');
		await fireEvent.click(screen.getByRole('tab', { name: 'Auth' }));
		expect(await screen.findByText('alice@example.test')).toBeInTheDocument();
		await fireEvent.change(screen.getByLabelText('Provider'), { target: { value: 'webauthn' } });
		await fireEvent.change(screen.getByLabelText('Event'), { target: { value: 'login_failed' } });
		await fireEvent.input(screen.getByLabelText('Email'), { target: { value: 'alice' } });
		await waitFor(() => expect(api.fetch).toHaveBeenCalledWith(expect.stringContaining('provider=webauthn')));
	});

	it('shows load and export failures and empty results', async () => {
		api.fetch.mockRejectedValueOnce(new Error('logs unavailable'));
		await renderAsUser(Page, {}, { isAdmin: true });
		expect(await screen.findByRole('alert')).toHaveTextContent('logs unavailable');

		api.fetch.mockResolvedValueOnce(response([]));
		await fireEvent.click(screen.getByRole('tab', { name: 'System' }));
		expect(await screen.findByText('No log entries found')).toBeInTheDocument();

		api.fetch.mockResolvedValueOnce(response({}, false));
		await fireEvent.click(screen.getByRole('button', { name: 'Export' }));
		expect(await screen.findByRole('alert')).toHaveTextContent('Export failed');
	});
});
