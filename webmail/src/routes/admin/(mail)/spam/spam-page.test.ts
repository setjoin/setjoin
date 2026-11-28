import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({ fetch: vi.fn() }));
vi.mock('$lib/admin/client', () => ({ adminFetch: api.fetch }));

import Page from './+page.svelte';

const stats = {
	enabled: true, total_models: 2, total_samples: 100, active_week: 1,
	total_classified: 20, total_fp: 1, fp_rate: 0.05, feature_size: 4096, min_samples: 10,
	top_users: [
		{ user_id: 1, email: 'active@example.test', disabled: false, sample_count: 60, model_size_kb: 12, trained_at: 'today' },
		{ user_id: 2, email: 'off@example.test', disabled: true, sample_count: 40, model_size_kb: 8, trained_at: 'yesterday' },
	],
};

function response(data: unknown = {}, ok = true) { return { ok, json: vi.fn().mockResolvedValue(data) }; }
function grant() {
	jmapSession.set({ accounts: {}, primaryAccounts: {}, capabilities: {
		'urn:setjoin:params:jmap:mail': { admin: { consoles: ['mail'], permissions: ['security.write'] } }
	} } as never);
}

describe('spam administration', () => {
	beforeEach(() => {
		resetStores(); vi.clearAllMocks(); vi.stubGlobal('confirm', vi.fn(() => true));
		api.fetch.mockImplementation(async (path: string) => path === '/admin/spam' ? response(stats) : response({}));
	});
	afterEach(() => { vi.unstubAllGlobals(); resetStores(); });

	it('renders model statistics and performs enable, disable, and reset actions', async () => {
		await renderAsUser(Page, {}, { isAdmin: true }); grant();
		expect(await screen.findByText('active@example.test')).toBeInTheDocument();
		expect(screen.getByText(/5\.00%/)).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Disable' }));
		await fireEvent.click(screen.getByRole('button', { name: 'Enable' }));
		await fireEvent.click(screen.getAllByRole('button', { name: 'Reset' })[0]);
		await waitFor(() => {
			expect(api.fetch).toHaveBeenCalledWith('/admin/spam/models/1/disable', { method: 'POST' });
			expect(api.fetch).toHaveBeenCalledWith('/admin/spam/models/2/enable', { method: 'POST' });
			expect(api.fetch).toHaveBeenCalledWith('/admin/spam/models/1', { method: 'DELETE' });
		});
	});

	it('honors cancelled confirmation and handles empty and failed mutations', async () => {
		vi.mocked(confirm).mockReturnValue(false);
		api.fetch.mockResolvedValueOnce(response({ enabled: false, top_users: [] }));
		await renderAsUser(Page, {}, { isAdmin: true }); grant();
		expect(await screen.findByText('No trained models yet')).toBeInTheDocument();
		expect(screen.getByText('Disabled')).toBeInTheDocument();
	});
});
