import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({ fetch: vi.fn() }));
vi.mock('$lib/admin/client', () => ({ adminFetch: api.fetch }));

import Page from './+page.svelte';

function response(data: unknown) {
	return { ok: true, json: vi.fn().mockResolvedValue(data) };
}

function grant() {
	jmapSession.set({ accounts: {}, primaryAccounts: {}, capabilities: {
		'urn:setjoin:params:jmap:mail': { admin: { consoles: ['system'], permissions: ['system.upgrade'] } }
	} } as never);
}

describe('deploy wizard workflows', () => {
	beforeEach(() => {
		resetStores();
		vi.clearAllMocks();
		api.fetch.mockResolvedValue(response({ status: 'config', nodes: [], steps: [], log: [], profile: 1 }));
	});
	afterEach(() => resetStores());

	it('validates all three hosts and starts an authorized deployment', async () => {
		await renderAsUser(Page, {}, { isAdmin: true });
		grant();
		await screen.findByText('Node Configuration');
		const start = screen.getByRole('button', { name: 'Start Deployment' });
		await fireEvent.click(start);
		expect(screen.getByRole('alert')).toHaveTextContent('All 3 node hosts are required.');

		for (const [input, host] of screen.getAllByLabelText('Host').map((el, i) => [el, `10.0.0.${i + 1}`] as const)) {
			await fireEvent.input(input, { target: { value: host } });
		}
		await fireEvent.click(start);
		await waitFor(() => expect(api.fetch).toHaveBeenCalledWith('/admin/deploy/start', expect.objectContaining({ method: 'POST' })));
	});

	it.each([
		['deploying', 'Deploying', 'Cancel Deployment'],
		['verifying', 'Verifying', 'Cancel Deployment'],
		['done', 'Complete', 'The HA cluster is ready. Update your gateway DSN to point to Pgpool-II.'],
		['failed', 'Failed', 'Check the step details below. Fix any issues and try again.'],
	] as const)('renders the %s status state', async (status, label, detail) => {
		api.fetch.mockResolvedValue(response({
			status,
			nodes: [],
			profile: 1,
			steps: [
				{ name: 'Prepare', status: 'ok' },
				{ name: 'Install', status: 'running' },
				{ name: 'Verify', status: 'failed', error: 'probe failed' },
				{ name: 'Finish', status: 'pending' },
			],
			log: ['first line', 'second line'],
		}));
		await renderAsUser(Page, {}, { isAdmin: true });
		grant();
		expect(await screen.findByText(label)).toBeInTheDocument();
		expect(screen.getByText(detail)).toBeInTheDocument();
		expect(screen.getByText(/first line/)).toBeInTheDocument();
	});

	it('surfaces start failures and cancels an active deployment', async () => {
		api.fetch.mockImplementation(async (path: string, init?: RequestInit) => {
			if (path === '/admin/deploy/status') return response({ status: 'deploying', nodes: [], profile: 1, steps: [], log: [] });
			if (path === '/admin/deploy/cancel' && init?.method === 'POST') return response({});
			throw new Error('start unavailable');
		});
		await renderAsUser(Page, {}, { isAdmin: true });
		grant();
		const cancel = await screen.findByRole('button', { name: 'Cancel Deployment' });
		await fireEvent.click(cancel);
		await waitFor(() => expect(api.fetch).toHaveBeenCalledWith('/admin/deploy/cancel', { method: 'POST' }));
	});
});
