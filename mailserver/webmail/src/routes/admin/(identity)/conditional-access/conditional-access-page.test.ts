import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';

const api = vi.hoisted(() => ({ fetch: vi.fn() }));
vi.mock('$lib/admin/client', () => ({ adminFetch: api.fetch }));

import Page from './+page.svelte';

const policies = [
	{
		id: 21, priority: 10, name: 'Block risky', description: 'Risk gate', state: 'report_only',
		scope_type: 'user', scope_target: '42', action: 'block', exclude_users: [], exclude_groups: [],
		conditions: { risk: 'high' }, actions: { operator: 'all', grants: [{ type: 'block' }] },
		created_at: '2026-01-01', updated_at: '2026-07-23', deleted_at: null,
	},
	{
		id: 22, priority: 20, name: 'Notify guests', description: '', state: 'off',
		scope_type: 'guests', scope_target: '', action: 'notify', exclude_users: [7], exclude_groups: [8],
		conditions: {}, actions: { operator: 'one', grants: [{ type: 'notify' }, { type: 'require_acr', acr: 'mfa' }] },
		created_at: '2026-01-02', updated_at: '2026-07-22', deleted_at: null,
	},
];

function response(data: unknown = {}, ok = true, status = ok ? 200 : 500) {
	return { ok, status, json: vi.fn().mockResolvedValue(data) };
}

async function renderPage() {
	await renderAsUser(Page, {}, { isAdmin: true });
	await waitFor(() => expect(screen.queryByLabelText('Loading policies…')).not.toBeInTheDocument());
}

describe('conditional access policy page', () => {
	beforeEach(() => {
		resetStores();
		vi.clearAllMocks();
		api.fetch.mockImplementation(async (path: string, init?: RequestInit) => {
			if (path === '/admin/conditional-access/policies' && !init) return response(policies);
			if (path === '/admin/conditional-access/policies?include_deleted=1') return response([
				...policies, { ...policies[0], name: 'Deleted guest rule', deleted_at: '2026-07-23' },
			]);
			if (path === '/admin/conditional-access/policies' && init?.method === 'POST') {
				return response({ ...policies[0], id: 30, name: 'New CA policy', state: 'off' });
			}
			if (path === '/admin/conditional-access/policies/21' && init?.method === 'PUT') {
				return response({ ...policies[0], name: 'Risk policy updated', state: 'report_only' });
			}
			if (path === '/admin/conditional-access/policies/21/restore') return response(policies[0]);
			// The editor mounts ImpactCard with fetchData — model the impact read
			// endpoint (no-data summary) so the card renders its NO-DATA state
			// instead of an error alert.
			if (path.startsWith('/admin/conditional-access/policies/21/impact')) {
				return response({ window: '7d', window_has_data: false, matched: 0, would_block: 0, would_step_up: 0, distinct_users: 0, would_block_admins: 0 });
			}
			return response({});
		});
	});
	afterEach(() => resetStores());

	it('renders policy states, navigation tiles, and reorders the list', async () => {
		await renderPage();
		expect(screen.getByRole('heading', { name: 'Conditional access policies' })).toBeInTheDocument();
		expect(screen.getByRole('link', { name: /Gaps/ })).toHaveAttribute('href', '/admin/conditional-access/coverage');
		expect(screen.getByText('Report-only')).toBeInTheDocument();
		expect(screen.getByText('Off')).toBeInTheDocument();
		expect(screen.getByText('user:42')).toBeInTheDocument();

		await fireEvent.click(screen.getAllByRole('button', { name: 'Down' })[0]);
		await waitFor(() => expect(api.fetch).toHaveBeenCalledWith('/admin/conditional-access/policies/reorder', {
			method: 'POST', body: JSON.stringify([22, 21])
		}));
	});

	it('validates JSON and creates a multi-control global policy', async () => {
		await renderPage();
		await fireEvent.click(screen.getByRole('button', { name: 'Add a policy' }));
		const dialog = screen.getByRole('dialog', { name: 'New policy' });
		await fireEvent.input(within(dialog).getByLabelText('Conditions'), { target: { value: '{bad' } });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
		expect(within(dialog).getByRole('alert')).toHaveTextContent(/Invalid/);

		await fireEvent.input(within(dialog).getByPlaceholderText('Block external IPs'), { target: { value: 'New CA policy' } });
		await fireEvent.input(within(dialog).getByLabelText('Conditions'), { target: { value: '{"country":"CN"}' } });
		await fireEvent.change(within(dialog).getByLabelText('Scope'), { target: { value: 'global' } });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Add control' }));
		const controls = within(dialog).getAllByLabelText('Control type');
		await fireEvent.change(controls[0], { target: { value: 'allow' } });
		await fireEvent.change(controls[1], { target: { value: 'step_up' } });
		await fireEvent.change(within(dialog).getAllByRole('combobox')[2], { target: { value: 'one' } });
		await fireEvent.click(within(dialog).getAllByRole('button', { name: 'Remove control' })[0]);
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
		await waitFor(() => expect(api.fetch).toHaveBeenCalledWith('/admin/conditional-access/policies', expect.objectContaining({
			method: 'POST', body: expect.stringContaining('"scope_type":"global"')
		})));
	});

	it('edits an existing policy and surfaces an exact backend save hint', async () => {
		await renderPage();
		await fireEvent.click(screen.getByRole('button', { name: 'Block risky' }));
		const dialog = screen.getByRole('dialog', { name: 'Edit policy' });
		expect(within(dialog).getByPlaceholderText('Block external IPs')).toHaveValue('Block risky');
		await fireEvent.input(within(dialog).getByPlaceholderText('Block external IPs'), { target: { value: 'Risk policy updated' } });

		api.fetch.mockResolvedValueOnce(response({ hint: 'would lock out all break-glass admins' }, false, 409));
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
		expect(await within(dialog).findByRole('alert')).toHaveTextContent(/lock out/i);

		await fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
		await waitFor(() => expect(api.fetch).toHaveBeenCalledWith('/admin/conditional-access/policies/21', expect.objectContaining({ method: 'PUT' })));
	});

	it('soft-deletes, loads trash, and restores a policy', async () => {
		await renderPage();
		await fireEvent.click(screen.getAllByRole('button', { name: 'Delete' })[0]);
		await waitFor(() => expect(api.fetch).toHaveBeenCalledWith('/admin/conditional-access/policies/21', { method: 'DELETE' }));
		const trash = screen.getByTestId('trash-section');
		await fireEvent.click(within(trash).getByText('Deleted policies'));
		await waitFor(() => expect(screen.getByText('Deleted guest rule')).toBeInTheDocument());
		await fireEvent.click(screen.getByTestId('trash-restore-btn'));
		await waitFor(() => expect(api.fetch).toHaveBeenCalledWith('/admin/conditional-access/policies/21/restore', { method: 'POST' }));
	});

	it('fails visibly on initial load and recovers through retry', async () => {
		let listFailed = false;
		api.fetch.mockImplementation(async (path: string) => {
			if (path === '/admin/conditional-access/policies' && !listFailed) {
				listFailed = true;
				throw new Error('CA unavailable');
			}
			if (path === '/admin/conditional-access/policies') return response(policies);
			return response({});
		});
		await renderPage();
		expect(screen.getByTestId('list-error')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
		await waitFor(() => expect(screen.getByText('Block risky')).toBeInTheDocument());
	});
});
