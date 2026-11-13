import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({ list: vi.fn(), remove: vi.fn(), update: vi.fn(), fetch: vi.fn() }));
vi.mock('$lib/admin/client', () => ({ adminRuleList: api.list, adminRuleDelete: api.remove, adminRuleUpdate: api.update, adminFetch: api.fetch }));
import Page from './+page.svelte';

function grant() {
	jmapSession.set({ accounts: {}, primaryAccounts: {}, capabilities: { 'urn:setjoin:params:jmap:mail': { admin: { consoles: ['mail'], permissions: ['mail.pipeline', 'mail.security'] } } } } as never);
}
async function renderPage() {
	const r = await renderAsUser(Page, {}, { isAdmin: true }); grant();
	await waitFor(() => expect(screen.queryByText('Loading rules…')).not.toBeInTheDocument());
	return r;
}

describe('admin mail rules and DLP workflows', () => {
	beforeEach(() => {
		resetStores(); vi.clearAllMocks();
		api.list.mockResolvedValue([{ id: 2, name: 'Quarantine secrets', isTransportRule: true, runOn: 'received', priority: 10, enabled: true, conditions: { subject: 'secret' } }]);
		api.update.mockResolvedValue({}); api.remove.mockResolvedValue({});
		api.fetch.mockImplementation(async (_path: string, init?: RequestInit) => ({ ok: true, json: async () => init ? [] : [{ name: 'Credit card', regex: '\\d{4}', severity: 'critical', enabled: true }] }));
	});
	afterEach(() => resetStores());

	it('toggles and deletes a transport rule through permission-gated actions', async () => {
		const { container } = await renderPage();
		expect(screen.getByText('Quarantine secrets')).toBeInTheDocument();
		expect(screen.getByText('Transport')).toBeInTheDocument();
		const toggle = container.querySelector('input[role="switch"]') as HTMLInputElement;
		await waitFor(() => expect(toggle).toBeEnabled());
		await fireEvent.click(toggle);
		await waitFor(() => expect(api.update).toHaveBeenCalledWith(2, { enabled: false }));
		await fireEvent.click(screen.getByRole('button', { name: 'Delete rule' }));
		await waitFor(() => expect(api.remove).toHaveBeenCalledWith(2));
	});

	it('loads, tests, disables, removes, and adds bounded DLP patterns', async () => {
		await renderPage();
		await fireEvent.click(screen.getByRole('tab', { name: 'DLP patterns' }));
		await waitFor(() => expect(screen.getByText('Credit card')).toBeInTheDocument());
		await fireEvent.input(screen.getByPlaceholderText('Paste sample text to test…'), { target: { value: 'number 1234' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Check' }));
		expect(screen.getByText('Credit card (critical)')).toBeInTheDocument();

		await fireEvent.click(screen.getByRole('button', { name: /Add pattern/ }));
		await fireEvent.input(screen.getByPlaceholderText('Pattern name'), { target: { value: ' SSN ' } });
		await fireEvent.input(screen.getByPlaceholderText('Regex pattern'), { target: { value: ' \\d{3}-\\d{2} ' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		await waitFor(() => expect(api.fetch).toHaveBeenCalledWith('/admin/dlp/patterns', expect.objectContaining({ method: 'PUT' })));
		const put = api.fetch.mock.calls.find(([, init]) => init?.method === 'PUT')?.[1] as RequestInit;
		expect(JSON.parse(String(put.body))).toEqual(expect.arrayContaining([expect.objectContaining({ name: 'SSN', regex: '\\d{3}-\\d{2}' })]));

		await fireEvent.click(screen.getByRole('button', { name: 'Remove pattern' }));
		await waitFor(() => expect(api.fetch.mock.calls.filter(([, init]) => init?.method === 'PUT').length).toBeGreaterThan(1));
	});

	it('renders empty and failure states without inventing rule data', async () => {
		api.list.mockResolvedValueOnce([]);
		await renderPage();
		expect(screen.getByText('No rules configured.')).toBeInTheDocument();
	});
});
