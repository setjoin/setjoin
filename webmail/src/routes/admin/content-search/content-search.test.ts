import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({ fetch: vi.fn() }));
vi.mock('$lib/admin/client', () => ({ adminFetch: api.fetch }));
import Page from './+page.svelte';

const results = [
	{ id: 1, subject: 'Phishing notice', from: 'attacker@test', mailbox: 'alice@test', receivedAt: '2026-01-01T00:00:00Z' },
	{ id: 2, subject: 'Follow-up', from: 'bob@test', mailbox: 'bob@test', receivedAt: '2026-01-02T00:00:00Z' },
];

function res(body: unknown, ok = true, status = 200) {
	return { ok, status, json: async () => body } as Response;
}

function grant() {
	jmapSession.set({ accounts: {}, primaryAccounts: {}, capabilities: { 'urn:setjoin:params:jmap:mail': { admin: { consoles: ['mail'], permissions: ['compliance.write'] } } } } as never);
}

describe('admin content search', () => {
	beforeEach(() => { resetStores(); vi.clearAllMocks(); api.fetch.mockResolvedValue(res({ results })); });
	afterEach(() => resetStores());

	it('searches exact filters from Enter and renders results', async () => {
		await renderAsUser(Page, {}, { isAdmin: true }); grant();
		await fireEvent.input(screen.getByPlaceholderText('Keywords (body/subject search)'), { target: { value: 'phishing' } });
		await fireEvent.input(screen.getByPlaceholderText('From address'), { target: { value: 'attacker@test' } });
		const dates = screen.getAllByDisplayValue('') as HTMLInputElement[];
		const dateInputs = dates.filter((input) => input.type === 'date');
		await fireEvent.input(dateInputs[0], { target: { value: '2026-01-01' } });
		await fireEvent.input(dateInputs[1], { target: { value: '2026-01-31' } });
		await fireEvent.keyDown(screen.getByPlaceholderText('Keywords (body/subject search)'), { key: 'Enter' });
		expect(await screen.findByText('Phishing notice')).toBeInTheDocument();
		const [, options] = api.fetch.mock.calls[0] as [string, RequestInit];
		expect(JSON.parse(String(options.body))).toEqual({ keywords: 'phishing', fromAddr: 'attacker@test', dateFrom: '2026-01-01', dateTo: '2026-01-31' });
	});

	it('requires a selection and a meaningful reason, then reports held messages', async () => {
		api.fetch.mockResolvedValueOnce(res({ results })).mockResolvedValueOnce(res({ deleted: 1, held: 1, notFound: 0 }));
		await renderAsUser(Page, {}, { isAdmin: true }); grant();
		await fireEvent.input(screen.getByPlaceholderText('Keywords (body/subject search)'), { target: { value: 'mail' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Search' }));
		await screen.findByText('Phishing notice');
		const checks = screen.getAllByRole('checkbox');
		await fireEvent.click(checks[1]);
		await fireEvent.click(screen.getByRole('button', { name: 'Delete selected (1)' }));
		const dialog = screen.getByRole('dialog');
		const confirm = within(dialog).getByRole('button', { name: 'Confirm delete' });
		expect(confirm).toBeDisabled();
		await fireEvent.input(within(dialog).getByLabelText('Reason (required, min 10 characters)'), { target: { value: 'confirmed phishing cleanup' } });
		await fireEvent.click(confirm);
		expect(await within(dialog).findByText(/Deleted 1 message\./)).toBeInTheDocument();
		expect(within(dialog).getByText(/1 message skipped/)).toBeInTheDocument();
		expect(screen.queryByText('Phishing notice')).toBeNull();
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Done' }));
		await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
	});

	it('toggles a selection off and surfaces search/delete transport failures', async () => {
		api.fetch.mockResolvedValueOnce(res({ results }));
		await renderAsUser(Page, {}, { isAdmin: true }); grant();
		await fireEvent.input(screen.getByPlaceholderText('From address'), { target: { value: 'bob@test' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Search' }));
		await screen.findByText('Follow-up');
		const checks = screen.getAllByRole('checkbox');
		await fireEvent.click(checks[1]);
		await fireEvent.click(checks[1]);
		expect(screen.getByRole('button', { name: 'Delete selected (0)' })).toBeDisabled();

		api.fetch.mockRejectedValueOnce(new Error('search offline'));
		await fireEvent.click(screen.getByRole('button', { name: 'Search' }));
		expect(await screen.findByRole('alert')).toHaveTextContent('search offline');

		api.fetch.mockResolvedValueOnce(res({ results }));
		await fireEvent.click(screen.getByRole('button', { name: 'Search' }));
		await screen.findByText('Phishing notice');
		await fireEvent.click(screen.getAllByRole('checkbox')[1]);
		await fireEvent.click(screen.getByRole('button', { name: 'Delete selected (1)' }));
		await fireEvent.input(screen.getByLabelText('Reason (required, min 10 characters)'), { target: { value: 'authorized cleanup' } });
		api.fetch.mockResolvedValueOnce(res({}, false, 503));
		await fireEvent.click(screen.getByRole('button', { name: 'Confirm delete' }));
		expect(await screen.findByRole('alert')).toHaveTextContent('Delete failed (503)');
	});
});
