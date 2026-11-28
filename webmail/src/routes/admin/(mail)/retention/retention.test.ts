import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({
	policies: vi.fn(), create: vi.fn(), update: vi.fn(), remove: vi.fn(),
	logs: vi.fn(), setLogs: vi.fn(), prune: vi.fn(), getConfig: vi.fn(), setConfig: vi.fn(),
}));
vi.mock('$lib/admin/client', () => ({
	adminRetentionPolicies: api.policies,
	adminRetentionCreate: api.create,
	adminRetentionUpdate: api.update,
	adminRetentionDelete: api.remove,
	adminLogRetention: api.logs,
	adminLogRetentionSet: api.setLogs,
	adminRetentionPrune: api.prune,
	adminConfigGet: api.getConfig,
	adminConfigSet: api.setConfig,
}));
import Page from './+page.svelte';

const policies = [
	{ id: 1, name: 'Finance', description: 'Seven years', retainDays: 2555, action: 'delete', isDefault: true, domainId: null },
	{ id: 2, name: 'Legal hold', description: null, retainDays: null, action: 'hold', isDefault: false, domainId: 8 },
];

function grant() {
	jmapSession.set({
		accounts: {}, primaryAccounts: {},
		capabilities: { 'urn:setjoin:params:jmap:mail': { admin: { consoles: ['mail'], permissions: ['compliance.write', 'system.config'] } } },
	} as never);
}

async function renderPage() {
	const rendered = await renderAsUser(Page, {}, { isAdmin: true });
	grant();
	await screen.findByText('Finance');
	return rendered;
}

describe('admin retention workflows', () => {
	beforeEach(() => {
		resetStores();
		vi.clearAllMocks();
		api.policies.mockResolvedValue(policies);
		api.logs.mockResolvedValue({ messageTraceDays: 30, mailboxAuditLogDays: 90, authEventDays: 30 });
		api.getConfig.mockImplementation(async (key: string) => ({ value: key === 'spam_purge_days' ? '45' : 60 }));
		api.create.mockResolvedValue({ id: 3 });
		api.update.mockResolvedValue({});
		api.remove.mockResolvedValue({});
		api.setLogs.mockResolvedValue({});
		api.setConfig.mockResolvedValue({});
		api.prune.mockResolvedValue([{ table: 'emails', deleted: 4 }]);
	});
	afterEach(() => resetStores());

	it('loads numeric and string settings and performs the maintenance actions', async () => {
		await renderPage();
		expect(screen.getByLabelText('Auto-purge after (days)')).toHaveValue(60);
		expect(screen.getByLabelText('Spam auto-purge (days)')).toHaveValue(45);
		expect(screen.getByText('Forever')).toBeInTheDocument();
		expect(screen.getAllByText('Default')).toHaveLength(2);

		await fireEvent.input(screen.getByLabelText('Message trace (days)'), { target: { value: '14' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Save log settings' }));
		await waitFor(() => expect(api.setLogs).toHaveBeenCalledWith({ messageTraceDays: 14, mailboxAuditLogDays: 90, authEventDays: 30 }));

		await fireEvent.input(screen.getByLabelText('Auto-purge after (days)'), { target: { value: '10' } });
		await fireEvent.input(screen.getByLabelText('Spam auto-purge (days)'), { target: { value: '20' } });
		await fireEvent.click(screen.getAllByRole('button', { name: 'Save' })[0]);
		await waitFor(() => expect(api.setConfig).toHaveBeenCalledWith('deleted_items_purge_days', '10'));
		expect(api.setConfig).toHaveBeenCalledWith('spam_purge_days', '20');

		// S19 hardening: prune is gated behind the shared typed-confirm dialog.
		await fireEvent.click(screen.getByRole('button', { name: 'Run prune now' }));
		const pruneDialog = await screen.findByRole('dialog');
		expect(within(pruneDialog).getByRole('button', { name: 'Run prune' })).toBeDisabled();
		await fireEvent.input(within(pruneDialog).getByLabelText('Type PRUNE to confirm'), { target: { value: 'PRUNE' } });
		await fireEvent.click(within(pruneDialog).getByRole('button', { name: 'Run prune' }));
		expect(await screen.findByText('emails: 4 rows deleted')).toBeInTheDocument();
	});

	it('creates from a template and edits a forever policy', async () => {
		await renderPage();
		await fireEvent.change(screen.getByRole('combobox'), { target: { value: 'HR 1-Year' } });
		let dialog = screen.getByRole('dialog');
		expect(within(dialog).getByLabelText('Name')).toHaveValue('HR 1-Year');
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
		await waitFor(() => expect(api.create).toHaveBeenCalledWith(expect.objectContaining({ name: 'HR 1-Year', retainDays: 365 })));

		await fireEvent.click(screen.getAllByRole('button', { name: 'Edit' })[1]);
		dialog = screen.getByRole('dialog');
		expect(within(dialog).getByLabelText('Keep forever')).toBeChecked();
		await fireEvent.input(within(dialog).getByLabelText('Description'), { target: { value: 'Preserve' } });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
		await waitFor(() => expect(api.update).toHaveBeenCalledWith(2, expect.objectContaining({ retainDays: null, description: 'Preserve' })));
	});

	it('validates create input and deletes an existing policy', async () => {
		await renderPage();
		await fireEvent.click(screen.getByRole('button', { name: 'New policy' }));
		const dialog = screen.getByRole('dialog');
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
		expect(screen.getByText('Name is required')).toBeInTheDocument();

		await fireEvent.input(within(dialog).getByLabelText('Name'), { target: { value: 'Short' } });
		await fireEvent.input(within(dialog).getByLabelText('Retention (days)'), { target: { value: '0' } });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
		expect(screen.getByText(/Retention days must be a positive number/)).toBeInTheDocument();

		await fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
		// S19 hardening: policy deletion is gated behind the typed-confirm dialog.
		await fireEvent.click(screen.getAllByRole('button', { name: 'Delete' })[0]);
		const deleteDialog = await screen.findByRole('dialog');
		expect(within(deleteDialog).getByRole('button', { name: 'Delete policy' })).toBeDisabled();
		await fireEvent.input(within(deleteDialog).getByLabelText('Type DELETE to confirm'), { target: { value: 'DELETE' } });
		await fireEvent.click(within(deleteDialog).getByRole('button', { name: 'Delete policy' }));
		await waitFor(() => expect(api.remove).toHaveBeenCalledWith(1));
	});

	it('uses config fallbacks and surfaces load and mutation failures', async () => {
		api.getConfig.mockRejectedValue(new Error('optional config unavailable'));
		api.policies.mockRejectedValueOnce(new Error('retention unavailable'));
		await renderAsUser(Page, {}, { isAdmin: true });
		expect(await screen.findByText('retention unavailable')).toBeInTheDocument();

		api.policies.mockResolvedValue(policies);
		api.setLogs.mockRejectedValueOnce('offline');
		await renderPage();
		await fireEvent.click(screen.getAllByRole('button', { name: 'Save log settings' }).at(-1)!);
		expect(await screen.findByText('Save failed')).toBeInTheDocument();
	});
});
