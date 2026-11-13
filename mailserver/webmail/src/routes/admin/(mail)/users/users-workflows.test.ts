import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({
	fetch: vi.fn(), list: vi.fn(), create: vi.fn(), update: vi.fn(), remove: vi.fn(), resetPassword: vi.fn(),
	aliases: vi.fn(), addAlias: vi.fn(), removeAlias: vi.fn(), quota: vi.fn(), setQuota: vi.fn(), importCSV: vi.fn(), depts: vi.fn(),
	lifecyclePreview: vi.fn(), lifecycleTransition: vi.fn(), retained: vi.fn(), purgeSchedule: vi.fn(),
}));
vi.mock('$lib/admin/client', () => ({
	adminFetch: api.fetch, adminUserList: api.list, adminUserCreate: api.create, adminUserUpdate: api.update,
	adminUserDelete: api.remove, adminUserResetPassword: api.resetPassword, adminUserAliases: api.aliases,
	adminUserAddAlias: api.addAlias, adminUserRemoveAlias: api.removeAlias, adminUserQuota: api.quota,
	adminUserSetQuota: api.setQuota, adminUserImportCSV: api.importCSV, adminDeptTree: api.depts,
	adminMailboxLifecyclePreview: api.lifecyclePreview, adminMailboxLifecycleTransition: api.lifecycleTransition,
	adminRetainedMailboxes: api.retained, adminMailboxPurgeSchedule: api.purgeSchedule,
}));
const goto = vi.hoisted(() => vi.fn());
vi.mock('$app/navigation', () => ({ goto }));
import Page from './+page.svelte';

const user = { id: 5, email: 'alice@example.test', displayName: 'Alice', enabled: true, isLocalAdmin: false, departmentId: 2, createdAt: '2026-01-01T00:00:00Z', manageable: true, isSelf: false, mailboxId: 50 };
const permissions = ['users.create', 'users.suspend', 'users.delete', 'users.password_reset', 'users.impersonate', 'roles.manage'];
function grant() {
	jmapSession.set({ accounts: {}, primaryAccounts: {}, capabilities: { 'urn:setjoin:params:jmap:mail': { admin: { consoles: ['mail'], permissions } } } } as never);
}
async function renderPage() {
	const r = await renderAsUser(Page, {}, { isAdmin: true }); grant();
	await waitFor(() => expect(screen.queryByText('Loading…')).not.toBeInTheDocument());
	await waitFor(() => expect(screen.getByRole('button', { name: 'Add user' })).toBeEnabled());
	return r;
}

describe('admin users workflows', () => {
	beforeEach(() => {
		resetStores(); vi.clearAllMocks();
		api.list.mockResolvedValue([user]);
		api.depts.mockResolvedValue([{ id: 1, name: 'Company', path: 'Company', children: [{ id: 2, name: 'Engineering', path: 'Company / Engineering', children: [] }] }]);
		api.create.mockResolvedValue({}); api.update.mockResolvedValue({}); api.remove.mockResolvedValue({}); api.resetPassword.mockResolvedValue({});
		api.aliases.mockResolvedValue([{ id: 9, email: 'alias@example.test', isPrimary: false }]);
		api.addAlias.mockResolvedValue({}); api.removeAlias.mockResolvedValue({});
		api.quota.mockResolvedValue({ quotaBytes: 4096, usedBytes: 1024, sendingQuotaDay: 50, sendingSentToday: 3 });
		api.setQuota.mockResolvedValue({});
		api.importCSV.mockResolvedValue({ created: 1, failed: [{ row: 3, email: 'bad@example.test', error: 'duplicate' }] });
		api.lifecyclePreview.mockResolvedValue({ state: { generation: '1', binding: 'bound', access: 'active', delivery: 'accepting' }, messageCount: 12, previewDigest: 'a'.repeat(64) });
		api.lifecycleTransition.mockResolvedValue({}); api.retained.mockResolvedValue([]); api.purgeSchedule.mockResolvedValue({});
		api.fetch.mockResolvedValue({ ok: true, json: async () => [{ id: 11, name: 'Phone', createdAt: '2026-01-01T00:00:00Z', lastUsedAt: null, revokedAt: null }] });
	});
	afterEach(() => resetStores());

	it('validates and creates a normalized user while keeping server errors inside the dialog', async () => {
		await renderPage();
		await fireEvent.click(screen.getByRole('button', { name: 'Add user' }));
		const dialog = screen.getByRole('dialog');
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Create' }));
		expect(within(dialog).getByText('Email is required')).toBeInTheDocument();
		await fireEvent.input(within(dialog).getByLabelText(/Email/), { target: { value: 'new@example.test' } });
		await fireEvent.input(within(dialog).getByLabelText('Display name'), { target: { value: 'New User' } });
		await fireEvent.input(within(dialog).getByLabelText('Password'), { target: { value: 'correct horse' } });
		await fireEvent.click(within(dialog).getByLabelText('Local admin'));
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Create' }));
		await waitFor(() => expect(api.create).toHaveBeenCalledWith({ email: 'new@example.test', displayName: 'New User', password: 'correct horse', isLocalAdmin: true }));
	});

	it('updates profile, status, admin role, and password policy', async () => {
		const { container } = await renderPage();
		const switches = [...container.querySelectorAll('input[role="switch"]')];
		await fireEvent.click(switches[0]);
		await waitFor(() => expect(api.update).toHaveBeenCalledWith(5, { enabled: false }));
		const refreshedSwitches = [...container.querySelectorAll('input[role="switch"]')];
		await fireEvent.click(refreshedSwitches[1]);
		await waitFor(() => expect(api.update).toHaveBeenCalledWith(5, { isLocalAdmin: true }));

		await fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
		let dialog = screen.getByRole('dialog');
		await fireEvent.input(within(dialog).getByLabelText('Display name'), { target: { value: 'Alice Updated' } });
		await fireEvent.change(within(dialog).getByLabelText('Department'), { target: { value: '1' } });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
		await waitFor(() => expect(api.update).toHaveBeenCalledWith(5, { displayName: 'Alice Updated', departmentId: 1 }));

		await fireEvent.click(screen.getByRole('button', { name: 'Password' }));
		dialog = screen.getByRole('dialog');
		await fireEvent.input(within(dialog).getByLabelText('New password'), { target: { value: 'new secure password' } });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Reset' }));
		await waitFor(() => expect(api.resetPassword).toHaveBeenCalledWith(5, 'new secure password', true));
	});

	it('adds and removes aliases and persists quota bounds', async () => {
		await renderPage();
		await fireEvent.click(screen.getByRole('button', { name: 'Aliases' }));
		let dialog = screen.getByRole('dialog');
		expect(within(dialog).getByText('alias@example.test')).toBeInTheDocument();
		await fireEvent.input(within(dialog).getByPlaceholderText('new@domain.com'), { target: { value: ' second@example.test ' } });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Add' }));
		await waitFor(() => expect(api.addAlias).toHaveBeenCalledWith(5, 'second@example.test'));
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Remove' }));
		await waitFor(() => expect(api.removeAlias).toHaveBeenCalledWith(5, 9));
		await fireEvent.click(within(dialog).getAllByRole('button', { name: 'Close' }).at(-1)!);

		await fireEvent.click(screen.getByRole('button', { name: 'Quota' }));
		dialog = await screen.findByRole('dialog');
		await fireEvent.input(within(dialog).getByLabelText('Storage quota (bytes)'), { target: { value: '8192' } });
		await fireEvent.input(within(dialog).getByLabelText('Daily send limit'), { target: { value: '75' } });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
		await waitFor(() => expect(api.setQuota).toHaveBeenCalledWith(5, { quotaBytes: 8192, sendingQuotaDay: 75 }));
	});

	it('imports CSV with row evidence and routes removal through explicit mailbox lifecycle', async () => {
		const { container } = await renderPage();
		await fireEvent.click(screen.getByRole('button', { name: 'Import CSV' }));
		const input = container.querySelector('#import-csv') as HTMLInputElement;
		const file = new File(['email,password\na@b.test,abcdefgh'], 'users.csv', { type: 'text/csv' });
		Object.defineProperty(input, 'files', { configurable: true, value: [file] });
		await fireEvent.change(input);
		await fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Import' }));
		await waitFor(() => expect(screen.getByText('Created: 1')).toBeInTheDocument());
		expect(screen.getByText(/Row 3.*duplicate/)).toBeInTheDocument();
		await fireEvent.click(within(screen.getByRole('dialog')).getAllByRole('button', { name: 'Close' }).at(-1)!);

		await fireEvent.click(screen.getByRole('button', { name: 'Mailbox lifecycle' }));
		const lifecycle = await screen.findByRole('dialog');
		expect(within(lifecycle).getByText(/preserves the binding/)).toBeInTheDocument();
		await fireEvent.input(within(lifecycle).getByLabelText('Audit reason'), { target: { value: 'Departed employee' } });
		await fireEvent.click(within(lifecycle).getByRole('button', { name: 'Suspend mailbox' }));
		await waitFor(() => expect(api.lifecycleTransition).toHaveBeenCalledWith(50, 'suspend', '1', 'Departed employee'));
		expect(api.remove).not.toHaveBeenCalled();
	});

	it('lists and explicitly revokes an app password', async () => {
		await renderPage();
		await fireEvent.click(screen.getByRole('button', { name: 'Keys' }));
		await waitFor(() => expect(screen.getByText('Active')).toBeInTheDocument());
		await fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Revoke' }));
		expect(screen.getByText(/lose access/)).toBeInTheDocument();
		await fireEvent.click(within(screen.getAllByRole('dialog').at(-1)!).getByRole('button', { name: 'Revoke' }));
		await waitFor(() => expect(api.fetch).toHaveBeenCalledWith('/admin/users/5/app-passwords/11', { method: 'DELETE' }));
	});
});
