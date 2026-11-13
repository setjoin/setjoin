import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/svelte/svelte5';
import { readable } from 'svelte/store';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({
	list: vi.fn(), remove: vi.fn(), catalog: vi.fn(), domains: vi.fn(), audit: vi.fn(),
}));
vi.mock('$lib/admin/roles', () => ({
	adminListRoles: api.list,
	adminDeleteRole: api.remove,
	adminPermissionCatalog: api.catalog,
}));
vi.mock('$lib/admin/client', () => ({ adminDomainList: api.domains, getAuditPolicy: api.audit }));
vi.mock('$app/stores', () => ({ page: readable({ url: new URL('https://setjoin.test/admin/roles') }) }));

import Page from './+page.svelte';

const roles = [
	{ id: 1, name: 'Global admin', description: 'Built in', permissions: ['users.read'], isBuiltin: true, memberCount: 3, sodClass: 'privileged', createdAt: '2026-01-01', updatedAt: '2026-07-01' },
	{ id: 2, name: 'Mail operator', description: 'Custom role', permissions: ['mail.read', 'mail.write', 'audit.read', 'queue.read', 'rules.write', 'extra.read'], isBuiltin: false, memberCount: 2, sodClass: null, createdAt: '2026-01-01', updatedAt: '2026-07-02' },
];

function grant() {
	jmapSession.set({ accounts: {}, primaryAccounts: {}, capabilities: {
		'urn:setjoin:params:jmap:mail': { admin: { consoles: ['system'], permissions: ['roles.manage'] } }
	} } as never);
}

async function renderPage() {
	await renderAsUser(Page, {}, { isAdmin: true });
	grant();
	await waitFor(() => expect(screen.queryByText('Loading…')).not.toBeInTheDocument());
}

describe('admin roles page workflows', () => {
	beforeEach(() => {
		resetStores();
		vi.clearAllMocks();
		api.list.mockResolvedValue(roles);
		api.remove.mockResolvedValue(undefined);
		api.catalog.mockResolvedValue([
			{ key: 'users.read', category: 'Users' }, { key: 'mail.read', category: 'Mail' },
			{ key: 'mail.write', category: 'Delivery' }, { key: 'audit.read', category: 'Audit' },
			{ key: 'queue.read', category: 'Queue' }, { key: 'rules.write', category: 'Rules' },
			{ key: 'extra.read', category: 'Other' },
		]);
		api.domains.mockResolvedValue([{ id: 9, name: 'example.test' }]);
		api.audit.mockResolvedValue({ reasonRequiredAreas: [] });
	});
	afterEach(() => resetStores());

	it('loads, categorizes, filters, and compares roles', async () => {
		await renderPage();
		expect(screen.getByText('Global admin')).toBeInTheDocument();
		expect(screen.getByText('+1')).toBeInTheDocument();
		expect(screen.getByText('(6)')).toBeInTheDocument();

		await fireEvent.input(screen.getByPlaceholderText('Search roles or permissions'), { target: { value: 'mail.write' } });
		expect(screen.queryByText('Global admin')).not.toBeInTheDocument();
		expect(screen.getByText('Mail operator')).toBeInTheDocument();
		await fireEvent.input(screen.getByPlaceholderText('Search roles or permissions'), { target: { value: '' } });

		await fireEvent.click(screen.getByRole('button', { name: 'Pin Global admin to comparison slot A' }));
		await fireEvent.click(screen.getByRole('button', { name: 'Pin Mail operator to comparison slot B' }));
		expect(screen.getByText(/Compare: Global admin/)).toBeInTheDocument();
		expect(screen.getByText(/mail\.read/)).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Pin Global admin to comparison slot A' }));
		expect(screen.queryByText(/Compare: Global admin/)).not.toBeInTheDocument();
	});

	it('opens create/edit/clone surfaces and deletes a custom role', async () => {
		await renderPage();
		await fireEvent.click(screen.getByRole('button', { name: 'New role' }));
		expect(screen.getByRole('dialog')).toBeInTheDocument();
		await fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }));

		await fireEvent.click(screen.getAllByRole('button', { name: 'Clone' })[1]);
		expect(screen.getByRole('dialog')).toBeInTheDocument();
		await fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }));

		await fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
		expect(screen.getByRole('dialog')).toBeInTheDocument();
		await fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Cancel' }));

		await fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
		const dialog = screen.getByRole('dialog', { name: 'Delete role' });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));
		await waitFor(() => expect(api.remove).toHaveBeenCalledWith(2, undefined));
	});

	it('surfaces a list failure while optional metadata failures degrade safely', async () => {
		api.list.mockRejectedValueOnce(new Error('roles unavailable'));
		api.catalog.mockRejectedValueOnce(new Error('catalog unavailable'));
		api.domains.mockRejectedValueOnce(new Error('domains unavailable'));
		api.audit.mockRejectedValueOnce(new Error('policy unavailable'));
		await renderPage();
		expect(screen.getByRole('alert')).toHaveTextContent('roles unavailable');
	});
});
