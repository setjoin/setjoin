import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores, mockSessionLoad } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({
	tree: vi.fn(), users: vi.fn(), create: vi.fn(), update: vi.fn(), remove: vi.fn(), assign: vi.fn(),
}));
vi.mock('$lib/admin/client', () => ({
	adminDeptTree: api.tree, adminUserList: api.users, adminDeptCreate: api.create,
	adminDeptUpdate: api.update, adminDeptDelete: api.remove, adminDeptAssignUser: api.assign,
}));
import Page from './+page.svelte';

const tree = [{ id: 1, name: 'Engineering', path: '/Engineering', ldapOu: 'OU=Engineering', userCount: 1, children: [
	{ id: 2, name: 'Platform', path: '/Engineering/Platform', ldapOu: 'OU=Platform', userCount: 0, children: [] },
]}];
const users = [{ id: 9, email: 'dev@example.test', displayName: 'Dev User', departmentId: 1 }];

function allowWrite() {
	jmapSession.set({
		accounts: { a1: { name: 'admin@example.test', isPrimary: true } },
		primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' },
		capabilities: { 'urn:ietf:params:jmap:core': {}, 'urn:setjoin:params:jmap:mail': { admin: { consoles: ['mail'], permissions: ['users.create'] } } },
	} as never);
}

describe('admin department workflows', () => {
	beforeEach(() => {
		vi.clearAllMocks(); resetStores(); mockSessionLoad();
		api.tree.mockResolvedValue(tree); api.users.mockResolvedValue(users);
		api.create.mockResolvedValue({}); api.update.mockResolvedValue({}); api.remove.mockResolvedValue({}); api.assign.mockResolvedValue({});
	});
	afterEach(() => vi.unstubAllGlobals());

	it('renders a nested tree and supports create, edit, assignment, and delete', async () => {
		await renderAsUser(Page, {}, { isAdmin: true }); allowWrite();
		await waitFor(() => expect(screen.getAllByText('Engineering')).toHaveLength(2));
		expect(screen.getByText('Platform')).toBeInTheDocument();
		expect(screen.getByText('Dev User')).toBeInTheDocument();

		await fireEvent.click(screen.getByRole('button', { name: 'New department' }));
		await fireEvent.input(screen.getByLabelText('Department name'), { target: { value: ' Sales ' } });
		await fireEvent.input(screen.getByLabelText('LDAP OU'), { target: { value: '' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Create' }));
		await waitFor(() => expect(api.create).toHaveBeenCalledWith({ name: 'Sales', parentId: null, ldapOu: 'Sales' }));

		await fireEvent.click(screen.getAllByRole('button', { name: 'Edit' })[0]);
		await fireEvent.input(screen.getByPlaceholderText('Name'), { target: { value: 'Engineering 2' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		await waitFor(() => expect(api.update).toHaveBeenCalledWith(1, expect.objectContaining({ name: 'Engineering 2' })));

		await fireEvent.change(screen.getByRole('combobox'), { target: { value: '2' } });
		await waitFor(() => expect(api.assign).toHaveBeenCalledWith(9, 2));

		await fireEvent.click(screen.getAllByRole('button', { name: 'Delete' })[0]);
		await fireEvent.click(screen.getAllByRole('button', { name: 'Delete' }).at(-1)!);
		await waitFor(() => expect(api.remove).toHaveBeenCalledWith(1));
	});

	it('surfaces independent tree and user-directory failures', async () => {
		api.tree.mockRejectedValueOnce(new Error('tree unavailable'));
		api.users.mockRejectedValueOnce(new Error('directory unavailable'));
		await renderAsUser(Page, {}, { isAdmin: true });
		await waitFor(() => expect(screen.getByText('tree unavailable')).toBeInTheDocument());
		expect(screen.getByText('directory unavailable')).toBeInTheDocument();
	});
});
