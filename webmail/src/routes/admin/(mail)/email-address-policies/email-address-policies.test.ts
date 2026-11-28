import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({
	list: vi.fn(), create: vi.fn(), update: vi.fn(), remove: vi.fn(), reorder: vi.fn(),
	preview: vi.fn(), apply: vi.fn(), status: vi.fn(), match: vi.fn(), domains: vi.fn(),
	users: vi.fn(), mailboxes: vi.fn(), departments: vi.fn(),
}));
vi.mock('$lib/admin/client', () => ({
	adminListEAPolicies: api.list,
	adminCreateEAPolicy: api.create,
	adminUpdateEAPolicy: api.update,
	adminDeleteEAPolicy: api.remove,
	adminReorderEAPolicies: api.reorder,
	adminPreviewEAPolicy: api.preview,
	adminApplyEAPolicy: api.apply,
	adminApplyStatusEAPolicy: api.status,
	adminMatchCountEAPolicy: api.match,
	adminDomainList: api.domains,
	adminUserList: api.users,
	adminMailboxList: api.mailboxes,
	adminDeptTree: api.departments,
}));

import Page from './+page.svelte';

const policies = [
	{
		id: 11, name: 'Engineering', priority: 10, enabled: true,
		overwriteDirectoryAddress: false, primaryTemplate: '{first_initial}{surname}@{domain}',
		additionalTemplates: ['{user_name}@{domain}'], duplicateResolution: 'numeric_suffix',
		condDepartment: ['Engineering'], condDomainIds: [3], condMailboxType: ['personal'],
		condAdOu: ['OU=Engineering'],
	},
	{
		id: 12, name: 'Everyone', priority: 20, enabled: false,
		overwriteDirectoryAddress: false, primaryTemplate: '{user_name}@{domain}',
		additionalTemplates: [], duplicateResolution: 'numeric_suffix',
		condDepartment: null, condDomainIds: null, condMailboxType: null, condAdOu: null,
	},
];

function grant() {
	jmapSession.set({ accounts: {}, primaryAccounts: {}, capabilities: {
		'urn:setjoin:params:jmap:mail': { admin: { consoles: ['mail'], permissions: ['identity.write'] } }
	} } as never);
}

async function renderPage() {
	await renderAsUser(Page, {}, { isAdmin: true });
	grant();
	await waitFor(() => expect(screen.queryByText('Loading…')).not.toBeInTheDocument());
}

describe('email address policy workflows', () => {
	beforeEach(() => {
		resetStores();
		vi.clearAllMocks();
		api.list.mockResolvedValue(policies);
		api.create.mockResolvedValue({ id: 13 });
		api.update.mockResolvedValue(undefined);
		api.remove.mockResolvedValue(undefined);
		api.reorder.mockResolvedValue(undefined);
		api.domains.mockResolvedValue([{ id: 3, name: 'example.test' }, { id: 4, name: 'secondary.test' }]);
		api.departments.mockResolvedValue([{ id: 1, name: 'Company', children: [{ id: 2, name: 'Engineering', children: [] }, { id: 3, name: 'Engineering', children: [] }] }]);
		api.match.mockResolvedValue({ count: 2 });
		api.users.mockResolvedValue([{ id: 5, email: 'alice@example.test', displayName: 'Alice' }]);
		api.mailboxes.mockResolvedValue([{ id: 9, isPrimary: true }]);
		api.preview.mockResolvedValue({ primary: 'aengineer2@example.test', additionals: ['alice@example.test'], collided: true, suffix: '2' });
		api.apply.mockResolvedValue({ jobId: 42 });
		api.status.mockResolvedValue({ status: 'done', applied: 2, total: 2 });
	});
	afterEach(() => resetStores());

	it('loads summaries, reorders policies, and confirms deletion', async () => {
		await renderPage();
		expect(screen.getByText('dept: Engineering · domain: example.test · type: personal · OU: OU=Engineering')).toBeInTheDocument();
		expect(screen.getByText('all mailboxes')).toBeInTheDocument();
		expect(screen.getByText('Off')).toBeInTheDocument();

		await fireEvent.click(screen.getByRole('button', { name: 'Move Engineering down' }));
		await waitFor(() => expect(api.reorder).toHaveBeenCalledWith([12, 11]));

		await fireEvent.click(screen.getAllByRole('button', { name: 'Delete' })[0]);
		const dialog = screen.getByRole('dialog', { name: /Delete this email address policy/ });
		expect(within(dialog).getByText('Engineering')).toBeInTheDocument();
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));
		await waitFor(() => expect(api.remove).toHaveBeenCalledWith(11));
	});

	it('validates and creates a scoped policy without dropping selected conditions', async () => {
		await renderPage();
		await fireEvent.click(screen.getByRole('button', { name: 'New Policy' }));
		const dialog = screen.getByRole('dialog', { name: 'New Policy' });
		await fireEvent.input(within(dialog).getByLabelText('Primary Template'), { target: { value: '' } });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
		expect(within(dialog).getByRole('alert')).toHaveTextContent('Name — required');

		await fireEvent.input(within(dialog).getByLabelText('Name'), { target: { value: ' New staff ' } });
		await fireEvent.input(within(dialog).getByLabelText('Primary Template'), { target: { value: '{user_name}@{domain}' } });
		await fireEvent.input(within(dialog).getByLabelText('Additional Templates'), { target: { value: ' {surname}@{domain} \n\n {given_name}@{domain} ' } });
		await fireEvent.click(within(dialog).getByLabelText('Engineering'));
		await fireEvent.click(within(dialog).getByLabelText('secondary.test'));
		await fireEvent.click(within(dialog).getByLabelText('shared'));
		await fireEvent.input(within(dialog).getByLabelText('AD Organizational Unit Condition'), { target: { value: ' OU=Staff, OU=People ' } });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
		await waitFor(() => expect(api.create).toHaveBeenCalledWith(expect.objectContaining({
			name: 'New staff', primaryTemplate: '{user_name}@{domain}',
			additionalTemplates: ['{surname}@{domain}', '{given_name}@{domain}'],
			condDepartment: ['Engineering'], condDomainIds: [4], condMailboxType: ['shared'],
			condAdOu: ['OU=Staff', 'OU=People'],
		})));
	});

	it('edits, previews, confirms overwrite, and applies a saved policy', async () => {
		await renderPage();
		await fireEvent.click(screen.getAllByRole('button', { name: 'Edit' })[0]);
		const dialog = screen.getByRole('dialog', { name: 'Edit Policy' });
		expect(within(dialog).getByLabelText('Name')).toHaveValue('Engineering');

		await fireEvent.input(within(dialog).getByPlaceholderText('Search a sample user…'), { target: { value: 'ali' } });
		await waitFor(() => expect(api.users).toHaveBeenCalledWith('ali', 8), { timeout: 1200 });
		await fireEvent.click(within(dialog).getByRole('button', { name: /Alice/ }));
		await waitFor(() => expect(within(dialog).getByText('aengineer2@example.test')).toBeInTheDocument());
		expect(within(dialog).getByText('collision → 2')).toBeInTheDocument();

		await fireEvent.click(within(dialog).getByLabelText('Overwrite Directory Address'));
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
		expect(within(dialog).getByText('This will overwrite existing directory addresses for matched mailboxes.')).toBeInTheDocument();
		await fireEvent.click(within(dialog).getByLabelText(/I understand this overrides/));
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
		await waitFor(() => expect(api.update).toHaveBeenCalledWith(11, expect.objectContaining({ overwriteDirectoryAddress: true })));

		await fireEvent.click(screen.getByRole('button', { name: 'Apply Now' }));
		await waitFor(() => expect(api.status).toHaveBeenCalledWith(42), { timeout: 2500 });
		expect(await screen.findByText(/Applied to 2/)).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));
	});

	it('surfaces primary and optional source failures without silently saving', async () => {
		api.list.mockRejectedValueOnce(new Error('policy list unavailable'));
		api.domains.mockRejectedValueOnce(new Error('domains unavailable'));
		api.departments.mockRejectedValueOnce(new Error('departments unavailable'));
		await renderPage();
		expect(screen.getByRole('alert')).toHaveTextContent('policy list unavailable');
		await fireEvent.click(screen.getAllByRole('button', { name: 'New Policy' })[0]);
		expect(screen.getByRole('dialog')).toHaveTextContent("Couldn't load domains");
	});

	it('preserves saved domain ids and surfaces reorder, delete, and update failures', async () => {
		api.domains.mockRejectedValue(new Error('domains unavailable'));
		api.reorder.mockRejectedValueOnce(new Error('reorder denied'));
		await renderPage();
		await fireEvent.click(screen.getByRole('button', { name: 'Move Engineering down' }));
		expect(await screen.findByRole('alert')).toHaveTextContent('reorder denied');

		api.remove.mockRejectedValueOnce(new Error('delete denied'));
		await fireEvent.click(screen.getAllByRole('button', { name: 'Delete' })[0]);
		let dialog = screen.getByRole('dialog', { name: /Delete this email address policy/ });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));
		expect(await screen.findByRole('alert')).toHaveTextContent('delete denied');
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));

		await fireEvent.click(screen.getAllByRole('button', { name: 'Edit' })[0]);
		dialog = screen.getByRole('dialog', { name: 'Edit Policy' });
		expect(dialog).toHaveTextContent("Couldn't load domains");
		await fireEvent.click(within(dialog).getByLabelText('Engineering'));
		await fireEvent.click(within(dialog).getByLabelText('personal'));
		await fireEvent.click(within(dialog).getByLabelText('Overwrite Directory Address'));
		await fireEvent.click(within(dialog).getByLabelText('Overwrite Directory Address'));

		api.update.mockRejectedValueOnce(new Error('update denied'));
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
		expect(await within(dialog).findByRole('alert')).toHaveTextContent('update denied');
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
		await waitFor(() => expect(api.update).toHaveBeenLastCalledWith(11, expect.objectContaining({
			condDepartment: null,
			condDomainIds: [3],
			condMailboxType: null,
		})));
	});

	it('handles empty sample searches, missing mailboxes, and preview failures', async () => {
		await renderPage();
		await fireEvent.click(screen.getAllByRole('button', { name: 'Edit' })[0]);
		const dialog = screen.getByRole('dialog', { name: 'Edit Policy' });
		const search = within(dialog).getByPlaceholderText('Search a sample user…');
		await fireEvent.input(search, { target: { value: '   ' } });
		await new Promise((resolve) => setTimeout(resolve, 400));
		expect(api.users).not.toHaveBeenCalled();

		api.mailboxes.mockResolvedValueOnce([]);
		await fireEvent.input(search, { target: { value: 'alice' } });
		await waitFor(() => expect(api.users).toHaveBeenCalledWith('alice', 8), { timeout: 1200 });
		await fireEvent.click(within(dialog).getByRole('button', { name: /Alice/ }));
		expect(await within(dialog).findByText('User has no mailbox')).toBeInTheDocument();

		api.mailboxes.mockResolvedValueOnce([{ id: 10, isPrimary: false }]);
		api.preview.mockRejectedValueOnce(new Error('preview denied'));
		await fireEvent.input(search, { target: { value: 'alice again' } });
		await waitFor(() => expect(api.users).toHaveBeenCalledWith('alice again', 8), { timeout: 1200 });
		await fireEvent.click(within(dialog).getByRole('button', { name: /Alice/ }));
		expect(await within(dialog).findByText('preview denied')).toBeInTheDocument();
	});

	it('surfaces enqueue and terminal apply-job failures', async () => {
		api.apply.mockRejectedValueOnce(new Error('queue unavailable'));
		await renderPage();
		await fireEvent.click(screen.getByRole('button', { name: 'Apply Now' }));
		expect(await screen.findByText('queue unavailable')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));

		api.status.mockResolvedValueOnce({ status: 'failed', applied: 1, total: 2, error: 'worker rejected policy' });
		await fireEvent.click(screen.getByRole('button', { name: 'Apply Now' }));
		expect(await screen.findByText('worker rejected policy', {}, { timeout: 2500 })).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));

		api.status
			.mockResolvedValueOnce({ status: 'running', applied: 1, total: 2 })
			.mockResolvedValueOnce({ status: 'completed', applied: 2, total: 2 });
		await fireEvent.click(screen.getByRole('button', { name: 'Apply Now' }));
		expect(await screen.findByText(/Applied to 2/, {}, { timeout: 4000 })).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Dismiss' }));

		api.status.mockResolvedValueOnce({ status: 'failed', applied: 0, total: 2 });
		await fireEvent.click(screen.getByRole('button', { name: 'Apply Now' }));
		expect(await screen.findByText('Apply job failed', {}, { timeout: 2500 })).toBeInTheDocument();
	}, 10000);
});
