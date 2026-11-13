import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({
	list: vi.fn(), create: vi.fn(), update: vi.fn(), remove: vi.fn(),
	folders: vi.fn(), createFolder: vi.fn(), deleteFolder: vi.fn(),
	importMailbox: vi.fn(), exportMailbox: vi.fn(), users: vi.fn()
}));

vi.mock('$lib/admin/client', () => ({
	adminMailboxList: api.list,
	adminMailboxCreate: api.create,
	adminMailboxUpdate: api.update,
	adminMailboxDelete: api.remove,
	adminMailboxFolders: api.folders,
	adminMailboxCreateFolder: api.createFolder,
	adminMailboxDeleteFolder: api.deleteFolder,
	adminMailboxImport: api.importMailbox,
	adminMailboxExport: api.exportMailbox,
	adminUserList: api.users
}));

const downloadBlob = vi.hoisted(() => vi.fn());
vi.mock('$lib/utils/downloadBlob', () => ({ downloadBlob }));

import Page from './+page.svelte';

const mailbox = {
	id: 7, userId: 3, userEmail: 'alice@example.test', name: 'Primary', role: 'inbox',
	quotaBytes: 1024, usedBytes: 512, enabled: true, isPrimary: true,
	deletedPurgeDays: 30, spamPurgeDays: 14, litigationHold: false
};

function grantPermissions() {
	jmapSession.set({
		accounts: {}, primaryAccounts: {}, capabilities: {
			'urn:setjoin:params:jmap:mail': { admin: { consoles: ['mail'], permissions: ['users.create'] } }
		}
	} as never);
}

async function renderPage() {
	const rendered = await renderAsUser(Page, {}, { isAdmin: true });
	grantPermissions();
	await waitFor(() => expect(screen.queryByText('Loading…')).not.toBeInTheDocument());
	await waitFor(() => expect(screen.getByRole('button', { name: 'New mailbox' })).toBeEnabled());
	return rendered;
}

describe('admin mailboxes workflows', () => {
	beforeEach(() => {
		resetStores();
		vi.clearAllMocks();
		api.list.mockResolvedValue([mailbox]);
		api.users.mockResolvedValue([{ id: 3, email: 'alice@example.test', displayName: 'Alice' }]);
		api.folders.mockResolvedValue([{ id: 'f1', path: 'Projects', role: null, totalCount: 4, unreadCount: 1 }]);
		api.create.mockResolvedValue({});
		api.update.mockResolvedValue({});
		api.remove.mockResolvedValue({});
		api.createFolder.mockResolvedValue({});
		api.deleteFolder.mockResolvedValue({});
		api.importMailbox.mockResolvedValue({ imported: 1, failed: [{ file: 'bad.eml', error: 'invalid' }] });
		api.exportMailbox.mockResolvedValue(new Blob(['mail']));
	});

	afterEach(() => resetStores());

	it('searches, creates, and edits a mailbox with bounded values', async () => {
		await renderPage();
		expect(screen.getByText('alice@example.test')).toBeInTheDocument();

		const search = screen.getByPlaceholderText('Search mailboxes…');
		await fireEvent.input(search, { target: { value: 'alice' } });
		await fireEvent.keyDown(search, { key: 'Enter' });
		await waitFor(() => expect(api.list).toHaveBeenLastCalledWith('alice'));

		await fireEvent.click(screen.getByRole('button', { name: 'New mailbox' }));
		await fireEvent.change(screen.getByLabelText('User'), { target: { value: '3' } });
		await fireEvent.input(screen.getByLabelText('Name'), { target: { value: ' Project ' } });
		await fireEvent.input(screen.getByLabelText('Role'), { target: { value: 'shared' } });
		await fireEvent.input(screen.getByLabelText('Quota (bytes)'), { target: { value: '2048' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Create' }));
		await waitFor(() => expect(api.create).toHaveBeenCalledWith({ userId: 3, name: 'Project', role: 'shared', quotaBytes: 2048 }));

		await fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
		const names = screen.getAllByLabelText('Name');
		await fireEvent.input(names.at(-1)!, { target: { value: 'Renamed' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		await waitFor(() => expect(api.update).toHaveBeenCalledWith(7, expect.objectContaining({ name: 'Renamed', quotaBytes: 1024, enabled: true })));
	});

	it('manages folders and requires confirmation before deletion', async () => {
		await renderPage();
		await fireEvent.click(screen.getByRole('button', { name: 'Folders' }));
		await waitFor(() => expect(screen.getByText('Projects')).toBeInTheDocument());
		await fireEvent.input(screen.getByPlaceholderText('New folder name'), { target: { value: ' Finance ' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Add folder' }));
		await waitFor(() => expect(api.createFolder).toHaveBeenCalledWith(7, { name: 'Finance' }));
		await fireEvent.click(screen.getAllByRole('button', { name: 'Delete' }).at(-1)!);
		await waitFor(() => expect(api.deleteFolder).toHaveBeenCalledWith(7, 'f1'));
		await fireEvent.click(screen.getAllByRole('button', { name: 'Close' }).at(-1)!);

		await fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
		expect(screen.getByText(/All messages will be lost/)).toBeInTheDocument();
		await fireEvent.click(screen.getAllByRole('button', { name: 'Delete' }).at(-1)!);
		await waitFor(() => expect(api.remove).toHaveBeenCalledWith(7));
	});

	it('imports with per-file evidence and exports the selected format', async () => {
		const { container } = await renderPage();
		await fireEvent.click(screen.getByRole('button', { name: 'Import' }));
		const file = new File(['message'], 'mail.eml', { type: 'message/rfc822' });
		const picker = container.querySelector('input[type="file"]') as HTMLInputElement;
		Object.defineProperty(picker, 'files', { configurable: true, value: [file] });
		await fireEvent.change(picker);
		await fireEvent.click(screen.getAllByRole('button', { name: 'Import' }).at(-1)!);
		await waitFor(() => expect(screen.getByText('Imported: 1')).toBeInTheDocument());
		expect(screen.getByText('bad.eml: invalid')).toBeInTheDocument();
		await fireEvent.click(screen.getAllByRole('button', { name: 'Close' }).at(-1)!);

		await fireEvent.click(screen.getByRole('button', { name: 'Export' }));
		await fireEvent.change(screen.getByLabelText('Format'), { target: { value: 'mbox' } });
		await fireEvent.click(screen.getAllByRole('button', { name: 'Export' }).at(-1)!);
		await waitFor(() => expect(api.exportMailbox).toHaveBeenCalledWith(7, 'mbox'));
		expect(downloadBlob).toHaveBeenCalledWith(expect.any(Blob), 'export-Primary.mbox');
	});

	it('surfaces mailbox and user-loading failures without opening unsafe flows', async () => {
		api.list.mockRejectedValueOnce(new Error('mailbox unavailable'));
		api.users.mockRejectedValueOnce(new Error('directory unavailable'));
		await renderPage();
		expect(screen.getByText('mailbox unavailable')).toBeInTheDocument();
		expect(screen.getByText('directory unavailable')).toBeInTheDocument();
		expect(screen.getByText('No mailboxes found.')).toBeInTheDocument();
	});
});
