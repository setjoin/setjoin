import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores, mockSessionLoad } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({
	list: vi.fn(), create: vi.fn(), update: vi.fn(), remove: vi.fn(),
}));
vi.mock('$lib/admin/client', () => ({
	adminDomainList: api.list,
	adminDomainCreate: api.create,
	adminDomainUpdate: api.update,
	adminDomainDelete: api.remove,
}));
import Page from './+page.svelte';

const domain = {
	id: 7, name: 'example.test', isLocal: true, isPrimary: true,
	dmarcPolicy: 'reject', mtaStsPolicy: 'enforce', maxMessageBytes: 10485760,
};

function allowWrite() {
	jmapSession.set({
		accounts: { a1: { name: 'admin@example.test', isPrimary: true } },
		primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' },
		capabilities: { 'urn:ietf:params:jmap:core': {}, 'urn:setjoin:params:jmap:mail': { admin: { consoles: ['mail'], permissions: ['domains.write'] } } },
	} as never);
}

describe('admin domains workflows', () => {
	beforeEach(() => {
		vi.clearAllMocks(); resetStores(); mockSessionLoad();
		api.list.mockResolvedValue([domain]); api.create.mockResolvedValue({});
		api.update.mockResolvedValue({}); api.remove.mockResolvedValue({});
	});
	afterEach(() => vi.unstubAllGlobals());

	it('renders domain posture and creates a validated domain', async () => {
		await renderAsUser(Page, {}, { isAdmin: true }); allowWrite();
		await waitFor(() => expect(screen.getByText('example.test')).toBeInTheDocument());
		expect(screen.getByText('Local')).toBeInTheDocument();
		expect(screen.getByText('reject')).toBeInTheDocument();
		expect(screen.getByText('10 MB')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Add domain' }));
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		expect(screen.getByText('Domain name is required')).toBeInTheDocument();
		await fireEvent.input(screen.getByLabelText('Domain name'), { target: { value: ' new.test ' } });
		await fireEvent.change(screen.getByLabelText('DMARC policy'), { target: { value: 'quarantine' } });
		await fireEvent.change(screen.getByLabelText('MTA-STS'), { target: { value: 'testing' } });
		await fireEvent.input(screen.getByLabelText('Max size (bytes)'), { target: { value: '2048' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		await waitFor(() => expect(api.create).toHaveBeenCalledWith(expect.objectContaining({ name: 'new.test', dmarcPolicy: 'quarantine', mtaStsPolicy: 'testing', maxMessageBytes: 2048 })));
	});

	it('updates and confirms deletion of an existing domain', async () => {
		await renderAsUser(Page, {}, { isAdmin: true }); allowWrite();
		await waitFor(() => expect(screen.getByRole('button', { name: 'Edit' })).toBeEnabled());
		await fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
		await fireEvent.input(screen.getByLabelText('Domain name'), { target: { value: 'edited.test' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		await waitFor(() => expect(api.update).toHaveBeenCalledWith(7, expect.objectContaining({ name: 'edited.test' })));
		await fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
		expect(screen.getByText(/Delete example\.test/)).toBeInTheDocument();
		await fireEvent.click(screen.getAllByRole('button', { name: 'Delete' }).at(-1)!);
		await waitFor(() => expect(api.remove).toHaveBeenCalledWith(7));
	});

	it('shows loading failures and keeps writes permission-gated', async () => {
		api.list.mockRejectedValueOnce(new Error('domain backend unavailable'));
		await renderAsUser(Page, {}, { isAdmin: true });
		await waitFor(() => expect(screen.getByText('domain backend unavailable')).toBeInTheDocument());
		expect(screen.getByRole('button', { name: 'Add domain' })).toBeDisabled();
	});
});
