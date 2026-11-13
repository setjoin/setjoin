import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({ list: vi.fn(), upsert: vi.fn(), remove: vi.fn() }));
vi.mock('$lib/admin/client', () => ({
	adminListFederationPeers: api.list,
	adminUpsertFederationPeer: api.upsert,
	adminDeleteFederationPeer: api.remove,
}));
import Page from './+page.svelte';

const peers = [
	{ peerDomain: 'on.example.test', scope: 'dm' as const, enabled: true, unackedDepth: 4, lastAckAgeSeconds: 120 },
	{ peerDomain: 'off.example.test', scope: 'room' as const, enabled: false, unackedDepth: null, lastAckAgeSeconds: null },
];
function grant() {
	jmapSession.set({ accounts: {}, primaryAccounts: {}, capabilities: {
		'urn:setjoin:params:jmap:mail': { admin: { consoles: ['system'], permissions: ['federation.manage'] } }
	} } as never);
}

describe('federation administration', () => {
	beforeEach(() => { resetStores(); vi.clearAllMocks(); api.list.mockResolvedValue(peers); api.upsert.mockResolvedValue(undefined); api.remove.mockResolvedValue(undefined); });
	afterEach(() => resetStores());

	it('renders health, toggles a peer, and deletes a disabled peer', async () => {
		await renderAsUser(Page, {}, { isAdmin: true }); grant();
		expect(await screen.findByText('on.example.test')).toBeInTheDocument();
		expect(screen.getByText('off.example.test')).toBeInTheDocument();
		await fireEvent.click(screen.getAllByRole('switch')[0]);
		await waitFor(() => expect(api.upsert).toHaveBeenCalledWith(expect.objectContaining({ domain: 'on.example.test', enabled: false, anchorPem: '' })));
		await fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
		const dialog = screen.getByRole('dialog', { name: 'Delete' });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));
		await waitFor(() => expect(api.remove).toHaveBeenCalledWith('off.example.test'));
	});

	it('validates and creates a new peer, then edits an existing peer', async () => {
		await renderAsUser(Page, {}, { isAdmin: true }); grant();
		await screen.findByText('on.example.test');
		await fireEvent.click(screen.getByRole('button', { name: 'Add peer' }));
		let dialog = screen.getByRole('dialog', { name: 'Add federated peer' });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
		expect(within(dialog).getByRole('alert')).toHaveTextContent('Peer domain is required.');
		await fireEvent.input(within(dialog).getByPlaceholderText('bravo.example.com'), { target: { value: 'new.example.test' } });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
		expect(within(dialog).getByRole('alert')).toHaveTextContent('trust anchor is required');
		await fireEvent.input(within(dialog).getByPlaceholderText(/BEGIN CERTIFICATE/), { target: { value: 'PEM' } });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
		await waitFor(() => expect(api.upsert).toHaveBeenCalledWith(expect.objectContaining({ domain: 'new.example.test', anchorPem: 'PEM' })));

		await fireEvent.click(screen.getAllByRole('button', { name: 'Edit' })[0]);
		dialog = screen.getByRole('dialog', { name: 'Edit federated peer' });
		expect(within(dialog).getByDisplayValue('on.example.test')).toBeDisabled();
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));
	});

	it('surfaces list and mutation failures', async () => {
		api.list.mockRejectedValueOnce(new Error('federation unavailable'));
		await renderAsUser(Page, {}, { isAdmin: true }); grant();
		expect(await screen.findByRole('alert')).toHaveTextContent('federation unavailable');
	});
});
