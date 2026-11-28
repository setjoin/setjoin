import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({ fetch: vi.fn() }));
vi.mock('$lib/admin/client', () => ({ adminFetch: api.fetch }));

import Page from './+page.svelte';

const subscriptions = [
	{ id: 7, url: 'https://hooks.example.test/active', eventTypes: ['user.created', 'mail.sent'], isActive: true },
	{ id: 8, url: 'https://hooks.example.test/off', eventTypes: [], isActive: false },
];

function response(data: unknown = {}, ok = true) {
	return { ok, json: vi.fn().mockResolvedValue(data) };
}

function grant() {
	jmapSession.set({ accounts: {}, primaryAccounts: {}, capabilities: {
		'urn:setjoin:params:jmap:mail': { admin: { consoles: ['system'], permissions: ['system.config'] } }
	} } as never);
}

describe('admin webhooks workflows', () => {
	beforeEach(() => {
		resetStores();
		vi.clearAllMocks();
		vi.stubGlobal('confirm', vi.fn(() => true));
		api.fetch.mockImplementation(async (path: string, init?: RequestInit) => {
			if (path === '/admin/webhooks' && !init) return response(subscriptions);
			if (path === '/admin/webhooks/events') return response([
				{ type: 'user.created', category: 'admin', source: 'mailserver/auth' },
				{ type: 'mail.sent', category: 'mailbox', source: 'mailserver/gateway' },
				{ type: 'calendar.invitation', category: 'mailbox', source: 'mailserver/gateway' },
				{ type: 'mailwork.completed', category: 'mailbox', source: 'mailserver/mailwork' },
			]);
			if (path === '/admin/webhooks/7/deliveries') return response([
				{ eventType: 'user.created', status: 'success', responseCode: 204, latencyMs: 15, createdAt: '2026-07-23T01:00:00Z' },
				{ eventType: 'mail.sent', status: 'failed', responseCode: 500, latencyMs: 0, createdAt: '2026-07-23T01:01:00Z' },
				{ eventType: 'mail.received', status: 'queued', responseCode: 0, latencyMs: null, createdAt: '2026-07-23T01:02:00Z' },
			]);
			if (path === '/admin/webhooks/7/rotate-secret') return response({ secret: 'rotated-secret' });
			if (path === '/admin/webhooks' && init?.method === 'POST') return response({ secret: 'created-secret' });
			return response({});
		});
	});

	afterEach(() => {
		vi.unstubAllGlobals();
		resetStores();
	});

	it('loads subscriptions, delivery variants, the catalog, and rotates a secret', async () => {
		await renderAsUser(Page, {}, { isAdmin: true });
		grant();
		await screen.findByText('https://hooks.example.test/active');
		expect(screen.getByText('2 events')).toBeInTheDocument();
		expect(screen.getByText('Off')).toBeInTheDocument();

		await fireEvent.click(screen.getAllByRole('button', { name: 'Log' })[0]);
		await screen.findByText('user.created');
		expect(screen.getByText('204')).toBeInTheDocument();
		expect(screen.getAllByText('—')).not.toHaveLength(0);

		await fireEvent.click(screen.getAllByRole('button', { name: 'Rotate' })[0]);
		const rotated = await screen.findByRole('dialog', { name: 'Secret rotated' });
		expect(within(rotated).getByText('rotated-secret')).toBeInTheDocument();
		await fireEvent.click(within(rotated).getByRole('button', { name: 'Done' }));

		await fireEvent.click(screen.getByRole('tab', { name: 'Event catalog' }));
		expect(screen.getByText('calendar.invitation')).toBeInTheDocument();
		expect(screen.getByText('mailwork.completed')).toBeInTheDocument();
		expect(screen.getByText(/"mailboxId":"<opaque>"/)).toBeInTheDocument();
	});

	it('creates and deletes subscriptions and surfaces server failures', async () => {
		await renderAsUser(Page, {}, { isAdmin: true });
		grant();
		await screen.findByText('https://hooks.example.test/active');

		await fireEvent.click(screen.getByRole('button', { name: 'New webhook' }));
		const dialog = screen.getByRole('dialog', { name: 'New webhook' });
		const create = within(dialog).getByRole('button', { name: 'Create' });
		expect(create).toBeDisabled();
		await fireEvent.input(within(dialog).getByLabelText('Destination URL'), { target: { value: 'https://new.example.test/hook' } });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'user.created' }));
		expect(create).toBeEnabled();
		await fireEvent.click(create);
		await waitFor(() => expect(api.fetch).toHaveBeenCalledWith('/admin/webhooks', expect.objectContaining({
			method: 'POST', body: JSON.stringify({ url: 'https://new.example.test/hook', eventTypes: ['user.created'] })
		})));
		expect(await within(dialog).findByText('created-secret')).toBeInTheDocument();
		await fireEvent.click(within(dialog).getByRole('button', { name: 'user.created' }));

		api.fetch.mockResolvedValueOnce(response({ error: 'invalid endpoint' }, false));
		await fireEvent.input(within(dialog).getByLabelText('Destination URL'), { target: { value: 'https://bad.example.test' } });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'mail.sent' }));
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Create' }));
		expect(await within(dialog).findByText('invalid endpoint')).toBeInTheDocument();
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));

		api.fetch.mockResolvedValueOnce(response({}, false));
		await fireEvent.click(screen.getAllByRole('button', { name: 'Delete' })[0]);
		await waitFor(() => expect(api.fetch).toHaveBeenCalledWith('/admin/webhooks/7', { method: 'DELETE' }));
	});

	it('honors a cancelled deletion and reports rotate failure', async () => {
		vi.mocked(confirm).mockReturnValueOnce(false);
		await renderAsUser(Page, {}, { isAdmin: true });
		grant();
		await screen.findByText('https://hooks.example.test/active');
		await fireEvent.click(screen.getAllByRole('button', { name: 'Delete' })[0]);
		expect(api.fetch).not.toHaveBeenCalledWith('/admin/webhooks/7', expect.anything());

		api.fetch.mockResolvedValueOnce(response({}, false));
		await fireEvent.click(screen.getAllByRole('button', { name: 'Rotate' })[0]);
		await waitFor(() => expect(api.fetch).toHaveBeenCalledWith('/admin/webhooks/7/rotate-secret', { method: 'POST' }));
	});
});
