import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({ fetch: vi.fn() }));
vi.mock('$lib/admin/client', () => ({ adminFetch: api.fetch }));
import Page from './+page.svelte';

function response(data: unknown) { return { ok: true, json: vi.fn().mockResolvedValue(data) }; }
function grant() {
	jmapSession.set({ accounts: {}, primaryAccounts: {}, capabilities: {
		'urn:setjoin:params:jmap:mail': { admin: { consoles: ['mail'], permissions: ['security.write'] } }
	} } as never);
}

describe('TLS certificate management', () => {
	beforeEach(() => { resetStores(); vi.clearAllMocks(); });
	afterEach(() => resetStores());

	it('renders certificate metadata, DNS fields, and persists configuration', async () => {
		api.fetch.mockImplementation(async (path: string) => path.endsWith('/status')
			? response({ challenge: 'dns-01', domains: ['mail.example.test'], email: 'ops@example.test', dns_provider: 'cloudflare', cache_dir: '/var/lib/acme', cert_info: { subject: 'mail.example.test', issuer: 'Test CA', not_after: '2026-08-01', days_left: 9 } })
			: response({}));
		await renderAsUser(Page, {}, { isAdmin: true }); grant();
		expect(await screen.findByText('Certificate: mail.example.test')).toBeInTheDocument();
		expect(screen.getByLabelText('DNS provider')).toBeInTheDocument();
		await fireEvent.change(screen.getByLabelText('ACME challenge type'), { target: { value: 'http-01' } });
		await fireEvent.input(screen.getByLabelText('Domains'), { target: { value: 'mail.example.test, imap.example.test' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		await waitFor(() => expect(api.fetch).toHaveBeenCalledWith('/admin/tls/config', expect.objectContaining({ method: 'PUT' })));
		expect(await screen.findByText('Saved. Restart gateway to apply.')).toBeInTheDocument();
	});

	it('surfaces load and save failures', async () => {
		api.fetch.mockRejectedValueOnce(new Error('TLS unavailable'));
		await renderAsUser(Page, {}, { isAdmin: true }); grant();
		expect(await screen.findByRole('alert')).toHaveTextContent('TLS unavailable');
		api.fetch.mockRejectedValueOnce(new Error('save denied'));
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		expect(await screen.findByRole('alert')).toHaveTextContent('save denied');
	});
});
