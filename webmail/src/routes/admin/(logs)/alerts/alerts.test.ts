import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores, mockSessionLoad } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({ list: vi.fn(), ack: vi.fn(), unsuppress: vi.fn() }));
vi.mock('$lib/admin/client', () => ({ adminAlertList: api.list, adminAlertAck: api.ack, adminAlertUnsuppress: api.unsuppress }));
import Page from './+page.svelte';

function allowWrite() {
	jmapSession.set({ accounts: { a1: { name: 'admin@test', isPrimary: true } }, primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' }, capabilities: { 'urn:ietf:params:jmap:core': {}, 'urn:setjoin:params:jmap:mail': { admin: { consoles: ['logs'], permissions: ['security.write'] } } } } as never);
}

describe('admin alerts', () => {
	beforeEach(() => { vi.clearAllMocks(); resetStores(); mockSessionLoad(); api.ack.mockResolvedValue({}); api.unsuppress.mockResolvedValue({}); });
	afterEach(() => vi.unstubAllGlobals());

	it('derives firing, warning, suppressed and healthy alert states', async () => {
		api.list.mockResolvedValue([
			{ checkName: 'database', lastError: 'timeout', consecutive: 3, suppressed: false, lastChecked: '2026-07-03T12:00:00Z' },
			{ checkName: 'storage', consecutive: 1, suppressed: false, lastChecked: '' },
			{ checkName: 'queue', consecutive: 4, suppressed: true, lastChecked: '' },
			{ checkName: 'dns', consecutive: 0, suppressed: false, lastChecked: '' },
		]);
		await renderAsUser(Page, {}, { isAdmin: true }); allowWrite();
		await waitFor(() => expect(screen.getByText('Firing')).toBeInTheDocument());
		expect(screen.getByText(/database — timeout — 3 consecutive failures/)).toBeInTheDocument();
		expect(screen.getByText('Warning')).toBeInTheDocument();
		expect(screen.getAllByText('Suppressed').length).toBeGreaterThan(0);
		expect(screen.getByText('OK')).toBeInTheDocument();
		await fireEvent.click(screen.getAllByRole('button', { name: 'Acknowledge' })[0]);
		await waitFor(() => expect(api.ack).toHaveBeenCalledWith('database'));
	});

	it('supports empty, retry and permission-denied states', async () => {
		api.list.mockRejectedValueOnce(new Error('monitor unavailable')).mockResolvedValueOnce([]);
		await renderAsUser(Page, {}, { isAdmin: true });
		await waitFor(() => expect(screen.getByText('monitor unavailable')).toBeInTheDocument());
		await fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
		await waitFor(() => expect(screen.getByText(/No active alerts/)).toBeInTheDocument());
	});
});
