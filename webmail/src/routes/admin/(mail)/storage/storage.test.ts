import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({ status: vi.fn(), start: vi.fn(), list: vi.fn(), get: vi.fn(), reconcile: vi.fn() }));
vi.mock('$lib/admin/client', () => ({
	adminStorageStatus: api.status, adminStorageDRScanStart: api.start,
	adminStorageDRScanList: api.list, adminStorageDRScanGet: api.get,
	adminStorageDRScanReconcile: api.reconcile
}));
import Page from './+page.svelte';

const status = {
	objects: { count: 1200 }, usage: { size: 4096 }, buckets: { count: 2 },
	mode: 'distributed', version: '4.40', deploymentID: 'dep-1',
	backend: { type: 1, onlineDisks: 3, offlineDisks: 1, standardParity: 2 },
	healing: { scannedItems: 7, healDisks: ['disk-1'] },
	pools: [{ index: 1, objects: 1200, sets: 2, rawUsage: 4096, rawCapacity: 8192 }],
	servers: [{ endpoint: 'storage:9000', state: 'online', poolNumber: 1, drives: [{ endpoint: '/data', state: 'ok', used: 4096, total: 8192 }] }]
};
const completed = {
	id: 4, status: 'completed', totalScanned: 10, orphanedCount: 2, missingCount: 1,
	reimportedCount: 0, startedAt: '2026-07-20T00:00:00Z',
	details: [{ sha256: 'abc', issue: 'orphaned', size: 12 }, { sha256: 'def', issue: 'missing' }]
};

function grant() {
	jmapSession.set({ accounts: {}, primaryAccounts: {}, capabilities: { 'urn:setjoin:params:jmap:mail': { admin: { consoles: ['mail'], permissions: ['system.config'] } } } } as never);
}
async function renderPage() {
	const r = await renderAsUser(Page, {}, { isAdmin: true }); grant();
	await waitFor(() => expect(screen.queryByText('Loading cluster status…')).not.toBeInTheDocument());
	return r;
}

describe('admin storage workflows', () => {
	beforeEach(() => {
		resetStores(); vi.clearAllMocks();
		api.status.mockResolvedValue(status); api.list.mockResolvedValue([completed]);
		api.start.mockResolvedValue({ id: 9 }); api.get.mockResolvedValue({ ...completed, id: 9, status: 'running', orphanedCount: 0, missingCount: 0, details: [] });
		api.reconcile.mockResolvedValue({ reimported: 2 });
		vi.stubGlobal('confirm', vi.fn(() => true));
	});
	afterEach(() => { vi.unstubAllGlobals(); resetStores(); });

	it('renders cluster capacity, healing, pools, disks, and refreshes', async () => {
		await renderPage();
		expect(screen.getByText('1,200')).toBeInTheDocument();
		expect(screen.getByText('distributed')).toBeInTheDocument();
		expect(screen.getByText(/disk-1/)).toBeInTheDocument();
		expect(screen.getByText(/storage:9000/)).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
		await waitFor(() => expect(api.status).toHaveBeenCalledTimes(2));
	});

	it('shows completed scan evidence, opens details, and reconciles after confirmation', async () => {
		await renderPage();
		await fireEvent.click(screen.getByRole('tab', { name: 'Disaster recovery' }));
		expect(screen.getByText('#4')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Details' }));
		expect(screen.getByText('abc')).toBeInTheDocument();
		expect(screen.getByText('def')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Reconcile' }));
		await waitFor(() => expect(api.reconcile).toHaveBeenCalledWith(4));
		expect(confirm).toHaveBeenCalledWith('Re-import 2 orphaned objects into the blobs table?');
	});

	it('starts a DR scan and renders progress while preventing duplicates', async () => {
		const running = { ...completed, id: 9, status: 'running', orphanedCount: 0, missingCount: 0, details: [] };
		api.list.mockResolvedValueOnce([]).mockResolvedValue([running]);
		api.get.mockResolvedValue(running);
		await renderPage();
		await fireEvent.click(screen.getByRole('tab', { name: 'Disaster recovery' }));
		const start = screen.getByRole('button', { name: 'Start DR scan' });
		await waitFor(() => expect(start).toBeEnabled());
		await fireEvent.click(start);
		await waitFor(() => expect(api.start).toHaveBeenCalled());
		await waitFor(() => expect(screen.getByText('Scan #9 in progress')).toBeInTheDocument());
		expect(start).toBeDisabled();
	});

	it('surfaces status and scan failures', async () => {
		api.status.mockRejectedValueOnce(new Error('status unavailable'));
		api.list.mockRejectedValueOnce(new Error('scan unavailable'));
		await renderAsUser(Page, {}, { isAdmin: true });
		await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('scan unavailable'));
	});
});
