import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores, mockSessionLoad } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const mocks = vi.hoisted(() => ({ fetch: vi.fn(), download: vi.fn() }));
vi.mock('$lib/admin/client', () => ({ adminFetch: mocks.fetch }));
vi.mock('$lib/utils/downloadBlob', () => ({ downloadBlob: mocks.download }));
import Page from './+page.svelte';

function response(data: unknown = {}, ok = true) {
	return { ok, json: async () => data, text: async () => String(data), blob: async () => new Blob(['config']) };
}

function allowAll() {
	jmapSession.set({
		accounts: { a1: { name: 'admin@example.test', isPrimary: true } },
		primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' },
		capabilities: { 'urn:ietf:params:jmap:core': {}, 'urn:setjoin:params:jmap:mail': { admin: { consoles: ['system'], permissions: ['backup.write', 'system.config', 'mail.pipeline', 'system.upgrade'] } } },
	} as never);
}

describe('admin system operations', () => {
	beforeEach(() => {
		vi.clearAllMocks(); resetStores(); mockSessionLoad();
		vi.stubGlobal('confirm', vi.fn(() => true));
		vi.stubGlobal('alert', vi.fn());
		mocks.fetch.mockImplementation(async (path: string) => {
			if (path === '/admin/system/health') return response({ database: 'ok', database_detail: 'ready', storage: 'error', storage_detail: 'offline', queue: { pending: 3 }, quarantine: 2 });
			if (path === '/admin/system/backup/list') return response({ items: [{ id: 5, createdAt: '2026-07-03T12:00:00Z', sizeBytes: 1048576, status: 'complete', resultPath: '/backups/db.sql' }] });
			if (path === '/admin/system/version') return response({ version: '1.2.3', gitHash: 'abc', go: 'go1.25', platform: 'linux', uptime: 172800 });
			if (path === '/admin/system/schema-version') return response({ current: 149, expected: 150, up_to_date: false });
			if (path.includes('listen.addr')) return response({ value: ':8443' });
			if (path.includes('http.mode')) return response({ value: 'redirect' });
			if (path === '/admin/branding') return response({ name: 'Acme', logoUrl: '/logo.png' });
			return response({});
		});
	});
	afterEach(() => vi.unstubAllGlobals());

	it('renders health, version, schema drift and backup evidence without calling a phantom env endpoint', async () => {
		await renderAsUser(Page, {}, { isAdmin: true }); allowAll();
		await waitFor(() => expect(screen.getByText('ready')).toBeInTheDocument());
		expect(screen.getByText('offline')).toBeInTheDocument();
		expect(screen.getByText('3 pending')).toBeInTheDocument();
		expect(screen.getByText(/v1\.2\.3/)).toBeInTheDocument();
		expect(screen.getByText(/Schema: 149\/150 1 pending/)).toBeInTheDocument();
		expect(screen.getByText('complete')).toBeInTheDocument();
		expect(screen.getByAltText('Logo preview')).toHaveAttribute('src', '/logo.png');
		expect(mocks.fetch).not.toHaveBeenCalledWith('/admin/system/env');
	});

	it('exports/imports configuration and rejects malformed JSON locally', async () => {
		await renderAsUser(Page, {}, { isAdmin: true }); allowAll();
		await fireEvent.click(screen.getByRole('button', { name: 'Export Config' }));
		await waitFor(() => expect(mocks.download).toHaveBeenCalledWith(expect.any(Blob), 'mailserver-config.json'));
		const fileInput = document.querySelector('input[type="file"][accept=".json"]') as HTMLInputElement;
		await fireEvent.change(fileInput, { target: { files: [new File(['{bad'], 'bad.json', { type: 'application/json' })] } });
		await waitFor(() => expect(screen.getByText('Invalid JSON file')).toBeInTheDocument());
		await fireEvent.change(fileInput, { target: { files: [new File(['{"safe":true}'], 'good.json', { type: 'application/json' })] } });
		await waitFor(() => expect(screen.getByText('Configuration imported successfully')).toBeInTheDocument());
		expect(mocks.fetch).toHaveBeenCalledWith('/admin/system/config/import', expect.objectContaining({ method: 'POST', body: '{"safe":true}' }));
	});

	it('persists network and branding, links to transactional updates, and keeps destructive backup confirmation', async () => {
		await renderAsUser(Page, {}, { isAdmin: true }); allowAll();
		await waitFor(() => expect(screen.getByLabelText('Listen address')).toHaveValue(':8443'));
		await fireEvent.input(screen.getByLabelText('Listen address'), { target: { value: ':9443' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Apply & Reload' }));
		await waitFor(() => expect(mocks.fetch).toHaveBeenCalledWith('/admin/system/config/set', expect.objectContaining({ body: JSON.stringify({ key: 'listen.addr', value: ':9443' }) })));
		expect(mocks.fetch).toHaveBeenCalledWith('/admin/reload', { method: 'POST' });

		await fireEvent.input(screen.getByLabelText('Brand name'), { target: { value: 'New Brand' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Save Branding' }));
		await waitFor(() => expect(mocks.fetch).toHaveBeenCalledWith('/admin/branding', expect.objectContaining({ method: 'POST', body: expect.any(FormData) })));

		expect(screen.getByText('Transactional update planning and durable progress are available here. Host execution remains fail-closed until the installation passes its recovery and runtime gates.')).toBeInTheDocument();
		expect(screen.getByRole('link', { name: 'Open server updates' })).toHaveAttribute('href', '/admin/updates/server');
		expect(screen.queryByRole('button', { name: 'Analyze' })).not.toBeInTheDocument();
		expect(screen.queryByRole('button', { name: 'Apply Upgrade' })).not.toBeInTheDocument();
		expect(screen.queryByRole('button', { name: 'Rollback' })).not.toBeInTheDocument();
		expect(mocks.fetch).not.toHaveBeenCalledWith(expect.stringMatching(/\/admin\/system\/upgrade\/(check|apply|rollback)/), expect.anything());

		await fireEvent.click(screen.getByRole('button', { name: 'Del' }));
		expect(confirm).toHaveBeenCalledWith('Delete this backup? This cannot be undone.');
		await waitFor(() => expect(mocks.fetch).toHaveBeenCalledWith(expect.stringContaining('/admin/system/backup?id=5'), { method: 'DELETE' }));
	});
});
