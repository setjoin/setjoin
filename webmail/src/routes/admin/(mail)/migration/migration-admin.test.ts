import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({ getConfig: vi.fn(), saveIMAP: vi.fn(), saveEWS: vi.fn(), saveM365: vi.fn(), deleteConfig: vi.fn(), connectUrl: vi.fn() }));
vi.mock('$lib/admin/client', () => ({
	getGlobalSourceConfig: api.getConfig, saveGlobalIMAPConfig: api.saveIMAP,
	saveGlobalEWSConfig: api.saveEWS, saveM365Config: api.saveM365,
	deleteGlobalSourceConfig: api.deleteConfig, getM365ConnectUrl: api.connectUrl
}));
const downloadBlob = vi.hoisted(() => vi.fn());
vi.mock('$lib/utils/downloadBlob', () => ({ downloadBlob }));
import Page from './+page.svelte';

const jobs = [
	{ id: 1, user_id: 5, source_type: 'imap', status: 'pending', conflict_strategy: 'merge', progress: { pct: 25, items_done: 25, items_total: 100, speed: 5, eta: '15m' }, error_log: [], started_at: '2026-07-20T00:00:00Z', completed_at: null, created_at: '2026-07-20T00:00:00Z' },
	{ id: 2, user_id: 6, source_type: 'ews', status: 'failed', conflict_strategy: '', progress: {}, error_log: ['authentication failed'], started_at: null, completed_at: null, created_at: '2026-07-20T00:00:00Z' },
	{ id: 3, user_id: 7, source_type: 'm365', status: 'completed', conflict_strategy: 'skip', progress: { pct: 100, items_done: 10, items_total: 10, speed: 1 }, error_log: [], started_at: '2026-07-20T00:00:00Z', completed_at: '2026-07-20T01:00:00Z', created_at: '2026-07-20T00:00:00Z' }
];

function ok(body: unknown = {}) {
	return Promise.resolve({ ok: true, status: 200, json: async () => body, text: async () => typeof body === 'string' ? body : JSON.stringify(body) });
}
function grant() {
	jmapSession.set({ accounts: {}, primaryAccounts: {}, capabilities: { 'urn:setjoin:params:jmap:mail': { admin: { consoles: ['mail'], permissions: ['mail.pipeline'] } } } } as never);
}
async function renderPage() {
	const r = await renderAsUser(Page, {}, { isAdmin: true }); grant();
	await waitFor(() => expect(screen.queryAllByText('Loading...')).toHaveLength(0));
	return r;
}

describe('admin migration workflows', () => {
	beforeEach(() => {
		resetStores(); vi.clearAllMocks();
		api.getConfig.mockImplementation(async (type: string) => {
			if (type === 'imap') return { host: 'imap.source.test', port: 993, tls_mode: 'ssl' };
			if (type === 'ews') return { serverURL: 'https://exchange.test/EWS/Exchange.asmx', username: 'CORP\\svc', password: 'stored', authMode: 'impersonation' };
			return { client_id: 'client-id', client_secret: 'secret', tenant_id: 'tenant-id', cloud: 'global' };
		});
		api.saveIMAP.mockResolvedValue({}); api.saveEWS.mockResolvedValue({}); api.saveM365.mockResolvedValue({}); api.deleteConfig.mockResolvedValue({}); api.connectUrl.mockReturnValue('/api/admin/migration/m365/connect');
		vi.stubGlobal('fetch', vi.fn((input: RequestInfo | URL, init?: RequestInit) => {
			const url = String(input);
			if (url === '/auth/me') return ok({ id: 1, email: 'admin@test', isAdmin: true, hasMailbox: true });
			if (url === '/api/admin/migration/jobs') return ok(jobs);
			if (url === '/api/admin/migration/test-connection') return ok({});
			if (url === '/api/admin/migration/start') return ok({ started: 1 });
			if (/\/api\/admin\/migration\/jobs\/\d+\/(cancel|retry)/.test(url) && init?.method === 'POST') return ok({});
			throw new Error(`Unstubbed fetch: ${url}`);
		}));
	});
	afterEach(() => { vi.unstubAllGlobals(); resetStores(); });

	it('loads, edits, saves, tests, and explains an IMAP source', async () => {
		await renderPage();
		expect(screen.getByDisplayValue('imap.source.test')).toBeInTheDocument();
		await fireEvent.input(screen.getByLabelText('IMAP Host'), { target: { value: 'imap.changed.test' } });
		await fireEvent.input(screen.getByLabelText('Port'), { target: { value: '143' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Save IMAP Config' }));
		await waitFor(() => expect(api.saveIMAP).toHaveBeenCalledWith({ host: 'imap.changed.test', port: 143, tls_mode: 'ssl' }));
		await fireEvent.click(screen.getByRole('button', { name: 'Test Connection' }));
		await waitFor(() => expect(screen.getByText(/Connected: Connection successful/)).toBeInTheDocument());
		await fireEvent.click(screen.getByRole('button', { name: 'Show Setup Guide' }));
		expect(screen.getByText('IMAP Connection Requirements')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Download Template' }));
		expect(downloadBlob).toHaveBeenCalledWith(expect.any(Blob), 'migration-template.csv');
	});

	it('configures EWS per-user credentials, adds a bounded target, and starts migration', async () => {
		await renderPage();
		await fireEvent.click(screen.getByRole('button', { name: 'Exchange EWS' }));
		await waitFor(() => expect(screen.getByDisplayValue('https://exchange.test/EWS/Exchange.asmx')).toBeInTheDocument());
		await fireEvent.click(screen.getByLabelText('Per-User Credentials'));
		// S19: saving requires re-entering the service-account password — a blank
		// save would clear the stored credential.
		await fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'svc-pass' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Save EWS Config' }));
		await waitFor(() => expect(api.saveEWS).toHaveBeenCalledWith(expect.objectContaining({ serverURL: 'https://exchange.test/EWS/Exchange.asmx', username: 'CORP\\svc', authMode: 'per_user', password: 'svc-pass' })));
		await fireEvent.click(screen.getByRole('button', { name: '+ Add User' }));
		await fireEvent.input(screen.getByLabelText('Source Email'), { target: { value: ' source@test ' } });
		await fireEvent.input(screen.getByLabelText('Target Email'), { target: { value: ' target@test ' } });
		await fireEvent.input(screen.getByPlaceholderText('User password'), { target: { value: 'source password' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Add' }));
		expect(screen.getByText('source@test')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Start Migration (1 user)' }));
		await waitFor(() => {
			const call = (fetch as ReturnType<typeof vi.fn>).mock.calls.find(([url]) => String(url) === '/api/admin/migration/start');
			expect(JSON.parse(String(call?.[1]?.body))).toEqual(expect.objectContaining({ source_type: 'ews', auth_mode: 'per_user', targets: [{ source_email: 'source@test', target_email: 'target@test', password: 'source password' }] }));
		});
	});

	it('saves and disconnects Microsoft 365 configuration and exposes RBAC guidance', async () => {
		await renderPage();
		await fireEvent.click(screen.getByRole('button', { name: 'Microsoft 365' }));
		await waitFor(() => expect(screen.getByDisplayValue('client-id')).toBeInTheDocument());
		// S19: the GET-returned secret is never bound into the form; type it.
		await fireEvent.input(screen.getByLabelText('Client Secret'), { target: { value: 'secret' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		await waitFor(() => expect(api.saveM365).toHaveBeenCalledWith({ client_id: 'client-id', client_secret: 'secret', cloud: 'global' }));
		await fireEvent.click(screen.getByRole('button', { name: /Permission scoping/ }));
		expect(screen.getByText(/New-ApplicationAccessPolicy/)).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Disconnect' }));
		await waitFor(() => expect(api.deleteConfig).toHaveBeenCalledWith('m365'));
	});

	it('imports CSV preview and exercises job detail, retry, cancel, and bulk selection', async () => {
		const { container } = await renderPage();
		const csv = new File(['source_email,target_email\na@test,b@test\ninvalid,'], 'targets.csv', { type: 'text/csv' });
		const input = container.querySelector('input[type="file"][accept=".csv"]') as HTMLInputElement;
		Object.defineProperty(input, 'files', { configurable: true, value: [csv] });
		await fireEvent.change(input);
		await waitFor(() => expect(screen.getByText(/CSV Preview: 1 entries/)).toBeInTheDocument());
		await fireEvent.click(screen.getByRole('button', { name: 'Import All' }));
		expect(screen.getByText('a@test')).toBeInTheDocument();

		const failedRow = screen.getAllByText('Failed').map((el) => el.closest('tr')).find(Boolean);
		expect(failedRow).not.toBeNull();
		await fireEvent.click(failedRow!);
		expect(screen.getAllByText('authentication failed').length).toBeGreaterThan(0);
		await fireEvent.click(screen.getAllByRole('button', { name: 'Retry' })[0]);
		await waitFor(() => expect(fetch).toHaveBeenCalledWith('/api/admin/migration/jobs/2/retry', { method: 'POST', credentials: 'include' }));
		await fireEvent.click(screen.getAllByRole('button', { name: 'Cancel' })[0]);
		await waitFor(() => expect(fetch).toHaveBeenCalledWith('/api/admin/migration/jobs/1/cancel', { method: 'POST', credentials: 'include' }));
	});
});
