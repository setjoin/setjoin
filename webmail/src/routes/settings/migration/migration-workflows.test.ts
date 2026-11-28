import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor } from '@testing-library/svelte/svelte5';

const admin = vi.hoisted(() => ({ globalConfig: vi.fn() }));
vi.mock('$lib/admin/client', () => ({ getGlobalSourceConfig: admin.globalConfig }));
import Page from './+page.svelte';

function response(body: unknown, ok = true, text = '') {
	return { ok, json: async () => body, text: async () => text } as Response;
}

describe('migration settings workflows', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		admin.globalConfig.mockImplementation(async (type: string) => type === 'imap'
			? { host: 'imap.default.test', port: 993, tls_mode: 'starttls' }
			: null);
		vi.stubGlobal('fetch', vi.fn(async () => response({ status: 'none' })));
		vi.stubGlobal('clearInterval', vi.fn());
		vi.stubGlobal('setInterval', vi.fn(() => 17));
	});
	afterEach(() => vi.unstubAllGlobals());

	it('tests IMAP, uploads optional data, and starts with exact connection settings', async () => {
		vi.mocked(fetch).mockImplementation(async (input, init) => {
			const url = String(input);
			if (url.endsWith('/test-imap')) return response({ success: true });
			if (url.includes('/upload?')) return response({});
			if (url === '/auth/me/migration' && init?.method === 'POST') return response({ id: 42 });
			return response({ status: 'none' });
		});
		render(Page);
		await fireEvent.input(screen.getByLabelText('IMAP server'), { target: { value: 'imap.default.test' } });
		await fireEvent.input(screen.getByLabelText('Username / Email'), { target: { value: 'alice@old.test' } });
		await fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'secret' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Test connection' }));
		expect(await screen.findByText('Connection successful')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Next: Upload data' }));

		await fireEvent.change(screen.getByLabelText('Calendar file (.ics)'), { target: { files: [new File(['ics'], 'calendar.ics')] } });
		await fireEvent.change(screen.getByLabelText('Contacts file (.vcf)'), { target: { files: [new File(['vcf'], 'contacts.vcf')] } });
		await fireEvent.change(screen.getByLabelText('When duplicate found:'), { target: { value: 'overwrite' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Start migration' }));
		expect(await screen.findByText('Migration in progress')).toBeInTheDocument();

		const create = vi.mocked(fetch).mock.calls.find(([url, init]) => String(url) === '/auth/me/migration' && init?.method === 'POST');
		expect(JSON.parse(String(create?.[1]?.body))).toEqual(expect.objectContaining({
			source_type: 'imap', conflict_strategy: 'overwrite',
			imap_config: expect.objectContaining({ host: 'imap.default.test', port: 993, tls_mode: 'starttls' }),
		}));
		expect(fetch).toHaveBeenCalledWith('/auth/me/migration/upload?job_id=42', expect.objectContaining({ method: 'POST' }));
		expect(setInterval).toHaveBeenCalled();
	});

	it('covers failed connection, thrown connection error, and custom-port selection', async () => {
		vi.mocked(fetch)
			.mockImplementationOnce(async () => response({ status: 'none' }))
			.mockImplementationOnce(async () => response({ success: false, error: 'denied' }))
			.mockRejectedValueOnce(new Error('network down'));
		render(Page);
		await fireEvent.input(screen.getByLabelText('IMAP server'), { target: { value: 'imap.test' } });
		await fireEvent.change(screen.getByLabelText('Port'), { target: { value: 'other' } });
		await fireEvent.input(await screen.findByLabelText('Custom port'), { target: { value: '1993' } });
		await fireEvent.input(screen.getByLabelText('Username / Email'), { target: { value: 'alice' } });
		await fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'secret' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Test connection' }));
		expect(await screen.findByText('Failed: denied')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Test connection' }));
		expect(await screen.findByText('Error: network down')).toBeInTheDocument();
	});

	it('starts the EWS path and allows returning from upload', async () => {
		vi.mocked(fetch).mockImplementation(async (input, init) => {
			if (String(input) === '/auth/me/migration' && init?.method === 'POST') return response({ id: 7 });
			return response({ status: 'none' });
		});
		render(Page);
		await fireEvent.click(screen.getByRole('button', { name: 'Exchange EWS' }));
		await fireEvent.input(await screen.findByLabelText('Server URL'), { target: { value: 'https://ews.test/EWS' } });
		await fireEvent.input(screen.getByLabelText('Username'), { target: { value: 'ACME\\alice' } });
		await fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'secret' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Next: Upload data' }));
		await fireEvent.click(screen.getByRole('button', { name: 'Back' }));
		expect(screen.getByLabelText('Server URL')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Next: Upload data' }));
		await fireEvent.click(screen.getByRole('button', { name: 'Start migration' }));
		const create = vi.mocked(fetch).mock.calls.find(([url, init]) => String(url) === '/auth/me/migration' && init?.method === 'POST');
		expect(JSON.parse(String(create?.[1]?.body))).toEqual(expect.objectContaining({ source_type: 'ews', ews_config: expect.objectContaining({ server_url: 'https://ews.test/EWS' }) }));
	});

	it('renders both Microsoft 365 configuration outcomes', async () => {
		admin.globalConfig.mockImplementation(async (type: string) => type === 'm365' ? null : null);
		const { unmount } = render(Page);
		await fireEvent.click(screen.getByRole('button', { name: 'Microsoft 365' }));
		expect(await screen.findByText(/has not been configured yet/i)).toBeInTheDocument();
		unmount();
		admin.globalConfig.mockImplementation(async (type: string) => type === 'm365' ? { configured: true } : null);
		render(Page);
		await fireEvent.click(screen.getByRole('button', { name: 'Microsoft 365' }));
		expect(await screen.findByText(/administrator has configured Microsoft 365/i)).toBeInTheDocument();
	});

	it('restores a completed job and reports imported/skipped totals', async () => {
		vi.mocked(fetch).mockResolvedValue(response({ status: 'completed', progress: { ics: { imported: 8, skipped: 2 } }, error_log: [] }));
		render(Page);
		expect(await screen.findByText('Mail imported: 8')).toBeInTheDocument();
		expect(screen.getByText('Skipped: 2')).toBeInTheDocument();
	});

	it('controls a paused job and surfaces resume/cancel failures', async () => {
		vi.mocked(fetch).mockImplementation(async (input, init) => {
			const url = String(input);
			if (url.endsWith('/resume')) throw new Error('resume unavailable');
			if (url.endsWith('/cancel')) throw new Error('cancel unavailable');
			if (url.endsWith('/test-imap')) return response({ success: true });
			if (url === '/auth/me/migration' && init?.method === 'POST') return response({ id: 9 });
			if (!init?.method) return response({ status: 'none' });
			return response({});
		});
		render(Page);
		await fireEvent.input(screen.getByLabelText('IMAP server'), { target: { value: 'imap.test' } });
		await fireEvent.input(screen.getByLabelText('Username / Email'), { target: { value: 'alice' } });
		await fireEvent.input(screen.getByLabelText('Password'), { target: { value: 'secret' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Test connection' }));
		await screen.findByText('Connection successful');
		await fireEvent.click(screen.getByRole('button', { name: 'Next: Upload data' }));
		await fireEvent.click(screen.getByRole('button', { name: 'Start migration' }));
		await screen.findByText('Migration in progress');
		await fireEvent.click(screen.getByRole('button', { name: 'Pause migration' }));
		expect(await screen.findByRole('button', { name: 'Resume migration' })).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Resume migration' }));
		expect(await screen.findByText('resume unavailable')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Cancel migration' }));
		expect(await screen.findByText('cancel unavailable')).toBeInTheDocument();
	});

	it('surfaces failed-job and polling errors without losing the page', async () => {
		vi.mocked(fetch).mockResolvedValueOnce(response({ status: 'failed', progress: 'invalid', error_log: ['source rejected'] }));
		const { unmount } = render(Page);
		expect(await screen.findByRole('alert')).toHaveTextContent('source rejected');
		unmount();
		vi.mocked(fetch).mockRejectedValue(new Error('status offline'));
		render(Page);
		expect(await screen.findByRole('alert')).toHaveTextContent('status offline');
	});
});
