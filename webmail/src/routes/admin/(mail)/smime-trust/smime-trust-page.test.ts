import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor, within } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';

const api = vi.hoisted(() => ({ fetch: vi.fn() }));
vi.mock('$lib/admin/client', () => ({ adminFetch: api.fetch }));
import Page from './+page.svelte';

const anchors = [
	{ id: 1, label: 'Expired CA', subjectCn: '', fingerprint: 'aa', domainId: null, notBefore: '2020-01-01', notAfter: '2021-01-01', createdAt: '2020-01-01' },
	{ id: 2, label: 'Current CA', subjectCn: 'Current Root', fingerprint: 'bb', domainId: 1, notBefore: '2026-01-01', notAfter: '2099-01-01', createdAt: '2026-01-01' },
];
function response(data: unknown = {}, ok = true, status = 200) { return { ok, status, json: vi.fn().mockResolvedValue(data) }; }

describe('S/MIME trust anchors', () => {
	beforeEach(() => {
		resetStores(); vi.clearAllMocks();
		api.fetch.mockImplementation(async (path: string) => path === '/admin/smime/trust-anchors' ? response({ anchors }) : response({}));
	});
	afterEach(() => resetStores());

	it('renders expiration states, imports a file, and deletes an anchor', async () => {
		await renderAsUser(Page, {}, { isAdmin: true });
		expect(await screen.findByText('Expired CA')).toBeInTheDocument();
		expect(screen.getByText('Current Root')).toBeInTheDocument();
		expect(screen.getByText('Expired')).toBeInTheDocument();

		const file = new File(['certificate'], 'root.pem', { type: 'application/x-pem-file' });
		await fireEvent.change(screen.getByLabelText('Root certificate (PEM)'), { target: { files: [file] } });
		await fireEvent.input(screen.getByLabelText('Label'), { target: { value: 'Imported CA' } });
		await fireEvent.click(screen.getAllByRole('button', { name: 'Import' })[0]);
		await waitFor(() => expect(api.fetch).toHaveBeenCalledWith('/admin/smime/trust-anchors', expect.objectContaining({ method: 'POST' })));

		await fireEvent.click(screen.getAllByRole('button', { name: 'Delete' })[0]);
		const dialog = screen.getByRole('dialog', { name: 'Delete' });
		await fireEvent.click(within(dialog).getByRole('button', { name: 'Delete' }));
		await waitFor(() => expect(api.fetch).toHaveBeenCalledWith('/admin/smime/trust-anchors/1', { method: 'DELETE' }));
	});

	it('shows load, import, and delete API errors', async () => {
		api.fetch.mockResolvedValueOnce(response({ error: 'load denied' }, false, 403));
		await renderAsUser(Page, {}, { isAdmin: true });
		expect(await screen.findByRole('alert')).toHaveTextContent('load denied');
	});
});
