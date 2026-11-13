import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen } from '@testing-library/svelte/svelte5';
import Page from './+page.svelte';

const doc = {
	id: 9,
	name: 'Acceptable use',
	version: 2,
	enabled: true,
	body_md: 'Use company data responsibly.',
	created_at: '2026-07-01T00:00:00Z',
	updated_at: '2026-07-20T00:00:00Z',
};

function response(body: unknown, status = 200) {
	return new Response(status === 204 ? null : typeof body === 'string' ? body : JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json' },
	});
}

describe('terms-of-use admin page', () => {
	beforeEach(() => vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response([doc]))));
	afterEach(() => vi.unstubAllGlobals());

	it('loads, edits, and saves an existing document', async () => {
		const fetchMock = vi.mocked(fetch);
		fetchMock.mockResolvedValueOnce(response([doc])).mockResolvedValueOnce(response({ ...doc, version: 3 }));
		render(Page);
		await vi.waitFor(() => expect(screen.getByText('Acceptable use')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Edit' }));
		await fireEvent.click(screen.getByRole('button', { name: /Bump version/ }));
		await fireEvent.input(screen.getByLabelText('Body (markdown)'), { target: { value: 'Updated terms' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/admin/terms-of-use/9', expect.objectContaining({ method: 'PUT' })));
	});

	it('creates from the empty state and renders the preview as inert text', async () => {
		const fetchMock = vi.mocked(fetch);
		fetchMock.mockResolvedValueOnce(response([])).mockResolvedValueOnce(response(doc));
		render(Page);
		await vi.waitFor(() => expect(screen.getByText('No terms of use yet')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Create your first document' }));
		await fireEvent.input(screen.getByLabelText('Name'), { target: { value: 'Acceptable use' } });
		await fireEvent.input(screen.getByLabelText('Body (markdown)'), { target: { value: '<img src=x onerror=alert(1)>' } });
		expect(document.querySelector('.tou-preview')?.textContent).toContain('<img src=x onerror=alert(1)>');
		expect(document.querySelector('.tou-preview img')).toBeNull();
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/admin/terms-of-use', expect.objectContaining({ method: 'POST' })));
	});

	it('requires a destructive confirmation before deleting and returns to empty', async () => {
		const fetchMock = vi.mocked(fetch);
		fetchMock.mockResolvedValueOnce(response([doc])).mockResolvedValueOnce(response('', 204));
		render(Page);
		await vi.waitFor(() => expect(screen.getByText('Acceptable use')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Delete' }));
		expect(fetchMock).toHaveBeenCalledTimes(1);
		const deleteButtons = screen.getAllByRole('button', { name: 'Delete' });
		await fireEvent.click(deleteButtons.at(-1)!);
		await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledWith('/api/admin/terms-of-use/9', { method: 'DELETE' }));
		expect(screen.getByText('No terms of use yet')).toBeTruthy();
	});

	it('surfaces list and save failures and keeps the dialog open', async () => {
		const fetchMock = vi.mocked(fetch);
		fetchMock.mockResolvedValueOnce(response('failed', 503));
		const failed = render(Page);
		await vi.waitFor(() => expect(screen.getByRole('alert')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
		failed.unmount();

		fetchMock.mockReset().mockResolvedValueOnce(response([])).mockResolvedValueOnce(response('invalid document', 400));
		render(Page);
		await vi.waitFor(() => expect(screen.getByText('No terms of use yet')).toBeTruthy());
		await fireEvent.click(screen.getByRole('button', { name: 'Create your first document' }));
		await fireEvent.click(screen.getByRole('button', { name: 'Save' }));
		await vi.waitFor(() => expect(screen.getByRole('alert').textContent).toContain('invalid document'));
	});
});
