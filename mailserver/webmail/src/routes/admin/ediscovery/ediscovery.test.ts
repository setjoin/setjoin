import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const api = vi.hoisted(() => ({ fetch: vi.fn() }));
vi.mock('$lib/admin/client', () => ({ adminFetch: api.fetch }));
import Page from './+page.svelte';

function res(body: unknown, ok = true, status = 200) { return { ok, status, json: async () => body } as Response; }
const rows = [{ id: 4, subject: 'Evidence', from: 'alice@test', mailbox: 'legal@test', receivedAt: '2026-01-01T00:00:00Z' }];

function grant() {
	jmapSession.set({ accounts: {}, primaryAccounts: {}, capabilities: { 'urn:setjoin:params:jmap:mail': { admin: { consoles: ['mail'], permissions: ['compliance.write'] } } } } as never);
}

async function renderPage() {
	await renderAsUser(Page, {}, { isAdmin: true });
	grant();
	await waitFor(() => expect(screen.getByRole('button', { name: 'Search' })).toBeEnabled());
}

describe('admin eDiscovery', () => {
	beforeEach(() => {
		resetStores(); vi.clearAllMocks();
		vi.stubGlobal('confirm', vi.fn(() => true));
		vi.stubGlobal('alert', vi.fn());
		vi.stubGlobal('open', vi.fn());
	});
	afterEach(() => { vi.unstubAllGlobals(); resetStores(); });

	it('runs and polls a bounded search with all filters', async () => {
		api.fetch.mockResolvedValueOnce(res({ id: 12 })).mockResolvedValueOnce(res({ search: { status: 'complete' }, results: rows }));
		await renderPage();
		await fireEvent.input(screen.getByPlaceholderText('Keywords (body/subject search)'), { target: { value: 'contract' } });
		await fireEvent.input(screen.getByPlaceholderText('From address'), { target: { value: 'alice@test' } });
		const dates = Array.from(document.querySelectorAll<HTMLInputElement>('input[type="date"]'));
		await fireEvent.input(dates[0], { target: { value: '2026-01-01' } });
		await fireEvent.input(dates[1], { target: { value: '2026-01-31' } });
		const callbacks: Array<() => void> = [];
		const timer = vi.spyOn(globalThis, 'setTimeout').mockImplementation(((callback: () => void) => { callbacks.push(callback); return 1; }) as typeof setTimeout);
		await fireEvent.click(screen.getByRole('button', { name: 'Search' }));
		timer.mockRestore();
		await callbacks.shift()?.();
		expect(await screen.findByText('Evidence')).toBeInTheDocument();
		expect(screen.getByText('1 results (complete)')).toBeInTheDocument();
		expect(api.fetch).toHaveBeenNthCalledWith(2, '/admin/ediscovery/12');
		const body = JSON.parse(String((api.fetch.mock.calls[0][1] as RequestInit).body));
		expect(body).toEqual(expect.objectContaining({ keywords: 'contract', fromAddr: 'alice@test', dateFrom: '2026-01-01', dateTo: '2026-01-31' }));
	});

	it('places selected evidence on hold and exports only selected ids', async () => {
		api.fetch
			.mockResolvedValueOnce(res({ id: 12 }))
			.mockResolvedValueOnce(res({ search: { status: 'complete' }, results: rows }))
			.mockResolvedValueOnce(res({ held: 1, total: 1 }));
		await renderPage();
		await fireEvent.input(screen.getByPlaceholderText('Keywords (body/subject search)'), { target: { value: 'evidence' } });
		const callbacks: Array<() => void> = [];
		const timer = vi.spyOn(globalThis, 'setTimeout').mockImplementation(((callback: () => void) => { callbacks.push(callback); return 1; }) as typeof setTimeout);
		await fireEvent.click(screen.getByRole('button', { name: 'Search' }));
		timer.mockRestore();
		await callbacks.shift()?.();
		await screen.findByText('Evidence');
		const checkbox = screen.getByRole('checkbox');
		await fireEvent.click(checkbox);
		await fireEvent.click(screen.getByRole('button', { name: 'Hold (1)' }));
		await waitFor(() => expect(alert).toHaveBeenCalledWith('Held 1 of 1 messages'));
		expect(confirm).toHaveBeenCalledWith('Place 1 messages on litigation hold?');
		await fireEvent.click(screen.getByRole('button', { name: 'Export (1)' }));
		expect(open).toHaveBeenCalledWith('/admin/ediscovery/export?ids=4', '_blank');
		await fireEvent.click(checkbox);
		expect(screen.getByRole('button', { name: 'Hold (0)' })).toBeDisabled();
	});

	it('honors cancelled confirmation and surfaces start, poll, and hold failures', async () => {
		api.fetch.mockResolvedValueOnce(res({}, false, 403));
		await renderPage();
		await fireEvent.input(screen.getByPlaceholderText('From address'), { target: { value: 'alice@test' } });
		await fireEvent.click(screen.getByRole('button', { name: 'Search' }));
		expect(await screen.findByRole('alert')).toHaveTextContent('Search failed (403)');

		api.fetch.mockResolvedValueOnce(res({ id: 13 })).mockResolvedValueOnce(res({}, false, 503));
		let callbacks: Array<() => void> = [];
		let timer = vi.spyOn(globalThis, 'setTimeout').mockImplementation(((callback: () => void) => { callbacks.push(callback); return 1; }) as typeof setTimeout);
		await fireEvent.click(screen.getByRole('button', { name: 'Search' }));
		timer.mockRestore();
		await callbacks.shift()?.();
		expect(await screen.findByRole('alert')).toHaveTextContent('Search status failed (503)');

		api.fetch.mockResolvedValueOnce(res({ id: 14 })).mockResolvedValueOnce(res({ search: { status: 'complete' }, results: rows }));
		callbacks = [];
		timer = vi.spyOn(globalThis, 'setTimeout').mockImplementation(((callback: () => void) => { callbacks.push(callback); return 1; }) as typeof setTimeout);
		await fireEvent.click(screen.getByRole('button', { name: 'Search' }));
		timer.mockRestore();
		await callbacks.shift()?.();
		await screen.findByText('Evidence');
		await fireEvent.click(screen.getByRole('checkbox'));
		vi.mocked(confirm).mockReturnValueOnce(false);
		await fireEvent.click(screen.getByRole('button', { name: 'Hold (1)' }));
		expect(api.fetch).toHaveBeenCalledTimes(5);
		vi.mocked(confirm).mockReturnValueOnce(true);
		api.fetch.mockRejectedValueOnce(new Error('hold offline'));
		await fireEvent.click(screen.getByRole('button', { name: 'Hold (1)' }));
		expect(await screen.findByRole('alert')).toHaveTextContent('hold offline');
	});
});
