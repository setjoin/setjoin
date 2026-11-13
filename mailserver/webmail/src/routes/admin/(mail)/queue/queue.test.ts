import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, screen, waitFor } from '@testing-library/svelte/svelte5';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

const mocks = vi.hoisted(() => ({ fetch: vi.fn(), toast: vi.fn() }));
vi.mock('$lib/admin/client', () => ({ adminFetch: mocks.fetch }));
vi.mock('$lib/components/ui', async () => ({
	...(await vi.importActual<typeof import('$lib/components/ui')>('$lib/components/ui')),
	showToast: mocks.toast,
}));
import Page from './+page.svelte';

const summary = { pending: 2, deferred: 1, bouncedToday: 1, stuck: 1, oldestMinutes: '2d' };
const items = [
	{ id: 1, messageId: 'm1', fromAddr: 'a'.repeat(50) + '@test', recipients: ['a@test', 'b@test', 'c@test'], status: 'deferred', attemptCount: 2, nextAttemptAt: '', lastError: 'temporary failure', queuedAt: '2026-01-01T11:59:30Z', mailboxId: 1 },
	{ id: 2, messageId: 'm2', fromAddr: 'bob@test', recipients: [], status: 'pending', attemptCount: 10, nextAttemptAt: '', lastError: '', queuedAt: '2026-01-01T11:30:00Z', mailboxId: null },
	{ id: 3, messageId: 'm3', fromAddr: 'carol@test', recipients: ['d@test'], status: 'delivered', attemptCount: 1, nextAttemptAt: '', lastError: '', queuedAt: '2026-01-01T10:00:00Z', mailboxId: 2 },
	{ id: 4, messageId: 'm4', fromAddr: 'dan@test', recipients: ['e@test'], status: 'bounced', attemptCount: 1, nextAttemptAt: '', lastError: 'permanent', queuedAt: '2025-12-30T12:00:00Z', mailboxId: 3 },
];

function res(body: unknown) { return { ok: true, json: async () => body } as Response; }
function grant() { jmapSession.set({ accounts: {}, primaryAccounts: {}, capabilities: { 'urn:setjoin:params:jmap:mail': { admin: { consoles: ['mail'], permissions: ['queue.write'] } } } } as never); }
function route(input: string, init?: RequestInit) {
	if (input.endsWith('/summary')) return Promise.resolve(res(summary));
	if (input.includes('/retry') || input.includes('/bounce')) return Promise.resolve(res({}));
	if (!init?.method && input.includes('/queue?')) return Promise.resolve(res(items));
	return Promise.resolve(res({}));
}
async function renderPage() {
	await renderAsUser(Page, {}, { isAdmin: true }); grant();
	await screen.findByText('temporary failure');
}

describe('mail queue operations', () => {
	beforeEach(() => {
		resetStores(); vi.clearAllMocks();
		mocks.fetch.mockImplementation(route);
		vi.spyOn(Date, 'now').mockReturnValue(new Date('2026-01-01T12:00:00Z').getTime());
	});
	afterEach(() => { vi.restoreAllMocks(); resetStores(); });

	it('renders every status, recipient compaction, age bucket, and refresh', async () => {
		await renderPage();
		expect(screen.getByText('a@test, b@test +1')).toBeInTheDocument();
		expect(screen.getByText('30s ago')).toBeInTheDocument();
		expect(screen.getByText('30m ago')).toBeInTheDocument();
		expect(screen.getByText('2h ago')).toBeInTheDocument();
		expect(screen.getByText('2d ago')).toBeInTheDocument();
		expect(screen.getByText('deferred')).toBeInTheDocument();
		expect(screen.getByText('delivered')).toBeInTheDocument();
		expect(screen.getByText('bounced')).toBeInTheDocument();
		await fireEvent.click(screen.getByRole('button', { name: 'Refresh' }));
		await waitFor(() => expect(mocks.fetch).toHaveBeenCalledWith('/admin/queue/summary'));
	});

	it('reloads the selected status tab and handles an empty queue', async () => {
		await renderPage();
		mocks.fetch.mockImplementation((input: string) => input.endsWith('/summary') ? Promise.resolve(res(summary)) : Promise.resolve(res([])));
		await fireEvent.click(screen.getByRole('tab', { name: /Deferred/ }));
		expect(await screen.findByText('Queue is empty.')).toBeInTheDocument();
		expect(mocks.fetch).toHaveBeenCalledWith('/admin/queue?status=deferred&limit=100');
	});

	it('retries and releases queue items, including the behavioral undo', async () => {
		await renderPage();
		const retries = screen.getAllByRole('button', { name: 'Retry' });
		await fireEvent.click(retries[0]);
		await waitFor(() => expect(mocks.fetch).toHaveBeenCalledWith('/admin/queue/1/retry', { method: 'POST' }));
		await waitFor(() => expect(mocks.toast).toHaveBeenCalledWith('Retrying delivery now'));

		const release = screen.getAllByRole('button', { name: 'Release' })[0];
		await waitFor(() => expect(release).toBeEnabled());
		await fireEvent.click(release);
		await waitFor(() => expect(mocks.fetch).toHaveBeenCalledWith('/admin/queue/1/bounce', { method: 'POST' }));
		await waitFor(() => expect(mocks.toast).toHaveBeenCalledWith('Released to recipient inbox', expect.objectContaining({ actionLabel: 'Undo' })));
		const toastOptions = mocks.toast.mock.calls.find(([message]) => message === 'Released to recipient inbox')?.[1] as { onAction: () => Promise<void> };
		expect(toastOptions).toEqual(expect.objectContaining({ actionLabel: 'Undo' }));
		await toastOptions.onAction();
		expect(mocks.fetch).toHaveBeenCalledWith('/admin/queue/1/retry', { method: 'POST' });
	});

	it('surfaces initial, retry, and release failures and always re-enables controls', async () => {
		mocks.fetch.mockRejectedValueOnce(new Error('summary offline'));
		const first = await renderAsUser(Page, {}, { isAdmin: true });
		expect(await screen.findByText('summary offline')).toBeInTheDocument();
		first.unmount();

		mocks.fetch.mockImplementation(route);
		await renderPage();
		mocks.fetch.mockRejectedValueOnce(new Error('retry offline'));
		await fireEvent.click(screen.getAllByRole('button', { name: 'Retry' })[0]);
		expect(await screen.findByText('retry offline')).toBeInTheDocument();
		expect(screen.getAllByRole('button', { name: 'Retry' })[0]).toBeEnabled();
		mocks.fetch.mockRejectedValueOnce(new Error('release offline'));
		await fireEvent.click(screen.getAllByRole('button', { name: 'Release' })[0]);
		expect(await screen.findByText('release offline')).toBeInTheDocument();
	});
});
