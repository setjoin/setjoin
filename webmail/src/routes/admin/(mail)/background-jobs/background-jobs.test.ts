import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { render, fireEvent } from '@testing-library/svelte/svelte5';
import { cleanup, screen, waitFor, within } from '@testing-library/svelte';
import { authenticated, user, authInitializing } from '$lib/stores/auth';
import { jmapSession } from '$lib/stores/session';

import Page from './+page.svelte';

// Set an admin session that carries queue.read + queue.write so the derived
// adminPermissions store resolves and the Retry control is enabled.
function setAdminSession() {
	authenticated.set(true);
	user.set({ email: 'ops@test.local', isAdmin: true, hasMailbox: true } as never);
	authInitializing.set(false);
	jmapSession.set({
		accounts: { a1: { name: 'ops@test.local', isPrimary: true } },
		primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' },
		capabilities: {
			'urn:ietf:params:jmap:core': {},
			'urn:setjoin:params:jmap:mail': {
				admin: { consoles: ['mail'], permissions: ['queue.read', 'queue.write'] }
			}
		}
	} as never);
}

function setViewOnlySession() {
	setAdminSession();
	jmapSession.update((session) => {
		const copy = structuredClone(session) as any;
		copy.capabilities['urn:setjoin:params:jmap:mail'].admin.permissions = ['queue.read'];
		return copy;
	});
}

function response(data: unknown, ok = true, status = 200): Response {
	return { ok, status, json: async () => data, text: async () => '' } as Response;
}

const DEAD_ROW = {
	id: '101',
	queue: 'journal',
	status: 'dead',
	normalized: 'dead',
	label: '<msg@test>',
	attemptCount: 5,
	nextAttemptAt: null,
	lastError: 'materialize failed',
	queuedAt: new Date().toISOString()
};

// Stub fetch (which adminFetch wraps): summary returns counts, the journal list
// returns one dead row; outbound/scheduled return empty.
function mockFetch() {
	return vi.fn(async (input: RequestInfo | URL, _init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input.toString();
		if (url.includes('/summary')) {
			if (url.includes('/journal/')) {
				return { ok: true, status: 200, json: async () => ({ active: 1, failed: 0, dead: 2, done: 5, total: 8 }), text: async () => '' } as Response;
			}
			return { ok: true, status: 200, json: async () => ({ active: 0, failed: 0, dead: 0, done: 0, total: 0 }), text: async () => '' } as Response;
		}
		if (url.includes('/admin/jobs/journal')) {
			return {
				ok: true,
				status: 200,
				json: async () => [
					DEAD_ROW
				],
				text: async () => ''
			} as Response;
		}
		// outbound / scheduled lists
		return { ok: true, status: 200, json: async () => [], text: async () => '' } as Response;
	});
}

describe('background-jobs page', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		vi.stubGlobal('fetch', mockFetch());
		setAdminSession();
	});

	afterEach(() => cleanup());

	it('renders a section heading for each queue', async () => {
		render(Page);
		await waitFor(() => {
			expect(screen.getByRole('heading', { name: /Journal/i })).toBeTruthy();
			expect(screen.getByRole('heading', { name: /Outbound/i })).toBeTruthy();
			expect(screen.getByRole('heading', { name: /Scheduled/i })).toBeTruthy();
		});
	});

	it('renders the dead journal row with its last error', async () => {
		render(Page);
		await waitFor(() => {
			expect(screen.getByText(/materialize failed/)).toBeTruthy();
		});
	});

	it('shows a Retry button for a dead journal row', async () => {
		render(Page);
		await waitFor(() => {
			expect(screen.getByRole('button', { name: /Retry/i })).toBeTruthy();
		});
	});

	it('fails closed with a page-level refresh action when every queue is unavailable', async () => {
		vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('gateway unavailable')));
		render(Page);
		await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(/couldn|load|unavailable/i));
		expect(screen.getAllByRole('button', { name: /refresh/i }).length).toBeGreaterThan(1);
		expect(screen.getAllByRole('alert')).toHaveLength(3);
	});

	it('retains the cross-queue trouble verdict when only some sections load', async () => {
		vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
			const url = String(input);
			if (url.includes('outbound')) throw new Error('outbound offline');
			if (url.includes('/summary/journal')) return response({ active: 0, failed: 1, dead: 1, done: 2, total: 4 });
			if (url.includes('/summary/')) return response({ active: 0, failed: 0, dead: 0, done: 0, total: 0 });
			if (url.includes('/journal')) return response([DEAD_ROW]);
			return response([]);
		}));
		render(Page);
		await waitFor(() => expect(screen.getByRole('status')).toHaveTextContent(/journal/i));
		expect(screen.getByRole('status')).toHaveTextContent(/check|stale|recheck/i);
		expect(screen.getByRole('alert')).toHaveTextContent(/outbound offline/i);
	});

	it('toggles a section between attention-only and all rows', async () => {
		const fetchMock = mockFetch();
		vi.stubGlobal('fetch', fetchMock);
		render(Page);
		await screen.findByText(/materialize failed/i);
		const showAll = screen.getAllByRole('button', { name: /show all/i })[0];
		await fireEvent.click(showAll);
		await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
			expect.stringContaining('/admin/jobs/journal?status=all&limit=100'),
			expect.anything()
		));
		expect(screen.getAllByRole('button', { name: /show only failures/i })[0]).toBeTruthy();
	});

	it('supports retry confirmation cancel and restores focus to the trigger', async () => {
		render(Page);
		const retry = await screen.findByRole('button', { name: /^retry$/i });
		await fireEvent.click(retry);
		const group = screen.getByRole('group');
		expect(group).toHaveTextContent(/re-queue/i);
		await fireEvent.click(within(group).getByRole('button', { name: /cancel/i }));
		await waitFor(() => expect(document.activeElement?.id).toBe('sj-retry-101'));
	});

	it('retries a dead journal row and refreshes the section', async () => {
		let journalLoads = 0;
		const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = String(input);
			if (url.endsWith('/journal/101/retry')) {
				expect(init?.method).toBe('POST');
				return response({});
			}
			if (url.includes('/summary/journal')) return response({ active: 0, failed: 0, dead: journalLoads ? 0 : 1, done: journalLoads ? 1 : 0, total: 1 });
			if (url.includes('/summary/')) return response({ active: 0, failed: 0, dead: 0, done: 0, total: 0 });
			if (url.includes('/admin/jobs/journal')) return response(journalLoads++ ? [] : [DEAD_ROW]);
			return response([]);
		});
		vi.stubGlobal('fetch', fetchMock);
		render(Page);
		await fireEvent.click(await screen.findByRole('button', { name: /^retry$/i }));
		await fireEvent.click(within(screen.getByRole('group')).getByRole('button', { name: /re-queue/i }));
		await waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
			expect.stringContaining('/journal/101/retry'),
			expect.objectContaining({ method: 'POST' })
		));
		await waitFor(() => expect(screen.queryByText(/materialize failed/i)).toBeNull());
	});

	it('keeps a failed retry actionable and shows an inline section error', async () => {
		const base = mockFetch();
		vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			if (String(input).endsWith('/journal/101/retry')) throw new Error('retry backend unavailable');
			return base(input, init);
		}));
		render(Page);
		await fireEvent.click(await screen.findByRole('button', { name: /^retry$/i }));
		await fireEvent.click(within(screen.getByRole('group')).getByRole('button', { name: /re-queue/i }));
		expect(await screen.findByRole('alert')).toHaveTextContent(/retry backend unavailable/i);
		expect(await screen.findByRole('button', { name: /^retry$/i })).toBeEnabled();
	});

	it('disables retry for administrators without queue.write', async () => {
		setViewOnlySession();
		render(Page);
		expect(await screen.findByRole('button', { name: /^retry$/i })).toBeDisabled();
	});

	it('renders normalized status variants and truncates oversized labels and errors', async () => {
		const long = 'x'.repeat(80);
		vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL) => {
			const url = String(input);
			if (url.includes('/summary/')) return response({ active: 1, failed: 1, dead: 1, done: 1, total: 4 });
			if (url.includes('/admin/jobs/journal')) return response([
				{ ...DEAD_ROW, id: '1', normalized: 'active', status: 'active', label: long, lastError: null },
				{ ...DEAD_ROW, id: '2', normalized: 'failed', status: 'failed', lastError: long },
				{ ...DEAD_ROW, id: '3', normalized: 'dead', status: 'dead' },
				{ ...DEAD_ROW, id: '4', normalized: 'done', status: 'done' },
			]);
			return response([]);
		}));
		render(Page);
		await screen.findByText('active');
		expect(screen.getAllByTitle(long)[0]).toHaveTextContent(/…$/);
		expect(screen.getByText('done')).toBeTruthy();
	});
});
