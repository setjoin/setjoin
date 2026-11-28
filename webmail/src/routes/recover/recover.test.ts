import { describe, it, expect, vi, beforeEach } from 'vitest';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { waitFor, fireEvent } from '@testing-library/svelte/svelte5';

import RecoverPage from './+page.svelte';

const EMAIL = {
	id: 'e1',
	subject: 'Old report',
	from: [{ email: 'boss@test.local', name: 'Boss' }],
	deletedAt: '2026-06-01T09:00:00Z',
	held: false
};

function jmapResponse(methodName: string, result: unknown, callId = '0') {
	return {
		ok: true,
		status: 200,
		json: async () => ({ methodResponses: [[methodName, result, callId]] }),
		text: async () => ''
	} as Response;
}

const SESSION_OBJECT = {
	accounts: { a1: { name: 'alice@test.local', isPrimary: true } },
	primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' },
	capabilities: { 'urn:ietf:params:jmap:core': {} }
};

function mockRecoverFetch() {
	return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input.toString();
		// loadSession() hits /.well-known/jmap and reads the session object directly.
		if (url.includes('/.well-known/jmap')) {
			return {
				ok: true,
				status: 200,
				json: async () => SESSION_OBJECT,
				text: async () => ''
			} as Response;
		}
		// onMount reads purge config from /jmap/session.
		if (url.includes('/jmap/session')) {
			return {
				ok: true,
				status: 200,
				json: async () => ({ purgeConfig: { deletedPurgeDays: 30 } }),
				text: async () => ''
			} as Response;
		}
		// jmapCall() POSTs method calls to /jmap.
		if (url.includes('/jmap')) {
			const body = init?.body ? JSON.parse(init.body as string) : {};
			const methodCalls = body.methodCalls || [];
			const name = methodCalls[0]?.[0] ?? 'Core/echo';
			const callId = methodCalls[0]?.[2] ?? '0';
			if (name === 'Email/deletedQuery') {
				return jmapResponse('Email/deletedQuery', { list: [EMAIL] }, callId);
			}
			if (name === 'Email/recover' || name === 'Email/purge') {
				return jmapResponse(name, { updated: { e1: null } }, callId);
			}
			return jmapResponse(name, {}, callId);
		}
		return { ok: true, status: 200, json: async () => ({}), text: async () => '' } as Response;
	});
}

describe('Recover deleted items page', () => {
	beforeEach(() => {
		resetStores();
	});

	it('renders deleted rows with accessible per-row select checkboxes', async () => {
		vi.stubGlobal('fetch', mockRecoverFetch());
		const { findByText, findByLabelText } = await renderAsUser(RecoverPage);
		expect(await findByText('Old report')).toBeTruthy();
		// Checkbox must have an accessible name referencing the subject.
		expect(await findByLabelText(/Old report/i)).toBeTruthy();
	});

	it('purge is an irreversible Dialog confirm, not native confirm()', async () => {
		const confirmSpy = vi.fn(() => true);
		vi.stubGlobal('confirm', confirmSpy);
		const fetchSpy = mockRecoverFetch();
		vi.stubGlobal('fetch', fetchSpy);

		const { findByText, findAllByRole, findByRole } = await renderAsUser(RecoverPage);
		await findByText('Old report');
		const purgeBtns = await findAllByRole('button', { name: 'Purge' });
		await fireEvent.click(purgeBtns[0]);

		// A Dialog (role=dialog) opens; native confirm is never used.
		expect(await findByRole('dialog')).toBeTruthy();
		expect(confirmSpy).not.toHaveBeenCalled();
	});

	it('loads the JMAP session once on mount, not on every action', async () => {
		const fetchSpy = mockRecoverFetch();
		vi.stubGlobal('fetch', fetchSpy);
		const { findByText, findAllByRole } = await renderAsUser(RecoverPage);
		await findByText('Old report');

		const recoverBtns = await findAllByRole('button', { name: 'Recover' });
		const recoverBtn = recoverBtns[0];

		// loadSession() GETs /.well-known/jmap — count those.
		function sessionLoads() {
			return fetchSpy.mock.calls.filter((c) => String(c[0]).includes('/.well-known/jmap')).length;
		}

		await waitFor(() => expect(sessionLoads()).toBeGreaterThanOrEqual(1));
		const afterMount = sessionLoads();

		await fireEvent.click(recoverBtn);
		await waitFor(() => {
			expect(
				fetchSpy.mock.calls.some((c) => {
					const init = c[1] as RequestInit | undefined;
					const body = init?.body ? JSON.parse(init.body as string) : {};
					return (body.methodCalls || []).some((m: unknown[]) => m[0] === 'Email/recover');
				})
			).toBe(true);
		});

		// No extra session reload triggered by the action.
		expect(sessionLoads()).toBe(afterMount);
	});
});
