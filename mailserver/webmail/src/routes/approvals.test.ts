import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { renderAsUser, resetStores } from '$lib/test-utils';
import { screen, fireEvent, waitFor } from '@testing-library/svelte/svelte5';
import ApprovalsPage from './approvals/+page.svelte';
import { t } from '$lib/i18n';
import en from '$lib/i18n/en';
import de from '$lib/i18n/de';
import zh from '$lib/i18n/zh';

// Approval keys every locale must define
const APPROVAL_KEYS = [
	'app.approvals',
	'approvals.tab.pending',
	'approvals.tab.my_requests',
	'approvals.empty.pending_title',
	'approvals.empty.my_requests_title',
	'approvals.btn.approve',
	'approvals.btn.deny',
	'approvals.decision.approved',
	'approvals.decision.race',
	'approvals.status.pending',
	'approvals.status.approved',
];

const SELF_EMAIL = 'alice@test.local';

const PENDING_ROW = {
	id: 1,
	consumerType: 'rbac.jit_activation' as const,
	requesterUserId: 99,
	requesterName: 'Bob Smith',
	requesterEmail: 'bob@test.local',
	subject: 'Admin: Helpdesk role',
	payload: { role_name: 'Helpdesk', justification: 'Need to reset a password', duration_minutes: 60 },
	status: 'pending' as const,
	approverKind: 'user' as const,
	approverRef: 42,
	approverName: 'Alice',
	createdAt: new Date(Date.now() - 5 * 60_000).toISOString(),
	expiresAt: new Date(Date.now() + 4 * 3600_000).toISOString(),
};

// Self-row: requester is the current user — should be filtered in Pending tab
const SELF_ROW = {
	...PENDING_ROW,
	id: 2,
	requesterUserId: 1,
	requesterName: 'Alice',
	requesterEmail: SELF_EMAIL,
	subject: 'Self-request should not appear',
};

function mockFetch(opts: {
	pendingForMe?: typeof PENDING_ROW[];
	myRequests?: typeof PENDING_ROW[];
	decideStatus?: string;
	decideError?: string;
} = {}) {
	const { pendingForMe = [PENDING_ROW], myRequests = [], decideStatus = 'approved', decideError } = opts;

	vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
		const url = typeof input === 'string' ? input : input.toString();
		const method = init?.method?.toUpperCase() ?? 'GET';

		// Session
		if (url.includes('/.well-known/jmap') || url.includes('/jmap/session')) {
			return {
				ok: true, status: 200,
				json: async () => ({ apiUrl: '/jmap', downloadUrl: '/blobs', uploadUrl: '/blobs', eventSourceUrl: '', username: SELF_EMAIL, primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' }, accounts: { a1: { name: SELF_EMAIL } } }),
				text: async () => '',
			};
		}

		// GET /me/approvals
		if (url.includes('/me/approvals') && method === 'GET') {
			return { ok: true, status: 200, json: async () => ({ pendingForMe, myRequests }), text: async () => '' };
		}

		// POST /me/approvals/{id}/decide
		if (url.includes('/me/approvals/') && method === 'POST') {
			if (decideError) {
				const code = decideError;
				return { ok: false, status: 409, json: async () => ({ code }), text: async () => code };
			}
			return { ok: true, status: 200, json: async () => ({ status: decideStatus }), text: async () => '' };
		}

		return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
	}));
}

describe('Approvals App', () => {
	beforeEach(() => {
		resetStores();
		vi.useFakeTimers({ shouldAdvanceTime: false });
	});

	afterEach(() => {
		vi.restoreAllMocks();
		vi.useRealTimers();
	});

	it('renders pending rows after load', async () => {
		mockFetch();
		await renderAsUser(ApprovalsPage);
		await waitFor(() => expect(screen.getByText('Bob Smith')).toBeInTheDocument());
		expect(screen.getByText('Admin: Helpdesk role')).toBeInTheDocument();
	});

	it('SoD self-row never appears in Pending tab', async () => {
		mockFetch({ pendingForMe: [PENDING_ROW, SELF_ROW] });
		await renderAsUser(ApprovalsPage);
		await waitFor(() => expect(screen.getByText('Bob Smith')).toBeInTheDocument());
		// The self-row subject must not be visible
		expect(screen.queryByText('Self-request should not appear')).toBeNull();
	});

	it('renders empty state "caught up" when Pending is empty', async () => {
		mockFetch({ pendingForMe: [] });
		await renderAsUser(ApprovalsPage);
		await waitFor(() => {
			expect(screen.getByText(t('approvals.empty.pending_title'))).toBeInTheDocument();
		});
	});

	it('selecting a row shows the detail panel evidence', async () => {
		mockFetch();
		await renderAsUser(ApprovalsPage);
		await waitFor(() => expect(screen.getByText('Bob Smith')).toBeInTheDocument());
		fireEvent.click(screen.getByText('Bob Smith'));
		await waitFor(() => {
			expect(screen.getByText('Helpdesk')).toBeInTheDocument(); // role name from payload
		});
	});

	it('Approve button disables on click and fires POST', async () => {
		let postCalled = false;
		vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input.toString();
			const method = init?.method?.toUpperCase() ?? 'GET';
			if (url.includes('/me/approvals') && method === 'GET') {
				return { ok: true, status: 200, json: async () => ({ pendingForMe: [PENDING_ROW], myRequests: [] }), text: async () => '' };
			}
			if (url.includes('/me/approvals/') && method === 'POST') {
				postCalled = true;
				return new Promise(() => {}); // never resolves — keeps button disabled
			}
			return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
		}));

		await renderAsUser(ApprovalsPage);
		await waitFor(() => expect(screen.getByText('Bob Smith')).toBeInTheDocument());
		fireEvent.click(screen.getByText('Bob Smith'));
		await waitFor(() => expect(screen.getByRole('button', { name: /Approve/ })).toBeInTheDocument());

		const approveBtn = screen.getByRole('button', { name: /Approve/ });
		fireEvent.click(approveBtn);

		await waitFor(() => expect(postCalled).toBe(true));
		// Button should be disabled after click
		expect(approveBtn).toBeDisabled();
	});

	it('BZ108 race shows calm inline message and removes row', async () => {
		mockFetch({ decideError: 'BZ108' });
		await renderAsUser(ApprovalsPage);
		await waitFor(() => expect(screen.getByText('Bob Smith')).toBeInTheDocument());
		fireEvent.click(screen.getByText('Bob Smith'));
		await waitFor(() => expect(screen.getByRole('button', { name: /Approve/ })).toBeInTheDocument());
		fireEvent.click(screen.getByRole('button', { name: /Approve/ }));
		await waitFor(() => expect(screen.queryByText('Bob Smith')).toBeNull());
	});

	it('Cancel button on My requests POSTs /cancel (not /decide) and succeeds', async () => {
		// Regression: onCancel used to POST decision:'cancel' to /decide, which
		// only accepts approve/deny and always 400ed — the Cancel button never
		// actually worked. approval_request_cancel is its own endpoint now.
		const myPendingRow = { ...PENDING_ROW, id: 3, requesterUserId: 1, requesterName: 'Alice', requesterEmail: SELF_EMAIL };
		let calledUrl = '';
		vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
			const url = typeof input === 'string' ? input : input.toString();
			const method = init?.method?.toUpperCase() ?? 'GET';
			if (url.includes('/.well-known/jmap') || url.includes('/jmap/session')) {
				return {
					ok: true, status: 200,
					json: async () => ({ apiUrl: '/jmap', downloadUrl: '/blobs', uploadUrl: '/blobs', eventSourceUrl: '', username: SELF_EMAIL, primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' }, accounts: { a1: { name: SELF_EMAIL } } }),
					text: async () => '',
				};
			}
			if (url.includes('/me/approvals') && method === 'GET') {
				return { ok: true, status: 200, json: async () => ({ pendingForMe: [], myRequests: [myPendingRow] }), text: async () => '' };
			}
			if (url.includes('/me/approvals/') && method === 'POST') {
				calledUrl = url;
				return { ok: true, status: 200, json: async () => ({ status: 'cancelled' }), text: async () => '' };
			}
			return { ok: true, status: 200, json: async () => ({}), text: async () => '' };
		}));

		await renderAsUser(ApprovalsPage);
		fireEvent.click(screen.getByText(t('approvals.tab.my_requests')));
		await waitFor(() => expect(screen.getByText(myPendingRow.subject)).toBeInTheDocument());
		fireEvent.click(screen.getByText(myPendingRow.subject));
		await waitFor(() => expect(screen.getByRole('button', { name: t('approvals.btn.cancel_request') })).toBeInTheDocument());
		fireEvent.click(screen.getByRole('button', { name: t('approvals.btn.cancel_request') }));

		await waitFor(() => expect(calledUrl).toContain('/cancel'));
		expect(calledUrl).not.toContain('/decide');
	});

	it('i18n keys resolve in en, de, zh — no missing-key fallback', () => {
		for (const key of APPROVAL_KEYS) {
			// en
			expect(en[key], `en missing key: ${key}`).toBeDefined();
			expect(en[key], `en key falls back: ${key}`).not.toBe(key);
			// de
			expect(de[key], `de missing key: ${key}`).toBeDefined();
			expect(de[key], `de key falls back: ${key}`).not.toBe(key);
			// zh
			expect(zh[key], `zh missing key: ${key}`).toBeDefined();
			expect(zh[key], `zh key falls back: ${key}`).not.toBe(key);
		}
	});
});
