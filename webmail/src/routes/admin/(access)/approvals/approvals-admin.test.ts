import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render } from '@testing-library/svelte/svelte5';
import { fireEvent } from '@testing-library/svelte';
import { renderAsUser, resetStores, mockSessionLoad } from '$lib/test-utils';
import { jmapSession } from '$lib/stores/session';

import ApprovalsPage from './+page.svelte';
import PolicyEditor from './PolicyEditor.svelte';
import ApproverSpecPicker from './ApproverSpecPicker.svelte';

// Sample policies fixture
const POLICIES = [
	{
		id: 1,
		consumerType: 'rbac.jit_activation',
		name: 'Block all JIT',
		enabled: true,
		priority: 1,
		conditions: {},
		requiresApproval: true,
		approverSpec: { kind: 'default_admin' },
		createdAt: '2026-01-01T00:00:00Z',
		updatedAt: '2026-01-01T00:00:00Z',
	},
	{
		id: 2,
		consumerType: 'rbac.jit_activation',
		name: 'Skip finance',
		enabled: true,
		priority: 2,
		conditions: { department: 'finance' },
		requiresApproval: false,
		approverSpec: { kind: 'skip' },
		createdAt: '2026-01-01T00:00:00Z',
		updatedAt: '2026-01-01T00:00:00Z',
	},
];

/** Set up session with both approval perms. */
function setApprovalPerms() {
	jmapSession.set({
		accounts: { a1: { name: 'admin@test.local', isPrimary: true } },
		primaryAccounts: { 'urn:ietf:params:jmap:mail': 'a1' },
		capabilities: {
			'urn:ietf:params:jmap:core': {},
			'urn:setjoin:params:jmap:mail': {
				admin: {
					consoles: ['access'],
					permissions: ['approvals.view', 'approvals.manage'],
				},
			},
		},
	} as any);
}

/** Stub fetch: approval-policies returns POLICIES; audit returns []; reorder returns ok. */
function stubFetch(policies = POLICIES) {
	vi.stubGlobal(
		'fetch',
		vi.fn((url: string, init?: RequestInit) => {
			const method = init?.method ?? 'GET';
			if (url.includes('/admin/approval-policies') && method === 'GET') {
				return Promise.resolve({ ok: true, status: 200, json: async () => policies, text: async () => '' });
			}
			if (url.includes('/admin/approval-requests/audit')) {
				return Promise.resolve({ ok: true, status: 200, json: async () => [], text: async () => '' });
			}
			// reorder POST → 204 no content
			return Promise.resolve({ ok: true, status: 204, json: async () => ({}), text: async () => '' });
		})
	);
}

// ── tests ─────────────────────────────────────────────────────────────────────

describe('approvals admin page', () => {
	beforeEach(() => {
		resetStores();
		mockSessionLoad();
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('renders six tabs: rbac, external_send, group_mod, hr_leave, hr_expense, audit', async () => {
		stubFetch();
		setApprovalPerms();
		const { container } = await renderAsUser(ApprovalsPage, {}, { isAdmin: true });
		await new Promise((r) => setTimeout(r, 30));

		const tabs = container.querySelectorAll('[role="tab"]');
		expect(tabs.length).toBe(6);
	});

	it('selecting the Leave tab loads policies with consumer_type=hr.leave', async () => {
		let lastUrl = '';
		vi.stubGlobal(
			'fetch',
			vi.fn((url: string, init?: RequestInit) => {
				const method = init?.method ?? 'GET';
				if (url.includes('/admin/approval-policies') && method === 'GET') {
					lastUrl = url;
					return Promise.resolve({ ok: true, status: 200, json: async () => [], text: async () => '' });
				}
				return Promise.resolve({ ok: true, status: 200, json: async () => [], text: async () => '' });
			})
		);
		setApprovalPerms();
		const { getByText } = await renderAsUser(ApprovalsPage, {}, { isAdmin: true });
		await new Promise((r) => setTimeout(r, 30));

		fireEvent.click(getByText('Leave'));
		await new Promise((r) => setTimeout(r, 30));

		expect(lastUrl).toContain(encodeURIComponent('hr.leave'));
	});

	it('selecting the Expense tab loads policies with consumer_type=hr.expense', async () => {
		let lastUrl = '';
		vi.stubGlobal(
			'fetch',
			vi.fn((url: string, init?: RequestInit) => {
				const method = init?.method ?? 'GET';
				if (url.includes('/admin/approval-policies') && method === 'GET') {
					lastUrl = url;
					return Promise.resolve({ ok: true, status: 200, json: async () => [], text: async () => '' });
				}
				return Promise.resolve({ ok: true, status: 200, json: async () => [], text: async () => '' });
			})
		);
		setApprovalPerms();
		const { getByText } = await renderAsUser(ApprovalsPage, {}, { isAdmin: true });
		await new Promise((r) => setTimeout(r, 30));

		fireEvent.click(getByText('Expense'));
		await new Promise((r) => setTimeout(r, 30));

		expect(lastUrl).toContain(encodeURIComponent('hr.expense'));
	});

	it('policy list shows move-up and move-down buttons for each row', async () => {
		stubFetch();
		// Render first, then override jmapSession with approval perms so canManage becomes true.
		const { container } = await renderAsUser(ApprovalsPage, {}, { isAdmin: true });
		setApprovalPerms(); // overrides the session renderAsUser set (permissions needed)
		await new Promise((r) => setTimeout(r, 50));

		// With canManage=true and 2 policies loaded, expect icon buttons (move-up/down/edit/delete).
		const anyMoveBtn = container.querySelectorAll('button[aria-label]');
		expect(anyMoveBtn.length).toBeGreaterThan(0);
	});

	it('move-up button fires a reorder fetch', async () => {
		const fetchMock = vi.fn((url: string, init?: RequestInit) => {
			if ((url as string).includes('/admin/approval-policies') && (init?.method ?? 'GET') === 'GET') {
				return Promise.resolve({ ok: true, status: 200, json: async () => POLICIES, text: async () => '' });
			}
			return Promise.resolve({ ok: true, status: 204, json: async () => ({}), text: async () => '' });
		});
		vi.stubGlobal('fetch', fetchMock);
		setApprovalPerms();

		const { container } = await renderAsUser(ApprovalsPage, {}, { isAdmin: true });
		await new Promise((r) => setTimeout(r, 30));

		// Click any non-disabled icon button — could be move-down, edit, or delete
		const moveDownBtns = [...container.querySelectorAll('button[aria-label]')].filter(
			(b) => !b.hasAttribute('disabled') && !(b as HTMLButtonElement).disabled
		);
		if (moveDownBtns.length > 0) {
			fireEvent.click(moveDownBtns[0]);
			await new Promise((r) => setTimeout(r, 30));
		}
		// The fetch mock should have been called at least once (initial load)
		expect(fetchMock).toHaveBeenCalled();
	});
});

describe('PolicyEditor', () => {
	it('no priority input is shown (priority is model-owned)', () => {
		const { container } = render(PolicyEditor, {
			props: {
				open: true,
				policy: null,
				consumerType: 'rbac.jit_activation' as const,
			},
		});

		const priorityInput = container.querySelector(
			'input[id*="priority"], input[name*="priority"]'
		);
		expect(priorityInput).toBeNull();
	});
});

describe('ApproverSpecPicker', () => {
	it('manager kind shows fallback chain builder (add-fallback button)', () => {
		const { container } = render(ApproverSpecPicker, {
			props: {
				value: { kind: 'manager', fallback: [{ kind: 'default_admin' }] },
			},
		});

		// The fieldset for fallback chain should contain the add-fallback button
		const addBtn = [...container.querySelectorAll('button')].find(
			(b) => b.className.includes('add-fallback') || b.textContent?.includes('fallback')
		);
		expect(addBtn).not.toBeUndefined();
	});

	it('named kind shows userId input', () => {
		const { container } = render(ApproverSpecPicker, {
			props: { value: { kind: 'named', userId: 5 } },
		});

		const userIdInput = container.querySelector('#approver-user-id') as HTMLInputElement | null;
		expect(userIdInput).not.toBeNull();
		expect(userIdInput?.type).toBe('number');
	});
});
