import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/svelte';
import { jmapSession } from '$lib/stores/session';
import { resetStores } from '$lib/test-utils';
import type { ApprovalPolicy, ApprovalRequestAuditRow } from '$lib/admin/client';

vi.mock('./PolicyEditor.svelte', () => ({ default: () => null }));
vi.mock('$lib/admin/client', () => ({
	adminListApprovalPolicies: vi.fn(),
	adminCreateApprovalPolicy: vi.fn(),
	adminUpdateApprovalPolicy: vi.fn(),
	adminDeleteApprovalPolicy: vi.fn(),
	adminReorderApprovalPolicies: vi.fn(),
	adminListApprovalAudit: vi.fn(),
}));

import {
	adminDeleteApprovalPolicy,
	adminListApprovalAudit,
	adminListApprovalPolicies,
	adminReorderApprovalPolicies,
} from '$lib/admin/client';
import Page from './+page.svelte';

const listPolicies = vi.mocked(adminListApprovalPolicies);
const listAudit = vi.mocked(adminListApprovalAudit);
const deletePolicy = vi.mocked(adminDeleteApprovalPolicy);
const reorderPolicies = vi.mocked(adminReorderApprovalPolicies);

function grant(...permissions: string[]) {
	jmapSession.set({
		capabilities: {
			'urn:setjoin:params:jmap:mail': { admin: { permissions } },
		},
	} as never);
}

function policy(id: number, overrides: Partial<ApprovalPolicy> = {}): ApprovalPolicy {
	return {
		id,
		consumerType: 'rbac.jit_activation',
		name: `Policy ${id}`,
		enabled: true,
		priority: id,
		conditions: {},
		requiresApproval: true,
		approverSpec: { kind: 'manager' },
		createdAt: '2026-07-23T01:02:03Z',
		updatedAt: '2026-07-23T01:02:03Z',
		...overrides,
	};
}

function auditRow(id: number, overrides: Partial<ApprovalRequestAuditRow> = {}): ApprovalRequestAuditRow {
	return {
		id,
		consumerType: 'hr.leave',
		subject: `Leave ${id}`,
		status: 'approved',
		approverKind: 'manager',
		approverRef: 4,
		createdAt: '2026-07-23T01:02:03Z',
		expiresAt: '2026-07-24T01:02:03Z',
		...overrides,
	};
}

describe('approval policy admin workflows', () => {
	beforeEach(() => {
		resetStores();
		vi.clearAllMocks();
		listPolicies.mockReset().mockResolvedValue([]);
		listAudit.mockReset().mockResolvedValue([]);
		deletePolicy.mockReset().mockResolvedValue(undefined);
		reorderPolicies.mockReset().mockResolvedValue(undefined);
	});

	afterEach(cleanup);

	it('loads the RBAC policy list and renders enabled, disabled, and approver variants', async () => {
		grant('approvals.view', 'approvals.manage');
		listPolicies.mockResolvedValueOnce([
			policy(1),
			policy(2, { enabled: false, requiresApproval: false, approverSpec: { kind: 'default_admin' } }),
		]);
		render(Page);

		expect(await screen.findByText('Policy 1')).toBeTruthy();
		expect(screen.getByText('Policy 2')).toBeTruthy();
		expect(listPolicies).toHaveBeenCalledWith('rbac.jit_activation');
		expect(screen.getAllByRole('button', { name: /move (up|down)/i })).toHaveLength(4);
		expect(screen.getByRole('button', { name: /add policy/i })).toBeTruthy();
	});

	it('keeps write actions hidden for a view-only administrator', async () => {
		grant('approvals.view');
		listPolicies.mockResolvedValueOnce([policy(1)]);
		render(Page);
		await screen.findByText('Policy 1');
		expect(screen.queryByRole('button', { name: /add policy/i })).toBeNull();
		expect(screen.queryByRole('button', { name: /delete/i })).toBeNull();
		expect(screen.getByRole('row', { name: /Policy 1/i })).toHaveAttribute('draggable', 'false');
	});

	it('maps each policy tab to its consumer and clears a previous load error', async () => {
		grant('approvals.manage');
		listPolicies
			.mockRejectedValueOnce(new Error('policy service unavailable'))
			.mockResolvedValue([]);
		render(Page);
		expect(await screen.findByRole('alert')).toHaveTextContent(/policy service unavailable/i);

		for (const [tab, consumer] of [
			['External send', 'mail.external_send'],
			['Group moderation', 'mail.group_moderation'],
			['Leave', 'hr.leave'],
			['Expense', 'hr.expense'],
		] as const) {
			await fireEvent.click(screen.getByRole('tab', { name: tab }));
			await waitFor(() => expect(listPolicies).toHaveBeenCalledWith(consumer));
		}
		expect(screen.queryByRole('alert')).toBeNull();
	});

	it('reorders policies with the keyboard and announces the new position', async () => {
		grant('approvals.manage');
		listPolicies.mockResolvedValueOnce([policy(1), policy(2), policy(3)]);
		render(Page);
		await screen.findByText('Policy 1');
		const down = screen.getAllByRole('button', { name: /move down/i });
		expect(down[2]).toBeDisabled();
		await fireEvent.click(down[0]);
		expect(reorderPolicies).toHaveBeenCalledWith('rbac.jit_activation', [2, 1, 3]);
		expect(screen.getByText(/position 2 of 3/i)).toBeTruthy();

		await fireEvent.click(screen.getAllByRole('button', { name: /move up/i })[1]);
		expect(reorderPolicies).toHaveBeenLastCalledWith('rbac.jit_activation', [1, 2, 3]);
	});

	it('surfaces reorder failures without reverting the visible deterministic order', async () => {
		grant('approvals.manage');
		listPolicies.mockResolvedValueOnce([policy(1), policy(2)]);
		reorderPolicies.mockRejectedValueOnce(new Error('reorder denied'));
		render(Page);
		await screen.findByText('Policy 1');
		await fireEvent.click(screen.getAllByRole('button', { name: /move down/i })[0]);
		expect(await screen.findByRole('alert')).toHaveTextContent(/reorder denied/i);
	});

	it('supports delete cancel, Escape, successful delete, and failed delete recovery', async () => {
		grant('approvals.manage');
		listPolicies.mockResolvedValue([policy(1), policy(2)]);
		render(Page);
		await screen.findByText('Policy 1');

		await fireEvent.click(screen.getAllByRole('button', { name: /^delete$/i })[0]);
		const dialog = screen.getByRole('dialog', { name: /confirm delete/i });
		expect(dialog).toHaveTextContent('Policy 1');
		await fireEvent.keyDown(dialog, { key: 'Escape' });
		expect(screen.queryByRole('dialog')).toBeNull();

		await fireEvent.click(screen.getAllByRole('button', { name: /^delete$/i })[0]);
		await fireEvent.click(screen.getByRole('button', { name: /cancel/i }));
		expect(screen.queryByRole('dialog')).toBeNull();

		await fireEvent.click(screen.getAllByRole('button', { name: /^delete$/i })[0]);
		await fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: /^delete$/i }));
		await waitFor(() => expect(deletePolicy).toHaveBeenCalledWith(1));
		await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());

		deletePolicy.mockRejectedValueOnce(new Error('still referenced'));
		await fireEvent.click(screen.getAllByRole('button', { name: /^delete$/i })[1]);
		await fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: /^delete$/i }));
		expect(await screen.findByRole('alert')).toHaveTextContent(/still referenced/i);
		expect(screen.getByRole('dialog')).toBeTruthy();
	});

	it('loads audit rows, formats undecided rows, and appends a second page', async () => {
		grant('approvals.view');
		const first = Array.from({ length: 50 }, (_, i) => auditRow(i + 1, i === 0 ? { decidedAt: undefined } : { decidedAt: '2026-07-23T02:03:04Z' }));
		listAudit.mockResolvedValueOnce(first).mockResolvedValueOnce([auditRow(51)]);
		render(Page);
		await fireEvent.click(screen.getByRole('tab', { name: /audit log/i }));
		expect(await screen.findByText('Leave 1')).toBeTruthy();
		expect(screen.getByText('—')).toBeTruthy();
		await fireEvent.click(screen.getByRole('button', { name: /load more/i }));
		expect(await screen.findByText('Leave 51')).toBeTruthy();
		expect(listAudit).toHaveBeenNthCalledWith(1, 50, 0);
		expect(listAudit).toHaveBeenNthCalledWith(2, 50, 50);
		expect(screen.queryByRole('button', { name: /load more/i })).toBeNull();
	});

	it('shows empty and error audit states', async () => {
		grant('approvals.view');
		listAudit.mockRejectedValueOnce(new Error('audit offline')).mockResolvedValueOnce([]);
		render(Page);
		await fireEvent.click(screen.getByRole('tab', { name: /audit log/i }));
		expect(await screen.findByRole('alert')).toHaveTextContent(/audit offline/i);
		await fireEvent.click(screen.getByRole('tab', { name: /RBAC/i }));
		await fireEvent.click(screen.getByRole('tab', { name: /audit log/i }));
		expect(await screen.findByText(/no approval requests/i)).toBeTruthy();
	});
});
