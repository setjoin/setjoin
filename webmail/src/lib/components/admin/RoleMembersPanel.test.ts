import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render } from '@testing-library/svelte/svelte5';
import { fireEvent, waitFor } from '@testing-library/svelte';
import RoleMembersPanel from './RoleMembersPanel.svelte';

// ── fetch mock helpers ────────────────────────────────────────────────────────

function makeOkResponse(body: unknown) {
	return Promise.resolve({
		ok: true,
		status: 200,
		json: async () => body,
		text: async () => JSON.stringify(body)
	});
}

// ── shared fixtures ───────────────────────────────────────────────────────────

const ROLE = {
	id: 1,
	name: 'Super Admin',
	description: '',
	permissions: ['users.manage'],
	isBuiltin: false,
	memberCount: 2,
	createdAt: '2026-01-01T00:00:00Z',
	updatedAt: '2026-01-01T00:00:00Z'
};

const MANAGEABLE_MEMBER = {
	userId: 10,
	userEmail: 'alice@example.com',
	displayName: 'Alice',
	grantedBy: 1,
	grantedAt: '2026-01-01T00:00:00Z',
	manageable: true
};

const PROTECTED_MEMBER = {
	userId: 20,
	userEmail: 'bob@example.com',
	displayName: 'Bob',
	grantedBy: 1,
	grantedAt: '2026-01-01T00:00:00Z',
	manageable: false
};

function makeRoleDetail(members: unknown[]) {
	return { role: ROLE, members } as import('$lib/admin/roles').RoleDetail;
}

// ── tests ─────────────────────────────────────────────────────────────────────

describe('RoleMembersPanel — admin-protection', () => {
	beforeEach(async () => {
		vi.resetAllMocks();
		const { getAuditPolicy, adminDeptTree } = await import('$lib/admin/client');
		vi.mocked(getAuditPolicy).mockResolvedValue({ level: 'lean', reasonRequiredAreas: [] });
		vi.mocked(adminDeptTree).mockResolvedValue([]);
		const { adminRemoveMember, adminAssignMember } = await import('$lib/admin/roles');
		vi.mocked(adminRemoveMember).mockResolvedValue(undefined);
		vi.mocked(adminAssignMember).mockResolvedValue({ id: 99 });
	});

	it('shows remove button enabled for a manageable member', async () => {
		const { adminGetRole } = await import('$lib/admin/roles');
		vi.mocked(adminGetRole).mockResolvedValue(makeRoleDetail([MANAGEABLE_MEMBER]));
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		let removeBtn: HTMLButtonElement | undefined;
		await waitFor(() => {
			removeBtn = Array.from(container.querySelectorAll('button')).find(
				(b) => b.textContent?.trim() === 'Remove'
			);
			expect(removeBtn).toBeDefined();
		});
		expect(removeBtn).toBeDefined();
		expect(removeBtn!.disabled).toBe(false);
	});

	it('disables remove button for a protected (manageable=false) member', async () => {
		const { adminGetRole } = await import('$lib/admin/roles');
		vi.mocked(adminGetRole).mockResolvedValue(makeRoleDetail([PROTECTED_MEMBER]));
		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 0));

		const removeBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Remove'
		);
		expect(removeBtn).not.toBeNull();
		expect(removeBtn!.disabled).toBe(true);
	});

	it('shows the Protected badge for a protected member', async () => {
		const { adminGetRole } = await import('$lib/admin/roles');
		vi.mocked(adminGetRole).mockResolvedValue(makeRoleDetail([PROTECTED_MEMBER]));
		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 0));

		expect(container.textContent).toContain('Protected');
	});

	it('does NOT show the Protected badge for a manageable member', async () => {
		const { adminGetRole } = await import('$lib/admin/roles');
		vi.mocked(adminGetRole).mockResolvedValue(makeRoleDetail([MANAGEABLE_MEMBER]));
		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 0));

		expect(container.textContent).not.toContain('Protected');
	});

	it('protection indicator is focusable (tabindex=0) on protected member row', async () => {
		const { adminGetRole } = await import('$lib/admin/roles');
		vi.mocked(adminGetRole).mockResolvedValue(makeRoleDetail([PROTECTED_MEMBER]));
		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 0));

		const indicator = container.querySelector('.sj-protection-indicator');
		expect(indicator).not.toBeNull();
		expect(indicator!.getAttribute('tabindex')).toBe('0');
	});

	it('protection indicator has aria-describedby wired by the Tooltip (a11y guard)', async () => {
		const { adminGetRole } = await import('$lib/admin/roles');
		vi.mocked(adminGetRole).mockResolvedValue(makeRoleDetail([PROTECTED_MEMBER]));
		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 0));

		const indicator = container.querySelector('.sj-protection-indicator[tabindex="0"]');
		expect(indicator).not.toBeNull();
		const describedById = indicator!.getAttribute('aria-describedby');
		expect(describedById).toBeTruthy();
		expect(describedById!.length).toBeGreaterThan(0);
	});

	it('manageable member remove button is NOT present when canEdit=false', async () => {
		const { adminGetRole } = await import('$lib/admin/roles');
		vi.mocked(adminGetRole).mockResolvedValue(makeRoleDetail([MANAGEABLE_MEMBER]));
		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: false } });
		await new Promise((r) => setTimeout(r, 0));

		const removeBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Remove'
		);
		expect(removeBtn).toBeUndefined();
	});
});

// ── Bulk add/remove tests ─────────────────────────────────────────────────────

// Additional user fixture: unmanageable user from the user list
const UNMANAGEABLE_USER = {
	id: 99,
	email: 'carol@example.com',
	displayName: 'Carol',
	enabled: true,
	isLocalAdmin: false,
	manageable: false,
	isSelf: false,
	createdAt: '2026-01-01T00:00:00Z'
};

const MANAGEABLE_USER = {
	id: 30,
	email: 'dave@example.com',
	displayName: 'Dave',
	enabled: true,
	isLocalAdmin: false,
	manageable: true,
	isSelf: false,
	createdAt: '2026-01-01T00:00:00Z'
};

const BULK_JOB_QUEUED = {
	id: 42,
	op: 'assign' as const,
	role_id: 1,
	actor_id: 1,
	user_ids: [30],
	expires_at: null,
	status: 'queued' as const,
	total: 1,
	processed: 0,
	results: [] as Array<{ user_id: number; status: string; reason?: string }>,
	error: null,
	created_at: '2026-01-01T00:00:00Z',
	updated_at: '2026-01-01T00:00:00Z'
};

const BULK_JOB_DONE_ASSIGN = {
	...BULK_JOB_QUEUED,
	op: 'assign' as const,
	status: 'done' as const,
	processed: 1,
	results: [{ user_id: 30, status: 'assigned' }]
};

const BULK_JOB_DONE_REVOKE = {
	...BULK_JOB_QUEUED,
	op: 'revoke' as const,
	status: 'done' as const,
	processed: 1,
	results: [{ user_id: 10, status: 'revoked' }]
};

const BULK_JOB_BLOCKED = {
	...BULK_JOB_QUEUED,
	op: 'assign' as const,
	status: 'done' as const,
	processed: 1,
	results: [{ user_id: 30, status: 'blocked', reason: 'sod_conflict' }]
};

vi.mock('$lib/admin/client', async (importOriginal) => {
	const actual = await importOriginal<typeof import('$lib/admin/client')>();
	return {
		...actual,
		adminUserList: vi.fn(),
		adminDeptTree: vi.fn().mockResolvedValue([]),
		adminListScopeSets: vi.fn().mockResolvedValue([]),
		adminGetScopeSet: vi.fn().mockResolvedValue({ id: 1, name: 'Test Set', description: '', members: [] }),
		bulkAssignRole: vi.fn(),
		bulkRevokeRole: vi.fn(),
		getBulkRoleJob: vi.fn(),
		getAuditPolicy: vi.fn().mockResolvedValue({ level: 'lean', reasonRequiredAreas: [] })
	};
});

describe('RoleMembersPanel — bulk add members', () => {
	beforeEach(async () => {
		vi.resetAllMocks();
		const { getAuditPolicy, adminDeptTree } = await import('$lib/admin/client');
		vi.mocked(getAuditPolicy).mockResolvedValue({ level: 'lean', reasonRequiredAreas: [] });
		vi.mocked(adminDeptTree).mockResolvedValue([]);
		const { adminGetRole, adminRemoveMember, adminAssignMember } = await import('$lib/admin/roles');
		vi.mocked(adminGetRole).mockResolvedValue({ role: ROLE, members: [MANAGEABLE_MEMBER] });
		vi.mocked(adminRemoveMember).mockResolvedValue(undefined);
		vi.mocked(adminAssignMember).mockResolvedValue({ id: 99 });
	});

	it('un-manageable user is NOT present in the bulk picker options', async () => {
		const { adminUserList, bulkAssignRole, getBulkRoleJob } = await import('$lib/admin/client');
		vi.mocked(adminUserList).mockResolvedValue([UNMANAGEABLE_USER, MANAGEABLE_USER]);
		vi.mocked(bulkAssignRole).mockResolvedValue({ jobId: 42 });
		vi.mocked(getBulkRoleJob).mockResolvedValue(BULK_JOB_DONE_ASSIGN);

		vi.stubGlobal(
			'fetch',
			vi.fn(() => makeOkResponse(makeRoleDetail([MANAGEABLE_MEMBER])))
		);
		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 0));

		// Click "Add members" bulk button to open bulk picker
		const addBulkBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Add members'
		);
		expect(addBulkBtn).toBeDefined();
		await fireEvent.click(addBulkBtn!);
		await new Promise((r) => setTimeout(r, 0));

		// The un-manageable user (carol) should NOT appear as a selectable option
		// The manageable user (dave) should appear
		const pickerText = container.textContent ?? '';
		expect(pickerText).toContain('dave@example.com');
		expect(pickerText).not.toContain('carol@example.com');
		vi.unstubAllGlobals();
	});

	it('submitting bulk add calls bulkAssignRole then polls getBulkRoleJob and renders the report', async () => {
		const { adminUserList, bulkAssignRole, getBulkRoleJob } = await import('$lib/admin/client');
		vi.mocked(adminUserList).mockResolvedValue([MANAGEABLE_USER]);
		vi.mocked(bulkAssignRole).mockResolvedValue({ jobId: 42 });
		// First poll returns queued, second returns done
		vi.mocked(getBulkRoleJob)
			.mockResolvedValueOnce(BULK_JOB_QUEUED)
			.mockResolvedValue(BULK_JOB_DONE_ASSIGN);

		vi.stubGlobal(
			'fetch',
			vi.fn(() => makeOkResponse(makeRoleDetail([])))
		);
		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		// Wait for load + searchBulkUsers to resolve
		await new Promise((r) => setTimeout(r, 10));

		// Open bulk picker
		const addBulkBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Add members'
		);
		expect(addBulkBtn).toBeDefined();
		await fireEvent.click(addBulkBtn!);
		// Wait for searchBulkUsers() to resolve and Svelte to re-render
		await new Promise((r) => setTimeout(r, 10));

		// Select dave via the picker checkbox (inside the bulk picker list)
		const daveCheckbox = Array.from(container.querySelectorAll('.sj-bulk-picker-item input[type="checkbox"]')).find(
			(el) => el.closest('.sj-bulk-picker-item')?.textContent?.includes('dave@example.com')
		) as HTMLInputElement | undefined;
		expect(daveCheckbox).toBeDefined();
		await fireEvent.click(daveCheckbox!);
		await new Promise((r) => setTimeout(r, 10));

		// Click "Add members (N)" — matches text containing "Add members ("
		const submitBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.includes('Add members') && b.textContent?.includes('(')
		);
		expect(submitBtn).toBeDefined();
		await fireEvent.click(submitBtn!);
		// Wait for the async poll to resolve
		await new Promise((r) => setTimeout(r, 50));

		// bulkAssignRole should have been called (no reason, no scope = null for whole-domain)
		expect(vi.mocked(bulkAssignRole)).toHaveBeenCalledWith(1, expect.any(Array), undefined, undefined, null);
		// getBulkRoleJob should have been polled
		expect(vi.mocked(getBulkRoleJob)).toHaveBeenCalledWith(42);
		vi.unstubAllGlobals();
	});

	it('bulk add with blocked results shows reason in report', async () => {
		const { adminUserList, bulkAssignRole, getBulkRoleJob } = await import('$lib/admin/client');
		vi.mocked(adminUserList).mockResolvedValue([MANAGEABLE_USER]);
		vi.mocked(bulkAssignRole).mockResolvedValue({ jobId: 42 });
		vi.mocked(getBulkRoleJob).mockResolvedValue(BULK_JOB_BLOCKED);

		vi.stubGlobal(
			'fetch',
			vi.fn(() => makeOkResponse(makeRoleDetail([])))
		);
		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 10));

		const addBulkBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Add members'
		);
		expect(addBulkBtn).toBeDefined();
		await fireEvent.click(addBulkBtn!);
		await new Promise((r) => setTimeout(r, 10));

		const daveCheckbox = Array.from(container.querySelectorAll('.sj-bulk-picker-item input[type="checkbox"]')).find(
			(el) => el.closest('.sj-bulk-picker-item')?.textContent?.includes('dave@example.com')
		) as HTMLInputElement | undefined;
		expect(daveCheckbox).toBeDefined();
		await fireEvent.click(daveCheckbox!);
		await new Promise((r) => setTimeout(r, 10));

		const submitBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.includes('Add members') && b.textContent?.includes('(')
		);
		expect(submitBtn).toBeDefined();
		await fireEvent.click(submitBtn!);
		await new Promise((r) => setTimeout(r, 50));

		// Report should show blocked + sod_conflict reason
		const text = container.textContent ?? '';
		expect(vi.mocked(bulkAssignRole)).toHaveBeenCalledWith(1, expect.any(Array), undefined, undefined, null);
		expect(vi.mocked(getBulkRoleJob)).toHaveBeenCalledWith(42);
		// sod_conflict reason label should appear as the exact translated string
		expect(text).toContain('SoD conflict');
		vi.unstubAllGlobals();
	});
});

describe('RoleMembersPanel — bulk remove members', () => {
	beforeEach(async () => {
		vi.resetAllMocks();
		const { getAuditPolicy, adminDeptTree } = await import('$lib/admin/client');
		vi.mocked(getAuditPolicy).mockResolvedValue({ level: 'lean', reasonRequiredAreas: [] });
		vi.mocked(adminDeptTree).mockResolvedValue([]);
		const { adminGetRole, adminRemoveMember, adminAssignMember } = await import('$lib/admin/roles');
		vi.mocked(adminGetRole).mockResolvedValue({ role: ROLE, members: [MANAGEABLE_MEMBER] });
		vi.mocked(adminRemoveMember).mockResolvedValue(undefined);
		vi.mocked(adminAssignMember).mockResolvedValue({ id: 99 });
	});

	it('"Remove selected" calls bulkRevokeRole with checked manageable member ids', async () => {
		const { bulkRevokeRole, getBulkRoleJob } = await import('$lib/admin/client');
		vi.mocked(bulkRevokeRole).mockResolvedValue({ jobId: 43 });
		vi.mocked(getBulkRoleJob).mockResolvedValue(BULK_JOB_DONE_REVOKE);

		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 0));

		// Check the checkbox for the manageable member
		const checkbox = container.querySelector('input[type="checkbox"]');
		expect(checkbox).not.toBeNull();
		await fireEvent.click(checkbox!);
		await new Promise((r) => setTimeout(r, 0));

		// Click "Remove selected" (no reason dialog since roles not reason-required)
		const removeSelectedBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Remove selected'
		);
		expect(removeSelectedBtn).toBeDefined();
		await fireEvent.click(removeSelectedBtn!);
		await new Promise((r) => setTimeout(r, 20));

		// no reason when roles not in reason-required areas
		expect(vi.mocked(bulkRevokeRole)).toHaveBeenCalledWith(1, [10], undefined);
		expect(vi.mocked(getBulkRoleJob)).toHaveBeenCalledWith(43);
	});

	it('protected member checkbox is disabled — cannot be bulk-removed', async () => {
		const { adminGetRole } = await import('$lib/admin/roles');
		vi.mocked(adminGetRole).mockResolvedValue(makeRoleDetail([PROTECTED_MEMBER]));
		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 0));

		const checkbox = container.querySelector('input[type="checkbox"]');
		// Either no checkbox, or the checkbox is disabled
		if (checkbox) {
			expect((checkbox as HTMLInputElement).disabled).toBe(true);
		}
	});

	it('"Remove selected" button is not present when nothing is checked', async () => {
		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 0));

		const removeSelectedBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Remove selected'
		);
		expect(removeSelectedBtn).toBeUndefined();
	});
});

// ── Audit-reason policy-conditional tests ────────────────────────────────────

// Also mock $lib/admin/roles so we can spy on adminRemoveMember
vi.mock('$lib/admin/roles', async (importOriginal) => {
	const actual = await importOriginal<typeof import('$lib/admin/roles')>();
	return {
		...actual,
		adminRemoveMember: vi.fn().mockResolvedValue(undefined),
		adminGetRole: vi.fn(),
		adminAssignMember: vi.fn().mockResolvedValue({ id: 99 })
	};
});

describe('RoleMembersPanel — reason-required policy (roles in reasonRequiredAreas)', () => {
	beforeEach(async () => {
		vi.resetAllMocks();
		// Re-wire the default mocks so the component can mount
		const { getAuditPolicy, adminDeptTree } = await import('$lib/admin/client');
		vi.mocked(getAuditPolicy).mockResolvedValue({ level: 'lean', reasonRequiredAreas: [] });
		vi.mocked(adminDeptTree).mockResolvedValue([]);
		const { adminRemoveMember, adminGetRole, adminAssignMember } = await import('$lib/admin/roles');
		vi.mocked(adminRemoveMember).mockResolvedValue(undefined);
		vi.mocked(adminGetRole).mockResolvedValue({ role: ROLE, members: [MANAGEABLE_MEMBER] });
		vi.mocked(adminAssignMember).mockResolvedValue({ id: 99 });
	});

	it('single remove dialog shows reason field when roles is reason-required', async () => {
		const { getAuditPolicy } = await import('$lib/admin/client');
		vi.mocked(getAuditPolicy).mockResolvedValue({ level: 'lean', reasonRequiredAreas: ['roles'] });

		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 20));

		// Click single Remove button (opens dialog)
		const removeBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Remove'
		);
		expect(removeBtn).toBeDefined();
		await fireEvent.click(removeBtn!);
		await new Promise((r) => setTimeout(r, 10));

		// The confirm dialog should show a reason textarea (via ReasonPrompt)
		const reasonTextarea = container.querySelector('textarea');
		expect(reasonTextarea).not.toBeNull();
	});

	it('single remove sends reason to adminRemoveMember when roles is reason-required', async () => {
		const { getAuditPolicy } = await import('$lib/admin/client');
		vi.mocked(getAuditPolicy).mockResolvedValue({ level: 'lean', reasonRequiredAreas: ['roles'] });
		const { adminRemoveMember } = await import('$lib/admin/roles');

		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 20));

		// Click single Remove button (the row action button opens the dialog)
		const removeBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Remove'
		);
		await fireEvent.click(removeBtn!);
		await new Promise((r) => setTimeout(r, 10));

		// Fill reason in the dialog's ReasonPrompt textarea
		const reasonTextarea = container.querySelector('textarea');
		expect(reasonTextarea).not.toBeNull();
		await fireEvent.input(reasonTextarea!, { target: { value: 'security review' } });

		// Click the submit button inside the dialog (it's inside .sj-dialog__body)
		const dialogBody = container.querySelector('.sj-dialog__body');
		expect(dialogBody).not.toBeNull();
		const submitBtn = Array.from(dialogBody!.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Remove' && !(b as HTMLButtonElement).disabled
		);
		expect(submitBtn).toBeDefined();
		await fireEvent.click(submitBtn!);
		await new Promise((r) => setTimeout(r, 20));

		// adminRemoveMember called with reason
		expect(vi.mocked(adminRemoveMember)).toHaveBeenCalledWith(1, MANAGEABLE_MEMBER.userId, 'security review');
	});

	it('single remove dialog has no reason field and calls adminRemoveMember without reason when NOT reason-required', async () => {
		const { getAuditPolicy } = await import('$lib/admin/client');
		vi.mocked(getAuditPolicy).mockResolvedValue({ level: 'lean', reasonRequiredAreas: [] });
		const { adminRemoveMember } = await import('$lib/admin/roles');

		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 20));

		const removeBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Remove'
		);
		await fireEvent.click(removeBtn!);
		await new Promise((r) => setTimeout(r, 10));

		// No reason textarea — not required
		expect(container.querySelector('textarea')).toBeNull();

		// The danger Remove button is in the dialog footer (no reason prompt)
		const dialogFooter = container.querySelector('.sj-dialog__footer');
		expect(dialogFooter).not.toBeNull();
		const confirmBtn = Array.from(dialogFooter!.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Remove'
		);
		expect(confirmBtn).toBeDefined();
		await fireEvent.click(confirmBtn!);
		await new Promise((r) => setTimeout(r, 20));

		// adminRemoveMember called without reason (undefined)
		expect(vi.mocked(adminRemoveMember)).toHaveBeenCalledWith(1, MANAGEABLE_MEMBER.userId, undefined);
	});

	it('bulk revoke sends reason to bulkRevokeRole when roles is reason-required', async () => {
		const { getAuditPolicy, bulkRevokeRole, getBulkRoleJob } = await import('$lib/admin/client');
		vi.mocked(getAuditPolicy).mockResolvedValue({ level: 'lean', reasonRequiredAreas: ['roles'] });
		vi.mocked(bulkRevokeRole).mockResolvedValue({ jobId: 43 });
		vi.mocked(getBulkRoleJob).mockResolvedValue(BULK_JOB_DONE_REVOKE);

		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 20));

		// Check the member checkbox
		const checkbox = container.querySelector('input[type="checkbox"]');
		expect(checkbox).not.toBeNull();
		await fireEvent.click(checkbox!);
		await new Promise((r) => setTimeout(r, 0));

		// Click "Remove selected" — should open reason dialog
		const removeSelectedBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Remove selected'
		);
		expect(removeSelectedBtn).toBeDefined();
		await fireEvent.click(removeSelectedBtn!);
		await new Promise((r) => setTimeout(r, 10));

		// Reason textarea should appear (via ReasonPrompt in the dialog)
		const reasonTextarea = container.querySelector('textarea');
		expect(reasonTextarea).not.toBeNull();
		await fireEvent.input(reasonTextarea!, { target: { value: 'bulk cleanup' } });

		// Submit — the ReasonPrompt submit button is inside the dialog body
		const dialogBody = container.querySelector('.sj-dialog__body');
		expect(dialogBody).not.toBeNull();
		const submitBtn = Array.from(dialogBody!.querySelectorAll('button')).find(
			(b) => b.textContent?.includes('Remove selected') && !(b as HTMLButtonElement).disabled
		);
		expect(submitBtn).toBeDefined();
		await fireEvent.click(submitBtn!);
		await new Promise((r) => setTimeout(r, 50));

		// bulkRevokeRole called WITH the reason
		expect(vi.mocked(bulkRevokeRole)).toHaveBeenCalledWith(1, [10], 'bulk cleanup');
	});

	it('bulk revoke does NOT prompt and sends no reason when roles is NOT reason-required', async () => {
		const { getAuditPolicy, bulkRevokeRole, getBulkRoleJob } = await import('$lib/admin/client');
		vi.mocked(getAuditPolicy).mockResolvedValue({ level: 'lean', reasonRequiredAreas: [] });
		vi.mocked(bulkRevokeRole).mockResolvedValue({ jobId: 43 });
		vi.mocked(getBulkRoleJob).mockResolvedValue(BULK_JOB_DONE_REVOKE);

		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 20));

		// Check the member checkbox
		const checkbox = container.querySelector('input[type="checkbox"]');
		expect(checkbox).not.toBeNull();
		await fireEvent.click(checkbox!);
		await new Promise((r) => setTimeout(r, 0));

		// Click "Remove selected" — no dialog, calls directly
		const removeSelectedBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Remove selected'
		);
		expect(removeSelectedBtn).toBeDefined();
		await fireEvent.click(removeSelectedBtn!);
		await new Promise((r) => setTimeout(r, 50));

		// bulkRevokeRole called WITHOUT reason (undefined)
		expect(vi.mocked(bulkRevokeRole)).toHaveBeenCalledWith(1, [10], undefined);
	});
});

// ── OU scope picker (Task 8) tests ───────────────────────────────────────────

describe('RoleMembersPanel — OU scope picker on single-assign', () => {
	beforeEach(async () => {
		vi.resetAllMocks();
		const { getAuditPolicy, adminDeptTree, adminListScopeSets } = await import('$lib/admin/client');
		vi.mocked(getAuditPolicy).mockResolvedValue({ level: 'lean', reasonRequiredAreas: [] });
		vi.mocked(adminDeptTree).mockResolvedValue([]);
		vi.mocked(adminListScopeSets).mockResolvedValue([]);
		const { adminGetRole, adminRemoveMember, adminAssignMember } = await import('$lib/admin/roles');
		vi.mocked(adminGetRole).mockResolvedValue({ role: ROLE, members: [] });
		vi.mocked(adminRemoveMember).mockResolvedValue(undefined);
		vi.mocked(adminAssignMember).mockResolvedValue({ id: 99 });
		const { adminUserList } = await import('$lib/admin/client');
		vi.mocked(adminUserList).mockResolvedValue([MANAGEABLE_USER]);
	});

	it('single-assign form renders the DepartmentTreePicker under a Scope section', async () => {
		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 10));

		// Open single-add dialog
		const addBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Add member'
		);
		expect(addBtn).toBeDefined();
		await fireEvent.click(addBtn!);
		await new Promise((r) => setTimeout(r, 10));

		// The assign dialog should contain a "Scope" section (DepartmentTreePicker renders a fieldset with legend "Scope")
		const scopeFieldset = container.querySelector('fieldset');
		expect(scopeFieldset).not.toBeNull();
		// The legend should say "Scope"
		expect(scopeFieldset!.querySelector('legend')?.textContent).toContain('Scope');
	});

	it('selecting a department sends scopeType/scopeId on assign', async () => {
		const ENG_TREE = [{
			id: 10, name: 'Engineering', path: '/eng', ldapOu: 'ou=eng',
			sortOrder: 1, userCount: 5, children: []
		}];
		const { adminDeptTree, adminUserList } = await import('$lib/admin/client');
		vi.mocked(adminDeptTree).mockResolvedValue(ENG_TREE);
		vi.mocked(adminUserList).mockResolvedValue([MANAGEABLE_USER]);
		const { adminAssignMember } = await import('$lib/admin/roles');

		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 20));

		// Open single-add dialog
		const addBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Add member'
		);
		expect(addBtn).toBeDefined();
		await fireEvent.click(addBtn!);
		await new Promise((r) => setTimeout(r, 20));

		// Pick a user
		const userSelect = Array.from(container.querySelectorAll('select')).find(
			(s) => s.closest('.sj-assign-form') != null
		);
		expect(userSelect).toBeDefined();
		await fireEvent.change(userSelect!, { target: { value: String(MANAGEABLE_USER.id) } });

		// Select the "Limit to a department" radio in the DepartmentTreePicker
		const ouRadio = Array.from(container.querySelectorAll('input[type="radio"]')).find(
			(r) => (r as HTMLInputElement).value === 'ou'
		) as HTMLInputElement | undefined;
		expect(ouRadio).toBeDefined();
		await fireEvent.click(ouRadio!);
		await new Promise((r) => setTimeout(r, 20));

		// Click the Engineering node in the tree
		const engNode = Array.from(container.querySelectorAll('[role="treeitem"]')).find(
			(el) => el.textContent?.includes('Engineering')
		);
		expect(engNode).toBeDefined();
		await fireEvent.click(engNode!);
		await new Promise((r) => setTimeout(r, 10));

		// Click Assign
		const assignBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Assign'
		);
		expect(assignBtn).toBeDefined();
		await fireEvent.click(assignBtn!);
		await new Promise((r) => setTimeout(r, 20));

		expect(vi.mocked(adminAssignMember)).toHaveBeenCalledWith(
			1,
			expect.objectContaining({ scopeType: 'ou', scopeId: 10 }),
			undefined
		);
	});

	it('default (null scope) sends no scope fields on assign', async () => {
		const { adminAssignMember } = await import('$lib/admin/roles');
		const { adminUserList } = await import('$lib/admin/client');
		vi.mocked(adminUserList).mockResolvedValue([MANAGEABLE_USER]);

		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 20));

		const addBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Add member'
		);
		expect(addBtn).toBeDefined();
		await fireEvent.click(addBtn!);
		await new Promise((r) => setTimeout(r, 20));

		// Pick a user
		const userSelect = Array.from(container.querySelectorAll('select')).find(
			(s) => s.closest('.sj-assign-form') != null
		);
		expect(userSelect).toBeDefined();
		await fireEvent.change(userSelect!, { target: { value: String(MANAGEABLE_USER.id) } });

		// Leave scope as default (whole domain) — no OU selection
		const assignBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Assign'
		);
		expect(assignBtn).toBeDefined();
		await fireEvent.click(assignBtn!);
		await new Promise((r) => setTimeout(r, 20));

		// Should NOT have scopeType or scopeId in the call
		expect(vi.mocked(adminAssignMember)).toHaveBeenCalledWith(
			1,
			expect.not.objectContaining({ scopeType: 'ou' }),
			undefined
		);
	});

	it('an OU scope whose dept is not in the tree shows "scope unavailable" (the "now unrestricted" string is retired)', async () => {
		const { adminGetRole } = await import('$lib/admin/roles');
		const SCOPED_MEMBER = {
			...MANAGEABLE_MEMBER,
			scopeType: 'ou' as const,
			scopeId: 999, // dept 999 does not exist in deptMap (empty tree)
		};
		vi.mocked(adminGetRole).mockResolvedValue({ role: ROLE, members: [SCOPED_MEMBER] });

		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 20));

		// V041 drops the grant on dept-delete, so the "(department removed — now
		// unrestricted)" string is retired; an un-resolvable id reads as unavailable.
		expect(container.textContent).toContain('scope unavailable');
		expect(container.textContent).not.toContain('department removed');
	});

	it('a scope-set member renders a "Scope set: <name>" chip linking to the console', async () => {
		const { adminGetRole } = await import('$lib/admin/roles');
		const SET_MEMBER = {
			...MANAGEABLE_MEMBER,
			scopeType: 'set' as const,
			scopeId: 7,
			setName: 'Region East',
		};
		vi.mocked(adminGetRole).mockResolvedValue({ role: ROLE, members: [SET_MEMBER] });

		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 20));

		const chip = container.querySelector('a.sj-scope-set-chip') as HTMLAnchorElement | null;
		expect(chip).not.toBeNull();
		expect(chip!.textContent).toContain('Region East');
		expect(chip!.getAttribute('href')).toBe('/admin/scope-sets?id=7');
	});

	it('a scope-set member with no setName (removed) shows the stale label', async () => {
		const { adminGetRole } = await import('$lib/admin/roles');
		const STALE_SET_MEMBER = {
			...MANAGEABLE_MEMBER,
			scopeType: 'set' as const,
			scopeId: 8,
			// setName absent → the set was removed/unavailable
		};
		vi.mocked(adminGetRole).mockResolvedValue({ role: ROLE, members: [STALE_SET_MEMBER] });

		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 20));

		expect(container.textContent).toContain('scope set removed');
	});

	it('OU-scoped member shows "scope unavailable" (NOT "department removed") when tree fetch fails', async () => {
		const { adminGetRole } = await import('$lib/admin/roles');
		const { adminDeptTree } = await import('$lib/admin/client');
		const SCOPED_MEMBER = {
			...MANAGEABLE_MEMBER,
			scopeType: 'ou' as const,
			scopeId: 5,
		};
		vi.mocked(adminGetRole).mockResolvedValue({ role: ROLE, members: [SCOPED_MEMBER] });
		vi.mocked(adminDeptTree).mockRejectedValue(new Error('Network error'));

		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 20));

		// Should NOT show "department removed" copy when the tree simply failed to load
		expect(container.textContent).not.toContain('department removed');
		// Should show neutral "scope unavailable" label instead
		expect(container.textContent).toContain('scope unavailable');
	});

	it('bulk-assign dialog contains a DepartmentTreePicker (Scope fieldset)', async () => {
		const { adminUserList } = await import('$lib/admin/client');
		vi.mocked(adminUserList).mockResolvedValue([MANAGEABLE_USER]);

		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 10));

		const bulkAddBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Add members'
		);
		expect(bulkAddBtn).toBeDefined();
		await fireEvent.click(bulkAddBtn!);
		await new Promise((r) => setTimeout(r, 10));

		const bulkDialog = Array.from(container.querySelectorAll('[role="dialog"]')).find(
			(d) => d.textContent?.includes('Add members')
		);
		expect(bulkDialog).toBeDefined();
		// DepartmentTreePicker renders a fieldset with legend "Scope"
		const fieldsetInBulk = bulkDialog!.querySelector('fieldset');
		expect(fieldsetInBulk).not.toBeNull();
		expect(fieldsetInBulk!.querySelector('legend')?.textContent).toContain('Scope');
	});

	it('set-mode with no set selected shows an error and does NOT call adminAssignMember', async () => {
		const { adminListScopeSets, adminUserList } = await import('$lib/admin/client');
		const SCOPE_SET = { id: 1, name: 'Region East', description: '' };
		vi.mocked(adminListScopeSets).mockResolvedValue([SCOPE_SET]);
		vi.mocked(adminUserList).mockResolvedValue([MANAGEABLE_USER]);
		const { adminAssignMember } = await import('$lib/admin/roles');
		vi.mocked(adminAssignMember).mockClear();

		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 20));

		// Open single-add dialog
		const addBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Add member'
		);
		expect(addBtn).toBeDefined();
		await fireEvent.click(addBtn!);
		await new Promise((r) => setTimeout(r, 20));

		// Pick a user
		const userSelect = Array.from(container.querySelectorAll('select')).find(
			(s) => s.closest('.sj-assign-form') != null
		);
		expect(userSelect).toBeDefined();
		await fireEvent.change(userSelect!, { target: { value: String(MANAGEABLE_USER.id) } });

		// Select the "A scope-set" radio
		const setRadio = Array.from(container.querySelectorAll('input[type="radio"]')).find(
			(r) => (r as HTMLInputElement).value === 'set'
		) as HTMLInputElement | undefined;
		expect(setRadio).toBeDefined();
		await fireEvent.click(setRadio!);
		await new Promise((r) => setTimeout(r, 20));

		// Do NOT pick a scope-set from the dropdown (leave at default '—', i.e. setScopeIdStr === '')
		// Click Assign
		const assignBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Assign'
		);
		expect(assignBtn).toBeDefined();
		await fireEvent.click(assignBtn!);
		await new Promise((r) => setTimeout(r, 20));

		// Must NOT fire the API call
		expect(vi.mocked(adminAssignMember)).not.toHaveBeenCalled();
		// Must show the error message
		expect(container.textContent).toContain('Choose a scope-set');
	});

	it('selecting a department in bulk-add threads scopeType/scopeId into bulkAssignRole', async () => {
		const ENG_TREE = [{
			id: 10, name: 'Engineering', path: '/eng', ldapOu: 'ou=eng',
			sortOrder: 1, userCount: 5, children: []
		}];
		const { adminDeptTree, adminUserList, bulkAssignRole, getBulkRoleJob } = await import('$lib/admin/client');
		vi.mocked(adminDeptTree).mockResolvedValue(ENG_TREE);
		vi.mocked(adminUserList).mockResolvedValue([MANAGEABLE_USER]);
		vi.mocked(bulkAssignRole).mockResolvedValue({ jobId: 42 });
		vi.mocked(getBulkRoleJob).mockResolvedValue(BULK_JOB_DONE_ASSIGN);

		vi.stubGlobal('fetch', vi.fn(() => makeOkResponse(makeRoleDetail([]))));
		const { default: RoleMembersPanel } = await import('./RoleMembersPanel.svelte');
		const { container } = render(RoleMembersPanel, { props: { roleId: 1, canEdit: true } });
		await new Promise((r) => setTimeout(r, 20));

		// Open bulk add dialog
		const bulkAddBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.trim() === 'Add members'
		);
		expect(bulkAddBtn).toBeDefined();
		await fireEvent.click(bulkAddBtn!);
		await new Promise((r) => setTimeout(r, 20));

		// Select Dave
		const daveCheckbox = Array.from(container.querySelectorAll('.sj-bulk-picker-item input[type="checkbox"]')).find(
			(el) => el.closest('.sj-bulk-picker-item')?.textContent?.includes('dave@example.com')
		) as HTMLInputElement | undefined;
		expect(daveCheckbox).toBeDefined();
		await fireEvent.click(daveCheckbox!);
		await new Promise((r) => setTimeout(r, 10));

		// Select "Limit to a department" radio in the DepartmentTreePicker
		const ouRadio = Array.from(container.querySelectorAll('input[type="radio"]')).find(
			(r) => (r as HTMLInputElement).value === 'ou'
		) as HTMLInputElement | undefined;
		expect(ouRadio).toBeDefined();
		await fireEvent.click(ouRadio!);
		await new Promise((r) => setTimeout(r, 20));

		// Click the Engineering node in the tree
		const engNode = Array.from(container.querySelectorAll('[role="treeitem"]')).find(
			(el) => el.textContent?.includes('Engineering')
		);
		expect(engNode).toBeDefined();
		await fireEvent.click(engNode!);
		await new Promise((r) => setTimeout(r, 10));

		// Submit
		const submitBtn = Array.from(container.querySelectorAll('button')).find(
			(b) => b.textContent?.includes('Add members') && b.textContent?.includes('(')
		);
		expect(submitBtn).toBeDefined();
		await fireEvent.click(submitBtn!);
		await new Promise((r) => setTimeout(r, 50));

		expect(vi.mocked(bulkAssignRole)).toHaveBeenCalledWith(
			1,
			expect.any(Array),
			undefined,
			undefined,
			{ scopeType: 'ou', scopeId: 10 }
		);
		vi.unstubAllGlobals();
	});
});
