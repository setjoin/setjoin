import { describe, it, expect, vi, beforeEach } from 'vitest';

vi.mock('./transport', () => ({
	adminFetch: vi.fn(async () => ({ json: async () => [{ id: 1, name: 'Help Desk' }] }))
}));

import {
	adminListRoles,
	adminCreateRole,
	adminUpdateRole,
	adminDeleteRole,
	adminSetSodMode,
} from './roles';
import { adminFetch } from './transport';

describe('roles client', () => {
	beforeEach(() => vi.clearAllMocks());
	it('lists roles via /admin/roles', async () => {
		const roles = await adminListRoles();
		expect(adminFetch).toHaveBeenCalledWith('/admin/roles');
		expect(roles[0].name).toBe('Help Desk');
	});
});

// ── Reason-header tests ───────────────────────────────────────────────────────
// For each op in the 'roles' and 'security' areas: verify X-Audit-Reason is
// sent when a reason is provided and NOT sent when absent (no prompt on default policy).

describe('adminCreateRole — X-Audit-Reason header', () => {
	beforeEach(() => {
		vi.mocked(adminFetch).mockResolvedValue({ json: async () => ({ id: 42 }) } as ReturnType<typeof adminFetch> extends Promise<infer R> ? R : never);
		vi.clearAllMocks();
		vi.mocked(adminFetch).mockResolvedValue({ json: async () => ({ id: 42 }) } as never);
	});

	it('sends X-Audit-Reason when reason is provided', async () => {
		await adminCreateRole({ name: 'Tester', description: '', permissions: ['queue.read'] }, 'compliance audit');
		expect(adminFetch).toHaveBeenCalledWith(
			'/admin/roles',
			expect.objectContaining({ headers: expect.objectContaining({ 'X-Audit-Reason': 'compliance audit' }) })
		);
	});

	it('does NOT send X-Audit-Reason when no reason provided (default policy)', async () => {
		await adminCreateRole({ name: 'Tester', description: '', permissions: ['queue.read'] });
		const [, opts] = vi.mocked(adminFetch).mock.calls[0];
		const headers = (opts?.headers ?? {}) as Record<string, string>;
		expect(headers['X-Audit-Reason']).toBeUndefined();
	});
});

describe('adminUpdateRole — X-Audit-Reason header', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		vi.mocked(adminFetch).mockResolvedValue({ json: async () => ({}) } as never);
	});

	it('sends X-Audit-Reason when reason is provided', async () => {
		await adminUpdateRole(1, { name: 'Updated' }, 'policy review');
		expect(adminFetch).toHaveBeenCalledWith(
			'/admin/roles/1',
			expect.objectContaining({ headers: expect.objectContaining({ 'X-Audit-Reason': 'policy review' }) })
		);
	});

	it('does NOT send X-Audit-Reason when no reason provided', async () => {
		await adminUpdateRole(1, { name: 'Updated' });
		const [, opts] = vi.mocked(adminFetch).mock.calls[0];
		const headers = (opts?.headers ?? {}) as Record<string, string>;
		expect(headers['X-Audit-Reason']).toBeUndefined();
	});
});

describe('adminDeleteRole — X-Audit-Reason header', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		vi.mocked(adminFetch).mockResolvedValue({ json: async () => ({}) } as never);
	});

	it('sends X-Audit-Reason when reason is provided', async () => {
		await adminDeleteRole(7, 'role decommission');
		expect(adminFetch).toHaveBeenCalledWith(
			'/admin/roles/7',
			expect.objectContaining({ headers: expect.objectContaining({ 'X-Audit-Reason': 'role decommission' }) })
		);
	});

	it('does NOT send X-Audit-Reason when no reason provided', async () => {
		await adminDeleteRole(7);
		const [, opts] = vi.mocked(adminFetch).mock.calls[0];
		const headers = (opts?.headers ?? {}) as Record<string, string>;
		expect(headers['X-Audit-Reason']).toBeUndefined();
	});
});

describe('adminSetSodMode — X-Audit-Reason header (security area)', () => {
	beforeEach(() => {
		vi.clearAllMocks();
		vi.mocked(adminFetch).mockResolvedValue({ json: async () => ({ enabled: true }) } as never);
	});

	it('sends X-Audit-Reason when reason is provided', async () => {
		await adminSetSodMode(true, 'enabling SoD for compliance');
		expect(adminFetch).toHaveBeenCalledWith(
			'/admin/dengbao/sod-mode',
			expect.objectContaining({ headers: expect.objectContaining({ 'X-Audit-Reason': 'enabling SoD for compliance' }) })
		);
	});

	it('does NOT send X-Audit-Reason when no reason provided', async () => {
		await adminSetSodMode(true);
		const [, opts] = vi.mocked(adminFetch).mock.calls[0];
		const headers = (opts?.headers ?? {}) as Record<string, string>;
		expect(headers['X-Audit-Reason']).toBeUndefined();
	});
});
