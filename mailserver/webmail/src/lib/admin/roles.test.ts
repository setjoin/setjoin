import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import {
	adminPermissionCatalog,
	adminListRoles,
	adminGetRole,
	adminCreateRole,
	adminUpdateRole,
	adminDeleteRole,
	adminAssignMember,
	adminRemoveMember,
	adminEffectivePermissions,
	adminGetSodMode,
	adminSetSodMode,
} from './roles';

function jsonResponse(body: unknown, status = 200): Response {
	return new Response(status === 204 ? null : JSON.stringify(body), {
		status,
		headers: status === 204 ? undefined : { 'content-type': 'application/json' },
	});
}

function headerValue(headers: HeadersInit | undefined, name: string): string | undefined {
	if (!headers) return undefined;
	if (headers instanceof Headers) return headers.get(name) ?? undefined;
	if (Array.isArray(headers)) {
		const hit = headers.find(([k]) => k.toLowerCase() === name.toLowerCase());
		return hit?.[1];
	}
	const record = headers as Record<string, string>;
	const key = Object.keys(record).find((k) => k.toLowerCase() === name.toLowerCase());
	return key ? record[key] : undefined;
}

describe('roles client', () => {
	const fetchMock = vi.fn();

	beforeEach(() => {
		fetchMock.mockReset();
		vi.stubGlobal('fetch', fetchMock);
	});

	afterEach(() => {
		vi.unstubAllGlobals();
	});

	it('lists roles via /api/admin/roles', async () => {
		fetchMock.mockResolvedValue(jsonResponse([{ id: 1, name: 'Help Desk' }]));
		const roles = await adminListRoles();
		expect(fetchMock).toHaveBeenCalledWith(
			'/api/admin/roles',
			expect.objectContaining({ method: 'GET', cache: 'no-store' })
		);
		expect(roles[0].name).toBe('Help Desk');
	});
});

// ── Reason-header tests ───────────────────────────────────────────────────────
// For each op in the 'roles' and 'security' areas: verify X-Audit-Reason is
// sent when a reason is provided and NOT sent when absent (no prompt on default policy).

describe('adminCreateRole — X-Audit-Reason header', () => {
	const fetchMock = vi.fn();

	beforeEach(() => {
		fetchMock.mockReset();
		fetchMock.mockResolvedValue(jsonResponse({ id: 42 }, 201));
		vi.stubGlobal('fetch', fetchMock);
	});

	afterEach(() => vi.unstubAllGlobals());

	it('sends X-Audit-Reason when reason is provided', async () => {
		await adminCreateRole({ name: 'Tester', description: '', permissions: ['queue.read'] }, 'compliance audit');
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe('/api/admin/roles');
		expect(init.method).toBe('POST');
		expect(headerValue(init.headers, 'X-Audit-Reason')).toBe('compliance audit');
	});

	it('does NOT send X-Audit-Reason when no reason provided (default policy)', async () => {
		await adminCreateRole({ name: 'Tester', description: '', permissions: ['queue.read'] });
		const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(headerValue(init.headers, 'X-Audit-Reason')).toBeUndefined();
	});
});

describe('adminUpdateRole — X-Audit-Reason header', () => {
	const fetchMock = vi.fn();

	beforeEach(() => {
		fetchMock.mockReset();
		fetchMock.mockResolvedValue(jsonResponse(null, 204));
		vi.stubGlobal('fetch', fetchMock);
	});

	afterEach(() => vi.unstubAllGlobals());

	it('sends X-Audit-Reason when reason is provided', async () => {
		await adminUpdateRole(1, { name: 'Updated' }, 'policy review');
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe('/api/admin/roles/1');
		expect(init.method).toBe('PUT');
		expect(headerValue(init.headers, 'X-Audit-Reason')).toBe('policy review');
	});

	it('does NOT send X-Audit-Reason when no reason provided', async () => {
		await adminUpdateRole(1, { name: 'Updated' });
		const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(headerValue(init.headers, 'X-Audit-Reason')).toBeUndefined();
	});
});

describe('adminDeleteRole — X-Audit-Reason header', () => {
	const fetchMock = vi.fn();

	beforeEach(() => {
		fetchMock.mockReset();
		fetchMock.mockResolvedValue(jsonResponse(null, 204));
		vi.stubGlobal('fetch', fetchMock);
	});

	afterEach(() => vi.unstubAllGlobals());

	it('sends X-Audit-Reason when reason is provided', async () => {
		await adminDeleteRole(7, 'role decommission');
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe('/api/admin/roles/7');
		expect(init.method).toBe('DELETE');
		expect(headerValue(init.headers, 'X-Audit-Reason')).toBe('role decommission');
	});

	it('does NOT send X-Audit-Reason when no reason provided', async () => {
		await adminDeleteRole(7);
		const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(headerValue(init.headers, 'X-Audit-Reason')).toBeUndefined();
	});
});

describe('adminSetSodMode — X-Audit-Reason header (security area)', () => {
	const fetchMock = vi.fn();

	beforeEach(() => {
		fetchMock.mockReset();
		fetchMock.mockResolvedValue(jsonResponse({ enabled: true }));
		vi.stubGlobal('fetch', fetchMock);
	});

	afterEach(() => vi.unstubAllGlobals());

	it('sends X-Audit-Reason when reason is provided', async () => {
		await adminSetSodMode(true, 'enabling SoD for compliance');
		const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(url).toBe('/api/admin/dengbao/sod-mode');
		expect(init.method).toBe('PUT');
		expect(headerValue(init.headers, 'X-Audit-Reason')).toBe('enabling SoD for compliance');
	});

	it('does NOT send X-Audit-Reason when no reason provided', async () => {
		await adminSetSodMode(true);
		const [, init] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(headerValue(init.headers, 'X-Audit-Reason')).toBeUndefined();
	});
});

describe('roles client — remaining endpoints and error handling', () => {
	const fetchMock = vi.fn();

	beforeEach(() => {
		fetchMock.mockReset();
		vi.stubGlobal('fetch', fetchMock);
	});

	afterEach(() => vi.unstubAllGlobals());

	it('fetches permission catalog, role detail, effective permissions, and SoD mode', async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse([{ key: 'users.read', category: 'users', description: 'Read users', isSensitive: false }]));
		const catalog = await adminPermissionCatalog();
		expect(catalog[0].key).toBe('users.read');

		fetchMock.mockResolvedValueOnce(jsonResponse({ role: { id: 3, name: 'Auditor' }, members: [] }));
		const detail = await adminGetRole(3);
		expect(detail.role.name).toBe('Auditor');

		fetchMock.mockResolvedValueOnce(jsonResponse({ permissions: ['users.read'], sources: [], consoles: undefined }));
		const eff = await adminEffectivePermissions(9);
		expect(eff.consoles).toEqual([]);

		fetchMock.mockResolvedValueOnce(jsonResponse({ enabled: false, violations: [] }));
		const sod = await adminGetSodMode();
		expect(sod.enabled).toBe(false);
	});

	it('assigns and removes role members with and without X-Audit-Reason', async () => {
		fetchMock.mockResolvedValueOnce(jsonResponse({ id: 99 }, 201));
		const assigned = await adminAssignMember(3, { userId: 12 }, 'grant access');
		expect(assigned.id).toBe(99);
		const [, assignInit] = fetchMock.mock.calls[0] as [string, RequestInit];
		expect(headerValue(assignInit.headers, 'X-Audit-Reason')).toBe('grant access');

		fetchMock.mockResolvedValueOnce(jsonResponse(null, 204));
		await adminRemoveMember(3, 12, 'revoke access');
		const [removeUrl, removeInit] = fetchMock.mock.calls[1] as [string, RequestInit];
		expect(removeUrl).toBe('/api/admin/roles/3/members/12');
		expect(headerValue(removeInit.headers, 'X-Audit-Reason')).toBe('revoke access');
	});

	it('surfaces legacy {error} messages and RFC 9457 problem fallbacks on every endpoint', async () => {
		const errBody = () => jsonResponse({ error: 'boom' }, 400);
		const problemBody = () => jsonResponse({ title: 'Bad Request', detail: 'bad input', status: 400 }, 400);

		fetchMock.mockResolvedValueOnce(errBody());
		await expect(adminPermissionCatalog()).rejects.toThrow('boom');
		fetchMock.mockResolvedValueOnce(problemBody());
		await expect(adminListRoles()).rejects.toThrow('bad input');
		fetchMock.mockResolvedValueOnce(errBody());
		await expect(adminGetRole(1)).rejects.toThrow('boom');
		fetchMock.mockResolvedValueOnce(errBody());
		await expect(adminCreateRole({ name: 'x', description: '', permissions: [] })).rejects.toThrow('boom');
		fetchMock.mockResolvedValueOnce(errBody());
		await expect(adminUpdateRole(1, {})).rejects.toThrow('boom');
		fetchMock.mockResolvedValueOnce(errBody());
		await expect(adminDeleteRole(1)).rejects.toThrow('boom');
		fetchMock.mockResolvedValueOnce(errBody());
		await expect(adminAssignMember(1, { userId: 2 })).rejects.toThrow('boom');
		fetchMock.mockResolvedValueOnce(errBody());
		await expect(adminRemoveMember(1, 2)).rejects.toThrow('boom');
		fetchMock.mockResolvedValueOnce(errBody());
		await expect(adminEffectivePermissions(1)).rejects.toThrow('boom');
		fetchMock.mockResolvedValueOnce(errBody());
		await expect(adminGetSodMode()).rejects.toThrow('boom');
		fetchMock.mockResolvedValueOnce(errBody());
		await expect(adminSetSodMode(true)).rejects.toThrow('boom');
	});
});
