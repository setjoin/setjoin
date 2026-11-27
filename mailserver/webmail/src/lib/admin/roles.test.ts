import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

import {
	adminListRoles,
	adminCreateRole,
	adminUpdateRole,
	adminDeleteRole,
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
