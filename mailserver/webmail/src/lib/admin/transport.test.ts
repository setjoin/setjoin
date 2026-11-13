import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import { adminFetch } from './transport';
import { adminHealth as healthOwner } from './health';
import { adminHealth as compatibilityHealth } from './client';

function response(status = 200, body: unknown = {}): Response {
	return {
		ok: status >= 200 && status < 300,
		status,
		json: async () => body,
		text: async () => JSON.stringify(body)
	} as Response;
}

describe('admin transport kernel', () => {
	afterEach(() => vi.unstubAllGlobals());

	it('preserves API prefix, JSON header, caller headers, no-store cache, method, body, and one request', async () => {
		const fetchMock = vi.fn().mockResolvedValue(response());
		vi.stubGlobal('fetch', fetchMock);
		const body = JSON.stringify({ enabled: false });

		await adminFetch('/admin/features/feature.test', {
			method: 'DELETE',
			body,
			headers: { 'X-Audit-Reason': 'retire test flag' },
			cache: 'force-cache'
		});

		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(fetchMock).toHaveBeenCalledWith('/api/admin/features/feature.test', expect.objectContaining({
			method: 'DELETE',
			body,
			cache: 'no-store',
			credentials: 'include',
			headers: {
				'Content-Type': 'application/json',
				'X-Audit-Reason': 'retire test flag'
			}
		}));
	});

	it('preserves explicit content type and leaves FormData content type to the browser', async () => {
		const fetchMock = vi.fn().mockResolvedValue(response());
		vi.stubGlobal('fetch', fetchMock);

		await adminFetch('/admin/import', {
			method: 'POST',
			body: 'raw',
			headers: { 'Content-Type': 'application/octet-stream', 'X-Import': 'one' }
		});
		const form = new FormData();
		form.set('file', new Blob(['csv']), 'users.csv');
		await adminFetch('/admin/import', { method: 'POST', body: form });

		expect((fetchMock.mock.calls[0][1] as RequestInit).headers).toEqual({
			'Content-Type': 'application/octet-stream',
			'X-Import': 'one'
		});
		expect((fetchMock.mock.calls[1][1] as RequestInit).headers).toEqual({});
		expect(fetchMock).toHaveBeenCalledTimes(2);
	});

	it('preserves login redirect and forbidden classification', async () => {
		vi.stubGlobal('window', { location: { href: '/admin' } });
		const fetchMock = vi.fn()
			.mockResolvedValueOnce(response(401))
			.mockResolvedValueOnce(response(403));
		vi.stubGlobal('fetch', fetchMock);

		await expect(adminFetch('/admin/health')).rejects.toThrow('Session expired');
		expect(window.location.href).toBe('/login');
		await expect(adminFetch('/admin/health')).rejects.toThrow('Admin access required');
		expect(fetchMock).toHaveBeenCalledTimes(2);
	});

	it('keeps the Health compatibility export identical and uses one transport request', async () => {
		const fetchMock = vi.fn().mockResolvedValue(response(200, { status: 'ok', checks: [] }));
		vi.stubGlobal('fetch', fetchMock);

		expect(compatibilityHealth).toBe(healthOwner);
		await expect(compatibilityHealth()).resolves.toEqual({ status: 'ok', checks: [] });
		expect(fetchMock).toHaveBeenCalledTimes(1);
		expect(fetchMock.mock.calls[0][0]).toBe('/api/admin/health');
	});
});

describe('admin transport ownership boundaries', () => {
	const adminDir = resolve(process.cwd(), 'src/lib/admin');
	const source = (file: string) => readFileSync(resolve(adminDir, file), 'utf8');

	it('keeps the exact moved export/import map and deletes moved definitions from client', () => {
		const client = source('client.ts');
		const transport = source('transport.ts');
		const health = source('health.ts');

		expect(client).toContain('export { adminFetch } from "./transport";');
		expect(client).toContain('export { adminHealth } from "./health";');
		expect(client).toContain('export type { HealthCheck, HealthResponse } from "./health";');
		expect(client).not.toMatch(/export function adminFetch\b/);
		expect(client).not.toMatch(/export async function adminHealth\b/);
		expect(client).not.toMatch(/export interface Health(?:Check|Response)\b/);
		expect(transport).toMatch(/export function adminFetch\b/);
		expect(health).toMatch(/export async function adminHealth\b/);
		expect(health).toMatch(/export interface HealthCheck\b/);
		expect(health).toMatch(/export interface HealthResponse\b/);

		const directExports = [...client.matchAll(
			/^export\s+(?:async\s+)?(?:function|interface|type|const|class)\s+(\w+)/gm
		)].map((match) => match[1]);
		const compatibilityExports = [...client.matchAll(
			/^export(?:\s+type)?\s+\{([^}]+)\}\s+from/gm
		)].flatMap((match) => match[1].split(',').map((name) => name.trim()));
		const publicExports = [...directExports, ...compatibilityExports];
		// 418: adminPathSegment (S19-URL-CONSTRUCTION hardening) joined the
		// public surface deliberately — guarded path-segment encoding for the
		// client.ts helpers. Bump ONLY with a reviewed, named addition.
		expect(publicExports).toHaveLength(418);
		expect(new Set(publicExports).size).toBe(418);
		expect(compatibilityExports).toEqual([
			'adminFetch',
			'adminHealth',
			'HealthCheck',
			'HealthResponse'
		]);

		for (const file of ['accessReviews.ts', 'guests.ts', 'roles.ts']) {
			expect(source(file), file).toContain("from './transport'");
			expect(source(file), file).not.toContain("from './client'");
		}
	});

	it('keeps transport acyclic and free of admin-domain imports', () => {
		const productionFiles = readdirSync(adminDir)
			.filter((file) => file.endsWith('.ts') && !file.endsWith('.test.ts'));
		const graph = new Map<string, string[]>();
		for (const file of productionFiles) {
			const dependencies: string[] = [];
			for (const match of source(file).matchAll(/from\s+['"]\.\/([^'"]+)['"]/g)) {
				const dependency = `${match[1]}.ts`;
				if (productionFiles.includes(dependency)) dependencies.push(dependency);
			}
			graph.set(file, dependencies);
		}

		expect(graph.get('transport.ts')).toEqual([]);
		const active = new Set<string>();
		const complete = new Set<string>();
		const visit = (file: string, path: string[]): void => {
			if (active.has(file)) throw new Error(`admin import cycle: ${[...path, file].join(' -> ')}`);
			if (complete.has(file)) return;
			active.add(file);
			for (const dependency of graph.get(file) ?? []) visit(dependency, [...path, file]);
			active.delete(file);
			complete.add(file);
		};
		for (const file of productionFiles) visit(file, []);
		expect(complete.size).toBe(productionFiles.length);
	});
});
