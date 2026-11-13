// @vitest-environment node
import { describe, it, expect, vi } from 'vitest';
import type { FetchLike } from './types.js';
import { DriveApiError, DriveHttp, withBackoff } from './protocol.js';

function jsonRes(status: number, body: unknown, headers: Record<string, string> = {}): Response {
	return new Response(JSON.stringify(body), {
		status,
		headers: { 'Content-Type': 'application/json', ...headers },
	});
}
function problemRes(status: number, type: string, code?: string): Response {
	return jsonRes(status, { type, status, detail: 'problem', code }, { 'Content-Type': 'application/problem+json' });
}

describe('DriveHttp.changes', () => {
	it('anchor call (since=null) reads GET /spaces, never touches /changes', async () => {
		const calls: string[] = [];
		const fetchFn: FetchLike = async (url) => {
			calls.push(url);
			return jsonRes(200, [
				{ id: 1, name: 'Personal', classification: 'regular', role: 'owner', changeSeq: 42 },
				{ id: 2, name: 'Other', classification: 'regular', role: 'owner', changeSeq: 7 },
			]);
		};
		const http = new DriveHttp(fetchFn, '/api/drive');
		const res = await http.changes(1, null);
		expect(res).toEqual({ resync: false, newState: '42', changed: [], hasMore: false });
		expect(calls).toEqual(['/api/drive/spaces']);
	});

	it('follows hasMore pages and concatenates changed in order', async () => {
		let call = 0;
		const fetchFn: FetchLike = async (url) => {
			call++;
			expect(url).toContain('/api/drive/changes?space=1');
			if (call === 1) {
				expect(url).toContain('since=10');
				return jsonRes(200, { newState: 11, changed: [{ nodeId: 1, op: 'update', seq: 11 }], hasMore: true });
			}
			expect(url).toContain('since=11');
			return jsonRes(200, { newState: 12, changed: [{ nodeId: 2, op: 'create', seq: 12 }], hasMore: false });
		};
		const http = new DriveHttp(fetchFn, '/api/drive');
		const res = await http.changes(1, '10');
		expect(res).toEqual({
			resync: false,
			newState: '12',
			changed: [
				{ nodeId: 1, op: 'update', seq: 11 },
				{ nodeId: 2, op: 'create', seq: 12 },
			],
			hasMore: false,
		});
		expect(call).toBe(2);
	});

	it('a 409 cannot-calculate-changes problem maps to {resync:true}, not a throw', async () => {
		const fetchFn: FetchLike = async () =>
			problemRes(409, 'https://setjoin.com/problems/drive/cannot-calculate-changes');
		const http = new DriveHttp(fetchFn, '/api/drive');
		await expect(http.changes(1, '0')).resolves.toEqual({ resync: true });
	});

	it('a non-409 error surfaces as a typed DriveApiError (status/code/type)', async () => {
		const fetchFn: FetchLike = async () => problemRes(413, 'https://setjoin.com/problems/drive/quota-exceeded', 'BZ148');
		const http = new DriveHttp(fetchFn, '/api/drive');
		await expect(http.changes(1, '0')).rejects.toMatchObject({
			status: 413,
			code: 'BZ148',
			type: 'https://setjoin.com/problems/drive/quota-exceeded',
		});
	});
});

describe('DriveHttp ACL synchronization', () => {
	it('follows hidden-only invalidation pages by opaque cursor and preserves the later relevant event', async () => {
		const calls: string[] = [];
		const fetchFn: FetchLike = async (url) => {
			calls.push(url);
			const parsed = new URL(url, 'http://test.invalid');
			if (!parsed.searchParams.has('cursor')) {
				return jsonRes(200, {
					cursor: '11111111-1111-1111-1111-111111111111', epoch: '8',
					invalidations: [], hasMore: true, fullReconcile: false,
				});
			}
			expect(parsed.searchParams.get('cursor')).toBe('11111111-1111-1111-1111-111111111111');
			return jsonRes(200, {
				cursor: '22222222-2222-2222-2222-222222222222', epoch: '8',
				invalidations: [{ anchorNodeId: '7', epoch: '8', reason: 'revoke', fullReconcile: false }],
				hasMore: false, fullReconcile: false,
			});
		};
		const http = new DriveHttp(fetchFn, '/api/drive');

		await expect(http.accessInvalidations(3, null, 1)).resolves.toEqual({
			cursor: '22222222-2222-2222-2222-222222222222', epoch: '8',
			invalidations: [{ anchorNodeId: '7', epoch: '8', reason: 'revoke', fullReconcile: false }],
			hasMore: false, fullReconcile: false,
		});
		expect(calls).toHaveLength(2);
	});

	it('stops paging immediately when the server declares the cursor unavailable', async () => {
		const fetchFn = vi.fn<FetchLike>(async () => jsonRes(200, {
			cursor: null, epoch: null, invalidations: [], hasMore: false,
			fullReconcile: true, reason: 'cursorUnavailable',
		}));
		const http = new DriveHttp(fetchFn, '/api/drive');
		const page = await http.accessInvalidations(3, 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');
		expect(page).toMatchObject({ fullReconcile: true, reason: 'cursorUnavailable' });
		expect(fetchFn).toHaveBeenCalledTimes(1);
	});

	it('surfaces an epoch conflict from visibility paging as a typed error', async () => {
		const http = new DriveHttp(
			async () => problemRes(409, 'https://setjoin.com/errors/drive-acl-conflict', 'BZ254'),
			'/api/drive',
		);
		await expect(http.visibilitySnapshot(3, '0', '7')).rejects.toMatchObject({ status: 409, code: 'BZ254' });
	});
});

describe('DriveHttp.nodesMeta', () => {
	it('chunks ids into <=500-id batches', async () => {
		const calls: string[] = [];
		const fetchFn: FetchLike = async (url) => {
			calls.push(url);
			return jsonRes(200, []);
		};
		const http = new DriveHttp(fetchFn, '/api/drive');
		const ids = Array.from({ length: 501 }, (_, i) => i + 1);
		await http.nodesMeta(ids);
		expect(calls).toHaveLength(2);
		expect(calls[0]).toContain(ids.slice(0, 500).join(','));
		expect(calls[1]).toContain('501');
	});

	it('empty ids makes no request', async () => {
		const fetchFn = vi.fn<FetchLike>();
		const http = new DriveHttp(fetchFn, '/api/drive');
		expect(await http.nodesMeta([])).toEqual([]);
		expect(fetchFn).not.toHaveBeenCalled();
	});

	it('passes branchCount straight through (P4 Task 17 -- no translation needed, NodeMeta already matches the wire shape)', async () => {
		const fetchFn: FetchLike = async () =>
			jsonRes(200, [
				{
					nodeId: 1,
					spaceId: 1,
					parentId: null,
					kind: 'file',
					name: 'Report.xlsx',
					deletedAt: null,
					headVersionId: 9,
					contentSha256: 'sha',
					sizeBytes: 5,
					contentType: null,
					branchCount: 2,
				},
			]);
		const http = new DriveHttp(fetchFn, '/api/drive');
		const [node] = await http.nodesMeta([1]);
		expect(node.branchCount).toBe(2);
	});
});

describe('DriveHttp.fileBranches', () => {
	it('GETs the file branch list and unwraps the wire array', async () => {
		let seenUrl: string | undefined;
		const fetchFn: FetchLike = async (url) => {
			seenUrl = url;
			return jsonRes(200, [
				{
					id: 5,
					name: 'budget-redo',
					status: 'open',
					autoCreated: false,
					headVersionId: 33,
					forkedFromVersionId: 10,
					createdBy: 1,
					createdAt: '2026-07-10T00:00:00Z',
					resolvedBy: null,
					resolvedAt: null,
					ffEligible: true,
				},
			]);
		};
		const http = new DriveHttp(fetchFn, '/api/drive');
		const branches = await http.fileBranches(3);
		expect(seenUrl).toBe('/api/drive/files/3/branches');
		expect(branches).toEqual([
			{ id: 5, name: 'budget-redo', status: 'open', headVersionId: 33, forkedFromVersionId: 10 },
		]);
	});
});

describe('DriveHttp chunk transport', () => {
	it('headChunk: 200 -> true, 404 -> false', async () => {
		let status = 200;
		const fetchFn: FetchLike = async () => new Response(null, { status });
		const http = new DriveHttp(fetchFn, '/api/drive');
		expect(await http.headChunk(1, 'abc')).toBe(true);
		status = 404;
		expect(await http.headChunk(1, 'abc')).toBe(false);
	});

	it('pushChunk PUTs raw bytes with an octet-stream content-type', async () => {
		let seenInit: RequestInit | undefined;
		const fetchFn: FetchLike = async (_url, init) => {
			seenInit = init;
			return new Response(null, { status: 201 });
		};
		const http = new DriveHttp(fetchFn, '/api/drive');
		const bytes = new Uint8Array([1, 2, 3]);
		await http.pushChunk(1, 'sha', bytes);
		expect(seenInit?.method).toBe('PUT');
		expect((seenInit?.headers as Record<string, string>)['Content-Type']).toBe('application/octet-stream');
		expect(seenInit?.body).toBe(bytes);
	});
});

describe('DriveHttp.contentRange', () => {
	it('sends a Range header and returns the body bytes', async () => {
		let seenInit: RequestInit | undefined;
		const fetchFn: FetchLike = async (_url, init) => {
			seenInit = init;
			return new Response(new Uint8Array([9, 8, 7]), { status: 206 });
		};
		const http = new DriveHttp(fetchFn, '/api/drive');
		const bytes = await http.contentRange(5, 10, 20);
		expect((seenInit?.headers as Record<string, string>).Range).toBe('bytes=10-20');
		expect(Array.from(bytes)).toEqual([9, 8, 7]);
	});
});

describe('DriveHttp.putVersion / listVersions', () => {
	it('putVersion sends the full body and parses the result', async () => {
		let seenBody: string | undefined;
		const fetchFn: FetchLike = async (_url, init) => {
			seenBody = init?.body as string;
			return jsonRes(201, { versionId: 9, conflict: false, branchId: null, headVersionId: 9, wormPending: false });
		};
		const http = new DriveHttp(fetchFn, '/api/drive');
		const result = await http.putVersion(3, {
			contentSha256: 'sha',
			size: 5,
			baseVersionId: null,
			manifest: [{ sha256: 'sha', size: 5 }],
			deviceLabel: 'bobs-laptop',
		});
		expect(result.versionId).toBe(9);
		expect(JSON.parse(seenBody!)).toMatchObject({ contentSha256: 'sha', deviceLabel: 'bobs-laptop' });
	});

	it('putVersion forwards branchId (P4 Task 17: a branch upload never lands on main)', async () => {
		let seenBody: string | undefined;
		const fetchFn: FetchLike = async (_url, init) => {
			seenBody = init?.body as string;
			return jsonRes(201, { versionId: 44, conflict: false, branchId: 5, headVersionId: null, wormPending: false });
		};
		const http = new DriveHttp(fetchFn, '/api/drive');
		const result = await http.putVersion(3, {
			contentSha256: 'sha',
			size: 5,
			baseVersionId: 10,
			manifest: [{ sha256: 'sha', size: 5 }],
			deviceLabel: 'bobs-laptop',
			branchId: 5,
		});
		expect(result.branchId).toBe(5);
		expect(JSON.parse(seenBody!)).toMatchObject({ branchId: 5 });
	});

	it('listVersions returns deviceLabel per version (C2 conflict-sibling naming input)', async () => {
		const fetchFn: FetchLike = async () =>
			jsonRes(200, [
				{
					id: 9,
					conflictOf: null,
					sha256: 'sha-head',
					size: 5,
					deviceLabel: 'bobs-laptop',
					createdAt: '2026-07-09T00:00:00Z',
				},
				{
					id: 8,
					conflictOf: 9,
					sha256: 'sha-old',
					size: 4,
					deviceLabel: 'anns-desktop',
					createdAt: '2026-07-08T00:00:00Z',
				},
			]);
		const http = new DriveHttp(fetchFn, '/api/drive');
		const versions = await http.listVersions(3);
		expect(versions).toHaveLength(2);
		expect(versions[1]).toMatchObject({ conflictOf: 9, deviceLabel: 'anns-desktop' });
	});
});

describe('DriveHttp.spaceLocks / lockFile', () => {
	it('spaceLocks GETs the space lock list and unwraps the {locks:[...]} envelope', async () => {
		let seenUrl: string | undefined;
		const fetchFn: FetchLike = async (url) => {
			seenUrl = url;
			return jsonRes(200, {
				locks: [
					{
						nodeId: 5,
						name: 'budget.xlsx',
						holderId: 42,
						holderName: 'Alice',
						mode: 'hard',
						branchId: null,
						acquiredAt: '2026-07-10T00:00:00Z',
						expiresAt: '2026-07-10T08:00:00Z',
						deviceLabel: 'alices-laptop',
					},
				],
			});
		};
		const http = new DriveHttp(fetchFn, '/api/drive');
		const locks = await http.spaceLocks(1);
		expect(seenUrl).toBe('/api/drive/spaces/1/locks');
		expect(locks).toEqual([
			{
				nodeId: 5,
				name: 'budget.xlsx',
				holderId: 42,
				holderName: 'Alice',
				mode: 'hard',
				branchId: null,
				acquiredAt: '2026-07-10T00:00:00Z',
				expiresAt: '2026-07-10T08:00:00Z',
				deviceLabel: 'alices-laptop',
			},
		]);
	});

	it('lockFile PUTs the body and returns the acquire/renew/held result', async () => {
		let seenUrl: string | undefined;
		let seenInit: RequestInit | undefined;
		const fetchFn: FetchLike = async (url, init) => {
			seenUrl = url;
			seenInit = init;
			return jsonRes(200, { status: 'acquired', expiresAt: '2026-07-10T08:00:00Z', mode: 'soft' });
		};
		const http = new DriveHttp(fetchFn, '/api/drive');
		const result = await http.lockFile(5, { mode: 'soft', deviceLabel: 'bobs-laptop' });
		expect(seenUrl).toBe('/api/drive/files/5/lock');
		expect(seenInit?.method).toBe('PUT');
		expect(JSON.parse(seenInit?.body as string)).toEqual({ mode: 'soft', deviceLabel: 'bobs-laptop' });
		expect(result).toEqual({ status: 'acquired', expiresAt: '2026-07-10T08:00:00Z', mode: 'soft' });
	});
});

describe('withBackoff', () => {
	it('retries a 5xx DriveApiError up to maxRetries then succeeds', async () => {
		let attempts = 0;
		const result = await withBackoff(
			async () => {
				attempts++;
				if (attempts < 3) throw new DriveApiError(503, 'about:blank');
				return 'ok';
			},
			{ maxRetries: 5, baseDelayMs: 1, sleep: async () => {} }
		);
		expect(result).toBe('ok');
		expect(attempts).toBe(3);
	});

	it('retries a network throw (non-DriveApiError)', async () => {
		let attempts = 0;
		const result = await withBackoff(
			async () => {
				attempts++;
				if (attempts < 2) throw new Error('ECONNRESET');
				return 'ok';
			},
			{ sleep: async () => {} }
		);
		expect(result).toBe('ok');
		expect(attempts).toBe(2);
	});

	it('does NOT retry a 4xx DriveApiError — a 422 must not loop', async () => {
		let attempts = 0;
		await expect(
			withBackoff(
				async () => {
					attempts++;
					throw new DriveApiError(422, 'https://setjoin.com/problems/drive/invalid-arguments', 'BZ141');
				},
				{ sleep: async () => {} }
			)
		).rejects.toMatchObject({ status: 422 });
		expect(attempts).toBe(1);
	});
});
