import { beforeEach, describe, expect, it, vi } from 'vitest';

const direct = vi.hoisted(() =>
	vi.fn().mockImplementation(async () => new Response(JSON.stringify({}), {
		status: 200,
		headers: { 'content-type': 'application/json' },
	}))
);

vi.mock('$lib/http', () => {
	class ProblemError extends Error {
		status: number;
		code: string;
		detail: string;
		extensions: Record<string, unknown>;
		constructor(shape: { status: number; code: string; detail: string; extensions?: Record<string, unknown> }) {
			super(shape.detail);
			this.status = shape.status;
			this.code = shape.code;
			this.detail = shape.detail;
			this.extensions = shape.extensions ?? {};
		}
	}
	return {
		ProblemError,
		httpRequest: direct,
		typedFetch: vi.fn(),
		problemFetch: () => ({ fetch: vi.fn(), fetchVoid: vi.fn() }),
	};
});

import * as drive from './api';

type Contract = [
	name: keyof typeof drive,
	args: unknown[],
	path: string,
	method?: string,
];

// These are transport-boundary contracts. They protect identifiers, encoding,
// destructive methods, and optional query parameters without coupling tests to
// component implementation details.
const contracts: Contract[] = [
	['listSpaces', [], '/api/drive/spaces'],
	['listSpacesAdmin', [], '/api/drive/spaces?admin=1'],
	['createSpace', [{ name: 'Team', classification: 'secure' }], '/api/drive/spaces', 'POST'],
	['patchSpace', [3, { quotaBytes: 10 }], '/api/drive/spaces/3', 'PATCH'],
	['listMembers', [3], '/api/drive/spaces/3/members'],
	['grantMember', [3, 7, 'editor'], '/api/drive/spaces/3/members', 'POST'],
	['revokeMember', [3, 7], '/api/drive/spaces/3/members/7', 'DELETE'],
	['tree', [3], '/api/drive/spaces/3/tree'],
	['tree', [3, { parent: 4, deleted: true }], '/api/drive/spaces/3/tree?parent=4&deleted=1'],
	['changes', [3, 12], '/api/drive/changes?space=3&since=12'],
	['getNodesMeta', [[5, 6]], '/api/drive/nodes?ids=5%2C6'],
	['createNode', [{ spaceId: 3, parentId: null, kind: 'folder', name: 'Docs' }], '/api/drive/nodes', 'POST'],
	['renameNode', [5, 'Roadmap'], '/api/drive/nodes/5', 'PATCH'],
	['moveNode', [5, null], '/api/drive/nodes/5', 'PATCH'],
	['trashNode', [5], '/api/drive/nodes/5/trash', 'POST'],
	['restoreNode', [5], '/api/drive/nodes/5/restore', 'POST'],
	['destroyNode', [5], '/api/drive/nodes/5', 'DELETE'],
	['putChunk', [3, 'abc', new Uint8Array([1])], '/api/drive/chunks/abc?space=3', 'PUT'],
	['putVersion', [5, { contentSha256: 'abc', size: 1, baseVersionId: null, manifest: [] }], '/api/drive/files/5/versions', 'POST'],
	['restoreVersion', [5, 9, { baseVersionId: 11 }], '/api/drive/files/5/versions/9/restore', 'POST'],
	['listVersions', [5], '/api/drive/files/5/versions'],
	['history', [5, { limit: 50, cursor: 'cursor/1' }], '/api/drive/files/5/history?limit=50&cursor=cursor%2F1'],
	['listBranches', [5], '/api/drive/files/5/branches'],
	['listBranches', [5, { all: true }], '/api/drive/files/5/branches?all=1'],
	['createBranch', [5, 'review', 9], '/api/drive/files/5/branches', 'POST'],
	['renameBranch', [2, 'release'], '/api/drive/branches/2', 'PATCH'],
	['setBranchStatus', [2, 'review'], '/api/drive/branches/2', 'PATCH'],
	['resolveBranch', [2, 'discard'], '/api/drive/branches/2/resolve', 'POST'],
	['resolveBranch', [2, 'keep_both', 'Copy'], '/api/drive/branches/2/resolve', 'POST'],
	['setLabel', [9, 'approved'], '/api/drive/versions/9/labels', 'POST'],
	['removeLabel', [9, 'legal hold'], '/api/drive/versions/9/labels/legal%20hold', 'DELETE'],
	['lockFile', [5], '/api/drive/files/5/lock', 'PUT'],
	['lockFile', [5, { mode: 'hard', ttlMinutes: 10 }], '/api/drive/files/5/lock', 'PUT'],
	['unlockFile', [5], '/api/drive/files/5/lock', 'DELETE'],
	['unlockFile', [5, { break: true, keepalive: true }], '/api/drive/files/5/lock?break=1', 'DELETE'],
	['listLocks', [3], '/api/drive/spaces/3/locks'],
	['setWatch', [5], '/api/drive/nodes/5/watch', 'PUT'],
	['setWatch', [5, ['version.created']], '/api/drive/nodes/5/watch', 'PUT'],
	['removeWatch', [5], '/api/drive/nodes/5/watch', 'DELETE'],
	['activity', [3], '/api/drive/spaces/3/activity'],
	['activity', [3, { node: 5, beforeId: 8, max: 20 }], '/api/drive/spaces/3/activity?node=5&beforeId=8&max=20'],
	['listFolderAdmins', [5], '/api/drive/nodes/5/folder-admins'],
	['grantFolderAdmin', [5, 7], '/api/drive/nodes/5/folder-admins/7', 'PUT'],
	['revokeFolderAdmin', [5, 7], '/api/drive/nodes/5/folder-admins/7', 'DELETE'],
	['verifyAuditChain', [3], '/api/drive/spaces/3/audit/verify'],
	['requestExport', [9, 'download', 30], '/api/drive/export', 'POST'],
	['searchNodes', ['report'], '/api/drive/search?q=report'],
	['searchNodes', ['report', { spaceId: 3, max: 5 }], '/api/drive/search?q=report&space=3&max=5'],
	['listWatches', [], '/api/drive/watches'],
	['trashAdminList', [3], '/api/drive/spaces/3/trash?tier=2'],
	['purgeRestore', [5], '/api/drive/nodes/5/purge-restore', 'POST'],
	['queryAudit', [{ spaceId: 3 }], '/api/drive/audit?space=3'],
	['queryAudit', [{ spaceId: 3, actor: 7, action: 'download', from: 'a', to: 'b', q: 'x', max: 10, beforeId: 9 }], '/api/drive/audit?space=3&actor=7&action=download&from=a&to=b&q=x&max=10&beforeId=9'],
	['getAuditActions', [], '/api/drive/audit-actions'],
	['listAuditAlarms', [], '/api/drive/audit-alarms'],
	['createAuditAlarm', [{ actionPattern: 'export.*' }], '/api/drive/audit-alarms', 'POST'],
	['updateAuditAlarm', [4, { enabled: false }], '/api/drive/audit-alarms/4', 'PATCH'],
	['deleteAuditAlarm', [4], '/api/drive/audit-alarms/4', 'DELETE'],
	['spaceAsOf', [3, '2026-01-01T00:00:00Z'], '/api/drive/spaces/3/asof?at=2026-01-01T00%3A00%3A00Z'],
];

describe('Drive REST helper endpoint contracts', () => {
	beforeEach(() => {
		direct.mockClear();
	});

	it.each(contracts)('%s preserves its endpoint and HTTP method', async (name, args, path, method = 'GET') => {
		const invoke = drive[name] as unknown as (...values: unknown[]) => Promise<unknown>;
		await invoke(...args);
		expect(direct).toHaveBeenCalledTimes(1);
		const [actualPath, options = {}] = direct.mock.calls[0] as [string, RequestInit?];
		expect(actualPath).toBe(path);
		expect(options.method ?? 'GET').toBe(method);
	});

	it('preserves content URLs, token encoding, and complete audit CSV filters', () => {
		expect(drive.contentUrl(9)).toBe('/api/drive/versions/9/content');
		expect(drive.previewUrl(9)).toBe('/api/drive/versions/9/preview');
		expect(drive.exportDownloadUrl('a/b c')).toBe('/api/drive/export/a%2Fb%20c');
		expect(drive.auditCsvUrl({
			spaceId: 3,
			actor: 7,
			action: 'download',
			from: 'a',
			to: 'b',
			q: 'x',
			max: 10,
			beforeId: 9,
		})).toBe('/api/drive/audit?space=3&actor=7&action=download&from=a&to=b&q=x&max=10&beforeId=9&format=csv');
	});

	it('passes caller options including Range header without inventing a client-controlled render proof', async () => {
		await drive.fetchVersionContent(9, { allowStatuses: [404], headers: { Accept: 'application/pdf', Range: 'bytes=0-1023' } });
		const [contentPath, contentOpts] = direct.mock.calls.at(-1) as [string, { allowStatuses?: number[]; headers?: Record<string, string> }];
		expect(contentPath).toBe('/api/drive/versions/9/content');
		expect(contentOpts.allowStatuses).toEqual([404]);
		expect(contentOpts.headers?.Accept).toBe('application/pdf');
		expect(contentOpts.headers?.Range).toBe('bytes=0-1023');

		await drive.fetchVersionPreview(9);
		const [previewPath, previewOpts] = direct.mock.calls.at(-1) as [string, { allowStatuses?: number[] }];
		expect(previewPath).toBe('/api/drive/versions/9/preview');
		expect(previewOpts.allowStatuses).toEqual([]);
	});

	it('returns an unread Response body when non-2xx status is passed through via allowStatuses', async () => {
		const pendingProblem = {
			type: 'https://setjoin.com/problems/drive/preview-not-ready',
			title: 'Not Found',
			status: 404,
			detail: 'preview rendition not ready (status=pending)',
		};
		direct.mockResolvedValueOnce(
			new Response(JSON.stringify(pendingProblem), {
				status: 404,
				headers: { 'content-type': 'application/problem+json' },
			})
		);
		const previewRes = await drive.fetchVersionPreview(9, { allowStatuses: [404] });
		expect(previewRes.status).toBe(404);
		expect(previewRes.bodyUsed).toBe(false);
		await expect(previewRes.json()).resolves.toEqual(pendingProblem);

		direct.mockResolvedValueOnce(
			new Response(JSON.stringify(pendingProblem), {
				status: 404,
				headers: { 'content-type': 'application/problem+json' },
			})
		);
		const contentRes = await drive.fetchVersionContent(9, { allowStatuses: [404] });
		expect(contentRes.status).toBe(404);
		expect(contentRes.bodyUsed).toBe(false);
		await expect(contentRes.json()).resolves.toEqual(pendingProblem);
	});

	it('maps the possession-proof HEAD response to a boolean', async () => {
		direct
			.mockResolvedValueOnce(new Response(null, { status: 200 }))
			.mockResolvedValueOnce(new Response(null, { status: 404 }));
		await expect(drive.headChunk(3, 'abc')).resolves.toBe(true);
		await expect(drive.headChunk(3, 'abc')).resolves.toBe(false);
		expect(direct).toHaveBeenCalledWith(
			'/api/drive/chunks/abc?space=3',
			expect.objectContaining({
				method: 'HEAD',
				allowStatuses: [404],
			})
		);
	});
});
