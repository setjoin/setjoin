import { beforeEach, describe, expect, it, vi } from 'vitest';

const transport = vi.hoisted(() => vi.fn().mockResolvedValue({}));
const direct = vi.hoisted(() => vi.fn().mockResolvedValue({ status: 200 }));

vi.mock('$lib/http', () => {
	class ProblemError extends Error {}
	return {
		ProblemError,
		httpRequest: direct,
		typedFetch: vi.fn(),
		problemFetch: () => ({ fetch: transport, fetchVoid: transport }),
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
	['listSpaces', [], '/spaces'],
	['listSpacesAdmin', [], '/spaces?admin=1'],
	['createSpace', [{ name: 'Team', classification: 'secure' }], '/spaces', 'POST'],
	['patchSpace', [3, { quotaBytes: 10 }], '/spaces/3', 'PATCH'],
	['listMembers', [3], '/spaces/3/members'],
	['grantMember', [3, 7, 'editor'], '/spaces/3/members', 'POST'],
	['revokeMember', [3, 7], '/spaces/3/members/7', 'DELETE'],
	['tree', [3], '/spaces/3/tree'],
	['tree', [3, { parent: 4, deleted: true }], '/spaces/3/tree?parent=4&deleted=1'],
	['changes', [3, 12], '/changes?space=3&since=12'],
	['createNode', [{ spaceId: 3, parentId: null, kind: 'folder', name: 'Docs' }], '/nodes', 'POST'],
	['renameNode', [5, 'Roadmap'], '/nodes/5', 'PATCH'],
	['moveNode', [5, null], '/nodes/5', 'PATCH'],
	['trashNode', [5], '/nodes/5/trash', 'POST'],
	['restoreNode', [5], '/nodes/5/restore', 'POST'],
	['destroyNode', [5], '/nodes/5', 'DELETE'],
	['putChunk', [3, 'abc', new Uint8Array([1])], '/chunks/abc?space=3', 'PUT'],
	['putVersion', [5, { contentSha256: 'abc', size: 1, baseVersionId: null, manifest: [] }], '/files/5/versions', 'POST'],
	['restoreVersion', [5, 9, { baseVersionId: 11 }], '/files/5/versions/9/restore', 'POST'],
	['listVersions', [5], '/files/5/versions'],
	['history', [5, { limit: 50, cursor: 'cursor/1' }], '/files/5/history?limit=50&cursor=cursor%2F1'],
	['listBranches', [5], '/files/5/branches'],
	['listBranches', [5, { all: true }], '/files/5/branches?all=1'],
	['createBranch', [5, 'review', 9], '/files/5/branches', 'POST'],
	['renameBranch', [2, 'release'], '/branches/2', 'PATCH'],
	['setBranchStatus', [2, 'review'], '/branches/2', 'PATCH'],
	['resolveBranch', [2, 'discard'], '/branches/2/resolve', 'POST'],
	['resolveBranch', [2, 'keep_both', 'Copy'], '/branches/2/resolve', 'POST'],
	['setLabel', [9, 'approved'], '/versions/9/labels', 'POST'],
	['removeLabel', [9, 'legal hold'], '/versions/9/labels/legal%20hold', 'DELETE'],
	['lockFile', [5], '/files/5/lock', 'PUT'],
	['lockFile', [5, { mode: 'hard', ttlMinutes: 10 }], '/files/5/lock', 'PUT'],
	['unlockFile', [5], '/files/5/lock', 'DELETE'],
	['unlockFile', [5, { break: true, keepalive: true }], '/files/5/lock?break=1', 'DELETE'],
	['listLocks', [3], '/spaces/3/locks'],
	['setWatch', [5], '/nodes/5/watch', 'PUT'],
	['setWatch', [5, ['version.created']], '/nodes/5/watch', 'PUT'],
	['removeWatch', [5], '/nodes/5/watch', 'DELETE'],
	['activity', [3], '/spaces/3/activity'],
	['activity', [3, { node: 5, beforeId: 8, max: 20 }], '/spaces/3/activity?node=5&beforeId=8&max=20'],
	['listFolderAdmins', [5], '/nodes/5/folder-admins'],
	['grantFolderAdmin', [5, 7], '/nodes/5/folder-admins/7', 'PUT'],
	['revokeFolderAdmin', [5, 7], '/nodes/5/folder-admins/7', 'DELETE'],
	['verifyAuditChain', [3], '/spaces/3/audit/verify'],
	['requestExport', [9, 'download', 30], '/export', 'POST'],
	['searchNodes', ['report'], '/search?q=report'],
	['searchNodes', ['report', { spaceId: 3, max: 5 }], '/search?q=report&space=3&max=5'],
	['listWatches', [], '/watches'],
	['trashAdminList', [3], '/spaces/3/trash?tier=2'],
	['purgeRestore', [5], '/nodes/5/purge-restore', 'POST'],
	['queryAudit', [{ spaceId: 3 }], '/audit?space=3'],
	['queryAudit', [{ spaceId: 3, actor: 7, action: 'download', from: 'a', to: 'b', q: 'x', max: 10, beforeId: 9 }], '/audit?space=3&actor=7&action=download&from=a&to=b&q=x&max=10&beforeId=9'],
	['getAuditActions', [], '/audit-actions'],
	['listAuditAlarms', [], '/audit-alarms'],
	['createAuditAlarm', [{ actionPattern: 'export.*' }], '/audit-alarms', 'POST'],
	['updateAuditAlarm', [4, { enabled: false }], '/audit-alarms/4', 'PATCH'],
	['deleteAuditAlarm', [4], '/audit-alarms/4', 'DELETE'],
	['spaceAsOf', [3, '2026-01-01T00:00:00Z'], '/spaces/3/asof?at=2026-01-01T00%3A00%3A00Z'],
];

describe('Drive REST helper endpoint contracts', () => {
	beforeEach(() => {
		transport.mockClear();
		direct.mockClear();
	});

	it.each(contracts)('%s preserves its endpoint and HTTP method', async (name, args, path, method = 'GET') => {
		const invoke = drive[name] as unknown as (...values: unknown[]) => Promise<unknown>;
		await invoke(...args);
		expect(transport).toHaveBeenCalledTimes(1);
		const [actualPath, options = {}] = transport.mock.calls[0] as [string, RequestInit?];
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

	it('passes caller options without inventing a client-controlled render proof', async () => {
		await drive.fetchVersionContent(9, { allowStatuses: [404], headers: { Accept: 'application/pdf' } });
		expect(direct).toHaveBeenLastCalledWith('/api/drive/versions/9/content', {
			allowStatuses: [404],
			headers: { Accept: 'application/pdf' },
		});
		await drive.fetchVersionPreview(9);
		expect(direct).toHaveBeenLastCalledWith('/api/drive/versions/9/preview', {});
	});

	it('maps the possession-proof HEAD response to a boolean', async () => {
		direct.mockResolvedValueOnce({ status: 200 }).mockResolvedValueOnce({ status: 404 });
		await expect(drive.headChunk(3, 'abc')).resolves.toBe(true);
		await expect(drive.headChunk(3, 'abc')).resolves.toBe(false);
		expect(direct).toHaveBeenCalledWith('/api/drive/chunks/abc?space=3', {
			method: 'HEAD',
			allowStatuses: [404],
		});
	});
});
