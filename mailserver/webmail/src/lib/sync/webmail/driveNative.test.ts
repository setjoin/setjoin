// @vitest-environment node
import { describe, expect, it, vi } from 'vitest';
import { DatabaseSync } from 'node:sqlite';
import type { DriveBridge, OfflineDbBridge } from '$lib/native/types';
import { applySchema, SqlMirrorIndex } from '$lib/drive/sync/schema.js';
import { SyncEngine, type DriveHttpLike } from '$lib/drive/sync/engine.js';
import { VaultStore } from '$lib/drive/sync/vaultstore.js';
import type { DbLike, Manifest, MirrorContentStore, NodeMeta, RevocationOutcome } from '$lib/drive/sync/types.js';
import { SyncCoordinator } from '../core/coordinator.js';
import { createDriveMirrorSyncAdapter, createDriveVaultSyncAdapter } from './adapters/driveNative';

vi.mock('$lib/drive/sync/nativeToken.js', () => ({
	getNativeToken: vi.fn().mockResolvedValue('tok-vault'),
}));

const DC_CHUNKS_DDL = `CREATE TABLE IF NOT EXISTS dc_chunks (
	sha256 TEXT NOT NULL PRIMARY KEY, size INTEGER NOT NULL, bytes BLOB NOT NULL,
	pinned_at INTEGER, last_read INTEGER)`;

function createSqliteDb(): { raw: DatabaseSync; dbLike: DbLike; bridge: OfflineDbBridge; wipeSpy: ReturnType<typeof vi.fn> } {
	const raw = new DatabaseSync(':memory:');
	raw.exec(DC_CHUNKS_DDL);
	const wipeSpy = vi.fn(async () => {});
	const dbLike: DbLike = {
		exec: async (sql, params = []) => Number(raw.prepare(sql).run(...(params as never[])).changes),
		query: async (sql, params = []) => raw.prepare(sql).all(...(params as never[])) as never,
	};
	const bridge: OfflineDbBridge = {
		open: async () => {},
		isOpen: async () => true,
		exec: async (_appKey, sql, params = []) => dbLike.exec(sql, params),
		query: async (_appKey, sql, params = []) => dbLike.query(sql, params),
		wipe: wipeSpy,
	};
	return { raw, dbLike, bridge, wipeSpy };
}

class FakeDriveBridge implements DriveBridge {
	deleteCalls: string[][] = [];
	constructor(private db: DatabaseSync) {}
	async importFile(): Promise<never> {
		throw new Error('unused');
	}
	async fetchChunk(_url: string, _bearer: string, sha256: string, size: number): Promise<void> {
		this.db
			.prepare('INSERT OR IGNORE INTO dc_chunks (sha256, size, bytes, last_read) VALUES (?, ?, ?, ?)')
			.run(sha256, size, Buffer.alloc(size), Date.now());
	}
	async pushChunk(): Promise<number> {
		return 201;
	}
	async hasChunk(sha256: string): Promise<boolean> {
		return this.db.prepare('SELECT 1 FROM dc_chunks WHERE sha256 = ?').get(sha256) != null;
	}
	async deleteChunks(sha256s: string[]): Promise<number> {
		this.deleteCalls.push(sha256s);
		let n = 0;
		for (const s of sha256s) n += Number(this.db.prepare('DELETE FROM dc_chunks WHERE sha256 = ?').run(s).changes);
		return n;
	}
	async serveStart(): Promise<{ port: number }> {
		return { port: 0 };
	}
	async serveGrant(): Promise<string> {
		return '/t/x';
	}
	async serveRevoke(): Promise<void> {}
}

describe('Drive native SyncScopeAdapters (#555)', () => {
	it('partial Drive space revoke purges ONLY that space from VaultStore (dc_manifests + unreferenced dc_chunks) without touching sibling space or calling db.wipe', async () => {
		const { raw, bridge, wipeSpy } = createSqliteDb();
		const drive = new FakeDriveBridge(raw);

		const space1Store = new VaultStore(drive, bridge, 1, () => null);
		const space2Store = new VaultStore(drive, bridge, 2, () => null);
		await space1Store.open();
		await space2Store.open();

		const m1Exclusive: Manifest = { contentSha256: 'm1', size: 10, chunks: [{ sha256: 'c-space1-only', size: 10 }] };
		const mShared: Manifest = { contentSha256: 'm-shared', size: 12, chunks: [{ sha256: 'c-shared', size: 12 }] };
		const m2Exclusive: Manifest = { contentSha256: 'm2', size: 14, chunks: [{ sha256: 'c-space2-only', size: 14 }] };

		await space1Store.putLocal(101, m1Exclusive);
		await space1Store.putLocal(102, mShared);
		await space2Store.putLocal(201, mShared);
		await space2Store.putLocal(202, m2Exclusive);

		const coord = new SyncCoordinator();
		coord.register(createDriveVaultSyncAdapter({ spaceId: 1, vaultStore: space1Store }));
		coord.register(createDriveVaultSyncAdapter({ spaceId: 2, vaultStore: space2Store }));

		// Revoke ONLY space 1!
		await coord.handleScopeRevoked({ scopeKind: 'space', scopeId: '1', reason: 'member_removed' });

		// Space 1 manifests & exclusive chunk purged; shared chunk & space 2 untouched; db.wipe NEVER called!
		expect(await space1Store.readLocalManifest(101)).toBeNull();
		expect(await space1Store.readLocalManifest(102)).toBeNull();
		expect(await space1Store.hasChunk('c-space1-only')).toBe(false);
		expect(await space2Store.readLocalManifest(201)).toEqual(mShared);
		expect(await space2Store.readLocalManifest(202)).toEqual(m2Exclusive);
		expect(await space2Store.hasChunk('c-shared')).toBe(true);
		expect(await space2Store.hasChunk('c-space2-only')).toBe(true);
		expect(wipeSpy).not.toHaveBeenCalled();

		coord.dispose();
	});

	it('Drive subtreeAnchorId closes via server-authoritative fullVisibilityReconcile() (ARCH-020)', async () => {
		const { dbLike } = createSqliteDb();
		await applySchema(dbLike);
		const index = new SqlMirrorIndex(dbLike);

		const nodeMeta = (nodeId: number, parentId: number | null, name: string): NodeMeta => ({
			nodeId,
			spaceId: 5,
			parentId,
			kind: parentId === null ? 'folder' : 'file',
			name,
			deletedAt: null,
			headVersionId: 1,
			contentSha256: 'sha',
			sizeBytes: 4,
			contentType: null,
			capabilities: ['read_metadata', 'download'],
		});

		await index.upsertNode(nodeMeta(10, null, 'secret'));
		await index.upsertNode(nodeMeta(11, 10, 'doc.txt'));
		await index.upsertNode(nodeMeta(12, null, 'public.txt'));
		await index.setSyncState(5, { version: 2, contentState: 'c1', accessCursor: 'a1', aclEpoch: 'e1' });

		const revokedNodes: number[] = [];
		const fakeStore = {
			putLocal: async () => {},
			readLocalManifest: async () => null,
			async *localChanges() {},
			hasChunk: async () => false,
			fetchChunk: async () => {},
			pushChunk: async () => {},
			remove: async () => {},
			revoke: async (nodeId: number): Promise<RevocationOutcome> => {
				revokedNodes.push(nodeId);
				return 'purged';
			},
			moveLocal: async () => {},
			renameToSibling: async () => {},
			existsCI: () => false,
			pushMissingChunks: async () => {},
			materializeVersion: async () => {},
			readManifestAtPath: async () => null,
			pushMissingChunksAtPath: async () => {},
			removeAtPath: async () => {},
			revokePath: async (): Promise<RevocationOutcome> => 'absent',
		} satisfies MirrorContentStore;

		const visibilityCalls = vi.fn(async (_spaceId: number, after: string) => ({
			epoch: 'e2',
			rootCapabilities: ['read_metadata'],
			// Server authoritatively retains ONLY node 12; nodes 10 & 11 are gone!
			nodes: after === '0' ? [nodeMeta(12, null, 'public.txt')] : [],
			nextAfter: '12',
			hasMore: false,
		}));

		const http: DriveHttpLike = {
			changes: async () => ({ resync: false, newState: 'c2', changed: [], hasMore: false }),
			accessInvalidations: async () => ({
				cursor: 'a2',
				epoch: 'e2',
				invalidations: [],
				hasMore: false,
				fullReconcile: false,
			}),
			visibilitySnapshot: visibilityCalls,
			nodesMeta: async () => [],
			treeChildren: async () => [],
			headChunk: async () => true,
			putVersion: async () => ({ versionId: 1, headVersionId: 1, conflict: false, branchId: null, wormPending: false }),
			listVersions: async () => [],
			createNode: async () => 1,
			renameNode: async () => {},
			moveNode: async () => {},
			trashNode: async () => {},
			restoreNode: async () => {},
			fileBranches: async () => [],
		};

		const engine = new SyncEngine({
			http,
			index,
			store: fakeStore,
			spaceId: 5,
			deviceLabel: 'test-dev',
			isExcluded: () => false,
			todayYmd: () => '2026-11-26',
			now: () => 1_700_000_000_000,
		});

		const coord = new SyncCoordinator();
		coord.register(createDriveMirrorSyncAdapter({ spaceId: 5, engine }));

		await coord.handleScopeRevoked({ scopeKind: 'space', scopeId: '5', subtreeAnchorId: '10' });

		// Server-authoritative visibilitySnapshot ran and purged BOTH anchor 10 & child 11, retaining 12, then advanced aclEpoch to e2.
		expect(visibilityCalls).toHaveBeenCalled();
		expect(revokedNodes.sort((a, b) => a - b)).toEqual([10, 11]);
		expect(await index.nodeIds(5)).toEqual([12]);
		expect((await index.getSyncState(5)).aclEpoch).toBe('e2');
		// Space stayed attached (not detached) on subtree revocation.
		expect(coord.getAttachedScopes()).toEqual([{ kind: 'space', id: '5' }]);

		coord.dispose();
	});

	it('FolderMirror "busy" revocation persists dc_pending_revocations + revocation-busy issue and purges once handle closes', async () => {
		const { dbLike } = createSqliteDb();
		await applySchema(dbLike);
		const index = new SqlMirrorIndex(dbLike);

		await index.upsertNode({
			nodeId: 88,
			spaceId: 9,
			parentId: null,
			kind: 'file',
			name: 'locked.docx',
			deletedAt: null,
			headVersionId: 1,
			contentSha256: 'sha88',
			sizeBytes: 100,
			contentType: null,
			capabilities: ['read_metadata', 'download'],
		});
		await index.upsertMirror({
			nodeId: 88,
			spaceId: 9,
			relPath: 'locked.docx',
			diskSha256: 'sha88',
			diskSize: 100,
			diskMtimeMs: 1,
			baseVersionId: 1,
			materializedOfVersion: null,
		});

		let handleOpen = true;
		const fakeStore = {
			putLocal: async () => {},
			readLocalManifest: async () => null,
			async *localChanges() {},
			hasChunk: async () => false,
			fetchChunk: async () => {},
			pushChunk: async () => {},
			remove: async () => {},
			revoke: async (): Promise<RevocationOutcome> => (handleOpen ? 'busy' : 'purged'),
			moveLocal: async () => {},
			renameToSibling: async () => {},
			existsCI: () => false,
			pushMissingChunks: async () => {},
			materializeVersion: async () => {},
			readManifestAtPath: async () => null,
			pushMissingChunksAtPath: async () => {},
			removeAtPath: async () => {},
			revokePath: async (): Promise<RevocationOutcome> => 'absent',
		} satisfies MirrorContentStore;

		const http = {} as DriveHttpLike;
		const engine = new SyncEngine({
			http,
			index,
			store: fakeStore,
			spaceId: 9,
			deviceLabel: 'test-dev',
			isExcluded: () => false,
			todayYmd: () => '2026-11-26',
			now: () => 1_700_000_000_000,
		});

		const onPendingBusy = vi.fn();
		const coord = new SyncCoordinator();
		coord.register(createDriveMirrorSyncAdapter({ spaceId: 9, engine, onPendingBusyRevocations: onPendingBusy }));

		// Revoke arrives while file handle is open → 'busy' persists pending marker + revocation-busy issue!
		await coord.handleScopeRevoked({ scopeKind: 'space', scopeId: '9' });
		expect(onPendingBusy).toHaveBeenCalledWith(1);
		expect(await index.listPendingRevocations(9)).toHaveLength(1);
		expect((await index.issues(9)).some((i) => i.code === 'revocation-busy' && i.relPath === 'locked.docx')).toBe(
			true,
		);
		expect(await index.nodeIds(9)).toEqual([88]);

		// Handle closes → detached retry timer drains pending revocation & clears node state (4d)!
		handleOpen = false;
		const drained = await engine.drainPendingRevocations();
		expect(drained).toEqual({ resolved: 1, remaining: 0 });
		expect(await index.listPendingRevocations(9)).toEqual([]);
		expect(await index.nodeIds(9)).toEqual([]);
		expect(await index.rootCapabilities(9)).toEqual([]);
		expect((await index.getSyncState(9)).aclEpoch).toBeNull();

		coord.dispose();
	});

	it('VaultStore open() backfills dc_manifest_spaces from pre-upgrade dc_nodes so purgeSpace evicts legacy manifests (5b)', async () => {
		const { raw, dbLike, bridge } = createSqliteDb();
		await applySchema(dbLike);
		const index = new SqlMirrorIndex(dbLike);
		const drive = new FakeDriveBridge(raw);

		// Simulate pre-upgrade vault with dc_manifests + dc_nodes but NO dc_manifest_spaces table yet.
		raw.exec(`CREATE TABLE dc_manifests (
			node_id INTEGER PRIMARY KEY, manifest_json TEXT NOT NULL,
			pinned INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL)`);
		await index.upsertNode({
			nodeId: 301,
			spaceId: 4,
			parentId: null,
			kind: 'file',
			name: 'legacy.pdf',
			deletedAt: null,
			headVersionId: 1,
			contentSha256: 'sha301',
			sizeBytes: 8,
			contentType: null,
		});
		const legacyManifest: Manifest = { contentSha256: 'sha301', size: 8, chunks: [{ sha256: 'c-legacy', size: 8 }] };
		raw.prepare('INSERT INTO dc_manifests VALUES (?, ?, 0, 0)').run(301, JSON.stringify(legacyManifest));
		raw.prepare('INSERT INTO dc_chunks VALUES (?, ?, ?, NULL, 0)').run('c-legacy', 8, Buffer.alloc(8));

		const store = new VaultStore(drive, bridge, 4, () => null);
		await store.open();
		expect(await store.listSpaceNodeIds(4)).toEqual([301]);

		expect(await store.purgeSpace(4)).toBe(1);
		expect(await store.readLocalManifest(301)).toBeNull();
		expect(await store.hasChunk('c-legacy')).toBe(false);
	});

	it('branch-mirror busy revocation still revokes sibling branches and main file, then retries detached busy branch on timer (4d)', async () => {
		vi.useFakeTimers();
		try {
			const { dbLike } = createSqliteDb();
			await applySchema(dbLike);
			const index = new SqlMirrorIndex(dbLike);

			await index.upsertNode({
				nodeId: 77,
				spaceId: 11,
				parentId: null,
				kind: 'file',
				name: 'spec.docx',
				deletedAt: null,
				headVersionId: 1,
				contentSha256: 'sha77',
				sizeBytes: 50,
				contentType: null,
			});
			await index.upsertMirror({
				nodeId: 77,
				spaceId: 11,
				relPath: 'spec.docx',
				diskSha256: 'sha77',
				diskSize: 50,
				diskMtimeMs: 1,
				baseVersionId: 1,
				materializedOfVersion: null,
			});
			await index.upsertBranchMirror({
				nodeId: 77,
				branchId: 1,
				relPath: 'spec (branch busy).docx',
				diskSha256: 'b1',
				diskSize: 50,
				diskMtimeMs: 1,
				baseVersionId: 2,
			});
			await index.upsertBranchMirror({
				nodeId: 77,
				branchId: 2,
				relPath: 'spec (branch clean).docx',
				diskSha256: 'b2',
				diskSize: 50,
				diskMtimeMs: 1,
				baseVersionId: 3,
			});

			let busyOpen = true;
			const revokedMain: number[] = [];
			const revokedPaths: string[] = [];
			const fakeStore = {
				putLocal: async () => {},
				readLocalManifest: async () => null,
				async *localChanges() {},
				hasChunk: async () => false,
				fetchChunk: async () => {},
				pushChunk: async () => {},
				remove: async () => {},
				revoke: async (nodeId: number): Promise<RevocationOutcome> => {
					revokedMain.push(nodeId);
					return 'purged';
				},
				moveLocal: async () => {},
				renameToSibling: async () => {},
				existsCI: () => false,
				pushMissingChunks: async () => {},
				materializeVersion: async () => {},
				readManifestAtPath: async () => null,
				pushMissingChunksAtPath: async () => {},
				removeAtPath: async () => {},
				revokePath: async (relPath: string): Promise<RevocationOutcome> => {
					revokedPaths.push(relPath);
					if (relPath === 'spec (branch busy).docx' && busyOpen) return 'busy';
					return 'purged';
				},
			} satisfies MirrorContentStore;

			const engine = new SyncEngine({
				http: {} as DriveHttpLike,
				index,
				store: fakeStore,
				spaceId: 11,
				deviceLabel: 'test-dev',
				isExcluded: () => false,
				todayYmd: () => '2026-11-26',
				now: () => 1_700_000_000_000,
			});

			const coord = new SyncCoordinator();
			coord.register(createDriveMirrorSyncAdapter({ spaceId: 11, engine, busyRetryMs: 100 }));

			await coord.handleScopeRevoked({ scopeKind: 'space', scopeId: '11' });
			// Both clean branch AND main file were revoked despite busy branch 1!
			expect(revokedPaths).toContain('spec (branch clean).docx');
			expect(revokedMain).toContain(77);
			expect(await index.listPendingRevocations(11)).toEqual([
				expect.objectContaining({ nodeId: 77, relPath: 'spec (branch busy).docx' }),
			]);

			// Handle closes → detached retry timer automatically drains the busy branch!
			busyOpen = false;
			await vi.advanceTimersByTimeAsync(120);
			expect(await index.listPendingRevocations(11)).toEqual([]);
			expect(await index.nodeIds(11)).toEqual([]);
			coord.dispose();
		} finally {
			vi.useRealTimers();
		}
	});
});
