// @vitest-environment node
import { describe, it, expect } from 'vitest';
import { memDb } from './schema.test.js';
import { applySchema, SqlMirrorIndex } from './schema.js';
import { SyncEngine, type ChangesResult, type DriveHttpLike, type EngineDeps } from './engine.js';
import { DriveApiError, type PutVersionBody, type PutVersionResult, type VersionMeta } from './protocol.js';
import type {
	AccessInvalidationPage,
	BranchMeta,
	ChunkRef,
	DownloadPlan,
	Manifest,
	MirrorContentStore,
	NodeMeta,
	VisibilityPage,
} from './types.js';

const ANCHOR = '__anchor__';

class FakeHttp implements DriveHttpLike {
	changesBySince = new Map<string, ChangesResult>();
	nodesMetaMap = new Map<number, NodeMeta>();
	treeByParent = new Map<number | null, NodeMeta[]>();
	putVersionResult: PutVersionResult = { versionId: 1, conflict: false, branchId: null, headVersionId: 1, wormPending: false };
	putVersionCalls: { nodeId: number; body: PutVersionBody }[] = [];
	presentChunks = new Set<string>();
	createNodeCalls: { spaceId: number; parentId: number | null; name: string }[] = [];
	nextCreatedId = 100;
	versionsByNode = new Map<number, VersionMeta[]>();
	renameNodeCalls: { nodeId: number; newName: string }[] = [];
	moveNodeCalls: { nodeId: number; newParentId: number | null }[] = [];
	trashNodeCalls: number[] = [];
	trashThrows: DriveApiError | null = null;
	putVersionThrows: DriveApiError | null = null;
	branchesByNode = new Map<number, BranchMeta[]>();
	fileBranchesCalls: number[] = [];
	accessPage: AccessInvalidationPage = {
		cursor: null,epoch: '0',invalidations: [],hasMore: false,fullReconcile: false,
	};
	accessCalls: Array<{ spaceId: number; cursor: string | null }> = [];
	visibilityCalls: Array<{ spaceId: number; after: string; expectedEpoch: string | null }> = [];
	accessHandler?: (spaceId: number, cursor: string | null) => Promise<AccessInvalidationPage>;
	visibilityHandler?: (spaceId: number, after: string, expectedEpoch: string | null) => Promise<VisibilityPage>;

	async changes(_spaceId: number, since: string | null): Promise<ChangesResult> {
		const got = this.changesBySince.get(since ?? ANCHOR);
		if (!got) throw new Error(`FakeHttp.changes: no scripted response for since=${since ?? ANCHOR}`);
		return got;
	}
	async accessInvalidations(spaceId: number, cursor: string | null): Promise<AccessInvalidationPage> {
		this.accessCalls.push({ spaceId, cursor });
		return this.accessHandler ? this.accessHandler(spaceId, cursor) : this.accessPage;
	}
	async visibilitySnapshot(spaceId: number, after: string, expectedEpoch: string | null): Promise<VisibilityPage> {
		this.visibilityCalls.push({ spaceId, after, expectedEpoch });
		if (this.visibilityHandler) return this.visibilityHandler(spaceId, after, expectedEpoch);
		const all: NodeMeta[]=[];
		const queue: (number|null)[]=[null];
		while (queue.length) {
			const parent=queue.shift() as number|null;
			for (const n of this.treeByParent.get(parent) ?? []) {
				const meta=this.nodesMetaMap.get(n.nodeId) ?? n;
				all.push({...meta,capabilities:meta.capabilities ?? ['read_metadata']});
				if (n.kind==='folder') queue.push(n.nodeId);
			}
		}
		const rows=all.filter((n)=>n.nodeId>Number(after)).sort((a,b)=>a.nodeId-b.nodeId).slice(0,500);
		return {
			epoch: expectedEpoch ?? this.accessPage.epoch ?? '0',rootCapabilities:['create_child'],nodes:rows,
			nextAfter:String(rows.at(-1)?.nodeId ?? Number(after)),hasMore:false,
		};
	}
	async nodesMeta(ids: number[]): Promise<NodeMeta[]> {
		return ids.map((id) => this.nodesMetaMap.get(id)).filter((m): m is NodeMeta => !!m);
	}
	async treeChildren(_spaceId: number, parentId: number | null): Promise<NodeMeta[]> {
		return this.treeByParent.get(parentId) ?? [];
	}
	async headChunk(_spaceId: number, sha256: string): Promise<boolean> {
		return this.presentChunks.has(sha256);
	}
	async putVersion(nodeId: number, body: PutVersionBody): Promise<PutVersionResult> {
		this.putVersionCalls.push({ nodeId, body });
		if (this.putVersionThrows) throw this.putVersionThrows;
		return this.putVersionResult;
	}
	async listVersions(nodeId: number): Promise<VersionMeta[]> {
		return this.versionsByNode.get(nodeId) ?? [];
	}
	async createNode(spaceId: number, parentId: number | null, _kind: 'file' | 'folder', name: string): Promise<number> {
		this.createNodeCalls.push({ spaceId, parentId, name });
		return this.nextCreatedId++;
	}
	async renameNode(nodeId: number, newName: string): Promise<void> {
		this.renameNodeCalls.push({ nodeId, newName });
	}
	async moveNode(nodeId: number, newParentId: number | null): Promise<void> {
		this.moveNodeCalls.push({ nodeId, newParentId });
	}
	async trashNode(nodeId: number): Promise<void> {
		this.trashNodeCalls.push(nodeId);
		if (this.trashThrows) throw this.trashThrows;
	}
	async restoreNode(_nodeId: number): Promise<void> {}
	async fileBranches(nodeId: number): Promise<BranchMeta[]> {
		this.fileBranchesCalls.push(nodeId);
		return this.branchesByNode.get(nodeId) ?? [];
	}
}

class MemContentStore implements MirrorContentStore {
	manifests = new Map<number, Manifest>();
	putLocalCalls: { nodeId: number; plan: Manifest | DownloadPlan }[] = [];
	putLocalThrowsOnce = false;
	removedNodes: number[] = [];
	movedCalls: { nodeId: number; oldRel: string; newRel: string }[] = [];
	renamedToSibling: { nodeId: number; siblingName: string }[] = [];
	materializedVersions: { versionId: number; relPath: string; sha: string; size: number }[] = [];
	pushedChunks: { nodeId: number; chunks: ChunkRef[] }[] = [];
	existingPathsCI = new Set<string>();
	// P4 Task 17: branch siblings are addressed by relPath, not nodeId.
	manifestsByPath = new Map<string, Manifest>();
	// med-shard3-020 r2: paths whose hash READ fails (unreadable/locked file —
	// distinct from "vanished", which maps to null like the real store does).
	readAtPathThrows = new Set<string>();
	pushedChunksAtPath: { relPath: string; chunks: ChunkRef[] }[] = [];
	removedPaths: string[] = [];
	revokeOutcome: 'purged' | 'quarantined' | 'busy' | 'absent' = 'purged';
	revokeCalls: Array<{ nodeId: number; forceQuarantine: boolean }> = [];

	async putLocal(nodeId: number, plan: Manifest | DownloadPlan): Promise<void> {
		if (this.putLocalThrowsOnce) {
			this.putLocalThrowsOnce = false;
			throw new Error('simulated crash mid-apply');
		}
		this.putLocalCalls.push({ nodeId, plan });
		this.manifests.set(nodeId, 'chunks' in plan
			? plan
			: { contentSha256: plan.contentSha256, size: plan.size, chunks: [] });
	}
	async readLocalManifest(nodeId: number): Promise<Manifest | null> {
		return this.manifests.get(nodeId) ?? null;
	}
	async *localChanges(): AsyncIterable<never> {}
	async hasChunk(): Promise<boolean> {
		return false;
	}
	async fetchChunk(): Promise<void> {}
	async pushChunk(): Promise<void> {}
	async remove(nodeId: number): Promise<void> {
		this.removedNodes.push(nodeId);
	}
	async revoke(nodeId: number, forceQuarantine: boolean): Promise<'purged' | 'quarantined' | 'busy' | 'absent'> {
		this.revokeCalls.push({ nodeId, forceQuarantine });
		if (this.revokeOutcome !== 'busy') {
			this.removedNodes.push(nodeId);
			this.manifests.delete(nodeId);
		}
		return this.revokeOutcome;
	}
	async moveLocal(nodeId: number, oldRelPath: string, newRelPath: string): Promise<void> {
		this.movedCalls.push({ nodeId, oldRel: oldRelPath, newRel: newRelPath });
	}
	async renameToSibling(nodeId: number, siblingName: string): Promise<void> {
		this.renamedToSibling.push({ nodeId, siblingName });
	}
	existsCI(relPath: string): boolean {
		return this.existingPathsCI.has(relPath.toLowerCase());
	}
	async pushMissingChunks(nodeId: number, chunks: ChunkRef[]): Promise<void> {
		this.pushedChunks.push({ nodeId, chunks });
	}
	async readManifestAtPath(relPath: string): Promise<Manifest | null> {
		if (this.readAtPathThrows.has(relPath)) throw new Error('EIO: disk hash read failed');
		return this.manifestsByPath.get(relPath) ?? null;
	}
	async pushMissingChunksAtPath(relPath: string, chunks: ChunkRef[]): Promise<void> {
		this.pushedChunksAtPath.push({ relPath, chunks });
	}
	async removeAtPath(relPath: string): Promise<void> {
		this.removedPaths.push(relPath);
	}
	async revokePath(relPath: string): Promise<'purged'> { this.removedPaths.push(relPath); return 'purged'; }
	async materializeVersion(versionId: number, relPath: string, sha256: string, size: number): Promise<void> {
		this.materializedVersions.push({ versionId, relPath, sha: sha256, size });
	}
}

async function makeHarness(
	overrides: Partial<Pick<EngineDeps, 'deviceLabel' | 'todayYmd' | 'isExcluded'>> = {},
	storeOverride?: MemContentStore,
) {
	const db = memDb();
	await applySchema(db);
	const index = new SqlMirrorIndex(db);
	await index.setRootCapabilities(1,['create_child']);
	const http = new FakeHttp();
	const store = storeOverride ?? new MemContentStore();
	let clock = 1_000_000;
	const engine = new SyncEngine({
		http,
		index,
		store,
		spaceId: 1,
		deviceLabel: overrides.deviceLabel ?? 'bobs-laptop',
		isExcluded: overrides.isExcluded ?? (() => false),
		todayYmd: overrides.todayYmd ?? (() => '2026-07-09'),
		now: () => clock,
	});
	return { engine, http, store, index, advanceClock: (ms: number) => (clock += ms) };
}

function meta(overrides: Partial<NodeMeta> = {}): NodeMeta {
	return {
		nodeId: 1,
		spaceId: 1,
		parentId: null,
		kind: 'file',
		name: 'a.txt',
		deletedAt: null,
		headVersionId: 5,
		contentSha256: 'sha-head',
		sizeBytes: 10,
		contentType: null,
		...overrides,
	};
}

describe('SyncEngine — local upsert -> chunk dedup -> putVersion', () => {
	it('bootstraps the ACL snapshot before accepting the first watcher event', async () => {
		const { engine, http, index } = await makeHarness();
		http.accessPage = { cursor: 'acl-1', epoch: '1', invalidations: [], hasMore: false, fullReconcile: false };
		http.changesBySince.set(ANCHOR, { resync: false, newState: '0', changed: [], hasMore: false });

		await engine.onLocalChange({ kind: 'upsert', relPath: 'first.txt' });

		expect(http.accessCalls).toEqual([{ spaceId: 1, cursor: null }]);
		expect(http.createNodeCalls).toEqual([{ spaceId: 1, parentId: null, name: 'first.txt' }]);
		expect((await index.getSyncState(1)).aclEpoch).toBe('1');
	});

	it('a brand-new local file: onLocalChange creates the node, then drainOutbound uploads with baseVersionId null', async () => {
		const { engine, http, store, index } = await makeHarness();
		await index.setCursor(1, '0'); // pretend already-anchored, so syncOnce only drains outbound this test
		await engine.onLocalChange({ kind: 'upsert', relPath: 'a.txt' });
		expect(http.createNodeCalls).toEqual([{ spaceId: 1, parentId: null, name: 'a.txt' }]);
		const nodeId = http.nextCreatedId - 1;

		store.manifests.set(nodeId, { contentSha256: 'sha1', size: 5, chunks: [{ sha256: 'c1', size: 5 }] });
		http.changesBySince.set('0', { resync: false, newState: '0', changed: [], hasMore: false });

		const result = await engine.syncOnce();
		expect(result.uploaded).toBe(1);
		expect(http.putVersionCalls).toHaveLength(1);
		expect(http.putVersionCalls[0].body.baseVersionId).toBeNull();
		expect(store.pushedChunks).toEqual([{ nodeId, chunks: [{ sha256: 'c1', size: 5 }] }]); // chunk was missing -> pushed
		const mirror = await index.getMirror(nodeId);
		expect(mirror?.baseVersionId).toBe(http.putVersionResult.versionId);
		expect(mirror?.diskSha256).toBe('sha1');
	});

	it('an existing file uploads with baseVersionId = the index base, and skips a chunk the server already has', async () => {
		const { engine, http, store, index } = await makeHarness();
		await index.setCursor(1, '0');
		http.changesBySince.set('0', { resync: false, newState: '0', changed: [], hasMore: false });
		await index.upsertMirror({
			nodeId: 7,
			spaceId: 1,
			relPath: 'b.txt',
			diskSha256: 'old',
			diskSize: 4,
			diskMtimeMs: 1,
			baseVersionId: 42,
			materializedOfVersion: null,
		});
		await index.enqueue(1, 'upsert', { nodeId: 7 });
		store.manifests.set(7, { contentSha256: 'new', size: 5, chunks: [{ sha256: 'c-have', size: 5 }] });
		http.presentChunks.add('c-have');

		await engine.syncOnce();
		expect(http.putVersionCalls[0].body.baseVersionId).toBe(42);
		expect(store.pushedChunks).toEqual([]); // already present server-side — no push
	});
});

describe('SyncEngine — ACL visibility and revocation', () => {
	async function seedRevokedFile() {
		const harness = await makeHarness();
		const { index, store } = harness;
		await index.setSyncState(1, { version: 2, contentState: '5', accessCursor: 'acl-old', aclEpoch: '1' });
		await index.upsertNode(meta({ nodeId: 7, name: 'private.txt', capabilities: ['read_metadata', 'download'] }));
		await index.upsertMirror({
			nodeId: 7,
			spaceId: 1,
			relPath: 'private.txt',
			diskSha256: 'old',
			diskSize: 3,
			diskMtimeMs: 1,
			baseVersionId: 5,
			materializedOfVersion: null,
		});
		store.manifests.set(7, { contentSha256: 'local-edit', size: 4, chunks: [{ sha256: 'chunk', size: 4 }] });
		await index.enqueue(1, 'upsert', { nodeId: 7 });
		return harness;
	}

	it('quarantines a brand-new local create when the visible root has no create_child capability', async () => {
		const { engine, http, store, index } = await makeHarness();
		await index.setSyncState(1, { version: 2, contentState: '0', accessCursor: 'acl-1', aclEpoch: '1' });
		await index.setRootCapabilities(1, []);

		await engine.onLocalChange({ kind: 'upsert', relPath: 'denied.txt' });

		expect(http.createNodeCalls).toEqual([]);
		expect(store.removedPaths).toEqual(['denied.txt']);
		expect(await index.due(Number.MAX_SAFE_INTEGER, 10)).toEqual([]);
		expect((await index.issues(1)).map((issue) => issue.code)).toContain('traverse-only');
	});

	it('quarantines an existing local edit without modify_content and restores the authoritative bytes', async () => {
		const { engine, http, store, index } = await makeHarness();
		await index.setSyncState(1, { version: 2, contentState: '4', accessCursor: 'acl-1', aclEpoch: '1' });
		const remote = meta({
			nodeId: 7, name: 'readonly.txt', contentSha256: 'server-sha', sizeBytes: 10,
			headVersionId: 5, capabilities: ['traverse', 'read_metadata', 'download'],
		});
		await index.upsertNode(remote);
		await index.upsertMirror({
			nodeId: 7, spaceId: 1, relPath: 'readonly.txt', diskSha256: 'server-sha',
			diskSize: 10, diskMtimeMs: 1, baseVersionId: 5, materializedOfVersion: null,
		});
		store.manifests.set(7, { contentSha256: 'local-edit', size: 11, chunks: [] });
		http.nodesMetaMap.set(7, remote);
		http.versionsByNode.set(7, []);

		await engine.onLocalChange({ kind: 'upsert', relPath: 'readonly.txt' });

		expect(store.revokeCalls).toEqual([{ nodeId: 7, forceQuarantine: true }]);
		expect(store.putLocalCalls.at(-1)).toMatchObject({ nodeId: 7, plan: { contentSha256: 'server-sha' } });
		expect(http.putVersionCalls).toEqual([]);
		expect(await index.due(Number.MAX_SAFE_INTEGER, 10)).toEqual([]);
		expect((await index.issues(1)).map((issue) => issue.code)).toContain('permission-denied');
	});

	it('quarantines pending outbound work and advances all cursors only after revoke persists', async () => {
		const { engine, http, store, index } = await seedRevokedFile();
		store.revokeOutcome = 'quarantined';
		http.accessPage = {
			cursor: 'acl-new', epoch: '2', hasMore: false, fullReconcile: false,
			invalidations: [{ anchorNodeId: '7', epoch: '2', reason: 'revoke', fullReconcile: false }],
		};
		http.visibilityHandler = async () => ({ epoch: '2', rootCapabilities: [], nodes: [], nextAfter: '0', hasMore: false });
		http.changesBySince.set(ANCHOR, { resync: false, newState: '6', changed: [], hasMore: false });
		http.changesBySince.set('6', { resync: false, newState: '6', changed: [], hasMore: false });

		const result = await engine.syncOnce();

		expect(result).toMatchObject({ uploaded: 0, issues: 1 });
		expect(http.putVersionCalls).toEqual([]);
		expect(store.revokeCalls).toEqual([{ nodeId: 7, forceQuarantine: true }]);
		expect(await index.getNode(7)).toBeNull();
		expect(await index.due(Number.MAX_SAFE_INTEGER, 10)).toEqual([]);
		expect(await index.getSyncState(1)).toEqual({
			version: 2, contentState: '6', accessCursor: 'acl-new', aclEpoch: '2',
		});
	});

	it('does not advance the access cursor when a revoked local file is busy', async () => {
		const { engine, http, store, index } = await seedRevokedFile();
		store.revokeOutcome = 'busy';
		http.accessPage = {
			cursor: 'acl-new', epoch: '2', hasMore: false, fullReconcile: false,
			invalidations: [{ anchorNodeId: '7', epoch: '2', reason: 'revoke', fullReconcile: false }],
		};
		http.visibilityHandler = async () => ({ epoch: '2', rootCapabilities: [], nodes: [], nextAfter: '0', hasMore: false });
		http.changesBySince.set(ANCHOR, { resync: false, newState: '6', changed: [], hasMore: false });

		await expect(engine.syncOnce()).rejects.toThrow('busy revoked file');
		expect(await index.getSyncState(1)).toEqual({
			version: 2, contentState: '5', accessCursor: 'acl-old', aclEpoch: '1',
		});
		expect(await index.getNode(7)).not.toBeNull();
		expect(await index.due(Number.MAX_SAFE_INTEGER, 10)).toHaveLength(1);
	});

	it('purges the whole local space when both content and visibility return 404 after terminal revocation', async () => {
		const { engine, http, store, index } = await seedRevokedFile();
		store.revokeOutcome = 'purged';
		http.accessPage = {
			cursor: null, epoch: null, invalidations: [], hasMore: false,
			fullReconcile: true, reason: 'accessRevoked',
		};
		let changeCalls = 0;
		http.changes = async () => {
			if (changeCalls++ === 0) throw new DriveApiError(404, 'about:blank', 'BZ139');
			return { resync: false, newState: '5', changed: [], hasMore: false };
		};
		http.visibilityHandler = async () => {
			throw new DriveApiError(404, 'about:blank', 'BZ139');
		};

		await engine.syncOnce();

		expect(store.revokeCalls).toEqual([{ nodeId: 7, forceQuarantine: true }]);
		expect(await index.getNode(7)).toBeNull();
		expect(await index.getSyncState(1)).toEqual({
			version: 2, contentState: '5', accessCursor: null, aclEpoch: null,
		});
	});

	it('discards an epoch-conflicted snapshot and retries from a fresh access cursor', async () => {
		const { engine, http, index } = await makeHarness();
		await index.setSyncState(1, { version: 2, contentState: '8', accessCursor: 'acl-0', aclEpoch: '0' });
		let accessCall = 0;
		http.accessHandler = async () => accessCall++ === 0
			? { cursor: 'acl-1', epoch: '1', invalidations: [{ anchorNodeId: null, epoch: '1', reason: 'grant', fullReconcile: true }], hasMore: false, fullReconcile: false }
			: { cursor: 'acl-2', epoch: '2', invalidations: [], hasMore: false, fullReconcile: false };
		let conflict = true;
		http.visibilityHandler = async () => {
			if (conflict) {
				conflict = false;
				throw new DriveApiError(409, 'https://setjoin.com/errors/drive-acl-conflict', 'BZ254');
			}
			return { epoch: '2', rootCapabilities: [], nodes: [], nextAfter: '0', hasMore: false };
		};
		http.changesBySince.set(ANCHOR, { resync: false, newState: '9', changed: [], hasMore: false });
		http.changesBySince.set('9', { resync: false, newState: '9', changed: [], hasMore: false });

		await engine.syncOnce();

		expect(http.accessCalls).toEqual([
			{ spaceId: 1, cursor: 'acl-0' },
			{ spaceId: 1, cursor: 'acl-1' },
		]);
		expect((await index.getSyncState(1))).toEqual({
			version: 2, contentState: '9', accessCursor: 'acl-2', aclEpoch: '2',
		});
	});

	it('applies an id-paged snapshot in parent dependency order after a move', async () => {
		const { engine, http, index } = await makeHarness();
		http.accessPage = { cursor: 'acl-1', epoch: '1', invalidations: [], hasMore: false, fullReconcile: false };
		http.visibilityHandler = async (_space, after) => after === '0'
			? {
				epoch: '1', rootCapabilities: [], nextAfter: '2', hasMore: false,
				nodes: [
					meta({ nodeId: 1, parentId: 2, name: 'child.txt', capabilities: ['read_metadata'], contentSha256: 'child-sha' }),
					meta({ nodeId: 2, kind: 'folder', parentId: null, name: 'new-parent', headVersionId: null, contentSha256: null, sizeBytes: null, capabilities: ['read_metadata'] }),
				],
			}
			: { epoch: '1', rootCapabilities: [], nodes: [], nextAfter: after, hasMore: false };
		http.changesBySince.set(ANCHOR, { resync: false, newState: '3', changed: [], hasMore: false });
		http.changesBySince.set('3', { resync: false, newState: '3', changed: [], hasMore: false });

		await engine.syncOnce();

		expect((await index.getMirror(1))?.relPath).toBe('new-parent/child.txt');
	});
});

describe('SyncEngine — remote update applies via putLocal', () => {
	it('downloads new content and updates the mirror row', async () => {
		const { engine, http, store, index } = await makeHarness();
		await index.setCursor(1, '10');
		http.changesBySince.set('10', {
			resync: false,
			newState: '11',
			changed: [{ nodeId: 1, op: 'update', seq: 11 }],
			hasMore: false,
		});
		http.nodesMetaMap.set(1, meta({ contentSha256: 'newsha', sizeBytes: 10, headVersionId: 5 }));
		http.versionsByNode.set(1, []); // no conflicts to check on the download branch either

		const res = await engine.syncOnce();
		expect(res.downloaded).toBe(1);
		expect(store.putLocalCalls).toEqual([
			{ nodeId: 1, plan: { contentSha256: 'newsha', size: 10, headVersionId: 5 } },
		]);
		expect(await index.getCursor(1)).toBe('11');
		const mirror = await index.getMirror(1);
		expect(mirror?.diskSha256).toBe('newsha');
		expect(mirror?.baseVersionId).toBe(5);
	});

	// Regression (found via the P2 Task 13 convergence suite): a file this
	// device already synced once, then never touched again, must still
	// receive a LATER remote update. The original code compared the mirror's
	// last-synced sha directly against the remote's NEW sha (the same
	// comparison the echo-suppression branch above already makes) and
	// treated any difference as "locally dirty" — which silently dropped
	// every subsequent remote update to an already-synced, untouched file.
	it('an already-synced file with a NEWER remote head still downloads when the local disk is untouched', async () => {
		const { engine, http, store, index } = await makeHarness();
		await index.upsertMirror({
			nodeId: 1,
			spaceId: 1,
			relPath: 'a.txt',
			diskSha256: 'oldsha',
			diskSize: 8,
			diskMtimeMs: 1,
			baseVersionId: 4,
			materializedOfVersion: null,
		});
		// The store's fresh re-hash of the disk file still matches what we
		// last synced — i.e. genuinely untouched locally.
		store.manifests.set(1, { contentSha256: 'oldsha', size: 8, chunks: [{ sha256: 'oldsha', size: 8 }] });
		await index.setCursor(1, '10');
		http.changesBySince.set('10', {
			resync: false,
			newState: '11',
			changed: [{ nodeId: 1, op: 'update', seq: 11 }],
			hasMore: false,
		});
		http.nodesMetaMap.set(1, meta({ contentSha256: 'newsha', sizeBytes: 10, headVersionId: 9 }));
		http.versionsByNode.set(1, []);

		const res = await engine.syncOnce();
		expect(res.downloaded).toBe(1);
		expect(store.putLocalCalls).toEqual([{ nodeId: 1, plan: { contentSha256: 'newsha', size: 10, headVersionId: 9 } }]);
		expect((await index.getMirror(1))?.diskSha256).toBe('newsha');
	});

	it('a GENUINELY dirty local file (fresh re-hash differs from last-synced sha) is never clobbered by a remote update', async () => {
		const { engine, http, store, index } = await makeHarness();
		await index.upsertMirror({
			nodeId: 1,
			spaceId: 1,
			relPath: 'a.txt',
			diskSha256: 'oldsha',
			diskSize: 8,
			diskMtimeMs: 1,
			baseVersionId: 4,
			materializedOfVersion: null,
		});
		// The store's fresh re-hash reveals an ACTUAL local edit since last sync.
		store.manifests.set(1, { contentSha256: 'locally-edited-sha', size: 9, chunks: [{ sha256: 'x', size: 9 }] });
		await index.setCursor(1, '10');
		http.changesBySince.set('10', {
			resync: false,
			newState: '11',
			changed: [{ nodeId: 1, op: 'update', seq: 11 }],
			hasMore: false,
		});
		http.nodesMetaMap.set(1, meta({ contentSha256: 'newsha', sizeBytes: 10, headVersionId: 9 }));
		http.versionsByNode.set(1, []);

		const res = await engine.syncOnce();
		expect(res.downloaded).toBe(0);
		expect(store.putLocalCalls).toEqual([]);
		expect((await index.getMirror(1))?.diskSha256).toBe('oldsha'); // untouched by the engine
	});
});

describe('SyncEngine — echo suppression', () => {
	it('an update whose head sha matches our own last-synced sha is not re-downloaded', async () => {
		const { engine, http, store, index } = await makeHarness();
		await index.upsertMirror({
			nodeId: 1,
			spaceId: 1,
			relPath: 'a.txt',
			diskSha256: 'samesha',
			diskSize: 10,
			diskMtimeMs: 1,
			baseVersionId: 4,
			materializedOfVersion: null,
		});
		store.manifests.set(1, { contentSha256: 'samesha', size: 10, chunks: [] });
		await index.setCursor(1, '10');
		http.changesBySince.set('10', {
			resync: false,
			newState: '11',
			changed: [{ nodeId: 1, op: 'update', seq: 11 }],
			hasMore: false,
		});
		http.nodesMetaMap.set(1, meta({ contentSha256: 'samesha', headVersionId: 9 }));
		http.versionsByNode.set(1, []);

		await engine.syncOnce();
		expect(store.putLocalCalls).toEqual([]);
		expect((await index.getMirror(1))?.baseVersionId).toBe(9);
	});

	it('C2: an unchanged-head update materializes a not-yet-known conflict sibling via listVersions', async () => {
		const { engine, http, store, index } = await makeHarness();
		await index.upsertMirror({
			nodeId: 1,
			spaceId: 1,
			relPath: 'plan.md',
			diskSha256: 'samesha',
			diskSize: 10,
			diskMtimeMs: 1,
			baseVersionId: 9,
			materializedOfVersion: null,
		});
		store.manifests.set(1, { contentSha256: 'samesha', size: 10, chunks: [] });
		await index.setCursor(1, '10');
		http.changesBySince.set('10', {
			resync: false,
			newState: '11',
			changed: [{ nodeId: 1, op: 'update', seq: 11 }],
			hasMore: false,
		});
		http.nodesMetaMap.set(1, meta({ nodeId: 1, name: 'plan.md', contentSha256: 'samesha', headVersionId: 9 }));
		http.versionsByNode.set(1, [
			{ id: 9, conflictOf: null, sha256: 'samesha', size: 10, deviceLabel: 'bobs-laptop', createdAt: '2026-07-09T00:00:00Z' },
			{ id: 8, conflictOf: 9, sha256: 'oldsha', size: 8, deviceLabel: 'anns-desktop', createdAt: '2026-07-08T00:00:00Z' },
		]);

		await engine.syncOnce();
		expect(store.materializedVersions).toEqual([
			{ versionId: 8, relPath: 'plan (conflict anns-desktop 2026-07-08).md', sha: 'oldsha', size: 8 },
		]);
		expect(await index.isVersionMaterialized(8)).toBe(true);

		// Running again must NOT re-materialize the same version.
		await index.setCursor(1, '10');
		http.changesBySince.set('10', {
			resync: false,
			newState: '11',
			changed: [{ nodeId: 1, op: 'update', seq: 11 }],
			hasMore: false,
		});
		await engine.syncOnce();
		expect(store.materializedVersions).toHaveLength(1);
	});
});

describe('SyncEngine — conflict on upload materializes a G4 sibling', () => {
	it('renames our dirty bytes to the sibling and re-downloads the real head', async () => {
		const { engine, http, store, index } = await makeHarness();
		await index.upsertMirror({
			nodeId: 1,
			spaceId: 1,
			relPath: 'plan.md',
			diskSha256: 'localedit',
			diskSize: 5,
			diskMtimeMs: 1,
			baseVersionId: 3,
			materializedOfVersion: null,
		});
		await index.enqueue(1, 'upsert', { nodeId: 1 });
		await index.setCursor(1, '0');
		http.changesBySince.set('0', { resync: false, newState: '0', changed: [], hasMore: false });
		store.manifests.set(1, { contentSha256: 'localedit', size: 5, chunks: [{ sha256: 'c1', size: 5 }] });
		http.presentChunks.add('c1');
		http.putVersionResult = { versionId: 50, conflict: true, branchId: null, headVersionId: 60, wormPending: false };
		http.nodesMetaMap.set(1, meta({ nodeId: 1, contentSha256: 'headsha', sizeBytes: 8, headVersionId: 60 }));

		await engine.syncOnce();
		expect(store.renamedToSibling).toEqual([{ nodeId: 1, siblingName: 'plan (conflict bobs-laptop 2026-07-09).md' }]);
		expect(await index.isVersionMaterialized(50)).toBe(true);
		expect(store.putLocalCalls).toEqual([{ nodeId: 1, plan: { contentSha256: 'headsha', size: 8, headVersionId: 60 } }]);
		const mirror = await index.getMirror(1);
		expect(mirror?.diskSha256).toBe('headsha');
		expect(mirror?.baseVersionId).toBe(60);
	});
});

describe('SyncEngine — remote trash/destroy vs. a local dirty edit', () => {
	it('removes a clean node', async () => {
		const { engine, http, store, index } = await makeHarness();
		await index.upsertMirror({
			nodeId: 1,
			spaceId: 1,
			relPath: 'gone.txt',
			diskSha256: 'sha',
			diskSize: 1,
			diskMtimeMs: 1,
			baseVersionId: 1,
			materializedOfVersion: null,
		});
		await index.setCursor(1, '10');
		http.changesBySince.set('10', {
			resync: false,
			newState: '11',
			changed: [{ nodeId: 1, op: 'trash', seq: 11 }],
			hasMore: false,
		});
		// nodesMeta silent-absent (trashed+later destroyed) OR deletedAt set — use deletedAt here.
		http.nodesMetaMap.set(1, meta({ nodeId: 1, deletedAt: '2026-07-09T00:00:00Z' }));

		const res = await engine.syncOnce();
		expect(res.issues).toBe(0);
		expect(store.removedNodes).toEqual([1]);
		expect(await index.getMirror(1)).toBeNull();
	});

	it('§4.4 edit wins: a node with a pending local upsert is NOT removed, and an issue is recorded', async () => {
		const { engine, http, store, index } = await makeHarness();
		await index.upsertMirror({
			nodeId: 1,
			spaceId: 1,
			relPath: 'edited.txt',
			diskSha256: 'sha',
			diskSize: 1,
			diskMtimeMs: 1,
			baseVersionId: 1,
			materializedOfVersion: null,
		});
		await index.enqueue(1, 'upsert', { nodeId: 1 }); // this device has a queued, not-yet-uploaded edit
		// The upload attempt itself fails transiently (5xx) in this same pass —
		// bumped (backed off), not acked, so it is still pending when the
		// download leg's hasPendingUpsert check runs right after.
		store.manifests.set(1, { contentSha256: 'sha', size: 1, chunks: [{ sha256: 'c1', size: 1 }] });
		http.presentChunks.add('c1');
		http.putVersionThrows = new DriveApiError(503, 'about:blank');
		await index.setCursor(1, '10');
		http.changesBySince.set('10', {
			resync: false,
			newState: '11',
			changed: [{ nodeId: 1, op: 'trash', seq: 11 }],
			hasMore: false,
		});
		http.nodesMetaMap.set(1, meta({ nodeId: 1, deletedAt: '2026-07-09T00:00:00Z' }));

		const res = await engine.syncOnce();
		expect(res.issues).toBe(1);
		expect(store.removedNodes).toEqual([]);
		expect(await index.getMirror(1)).not.toBeNull();
		expect((await index.issues(1))[0]).toMatchObject({ code: 'unsynced-local-edit' });
	});
});

describe('SyncEngine — remote rename/move applies via moveLocal', () => {
	it('moves the local file when the server-reported relPath differs from the mirror row', async () => {
		const { engine, http, store, index } = await makeHarness();
		await index.upsertNode({
			nodeId: 2,
			spaceId: 1,
			parentId: null,
			kind: 'folder',
			name: 'archive',
			deletedAt: null,
			headVersionId: null,
			contentSha256: null,
			sizeBytes: null,
			contentType: null,
		});
		await index.upsertMirror({
			nodeId: 1,
			spaceId: 1,
			relPath: 'old-name.txt',
			diskSha256: 'sha',
			diskSize: 1,
			diskMtimeMs: 1,
			baseVersionId: 1,
			materializedOfVersion: null,
		});
		await index.setCursor(1, '10');
		http.changesBySince.set('10', {
			resync: false,
			newState: '11',
			changed: [{ nodeId: 1, op: 'rename', seq: 11 }],
			hasMore: false,
		});
		http.nodesMetaMap.set(1, meta({ nodeId: 1, parentId: 2, name: 'new-name.txt', contentSha256: 'sha', sizeBytes: 1 }));
		http.versionsByNode.set(1, []);

		await engine.syncOnce();
		expect(store.movedCalls).toEqual([{ nodeId: 1, oldRel: 'old-name.txt', newRel: 'archive/new-name.txt' }]);
	});
});

describe('SyncEngine — stale cursor triggers a windowed full resync', () => {
	it('anchors, BFS-walks the tree, resolves shas via nodesMeta, and converges', async () => {
		const { engine, http, store, index } = await makeHarness();
		await index.setCursor(1, '5');
		http.changesBySince.set('5', { resync: true });
		http.changesBySince.set(ANCHOR, { resync: false, newState: '99', changed: [], hasMore: false });
		http.treeByParent.set(null, [meta({ nodeId: 10, kind: 'folder', name: 'docs', contentSha256: null, sizeBytes: null, headVersionId: null })]);
		http.treeByParent.set(10, [meta({ nodeId: 11, name: 'a.txt', parentId: 10 })]);
		http.nodesMetaMap.set(10, meta({ nodeId: 10, kind: 'folder', name: 'docs', contentSha256: null, sizeBytes: null, headVersionId: null }));
		http.nodesMetaMap.set(11, meta({ nodeId: 11, name: 'a.txt', parentId: 10 }));
		http.versionsByNode.set(11, []);

		const res = await engine.syncOnce();
		expect(res.downloaded).toBe(1); // the file; the folder has no content to download
		expect(store.putLocalCalls).toHaveLength(1);
		expect(await index.getCursor(1)).toBe('99');
	});
});

describe('SyncEngine — crash-safe resume', () => {
	it('a throw mid-apply leaves the cursor unmoved; re-running the same batch converges exactly once', async () => {
		const { engine, http, store, index } = await makeHarness();
		await index.setCursor(1, '5');
		http.changesBySince.set('5', {
			resync: false,
			newState: '6',
			changed: [{ nodeId: 1, op: 'update', seq: 6 }],
			hasMore: false,
		});
		http.nodesMetaMap.set(1, meta({ nodeId: 1, contentSha256: 'sha1', headVersionId: 5 }));
		http.versionsByNode.set(1, []);

		store.putLocalThrowsOnce = true;
		await expect(engine.syncOnce()).rejects.toThrow('simulated crash mid-apply');
		expect(await index.getCursor(1)).toBe('5'); // unmoved — the batch never fully applied

		const res = await engine.syncOnce(); // same cursor -> same scripted batch, now succeeds
		expect(res.downloaded).toBe(1);
		expect(store.putLocalCalls).toHaveLength(1); // not double-applied
		expect(await index.getCursor(1)).toBe('6');
	});
});

describe('SyncEngine — upload rejections', () => {
	it('a 4xx (BZ148 quota) records an issue and dequeues — never retry-loops', async () => {
		const { engine, http, store, index } = await makeHarness();
		await index.setCursor(1, '0');
		http.changesBySince.set('0', { resync: false, newState: '0', changed: [], hasMore: false });
		await index.upsertMirror({
			nodeId: 1,
			spaceId: 1,
			relPath: 'big.bin',
			diskSha256: 'old',
			diskSize: 1,
			diskMtimeMs: 1,
			baseVersionId: 1,
			materializedOfVersion: null,
		});
		await index.enqueue(1, 'upsert', { nodeId: 1 });
		store.manifests.set(1, { contentSha256: 'new', size: 999, chunks: [{ sha256: 'c1', size: 999 }] });
		http.presentChunks.add('c1');
		http.putVersionThrows = new DriveApiError(413, 'https://setjoin.com/problems/drive/quota-exceeded', 'BZ148');

		const res = await engine.syncOnce();
		expect(res.issues).toBe(1);
		expect(await index.due(Number.MAX_SAFE_INTEGER, 10)).toHaveLength(0); // dequeued, not retried
		expect((await index.issues(1))[0]).toMatchObject({ code: 'quota', relPath: 'big.bin' });
	});

	it('a 423 (BZ149 hard-locked) records a locked-file issue and dequeues — never retry-loops (P4 Task 16)', async () => {
		const { engine, http, store, index } = await makeHarness();
		await index.setCursor(1, '0');
		http.changesBySince.set('0', { resync: false, newState: '0', changed: [], hasMore: false });
		await index.upsertMirror({
			nodeId: 1,
			spaceId: 1,
			relPath: 'locked.docx',
			diskSha256: 'old',
			diskSize: 1,
			diskMtimeMs: 1,
			baseVersionId: 1,
			materializedOfVersion: null,
		});
		await index.enqueue(1, 'upsert', { nodeId: 1 });
		store.manifests.set(1, { contentSha256: 'new', size: 3, chunks: [{ sha256: 'c1', size: 3 }] });
		http.presentChunks.add('c1');
		http.putVersionThrows = new DriveApiError(423, 'https://setjoin.com/problems/drive/locked', 'BZ149');

		const res = await engine.syncOnce();
		expect(res.issues).toBe(1);
		expect(await index.due(Number.MAX_SAFE_INTEGER, 10)).toHaveLength(0); // dequeued (ack), not retried
		expect((await index.issues(1))[0]).toMatchObject({ code: 'locked-file', relPath: 'locked.docx' });
	});

	it('a 5xx backs off instead of dequeuing', async () => {
		const { engine, http, index } = await makeHarness();
		await index.setCursor(1, '0');
		http.changesBySince.set('0', { resync: false, newState: '0', changed: [], hasMore: false });
		await index.upsertMirror({
			nodeId: 1,
			spaceId: 1,
			relPath: 'x.txt',
			diskSha256: 'old',
			diskSize: 1,
			diskMtimeMs: 1,
			baseVersionId: 1,
			materializedOfVersion: null,
		});
		await index.enqueue(1, 'upsert', { nodeId: 1 });
		http.putVersionThrows = new DriveApiError(503, 'about:blank');

		const res = await engine.syncOnce();
		expect(res.issues).toBe(0); // not an issue yet — it's a transient failure
		expect(await index.due(1_000_000, 10)).toHaveLength(0); // in backoff, not immediately due
	});
});

describe('SyncEngine — selective sync', () => {
	it('excludes a local change from ever being enqueued', async () => {
		const { engine, index } = await makeHarness({ isExcluded: (p) => p.startsWith('big/') });
		await engine.onLocalChange({ kind: 'upsert', relPath: 'big/movie.mp4' });
		expect(await index.due(Number.MAX_SAFE_INTEGER, 10)).toHaveLength(0);
	});

	it('excludes a remote feed op from content download but keeps the metadata mirror whole', async () => {
		const { engine, http, store, index } = await makeHarness({ isExcluded: (p) => p === 'big/movie.mp4' });
		await index.upsertNode({
			nodeId: 5,
			spaceId: 1,
			parentId: null,
			kind: 'folder',
			name: 'big',
			deletedAt: null,
			headVersionId: null,
			contentSha256: null,
			sizeBytes: null,
			contentType: null,
		});
		await index.setCursor(1, '10');
		http.changesBySince.set('10', {
			resync: false,
			newState: '11',
			changed: [{ nodeId: 1, op: 'create', seq: 11 }],
			hasMore: false,
		});
		http.nodesMetaMap.set(1, meta({ nodeId: 1, parentId: 5, name: 'movie.mp4' }));

		await engine.syncOnce();
		expect(store.putLocalCalls).toEqual([]);
		expect(await index.getNode(1)).not.toBeNull(); // metadata mirror stays whole
	});
});

describe('SyncEngine — P4 Task 17: branch-sibling materialization', () => {
	it('a branchCount>0 feed update materializes each open branch head as a sibling, registered in dc_branch_mirror', async () => {
		const { engine, http, store, index } = await makeHarness();
		await index.setCursor(1, '10');
		http.changesBySince.set('10', {
			resync: false,
			newState: '11',
			changed: [{ nodeId: 1, op: 'update', seq: 11 }],
			hasMore: false,
		});
		http.nodesMetaMap.set(
			1,
			meta({ nodeId: 1, name: 'Report.xlsx', contentSha256: 'main-sha', sizeBytes: 9, headVersionId: 20, branchCount: 1 })
		);
		http.versionsByNode.set(1, [
			{ id: 20, conflictOf: null, sha256: 'main-sha', size: 9, deviceLabel: null, createdAt: '2026-07-09T00:00:00Z' },
			{ id: 33, conflictOf: null, sha256: 'branch-sha', size: 12, deviceLabel: 'bobs-laptop', createdAt: '2026-07-10T00:00:00Z' },
		]);
		http.branchesByNode.set(1, [{ id: 5, name: 'budget-redo', status: 'open', headVersionId: 33, forkedFromVersionId: 20 }]);

		await engine.syncOnce();

		expect(http.fileBranchesCalls).toContain(1);
		expect(store.materializedVersions).toContainEqual({
			versionId: 33,
			relPath: 'Report (branch budget-redo).xlsx',
			sha: 'branch-sha',
			size: 12,
		});
		const branchRow = await index.getBranchMirror(1, 5);
		expect(branchRow).toMatchObject({
			nodeId: 1,
			branchId: 5,
			relPath: 'Report (branch budget-redo).xlsx',
			diskSha256: 'branch-sha',
			diskSize: 12,
			baseVersionId: 33,
		});
	});

	it('skips the fileBranches network call when branchCount is 0 and nothing is locally materialized', async () => {
		const { engine, http, index } = await makeHarness();
		await index.setCursor(1, '10');
		http.changesBySince.set('10', {
			resync: false,
			newState: '11',
			changed: [{ nodeId: 1, op: 'update', seq: 11 }],
			hasMore: false,
		});
		http.nodesMetaMap.set(1, meta({ nodeId: 1, name: 'plain.txt', contentSha256: 'sha', sizeBytes: 3, headVersionId: 1 }));

		await engine.syncOnce();
		expect(http.fileBranchesCalls).toEqual([]);
		expect(await index.branchMirrorsForNode(1)).toEqual([]);
	});

	it('editing a materialized sibling uploads with putVersion(..., branchId) and never touches main', async () => {
		const { engine, http, store, index } = await makeHarness();
		await index.upsertMirror({
			nodeId: 1,
			spaceId: 1,
			relPath: 'Report.xlsx',
			diskSha256: 'main-sha',
			diskSize: 9,
			diskMtimeMs: 1,
			baseVersionId: 20,
			materializedOfVersion: null,
		});
		await index.upsertBranchMirror({
			nodeId: 1,
			branchId: 5,
			relPath: 'Report (branch budget-redo).xlsx',
			diskSha256: 'branch-sha',
			diskSize: 12,
			diskMtimeMs: 2,
			baseVersionId: 33,
		});
		store.manifestsByPath.set('Report (branch budget-redo).xlsx', {
			contentSha256: 'edited-sha',
			size: 20,
			chunks: [{ sha256: 'c1', size: 20 }],
		});
		http.presentChunks.add('c1');
		await index.setCursor(1, '0');
		http.changesBySince.set('0', { resync: false, newState: '0', changed: [], hasMore: false });

		await engine.onLocalChange({ kind: 'upsert', relPath: 'Report (branch budget-redo).xlsx' });
		await engine.syncOnce();

		expect(http.putVersionCalls).toHaveLength(1);
		expect(http.putVersionCalls[0]).toMatchObject({
			nodeId: 1,
			body: { contentSha256: 'edited-sha', baseVersionId: 33, branchId: 5 },
		});
		// Main's own mirror row is untouched -- the save never landed on main.
		expect((await index.getMirror(1))?.diskSha256).toBe('main-sha');
		const branchRow = await index.getBranchMirror(1, 5);
		expect(branchRow?.diskSha256).toBe('edited-sha');
	});

	it('a branch turned merged/discarded removes the sibling file and the dc_branch_mirror row', async () => {
		const { engine, http, store, index } = await makeHarness();
		await index.upsertMirror({
			nodeId: 1,
			spaceId: 1,
			relPath: 'Report.xlsx',
			diskSha256: 'main-sha',
			diskSize: 9,
			diskMtimeMs: 1,
			baseVersionId: 20,
			materializedOfVersion: null,
		});
		await index.upsertBranchMirror({
			nodeId: 1,
			branchId: 5,
			relPath: 'Report (branch budget-redo).xlsx',
			diskSha256: 'branch-sha',
			diskSize: 12,
			diskMtimeMs: 2,
			baseVersionId: 33,
		});
		await index.setCursor(1, '10');
		http.changesBySince.set('10', {
			resync: false,
			newState: '11',
			changed: [{ nodeId: 1, op: 'update', seq: 11 }],
			hasMore: false,
		});
		http.nodesMetaMap.set(1, meta({ nodeId: 1, name: 'Report.xlsx', contentSha256: 'main-sha', sizeBytes: 9, headVersionId: 20 }));
		http.branchesByNode.set(1, []); // merged/discarded -- the server's live list omits it

		await engine.syncOnce();

		expect(store.removedPaths).toEqual(['Report (branch budget-redo).xlsx']);
		expect(await index.getBranchMirror(1, 5)).toBeNull();
		expect(await index.branchMirrorsForNode(1)).toEqual([]);
	});

	it('conflict-on-upload adopts the server auto-branch, so a LATER edit of the conflict sibling extends that branch', async () => {
		const { engine, http, store, index } = await makeHarness();
		await index.upsertMirror({
			nodeId: 1,
			spaceId: 1,
			relPath: 'plan.md',
			diskSha256: 'localedit',
			diskSize: 5,
			diskMtimeMs: 1,
			baseVersionId: 3,
			materializedOfVersion: null,
		});
		await index.enqueue(1, 'upsert', { nodeId: 1 });
		await index.setCursor(1, '0');
		http.changesBySince.set('0', { resync: false, newState: '0', changed: [], hasMore: false });
		store.manifests.set(1, { contentSha256: 'localedit', size: 5, chunks: [{ sha256: 'c1', size: 5 }] });
		http.presentChunks.add('c1');
		http.putVersionResult = { versionId: 50, conflict: true, branchId: 7, headVersionId: 60, wormPending: false };
		http.nodesMetaMap.set(1, meta({ nodeId: 1, contentSha256: 'headsha', sizeBytes: 8, headVersionId: 60 }));

		await engine.syncOnce();

		const siblingPath = 'plan (conflict bobs-laptop 2026-07-09).md';
		expect(store.renamedToSibling).toEqual([{ nodeId: 1, siblingName: 'plan (conflict bobs-laptop 2026-07-09).md' }]);
		const branchRow = await index.getBranchMirror(1, 7);
		expect(branchRow).toMatchObject({ nodeId: 1, branchId: 7, relPath: siblingPath, diskSha256: 'localedit', baseVersionId: 50 });

		// A later edit of that same sibling path must upload to branch 7 -- not
		// spawn an unrelated new server node (P2's materializedOfVersion-only
		// dead end this upgrades).
		store.manifestsByPath.set(siblingPath, { contentSha256: 'edited-again', size: 6, chunks: [{ sha256: 'c2', size: 6 }] });
		http.presentChunks.add('c2');
		http.putVersionResult = { versionId: 51, conflict: false, branchId: 7, headVersionId: null, wormPending: false };
		await index.setCursor(1, '11');
		http.changesBySince.set('11', { resync: false, newState: '11', changed: [], hasMore: false });

		await engine.onLocalChange({ kind: 'upsert', relPath: siblingPath });
		await engine.syncOnce();

		expect(http.createNodeCalls).toEqual([]); // never treated as a brand-new file
		const branchCall = http.putVersionCalls.find((c) => c.body.branchId === 7 && c.body.contentSha256 === 'edited-again');
		expect(branchCall).toMatchObject({ nodeId: 1, body: { branchId: 7 } });
	});

	it('C2 discovery (materializeKnownConflicts) also adopts a listVersions row\'s branchId — the non-conflicting device gets a routable sibling too', async () => {
		const { engine, http, store, index } = await makeHarness();
		await index.upsertMirror({
			nodeId: 1,
			spaceId: 1,
			relPath: 'plan.md',
			diskSha256: 'samesha',
			diskSize: 10,
			diskMtimeMs: 1,
			baseVersionId: 9,
			materializedOfVersion: null,
		});
		store.manifests.set(1, { contentSha256: 'samesha', size: 10, chunks: [] });
		await index.setCursor(1, '10');
		http.changesBySince.set('10', {
			resync: false,
			newState: '11',
			changed: [{ nodeId: 1, op: 'update', seq: 11 }],
			hasMore: false,
		});
		http.nodesMetaMap.set(1, meta({ nodeId: 1, name: 'plan.md', contentSha256: 'samesha', headVersionId: 9, branchCount: 1 }));
		http.versionsByNode.set(1, [
			{ id: 9, conflictOf: null, sha256: 'samesha', size: 10, deviceLabel: 'bobs-laptop', createdAt: '2026-07-09T00:00:00Z' },
			{
				id: 8,
				conflictOf: 9,
				sha256: 'oldsha',
				size: 8,
				deviceLabel: 'anns-desktop',
				createdAt: '2026-07-08T00:00:00Z',
				branchId: 12,
			},
		]);
		// The auto-branch is genuinely still open server-side (fileBranches and
		// listVersions must agree -- same DB in the real product); its head is
		// already version 8, matching what materializeKnownConflicts registers
		// below, so reconcileBranches' "already at this head" guard must skip
		// re-materializing it under a second name, not remove the row as closed.
		http.branchesByNode.set(1, [{ id: 12, name: 'anns-desktop 2026-07-08', status: 'open', headVersionId: 8, forkedFromVersionId: 9 }]);

		await engine.syncOnce();

		expect(store.materializedVersions).toEqual([
			{ versionId: 8, relPath: 'plan (conflict anns-desktop 2026-07-08).md', sha: 'oldsha', size: 8 },
		]);
		const branchRow = await index.getBranchMirror(1, 12);
		expect(branchRow).toMatchObject({
			nodeId: 1,
			branchId: 12,
			relPath: 'plan (conflict anns-desktop 2026-07-08).md',
			diskSha256: 'oldsha',
			baseVersionId: 8,
		});
	});
});

// med-shard3-020: remote-controlled metadata (a co-tenant's putVersion
// deviceLabel, a co-tenant's branch name) must never be able to (a) steer a
// local filename outside a single safe path segment, (b) wedge whole-space
// sync or the revocation purge because one poisoned sibling's store op
// throws, or (c) silently rm a sibling whose disk content no longer matches
// the last-synced sha (undrained local edits).
	describe('SyncEngine — poisoned remote labels and guarded sibling deletion (med-shard3-020)', () => {
		type Harness = Awaited<ReturnType<typeof makeHarness>>;

		function poisonedConflictRow(nodeId: number, headVersionId: number, extra: Partial<VersionMeta> = {}): VersionMeta {
			return {
				id: 8,
				conflictOf: headVersionId,
				sha256: 'oldsha',
				size: 8,
				deviceLabel: '../../pwn',
				createdAt: '2026-07-08T00:00:00Z',
				...extra,
			};
		}

		async function seedEchoConflict(harness: Harness, poisoned: VersionMeta) {
			const { http, store, index } = harness;
			await index.upsertMirror({
				nodeId: 1,
				spaceId: 1,
				relPath: 'plan.md',
				diskSha256: 'samesha',
				diskSize: 10,
				diskMtimeMs: 1,
				baseVersionId: 9,
				materializedOfVersion: null,
			});
			store.manifests.set(1, { contentSha256: 'samesha', size: 10, chunks: [] });
			await index.setCursor(1, '10');
			http.changesBySince.set('10', {
				resync: false,
				newState: '11',
				changed: [{ nodeId: 1, op: 'update', seq: 11 }],
				hasMore: false,
			});
			http.nodesMetaMap.set(1, meta({ nodeId: 1, name: 'plan.md', contentSha256: 'samesha', headVersionId: 9 }));
			http.versionsByNode.set(1, [
				{ id: 9, conflictOf: null, sha256: 'samesha', size: 10, deviceLabel: 'bobs-laptop', createdAt: '2026-07-09T00:00:00Z' },
				poisoned,
			]);
		}

	it('a co-tenant-poisoned deviceLabel is sanitized to a single safe path segment before materialization', async () => {
		const harness = await makeHarness();
		const { engine, store, index } = harness;
		await seedEchoConflict(harness, poisonedConflictRow(1, 9));

		await engine.syncOnce();

		// '../../pwn' can no longer survive into the filename: every path
		// separator became '_', so the derived sibling stays ONE segment and
		// FolderMirror's absPath jail could never trip on it.
		expect(store.materializedVersions).toEqual([
			{ versionId: 8, relPath: 'plan (conflict .._.._pwn 2026-07-08).md', sha: 'oldsha', size: 8 },
		]);
		expect(store.materializedVersions[0].relPath).not.toContain('/');
		expect(store.materializedVersions[0].relPath).not.toContain('\\');
		expect(await index.isVersionMaterialized(8)).toBe(true);
		expect(await index.getCursor(1)).toBe('11'); // the pass was never wedged
	});

	it('one poisoned sibling cannot wedge whole-space sync: the rest of the batch applies, the cursor advances, and a quarantine marker is recorded', async () => {
		class JailRejectingStore extends MemContentStore {
			override async materializeVersion(versionId: number, relPath: string, sha256: string, size: number): Promise<void> {
				if (sha256 === 'evil-sha') throw new Error('unsafe Drive mirror path (simulated jail rejection)');
				await super.materializeVersion(versionId, relPath, sha256, size);
			}
		}
		const harness = await makeHarness({}, new JailRejectingStore());
		const { engine, http, store, index } = harness;
		await seedEchoConflict(harness, poisonedConflictRow(1, 9, { sha256: 'evil-sha', size: 6 }));
		// A second, healthy node shares the same feed batch.
		http.changesBySince.set('10', {
			resync: false,
			newState: '11',
			changed: [
				{ nodeId: 1, op: 'update', seq: 11 },
				{ nodeId: 2, op: 'update', seq: 12 },
			],
			hasMore: false,
		});
		http.nodesMetaMap.set(2, meta({ nodeId: 2, name: 'healthy.txt', contentSha256: 'newsha', headVersionId: 5 }));
		http.versionsByNode.set(2, []);

		await engine.syncOnce(); // resolves — no wedge

		// The healthy node in the SAME batch still downloaded.
		expect(store.putLocalCalls).toEqual([{ nodeId: 2, plan: { contentSha256: 'newsha', size: 10, headVersionId: 5 } }]);
		expect(store.materializedVersions).toEqual([]); // the poisoned sibling was skipped, not applied
		const issues = await index.issues(1);
		expect(issues.map((i) => i.code)).toContain('transfer-failed');
		expect(issues.find((i) => i.code === 'transfer-failed')).toMatchObject({
			relPath: 'plan (conflict .._.._pwn 2026-07-08).md',
		});
		expect(await index.isVersionMaterialized(8)).toBe(false); // not fake-marked as done
		expect(await index.getCursor(1)).toBe('11'); // the batch still committed
	});

	it('end-to-end: a poisoned-label conflict sibling materializes sanitized and the revocation purge still completes', async () => {
		const harness = await makeHarness();
		const { engine, http, store, index } = harness;
		// Phase 1: echo pass discovers the co-tenant's conflicting version
		// (poisoned label) and adopts its auto-branch.
		await index.upsertMirror({
			nodeId: 7,
			spaceId: 1,
			relPath: 'private.txt',
			diskSha256: 'samesha',
			diskSize: 10,
			diskMtimeMs: 1,
			baseVersionId: 9,
			materializedOfVersion: null,
		});
		store.manifests.set(7, { contentSha256: 'samesha', size: 10, chunks: [] });
		await index.setCursor(1, '10');
		http.changesBySince.set('10', {
			resync: false,
			newState: '11',
			changed: [{ nodeId: 7, op: 'update', seq: 11 }],
			hasMore: false,
		});
		http.nodesMetaMap.set(7, meta({ nodeId: 7, name: 'private.txt', contentSha256: 'samesha', headVersionId: 9, branchCount: 1 }));
		http.versionsByNode.set(7, [
			{ id: 9, conflictOf: null, sha256: 'samesha', size: 10, deviceLabel: 'bobs-laptop', createdAt: '2026-07-09T00:00:00Z' },
			poisonedConflictRow(7, 9, { sha256: 'pwn-sha', size: 6, branchId: 12 }),
		]);
		http.branchesByNode.set(7, [{ id: 12, name: '../../pwn', status: 'open', headVersionId: 8, forkedFromVersionId: 9 }]);

		await engine.syncOnce();

		const safeSibling = 'private (conflict .._.._pwn 2026-07-08).txt';
		expect(store.materializedVersions).toEqual([{ versionId: 8, relPath: safeSibling, sha: 'pwn-sha', size: 6 }]);
		expect(await index.getBranchMirror(7, 12)).toMatchObject({ relPath: safeSibling, baseVersionId: 8 });

		// Phase 2: access is revoked. The purge transaction must complete with
		// the poisoned node present — no sibling may abort it.
		store.revokeOutcome = 'purged';
		http.accessPage = {
			cursor: null, epoch: null, invalidations: [], hasMore: false,
			fullReconcile: true, reason: 'accessRevoked',
		};
		let changeCalls = 0;
		http.changes = async () => {
			if (changeCalls++ === 0) throw new DriveApiError(404, 'about:blank', 'BZ139');
			return { resync: false, newState: '11', changed: [], hasMore: false };
		};
		http.visibilityHandler = async () => {
			throw new DriveApiError(404, 'about:blank', 'BZ139');
		};

		await engine.syncOnce();

		expect(store.removedPaths).toContain(safeSibling);
		expect(await index.getNode(7)).toBeNull();
		expect(await index.getBranchMirror(7, 12)).toBeNull();
		expect(await index.getSyncState(1)).toEqual({
			version: 2, contentState: '11', accessCursor: null, aclEpoch: null,
		});
	});

	async function seedMergedBranchSibling(harness: {
		engine: SyncEngine; http: FakeHttp; store: MemContentStore; index: SqlMirrorIndex;
	}, branchRow: { diskSha256: string | null }, manifestAtSibling?: Manifest) {
		const { engine, http, store, index } = harness;
		await index.upsertMirror({
			nodeId: 1,
			spaceId: 1,
			relPath: 'Report.xlsx',
			diskSha256: 'main-sha',
			diskSize: 9,
			diskMtimeMs: 1,
			baseVersionId: 20,
			materializedOfVersion: null,
		});
		await index.upsertBranchMirror({
			nodeId: 1,
			branchId: 5,
			relPath: 'Report (branch budget-redo).xlsx',
			diskSha256: branchRow.diskSha256,
			diskSize: 12,
			diskMtimeMs: 2,
			baseVersionId: 33,
		});
		store.manifests.set(1, { contentSha256: 'main-sha', size: 9, chunks: [] });
		if (manifestAtSibling) {
			store.manifestsByPath.set('Report (branch budget-redo).xlsx', manifestAtSibling);
		}
		await index.setCursor(1, '10');
		http.changesBySince.set('10', {
			resync: false,
			newState: '11',
			changed: [{ nodeId: 1, op: 'update', seq: 11 }],
			hasMore: false,
		});
		http.nodesMetaMap.set(1, meta({ nodeId: 1, name: 'Report.xlsx', contentSha256: 'main-sha', sizeBytes: 9, headVersionId: 20 }));
		http.versionsByNode.set(1, []);
		http.branchesByNode.set(1, []); // merged/discarded -- the server's live list omits it
	}

	it('a merged/discarded branch refuses to delete a sibling with undrained local edits — it is kept and marked', async () => {
		const harness = await makeHarness();
		await seedMergedBranchSibling(
			harness,
			{ diskSha256: 'branch-sha' },
			{ contentSha256: 'undrained-edit', size: 99, chunks: [] },
		);

		await harness.engine.syncOnce();

		expect(harness.store.removedPaths).toEqual([]); // never rm'd
		const issues = await harness.index.issues(1);
		expect(issues.map((i) => i.code)).toContain('unsynced-local-edit');
		expect(issues.find((i) => i.code === 'unsynced-local-edit')).toMatchObject({
			relPath: 'Report (branch budget-redo).xlsx',
		});
		expect(await harness.index.getBranchMirror(1, 5)).toMatchObject({
			relPath: 'Report (branch budget-redo).xlsx',
		}); // row kept — the edit stays routable/visible
	});

	it('a closed-branch sibling with no recorded sha is kept (fail closed) — cleanliness must be provable before deletion', async () => {
		const harness = await makeHarness();
		await seedMergedBranchSibling(
			harness,
			{ diskSha256: null },
			{ contentSha256: 'whatever-is-on-disk', size: 12, chunks: [] },
		);

		await harness.engine.syncOnce();

		expect(harness.store.removedPaths).toEqual([]);
		expect((await harness.index.issues(1)).map((i) => i.code)).toContain('unsynced-local-edit');
		expect(await harness.index.getBranchMirror(1, 5)).not.toBeNull();
	});

	// med-shard3-020 r2 — a disk-hash read FAILURE is a third state, never
	// folded into "vanished": an unreadable sibling can still be unlinkable, so
	// treating a thrown hash read as manifest=null would delete content without
	// proving cleanliness. The sibling is kept with a dc_issues marker instead.
	it('a closed-branch sibling whose disk hash cannot be read is kept and marked — a read error is not a vanished file', async () => {
		const harness = await makeHarness();
		await seedMergedBranchSibling(harness, { diskSha256: 'branch-sha' });
		harness.store.readAtPathThrows.add('Report (branch budget-redo).xlsx');

		await harness.engine.syncOnce();

		expect(harness.store.removedPaths).toEqual([]); // never rm'd
		const issues = await harness.index.issues(1);
		expect(issues.map((i) => i.code)).toContain('transfer-failed');
		expect(issues.find((i) => i.code === 'transfer-failed')).toMatchObject({
			relPath: 'Report (branch budget-redo).xlsx',
		});
		expect(await harness.index.getBranchMirror(1, 5)).not.toBeNull(); // row kept — the sibling stays routable
	});

	it('a closed-branch sibling whose disk content still matches the recorded sha is still removed', async () => {
		const harness = await makeHarness();
		await seedMergedBranchSibling(
			harness,
			{ diskSha256: 'branch-sha' },
			{ contentSha256: 'branch-sha', size: 12, chunks: [] },
		);

		await harness.engine.syncOnce();

		expect(harness.store.removedPaths).toEqual(['Report (branch budget-redo).xlsx']);
		expect(await harness.index.getBranchMirror(1, 5)).toBeNull();
	});
});

describe('SyncEngine — bounded issue ledger (unbounded-retry-ledger hardening)', () => {
	it('an identical (code, relPath) failure on a later pass reports the failure but does not grow dc_issues', async () => {
		const { engine, http, store, index } = await makeHarness();
		const seedFailure = async () => {
			await index.setCursor(1, '0');
			http.changesBySince.set('0', { resync: false, newState: '0', changed: [], hasMore: false });
			await index.upsertMirror({
				nodeId: 1,
				spaceId: 1,
				relPath: 'locked.docx',
				diskSha256: 'old',
				diskSize: 1,
				diskMtimeMs: 1,
				baseVersionId: 1,
				materializedOfVersion: null,
			});
			await index.enqueue(1, 'upsert', { nodeId: 1 });
			store.manifests.set(1, { contentSha256: 'new', size: 3, chunks: [{ sha256: 'c1', size: 3 }] });
			http.presentChunks.add('c1');
		};

		http.putVersionThrows = new DriveApiError(423, 'https://setjoin.com/problems/drive/locked', 'BZ149');
		await seedFailure();
		const first = await engine.syncOnce();
		expect(first.issues).toBe(1);
		expect(await index.issues(1)).toHaveLength(1);

		// A second pass hitting the SAME failure still surfaces the issue...
		await seedFailure();
		const second = await engine.syncOnce();
		expect(second.issues).toBe(1);
		// ...but the ledger holds one open entry, not one per pass.
		expect(await index.issues(1)).toHaveLength(1);
	});
});
