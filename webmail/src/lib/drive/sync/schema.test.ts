// @vitest-environment node
import { DatabaseSync } from 'node:sqlite';
import { describe, it, expect } from 'vitest';
import type { DbLike, NodeMeta } from './types.js';
import { applySchema, DC_SCHEMA, SqlMirrorIndex } from './schema.js';

/** node:sqlite-backed DbLike — a real SQL oracle, zero new deps (Node ≥22).
 *  Re-exported so the future convergence suite can reuse it. */
export function memDb(): DbLike {
	const db = new DatabaseSync(':memory:');
	return {
		exec: async (sql, params = []) => {
			const st = db.prepare(sql);
			const r = st.run(...(params as never[]));
			return Number(r.changes);
		},
		query: async (sql, params = []) => db.prepare(sql).all(...(params as never[])) as never,
	};
}

function node(overrides: Partial<NodeMeta> = {}): NodeMeta {
	return {
		nodeId: 1,
		spaceId: 1,
		parentId: null,
		kind: 'file',
		name: 'a.txt',
		deletedAt: null,
		headVersionId: null,
		contentSha256: null,
		sizeBytes: null,
		contentType: null,
		...overrides,
	};
}

describe('applySchema', () => {
	it('is idempotent — running twice does not throw', async () => {
		const db = memDb();
		await applySchema(db);
		await applySchema(db);
		expect(DC_SCHEMA.length).toBeGreaterThan(0);
	});
});

describe('SqlMirrorIndex — dc_nodes', () => {
	it('upserts/gets a node and lists children by parent', async () => {
		const db = memDb();
		await applySchema(db);
		const idx = new SqlMirrorIndex(db);

		await idx.upsertNode(node({ nodeId: 1, kind: 'folder', name: 'docs', parentId: null }));
		await idx.upsertNode(node({ nodeId: 2, name: 'a.txt', parentId: 1, contentSha256: 'sha-a' }));

		const got = await idx.getNode(2);
		expect(got?.name).toBe('a.txt');
		expect(got?.contentSha256).toBe('sha-a');
		expect(await idx.getNode(999)).toBeNull();

		expect(await idx.childNameExistsCI(1, 1, 'A.TXT')).toBe(true);
		expect(await idx.childNameExistsCI(1, 1, 'missing.txt')).toBe(false);

		const child = await idx.findChildByName(1, 1, 'A.TXT');
		expect(child?.nodeId).toBe(2);
		expect(await idx.findChildByName(1, 1, 'nope.txt')).toBeNull();
	});

	it('resolves relPath by walking parent_id to the root; null on a gap', async () => {
		const db = memDb();
		await applySchema(db);
		const idx = new SqlMirrorIndex(db);
		await idx.upsertNode(node({ nodeId: 1, kind: 'folder', name: 'docs', parentId: null }));
		await idx.upsertNode(node({ nodeId: 2, kind: 'folder', name: 'sub', parentId: 1 }));
		await idx.upsertNode(node({ nodeId: 3, name: 'a.txt', parentId: 2 }));

		expect(await idx.relPath(3)).toBe('docs/sub/a.txt');
		expect(await idx.relPath(1)).toBe('docs');
		expect(await idx.relPath(42)).toBeNull(); // unknown node — a gap
	});
});

describe('SqlMirrorIndex — dc_meta cursor', () => {
	it('gets/sets a cursor per space, independently', async () => {
		const db = memDb();
		await applySchema(db);
		const idx = new SqlMirrorIndex(db);
		expect(await idx.getCursor(1)).toBeNull();
		await idx.setCursor(1, '100');
		await idx.setCursor(2, '7');
		expect(await idx.getCursor(1)).toBe('100');
		expect(await idx.getCursor(2)).toBe('7');
		await idx.setCursor(1, '200');
		expect(await idx.getCursor(1)).toBe('200');
	});

	it('migrates a legacy content cursor into independent v2 content/access/epoch state', async () => {
		const db = memDb();
		await applySchema(db);
		const idx = new SqlMirrorIndex(db);
		await db.exec(`INSERT INTO dc_meta (k,v) VALUES (?,?)`, ['cursor:9', '41']);

		expect(await idx.getSyncState(9)).toEqual({
			version: 2, contentState: '41', accessCursor: null, aclEpoch: null,
		});
		await idx.setSyncState(9, {
			version: 2, contentState: '42', accessCursor: 'opaque-token', aclEpoch: '7',
		});
		expect(await idx.getSyncState(9)).toEqual({
			version: 2, contentState: '42', accessCursor: 'opaque-token', aclEpoch: '7',
		});
	});
});

describe('SqlMirrorIndex — ACL cache and quarantine', () => {
	it('persists exact node/root capabilities and purges node authority with local state', async () => {
		const db = memDb();
		await applySchema(db);
		const idx = new SqlMirrorIndex(db);
		await idx.upsertNode(node({ nodeId: 7, capabilities: ['traverse', 'read_metadata', 'download'], traverseOnly: false }));
		await idx.setRootCapabilities(1, ['create_child']);
		await idx.upsertMirror({
			nodeId: 7, spaceId: 1, relPath: 'a.txt', diskSha256: 'sha', diskSize: 1,
			diskMtimeMs: 1, baseVersionId: 3, materializedOfVersion: null,
		});

		expect(await idx.capabilities(7)).toEqual(['traverse', 'read_metadata', 'download']);
		await idx.upsertNode(node({ nodeId: 7, name: 'renamed.txt' }));
		expect(await idx.capabilities(7)).toEqual(['traverse', 'read_metadata', 'download']);
		expect(await idx.rootCapabilities(1)).toEqual(['create_child']);
		await idx.removeNodeState(7);
		expect(await idx.getNode(7)).toBeNull();
		expect(await idx.getMirror(7)).toBeNull();
		expect(await idx.capabilities(7)).toEqual([]);
	});

	it('moves pending outbound work into the durable quarantine ledger atomically', async () => {
		const db = memDb();
		await applySchema(db);
		const idx = new SqlMirrorIndex(db);
		await idx.enqueue(1, 'upsert', { nodeId: 7, contentSha256: 'local' });

		expect(await idx.quarantineOutbound(7, 'a.txt', 'access-revoked', 1234)).toBe(1);
		expect(await idx.due(Number.MAX_SAFE_INTEGER, 10)).toEqual([]);
		const rows = await db.query<{ node_id: number; rel_path: string; reason: string }>(
			`SELECT node_id,rel_path,reason FROM dc_quarantine`,
		);
		expect(rows).toEqual([{ node_id: 7, rel_path: 'a.txt', reason: 'access-revoked' }]);
	});
});

describe('SqlMirrorIndex — dc_mirror', () => {
	it('upserts, looks up by nodeId and by case-insensitive relPath, and by content for move-pairing', async () => {
		const db = memDb();
		await applySchema(db);
		const idx = new SqlMirrorIndex(db);
		await idx.upsertMirror({
			nodeId: 1,
			spaceId: 1,
			relPath: 'docs/A.txt',
			diskSha256: 'sha1',
			diskSize: 5,
			diskMtimeMs: 1000,
			baseVersionId: 10,
			materializedOfVersion: null,
		});

		expect((await idx.getMirror(1))?.relPath).toBe('docs/A.txt');
		expect(await idx.getMirror(999)).toBeNull();
		expect((await idx.findByPathCI(1, 'docs/a.TXT'))?.nodeId).toBe(1);
		expect(await idx.findByPathCI(1, 'nope')).toBeNull();

		const byContent = await idx.findByContent(1, 'sha1', 5);
		expect(byContent).toHaveLength(1);
		expect(byContent[0].nodeId).toBe(1);

		await idx.removeMirror(1);
		expect(await idx.getMirror(1)).toBeNull();
	});
});

describe('SqlMirrorIndex — dc_branch_mirror (P4 Task 17)', () => {
	it('upserts/gets keyed by (node_id, branch_id), lists by node, looks up by path (space-scoped via the dc_mirror join), and removes', async () => {
		const db = memDb();
		await applySchema(db);
		const idx = new SqlMirrorIndex(db);
		// The parent main file must have its own dc_mirror row -- a branch
		// sibling's space scoping is derived via that join (no space_id column
		// on dc_branch_mirror itself, per the locked DDL).
		await idx.upsertMirror({
			nodeId: 1,
			spaceId: 1,
			relPath: 'Report.xlsx',
			diskSha256: 'main-sha',
			diskSize: 9,
			diskMtimeMs: 1,
			baseVersionId: 10,
			materializedOfVersion: null,
		});

		expect(await idx.getBranchMirror(1, 5)).toBeNull();
		await idx.upsertBranchMirror({
			nodeId: 1,
			branchId: 5,
			relPath: 'Report (branch budget-redo).xlsx',
			diskSha256: 'branch-sha',
			diskSize: 12,
			diskMtimeMs: 2000,
			baseVersionId: 33,
		});

		const row = await idx.getBranchMirror(1, 5);
		expect(row).toMatchObject({ nodeId: 1, branchId: 5, relPath: 'Report (branch budget-redo).xlsx', diskSha256: 'branch-sha' });

		const forNode = await idx.branchMirrorsForNode(1);
		expect(forNode).toHaveLength(1);
		expect(forNode[0].branchId).toBe(5);

		const byPath = await idx.findBranchMirrorByPath(1, 'report (BRANCH budget-redo).xlsx'); // case-insensitive
		expect(byPath?.branchId).toBe(5);
		expect(await idx.findBranchMirrorByPath(1, 'nope.xlsx')).toBeNull();
		// A different space never sees this space's branch sibling by path (no
		// dc_mirror row for node_id=1 under space_id=2).
		expect(await idx.findBranchMirrorByPath(2, 'Report (branch budget-redo).xlsx')).toBeNull();

		await idx.removeBranchMirror(1, 5);
		expect(await idx.getBranchMirror(1, 5)).toBeNull();
		expect(await idx.branchMirrorsForNode(1)).toHaveLength(0);
	});

	it('a second branch on the same node coexists under a distinct composite key', async () => {
		const db = memDb();
		await applySchema(db);
		const idx = new SqlMirrorIndex(db);
		await idx.upsertMirror({
			nodeId: 1,
			spaceId: 1,
			relPath: 'Report.xlsx',
			diskSha256: 'main-sha',
			diskSize: 9,
			diskMtimeMs: 1,
			baseVersionId: 10,
			materializedOfVersion: null,
		});
		await idx.upsertBranchMirror({
			nodeId: 1,
			branchId: 5,
			relPath: 'Report (branch a).xlsx',
			diskSha256: 'a-sha',
			diskSize: 1,
			diskMtimeMs: 1,
			baseVersionId: 10,
		});
		await idx.upsertBranchMirror({
			nodeId: 1,
			branchId: 6,
			relPath: 'Report (branch b).xlsx',
			diskSha256: 'b-sha',
			diskSize: 2,
			diskMtimeMs: 2,
			baseVersionId: 10,
		});
		expect(await idx.branchMirrorsForNode(1)).toHaveLength(2);
	});
});

describe('SqlMirrorIndex — dc_versions (C9 materialization bookkeeping)', () => {
	it('tracks which server versions have already been materialized locally', async () => {
		const db = memDb();
		await applySchema(db);
		const idx = new SqlMirrorIndex(db);
		expect(await idx.isVersionMaterialized(55)).toBe(false);
		await idx.addMaterializedVersion({ versionId: 55, nodeId: 1, relPath: 'x (conflict d 2026-07-09).txt', sha256: 'sha', atMs: 1000 });
		expect(await idx.isVersionMaterialized(55)).toBe(true);
	});
});

describe('SqlMirrorIndex — dc_outbound', () => {
	it('enqueues, lists due work, acks, and backs off on bump', async () => {
		const db = memDb();
		await applySchema(db);
		const idx = new SqlMirrorIndex(db);
		await idx.enqueue(1, 'upsert', { relPath: 'a.txt' });

		const due = await idx.due(0, 10);
		expect(due).toHaveLength(1);
		expect(due[0].kind).toBe('upsert');
		expect(due[0].payload).toEqual({ relPath: 'a.txt' });
		expect(due[0].attempts).toBe(0);

		const id = due[0].id;
		await idx.bump(id, 1_000_000);
		const afterBump = await idx.due(1_000_000, 10);
		expect(afterBump).toHaveLength(0); // next_attempt_ms pushed into the future
		expect(await idx.due(1_000_000 + 2_100, 10)).toHaveLength(1); // 2^1s backoff elapsed

		await idx.ack(id);
		expect(await idx.due(10_000_000, 10)).toHaveLength(0);
	});

	it('hasPendingUpsert finds a queued upsert by nodeId regardless of backoff state', async () => {
		const db = memDb();
		await applySchema(db);
		const idx = new SqlMirrorIndex(db);
		expect(await idx.hasPendingUpsert(5)).toBe(false);
		await idx.enqueue(1, 'upsert', { nodeId: 5 });
		expect(await idx.hasPendingUpsert(5)).toBe(true);
		expect(await idx.hasPendingUpsert(6)).toBe(false);
	});
});

describe('SqlMirrorIndex — dc_issues', () => {
	it('appends, lists (optionally scoped to a space), and the ledger empties after clear-by-ack pattern', async () => {
		const db = memDb();
		await applySchema(db);
		const idx = new SqlMirrorIndex(db);
		await idx.addIssue({ spaceId: 1, relPath: 'a.txt', code: 'quota', detail: 'over quota', atMs: 1 });
		await idx.addIssue({ spaceId: 2, relPath: 'b.txt', code: 'locked-file', detail: 'locked', atMs: 2 });

		expect(await idx.issues()).toHaveLength(2);
		const scoped = await idx.issues(1);
		expect(scoped).toHaveLength(1);
		expect(scoped[0].code).toBe('quota');
	});
});
