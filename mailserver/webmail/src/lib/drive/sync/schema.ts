// schema.ts — the shared dc_* metadata mirror (spec §4.3). One SQLCipher
// 'drive' store per device; FolderMirror (Electron main, P2) and VaultStore
// (P3, renderer) apply the same DDL over the same DbLike surface (offline-core
// dbExec/dbQuery in production; node:sqlite in tests — see the test file's
// memDb helper). All statements are single, allowlist-safe keywords
// (CREATE/SELECT/INSERT/UPDATE/DELETE) so they pass offline-core's SQL
// allowlist unchanged.
//
// dc_mirror.disk_sha256 IS the last-synced sha (C8) — there is no separate
// "lastSyncedSha" column. "Dirty" = a freshly-hashed disk sha that differs
// from this column; the fresh hash travels in-memory from the scan/watch
// path, never a second persisted column.
//
// dc_versions (C9, spec §4.3's locked table list) is NOT a copy of dc_mirror:
// dc_mirror is keyed 1:1 by the REAL server node_id (the one canonical local
// path a synced node lives at); a conflict-sibling materialization is a
// second, orphan local file with no server node_id of its own. dc_versions
// tracks "server version V has already been materialized locally at
// rel_path" independently, keyed by the server's own version_id, so the
// engine can ask "has this listVersions() row already been materialized?"
// without overloading dc_mirror's per-node uniqueness.
import type {
	BranchMirrorRow,
	DbLike,
	DriveSyncStateV2,
	MirrorRow,
	NodeMeta,
	OutboundKind,
	OutboundRow,
	SyncIssue,
} from './types.js';

export const DC_SCHEMA: string[] = [
	`CREATE TABLE IF NOT EXISTS dc_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL)`,
	// Server-tree mirror: what we last learned about each node (delta apply + relPath walk).
	`CREATE TABLE IF NOT EXISTS dc_nodes (
	   node_id INTEGER PRIMARY KEY, space_id INTEGER NOT NULL, parent_id INTEGER,
	   kind TEXT NOT NULL, name TEXT NOT NULL,
	   head_version_id INTEGER, content_sha256 TEXT, size_bytes INTEGER,
	   deleted_at TEXT)`,
	`CREATE INDEX IF NOT EXISTS dc_nodes_parent ON dc_nodes (space_id, parent_id)`,
	`CREATE TABLE IF NOT EXISTS dc_node_access (
	   node_id INTEGER PRIMARY KEY, capabilities_json TEXT NOT NULL,
	   traverse_only INTEGER NOT NULL DEFAULT 0)`,
	// Disk state per synced node: the SHA index that outranks mtime (long-tail rule).
	`CREATE TABLE IF NOT EXISTS dc_mirror (
	   node_id INTEGER PRIMARY KEY, space_id INTEGER NOT NULL, rel_path TEXT NOT NULL,
	   disk_sha256 TEXT, disk_size INTEGER, disk_mtime_ms INTEGER,
	   base_version_id INTEGER, materialized_of_version INTEGER)`,
	`CREATE INDEX IF NOT EXISTS dc_mirror_path ON dc_mirror (space_id, rel_path)`,
	// P4 Task 17: this device's disk-state record for ONE materialized
	// open-branch sibling — a distinct satellite table from dc_mirror (no
	// space_id column; scoping is derived by joining node_id through the main
	// file's own dc_mirror row, since a branch sibling can't exist locally
	// before the main file is synced). PK (node_id, branch_id): a node with
	// two open branches materialized locally gets two rows here.
	`CREATE TABLE IF NOT EXISTS dc_branch_mirror (
	   node_id INTEGER NOT NULL, branch_id INTEGER NOT NULL, rel_path TEXT NOT NULL,
	   disk_sha256 TEXT, disk_size INTEGER, disk_mtime_ms INTEGER, base_version_id INTEGER,
	   PRIMARY KEY (node_id, branch_id))`,
	`CREATE INDEX IF NOT EXISTS dc_branch_mirror_path ON dc_branch_mirror (rel_path)`,
	// Conflict-sibling materialization bookkeeping (C9) — see file header.
	`CREATE TABLE IF NOT EXISTS dc_versions (
	   version_id INTEGER PRIMARY KEY, node_id INTEGER NOT NULL, rel_path TEXT NOT NULL,
	   sha256 TEXT, materialized_at_ms INTEGER NOT NULL)`,
	// Outbound journal: local ops queued for the server (crash-safe, backoff).
	`CREATE TABLE IF NOT EXISTS dc_outbound (
	   id INTEGER PRIMARY KEY AUTOINCREMENT, space_id INTEGER NOT NULL,
	   kind TEXT NOT NULL, payload TEXT NOT NULL,
	   attempts INTEGER NOT NULL DEFAULT 0, next_attempt_ms INTEGER NOT NULL DEFAULT 0)`,
	// Sync-issue ledger (surfaced in the status UI; spec §4.1).
	`CREATE TABLE IF NOT EXISTS dc_issues (
	   id INTEGER PRIMARY KEY AUTOINCREMENT, space_id INTEGER, rel_path TEXT,
	   code TEXT NOT NULL, detail TEXT, at_ms INTEGER NOT NULL)`,
	`CREATE TABLE IF NOT EXISTS dc_quarantine (
	   id INTEGER PRIMARY KEY AUTOINCREMENT, space_id INTEGER NOT NULL,
	   node_id INTEGER, rel_path TEXT NOT NULL, kind TEXT NOT NULL,
	   payload TEXT NOT NULL, reason TEXT NOT NULL, at_ms INTEGER NOT NULL)`,
];

export async function applySchema(db: DbLike): Promise<void> {
	for (const stmt of DC_SCHEMA) {
		await db.exec(stmt);
	}
}

// ── row shapes as they come back from DbLike.query (snake_case columns) ────

interface NodeRow {
	node_id: number;
	space_id: number;
	parent_id: number | null;
	kind: string;
	name: string;
	head_version_id: number | null;
	content_sha256: string | null;
	size_bytes: number | null;
	deleted_at: string | null;
}
interface MirrorSqlRow {
	node_id: number;
	space_id: number;
	rel_path: string;
	disk_sha256: string | null;
	disk_size: number | null;
	disk_mtime_ms: number | null;
	base_version_id: number | null;
	materialized_of_version: number | null;
}
interface BranchMirrorSqlRow {
	node_id: number;
	branch_id: number;
	rel_path: string;
	disk_sha256: string | null;
	disk_size: number | null;
	disk_mtime_ms: number | null;
	base_version_id: number | null;
}
interface OutboundSqlRow {
	id: number;
	space_id: number;
	kind: OutboundKind;
	payload: string;
	attempts: number;
	next_attempt_ms: number;
}
interface IssueSqlRow {
	space_id: number | null;
	rel_path: string | null;
	code: string;
	detail: string | null;
	at_ms: number;
}

function nodeFromRow(r: NodeRow): NodeMeta {
	return {
		nodeId: r.node_id,
		spaceId: r.space_id,
		parentId: r.parent_id,
		kind: r.kind as NodeMeta['kind'],
		name: r.name,
		deletedAt: r.deleted_at,
		headVersionId: r.head_version_id,
		contentSha256: r.content_sha256,
		sizeBytes: r.size_bytes,
		contentType: null,
	};
}
function mirrorFromRow(r: MirrorSqlRow): MirrorRow {
	return {
		nodeId: r.node_id,
		spaceId: r.space_id,
		relPath: r.rel_path,
		diskSha256: r.disk_sha256,
		diskSize: r.disk_size,
		diskMtimeMs: r.disk_mtime_ms,
		baseVersionId: r.base_version_id,
		materializedOfVersion: r.materialized_of_version,
	};
}
function branchMirrorFromRow(r: BranchMirrorSqlRow): BranchMirrorRow {
	return {
		nodeId: r.node_id,
		branchId: r.branch_id,
		relPath: r.rel_path,
		diskSha256: r.disk_sha256,
		diskSize: r.disk_size,
		diskMtimeMs: r.disk_mtime_ms,
		baseVersionId: r.base_version_id,
	};
}
function outboundFromRow(r: OutboundSqlRow): OutboundRow {
	return {
		id: r.id,
		spaceId: r.space_id,
		kind: r.kind,
		payload: JSON.parse(r.payload) as unknown,
		attempts: r.attempts,
		nextAttemptMs: r.next_attempt_ms,
	};
}

const LEGACY_CURSOR_KEY = (spaceId: number) => `cursor:${spaceId}`;
const SYNC_STATE_KEY = (spaceId: number) => `sync-v2:${spaceId}`;
const ROOT_CAPS_KEY = (spaceId: number) => `root-caps:${spaceId}`;

export class SqlMirrorIndex {
	constructor(private db: DbLike) {}

	// ── dc_meta: cursor per space ──────────────────────────────────────────

	async getSyncState(spaceId: number): Promise<DriveSyncStateV2> {
		const rows = await this.db.query<{ v: string }>(`SELECT v FROM dc_meta WHERE k = ?`, [SYNC_STATE_KEY(spaceId)]);
		if (rows.length > 0) {
			const parsed = JSON.parse(rows[0].v) as Partial<DriveSyncStateV2>;
			if (parsed.version === 2) return {
				version: 2,
				contentState: typeof parsed.contentState === 'string' ? parsed.contentState : null,
				accessCursor: typeof parsed.accessCursor === 'string' ? parsed.accessCursor : null,
				aclEpoch: typeof parsed.aclEpoch === 'string' ? parsed.aclEpoch : null,
			};
		}
		const legacy = await this.db.query<{ v: string }>(`SELECT v FROM dc_meta WHERE k = ?`, [LEGACY_CURSOR_KEY(spaceId)]);
		return { version: 2, contentState: legacy[0]?.v ?? null, accessCursor: null, aclEpoch: null };
	}
	async setSyncState(spaceId: number, state: DriveSyncStateV2): Promise<void> {
		await this.db.exec(`INSERT OR REPLACE INTO dc_meta (k, v) VALUES (?, ?)`, [SYNC_STATE_KEY(spaceId), JSON.stringify(state)]);
	}
	async getCursor(spaceId: number): Promise<string | null> {
		return (await this.getSyncState(spaceId)).contentState;
	}
	async setCursor(spaceId: number, token: string): Promise<void> {
		const state = await this.getSyncState(spaceId);
		await this.setSyncState(spaceId, { ...state, contentState: token, aclEpoch: state.aclEpoch ?? '0' });
	}
	async setRootCapabilities(spaceId: number, capabilities: string[]): Promise<void> {
		await this.db.exec(`INSERT OR REPLACE INTO dc_meta (k, v) VALUES (?, ?)`, [ROOT_CAPS_KEY(spaceId), JSON.stringify(capabilities)]);
	}
	async rootCapabilities(spaceId: number): Promise<string[]> {
		const rows = await this.db.query<{ v: string }>(`SELECT v FROM dc_meta WHERE k = ?`, [ROOT_CAPS_KEY(spaceId)]);
		return rows.length > 0 ? (JSON.parse(rows[0].v) as string[]) : [];
	}
	async begin(): Promise<void> { await this.db.exec('BEGIN'); }
	async commit(): Promise<void> { await this.db.exec('COMMIT'); }
	async rollback(): Promise<void> { await this.db.exec('ROLLBACK'); }
	async transaction<T>(fn: () => Promise<T>): Promise<T> {
		await this.begin();
		try { const out = await fn(); await this.commit(); return out; }
		catch (err) { await this.rollback(); throw err; }
	}

	// ── dc_nodes ─────────────────────────────────────────────────────────────

	async upsertNode(n: NodeMeta): Promise<void> {
		await this.db.exec(
			`INSERT INTO dc_nodes
			   (node_id, space_id, parent_id, kind, name, head_version_id, content_sha256, size_bytes, deleted_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(node_id) DO UPDATE SET
			   space_id=excluded.space_id,
			   parent_id=excluded.parent_id,
			   kind=excluded.kind,
			   name=excluded.name,
			   head_version_id=excluded.head_version_id,
			   content_sha256=excluded.content_sha256,
			   size_bytes=excluded.size_bytes,
			   deleted_at=excluded.deleted_at`,
			[n.nodeId, n.spaceId, n.parentId, n.kind, n.name, n.headVersionId, n.contentSha256, n.sizeBytes, n.deletedAt]
		);
		if (n.capabilities) {
			await this.db.exec(
				`INSERT OR REPLACE INTO dc_node_access (node_id, capabilities_json, traverse_only) VALUES (?, ?, ?)`,
				[n.nodeId, JSON.stringify(n.capabilities), n.traverseOnly ? 1 : 0],
			);
		}
	}

	async capabilities(nodeId: number): Promise<string[]> {
		const rows = await this.db.query<{ capabilities_json: string }>(
			`SELECT capabilities_json FROM dc_node_access WHERE node_id = ?`, [nodeId],
		);
		return rows.length > 0 ? (JSON.parse(rows[0].capabilities_json) as string[]) : [];
	}

	async nodeIds(spaceId: number): Promise<number[]> {
		const rows = await this.db.query<{ node_id: number }>(
			`SELECT node_id FROM dc_nodes WHERE space_id = ? ORDER BY node_id`, [spaceId],
		);
		return rows.map((r) => r.node_id);
	}

	async removeNodeState(nodeId: number): Promise<void> {
		await this.db.exec(`DELETE FROM dc_node_access WHERE node_id = ?`, [nodeId]);
		await this.db.exec(`DELETE FROM dc_branch_mirror WHERE node_id = ?`, [nodeId]);
		await this.db.exec(`DELETE FROM dc_versions WHERE node_id = ?`, [nodeId]);
		await this.db.exec(`DELETE FROM dc_mirror WHERE node_id = ?`, [nodeId]);
		await this.db.exec(`DELETE FROM dc_nodes WHERE node_id = ?`, [nodeId]);
	}

	async getNode(nodeId: number): Promise<NodeMeta | null> {
		const rows = await this.db.query<NodeRow>(`SELECT * FROM dc_nodes WHERE node_id = ?`, [nodeId]);
		return rows.length > 0 ? nodeFromRow(rows[0]) : null;
	}

	/** Walk parent_id -> root, joining names with '/'. Null on any gap
	 *  (an ancestor this device has never learned about). */
	async relPath(nodeId: number): Promise<string | null> {
		const segments: string[] = [];
		let cursor: number | null = nodeId;
		let guard = 0;
		while (cursor !== null) {
			if (++guard > 1000) return null; // cycle guard — dc_nodes should never form one
			const node = await this.getNode(cursor);
			if (!node) return null;
			segments.unshift(node.name);
			cursor = node.parentId;
		}
		return segments.join('/');
	}

	async childNameExistsCI(spaceId: number, parentId: number | null, name: string): Promise<boolean> {
		const rows = await this.db.query<{ n: number }>(
			`SELECT count(*) as n FROM dc_nodes
			  WHERE space_id = ? AND parent_id IS ? AND lower(name) = lower(?) AND deleted_at IS NULL`,
			[spaceId, parentId, name]
		);
		return rows.length > 0 && Number(rows[0].n) > 0;
	}

	/** Case-insensitive child lookup by (parent, name) — the engine's
	 *  path->parentId resolution for creating a brand-new local file's node
	 *  under the right server folder (SyncEngine.resolveParent). */
	async findChildByName(spaceId: number, parentId: number | null, name: string): Promise<NodeMeta | null> {
		const rows = await this.db.query<NodeRow>(
			`SELECT * FROM dc_nodes
			  WHERE space_id = ? AND parent_id IS ? AND lower(name) = lower(?) AND deleted_at IS NULL`,
			[spaceId, parentId, name]
		);
		return rows.length > 0 ? nodeFromRow(rows[0]) : null;
	}

	// ── dc_mirror ────────────────────────────────────────────────────────────

	async getMirror(nodeId: number): Promise<MirrorRow | null> {
		const rows = await this.db.query<MirrorSqlRow>(`SELECT * FROM dc_mirror WHERE node_id = ?`, [nodeId]);
		return rows.length > 0 ? mirrorFromRow(rows[0]) : null;
	}

	/** Case-insensitive rel_path lookup — the case-insensitive-FS long tail. */
	async findByPathCI(spaceId: number, relPath: string): Promise<MirrorRow | null> {
		const rows = await this.db.query<MirrorSqlRow>(
			`SELECT * FROM dc_mirror WHERE space_id = ? AND lower(rel_path) = lower(?)`,
			[spaceId, relPath]
		);
		return rows.length > 0 ? mirrorFromRow(rows[0]) : null;
	}

	/** Move/rename pairing: candidates sharing (sha256, size) in this space. */
	async findByContent(spaceId: number, sha256: string, size: number): Promise<MirrorRow[]> {
		const rows = await this.db.query<MirrorSqlRow>(
			`SELECT * FROM dc_mirror WHERE space_id = ? AND disk_sha256 = ? AND disk_size = ?`,
			[spaceId, sha256, size]
		);
		return rows.map(mirrorFromRow);
	}

	async upsertMirror(row: MirrorRow): Promise<void> {
		await this.db.exec(
			`INSERT OR REPLACE INTO dc_mirror
			   (node_id, space_id, rel_path, disk_sha256, disk_size, disk_mtime_ms, base_version_id, materialized_of_version)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			[
				row.nodeId,
				row.spaceId,
				row.relPath,
				row.diskSha256,
				row.diskSize,
				row.diskMtimeMs,
				row.baseVersionId,
				row.materializedOfVersion,
			]
		);
	}

	async removeMirror(nodeId: number): Promise<void> {
		await this.db.exec(`DELETE FROM dc_mirror WHERE node_id = ?`, [nodeId]);
	}

	// ── dc_branch_mirror (P4 Task 17) ─────────────────────────────────────────

	async getBranchMirror(nodeId: number, branchId: number): Promise<BranchMirrorRow | null> {
		const rows = await this.db.query<BranchMirrorSqlRow>(
			`SELECT * FROM dc_branch_mirror WHERE node_id = ? AND branch_id = ?`,
			[nodeId, branchId]
		);
		return rows.length > 0 ? branchMirrorFromRow(rows[0]) : null;
	}

	/** Every branch sibling this device has materialized for one node —
	 *  reconcileBranches' basis for deciding what to remove (branch no longer
	 *  open) vs. what to (re)materialize (an open branch not yet here). */
	async branchMirrorsForNode(nodeId: number): Promise<BranchMirrorRow[]> {
		const rows = await this.db.query<BranchMirrorSqlRow>(`SELECT * FROM dc_branch_mirror WHERE node_id = ?`, [
			nodeId,
		]);
		return rows.map(branchMirrorFromRow);
	}

	/** Case-insensitive relPath lookup, space-scoped via a join through the
	 *  main file's own dc_mirror row (dc_branch_mirror carries no space_id —
	 *  see the DDL comment). The authoritative path->(node,branch) mapping
	 *  drainOutbound uses to decide a local edit targets a branch, never
	 *  parsed from the filename. */
	async findBranchMirrorByPath(spaceId: number, relPath: string): Promise<BranchMirrorRow | null> {
		const rows = await this.db.query<BranchMirrorSqlRow>(
			`SELECT bm.* FROM dc_branch_mirror bm
			   JOIN dc_mirror m ON m.node_id = bm.node_id
			  WHERE m.space_id = ? AND lower(bm.rel_path) = lower(?)`,
			[spaceId, relPath]
		);
		return rows.length > 0 ? branchMirrorFromRow(rows[0]) : null;
	}

	async upsertBranchMirror(row: BranchMirrorRow): Promise<void> {
		await this.db.exec(
			`INSERT OR REPLACE INTO dc_branch_mirror
			   (node_id, branch_id, rel_path, disk_sha256, disk_size, disk_mtime_ms, base_version_id)
			 VALUES (?, ?, ?, ?, ?, ?, ?)`,
			[row.nodeId, row.branchId, row.relPath, row.diskSha256, row.diskSize, row.diskMtimeMs, row.baseVersionId]
		);
	}

	async removeBranchMirror(nodeId: number, branchId: number): Promise<void> {
		await this.db.exec(`DELETE FROM dc_branch_mirror WHERE node_id = ? AND branch_id = ?`, [nodeId, branchId]);
	}

	// ── dc_versions (C9 — conflict-sibling materialization bookkeeping) ──────

	async isVersionMaterialized(versionId: number): Promise<boolean> {
		const rows = await this.db.query<{ n: number }>(`SELECT count(*) as n FROM dc_versions WHERE version_id = ?`, [
			versionId,
		]);
		return rows.length > 0 && Number(rows[0].n) > 0;
	}

	async addMaterializedVersion(row: {
		versionId: number;
		nodeId: number;
		relPath: string;
		sha256: string | null;
		atMs: number;
	}): Promise<void> {
		await this.db.exec(
			`INSERT OR REPLACE INTO dc_versions (version_id, node_id, rel_path, sha256, materialized_at_ms)
			 VALUES (?, ?, ?, ?, ?)`,
			[row.versionId, row.nodeId, row.relPath, row.sha256, row.atMs]
		);
	}

	// ── dc_outbound ──────────────────────────────────────────────────────────

	async enqueue(spaceId: number, kind: OutboundKind, payload: unknown): Promise<void> {
		await this.db.exec(
			`INSERT INTO dc_outbound (space_id, kind, payload, attempts, next_attempt_ms) VALUES (?, ?, ?, 0, 0)`,
			[spaceId, kind, JSON.stringify(payload)]
		);
	}

	async due(nowMs: number, limit: number): Promise<OutboundRow[]> {
		const rows = await this.db.query<OutboundSqlRow>(
			`SELECT * FROM dc_outbound WHERE next_attempt_ms <= ? ORDER BY id LIMIT ?`,
			[nowMs, limit]
		);
		return rows.map(outboundFromRow);
	}

	async ack(id: number): Promise<void> {
		await this.db.exec(`DELETE FROM dc_outbound WHERE id = ?`, [id]);
	}

	/** Is there a queued (not yet acked) 'upsert' for this node? Used by the
	 *  engine's delete-vs-edit rule (§4.4 "edit wins" — a remote trash/destroy
	 *  must not clobber a local edit this device has not uploaded yet). Scans
	 *  the JSON payload via sqlite's json_extract (json1, bundled by default). */
	async hasPendingUpsert(nodeId: number): Promise<boolean> {
		const rows = await this.db.query<{ n: number }>(
			`SELECT count(*) as n FROM dc_outbound WHERE kind = 'upsert' AND json_extract(payload, '$.nodeId') = ?`,
			[nodeId]
		);
		return rows.length > 0 && Number(rows[0].n) > 0;
	}

	async quarantineOutbound(nodeId: number, relPath: string, reason: string, atMs: number): Promise<number> {
		const rows = await this.db.query<{ id: number; space_id: number; kind: string; payload: string }>(
			`SELECT id, space_id, kind, payload FROM dc_outbound
			  WHERE json_extract(payload, '$.nodeId') = ? ORDER BY id`, [nodeId],
		);
		for (const row of rows) {
			await this.db.exec(
				`INSERT INTO dc_quarantine (space_id,node_id,rel_path,kind,payload,reason,at_ms)
				 VALUES (?, ?, ?, ?, ?, ?, ?)`,
				[row.space_id,nodeId,relPath,row.kind,row.payload,reason,atMs],
			);
			await this.db.exec(`DELETE FROM dc_outbound WHERE id = ?`, [row.id]);
		}
		return rows.length;
	}

	async quarantineIntent(spaceId: number, relPath: string, kind: string, payload: unknown, reason: string, atMs: number): Promise<void> {
		await this.db.exec(
			`INSERT INTO dc_quarantine (space_id,node_id,rel_path,kind,payload,reason,at_ms)
			 VALUES (?, NULL, ?, ?, ?, ?, ?)`,
			[spaceId,relPath,kind,JSON.stringify(payload),reason,atMs],
		);
	}

	/** attempts++, next_attempt_ms = now + min(2^attempts, 300) seconds — capped exponential backoff. */
	async bump(id: number, nowMs: number): Promise<void> {
		const rows = await this.db.query<{ attempts: number }>(`SELECT attempts FROM dc_outbound WHERE id = ?`, [id]);
		if (rows.length === 0) return;
		const attempts = rows[0].attempts + 1;
		const delaySec = Math.min(2 ** attempts, 300);
		await this.db.exec(`UPDATE dc_outbound SET attempts = ?, next_attempt_ms = ? WHERE id = ?`, [
			attempts,
			nowMs + delaySec * 1000,
			id,
		]);
	}

	// ── dc_issues ────────────────────────────────────────────────────────────

	async addIssue(i: SyncIssue & { spaceId: number }): Promise<void> {
		await this.db.exec(`INSERT INTO dc_issues (space_id, rel_path, code, detail, at_ms) VALUES (?, ?, ?, ?, ?)`, [
			i.spaceId,
			i.relPath,
			i.code,
			i.detail,
			i.atMs,
		]);
	}

	async issues(spaceId?: number): Promise<SyncIssue[]> {
		const rows =
			spaceId === undefined
				? await this.db.query<IssueSqlRow>(`SELECT * FROM dc_issues ORDER BY at_ms DESC`)
				: await this.db.query<IssueSqlRow>(`SELECT * FROM dc_issues WHERE space_id = ? ORDER BY at_ms DESC`, [
						spaceId,
					]);
		return rows.map((r) => ({
			code: r.code as SyncIssue['code'],
			relPath: r.rel_path ?? '',
			detail: r.detail ?? '',
			atMs: r.at_ms,
		}));
	}
}
