// mailserver/webmail/src/lib/drive/sync/types.ts — the ONE sync engine's
// contract (spec §4.1/§4.3). Pure types: no Svelte, no Node, no Electron
// imports anywhere in this directory — all I/O is injected, so FolderMirror
// (Electron main, P2) and VaultStore (renderer, P3) ride the identical
// engine. `.js`-suffixed relative imports (see engine.ts etc.) keep both the
// webmail Vite toolchain and the Electron tsc/esbuild toolchain happy.

export const CHUNK_SIZE = 4 * 1024 * 1024; // fixed v1 chunker (spec §3.1)
export const SHA256_EMPTY = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

export interface ChunkRef {
	sha256: string;
	size: number;
}

/** Upload-side manifest: local content, full per-chunk shas known (hashFile owns this). */
export interface Manifest {
	contentSha256: string;
	size: number;
	chunks: ChunkRef[];
}

/**
 * Download-side plan (C16): no P2-consumed route serves per-chunk shas for a
 * remote version (nodesMeta/listVersions carry only the whole-file sha;
 * downloads are Range reads over /versions/{id}/content). Chunk boundaries
 * for the download are computed from `size` + CHUNK_SIZE; the whole-file sha
 * is the sole verification authority after assembly — there is no per-chunk
 * verification on the download leg (unlike the upload leg's Manifest).
 */
export interface DownloadPlan {
	contentSha256: string;
	size: number;
	headVersionId: number;
}

export type LocalChangeKind = 'upsert' | 'delete';
export interface LocalChange {
	kind: LocalChangeKind;
	relPath: string;
}

/** Spec §4.1 — the ONLY mode-varying seam. */
export interface ContentStore {
	/** Materialize `plan`'s bytes at the path for `nodeId`. Manifest (upload
	 *  echo/adoption) or DownloadPlan (remote content) — see the type doc above. */
	putLocal(nodeId: number, plan: Manifest | DownloadPlan): Promise<void>;
	readLocalManifest(nodeId: number): Promise<Manifest | null>;
	localChanges(): AsyncIterable<LocalChange>;
	hasChunk(sha256: string): Promise<boolean>;
	fetchChunk(c: ChunkRef, url: string, bearer: string): Promise<void>;
	pushChunk(c: ChunkRef, url: string, bearer: string): Promise<void>;
	remove(nodeId: number): Promise<void>;
	/** Access revocation is stronger than ordinary remote delete. Managed
	 *  stores purge; unmanaged mirrors quarantine dirty/pending bytes and may
	 *  honestly report a busy-file residual. */
	revoke(nodeId: number, forceQuarantine: boolean): Promise<RevocationOutcome>;
}

export type RevocationOutcome = 'purged' | 'quarantined' | 'busy' | 'absent';

/**
 * `ContentStore` plus the three FS verbs the engine needs for rename/move
 * apply and conflict-sibling materialization (Task 6). FolderMirror (P2,
 * Electron main) implements all three as real filesystem operations; P3's
 * VaultStore implements `moveLocal` as a metadata-only update and
 * `renameToSibling` as a no-op (the viewer shows a conflict banner instead of
 * a second file) — documented here, not a mode conditional in the engine.
 */
export interface MirrorContentStore extends ContentStore {
	moveLocal(nodeId: number, oldRelPath: string, newRelPath: string): Promise<void>;
	renameToSibling(nodeId: number, siblingName: string): Promise<void>;
	/** Case-insensitive existence check in the store's own namespace (disk dir listing). */
	existsCI(relPath: string): boolean;
	/**
	 * Upload-leg byte transfer for the chunks the engine's HEAD-check found
	 * missing server-side. The store reads each chunk's bytes from `nodeId`'s
	 * local file and PUTs it (own DriveHttp reference) — the engine only ever
	 * decides WHICH chunks are missing (network dedup check via headChunk),
	 * never touches raw bytes itself. Not part of the spec §4.1 ContentStore
	 * (which reserves fetchChunk/pushChunk for a bearer-token-based transfer
	 * this engine design does not use — see protocol.ts's doc comment).
	 */
	pushMissingChunks(nodeId: number, chunks: ChunkRef[]): Promise<void>;
	/**
	 * C2: materialize a specific NON-head version's content at an explicit
	 * sibling path — the path by which a conflict this device did not create
	 * (discovered via listVersions) still reaches this device. Distinct from
	 * `putLocal` (which is always keyed by a real server node_id resolved
	 * through dc_mirror): a conflict sibling is an orphan local file with no
	 * node_id of its own, so it is addressed by relPath directly.
	 */
	materializeVersion(versionId: number, relPath: string, contentSha256: string, size: number): Promise<void>;
	/**
	 * P4 Task 17: hash whatever is currently on disk at an explicit relPath —
	 * the upload-leg read counterpart to `materializeVersion`'s download-leg
	 * write. A branch sibling is addressed by relPath (via dc_branch_mirror),
	 * never by nodeId — `readLocalManifest`/`pushMissingChunks` stay
	 * nodeId-keyed (main file only) so this is a distinct pair, not an
	 * overload.
	 */
	readManifestAtPath(relPath: string): Promise<Manifest | null>;
	/** The path-keyed counterpart to `pushMissingChunks` (P4 Task 17 branch uploads). */
	pushMissingChunksAtPath(relPath: string, chunks: ChunkRef[]): Promise<void>;
	/** Deletes whatever is at relPath, unconditionally (P4 Task 17: a
	 *  merged/discarded branch's sibling is removed on the next reconcile —
	 *  ponytail: no dirty-guard here, unlike nodeId-keyed `remove()` — a
	 *  mid-edit sibling deletion on merge/discard is an accepted P4 v1 edge
	 *  case; upgrade path is a dirty check against the dc_branch_mirror row's
	 *  own diskSha256 if this bites in practice. */
	removeAtPath(relPath: string): Promise<void>;
	/** Revocation counterpart for branch/conflict siblings addressed only by
	 *  path. Unmanaged adapters quarantine dirty bytes; managed adapters purge. */
	revokePath(relPath: string, forceQuarantine: boolean): Promise<RevocationOutcome>;
}

export type DriveOp =
	| 'create'
	| 'update'
	| 'move'
	| 'rename'
	| 'trash'
	| 'restore'
	| 'destroy'
	| 'member'
	| 'space';
export interface DriveChange {
	nodeId: number;
	op: DriveOp;
	seq: number;
}
export interface ChangesPage {
	newState: string;
	changed: DriveChange[];
	hasMore: boolean;
}

export interface AccessInvalidation {
	anchorNodeId: string | null;
	epoch: string;
	reason: string;
	fullReconcile: boolean;
}

export interface AccessInvalidationPage {
	cursor: string | null;
	epoch: string | null;
	invalidations: AccessInvalidation[];
	hasMore: boolean;
	fullReconcile: boolean;
	reason?: 'cursorUnavailable' | 'cursorExpired' | 'accessRevoked';
}

export interface VisibilityPage {
	epoch: string;
	rootCapabilities: string[];
	nodes: NodeMeta[];
	nextAfter: string;
	hasMore: boolean;
}

export interface DriveSyncStateV2 {
	version: 2;
	contentState: string | null;
	accessCursor: string | null;
	aclEpoch: string | null;
}

export interface NodeMeta {
	nodeId: number;
	spaceId: number;
	parentId: number | null;
	kind: 'folder' | 'file';
	name: string;
	deletedAt: string | null;
	headVersionId: number | null;
	contentSha256: string | null;
	sizeBytes: number | null;
	contentType: string | null;
	/** Open+review branch count (P4 Task 17) — carried only by the LIVE
	 *  `nodesMeta()` read (not persisted in dc_nodes: it's a live reconcile
	 *  signal, not durable state). Optional/undefined everywhere else
	 *  (tree(), the local dc_nodes reconstruction) — treat as 0. */
	branchCount?: number;
	/** Present on stable visibility pages. Incremental metadata may omit it;
	 *  the local access satellite is then preserved until the next ACL page. */
	capabilities?: string[];
	traverseOnly?: boolean;
}

/** A live (unexpired) lock row from `GET /drive/spaces/{id}/locks` (P4
 *  drive_lock_list) — camelCase 1:1 with the server's jsonb shape, no wire
 *  translation needed. */
export interface LockRow {
	nodeId: number;
	name: string;
	holderId: number;
	holderName: string | null;
	mode: 'soft' | 'hard';
	branchId: number | null;
	acquiredAt: string;
	expiresAt: string;
	deviceLabel: string | null;
}

export interface SyncIssue {
	code:
		| 'quota'
		| 'name-collision'
		| 'locked-file'
		| 'invalid-name'
		| 'symlink'
		| 'unsynced-local-edit'
		| 'transfer-failed'
		| 'access-revoked'
		| 'revocation-busy'
		| 'traverse-only'
		| 'permission-denied';
	relPath: string;
	detail: string;
	atMs: number;
}

/** Minimal SQL surface (offline-core dbExec/dbQuery shape; node:sqlite in tests). */
export interface DbLike {
	exec(sql: string, params?: unknown[]): Promise<number>;
	query<T = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<T[]>;
}
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

// ── dc_* row shapes (schema.ts / SqlMirrorIndex) ────────────────────────────

/** A dc_mirror row: this device's disk-state record for a synced node.
 *  `diskSha256` IS the last-synced sha (C8) — "dirty" means a freshly-hashed
 *  disk sha differs from this column; there is no separate lastSyncedSha
 *  column. `materializedOfVersion` is set when this path is a conflict-
 *  sibling materialization of a non-head version (§4.4) — such rows never
 *  upload while unedited. */
export interface MirrorRow {
	nodeId: number;
	spaceId: number;
	relPath: string;
	diskSha256: string | null;
	diskSize: number | null;
	diskMtimeMs: number | null;
	baseVersionId: number | null;
	materializedOfVersion: number | null;
}

export type OutboundKind = 'upsert' | 'delete' | 'move' | 'rename';
export interface OutboundRow {
	id: number;
	spaceId: number;
	kind: OutboundKind;
	payload: unknown;
	attempts: number;
	nextAttemptMs: number;
}

/** A dc_branch_mirror row (P4 Task 17): this device's disk-state record for
 *  ONE open branch's materialized sibling file. Keyed by (nodeId, branchId)
 *  — a distinct satellite table from dc_mirror (PK nodeId), so a file with
 *  branches gets one dc_mirror row (main) plus one dc_branch_mirror row per
 *  locally-materialized open branch. No space_id column: space scoping is
 *  derived by joining through the main file's own dc_mirror row (the branch
 *  can't exist locally before the main file is synced). */
export interface BranchMirrorRow {
	nodeId: number;
	branchId: number;
	relPath: string;
	diskSha256: string | null;
	diskSize: number | null;
	diskMtimeMs: number | null;
	baseVersionId: number | null;
}

/** The subset of `GET /drive/files/{id}/branches`' branchOut wire shape the
 *  sync engine needs to reconcile local siblings (P4 Task 17). */
export interface BranchMeta {
	id: number;
	name: string;
	status: 'open' | 'review' | 'merged' | 'discarded';
	headVersionId: number;
	forkedFromVersionId: number;
}
