// mirror.ts — the regular-space ContentStore adapter (spec §4.1). Owns: mirror
// root (~/setjoin Drive/<space>/ — injected), disk applies (temp+rename), the
// dc_mirror disk-index discipline (sha authoritative, mtime a gate), watcher
// intake -> move-pairing -> dc_outbound, and the §4.4 materialization rules.
// It does NOT own protocol order or cursors -- that is the engine's (engine.ts,
// frozen contract, not modified here). `index` is the SAME SqlMirrorIndex
// instance the engine uses (service.ts wires one DB per space to both), which
// is how a nodeId-keyed ContentStore call resolves a disk path.
import * as fsp from 'node:fs/promises';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { CHUNK_SIZE } from '../../../../../mailserver/webmail/src/lib/drive/sync/types.js';
import type {
	ChunkRef,
	DownloadPlan,
	LocalChange,
	Manifest,
	MirrorContentStore,
	RevocationOutcome,
	SyncIssue,
} from '../../../../../mailserver/webmail/src/lib/drive/sync/types.js';
import { dedupeName, isIgnoredName } from '../../../../../mailserver/webmail/src/lib/drive/sync/names.js';
import type { SqlMirrorIndex } from '../../../../../mailserver/webmail/src/lib/drive/sync/schema.js';
import { hashFile, readChunk } from './hash.js';
import { MirrorWatcher } from './watcher.js';

/** The 3 protocol calls FolderMirror makes directly (upload/download bytes) --
 *  a deliberately narrow slice of DriveHttp, mirroring engine.ts's own
 *  DriveHttpLike pattern. Everything else (versions, nodes, cursors) is the
 *  engine's job. */
export interface MirrorHttp {
	headChunk(spaceId: number, sha256: string): Promise<boolean>;
	pushChunk(spaceId: number, sha256: string, bytes: Uint8Array): Promise<void>;
	contentRange(versionId: number, start: number, endIncl: number): Promise<Uint8Array>;
}

export interface FolderMirrorDeps {
	root: string;
	spaceId: number;
	http: MirrorHttp;
	index: SqlMirrorIndex;
	platform?: NodeJS.Platform;
	renameFn?: (oldPath: string, newPath: string) => Promise<void>;
	removeFn?: (targetPath: string) => Promise<void>;
	renameMaxAttempts?: number;
	renameRetryMs?: number;
	/** Move/rename pairing window (default 5s, spec's "within 5 s" test). */
	movePairMs?: number;
	now?: () => number;
}

interface PendingDelete {
	relPath: string;
	nodeId: number;
	sha256: string;
	size: number;
	baseVersionId: number | null;
	materializedOfVersion: number | null;
	timer: ReturnType<typeof setTimeout>;
}

class UnsafeMirrorPathError extends Error {}

/** FolderMirror: the regular/plaintext-space adapter. `implements
 *  MirrorContentStore` is asserted at the bottom of this file (Task 9 rule 10 --
 *  compile-time conformance). */
export class FolderMirror implements MirrorContentStore {
	private watcher: MirrorWatcher | null = null;
	private queue: LocalChange[] = [];
	private pendingDeletes = new Map<string, PendingDelete>();

	constructor(private deps: FolderMirrorDeps) {}

	// ── path helpers ──────────────────────────────────────────────────────────

	private absPath(relPath: string): string {
		// Server paths are portable slash-separated relative names.  Treat a
		// backslash as a separator even on POSIX so a name accepted on one host
		// cannot become `..\outside` when the same mirror is opened on Windows.
		const portable = relPath.replace(/\\/g, '/');
		const segments = portable.split('/');
		if (
			relPath.length === 0 ||
			path.posix.isAbsolute(portable) ||
			path.win32.isAbsolute(relPath) ||
			relPath.includes('\\') ||
			segments.some((segment) => segment.length === 0 || segment === '.' || segment === '..')
		) {
			throw new UnsafeMirrorPathError(`unsafe Drive mirror path: ${JSON.stringify(relPath)}`);
		}
		const root = path.resolve(this.deps.root);
		const candidate = path.resolve(root, ...segments);
		const relative = path.relative(root, candidate);
		if (relative === '..' || relative.startsWith(`..${path.sep}`) || path.isAbsolute(relative)) {
			throw new UnsafeMirrorPathError(`Drive mirror path escapes root: ${JSON.stringify(relPath)}`);
		}
		return this.confineWithinRoot(candidate, relPath);
	}

	/**
	 * Realpath confinement for a lexically-validated mirror path. Lexical
	 * checks cannot see a parent-directory symlink planted INSIDE the mirror
	 * root: a download/rename/remove walking such a parent would act outside
	 * the root. Every symlink hop in the candidate's ancestor chain is
	 * resolved and checked to stay inside the root's own resolved location —
	 * the same realpath-on-BOTH-sides discipline as handlers/drive.ts's
	 * isPathInsideRoots. Semantics:
	 *   - the FINAL component is deliberately never symlink-resolved:
	 *     removing a symlinked entry must unlink the link, never follow it to
	 *     the target (reads of symlinked files stay the scan/watcher's
	 *     recorded-issue business, unchanged);
	 *   - a root that does not exist YET resolves lexically — no planted
	 *     symlink can exist below a directory that does not exist;
	 *   - any unresolvable hop (EACCES/ELOOP/…) fails closed.
	 */
	private confineWithinRoot(candidate: string, relPath: string): string {
		const root = path.resolve(this.deps.root);
		let base: string;
		try {
			base = fs.realpathSync(root);
		} catch {
			base = root;
		}
		const ensureInside = (resolved: string): void => {
			const rel = path.relative(base, resolved);
			if (
				rel === '' ||
				rel === '..' ||
				rel.startsWith(`..${path.sep}`) ||
				path.isAbsolute(rel)
			) {
				throw new UnsafeMirrorPathError(
					`Drive mirror path escapes the root through a parent symlink: ${JSON.stringify(relPath)}`,
				);
			}
		};
		let current = base;
		const unresolved: string[] = [];
		const segments = path.relative(root, candidate).split(path.sep);
		const last = segments.pop() as string; // never empty: lexical checks refuse empty relPaths
		for (const segment of segments) {
			if (unresolved.length > 0) {
				unresolved.push(segment);
				continue;
			}
			const next = path.join(current, segment);
			let st: fs.Stats;
			try {
				st = fs.lstatSync(next);
			} catch {
				// Nothing exists here yet — everything below is created inside the
				// already-confined `current`, so the remaining segments need no
				// symlink resolution.
				unresolved.push(segment);
				continue;
			}
			if (!st.isSymbolicLink()) {
				current = next;
				continue;
			}
			try {
				current = fs.realpathSync(next);
			} catch {
				throw new UnsafeMirrorPathError(
					`Drive mirror path traverses an unresolvable symlink: ${JSON.stringify(relPath)}`,
				);
			}
			ensureInside(current);
		}
		// The final component joins unresolved: it is never symlink-resolved
		// (removing a symlinked entry must unlink the link, never follow it).
		unresolved.push(last);
		return path.join(current, ...unresolved);
	}
	private relOf(abs: string): string {
		return path.relative(this.deps.root, abs).split(path.sep).join('/');
	}
	private now(): number {
		return this.deps.now?.() ?? Date.now();
	}
	private push(c: LocalChange): void {
		this.queue.push(c);
	}

	/** Resolve where nodeId's content lives on disk. Prefers `dc_mirror`
	 *  (FolderMirror's own disk-state record, populated the instant a node is
	 *  created — including a brand-new LOCAL upload that has never round-
	 *  tripped through a remote apply and so has no `dc_nodes` row yet);
	 *  falls back to the `dc_nodes` walk (`index.relPath`, the server-tree
	 *  mirror populated by `applyNode`) for a remote-only node dc_mirror
	 *  hasn't recorded. Bug found via the Task 13 convergence suite: using
	 *  `index.relPath` alone here made every brand-new local upload silently
	 *  no-op (readLocalManifest returned null before any hash/upload ran). */
	private async resolveDiskRelPath(nodeId: number): Promise<string | null> {
		const mirror = await this.deps.index.getMirror(nodeId);
		if (mirror) return mirror.relPath;
		return this.deps.index.relPath(nodeId);
	}
	private async recordIssue(code: SyncIssue['code'], relPath: string, detail: string): Promise<void> {
		await this.deps.index.addIssue({ spaceId: this.deps.spaceId, code, relPath, detail, atMs: this.now() });
	}

	// ── lifecycle: watcher wiring ─────────────────────────────────────────────

	async start(): Promise<void> {
		this.watcher = new MirrorWatcher({
			root: this.deps.root,
			onChange: (c) => void this.handleWatchEvent(c),
			onSkipped: (relPath, reason) => void this.recordIssue(reason, relPath, `${reason}s are not synced`),
		});
		await this.watcher.start();
	}

	async stop(): Promise<void> {
		await this.watcher?.stop();
		this.watcher = null;
		for (const p of this.pendingDeletes.values()) clearTimeout(p.timer);
		this.pendingDeletes.clear();
	}

	// ── move/rename pairing (Task 9 rule 4/7) ────────────────────────────────

	private async handleWatchEvent(c: LocalChange): Promise<void> {
		if (c.kind === 'delete') {
			const mirror = await this.deps.index.findByPathCI(this.deps.spaceId, c.relPath);
			if (!mirror || mirror.diskSha256 == null || mirror.diskSize == null) {
				this.push(c);
				return;
			}
			const timer = setTimeout(() => {
				this.pendingDeletes.delete(c.relPath);
				this.push(c); // pairing window expired -> genuine delete
			}, this.deps.movePairMs ?? 5000);
			this.pendingDeletes.set(c.relPath, {
				relPath: c.relPath,
				nodeId: mirror.nodeId,
				sha256: mirror.diskSha256,
				size: mirror.diskSize,
				baseVersionId: mirror.baseVersionId,
				materializedOfVersion: mirror.materializedOfVersion,
				timer,
			});
			return;
		}

		// upsert
		let manifest: Manifest;
		try {
			manifest = await hashFile(this.absPath(c.relPath));
		} catch {
			return; // vanished again before we could hash it -- next settle cycle handles it
		}
		const match = [...this.pendingDeletes.values()].find(
			(p) => p.sha256 === manifest.contentSha256 && p.size === manifest.size
		);
		if (match) {
			clearTimeout(match.timer);
			this.pendingDeletes.delete(match.relPath);
			await this.pairAsMoveOrRename(match, c.relPath, manifest);
			return;
		}
		this.push(c);
	}

	private async resolveParentId(relPath: string): Promise<number | null | undefined> {
		const parts = relPath.split('/');
		parts.pop();
		let parentId: number | null = null;
		for (const seg of parts) {
			const child = await this.deps.index.findChildByName(this.deps.spaceId, parentId, seg);
			if (!child) return undefined; // unknown parent -- caller falls back to a plain upsert
			parentId = child.nodeId;
		}
		return parentId;
	}

	private async pairAsMoveOrRename(oldRow: PendingDelete, newRelPath: string, manifest: Manifest): Promise<void> {
		const oldDir = path.dirname(oldRow.relPath);
		const newDir = path.dirname(newRelPath);
		const oldName = path.basename(oldRow.relPath);
		const newName = path.basename(newRelPath);

		if (oldDir !== newDir) {
			const newParentId = await this.resolveParentId(newRelPath);
			if (newParentId === undefined) {
				this.push({ kind: 'upsert', relPath: newRelPath }); // unknown parent -- can't express a move yet
				return;
			}
			await this.deps.index.enqueue(this.deps.spaceId, 'move', { nodeId: oldRow.nodeId, newParentId });
		}
		if (oldName !== newName) {
			await this.deps.index.enqueue(this.deps.spaceId, 'rename', { nodeId: oldRow.nodeId, newName });
		}

		const st = await fsp.stat(this.absPath(newRelPath)).catch(() => null);
		await this.deps.index.upsertMirror({
			nodeId: oldRow.nodeId,
			spaceId: this.deps.spaceId,
			relPath: newRelPath,
			diskSha256: manifest.contentSha256,
			diskSize: manifest.size,
			diskMtimeMs: st?.mtimeMs ?? null,
			baseVersionId: oldRow.baseVersionId,
			materializedOfVersion: oldRow.materializedOfVersion,
		});
	}

	// ── ContentStore: upload leg ──────────────────────────────────────────────

	async readLocalManifest(nodeId: number): Promise<Manifest | null> {
		const relPath = await this.resolveDiskRelPath(nodeId);
		if (!relPath) return null;
		return this.readManifestAtPath(relPath);
	}

	/** P4 Task 17: the path-keyed counterpart — a branch sibling has no
	 *  server node_id of its own (it shares the main file's), so a branch
	 *  upload addresses it by relPath directly (via dc_branch_mirror). */
	async readManifestAtPath(relPath: string): Promise<Manifest | null> {
		try {
			return await hashFile(this.absPath(relPath));
		} catch {
			return null; // vanished locally between enqueue and drain
		}
	}

	/** Reads each missing chunk's bytes straight from the node's current local
	 *  file and PUTs it. Re-derives ordinals via a fresh hash pass (the chunk
	 *  list handed in has already been filtered down from the full manifest, so
	 *  the original ordinal position isn't preserved) -- ponytail: an extra
	 *  re-hash per upload; thread ordinals through if this shows up hot. */
	async pushMissingChunks(nodeId: number, chunks: ChunkRef[]): Promise<void> {
		const relPath = await this.resolveDiskRelPath(nodeId);
		if (!relPath) throw new Error(`pushMissingChunks: no relPath known for node ${nodeId}`);
		await this.pushMissingChunksAtPath(relPath, chunks);
	}

	/** P4 Task 17: the path-keyed counterpart (branch sibling uploads). */
	async pushMissingChunksAtPath(relPath: string, chunks: ChunkRef[]): Promise<void> {
		const abs = this.absPath(relPath);
		const manifest = await hashFile(abs);
		for (const want of chunks) {
			const ordinal = manifest.chunks.findIndex((c) => c.sha256 === want.sha256 && c.size === want.size);
			if (ordinal === -1) throw new Error(`pushMissingChunksAtPath: chunk ${want.sha256} not found in ${relPath}`);
			const bytes = await readChunk(abs, ordinal, want.size);
			await this.deps.http.pushChunk(this.deps.spaceId, want.sha256, bytes);
		}
	}

	/** P4 Task 17: unconditional delete for an orphan sibling path (a
	 *  merged/discarded branch's materialization). ponytail: no dirty-guard
	 *  here, unlike nodeId-keyed `remove()` -- see the interface doc. */
	async removeAtPath(relPath: string): Promise<void> {
		await fsp.rm(this.absPath(relPath), { force: true });
	}

	async hasChunk(sha256: string): Promise<boolean> {
		return this.deps.http.headChunk(this.deps.spaceId, sha256);
	}

	/** Spec §4.1 ContentStore members reserved for a bearer-token chunk-transfer
	 *  model this engine doesn't use (uploads go through pushMissingChunks,
	 *  downloads through putLocal/materializeVersion — see types.ts's doc on
	 *  MirrorContentStore.pushMissingChunks). Kept for interface conformance;
	 *  nothing in this codebase calls them. */
	async fetchChunk(_c: ChunkRef, _url: string, _bearer: string): Promise<void> {
		throw new Error('FolderMirror.fetchChunk: unused by this engine design (see putLocal/materializeVersion)');
	}
	async pushChunk(_c: ChunkRef, _url: string, _bearer: string): Promise<void> {
		throw new Error('FolderMirror.pushChunk: unused by this engine design (see pushMissingChunks)');
	}

	// ── ContentStore: download leg ────────────────────────────────────────────

	async putLocal(nodeId: number, plan: Manifest | DownloadPlan): Promise<void> {
		if (!('headVersionId' in plan)) {
			throw new Error('FolderMirror.putLocal: only DownloadPlan is supported — this engine never downloads via a Manifest');
		}
		// Bug found via the Task 13 convergence suite: resolveCollision must
		// run ONLY the first time this node materializes at this path (an
		// untracked-local-file-shares-the-name arrival, rule 6). A node
		// already tracked in dc_mirror is receiving an ORDINARY content
		// update the engine already decided was safe to apply (echo/clean-
		// remote-ahead) — treating its own prior (now-stale) content as a
		// "foreign collision" every time renamed it aside on every update.
		const alreadyTracked = (await this.deps.index.getMirror(nodeId)) !== null;
		const relPath = await this.resolveDiskRelPath(nodeId);
		if (!relPath) throw new Error(`putLocal: no relPath known for node ${nodeId}`);

		if (this.isInvalidForPlatform(relPath)) {
			await this.recordIssue('invalid-name', relPath, 'name is not valid on this platform — kept server-side only');
			return; // swallow: engine has no try/catch around putLocal (see class doc)
		}
		if (!alreadyTracked) {
			await this.resolveCollision(relPath, plan.contentSha256, plan.size);
		}
		await this.writeDownload(relPath, plan);
	}

	/** C2: materialize a specific NON-head version at an explicit sibling path
	 *  (an orphan local file with no server node_id of its own). */
	async materializeVersion(versionId: number, relPath: string, contentSha256: string, size: number): Promise<void> {
		await this.writeDownload(relPath, { contentSha256, size, headVersionId: versionId });
	}

	private isInvalidForPlatform(relPath: string): boolean {
		try {
			this.absPath(relPath);
		} catch {
			return true;
		}
		if ((this.deps.platform ?? process.platform) !== 'win32') return false;
		const base = path.win32.basename(relPath);
		if (/[<>:"|?*\x00-\x1f]/.test(base)) return true;
		// ponytail: skip-don't-mangle -- per-platform escaping is a deferred upgrade
		return /^(con|prn|aux|nul|com\d|lpt\d)(\.|$)/i.test(base);
	}

	/** Rule 6 (adoption/collision): identical content already at the
	 *  destination -> silent adopt, no transfer needed. Different content ->
	 *  the pre-existing file is moved aside (G4 dedupe) and flagged, never
	 *  clobbered. (Simplification: a materialized-but-unedited sibling landing
	 *  here would ideally replace silently per the plan's finer rule; this
	 *  always flags a mismatch instead — safer, slightly noisier.) */
	private async resolveCollision(relPath: string, contentSha256: string, size: number): Promise<void> {
		const abs = this.absPath(relPath);
		let existing: Manifest;
		try {
			existing = await hashFile(abs);
		} catch {
			return; // nothing there yet
		}
		if (existing.contentSha256 === contentSha256 && existing.size === size) return;
		const dir = path.dirname(relPath);
		const base = path.basename(relPath);
		const siblingName = dedupeName(base, (n) => this.existsCI(dir === '.' ? n : `${dir}/${n}`));
		const siblingRel = dir === '.' ? siblingName : `${dir}/${siblingName}`;
		await fsp.rename(abs, this.absPath(siblingRel));
		await this.recordIssue('name-collision', relPath, `kept the existing local file as ${siblingName}`);
	}

	/** Streams `plan`'s bytes into `.setjoin-tmp-dl-<versionId>` IN THE
	 *  DESTINATION DIRECTORY, chunk by chunk, then atomically renames onto the
	 *  final path. A crash mid-loop leaves only the temp file (never the
	 *  destination); re-running resumes from the temp file's current size
	 *  (C16: no per-chunk verification on the download leg -- the whole-file
	 *  sha after assembly is the sole authority). */
	private async writeDownload(relPath: string, plan: DownloadPlan): Promise<void> {
		const abs = this.absPath(relPath);
		await fsp.mkdir(path.dirname(abs), { recursive: true });
		const tmp = path.join(path.dirname(abs), `.setjoin-tmp-dl-${plan.headVersionId}`);

		let offset = 0;
		try {
			offset = (await fsp.stat(tmp)).size;
		} catch {
			/* fresh download */
		}
		if (offset > plan.size) offset = 0; // stale/corrupt partial -- restart clean

		const fh = await fsp.open(tmp, offset > 0 ? 'r+' : 'w');
		try {
			while (offset < plan.size) {
				const end = Math.min(offset + CHUNK_SIZE, plan.size) - 1;
				const bytes = await this.deps.http.contentRange(plan.headVersionId, offset, end);
				await fh.write(bytes, 0, bytes.length, offset);
				offset += bytes.length;
			}
		} finally {
			await fh.close();
		}

		const manifest = await hashFile(tmp);
		if (manifest.contentSha256 !== plan.contentSha256 || manifest.size !== plan.size) {
			await fsp.unlink(tmp).catch(() => {});
			throw new Error(`putLocal: whole-file sha mismatch for ${relPath}`);
		}
		await this.atomicRename(tmp, abs);
	}

	/** Rule 2: retries a locked-file rename with backoff; exhausting attempts
	 *  cleans the temp file and records an issue rather than throwing (the
	 *  engine has no try/catch around putLocal). */
	private async atomicRename(tmp: string, dest: string): Promise<void> {
		const renameFn = this.deps.renameFn ?? ((a: string, b: string) => fsp.rename(a, b));
		const maxAttempts = this.deps.renameMaxAttempts ?? 5;
		for (let attempt = 1; ; attempt++) {
			try {
				await renameFn(tmp, dest);
				return;
			} catch (err) {
				if (attempt >= maxAttempts) {
					await fsp.unlink(tmp).catch(() => {});
					await this.recordIssue(
						'locked-file',
						this.relOf(dest),
						`could not replace the local file after ${maxAttempts} attempts: ${String(err)}`
					);
					return;
				}
				await new Promise((r) => setTimeout(r, this.deps.renameRetryMs ?? 50));
			}
		}
	}

	// ── ContentStore: the three FS verbs ──────────────────────────────────────

	async remove(nodeId: number): Promise<void> {
		const mirror = await this.deps.index.getMirror(nodeId);
		if (!mirror) return;
		const abs = this.absPath(mirror.relPath);
		let dirty = false;
		try {
			const fresh = await hashFile(abs);
			dirty = fresh.contentSha256 !== mirror.diskSha256;
		} catch {
			/* already gone -- nothing to remove */
			return;
		}
		if (dirty) {
			await this.recordIssue('unsynced-local-edit', mirror.relPath, 'kept a local edit instead of deleting');
			return;
		}
		await fsp.rm(abs, { force: true });
	}

	/** ACL revocation is deliberately different from an ordinary remote
	 *  delete: dirty or pending bytes move under the watcher-ignored
	 *  `.setjoin-quarantine` directory and are never uploaded. Clean bytes are
	 *  removed. A busy/locked file is reported so the engine does not advance
	 *  the access cursor and retries on the next pass. */
	async revoke(nodeId: number, forceQuarantine: boolean): Promise<RevocationOutcome> {
		const mirror = await this.deps.index.getMirror(nodeId);
		if (!mirror) return 'absent';
		let dirty = forceQuarantine;
		try {
			const fresh = await hashFile(this.absPath(mirror.relPath));
			dirty ||= mirror.diskSha256 == null || fresh.contentSha256 !== mirror.diskSha256;
		} catch (err) {
			if (err instanceof UnsafeMirrorPathError) throw err;
			return 'absent';
		}
		return this.revokeRelPath(mirror.relPath, dirty);
	}

	async revokePath(relPath: string, forceQuarantine: boolean): Promise<RevocationOutcome> {
		return this.revokeRelPath(relPath, forceQuarantine);
	}

	private async revokeRelPath(relPath: string, quarantine: boolean): Promise<RevocationOutcome> {
		const abs = this.absPath(relPath);
		try {
			await fsp.lstat(abs);
		} catch {
			return 'absent';
		}
		try {
			if (!quarantine) {
				if (this.deps.removeFn) await this.deps.removeFn(abs);
				else await fsp.rm(abs, { force: true });
				return 'purged';
			}
			const quarantineDir = this.absPath('.setjoin-quarantine');
			await fsp.mkdir(quarantineDir, { recursive: true, mode: 0o700 });
			const base = path.basename(relPath);
			let candidate = `${Date.now()}-${base}`;
			let ordinal = 1;
			while (fs.existsSync(path.join(quarantineDir, candidate))) {
				candidate = `${Date.now()}-${ordinal++}-${base}`;
			}
			const renameFn = this.deps.renameFn ?? fsp.rename;
			await renameFn(abs, path.join(quarantineDir, candidate));
			return 'quarantined';
		} catch (err) {
			const code = (err as NodeJS.ErrnoException).code;
			if (code === 'EBUSY' || code === 'EPERM' || code === 'EACCES') {
				await this.recordIssue('revocation-busy', relPath, 'close the file so revoked local content can be removed');
				return 'busy';
			}
			throw err;
		}
	}

	/** `nodeId` isn't needed (the move is a pure path->path FS rename; the
	 *  engine already updated the index) — kept in the signature only because
	 *  `MirrorContentStore` declares it. */
	async moveLocal(_nodeId: number, oldRelPath: string, newRelPath: string): Promise<void> {
		const oldAbs = this.absPath(oldRelPath);
		const newAbs = this.absPath(newRelPath);
		await fsp.mkdir(path.dirname(newAbs), { recursive: true });
		try {
			await fsp.rename(oldAbs, newAbs);
		} catch (err) {
			if ((err as NodeJS.ErrnoException).code === 'ENOENT') return; // already moved/missing -- next verify() converges
			throw err;
		}
	}

	async renameToSibling(nodeId: number, siblingName: string): Promise<void> {
		const relPath = await this.resolveDiskRelPath(nodeId);
		if (!relPath) return;
		const dir = path.dirname(relPath);
		const newRel = dir === '.' ? siblingName : `${dir}/${siblingName}`;
		await fsp.rename(this.absPath(relPath), this.absPath(newRel));
	}

	existsCI(relPath: string): boolean {
		const abs = this.absPath(relPath);
		const dir = path.dirname(abs);
		const base = path.basename(abs).toLowerCase();
		let entries: string[];
		try {
			entries = fs.readdirSync(dir);
		} catch {
			return false;
		}
		return entries.some((e) => e.toLowerCase() === base);
	}

	// ── spec conformance (unused by this engine, see localChanges' doc) ──────

	/** Spec §4.1 member -- no caller in this codebase drives it: SyncEngine
	 *  intake is wired directly from the watcher/scanLocal callback via
	 *  MirrorService (Task 10), not through this iterable. Drains whatever is
	 *  currently queued and completes (a real long-lived generator is unneeded
	 *  work for an interface member nothing here consumes). */
	async *localChanges(): AsyncIterable<LocalChange> {
		while (this.queue.length > 0) {
			yield this.queue.shift() as LocalChange;
		}
	}

	/** Test/service hook: pull whatever local changes have accumulated (from
	 *  the watcher and/or scanLocal) since the last drain. */
	drainLocalChanges(): LocalChange[] {
		const out = this.queue;
		this.queue = [];
		return out;
	}

	// ── lifecycle: startup reconcile + full re-verify ────────────────────────

	private async walkDisk(cb: (relPath: string, abs: string) => Promise<void>): Promise<void> {
		const walk = async (dir: string, prefix: string): Promise<void> => {
			let entries: fs.Dirent[];
			try {
				entries = await fsp.readdir(dir, { withFileTypes: true });
			} catch {
				return;
			}
			for (const e of entries) {
				if (isIgnoredName(e.name)) continue;
				const rel = prefix ? `${prefix}/${e.name}` : e.name;
				const abs = path.join(dir, e.name);
				if (e.isDirectory()) {
					await walk(abs, rel);
					continue;
				}
				await cb(rel, abs);
			}
		};
		await walk(this.deps.root, '');
	}

	/** `force=false` (scanLocal, startup reconcile): a file whose (size, mtime)
	 *  match the index is skipped -- no re-hash (the mtime-untrust rule gates
	 *  re-hashing, never cross-wire comparison). `force=true` (verify(), the
	 *  full re-hash pass wired to the bridge's `resync`): always re-hashes,
	 *  the escape hatch for a mtime-preserving edit. */
	private async scanOrVerify(force: boolean): Promise<void> {
		await this.walkDisk(async (relPath, abs) => {
			const st = await fsp.lstat(abs).catch(() => null);
			if (!st) return;
			if (st.isSymbolicLink()) {
				await this.recordIssue('symlink', relPath, 'symlinks are not synced');
				return;
			}
			const mirror = await this.deps.index.findByPathCI(this.deps.spaceId, relPath);
			if (!mirror) return; // untracked -- new-file discovery is the watcher's/engine's job, not scanLocal's
			if (!force && mirror.diskSize === st.size && mirror.diskMtimeMs === st.mtimeMs) return;
			const fresh = await hashFile(abs);
			if (fresh.contentSha256 === mirror.diskSha256) {
				await this.deps.index.upsertMirror({ ...mirror, diskSize: st.size, diskMtimeMs: st.mtimeMs });
				return;
			}
			this.push({ kind: 'upsert', relPath });
		});
	}

	async scanLocal(): Promise<void> {
		await this.scanOrVerify(false);
	}
	async verify(): Promise<void> {
		await this.scanOrVerify(true);
	}
}
