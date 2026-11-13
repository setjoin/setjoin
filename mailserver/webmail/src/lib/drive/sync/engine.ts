// engine.ts — ONE two-way delta pass per call. Deliberately single-flight,
// per-space (the caller serializes; parallel spaces are separate engines).
// Order per pass: (1) drain outbound (local wins -> server, conflicts surface
// here), (2) pull the feed since cursor and apply, (3) persist cursor. All
// applies are sha-compared and therefore idempotent -- crash anywhere, re-run,
// converge (spec §4.2's "all steps idempotent, retry-safe resume").
//
// Local-change intake (`onLocalChange`) also lives here, not in the watcher
// (Task 8's note: "exclusion is the engine's job, not the watcher's -- one
// owner"). It resolves a brand-new local file's server-side node eagerly (at
// intake, not at drain time) so every `dc_outbound` 'upsert' row always
// carries a real, already-created node_id -- matching ContentStore's
// nodeId-keyed contract (`readLocalManifest`/`putLocal` take no relPath).
import { branchSiblingName, conflictSiblingName, dedupeName } from './names.js';
import { DriveApiError, type PutVersionBody, type PutVersionResult, type VersionMeta } from './protocol.js';
import type { SqlMirrorIndex } from './schema.js';
import type {
	AccessInvalidationPage,
	BranchMeta,
	ChunkRef,
	DownloadPlan,
	DriveChange,
	Manifest,
	MirrorContentStore,
	NodeMeta,
	OutboundRow,
	SyncIssue,
	VisibilityPage,
} from './types.js';

export type ChangesResult =
	| { resync: true }
	| { resync: false; newState: string; changed: DriveChange[]; hasMore: boolean };

/** The subset of DriveHttp the engine calls -- lets tests supply a fake
 *  without instantiating the real HTTP class (DriveHttp structurally
 *  satisfies this already). */
export interface DriveHttpLike {
	changes(spaceId: number, since: string | null, max?: number): Promise<ChangesResult>;
	accessInvalidations(spaceId: number, cursor: string | null, max?: number): Promise<AccessInvalidationPage>;
	visibilitySnapshot(
		spaceId: number,
		after: string,
		expectedEpoch: string | null,
		max?: number,
	): Promise<VisibilityPage>;
	nodesMeta(ids: number[]): Promise<NodeMeta[]>;
	treeChildren(spaceId: number, parentId: number | null): Promise<NodeMeta[]>;
	headChunk(spaceId: number, sha256: string): Promise<boolean>;
	putVersion(fileNodeId: number, body: PutVersionBody): Promise<PutVersionResult>;
	listVersions(fileNodeId: number): Promise<VersionMeta[]>;
	createNode(
		spaceId: number,
		parentId: number | null,
		kind: 'file' | 'folder',
		name: string,
		contentType?: string
	): Promise<number>;
	renameNode(nodeId: number, newName: string): Promise<void>;
	moveNode(nodeId: number, newParentId: number | null): Promise<void>;
	trashNode(nodeId: number): Promise<void>;
	restoreNode(nodeId: number): Promise<void>;
	/** P4 Task 17: live open/review branches for a file — reconcileBranches'
	 *  basis for deciding which siblings should exist locally. */
	fileBranches(fileNodeId: number): Promise<BranchMeta[]>;
}

export interface EngineDeps {
	http: DriveHttpLike;
	index: SqlMirrorIndex;
	store: MirrorContentStore;
	spaceId: number;
	deviceLabel: string;
	isExcluded(relPath: string): boolean;
	todayYmd(): string;
	now(): number;
}

interface UpsertPayload {
	nodeId: number;
	/** P4 Task 17: present only when this upsert targets a materialized
	 *  branch sibling — main mirror uploads never carry this field. */
	branchId?: number;
}
interface DeletePayload {
	nodeId: number;
}
interface RenamePayload {
	nodeId: number;
	newName: string;
}
interface MovePayload {
	nodeId: number;
	newParentId: number | null;
}

export class SyncEngine {
	constructor(private d: EngineDeps) {}

	// ── local-change intake ──────────────────────────────────────────────────

	async onLocalChange(change: { kind: 'upsert' | 'delete'; relPath: string }): Promise<void> {
		if (this.d.isExcluded(change.relPath)) return; // guard at intake — never enqueued

		// The watcher may report a local edit before this engine has completed its
		// first sync pass (for example immediately after enabling a desktop
		// mirror).  Capability state is deny-by-default, so establish the stable
		// visibility snapshot before deciding whether the edit may be enqueued.
		// This is deliberately only a bootstrap call: every normal sync pass still
		// reconciles invalidations before draining outbound work, which closes the
		// revoke-between-intake-and-upload race.
		const syncState = await this.d.index.getSyncState(this.d.spaceId);
		if (syncState.aclEpoch === null) await this.reconcileAccess();

		// P4 Task 17: a branch-sibling path always wins over the main mirror —
		// the local index maps path<->(node,branch) authoritatively, never
		// parsed from the filename.
		const branchMirror = await this.d.index.findBranchMirrorByPath(this.d.spaceId, change.relPath);
		if (branchMirror) {
			if (change.kind === 'delete') {
				// ponytail: a locally-deleted sibling is NOT propagated as a
				// branch discard (deleting a file ≠ discarding a branch) — the
				// local row just drops; the next reconcile re-materializes it
				// if the branch is still open.
				await this.d.index.removeBranchMirror(branchMirror.nodeId, branchMirror.branchId);
				return;
			}
			if (!(await this.nodeAllows(branchMirror.nodeId, 'modify_content'))) {
				await this.d.index.enqueue(this.d.spaceId, 'upsert', {
					nodeId: branchMirror.nodeId,
					branchId: branchMirror.branchId,
				} satisfies UpsertPayload);
				await this.d.index.quarantineOutbound(
					branchMirror.nodeId, change.relPath, 'permission-denied', this.d.now(),
				);
				await this.d.store.revokePath(change.relPath, true);
				await this.d.index.removeBranchMirror(branchMirror.nodeId, branchMirror.branchId);
				await this.recordIssue(
					'permission-denied', change.relPath,
					'local branch edit was quarantined; modify permission is required',
				);
				return;
			}
			await this.d.index.enqueue(this.d.spaceId, 'upsert', {
				nodeId: branchMirror.nodeId,
				branchId: branchMirror.branchId,
			} satisfies UpsertPayload);
			return;
		}

		const existing = await this.d.index.findByPathCI(this.d.spaceId, change.relPath);

		if (change.kind === 'delete') {
			if (existing) {
				if (!(await this.nodeAllows(existing.nodeId, 'delete'))) {
					await this.quarantineExistingChange(change, existing.nodeId, 'delete');
					return;
				}
				await this.d.index.enqueue(this.d.spaceId, 'delete', { nodeId: existing.nodeId } satisfies DeletePayload);
			}
			return;
		}

		if (existing) {
			if (!(await this.nodeAllows(existing.nodeId, 'modify_content'))) {
				await this.quarantineExistingChange(change, existing.nodeId, 'modify_content');
				return;
			}
			await this.d.index.enqueue(this.d.spaceId, 'upsert', { nodeId: existing.nodeId } satisfies UpsertPayload);
			return;
		}

		const parent = await this.resolveParent(change.relPath);
		if (!parent) {
			await this.recordIssue('invalid-name', change.relPath, 'parent folder not yet known to the mirror');
			return;
		}
		const parentCaps = parent.parentId == null
			? await this.d.index.rootCapabilities(this.d.spaceId)
			: await this.d.index.capabilities(parent.parentId);
		if (!parentCaps.includes('create_child')) {
			await this.d.index.quarantineIntent(
				this.d.spaceId,change.relPath,'upsert',change,'traverse-only',this.d.now(),
			);
			const outcome = await this.d.store.revokePath(change.relPath, true);
			if (outcome === 'busy') {
				await this.recordIssue(
					'revocation-busy',change.relPath,
					'close the file so the denied local create can be quarantined',
				);
				return;
			}
			await this.recordIssue('traverse-only',change.relPath,'local change kept in quarantine; create permission is required');
			return;
		}
		const nodeId = await this.d.http.createNode(this.d.spaceId, parent.parentId, 'file', parent.name);
		await this.d.index.upsertMirror({
			nodeId,
			spaceId: this.d.spaceId,
			relPath: change.relPath,
			diskSha256: null,
			diskSize: null,
			diskMtimeMs: null,
			baseVersionId: null,
			materializedOfVersion: null,
		});
		await this.d.index.enqueue(this.d.spaceId, 'upsert', { nodeId } satisfies UpsertPayload);
	}

	private async nodeAllows(nodeId: number, capability: string): Promise<boolean> {
		// A brand-new local node has a server id and mirror row before the next
		// visibility page creates its dc_nodes/access satellite. Its parent
		// create_child decision already authorized intake; commit is rechecked by
		// the server. Every known remote node fails closed on missing capability.
		if ((await this.d.index.getNode(nodeId)) == null) return true;
		return (await this.d.index.capabilities(nodeId)).includes(capability);
	}

	private async quarantineExistingChange(
		change: { kind: 'upsert' | 'delete'; relPath: string },
		nodeId: number,
		requiredCapability: string,
	): Promise<void> {
		await this.d.index.enqueue(this.d.spaceId, change.kind, { nodeId });
		await this.d.index.quarantineOutbound(nodeId, change.relPath, 'permission-denied', this.d.now());
		if (change.kind === 'upsert') {
			const outcome = await this.d.store.revoke(nodeId, true);
			if (outcome === 'busy') {
				await this.recordIssue(
					'revocation-busy',change.relPath,
					'close the file so the denied local edit can be quarantined',
				);
				return;
			}
		}
		await this.restoreAuthoritativeNode(nodeId);
		await this.recordIssue(
			'permission-denied',change.relPath,
			`local ${change.kind} was quarantined; ${requiredCapability} permission is required`,
		);
	}

	private async restoreAuthoritativeNode(nodeId: number): Promise<void> {
		await this.d.index.removeMirror(nodeId);
		const [meta] = await this.d.http.nodesMeta([nodeId]);
		if (meta) await this.applyNode(meta);
	}

	/** Walks a relPath's directory segments through the known dc_nodes tree to
	 *  find the real parent node_id. Null on a gap (a parent folder this
	 *  device hasn't learned a node_id for yet — issue'd by the caller, never
	 *  silently guessed). */
	private async resolveParent(relPath: string): Promise<{ parentId: number | null; name: string } | null> {
		const parts = relPath.split('/');
		const name = parts.pop();
		if (name === undefined) return null;
		let parentId: number | null = null;
		for (const seg of parts) {
			const child = await this.d.index.findChildByName(this.d.spaceId, parentId, seg);
			if (!child) return null;
			parentId = child.nodeId;
		}
		return { parentId, name };
	}

	private async recordIssue(code: SyncIssue['code'], relPath: string, detail: string): Promise<void> {
		// Bounded issue ledger: a sibling that fails identically on EVERY pass
		// (persistent ACL churn, a poisoned file) must not append a fresh
		// dc_issues row per pass — an open (code, relPath) entry is refreshed in
		// place instead of growing the ledger without bound. A genuinely new
		// (code, relPath) pair still records immediately.
		const open = await this.d.index.issues(this.d.spaceId);
		if (open.some((issue) => issue.code === code && issue.relPath === relPath)) return;
		await this.d.index.addIssue({ spaceId: this.d.spaceId, code, relPath, detail, atMs: this.d.now() });
	}

	// ── the one two-way delta pass ───────────────────────────────────────────

	async syncOnce(): Promise<{ uploaded: number; downloaded: number; issues: number }> {
		const access = await this.reconcileAccess();
		const up = await this.drainOutbound();
		const down = await this.pullAndApply();
		return {
			uploaded: up.uploaded,
			downloaded: access.downloaded + down.downloaded,
			issues: access.issues + up.issues + down.issues,
		};
	}

	private async reconcileAccess(): Promise<{ downloaded: number; issues: number }> {
		const state = await this.d.index.getSyncState(this.d.spaceId);
		const page = await this.d.http.accessInvalidations(this.d.spaceId,state.accessCursor);
		const epochChanged = page.epoch != null && page.epoch !== state.aclEpoch;
		if (state.aclEpoch == null || page.fullReconcile || page.invalidations.length > 0 || epochChanged) {
			return this.fullVisibilityReconcile(page.cursor,page.epoch);
		}
		if (page.cursor !== state.accessCursor) {
			await this.d.index.setSyncState(this.d.spaceId,{...state,accessCursor:page.cursor,aclEpoch:page.epoch});
		}
		return { downloaded: 0, issues: 0 };
	}

	// ── upload leg ────────────────────────────────────────────────────────────

	private async drainOutbound(): Promise<{ uploaded: number; issues: number }> {
		const now = this.d.now();
		const rows = await this.d.index.due(now, 50);
		let uploaded = 0;
		let issues = 0;
		for (const row of rows) {
			try {
				if (await this.quarantineUnauthorizedOutbound(row)) {
					issues++;
					continue;
				}
				if (row.kind === 'upsert') {
					if (await this.uploadOne(row)) uploaded++;
				} else if (row.kind === 'delete') {
					await this.trashOne(row.payload as DeletePayload);
				} else if (row.kind === 'rename') {
					const p = row.payload as RenamePayload;
					await this.d.http.renameNode(p.nodeId, p.newName);
				} else if (row.kind === 'move') {
					const p = row.payload as MovePayload;
					await this.d.http.moveNode(p.nodeId, p.newParentId);
				}
				await this.d.index.ack(row.id);
			} catch (err) {
				if (err instanceof DriveApiError && err.status === 409 && err.code === 'BZ254') {
					issues++;
					await this.d.index.bump(row.id, now);
					await this.recordIssue(
						'transfer-failed','',
						'access generation changed during upload; will reconcile and retry',
					);
				} else if (err instanceof DriveApiError && (err.status === 403 || err.status === 404)) {
					issues++;
					await this.quarantineRejectedOutbound(row);
				} else if (err instanceof DriveApiError && err.status < 500) {
					issues++;
					const payload = row.payload as { nodeId?: number; branchId?: number };
					let relPath = '';
					if (payload.nodeId != null) {
						relPath =
							payload.branchId != null
								? ((await this.d.index.getBranchMirror(payload.nodeId, payload.branchId))?.relPath ?? '')
								: ((await this.d.index.getMirror(payload.nodeId))?.relPath ?? '');
					}
					await this.recordIssue(mapErrorToIssueCode(err), relPath, err.message);
					await this.d.index.ack(row.id); // a 4xx never retry-loops
				} else {
					await this.d.index.bump(row.id, now); // 5xx / network — capped backoff
				}
			}
		}
		return { uploaded, issues };
	}

	private outboundNode(row: OutboundRow): { nodeId: number; required: string } | null {
		const nodeId = (row.payload as { nodeId?: number }).nodeId;
		if (nodeId == null) return null;
		const required = row.kind === 'upsert' ? 'modify_content'
			: row.kind === 'delete' ? 'delete'
			: row.kind === 'rename' ? 'rename'
			: row.kind === 'move' ? 'move'
			: null;
		return required ? { nodeId, required } : null;
	}

	private async quarantineUnauthorizedOutbound(row: OutboundRow): Promise<boolean> {
		const target = this.outboundNode(row);
		if (!target || await this.nodeAllows(target.nodeId, target.required)) return false;
		await this.quarantineRejectedOutbound(row, target.required);
		return true;
	}

	private async quarantineRejectedOutbound(row: OutboundRow, required = 'current access'): Promise<void> {
		const target = this.outboundNode(row);
		if (!target) {
			await this.d.index.ack(row.id);
			return;
		}
		const mirror = await this.d.index.getMirror(target.nodeId);
		const relPath = mirror?.relPath ?? (await this.d.index.relPath(target.nodeId)) ?? '';
		await this.d.index.quarantineOutbound(target.nodeId, relPath, 'permission-denied', this.d.now());
		if (row.kind === 'upsert') {
			const outcome = await this.d.store.revoke(target.nodeId, true);
			if (outcome === 'busy') {
				await this.recordIssue(
					'revocation-busy',relPath,
					'close the file so rejected local work can be quarantined',
				);
				return;
			}
		}
		await this.restoreAuthoritativeNode(target.nodeId);
		await this.recordIssue(
			'permission-denied',relPath,
			`local operation was quarantined; ${required} permission is required`,
		);
	}

	private async trashOne(p: DeletePayload): Promise<void> {
		try {
			await this.d.http.trashNode(p.nodeId);
		} catch (err) {
			if (err instanceof DriveApiError && err.status === 404) return; // already gone server-side
			throw err;
		}
	}

	private async uploadOne(row: OutboundRow): Promise<boolean> {
		const { nodeId, branchId } = row.payload as UpsertPayload;
		if (branchId != null) return this.uploadBranchOne(nodeId, branchId);

		const manifest = await this.d.store.readLocalManifest(nodeId);
		if (!manifest) return false; // vanished locally between enqueue and drain — nothing to upload

		const missing: ChunkRef[] = [];
		for (const c of manifest.chunks) {
			if (!(await this.d.http.headChunk(this.d.spaceId, c.sha256))) missing.push(c);
		}
		if (missing.length > 0) await this.d.store.pushMissingChunks(nodeId, missing);

		const mirror = await this.d.index.getMirror(nodeId);
		const result = await this.d.http.putVersion(nodeId, {
			contentSha256: manifest.contentSha256,
			size: manifest.size,
			baseVersionId: mirror?.baseVersionId ?? null,
			manifest: manifest.chunks,
			deviceLabel: this.d.deviceLabel,
		});

		if (result.conflict) {
			await this.materializeConflict(nodeId, result.versionId, result.headVersionId, result.branchId);
			return true;
		}
		await this.d.index.upsertMirror({
			nodeId,
			spaceId: this.d.spaceId,
			relPath: mirror?.relPath ?? '',
			diskSha256: manifest.contentSha256,
			diskSize: manifest.size,
			diskMtimeMs: mirror?.diskMtimeMs ?? null,
			baseVersionId: result.versionId,
			materializedOfVersion: null,
		});
		return true;
	}

	/** P4 Task 17: the branch-sibling upload leg — a save from a materialized
	 *  branch head always lands on that ref, never main (§5.3). Mirrors
	 *  `uploadOne`'s shape but is path-keyed (readManifestAtPath/
	 *  pushMissingChunksAtPath) since a branch sibling has no server node_id
	 *  of its own — it shares the main file's nodeId, addressed by relPath. */
	private async uploadBranchOne(nodeId: number, branchId: number): Promise<boolean> {
		const branchRow = await this.d.index.getBranchMirror(nodeId, branchId);
		if (!branchRow) return false; // vanished locally between enqueue and drain

		const manifest = await this.d.store.readManifestAtPath(branchRow.relPath);
		if (!manifest) return false;

		const missing: ChunkRef[] = [];
		for (const c of manifest.chunks) {
			if (!(await this.d.http.headChunk(this.d.spaceId, c.sha256))) missing.push(c);
		}
		if (missing.length > 0) await this.d.store.pushMissingChunksAtPath(branchRow.relPath, missing);

		const result = await this.d.http.putVersion(nodeId, {
			contentSha256: manifest.contentSha256,
			size: manifest.size,
			baseVersionId: branchRow.baseVersionId,
			manifest: manifest.chunks,
			deviceLabel: this.d.deviceLabel,
			branchId,
		});

		// ponytail: a stale-base save on a branch ref (LR-5's uniform rule)
		// isn't chained into a further sub-sibling here (P4 v1) — the row is
		// just refreshed to whatever the server returned; a genuine race
		// surfaces on the NEXT pass via the normal conflict/issue paths.
		await this.d.index.upsertBranchMirror({
			nodeId,
			branchId,
			relPath: branchRow.relPath,
			diskSha256: manifest.contentSha256,
			diskSize: manifest.size,
			diskMtimeMs: branchRow.diskMtimeMs,
			baseVersionId: result.versionId,
		});
		return true;
	}

	/** Our own edit lost the race (stale baseVersionId): the edited bytes
	 *  already on disk become the sibling (renamed, never re-uploaded), and
	 *  the real head is re-downloaded to the original path. Never data loss.
	 *  P4: if the server auto-created a branch for this conflict (branchId),
	 *  the sibling registers in dc_branch_mirror too, so a LATER edit of this
	 *  same path (onLocalChange) routes to uploadBranchOne and actually
	 *  extends that branch — upgrading the P2-only materializedOfVersion
	 *  bookkeeping, which never routed a re-edit anywhere. */
	private async materializeConflict(
		nodeId: number,
		ourVersionId: number,
		headVersionId: number | null,
		branchId: number | null
	): Promise<void> {
		const mirror = await this.d.index.getMirror(nodeId);
		const relPath = mirror?.relPath ?? '';
		const name = relPath.split('/').pop() ?? relPath;
		const sibling = dedupeName(conflictSiblingName(name, this.d.deviceLabel, this.d.todayYmd()), (n) =>
			this.d.store.existsCI(siblingPathFor(relPath, n))
		);
		const siblingPath = siblingPathFor(relPath, sibling);

		await this.d.store.renameToSibling(nodeId, sibling);
		await this.d.index.addMaterializedVersion({
			versionId: ourVersionId,
			nodeId,
			relPath: siblingPath,
			sha256: mirror?.diskSha256 ?? null,
			atMs: this.d.now(),
		});
		if (branchId != null) {
			await this.d.index.upsertBranchMirror({
				nodeId,
				branchId,
				relPath: siblingPath,
				diskSha256: mirror?.diskSha256 ?? null,
				diskSize: mirror?.diskSize ?? null,
				diskMtimeMs: null,
				baseVersionId: ourVersionId,
			});
		}

		if (headVersionId == null) return;
		const [head] = (await this.d.http.nodesMeta([nodeId])).filter((n) => n.nodeId === nodeId);
		if (!head?.contentSha256 || head.sizeBytes == null) return;
		await this.d.store.putLocal(nodeId, {
			contentSha256: head.contentSha256,
			size: head.sizeBytes,
			headVersionId,
		} satisfies DownloadPlan);
		await this.d.index.upsertMirror({
			nodeId,
			spaceId: this.d.spaceId,
			relPath,
			diskSha256: head.contentSha256,
			diskSize: head.sizeBytes,
			diskMtimeMs: null,
			baseVersionId: headVersionId,
			materializedOfVersion: null,
		});
	}

	// ── download leg ──────────────────────────────────────────────────────────

	private async pullAndApply(): Promise<{ downloaded: number; issues: number }> {
		const state = await this.d.index.getSyncState(this.d.spaceId);
		const cursor = state.contentState;
		if (cursor === null) return this.fullVisibilityReconcile(state.accessCursor,state.aclEpoch);

		const res = await this.d.http.changes(this.d.spaceId, cursor);
		if (res.resync) return this.fullVisibilityReconcile(state.accessCursor,state.aclEpoch);

		// Group by nodeId keeping the LAST op — the feed already arrives
		// seq-ascending, so a later Map.set simply overwrites an earlier one.
		const lastOpByNode = new Map<number, DriveChange>();
		for (const c of res.changed) lastOpByNode.set(c.nodeId, c);
		const ids = [...lastOpByNode.keys()];
		const metas = await this.d.http.nodesMeta(ids);
		const metaById = new Map(metas.map((m) => [m.nodeId, m]));

		let downloaded = 0;
		let issues = 0;
		for (const nodeId of lastOpByNode.keys()) {
			const meta = metaById.get(nodeId);
			const r = meta ? await this.applyNode(meta) : await this.applyRemove(nodeId);
			if (r === 'downloaded') downloaded++;
			if (r === 'issue') issues++;
		}
		// Cursor persists only after the WHOLE batch applies — a crash mid-loop
		// leaves the cursor unmoved, so the next run re-applies the same batch
		// (every apply is sha-gated, so re-applying is a no-op).
		await this.d.index.setSyncState(this.d.spaceId,{...state,contentState:res.newState});
		return { downloaded, issues };
	}

	private async applyNode(meta: NodeMeta): Promise<'downloaded' | 'ok' | 'issue'> {
		if (meta.deletedAt) return this.applyRemove(meta.nodeId);
		await this.d.index.upsertNode(meta);
		return meta.kind === 'folder' ? this.applyFolder(meta) : this.applyFile(meta);
	}

	private async applyFolder(meta: NodeMeta): Promise<'ok'> {
		const mirror = await this.d.index.getMirror(meta.nodeId);
		const relPath = await this.d.index.relPath(meta.nodeId);
		if (mirror && relPath && mirror.relPath !== relPath) {
			await this.d.store.moveLocal(meta.nodeId, mirror.relPath, relPath);
			await this.d.index.upsertMirror({ ...mirror, relPath });
		}
		return 'ok';
	}

	private async applyFile(meta: NodeMeta): Promise<'downloaded' | 'ok' | 'issue'> {
		const relPath = (await this.d.index.relPath(meta.nodeId)) ?? meta.name;
		if (this.d.isExcluded(relPath)) {
			await this.d.index.upsertNode(meta); // metadata mirror stays whole; content stays excluded
			return 'ok';
		}
		let mirror = await this.d.index.getMirror(meta.nodeId);

		if (mirror && mirror.relPath !== relPath) {
			await this.d.store.moveLocal(meta.nodeId, mirror.relPath, relPath);
			mirror = { ...mirror, relPath };
			await this.d.index.upsertMirror(mirror);
		}

		let result: 'downloaded' | 'ok';

		if (
			mirror
			&& mirror.diskSha256 === meta.contentSha256
			&& (await this.d.store.readLocalManifest(meta.nodeId))?.contentSha256 === meta.contentSha256
		) {
			// Echo (our own upload coming back) OR genuinely unchanged: refresh
			// the base-version pointer, then check for conflict siblings this
			// device did not create itself (C2 — the only path by which a
			// conflict reaches the non-conflicting machine).
			await this.d.index.upsertMirror({ ...mirror, relPath, baseVersionId: meta.headVersionId });
			await this.materializeKnownConflicts(meta, relPath);
			result = 'ok';
		} else if (
			mirror &&
			mirror.diskSha256 !== null &&
			(await this.isGenuinelyDirty(meta.nodeId, mirror.diskSha256))
		) {
			// Genuinely locally dirty — never clobber it. The next
			// drainOutbound upload of this node surfaces the real conflict via
			// putVersion's stale-base response. See isGenuinelyDirty's doc for
			// the C8/mtime-untrust discipline this re-hash enforces.
			result = 'ok';
		} else if (meta.contentSha256 == null || meta.sizeBytes == null || meta.headVersionId == null) {
			result = 'ok'; // no content yet
		} else {
			await this.d.store.putLocal(meta.nodeId, {
				contentSha256: meta.contentSha256,
				size: meta.sizeBytes,
				headVersionId: meta.headVersionId,
			} satisfies DownloadPlan);
			await this.d.index.upsertMirror({
				nodeId: meta.nodeId,
				spaceId: this.d.spaceId,
				relPath,
				diskSha256: meta.contentSha256,
				diskSize: meta.sizeBytes,
				diskMtimeMs: null,
				baseVersionId: meta.headVersionId,
				materializedOfVersion: null,
			});
			result = 'downloaded';
		}

		// P4 Task 17: branches are a separate ref from main — reconcile
		// regardless of what main's own apply above decided. Runs LAST (after
		// materializeKnownConflicts above has a chance to register a
		// conflict-triggered dc_branch_mirror row): reconcileBranches' own
		// "already at this head" guard then skips re-materializing the SAME
		// branch head under a second, different sibling name.
		await this.reconcileBranches(meta, relPath);
		return result;
	}

	/** The remote head moved on from what this device last synced (C8/mtime-
	 *  untrust discipline): before refusing to download, verify the local
	 *  file ITSELF has actually changed (a fresh re-hash) — never a
	 *  comparison against the *remote's* new sha, which differs on every
	 *  normal remote-only update regardless of local state. Bug found via the
	 *  Task 13 convergence suite: the original inline code compared against
	 *  meta.contentSha256 here — the SAME check applyFile's echo branch
	 *  already makes — silently dropping every remote update to an
	 *  already-synced, untouched file. */
	private async isGenuinelyDirty(nodeId: number, lastSyncedSha: string): Promise<boolean> {
		const current = await this.d.store.readLocalManifest(nodeId);
		return current != null && current.contentSha256 !== lastSyncedSha;
	}

	/** C2: any listVersions row with conflict_of === head not yet materialized
	 *  locally gets its own sibling file — the path by which a conflict this
	 *  device did NOT create still reaches this device. P4 Task 17: if that
	 *  row carries a branchId (the OTHER device's conflicting save auto-
	 *  branched server-side), this device's sibling ALSO registers in
	 *  dc_branch_mirror — the same upgrade `materializeConflict` applies on
	 *  the conflicting device's own path, so either discovery route ends up
	 *  routable, not a dead end.
	 *
	 *  The device label on a version row is REMOTE-CONTROLLED (any co-tenant
	 *  sets it in their putVersion body), so it is sanitized to the same
	 *  single-safe-segment standard as FolderMirror.absPath's jail before it
	 *  may ride in a local filename, and each sibling's materialization is
	 *  isolated: one poisoned/unwritable sibling is skipped with a dc_issues
	 *  marker instead of aborting the whole apply pass (which would wedge
	 *  every later sync and abort an in-flight revocation purge). */
	private async materializeKnownConflicts(meta: NodeMeta, relPath: string): Promise<void> {
		if (meta.headVersionId == null) return;
		const versions = await this.d.http.listVersions(meta.nodeId);
		const name = relPath.split('/').pop() ?? relPath;
		for (const v of versions) {
			if (v.conflictOf !== meta.headVersionId) continue;
			if (await this.d.index.isVersionMaterialized(v.id)) continue;
			const dateYmd = v.createdAt.slice(0, 10);
			const sibling = dedupeName(conflictSiblingName(name, sanitizeLabel(v.deviceLabel), dateYmd), (n) =>
				this.d.store.existsCI(siblingPathFor(relPath, n))
			);
			const siblingPath = siblingPathFor(relPath, sibling);
			try {
				await this.d.store.materializeVersion(v.id, siblingPath, v.sha256, v.size);
			} catch (err) {
				await this.recordIssue(
					'transfer-failed', siblingPath,
					`conflict version ${v.id} left unmaterialized; sync continues: ${errorDetail(err)}`,
				);
				continue;
			}
			await this.d.index.addMaterializedVersion({
				versionId: v.id,
				nodeId: meta.nodeId,
				relPath: siblingPath,
				sha256: v.sha256,
				atMs: this.d.now(),
			});
			if (v.branchId != null) {
				await this.d.index.upsertBranchMirror({
					nodeId: meta.nodeId,
					branchId: v.branchId,
					relPath: siblingPath,
					diskSha256: v.sha256,
					diskSize: v.size,
					diskMtimeMs: null,
					baseVersionId: v.id,
				});
			}
		}
	}

	/** P4 Task 17: materializes every open/review branch head as a sibling
	 *  file, and removes any previously-materialized sibling whose branch has
	 *  since closed (merged/discarded). Skips the `fileBranches` network call
	 *  entirely when there is nothing to reconcile (branchCount 0 and no
	 *  locally-materialized siblings) — the common case for the vast
	 *  majority of files, which never have branches.
	 *
	 *  Deletion is remote-triggered (any co-tenant can merge/discard), so it
	 *  carries a dirty/hash guard: a sibling is only removed when its freshly
	 *  hashed disk content still matches the dc_branch_mirror row's
	 *  last-synced sha. Anything else — undrained local edits, or a row with
	 *  no recorded sha to prove cleanliness — is kept and marked with an
	 *  unsynced-local-edit issue instead of being silently rm'd. Both store
	 *  operations are also isolated per branch: one poisoned/unwritable
	 *  sibling fails with a dc_issues marker and never aborts the apply pass
	 *  (which would wedge every later sync and abort an in-flight revocation
	 *  purge). Branch names are remote-supplied too, so they pass through the
	 *  same label sanitizer before reaching a filename. */
	private async reconcileBranches(meta: NodeMeta, relPath: string): Promise<void> {
		const existing = await this.d.index.branchMirrorsForNode(meta.nodeId);
		if ((meta.branchCount ?? 0) === 0 && existing.length === 0) return;

		const branches = await this.d.http.fileBranches(meta.nodeId);
		const openIds = new Set(branches.map((b) => b.id)); // fileBranches is already server-filtered to open/review

		for (const row of existing) {
			if (openIds.has(row.branchId)) continue;
			// Dirty/hash guard (fail closed): with no manifest the file has
			// vanished (or its path was never safe) and removeAtPath below
			// decides; with a manifest, delete only on a sha match. A THROWN
			// read is a third state, never folded into "vanished" (the
			// med-shard3-020 r2 fix): the file is present but its hash cannot
			// be proven clean, and rm can still succeed where the hash read
			// failed — so the sibling is kept with a dc_issues marker instead
			// of being deleted without proving cleanliness.
			let manifest: Manifest | null;
			try {
				manifest = await this.d.store.readManifestAtPath(row.relPath);
			} catch (err) {
				await this.recordIssue(
					'transfer-failed', row.relPath,
					`closed branch sibling hash could not be read; kept without proving cleanliness: ${errorDetail(err)}`,
				);
				continue;
			}
			if (manifest && (row.diskSha256 == null || manifest.contentSha256 !== row.diskSha256)) {
				await this.recordIssue(
					'unsynced-local-edit', row.relPath,
					'branch was merged/discarded server-side; kept the sibling with undrained local edits',
				);
				continue;
			}
			try {
				await this.d.store.removeAtPath(row.relPath);
			} catch (err) {
				await this.recordIssue(
					'transfer-failed', row.relPath,
					`closed branch sibling could not be removed; kept: ${errorDetail(err)}`,
				);
				continue;
			}
			await this.d.index.removeBranchMirror(row.nodeId, row.branchId);
		}

		const name = relPath.split('/').pop() ?? relPath;
		for (const b of branches) {
			const row = await this.d.index.getBranchMirror(meta.nodeId, b.id);
			if (row && row.baseVersionId === b.headVersionId) continue; // already materialized at the current head

			const content = await this.branchHeadContent(meta.nodeId, b.headVersionId);
			if (!content) continue; // transient (version not resolvable yet) -- next pass retries

			// Keep the on-disk name stable across a head refresh; only a
			// brand-new materialization picks (and G4-dedupes) a fresh name.
			const siblingRelPath = row
				? row.relPath
				: siblingPathFor(
						relPath,
						dedupeName(branchSiblingName(name, sanitizeLabel(b.name)), (n) => this.d.store.existsCI(siblingPathFor(relPath, n)))
					);

			try {
				await this.d.store.materializeVersion(b.headVersionId, siblingRelPath, content.sha256, content.size);
			} catch (err) {
				await this.recordIssue(
					'transfer-failed', siblingRelPath,
					`branch ${b.id} head left unmaterialized; sync continues: ${errorDetail(err)}`,
				);
				continue;
			}
			await this.d.index.upsertBranchMirror({
				nodeId: meta.nodeId,
				branchId: b.id,
				relPath: siblingRelPath,
				diskSha256: content.sha256,
				diskSize: content.size,
				diskMtimeMs: null,
				baseVersionId: b.headVersionId,
			});
		}
	}

	/** BranchMeta carries no sha/size (server's branchOut has none) — resolve
	 *  the branch head's content via listVersions, the same lookup
	 *  materializeKnownConflicts already uses for conflict siblings. */
	private async branchHeadContent(nodeId: number, headVersionId: number): Promise<{ sha256: string; size: number } | null> {
		const versions = await this.d.http.listVersions(nodeId);
		const v = versions.find((x) => x.id === headVersionId);
		return v ? { sha256: v.sha256, size: v.size } : null;
	}

	private async applyRemove(nodeId: number): Promise<'ok' | 'issue'> {
		const mirror = await this.d.index.getMirror(nodeId);
		if (!mirror) return 'ok'; // never synced on this device — nothing to remove

		// delete-vs-edit: edit wins (§4.4). A node this device has queued (but
		// not yet uploaded) an edit for survives a remote trash/destroy.
		if (await this.d.index.hasPendingUpsert(nodeId)) {
			await this.recordIssue('unsynced-local-edit', mirror.relPath, 'kept a local edit instead of deleting');
			return 'issue';
		}
		await this.d.store.remove(nodeId);
		await this.d.index.removeMirror(nodeId);
		return 'ok';
	}

	// ── stale cursor / first-ever sync -> windowed full resync ───────────────

	private async fullVisibilityReconcile(
		accessCursor: string | null,
		expectedEpoch: string | null,
	): Promise<{ downloaded: number; issues: number }> {
		for (let attempt=0;attempt<3;attempt++) {
			const priorState=await this.d.index.getSyncState(this.d.spaceId);
			let anchorState: string | null;
			try {
				const anchor=await this.d.http.changes(this.d.spaceId,null);
				if (anchor.resync) throw new Error('drive-sync: anchor returned resync');
				anchorState=anchor.newState;
			} catch (err) {
				if (!(err instanceof DriveApiError && err.status===404)) throw err;
				// A retained ACL cursor can outlive all content authority.  Preserve
				// the last content cursor only long enough to purge local state; it
				// is not reused for another server request after access is gone.
				anchorState=priorState.contentState;
			}
			const visible: NodeMeta[]=[];
			let after='0';
			let epoch=expectedEpoch;
			let rootCapabilities: string[]=[];
			try {
				for (let pageNo=0;pageNo<10_000;pageNo++) {
					const page=await this.d.http.visibilitySnapshot(this.d.spaceId,after,epoch);
					if (epoch==null) epoch=page.epoch;
					rootCapabilities=page.rootCapabilities;
					visible.push(...page.nodes);
					after=page.nextAfter;
					if (!page.hasMore) {
						// Final empty/page-edge probe closes the epoch-change window between
						// the penultimate page and local commit.
						await this.d.http.visibilitySnapshot(this.d.spaceId,after,epoch,1);
						break;
					}
				}
			} catch (err) {
				if (err instanceof DriveApiError && err.status===409) {
					const fresh=await this.d.http.accessInvalidations(this.d.spaceId,accessCursor);
					accessCursor=fresh.cursor; expectedEpoch=fresh.epoch;
					continue;
				}
				if (!(err instanceof DriveApiError && err.status===404)) throw err;
				// A valid prior cursor plus 404 means the caller lost the entire
				// space. The empty visible set is the authoritative purge result.
				visible.length=0; rootCapabilities=[]; epoch=null;
			}

			const orderedVisible=dependencyOrder(visible);
			const seen=new Set(orderedVisible.map((n)=>n.nodeId));
			const known=await this.d.index.nodeIds(this.d.spaceId);
			let downloaded=0; let issues=0;
			await this.d.index.transaction(async()=>{
				await this.d.index.setRootCapabilities(this.d.spaceId,rootCapabilities);
				for (const meta of orderedVisible) {
					if ((await this.applyNode(meta))==='downloaded') downloaded++;
				}
				for (const nodeId of known) {
					if (seen.has(nodeId)) continue;
					issues+=await this.applyAccessRevocation(nodeId);
				}
				await this.d.index.setSyncState(this.d.spaceId,{
					version:2,contentState:anchorState,accessCursor,aclEpoch:epoch,
				});
			});
			return {downloaded,issues};
		}
		throw new Error('drive-sync: ACL epoch changed during every visibility snapshot attempt');
	}

	private async applyAccessRevocation(nodeId: number): Promise<number> {
		const mirror=await this.d.index.getMirror(nodeId);
		const relPath=mirror?.relPath ?? (await this.d.index.relPath(nodeId)) ?? '';
		const pending=await this.d.index.quarantineOutbound(nodeId,relPath,'access-revoked',this.d.now());
		const branches=await this.d.index.branchMirrorsForNode(nodeId);
		for (const branch of branches) {
			const outcome=await this.d.store.revokePath(branch.relPath,pending>0);
			if (outcome==='busy') throw new Error(`drive-sync: busy revoked branch ${branch.relPath}`);
		}
		const outcome=await this.d.store.revoke(nodeId,pending>0);
		if (outcome==='busy') throw new Error(`drive-sync: busy revoked file ${relPath}`);
		await this.d.index.removeNodeState(nodeId);
		if (outcome==='quarantined' || pending>0) {
			await this.recordIssue('access-revoked',relPath,'access was removed; pending local work was quarantined and was not uploaded');
			return 1;
		}
		return 0;
	}
}

/** Visibility pages are id-ordered for stable opaque paging, but a move can
 * attach an older node beneath a newer parent.  Apply the complete snapshot in
 * dependency order so relPath construction never observes a child before a
 * visible parent.  A server-side cycle is rejected rather than flattened: the
 * closure invariant says it is corruption, not a client recovery case. */
function dependencyOrder(nodes: NodeMeta[]): NodeMeta[] {
	const byID = new Map(nodes.map((node) => [node.nodeId, node]));
	const visiting = new Set<number>();
	const visited = new Set<number>();
	const ordered: NodeMeta[] = [];
	const visit = (node: NodeMeta): void => {
		if (visited.has(node.nodeId)) return;
		if (visiting.has(node.nodeId)) throw new Error('drive-sync: visibility snapshot contains a parent cycle');
		visiting.add(node.nodeId);
		if (node.parentId != null) {
			const parent = byID.get(node.parentId);
			if (parent) visit(parent);
		}
		visiting.delete(node.nodeId);
		visited.add(node.nodeId);
		ordered.push(node);
	};
	for (const node of nodes) visit(node);
	return ordered;
}

function siblingPathFor(originalRelPath: string, siblingName: string): string {
	const idx = originalRelPath.lastIndexOf('/');
	return idx === -1 ? siblingName : originalRelPath.slice(0, idx + 1) + siblingName;
}

/** A device label or branch name arriving from the server is attacker-
 *  controlled by any co-tenant, and it is embedded verbatim into a LOCAL
 *  sibling filename (conflict/branch materialization). Sanitize it to the
 *  same single-safe-segment standard FolderMirror.absPath's jail enforces
 *  and service.ts's sanitizeFolderName applies to space folders: path
 *  separators, Windows-reserved characters and control bytes become `_`, and
 *  a label that collapses to nothing falls back to the same placeholder the
 *  engine already used for a missing label. The label is always embedded
 *  mid-segment (`<base> (conflict <label> <date>)<ext>`), so it can never
 *  become a whole `.`/`..` segment once the separators are gone. */
function sanitizeLabel(label: string | null | undefined): string {
	// eslint-disable-next-line no-control-regex -- stripping control bytes is the point; they are illegal in filenames
	const cleaned = (label ?? '').replace(/[<>:"/\\|?*\x00-\x1f\x7f]/g, '_').trim();
	return cleaned || 'unknown-device';
}

function errorDetail(err: unknown): string {
	return err instanceof Error ? err.message : String(err);
}

function mapErrorToIssueCode(err: DriveApiError): SyncIssue['code'] {
	switch (err.code) {
		case 'BZ148':
			return 'quota';
		case 'BZ147':
			return 'name-collision';
		case 'BZ149': // P4 Task 16: hard-locked-by-another-user (423) — ack, no retry loop
			return 'locked-file';
		default:
			return 'transfer-failed';
	}
}
