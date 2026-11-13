// fakeDriveServer.ts — an in-memory, fetch-shaped Drive server implementing
// the P2-consumed protocol subset (mailserver/internal/drive's wire contract,
// spec §4.2/§3.3/§7) with the SPEC's semantics, not just its shapes: journal
// append on every mutation, changes() anchor/paging/409-below-the-pruned-
// floor, chunk HEAD/PUT idempotency, putVersion's conflict rule (stale base ->
// conflict:true, head unchanged, conflict_of=head), idempotent re-POST, and
// Range-honoring content reads. Zero real HTTP — a `FetchLike` closure over an
// in-memory model. This is the acceptance-gate oracle (Task 13); each
// behavior below is self-evident from the P1 spec it pins, not re-derived
// from the client code that consumes it.
import type { FetchLike } from '../../../../../../mailserver/webmail/src/lib/drive/sync/types.js';

interface NodeRow {
	id: number;
	spaceId: number;
	parentId: number | null;
	kind: 'file' | 'folder';
	name: string;
	deletedAt: string | null;
	headVersionId: number | null;
}
interface VersionRow {
	id: number;
	spaceId: number;
	nodeId: number;
	contentSha256: string;
	size: number;
	contentType: string | null;
	manifest: Array<{ sha256: string; size: number }>;
	conflictOf: number | null;
	deviceLabel: string | null;
	createdAt: string;
	/** P4 Task 17: the ref this version was saved to (null = main). */
	branchId: number | null;
}
/** P4 Task 17: a save ref. "main" is never a row here — it's always
 *  drive_files.head_version_id (mirrored by NodeRow.headVersionId); only
 *  branches get a row, matching the real server's model (spec §5). */
interface BranchRow {
	id: number;
	fileNodeId: number;
	name: string;
	status: 'open' | 'review' | 'merged' | 'discarded';
	headVersionId: number;
	forkedFromVersionId: number;
	createdAt: string;
}
interface JournalRow {
	spaceId: number;
	nodeId: number;
	op: string;
	seq: number;
}
interface SpaceRow {
	id: number;
	name: string;
	classification: string;
	role: string;
	changeSeq: number;
}

function json(body: unknown, status = 200): Response {
	return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } });
}
function problem(status: number, type: string, code?: string): Response {
	return new Response(JSON.stringify({ type, status, code }), {
		status,
		headers: { 'Content-Type': 'application/problem+json' },
	});
}

export class FakeDriveServer {
	private spaces = new Map<number, SpaceRow>();
	private nodes = new Map<number, NodeRow>();
	private versions = new Map<number, VersionRow>();
	private branches = new Map<number, BranchRow>(); // P4 Task 17
	private chunks = new Map<string, Uint8Array>(); // key: `${spaceId}:${sha256}`
	private journal: JournalRow[] = [];
	private prunedFloor = new Map<number, number>();
	private nextNodeId = 1;
	private nextVersionId = 1;
	private nextBranchId = 1;
	private clockMs = Date.UTC(2026, 0, 1);
	quotaBytes = Infinity;

	// ── test setup hooks ──────────────────────────────────────────────────────

	addSpace(id: number, name: string, opts: Partial<SpaceRow> = {}): void {
		this.spaces.set(id, { id, name, classification: 'regular', role: 'manager', changeSeq: 0, ...opts });
	}

	pruneBelow(spaceId: number, seq: number): void {
		this.prunedFloor.set(spaceId, seq);
	}

	currentSeq(spaceId: number): number {
		return this.spaces.get(spaceId)?.changeSeq ?? 0;
	}

	/** P4 Task 17 test inspection: live (open/review) branches for a node. */
	openBranchesFor(nodeId: number): BranchRow[] {
		return [...this.branches.values()].filter((b) => b.fileNodeId === nodeId && (b.status === 'open' || b.status === 'review'));
	}

	/** How many times `changes()` was called with a given `since` — the
	 *  kill-and-restart resume test asserts no from-zero refetch. */
	changesCalls: string[] = [];

	// ── internals ────────────────────────────────────────────────────────────

	private nowISO(): string {
		this.clockMs += 1000;
		return new Date(this.clockMs).toISOString();
	}
	private bump(spaceId: number): number {
		const s = this.spaces.get(spaceId);
		if (!s) throw new Error(`unknown space ${spaceId}`);
		s.changeSeq += 1;
		return s.changeSeq;
	}
	private appendJournal(spaceId: number, nodeId: number, op: string): void {
		const seq = this.bump(spaceId);
		this.journal.push({ spaceId, nodeId, op, seq });
	}
	private headOf(nodeId: number): VersionRow | null {
		const node = this.nodes.get(nodeId);
		return node?.headVersionId != null ? (this.versions.get(node.headVersionId) ?? null) : null;
	}
	private siblingCI(spaceId: number, parentId: number | null, name: string, excludeId?: number): NodeRow | null {
		for (const n of this.nodes.values()) {
			if (n.spaceId !== spaceId || n.parentId !== parentId || n.deletedAt || n.id === excludeId) continue;
			if (n.name.toLowerCase() === name.toLowerCase()) return n;
		}
		return null;
	}

	/** Assemble a version's full content by concatenating its manifest's
	 *  chunks (which must already have been PUT — real client flow always
	 *  pushes missing chunks before putVersion). */
	private assemble(v: VersionRow): Uint8Array {
		const parts: Uint8Array[] = [];
		for (const c of v.manifest) {
			const bytes = this.chunks.get(`${v.spaceId}:${c.sha256}`);
			if (!bytes) throw new Error(`fakeDriveServer: chunk ${c.sha256} was never pushed`);
			parts.push(bytes);
		}
		const total = parts.reduce((n, p) => n + p.length, 0);
		const out = new Uint8Array(total);
		let off = 0;
		for (const p of parts) {
			out.set(p, off);
			off += p.length;
		}
		return out;
	}

	// ── fetch entry point ────────────────────────────────────────────────────

	fetch: FetchLike = async (input, init) => {
		const url = new URL(input, 'http://fake.invalid');
		const method = (init?.method ?? 'GET').toUpperCase();
		const p = url.pathname;

		if (p === '/spaces' && method === 'GET') {
			return json([...this.spaces.values()].map((s) => ({ ...s, aclMode: 'legacy', aclEpoch: 0 })));
		}

		if (p === '/access-invalidations' && method === 'GET') {
			return json({ cursor: null, epoch: '0', invalidations: [], hasMore: false, fullReconcile: false });
		}

		if (p === '/visibility-snapshot' && method === 'GET') {
			const spaceId = Number(url.searchParams.get('space'));
			const after = Number(url.searchParams.get('after') ?? '0');
			const max = Number(url.searchParams.get('max') ?? '500');
			const rows = [...this.nodes.values()]
				.filter((n) => n.spaceId === spaceId && !n.deletedAt && n.id > after)
				.sort((a, b) => a.id - b.id)
				.slice(0, max)
				.map((n) => {
					const head = n.headVersionId != null ? this.versions.get(n.headVersionId) : undefined;
					return {
						nodeId: n.id, spaceId: n.spaceId, parentId: n.parentId, kind: n.kind, name: n.name,
						deletedAt: null, headVersionId: n.headVersionId,
						contentSha256: head?.contentSha256 ?? null, sizeBytes: head?.size ?? null,
						contentType: head?.contentType ?? null, branchCount: this.openBranchesFor(n.id).length,
						capabilities: ['traverse','list_children','read_metadata','preview','download','create_child','modify_content','rename','move','delete','manage_acl','view_audit'],
						traverseOnly: false,
					};
				});
			const nextAfter = rows.at(-1)?.nodeId ?? after;
			const hasMore = [...this.nodes.values()].some((n) => n.spaceId === spaceId && !n.deletedAt && n.id > nextAfter);
			return json({ epoch: '0', rootCapabilities: ['create_child'], nodes: rows, nextAfter: String(nextAfter), hasMore });
		}

		let m: RegExpMatchArray | null;

		if ((m = p.match(/^\/spaces\/(\d+)\/tree$/)) && method === 'GET') {
			const spaceId = Number(m[1]);
			const parentParam = url.searchParams.get('parent');
			const parentId = parentParam == null ? null : Number(parentParam);
			const rows = [...this.nodes.values()].filter(
				(n) => n.spaceId === spaceId && n.parentId === parentId && !n.deletedAt
			);
			return json(
				rows.map((n) => {
					const head = n.headVersionId != null ? this.versions.get(n.headVersionId) : undefined;
					return {
						id: n.id,
						parentId: n.parentId,
						kind: n.kind,
						name: n.name,
						size: head?.size,
						contentType: head?.contentType ?? undefined,
						headVersionId: n.headVersionId ?? undefined,
						deletedAt: n.deletedAt ?? undefined,
					};
				})
			);
		}

		if (p === '/nodes' && method === 'GET') {
			const idsParam = url.searchParams.get('ids');
			const ids = idsParam ? idsParam.split(',').map(Number) : [];
			const out = ids
				.map((id) => this.nodes.get(id))
				.filter((n): n is NodeRow => !!n)
				.map((n) => {
					const head = n.headVersionId != null ? this.versions.get(n.headVersionId) : undefined;
					return {
						nodeId: n.id,
						spaceId: n.spaceId,
						parentId: n.parentId,
						kind: n.kind,
						name: n.name,
						deletedAt: n.deletedAt,
						headVersionId: n.headVersionId,
						contentSha256: head?.contentSha256 ?? null,
						sizeBytes: head?.size ?? null,
						contentType: head?.contentType ?? null,
						branchCount: this.openBranchesFor(n.id).length,
						capabilities: ['traverse','list_children','read_metadata','preview','download','create_child','modify_content','rename','move','delete','manage_acl','view_audit'],
						traverseOnly: false,
					};
				});
			return json(out);
		}

		if ((m = p.match(/^\/files\/(\d+)\/branches$/)) && method === 'GET') {
			const nodeId = Number(m[1]);
			const rows = this.openBranchesFor(nodeId).map((b) => ({
				id: b.id,
				name: b.name,
				status: b.status,
				autoCreated: true,
				headVersionId: b.headVersionId,
				forkedFromVersionId: b.forkedFromVersionId,
				createdBy: 0,
				createdAt: b.createdAt,
				resolvedBy: null,
				resolvedAt: null,
				ffEligible: false,
			}));
			return json(rows);
		}

		if (p === '/nodes' && method === 'POST') {
			const body = (await new Response(init?.body).json()) as {
				spaceId: number;
				parentId: number | null;
				kind: 'file' | 'folder';
				name: string;
				contentType?: string;
			};
			if (this.siblingCI(body.spaceId, body.parentId, body.name)) {
				return problem(409, 'https://setjoin.com/errors/drive/name-collision', 'BZ147');
			}
			const id = this.nextNodeId++;
			this.nodes.set(id, {
				id,
				spaceId: body.spaceId,
				parentId: body.parentId,
				kind: body.kind,
				name: body.name,
				deletedAt: null,
				headVersionId: null,
			});
			this.appendJournal(body.spaceId, id, 'create');
			return json({ id });
		}

		if ((m = p.match(/^\/nodes\/(\d+)$/)) && method === 'PATCH') {
			const nodeId = Number(m[1]);
			const node = this.nodes.get(nodeId);
			if (!node) return problem(404, 'https://setjoin.com/errors/not-found', 'BZ139');
			const body = (await new Response(init?.body).json()) as { newName?: string; newParentId?: number | null };
			if (body.newName !== undefined) {
				if (this.siblingCI(node.spaceId, node.parentId, body.newName, node.id)) {
					return problem(409, 'https://setjoin.com/errors/drive/name-collision', 'BZ147');
				}
				node.name = body.newName;
				this.appendJournal(node.spaceId, node.id, 'rename');
			}
			if (body.newParentId !== undefined) {
				if (this.siblingCI(node.spaceId, body.newParentId, node.name, node.id)) {
					return problem(409, 'https://setjoin.com/errors/drive/name-collision', 'BZ147');
				}
				node.parentId = body.newParentId;
				this.appendJournal(node.spaceId, node.id, 'move');
			}
			return json({});
		}

		if ((m = p.match(/^\/nodes\/(\d+)\/trash$/)) && method === 'POST') {
			const node = this.nodes.get(Number(m[1]));
			if (!node) return problem(404, 'https://setjoin.com/errors/not-found', 'BZ139');
			node.deletedAt = this.nowISO();
			this.appendJournal(node.spaceId, node.id, 'trash');
			return json({});
		}
		if ((m = p.match(/^\/nodes\/(\d+)\/restore$/)) && method === 'POST') {
			const node = this.nodes.get(Number(m[1]));
			if (!node) return problem(404, 'https://setjoin.com/errors/not-found', 'BZ139');
			node.deletedAt = null;
			this.appendJournal(node.spaceId, node.id, 'restore');
			return json({});
		}

		if ((m = p.match(/^\/chunks\/([0-9a-f]+)$/)) && method === 'HEAD') {
			const spaceId = Number(url.searchParams.get('space'));
			const has = this.chunks.has(`${spaceId}:${m[1]}`);
			return new Response(null, { status: has ? 200 : 404 });
		}
		if ((m = p.match(/^\/chunks\/([0-9a-f]+)$/)) && method === 'PUT') {
			const spaceId = Number(url.searchParams.get('space'));
			const bytes = new Uint8Array(await new Response(init?.body).arrayBuffer());
			this.chunks.set(`${spaceId}:${m[1]}`, bytes);
			return json({});
		}

		if ((m = p.match(/^\/files\/(\d+)\/versions$/)) && method === 'POST') {
			return this.putVersion(Number(m[1]), init);
		}
		if ((m = p.match(/^\/files\/(\d+)\/versions$/)) && method === 'GET') {
			const nodeId = Number(m[1]);
			const rows = [...this.versions.values()]
				.filter((v) => v.nodeId === nodeId)
				.sort((a, b) => a.id - b.id)
				.map((v) => ({
					id: v.id,
					conflictOf: v.conflictOf,
					sha256: v.contentSha256,
					size: v.size,
					deviceLabel: v.deviceLabel,
					createdAt: v.createdAt,
					branchId: v.branchId,
				}));
			return json(rows);
		}

		if ((m = p.match(/^\/versions\/(\d+)\/content$/)) && method === 'GET') {
			const v = this.versions.get(Number(m[1]));
			if (!v) return problem(404, 'https://setjoin.com/errors/not-found', 'BZ139');
			const full = this.assemble(v);
			const range = (init?.headers as Record<string, string> | undefined)?.Range ?? '';
			const rm = range.match(/bytes=(\d+)-(\d+)/);
			const [start, endIncl] = rm ? [Number(rm[1]), Number(rm[2])] : [0, full.length - 1];
			const slice = full.slice(start, endIncl + 1); // copy (not subarray) -- a plain Uint8Array is valid BodyInit
			return new Response(slice, {
				status: rm ? 206 : 200,
			});
		}

		if (p === '/changes' && method === 'GET') {
			return this.changes(url);
		}

		return problem(404, 'https://setjoin.com/errors/not-found');
	};

	/** P4 Task 17: per-ref save (spec §5.3). `body.branchId` selects the ref;
	 *  omitted/null means main. Ref-agnostic base-check (LR-5): a stale base
	 *  on EITHER ref reports conflict:true without moving that ref's head. A
	 *  stale-base save on MAIN additionally auto-branches (spec's "conflict ->
	 *  auto-branch", LR-7 naming) so the loser's bytes land somewhere
	 *  advanceable, not just a dead orphan version row. A stale-base save on a
	 *  BRANCH does not chain into a further sub-branch here (P4 v1 — matches
	 *  the accepted limitation `SyncEngine.uploadBranchOne` documents; no
	 *  required scenario exercises branch-of-a-branch).
	 */
	private async putVersion(nodeId: number, init: RequestInit | undefined): Promise<Response> {
		const node = this.nodes.get(nodeId);
		if (!node) return problem(404, 'https://setjoin.com/errors/not-found', 'BZ139');
		const body = (await new Response(init?.body).json()) as {
			contentSha256: string;
			size: number;
			contentType?: string | null;
			baseVersionId: number | null;
			manifest: Array<{ sha256: string; size: number }>;
			deviceLabel?: string | null;
			branchId?: number | null;
		};

		if (this.quotaBytes !== Infinity && body.size > this.quotaBytes) {
			return problem(413, 'https://setjoin.com/errors/drive/quota-exceeded', 'BZ148');
		}

		const targetBranchId = body.branchId ?? null;
		const branch = targetBranchId != null ? this.branches.get(targetBranchId) : undefined;
		if (targetBranchId != null && (!branch || branch.fileNodeId !== nodeId)) {
			return problem(409, 'https://setjoin.com/errors/drive/branch-error', 'BZ150');
		}
		const refHeadId = branch ? branch.headVersionId : this.headOf(nodeId)?.id;

		// Idempotent re-POST: same file + ref + sha + base -> the existing version.
		const existing = [...this.versions.values()].find(
			(v) => v.nodeId === nodeId && v.branchId === targetBranchId && v.contentSha256 === body.contentSha256 && v.size === body.size
		);
		if (existing && existing.id === refHeadId) {
			return json({
				versionId: existing.id,
				conflict: false,
				branchId: targetBranchId,
				headVersionId: node.headVersionId,
				wormPending: false,
			});
		}

		const baseMatches = body.baseVersionId === (refHeadId ?? null);
		const version: VersionRow = {
			id: this.nextVersionId++,
			spaceId: node.spaceId,
			nodeId,
			contentSha256: body.contentSha256,
			size: body.size,
			contentType: body.contentType ?? null,
			manifest: body.manifest,
			conflictOf: baseMatches ? null : (refHeadId ?? null),
			deviceLabel: body.deviceLabel ?? null,
			createdAt: this.nowISO(),
			branchId: targetBranchId,
		};
		this.versions.set(version.id, version);

		if (baseMatches) {
			if (branch) {
				branch.headVersionId = version.id;
			} else {
				node.headVersionId = version.id;
			}
			// Branch mutations ride journal op 'update' on the file node too
			// (architecture note: "branch/label/folder-admin events ride
			// journal op update on the file/folder node") -- otherwise the
			// OTHER device's next pull never re-visits this node's applyFile
			// and so never notices the branch's new head.
			this.appendJournal(node.spaceId, nodeId, branch || refHeadId != null ? 'update' : 'create');
			return json({
				versionId: version.id,
				conflict: false,
				branchId: targetBranchId,
				headVersionId: node.headVersionId,
				wormPending: false,
			});
		}

		if (!branch) {
			// Main conflict -> auto-branch (spec §5.2/I-9, LR-7 naming): the
			// loser's bytes become a fresh branch's head, forked at the head
			// this save was actually based against having lost the race.
			const autoBranch: BranchRow = {
				id: this.nextBranchId++,
				fileNodeId: nodeId,
				name: `${body.deviceLabel ?? 'web'} ${version.createdAt.slice(0, 10)}`,
				status: 'open',
				headVersionId: version.id,
				forkedFromVersionId: refHeadId ?? version.id,
				createdAt: version.createdAt,
			};
			this.branches.set(autoBranch.id, autoBranch);
			version.branchId = autoBranch.id;
			this.appendJournal(node.spaceId, nodeId, 'update');
			return json({
				versionId: version.id,
				conflict: true,
				branchId: autoBranch.id,
				headVersionId: node.headVersionId,
				wormPending: false,
			});
		}
		// Branch-vs-branch conflict: head unchanged, no further auto-branch (P4 v1).
		this.appendJournal(node.spaceId, nodeId, 'update');
		return json({
			versionId: version.id,
			conflict: true,
			branchId: targetBranchId,
			headVersionId: node.headVersionId,
			wormPending: false,
		});
	}

	private changes(url: URL): Response {
		const spaceId = Number(url.searchParams.get('space'));
		const space = this.spaces.get(spaceId);
		if (!space) return problem(404, 'https://setjoin.com/errors/not-found');
		const sinceParam = url.searchParams.get('since');
		this.changesCalls.push(sinceParam ?? '(anchor)');
		const max = Number(url.searchParams.get('max') ?? '500');

		if (sinceParam === null) {
			return json({ newState: String(space.changeSeq), changed: [], hasMore: false });
		}
		const since = Number(sinceParam);
		const floor = this.prunedFloor.get(spaceId);
		if (!Number.isFinite(since) || since < 0 || (floor !== undefined && since < floor)) {
			return problem(409, 'https://setjoin.com/errors/drive/cannot-calculate-changes');
		}
		const all = this.journal.filter((j) => j.spaceId === spaceId && j.seq > since).sort((a, b) => a.seq - b.seq);
		const page = all.slice(0, max);
		const hasMore = all.length > page.length;
		const newState = page.length > 0 ? String(page[page.length - 1].seq) : String(space.changeSeq);
		return json({ newState, changed: page.map((r) => ({ nodeId: r.nodeId, op: r.op, seq: r.seq })), hasMore });
	}
}
