// protocol.ts — the REST envelope of spec §4.2/§3.3/§7 over `mailserver/
// internal/drive`'s wire contract. `fetchFn` is injected: Electron main
// passes `session.defaultSession.fetch` (cookies ride along) or a
// bearer-wrapping wrapper around it; tests pass fakes; P3's VaultStore passes
// the renderer fetch. No retries happen inside these methods except via the
// exported `withBackoff` — callers decide what is worth retrying.
import type {
	AccessInvalidationPage,
	BranchMeta,
	ChangesPage,
	DriveChange,
	DriveOp,
	FetchLike,
	LockRow,
	NodeMeta,
	VisibilityPage,
} from './types.js';

export class DriveApiError extends Error {
	constructor(
		readonly status: number,
		readonly type: string,
		readonly code?: string
	) {
		super(`drive api error ${status}${code ? ` (${code})` : ''}: ${type}`);
		this.name = 'DriveApiError';
	}
}

interface ProblemBody {
	type?: string;
	title?: string;
	status?: number;
	detail?: string;
	code?: string;
}

async function throwProblem(res: Response): Promise<never> {
	let body: ProblemBody = {};
	try {
		body = (await res.json()) as ProblemBody;
	} catch {
		/* non-JSON error body — fall through with a bare status */
	}
	throw new DriveApiError(res.status, body.type ?? 'about:blank', body.code);
}

async function okJson<T>(res: Response): Promise<T> {
	if (!res.ok) return throwProblem(res);
	return (await res.json()) as T;
}
async function okVoid(res: Response): Promise<void> {
	if (!res.ok) await throwProblem(res);
}

// ── wire row shapes (mirror mailserver/internal/drive/*.go response structs) ─

interface ChangeRowWire {
	nodeId: number;
	op: DriveOp;
	seq: number;
}
interface ChangesPageWire {
	newState: number;
	changed: ChangeRowWire[];
	hasMore: boolean;
}
interface CannotCalculateWire {
	cannotCalculateChanges: true;
}
interface SpaceWire {
	id: number;
	name: string;
	classification: string;
	role: string;
	changeSeq: number;
	aclMode: 'legacy' | 'shadow' | 'acl';
	aclEpoch: number;
}
interface TreeNodeWire {
	id: number;
	parentId: number | null;
	kind: 'folder' | 'file';
	name: string;
	size?: number;
	contentType?: string;
	headVersionId?: number;
	deletedAt?: string;
}
export interface VersionMeta {
	id: number;
	conflictOf: number | null;
	sha256: string;
	size: number;
	deviceLabel: string | null;
	createdAt: string;
	/** P4 Task 17: the ref this version was saved to (null = main). Optional
	 *  for the same reason NodeMeta.branchCount is — most call sites never
	 *  set it. Lets `materializeKnownConflicts` (C2 — the non-conflicting
	 *  device's discovery path) adopt the SAME auto-branch `materializeConflict`
	 *  (the conflicting device's own path) already does, so a conflict
	 *  discovered either way still registers in dc_branch_mirror. */
	branchId?: number | null;
}
export interface PutVersionBody {
	contentSha256: string;
	size: number;
	contentType?: string | null;
	baseVersionId: number | null;
	manifest: { sha256: string; size: number }[];
	note?: string | null;
	deviceLabel?: string | null;
	/** P4 Task 17: the ref this save targets — omitted/null means main. A
	 *  branch-sibling upload always sets this (never lands on main, §5.3). */
	branchId?: number | null;
}
export interface PutVersionResult {
	versionId: number;
	conflict: boolean;
	branchId: number | null;
	headVersionId: number | null;
	wormPending: boolean;
}
export type ChangesResult = { resync: true } | ({ resync: false } & ChangesPage);

/** P4 §6.3 drive_file_lock body/result — the mirror only ever sends `mode`
 *  (+ optional deviceLabel/branchId for the P4 Task 17 branch-aware leg);
 *  ttlMinutes/versionId are server-defaulted. */
export interface LockAcquireBody {
	mode: 'soft' | 'hard';
	branchId?: number | null;
	versionId?: number | null;
	deviceLabel?: string | null;
	ttlMinutes?: number;
}
export interface LockAcquireResult {
	status: 'acquired' | 'renewed' | 'held';
	holderId?: number;
	mode?: string;
	since?: string;
	expiresAt: string;
	branchId?: number | null;
}

const JSON_HEADERS = { 'Content-Type': 'application/json' };

/** Chunks a list to at most `size` per page — nodesMeta's ≤500 server cap (BZ141). */
function chunked<T>(items: T[], size: number): T[][] {
	const out: T[][] = [];
	for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
	return out;
}

export class DriveHttp {
	constructor(
		private fetchFn: FetchLike,
		private base: string
	) {}

	private url(path: string): string {
		return `${this.base}${path}`;
	}

	/**
	 * `since === null` is the anchor call: the caller wants the CURRENT
	 * newState with no diff (bootstrap / fullResync's cursor anchor). The
	 * `/drive/changes` route itself 400s on a missing `since` (a real P1 gap —
	 * the anchor semantics named by spec §4.2 are not wired server-side yet,
	 * out of this task's scope), so the anchor path is served entirely from
	 * `GET /drive/spaces`'s existing `changeSeq` field instead of touching
	 * that route — zero server change, and `changed:[]`/`hasMore:false` are
	 * correct by construction (no diff was computed, none happened).
	 */
	async changes(spaceId: number, since: string | null, max = 500): Promise<ChangesResult> {
		if (since === null) {
			const spaces = await this.spaces();
			const space = spaces.find((s) => s.id === spaceId);
			if (!space) throw new DriveApiError(404, 'https://setjoin.com/errors/not-found');
			return { resync: false, newState: String(space.changeSeq), changed: [], hasMore: false };
		}

		let cursor = since;
		const changed: DriveChange[] = [];
		let hasMore = false;
		const MAX_PAGES = 20; // circuit breaker — a single call never loops forever
		for (let page = 0; page < MAX_PAGES; page++) {
			const res = await this.fetchFn(this.url(`/changes?space=${spaceId}&since=${cursor}&max=${max}`));
			if (!res.ok) {
				let body: ProblemBody = {};
				try {
					body = (await res.json()) as ProblemBody;
				} catch {
					/* non-JSON body */
				}
				if (res.status === 409 && (body.type ?? '').includes('cannot-calculate-changes')) {
					return { resync: true };
				}
				throw new DriveApiError(res.status, body.type ?? 'about:blank', body.code);
			}
			const wire = (await res.json()) as ChangesPageWire | CannotCalculateWire;
			if ('cannotCalculateChanges' in wire) return { resync: true };
			changed.push(...wire.changed);
			cursor = String(wire.newState);
			hasMore = wire.hasMore;
			if (!wire.hasMore) break;
		}
		return { resync: false, newState: cursor, changed, hasMore };
	}

	async accessInvalidations(
		spaceId: number,
		cursor: string | null,
		max = 200,
	): Promise<AccessInvalidationPage> {
		const seen: AccessInvalidationPage['invalidations'] = [];
		let next = cursor;
		let epoch: string | null = null;
		for (let page = 0; page < 20; page++) {
			const qs = new URLSearchParams({ space: String(spaceId), max: String(max) });
			if (next) qs.set('cursor', next);
			const res = await this.fetchFn(this.url(`/access-invalidations?${qs.toString()}`));
			const wire = await okJson<AccessInvalidationPage>(res);
			if (wire.fullReconcile) return wire;
			seen.push(...wire.invalidations);
			next = wire.cursor;
			epoch = wire.epoch;
			if (!wire.hasMore) {
				return { ...wire, cursor: next, epoch, invalidations: seen };
			}
		}
		return { cursor: next, epoch, invalidations: seen, hasMore: true, fullReconcile: false };
	}

	async visibilitySnapshot(
		spaceId: number,
		after: string,
		expectedEpoch: string | null,
		max = 500,
	): Promise<VisibilityPage> {
		const qs = new URLSearchParams({ space: String(spaceId), after, max: String(max) });
		if (expectedEpoch != null) qs.set('epoch', expectedEpoch);
		return okJson<VisibilityPage>(await this.fetchFn(this.url(`/visibility-snapshot?${qs.toString()}`)));
	}

	async nodesMeta(ids: number[]): Promise<NodeMeta[]> {
		if (ids.length === 0) return [];
		const out: NodeMeta[] = [];
		for (const batch of chunked(ids, 500)) {
			const res = await this.fetchFn(this.url(`/nodes?ids=${batch.join(',')}`));
			out.push(...(await okJson<NodeMeta[]>(res)));
		}
		return out;
	}

	async treeChildren(spaceId: number, parentId: number | null): Promise<NodeMeta[]> {
		const qs = parentId != null ? `?parent=${parentId}` : '';
		const res = await this.fetchFn(this.url(`/spaces/${spaceId}/tree${qs}`));
		const rows = await okJson<TreeNodeWire[]>(res);
		// tree() carries no contentSha256 (C7) — callers resolve content shas
		// separately via nodesMeta for the ids they actually need.
		return rows.map((r) => ({
			nodeId: r.id,
			spaceId,
			parentId: r.parentId,
			kind: r.kind,
			name: r.name,
			deletedAt: r.deletedAt ?? null,
			headVersionId: r.headVersionId ?? null,
			contentSha256: null,
			sizeBytes: r.size ?? null,
			contentType: r.contentType ?? null,
		}));
	}

	async spaces(): Promise<SpaceWire[]> {
		const res = await this.fetchFn(this.url('/spaces'));
		return okJson<SpaceWire[]>(res);
	}

	/** I-4 anti-oracle existence probe: true only if the chunk exists AND the
	 *  caller can prove possession — 404 is the expected "not yet uploaded" case. */
	async headChunk(spaceId: number, sha256: string): Promise<boolean> {
		const res = await this.fetchFn(this.url(`/chunks/${sha256}?space=${spaceId}`), { method: 'HEAD' });
		if (res.status === 404) return false;
		if (!res.ok) return throwProblem(res);
		return true;
	}

	async pushChunk(spaceId: number, sha256: string, bytes: Uint8Array): Promise<void> {
		const res = await this.fetchFn(this.url(`/chunks/${sha256}?space=${spaceId}`), {
			method: 'PUT',
			headers: { 'Content-Type': 'application/octet-stream' },
			body: bytes as unknown as BodyInit,
		});
		await okVoid(res);
	}

	async putVersion(fileNodeId: number, body: PutVersionBody): Promise<PutVersionResult> {
		const res = await this.fetchFn(this.url(`/files/${fileNodeId}/versions`), {
			method: 'POST',
			headers: JSON_HEADERS,
			body: JSON.stringify(body),
		});
		return okJson<PutVersionResult>(res);
	}

	/** C2: resolves conflict-sibling materialization — lists every known
	 *  version of a file so the engine can find `conflict_of === head` rows
	 *  not yet materialized locally. */
	async listVersions(fileNodeId: number): Promise<VersionMeta[]> {
		const res = await this.fetchFn(this.url(`/files/${fileNodeId}/versions`));
		return okJson<VersionMeta[]>(res);
	}

	/** P4 Task 17: live open/review branches for a file — the mirror's basis
	 *  for reconciling which siblings should exist locally. Live lanes only
	 *  (server default omits merged/discarded, matching the branch panel). */
	async fileBranches(fileNodeId: number): Promise<BranchMeta[]> {
		const res = await this.fetchFn(this.url(`/files/${fileNodeId}/branches`));
		const wire = await okJson<
			Array<{ id: number; name: string; status: BranchMeta['status']; headVersionId: number; forkedFromVersionId: number }>
		>(res);
		return wire.map((b) => ({
			id: b.id,
			name: b.name,
			status: b.status,
			headVersionId: b.headVersionId,
			forkedFromVersionId: b.forkedFromVersionId,
		}));
	}

	/** LR-6: the mirror polls live locks per space each sync cycle (locks are
	 *  deliberately not journal ops). */
	async spaceLocks(spaceId: number): Promise<LockRow[]> {
		const res = await this.fetchFn(this.url(`/spaces/${spaceId}/locks`));
		return (await okJson<{ locks: LockRow[] }>(res)).locks;
	}

	/** Acquire/heartbeat/presence (§5.4) — the mirror's auto-soft-checkout leg. */
	async lockFile(nodeId: number, body: LockAcquireBody): Promise<LockAcquireResult> {
		const res = await this.fetchFn(this.url(`/files/${nodeId}/lock`), {
			method: 'PUT',
			headers: JSON_HEADERS,
			body: JSON.stringify(body),
		});
		return okJson<LockAcquireResult>(res);
	}

	async contentRange(versionId: number, start: number, endIncl: number): Promise<Uint8Array> {
		const res = await this.fetchFn(this.url(`/versions/${versionId}/content`), {
			headers: { Range: `bytes=${start}-${endIncl}` },
		});
		if (!res.ok) return throwProblem(res);
		return new Uint8Array(await res.arrayBuffer());
	}

	async createNode(
		spaceId: number,
		parentId: number | null,
		kind: 'file' | 'folder',
		name: string,
		contentType?: string
	): Promise<number> {
		const res = await this.fetchFn(this.url('/nodes'), {
			method: 'POST',
			headers: JSON_HEADERS,
			body: JSON.stringify({ spaceId, parentId, kind, name, contentType }),
		});
		return (await okJson<{ id: number }>(res)).id;
	}

	async renameNode(nodeId: number, newName: string): Promise<void> {
		const res = await this.fetchFn(this.url(`/nodes/${nodeId}`), {
			method: 'PATCH',
			headers: JSON_HEADERS,
			body: JSON.stringify({ newName }),
		});
		await okVoid(res);
	}

	async moveNode(nodeId: number, newParentId: number | null): Promise<void> {
		const res = await this.fetchFn(this.url(`/nodes/${nodeId}`), {
			method: 'PATCH',
			headers: JSON_HEADERS,
			body: JSON.stringify({ newParentId }),
		});
		await okVoid(res);
	}

	async trashNode(nodeId: number): Promise<void> {
		await okVoid(await this.fetchFn(this.url(`/nodes/${nodeId}/trash`), { method: 'POST' }));
	}
	async restoreNode(nodeId: number): Promise<void> {
		await okVoid(await this.fetchFn(this.url(`/nodes/${nodeId}/restore`), { method: 'POST' }));
	}
}

export interface BackoffOptions {
	maxRetries?: number;
	baseDelayMs?: number;
	capDelayMs?: number;
	sleep?: (ms: number) => Promise<void>;
}

/** Retries 5xx DriveApiErrors and non-DriveApiError throws (network/timeout);
 *  a 4xx DriveApiError is a client-side mistake and is never retried (an
 *  invalid request looping forever is worse than failing fast). Capped
 *  exponential backoff with jitter. */
export async function withBackoff<T>(fn: () => Promise<T>, opts: BackoffOptions = {}): Promise<T> {
	const maxRetries = opts.maxRetries ?? 5;
	const baseDelayMs = opts.baseDelayMs ?? 200;
	const capDelayMs = opts.capDelayMs ?? 30_000;
	const sleep = opts.sleep ?? ((ms: number) => new Promise((r) => setTimeout(r, ms)));

	let attempt = 0;
	for (;;) {
		try {
			return await fn();
		} catch (err) {
			const retryable = !(err instanceof DriveApiError) || err.status >= 500;
			if (!retryable || attempt >= maxRetries) throw err;
			const delay = Math.min(capDelayMs, baseDelayMs * 2 ** attempt) * (0.5 + Math.random() * 0.5);
			await sleep(delay);
			attempt++;
		}
	}
}
