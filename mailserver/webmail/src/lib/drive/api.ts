// Drive P1 client transport — typed openapi-fetch wrappers over every /api/drive/*
// route routed through $lib/edge/client -> $lib/http's timeout/auth/DPoP machinery.
// Callers branch on `.code` (drive.errors.BZ* i18n keys) via DriveError (= ProblemError).
import { ProblemError, type HttpOptions, type ProblemShape } from '$lib/http';
import { createEdgeClient, EDGE_DEFAULT_ALLOW_STATUSES } from '$lib/edge/client';

const BASE = '/api/drive';

// ── DriveError ───────────────────────────────────────────────────────────
export const DriveError = ProblemError;
export type DriveError = ProblemError;

const PROBLEM_STANDARD_FIELDS = new Set(['type', 'title', 'status', 'detail', 'instance', 'code']);

function buildDriveProblemShape(payload: unknown, status: number): ProblemShape {
	const body = (payload && typeof payload === 'object' ? payload : {}) as Record<string, unknown>;
	const extensions: Record<string, unknown> = {};
	for (const [k, v] of Object.entries(body)) {
		if (!PROBLEM_STANDARD_FIELDS.has(k)) extensions[k] = v;
	}
	const detail =
		typeof body.detail === 'string'
			? body.detail
			: typeof body.title === 'string'
				? body.title
				: `Request failed (${status})`;
	return {
		status,
		code: typeof body.code === 'string' ? body.code : '',
		detail,
		extensions,
	};
}

async function driveProblemOnError(res: Response): Promise<string> {
	const body = await res.json().catch(() => ({}));
	return JSON.stringify(buildDriveProblemShape(body, res.status));
}

function decodeEncodedProblem(err: unknown): ProblemError | null {
	if (!(err instanceof Error)) return null;
	try {
		const p = JSON.parse(err.message) as Partial<ProblemShape>;
		if (typeof p.status === 'number' && typeof p.detail === 'string') {
			return new ProblemError({ extensions: {}, ...p } as ProblemShape);
		}
	} catch {
		/* not an encoded ProblemShape — network/timeout/auth error, pass through */
	}
	return null;
}

const driveEdge = createEdgeClient({
	allowStatuses: [...EDGE_DEFAULT_ALLOW_STATUSES, 416, 423],
	onError: driveProblemOnError,
});

const driveHeadEdge = createEdgeClient({
	allowStatuses: [404],
});

async function runDrive<T>(
	call: () => Promise<{ data?: T; error?: unknown; response: Response }>
): Promise<T> {
	let result: { data?: T; error?: unknown; response: Response };
	try {
		result = await call();
	} catch (err) {
		const problem = decodeEncodedProblem(err);
		if (problem) throw problem;
		throw err;
	}
	const { data, error, response } = result;
	if (!response.ok || error !== undefined || data === undefined) {
		throw new ProblemError(buildDriveProblemShape(error, response.status));
	}
	return data;
}

async function runDriveVoid(
	call: () => Promise<{ error?: unknown; response: Response }>
): Promise<void> {
	let result: { error?: unknown; response: Response };
	try {
		result = await call();
	} catch (err) {
		const problem = decodeEncodedProblem(err);
		if (problem) throw problem;
		throw err;
	}
	const { error, response } = result;
	if (!response.ok || error !== undefined) {
		throw new ProblemError(buildDriveProblemShape(error, response.status));
	}
}

// ── wire types ───────────────────────────────────────────────────────────

export interface DriveSpace {
	id: number;
	name: string;
	isPersonal: boolean;
	classification: 'regular' | 'secure' | 'gxp';
	role: string;
	usedBytes: number;
	quotaBytes: number | null;
	changeSeq: number;
	aclMode?: 'legacy' | 'shadow' | 'acl';
	aclEpoch?: number;
	rootCapabilities?: DriveCapability[];
	accessGovernanceEnabled?: boolean;
	wormPending?: number;
}

export interface DriveMember {
	userId: number;
	role: string;
	email: string;
	displayName: string;
	grantedAt: string;
}

export interface DriveLockPresence {
	holderId: number;
	holderName: string;
	mode: string;
	branchId: number | null;
	acquiredAt: string;
	expiresAt: string;
}

export interface DriveNode {
	id: number;
	parentId: number | null;
	kind: 'folder' | 'file';
	name: string;
	size?: number;
	contentType?: string;
	headVersionId?: number;
	deletedAt?: string;
	branchCount: number;
	lock: DriveLockPresence | null;
	capabilities?: DriveCapability[];
	traverseOnly?: boolean;
}

export interface DriveNodeMeta {
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
	branchCount: number;
	capabilities: DriveCapability[];
	traverseOnly: boolean;
}

export type DriveCapability =
	| 'traverse' | 'list_children' | 'read_metadata' | 'preview' | 'download'
	| 'create_child' | 'modify_content' | 'rename' | 'move' | 'delete'
	| 'manage_acl' | 'view_audit';
export type DrivePreset = 'viewer' | 'contributor' | 'editor' | 'folder_manager';
export type DriveACLRelation = 'direct' | 'inherited';

export interface DriveACLGrant {
	grantId: string;
	anchorNodeId: string;
	anchorName: string;
	subjectKind: 'user' | 'group';
	subjectId: string;
	subjectLabel: string;
	subjectSecondary?: string | null;
	preset: DrivePreset | 'custom';
	capabilities: DriveCapability[];
	propagation: 'self' | 'children' | 'subtree';
	source: 'direct' | 'group' | 'legacy_folder_admin' | 'approval' | 'emergency';
	relation: DriveACLRelation;
	startsAt?: string | null;
	expiresAt?: string | null;
	maxUses?: number | null;
	usedCount: number;
	createdAt: string;
}

export interface DriveAccessSource {
	capability: DriveCapability;
	sourceKind: 'space_role' | 'direct' | 'group' | 'folder_admin';
	sourceId?: string | null;
	anchorNodeId?: string | null;
}

export interface DriveNodeAccess {
	nodeId: string;
	spaceId: string;
	nodeName: string;
	nodeKind: 'folder' | 'file';
	aclMode: 'legacy' | 'shadow' | 'acl';
	epoch: string;
	capabilities: DriveCapability[];
	traverseOnly: boolean;
	canManage: boolean;
	writesEnabled: boolean;
	governanceEnabled: boolean;
	inheritanceBroken: boolean;
	grants: DriveACLGrant[];
	sources: DriveAccessSource[];
	presets: DrivePreset[];
}

export interface DriveACLSubject {
	kind: 'user' | 'group';
	id: string;
	label: string;
	secondary?: string;
}

export interface DriveInheritancePreview {
	nodeId: string;
	spaceId: string;
	epoch: string;
	requestedBreak: boolean;
	currentBreak: boolean;
	changed: boolean;
	affectedNodeCount: number;
	affectedPrincipalCount: number;
	currentManagerSourceCount: number;
	mayRemoveOfflineContent: boolean;
}

export interface DriveQuickViewItem {
	kind: 'shared' | 'share' | 'request';
	nodeId: string;
	spaceId: string;
	name: string;
	nodeKind: 'folder' | 'file';
	spaceName: string;
	source?: 'direct' | 'group';
	preset?: DrivePreset | 'custom';
	sharedAt?: string;
	activeGrantCount?: number;
	requestId?: string;
	status?: string;
	capabilities?: DriveCapability[];
	propagation?: 'self' | 'children' | 'subtree';
	expiresAt?: string;
	createdAt?: string;
	grantId?: string | null;
}

export interface DriveChange {
	nodeId: number;
	op: string;
	seq: number;
}

export interface DriveChangesResult {
	cannotCalculateChanges?: boolean;
	newState?: number;
	changed?: DriveChange[];
	hasMore?: boolean;
}

export interface DriveVersion {
	id: number;
	parentVersionId: number | null;
	conflictOf: number | null;
	sha256: string;
	size: number;
	contentType?: string;
	author: number;
	deviceLabel?: string;
	note?: string;
	previewStatus: string;
	createdAt: string;
	branchId: number | null;
	labels: string[];
}

export interface DriveHistoryItem {
	occurredAt: string;
	sourceRank: number;
	sourceId: string | number;
	source: string;
	kind: string;
	details: Record<string, unknown> | null;
}

export interface DriveHistoryCoverage {
	mode: string;
	freshnessSeconds: number | null;
	coveredSources: string[];
	omissions: string[];
}

export interface DriveHistoryResult {
	items: DriveHistoryItem[];
	hasMore: boolean;
	nextCursor: string | null;
	coverage: DriveHistoryCoverage;
	generatedAt: string;
}

export interface PutVersionResult {
	versionId: number;
	conflict: boolean;
	branchId: number | null;
	headVersionId: number | null;
	wormPending: boolean;
}

// ── spaces ───────────────────────────────────────────────────────────────

export const listSpaces = () =>
	runDrive(() => driveEdge.GET('/api/drive/spaces')) as Promise<DriveSpace[]>;

export const listSpacesAdmin = () =>
	runDrive(() => driveEdge.GET('/api/drive/spaces', { params: { query: { admin: '1' } } })) as Promise<DriveSpace[]>;

export const createSpace = (body: {
	name: string;
	classification?: 'regular' | 'secure' | 'gxp';
	isPersonal?: boolean;
	retentionDays?: number | null;
	wormMode?: string | null;
	exportPolicy?: unknown;
}) =>
	runDrive(() =>
		driveEdge.POST('/api/drive/spaces', {
			body: body as {
				name: string;
				classification?: 'regular' | 'secure' | 'gxp';
				isPersonal?: boolean;
				retentionDays?: number | null;
				wormMode?: string | null;
				exportPolicy?: Record<string, unknown>;
			},
		})
	);

export const patchSpace = (id: number, fields: Record<string, unknown>) =>
	runDriveVoid(() =>
		driveEdge.PATCH('/api/drive/spaces/{id}', {
			params: { path: { id } },
			body: fields,
		})
	);

// ── members ──────────────────────────────────────────────────────────────

export const listMembers = (spaceId: number) =>
	runDrive(() => driveEdge.GET('/api/drive/spaces/{id}/members', { params: { path: { id: spaceId } } })) as Promise<DriveMember[]>;

export const grantMember = (spaceId: number, userId: number, role: string) =>
	runDrive(() =>
		driveEdge.POST('/api/drive/spaces/{id}/members', {
			params: { path: { id: spaceId } },
			body: { userId, role },
		})
	) as Promise<{ status: string }>;

export const revokeMember = (spaceId: number, userId: number) =>
	runDriveVoid(() =>
		driveEdge.DELETE('/api/drive/spaces/{id}/members/{userId}', {
			params: { path: { id: spaceId, userId } },
		})
	);

// ── tree ─────────────────────────────────────────────────────────────────

export const tree = (spaceId: number, opts: { parent?: number | null; deleted?: boolean } = {}) => {
	const query: { parent?: number; deleted?: string } = {};
	if (opts.parent != null) query.parent = opts.parent;
	if (opts.deleted) query.deleted = '1';
	return runDrive(() =>
		driveEdge.GET('/api/drive/spaces/{id}/tree', {
			params: {
				path: { id: spaceId },
				query: Object.keys(query).length ? query : undefined,
			},
		})
	) as Promise<DriveNode[]>;
};

// ── changes ──────────────────────────────────────────────────────────────

export const changes = (spaceId: number, since: number) =>
	runDrive(() =>
		driveEdge.GET('/api/drive/changes', {
			params: { query: { space: spaceId, since } },
		})
	) as Promise<DriveChangesResult>;

// ── nodes ────────────────────────────────────────────────────────────────

export const getNodesMeta = (ids: number[]) =>
	runDrive(() =>
		driveEdge.GET('/api/drive/nodes', {
			params: { query: { ids: ids.join(',') } },
		})
	) as Promise<DriveNodeMeta[]>;

export const createNode = (body: {
	spaceId: number;
	parentId: number | null;
	kind: 'folder' | 'file';
	name: string;
	contentType?: string | null;
}) => runDrive(() => driveEdge.POST('/api/drive/nodes', { body }));

export const renameNode = (id: number, newName: string) =>
	runDriveVoid(() =>
		driveEdge.PATCH('/api/drive/nodes/{id}', {
			params: { path: { id } },
			body: { newName },
		})
	);

export const moveNode = (id: number, newParentId: number | null) =>
	runDriveVoid(() =>
		driveEdge.PATCH('/api/drive/nodes/{id}', {
			params: { path: { id } },
			body: { newParentId },
		})
	);

export const trashNode = (id: number) =>
	runDriveVoid(() => driveEdge.POST('/api/drive/nodes/{id}/trash', { params: { path: { id } } }));

export const restoreNode = (id: number) =>
	runDriveVoid(() => driveEdge.POST('/api/drive/nodes/{id}/restore', { params: { path: { id } } }));

export const destroyNode = (id: number) =>
	runDriveVoid(() => driveEdge.DELETE('/api/drive/nodes/{id}', { params: { path: { id } } }));

// ── node ACL and governed-access UX ─────────────────────────────────────

export const getNodeAccess = (nodeId: number) =>
	runDrive(() => driveEdge.GET('/api/drive/nodes/{id}/access', { params: { path: { id: nodeId } } })) as Promise<DriveNodeAccess>;

export const searchACLSubjects = (nodeId: number, query: string) =>
	runDrive(() =>
		driveEdge.GET('/api/drive/acl-subjects', {
			params: { query: { node: nodeId, q: query } },
		})
	) as Promise<DriveACLSubject[]>;

export interface DriveGrantInput {
	subjectKind: 'user' | 'group';
	subjectId: string;
	preset: DrivePreset;
	scope: 'self' | 'subtree';
	startsAt?: string;
	expiresAt?: string;
	maxUses?: number;
	reason?: string;
}

export const previewNodeGrant = (nodeId: number, body: DriveGrantInput) =>
	runDrive(() =>
		driveEdge.POST('/api/drive/nodes/{id}/acl/preview', {
			params: { path: { id: nodeId } },
			body,
		})
	) as Promise<Record<string, unknown>>;

export const grantNodeAccess = (nodeId: number, body: DriveGrantInput & { expectedEpoch: string; idempotencyKey: string }) =>
	runDrive(() =>
		driveEdge.POST('/api/drive/nodes/{id}/acl', {
			params: { path: { id: nodeId }, header: { 'Idempotency-Key': body.idempotencyKey } },
			body,
		})
	);

export const revokeNodeGrant = (grantId: string, expectedEpoch: string, reason: string) =>
	runDrive(() =>
		driveEdge.DELETE('/api/drive/acl-grants/{id}', {
			params: { path: { id: grantId } },
			body: { expectedEpoch, reason },
		})
	) as Promise<{ grantId: string; epoch: string; state: 'revoked' }>;

export const previewNodeInheritance = (nodeId: number, value: boolean) =>
	runDrive(() =>
		driveEdge.POST('/api/drive/nodes/{id}/inheritance/preview', {
			params: { path: { id: nodeId } },
			body: { break: value },
		})
	) as Promise<DriveInheritancePreview>;

export const setNodeInheritance = (nodeId: number, value: boolean, expectedEpoch: string) =>
	runDrive(() =>
		driveEdge.PUT('/api/drive/nodes/{id}/inheritance', {
			params: { path: { id: nodeId } },
			body: { break: value, expectedEpoch },
		})
	);

export const listDriveQuickView = (view: 'shared' | 'shares' | 'requests') =>
	runDrive(() =>
		driveEdge.GET('/api/drive/quick-views', {
			params: { query: { view } },
		})
	) as Promise<DriveQuickViewItem[]>;

export interface DriveAccessRequestInput {
	subjectKind: 'user' | 'group';
	subjectId: string;
	capabilities: DriveCapability[];
	propagation: 'self' | 'children' | 'subtree';
	durationMinutes: number;
	maxUses?: number;
	emergency?: boolean;
	mfaSessionId?: string;
	reason: string;
}

export const previewDriveAccessRequest = (nodeId: number, body: DriveAccessRequestInput) =>
	runDrive(() =>
		driveEdge.POST('/api/drive/nodes/{id}/access-requests/preview', {
			params: { path: { id: nodeId } },
			body,
		})
	) as Promise<Record<string, unknown>>;

export const createDriveAccessRequest = (nodeId: number, body: DriveAccessRequestInput & { idempotencyKey: string }) =>
	runDrive(() =>
		driveEdge.POST('/api/drive/nodes/{id}/access-requests', {
			params: { path: { id: nodeId }, header: { 'Idempotency-Key': body.idempotencyKey } },
			body,
		})
	) as Promise<{ requestId: string; status: 'pending'; replayed: boolean }>;

// ── chunks (spec §3.3) ───────────────────────────────────────────────────

export async function headChunk(spaceId: number, sha256: string): Promise<boolean> {
	const { response } = await driveHeadEdge.HEAD('/api/drive/chunks/{sha256}', {
		params: { path: { sha256 }, query: { space: spaceId } },
		parseAs: 'stream',
	});
	return response.status === 200;
}

export const putChunk = (spaceId: number, sha256: string, bytes: Uint8Array<ArrayBuffer>) =>
	runDriveVoid(() =>
		driveEdge.PUT('/api/drive/chunks/{sha256}', {
			params: { path: { sha256 }, query: { space: spaceId } },
			headers: { 'Content-Type': 'application/octet-stream' },
			body: bytes as unknown as string,
			bodySerializer: (b) => b as unknown as BodyInit,
		})
	);

// ── versions / content ───────────────────────────────────────────────────

export const putVersion = (
	nodeId: number,
	body: {
		contentSha256: string;
		size: number;
		contentType?: string | null;
		baseVersionId: number | null;
		manifest: { sha256: string; size: number }[];
		note?: string;
		deviceLabel?: string;
		branchId?: number | null;
	},
) =>
	runDrive(() =>
		driveEdge.POST('/api/drive/files/{id}/versions', {
			params: { path: { id: nodeId } },
			body,
		})
	) as Promise<PutVersionResult>;

export const listVersions = (nodeId: number) =>
	runDrive(() => driveEdge.GET('/api/drive/files/{id}/versions', { params: { path: { id: nodeId } } })) as Promise<DriveVersion[]>;

export const history = (
	nodeId: number,
	opts: { limit?: number; cursor?: string | null } = {},
) => {
	const query: { limit?: number; cursor?: string } = {};
	if (opts.limit != null) query.limit = opts.limit;
	if (opts.cursor) query.cursor = opts.cursor;
	return runDrive(() =>
		driveEdge.GET('/api/drive/files/{id}/history', {
			params: {
				path: { id: nodeId },
				query: Object.keys(query).length ? query : undefined,
			},
		})
	) as Promise<DriveHistoryResult>;
};

export interface OfficeChoice {
	providerId: string;
	mode: 'edit_online';
	fileFamily: 'word' | 'sheet' | 'presentation';
	available: boolean;
	buildId: string | null;
}

export interface OfficeChoicesResult {
	fileFamily: 'word' | 'sheet' | 'presentation';
	platform: 'web' | 'electron';
	localOpenAllowed: boolean;
	choices: OfficeChoice[];
}

export interface OfficeLaunchResult {
	launchId: string;
	sessionId: string;
	fenceGeneration: number;
	expiresAt: string;
	accessToken: string;
	wopiSrc: string;
	editorUrl: string;
}

export const officeChoices = (nodeId: number, platform: 'web' | 'electron') =>
	runDrive(() =>
		driveEdge.GET('/api/drive/files/{id}/office/choices', {
			params: { path: { id: nodeId }, query: { platform } },
		})
	) as Promise<OfficeChoicesResult>;

export const officeLaunch = (
	nodeId: number,
	body: { baseVersionId: number; providerId: string; deviceId: string; cohortKey: string },
) =>
	runDrive(() =>
		driveEdge.POST('/api/drive/files/{id}/office/launches', {
			params: { path: { id: nodeId } },
			body,
		})
	) as Promise<OfficeLaunchResult>;

export const officeRevoke = (nodeId: number, launchId: string) =>
	runDriveVoid(() =>
		driveEdge.DELETE('/api/drive/files/{id}/office/launches/{launchId}', {
			params: { path: { id: nodeId, launchId } },
		})
	);

export const restoreVersion = (
	nodeId: number,
	versionId: number,
	body: { baseVersionId?: number | null; note?: string; deviceLabel?: string; branchId?: number | null } = {},
) =>
	runDrive(() =>
		driveEdge.POST('/api/drive/files/{id}/versions/{versionId}/restore', {
			params: { path: { id: nodeId, versionId } },
			body,
		})
	) as Promise<PutVersionResult>;

export const contentUrl = (versionId: number) => `${BASE}/versions/${versionId}/content`;

export const previewUrl = (versionId: number) => `${BASE}/versions/${versionId}/preview`;

function ensureReadableResponse(response: Response, parsedError: unknown): Response {
	if (response.ok || !response.bodyUsed) return response;
	const body =
		parsedError === undefined || parsedError === null
			? null
			: typeof parsedError === 'string'
				? parsedError
				: JSON.stringify(parsedError);
	const headers = new Headers(response.headers);
	if (body !== null && !headers.has('content-type') && typeof parsedError === 'object') {
		headers.set('content-type', 'application/problem+json');
	}
	return new Response(body, {
		status: response.status,
		statusText: response.statusText,
		headers,
	});
}

/** Fetches regular original content (including Range / 206 Partial Content). */
export async function fetchVersionContent(versionId: number, opts: HttpOptions = {}): Promise<Response> {
	const driveContentEdge = createEdgeClient({
		timeoutMs: opts.timeoutMs,
		cache: opts.cache,
		loginRedirect: opts.loginRedirect,
		unauthorizedMessage: opts.unauthorizedMessage,
		forbiddenMessage: opts.forbiddenMessage,
		onError: opts.onError,
		allowStatuses: opts.allowStatuses ?? [],
	});
	const { error, response } = await driveContentEdge.GET('/api/drive/versions/{id}/content', {
		params: { path: { id: versionId } },
		headers: opts.headers,
		signal: opts.signal,
		credentials: opts.credentials,
		parseAs: 'stream',
	});
	return ensureReadableResponse(response, error);
}

/** Fetches the server-generated office rendition under exact preview authority. */
export async function fetchVersionPreview(versionId: number, opts: HttpOptions = {}): Promise<Response> {
	const drivePreviewEdge = createEdgeClient({
		timeoutMs: opts.timeoutMs,
		cache: opts.cache,
		loginRedirect: opts.loginRedirect,
		unauthorizedMessage: opts.unauthorizedMessage,
		forbiddenMessage: opts.forbiddenMessage,
		onError: opts.onError,
		allowStatuses: opts.allowStatuses ?? [],
	});
	const { error, response } = await drivePreviewEdge.GET('/api/drive/versions/{id}/preview', {
		params: { path: { id: versionId } },
		headers: opts.headers,
		signal: opts.signal,
		credentials: opts.credentials,
		parseAs: 'stream',
	});
	return ensureReadableResponse(response, error);
}

// ── branches (P4 §5.1/§5.2) ─────────────────────────────────────────────────

export interface DriveBranch {
	id: number;
	name: string;
	status: 'open' | 'review' | 'merged' | 'discarded';
	autoCreated: boolean;
	headVersionId: number;
	forkedFromVersionId: number;
	createdBy: number;
	createdAt: string;
	resolvedBy: number | null;
	resolvedAt: string | null;
	ffEligible: boolean;
}

export const listBranches = (nodeId: number, opts: { all?: boolean } = {}) =>
	runDrive(() =>
		driveEdge.GET('/api/drive/files/{id}/branches', {
			params: {
				path: { id: nodeId },
				query: opts.all ? { all: '1' } : undefined,
			},
		})
	) as Promise<DriveBranch[]>;

export const createBranch = (nodeId: number, name: string, fromVersionId: number) =>
	runDrive(() =>
		driveEdge.POST('/api/drive/files/{id}/branches', {
			params: { path: { id: nodeId } },
			body: { name, fromVersionId },
		})
	);

export const renameBranch = (branchId: number, name: string) =>
	runDriveVoid(() =>
		driveEdge.PATCH('/api/drive/branches/{id}', {
			params: { path: { id: branchId } },
			body: { name },
		})
	);

export const setBranchStatus = (branchId: number, status: 'open' | 'review') =>
	runDriveVoid(() =>
		driveEdge.PATCH('/api/drive/branches/{id}', {
			params: { path: { id: branchId } },
			body: { status },
		})
	);

export type ResolveVerb = 'ff' | 'adopt' | 'keep_both' | 'discard';

export interface ResolveBranchResult {
	verb: ResolveVerb;
	headVersionId: number | null;
	newNodeId: number | null;
}

export const resolveBranch = (branchId: number, verb: ResolveVerb, newName?: string) =>
	runDrive(() =>
		driveEdge.POST('/api/drive/branches/{id}/resolve', {
			params: { path: { id: branchId } },
			body: { verb, newName: newName ?? null },
		})
	) as Promise<ResolveBranchResult>;

// ── version labels ───────────────────────────────────────────────────────

export const setLabel = (versionId: number, label: string) =>
	runDriveVoid(() =>
		driveEdge.POST('/api/drive/versions/{id}/labels', {
			params: { path: { id: versionId } },
			body: { label },
		})
	);

export const removeLabel = (versionId: number, label: string) =>
	runDriveVoid(() =>
		driveEdge.DELETE('/api/drive/versions/{id}/labels/{label}', {
			params: { path: { id: versionId, label } },
		})
	);

// ── locks (§5.4) ─────────────────────────────────────────────────────────

export interface LockAcquireResult {
	status: 'acquired' | 'renewed' | 'held';
	mode?: string;
	expiresAt?: string;
	holderId?: number;
	since?: string;
	branchId?: number | null;
}

export const lockFile = (
	nodeId: number,
	body: {
		mode?: 'soft' | 'hard';
		branchId?: number | null;
		versionId?: number | null;
		deviceLabel?: string;
		ttlMinutes?: number;
	} = {},
) =>
	runDrive(() =>
		driveEdge.PUT('/api/drive/files/{id}/lock', {
			params: { path: { id: nodeId } },
			body,
		})
	) as Promise<LockAcquireResult>;

export const unlockFile = (nodeId: number, opts: { break?: boolean; keepalive?: boolean } = {}) =>
	runDriveVoid(() =>
		driveEdge.DELETE('/api/drive/files/{id}/lock', {
			params: {
				path: { id: nodeId },
				query: opts.break ? { break: '1' } : undefined,
			},
			keepalive: opts.keepalive,
		})
	);

export interface DriveLockRow {
	nodeId: number;
	name: string;
	holderId: number;
	holderName: string;
	mode: string;
	branchId: number | null;
	acquiredAt: string;
	expiresAt: string;
	deviceLabel: string | null;
}

export const listLocks = (spaceId: number) =>
	runDrive(() => driveEdge.GET('/api/drive/spaces/{id}/locks', { params: { path: { id: spaceId } } })) as Promise<{ locks: DriveLockRow[] }>;

// ── watches (§5.6) ───────────────────────────────────────────────────────

export const setWatch = (nodeId: number, ops?: string[]) =>
	runDriveVoid(() =>
		driveEdge.PUT('/api/drive/nodes/{id}/watch', {
			params: { path: { id: nodeId } },
			body: { ops: ops ?? null },
		})
	);

export const removeWatch = (nodeId: number) =>
	runDriveVoid(() => driveEdge.DELETE('/api/drive/nodes/{id}/watch', { params: { path: { id: nodeId } } }));

// ── activity feed (§5.6, LR-2) ──────────────────────────────────────────

export interface DriveActivityItem {
	id: number;
	action: string;
	actorId: number;
	actorName: string;
	targetType: string;
	targetId: number;
	at: string;
	notes: string | null;
}

export const activity = (spaceId: number, opts: { node?: number; beforeId?: number; max?: number } = {}) => {
	const query: { node?: number; beforeId?: number; max?: number } = {};
	if (opts.node != null) query.node = opts.node;
	if (opts.beforeId != null) query.beforeId = opts.beforeId;
	if (opts.max != null) query.max = opts.max;
	return runDrive(() =>
		driveEdge.GET('/api/drive/spaces/{id}/activity', {
			params: {
				path: { id: spaceId },
				query: Object.keys(query).length ? query : undefined,
			},
		})
	) as Promise<{ items: DriveActivityItem[] }>;
};

// ── folder admins (§5.5) ─────────────────────────────────────────────────

export interface DriveFolderAdmin {
	userId: number;
	displayName: string;
	grantedBy: number;
	grantedAt: string;
}

export const listFolderAdmins = (nodeId: number) =>
	runDrive(() => driveEdge.GET('/api/drive/nodes/{id}/folder-admins', { params: { path: { id: nodeId } } })) as Promise<DriveFolderAdmin[]>;

export const grantFolderAdmin = (nodeId: number, userId: number) =>
	runDriveVoid(() =>
		driveEdge.PUT('/api/drive/nodes/{id}/folder-admins/{userId}', {
			params: { path: { id: nodeId, userId } },
		})
	);

export const revokeFolderAdmin = (nodeId: number, userId: number) =>
	runDriveVoid(() =>
		driveEdge.DELETE('/api/drive/nodes/{id}/folder-admins/{userId}', {
			params: { path: { id: nodeId, userId } },
		})
	);

// ── P5 compliance: audit-chain verify ────────────────────────────────────

export interface AuditVerifyResult {
	checked: number;
	broken: number[];
}

export const verifyAuditChain = (spaceId: number) =>
	runDrive(() => driveEdge.GET('/api/drive/spaces/{id}/audit/verify', { params: { path: { id: spaceId } } }));

// ── P5 compliance: export/print approval flow ────────────────────────────

export type ExportAction = 'download' | 'print';

export interface ExportRequestResult {
	status: 'granted' | 'pending';
	grantId?: number;
	requestId?: number;
	token: string;
}

export const requestExport = (versionId: number, action: ExportAction, ttlMinutes?: number) =>
	runDrive(() =>
		driveEdge.POST('/api/drive/export', {
			body: ttlMinutes !== undefined ? { versionId, action, ttlMinutes } : { versionId, action },
		})
	) as Promise<ExportRequestResult>;

export const exportDownloadUrl = (token: string) => `${BASE}/export/${encodeURIComponent(token)}`;

// ── P6: name search (§6.4) ──────────────────────────────────────────────

export interface DriveSearchItem {
	id: number;
	spaceId: number;
	parentId: number | null;
	kind: 'folder' | 'file';
	name: string;
	sizeBytes?: number;
	contentType?: string;
	createdAt: string;
}

export const searchNodes = (
	q: string,
	opts: { spaceId?: number | null; max?: number; signal?: AbortSignal } = {},
) => {
	const query: { q: string; space?: number; max?: number } = { q };
	if (opts.spaceId != null) query.space = opts.spaceId;
	if (opts.max != null) query.max = opts.max;
	return runDrive(() =>
		driveEdge.GET('/api/drive/search', {
			params: { query },
			signal: opts.signal,
		})
	) as Promise<{ items: DriveSearchItem[] }>;
};

// ── P6: watch list (§5.6 subscription manager) ──────────────────────────

export interface DriveWatchRow {
	nodeId: number;
	nodeName: string;
	kind: 'folder' | 'file';
	ops: string[] | null;
}

export const listWatches = () =>
	runDrive(() => driveEdge.GET('/api/drive/watches')) as Promise<DriveWatchRow[]>;

// ── P6: admin tier-2 trash (the "admin bin") ─────────────────────────────

export interface DriveTrashItem {
	id: number;
	name: string;
	kind: 'folder' | 'file';
	purgedAt: string;
	purgedBy: string | null;
	deletedAt: string | null;
	sizeBytes: number;
}

export const trashAdminList = (spaceId: number) =>
	runDrive(() =>
		driveEdge.GET('/api/drive/spaces/{id}/trash', {
			params: { path: { id: spaceId }, query: { tier: 2 } },
		})
	) as Promise<{ items: DriveTrashItem[] }>;

export const purgeRestore = (nodeId: number) =>
	runDriveVoid(() => driveEdge.POST('/api/drive/nodes/{id}/purge-restore', { params: { path: { id: nodeId } } }));

// ── P6: audit query + CSV export (§9.3) ──────────────────────────────────

export interface DriveAuditRow {
	id: number;
	occurredAt: string;
	userId: number | null;
	userEmail: string;
	ip: string;
	action: string;
	targetType?: string;
	targetId?: number;
	notes?: string;
}

export interface AuditQueryParams {
	spaceId: number;
	actor?: number | null;
	action?: string | null;
	from?: string | null;
	to?: string | null;
	q?: string | null;
	max?: number;
	beforeId?: number | null;
}

function auditSearchParams(p: AuditQueryParams): URLSearchParams {
	const params = new URLSearchParams({ space: String(p.spaceId) });
	if (p.actor != null) params.set('actor', String(p.actor));
	if (p.action) params.set('action', p.action);
	if (p.from) params.set('from', p.from);
	if (p.to) params.set('to', p.to);
	if (p.q) params.set('q', p.q);
	if (p.max != null) params.set('max', String(p.max));
	if (p.beforeId != null) params.set('beforeId', String(p.beforeId));
	return params;
}

export const queryAudit = (p: AuditQueryParams) => {
	const query: {
		space: number;
		actor?: number;
		action?: string;
		from?: string;
		to?: string;
		q?: string;
		max?: number;
		beforeId?: number;
	} = { space: p.spaceId };
	if (p.actor != null) query.actor = p.actor;
	if (p.action) query.action = p.action;
	if (p.from) query.from = p.from;
	if (p.to) query.to = p.to;
	if (p.q) query.q = p.q;
	if (p.max != null) query.max = p.max;
	if (p.beforeId != null) query.beforeId = p.beforeId;
	return runDrive(() =>
		driveEdge.GET('/api/drive/audit', {
			params: { query },
		})
	) as Promise<{ items: DriveAuditRow[]; hasMore: boolean }>;
};

export const auditCsvUrl = (p: AuditQueryParams) => {
	const params = auditSearchParams(p);
	params.set('format', 'csv');
	return `${BASE}/audit?${params.toString()}`;
};

// ── P6: audit alarm rules CRUD (§9.3) ────────────────────────────────────

export interface DriveAuditAlarm {
	id: number;
	spaceId: number | null;
	actionPattern: string;
	threshold: number;
	windowMinutes: number;
	enabled: boolean;
	createdBy: number | null;
	createdAt: string;
}

export const getAuditActions = () =>
	runDrive(() => driveEdge.GET('/api/drive/audit-actions'));

export const listAuditAlarms = () =>
	runDrive(() => driveEdge.GET('/api/drive/audit-alarms')) as Promise<DriveAuditAlarm[]>;

export const createAuditAlarm = (body: {
	spaceId?: number | null;
	actionPattern: string;
	threshold?: number;
	windowMinutes?: number;
}) => runDrive(() => driveEdge.POST('/api/drive/audit-alarms', { body }));

export const updateAuditAlarm = (id: number, fields: Record<string, unknown>) =>
	runDriveVoid(() =>
		driveEdge.PATCH('/api/drive/audit-alarms/{id}', {
			params: { path: { id } },
			body: fields,
		})
	);

export const deleteAuditAlarm = (id: number) =>
	runDriveVoid(() => driveEdge.DELETE('/api/drive/audit-alarms/{id}', { params: { path: { id } } }));

// ── P6: "space as of T" time-point view ──────────────────────────────────

export interface DriveAsOfItem {
	id: number;
	parentId: number | null;
	kind: 'folder' | 'file';
	name: string;
	versionId: number | null;
	versionCreatedAt: string | null;
	sizeBytes?: number;
	contentType?: string;
	liveNow: boolean;
}

export const spaceAsOf = (spaceId: number, at: string) =>
	runDrive(() =>
		driveEdge.GET('/api/drive/spaces/{id}/asof', {
			params: { path: { id: spaceId }, query: { at } },
		})
	) as Promise<{ items: DriveAsOfItem[] }>;
