// Drive P1 client transport — typed fetch wrappers over every /api/drive/*
// route (Tasks 17-20). Reuses $lib/http's timeout/auth/DPoP machinery
// (httpRequest/typedFetch) rather than re-implementing it — callers branch on
// `.code` (drive.errors.BZ* i18n keys) instead of parsing status text.
import { httpRequest, typedFetch, problemFetch, ProblemError, type HttpOptions } from '$lib/http';

const BASE = '/api/drive';

// ── DriveError ───────────────────────────────────────────────────────────
//
// Arch review #A1: ChatError/MeetError/DriveError were three verbatim copies
// of the same RFC-7807-via-encoded-message transport (`$lib/http.ts`'s
// problemFetch), differing only in this one's `holderId` field — now just
// another `extensions` entry. DriveError is a plain alias onto the one
// shared `ProblemError` class; every existing call site (`instanceof
// DriveError`, `.status`/`.code`/`.detail`) keeps working unchanged. The one
// `.holderId` reader (versionSave.svelte.ts, BZ149 hard-lock) moved to
// `.extensions.holderId`.
export const DriveError = ProblemError;
export type DriveError = ProblemError;

const { fetch: driveFetch, fetchVoid: driveFetchVoid } = problemFetch(BASE);

const JSON_HEADERS = { 'Content-Type': 'application/json' };

// ── wire types (mirrors mailserver/internal/drive/*.go response structs) ──

export interface DriveSpace {
	id: number;
	name: string;
	isPersonal: boolean;
	classification: 'regular' | 'secure' | 'gxp';
	role: string;
	usedBytes: number;
	quotaBytes: number | null;
	changeSeq: number;
	/** Present on ACL-aware servers; optional keeps rolling-upgrade clients
	 * compatible with a pre-A7 node until the server fleet converges. */
	aclMode?: 'legacy' | 'shadow' | 'acl';
	aclEpoch?: number;
	rootCapabilities?: DriveCapability[];
	accessGovernanceEnabled?: boolean;
	/** P5 G1 admin surface (drive_worm_pending, merged into ?admin=1 rows) —
	 *  count of this space's gxp chunks whose Object-Lock apply is still
	 *  pending. Absent on the member-scoped /spaces read and on any backend
	 *  build that hasn't wired the merge yet; callers default to 0. */
	wormPending?: number;
}

export interface DriveMember {
	userId: number;
	role: string;
	email: string;
	displayName: string;
	grantedAt: string;
}

/** Unexpired lock-presence row on a tree node (P4 Task 10's tree() LATERAL) — null when unlocked. */
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
	/** Open+review branch count (P4 Task 10). 0 for folders. */
	branchCount: number;
	/** Unexpired lock row, or null (P4 Task 10). */
	lock: DriveLockPresence | null;
	/** Exact server-computed node authority. Absent only during rolling upgrade;
	 * callers fail closed instead of inferring from the legacy space role. */
	capabilities?: DriveCapability[];
	traverseOnly?: boolean;
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

/**
 * Normalized, permission-filtered file-history fact returned by the H0
 * authority query.  `sourceId` stays opaque to the default timeline; it is
 * exposed only by the forensic Details view.
 */
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

export const listSpaces = () => driveFetch<DriveSpace[]>('/spaces');

/** Cross-tenant metadata read for a drive.view admin (handler.go's
 *  listSpacesAdmin, ?admin=1) — every space, not just ones the caller is a
 *  member of. The P5 admin console's compliance panel and the wormPending
 *  queue both need every gxp space, not just the admin's own. */
export const listSpacesAdmin = () => driveFetch<DriveSpace[]>('/spaces?admin=1');

export const createSpace = (body: {
	name: string;
	classification?: 'regular' | 'secure' | 'gxp';
	isPersonal?: boolean;
	retentionDays?: number | null;
	wormMode?: string | null;
	exportPolicy?: unknown;
}) => driveFetch<{ id: number }>('/spaces', { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify(body) });

/** Field-driven patch — see handler.go's patchSpace: presence of a key picks
 *  its route (classification | exportPolicy/retentionDays/wormMode/vaultQuotaMb | quotaBytes). */
export const patchSpace = (id: number, fields: Record<string, unknown>) =>
	driveFetchVoid(`/spaces/${id}`, { method: 'PATCH', headers: JSON_HEADERS, body: JSON.stringify(fields) });

// ── members ──────────────────────────────────────────────────────────────

export const listMembers = (spaceId: number) => driveFetch<DriveMember[]>(`/spaces/${spaceId}/members`);

export const grantMember = (spaceId: number, userId: number, role: string) =>
	driveFetch<{ status: string }>(`/spaces/${spaceId}/members`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ userId, role }),
	});

export const revokeMember = (spaceId: number, userId: number) =>
	driveFetchVoid(`/spaces/${spaceId}/members/${userId}`, { method: 'DELETE' });

// ── tree ─────────────────────────────────────────────────────────────────

export const tree = (spaceId: number, opts: { parent?: number | null; deleted?: boolean } = {}) => {
	const params = new URLSearchParams();
	if (opts.parent != null) params.set('parent', String(opts.parent));
	if (opts.deleted) params.set('deleted', '1');
	const qs = params.toString();
	return driveFetch<DriveNode[]>(`/spaces/${spaceId}/tree${qs ? '?' + qs : ''}`);
};

// ── changes ──────────────────────────────────────────────────────────────

export const changes = (spaceId: number, since: number) =>
	driveFetch<DriveChangesResult>(`/changes?space=${spaceId}&since=${since}`);

// ── nodes ────────────────────────────────────────────────────────────────

export const createNode = (body: {
	spaceId: number;
	parentId: number | null;
	kind: 'folder' | 'file';
	name: string;
	contentType?: string | null;
}) => driveFetch<{ id: number }>('/nodes', { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify(body) });

export const renameNode = (id: number, newName: string) =>
	driveFetchVoid(`/nodes/${id}`, { method: 'PATCH', headers: JSON_HEADERS, body: JSON.stringify({ newName }) });

export const moveNode = (id: number, newParentId: number | null) =>
	driveFetchVoid(`/nodes/${id}`, { method: 'PATCH', headers: JSON_HEADERS, body: JSON.stringify({ newParentId }) });

export const trashNode = (id: number) => driveFetchVoid(`/nodes/${id}/trash`, { method: 'POST' });
export const restoreNode = (id: number) => driveFetchVoid(`/nodes/${id}/restore`, { method: 'POST' });
export const destroyNode = (id: number) => driveFetchVoid(`/nodes/${id}`, { method: 'DELETE' });

// ── node ACL and governed-access UX ─────────────────────────────────────

export const getNodeAccess = (nodeId: number) => driveFetch<DriveNodeAccess>(`/nodes/${nodeId}/access`);

export const searchACLSubjects = (nodeId: number, query: string) =>
	driveFetch<DriveACLSubject[]>(`/acl-subjects?node=${nodeId}&q=${encodeURIComponent(query)}`);

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
	driveFetch<Record<string, unknown>>(`/nodes/${nodeId}/acl/preview`, {
		method: 'POST', headers: JSON_HEADERS, body: JSON.stringify(body),
	});

export const grantNodeAccess = (nodeId: number, body: DriveGrantInput & { expectedEpoch: string; idempotencyKey: string }) =>
	driveFetch<{ grantId: string; epoch: string; replayed: boolean }>(`/nodes/${nodeId}/acl`, {
		method: 'POST', headers: { ...JSON_HEADERS, 'Idempotency-Key': body.idempotencyKey }, body: JSON.stringify(body),
	});

export const revokeNodeGrant = (grantId: string, expectedEpoch: string, reason: string) =>
	driveFetch<{ grantId: string; epoch: string; state: 'revoked' }>(`/acl-grants/${grantId}`, {
		method: 'DELETE', headers: JSON_HEADERS, body: JSON.stringify({ expectedEpoch, reason }),
	});

export const previewNodeInheritance = (nodeId: number, value: boolean) =>
	driveFetch<DriveInheritancePreview>(`/nodes/${nodeId}/inheritance/preview`, {
		method: 'POST', headers: JSON_HEADERS, body: JSON.stringify({ break: value }),
	});

export const setNodeInheritance = (nodeId: number, value: boolean, expectedEpoch: string) =>
	driveFetch<{ epoch: string; changed: boolean }>(`/nodes/${nodeId}/inheritance`, {
		method: 'PUT', headers: JSON_HEADERS, body: JSON.stringify({ break: value, expectedEpoch }),
	});

export const listDriveQuickView = (view: 'shared' | 'shares' | 'requests') =>
	driveFetch<DriveQuickViewItem[]>(`/quick-views?view=${view}`);

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
	driveFetch<Record<string, unknown>>(`/nodes/${nodeId}/access-requests/preview`, {
		method: 'POST', headers: JSON_HEADERS, body: JSON.stringify(body),
	});

export const createDriveAccessRequest = (nodeId: number, body: DriveAccessRequestInput & { idempotencyKey: string }) =>
	driveFetch<{ requestId: string; status: 'pending'; replayed: boolean }>(`/nodes/${nodeId}/access-requests`, {
		method: 'POST', headers: { ...JSON_HEADERS, 'Idempotency-Key': body.idempotencyKey }, body: JSON.stringify(body),
	});

// ── chunks (spec §3.3) ───────────────────────────────────────────────────

/** I-4 anti-oracle existence probe: true only if the chunk exists AND the
 *  caller can prove possession — 404 is the expected "not yet uploaded" case. */
export async function headChunk(spaceId: number, sha256: string): Promise<boolean> {
	const res = await httpRequest(`${BASE}/chunks/${sha256}?space=${spaceId}`, {
		method: 'HEAD',
		allowStatuses: [404],
	});
	return res.status === 200;
}

export const putChunk = (spaceId: number, sha256: string, bytes: Uint8Array<ArrayBuffer>) =>
	driveFetchVoid(`/chunks/${sha256}?space=${spaceId}`, {
		method: 'PUT',
		headers: { 'Content-Type': 'application/octet-stream' },
		body: bytes,
	});

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
		/** Saves land on this branch's ref instead of main (§5.3 — a save always
		 *  lands on the ref it was opened from). Requires the Go route's
		 *  postVersionBody to carry a BranchID field through to
		 *  drive_file_put_version's p_branch_id — see the P4 Task 14 DOX note. */
		branchId?: number | null;
	},
) =>
	driveFetch<PutVersionResult>(`/files/${nodeId}/versions`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify(body),
	});

export const listVersions = (nodeId: number) => driveFetch<DriveVersion[]>(`/files/${nodeId}/versions`);

/**
 * Reads the bounded H0 file-history envelope.  The cursor is opaque and is
 * returned only by the server; callers must pass it back unchanged.
 */
export const history = (
	nodeId: number,
	opts: { limit?: number; cursor?: string | null } = {},
) => {
	const params = new URLSearchParams();
	if (opts.limit != null) params.set('limit', String(opts.limit));
	if (opts.cursor) params.set('cursor', opts.cursor);
	const qs = params.toString();
	return driveFetch<DriveHistoryResult>(`/files/${nodeId}/history${qs ? `?${qs}` : ''}`);
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
	driveFetch<OfficeChoicesResult>(`/files/${nodeId}/office/choices?platform=${platform}`);

export const officeLaunch = (
	nodeId: number,
	body: { baseVersionId: number; providerId: string; deviceId: string; cohortKey: string },
) => driveFetch<OfficeLaunchResult>(`/files/${nodeId}/office/launches`, {
	method: 'POST',
	headers: JSON_HEADERS,
	body: JSON.stringify(body),
});

export const officeRevoke = (nodeId: number, launchId: string) =>
	driveFetchVoid(`/files/${nodeId}/office/launches/${encodeURIComponent(launchId)}`, { method: 'DELETE' });

/** Restores an existing same-file version without returning original bytes or
 *  its manifest to the browser. The server reuses the canonical version-save
 *  authority, including lock/conflict/quota/WORM behavior. */
export const restoreVersion = (
	nodeId: number,
	versionId: number,
	body: { baseVersionId?: number | null; note?: string; deviceLabel?: string; branchId?: number | null } = {},
) =>
	driveFetch<PutVersionResult>(`/files/${nodeId}/versions/${versionId}/restore`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify(body),
	});

/** Original-content URL. Protected classifications reject this route and use
 *  governed export; regular content may render inline. */
export const contentUrl = (versionId: number) => `${BASE}/versions/${versionId}/content`;

/** Office→PDF rendition URL (P3 Task 14 / preview.go's getPreview). Exact
 *  preview capability is server-authorized; a 'none' status is lazily flipped
 *  to 'pending' on first hit. */
export const previewUrl = (versionId: number) => `${BASE}/versions/${versionId}/preview`;

/** Fetches regular original content. `opts` passes through to httpRequest. */
export const fetchVersionContent = (versionId: number, opts: HttpOptions = {}) =>
	httpRequest(contentUrl(versionId), opts);

/** Fetches the server-generated office rendition under exact preview authority. */
export const fetchVersionPreview = (versionId: number, opts: HttpOptions = {}) =>
	httpRequest(previewUrl(versionId), opts);

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
	/** True iff main never moved since this branch's fork point (still open/review) — the ff verb is only offered when this holds. */
	ffEligible: boolean;
}

/** Lists open+review branches by default; pass all:true for the closed history too (§5.2 "show closed"). */
export const listBranches = (nodeId: number, opts: { all?: boolean } = {}) =>
	driveFetch<DriveBranch[]>(`/files/${nodeId}/branches${opts.all ? '?all=1' : ''}`);

export const createBranch = (nodeId: number, name: string, fromVersionId: number) =>
	driveFetch<{ branchId: number }>(`/files/${nodeId}/branches`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ name, fromVersionId }),
	});

export const renameBranch = (branchId: number, name: string) =>
	driveFetchVoid(`/branches/${branchId}`, { method: 'PATCH', headers: JSON_HEADERS, body: JSON.stringify({ name }) });

export const setBranchStatus = (branchId: number, status: 'open' | 'review') =>
	driveFetchVoid(`/branches/${branchId}`, { method: 'PATCH', headers: JSON_HEADERS, body: JSON.stringify({ status }) });

export type ResolveVerb = 'ff' | 'adopt' | 'keep_both' | 'discard';

export interface ResolveBranchResult {
	verb: ResolveVerb;
	headVersionId: number | null;
	/** Set only for keep_both — the newly-created sibling file's node id. */
	newNodeId: number | null;
}

export const resolveBranch = (branchId: number, verb: ResolveVerb, newName?: string) =>
	driveFetch<ResolveBranchResult>(`/branches/${branchId}/resolve`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ verb, newName: newName ?? null }),
	});

// ── version labels ───────────────────────────────────────────────────────

export const setLabel = (versionId: number, label: string) =>
	driveFetchVoid(`/versions/${versionId}/labels`, {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ label }),
	});

export const removeLabel = (versionId: number, label: string) =>
	driveFetchVoid(`/versions/${versionId}/labels/${encodeURIComponent(label)}`, { method: 'DELETE' });

// ── locks (§5.4) ─────────────────────────────────────────────────────────

export interface LockAcquireResult {
	/** 'held' is a 200, not an error — presence is an answer (§5.4). */
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
) => driveFetch<LockAcquireResult>(`/files/${nodeId}/lock`, { method: 'PUT', headers: JSON_HEADERS, body: JSON.stringify(body) });

/** Releases the caller's own lock, or (opts.break) an authorized break (LR-4). */
export const unlockFile = (nodeId: number, opts: { break?: boolean; keepalive?: boolean } = {}) =>
	driveFetchVoid(`/files/${nodeId}/lock${opts.break ? '?break=1' : ''}`, {
		method: 'DELETE',
		keepalive: opts.keepalive,
	});

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

/** Admin console read (LR-12): a space member OR a drive.view admin non-member. */
export const listLocks = (spaceId: number) => driveFetch<{ locks: DriveLockRow[] }>(`/spaces/${spaceId}/locks`);

// ── watches (§5.6) ───────────────────────────────────────────────────────

export const setWatch = (nodeId: number, ops?: string[]) =>
	driveFetchVoid(`/nodes/${nodeId}/watch`, { method: 'PUT', headers: JSON_HEADERS, body: JSON.stringify({ ops: ops ?? null }) });

export const removeWatch = (nodeId: number) => driveFetchVoid(`/nodes/${nodeId}/watch`, { method: 'DELETE' });

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
	const params = new URLSearchParams();
	if (opts.node != null) params.set('node', String(opts.node));
	if (opts.beforeId != null) params.set('beforeId', String(opts.beforeId));
	if (opts.max != null) params.set('max', String(opts.max));
	const qs = params.toString();
	return driveFetch<{ items: DriveActivityItem[] }>(`/spaces/${spaceId}/activity${qs ? '?' + qs : ''}`);
};

// ── folder admins (§5.5) ─────────────────────────────────────────────────

export interface DriveFolderAdmin {
	userId: number;
	displayName: string;
	grantedBy: number;
	grantedAt: string;
}

export const listFolderAdmins = (nodeId: number) => driveFetch<DriveFolderAdmin[]>(`/nodes/${nodeId}/folder-admins`);

export const grantFolderAdmin = (nodeId: number, userId: number) =>
	driveFetchVoid(`/nodes/${nodeId}/folder-admins/${userId}`, { method: 'PUT' });

export const revokeFolderAdmin = (nodeId: number, userId: number) =>
	driveFetchVoid(`/nodes/${nodeId}/folder-admins/${userId}`, { method: 'DELETE' });

// ── P5 compliance: audit-chain verify (AUTOPLAN correction #2) ─────────────

export interface AuditVerifyResult {
	checked: number;
	/** Row ids whose HMAC link broke the chain — empty when clean. */
	broken: number[];
}

/** drive.view-gated (worm.go's handleVerifyAuditChain) — walks the space's
 *  tamper-evident audit chain and reports any broken link. */
export const verifyAuditChain = (spaceId: number) =>
	driveFetch<AuditVerifyResult>(`/spaces/${spaceId}/audit/verify`);

// ── P5 compliance: export/print approval flow (spec §7, §9.2) ──────────────

export type ExportAction = 'download' | 'print';

export interface ExportRequestResult {
	status: 'granted' | 'pending';
	grantId?: number;
	requestId?: number;
	/** Plaintext single-use token — minted client-side, merged into BOTH
	 *  statuses by export.go (a hash cannot be inverted at decide time). The
	 *  caller must never render it as an href (single-use-burning GET). */
	token: string;
}

/** POST /api/drive/export — mints a fresh token and either grants immediately
 *  (regular/secure with an 'allow' policy) or routes to the approval engine
 *  (always on gxp). ttlMinutes defaults server-side to 60. */
export const requestExport = (versionId: number, action: ExportAction, ttlMinutes?: number) =>
	driveFetch<ExportRequestResult>('/export', {
		method: 'POST',
		headers: JSON_HEADERS,
		body: JSON.stringify({ versionId, action, ttlMinutes }),
	});

/** Single-use, BURNING-on-GET download URL. NEVER render this as an <a href>
 *  — a prefetcher or hover-preload would consume the grant before the user
 *  clicks. Navigate with window.location.assign(exportDownloadUrl(token))
 *  only (AUTOPLAN correction #5-Task8). */
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
	const params = new URLSearchParams({ q });
	if (opts.spaceId != null) params.set('space', String(opts.spaceId));
	if (opts.max != null) params.set('max', String(opts.max));
	return driveFetch<{ items: DriveSearchItem[] }>(`/search?${params.toString()}`, { signal: opts.signal });
};

// ── P6: watch list (§5.6 subscription manager) ──────────────────────────

export interface DriveWatchRow {
	nodeId: number;
	nodeName: string;
	kind: 'folder' | 'file';
	/** null = watching every event class. */
	ops: string[] | null;
}

export const listWatches = () => driveFetch<DriveWatchRow[]>('/watches');

// ── P6: admin tier-2 trash (the "admin bin") ─────────────────────────────

export interface DriveTrashItem {
	id: number;
	name: string;
	kind: 'folder' | 'file';
	purgedAt: string;
	/** null = aged out automatically (30-day sweep), not a manager destroy. */
	purgedBy: string | null;
	deletedAt: string | null;
	sizeBytes: number;
}

export const trashAdminList = (spaceId: number) =>
	driveFetch<{ items: DriveTrashItem[] }>(`/spaces/${spaceId}/trash?tier=2`);

export const purgeRestore = (nodeId: number) => driveFetchVoid(`/nodes/${nodeId}/purge-restore`, { method: 'POST' });

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

export const queryAudit = (p: AuditQueryParams) =>
	driveFetch<{ items: DriveAuditRow[]; hasMore: boolean }>(`/audit?${auditSearchParams(p).toString()}`);

/** A real `<a href download>` target (cookie auth, no single-use burn semantics
 *  — unlike exportDownloadUrl above, a plain GET here is safely re-fetchable). */
export const auditCsvUrl = (p: AuditQueryParams) => {
	const params = auditSearchParams(p);
	params.set('format', 'csv');
	return `${BASE}/audit?${params.toString()}`;
};

// ── P6: audit alarm rules CRUD (§9.3) ────────────────────────────────────

export interface DriveAuditAlarm {
	id: number;
	/** null = applies org-wide, across every space. */
	spaceId: number | null;
	actionPattern: string;
	threshold: number;
	windowMinutes: number;
	enabled: boolean;
	createdBy: number | null;
	createdAt: string;
}

/** The closed §9.3 event catalog (drive_audit_actions()) — for the alarm-rule
 *  dropdown and the query filter (Task 8: was a hardcoded literal in
 *  AdminAuditPanel.svelte, now the one source of truth). */
export const getAuditActions = () => driveFetch<string[]>('/audit-actions');

export const listAuditAlarms = () => driveFetch<DriveAuditAlarm[]>('/audit-alarms');

export const createAuditAlarm = (body: {
	spaceId?: number | null;
	actionPattern: string;
	threshold?: number;
	windowMinutes?: number;
}) => driveFetch<{ id: number }>('/audit-alarms', { method: 'POST', headers: JSON_HEADERS, body: JSON.stringify(body) });

export const updateAuditAlarm = (id: number, fields: Record<string, unknown>) =>
	driveFetchVoid(`/audit-alarms/${id}`, { method: 'PATCH', headers: JSON_HEADERS, body: JSON.stringify(fields) });

export const deleteAuditAlarm = (id: number) => driveFetchVoid(`/audit-alarms/${id}`, { method: 'DELETE' });

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
	driveFetch<{ items: DriveAsOfItem[] }>(`/spaces/${spaceId}/asof?at=${encodeURIComponent(at)}`);
