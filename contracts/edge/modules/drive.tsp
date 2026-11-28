import "@typespec/http";
import "../common/problem.tsp";

using TypeSpec.Http;
using SetjoinEdge.Common;

namespace SetjoinEdge.Drive;

// ── Common Drive Enums & Wire Models ─────────────────────────────────────

enum DriveClassification {
  regular: "regular",
  secure: "secure",
  gxp: "gxp",
}

enum DriveAclMode {
  legacy: "legacy",
  shadow: "shadow",
  acl: "acl",
}

enum DriveCapability {
  traverse: "traverse",
  listChildren: "list_children",
  readMetadata: "read_metadata",
  preview: "preview",
  download: "download",
  createChild: "create_child",
  modifyContent: "modify_content",
  rename: "rename",
  move: "move",
  delete: "delete",
  manageAcl: "manage_acl",
  viewAudit: "view_audit",
}

enum DriveNodeKind {
  folder: "folder",
  file: "file",
}

enum DrivePreset {
  viewer: "viewer",
  contributor: "contributor",
  editor: "editor",
  folderManager: "folder_manager",
}

enum DriveGrantPreset {
  viewer: "viewer",
  contributor: "contributor",
  editor: "editor",
  folderManager: "folder_manager",
  custom: "custom",
}

enum DriveAclSubjectKind {
  user: "user",
  group: "group",
}

enum DriveAclPropagation {
  self: "self",
  children: "children",
  subtree: "subtree",
}

enum DriveAclGrantScope {
  self: "self",
  subtree: "subtree",
}

enum DriveAclRelation {
  direct: "direct",
  inherited: "inherited",
}

enum DriveAclSource {
  direct: "direct",
  group: "group",
  legacyFolderAdmin: "legacy_folder_admin",
  approval: "approval",
  emergency: "emergency",
}

enum DriveAccessSourceKind {
  spaceRole: "space_role",
  direct: "direct",
  group: "group",
  folderAdmin: "folder_admin",
}

enum DriveBranchStatus {
  open: "open",
  review: "review",
  merged: "merged",
  discarded: "discarded",
}

enum DriveResolveVerb {
  ff: "ff",
  adopt: "adopt",
  keepBoth: "keep_both",
  discard: "discard",
}

enum DriveExportAction {
  download: "download",
  print: "print",
}

enum DriveOfficeFileFamily {
  word: "word",
  sheet: "sheet",
  presentation: "presentation",
}

enum DriveOfficePlatform {
  web: "web",
  electron: "electron",
}

enum DriveQuickViewKind {
  shared: "shared",
  share: "share",
  request: "request",
}

enum DriveQuickViewFilter {
  shared: "shared",
  shares: "shares",
  requests: "requests",
}

enum DriveLockMode {
  soft: "soft",
  hard: "hard",
}

model DriveIdResponse {
  id: int64;
}

// ── Spaces & Members ─────────────────────────────────────────────────────

model DriveSpace {
  id: int64;
  name: string;
  isPersonal: boolean;
  classification: DriveClassification;
  role: string;
  usedBytes: int64;
  quotaBytes?: int64 | null;
  changeSeq: int64;
  aclMode?: DriveAclMode;
  aclEpoch?: int64;
  rootCapabilities?: DriveCapability[];
  accessGovernanceEnabled?: boolean;
  wormPending?: int64;
}

model DriveCreateSpaceRequest {
  name: string;
  classification?: DriveClassification;
  isPersonal?: boolean;
  retentionDays?: int32 | null;
  wormMode?: string | null;
  exportPolicy?: Record<unknown>;
}

model DriveMember {
  userId: int64;
  role: string;
  email: string;
  displayName: string;
  grantedAt: string;
}

model DriveGrantMemberRequest {
  userId: int64;
  role: string;
}

model DriveGrantMemberResponse {
  status: string;
  requestId?: int64;
}

// ── Tree, Nodes & Changes ────────────────────────────────────────────────

model DriveLockPresence {
  holderId: int64;
  holderName: string;
  mode: string;
  branchId: int64 | null;
  acquiredAt: string;
  expiresAt: string;
}

model DriveNode {
  id: int64;
  parentId: int64 | null;
  kind: DriveNodeKind;
  name: string;
  size?: int64 | null;
  contentType?: string | null;
  headVersionId?: int64 | null;
  deletedAt?: string | null;
  branchCount: int64;
  lock: DriveLockPresence | null;
  capabilities?: DriveCapability[];
  traverseOnly?: boolean;
}

model DriveNodeMeta {
  nodeId: int64;
  spaceId: int64;
  parentId: int64 | null;
  kind: DriveNodeKind;
  name: string;
  deletedAt: string | null;
  headVersionId: int64 | null;
  contentSha256: string | null;
  sizeBytes: int64 | null;
  contentType: string | null;
  branchCount: int64;
  capabilities: DriveCapability[];
  traverseOnly: boolean;
}

model DriveCreateNodeRequest {
  spaceId: int64;
  parentId: int64 | null;
  kind: DriveNodeKind;
  name: string;
  contentType?: string | null;
}

model DrivePatchNodeRequest {
  newName?: string;
  newParentId?: int64 | null;
}

model DriveChange {
  nodeId: int64 | string;
  `op`: string;
  seq: int64 | string;
}

model DriveChangesResult {
  cannotCalculateChanges?: boolean;
  newState?: int64 | string;
  changed?: DriveChange[];
  hasMore?: boolean;
}

// ── ACL & Governed Access ────────────────────────────────────────────────

model DriveAclGrant {
  grantId: string;
  anchorNodeId: string;
  anchorName: string;
  subjectKind: DriveAclSubjectKind;
  subjectId: string;
  subjectLabel: string;
  subjectSecondary?: string | null;
  preset: DriveGrantPreset;
  capabilities: DriveCapability[];
  propagation: DriveAclPropagation;
  source: DriveAclSource;
  relation: DriveAclRelation;
  startsAt?: string | null;
  expiresAt?: string | null;
  maxUses?: int32 | null;
  usedCount: int32;
  createdAt: string;
}

model DriveAccessSource {
  capability: DriveCapability;
  sourceKind: DriveAccessSourceKind;
  sourceId?: string | null;
  anchorNodeId?: string | null;
}

model DriveNodeAccess {
  nodeId: string;
  spaceId: string;
  nodeName: string;
  nodeKind: DriveNodeKind;
  aclMode: DriveAclMode;
  epoch: string;
  capabilities: DriveCapability[];
  traverseOnly: boolean;
  canManage: boolean;
  writesEnabled: boolean;
  governanceEnabled: boolean;
  inheritanceBroken: boolean;
  grants: DriveAclGrant[];
  sources: DriveAccessSource[];
  presets: DrivePreset[];
}

model DriveAclSubject {
  kind: DriveAclSubjectKind;
  id: string;
  label: string;
  secondary?: string;
}

model DriveGrantInput {
  subjectKind: DriveAclSubjectKind;
  subjectId: string;
  preset: DrivePreset;
  scope: DriveAclGrantScope;
  startsAt?: string;
  expiresAt?: string;
  maxUses?: int32;
  reason?: string;
}

model DriveGrantCreateRequest {
  ...DriveGrantInput;
  expectedEpoch: string;
  idempotencyKey: string;
}

model DriveGrantCreateResponse {
  grantId: string;
  epoch: string;
  replayed: boolean;
}

model DriveGrantRevokeRequest {
  expectedEpoch: string;
  reason: string;
}

model DriveGrantRevokeResponse {
  grantId: string;
  epoch: string;
  state: string;
}

model DriveInheritancePreviewRequest {
  `break`: boolean;
}

model DriveInheritancePreview {
  nodeId: string;
  spaceId: string;
  epoch: string;
  requestedBreak: boolean;
  currentBreak: boolean;
  changed: boolean;
  affectedNodeCount: int64;
  affectedPrincipalCount: int64;
  currentManagerSourceCount: int64;
  mayRemoveOfflineContent: boolean;
}

model DriveInheritanceSetRequest {
  `break`: boolean;
  expectedEpoch: string;
}

model DriveInheritanceSetResponse {
  epoch: string;
  changed: boolean;
}

model DriveQuickViewItem {
  kind: DriveQuickViewKind;
  nodeId: string;
  spaceId: string;
  name: string;
  nodeKind: DriveNodeKind;
  spaceName: string;
  source?: DriveAclSubjectKind | string;
  preset?: DriveGrantPreset;
  sharedAt?: string;
  activeGrantCount?: int32;
  requestId?: string;
  status?: string;
  capabilities?: DriveCapability[];
  propagation?: DriveAclPropagation;
  expiresAt?: string;
  createdAt?: string;
  grantId?: string | null;
}

model DriveAccessRequestInput {
  subjectKind: DriveAclSubjectKind;
  subjectId: string;
  capabilities: DriveCapability[];
  propagation: DriveAclPropagation;
  durationMinutes: int32;
  maxUses?: int32;
  emergency?: boolean;
  mfaSessionId?: string;
  reason: string;
}

model DriveAccessRequestCreateRequest {
  ...DriveAccessRequestInput;
  idempotencyKey: string;
}

model DriveAccessRequestCreateResponse {
  requestId: string;
  status: string;
  replayed: boolean;
}

// ── Versions, History & Range Content ────────────────────────────────────

model DriveManifestChunk {
  sha256: string;
  size: int64;
}

model DrivePutVersionRequest {
  contentSha256: string;
  size: int64;
  contentType?: string | null;
  baseVersionId: int64 | null;
  manifest: DriveManifestChunk[];
  note?: string;
  deviceLabel?: string;
  branchId?: int64 | null;
}

model DriveRestoreVersionRequest {
  baseVersionId?: int64 | null;
  note?: string;
  deviceLabel?: string;
  branchId?: int64 | null;
}

model PutVersionResult {
  versionId: int64;
  conflict: boolean;
  branchId: int64 | null;
  headVersionId: int64 | null;
  wormPending: boolean;
}

model DriveVersion {
  id: int64;
  parentVersionId: int64 | null;
  conflictOf: int64 | null;
  sha256: string;
  size: int64;
  contentType?: string | null;
  author: int64;
  deviceLabel?: string | null;
  note?: string | null;
  previewStatus: string;
  createdAt: string;
  branchId: int64 | null;
  labels: string[];
}

model DriveHistoryItem {
  occurredAt: string;
  sourceRank: int32;
  sourceId: string | int64;
  source: string;
  kind: string;
  details: Record<unknown> | null;
}

model DriveHistoryCoverage {
  mode: string;
  freshnessSeconds: int64 | null;
  coveredSources: string[];
  omissions: string[];
}

model DriveHistoryResult {
  items: DriveHistoryItem[];
  hasMore: boolean;
  nextCursor: string | null;
  coverage: DriveHistoryCoverage;
  generatedAt: string;
}

// ── Office ───────────────────────────────────────────────────────────────

model OfficeChoice {
  providerId: string;
  mode: string;
  fileFamily: DriveOfficeFileFamily;
  available: boolean;
  buildId: string | null;
}

model OfficeChoicesResult {
  fileFamily: DriveOfficeFileFamily;
  platform: DriveOfficePlatform;
  localOpenAllowed: boolean;
  choices: OfficeChoice[];
}

model OfficeLaunchRequest {
  baseVersionId: int64;
  providerId: string;
  deviceId: string;
  cohortKey: string;
}

model OfficeLaunchResult {
  launchId: string;
  sessionId: string;
  fenceGeneration: int64;
  expiresAt: string;
  accessToken: string;
  wopiSrc: string;
  editorUrl: string;
}

// ── Branches & Labels ────────────────────────────────────────────────────

model DriveBranch {
  id: int64;
  name: string;
  status: DriveBranchStatus;
  autoCreated: boolean;
  headVersionId: int64;
  forkedFromVersionId: int64;
  createdBy: int64;
  createdAt: string;
  resolvedBy: int64 | null;
  resolvedAt: string | null;
  ffEligible: boolean;
}

model DriveCreateBranchRequest {
  name: string;
  fromVersionId: int64;
}

model DriveCreateBranchResponse {
  branchId: int64;
}

model DrivePatchBranchRequest {
  name?: string;
  status?: string;
}

model DriveResolveBranchRequest {
  verb: DriveResolveVerb;
  newName?: string | null;
}

model ResolveBranchResult {
  verb: DriveResolveVerb;
  headVersionId: int64 | null;
  newNodeId: int64 | null;
}

model DriveSetLabelRequest {
  label: string;
}

// ── Locks, Watches, Activity & Folder Admins ─────────────────────────────

model DriveLockFileRequest {
  mode?: DriveLockMode;
  branchId?: int64 | null;
  versionId?: int64 | null;
  deviceLabel?: string;
  ttlMinutes?: int32;
}

model LockAcquireResult {
  status: string;
  mode?: string;
  expiresAt?: string;
  holderId?: int64;
  since?: string;
  branchId?: int64 | null;
}

model DriveLockRow {
  nodeId: int64;
  name: string;
  holderId: int64;
  holderName: string;
  mode: string;
  branchId: int64 | null;
  acquiredAt: string;
  expiresAt: string;
  deviceLabel: string | null;
}

model DriveLocksListResponse {
  locks: DriveLockRow[];
}

model DriveSetWatchRequest {
  ops: string[] | null;
}

model DriveWatchRow {
  nodeId: int64;
  nodeName: string;
  kind: DriveNodeKind;
  ops: string[] | null;
}

model DriveActivityItem {
  id: int64;
  action: string;
  actorId: int64;
  actorName: string;
  targetType: string;
  targetId: int64;
  at: string;
  notes: string | null;
}

model DriveActivityListResponse {
  items: DriveActivityItem[];
}

model DriveFolderAdmin {
  userId: int64;
  displayName: string;
  grantedBy: int64;
  grantedAt: string;
}

// ── Compliance, Export, Search, Trash, Audit & AsOf ──────────────────────

model AuditVerifyResult {
  checked: int64;
  broken: int64[];
}

model ExportRequestBody {
  versionId: int64;
  action: DriveExportAction;
  ttlMinutes?: int32;
}

model ExportRequestResult {
  status: string;
  grantId?: int64;
  requestId?: int64;
  token: string;
}

model DriveSearchItem {
  id: int64;
  spaceId: int64;
  parentId: int64 | null;
  kind: DriveNodeKind;
  name: string;
  sizeBytes?: int64 | null;
  contentType?: string | null;
  createdAt: string;
}

model DriveSearchResponse {
  items: DriveSearchItem[];
}

model DriveTrashItem {
  id: int64;
  name: string;
  kind: DriveNodeKind;
  purgedAt: string;
  purgedBy: string | null;
  deletedAt: string | null;
  sizeBytes: int64;
}

model DriveTrashListResponse {
  items: DriveTrashItem[];
}

model DriveAuditRow {
  id: int64;
  occurredAt: string;
  userId: int64 | null;
  userEmail: string;
  ip: string;
  action: string;
  targetType?: string | null;
  targetId?: int64 | null;
  notes?: string | null;
}

model DriveAuditQueryResponse {
  items: DriveAuditRow[];
  hasMore: boolean;
}

model DriveAuditAlarm {
  id: int64;
  spaceId: int64 | null;
  actionPattern: string;
  threshold: int32;
  windowMinutes: int32;
  enabled: boolean;
  createdBy: int64 | null;
  createdAt: string;
}

model DriveCreateAuditAlarmRequest {
  spaceId?: int64 | null;
  actionPattern: string;
  threshold?: int32;
  windowMinutes?: int32;
}

model DriveAsOfItem {
  id: int64;
  parentId: int64 | null;
  kind: DriveNodeKind;
  name: string;
  versionId: int64 | null;
  versionCreatedAt: string | null;
  sizeBytes?: int64 | null;
  contentType?: string | null;
  liveNow: boolean;
}

model DriveAsOfResponse {
  items: DriveAsOfItem[];
}

// ── Binary / Range Content Responses ─────────────────────────────────────

model DriveContentFullOctetResponse {
  @statusCode statusCode: 200;
  @header("content-type") contentType: "application/octet-stream";
  @header("accept-ranges") acceptRanges?: string;
  @header("content-disposition") contentDisposition?: string;
  @header("content-length") contentLength?: string;
  @header("content-security-policy") contentSecurityPolicy?: string;
  @body body: bytes;
}

model DriveContentFullTextResponse {
  @statusCode statusCode: 200;
  @header("content-type") contentType: "text/plain";
  @header("accept-ranges") acceptRanges?: string;
  @header("content-disposition") contentDisposition?: string;
  @header("content-length") contentLength?: string;
  @header("content-security-policy") contentSecurityPolicy?: string;
  @body body: string;
}

model DriveContentFullAnyResponse {
  @statusCode statusCode: 200;
  @header("content-type") contentType: "*/*";
  @header("accept-ranges") acceptRanges?: string;
  @header("content-disposition") contentDisposition?: string;
  @header("content-length") contentLength?: string;
  @header("content-security-policy") contentSecurityPolicy?: string;
  @body body: bytes;
}

model DriveContentPartialOctetResponse {
  @statusCode statusCode: 206;
  @header("content-type") contentType: "application/octet-stream";
  @header("content-range") contentRange: string;
  @header("accept-ranges") acceptRanges?: string;
  @header("content-disposition") contentDisposition?: string;
  @header("content-length") contentLength?: string;
  @header("content-security-policy") contentSecurityPolicy?: string;
  @body body: bytes;
}

model DriveContentPartialTextResponse {
  @statusCode statusCode: 206;
  @header("content-type") contentType: "text/plain";
  @header("content-range") contentRange: string;
  @header("accept-ranges") acceptRanges?: string;
  @header("content-disposition") contentDisposition?: string;
  @header("content-length") contentLength?: string;
  @header("content-security-policy") contentSecurityPolicy?: string;
  @body body: string;
}

model DriveContentPartialAnyResponse {
  @statusCode statusCode: 206;
  @header("content-type") contentType: "*/*";
  @header("content-range") contentRange: string;
  @header("accept-ranges") acceptRanges?: string;
  @header("content-disposition") contentDisposition?: string;
  @header("content-length") contentLength?: string;
  @header("content-security-policy") contentSecurityPolicy?: string;
  @body body: bytes;
}

@error
model DriveRangeNotSatisfiableResponse {
  @statusCode statusCode: 416;
  @header("content-type") contentType: "application/problem+json";
  @header("accept-ranges") acceptRanges?: string;
  @header("content-disposition") contentDisposition?: string;
  @header("content-security-policy") contentSecurityPolicy?: string;
  @body body: ProblemDetails;
}

@error
model HeadBadRequestResponse {
  @statusCode statusCode: 400;
}

@error
model HeadUnauthorizedResponse {
  @statusCode statusCode: 401;
}

@error
model HeadForbiddenResponse {
  @statusCode statusCode: 403;
}

@error
model HeadNotFoundResponse {
  @statusCode statusCode: 404;
}

@error
model HeadConflictResponse {
  @statusCode statusCode: 409;
}

@error
model HeadInternalServerResponse {
  @statusCode statusCode: 500;
}

model DrivePreviewFullResponse {
  @statusCode statusCode: 200;
  @header("content-type") contentType: "application/pdf";
  @header("accept-ranges") acceptRanges?: string;
  @header("content-disposition") contentDisposition?: string;
  @header("content-length") contentLength?: string;
  @body body: bytes;
}

model DrivePreviewPartialResponse {
  @statusCode statusCode: 206;
  @header("content-type") contentType: "application/pdf";
  @header("content-range") contentRange: string;
  @header("accept-ranges") acceptRanges?: string;
  @header("content-disposition") contentDisposition?: string;
  @header("content-length") contentLength?: string;
  @body body: bytes;
}

// ── Interface ────────────────────────────────────────────────────────────

@tag("Drive")
@route("/api/drive")
interface DriveApi {
  // Spaces & Members
  @doc("List Drive spaces accessible to the caller (or all spaces with admin=1).")
  @get
  @route("/spaces")
  listSpaces(@query admin?: string):
    | DriveSpace[]
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Create a new Drive space.")
  @post
  @route("/spaces")
  createSpace(@body body: DriveCreateSpaceRequest):
    | {
        @statusCode statusCode: 201;
        @body body: DriveIdResponse;
      }
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | InternalServerProblem;

  @doc("Patch space metadata, quota, classification, or retention policy.")
  @patch
  @route("/spaces/{id}")
  patchSpace(
    @path id: int64,
    @body body: Record<unknown>,
  ):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | InternalServerProblem;

  @doc("List explicit members of a Drive space.")
  @get
  @route("/spaces/{id}/members")
  listMembers(@path id: int64):
    | DriveMember[]
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Grant or update space membership for a user.")
  @post
  @route("/spaces/{id}/members")
  grantMember(
    @path id: int64,
    @body body: DriveGrantMemberRequest,
  ):
    | DriveGrantMemberResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | InternalServerProblem;

  @doc("Revoke a user's explicit membership from a Drive space.")
  @delete
  @route("/spaces/{id}/members/{userId}")
  revokeMember(@path id: int64, @path userId: int64):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | InternalServerProblem;

  // Tree, Changes & Nodes
  @doc("List folder children (or trashed nodes) in a Drive space.")
  @get
  @route("/spaces/{id}/tree")
  listTree(
    @path id: int64,
    @query parent?: int64,
    @query deleted?: string,
  ):
    | DriveNode[]
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Fetch incremental change feed for a Drive space since a sequence number.")
  @get
  @route("/changes")
  getChanges(
    @query space: int64,
    @query since: int64,
  ):
    | DriveChangesResult
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | InternalServerProblem;

  @doc("Batch-read metadata for up to 500 Drive node IDs (omitting `ids` returns `[]`).")
  @get
  @route("/nodes")
  getNodesMeta(@query ids?: string):
    | DriveNodeMeta[]
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | UnprocessableEntityProblem
    | InternalServerProblem;

  @doc("Create a folder or file node inside a Drive space.")
  @post
  @route("/nodes")
  createNode(@body body: DriveCreateNodeRequest):
    | {
        @statusCode statusCode: 201;
        @body body: DriveIdResponse;
      }
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | InternalServerProblem;

  @doc("Rename or move a Drive node.")
  @patch
  @route("/nodes/{id}")
  patchNode(
    @path id: int64,
    @body body: DrivePatchNodeRequest,
  ):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | LockedProblem
    | InternalServerProblem;

  @doc("Permanently delete a Drive node.")
  @delete
  @route("/nodes/{id}")
  destroyNode(@path id: int64):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | LockedProblem
    | InternalServerProblem;

  @doc("Move a Drive node to the trash.")
  @post
  @route("/nodes/{id}/trash")
  trashNode(@path id: int64):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | LockedProblem
    | InternalServerProblem;

  @doc("Restore a Drive node from tier-1 trash.")
  @post
  @route("/nodes/{id}/restore")
  restoreNode(@path id: int64):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | InternalServerProblem;

  @doc("Restore a purged Drive node from admin tier-2 trash.")
  @post
  @route("/nodes/{id}/purge-restore")
  purgeRestoreNode(@path id: int64):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | InternalServerProblem;

  // ACL & Governed Access
  @doc("Read effective node ACL state, grants, and capability sources.")
  @get
  @route("/nodes/{id}/access")
  getNodeAccess(@path id: int64):
    | DriveNodeAccess
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Search users and groups eligible for a Drive ACL grant on a node.")
  @get
  @route("/acl-subjects")
  searchAclSubjects(
    @query node: int64,
    @query q: string,
  ):
    | DriveAclSubject[]
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Preview the impact of a prospective node ACL grant.")
  @post
  @route("/nodes/{id}/acl/preview")
  previewNodeGrant(
    @path id: int64,
    @body body: DriveGrantInput,
  ):
    | Record<unknown>
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | InternalServerProblem;

  @doc("Create a node ACL grant with optimistic epoch concurrency and idempotency key.")
  @post
  @route("/nodes/{id}/acl")
  grantNodeAccess(
    @path id: int64,
    @header("Idempotency-Key") idempotencyKey: string,
    @body body: DriveGrantCreateRequest,
  ):
    | DriveGrantCreateResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | InternalServerProblem;

  @doc("Revoke a node ACL grant.")
  @delete
  @route("/acl-grants/{id}")
  revokeNodeGrant(
    @path id: string,
    @body body: DriveGrantRevokeRequest,
  ):
    | DriveGrantRevokeResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | InternalServerProblem;

  @doc("Preview breaking or restoring ACL inheritance on a node.")
  @post
  @route("/nodes/{id}/inheritance/preview")
  previewNodeInheritance(
    @path id: int64,
    @body body: DriveInheritancePreviewRequest,
  ):
    | DriveInheritancePreview
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | InternalServerProblem;

  @doc("Break or restore ACL inheritance on a node.")
  @put
  @route("/nodes/{id}/inheritance")
  setNodeInheritance(
    @path id: int64,
    @body body: DriveInheritanceSetRequest,
  ):
    | DriveInheritanceSetResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | InternalServerProblem;

  @doc("List governed Drive quick-views (shared-with-me, my shares, pending requests).")
  @get
  @route("/quick-views")
  listQuickViews(@query view: DriveQuickViewFilter):
    | DriveQuickViewItem[]
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Preview a governed Drive access request.")
  @post
  @route("/nodes/{id}/access-requests/preview")
  previewAccessRequest(
    @path id: int64,
    @body body: DriveAccessRequestInput,
  ):
    | Record<unknown>
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | InternalServerProblem;

  @doc("Submit a governed Drive access request.")
  @post
  @route("/nodes/{id}/access-requests")
  createAccessRequest(
    @path id: int64,
    @header("Idempotency-Key") idempotencyKey: string,
    @body body: DriveAccessRequestCreateRequest,
  ):
    | DriveAccessRequestCreateResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | InternalServerProblem;

  // Chunks
  @doc("Anti-oracle existence probe for a content-addressed Drive chunk.")
  @head
  @route("/chunks/{sha256}")
  headChunk(
    @path sha256: string,
    @query space: int64,
    @query target?: int64,
    @query aclEpoch?: int64,
  ):
    | EmptyOkResponse
    | HeadBadRequestResponse
    | HeadUnauthorizedResponse
    | HeadForbiddenResponse
    | HeadNotFoundResponse
    | HeadConflictResponse
    | HeadInternalServerResponse;

  @doc("Upload a content-addressed Drive chunk (raw octet stream).")
  @put
  @route("/chunks/{sha256}")
  putChunk(
    @path sha256: string,
    @query space: int64,
    @query target?: int64,
    @query aclEpoch?: int64,
    @header("content-type") contentType: "application/octet-stream",
    @body body: bytes,
  ):
    | EmptyCreatedResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | PayloadTooLargeProblem
    | UnprocessableEntityProblem
    | ServiceUnavailableProblem
    | InternalServerProblem;

  // Versions, History & Range Content / Preview
  @doc("List all versions of a Drive file.")
  @get
  @route("/files/{id}/versions")
  listVersions(@path id: int64):
    | DriveVersion[]
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Commit a new file version manifest.")
  @post
  @route("/files/{id}/versions")
  putVersion(
    @path id: int64,
    @body body: DrivePutVersionRequest,
  ):
    | {
        @statusCode statusCode: 201;
        @body body: PutVersionResult;
      }
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | PayloadTooLargeProblem
    | UnprocessableEntityProblem
    | LockedProblem
    | InternalServerProblem;

  @doc("Restore an older version of a Drive file as the new head version.")
  @post
  @route("/files/{id}/versions/{versionId}/restore")
  restoreVersion(
    @path id: int64,
    @path versionId: int64,
    @body body: DriveRestoreVersionRequest,
  ):
    | {
        @statusCode statusCode: 201;
        @body body: PutVersionResult;
      }
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | PayloadTooLargeProblem
    | UnprocessableEntityProblem
    | LockedProblem
    | InternalServerProblem;

  @doc("Read bounded permission-filtered file history timeline.")
  @get
  @route("/files/{id}/history")
  getFileHistory(
    @path id: int64,
    @query limit?: int32,
    @query cursor?: string,
  ):
    | DriveHistoryResult
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Stream original file version bytes with single-range HTTP 206 Partial Content support.")
  @get
  @route("/versions/{id}/content")
  getVersionContent(
    @path id: int64,
    @header("Range") range?: string,
  ):
    | DriveContentFullOctetResponse
    | DriveContentFullTextResponse
    | DriveContentFullAnyResponse
    | DriveContentPartialOctetResponse
    | DriveContentPartialTextResponse
    | DriveContentPartialAnyResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | DriveRangeNotSatisfiableResponse
    | ServiceUnavailableProblem
    | InternalServerProblem;

  @doc("Stream server-generated PDF office preview with HTTP 206 Partial Content support.")
  @get
  @route("/versions/{id}/preview")
  getVersionPreview(
    @path id: int64,
    @header("Range") range?: string,
  ):
    | DrivePreviewFullResponse
    | DrivePreviewPartialResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | DriveRangeNotSatisfiableResponse
    | ServiceUnavailableProblem
    | InternalServerProblem;

  // Office
  @doc("Query available online/local Office editor providers for a Drive file.")
  @get
  @route("/files/{id}/office/choices")
  getOfficeChoices(
    @path id: int64,
    @query platform: DriveOfficePlatform,
  ):
    | OfficeChoicesResult
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Launch a WOPI/online Office editing session for a Drive file.")
  @post
  @route("/files/{id}/office/launches")
  createOfficeLaunch(
    @path id: int64,
    @body body: OfficeLaunchRequest,
  ):
    | OfficeLaunchResult
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | LockedProblem
    | InternalServerProblem;

  @doc("Revoke an active online Office editing launch.")
  @delete
  @route("/files/{id}/office/launches/{launchId}")
  revokeOfficeLaunch(@path id: int64, @path launchId: string):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  // Branches & Version Labels
  @doc("List branches of a Drive file.")
  @get
  @route("/files/{id}/branches")
  listBranches(
    @path id: int64,
    @query all?: string,
  ):
    | DriveBranch[]
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Create a branch from a file version.")
  @post
  @route("/files/{id}/branches")
  createBranch(
    @path id: int64,
    @body body: DriveCreateBranchRequest,
  ):
    | {
        @statusCode statusCode: 201;
        @body body: DriveCreateBranchResponse;
      }
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | InternalServerProblem;

  @doc("Rename a branch or update its open/review status.")
  @patch
  @route("/branches/{id}")
  patchBranch(
    @path id: int64,
    @body body: DrivePatchBranchRequest,
  ):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | InternalServerProblem;

  @doc("Resolve a Drive file branch via fast-forward, adopt, keep-both, or discard.")
  @post
  @route("/branches/{id}/resolve")
  resolveBranch(
    @path id: int64,
    @body body: DriveResolveBranchRequest,
  ):
    | ResolveBranchResult
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | LockedProblem
    | InternalServerProblem;

  @doc("Attach a label to a Drive file version.")
  @post
  @route("/versions/{id}/labels")
  setVersionLabel(
    @path id: int64,
    @body body: DriveSetLabelRequest,
  ):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | InternalServerProblem;

  @doc("Remove a label from a Drive file version.")
  @delete
  @route("/versions/{id}/labels/{label}")
  removeVersionLabel(@path id: int64, @path label: string):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | InternalServerProblem;

  // Locks, Watches, Activity & Folder Admins
  @doc("Acquire or renew a soft/hard lock on a Drive file.")
  @put
  @route("/files/{id}/lock")
  lockFile(
    @path id: int64,
    @body body: DriveLockFileRequest,
  ):
    | LockAcquireResult
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | LockedProblem
    | InternalServerProblem;

  @doc("Release the caller's lock on a Drive file (or break it when authorized).")
  @delete
  @route("/files/{id}/lock")
  unlockFile(
    @path id: int64,
    @query `break`?: string,
  ):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | InternalServerProblem;

  @doc("List active file locks inside a Drive space.")
  @get
  @route("/spaces/{id}/locks")
  listSpaceLocks(@path id: int64):
    | DriveLocksListResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Subscribe to change notifications on a Drive node.")
  @put
  @route("/nodes/{id}/watch")
  setNodeWatch(
    @path id: int64,
    @body body: DriveSetWatchRequest,
  ):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Remove a change watch from a Drive node.")
  @delete
  @route("/nodes/{id}/watch")
  removeNodeWatch(@path id: int64):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("List the caller's active Drive node watch subscriptions.")
  @get
  @route("/watches")
  listWatches():
    | DriveWatchRow[]
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Read recent activity events for a Drive space or node.")
  @get
  @route("/spaces/{id}/activity")
  listSpaceActivity(
    @path id: int64,
    @query node?: int64,
    @query beforeId?: int64,
    @query max?: int32,
  ):
    | DriveActivityListResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("List delegated folder administrators on a folder node.")
  @get
  @route("/nodes/{id}/folder-admins")
  listFolderAdmins(@path id: int64):
    | DriveFolderAdmin[]
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Grant delegated folder administrator authority on a folder node.")
  @put
  @route("/nodes/{id}/folder-admins/{userId}")
  grantFolderAdmin(@path id: int64, @path userId: int64):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | InternalServerProblem;

  @doc("Revoke delegated folder administrator authority on a folder node.")
  @delete
  @route("/nodes/{id}/folder-admins/{userId}")
  revokeFolderAdmin(@path id: int64, @path userId: int64):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  // Compliance, Export, Search, Trash, Audit & AsOf
  @doc("Verify tamper-evident HMAC audit chain integrity for a Drive space.")
  @get
  @route("/spaces/{id}/audit/verify")
  verifyAuditChain(@path id: int64):
    | AuditVerifyResult
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Request a governed download/print export grant for a file version.")
  @post
  @route("/export")
  requestExport(@body body: ExportRequestBody):
    | ExportRequestResult
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | InternalServerProblem;

  @doc("Search Drive nodes by name across accessible spaces.")
  @get
  @route("/search")
  searchNodes(
    @query q: string,
    @query space?: int64,
    @query max?: int32,
  ):
    | DriveSearchResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("List admin tier-2 purged trash entries for a Drive space.")
  @get
  @route("/spaces/{id}/trash")
  listSpaceTrash(
    @path id: int64,
    @query tier?: int32,
  ):
    | DriveTrashListResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Query Drive audit log entries for a space (JSON or CSV).")
  @get
  @route("/audit")
  queryAudit(
    @query space: int64,
    @query actor?: int64,
    @query action?: string,
    @query from?: string,
    @query to?: string,
    @query q?: string,
    @query max?: int32,
    @query beforeId?: int64,
    @query format?: string,
  ):
    | DriveAuditQueryResponse
    | {
        @statusCode statusCode: 200;
        @header("content-type") contentType: "text/csv";
        @body body: string;
      }
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Return the closed catalog of Drive audit action names.")
  @get
  @route("/audit-actions")
  getAuditActions():
    | string[]
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("List configured Drive audit alarm rules.")
  @get
  @route("/audit-alarms")
  listAuditAlarms():
    | DriveAuditAlarm[]
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Create a Drive audit alarm rule.")
  @post
  @route("/audit-alarms")
  createAuditAlarm(@body body: DriveCreateAuditAlarmRequest):
    | {
        @statusCode statusCode: 201;
        @body body: DriveIdResponse;
      }
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | InternalServerProblem;

  @doc("Update fields on a Drive audit alarm rule.")
  @patch
  @route("/audit-alarms/{id}")
  updateAuditAlarm(
    @path id: int64,
    @body body: Record<unknown>,
  ):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | UnprocessableEntityProblem
    | InternalServerProblem;

  @doc("Delete a Drive audit alarm rule.")
  @delete
  @route("/audit-alarms/{id}")
  deleteAuditAlarm(@path id: int64):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Reconstruct a point-in-time snapshot of a Drive space as of timestamp `at`.")
  @get
  @route("/spaces/{id}/asof")
  getSpaceAsOf(
    @path id: int64,
    @query at: string,
  ):
    | DriveAsOfResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | UnprocessableEntityProblem
    | InternalServerProblem;
}
