import "@typespec/http";
import "../common/problem.tsp";

using TypeSpec.Http;
using SetjoinEdge.Common;

namespace SetjoinEdge.Admin;

// ── Roles, Permissions & SoD ─────────────────────────────────────────────

model PermissionCatalogEntry {
  key: string;
  category: string;
  description: string;
  isSensitive: boolean;
}

model AdminRole {
  id: int64;
  name: string;
  description: string;
  permissions: string[];
  domainScope?: int64 | null;
  isBuiltin: boolean;
  memberCount: int64;
  createdAt: string;
  updatedAt: string;
  sodClass?: string | null;
}

enum AdminRoleScopeType {
  ou: "ou",
  set: "set",
}

model RoleMember {
  userId: int64;
  userEmail: string;
  displayName: string;
  domainOverride?: int64 | null;
  grantedBy: int64;
  grantedAt: string;
  expiresAt?: string | null;
  manageable?: boolean;
  scopeType?: AdminRoleScopeType | null;
  scopeId?: int64 | null;
  setName?: string;
}

model RoleDetail {
  role: AdminRole;
  members: RoleMember[];
}

model EffectivePermSource {
  roleGroupId: int64;
  roleName: string;
  permissions: string[];
  effectiveScope?: int64 | null;
}

model EffectivePerms {
  permissions: string[];
  domainScope?: int64 | null;
  sources: EffectivePermSource[];
  consoles: string[] | null;
}

model AdminRoleCreateRequest {
  name: string;
  description: string;
  permissions: string[];
  domainScope?: int64 | null;
}

model AdminRoleUpdateRequest {
  name?: string;
  description?: string;
  permissions?: string[];
  domainScope?: int64 | null;
}

model AdminRoleAssignMemberRequest {
  userId: int64;
  domainOverride?: int64 | null;
  expiresAt?: string | null;
  scopeType?: AdminRoleScopeType | null;
  scopeId?: int64 | null;
  eligible?: boolean;
}

model AdminCreatedIdResponse {
  id: int64;
}

model SodViolation {
  violationType: string;
  subject: string;
  detail: string;
}

model SodModeStatus {
  enabled: boolean;
  violations: SodViolation[];
}

model SodModeSetRequest {
  enabled: boolean;
}

model SodModeSetResponse {
  enabled: boolean;
}

model SodModeConflictBody {
  error: string;
  violations: SodViolation[];
}

@error
model SodModeConflictResponse {
  @statusCode statusCode: 409;
  @header("content-type") contentType: "application/json";
  @body body: SodModeConflictBody;
}

// ── Access Reviews ───────────────────────────────────────────────────────

enum AccessReviewStatus {
  open: "open",
  closed: "closed",
}

enum AccessReviewDecision {
  undecided: "undecided",
  keep: "keep",
  revoke: "revoke",
}

enum AccessReviewWriteDecision {
  keep: "keep",
  revoke: "revoke",
}

model AccessReviewCampaign {
  id: int64;
  name: string;
  status: AccessReviewStatus;
  reviewed: int32;
  total: int32;
  createdBy: string;
  createdAt: string;
  closedBy?: string | null;
  closedAt?: string | null;
}

model AccessReviewItem {
  id: int64;
  userEmail: string;
  roleName: string;
  scope: int64 | null;
  grantedAt: string | null;
  grantedBy?: string | null;
  isSso: boolean;
  isSelf: boolean;
  decision: AccessReviewDecision;
  appliedAt: string | null;
}

model AccessReviewDetail {
  campaign: AccessReviewCampaign;
  items: AccessReviewItem[];
}

model AccessReviewCreateRequest {
  name: string;
}

model AccessReviewItemDecideRequest {
  decision: AccessReviewWriteDecision;
  note?: string;
}

model AccessReviewBulkDecideRequest {
  itemIds: int64[];
  decision: AccessReviewWriteDecision;
}

model AccessReviewBulkResult {
  applied: int32;
  skipped: int32;
}

// ── Guests & Guest Profiles ──────────────────────────────────────────────

enum GuestStatus {
  invited: "invited",
  active: "active",
  disabled: "disabled",
  expired: "expired",
}

enum GuestInviteState {
  pending: "pending",
  expired: "expired",
  accepted: "accepted",
  superseded: "superseded",
  revoked: "revoked",
  `unknown`: "unknown",
}

enum GuestProfileApp {
  chat: "chat",
  drive: "drive",
  meet: "meet",
}

model GuestProfileInput {
  hostDomainId: int64;
  name: string;
  canPost: boolean;
  historyFromJoin: boolean;
  allowDownload: boolean;
  allowMeetCreate: boolean;
  allowMeetHost: boolean;
  canInitiateDm: boolean;
  allowNativeShell: boolean;
  defaultExpiryDays: int32 | null;
  apps: GuestProfileApp[];
}

model GuestProfile {
  ...GuestProfileInput;
  id: int64;
  assignedCount: int64;
  createdAt: string;
  updatedAt: string;
}

model GuestProfileDomain {
  id: int64;
  name: string;
}

model GuestSummary {
  id: int64;
  displayName: string;
  invitedEmail: string;
  status: GuestStatus;
  effectiveStatus: GuestStatus;
  expiresAt: string | null;
  sponsorUserId: int64 | null;
  sponsorDisplayName: string | null;
  sponsorNeedsReview: boolean;
  profileId: int64 | null;
  profileName: string | null;
  pendingInvite: boolean;
  channelGrantCount: int64;
  createdAt: string;
  updatedAt: string;
}

model GuestPendingInvite {
  inviteId: string;
  expiresAt: string;
  createdAt: string;
  createdByEmail: string | null;
}

model GuestInviteHistoryEntry {
  inviteId: string;
  state: GuestInviteState;
  createdAt: string;
  expiresAt: string;
  terminalAt: string | null;
  createdByEmail: string | null;
}

model GuestChannelGrant {
  channelId: int64;
  kind: string;
  name: string | null;
  role: string;
  canPost: boolean | null;
  historyFloorSeq: int64 | null;
}

model GuestDetail {
  id: int64;
  displayName: string;
  invitedEmail: string;
  status: GuestStatus;
  effectiveStatus: GuestStatus;
  expiresAt: string | null;
  sponsorUserId: int64 | null;
  sponsorDisplayName: string | null;
  sponsorNeedsReview: boolean;
  profileId: int64 | null;
  profileName: string | null;
  channelGrantCount: int64;
  createdAt: string;
  updatedAt: string;
  invitedBy: int64 | null;
  invitedByEmail: string | null;
  pendingInvite: GuestPendingInvite | null;
  inviteHistory: GuestInviteHistoryEntry[];
  inviteHistoryHasMore: boolean;
  channelGrants: GuestChannelGrant[];
  appEntitlements: Record<boolean>;
}

model GuestInviteInput {
  email: string;
  displayName: string;
  profileId?: int64 | null;
  expiresAt?: string;
}

model GuestReinviteInput {
  expiresAt?: string;
}

model GuestInviteMutationResult {
  guestUserId: int64;
  inviteId: string;
  expiresAt: string;
  invitedEmail?: string;
}

model GuestInviteDeliveryUnconfirmedBody {
  code: string;
  retryable: boolean;
  inviteId: string;
  guestUserId: int64;
  error: string;
}

@error
model GuestInviteDeliveryUnconfirmedResponse {
  @statusCode statusCode: 503;
  @header("content-type") contentType: "application/json";
  @header("X-Operation-ID") operationId?: string;
  @body body: GuestInviteDeliveryUnconfirmedBody;
}

model GuestAssignProfileRequest {
  profileId: int64 | null;
}

model GuestExtendRequest {
  expiresAt: string;
}

model GuestSponsorOption {
  id: int64;
  email: string;
  displayName: string;
}

model GuestTransferRequest {
  sponsorUserId: int64;
}

model GuestTransferResult {
  guestUserId: int64;
  sponsorUserId: int64;
  channelOwnersTransferred: int64;
  driveSpacesTransferred: int64;
}

model GuestRevokeInviteRequest {
  expectedInviteId: string;
}

// ── Interfaces ───────────────────────────────────────────────────────────

@tag("AdminRoles")
@route("/api/admin")
interface AdminRolesApi {
  @doc("List the full admin permission catalog.")
  @get
  @route("/permissions")
  listPermissions():
    | PermissionCatalogEntry[]
    | UnauthorizedProblem
    | ForbiddenProblem
    | InternalServerProblem;

  @doc("List all admin roles.")
  @get
  @route("/roles")
  listRoles():
    | AdminRole[]
    | UnauthorizedProblem
    | ForbiddenProblem
    | InternalServerProblem;

  @doc("Create a custom admin role.")
  @post
  @route("/roles")
  createRole(
    @header("X-Audit-Reason") auditReason?: string,
    @body body: AdminRoleCreateRequest,
  ):
    | {
        @statusCode statusCode: 201;
        @body body: AdminCreatedIdResponse;
      }
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | ConflictProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("Get details and current members of an admin role.")
  @get
  @route("/roles/{id}")
  getRole(@path id: int64):
    | RoleDetail
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Update an admin role.")
  @put
  @route("/roles/{id}")
  updateRole(
    @path id: int64,
    @header("X-Audit-Reason") auditReason?: string,
    @body body: AdminRoleUpdateRequest,
  ):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("Delete a custom admin role.")
  @delete
  @route("/roles/{id}")
  deleteRole(
    @path id: int64,
    @header("X-Audit-Reason") auditReason?: string,
  ):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("Assign a user to an admin role.")
  @post
  @route("/roles/{id}/members")
  assignRoleMember(
    @path id: int64,
    @header("X-Audit-Reason") auditReason?: string,
    @body body: AdminRoleAssignMemberRequest,
  ):
    | {
        @statusCode statusCode: 201;
        @body body: AdminCreatedIdResponse;
      }
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("Remove a user from an admin role.")
  @delete
  @route("/roles/{id}/members/{userId}")
  removeRoleMember(
    @path id: int64,
    @path userId: int64,
    @header("X-Audit-Reason") auditReason?: string,
  ):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("Resolve effective admin permissions and accessible consoles for a user.")
  @get
  @route("/users/{id}/effective-permissions")
  getEffectivePermissions(@path id: int64):
    | EffectivePerms
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Read Dengbao Separation of Duties (SoD) mode status and current violations.")
  @get
  @route("/dengbao/sod-mode")
  getSodMode():
    | SodModeStatus
    | UnauthorizedProblem
    | ForbiddenProblem
    | InternalServerProblem;

  @doc("Enable or disable Dengbao Separation of Duties (SoD) enforcement.")
  @put
  @route("/dengbao/sod-mode")
  setSodMode(
    @header("X-Audit-Reason") auditReason?: string,
    @body body: SodModeSetRequest,
  ):
    | SodModeSetResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | SodModeConflictResponse
    | ConflictProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;
}

@tag("AdminAccessReviews")
@route("/api/admin/access-reviews")
interface AdminAccessReviewsApi {
  @doc("List access review campaigns.")
  @get
  listAccessReviews():
    | AccessReviewCampaign[]
    | UnauthorizedProblem
    | ForbiddenProblem
    | InternalServerProblem;

  @doc("Create a new access review campaign.")
  @post
  createAccessReview(@body body: AccessReviewCreateRequest):
    | {
        @statusCode statusCode: 201;
        @body body: AdminCreatedIdResponse;
      }
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | ConflictProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("Get campaign summary and review items.")
  @get
  @route("/{id}")
  getAccessReview(@path id: int64):
    | AccessReviewDetail
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Record a keep/revoke decision on a single access review item.")
  @put
  @route("/{id}/items/{itemId}")
  decideAccessReviewItem(
    @path id: int64,
    @path itemId: int64,
    @body body: AccessReviewItemDecideRequest,
  ):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("Record bulk keep/revoke decisions across access review items.")
  @put
  @route("/{id}/items")
  decideAccessReviewBulk(
    @path id: int64,
    @body body: AccessReviewBulkDecideRequest,
  ):
    | AccessReviewBulkResult
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("Close an access review campaign.")
  @post
  @route("/{id}/close")
  closeAccessReview(@path id: int64):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;
}

@tag("AdminGuests")
@route("/api/admin")
interface AdminGuestsApi {
  @doc("List all guest accounts.")
  @get
  @route("/guests")
  listGuests():
    | GuestSummary[]
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Invite a new external guest account.")
  @post
  @route("/guests")
  inviteGuest(@body body: GuestInviteInput):
    | {
        @statusCode statusCode: 202;
        @body body: GuestInviteMutationResult;
      }
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | GuestInviteDeliveryUnconfirmedResponse
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("Get full detail for a guest account.")
  @get
  @route("/guests/{id}")
  getGuest(@path id: int64):
    | GuestDetail
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Assign or clear a guest profile on a guest account.")
  @put
  @route("/guests/{id}/profile")
  assignGuestProfile(
    @path id: int64,
    @body body: GuestAssignProfileRequest,
  ):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("Disable a guest account.")
  @post
  @route("/guests/{id}/disable")
  disableGuest(@path id: int64):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("Re-enable a disabled guest account.")
  @post
  @route("/guests/{id}/enable")
  enableGuest(@path id: int64):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("Extend a guest account expiration timestamp.")
  @post
  @route("/guests/{id}/extend")
  extendGuest(
    @path id: int64,
    @body body: GuestExtendRequest,
  ):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("Search eligible sponsors for a guest account.")
  @get
  @route("/guests/{id}/sponsor-options")
  listGuestSponsorOptions(
    @path id: int64,
    @query q?: string,
  ):
    | GuestSponsorOption[]
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Transfer guest sponsorship and owned collaboration resources.")
  @post
  @route("/guests/{id}/transfer")
  transferGuest(
    @path id: int64,
    @body body: GuestTransferRequest,
  ):
    | GuestTransferResult
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("Issue a fresh invitation email for an existing guest account.")
  @post
  @route("/guests/{id}/reinvite")
  reinviteGuest(
    @path id: int64,
    @body body: GuestReinviteInput,
  ):
    | {
        @statusCode statusCode: 202;
        @body body: GuestInviteMutationResult;
      }
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | GuestInviteDeliveryUnconfirmedResponse
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("Revoke a pending guest invitation.")
  @delete
  @route("/guests/{userId}/invite")
  revokeGuestInvite(
    @path userId: int64,
    @body body: GuestRevokeInviteRequest,
  ):
    | EmptyOkResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("List configured guest profiles.")
  @get
  @route("/guest-profiles")
  listGuestProfiles():
    | GuestProfile[]
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Create a guest profile.")
  @post
  @route("/guest-profiles")
  createGuestProfile(@body body: GuestProfileInput):
    | {
        @statusCode statusCode: 201;
        @body body: GuestProfile;
      }
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("Get a single guest profile by id.")
  @get
  @route("/guest-profiles/{id}")
  getGuestProfile(@path id: int64):
    | GuestProfile
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;

  @doc("Update a guest profile.")
  @put
  @route("/guest-profiles/{id}")
  updateGuestProfile(
    @path id: int64,
    @body body: GuestProfileInput,
  ):
    | GuestProfile
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("Delete a guest profile.")
  @delete
  @route("/guest-profiles/{id}")
  deleteGuestProfile(@path id: int64):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("List host domains eligible for guest profiles.")
  @get
  @route("/guest-profile-domains")
  listGuestProfileDomains():
    | GuestProfileDomain[]
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | InternalServerProblem;
}
