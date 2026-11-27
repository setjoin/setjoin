import "@typespec/http";
import "../common/problem.tsp";

using TypeSpec.Http;
using SetjoinEdge.Common;

namespace SetjoinEdge.Sharing;

enum DelegatePermission {
  read: "read",
  sendAs: "send_as",
  sendOnBehalf: "send_on_behalf",
  fullAccess: "full_access",
  manageCalendar: "manage_calendar",
}

enum SharingLevel {
  none: "none",
  freebusy: "freebusy",
  read: "read",
}

enum SharingAudience {
  everyone: "everyone",
  ou: "ou",
  group: "group",
}

enum SharingOwnerScope {
  org: "org",
  ou: "ou",
  group: "group",
  user: "user",
}

model SharingDelegate {
  userId: int64;
  email: string;
  name: string;
  permission: DelegatePermission;
  grantedAt: string;
}

model SharingCalendarGrant {
  calendarId: int64;
  calendarName: string;
  userEmail: string;
  userName: string;
  level: string;
}

model SharingDefault {
  id: int64;
  ownerScope: SharingOwnerScope;
  audience: SharingAudience;
  audienceRef: int64;
  level: SharingLevel;
}

model SharingOverview {
  delegates: SharingDelegate[];
  calendarGrants: SharingCalendarGrant[];
  myDefaults: SharingDefault[];
  inheritedDefaults: SharingDefault[];
  defaultsEnabled: boolean;
}

model GrantDelegateRequest {
  granteeEmail: string;
  permission: DelegatePermission;
}

model SetMyDefaultRequest {
  audience: SharingAudience;
  audienceRef: int64;
  level: SharingLevel;
}

model SharingDefaultIdResponse {
  id: int64;
}

@tag("Sharing")
@route("/api/me/sharing")
interface SharingApi {
  @doc("Get the caller's mailbox delegation, calendar grant, and default sharing overview.")
  @get
  getSharingOverview():
    | SharingOverview
    | UnauthorizedProblem
    | ForbiddenProblem
    | InternalServerProblem;

  @doc("Grant mailbox delegation permission to another user.")
  @post
  @route("/delegates")
  grantDelegate(@body body: GrantDelegateRequest):
    | EmptyCreatedResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("Revoke mailbox delegation permission from a user.")
  @delete
  @route("/delegates/{userId}")
  revokeDelegate(@path userId: int64):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("Upsert the caller's own user-scope calendar sharing default.")
  @put
  @route("/default")
  setMyDefault(@body body: SetMyDefaultRequest):
    | SharingDefaultIdResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | ConflictProblem
    | UnprocessableEntityProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;

  @doc("Clear one of the caller's user-scope calendar sharing defaults.")
  @delete
  @route("/default/{id}")
  clearMyDefault(@path id: int64):
    | NoContentResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | NotFoundProblem
    | UnknownOutcomeProblem
    | InternalServerProblem;
}
