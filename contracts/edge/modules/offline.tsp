import "@typespec/http";
import "../common/problem.tsp";

using TypeSpec.Http;
using SetjoinEdge.Common;

namespace SetjoinEdge.Offline;

@doc("Supported native offline mail cache time windows.")
union OfflineWindow {
  days7: "7d",
  days30: "30d",
  days90: "90d",
  days180: "180d",
  days365: "365d",
  all: "all",
}

@doc("Estimated message count and body bytes for one offline window.")
model OfflineSizeBucket {
  window: OfflineWindow;
  messageCount: int64;
  bodyBytes: int64;
}

@doc("Server-computed offline storage size estimate across all windows.")
model OfflineSizeEstimate {
  buckets: OfflineSizeBucket[];
}

@doc("User-scoped mailbox storage usage and quota totals in bytes.")
model MailboxQuota {
  usedBytes: int64;
  quotaBytes: int64;
}

@doc("User view preferences JSON document (preserves additional sibling preference keys and explicit nulls).")
model ViewPreferences {
  defaultView?: string | null;
  readingPane?: string | null;
  senderImages?: boolean | null;
  extSenderWarning?: boolean | null;
  smartMute?: boolean | null;
  undoSendDelay?: int32 | null;
  offlineWindow?: OfflineWindow | string | null;
  ...Record<unknown>;
}

@doc("Generic acknowledgement payload.")
model OkStatus {
  status: string;
}

model OfflineSizeEstimateResponse {
  @statusCode statusCode: 200;
  @header("content-type") contentType: "application/json";
  @body body: OfflineSizeEstimate;
}

model MailboxQuotaResponse {
  @statusCode statusCode: 200;
  @header("content-type") contentType: "application/json";
  @body body: MailboxQuota;
}

model ViewPreferencesResponse {
  @statusCode statusCode: 200;
  @header("content-type") contentType: "application/json";
  @body body: ViewPreferences;
}

model ViewPreferencesUpdatedTextResponse {
  @statusCode statusCode: 200;
  @header("content-type") contentType: "text/plain";
  @doc("JSON-encoded OkStatus acknowledgement (`{\"status\":\"ok\"}\\n`) sent with text/plain content type.")
  @body body: string;
}

@tag("Offline")
interface OfflineOperations {
  @get
  @route("/api/offline/size-estimate")
  @summary("Estimate local storage size across offline mail cache windows")
  getOfflineSizeEstimate():
    | OfflineSizeEstimateResponse
    | UnauthorizedProblem
    | ForbiddenProblem
    | TooManyRequestsProblem
    | InternalServerProblem
    | ServiceUnavailableProblem;

  @get
  @route("/api/user/quota")
  @summary("Get aggregated mailbox storage usage and quota for the authenticated user")
  getMailboxQuota():
    | MailboxQuotaResponse
    | UnauthorizedProblem
    | ForbiddenProblem
    | TooManyRequestsProblem
    | InternalServerProblem
    | ServiceUnavailableProblem;

  @get
  @route("/api/settings/view")
  @summary("Get user view preferences including offlineWindow")
  getViewPreferences():
    | ViewPreferencesResponse
    | UnauthorizedProblem
    | ForbiddenProblem
    | TooManyRequestsProblem
    | InternalServerProblem
    | ServiceUnavailableProblem;

  @put
  @route("/api/settings/view")
  @summary("Replace user view preferences document (accepts partial object with sibling keys or null)")
  putViewPreferences(
    @body body: ViewPreferences | null,
  ):
    | ViewPreferencesUpdatedTextResponse
    | BadRequestProblem
    | UnauthorizedProblem
    | ForbiddenProblem
    | TooManyRequestsProblem
    | InternalServerProblem
    | ServiceUnavailableProblem;
}
