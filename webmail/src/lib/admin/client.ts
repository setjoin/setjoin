// Admin REST API client
import { httpRequest } from "$lib/http";
import { problemDetail } from "$lib/errors";
import type { Recipient } from "$lib/types/delivery";
import { adminFetch } from "./transport";
import {
  decodeOfficeAdminState,
  decodeOfficeAppOperationAccepted,
  decodeOfficeAppsState,
  decodeOfficeProviderActivationResult,
  decodeOfficeProviderConfigureResult,
  decodeOfficeProviderQualificationResult,
} from "./office";
import type {
  OfficeAdminState as DecodedOfficeAdminState,
  OfficeAppOperation as DecodedOfficeAppOperation,
  OfficeAppsState as DecodedOfficeAppsState,
  OfficeEntitlementState as DecodedOfficeEntitlementState,
  OfficeProviderPolicy as DecodedOfficeProviderPolicy,
  OfficeProviderConfigureResult,
  OfficeProviderQualificationResult,
  OfficeProviderActivationResult,
  OfficeAppOperationAccepted,
} from "./office";
export { adminFetch } from "./transport";
export { adminHealth } from "./health";
export type { HealthCheck, HealthResponse } from "./health";

// scopeSetFetch deliberately bypasses adminFetch to surface problem details;
// it still targets the same canonical application API namespace.
const API_BASE = "/api";

/**
 * Encode one interpolated PATH SEGMENT for an admin API URL.
 *
 * The module's convention is encode-by-default (encodeURIComponent at the
 * call site); this helper is the guarded form for string segments whose
 * values may be server-sourced or config-sourced: it rejects the
 * segment-boundary hostiles outright (empty, '/', '?', '#', '..' — the
 * request-retargeting primitives) instead of merely percent-encoding them,
 * then encodes so even benign delimiters cannot cross a segment.
 *
 * Throws on a hostile value: callers pass ids minted by the server or closed
 * unions; seeing a hostile value is a caller bug, not a request to send.
 */
export function adminPathSegment(value: string | number): string {
  // Number-typed ids stay raw on the wire (String() of a finite JS number is
  // already a safe segment); the hostile-value grammar only applies to
  // string segments, which may carry server/config-sourced text.
  const segment = typeof value === "number" ? String(value) : value;
  if (
    segment.length === 0 ||
    segment.includes("/") ||
    segment.includes("?") ||
    segment.includes("#") ||
    segment.includes("..")
  ) {
    throw new RangeError(
      `adminPathSegment: refusing hostile path segment ${JSON.stringify(segment)}`,
    );
  }
  return encodeURIComponent(segment);
}


export type OfficeEntitlementState = DecodedOfficeEntitlementState;
export type OfficeProviderPolicy = DecodedOfficeProviderPolicy;
export type OfficeAdminState = DecodedOfficeAdminState;
export type OfficeAppOperation = DecodedOfficeAppOperation;
export type OfficeAppsState = DecodedOfficeAppsState;

export async function adminOfficeGet(): Promise<OfficeAdminState> {
  const response = await adminFetch("/admin/office");
  return decodeOfficeAdminState(await response.json());
}

export async function adminOfficeConfigureProvider(
  providerId: string,
  input: {
    expectedGeneration: number;
    profile: string;
    entitlementState: OfficeEntitlementState;
    buildId: string | null;
    proofDiscoveryUrl: string;
    wopiPublicBaseUrl: string;
    editorUrl: string;
    privateAllowHosts: string[];
    privateAllowCidrs: string[];
  },
  reason: string,
): Promise<OfficeProviderConfigureResult> {
  const response = await adminFetch(
    `/admin/office/providers/${encodeURIComponent(providerId)}`,
    {
      method: "PUT",
      headers: { "X-Audit-Reason": reason },
      body: JSON.stringify({
        expectedGeneration: input.expectedGeneration,
        profile: input.profile,
        entitlementState: input.entitlementState,
        buildId: input.buildId,
        config: {
          proofDiscoveryUrl: input.proofDiscoveryUrl.trim(),
          wopiPublicBaseUrl: input.wopiPublicBaseUrl.trim(),
          editorUrl: input.editorUrl.trim(),
          profile: input.profile,
          privateAllowHosts: input.privateAllowHosts,
          privateAllowCidrs: input.privateAllowCidrs,
        },
      }),
    },
  );
  return decodeOfficeProviderConfigureResult(await response.json());
}

export async function adminOfficeQualifyProvider(
  providerId: string,
  input: {
    expectedGeneration: number;
    syntheticReceiptId: number;
    buildDigest?: string;
    routeRevision?: number;
  },
  reason: string,
): Promise<OfficeProviderQualificationResult> {
  const response = await adminFetch(
    `/admin/office/providers/${encodeURIComponent(providerId)}/qualify`,
    {
      method: "POST",
      headers: { "X-Audit-Reason": reason },
      body: JSON.stringify(input),
    },
  );
  return decodeOfficeProviderQualificationResult(await response.json());
}

export async function adminOfficeActivateProvider(
  providerId: string,
  input: {
    expectedGeneration: number;
    qualificationId: string;
    scope: Record<string, unknown>;
  },
  reason: string,
): Promise<OfficeProviderActivationResult> {
  const response = await adminFetch(
    `/admin/office/providers/${encodeURIComponent(providerId)}/activate`,
    {
      method: "POST",
      headers: { "X-Audit-Reason": reason },
      body: JSON.stringify(input),
    },
  );
  return decodeOfficeProviderActivationResult(await response.json());
}

export async function adminOfficeAppsGet(): Promise<OfficeAppsState> {
  const response = await adminFetch("/admin/apps");
  return decodeOfficeAppsState(await response.json());
}

export async function adminOfficeAppInstall(input: {
  providerId: string;
  expectedProviderGeneration: number;
  profile: string;
  ingress: Record<string, unknown>;
  reason: string;
  idempotencyKey: string;
}): Promise<OfficeAppOperationAccepted> {
  const response = await adminFetch("/admin/apps/collabora-code/operations", {
    method: "POST",
    headers: {
      "X-Audit-Reason": input.reason,
      "Idempotency-Key": input.idempotencyKey,
    },
    body: JSON.stringify({
      kind: "install",
      providerId: input.providerId,
      expectedProviderGeneration: input.expectedProviderGeneration,
      idempotencyKey: input.idempotencyKey,
      request: {
        profile: input.profile,
        ingress: input.ingress,
        catalogRevision: 1,
      },
    }),
  });
  return decodeOfficeAppOperationAccepted(await response.json());
}

export async function adminOfficeRemoveProvider(
  providerId: string,
  reason: string,
): Promise<void> {
  await adminFetch(
    `/admin/office/providers/${encodeURIComponent(providerId)}`,
    {
      method: "DELETE",
      headers: { "X-Audit-Reason": reason },
    },
  );
}

// ── Client-assisted mail recovery ──

export interface MailRecoverySignal {
  mailboxId: string;
  email: string;
  tokenSha256: string;
  timelineGeneration: string;
  stateWatermark: string;
  bootEpoch: string;
  issuedAt: string;
  observedAt: string;
  signalClass: "client_observed_newer_timeline";
}

export interface MailRecoveryStatus {
  installationId: string;
  localTimelineGeneration: string;
  lastWallClock: string | null;
  lastBootEpoch: string | null;
  lastBootAt: string | null;
  restoreDeclaredAt: string | null;
  signals: MailRecoverySignal[];
}

export interface MailRecoveryIncident {
  id: string;
  status: "open" | "closed" | "expired";
  minimumTimeline: string;
  maximumTimeline: string;
  reason: string;
  openedBy: string;
  approvalRequired: boolean;
  approvedBy: string | null;
  expiresAt: string;
  createdAt: string;
  mailboxCount: number;
  counts: Record<
    "uploading" | "quarantined" | "accepted" | "rejected" | "deduplicated",
    number
  >;
}

export interface MailRecoveryArtifact {
  id: string;
  mailboxId: string;
  uploadingUserId: string;
  deviceId: string;
  artifactIdentity: string;
  rawMimeSha256: string;
  rawMimeSize: string;
  signedTimeline: string;
  signedBootEpoch: string;
  headers: {
    subject?: string;
    from?: string;
    date?: string;
    messageId?: string;
  };
  malwareStatus: "clean" | "infected";
  status:
    | "quarantined"
    | "fork_conflict"
    | "tampered"
    | "accepted"
    | "rejected"
    | "deduplicated";
  rejectionReason: string | null;
  forkConsented: boolean;
  createdAt: string;
  terminalAt: string | null;
}

export async function adminMailRecoveryStatus(): Promise<MailRecoveryStatus> {
  const response = await adminFetch("/admin/system/recovery/signals?limit=100");
  return (await response.json()) as MailRecoveryStatus;
}

export async function adminMailRecoveryIncidents(): Promise<
  MailRecoveryIncident[]
> {
  const response = await adminFetch(
    "/admin/system/recovery/incidents?limit=100",
  );
  const body = (await response.json()) as { list: MailRecoveryIncident[] };
  return body.list ?? [];
}

export async function adminMailRecoveryArtifacts(
  incidentId: string,
): Promise<MailRecoveryArtifact[]> {
  const response = await adminFetch(
    `/admin/system/recovery/incidents/${encodeURIComponent(incidentId)}/artifacts?limit=100`,
  );
  const body = (await response.json()) as { list: MailRecoveryArtifact[] };
  return body.list ?? [];
}

export async function adminMailRecoveryOpen(input: {
  mailboxIds: string[];
  evidence: Record<string, string>;
  minimumTimeline: string;
  maximumTimeline: string;
  expiresAt: string;
  reason: string;
  approvalRequired: boolean;
}): Promise<{ id: string; status: string }> {
  const incidentId = crypto.randomUUID();
  const idempotencyKey = crypto.randomUUID();
  const response = await adminFetch("/admin/system/recovery/incidents", {
    method: "POST",
    headers: {
      "X-Audit-Reason": input.reason,
      "Idempotency-Key": idempotencyKey,
    },
    body: JSON.stringify({ ...input, incidentId, idempotencyKey }),
    onError: problemDetail,
  });
  return (await response.json()) as { id: string; status: string };
}

export async function adminMailRecoveryIncidentAction(
  incidentId: string,
  action: "approve" | "close",
  reason: string,
): Promise<void> {
  await adminFetch(
    `/admin/system/recovery/incidents/${encodeURIComponent(incidentId)}/${action}`,
    {
      method: "POST",
      headers: { "X-Audit-Reason": reason },
      body: JSON.stringify({ reason }),
      onError: problemDetail,
    },
  );
}

export async function adminMailRecoveryAccept(
  artifactId: string,
  resolution: "accept" | "accept_fork",
  reason: string,
): Promise<void> {
  await adminFetch(
    `/admin/system/recovery/artifacts/${encodeURIComponent(artifactId)}/accept`,
    {
      method: "POST",
      headers: { "X-Audit-Reason": reason },
      body: JSON.stringify({ resolution, reason }),
      onError: problemDetail,
    },
  );
}

// ── Users ──

export interface AdminUser {
  id: number;
  email: string;
  displayName: string;
  enabled: boolean;
  isLocalAdmin: boolean;
  departmentId?: number;
  createdAt: string;
  mailboxId?: number;
  /** True when the caller has sufficient authority to manage this user. Only set by the List endpoint. */
  manageable: boolean;
  /** True when this row is the caller's own account. Only set by the List endpoint. */
  isSelf: boolean;
}

export async function adminUserList(
  q?: string,
  limit = 50,
  offset = 0,
): Promise<AdminUser[]> {
  const params = new URLSearchParams();
  if (q) params.set("q", q);
  params.set("limit", String(limit));
  params.set("offset", String(offset));
  const res = await adminFetch("/admin/users?" + params.toString());
  // Go marshals a nil slice as `null` — normalize so an empty result (e.g. a
  // non-matching ?q= filter) doesn't wedge the page render on users.length.
  return ((await res.json()) ?? []) as AdminUser[];
}

export async function adminUserCreate(data: {
  email: string;
  displayName?: string;
  password: string;
  isLocalAdmin?: boolean;
}): Promise<{ id: number }> {
  const res = await adminFetch("/admin/users", {
    method: "POST",
    body: JSON.stringify(data),
    // Surface the server's actionable rejection (password policy, duplicate,
    // non-local domain) — the create dialog renders this string in-dialog.
    onError: problemDetail,
  });
  return (await res.json()) as { id: number };
}

export async function adminUserUpdate(
  id: number,
  patch: Partial<
    Pick<AdminUser, "displayName" | "enabled" | "isLocalAdmin" | "departmentId">
  >,
): Promise<void> {
  await adminFetch(`/admin/users/${id}`, {
    method: "PUT",
    body: JSON.stringify(patch),
  });
}

export async function adminUserResetPassword(
  id: number,
  password: string,
  mustChange = true,
): Promise<void> {
  await adminFetch(`/admin/users/${id}/password`, {
    method: "PUT",
    body: JSON.stringify({ password, mustChange }),
  });
}

export interface Alias {
  id: number;
  email: string;
  isPrimary: boolean;
}

export async function adminUserAliases(id: number): Promise<Alias[]> {
  const res = await adminFetch(`/admin/users/${id}/aliases`);
  return (await res.json()) as Alias[];
}

export async function adminUserAddAlias(
  id: number,
  email: string,
): Promise<{ id: number }> {
  const res = await adminFetch(`/admin/users/${id}/aliases`, {
    method: "POST",
    body: JSON.stringify({ email }),
  });
  return (await res.json()) as { id: number };
}

export async function adminUserRemoveAlias(
  userId: number,
  aliasId: number,
): Promise<void> {
  await adminFetch(`/admin/users/${userId}/aliases/${aliasId}`, {
    method: "DELETE",
  });
}

export interface Quota {
  quotaBytes: number;
  usedBytes: number;
  sendingQuotaDay: number;
  sendingSentToday: number;
}

export async function adminUserQuota(id: number): Promise<Quota> {
  const res = await adminFetch(`/admin/users/${id}/quota`);
  return (await res.json()) as Quota;
}

export async function adminUserDelete(id: number): Promise<void> {
  await adminFetch(`/admin/users/${id}`, { method: "DELETE" });
}

export interface MailboxLifecycleState {
  mailboxId: string;
  binding: "bound" | "retained" | "shared";
  access: "active" | "suspended" | "detached";
  delivery: "accepting" | "rejecting" | "redirecting";
  boundUserId: string | null;
  generation: string;
  retainedAt: string | null;
  retentionUntil: string | null;
  reason: string | null;
}

export interface MailboxLifecyclePreview {
  state: MailboxLifecycleState;
  addresses: string[];
  messageCount: number;
  blobCount: number;
  blockers: Array<{
    domain: string;
    kind: string;
    count: number;
    until?: string | null;
  }>;
  previewDigest: string;
}

export interface RetainedMailbox {
  mailboxId: string;
  email: string;
  displayName: string;
  generation: string;
  access: "detached";
  delivery: "accepting" | "rejecting" | "redirecting";
  retainedAt: string;
  retentionUntil: string;
  addresses: string[];
}

export async function adminRetainedMailboxes(): Promise<RetainedMailbox[]> {
  const response = await adminFetch("/admin/mailboxes/retained", {
    onError: problemDetail,
  });
  return ((await response.json()) ?? []) as RetainedMailbox[];
}

export async function adminMailboxLifecyclePreview(
  mailboxId: number,
): Promise<MailboxLifecyclePreview> {
  const response = await adminFetch(
    `/admin/mailboxes/${mailboxId}/lifecycle/preview`,
    { onError: problemDetail },
  );
  return (await response.json()) as MailboxLifecyclePreview;
}

export async function adminMailboxLifecycleTransition(
  mailboxId: number,
  action: "suspend" | "resume" | "detach_retain" | "reconnect",
  expectedGeneration: string,
  reason: string,
  extra: Record<string, string> = {},
): Promise<MailboxLifecycleState> {
  const idempotencyKey = crypto.randomUUID();
  const response = await adminFetch(`/admin/mailboxes/${mailboxId}/lifecycle`, {
    method: "POST",
    headers: { "Idempotency-Key": idempotencyKey, "X-Audit-Reason": reason },
    body: JSON.stringify({
      action,
      expectedGeneration,
      reason,
      idempotencyKey,
      ...extra,
    }),
    onError: problemDetail,
  });
  return (await response.json()) as MailboxLifecycleState;
}

export async function adminMailboxPurgeSchedule(
  mailboxId: number,
  expectedGeneration: string,
  previewDigest: string,
  approverUserId: number,
  reason: string,
): Promise<{
  purgeRequestId: string;
  approvalRequestId: number;
  eligibleAt: string;
}> {
  const idempotencyKey = crypto.randomUUID();
  const response = await adminFetch(`/admin/mailboxes/${mailboxId}/purge`, {
    method: "POST",
    headers: { "Idempotency-Key": idempotencyKey, "X-Audit-Reason": reason },
    body: JSON.stringify({
      expectedGeneration,
      previewDigest,
      approverUserId: String(approverUserId),
      reason,
      idempotencyKey,
    }),
    onError: problemDetail,
  });
  return (await response.json()) as {
    purgeRequestId: string;
    approvalRequestId: number;
    eligibleAt: string;
  };
}

export async function adminMailboxPurgeCancel(
  purgeRequestId: string,
  reason: string,
): Promise<{
  purgeRequestId: string;
  mailboxId: string;
  state: "cancelled";
  generation: string;
}> {
  const idempotencyKey = crypto.randomUUID();
  const response = await adminFetch(
    `/admin/mailbox-purges/${adminPathSegment(purgeRequestId)}/cancel`,
    {
      method: "POST",
      headers: { "Idempotency-Key": idempotencyKey, "X-Audit-Reason": reason },
      body: JSON.stringify({ reason, idempotencyKey }),
      onError: problemDetail,
    },
  );
  return (await response.json()) as {
    purgeRequestId: string;
    mailboxId: string;
    state: "cancelled";
    generation: string;
  };
}

export async function adminUserImportCSV(file: File): Promise<{
  created: number;
  failed: Array<{ row: number; email: string; error: string }>;
}> {
  const form = new FormData();
  form.append("file", file);
  const res = await adminFetch("/admin/users/import", {
    method: "POST",
    body: form,
  });
  return (await res.json()) as {
    created: number;
    failed: Array<{ row: number; email: string; error: string }>;
  };
}

export async function adminUserSetQuota(
  id: number,
  patch: Partial<Quota>,
): Promise<void> {
  await adminFetch(`/admin/users/${id}/quota`, {
    method: "PUT",
    body: JSON.stringify(patch),
  });
}

// ── App access entitlements (B8) ──

export interface AppEntitlement {
  app: string;
  enabled: boolean;
}

export async function adminUserAppAccess(
  userId: number,
): Promise<AppEntitlement[]> {
  const res = await adminFetch(`/admin/users/${userId}/app-access`);
  return (await res.json()) as AppEntitlement[];
}

export async function adminUserSetAppAccess(
  userId: number,
  app: string,
  enabled: boolean,
): Promise<void> {
  await adminFetch(`/admin/users/${adminPathSegment(userId)}/app-access/${adminPathSegment(app)}`, {
    method: "PUT",
    body: JSON.stringify({ enabled }),
  });
}

// ── Rules ──

export interface AdminRule {
  id: number;
  name: string;
  enabled: boolean;
  priority: number;
  runOn: string;
  isTransportRule: boolean;
  conditions: unknown;
  actions: unknown;
  stopProcessing: boolean;
  createdAt: string;
  updatedAt: string;
}

// ── Retention Policies ──

export interface RetentionPolicy {
  id: number;
  name: string;
  description?: string;
  retainDays: number | null; // null = forever
  action: "delete" | "hold";
  isDefault: boolean;
  domainId?: number;
  createdAt: string;
}

export interface LogRetentionSettings {
  messageTraceDays: number | null;
  mailboxAuditLogDays: number | null;
  authEventDays: number;
}

export async function adminRetentionPolicies(): Promise<RetentionPolicy[]> {
  const res = await adminFetch("/admin/retention/policies");
  return (await res.json()) as RetentionPolicy[];
}

export async function adminRetentionCreate(
  data: Omit<RetentionPolicy, "id" | "createdAt">,
): Promise<{ id: number }> {
  const res = await adminFetch("/admin/retention/policies", {
    method: "POST",
    body: JSON.stringify(data),
  });
  return (await res.json()) as { id: number };
}

export async function adminRetentionUpdate(
  id: number,
  patch: Partial<Omit<RetentionPolicy, "id" | "createdAt">>,
): Promise<void> {
  await adminFetch(`/admin/retention/policies/${id}`, {
    method: "PUT",
    body: JSON.stringify(patch),
  });
}

export async function adminRetentionDelete(id: number): Promise<void> {
  await adminFetch(`/admin/retention/policies/${id}`, { method: "DELETE" });
}

export async function adminLogRetention(): Promise<LogRetentionSettings> {
  const res = await adminFetch("/admin/retention/logs");
  return (await res.json()) as LogRetentionSettings;
}

export async function adminLogRetentionSet(
  settings: LogRetentionSettings,
): Promise<void> {
  await adminFetch("/admin/retention/logs", {
    method: "PUT",
    body: JSON.stringify(settings),
  });
}

export async function adminRetentionPrune(): Promise<
  { table: string; deleted: number }[]
> {
  const res = await adminFetch("/admin/retention/prune", { method: "POST" });
  return (await res.json()) as { table: string; deleted: number }[];
}

// ── Rules ──

// ── Domains ──

export interface Domain {
  id: number;
  name: string;
  isPrimary: boolean;
  isLocal: boolean;
  catchAllMailboxId?: number;
  dkimSelector?: string;
  dkimKeyExpiresAt?: string;
  spfRecord?: string;
  dmarcPolicy: string;
  dmarcRua?: string;
  dmarcRuf?: string;
  mtaStsPolicy: string;
  maxMessageBytes: number;
  createdAt: string;
}

export async function adminDomainList(): Promise<Domain[]> {
  const res = await adminFetch("/admin/domains");
  return (await res.json()) as Domain[];
}

export async function adminDomainCreate(
  data: Omit<Domain, "id" | "createdAt">,
): Promise<{ id: number }> {
  const res = await adminFetch("/admin/domains", {
    method: "POST",
    body: JSON.stringify(data),
  });
  return (await res.json()) as { id: number };
}

export async function adminDomainUpdate(
  id: number,
  patch: Partial<Omit<Domain, "id" | "createdAt">>,
): Promise<void> {
  await adminFetch(`/admin/domains/${id}`, {
    method: "PUT",
    body: JSON.stringify(patch),
  });
}

export async function adminDomainDelete(id: number): Promise<void> {
  await adminFetch(`/admin/domains/${id}`, { method: "DELETE" });
}

// ── Rules ──

export async function adminRuleList(): Promise<AdminRule[]> {
  const res = await adminFetch("/admin/rules");
  return (await res.json()) as AdminRule[];
}

export async function adminRuleUpdate(
  id: number,
  data: Partial<AdminRule>,
): Promise<unknown> {
  const res = await adminFetch(`/admin/rules/${id}`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
  return res.json();
}

export async function adminRuleDelete(id: number): Promise<void> {
  await adminFetch(`/admin/rules/${id}`, { method: "DELETE" });
}

// ── System Config ──

export interface ConfigItem {
  key: string;
  value: unknown;
  encrypted: boolean;
}

export async function adminConfigGet(key: string): Promise<ConfigItem> {
  const res = await adminFetch(`/admin/system/config/${adminPathSegment(key)}`);
  return (await res.json()) as ConfigItem;
}

export async function adminConfigSet(
  key: string,
  value: unknown,
  encrypted = false,
): Promise<void> {
  await adminFetch(`/admin/system/config/${adminPathSegment(key)}`, {
    method: "PUT",
    body: JSON.stringify({ value, encrypted }),
  });
}

// ── Auth Methods ──

export interface AuthMethod {
  slug: string;
  name: string;
  enabled: boolean;
  priority: number;
  config?: unknown;
}

export async function adminAuthMethodList(): Promise<AuthMethod[]> {
  const res = await adminFetch("/admin/auth/methods");
  return (await res.json()) as AuthMethod[];
}

export async function adminAuthMethodUpdate(
  slug: string,
  patch: Partial<Pick<AuthMethod, "enabled" | "priority">>,
): Promise<void> {
  await adminFetch(`/admin/auth/methods/${adminPathSegment(slug)}`, {
    method: "PUT",
    body: JSON.stringify(patch),
  });
}

// ── Departments ──

export interface TreeNode {
  id: number;
  name: string;
  parentId?: number;
  path: string;
  ldapOu: string;
  sortOrder: number;
  userCount: number;
  children: TreeNode[];
}

export async function adminDeptTree(): Promise<TreeNode[]> {
  const res = await adminFetch("/admin/departments/tree");
  // Go marshals a nil slice as `null` (zero departments) — normalize so
  // flatDepts()/#each consumers don't throw "not iterable" and wedge the page.
  return ((await res.json()) ?? []) as TreeNode[];
}

export async function adminDeptCreate(data: {
  name: string;
  parentId?: number | null;
  ldapOu?: string;
}): Promise<{ id: number }> {
  const res = await adminFetch("/admin/departments", {
    method: "POST",
    body: JSON.stringify(data),
  });
  return (await res.json()) as { id: number };
}

export async function adminDeptUpdate(
  id: number,
  data: {
    name?: string;
    ldapOu?: string;
    parentId?: number | null;
    sortOrder?: number;
  },
): Promise<void> {
  await adminFetch(`/admin/departments/${id}`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export async function adminDeptDelete(id: number): Promise<void> {
  await adminFetch(`/admin/departments/${id}`, { method: "DELETE" });
}

export async function adminDeptAssignUser(
  userId: number,
  departmentId: number | null,
): Promise<void> {
  await adminFetch("/admin/departments/assign-user", {
    method: "POST",
    body: JSON.stringify({ userId, departmentId }),
  });
}

// ── Message Trace ──

export interface TraceRecord {
  id: number;
  messageId: string;
  event: string;
  fromAddr: string;
  rcptAddr: string;
  remoteHost?: string;
  details?: unknown;
  occurredAt: string;
}

export interface TraceResponse {
  records: TraceRecord[];
  total: number;
  limit: number;
  offset: number;
}

// ── Reports ──

export interface DailyStat {
  date: string;
  sent: number;
  received: number;
  bounced: number;
  spam: number;
}

export interface ActorStat {
  email: string;
  count: number;
}

export interface RuleStat {
  ruleName: string;
  count: number;
}

export interface MailFlowSummary {
  period: string;
  totalSent: number;
  totalReceived: number;
  totalBounced: number;
  spamCount: number;
  daily: DailyStat[];
  topSenders: ActorStat[];
  topRecipients: ActorStat[];
  ruleTriggers: RuleStat[];
}

// ── DNS Wizard ──

export interface DKIMRecord {
  selector: string;
  record: string;
}

export interface DNSRecords {
  domain: string;
  mx: string;
  spf: string;
  dkim: DKIMRecord[];
  dmarc: string;
  mtasts?: string;
  tlsa?: string;
  reverseDns?: string;
  recommendedA?: string;
}

export interface DNSCheck {
  type: string;
  name: string;
  status: string;
  value?: string;
  expected?: string;
}

export interface DNSHealth {
  domain: string;
  checks: DNSCheck[];
  allPass: boolean;
}

export async function adminDNSGenerate(domain: string): Promise<DNSRecords> {
  const res = await adminFetch(
    `/admin/dns/records?domain=${encodeURIComponent(domain)}`,
  );
  return (await res.json()) as DNSRecords;
}

export async function adminDNSVerify(domain: string): Promise<DNSHealth> {
  const res = await adminFetch(
    `/admin/dns/verify?domain=${encodeURIComponent(domain)}`,
  );
  return (await res.json()) as DNSHealth;
}

// ── TLS Policy ──

export interface TLSPolicy {
  enforce_domains: string[];
  skip_domains: string[];
  global_mode: string;
}

export async function adminGetTLSPolicy(): Promise<TLSPolicy> {
  const res = await adminFetch("/admin/outbound-tls-policy");
  return (await res.json()) as TLSPolicy;
}

export async function adminPutTLSPolicy(policy: TLSPolicy): Promise<void> {
  await adminFetch("/admin/outbound-tls-policy", {
    method: "PUT",
    body: JSON.stringify(policy),
  });
}

// ── Alerts ──

export interface AlertStatus {
  checkName: string;
  consecutive: number;
  lastError?: string;
  lastChecked?: string;
  alertSentAt?: string;
  suppressed: boolean;
}

export async function adminAlertList(): Promise<AlertStatus[]> {
  const res = await adminFetch("/admin/alerts");
  return (await res.json()) as AlertStatus[];
}

export async function adminAlertAck(checkName: string): Promise<void> {
  await adminFetch("/admin/alerts/ack", {
    method: "POST",
    body: JSON.stringify({ checkName }),
  });
}

export async function adminAlertUnsuppress(checkName: string): Promise<void> {
  await adminFetch("/admin/alerts/unsuppress", {
    method: "POST",
    body: JSON.stringify({ checkName }),
  });
}

// ── Mailboxes ──

export interface AdminMailbox {
  id: number;
  userId: number;
  userEmail: string;
  name: string;
  isPrimary: boolean;
  role: string;
  quotaBytes: number;
  usedBytes: number;
  enabled: boolean;
  deletedPurgeDays?: number | null;
  spamPurgeDays?: number | null;
  litigationHold?: boolean;
  createdAt: string;
}

export interface AdminFolder {
  id: number;
  mailboxId: number;
  name: string;
  role: string;
  path: string;
  totalCount: number;
  unreadCount: number;
}

export async function adminMailboxList(
  q?: string,
  userId?: number,
): Promise<AdminMailbox[]> {
  const sp = new URLSearchParams();
  if (q) sp.set("q", q);
  if (userId) sp.set("user_id", String(userId));
  const res = await adminFetch("/admin/mailboxes?" + sp.toString());
  return (await res.json()) as AdminMailbox[];
}

export async function adminMailboxCreate(data: {
  userId: number;
  name: string;
  role?: string;
  quotaBytes?: number;
}): Promise<{ id: number }> {
  const res = await adminFetch("/admin/mailboxes", {
    method: "POST",
    body: JSON.stringify(data),
  });
  return (await res.json()) as { id: number };
}

export async function adminMailboxUpdate(
  id: number,
  patch: Partial<
    Pick<
      AdminMailbox,
      | "name"
      | "quotaBytes"
      | "enabled"
      | "deletedPurgeDays"
      | "spamPurgeDays"
      | "litigationHold"
    >
  >,
): Promise<void> {
  await adminFetch(`/admin/mailboxes/${id}`, {
    method: "PUT",
    body: JSON.stringify(patch),
  });
}

export async function adminMailboxDelete(id: number): Promise<void> {
  await adminFetch(`/admin/mailboxes/${id}`, { method: "DELETE" });
}

export async function adminMailboxFolders(
  mbId: number,
): Promise<AdminFolder[]> {
  const res = await adminFetch(`/admin/mailboxes/${mbId}/folders`);
  return (await res.json()) as AdminFolder[];
}

export async function adminMailboxCreateFolder(
  mbId: number,
  data: { name: string; parentId?: number },
): Promise<{ id: number }> {
  const res = await adminFetch(`/admin/mailboxes/${mbId}/folders`, {
    method: "POST",
    body: JSON.stringify(data),
  });
  return (await res.json()) as { id: number };
}

export async function adminMailboxDeleteFolder(
  mbId: number,
  folderId: number,
): Promise<void> {
  await adminFetch(`/admin/mailboxes/${mbId}/folders/${folderId}`, {
    method: "DELETE",
  });
}

export async function adminMailboxImport(
  mbId: number,
  file: File,
  folderId?: number,
): Promise<{
  imported: number;
  failed: Array<{ index?: number; file?: string; error: string }>;
}> {
  const form = new FormData();
  form.append("file", file);
  if (folderId) form.append("folder_id", String(folderId));
  const res = await adminFetch(`/admin/mailboxes/${mbId}/import`, {
    method: "POST",
    body: form,
  });
  return (await res.json()) as {
    imported: number;
    failed: Array<{ index?: number; file?: string; error: string }>;
  };
}

export async function adminMailboxExport(
  mbId: number,
  format: "mbox" | "eml",
  folderId?: number,
): Promise<Blob> {
  const sp = new URLSearchParams();
  sp.set("format", format);
  if (folderId) sp.set("folder_id", String(folderId));
  const res = await adminFetch(
    `/admin/mailboxes/${mbId}/export?` + sp.toString(),
  );
  return await res.blob();
}

// ── Reports ──

export async function adminReportsSummary(days = 7): Promise<MailFlowSummary> {
  const res = await adminFetch(`/admin/reports/summary?days=${days}`);
  return (await res.json()) as MailFlowSummary;
}

// ── Message Trace ──

export async function adminTraceExport(params: {
  from?: string;
  to?: string;
  subject?: string;
  event?: string;
  status?: string;
  dateFrom?: string;
  dateTo?: string;
}): Promise<Blob> {
  const sp = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== "") sp.set(k, String(v));
  });
  const res = await adminFetch("/admin/trace/export?" + sp.toString());
  return await res.blob();
}

export async function adminTraceSearch(params: {
  from?: string;
  to?: string;
  subject?: string;
  event?: string;
  status?: string;
  dateFrom?: string;
  dateTo?: string;
  limit?: number;
  offset?: number;
}): Promise<TraceResponse> {
  const sp = new URLSearchParams();
  Object.entries(params).forEach(([k, v]) => {
    if (v !== undefined && v !== "") sp.set(k, String(v));
  });
  const res = await adminFetch("/admin/trace?" + sp.toString());
  return (await res.json()) as TraceResponse;
}

export interface TraceEvent {
  event: string;
  rcptAddr: string | null;
  fromAddr: string | null;
  remoteHost: string | null;
  details: unknown | null;
  occurredAt: string;
}

export interface QueueState {
  status: string;
  attemptCount: number;
  nextAttemptAt: string | null;
  lastError: string | null;
  rcptAddrs: string[];
  queuedAt: string;
}

export interface TraceTimeline {
  messageId: string;
  events: TraceEvent[];
  queue: QueueState | null;
  multiRecipient: boolean;
  // Phase 2b: per-recipient cross-mailbox delivery, server-sorted problems-first.
  // Reuses the `Recipient` shape from `$lib/types/delivery` verbatim (do NOT redefine it).
  recipients?: Recipient[];
  // Phase 2b: the server-MAPPED queue verdict (e.g. pending→queued) — NOT the raw
  // `queue.status` enum. Rendered directly into `OutboundTimeline`.
  overallStatus?: string;
  // Phase 2b: attempts pruned (retention window) but the queue row is terminal →
  // show the "detail expired" note instead of fabricating per-recipient rows.
  detailExpired?: boolean;
}

export async function adminTraceTimeline(
  messageId: string,
): Promise<TraceTimeline> {
  const res = await adminFetch(`/admin/trace/${encodeURIComponent(messageId)}`);
  return (await res.json()) as TraceTimeline;
}

// ── Storage ──

export interface StorageStatus {
  mode: string;
  deploymentID: string;
  version: string;
  buckets: { count: number };
  objects: { count: number };
  usage: { size: number };
  backend: {
    type: number;
    onlineDisks: number;
    offlineDisks: number;
    totalSets: number[];
    drivesPerSet: number[];
    standardParity: number;
  };
  pools: Array<{
    index: number;
    sets: number;
    rawUsage: number;
    rawCapacity: number;
    objects: number;
  }>;
  servers: Array<{
    endpoint: string;
    state: string;
    version: string;
    uptime: number;
    poolNumber: number;
    drives: Array<{
      endpoint: string;
      state: string;
      used: number;
      total: number;
    }>;
  }>;
  healing: {
    scannedItems: number;
    healDisks: string[];
    sets: unknown[];
  };
}

export interface DRScan {
  id: number;
  status: string;
  totalScanned: number;
  orphanedCount: number;
  missingCount: number;
  reimportedCount: number;
  startedAt: string;
  completedAt?: string;
  details?: Array<{ sha256: string; issue: string; size?: number }>;
}

export async function adminStorageStatus(): Promise<StorageStatus> {
  const res = await adminFetch("/admin/storage/status");
  return (await res.json()) as StorageStatus;
}

export async function adminStorageDRScanStart(): Promise<{ id: number }> {
  const res = await adminFetch("/admin/storage/dr-scan", { method: "POST" });
  return (await res.json()) as { id: number };
}

export async function adminStorageDRScanList(): Promise<DRScan[]> {
  const res = await adminFetch("/admin/storage/dr-scan");
  return (await res.json()) as DRScan[];
}

export async function adminStorageDRScanGet(id: number): Promise<DRScan> {
  const res = await adminFetch(`/admin/storage/dr-scan/${id}`);
  return (await res.json()) as DRScan;
}

export async function adminStorageDRScanReconcile(
  id: number,
): Promise<{ reimported: number }> {
  const res = await adminFetch(`/admin/storage/dr-scan/${id}/reconcile`, {
    method: "POST",
  });
  return (await res.json()) as { reimported: number };
}

// ── Feature Toggles ──

export interface FeatureToggle {
  key: string;
  enabled: boolean;
  storedEnabled: boolean | null;
  defaultEnabled: boolean;
  classification: "known" | "unknown";
  registryMode: "observe" | "enforce";
  gatewayEffective: boolean;
  gatewaySource: "environment" | "database" | "default";
  authserverEffective: null;
  authserverSource: "not_reported";
  changeMode: "live" | "disconnect-live-clients" | "";
  disableBehavior: "immediate" | "stop-admission-drain-existing" | "";
  dependencies: string[];
  confirmationRequired: boolean;
  description?: string;
}

export async function adminFeatureList(): Promise<FeatureToggle[]> {
  const res = await adminFetch("/admin/features");
  const rows = (await res.json()) as FeatureToggle[];
  for (const row of rows) {
    if (
      row.authserverEffective !== null ||
      row.authserverSource !== "not_reported" ||
      !["environment", "database", "default"].includes(row.gatewaySource) ||
      !["known", "unknown"].includes(row.classification) ||
      !["observe", "enforce"].includes(row.registryMode) ||
      !["", "live", "disconnect-live-clients"].includes(row.changeMode ?? "") ||
      !["", "immediate", "stop-admission-drain-existing"].includes(
        row.disableBehavior ?? "",
      ) ||
      !Array.isArray(row.dependencies ?? []) ||
      !(row.dependencies ?? []).every((key) => typeof key === "string") ||
      !["boolean", "undefined"].includes(typeof row.confirmationRequired) ||
      (row.storedEnabled !== null && typeof row.storedEnabled !== "boolean")
    ) {
      throw new Error("invalid feature registry response");
    }
  }
  for (const row of rows) {
    row.changeMode ??= "";
    row.disableBehavior ??= "";
    row.dependencies ??= [];
    row.confirmationRequired ??= false;
  }
  return rows;
}

export async function adminFeatureSet(
  key: string,
  enabled: boolean,
  reason: string,
): Promise<void> {
  await adminFetch(`/admin/features/${encodeURIComponent(key)}`, {
    method: "PUT",
    headers: { "X-Audit-Reason": reason.trim() },
    body: JSON.stringify({ enabled }),
  });
}

export async function adminFeatureDeleteUnknown(
  key: string,
  reason: string,
): Promise<void> {
  await adminFetch(`/admin/features/${encodeURIComponent(key)}`, {
    method: "DELETE",
    headers: { "X-Audit-Reason": reason.trim() },
  });
}

export async function adminFeatureRegistryModeSet(
  mode: "observe" | "enforce",
  reason: string,
): Promise<{ mode: "observe" | "enforce"; registryDigest: string }> {
  const res = await adminFetch("/admin/features/registry-mode", {
    method: "PUT",
    headers: { "X-Audit-Reason": reason.trim() },
    body: JSON.stringify({ mode }),
  });
  return (await res.json()) as {
    mode: "observe" | "enforce";
    registryDigest: string;
  };
}

// ── AD (Active Directory) ──

export interface ADHealth {
  lastSync: string | null;
  status: "healthy" | "error" | "unknown";
  checked: number;
  created: number;
  updated: number;
  disabled: number;
  skipped: number;
  errors: number;
  pendingConflicts: number;
}

export async function adminADHealth(): Promise<ADHealth> {
  const res = await adminFetch("/admin/ad/health");
  return (await res.json()) as ADHealth;
}

export async function adminADConfig(): Promise<Record<string, string>> {
  const res = await adminFetch("/admin/ad/config");
  return (await res.json()) as Record<string, string>;
}

export async function adminADSetConfig(
  cfg: Record<string, string>,
): Promise<void> {
  await adminFetch("/admin/ad/config", {
    method: "PUT",
    body: JSON.stringify(cfg),
  });
}

export async function adminADTestConnection(): Promise<{ checked: number }> {
  const res = await adminFetch("/admin/ad/test-connection", { method: "POST" });
  return (await res.json()) as { checked: number };
}

export async function adminADSync(): Promise<{
  checked: number;
  created: number;
  updated: number;
}> {
  const res = await adminFetch("/admin/ad/sync", { method: "POST" });
  return (await res.json()) as {
    checked: number;
    created: number;
    updated: number;
  };
}

export interface SyncLogEntry {
  source: string;
  checked: number;
  created: number;
  updated: number;
  disabled: number;
  skipped: number;
  errors: number;
  durationSeconds: number;
  syncedAt: string;
  details: unknown;
}

export interface SyncConflict {
  id: number;
  userId: number;
  email: string;
  field: string;
  localValue: string;
  remoteValue: string;
  detectedAt: string;
}

export async function adminADConflicts(): Promise<SyncConflict[]> {
  const res = await adminFetch("/admin/ad/conflicts");
  return (await res.json()) as SyncConflict[];
}

export async function adminADResolveConflict(
  id: number,
  resolution: "keep_local" | "accept_remote",
): Promise<void> {
  await adminFetch(`/admin/ad/conflicts/${id}/resolve`, {
    method: "POST",
    body: JSON.stringify({ resolution }),
  });
}

export async function adminADResolveAllConflicts(
  resolution: "keep_local" | "accept_remote",
): Promise<void> {
  await adminFetch("/admin/ad/conflicts/resolve-all", {
    method: "POST",
    body: JSON.stringify({ resolution }),
  });
}

// ── Custom LDAP sync ─────────────────────────────────────────────────
// Mirrors the AD functions above; "Test connection" is a true dry-run (bind +
// search first N + count, zero writes) — unlike the AD twin, it never
// mutates the users table.

export interface LDAPHealth {
  lastSync: string | null;
  status: "healthy" | "error" | "unknown";
  checked: number;
  created: number;
  updated: number;
  disabled: number;
  skipped: number;
  errors: number;
  pendingConflicts: number;
}

export async function adminLDAPHealth(): Promise<LDAPHealth> {
  const res = await adminFetch("/admin/ldap/health");
  return (await res.json()) as LDAPHealth;
}

export async function adminLDAPConfig(): Promise<Record<string, string>> {
  const res = await adminFetch("/admin/ldap/config");
  return (await res.json()) as Record<string, string>;
}

export async function adminLDAPSetConfig(
  cfg: Record<string, string>,
): Promise<void> {
  await adminFetch("/admin/ldap/config", {
    method: "PUT",
    body: JSON.stringify(cfg),
  });
}

export async function adminLDAPTestConnection(): Promise<{ checked: number }> {
  const res = await adminFetch("/admin/ldap/test-connection", {
    method: "POST",
    onError: problemDetail,
  });
  return (await res.json()) as { checked: number };
}

export interface LDAPPreviewRow {
  email: string;
  displayName: string;
  action: "create" | "update" | "disable" | "skip";
  reason?: string;
}

export interface LDAPPreview {
  total: number;
  rows: LDAPPreviewRow[];
}

export async function adminLDAPPreview(limit = 25): Promise<LDAPPreview> {
  const res = await adminFetch(`/admin/ldap/preview?limit=${limit}`, {
    onError: problemDetail,
  });
  return (await res.json()) as LDAPPreview;
}

export async function adminLDAPSync(): Promise<{
  checked: number;
  created: number;
  updated: number;
}> {
  const res = await adminFetch("/admin/ldap/sync", { method: "POST" });
  return (await res.json()) as {
    checked: number;
    created: number;
    updated: number;
  };
}

export async function adminLDAPSyncLog(
  limit?: number,
): Promise<SyncLogEntry[]> {
  const res = await adminFetch(`/admin/ldap/sync-log?limit=${limit || 20}`);
  return (await res.json()) as SyncLogEntry[];
}

// ── Global Migration Source Config ───────────────────────────────────────

export interface GlobalIMAPConfig {
  host: string;
  port: number;
  tls_mode: string;
}

export interface GlobalEWSConfig {
  serverURL: string;
  username: string;
  password: string;
  authMode: "impersonation" | "per_user";
  insecureSkipVerify: boolean;
}

export interface M365Config {
  client_id: string;
  client_secret: string;
  tenant_id: string;
  cloud: "global" | "china";
}

export async function getGlobalSourceConfig(
  sourceType: string,
): Promise<GlobalIMAPConfig | GlobalEWSConfig | M365Config | null> {
  const res = await httpRequest(`/api/admin/migration/source/${adminPathSegment(sourceType)}`, {
    cache: "no-store",
    loginRedirect: "/login",
    forbiddenMessage: "Admin access required",
    allowStatuses: [404],
  });
  if (res.status === 404) return null;
  return res.json();
}

export async function saveGlobalIMAPConfig(
  config: GlobalIMAPConfig,
): Promise<void> {
  await adminFetch("/admin/migration/source/imap", {
    method: "PUT",
    body: JSON.stringify(config),
  });
}

export async function saveGlobalEWSConfig(
  config: GlobalEWSConfig,
): Promise<void> {
  await adminFetch("/admin/migration/source/ews", {
    method: "PUT",
    body: JSON.stringify(config),
  });
}

export async function saveM365Config(config: {
  client_id: string;
  client_secret: string;
  cloud: string;
}): Promise<void> {
  await adminFetch("/admin/migration/source/m365", {
    method: "PUT",
    body: JSON.stringify(config),
  });
}

export async function deleteGlobalSourceConfig(
  sourceType: string,
): Promise<void> {
  await adminFetch(`/admin/migration/source/${adminPathSegment(sourceType)}`, {
    method: "DELETE",
  });
}

export function getM365ConnectUrl(cloud: string): string {
  return `/admin/migration/m365/connect?cloud=${encodeURIComponent(cloud)}`;
}

// ── Group Mappings ────────────────────────────────────────────────────

export interface GroupMapping {
  idp_group: string;
  distribution_group_id?: number | null;
  admin_role?: string | null;
  department_id?: number | null;
}

export async function adminGetGroupMappings(): Promise<
  Record<string, Record<string, GroupMapping[]>>
> {
  const res = await adminFetch("/admin/identity/group-mappings");
  return res.json();
}

export async function adminUpdateGroupMappings(
  type: string,
  id: string,
  mappings: GroupMapping[],
  reason?: string,
): Promise<void> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };
  if (reason) headers["X-Audit-Reason"] = reason;
  await adminFetch(
    `/admin/identity/group-mappings/${adminPathSegment(type)}/${encodeURIComponent(id)}`,
    {
      method: "PUT",
      headers,
      body: JSON.stringify(mappings),
    },
  );
}

export interface IdentityV2Source {
  sourceKey: string;
  displayName: string;
  kind: string;
  state: string;
  generation: string;
  mappingVersion?: string;
  capabilities?: Record<string, unknown>;
  attentionCount: number;
  lastSuccessAt?: string | null;
  lastFailureAt?: string | null;
  lastErrorCode?: string | null;
  hasCursor?: boolean;
}

export interface IdentityV2Conflict {
  id: string;
  sourceKey: string;
  evidenceClass: string;
  state: string;
  generation: string;
  explanation: string;
  createdAt: string;
  expiresAt?: string;
}

export interface IdentityV2Person {
  userId: string;
  email: string;
  displayName?: string | null;
  enabled: boolean;
  lifecycleAuthority: "local" | "source";
  sourceKey?: string | null;
  activeLinks: number;
  detachedLinks: number;
}

export interface IdentityV2Transition {
  id: string;
  userId: string;
  kind: string;
  state: string;
  sourceKey: string;
  protected: boolean;
  reason?: string;
  failureCode?: string | null;
  pendingEffects: number;
  createdAt?: string;
  updatedAt: string;
}

export interface IdentityV2Event {
  id: string;
  occurredAt: string;
  userId?: string | null;
  sourceKey?: string | null;
  linkId?: string | null;
  transitionId?: string | null;
  action: string;
  reason: string;
  correlationId: string;
  metadata?: Record<string, unknown>;
}

export interface IdentitySourceDocument {
  apiVersion: "setjoin.io/v1";
  kind: "IdentitySource";
  metadata: {
    sourceKey: string;
    displayName: string;
  };
  spec: Record<string, unknown> & { type: string };
}

export interface IdentitySourceDetail extends Omit<
  IdentityV2Source,
  "attentionCount"
> {
  document: IdentitySourceDocument;
  secretConfigured: Record<string, boolean>;
}

export interface IdentitySourcePlan {
  sourceKey: string;
  create: boolean;
  changed: boolean;
  currentGeneration?: string;
  desired: IdentitySourceDocument;
  operations: string[];
}

export interface IdentitySourceMutationResult {
  sourceKey?: string;
  state?: string;
  generation: string;
  replayed?: boolean;
  valid?: boolean;
  transport?: string;
  personWrites?: number;
  blockers?: string[];
  secretConfigured?: Record<string, boolean>;
}

export interface IdentityPersonLink {
  id: string;
  sourceKey: string;
  sourceKind: string;
  purposes: string[];
  state: string;
  generation: string;
  linkMethod: string;
  subjectFingerprint: string;
  firstSeenAt: string;
  lastSeenAt: string;
  detachedAt?: string | null;
}

export interface IdentityPersonDetail {
  userId: string;
  email: string;
  displayName?: string | null;
  enabled: boolean;
  relationship: string;
  protected: boolean;
  lifecycleAuthority: {
    kind: "local" | "source";
    generation: string;
    linkId?: string | null;
    sourceKey?: string | null;
  };
  recovery: {
    hasLocalPassword: boolean;
    passkeyCount: number;
    activeAuthenticationLinks: number;
  };
  links: IdentityPersonLink[];
  fieldAuthority: Array<{
    field: string;
    authorityKind: string;
    sourceKey?: string | null;
    linkId?: string | null;
    generation: string;
    localOverrideState: string;
  }>;
  entitlementProvenance: Array<{
    id: string;
    targetKind: string;
    targetId: string;
    entitlementKind: string;
    entitlementId: string;
    provenanceKind: string;
    sourceKey?: string | null;
    linkId?: string | null;
    sourceGeneration: string;
    validUntil?: string | null;
    revokedAt?: string | null;
  }>;
  transitionHistory: Array<{
    id: string;
    kind: string;
    state: string;
    protected: boolean;
    generation: string;
    createdAt: string;
    updatedAt: string;
    completedAt?: string | null;
    failureCode?: string | null;
  }>;
  linkHistory: Array<{
    id: string;
    occurredAt: string;
    action: string;
    sourceKey?: string | null;
    linkId?: string | null;
    reason: string;
    correlationId: string;
  }>;
}

export interface IdentityConflictDetail {
  id: string;
  source: {
    sourceKey: string;
    displayName: string;
    kind: string;
    state: string;
    generation: string;
  };
  subjectFingerprint: string;
  evidenceClass: string;
  evidenceDigest: string;
  explanation: string;
  state: string;
  generation: string;
  createdAt: string;
  expiresAt: string;
  decidedAt?: string | null;
  candidatePerson?: {
    userId: string;
    email: string;
    displayName?: string | null;
    enabled: boolean;
    protected: boolean;
  } | null;
  allowedDecisions: Array<"link" | "create" | "reject" | "defer">;
  decisionHistory: Array<{
    id: string;
    decision: string;
    reason: string;
    personId?: string | null;
    linkId?: string | null;
    decidedBy: string;
    occurredAt: string;
  }>;
}

export interface IdentityConflictDecisionResult {
  candidateId?: string;
  decision: string;
  status: string;
  generation?: string;
  personId?: string | null;
  linkId?: string | null;
  replayed?: boolean;
}

export interface IdentityUpgradeStatus {
  schemaVersion: number;
  masterEnabled: boolean;
  normalizedReadsEnabled: boolean;
  transitionsEnabled: boolean;
  sources: {
    total: number;
    shadow: number;
    canary: number;
    normalized: number;
    cohortMembers: number;
  };
  blockers: {
    criticalDivergences: number;
    pendingCandidates: number;
    pendingEffects: number;
  };
}

export interface IdentityTransitionPreview {
  transitionId: string;
  state: "previewed";
  transitionGeneration: string;
  previewDigest: string;
  previewExpiresAt: string;
  protected: boolean;
  recoveryReady: boolean;
  sourceGeneration: string;
  linkGeneration: string;
  lifecycleGeneration: string;
  targetSourceGeneration?: string;
  targetLinkGeneration?: string;
  preview?: {
    type?: "directory_to_local" | "source_to_source";
    targetSourceId?: string;
    targetLinkId?: string;
  };
  replayed: boolean;
}

export interface IdentityTransitionEffect {
  effectId: string;
  kind: string;
  state: string;
  attemptCount: number;
  nextAttemptAt: string;
  lastErrorCode?: string | null;
  completedAt?: string | null;
}

export interface IdentityTransitionDetail {
  transitionId: string;
  correlationId: string;
  personId: string;
  type: string;
  state: string;
  transitionGeneration: string;
  previewVersion: string;
  previewDigest: string;
  previewExpiresAt: string;
  protected: boolean;
  requestedBy?: string;
  requestedAt?: string | null;
  approvalRequestId?: string | null;
  approvedBy?: string | null;
  approvedAt?: string | null;
  authorizedAt?: string | null;
  rollback: {
    boundary: string;
    previewDigest?: string | null;
    previewExpiresAt?: string | null;
    approvalRequestId?: string | null;
    requestedAt?: string | null;
    approvedBy?: string | null;
    approvedAt?: string | null;
  };
  failureCode?: string | null;
  createdAt?: string;
  committedAt?: string | null;
  completedAt?: string | null;
  steps?: Array<{
    ordinal: number;
    stage: string;
    state: string;
    attemptCount: number;
    startedAt?: string | null;
    finishedAt?: string | null;
    retryAt?: string | null;
    errorCode?: string | null;
  }>;
  effects: IdentityTransitionEffect[];
}

export interface IdentityTransitionChallenge {
  challengeId: string;
  transitionId: string;
  transitionGeneration: string;
  previewDigest: string;
  expiresAt: string;
  handoffMethod: "browser";
  displayCode: string;
  completed: boolean;
  invalidated: boolean;
}

export interface IdentityTransitionElevation {
  challengeId: string;
  elevationId: string;
  transitionId: string;
  transitionGeneration: string;
  expiresAt: string;
  consumed: boolean;
  invalidated: boolean;
  replayed: boolean;
}

async function identityProblemDetail(res: Response): Promise<string> {
  const body = (await res.json().catch(() => null)) as {
    detail?: unknown;
    title?: unknown;
    code?: unknown;
    remediation?: unknown;
    retryable?: unknown;
  } | null;
  const detail =
    body && typeof body.detail === "string"
      ? body.detail
      : body && typeof body.title === "string"
        ? body.title
        : "Identity operation failed";
  const evidence: string[] = [];
  if (body && typeof body.code === "string") evidence.push(body.code);
  if (body && typeof body.remediation === "string" && body.remediation) {
    evidence.push(body.remediation);
  }
  if (body?.retryable === true)
    evidence.push("Retry is safe without changing the request.");
  return evidence.length > 0 ? `${detail} — ${evidence.join(" · ")}` : detail;
}

async function identityV2List<T>(
  kind: "sources" | "people" | "conflicts" | "transitions" | "events",
  params?: Record<string, string | undefined>,
): Promise<T[]> {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params ?? {})) {
    if (value) query.set(key, value);
  }
  const suffix = query.size > 0 ? `?${query.toString()}` : "";
  const res = await adminFetch(`/admin/identity/v2/${kind}${suffix}`, {
    onError: identityProblemDetail,
  });
  const body = (await res.json()) as { items?: T[] };
  return body.items ?? [];
}

export const adminIdentitySources = (filter?: string) =>
  identityV2List<IdentityV2Source>("sources", { filter });
export const adminIdentityPeople = (filter?: string) =>
  identityV2List<IdentityV2Person>("people", { filter });
export const adminIdentityConflicts = (filter?: string) =>
  identityV2List<IdentityV2Conflict>("conflicts", { filter });
export const adminIdentityTransitions = (filter?: string) =>
  identityV2List<IdentityV2Transition>("transitions", { filter });
export const adminIdentityEvents = (filter?: string) =>
  identityV2List<IdentityV2Event>("events", { filter });

export async function adminIdentitySourceDetail(
  sourceKey: string,
): Promise<IdentitySourceDetail> {
  const res = await adminFetch(
    `/admin/identity/v2/sources/${encodeURIComponent(sourceKey)}`,
    { onError: identityProblemDetail },
  );
  return (await res.json()) as IdentitySourceDetail;
}

export async function adminIdentitySourcePlan(
  document: IdentitySourceDocument,
): Promise<IdentitySourcePlan> {
  const res = await adminFetch("/admin/identity/v2/sources/plan", {
    method: "POST",
    body: JSON.stringify(document),
    onError: identityProblemDetail,
  });
  return (await res.json()) as IdentitySourcePlan;
}

export async function adminIdentitySourceApply(
  document: IdentitySourceDocument,
  reason: string,
  idempotencyKey: string,
  expectedGeneration?: string,
): Promise<IdentitySourceMutationResult> {
  const sourceKey = document.metadata.sourceKey;
  const headers: Record<string, string> = {
    "Idempotency-Key": idempotencyKey,
    "X-Audit-Reason": reason,
  };
  if (expectedGeneration) headers["If-Match"] = `"${expectedGeneration}"`;
  const res = await adminFetch(
    expectedGeneration
      ? `/admin/identity/v2/sources/${encodeURIComponent(sourceKey)}`
      : "/admin/identity/v2/sources",
    {
      method: expectedGeneration ? "PUT" : "POST",
      headers,
      body: JSON.stringify({ document, reason, idempotencyKey }),
      onError: identityProblemDetail,
    },
  );
  return (await res.json()) as IdentitySourceMutationResult;
}

async function adminIdentitySourceGenerationMutation(
  sourceKey: string,
  action: "dry-run" | "activate" | "pause" | "resume" | "retire",
  expectedGeneration: string,
  reason: string,
  idempotencyKey: string,
): Promise<IdentitySourceMutationResult> {
  const res = await adminFetch(
    `/admin/identity/v2/sources/${encodeURIComponent(sourceKey)}/${action}`,
    {
      method: "POST",
      headers: {
        "Idempotency-Key": idempotencyKey,
        "If-Match": `"${expectedGeneration}"`,
        "X-Audit-Reason": reason,
      },
      body: JSON.stringify({ expectedGeneration, reason, idempotencyKey }),
      onError: identityProblemDetail,
    },
  );
  return (await res.json()) as IdentitySourceMutationResult;
}

export const adminIdentitySourceDryRun = (
  sourceKey: string,
  generation: string,
  reason: string,
  idempotencyKey: string,
) =>
  adminIdentitySourceGenerationMutation(
    sourceKey,
    "dry-run",
    generation,
    reason,
    idempotencyKey,
  );
export const adminIdentitySourceActivate = (
  sourceKey: string,
  generation: string,
  reason: string,
  idempotencyKey: string,
) =>
  adminIdentitySourceGenerationMutation(
    sourceKey,
    "activate",
    generation,
    reason,
    idempotencyKey,
  );
export const adminIdentitySourcePause = (
  sourceKey: string,
  generation: string,
  reason: string,
  idempotencyKey: string,
) =>
  adminIdentitySourceGenerationMutation(
    sourceKey,
    "pause",
    generation,
    reason,
    idempotencyKey,
  );
export const adminIdentitySourceResume = (
  sourceKey: string,
  generation: string,
  reason: string,
  idempotencyKey: string,
) =>
  adminIdentitySourceGenerationMutation(
    sourceKey,
    "resume",
    generation,
    reason,
    idempotencyKey,
  );
export const adminIdentitySourceRetire = (
  sourceKey: string,
  generation: string,
  reason: string,
  idempotencyKey: string,
) =>
  adminIdentitySourceGenerationMutation(
    sourceKey,
    "retire",
    generation,
    reason,
    idempotencyKey,
  );

export async function adminIdentitySourceSecret(
  sourceKey: string,
  name: string,
  secret: string,
  expectedGeneration: string,
  reason: string,
  idempotencyKey: string,
  rotate: boolean,
): Promise<IdentitySourceMutationResult> {
  const suffix = rotate ? "/rotate" : "";
  const res = await adminFetch(
    `/admin/identity/v2/sources/${encodeURIComponent(sourceKey)}/secrets/${encodeURIComponent(name)}${suffix}`,
    {
      method: rotate ? "POST" : "PUT",
      headers: {
        "Content-Type": "application/octet-stream",
        "Idempotency-Key": idempotencyKey,
        "If-Match": `"${expectedGeneration}"`,
        "X-Audit-Reason": reason,
        "X-Identity-Reason": reason,
      },
      body: secret,
      onError: identityProblemDetail,
    },
  );
  return (await res.json()) as IdentitySourceMutationResult;
}

export async function adminIdentityPersonDetail(
  id: string,
): Promise<IdentityPersonDetail> {
  const res = await adminFetch(
    `/admin/identity/v2/people/${encodeURIComponent(id)}`,
    { onError: identityProblemDetail },
  );
  return (await res.json()) as IdentityPersonDetail;
}

export async function adminIdentityConflictDetail(
  id: string,
): Promise<IdentityConflictDetail> {
  const res = await adminFetch(
    `/admin/identity/v2/conflicts/${encodeURIComponent(id)}`,
    { onError: identityProblemDetail },
  );
  return (await res.json()) as IdentityConflictDetail;
}

export async function adminIdentityConflictDecide(
  detail: IdentityConflictDetail,
  decision: "link" | "create" | "reject" | "defer",
  reason: string,
  idempotencyKey: string,
  personId?: string,
): Promise<IdentityConflictDecisionResult> {
  const res = await adminFetch(
    `/admin/identity/v2/conflicts/${encodeURIComponent(detail.id)}/decision`,
    {
      method: "POST",
      headers: {
        "Idempotency-Key": idempotencyKey,
        "If-Match": `"${detail.generation}"`,
        "X-Audit-Reason": reason,
      },
      body: JSON.stringify({
        decision,
        ...(personId ? { personId } : {}),
        expectedGeneration: detail.generation,
        reason,
        idempotencyKey,
      }),
      onError: identityProblemDetail,
    },
  );
  return (await res.json()) as IdentityConflictDecisionResult;
}

export async function adminIdentityUpgradeStatus(): Promise<IdentityUpgradeStatus> {
  const res = await adminFetch("/admin/identity/v2/upgrade/status", {
    onError: identityProblemDetail,
  });
  return (await res.json()) as IdentityUpgradeStatus;
}

// Transactional server updater v1. All bigint identifiers remain decimal
// strings and no client method accepts a binary path, URL, command, unit, or
// diagnostics filesystem path.
export type UpgradeState =
  | "awaiting_approval"
  | "approved"
  | "scheduled"
  | "claimed"
  | "preflight"
  | "recovery_point"
  | "staged"
  | "maintenance"
  | "migrations"
  | "switched"
  | "readiness"
  | "committed"
  | "verified"
  | "cancel_requested"
  | "rolling_back"
  | "rolled_back"
  | "failed"
  | "recovery_required"
  | "cancelled"
  | "expired";

export interface UpgradeReadiness {
  status: "checking" | "ready" | "blocked";
  generation: string;
  checks: Record<string, boolean | string | number>;
  blockerCount: number;
  expiresAt: string;
}

export interface UpgradeRelease {
  releaseId: string;
  version: string;
  channel: "community" | "enterprise";
  manifestDigest: string;
  metadataExpiresAt: string;
  entitlementGraceUntil: string | null;
  status: "available" | "withdrawn";
  readiness: UpgradeReadiness | null;
}

export interface UpgradeRecoverySet {
  recoverySetId: string;
  manifestDigest: string;
  status: "verified" | "invalidated";
  createdAt: string;
  expiresAt: string;
  fresh: boolean;
  restoreProof: null | {
    proofId: string;
    targetId: string;
    provedAt: string;
    staleWarning: boolean;
  };
}

export interface UpgradeIntent {
  intentId: string;
  releaseId: string;
  manifestDigest: string;
  recoverySetId: string | null;
  recoverySetDigest: string | null;
  state: UpgradeState;
  stateGeneration: string;
  reason: string;
  scheduleAt: string | null;
  expiresAt: string;
  result: Record<string, unknown> | null;
  events: Array<{
    generation: string;
    from: UpgradeState | null;
    to: UpgradeState;
    occurredAt: string;
  }>;
}

export interface UpgradeConsoleModel {
  schemaVersion: 1;
  flags: { catalog: boolean; execution: boolean };
  releases: UpgradeRelease[];
  recoverySet: UpgradeRecoverySet | null;
  intent: UpgradeIntent | null;
}

export interface UpgradePreview {
  preview: {
    releaseId: string;
    targetVersion: string;
    channel: "community" | "enterprise";
    manifestDigest: string;
    recoverySetId: string;
    recoverySetDigest: string;
    recoverySetExpiresAt: string;
    approvalRequired: boolean;
  };
  previewDigest: string;
  expiresAt: string;
}

export async function adminUpgradeConsole(): Promise<UpgradeConsoleModel> {
  const response = await adminFetch("/admin/system/upgrades");
  return (await response.json()) as UpgradeConsoleModel;
}

export async function adminUpgradePreview(
  releaseId: string,
  reason: string,
  scheduleAt: string | null,
): Promise<UpgradePreview> {
  const response = await adminFetch("/admin/system/upgrades/preview", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Audit-Reason": reason },
    body: JSON.stringify({ releaseId, reason, scheduleAt }),
  });
  return (await response.json()) as UpgradePreview;
}

export async function adminUpgradeChallenge(
  preview: UpgradePreview,
  reason: string,
  scheduleAt: string | null,
  idempotencyKey: string,
): Promise<{ challengeId: string; expiresAt: string }> {
  const response = await adminFetch("/admin/system/upgrades/challenges", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Audit-Reason": reason,
      "Idempotency-Key": idempotencyKey,
    },
    body: JSON.stringify({
      releaseId: preview.preview.releaseId,
      reason,
      scheduleAt,
      previewDigest: preview.previewDigest,
      idempotencyKey,
    }),
  });
  return await response.json();
}

export async function adminUpgradeCompleteChallenge(
  challengeId: string,
): Promise<{ elevationId: string; expiresAt: string }> {
  const response = await adminFetch(
    "/admin/system/upgrades/challenges/complete",
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ challengeId }),
    },
  );
  return await response.json();
}

export async function adminUpgradeRequest(
  preview: UpgradePreview,
  reason: string,
  scheduleAt: string | null,
  elevationId: string,
  idempotencyKey: string,
): Promise<{ intentId: string; state: UpgradeState }> {
  const response = await adminFetch("/admin/system/upgrades/intents", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Audit-Reason": reason,
      "Idempotency-Key": idempotencyKey,
    },
    body: JSON.stringify({
      releaseId: preview.preview.releaseId,
      reason,
      scheduleAt,
      previewDigest: preview.previewDigest,
      elevationId,
      idempotencyKey,
    }),
  });
  return await response.json();
}

export async function adminUpgradeIntent(id: string): Promise<UpgradeIntent> {
  if (!/^[1-9][0-9]*$/.test(id)) throw new Error("invalid upgrade intent id");
  const response = await adminFetch(`/admin/system/upgrades/intents/${adminPathSegment(id)}`);
  return (await response.json()) as UpgradeIntent;
}

export async function adminUpgradeCancel(
  intent: UpgradeIntent,
  reason: string,
): Promise<{ intentId: string; state: UpgradeState; stateGeneration: string }> {
  const response = await adminFetch(
    `/admin/system/upgrades/intents/${adminPathSegment(intent.intentId)}/cancel`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Audit-Reason": reason },
      body: JSON.stringify({
        expectedGeneration: intent.stateGeneration,
        reason,
      }),
    },
  );
  return (await response.json()) as {
    intentId: string;
    state: UpgradeState;
    stateGeneration: string;
  };
}

function identityTransitionMutationHeaders(
  idempotencyKey: string,
  ifMatch: string,
  reason?: string,
): Record<string, string> {
  const headers: Record<string, string> = {
    "Idempotency-Key": idempotencyKey,
    "If-Match": `"${ifMatch}"`,
  };
  if (reason) headers["X-Audit-Reason"] = reason;
  return headers;
}

export async function adminIdentityTransitionPreview(
  userId: string,
  reason: string,
  idempotencyKey: string,
  targetLinkId?: string,
): Promise<IdentityTransitionPreview> {
  const res = await adminFetch("/admin/identity/v2/transitions/preview", {
    method: "POST",
    headers: {
      "X-Audit-Reason": reason,
      "Idempotency-Key": idempotencyKey,
    },
    body: JSON.stringify({
      userId,
      reason,
      idempotencyKey,
      ...(targetLinkId ? { targetLinkId } : {}),
    }),
    onError: identityProblemDetail,
  });
  return (await res.json()) as IdentityTransitionPreview;
}

export async function adminIdentityTransitionDetail(
  id: string,
): Promise<IdentityTransitionDetail> {
  const res = await adminFetch(
    `/admin/identity/v2/transitions/${encodeURIComponent(id)}`,
    { onError: identityProblemDetail },
  );
  return (await res.json()) as IdentityTransitionDetail;
}

export async function adminIdentityTransitionChallenge(
  preview: Pick<IdentityTransitionPreview, "transitionId" | "previewDigest">,
  idempotencyKey: string,
): Promise<IdentityTransitionChallenge> {
  const res = await adminFetch(
    `/admin/identity/v2/transitions/${encodeURIComponent(preview.transitionId)}/step-up/challenge`,
    {
      method: "POST",
      headers: identityTransitionMutationHeaders(
        idempotencyKey,
        preview.previewDigest,
      ),
      body: JSON.stringify({
        previewDigest: preview.previewDigest,
        idempotencyKey,
      }),
      onError: identityProblemDetail,
    },
  );
  return (await res.json()) as IdentityTransitionChallenge;
}

export async function adminIdentityTransitionChallengeComplete(
  preview: Pick<IdentityTransitionPreview, "transitionId" | "previewDigest">,
  challengeId: string,
  idempotencyKey: string,
): Promise<IdentityTransitionElevation> {
  const res = await adminFetch(
    `/admin/identity/v2/transitions/${encodeURIComponent(preview.transitionId)}/step-up/complete`,
    {
      method: "POST",
      headers: identityTransitionMutationHeaders(
        idempotencyKey,
        preview.previewDigest,
      ),
      body: JSON.stringify({
        challengeId,
        previewDigest: preview.previewDigest,
        idempotencyKey,
      }),
      onError: identityProblemDetail,
    },
  );
  return (await res.json()) as IdentityTransitionElevation;
}

async function adminIdentityTransitionAuthorizedCommand(
  command: "request" | "approve" | "deny" | "execute" | "rollback",
  transitionId: string,
  previewDigest: string,
  elevationId: string,
  reason: string,
  idempotencyKey: string,
  approvalRequestId?: string,
): Promise<IdentityTransitionDetail> {
  const res = await adminFetch(
    `/admin/identity/v2/transitions/${encodeURIComponent(transitionId)}/${command}`,
    {
      method: "POST",
      headers: identityTransitionMutationHeaders(
        idempotencyKey,
        previewDigest,
        reason,
      ),
      body: JSON.stringify({
        previewDigest,
        elevationId,
        reason,
        idempotencyKey,
        ...(approvalRequestId ? { approvalRequestId } : {}),
      }),
      onError: identityProblemDetail,
    },
  );
  return (await res.json()) as IdentityTransitionDetail;
}

export const adminIdentityTransitionRequest = (
  preview: IdentityTransitionPreview,
  elevationId: string,
  reason: string,
  idempotencyKey: string,
) =>
  adminIdentityTransitionAuthorizedCommand(
    "request",
    preview.transitionId,
    preview.previewDigest,
    elevationId,
    reason,
    idempotencyKey,
  );

export const adminIdentityTransitionApprove = (
  detail: IdentityTransitionDetail,
  elevationId: string,
  reason: string,
  idempotencyKey: string,
) =>
  adminIdentityTransitionAuthorizedCommand(
    "approve",
    detail.transitionId,
    detail.previewDigest,
    elevationId,
    reason,
    idempotencyKey,
  );

export const adminIdentityTransitionDeny = (
  detail: IdentityTransitionDetail,
  elevationId: string,
  reason: string,
  idempotencyKey: string,
) =>
  adminIdentityTransitionAuthorizedCommand(
    "deny",
    detail.transitionId,
    detail.previewDigest,
    elevationId,
    reason,
    idempotencyKey,
  );

export const adminIdentityTransitionExecute = (
  detail: IdentityTransitionDetail,
  elevationId: string,
  reason: string,
  idempotencyKey: string,
  approvalRequestId?: string,
) =>
  adminIdentityTransitionAuthorizedCommand(
    "execute",
    detail.transitionId,
    detail.previewDigest,
    elevationId,
    reason,
    idempotencyKey,
    approvalRequestId,
  );

export async function adminIdentityTransitionCancel(
  detail: IdentityTransitionDetail,
  reason: string,
  idempotencyKey: string,
): Promise<IdentityTransitionDetail> {
  const res = await adminFetch(
    `/admin/identity/v2/transitions/${encodeURIComponent(detail.transitionId)}/cancel`,
    {
      method: "POST",
      headers: identityTransitionMutationHeaders(
        idempotencyKey,
        detail.transitionGeneration,
        reason,
      ),
      body: JSON.stringify({
        expectedGeneration: detail.transitionGeneration,
        reason,
        idempotencyKey,
      }),
      onError: identityProblemDetail,
    },
  );
  return (await res.json()) as IdentityTransitionDetail;
}

export async function adminIdentityTransitionRetry(
  detail: IdentityTransitionDetail,
  effectId: string,
  reason: string,
  idempotencyKey: string,
): Promise<IdentityTransitionDetail> {
  const res = await adminFetch(
    `/admin/identity/v2/transitions/${encodeURIComponent(detail.transitionId)}/effects/${encodeURIComponent(effectId)}/retry`,
    {
      method: "POST",
      headers: identityTransitionMutationHeaders(
        idempotencyKey,
        detail.transitionGeneration,
        reason,
      ),
      body: JSON.stringify({
        expectedGeneration: detail.transitionGeneration,
        reason,
        idempotencyKey,
      }),
      onError: identityProblemDetail,
    },
  );
  return (await res.json()) as IdentityTransitionDetail;
}

export async function adminIdentityTransitionRollbackPreview(
  detail: IdentityTransitionDetail,
  reason: string,
  idempotencyKey: string,
): Promise<IdentityTransitionDetail> {
  const res = await adminFetch(
    `/admin/identity/v2/transitions/${encodeURIComponent(detail.transitionId)}/rollback-preview`,
    {
      method: "POST",
      headers: identityTransitionMutationHeaders(
        idempotencyKey,
        detail.transitionGeneration,
        reason,
      ),
      body: JSON.stringify({
        expectedGeneration: detail.transitionGeneration,
        reason,
        idempotencyKey,
      }),
      onError: identityProblemDetail,
    },
  );
  return (await res.json()) as IdentityTransitionDetail;
}

export async function adminIdentityTransitionRollback(
  detail: IdentityTransitionDetail,
  elevationId: string,
  reason: string,
  idempotencyKey: string,
  approvalRequestId: string,
): Promise<IdentityTransitionDetail> {
  const previewDigest = detail.rollback.previewDigest;
  if (!previewDigest) throw new Error("Rollback preview is missing or stale.");
  const res = await adminFetch(
    `/admin/identity/v2/transitions/${encodeURIComponent(detail.transitionId)}/rollback`,
    {
      method: "POST",
      headers: identityTransitionMutationHeaders(
        idempotencyKey,
        previewDigest,
        reason,
      ),
      body: JSON.stringify({
        previewDigest,
        elevationId,
        reason,
        idempotencyKey,
        approvalRequestId,
      }),
      onError: identityProblemDetail,
    },
  );
  return (await res.json()) as IdentityTransitionDetail;
}

export async function adminIdentityTransitionReport(id: string): Promise<Blob> {
  const res = await adminFetch(
    `/admin/identity/v2/transitions/${encodeURIComponent(id)}/report`,
    {
      onError: identityProblemDetail,
    },
  );
  return await res.blob();
}

// ── Email Address Policies ────────────────────────────────────────────

export interface EmailAddressPolicy {
  id: number;
  priority: number;
  name: string;
  enabled: boolean;
  overwriteDirectoryAddress: boolean;
  condDepartment: string[] | null;
  condDomainIds: number[] | null;
  condMailboxType: string[] | null;
  condAdOu: string[] | null;
  primaryTemplate: string;
  additionalTemplates: string[] | null;
  duplicateResolution: string;
  createdAt: string;
  updatedAt: string;
}

export interface EmailAddressPolicyInput {
  priority?: number;
  name: string;
  enabled?: boolean;
  overwriteDirectoryAddress?: boolean;
  condDepartment?: string[] | null;
  condDomainIds?: number[] | null;
  condMailboxType?: string[] | null;
  condAdOu?: string[] | null;
  primaryTemplate: string;
  additionalTemplates?: string[] | null;
  duplicateResolution?: string;
}

export async function adminListEAPolicies(): Promise<EmailAddressPolicy[]> {
  // -list suffix: the SPA page lives at /admin/email-address-policies, so the List
  // API must use a disjoint path or it shadows the SPA on deep-link/refresh.
  const res = await adminFetch("/admin/email-address-policies-list");
  return (await res.json()) as EmailAddressPolicy[];
}

export async function adminCreateEAPolicy(
  data: EmailAddressPolicyInput,
): Promise<EmailAddressPolicy> {
  const res = await adminFetch("/admin/email-address-policies", {
    method: "POST",
    body: JSON.stringify(data),
  });
  return (await res.json()) as EmailAddressPolicy;
}

export async function adminUpdateEAPolicy(
  id: number,
  data: EmailAddressPolicyInput,
): Promise<EmailAddressPolicy> {
  const res = await adminFetch(`/admin/email-address-policies/${id}`, {
    method: "PUT",
    body: JSON.stringify(data),
  });
  return (await res.json()) as EmailAddressPolicy;
}

export async function adminDeleteEAPolicy(id: number): Promise<void> {
  await adminFetch(`/admin/email-address-policies/${id}`, { method: "DELETE" });
}

export async function adminReorderEAPolicies(ids: number[]): Promise<void> {
  await adminFetch("/admin/email-address-policies/reorder", {
    method: "POST",
    body: JSON.stringify({ order: ids }),
  });
}

export async function adminPreviewEAPolicy(
  policyId: number,
  userId: number,
  mailboxId: number,
): Promise<{
  primary: string;
  additionals: string[];
  collided: boolean;
  suffix: string;
}> {
  const res = await adminFetch(
    `/admin/email-address-policies/${policyId}/preview`,
    {
      method: "POST",
      body: JSON.stringify({ policyId, userId, mailboxId }),
    },
  );
  return (await res.json()) as {
    primary: string;
    additionals: string[];
    collided: boolean;
    suffix: string;
  };
}

export async function adminApplyEAPolicy(
  policyId?: number,
): Promise<{ jobId: number }> {
  const res = await adminFetch("/admin/email-address-policies/apply", {
    method: "POST",
    body: JSON.stringify({ policyId: policyId ?? null }),
  });
  return (await res.json()) as { jobId: number };
}

export async function adminApplyStatusEAPolicy(jobId: number): Promise<{
  status: string;
  applied: number;
  total: number | null;
  error: string | null;
}> {
  const res = await adminFetch(`/admin/email-address-policies/apply/${jobId}`);
  return (await res.json()) as {
    status: string;
    applied: number;
    total: number | null;
    error: string | null;
  };
}

export async function adminMatchCountEAPolicy(cond: {
  condDepartment?: string[] | null;
  condDomainIds?: number[] | null;
  condMailboxType?: string[] | null;
  condAdOu?: string[] | null;
}): Promise<{ count: number }> {
  const res = await adminFetch("/admin/email-address-policies/match-count", {
    method: "POST",
    body: JSON.stringify(cond),
  });
  return (await res.json()) as { count: number };
}

// ── MAM (Managed Application Management) ──────────────────────────────

export interface MAMDevice {
  id: number;
  user_id: number;
  platform: string;
  device_name: string;
  os_version: string;
  app_version: string;
  compliance_status: string;
  last_checkin_at: string | null;
  wipe_requested: boolean;
  created_at: string;
}

export interface MAMDeviceListResponse {
  devices: MAMDevice[];
  total: number;
}

export interface MAMPolicyItem {
  id: number;
  policy_key: string;
  policy_value: string;
  updated_at: string;
}

export interface MAMGroupPolicyItem extends MAMPolicyItem {
  group_type: string;
  group_id: number;
}

export interface MAMPolicyListResponse {
  global: MAMPolicyItem[];
  groups: MAMGroupPolicyItem[];
}

export interface MAMDeviceEvent {
  id: number;
  device_id: number;
  event_type: string;
  severity: string;
  details: Record<string, unknown> | null;
  occurred_at: string;
}

export interface MAMDeviceEventsResponse {
  events: MAMDeviceEvent[];
  total: number;
}

export async function adminMAMListDevices(): Promise<MAMDeviceListResponse> {
  const res = await adminFetch("/admin/mam/devices");
  return (await res.json()) as MAMDeviceListResponse;
}

export async function adminMAMLockDevice(
  deviceId: number,
): Promise<{ status: string; device_id: string }> {
  const res = await adminFetch(`/admin/mam/devices/${deviceId}/lock`, {
    method: "POST",
  });
  return (await res.json()) as { status: string; device_id: string };
}

export async function adminMAMUnlockDevice(
  deviceId: number,
): Promise<{ status: string; device_id: string }> {
  const res = await adminFetch(`/admin/mam/devices/${deviceId}/unlock`, {
    method: "POST",
  });
  return (await res.json()) as { status: string; device_id: string };
}

export async function adminMAMGetDeviceEvents(
  deviceId: number,
  limit = 50,
): Promise<MAMDeviceEventsResponse> {
  const res = await adminFetch(
    `/admin/mam/devices/${deviceId}/events?limit=${limit}`,
  );
  return (await res.json()) as MAMDeviceEventsResponse;
}

export async function adminMAMSetPerDevicePolicy(
  deviceId: number,
  policies: Record<string, string>,
): Promise<{ status: string; device_id: string }> {
  const res = await adminFetch(`/admin/mam/devices/${deviceId}/policy`, {
    method: "PUT",
    body: JSON.stringify({ policies }),
  });
  return (await res.json()) as { status: string; device_id: string };
}

export async function adminMAMUnsetPerDevicePolicy(
  deviceId: number,
  key: string,
): Promise<{ status: string }> {
  const res = await adminFetch(
    `/admin/mam/devices/${deviceId}/policy/${encodeURIComponent(key)}`,
    { method: "DELETE" },
  );
  return (await res.json()) as { status: string };
}

export async function adminMAMListPolicies(): Promise<MAMPolicyListResponse> {
  const res = await adminFetch("/admin/mam/policies");
  return (await res.json()) as MAMPolicyListResponse;
}

export async function adminMAMSetGlobalPolicy(
  policies: Record<string, string>,
): Promise<{ status: string }> {
  const res = await adminFetch("/admin/mam/policies", {
    method: "PUT",
    body: JSON.stringify({ policies }),
  });
  return (await res.json()) as { status: string };
}

export async function adminMAMSetGroupPolicy(
  groupType: string,
  groupId: number,
  policies: Record<string, string>,
): Promise<{ status: string }> {
  const res = await adminFetch("/admin/mam/policies/group", {
    method: "PUT",
    body: JSON.stringify({
      group_type: groupType,
      group_id: groupId,
      policies,
    }),
  });
  return (await res.json()) as { status: string };
}

export async function adminMAMUnsetGroupPolicy(
  groupType: string,
  groupId: number,
  key: string,
): Promise<{ status: string }> {
  const res = await adminFetch(
    `/admin/mam/policies/group/${encodeURIComponent(groupType)}/${groupId}/${encodeURIComponent(key)}`,
    { method: "DELETE" },
  );
  return (await res.json()) as { status: string };
}

// ── Threat Flows ────────────────────────────────────────────────────────

export interface ThreatApiResponse {
  rows: Record<string, unknown>[];
  total: number;
  limit: number;
  offset: number;
}

export interface ThreatQueryParams {
  view?: string;
  limit?: number;
  offset?: number;
  since?: string;
  q?: string;
  sort?: string;
  dir?: string;
  risk?: string;
}

/**
 * Fetch threat-flow rows from GET /admin/threat/{view}.
 * Views: attempts, lockouts, feed-blocks, rate-counters.
 * Envelope: {rows, total, limit, offset}.
 */
export async function fetchThreatFlows(
  view: string,
  params: ThreatQueryParams = {},
): Promise<ThreatApiResponse> {
  const sp = new URLSearchParams();
  if (params.limit !== undefined) sp.set("limit", String(params.limit));
  if (params.offset !== undefined) sp.set("offset", String(params.offset));
  if (params.since) sp.set("since", params.since);
  if (params.q) sp.set("q", params.q);
  if (params.sort) sp.set("sort", params.sort);
  if (params.dir) sp.set("dir", params.dir);
  if (params.risk) sp.set("risk", params.risk);
  const qs = sp.toString();
  const res = await adminFetch(
    `/admin/threat/${encodeURIComponent(view)}${qs ? "?" + qs : ""}`,
  );
  return (await res.json()) as ThreatApiResponse;
}

// ── IP Rules ────────────────────────────────────────────────────────────

export interface IPRule {
  id: number;
  cidr: string;
  action: "allow" | "block";
  description: string;
  expiresAt: string | null;
  createdAt: string;
  createdBy: number | null;
}

export interface IPRuleListResponse {
  rows: IPRule[];
  total: number;
  limit: number;
  offset: number;
}

export interface IPRuleCreateRequest {
  cidr: string;
  action: "allow" | "block";
  description: string;
  expiresAt?: string | null;
}

/**
 * List IP rules from GET /admin/threat/ip-rules.
 */
export async function listIPRules(
  limit = 100,
  offset = 0,
): Promise<IPRuleListResponse> {
  const res = await adminFetch(
    `/admin/threat/ip-rules?limit=${limit}&offset=${offset}`,
  );
  return (await res.json()) as IPRuleListResponse;
}

/**
 * Create an IP rule via POST /admin/threat/ip-rules.
 */
export async function createIPRule(data: IPRuleCreateRequest): Promise<IPRule> {
  const res = await adminFetch("/admin/threat/ip-rules", {
    method: "POST",
    body: JSON.stringify(data),
  });
  return (await res.json()) as IPRule;
}

/**
 * Delete an IP rule via DELETE /admin/threat/ip-rules/{id}.
 */
export async function deleteIPRule(id: number): Promise<void> {
  await adminFetch(`/admin/threat/ip-rules/${id}`, { method: "DELETE" });
}

// ── Audit Log ────────────────────────────────────────────────────────────

export interface AuditEntry {
  id: number;
  occurredAt: string;
  userId?: number | null;
  userEmail: string;
  ip: string;
  action: string;
  targetType?: string | null;
  targetId?: number | null;
  beforeState?: unknown;
  afterState?: unknown;
  notes?: string;
}

export interface AuditApiResponse {
  items: AuditEntry[];
  total: number;
}

/**
 * Fetch audit log entries from GET /admin/audit.
 * Query params: q (substring match over notes+action), action, limit, offset.
 */
export async function fetchAuditLog(
  params: {
    q?: string;
    action?: string;
    limit?: number;
    offset?: number;
  } = {},
): Promise<AuditApiResponse> {
  const sp = new URLSearchParams();
  if (params.q) sp.set("q", params.q);
  if (params.action) sp.set("action", params.action);
  if (params.limit !== undefined) sp.set("limit", String(params.limit));
  if (params.offset !== undefined) sp.set("offset", String(params.offset));
  const qs = sp.toString();
  const res = await adminFetch(`/admin/audit${qs ? "?" + qs : ""}`);
  return (await res.json()) as AuditApiResponse;
}

/**
 * Export audit log as CSV. Returns a Blob.
 */
export async function exportAuditCSV(): Promise<Blob> {
  const res = await adminFetch("/admin/audit/csv");
  return await res.blob();
}

export interface VerifyChainRow {
  id: number;
  valid: boolean;
  occurredAt: string;
  action: string;
}

/**
 * Verify the audit chain for a contiguous id-range.
 * Calls GET /admin/audit/verify?from_id=&to_id= → {chain: [{id,valid,occurredAt,action}]}
 */
export async function verifyAuditChain(
  fromId: number,
  toId: number,
): Promise<{ chain: VerifyChainRow[] }> {
  const res = await adminFetch(
    `/admin/audit/verify?from_id=${fromId}&to_id=${toId}`,
  );
  return (await res.json()) as { chain: VerifyChainRow[] };
}

// ── Welcome email (system config; gated on system.config) ──

export interface WelcomeLocaleContent {
  subject: string;
  body_text: string;
  body_html: string;
}

export interface WelcomeEmailConfig {
  enabled: boolean;
  default_locale: string;
  locales: Record<string, WelcomeLocaleContent>;
}

/** GET the org-wide welcome-email config (seeded by V018). */
export async function adminGetWelcomeEmail(): Promise<WelcomeEmailConfig> {
  const res = await adminFetch("/admin/system/welcome-email");
  return (await res.json()) as WelcomeEmailConfig;
}

/** PUT the full welcome-email config (super-admin + system.config). */
export async function adminPutWelcomeEmail(
  cfg: WelcomeEmailConfig,
): Promise<void> {
  await adminFetch("/admin/system/welcome-email", {
    method: "PUT",
    body: JSON.stringify(cfg),
  });
}

/** POST a test-send of the given locale's content to the signed-in admin's mailbox. */
export async function adminTestSendWelcomeEmail(req: {
  locale: string;
  subject: string;
  body_text: string;
  body_html: string;
}): Promise<void> {
  await adminFetch("/admin/system/welcome-email/test", {
    method: "POST",
    body: JSON.stringify(req),
  });
}

// ── Per-user sign-in activity (Task 13 / admin_signin.go) ──

export interface AdminSignInEvent {
  id: number;
  occurred_at: string;
  source_ip: string;
  location: string;
  device_name: string;
  platform: string;
  client: string;
  protocol: string;
  auth_method: string;
  success: boolean;
  fail_reason: string;
}

export interface AdminSession {
  id: string;
  kind: string;
  client_id: string;
  device: string;
  location: string;
  last_used_at: string;
  auth_method: string;
}

/** GET /admin/users/{id}/sign-ins — per-user login_events (200 row cap, newest first). */
export async function adminGetSignIns(
  userId: number,
): Promise<{ status: number; items: AdminSignInEvent[] }> {
  const res = await adminFetch(`/admin/users/${userId}/sign-ins`);
  if (!res.ok) return { status: res.status, items: [] };
  const data = await res.json();
  return {
    status: res.status,
    items: (data.items ?? []) as AdminSignInEvent[],
  };
}

/** GET /admin/users/{id}/sessions — per-user active sessions + oauth families. */
export async function adminGetSessions(
  userId: number,
): Promise<{ status: number; sessions: AdminSession[] }> {
  const res = await adminFetch(`/admin/users/${userId}/sessions`);
  if (!res.ok) return { status: res.status, sessions: [] };
  const data = await res.json();
  return {
    status: res.status,
    sessions: (data.sessions ?? []) as AdminSession[],
  };
}

/** POST /admin/users/{id}/secure-account — force-secure: revoke sessions + force password reset. */
export async function adminSecureAccount(userId: number): Promise<void> {
  const res = await adminFetch(`/admin/users/${userId}/secure-account`, {
    method: "POST",
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(
      (body as { detail?: string }).detail ?? `HTTP ${res.status}`,
    );
  }
}

// ── Offline-mail governance (#2a) ──────────────────────────────────────────
// ponytail: no res.ok checks — adminFetch (via httpRequest) already throws on
// any non-2xx before control returns here.

export type OfflineApprovalState =
  "pending" | "approved" | "denied" | "revoked";

export interface OfflinePolicy {
  id: number;
  name: string;
  scope_type: "global" | "group" | "user";
  scope_id: number | null;
  enabled: boolean;
  max_offline_days: number;
  require_approval: boolean;
  wipe_on_logout: "always" | "admin_default" | "never";
  priority: number;
  updated_at?: string;
}

export interface OfflinePendingDevice {
  id: number;
  user_id: number;
  user_email?: string;
  platform: "desktop" | "ios" | "android";
  device_name: string;
  offline_approval: OfflineApprovalState;
  last_seen_at: string;
  // V041: wipe lifecycle (async push-driven wipe)
  wipe_requested?: boolean;
  wipe_acked_at?: string | null;
}

export interface OfflinePolicyInput {
  name: string;
  scope_type: "global" | "group" | "user";
  scope_id: number | null;
  enabled: boolean;
  max_offline_days: number;
  require_approval: boolean;
  wipe_on_logout: "always" | "admin_default" | "never";
  priority: number;
}

export async function adminOfflinePolicyList(): Promise<OfflinePolicy[]> {
  const res = await adminFetch("/admin/offline/policies");
  return (await res.json()) as OfflinePolicy[];
}

export async function adminOfflinePolicyCreate(
  body: OfflinePolicyInput,
): Promise<{ id: number }> {
  const res = await adminFetch("/admin/offline/policies", {
    method: "POST",
    body: JSON.stringify(body),
  });
  return (await res.json()) as { id: number };
}

export async function adminOfflinePolicyUpdate(
  id: number,
  body: OfflinePolicyInput,
): Promise<{ id: number }> {
  const res = await adminFetch(`/admin/offline/policies/${id}`, {
    method: "PUT",
    body: JSON.stringify(body),
  });
  return (await res.json()) as { id: number };
}

export async function adminOfflinePolicyDelete(id: number): Promise<void> {
  await adminFetch(`/admin/offline/policies/${id}`, { method: "DELETE" });
}

export async function adminOfflineGetEnabled(): Promise<boolean> {
  const res = await adminFetch("/admin/offline/enabled");
  const data = (await res.json()) as { enabled: boolean };
  return data.enabled;
}

export async function adminOfflineSetEnabled(enabled: boolean): Promise<void> {
  await adminFetch("/admin/offline/enabled", {
    method: "PUT",
    body: JSON.stringify({ enabled }),
  });
}

// User-facing: opt this device into offline mail (surfaces it in the admin pending queue).
// ponytail: uses httpRequest (not adminFetch) — this is a user endpoint, not admin.
export async function offlineOptIn(optIn: boolean): Promise<void> {
  await httpRequest("/api/user/offline/opt-in", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ opt_in: optIn }),
    loginRedirect: "/login",
  });
}

export async function adminOfflineListPendingDevices(): Promise<
  OfflinePendingDevice[]
> {
  const res = await adminFetch("/admin/offline/devices/pending");
  return (await res.json()) as OfflinePendingDevice[];
}

async function offlineDeviceAction(
  id: number,
  action: "approve" | "deny" | "revoke" | "wipe",
): Promise<void> {
  await adminFetch(`/admin/offline/devices/${id}/${action}`, {
    method: "POST",
  });
}

export const adminOfflineApproveDevice = (id: number) =>
  offlineDeviceAction(id, "approve");
export const adminOfflineDenyDevice = (id: number) =>
  offlineDeviceAction(id, "deny");
export const adminOfflineRevokeDevice = (id: number) =>
  offlineDeviceAction(id, "revoke");
// WipeDevice: POST /admin/offline/devices/{id}/wipe → 202 Accepted (async wipe push).
export const adminOfflineWipeDevice = (id: number) =>
  offlineDeviceAction(id, "wipe");

// ── Bulk role assignment ──

export interface BulkRoleJob {
  id: number;
  op: "assign" | "revoke";
  role_id: number;
  actor_id: number;
  user_ids: number[];
  expires_at: string | null;
  status: "queued" | "running" | "done" | "error";
  total: number;
  processed: number;
  results: Array<{ user_id: number; status: string; reason?: string }>;
  error: string | null;
  created_at: string;
  updated_at: string;
}

/** POST /admin/roles/{roleId}/members:bulk — enqueue a bulk assign job. */
export async function bulkAssignRole(
  roleId: number,
  userIds: number[],
  expiresAt?: string,
  reason?: string,
  scope?: { scopeType: "ou"; scopeId: number } | null,
): Promise<{ jobId: number }> {
  const headers: Record<string, string> = {};
  if (reason) headers["X-Audit-Reason"] = reason;
  const res = await adminFetch(`/admin/roles/${roleId}/members:bulk`, {
    method: "POST",
    body: JSON.stringify({
      userIds,
      ...(expiresAt ? { expiresAt } : {}),
      ...(scope ? { scopeType: scope.scopeType, scopeId: scope.scopeId } : {}),
    }),
    headers,
  });
  return (await res.json()) as { jobId: number };
}

/** DELETE /admin/roles/{roleId}/members:bulk — enqueue a bulk revoke job. */
export async function bulkRevokeRole(
  roleId: number,
  userIds: number[],
  reason?: string,
): Promise<{ jobId: number }> {
  const headers: Record<string, string> = {};
  if (reason) headers["X-Audit-Reason"] = reason;
  const res = await adminFetch(`/admin/roles/${roleId}/members:bulk`, {
    method: "DELETE",
    body: JSON.stringify({ userIds }),
    headers,
  });
  return (await res.json()) as { jobId: number };
}

/** GET /admin/jobs/bulk_role/{id} — fetch full job row incl. results. */
export async function getBulkRoleJob(id: number): Promise<BulkRoleJob> {
  const res = await adminFetch(`/admin/jobs/bulk_role/${id}`);
  return (await res.json()) as BulkRoleJob;
}

// ── Audit Policy ──

export interface AuditPolicy {
  level: "lean" | "full";
  reasonRequiredAreas: string[];
}

/** GET /admin/audit/policy — fetch the singleton audit policy. */
export async function getAuditPolicy(): Promise<AuditPolicy> {
  const res = await adminFetch("/admin/audit/policy");
  return (await res.json()) as AuditPolicy;
}

/** PUT /admin/audit/policy — update the audit policy (audit.export gated). */
export async function putAuditPolicy(
  payload: AuditPolicy & { reason: string },
): Promise<void> {
  await adminFetch("/admin/audit/policy", {
    method: "PUT",
    body: JSON.stringify(payload),
    headers: { "X-Audit-Reason": payload.reason },
  });
}

// ── Scope sets (RBAC named governed scope containers; scope_sets.manage, Super-only) ──

export interface ScopeSetMember {
  memberType: "ou" | "group" | "user";
  memberId: number;
  label?: string;
}

export interface ScopeSet {
  id: number;
  name: string;
  domainId?: number | null;
  description?: string;
  createdAt?: string;
  updatedAt?: string;
  members?: ScopeSetMember[];
}

/** A directory group as a candidate scope-set member (eligibility computed by the UI). */
export interface DirectoryGroup {
  id: number;
  name: string;
  isDynamic: boolean;
  /** scim_external_id IS NOT NULL — directory/SCIM-synced. */
  scimSynced: boolean;
  usableAsAdminScope: boolean;
  memberCount: number;
}

// scope-set mutations route through httpRequest directly (not adminFetch) so the
// backend problem `detail` flows through on 403/409 — adminFetch pins a generic
// forbiddenMessage that would mask the out-of-reach / in-use reasons. The POST/
// PUT/DELETE routes are wrapped in requireReason(scope_sets.manage): the optional
// `reason` becomes the X-Audit-Reason header when the audit policy lists the
// scope_sets area (no-op by default — reason_required_areas defaults to '{}').
function scopeSetFetch(
  path: string,
  init: RequestInit = {},
  reason?: string,
): Promise<Response> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init.headers as Record<string, string> | undefined),
  };
  if (reason) headers["X-Audit-Reason"] = reason;
  return httpRequest(API_BASE + path, {
    ...init,
    headers,
    cache: "no-store",
    loginRedirect: "/login",
    onError: problemDetail,
  });
}

export async function adminListScopeSets(): Promise<ScopeSet[]> {
  const res = await adminFetch("/admin/scope-sets");
  return (await res.json()) as ScopeSet[];
}

/** GET a single set. The wire shape is {set, members}; this flattens it to ScopeSet. */
export async function adminGetScopeSet(id: number): Promise<ScopeSet> {
  const res = await adminFetch(`/admin/scope-sets/${id}`);
  const data = (await res.json()) as {
    set: ScopeSet;
    members: ScopeSetMember[];
  };
  return { ...data.set, members: data.members ?? [] };
}

export async function adminCreateScopeSet(
  d: { name: string; domainId?: number | null; description?: string },
  reason?: string,
): Promise<{ id: number }> {
  const res = await scopeSetFetch(
    "/admin/scope-sets",
    { method: "POST", body: JSON.stringify(d) },
    reason,
  );
  return (await res.json()) as { id: number };
}

export async function adminUpdateScopeSet(
  id: number,
  p: Partial<Pick<ScopeSet, "name" | "description">>,
  reason?: string,
): Promise<void> {
  await scopeSetFetch(
    `/admin/scope-sets/${id}`,
    { method: "PUT", body: JSON.stringify(p) },
    reason,
  );
}

export async function adminDeleteScopeSet(
  id: number,
  reason?: string,
): Promise<void> {
  await scopeSetFetch(`/admin/scope-sets/${id}`, { method: "DELETE" }, reason);
}

export async function adminAddScopeSetMember(
  id: number,
  m: ScopeSetMember,
  reason?: string,
): Promise<void> {
  await scopeSetFetch(
    `/admin/scope-sets/${id}/members`,
    { method: "POST", body: JSON.stringify(m) },
    reason,
  );
}

export async function adminRemoveScopeSetMember(
  id: number,
  m: ScopeSetMember,
  reason?: string,
): Promise<void> {
  await scopeSetFetch(
    `/admin/scope-sets/${adminPathSegment(id)}/members/${adminPathSegment(m.memberType)}/${adminPathSegment(m.memberId)}`,
    { method: "DELETE" },
    reason,
  );
}

/** GET /admin/distribution-groups — candidate group members for a scope set. */
export async function adminListDirectoryGroups(): Promise<DirectoryGroup[]> {
  const res = await adminFetch("/admin/distribution-groups");
  return (await res.json()) as DirectoryGroup[];
}

// ── JIT activation (P3 — eligible vs active, time-boxed admin roles) ──

export interface ActivationPolicy {
  maxDurationMinutes: number;
  requireJustification: boolean;
}

/** One row of the caller's own roles, from GET /admin/me/roles. */
export interface MyRole {
  roleGroupId: number;
  name: string;
  /** Optional human scope label (whole-org / domain / OU). Absent on the current backend; rendered when present. */
  scope?: string;
  /** false = standing (always-on); true = eligible (JIT-gated). */
  eligible: boolean;
  /** When set + in the future, the role is currently active until this instant. */
  activatedUntil?: string | null;
  /** Grant expiry — caps activation windows; null = never. */
  expiresAt?: string | null;
  policy: ActivationPolicy;
}

export interface ActivateResult {
  activatedUntil: string;
  /** D6 cold-start: the live token predates the eligible grant — refresh before treating the console as active. */
  tokenRefreshRequired?: boolean;
}

/** GET /admin/me/roles — the caller's roles with eligible/active state + policy. */
export async function adminMyRoles(): Promise<MyRole[]> {
  const res = await adminFetch("/admin/me/roles");
  return (await res.json()) as MyRole[];
}

/**
 * POST /admin/me/roles/{id}/activate. On a 400 the thrown Error carries the
 * backend's problem `detail` (BZ104 not-eligible/JIT-off; BZ105 justification
 * required) so the dialog can show the cause inline.
 */
export async function adminActivateRole(
  roleGroupId: number,
  durationMinutes: number,
  justification?: string,
): Promise<ActivateResult> {
  // Direct httpRequest (not adminFetch) so the 400 problem `detail` surfaces via
  // onError instead of a generic status text — the dialog shows the cause inline.
  const res = await httpRequest(`/api/admin/me/roles/${roleGroupId}/activate`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      durationMinutes,
      ...(justification ? { justification } : {}),
    }),
    loginRedirect: "/login",
    onError: problemDetail,
  });
  return (await res.json()) as ActivateResult;
}

/** POST /admin/me/roles/{id}/deactivate — end the caller's active window early. */
export async function adminDeactivateRole(roleGroupId: number): Promise<void> {
  await adminFetch(`/admin/me/roles/${roleGroupId}/deactivate`, {
    method: "POST",
  });
}

/** GET /admin/roles/{id}/activation-policy — per-role override, else resolved org defaults. */
export async function adminGetActivationPolicy(
  roleId: number,
): Promise<ActivationPolicy> {
  const res = await adminFetch(`/admin/roles/${roleId}/activation-policy`);
  return (await res.json()) as ActivationPolicy;
}

/** PUT /admin/roles/{id}/activation-policy — upsert the per-role policy. */
export async function adminPutActivationPolicy(
  roleId: number,
  p: ActivationPolicy,
): Promise<void> {
  await adminFetch(`/admin/roles/${roleId}/activation-policy`, {
    method: "PUT",
    body: JSON.stringify(p),
  });
}

export interface JitDefaults {
  defaultMaxDurationMinutes: number;
  defaultRequireJustification: boolean;
}

/** GET /admin/system/jit-defaults — the org-wide fallback policy. */
export async function adminGetJitDefaults(): Promise<JitDefaults> {
  const res = await adminFetch("/admin/system/jit-defaults");
  return (await res.json()) as JitDefaults;
}

/** PUT /admin/system/jit-defaults — update the org-wide fallback policy. */
export async function adminPutJitDefaults(d: JitDefaults): Promise<void> {
  await adminFetch("/admin/system/jit-defaults", {
    method: "PUT",
    body: JSON.stringify(d),
  });
}

// ── Approval policy admin (Task 13) ───────────────────────────────────────────

export type ApprovalConsumerType =
  | "rbac.jit_activation"
  | "mail.external_send"
  | "mail.group_moderation"
  | "hr.leave"
  | "hr.expense";

export type ApproverKind =
  "manager" | "named" | "role_group" | "default_admin" | "skip";

export interface ApproverFallbackStep {
  kind: "default_admin" | "named" | "skip";
  userId?: number;
}

export interface ApproverSpec {
  kind: ApproverKind;
  userId?: number;
  roleGroupId?: number;
  fallback?: ApproverFallbackStep[];
}

export interface ApprovalPolicy {
  id: number;
  consumerType: ApprovalConsumerType;
  name: string;
  enabled: boolean;
  priority: number;
  conditions: Record<string, unknown>;
  requiresApproval: boolean;
  approverSpec: ApproverSpec;
  createdAt: string;
  updatedAt: string;
}

export interface ApprovalRequestAuditRow {
  id: number;
  consumerType: ApprovalConsumerType;
  requesterUserId?: number; // absent for mail.group_moderation (external sender)
  subject: string;
  status: string;
  approverKind: string;
  approverRef: number;
  decidedByUserId?: number;
  decidedAt?: string;
  decisionComment?: string;
  createdAt: string;
  expiresAt: string;
}

/** GET /admin/approval-policies?consumer_type={ct} */
export async function adminListApprovalPolicies(
  consumerType: ApprovalConsumerType,
): Promise<ApprovalPolicy[]> {
  const res = await adminFetch(
    `/admin/approval-policies?consumer_type=${encodeURIComponent(consumerType)}`,
  );
  return (await res.json()) as ApprovalPolicy[];
}

/** POST /admin/approval-policies */
export async function adminCreateApprovalPolicy(
  p: Omit<ApprovalPolicy, "id" | "createdAt" | "updatedAt">,
): Promise<{ id: number }> {
  const res = await adminFetch("/admin/approval-policies", {
    method: "POST",
    body: JSON.stringify(p),
  });
  return (await res.json()) as { id: number };
}

/** PUT /admin/approval-policies/{id} */
export async function adminUpdateApprovalPolicy(
  id: number,
  p: Partial<Omit<ApprovalPolicy, "id" | "createdAt" | "updatedAt">>,
): Promise<void> {
  await adminFetch(`/admin/approval-policies/${id}`, {
    method: "PUT",
    body: JSON.stringify(p),
  });
}

/** DELETE /admin/approval-policies/{id} */
export async function adminDeleteApprovalPolicy(id: number): Promise<void> {
  await adminFetch(`/admin/approval-policies/${id}`, { method: "DELETE" });
}

/** POST /admin/approval-policies/reorder */
export async function adminReorderApprovalPolicies(
  consumerType: ApprovalConsumerType,
  orderedIds: number[],
): Promise<void> {
  await adminFetch("/admin/approval-policies/reorder", {
    method: "POST",
    body: JSON.stringify({ consumerType, orderedIds }),
  });
}

/** GET /admin/approval-requests/audit */
export async function adminListApprovalAudit(
  limit = 50,
  offset = 0,
): Promise<ApprovalRequestAuditRow[]> {
  const res = await adminFetch(
    `/admin/approval-requests/audit?limit=${limit}&offset=${offset}`,
  );
  return (await res.json()) as ApprovalRequestAuditRow[];
}

// ── Chat compliance admin (Chat A4a Task 11a/11b — retention/hold/classification/audit) ──

export type ChatAppliesTo = "channel" | "dm" | "group_dm" | "all";

export interface ChatRetentionPolicy {
  id: number;
  name: string;
  appliesTo: ChatAppliesTo;
  durationDays: number;
  enabled: boolean;
  effectiveAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface ChatChannelParticipant {
  userId: number;
  displayName: string;
  email: string;
}

export interface ChatChannelRow {
  id: number;
  kind: string;
  name?: string;
  classification: "regular" | "gxp";
  retentionDays?: number;
  wormMode?: string;
  legalHold: boolean;
  legalHoldReason?: string;
  lastPurgedSeq: number;
  effectiveRetentionDays?: number;
  memberCount: number;
  participants: ChatChannelParticipant[];
}

export interface ChatPurgePreviewRow {
  channelId: number;
  purgedCount: number;
  idFrom: number;
  idTo: number;
  retentionDays: number;
}

export interface ChatPurgePreview {
  channels: ChatPurgePreviewRow[];
  totalChannels: number;
  totalMessages: number;
}

export interface ChatComplianceOverviewChannel {
  id: number;
  kind: string;
  name?: string;
  legalHoldReason?: string;
  retentionDays?: number;
  wormMode?: string;
}

export interface ChatLastPurgeRun {
  channels: number;
  messages: number;
  drained: boolean;
  occurredAt: string;
}

export interface ChatComplianceOverview {
  channelsUnderHold: ChatComplianceOverviewChannel[];
  gxpChannels: ChatComplianceOverviewChannel[];
  channelsWithOverrides: ChatComplianceOverviewChannel[];
  lastPurgeRun: ChatLastPurgeRun | null;
  nextRunAt: string;
}

export interface ChatAuditAct {
  id: number;
  occurredAt: string;
  userId?: number;
  ip?: string;
  action: string;
  targetType?: string;
  targetId?: number;
  beforeState?: unknown;
  afterState?: unknown;
  notes?: string;
}

export interface ChatAuditHead {
  id: number;
  checksum: string;
}

export interface ChatAnchorVerdict {
  anchorId: number;
  idFrom: number;
  idTo: number;
  valid: boolean;
  reconciledFromPurge: number;
  revisionsUnchained: number;
}

export interface ChatAuditVerifyResult {
  channelId: number;
  checked: number;
  fromId: number | null;
  toId: number | null;
  chainValid: boolean;
  firstInvalid: number | null;
  verifiedAt: string;
  keyVersion: string;
  truncationDetected: boolean;
  notarizedHead?: ChatAuditHead;
  liveHead?: ChatAuditHead;
  anchors?: ChatAnchorVerdict[];
}

export interface ChatPolicyExposureConflict {
  code: "exposure";
  exposedChannels: number;
}

// ── Chat A4b Task 9 — durable case/custodian holds (chat.compliance_manage) ──

export interface ChatEDiscoveryCase {
  id: number;
  name: string;
  status: "active" | "closed";
}

export interface ChatCaseHold {
  id: number;
  caseId: number;
  custodianUserId?: number;
  channelId?: number;
  reason: string;
  createdBy: number;
  createdAt: string;
  releasedAt?: string;
  releasedBy?: number;
  /** Covered-channel count (snapshot + join growth), not the raw scope. */
  channels: number;
}

/** GET /admin/chat-retention-policies */
export async function adminListChatRetentionPolicies(): Promise<
  ChatRetentionPolicy[]
> {
  const res = await adminFetch("/admin/chat-retention-policies", {
    onError: problemDetail,
  });
  return (await res.json()) as ChatRetentionPolicy[];
}

/** POST /admin/chat-retention-policies */
export async function adminCreateChatRetentionPolicy(p: {
  name: string;
  appliesTo: ChatAppliesTo;
  durationDays: number;
  enabled: boolean;
}): Promise<{ id: number; effectiveAt: string }> {
  const res = await adminFetch("/admin/chat-retention-policies", {
    method: "POST",
    body: JSON.stringify(p),
    onError: problemDetail,
  });
  return (await res.json()) as { id: number; effectiveAt: string };
}

/** PUT /admin/chat-retention-policies/{id} — response carries the (possibly re-armed) effectiveAt (N4). */
export async function adminUpdateChatRetentionPolicy(
  id: number,
  p: {
    name: string;
    appliesTo: ChatAppliesTo;
    durationDays: number;
    enabled: boolean;
  },
): Promise<{ effectiveAt: string }> {
  const res = await adminFetch(`/admin/chat-retention-policies/${id}`, {
    method: "PUT",
    body: JSON.stringify(p),
    onError: problemDetail,
  });
  return (await res.json()) as { effectiveAt: string };
}

/**
 * DELETE /admin/chat-retention-policies/{id}[?confirm=DESTROY] (FIX 3). Returns
 * the exposure conflict body on a 409 (caller opens ConfirmDestructive and
 * retries with confirmDestroy=true); returns null on a successful delete.
 */
export async function adminDeleteChatRetentionPolicy(
  id: number,
  confirmDestroy = false,
): Promise<ChatPolicyExposureConflict | null> {
  const qs = confirmDestroy ? "?confirm=DESTROY" : "";
  const res = await adminFetch(`/admin/chat-retention-policies/${id}${qs}`, {
    method: "DELETE",
    allowStatuses: [409],
    onError: problemDetail,
  });
  if (res.status === 409)
    return (await res.json()) as ChatPolicyExposureConflict;
  return null;
}

/** GET /admin/chat-channels?q=&userId=&limit=&offset= — participant-projecting (verify C3). */
export async function adminListChatChannels(
  params: { q?: string; userId?: number; limit?: number; offset?: number } = {},
): Promise<ChatChannelRow[]> {
  const sp = new URLSearchParams();
  if (params.q) sp.set("q", params.q);
  if (params.userId != null) sp.set("userId", String(params.userId));
  if (params.limit != null) sp.set("limit", String(params.limit));
  if (params.offset != null) sp.set("offset", String(params.offset));
  const qs = sp.toString();
  const res = await adminFetch(`/admin/chat-channels${qs ? "?" + qs : ""}`, {
    onError: problemDetail,
  });
  return (await res.json()) as ChatChannelRow[];
}

/** POST /admin/chat-channels/{id}/hold */
export async function adminSetChatChannelHold(
  id: number,
  on: boolean,
  reason?: string,
): Promise<void> {
  await adminFetch(`/admin/chat-channels/${id}/hold`, {
    method: "POST",
    body: JSON.stringify({ on, reason }),
    onError: problemDetail,
  });
}

/**
 * GET /admin/chat-ediscovery/cases — the Task 5 chat-side case projection
 * (review F3): the mail console's own GET /admin/ediscovery/cases is
 * requireMailPerm-gated and 403s a chat-compliance-only persona. D-H still
 * holds — one case registry (ediscovery_cases), two permission-gated reads.
 */
export async function adminListChatEDiscoveryCases(): Promise<
  ChatEDiscoveryCase[]
> {
  const res = await adminFetch("/admin/chat-ediscovery/cases", {
    onError: problemDetail,
  });
  return (await res.json()) as ChatEDiscoveryCase[];
}

/** GET /admin/chat-ediscovery/holds?caseId= */
export async function adminListChatCaseHolds(
  caseId: number,
): Promise<ChatCaseHold[]> {
  const res = await adminFetch(
    `/admin/chat-ediscovery/holds?caseId=${caseId}`,
    { onError: problemDetail },
  );
  return (await res.json()) as ChatCaseHold[];
}

/**
 * POST /admin/chat-ediscovery/holds — exactly one of custodianUserId/channelId
 * (chat_case_hold_set BZ197 otherwise). Idempotent re-set of an identical
 * active hold returns the existing holdId.
 */
export async function adminSetChatCaseHold(p: {
  caseId: number;
  custodianUserId?: number;
  channelId?: number;
  reason: string;
}): Promise<{ holdId: number }> {
  const res = await adminFetch("/admin/chat-ediscovery/holds", {
    method: "POST",
    body: JSON.stringify(p),
    onError: problemDetail,
  });
  return (await res.json()) as { holdId: number };
}

/** POST /admin/chat-ediscovery/holds/{id}/release — case-scoped by construction. */
export async function adminReleaseChatCaseHold(
  id: number,
  reason: string,
): Promise<void> {
  await adminFetch(`/admin/chat-ediscovery/holds/${id}/release`, {
    method: "POST",
    body: JSON.stringify({ reason }),
    onError: problemDetail,
  });
}

// ── Chat A4b Task 10 — eDiscovery search/reader/export (chat.ediscovery) ──
// Every shape below is the reducer's JSONB verbatim (admin_chat_ediscovery.go
// writes it straight through — zero result-shaping in Go), which is why
// these interfaces exist here rather than being inferred: the wire contract
// IS the reducer's RETURN, not a Go DTO.

export interface ChatEDiscoveryHit {
  messageId: number;
  channelId: number;
  authorId: number;
  createdAt: string;
  deleted: boolean;
  matchedIn: string[];
  excerpt: string;
}

export interface ChatEDiscoveryScheduledHit {
  /** scheduled_actions.id is a uuid, not a bigint (review F4). */
  scheduledActionId: string;
  channelId: number;
  authorId: number;
  status: string;
  fireAt: string;
  excerpt: string;
}

export interface ChatEDiscoverySearchResult {
  searchId: number;
  hits: ChatEDiscoveryHit[];
  scheduledHits: ChatEDiscoveryScheduledHit[];
  resultCount: number;
}

export interface ChatEDiscoveryRevision {
  id: number;
  priorBody: string;
  editedBy: number;
  createdAt: string;
}

export interface ChatEDiscoveryAttachment {
  id: number;
  filename: string;
  contentType?: string;
  sizeBytes?: number;
  fileNodeId: number;
  versionId: number;
  sha256?: string;
}

export interface ChatEDiscoveryPollOption {
  id: number;
  ordinal: number;
  label: string;
}

export interface ChatEDiscoveryPollVote {
  optionId: number;
  userId: number;
  createdAt: string;
}

export interface ChatEDiscoveryPoll {
  question: string;
  multi: boolean;
  closesAt?: string;
  options: ChatEDiscoveryPollOption[];
  votes: ChatEDiscoveryPollVote[];
}

export interface ChatEDiscoveryMessage {
  messageId: number;
  channelId: number;
  authorId: number;
  seq: number;
  createdAt: string;
  editedAt?: string;
  deletedAt?: string;
  msgType: string;
  body: string;
  revisions: ChatEDiscoveryRevision[];
  reactions: ChatEDiscoveryReaction[];
  attachments: ChatEDiscoveryAttachment[];
  poll: ChatEDiscoveryPoll | null;
}

export interface ChatEDiscoveryReaction {
  emoji: string;
  userId: number;
}

export interface ChatEDiscoveryPurgeAct {
  actId: number;
  idFrom: number;
  idTo: number;
  purgedCount: number;
}

export interface ChatEDiscoveryScheduledRow {
  scheduledActionId: string;
  channelId: number;
  authorId: number;
  status: string;
  fireAt: string;
  body: string;
}

export interface ChatEDiscoveryReadResult {
  channelId: number;
  lastPurgedSeq: number;
  purgeActs: ChatEDiscoveryPurgeAct[];
  scheduledRows: ChatEDiscoveryScheduledRow[];
  messages: ChatEDiscoveryMessage[];
}

/**
 * POST /admin/chat-ediscovery/search — named-field request (R2: the server
 * builds the reducer's JSONB query itself; this is not a raw body pass-through).
 */
export async function adminChatEDiscoverySearch(req: {
  caseId: number;
  terms: string;
  channelIds?: number[];
  authorId?: number;
  dateFrom?: string;
  dateTo?: string;
  beforeId?: number;
  limit?: number;
}): Promise<ChatEDiscoverySearchResult> {
  const res = await adminFetch("/admin/chat-ediscovery/search", {
    method: "POST",
    body: JSON.stringify(req),
    onError: problemDetail,
  });
  return (await res.json()) as ChatEDiscoverySearchResult;
}

/** GET /admin/chat-ediscovery/channels/{id}/messages?caseId=&beforeId=&limit= */
export async function adminChatEDiscoveryMessages(
  channelId: number,
  caseId: number,
  opts: { beforeId?: number; limit?: number } = {},
): Promise<ChatEDiscoveryReadResult> {
  const sp = new URLSearchParams();
  sp.set("caseId", String(caseId));
  if (opts.beforeId != null) sp.set("beforeId", String(opts.beforeId));
  if (opts.limit != null) sp.set("limit", String(opts.limit));
  const res = await adminFetch(
    `/admin/chat-ediscovery/channels/${channelId}/messages?${sp.toString()}`,
    {
      onError: problemDetail,
    },
  );
  return (await res.json()) as ChatEDiscoveryReadResult;
}

/**
 * GET /admin/chat-ediscovery/export?caseId=&channels=&includeAttachments= — a
 * plain same-origin cookie-authed download URL (the chatChannelAuditCsvUrl
 * precedent), not a fetch call: export destroys nothing (spec §8), so a
 * plain `<a download>` is enough — no ConfirmDestructive.
 */
export function adminChatEDiscoveryExportUrl(
  caseId: number,
  channelIds: number[],
  includeAttachments: boolean,
): string {
  const sp = new URLSearchParams();
  sp.set("caseId", String(caseId));
  sp.set("channels", channelIds.join(","));
  if (includeAttachments) sp.set("includeAttachments", "1");
  return `/api/admin/chat-ediscovery/export?${sp.toString()}`;
}

/** POST /admin/chat-channels/{id}/classification — the only reducer-valid transition is to 'gxp'. */
export async function adminSetChatChannelClassification(
  id: number,
  retentionDays: number,
  wormMode: "governance" | "compliance",
): Promise<void> {
  await adminFetch(`/admin/chat-channels/${id}/classification`, {
    method: "POST",
    body: JSON.stringify({ classification: "gxp", retentionDays, wormMode }),
    onError: problemDetail,
  });
}

/** PUT /admin/chat-channels/{id}/retention — immediate-by-design (no org grace), null clears. */
export async function adminSetChatChannelRetention(
  id: number,
  retentionDays: number | null,
): Promise<void> {
  await adminFetch(`/admin/chat-channels/${id}/retention`, {
    method: "PUT",
    body: JSON.stringify({ retentionDays }),
    onError: problemDetail,
  });
}

/** GET /admin/chat-purge/preview — dry-runs the sweep; N is the total backlog, not one night's work. */
export async function adminPreviewChatPurge(): Promise<ChatPurgePreview> {
  const res = await adminFetch("/admin/chat-purge/preview", {
    onError: problemDetail,
  });
  return (await res.json()) as ChatPurgePreview;
}

/** GET /admin/chat-compliance/overview */
export async function adminGetChatComplianceOverview(): Promise<ChatComplianceOverview> {
  const res = await adminFetch("/admin/chat-compliance/overview", {
    onError: problemDetail,
  });
  return (await res.json()) as ChatComplianceOverview;
}

/** GET /admin/chat-channels/{id}/audit?limit=&beforeId= (newest first, keyset). */
export async function adminGetChatChannelAudit(
  id: number,
  opts: { limit?: number; beforeId?: number } = {},
): Promise<ChatAuditAct[]> {
  const sp = new URLSearchParams();
  if (opts.limit != null) sp.set("limit", String(opts.limit));
  if (opts.beforeId != null) sp.set("beforeId", String(opts.beforeId));
  const qs = sp.toString();
  const res = await adminFetch(
    `/admin/chat-channels/${id}/audit${qs ? "?" + qs : ""}`,
    {
      onError: problemDetail,
    },
  );
  return (await res.json()) as ChatAuditAct[];
}

/** GET /admin/chat-channels/{id}/audit/verify — the ordered notary/chain/anchor check (FIX 1). */
export async function adminVerifyChatChannelAudit(
  id: number,
): Promise<ChatAuditVerifyResult> {
  const res = await adminFetch(`/admin/chat-channels/${id}/audit/verify`, {
    onError: problemDetail,
  });
  return (await res.json()) as ChatAuditVerifyResult;
}

/** The downloadable evidence CSV — a plain same-origin GET (cookie auth), opened in a new tab. */
export function chatChannelAuditCsvUrl(id: number): string {
  return `/api/admin/chat-channels/${id}/audit?format=csv`;
}

// ── Sharing console (spec 2026-06-27-sharing-delegation-design.md §7) ──
// Defaults CRUD (sharing.manage), per-user oversight + audit (sharing.read).
// POST/DELETE on defaults sit behind requireReason(sharing.manage) — the
// optional reason threads through as X-Audit-Reason (same pattern as roles).

export interface SharingDefaultAdminRow {
  id: number;
  resource: string;
  ownerScope: "org" | "ou" | "group" | "user";
  ownerRef: number;
  ownerLabel: string;
  audience: "everyone" | "ou" | "group";
  audienceRef: number;
  audienceLabel: string;
  level: "none" | "freebusy" | "read";
  createdBy: number;
  updatedAt: string;
}

export interface SharingUserOversight {
  userId: number;
  email: string;
  displayName: string;
  delegates: {
    userId: number;
    email: string;
    name: string;
    permission: string;
    grantedAt: string;
  }[];
  calendarGrants: {
    calendarId: number;
    calendarName: string;
    userEmail: string;
    userName: string;
    level: string;
  }[];
  defaults: SharingDefaultAdminRow[];
}

export interface SharingAuditRow {
  id: number;
  occurredAt: string;
  userId?: number;
  userEmail: string;
  action: string;
  targetType?: string;
  targetId?: number;
  beforeState?: unknown;
  afterState?: unknown;
}

/** GET /admin/sharing/defaults */
export async function adminListSharingDefaults(): Promise<
  SharingDefaultAdminRow[]
> {
  const res = await adminFetch("/admin/sharing/defaults");
  return ((await res.json()) ?? []) as SharingDefaultAdminRow[];
}

/** POST /admin/sharing/defaults — upsert on (resource, scope, ref, audience, ref). */
export async function adminCreateSharingDefault(
  p: {
    ownerScope: SharingDefaultAdminRow["ownerScope"];
    ownerRef: number;
    audience: SharingDefaultAdminRow["audience"];
    audienceRef: number;
    level: SharingDefaultAdminRow["level"];
  },
  reason?: string,
): Promise<{ id: number }> {
  const res = await adminFetch("/admin/sharing/defaults", {
    method: "POST",
    headers: reason ? { "X-Audit-Reason": reason } : undefined,
    body: JSON.stringify(p),
    onError: problemDetail,
  });
  return (await res.json()) as { id: number };
}

/** DELETE /admin/sharing/defaults/{id} */
export async function adminDeleteSharingDefault(
  id: number,
  reason?: string,
): Promise<void> {
  await adminFetch(`/admin/sharing/defaults/${id}`, {
    method: "DELETE",
    headers: reason ? { "X-Audit-Reason": reason } : undefined,
    onError: problemDetail,
  });
}

/** GET /admin/sharing/users/{id} — per-user oversight panel. */
export async function adminSharingUserOversight(
  userId: number,
): Promise<SharingUserOversight> {
  const res = await adminFetch(`/admin/sharing/users/${userId}`, {
    onError: problemDetail,
  });
  return (await res.json()) as SharingUserOversight;
}

/** GET /admin/sharing/audit?user_id=&limit=&offset= */
export async function adminListSharingAudit(
  limit = 50,
  offset = 0,
  userId?: number,
): Promise<SharingAuditRow[]> {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
  });
  if (userId) params.set("user_id", String(userId));
  const res = await adminFetch("/admin/sharing/audit?" + params.toString());
  return ((await res.json()) ?? []) as SharingAuditRow[];
}

// ── Meet recordings admin (Meet B2 Task 8's admin_meet_recordings.go, whole-pipeline review UX #11) ──
// GET /admin/meet/recordings?state=&meetingId= — drive.view-gated (no new
// permission minted; recordings are Drive-governed content). Deliberately NO
// feature.meet_recording toggle gate — D10: the registry row exists from
// 'requested' onward regardless of the toggle, this is a findability surface.

/** meetRecordingResponse wire shape (admin_meet_recordings.go). */
export interface AdminMeetRecordingRow {
  id: number;
  meetingId: number;
  meetingTitle: string;
  state:
    "requested" | "active" | "stopping" | "pending_ingest" | "ready" | "failed";
  startedBy: number;
  startedAt: string;
  stoppedAt?: string;
  durationMs?: number;
  sizeBytes?: number;
  fileNodeId?: number;
  versionId?: number;
  error?: string;
}

/** GET /admin/meet/recordings?state=&meetingId= */
export async function adminListMeetRecordings(
  params: { state?: string; meetingId?: number } = {},
): Promise<AdminMeetRecordingRow[]> {
  const sp = new URLSearchParams();
  if (params.state) sp.set("state", params.state);
  if (params.meetingId != null) sp.set("meetingId", String(params.meetingId));
  const qs = sp.toString();
  const res = await adminFetch(`/admin/meet/recordings${qs ? "?" + qs : ""}`, {
    onError: problemDetail,
  });
  return ((await res.json()) ?? []) as AdminMeetRecordingRow[];
}

// ── Federation admin console (Pillar C1 Task 8's admin_federation.go) ──
// GET/POST/DELETE /admin/federation/peers[/{domain}] — federation.manage-gated.
// NOT toggle-gated: the console must be usable to prep an allow-list before
// feature.federation ever flips ON.

/** federationPeerResponse wire shape (admin_federation.go). The anchor PEM is
 * NEVER echoed back — an admin re-pastes it to change it, never round-trips it. */
export interface FederationPeer {
  peerDomain: string;
  scope: "dm" | "room";
  enabled: boolean;
  createdAt: string;
  updatedAt: string;
  unackedDepth?: number;
  lastAckAgeSeconds?: number;
}

/** GET /admin/federation/peers */
export async function adminListFederationPeers(): Promise<FederationPeer[]> {
  const res = await adminFetch("/admin/federation/peers", {
    onError: problemDetail,
  });
  return ((await res.json()) ?? []) as FederationPeer[];
}

/** POST /admin/federation/peers — add or update (upsert on domain). */
export async function adminUpsertFederationPeer(p: {
  domain: string;
  anchorPem: string;
  scope: "dm" | "room";
  enabled: boolean;
}): Promise<void> {
  await adminFetch("/admin/federation/peers", {
    method: "POST",
    body: JSON.stringify(p),
    onError: problemDetail,
  });
}

/** DELETE /admin/federation/peers/{domain} — requires the peer already disabled. */
export async function adminDeleteFederationPeer(domain: string): Promise<void> {
  await adminFetch(`/admin/federation/peers/${encodeURIComponent(domain)}`, {
    method: "DELETE",
    onError: problemDetail,
  });
}

// ── Exchange replacement assessment (V1A, default OFF) ──

export interface ExchangeLocalizedText {
  zh: string;
  en: string;
}
export interface ExchangeCapability {
  id: string;
  category: string;
  outcome: ExchangeLocalizedText;
  mappingMaximum: "native" | "transformed" | "alternative" | "none";
  claimMaximum: string;
  phaseImpacts: Array<{ phase: string; impact: string; reason: string }>;
}
export interface ExchangeRegistryProjection {
  schemaVersion: string;
  registryVersion: number;
  catalogVersion: number;
  sourceDigest: string;
  capabilities: ExchangeCapability[];
  supportCells: Array<{
    id: string;
    productFamily: string;
    topology: string;
    admission: string;
    digest: string;
    collectorVersion: string;
  }>;
}
export interface ExchangeAssessmentProject {
  id: number;
  domainId: number;
  name: string;
  state: string;
  retentionUntil: string | null;
  createdAt: string;
  updatedAt: string;
}
export interface ExchangeAssessmentRun {
  id: number;
  projectId: number;
  generation: number;
  state: string;
  supportCellId: string;
  supportCellDigest: string;
  registryVersion: number;
  registryDigest: string;
  catalogVersion: number;
  collectorVersion: string;
  errorCode: string | null;
  createdAt: string;
  updatedAt: string;
  completedAt: string | null;
}

export async function adminExchangeRegistry(): Promise<ExchangeRegistryProjection> {
  const res = await adminFetch("/admin/exchange-replacement/registry", {
    onError: problemDetail,
  });
  return (await res.json()) as ExchangeRegistryProjection;
}

export async function adminExchangeProjects(): Promise<
  ExchangeAssessmentProject[]
> {
  const res = await adminFetch("/admin/exchange-replacement/projects", {
    onError: problemDetail,
  });
  return (await res.json()) as ExchangeAssessmentProject[];
}

export async function adminCreateExchangeProject(input: {
  domainId: number;
  name: string;
  retentionUntil?: string;
}): Promise<ExchangeAssessmentProject> {
  const res = await adminFetch("/admin/exchange-replacement/projects", {
    method: "POST",
    headers: {
      "X-Audit-Reason": "Create Exchange replacement assessment project",
      "Idempotency-Key": crypto.randomUUID(),
    },
    body: JSON.stringify(input),
    onError: problemDetail,
  });
  return (await res.json()) as ExchangeAssessmentProject;
}

export async function adminExchangeRuns(
  projectId: number,
): Promise<ExchangeAssessmentRun[]> {
  const res = await adminFetch(
    `/admin/exchange-replacement/projects/${projectId}/runs`,
    { onError: problemDetail },
  );
  return (await res.json()) as ExchangeAssessmentRun[];
}

export async function adminCreateExchangeRun(
  projectId: number,
  input: {
    supportCellId: string;
    supportCellDigest: string;
    registryVersion: number;
    registryDigest: string;
    catalogVersion: number;
    collectorVersion: string;
  },
): Promise<ExchangeAssessmentRun> {
  const res = await adminFetch(
    `/admin/exchange-replacement/projects/${projectId}/runs`,
    {
      method: "POST",
      headers: {
        "X-Audit-Reason": "Create Exchange replacement assessment run",
        "Idempotency-Key": crypto.randomUUID(),
      },
      body: JSON.stringify(input),
      onError: problemDetail,
    },
  );
  return (await res.json()) as ExchangeAssessmentRun;
}
export async function adminExchangeTransitionRun(
  runId: number,
  expectedGeneration: number,
  state: string,
  errorCode?: string,
): Promise<ExchangeAssessmentRun> {
  const res = await adminFetch(
    `/admin/exchange-replacement/runs/${runId}/transition`,
    {
      method: "POST",
      headers: {
        "X-Audit-Reason": `Transition Exchange assessment run to ${state}`,
      },
      body: JSON.stringify({ expectedGeneration, state, errorCode }),
      onError: problemDetail,
    },
  );
  return (await res.json()) as ExchangeAssessmentRun;
}
export async function adminExchangeDecision(
  runId: number,
  input: {
    expectedGeneration: number;
    capabilityId: string;
    outcomeMapping: string;
    decision: string;
    reason: string;
    waiverExpiresAt?: string;
  },
): Promise<Record<string, unknown>> {
  // HTTP header values are byte strings in browsers; the operator's reason can
  // contain CJK and belongs in the reducer-validated JSON body. Keep the routing
  // audit header stable ASCII so valid localized input cannot fail before fetch.
  const res = await adminFetch(
    `/admin/exchange-replacement/runs/${runId}/decisions`,
    {
      method: "POST",
      headers: { "X-Audit-Reason": "Record Exchange assessment decision" },
      body: JSON.stringify(input),
      onError: problemDetail,
    },
  );
  return await res.json();
}
export async function adminExchangeAttest(
  runId: number,
  input: {
    kind: string;
    subjectDigest: string;
    statement: Record<string, unknown>;
  },
): Promise<Record<string, unknown>> {
  const res = await adminFetch(
    `/admin/exchange-replacement/runs/${runId}/attestations`,
    {
      method: "POST",
      headers: { "X-Audit-Reason": `Create ${input.kind} attestation` },
      body: JSON.stringify(input),
      onError: problemDetail,
    },
  );
  return await res.json();
}
export async function adminExchangeResolveClaims(
  runId: number,
  expectedGeneration: number,
): Promise<Record<string, unknown>> {
  const res = await adminFetch(
    `/admin/exchange-replacement/runs/${runId}/claims/resolve`,
    {
      method: "POST",
      headers: {
        "X-Audit-Reason": "Resolve Exchange assessment claim snapshot",
      },
      body: JSON.stringify({ expectedGeneration }),
      onError: problemDetail,
    },
  );
  return await res.json();
}
export async function adminExchangeAudit(
  runId: number,
): Promise<{
  claims: Record<string, unknown>[];
  attestations: Record<string, unknown>[];
  evidence: Record<string, unknown>[];
  publications: Record<string, unknown>[];
}> {
  const res = await adminFetch(
    `/admin/exchange-replacement/runs/${runId}/audit`,
    { onError: problemDetail },
  );
  return await res.json();
}
export async function adminExchangePublish(
  runId: number,
  projectionDigest: string,
): Promise<Record<string, unknown>> {
  const res = await adminFetch(
    `/admin/exchange-replacement/runs/${runId}/publications`,
    {
      method: "POST",
      headers: {
        "X-Audit-Reason": "Publish evidence-derived Exchange comparison",
      },
      body: JSON.stringify({ projectionDigest }),
      onError: problemDetail,
    },
  );
  return await res.json();
}
export async function adminExchangeDelete(
  projectId: number,
  input: {
    scope: "artifact" | "run" | "project";
    runId?: number;
    artifactId?: number;
    reason: string;
  },
): Promise<Record<string, unknown>> {
  const res = await adminFetch(
    `/admin/exchange-replacement/projects/${projectId}/deletions`,
    {
      method: "POST",
      headers: { "X-Audit-Reason": "Request Exchange assessment deletion" },
      body: JSON.stringify(input),
      onError: problemDetail,
    },
  );
  return await res.json();
}
