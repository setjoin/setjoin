// JMAP HTTP client (RFC 8620)
import { httpRequest, typedFetch } from "$lib/http";
import { attachDeviceProofHeaders } from "$lib/native/deviceProof";
import { hasCapability } from "$lib/native";
import { deviceBlock } from "$lib/stores/deviceBlock";
import type {
  JmapSession,
  JmapMethodCall,
  JmapResponse,
  JmapMethodResponse,
  Mailbox,
  Email,
  EmailBundle,
  EmailNudge,
  EmailSubmission,
  Calendar,
  CalendarEvent,
  AddressBook,
  ContactCard,
  ContactGroup,
  ContactGroupMember,
  ExpandedRecipient,
  Task,
  TaskActivity,
  TaskList,
  AssignedTask,
  Identity,
} from "$lib/types/jmap";

const API_URL = "/jmap";

/**
 * Throw if the gateway returned a method-level error envelope (name "error",
 * carrying `type`/`description` per mapReducerErr). Mirrors quicksteps.assertOk
 * and stores/directory's name-check so mutation helpers surface reducer failures
 * (RLS/quota/invalid-state) instead of casting the error body to a success shape.
 * Checks ONLY the method-level envelope — per-record notCreated is left for the
 * caller (compose reads notCreated.addresses).
 */
/**
 * Method-level JMAP error envelope (b1r2-011 r3). The thrown Error carries the
 * STRUCTURED `type` (and optional `description`) from the gateway's error
 * response instead of flattening them into one prose string. The message text
 * is unchanged (`description || type`), so every catch block reading `.message`
 * keeps working byte-for-byte; consumers that need the closed-vocabulary type
 * (offline replay classification) read `.jmapType` directly.
 */
export class JmapMethodError extends Error {
  /** Structured JMAP error type, e.g. 'notFound' | 'forbidden' | 'serverFail'. */
  readonly jmapType: string;
  /** Server description, when the envelope supplied one. */
  readonly jmapDescription: string | undefined;
  constructor(type: string, description?: string) {
    super(description || type);
    this.name = "JmapMethodError";
    this.jmapType = type;
    this.jmapDescription = description;
  }
}

/**
 * Typed guard for a method-level JMAP error, optionally of one exact
 * closed-vocabulary `type` (e.g. `isJmapMethodError(e, 'cannotCalculateChanges')`).
 * Use this instead of casting an unknown catch value to read `.jmapType`.
 */
export function isJmapMethodError(err: unknown, type?: string): err is JmapMethodError {
  return err instanceof JmapMethodError && (type === undefined || err.jmapType === type);
}

function assertOk(resp: JmapMethodResponse): JmapMethodResponse {
  if (resp && typeof resp.type === "string") {
    throw new JmapMethodError(resp.type, resp.description);
  }
  return resp;
}

let session: JmapSession | null = null;
let accountId: string | null = null;
let accountIdCacheTime = 0;
let authGeneration = 0;
const ACCOUNT_ID_TTL_MS = 60_000; // 1 minute

class JmapAuthGenerationError extends Error {
  constructor() {
    super("JMAP auth context changed during session discovery");
    this.name = "JmapAuthGenerationError";
  }
}

/**
 * Clear every user-scoped JMAP discovery value synchronously. Auth teardown
 * calls this before another identity can start discovery; the generation also
 * fences completions which were already in flight for the prior identity.
 */
export function resetJmapAuthContext(): void {
  authGeneration++;
  session = null;
  accountId = null;
  accountIdCacheTime = 0;
}

// ── Capability table (c4) ─────────────────────────────────────────────────
// One table, keyed by method-type prefix, mirroring the gateway's method
// registry (mailserver/internal/jmap/handler.go registerMethods). The vitest
// in client.test.ts reads the server's golden artifact
// (internal/jmap/testdata/methods.golden) and pins every method row against
// this table, so the two sides cannot drift silently.
const CORE = "urn:ietf:params:jmap:core";
const MAIL = "urn:ietf:params:jmap:mail";
const SUBMISSION = "urn:ietf:params:jmap:submission";
const VENDOR = "urn:setjoin:params:jmap:mail";

const CAP_BY_PREFIX: Record<string, string> = {
  Core: CORE,
  Mailbox: MAIL,
  Email: MAIL,
  Thread: MAIL,
  SearchSnippet: MAIL,
  MailWork: MAIL,
  MailWorkCollaborators: MAIL,
  MailWorkMetrics: MAIL,
  MailWorkNotificationPreferences: MAIL,
  MailWorkPolicy: MAIL,
  MailComment: MAIL,
  MailDraft: MAIL,
  Continuity: MAIL,
  // Identity/* is a submission-capability type (RFC 8621 §6).
  EmailSubmission: SUBMISSION,
  Identity: SUBMISSION,
  Calendar: "urn:ietf:params:jmap:calendars",
  CalendarEvent: "urn:ietf:params:jmap:calendars",
  AddressBook: "urn:ietf:params:jmap:contacts",
  ContactCard: "urn:ietf:params:jmap:contacts",
  ContactGroup: "urn:ietf:params:jmap:contacts",
  Task: "urn:ietf:params:jmap:tasks",
  // TaskComment/* — QoL #17 activity-feed extension over the tasks capability.
  TaskComment: "urn:ietf:params:jmap:tasks",
  // TaskList/* + TaskAssigned/* — shared/team task lists (Phase 1, V112).
  TaskList: "urn:ietf:params:jmap:tasks",
  TaskListMember: "urn:ietf:params:jmap:tasks",
  TaskAssigned: "urn:ietf:params:jmap:tasks",
  Reminder: "urn:setjoin:params:jmap:reminders",
  Blob: "urn:ietf:params:jmap:blob",
  // setjoin vendor surfaces (Quick Steps, saved searches, compose templates).
  QuickStep: VENDOR,
  SavedSearch: VENDOR,
  EmailTemplate: VENDOR,
};

/**
 * Derive the `using` array for a batch of method calls: core plus each
 * method's required capability, in table order. EmailSubmission/* also keeps
 * mail declared for its onSuccessUpdateEmail references.
 */
export function usingFor(methods: string[]): string[] {
  const caps = new Set([CORE]);
  for (const m of methods) {
    const cap = CAP_BY_PREFIX[m.split("/")[0]];
    if (cap) caps.add(cap);
    if (cap === SUBMISSION) caps.add(MAIL);
  }
  return [...caps];
}

export async function jmapCall(
  methodCalls: JmapMethodCall[],
  capabilities?: string[],
  signal?: AbortSignal,
): Promise<JmapResponse> {
  const using = capabilities || usingFor(methodCalls.map((c) => c[0]));
  const headers = new Headers({ "Content-Type": "application/json" });
  // ponytail: guard before await to skip the microtask when capability is absent —
  // an unconditional `await asyncFn()` yields even on early return, which races
  // with test-controlled mock-fetch resolvers.
  if (hasCapability("deviceProof")) {
    await attachDeviceProofHeaders(headers);
  }
  const res = await httpRequest(API_URL, {
    method: "POST",
    signal,
    loginRedirect: "/",
    headers,
    body: JSON.stringify({ using, methodCalls }),
    // ponytail: detect BZ095 (device lockdown) before surfacing a generic 403 —
    // set the deviceBlock store so +layout.svelte navigates to /blocked, keeping
    // the user in the SPA rather than showing a broken inbox.
    onError: async (r) => {
      if (r.status === 403) {
        try {
          const body = await r.clone().json();
          if (body?.code === "BZ095") {
            const ref = r.headers.get("X-CA-Correlation-Id") ?? undefined;
            deviceBlock.set({ blocked: true, ref });
            throw new Error("device_blocked");
          }
        } catch (e) {
          if ((e as Error).message === "device_blocked") throw e;
          // JSON parse failed — fall through to generic error
        }
      }
      return "JMAP error: " + r.status;
    },
  });
  return parseJmapResponse(await res.json());
}

/**
 * Boundary validation for the one response seam every read helper flows
 * through (replaces the historical blind `as JmapResponse`): the body must be
 * an object carrying a methodResponses array of [name, args, callId] triples.
 * A structurally invalid body — a gateway regression, a proxy error page —
 * fails closed here instead of surfacing as `undefined` field access or a
 * positional [0] hit on garbage downstream.
 */
function parseJmapResponse(body: unknown): JmapResponse {
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    throw new Error("JMAP error: malformed response");
  }
  const responses = (body as Record<string, unknown>).methodResponses;
  if (
    !Array.isArray(responses) ||
    !responses.every(
      (m) =>
        Array.isArray(m) &&
        m.length === 3 &&
        typeof m[0] === "string" &&
        typeof m[1] === "object" &&
        m[1] !== null &&
        typeof m[2] === "string",
    )
  ) {
    throw new Error("JMAP error: malformed response");
  }
  return body as JmapResponse;
}

export async function loadSession(): Promise<JmapSession> {
  const generation = authGeneration;
  let loaded: JmapSession;
  try {
    const res = await httpRequest("/.well-known/jmap", {
      loginRedirect: null,
      unauthorizedMessage: "Session load failed",
      onError: () => "Session load failed",
    });
    loaded = (await res.json()) as JmapSession;
  } catch (e) {
    if (generation !== authGeneration) {
      throw new JmapAuthGenerationError();
    }
    // A REFRESH failure must not fail an action that only needs the
    // already-loaded session — e.g. the service worker's first-install
    // clients.claim() aborts in-flight fetches (net::ERR_ABORTED), which
    // made the mutation racing it fail with a spurious "Network error".
    if (session) return session;
    throw e;
  }
  if (generation !== authGeneration) {
    throw new JmapAuthGenerationError();
  }
  session = loaded;
  // BUG FIX (found building #13): `Object.keys(session.accounts)[0]` looked
  // like "the caller's own account" back when accounts had exactly one entry,
  // but JS objects iterate integer-like string keys in ASCENDING NUMERIC order
  // regardless of insertion order — so once #13 added delegated mailboxes as
  // additional accounts, a delegated mailbox with a SMALLER id than the
  // caller's own primary mailbox silently became "accountId" everywhere
  // (every JMAP call would act on the wrong account). primaryAccounts.mail is
  // the one field the server always sets to the caller's OWN primary (see
  // handler.go Session(): "delegated accounts are additional, never primary").
  accountId =
    session.primaryAccounts?.["urn:ietf:params:jmap:mail"] ??
    Object.keys(session.accounts)[0];
  accountIdCacheTime = Date.now();
  return session;
}

export async function getAccountId(): Promise<string | null> {
  if (
    accountId !== null &&
    Date.now() - accountIdCacheTime < ACCOUNT_ID_TTL_MS
  ) {
    return accountId;
  }
  const generation = authGeneration;
  try {
    await loadSession();
  } catch (error) {
    // Same-generation refresh failures retain the established stale-cache
    // fallback. A prior user's in-flight discovery must never borrow the next
    // user's cache after teardown, so generation errors are non-swallowable.
    if (
      error instanceof JmapAuthGenerationError ||
      generation !== authGeneration
    ) {
      throw error;
    }
  }
  return accountId;
}

// ── #13 shared-mailbox use-surface: delegated-account enumeration ──────────
// The JMAP session already carries every MAIL-delegated mailbox as an
// additional account (handler.go Session()) — this is the ONE identity
// enumeration the sidebar's SHARED MAILBOXES section and the compose From
// Select consume, no second roundtrip.

export interface DelegatedAccount {
  id: string;
  name: string;
  isReadOnly: boolean;
  /** Raw mailbox_delegates.permission values (read|send_as|send_on_behalf|full_access). */
  grants: string[];
  /** Aliases on this mailbox, exposed only for send_as/full_access delegates. */
  sendAsAliases: string[];
}

/** Every account in the session other than the caller's own (primaryAccounts.mail). */
export async function getDelegatedAccounts(): Promise<DelegatedAccount[]> {
  const s = await loadSession();
  const ownId = s.primaryAccounts?.["urn:ietf:params:jmap:mail"];
  const out: DelegatedAccount[] = [];
  for (const [id, acct] of Object.entries(s.accounts)) {
    if (id === ownId) continue;
    const vendor = (acct.accountCapabilities?.[
      "urn:setjoin:params:jmap:mail"
    ] ?? {}) as {
      delegateGrants?: string[];
      sendAsAliases?: string[];
    };
    out.push({
      id,
      name: acct.name,
      isReadOnly: acct.isReadOnly ?? true,
      grants: vendor.delegateGrants ?? [],
      sendAsAliases: vendor.sendAsAliases ?? [],
    });
  }
  return out;
}

// #13 shared-mailbox use-surface — the MAIL-family accountId override.
// `accountId` (above) is a module singleton (the caller's own primary mailbox);
// the shared-mailbox workspace (/inbox?mbx=<id>) needs a PER-CALL override for
// MAIL calls only (Tasks/Contacts/Calendar stay personal — they never take
// one). Read helpers separate that selection from their method-envelope policy
// through MailReadOptions. Their legacy string override remains only to preserve
// the existing shared-workspace behavior while callers migrate incrementally.
function mailAccount(acct?: string | null): string | null {
  return acct ?? accountId;
}

export type MailReadErrorPolicy = "return-empty" | "throw";

export interface MailReadOptions {
  accountId?: string | null;
  errorPolicy?: MailReadErrorPolicy;
}

type MailReadContext = MailReadOptions | string | null | undefined;

/**
 * Resolve account selection separately from response policy. The string/null
 * branch is a compatibility shim for existing shared-mailbox callers and keeps
 * their wire/error behavior byte-for-byte: a non-empty string historically
 * enabled assertOk, while empty/null did not. New call sites use explicit
 * options and can select either policy independently of account identity.
 */
function mailReadContext(value: MailReadContext): {
  accountId: string | null;
  errorPolicy: MailReadErrorPolicy;
} {
  if (typeof value === "string" || value === null) {
    return {
      accountId: mailAccount(value),
      errorPolicy: value ? "throw" : "return-empty",
    };
  }
  return {
    accountId: mailAccount(value?.accountId),
    errorPolicy: value?.errorPolicy ?? "return-empty",
  };
}

function applyMailReadErrorPolicy(
  response: JmapMethodResponse,
  policy: MailReadErrorPolicy,
): JmapMethodResponse {
  return policy === "throw" ? assertOk(response) : response;
}

export async function mailboxGet(
  ids?: string[],
  options?: MailReadOptions | string | null,
): Promise<Mailbox[]> {
  const context = mailReadContext(options);
  const args: { accountId: string | null; ids?: string[] } = {
    accountId: context.accountId,
  };
  if (ids) args.ids = ids;
  const data = await jmapCall([["Mailbox/get", args, "0"]]);
  const resp = applyMailReadErrorPolicy(
    data.methodResponses[0][1] as JmapMethodResponse,
    context.errorPolicy,
  );
  return (resp.list as Mailbox[]) ?? [];
}

/**
 * The account's current Mailbox state string (RFC 8620 §5.1 `state`), read with
 * an id-only projection. The gateway treats `ids: []` as get-all, so the record
 * payload is kept to ids; callers use only the state (InboxStore push/reconnect
 * anchoring, #225).
 */
export async function mailboxState(
  options?: MailReadOptions | string | null,
  signal?: AbortSignal,
): Promise<string> {
  const context = mailReadContext(options);
  const data = await jmapCall(
    [["Mailbox/get", { accountId: context.accountId, properties: ["id"] }, "0"]],
    undefined,
    signal,
  );
  const resp = applyMailReadErrorPolicy(
    data.methodResponses[0][1] as JmapMethodResponse,
    context.errorPolicy,
  );
  return String((resp as unknown as Record<string, unknown>).state ?? "");
}

export async function emailQuery(
  filter: Record<string, unknown>,
  sort: unknown,
  limit = 20,
  position?: number,
  signal?: AbortSignal,
  options?: MailReadOptions | string | null,
): Promise<{ ids: string[]; total?: number; position?: number }> {
  const context = mailReadContext(options);
  const args: Record<string, unknown> = {
    accountId: context.accountId,
    filter,
    sort: sort || [{ property: "receivedAt", isAscending: false }],
    limit,
  };
  if (position !== undefined) args.position = position;
  const data = await jmapCall([["Email/query", args, "0"]], undefined, signal);
  const resp = applyMailReadErrorPolicy(
    data.methodResponses[0][1] as JmapMethodResponse,
    context.errorPolicy,
  );
  return { ids: resp.ids ?? [], total: resp.total, position: resp.position };
}

// Bounded Email/changes page for the E4-I offline coordinator's delta step
// (lib/offline/steps.ts DeltaChangesClient). Same account/error-policy
// conventions as emailQuery; the caller bounds maxChanges (the coordinator
// enforces the 64-record page limit) and passes its AbortSignal through.
export async function emailChanges(
  sinceState: string,
  maxChanges: number,
  signal?: AbortSignal,
  options?: MailReadOptions | string | null,
): Promise<{
  newState: string;
  hasMoreChanges: boolean;
  created: string[];
  updated: string[];
  destroyed: string[];
}> {
  const context = mailReadContext(options);
  const args = { accountId: context.accountId, sinceState, maxChanges };
  const data = await jmapCall([["Email/changes", args, "0"]], undefined, signal);
  const resp = applyMailReadErrorPolicy(
    data.methodResponses[0][1] as JmapMethodResponse,
    context.errorPolicy,
  );
  // newState/hasMoreChanges are plain RFC 8620 Email/changes response fields;
  // the shared response type does not carry them yet (unvalidated wire cast).
  const raw = resp as unknown as Record<string, unknown>;
  return {
    newState: String(raw.newState ?? ""),
    hasMoreChanges: raw.hasMoreChanges === true,
    created: (raw.created as string[] | undefined) ?? [],
    updated: (raw.updated as string[] | undefined) ?? [],
    destroyed: (raw.destroyed as string[] | undefined) ?? [],
  };
}

// Full single-message read projection — body + recipients + every compose option.
// The reading-pane open and the draft/reply loads MUST pass this; the list keeps the
// narrow default below for bandwidth. (The reducer honours `properties`, so the
// default's omission of bodyHTML/bodyText silently truncated every read to `preview`.)
export const FULL_EMAIL_PROPS = [
  "id",
  "threadId",
  "mailboxIds",
  "from",
  "to",
  "cc",
  "bcc",
  "replyTo",
  "subject",
  "receivedAt",
  "sentAt",
  "hasAttachment",
  "preview",
  "keywords",
  "bodyText",
  "bodyHTML",
  "inlineImages",
  "attachments",
  "priority",
  "sensitivity",
  "voteOptions",
  "scheduledAt",
  "readReceiptRequested",
];

/** Email/get result WITH the response `state` string (RFC 8620 §5.1). */
export interface EmailGetResult {
  list: Email[];
  /**
   * The server's current Email state exactly as the gateway returned it.
   * Callers that anchor a delta cursor on it (offline steps.ts re-anchor)
   * must commit THIS string — a fabricated state commits a delta walk the
   * gateway can never calculate changes from.
   */
  state: string;
}

/**
 * Email/get carrying the response `state` (ids=[] reads state without
 * records). The list-only {@link emailGet} stays the convenience form for
 * every caller that does not consume the state string.
 */
export async function emailGetWithState(
  ids: string[],
  properties?: string[],
  signal?: AbortSignal,
  options?: MailReadOptions | string | null,
): Promise<EmailGetResult> {
  const context = mailReadContext(options);
  const data = await jmapCall(
    [
      [
        "Email/get",
        {
          accountId: context.accountId,
          ids,
          properties: properties || [
            "id",
            "threadId",
            "mailboxIds",
            "from",
            "to",
            "subject",
            "receivedAt",
            "hasAttachment",
            "preview",
            "keywords",
          ],
        },
        "0",
      ],
    ],
    undefined,
    signal,
  );
  const resp = applyMailReadErrorPolicy(
    data.methodResponses[0][1] as JmapMethodResponse,
    context.errorPolicy,
  );
  // `state` is a plain RFC 8620 Email/get response field; the shared response
  // type does not carry it yet (unvalidated wire cast, same as emailChanges).
  const raw = resp as unknown as Record<string, unknown>;
  return {
    list: (resp.list as Email[]) ?? [],
    state: String(raw.state ?? ""),
  };
}

export async function emailGet(
  ids: string[],
  properties?: string[],
  signal?: AbortSignal,
  options?: MailReadOptions | string | null,
): Promise<Email[]> {
  return (await emailGetWithState(ids, properties, signal, options)).list;
}

export interface ContinuityTokenResponse {
  accountId: string;
  token: string;
  timelineGeneration: string;
  stateWatermark: string;
  bootEpoch: string;
}

export async function continuityGet(
  acct?: string | null,
): Promise<ContinuityTokenResponse> {
  const data = await jmapCall([
    ["Continuity/get", { accountId: mailAccount(acct) }, "0"],
  ]);
  return assertOk(
    data.methodResponses[0][1] as JmapMethodResponse,
  ) as ContinuityTokenResponse;
}

export async function continuityPresent(
  token: string,
  acct?: string | null,
): Promise<{
  signalClass: string;
  verificationStatus: string;
  recoveryIntakeAllowed: false;
}> {
  const data = await jmapCall([
    ["Continuity/present", { accountId: mailAccount(acct), token }, "0"],
  ]);
  return assertOk(data.methodResponses[0][1] as JmapMethodResponse) as {
    signalClass: string;
    verificationStatus: string;
    recoveryIntakeAllowed: false;
  };
}

export interface RecoveryReceiptResponse {
  accountId: string;
  list: Array<{
    id: string;
    eligibility: "received" | "sent-terminal";
    receivedAt: string;
    artifactIdentity: string;
    receipt: {
      claims: {
        installationId: string;
        accountId: string;
        originalMessageId: string;
        rawMimeSha256: string;
        rawMimeSize: string;
        blobs: Array<{ blobId: string; sha256: string; size: string }>;
        timelineGeneration: string;
        stateWatermark: string;
        bootEpoch: string;
        issuedAt: string;
        keyId: string;
      };
      signature: string;
    };
    raw: { sha256: string; size: string; url: string };
    blobs: Array<{
      blobId: string;
      sha256: string;
      size: string;
      role: "attachment" | "inline";
    }>;
  }>;
  notFound: string[];
}

export async function recoveryReceiptGet(
  ids: string[],
  acct?: string | null,
): Promise<RecoveryReceiptResponse> {
  const data = await jmapCall([
    ["Email/recoveryReceipt", { accountId: mailAccount(acct), ids }, "0"],
  ]);
  return assertOk(
    data.methodResponses[0][1] as JmapMethodResponse,
  ) as RecoveryReceiptResponse;
}

export async function fetchRecoveryBytes(
  url: string,
  signal?: AbortSignal,
): Promise<Response> {
  // Source-of-URL guard: `url` originates from a gateway response body, so the
  // credentialed fetch is pinned to THIS origin — root-relative or absolute
  // same-origin only. Anything else (another host, other scheme, empty) fails
  // closed rather than letting a regressed or injected response point a
  // cookie-bearing request off-origin.
  if (typeof url !== "string" || url === "") {
    throw new Error("Recovery download failed");
  }
  if (typeof location === "undefined") {
    throw new Error("Recovery download failed");
  }
  const resolved = new URL(url, location.origin);
  if (resolved.origin !== location.origin) {
    throw new Error("Recovery download failed");
  }
  // Normalized to a root-relative path so the request keeps the directory's
  // root-relative invariant (and the http seam's htu derivation) intact.
  return httpRequest(resolved.pathname + resolved.search + resolved.hash, {
    signal,
    credentials: "include",
  });
}

export interface RecoveryUploadItem {
  itemId: string;
  nextOffset: string;
  size: string;
  status: "uploading" | "verified";
}

export interface RecoveryIncidentOffer {
  id: string;
  mailboxId: string;
  minimumTimeline: string;
  maximumTimeline: string;
  expiresAt: string;
  reason: string;
}

export async function recoveryIncidentOffers(): Promise<
  RecoveryIncidentOffer[]
> {
  const response = await httpRequest("/api/recovery/incidents", {
    credentials: "include",
    loginRedirect: "/",
  });
  const body = (await response.json()) as { list: RecoveryIncidentOffer[] };
  return body.list ?? [];
}

export interface RecoveryUploadSession {
  sessionId: string;
  status: "uploading" | "quarantined" | "deduplicated" | "rejected";
  expiresAt: string;
  items: RecoveryUploadItem[];
  replayed: boolean;
}

export async function recoveryUploadBegin(
  payload: Record<string, unknown>,
  idempotencyKey: string,
): Promise<RecoveryUploadSession> {
  const headers = new Headers({
    "Content-Type": "application/json",
    "Idempotency-Key": idempotencyKey,
  });
  if (hasCapability("deviceProof")) await attachDeviceProofHeaders(headers);
  const response = await httpRequest("/api/recovery/uploads", {
    method: "POST",
    headers,
    body: JSON.stringify(payload),
    loginRedirect: "/",
  });
  return (await response.json()) as RecoveryUploadSession;
}

export async function recoveryUploadChunk(
  sessionId: string,
  itemId: string,
  start: number,
  total: number,
  chunk: Uint8Array,
): Promise<void> {
  const headers = new Headers({
    "Content-Type": "application/octet-stream",
    "Content-Range": `bytes ${start}-${start + chunk.byteLength - 1}/${total}`,
  });
  if (hasCapability("deviceProof")) await attachDeviceProofHeaders(headers);
  await httpRequest(
    `/api/recovery/uploads/${encodeURIComponent(sessionId)}/items/${encodeURIComponent(itemId)}`,
    {
      method: "PUT",
      headers,
      body: new Uint8Array(chunk).buffer as ArrayBuffer,
      loginRedirect: "/",
    },
  );
}

export async function recoveryUploadCommit(
  sessionId: string,
  itemId: string,
): Promise<void> {
  await httpRequest(
    `/api/recovery/uploads/${encodeURIComponent(sessionId)}/items/${encodeURIComponent(itemId)}/commit`,
    {
      method: "POST",
      headers: new Headers({ "Content-Type": "application/json" }),
      body: "{}",
      loginRedirect: "/",
    },
  );
}

export async function recoveryUploadFinalize(
  sessionId: string,
): Promise<{ id: string; status: string; replayed?: boolean }> {
  const response = await httpRequest(
    `/api/recovery/uploads/${encodeURIComponent(sessionId)}/finalize`,
    {
      method: "POST",
      headers: new Headers({ "Content-Type": "application/json" }),
      body: "{}",
      loginRedirect: "/",
    },
  );
  return (await response.json()) as {
    id: string;
    status: string;
    replayed?: boolean;
  };
}

export async function recoveryUploadAbort(sessionId: string): Promise<void> {
  await httpRequest(`/api/recovery/uploads/${encodeURIComponent(sessionId)}`, {
    method: "DELETE",
    loginRedirect: "/",
  });
}

/** One BM25 highlight match — subject/preview are server HTML with <mark> tags. */
export interface SearchSnippet {
  emailId: string;
  subject: string;
  preview: string;
}

// SearchSnippet/get — per-match highlighted subject/preview for a text query.
// Same capability set as emailQuery/emailGet (default core+mail); the gateway
// requires a text/subject/body filter or the reducer raises invalidArguments.
export async function searchSnippetGet(
  filter: Record<string, unknown>,
  ids: string[],
  options?: MailReadOptions | string | null,
): Promise<SearchSnippet[]> {
  const context = mailReadContext(options);
  const data = await jmapCall([
    [
      "SearchSnippet/get",
      { accountId: context.accountId, filter, emailIds: ids },
      "0",
    ],
  ]);
  const resp = applyMailReadErrorPolicy(
    data.methodResponses[0][1] as JmapMethodResponse,
    context.errorPolicy,
  );
  return (resp.list as SearchSnippet[]) ?? [];
}

export async function emailSet(
  create: Record<string, Partial<Email>> | null,
  update: Record<string, Partial<Email>> | null,
  destroy: string[] | null,
  acct?: string | null,
): Promise<JmapMethodResponse> {
  const data = await jmapCall([
    [
      "Email/set",
      { accountId: mailAccount(acct), create, update, destroy },
      "0",
    ],
  ]);
  return assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

export async function identityGet(): Promise<Identity[]> {
  const data = await jmapCall([["Identity/get", { accountId }, "0"]]);
  return (
    ((data.methodResponses[0][1] as JmapMethodResponse).list as Identity[]) ??
    []
  );
}

// Calendar JMAP helpers

export async function calendarGet(ids?: string[]): Promise<Calendar[]> {
  const args: { accountId: string | null; ids?: string[] } = { accountId };
  if (ids) args.ids = ids;
  const data = await jmapCall([["Calendar/get", args, "0"]]);
  return (
    ((data.methodResponses[0][1] as JmapMethodResponse).list as Calendar[]) ??
    []
  );
}

export async function calendarEventQuery(
  filter: Record<string, unknown>,
  limit = 500,
): Promise<string[]> {
  const args = { accountId, filter, limit };
  const data = await jmapCall([["CalendarEvent/query", args, "0"]]);
  return (data.methodResponses[0][1] as JmapMethodResponse).ids ?? [];
}

export async function calendarEventGet(
  ids: string[],
): Promise<CalendarEvent[]> {
  const data = await jmapCall([["CalendarEvent/get", { accountId, ids }, "0"]]);
  return (
    ((data.methodResponses[0][1] as JmapMethodResponse)
      .list as CalendarEvent[]) ?? []
  );
}

export async function calendarEventSet(
  create: Record<string, Partial<CalendarEvent>> | null,
  update: Record<string, Partial<CalendarEvent>> | null,
  destroy: string[] | null,
): Promise<JmapMethodResponse> {
  const args: {
    accountId: string | null;
    create?: Record<string, Partial<CalendarEvent>>;
    update?: Record<string, Partial<CalendarEvent>>;
    destroy?: string[];
  } = { accountId };
  if (create) args.create = create;
  if (update) args.update = update;
  if (destroy) args.destroy = destroy;
  const data = await jmapCall([["CalendarEvent/set", args, "0"]]);
  return assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

export interface IcsImportResult {
  imported: number;
  skipped: number;
}

/**
 * CalendarEvent/import — import an uploaded .ics file into one owned calendar.
 * The gateway parses the iCal and routes each event through the ownership-checked
 * calendar_import_ics reducer (never a raw INSERT). strategy ∈ skip|overwrite|rename.
 */
export async function calendarEventImport(
  calendarId: string,
  ics: string,
  strategy: "skip" | "overwrite" | "rename",
): Promise<IcsImportResult> {
  const data = await jmapCall([
    ["CalendarEvent/import", { accountId, calendarId, ics, strategy }, "0"],
  ]);
  const res = assertOk(
    data.methodResponses[0][1] as JmapMethodResponse,
  ) as unknown as {
    imported?: number;
    skipped?: number;
  };
  return { imported: res.imported ?? 0, skipped: res.skipped ?? 0 };
}

export async function calendarEventRsvp(
  eventId: string,
  status: string,
): Promise<JmapMethodResponse> {
  const data = await jmapCall([
    ["CalendarEvent/rsvp", { accountId, eventId, status }, "0"],
  ]);
  return assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

// Outbound iTIP COUNTER: an invitee proposes new times to the organizer. The proposing
// attendee is the authenticated user server-side (never passed from the client). start/end
// are the PROPOSED times; the event itself is unchanged until the organizer accepts.
export async function calendarEventCounter(
  eventId: string,
  start: string,
  end: string,
): Promise<JmapMethodResponse> {
  const data = await jmapCall([
    ["CalendarEvent/counter", { accountId, eventId, start, end }, "0"],
  ]);
  return assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

export async function calendarEventQueryFreeSlots(params: {
  userIds: string[];
  start: string;
  end: string;
  durationMinutes?: number;
  slotIntervalMinutes?: number;
  workingStartTime?: string;
  workingEndTime?: string;
  maxSlots?: number;
}): Promise<JmapMethodResponse> {
  const data = await jmapCall([
    ["CalendarEvent/queryFreeSlots", { accountId, ...params }, "0"],
  ]);
  return data.methodResponses[0][1] as JmapMethodResponse;
}

// ── Calendar A3: sharing, shared reads, occurrence edit, delegate, rooms, send update ──

export async function calendarGetShared(
  ownerEmail: string,
): Promise<Calendar[]> {
  const data = await jmapCall([
    ["Calendar/getShared", { accountId, ownerEmail }, "0"],
  ]);
  return (
    ((data.methodResponses[0][1] as JmapMethodResponse).list as Calendar[]) ??
    []
  );
}

export async function calendarEventGetShared(
  ownerEmail: string,
  after?: string,
  before?: string,
): Promise<CalendarEvent[]> {
  const args: Record<string, unknown> = { accountId, ownerEmail };
  if (after) args.after = after;
  if (before) args.before = before;
  const data = await jmapCall([["CalendarEvent/getShared", args, "0"]]);
  return (
    ((data.methodResponses[0][1] as JmapMethodResponse)
      .list as CalendarEvent[]) ?? []
  );
}

export async function calendarShareGet(
  calendarId: string,
): Promise<JmapMethodResponse> {
  const data = await jmapCall([
    ["Calendar/shareGet", { accountId, calendarId }, "0"],
  ]);
  return data.methodResponses[0][1] as JmapMethodResponse;
}

export async function calendarShareSet(
  calendarId: string,
  grants: { userEmail: string; level: string }[],
  revokes: { userEmail: string }[],
): Promise<JmapMethodResponse> {
  const data = await jmapCall([
    ["Calendar/shareSet", { accountId, calendarId, grants, revokes }, "0"],
  ]);
  return assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

export async function calendarDelegateList(): Promise<JmapMethodResponse> {
  const data = await jmapCall([["Calendar/delegateList", { accountId }, "0"]]);
  return data.methodResponses[0][1] as JmapMethodResponse;
}

export async function calendarEventSetOccurrence(
  masterId: string,
  recurrenceId: string,
  scope: "this" | "following" | "series",
  patch: Record<string, unknown>,
): Promise<JmapMethodResponse> {
  const data = await jmapCall([
    [
      "CalendarEvent/setOccurrence",
      { accountId, masterId, recurrenceId, scope, patch },
      "0",
    ],
  ]);
  return assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

export async function calendarEventResourceList(): Promise<JmapMethodResponse> {
  const data = await jmapCall([
    ["CalendarEvent/resourceList", { accountId }, "0"],
  ]);
  return data.methodResponses[0][1] as JmapMethodResponse;
}

export async function calendarEventSendUpdate(
  eventId: string,
): Promise<JmapMethodResponse> {
  const data = await jmapCall([
    ["CalendarEvent/sendUpdate", { accountId, eventId }, "0"],
  ]);
  return assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

export async function calendarEventRsvpOnBehalf(
  eventId: string,
  status: string,
  onBehalfOf: string,
): Promise<JmapMethodResponse> {
  const data = await jmapCall([
    ["CalendarEvent/rsvp", { accountId, eventId, status, onBehalfOf }, "0"],
  ]);
  return assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

// Contact JMAP helpers

export async function addressBookGet(ids?: string[]): Promise<AddressBook[]> {
  const args: { accountId: string | null; ids?: string[] } = { accountId };
  if (ids) args.ids = ids;
  const data = await jmapCall([["AddressBook/get", args, "0"]]);
  return (
    ((data.methodResponses[0][1] as JmapMethodResponse)
      .list as AddressBook[]) ?? []
  );
}

export async function addressBookSet(
  create: Record<string, Partial<AddressBook>> | null,
  update: Record<string, Partial<AddressBook>> | null,
  destroy: string[] | null,
): Promise<JmapMethodResponse> {
  const args: {
    accountId: string | null;
    create?: Record<string, Partial<AddressBook>>;
    update?: Record<string, Partial<AddressBook>>;
    destroy?: string[];
  } = { accountId };
  if (create) args.create = create;
  if (update) args.update = update;
  if (destroy) args.destroy = destroy;
  const data = await jmapCall([["AddressBook/set", args, "0"]]);
  return assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

export async function contactQuery(
  filter: Record<string, unknown>,
  sort: unknown,
  position: number | undefined,
  limit: number | undefined,
  signal?: AbortSignal,
): Promise<{ ids: string[]; total?: number; position?: number }> {
  const args: Record<string, unknown> = { accountId, filter };
  if (sort !== undefined) args.sort = sort;
  if (position !== undefined) args.position = position;
  if (limit !== undefined) args.limit = limit;
  const data = await jmapCall(
    [["ContactCard/query", args, "0"]],
    undefined,
    signal,
  );
  const resp = data.methodResponses[0][1] as JmapMethodResponse;
  return { ids: resp.ids ?? [], total: resp.total, position: resp.position };
}

export async function contactGet(
  ids: string[],
  properties?: string[],
  signal?: AbortSignal,
): Promise<ContactCard[]> {
  const args: {
    accountId: string | null;
    ids: string[];
    properties?: string[];
  } = {
    accountId,
    ids,
  };
  if (properties) args.properties = properties;
  const data = await jmapCall(
    [["ContactCard/get", args, "0"]],
    undefined,
    signal,
  );
  return (
    ((data.methodResponses[0][1] as JmapMethodResponse)
      .list as ContactCard[]) ?? []
  );
}

export async function contactSet(
  create: Record<string, Partial<ContactCard>> | null,
  update: Record<string, Partial<ContactCard>> | null,
  destroy: string[] | null,
): Promise<JmapMethodResponse> {
  const args: {
    accountId: string | null;
    create?: Record<string, Partial<ContactCard>>;
    update?: Record<string, Partial<ContactCard>>;
    destroy?: string[];
  } = { accountId };
  if (create) args.create = create;
  if (update) args.update = update;
  if (destroy) args.destroy = destroy;
  const data = await jmapCall([["ContactCard/set", args, "0"]]);
  return assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

export async function galSearch(
  text: string,
  limit = 50,
  signal?: AbortSignal,
): Promise<ContactCard[]> {
  const data = await jmapCall(
    [["ContactCard/galSearch", { accountId, text, limit }, "0"]],
    undefined,
    signal,
  );
  return (
    ((data.methodResponses[0][1] as JmapMethodResponse)
      .list as ContactCard[]) ?? []
  );
}

/** One find-duplicates cluster: an email shared by ≥2 of the caller's contacts. */
export interface DuplicateCluster {
  email: string;
  contactIds: string[];
}

/**
 * ContactCard/findDuplicates — clusters of the caller's contacts sharing an
 * email. The reducer returns a BARE array (jsonb_agg), not a `{list}` envelope,
 * and emits contactIds as JSON numbers — map them to the string ids the rest of
 * the JMAP contract (and contactMerge) use.
 */
export async function contactFindDuplicates(): Promise<DuplicateCluster[]> {
  const data = await jmapCall([
    ["ContactCard/findDuplicates", { accountId }, "0"],
  ]);
  const raw = data.methodResponses[0][1] as unknown as {
    email: string;
    contactIds: number[];
  }[];
  if (!Array.isArray(raw)) return [];
  return raw.map((c) => ({
    email: c.email,
    contactIds: c.contactIds.map(String),
  }));
}

/** ContactCard/merge — union dropId into keepId (returns {merged}); throws on error. */
export async function contactMerge(
  keepId: string,
  dropId: string,
): Promise<void> {
  const data = await jmapCall([
    ["ContactCard/merge", { accountId, keepId, dropId }, "0"],
  ]);
  assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

// ── Personal contact groups (A4) ──

export async function contactGroupGet(ids?: string[]): Promise<ContactGroup[]> {
  const args: { accountId: string | null; ids?: string[] } = { accountId };
  if (ids) args.ids = ids;
  const data = await jmapCall([["ContactGroup/get", args, "0"]]);
  return (
    ((data.methodResponses[0][1] as JmapMethodResponse)
      .list as ContactGroup[]) ?? []
  );
}

export async function contactGroupQuery(
  filter?: Record<string, unknown>,
): Promise<{ ids: string[]; total?: number }> {
  const args: Record<string, unknown> = { accountId };
  if (filter) args.filter = filter;
  const data = await jmapCall([["ContactGroup/query", args, "0"]]);
  const resp = data.methodResponses[0][1] as JmapMethodResponse;
  return { ids: resp.ids ?? [], total: resp.total };
}

export async function contactGroupSet(
  create: Record<string, { name: string }> | null,
  update: Record<string, { name?: string }> | null,
  destroy: string[] | null,
  members?: {
    groupId: string;
    add?: ContactGroupMember[];
    remove?: ContactGroupMember[];
  },
): Promise<JmapMethodResponse> {
  const args: {
    accountId: string | null;
    create?: Record<string, { name: string }>;
    update?: Record<string, { name?: string }>;
    destroy?: string[];
    members?: {
      groupId: string;
      add?: ContactGroupMember[];
      remove?: ContactGroupMember[];
    };
  } = { accountId };
  if (create) args.create = create;
  if (update) args.update = update;
  if (destroy) args.destroy = destroy;
  if (members) args.members = members;
  const data = await jmapCall([["ContactGroup/set", args, "0"]]);
  return assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

export async function contactGroupExpand(
  groupId: string,
): Promise<ExpandedRecipient[]> {
  const data = await jmapCall([
    ["ContactGroup/expand", { accountId, groupId }, "0"],
  ]);
  return (
    ((data.methodResponses[0][1] as JmapMethodResponse)
      .list as ExpandedRecipient[]) ?? []
  );
}

// ── Blob upload (SHA-256-first PUT /api/blobs/{sha}) ──
// The content-addressed contract: hash the whole file client-side, then PUT the
// bytes under that key. sha256Hex + putBlob are exported separately so the
// compose upload UI can surface the two phases (hashing = indeterminate
// "preparing", PUT = real progress) and skip the PUT for an already-staged
// blob; uploadBlob stays the one-shot helper for everything else (avatars).

/** Whole-file SHA-256 as lowercase hex — the blob's content address. */
export async function sha256Hex(file: File): Promise<string> {
  const buf = await file.arrayBuffer();
  const hash = await crypto.subtle.digest("SHA-256", buf);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * PUT the file bytes under their SHA-256 key. XHR, not fetch: fetch cannot
 * report UPLOAD progress (its streams cover the response side only) and
 * xhr.abort() gives cancel. Same-origin, so cookies ride along as with fetch.
 * Rejects with an 'AbortError'-named DOMException when opts.signal fires.
 */
export function putBlob(
  blobId: string,
  file: File,
  opts?: { onProgress?: (fraction: number) => void; signal?: AbortSignal },
): Promise<void> {
  return new Promise((resolve, reject) => {
    if (opts?.signal?.aborted) {
      reject(new DOMException("Aborted", "AbortError"));
      return;
    }
    const xhr = new XMLHttpRequest();
    // blobId is percent-encoded at this boundary (every in-repo producer passes
    // a sha256 hex digest, so this is a no-op for real callers) — a malformed
    // id can shape the URL but never escape the /api/blobs/ namespace.
    xhr.open("PUT", `/api/blobs/${encodeURIComponent(blobId)}`);
    if (file.type) xhr.setRequestHeader("Content-Type", file.type);
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && e.total > 0)
        opts?.onProgress?.(e.loaded / e.total);
    };
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) resolve();
      else reject(new Error(`Upload failed (${xhr.status})`));
    };
    xhr.onerror = () => reject(new Error("Upload failed"));
    xhr.onabort = () => reject(new DOMException("Aborted", "AbortError"));
    opts?.signal?.addEventListener("abort", () => xhr.abort(), { once: true });
    xhr.send(file);
  });
}

/** One-shot hash + PUT (no progress surface) — avatar upload etc. */
export async function uploadBlob(
  file: File,
): Promise<{ blobId: string; size: number }> {
  const blobId = await sha256Hex(file);
  await putBlob(blobId, file);
  return { blobId, size: file.size };
}

// Task JMAP helpers

export async function taskGet(ids: string[]): Promise<Task[]> {
  const data = await jmapCall([["Task/get", { accountId, ids }, "0"]]);
  return (
    ((data.methodResponses[0][1] as JmapMethodResponse).list as Task[]) ?? []
  );
}

export async function taskQuery(
  filter: Record<string, unknown>,
  limit = 100,
): Promise<string[]> {
  const args = { accountId, filter, limit };
  const data = await jmapCall([["Task/query", args, "0"]]);
  return (data.methodResponses[0][1] as JmapMethodResponse).ids ?? [];
}

export async function taskSet(
  create: Record<string, Partial<Task>> | null,
  update: Record<string, Partial<Task>> | null,
  destroy: string[] | null,
): Promise<JmapMethodResponse> {
  const args: {
    accountId: string | null;
    create?: Record<string, Partial<Task>>;
    update?: Record<string, Partial<Task>>;
    destroy?: string[];
  } = { accountId };
  if (create) args.create = create;
  if (update) args.update = update;
  if (destroy) args.destroy = destroy;
  const data = await jmapCall([["Task/set", args, "0"]]);
  return assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

// ── Task comments / activity feed (QoL #17) ──

/** TaskComment/get — the ownership-checked activity feed for one task. */
export async function taskActivityList(
  taskId: string,
): Promise<TaskActivity[]> {
  const data = await jmapCall([
    ["TaskComment/get", { accountId, taskId }, "0"],
  ]);
  const resp = assertOk(data.methodResponses[0][1] as JmapMethodResponse);
  return (resp.list as TaskActivity[]) ?? [];
}

/** TaskComment/set — append a comment (with optional @mention emails) to a task. */
export async function taskCommentCreate(
  taskId: string,
  body: string,
  mentionedEmails: string[] = [],
): Promise<void> {
  const data = await jmapCall([
    ["TaskComment/set", { accountId, taskId, body, mentionedEmails }, "0"],
  ]);
  assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

// ── Shared / team task lists (Phase 1) ── all USER-scoped: no accountId.

export async function taskListGet(): Promise<TaskList[]> {
  const data = await jmapCall([["TaskList/get", {}, "0"]]);
  const resp = assertOk(data.methodResponses[0][1] as JmapMethodResponse);
  return (resp.lists as TaskList[]) ?? [];
}

export async function taskListSet(
  create: Record<string, { name: string; color?: string | null }> | null,
  update: Record<string, { name?: string; color?: string | null }> | null,
  destroy: string[] | null,
): Promise<JmapMethodResponse> {
  const args: Record<string, unknown> = {};
  if (create) args.create = create;
  if (update) args.update = update;
  if (destroy) args.destroy = destroy;
  const data = await jmapCall([["TaskList/set", args, "0"]]);
  return assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

export async function taskListMemberSet(
  listId: string,
  add: string[] = [],
  remove: string[] = [],
): Promise<JmapMethodResponse> {
  const data = await jmapCall([
    ["TaskListMember/set", { listId, add, remove }, "0"],
  ]);
  return assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

export async function taskListTasks(
  listId: string,
): Promise<{ state: string; list: Task[] }> {
  const data = await jmapCall([["TaskList/tasks", { listId }, "0"]]);
  const resp = assertOk(data.methodResponses[0][1] as JmapMethodResponse);
  return {
    state: (resp.state as string) ?? "0",
    list: (resp.list as Task[]) ?? [],
  };
}

export async function taskListTaskSet(
  listId: string,
  create: Record<string, Partial<Task>> | null,
  update: Record<string, Partial<Task>> | null,
  destroy: string[] | null,
): Promise<JmapMethodResponse> {
  const args: Record<string, unknown> = { listId };
  if (create) args.create = create;
  if (update) args.update = update;
  if (destroy) args.destroy = destroy;
  const data = await jmapCall([["TaskList/taskSet", args, "0"]]);
  return assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

export async function taskAssignedGet(): Promise<AssignedTask[]> {
  const data = await jmapCall([["TaskAssigned/get", {}, "0"]]);
  const resp = assertOk(data.methodResponses[0][1] as JmapMethodResponse);
  return (resp.list as AssignedTask[]) ?? [];
}

export async function taskAssignedSetStatus(
  taskId: string,
  status: string,
): Promise<void> {
  const data = await jmapCall([
    ["TaskAssigned/setStatus", { taskId, status }, "0"],
  ]);
  assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

// EmailSubmission/* lives under the JMAP submission capability (RFC 8621);
// usingFor derives it (and keeps `mail` for onSuccessUpdateEmail references).

export async function emailSubmissionSet(
  create: Record<string, unknown>,
  acct?: string | null,
): Promise<JmapMethodResponse> {
  const data = await jmapCall([
    ["EmailSubmission/set", { accountId: mailAccount(acct), create }, "0"],
  ]);
  return assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

// Undo-window cancel: the gateway returns a method-level error envelope when the
// send already left the window (or the delegation was revoked) — assertOk surfaces
// that instead of letting the UI treat the send as canceled when it still delivers.
export async function emailSubmissionCancel(
  emailId: string,
  acct?: string | null,
): Promise<JmapMethodResponse> {
  const data = await jmapCall([
    ["EmailSubmission/cancel", { accountId: mailAccount(acct), emailId }, "0"],
  ]);
  return assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

export async function emailSubmissionQuery(
  filter?: Record<string, unknown>,
  position?: number,
  limit?: number,
): Promise<{ ids: string[]; total?: number; position?: number }> {
  const args: Record<string, unknown> = { accountId, filter: filter ?? {} };
  if (position !== undefined) args.position = position;
  if (limit !== undefined) args.limit = limit;
  const data = await jmapCall([["EmailSubmission/query", args, "0"]]);
  const resp = data.methodResponses[0][1] as JmapMethodResponse;
  return { ids: resp.ids ?? [], total: resp.total, position: resp.position };
}

export async function emailSubmissionGet(
  ids: string[],
): Promise<EmailSubmission[]> {
  const data = await jmapCall([
    ["EmailSubmission/get", { accountId, ids }, "0"],
  ]);
  return (
    ((data.methodResponses[0][1] as JmapMethodResponse)
      .list as EmailSubmission[]) ?? []
  );
}

export async function emailBundles(
  limit = 50,
  position = 0,
): Promise<{ bundles: EmailBundle[]; position: number }> {
  // Email/bundles is an Email/* method: usingFor derives the STANDARD mail
  // capability the gateway requires (declaring only the vendor URN 400s).
  const data = await jmapCall([
    ["Email/bundles", { accountId, limit, position }, "0"],
  ]);
  const resp = data.methodResponses[0][1] as JmapMethodResponse & {
    bundles?: EmailBundle[];
    position?: number;
  };
  return { bundles: resp.bundles ?? [], position: resp.position ?? 0 };
}

/**
 * Email/nudges (#13) — the computed stale-thread / no-reply nudge list for the
 * caller's mailbox. Returns an empty list when feature.stale_nudges is OFF (the
 * gateway gates it), so the banner just renders nothing without any extra
 * capability plumbing.
 */
export async function emailNudges(
  limit = 50,
  position = 0,
): Promise<EmailNudge[]> {
  const data = await jmapCall([
    ["Email/nudges", { accountId, limit, position }, "0"],
  ]);
  const resp = data.methodResponses[0][1] as JmapMethodResponse & {
    nudges?: EmailNudge[];
  };
  return resp.nudges ?? [];
}

/** Email/nudgeDismiss (#13) — dismiss one stale-thread nudge by thread id. */
export async function emailNudgeDismiss(threadId: string): Promise<void> {
  const data = await jmapCall([
    ["Email/nudgeDismiss", { accountId, threadId }, "0"],
  ]);
  assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

export async function threadGet(
  ids: string[],
  options?: MailReadOptions | string | null,
): Promise<{ id: string; emailIds: string[] }[]> {
  const context = mailReadContext(options);
  const data = await jmapCall([
    ["Thread/get", { accountId: context.accountId, ids }, "0"],
  ]);
  const resp = applyMailReadErrorPolicy(
    data.methodResponses[0][1] as JmapMethodResponse,
    context.errorPolicy,
  );
  return (resp.list as { id: string; emailIds: string[] }[] | undefined) ?? [];
}

export async function emailDeletedQuery(
  limit?: number,
  offset?: number,
): Promise<{ list: unknown[] }> {
  const data = await jmapCall([
    ["Email/deletedQuery", { accountId, limit, offset }, "0"],
  ]);
  return {
    list: (data.methodResponses[0][1] as JmapMethodResponse).list ?? [],
  };
}

export async function emailRecover(ids: string[]): Promise<JmapMethodResponse> {
  const data = await jmapCall([["Email/recover", { accountId, ids }, "0"]]);
  return assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

export async function emailPurge(ids: string[]): Promise<JmapMethodResponse> {
  const data = await jmapCall([["Email/purge", { accountId, ids }, "0"]]);
  return assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

/**
 * Move a message to the Focused (focused=true) or Other (focused=false) pile of the
 * Focused/Other inbox split (V078). The gateway also learns a per-sender override so
 * future mail from the same sender lands the same way. Backed by POST
 * /messages/{id}/focus (mirrors the recall REST surface).
 */
export async function setMessageFocus(
  id: string,
  focused: boolean,
): Promise<void> {
  await httpRequest(`/api/messages/${encodeURIComponent(id)}/focus`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ focused }),
  });
}

// ── Reminders (A6 — Scheduled Actions remind surface) ──

export interface Reminder {
  id: string;
  sourceType: "event" | "task" | "flag";
  sourceId: string;
  fireAt: string;
  firedAt: string | null;
  title: string;
  body: string | null;
}

/** Reminder/get — the account's active (fired, not dismissed, not snoozed) reminders. */
export async function reminderGet(): Promise<Reminder[]> {
  const id = await getAccountId();
  const data = await jmapCall([["Reminder/get", { accountId: id }, "0"]]);
  const res = data.methodResponses[0][1] as { list?: Reminder[] };
  return res.list ?? [];
}

/** Reminder/dismiss — dismiss one reminder, or all when no id is given. */
export async function reminderDismiss(reminderId?: string): Promise<void> {
  const id = await getAccountId();
  const args: Record<string, unknown> = { accountId: id };
  if (reminderId) args.reminderId = reminderId;
  else args.all = true;
  const data = await jmapCall([["Reminder/dismiss", args, "0"]]);
  assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

/** Reminder/snooze — re-arm a reminder for a later ISO time. */
export async function reminderSnooze(
  reminderId: string,
  until: string,
): Promise<void> {
  const id = await getAccountId();
  const data = await jmapCall([
    ["Reminder/snooze", { accountId: id, reminderId, until }, "0"],
  ]);
  assertOk(data.methodResponses[0][1] as JmapMethodResponse);
}

export interface AssistMessage {
  role: string;
  content: string;
}

/**
 * Calls the B4 assist endpoint (POST /assist/complete) gated on feature.assist.
 * Returns the generated completion text; throws on non-2xx with the parsed detail.
 */
export async function assistComplete(
  messages: AssistMessage[],
  locale?: string,
): Promise<string> {
  const body: Record<string, unknown> = { messages };
  if (locale) body.locale = locale;
  const data = await typedFetch<{ content?: string }>("/api/assist/complete", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
    loginRedirect: null,
    onError: async (res) => {
      const detail = await res.json().catch(() => ({}));
      return (detail as { detail?: string }).detail || "Assist unavailable";
    },
  });
  return data.content ?? "";
}
