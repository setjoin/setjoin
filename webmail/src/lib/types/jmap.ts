// JMAP Core + Mail + Calendar + Contacts type definitions (RFC 8620 / 8621)

// ── Session ──

export interface BrandingConfig {
  name: string;
  logoUrl: string;
}

export type AppId =
  | "mail"
  | "calendar"
  | "contacts"
  | "tasks"
  | "approvals"
  | "drive"
  | "chat"
  | "meet";

/** Runtime AppId order (single source for the enabled-apps derivation below). */
export const APP_IDS = [
  "mail",
  "calendar",
  "contacts",
  "tasks",
  "approvals",
  "drive",
  "chat",
  "meet",
] as const;

/**
 * Fail-closed derivation of the enabled-app set from the server payload: an
 * app is enabled ONLY when the server explicitly asserts `true` for it.
 *
 * The wire payload keeps `Partial<Record<AppId, boolean>>` for the B8
 * compatibility window (see EffectiveCapabilitiesPayload), and the session
 * store still consumes that default-allow shape until B8 lands; this helper
 * is the strict counterpart deployers can adopt the moment the window
 * closes. kept next to the payload type so the two postures cannot drift
 * apart unnoticed.
 */
export function explicitlyEnabledApps(payload: EffectiveCapabilitiesPayload): AppId[] {
  return APP_IDS.filter((app) => payload.apps[app] === true);
}

// Server payload shape (backend-wave2 B8.3 — object-of-booleans). Partial
// (not Record<AppId, boolean>): effectiveCaps' own filter already treats an
// absent key as enabled (default-allow — the documented B8 compatibility
// window), and a new AppId (meet, Task 15) would otherwise force every
// existing apps-literal call site to grow a key it doesn't need to assert.
// The strict, fail-closed derivation over this shape is `explicitlyEnabledApps`
// above; adopt it at the same time the window closes.
export interface EffectiveCapabilitiesPayload {
  apps: Partial<Record<AppId, boolean>>;
  features: {
    assist: boolean;
    bundles: boolean;
    device_lockdown?: boolean;
    external_labels?: boolean;
    guest_accounts?: boolean;
    guest_invite?: boolean;
    mail_search_builder?: boolean;
    sender_control_center?: boolean;
    shared_mail_work?: boolean;
    shared_mail_comments?: boolean;
    shared_mail_drafts?: boolean;
    shared_mail_notifications?: boolean;
    shared_mail_analytics?: boolean;
    shared_mail_integrations?: boolean;
  };
  /** Optional guest-only runtime policy. Absence is deliberately deny-by-default. */
  guest?: {
    allowMeetCreate?: boolean;
    allowMeetHost?: boolean;
    allowDownload?: boolean;
  };
}

// Derived view the M2 shell consumes (array + flat flags).
export interface EffectiveCapabilities {
  enabledApps: AppId[]; // ordered; first = post-login landing
  assist: boolean; // features.assist effective value
  bundling: boolean; // features.bundles effective value
  deviceLockdown: boolean; // features.device_lockdown — show report-only banner
  externalLabels: boolean; // features.external_labels — sender/recipient External labels
  guestAccounts: boolean;
  guestInvite: boolean;
  mailSearchBuilder: boolean;
  senderControlCenter: boolean;
  sharedMailWork: boolean;
  sharedMailComments: boolean;
  sharedMailDrafts: boolean;
  sharedMailNotifications: boolean;
  sharedMailAnalytics: boolean;
  sharedMailIntegrations: boolean;
  allowMeetCreate: boolean;
  allowMeetHost: boolean;
  allowDownload: boolean;
}

export interface JmapSession {
  apiUrl: string;
  downloadUrl: string;
  uploadUrl: string;
  eventSourceUrl: string;
  state: string;
  accounts: Record<string, JmapAccount>;
  primaryAccounts: Record<string, string>;
  username: string;
  capabilities: Record<string, unknown>;
  branding?: BrandingConfig;
  purgeConfig?: { deletedPurgeDays: number; spamPurgeDays: number };
  effectiveCapabilities?: EffectiveCapabilitiesPayload;
  dengbao?: { sodMode: boolean; sodClass: string };
  /** Org-configured IT helpdesk email (system_config: help_email). Present only when set. */
  helpEmail?: string;
  /** Server-authenticated principal kind; absent means a normal member. */
  isGuest?: boolean;
}

export interface JmapAccount {
  name: string;
  isPersonal: boolean;
  /** Absent on the caller's own primary account. True for a delegated mailbox
   *  unless the grant includes full_access (#13 shared-mailbox use-surface). */
  isReadOnly?: boolean;
  accountCapabilities: Record<string, unknown>;
}

// ── Core method types ──

/**
 * Runtime method-name list — the single source for the `JmapMethodName` union
 * below and for `isJmapMethodCall`'s closed-set check. Add a new method here
 * and the union grows with it.
 */
export const JMAP_METHOD_NAME_LIST = [
  "Mailbox/get",
  "Mailbox/set",
  "Email/query",
  "Email/changes",
  "Email/get",
  "Email/recoveryReceipt",
  "Email/set",
  "Email/deletedQuery",
  "Email/recover",
  "Email/purge",
  "SearchSnippet/get",
  "EmailSubmission/set",
  "EmailSubmission/get",
  "EmailSubmission/query",
  "EmailSubmission/cancel",
  "MailDraft/get",
  "MailDraft/open",
  "MailDraft/lease",
  "MailDraft/save",
  "MailDraft/replace",
  "Thread/get",
  "Calendar/get",
  "Calendar/set",
  "CalendarEvent/query",
  "CalendarEvent/get",
  "CalendarEvent/set",
  "CalendarEvent/import",
  "CalendarEvent/rsvp",
  "CalendarEvent/counter",
  "CalendarEvent/queryFreeSlots",
  "Calendar/getShared",
  "CalendarEvent/getShared",
  "Calendar/shareGet",
  "Calendar/shareSet",
  "Calendar/delegateList",
  "CalendarEvent/setOccurrence",
  "CalendarEvent/resourceList",
  "CalendarEvent/sendUpdate",
  "AddressBook/get",
  "AddressBook/set",
  "ContactCard/query",
  "ContactCard/get",
  "ContactCard/set",
  "ContactCard/galSearch",
  "ContactCard/findDuplicates",
  "ContactCard/merge",
  "ContactCard/directoryTree",
  "ContactCard/directoryMembers",
  "ContactCard/directorySearch",
  "ContactGroup/get",
  "ContactGroup/query",
  "ContactGroup/set",
  "ContactGroup/expand",
  "Task/get",
  "Task/query",
  "Task/changes",
  "Task/set",
  "TaskComment/get",
  "TaskComment/set",
  "TaskList/get",
  "TaskList/set",
  "TaskListMember/set",
  "TaskList/tasks",
  "TaskList/taskSet",
  "TaskAssigned/get",
  "TaskAssigned/setStatus",
  "Email/nudges",
  "Email/nudgeDismiss",
  "Identity/get",
  "Email/bundles",
  "Reminder/get",
  "Reminder/dismiss",
  "Reminder/snooze",
  "QuickStep/get",
  "QuickStep/set",
  "QuickStep/apply",
  "SavedSearch/list",
  "SavedSearch/set",
  "SavedSearch/delete",
  "EmailTemplate/list",
  "EmailTemplate/set",
  "EmailTemplate/delete",
  "Continuity/get",
  "Continuity/present",
  "MailWork/get",
  "MailWork/changes",
  "MailWork/set",
  "MailWork/action",
  "MailWorkCollaborators/get",
  "MailWorkPolicy/get",
  "MailWorkPolicy/set",
  "MailWorkMetrics/get",
  "MailWorkNotificationPreferences/get",
  "MailWorkNotificationPreferences/set",
  "MailComment/get",
  "MailComment/set",
] as const;

export type JmapMethodName = (typeof JMAP_METHOD_NAME_LIST)[number];

/**
 * Runtime validation for a wire-decoded method call (unvalidated-wire-type-cast
 * hardening): the tuple must be `[name, args, callId]` with the name in the
 * closed method set and a non-empty string call id. Use at every boundary that
 * trusts a decoded JSON payload as a `JmapMethodCall` — never assume the shape.
 */
export function isJmapMethodCall(value: unknown): value is JmapMethodCall {
  return (
    Array.isArray(value) &&
    value.length === 3 &&
    typeof value[0] === "string" &&
    (JMAP_METHOD_NAME_LIST as readonly string[]).includes(value[0]) &&
    typeof value[1] === "object" &&
    value[1] !== null &&
    typeof value[2] === "string" &&
    value[2].length > 0
  );
}

export type JmapMethodCall = [JmapMethodName, unknown, string];

export interface JmapMethodResponse {
  accountId?: string;
  list?: unknown[];
  ids?: string[];
  created?: Record<string, { id: string }>;
  updated?: Record<string, unknown>;
  destroyed?: string[];
  // addresses is set by the S/MIME fail-closed encrypt check (smime_encrypt_no_cert)
  // to name every recipient without a usable cert; the compose UX lists them.
  notCreated?: Record<
    string,
    { type: string; description: string; addresses?: string[] }
  >;
  notUpdated?: Record<string, { type: string; description: string }>;
  notDestroyed?: Record<string, { type: string; description: string }>;
  total?: number;
  position?: number;
  /** Method-level error envelope (the gateway returns name "error" with these). */
  type?: string;
  description?: string;
  /** QuickStep/set returns the new/updated id. */
  id?: string;
  /** QuickStep/apply echoes the applied quick-step id. */
  applied?: string;
  /** TaskList/get — the caller's owned + member lists. */
  lists?: unknown[];
  /** TaskList/tasks — the per-list sync token (task_lists.state_seq). */
  state?: string;
  /** TaskListMember/set — the roster after the add/remove. */
  members?: unknown[];
  notAdded?: Record<string, { type: string; description: string }>;
  notRemoved?: Record<string, { type: string; description: string }>;
}

export interface JmapResponse {
  methodResponses: [JmapMethodName, JmapMethodResponse, string][];
  sessionState?: string;
}

// ── Mail ──

export interface EmailAddress {
  name?: string;
  email: string;
}

export interface Identity {
  id: string;
  name: string;
  email: string;
  isDefault?: boolean;
  mayDelete?: boolean;
}

/** A received/sent attachment (RFC 8621 EmailBodyPart subset, from Email/get). */
export interface Attachment {
  blobId: string;
  type?: string;
  name?: string;
  disposition?: "attachment" | "inline";
  cid?: string | null;
  size?: number;
}

export interface Email {
  id: string;
  threadId?: string;
  mailboxIds: Record<string, boolean>;
  from?: EmailAddress[];
  to?: EmailAddress[];
  cc?: EmailAddress[];
  bcc?: EmailAddress[];
  replyTo?: EmailAddress[];
  subject?: string;
  receivedAt?: string;
  hasAttachment?: boolean;
  /** Attachment filenames, when the body-part projection is fetched. */
  attachmentNames?: string[];
  /** Full attachment list (Email/get with the 'attachments' property). */
  attachments?: Attachment[];
  preview?: string;
  bodyText?: string;
  bodyHTML?: string;
  inlineImages?: Record<string, string>;
  keywords?: Record<string, boolean>;
  bodyValues?: Record<string, { value: string; partId: string }>;
  textBody?: { partId: string; type: string }[];
  priority?: number;
  sensitivity?: string;
  readReceiptRequested?: boolean;
  deliveryReceiptRequested?: boolean;
  voteOptions?: string[];
  scheduledAt?: string;
  pinnedAt?: string;
  deletedAt?: string;
  cryptoType?: string;
  /**
   * SP1 P5 hosted decrypt-on-read outcome for a cryptoType==='smime-encrypted'
   * message. 'decrypted' ⇒ bodyText carries transient cleartext; the others are
   * calm can't-decrypt read-states (no body injected): 'no_key' (reader has no
   * keystore key), 'wrong_key' (rotated/foreign cert), 'error' (malformed /
   * cost-bound). Absent for non-encrypted mail.
   */
  decryptState?: "decrypted" | "no_key" | "wrong_key" | "error";
  /** Inbound S/MIME signature verdict. 'valid' ⇒ verified + trusted + From-match (green shield). */
  smimeStatus?: "valid" | "invalid" | "untrusted";
  smimeSignerEmail?: string;
  smimeSignerCn?: string;
  smimeIssuerCn?: string;
  /** Machine-generated mail (monitoring alerts, delivery reports) — body rendered in mono. */
  mono?: boolean;
  held?: boolean;
  isExternal?: boolean;
  senderDisplayName?: string;
  isNameSpoof?: boolean;
  isFirstTime?: boolean;
  /** Follow-up flag due instant (ISO). Set via Email/set; A6's scan fires the reminder. */
  flagDueAt?: string;
  /** Follow-up flag reminder instant (ISO). Stored only; A6 fires it. */
  flagReminderAt?: string;
  /** SearchSnippet/get highlighted subject — server HTML with <mark>. Sanitize before render. */
  searchSubject?: string;
  /** SearchSnippet/get highlighted body preview — server HTML with <mark>. Sanitize before render. */
  searchPreview?: string;
}

// ── Quick Steps (A2 — user-defined one-click triage macros) ──

/** A single Quick Step action — a subset of the rule-engine action vocabulary. */
export interface QuickStepAction {
  type: "move_to" | "categorize" | "flag" | "mark_read" | "forward_to";
  params?: Record<string, string>;
}

/** A named, ordered macro the user applies from the reading pane. */
export interface QuickStep {
  id: string;
  name: string;
  icon: string;
  position: number;
  actions: QuickStepAction[];
}

// ── Compose templates / Quick Parts (reusable named body snippets) ──

/** A named compose template. `bodyHtml` is user-authored HTML — sanitize before
 *  it enters the editor / outbound mail. */
export interface EmailTemplate {
  id: string;
  name: string;
  subject: string;
  bodyHtml: string;
}

// ── Saved-search folders (named per-mailbox persisted queries the user re-runs) ──

/** A named saved search. `query` is the RAW search string, re-parsed at click time. */
export interface SavedSearch {
  id: string;
  name: string;
  query: string;
  position: number;
}

export interface EmailSubmission {
  id: string;
  emailId: string;
  sendAt: string;
  undoSendBefore?: string;
}

export interface EmailBundle {
  listId: string;
  count: number;
  latestEmailId: string;
  latestReceivedAt: string;
  latestSubject?: string;
}

/** A stale-thread / no-reply nudge (#13, feature.stale_nudges). */
export interface EmailNudge {
  threadId: string;
  emailId: string;
  subject: string;
  counterpart: string;
  kind: "no_reply_sent" | "stale_unanswered";
  lastActivityAt: string;
}

export interface Mailbox {
  id: string;
  name: string;
  role?: string;
  parentId?: string;
  color?: string;
  icon?: string;
  tagType?: string;
  unreadEmails?: number;
  totalEmails?: number;
  isSubscribed?: boolean;
  myRights?: {
    mayReadItems?: boolean;
    mayAddItems?: boolean;
    mayRemoveItems?: boolean;
    maySetSeen?: boolean;
    maySetKeywords?: boolean;
    mayCreateChild?: boolean;
    mayRename?: boolean;
    mayDelete?: boolean;
    maySubmit?: boolean | null;
  };
}

// ── Calendar ──

export interface CalendarRights {
  mayReadItems?: boolean;
  mayReadFreeBusy?: boolean;
  mayReadDetails?: boolean;
  mayAddItems?: boolean;
  mayRemoveItems?: boolean;
  mayRSVP?: boolean;
  mayDelete?: boolean;
}

export interface Calendar {
  id: string;
  name: string;
  color?: string;
  isShared?: boolean;
  isReadOnly?: boolean;
  ownerEmail?: string;
  shareLevel?: CalendarShareLevel;
  myRights?: CalendarRights;
  resourceType?: "personal" | "room" | "equipment";
  capacity?: number | null;
  bookingPolicy?: "auto-accept" | "manual" | "decline-conflict";
}

export type CalendarShareLevel = "freebusy" | "read" | "write" | "admin";

export interface CalendarShare {
  userEmail: string;
  name?: string;
  level: CalendarShareLevel;
}

export interface CalendarResource {
  id: string;
  name: string;
  email: string;
  resourceType: "room" | "equipment";
  capacity?: number | null;
  bookingPolicy: "auto-accept" | "manual" | "decline-conflict";
}

export interface Delegation {
  email: string;
  name?: string;
  permission: string;
}

export interface EventAttendee {
  email: string;
  name?: string;
  role?: string;
  participationStatus?: string;
}

export interface CalendarEvent {
  id: string;
  calendarId: string;
  uid?: string;
  title?: string;
  description?: string;
  location?: string;
  start: string;
  end?: string;
  isAllDay?: boolean;
  timeZone?: string;
  status?: string;
  recurrenceRule?: string | null;
  recurrenceOverrides?: Record<string, unknown> | null;
  sequence?: number;
  attendees?: EventAttendee[];
  organizer?: EmailAddress;
  color?: string | null;
  /** Organizer's own busy status for this event (free↔TRANSPARENT, busy↔OPAQUE, tentative↔status). Orthogonal to attendee RSVP. */
  freeBusyStatus?: string;
  /** Event privacy/CLASS. Non-owner shared viewers are server-side-redacted; the v1 UI is binary (private↔public). */
  privacy?: "public" | "private" | "secret";
  /** Reminder alerts (RFC 8984). Each trigger is an ABSOLUTE ISO instant (start − N, computed client-side). */
  valarm?: EventAlarm[] | null;
  isReadOnly?: boolean;
  /** Meet B1 Task 16 calendar hook (spec §3.2): true once a setjoin Meet is
   *  attached — stamped by meeting_create.sql, cleared only by an
   *  {isMeeting:false} update patch (design #15; there is no delete route
   *  on the meeting itself — the meeting row survives). */
  isMeeting?: boolean;
  /** The join link ('/meet/join/{slug}') when isMeeting is true, else null. */
  meetingUrl?: string | null;
}

/** A single event reminder. `trigger` is an absolute ISO instant; `action` is DISPLAY. */
export interface EventAlarm {
  trigger: string;
  action?: string;
}

export interface FreeSlot {
  start: string;
  end: string;
  score: number;
  contiguousFreeMinutes: number;
  /** Number of requested attendees whose busy intervals overlap this slot (0 = fully free). */
  conflictCount: number;
}

// ── Contacts ──

export interface AddressBook {
  id: string;
  name: string;
}

export interface ContactEmail {
  type: string;
  address: string;
  is_primary?: boolean;
}

// ARCH-004: the directory/GAL returns a person's FULL address set
// (primary ∪ aliases ∪ UPN). Each entry: lowercased address + its kind +
// whether it is the person's primary. Deduplicated, primary first.
export interface DirectoryAddress {
  email: string;
  type: "primary" | "alias" | "upn";
  isPrimary: boolean;
}

export interface ContactPhone {
  type: string;
  number: string;
}

export interface ContactAvatar {
  blobId?: string;
}

export interface ContactCard {
  id: string;
  addressbookId?: string;
  displayName?: string;
  firstName?: string;
  lastName?: string;
  company?: string;
  jobTitle?: string;
  department?: string;
  emails?: ContactEmail[];
  phones?: ContactPhone[];
  notes?: string;
  avatar?: string | ContactAvatar;
  email?: string; // fallback for GAL entries
  // ARCH-004: a GAL/directory person's full address set (primary ∪ aliases ∪ UPN).
  // Present only on GAL result cards, not on personal contacts.
  addresses?: DirectoryAddress[];
}

// ── Personal contact groups (A4 — user-created distribution lists) ──

export interface ContactGroupMember {
  contactId?: string;
  email: string;
  displayName?: string;
}

export interface ContactGroup {
  id: string;
  name: string;
  memberCount: number;
  members?: ContactGroupMember[];
}

// A single recipient produced by expanding a contact group at compose time.
export interface ExpandedRecipient {
  name: string;
  email: string;
}

// ── Tasks ──

export interface Task {
  id: string;
  title: string;
  description?: string;
  status: "needs-action" | "in-progress" | "completed" | "cancelled";
  priority: number;
  startAt?: string;
  dueAt?: string;
  reminderAt?: string;
  completedAt?: string;
  assigneeUserId?: string;
  assigneeEmail?: string;
  assigneeName?: string;
  parentId?: string;
  linkedMessageId?: string;
  /** Partition key of the linked message. REQUIRED alongside linkedMessageId — the
   *  FK tasks(linked_message_id, linked_message_received_at) → messages is MATCH
   *  SIMPLE, so without this the link is unenforced. */
  linkedMessageReceivedAt?: string;
  linkedEventId?: string;
  categories?: string[];
  recurrenceRule?: string | null;
  /** Manual (drag/reorder) fractional sort key — QoL #20. */
  sortOrder?: number;
  /** In-task lightweight checklist — QoL #21. Whole-array replace on save. */
  checklist?: ChecklistItem[];
  createdAt?: string;
  updatedAt?: string;
  /** Shared task lists (Phase 1): set when this task lives in a shared list
   *  (personal tasks never carry this). */
  listId?: string;
  /** Present only on TaskList/tasks reads (list-scoped) — whose task this is. */
  creatorEmail?: string;
  creatorName?: string;
}

/** One in-task checklist step (QoL #21). `id` is server-assigned. */
export interface ChecklistItem {
  id: string;
  text: string;
  done: boolean;
}

/** One task activity-feed entry (QoL #17): a comment or a system change row. */
export interface TaskActivity {
  id: string;
  kind: "comment" | "status_change" | "assignee_change" | "due_change";
  body: string | null;
  meta: { old?: unknown; new?: unknown } | null;
  authorName: string;
  authorEmail: string;
  mentionedUserIds: number[];
  createdAt: string;
}

// ── Shared / team task lists (Phase 1) ──

export interface TaskListMember {
  userId: string;
  email: string;
  displayName: string;
  role: "owner" | "member";
}

export interface TaskList {
  id: string;
  name: string;
  color: string | null;
  state: string;
  role?: "owner" | "member";
  memberCount?: number;
  openCount?: number;
  members?: TaskListMember[];
}

/** One row from TaskAssigned/get — "assigned to me" (cross-mailbox, Phase 1). */
export interface AssignedTask {
  id: string;
  title: string;
  description?: string;
  status: "needs-action" | "in-progress" | "completed" | "cancelled";
  priority: number;
  startAt?: string;
  dueAt?: string;
  completedAt?: string;
  checklist?: ChecklistItem[];
  listId: string | null;
  listName: string | null;
  ownerEmail: string;
  ownerName: string;
  updatedAt?: string;
}
