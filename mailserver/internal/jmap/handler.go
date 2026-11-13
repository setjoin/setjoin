package jmap

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"setjoin.com/mailserver/internal/admin"
	"setjoin.com/mailserver/internal/audit"
	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/blob"
	servercontinuity "setjoin.com/mailserver/internal/continuity"
	"setjoin.com/mailserver/internal/metrics"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/mailserver/internal/reducercall"
	"setjoin.com/shared/dbscope"
	"setjoin.com/shared/httputil"
	"setjoin.com/shared/identity"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

// --- JMAP wire types (RFC 8620) ---

type BatchRequest struct {
	Using       []string          `json:"using"`
	MethodCalls []MethodCall      `json:"methodCalls"`
	CreatedIDs  map[string]string `json:"createdIds,omitempty"`
}

// Request is the HTTP wire spelling retained for callers. BatchRequest is the
// transport-neutral execution input shared by HTTP and WebSocket.
type Request = BatchRequest

// MethodCall encodes the 3-element JSON array [method, args, callId].
type MethodCall struct {
	Name     string
	Args     json.RawMessage
	ClientID string
}

func (m *MethodCall) UnmarshalJSON(data []byte) error {
	var raw [3]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if err := json.Unmarshal(raw[0], &m.Name); err != nil {
		return err
	}
	m.Args = raw[1]
	return json.Unmarshal(raw[2], &m.ClientID)
}

func (m MethodCall) MarshalJSON() ([]byte, error) {
	nameJSON, _ := json.Marshal(m.Name)
	clientIDJSON, _ := json.Marshal(m.ClientID)
	return json.Marshal([]json.RawMessage{nameJSON, m.Args, clientIDJSON})
}

type Response struct {
	SessionState    string            `json:"sessionState"`
	MethodResponses []MethodCall      `json:"methodResponses"`
	CreatedIDs      map[string]string `json:"createdIds,omitempty"`
}

const (
	maxCallsInBatch = 32
	maxCallArgsSize = 2_000_000
)

// BatchResult is the single outcome of JMAP batch execution. Exactly one of
// Response and Problem is non-nil. Transports own only their RFC-specific
// encoding (HTTP Problem Details vs RFC 8887 RequestError).
type BatchResult struct {
	Response *Response
	Problem  *ProblemDetails
}

// Error represents a JMAP method-level error. When serialized, it produces an
// RFC 8620 §7.1 Problem Details object (RFC 7807 application/problem+json) with
// a URN-prefixed type, HTTP status code, and detail string.
//
// Usage is unchanged — construction sites use short type strings and Description:
//
//	json.Marshal(Error{Type: "invalidArguments", Description: "missing field"})
//
// The JSON output is RFC 8620–compliant:
//
//	{"type":"urn:ietf:params:jmap:error:invalidArguments","status":400,"detail":"missing field"}
type Error struct {
	Type        string `json:"-"`
	Description string `json:"-"`
}

// MarshalJSON serialises the Error as an RFC 7807 Problem Details object.
func (e Error) MarshalJSON() ([]byte, error) {
	return json.Marshal(ProblemDetails{
		Type:   "urn:ietf:params:jmap:error:" + e.Type,
		Status: errorStatus(e.Type),
		Detail: e.Description,
	})
}

// UnmarshalJSON deserialises an RFC 7807 Problem Details object back into an Error,
// stripping the urn:ietf:params:jmap:error: prefix from the type.
func (e *Error) UnmarshalJSON(data []byte) error {
	var pd ProblemDetails
	if err := json.Unmarshal(data, &pd); err != nil {
		return err
	}
	e.Type = strings.TrimPrefix(pd.Type, "urn:ietf:params:jmap:error:")
	e.Description = pd.Detail
	return nil
}

// errorStatus maps JMAP error type strings to HTTP status codes per RFC 8620 §7.1.
func errorStatus(typ string) int {
	switch typ {
	case "invalidArguments", "invalidPatch", "invalidProperties",
		"notJSON", "notRequest", "unknownMethod", "unknownCapability",
		"invalidResultReference":
		return 400
	case "accountNotFound", "accountNotSupportedByMethod",
		"anchorNotFound", "blobNotFound", "calendarEventNotFound",
		"emailNotFound", "mailboxNotFound", "stateMismatch",
		"singleton", "cannotCalculateChanges", "requestTooLarge":
		return 400
	case "accountReadOnly":
		return 403
	case "tooLarge":
		return 413
	case "rateLimit":
		return 429
	default:
		// serverFail, serverUnavailable, serverPartial, forbidden,
		// overQuota, serviceUnavailable — all server-side.
		return 500
	}
}

// ProblemDetails is an RFC 7807 Problem Details object.
type ProblemDetails struct {
	Type   string `json:"type"`
	Status int    `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// WriteProblem sends an RFC 7807 Problem Details JSON response at the HTTP level.
func WriteProblem(w http.ResponseWriter, status int, problemType, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(ProblemDetails{
		Type:   "urn:ietf:params:jmap:error:" + problemType,
		Status: status,
		Detail: detail,
	})
}

func mustUser(w http.ResponseWriter, r *http.Request) *auth.Claims {
	claims := auth.UserFromContext(r.Context())
	if claims == nil {
		httputil.WriteProblem(w, r, httputil.NewUnauthorizedProblem("authentication required"))
		return nil
	}
	return claims
}

// --- Handler ---

// MethodFunc is the signature all JMAP method implementations must satisfy.
// Returns (responseMethodName, responseArgs) — name is "error" on failure.
type MethodFunc func(ctx context.Context, user *auth.Claims, args json.RawMessage) (string, json.RawMessage)

// JMAP capability URIs (the `using` currency, RFC 8620 §3.2). The vendor URN
// for setjoin extensions is VendorCapability (mail.go).
const (
	capCore       = "urn:ietf:params:jmap:core"
	capMail       = "urn:ietf:params:jmap:mail"
	capSubmission = "urn:ietf:params:jmap:submission"
	capCalendars  = "urn:ietf:params:jmap:calendars"
	capContacts   = "urn:ietf:params:jmap:contacts"
	capTasks      = "urn:ietf:params:jmap:tasks"
	capReminders  = "urn:setjoin:params:jmap:reminders"
	capBlob       = "urn:ietf:params:jmap:blob"
)

// gateClass is the #13 shared-mailbox METHOD GATE column of the registry:
// when a request's accountId is a DELEGATED mailbox (not the caller's
// primary), RLS gives it SCOPE but not PERMISSION LEVEL — this class says
// which mailbox_delegates grant the method requires. On the caller's own
// primary account the gate never fires.
type gateClass uint8

const (
	// gatePersonal (the zero value — fail-closed default): valid on the
	// caller's primary account ONLY; every delegated accountId is rejected.
	gatePersonal gateClass = iota
	// gateRead: any MAIL delegate grant (read|send_as|send_on_behalf|
	// full_access). manage_calendar is deliberately NOT a mail grant — a
	// calendar delegate is not a mail reader; calendar delegation flows
	// through its own reducer paths (Calendar/delegateList, delegate rsvp),
	// never through accountId switching.
	gateRead
	// gateMutate: full_access only.
	gateMutate
	// gateSubmit: send_as | send_on_behalf | full_access. From-address pin
	// (send.sql): send_as|full_access may set From = the shared address;
	// send_on_behalf keeps From = the delegate's own address (a shared From
	// on an on-behalf grant is rejected by the reducer with BZ003).
	gateSubmit
	// gateCollaborate: shared-mail work/comments/drafts may be changed by a
	// send-capable delegate. Reducers remain the action-specific authority.
	gateCollaborate
)

func (c gateClass) String() string {
	switch c {
	case gateRead:
		return "read"
	case gateMutate:
		return "mutate"
	case gateSubmit:
		return "submit"
	case gateCollaborate:
		return "collaborate"
	default:
		return "personal"
	}
}

// allows reports whether a delegate holding `grants` may call a method of
// this class. gatePersonal allows nothing — delegated access is opt-in per
// method class, never default.
func (c gateClass) allows(grants []string) bool {
	for _, g := range grants {
		switch c {
		case gateRead:
			if g == "read" || g == "send_as" || g == "send_on_behalf" || g == "full_access" {
				return true
			}
		case gateMutate:
			if g == "full_access" {
				return true
			}
		case gateSubmit:
			if g == "send_as" || g == "send_on_behalf" || g == "full_access" {
				return true
			}
		case gateCollaborate:
			if g == "send_as" || g == "send_on_behalf" || g == "full_access" {
				return true
			}
		}
	}
	return false
}

// invocationMetadata is registry-derived execution policy for one method
// invocation. It travels as a typed value with the invocation; no private
// context key may recreate a second gate-policy channel.
type invocationMetadata struct {
	Capability string
	App        string
	Gate       gateClass
}

// invocationContext carries the ordinary cancellation/deadline context plus
// the registry metadata for the method currently executing. It implements
// context.Context through embedding, while making the metadata a typed field
// rather than an untyped context value.
type invocationContext struct {
	context.Context
	Metadata invocationMetadata
}

type invocation struct {
	name     string
	fn       MethodFunc
	metadata invocationMetadata
}

// methodEntry is the single registry record for a JMAP method (c4): its
// handler, the capability URI the request's `using` array must declare, the
// app the B8.4 entitlement gate checks ("" = ungated), and the #13 delegate
// gate class. This one table drives Dispatch, HasCapability, the app gate,
// and the shared-mailbox method gate; the golden test (registry_test.go ×
// testdata/methods.golden) pins every row, so a method added with the wrong
// capability/app/gate fails the table, not production.
type methodEntry struct {
	fn         MethodFunc
	capability string
	app        string // "" | "calendar" | "contacts" | "tasks"
	gate       gateClass
}

// jmapEntitlementGate is an optional per-method access gate injected on
// JMAPHandler (B8.4). Allowed returns true when the user may call the app.
// userID is the authenticated user's ID from JWT claims.
// app is one of "calendar", "contacts", "tasks".
type jmapEntitlementGate interface {
	Allowed(ctx context.Context, userID int64, app string) bool
}

// JMAPHandler dispatches JMAP method calls to registered implementations.
// Phase 3 will fill in Mailbox/*, Email/*, Thread/*, EmailSubmission/*, etc.
// For now (Phase 2), only the framework and Core/echo exist.
type JMAPHandler struct {
	pool            *pgxpool.Pool
	caller          reducerCaller // tenant-scoped reducer-call seam over the app pool (see caller.go)
	workerCaller    reducerCaller // BYPASSRLS reducer-call seam over the worker pool — cross-tenant legs only (native-RLS W4)
	workerPool      *pgxpool.Pool // BYPASSRLS pool for RAW (non-reducer) cross-mailbox reads — the Blob/* ownership checks (native-RLS W7)
	methods         map[string]methodEntry
	hostname        string
	logger          *slog.Logger
	minio           *minio.Client
	bucket          string
	maxUploadSize   int
	metrics         *metrics.Handler
	entitlementGate jmapEntitlementGate  // nil = no gating (unit-test / legacy)
	toggles         *toggle.FeatureFlags // nil = no toggle gating (unit-test / legacy)
	encryptOps      smimeEncryptOps      // SP1 encrypt-at-submission seam; nil = no infra (fail-closed if encrypt requested)
	decryptLimiter  middleware.Limiter   // SP1 P5 per-user decrypt-on-read cost bound; nil = allow (unit-test / unconfigured)
	continuity      *servercontinuity.Service
	jwt             *auth.JWTProvider // exact E3 mail-attachment transfer mint; nil until wired
	// Reclamation/quota policy for the JMAP upload path (er6 residual rollup on
	// occ_2ee199); set once at startup via SetReclamationPolicy, mirroring
	// blob.Handler.SetReclamationPolicy (D-MAILSERVER-INTERNAL-BLOB-002). Zero
	// values are safe: the default grace window applies and per-user
	// enforcement stays OFF (accounting is still recorded) — exactly the
	// pre-wiring behavior of this path.
	reclaimGraceMinutes int
	userQuotaBytes      int64
}

// NewJMAPHandler builds the JMAP handler. pool is the tenant-scoped app pool;
// workerPool is the setjoin_worker (BYPASSRLS) pool used ONLY for the cross-tenant
// legs — today only EmailSubmission/set, whose reducer chain (send → deliver)
// writes the local-recipient copies into OTHER mailboxes (native-RLS W4). When
// DB_WORKER_DSN is unset, workerPool aliases pool (W1b), so this is INERT until
// the W6 FORCE flip. In unit tests workerPool may be nil; only the cross-tenant
// handlers touch workerCaller, and they are exercised through an injected fake.
func NewJMAPHandler(pool *pgxpool.Pool, workerPool pgxutil.WorkerPool, hostname string, minioClient *minio.Client, bucket string, maxUploadSize int, logger *slog.Logger) *JMAPHandler {
	h := &JMAPHandler{
		pool:          pool,
		caller:        reducercall.PoolCaller{Pool: pool},
		workerCaller:  reducercall.PoolCaller{Pool: workerPool.Pool},
		workerPool:    workerPool.Pool,
		methods:       make(map[string]methodEntry),
		hostname:      hostname,
		logger:        logger,
		minio:         minioClient,
		bucket:        bucket,
		maxUploadSize: maxUploadSize,
		// SP1 P5: cost-bound decrypt-on-read. RSA unwrap is expensive; a poller
		// forcing repeated decrypts is a DoS (spec C5/P1-9). 120 decrypts/user/min
		// is generous for interactive reading. A denied op serves the encrypted
		// read-state (never plaintext) — fail-closed-to-ciphertext.
		decryptLimiter: middleware.NewRateLimiter(120, time.Minute),
	}
	// SP1: the DB/S3-backed encrypt-at-submission seam is available only when the
	// infra is present. With no pool or no S3, encryptOps stays nil → an
	// encrypt-requested submission fails closed (never sends plaintext).
	if pool != nil && minioClient != nil {
		h.encryptOps = &poolEncryptOps{h: h}
	}
	h.registerMethods()
	return h
}

func (h *JMAPHandler) SetMetrics(m *metrics.Handler) { h.metrics = m }

// SetReclamationPolicy configures the JMAP upload path's reclamation arming and
// per-user blob storage enforcement, mirroring blob.Handler.SetReclamationPolicy
// (D-MAILSERVER-INTERNAL-BLOB-002): JMAP uploads run the SAME blob_upload_account
// reducer as the blob gateway, so the measured-bytes charge bound must be
// enforced on this path too — occ_2ee199 added the reducer's bound check but
// left this caller passing enforcement-OFF forever (er6 residual rollup).
// graceMinutes selects the reclamation arming window (<= 0 keeps
// blob.DefaultReclaimGraceMinutes); quotaBytes is the per-user charged-bytes
// bound, with values <= 0 leaving enforcement OFF (accounting is still
// recorded). The bound check itself runs inside blob_upload_account under the
// per-user FOR UPDATE row lock, so simultaneous uploads can never exceed it.
// Called once from main; zero-value Handlers (unit tests) keep the old
// defaults.
func (h *JMAPHandler) SetReclamationPolicy(graceMinutes int, quotaBytes int64) {
	h.reclaimGraceMinutes = graceMinutes
	h.userQuotaBytes = quotaBytes
}

// reclaimGrace resolves the effective JMAP-upload reclamation arming window
// (blob.Handler's same rule).
func (h *JMAPHandler) reclaimGrace() int {
	if h.reclaimGraceMinutes > 0 {
		return h.reclaimGraceMinutes
	}
	return blob.DefaultReclaimGraceMinutes
}

// SetEntitlementChecker injects the per-app entitlement gate used by Dispatch
// to block gated JMAP methods (B8.4). When nil (the default), no gating is applied.
func (h *JMAPHandler) SetEntitlementChecker(g jmapEntitlementGate) { h.entitlementGate = g }

// HasAppEntitlement exposes the already-injected user-id entitlement authority
// to the push transports. It is intentionally fail-closed when the handler or
// checker is absent: callers use it only for guest Chat/Drive/Meet
// subscriptions, where an unverified subscription would leak app-scoped ids
// and presence. Ordinary member push topology does not call this method.
func (h *JMAPHandler) HasAppEntitlement(ctx context.Context, userID int64, app string) bool {
	return h != nil && h.entitlementGate != nil && h.entitlementGate.Allowed(ctx, userID, app)
}

// SetFeatureFlags injects the live feature-toggle set. Used by the session
// handler to gate the dengbao block behind SodMode. When nil (the default,
// unit-test / legacy), the dengbao block is omitted — identical to SodMode=OFF.
func (h *JMAPHandler) SetFeatureFlags(f *toggle.FeatureFlags) { h.toggles = f }

// SetJWTProvider wires the gateway's narrow mail-attachment token signer.
func (h *JMAPHandler) SetJWTProvider(p *auth.JWTProvider) { h.jwt = p }

func (h *JMAPHandler) SetContinuityService(service *servercontinuity.Service) {
	h.continuity = service
}

// registerMethods is the ONE method table: name → (handler, capability, app).
// Every row is pinned by testdata/methods.golden — update the golden file
// (UPDATE_GOLDEN=1 go test ./internal/jmap/ -run TestMethodRegistryGolden)
// when adding a method, and keep the webmail capability table
// (webmail/src/lib/jmap/client.ts usingFor) in the same commit.
func (h *JMAPHandler) registerMethods() {
	// reg registers a PRIMARY-ACCOUNT-ONLY method: gate is the zero value
	// gatePersonal, so a delegated shared-mailbox accountId is rejected.
	reg := func(name, capability, app string, fn MethodFunc) {
		h.methods[name] = methodEntry{fn: fn, capability: capability, app: app}
	}
	// regMail registers a method ALSO valid on a delegated shared-mailbox
	// account, at the given #13 gate class (mail methods carry no app gate).
	regMail := func(name, capability string, gate gateClass, fn MethodFunc) {
		h.methods[name] = methodEntry{fn: fn, capability: capability, gate: gate}
	}

	// RFC 8620 Core
	reg("Core/echo", capCore, "", h.coreEcho)
	regMail("Continuity/get", capMail, gateRead, h.continuityGet)
	regMail("Continuity/present", capMail, gateRead, h.continuityPresent)

	// JMAP Mail (RFC 8621). Email/deletedQuery|recover|purge|bundles are
	// setjoin vendor methods over the mail data model — they stay under the
	// mail capability the clients already declare.
	regMail("Mailbox/get", capMail, gateRead, h.mailboxGet)
	regMail("Mailbox/changes", capMail, gateRead, h.mailboxChanges)
	regMail("Mailbox/query", capMail, gateRead, h.mailboxQuery)
	regMail("Mailbox/queryChanges", capMail, gateRead, h.mailboxQueryChanges)
	regMail("Mailbox/set", capMail, gateMutate, h.mailboxSet)
	regMail("Email/get", capMail, gateRead, h.emailGet)
	regMail("Email/recoveryReceipt", capMail, gateRead, h.emailRecoveryReceipt)
	regMail("Email/query", capMail, gateRead, h.emailQuery)
	regMail("Email/changes", capMail, gateRead, h.emailChanges)
	regMail("Email/set", capMail, gateMutate, h.emailSet)
	regMail("Email/deletedQuery", capMail, gateRead, h.emailDeletedQuery)
	regMail("Email/recover", capMail, gateMutate, h.emailRecover)
	regMail("Email/purge", capMail, gateMutate, h.emailPurge)
	regMail("Email/bundles", capMail, gateRead, h.emailBundles)             // B5.2 newsletter bundles
	regMail("Email/nudges", capMail, gateRead, h.emailNudges)               // #13 stale-thread nudges (feature.stale_nudges)
	regMail("Email/nudgeDismiss", capMail, gateMutate, h.emailNudgeDismiss) // #13 dismiss a nudge
	regMail("Thread/get", capMail, gateRead, h.threadGet)
	regMail("Thread/changes", capMail, gateRead, h.threadChanges)
	regMail("SearchSnippet/get", capMail, gateRead, h.searchSnippetGet)
	regMail("MailWork/get", capMail, gateRead, h.mailWorkGet)
	regMail("MailWork/changes", capMail, gateRead, h.mailWorkChanges)
	regMail("MailWork/set", capMail, gateCollaborate, h.mailWorkSet)
	regMail("MailWork/action", capMail, gateCollaborate, h.mailWorkAction)
	regMail("MailWorkCollaborators/get", capMail, gateRead, h.mailWorkCollaboratorsGet)
	regMail("MailWorkPolicy/get", capMail, gateRead, h.mailWorkPolicyGet)
	regMail("MailWorkPolicy/set", capMail, gateCollaborate, h.mailWorkPolicySet)
	regMail("MailWorkNotificationPreferences/get", capMail, gateRead, h.mailWorkNotificationPreferencesGet)
	regMail("MailWorkNotificationPreferences/set", capMail, gateCollaborate, h.mailWorkNotificationPreferencesSet)
	regMail("MailWorkMetrics/get", capMail, gateRead, h.mailWorkMetricsGet)
	regMail("MailComment/get", capMail, gateRead, h.mailCommentGet)
	regMail("MailComment/set", capMail, gateCollaborate, h.mailCommentSet)
	regMail("MailDraft/get", capMail, gateRead, h.mailDraftGet)
	regMail("MailDraft/open", capMail, gateCollaborate, h.mailDraftOpen)
	regMail("MailDraft/lease", capMail, gateCollaborate, h.mailDraftLease)
	regMail("MailDraft/save", capMail, gateCollaborate, h.mailDraftSave)
	regMail("MailDraft/replace", capMail, gateCollaborate, h.mailDraftReplace)

	// JMAP Submission (RFC 8621 §6–7). Identity/* lives under the submission
	// capability per RFC 8621 §6 — it was mis-gated under core pre-registry.
	// Identity/* stays PERSONAL: the delegate From Select consumes the session
	// accounts payload (vendor delegateGrants), not Identity/get on the
	// shared account.
	regMail("EmailSubmission/set", capSubmission, gateSubmit, h.emailSubmissionSet)
	regMail("EmailSubmission/cancel", capSubmission, gateSubmit, h.emailSubmissionCancel)
	regMail("EmailSubmission/get", capSubmission, gateSubmit, h.emailSubmissionGet)
	regMail("EmailSubmission/query", capSubmission, gateSubmit, h.emailSubmissionQuery)
	reg("Identity/get", capSubmission, "", h.identityGet)
	reg("Identity/changes", capSubmission, "", h.identityChanges)
	reg("Identity/set", capSubmission, "", h.identitySet)

	// JMAP Calendars (draft), incl. free/busy, rsvp, and the A3 parity surface
	// (shared reads, sharing CRUD, occurrence edit, delegate respond, resource
	// list, send update — see calendar_a3.go).
	reg("Calendar/get", capCalendars, "calendar", h.calendarGet)
	reg("Calendar/changes", capCalendars, "calendar", h.calendarChanges)
	reg("Calendar/set", capCalendars, "calendar", h.calendarSet)
	reg("Calendar/getShared", capCalendars, "calendar", h.calendarGetShared)
	reg("Calendar/shareGet", capCalendars, "calendar", h.calendarShareGet)
	reg("Calendar/shareSet", capCalendars, "calendar", h.calendarShareSet)
	reg("Calendar/delegateList", capCalendars, "calendar", h.calendarDelegateList)
	reg("CalendarEvent/get", capCalendars, "calendar", h.calendarEventGet)
	reg("CalendarEvent/query", capCalendars, "calendar", h.calendarEventQuery)
	reg("CalendarEvent/changes", capCalendars, "calendar", h.calendarEventChanges)
	reg("CalendarEvent/set", capCalendars, "calendar", h.calendarEventSet)
	reg("CalendarEvent/import", capCalendars, "calendar", h.calendarEventImport)
	reg("CalendarEvent/freeBusy", capCalendars, "calendar", h.calendarEventFreeBusy)
	reg("CalendarEvent/queryFreeSlots", capCalendars, "calendar", h.calendarEventQueryFreeSlots)
	reg("CalendarEvent/rsvp", capCalendars, "calendar", h.calendarEventRsvp)
	reg("CalendarEvent/counter", capCalendars, "calendar", h.calendarEventCounter)
	reg("CalendarEvent/getShared", capCalendars, "calendar", h.calendarEventGetShared)
	reg("CalendarEvent/setOccurrence", capCalendars, "calendar", h.calendarEventSetOccurrence)
	reg("CalendarEvent/resourceList", capCalendars, "calendar", h.calendarEventResourceList)
	reg("CalendarEvent/sendUpdate", capCalendars, "calendar", h.calendarEventSendUpdate)

	// JMAP Contacts (draft) + A4 personal contact groups (contact_group.go).
	reg("AddressBook/get", capContacts, "contacts", h.addressBookGet)
	reg("AddressBook/changes", capContacts, "contacts", h.addressBookChanges)
	reg("AddressBook/set", capContacts, "contacts", h.addressBookSet)
	reg("ContactCard/get", capContacts, "contacts", h.contactCardGet)
	reg("ContactCard/query", capContacts, "contacts", h.contactCardQuery)
	reg("ContactCard/changes", capContacts, "contacts", h.contactCardChanges)
	reg("ContactCard/set", capContacts, "contacts", h.contactCardSet)
	reg("ContactCard/findDuplicates", capContacts, "contacts", h.contactCardFindDuplicates)
	reg("ContactCard/merge", capContacts, "contacts", h.contactCardMerge)
	reg("ContactCard/galSearch", capContacts, "contacts", h.contactCardGalSearch)
	reg("ContactCard/directoryTree", capContacts, "contacts", h.contactCardDirectoryTree)
	reg("ContactCard/directoryMembers", capContacts, "contacts", h.contactCardDirectoryMembers)
	reg("ContactCard/directorySearch", capContacts, "contacts", h.contactCardDirectorySearch)
	reg("ContactGroup/get", capContacts, "contacts", h.contactGroupGet)
	reg("ContactGroup/query", capContacts, "contacts", h.contactGroupQuery)
	reg("ContactGroup/set", capContacts, "contacts", h.contactGroupSet)
	reg("ContactGroup/expand", capContacts, "contacts", h.contactGroupExpand)

	// JMAP Tasks (draft)
	reg("Task/get", capTasks, "tasks", h.taskGet)
	reg("Task/query", capTasks, "tasks", h.taskQuery)
	reg("Task/changes", capTasks, "tasks", h.taskChanges)
	reg("Task/set", capTasks, "tasks", h.taskSet)
	// TaskComment/* — QoL #17 activity-feed extension over the tasks capability.
	reg("TaskComment/get", capTasks, "tasks", h.taskActivityGet)
	reg("TaskComment/set", capTasks, "tasks", h.taskCommentCreate)
	// TaskList/* + TaskAssigned/* — shared/team task lists (Phase 1, V112).
	// User-scoped (claims.UserID), gated by feature.shared_task_lists — see
	// task_lists.go.
	reg("TaskList/get", capTasks, "tasks", h.taskListGet)
	reg("TaskList/set", capTasks, "tasks", h.taskListSet)
	reg("TaskListMember/set", capTasks, "tasks", h.taskListMemberSet)
	reg("TaskList/tasks", capTasks, "tasks", h.taskListTasks)
	reg("TaskList/taskSet", capTasks, "tasks", h.taskListTaskSet)
	reg("TaskAssigned/get", capTasks, "tasks", h.taskAssignedGet)
	reg("TaskAssigned/setStatus", capTasks, "tasks", h.taskAssignedSetStatus)

	// Reminders (A6 — Scheduled Actions remind handler surface)
	reg("Reminder/get", capReminders, "", h.reminderGet)
	reg("Reminder/dismiss", capReminders, "", h.reminderDismiss)
	reg("Reminder/snooze", capReminders, "", h.reminderSnooze)

	// setjoin vendor surfaces without a standard data model: Quick Steps (A2),
	// saved searches, compose templates. Gated under the vendor URN — they were
	// mis-bucketed under core pre-registry (c4).
	reg("QuickStep/get", VendorCapability, "", h.quickStepGet)
	reg("QuickStep/set", VendorCapability, "", h.quickStepSet)
	reg("QuickStep/apply", VendorCapability, "", h.quickStepApply)
	reg("SavedSearch/list", VendorCapability, "", h.savedSearchList)
	reg("SavedSearch/set", VendorCapability, "", h.savedSearchSet)
	reg("SavedSearch/delete", VendorCapability, "", h.savedSearchDelete)
	reg("EmailTemplate/list", VendorCapability, "", h.emailTemplateList)
	reg("EmailTemplate/set", VendorCapability, "", h.emailTemplateSet)
	reg("EmailTemplate/delete", VendorCapability, "", h.emailTemplateDelete)

	// JMAP Blob Management (RFC 9404)
	reg("Blob/get", capBlob, "", h.blobGet)
	reg("Blob/copy", capBlob, "", h.blobCopy)
	reg("Blob/lookup", capBlob, "", h.blobLookup)
}

// RegisterMethod allows Phase 3 (and later) to add method implementations.
// Dynamically registered methods keep the pre-registry defaults: core
// capability, no app gate, gatePersonal (delegated accountIds fail closed).
func (h *JMAPHandler) RegisterMethod(name string, fn MethodFunc) {
	h.methods[name] = methodEntry{fn: fn, capability: capCore}
}

// parseAccountID validates a JMAP accountId against the authenticated user:
// the caller's PRIMARY mailbox (the ARCH-003 rule, resolved via the shared
// identity seam — never users.id), OR a mailbox the caller holds a
// mailbox_delegates grant on (#13 shared-mailbox use-surface). For a
// delegated accountId the METHOD GATE fires: the dispatched method's
// registry gateClass (threaded through ctx by Dispatch) must be satisfied by
// the caller's grant levels — RLS scopes the data, the gate scopes the
// permission level. A grant-less mailbox, a non-primary mailbox with no
// grant, no primary mailbox at all, or any lookup error all collapse to
// accountNotFound (fail-closed, no existence disclosure); a granted mailbox
// whose level is insufficient for THIS method is a forbidden method error
// (the caller legitimately knows the mailbox exists).
//
// The delegate check is per-request and uncached — a revocation 403s the
// very next call (the design's full-pane revoked state).
//
// When h.pool is nil (unit-test mode), falls back to comparing accountID against
// userID so existing tests continue to work.
func (h *JMAPHandler) parseAccountID(ctx context.Context, reqAccountID string, userID int64) (int64, json.RawMessage) {
	if reqAccountID == "" {
		errJSON, _ := json.Marshal(Error{Type: "accountNotFound", Description: "accountId is required"})
		return 0, errJSON
	}
	accountID, err := strconv.ParseInt(reqAccountID, 10, 64)
	if err != nil || accountID <= 0 {
		errJSON, _ := json.Marshal(Error{Type: "accountNotFound", Description: "invalid accountId"})
		return 0, errJSON
	}

	if h.pool != nil {
		own, grants, err := identity.ValidateAccountID(ctx, h.pool, accountID, userID, h.delegateGrants)
		if err != nil || (!own && len(grants) == 0) {
			errJSON, _ := json.Marshal(Error{Type: "accountNotFound", Description: "accountId does not match authenticated user"})
			return 0, errJSON
		}
		if !own {
			// Delegated account: gate by typed registry metadata. A context
			// outside a resolved invocation is gatePersonal and fails closed.
			class := gatePersonal
			if invCtx, ok := ctx.(invocationContext); ok {
				class = invCtx.Metadata.Gate
			}
			if !class.allows(grants) {
				errJSON, _ := json.Marshal(Error{Type: "forbidden", Description: "insufficient delegate permission for this method"})
				return 0, errJSON
			}
		}
		var lifecycleAllowed bool
		if err := h.pool.QueryRow(ctx, `SELECT mailbox_lifecycle_access_allowed($1)`, accountID).Scan(&lifecycleAllowed); err != nil || !lifecycleAllowed {
			errJSON, _ := json.Marshal(Error{Type: "forbidden", Description: "mailbox access is suspended or detached"})
			return 0, errJSON
		}
	} else {
		// Nil pool fallback: compare against userID for unit-test backward compat.
		if accountID != userID {
			errJSON, _ := json.Marshal(Error{Type: "accountNotFound", Description: "accountId does not match authenticated user"})
			return 0, errJSON
		}
	}

	return accountID, nil
}

// delegateGrants is the identity.DelegateGrants implementation: the
// mailbox_delegates.permission values userID holds on mailboxID.
//
// ⚠ It MUST run via dbscope.RunUserScoped — mailbox_delegates is FORCE-RLS
// (V090) and fail-closed with no GUC, so a bare h.pool query compiles, passes
// superuser-pool unit tests, and silently returns ZERO rows under the live
// flip (V090's delegate arm admits app.current_user_id). Per-request and
// uncached by design: revocation must take effect on the next call.
func (h *JMAPHandler) delegateGrants(ctx context.Context, mailboxID, userID int64) ([]string, error) {
	var grants []string
	err := dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT permission FROM mailbox_delegates WHERE mailbox_id = $1 AND user_id = $2`,
			mailboxID, userID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var g string
			if err := rows.Scan(&g); err != nil {
				return err
			}
			grants = append(grants, g)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return grants, nil
}

func (h *JMAPHandler) auditMailbox(ctx context.Context, userID int64, mailboxID int64, action string, msgID *int64) {
	if h.pool == nil { // unit-test mode (nil pool): audit logging is best-effort
		return
	}
	h.pool.Exec(ctx,
		`INSERT INTO mailbox_audit_log (mailbox_id, actor_user_id, action, message_id)
		 VALUES ($1, $2, $3, $4)`,
		mailboxID, userID, action, msgID)
}

// capabilityForMethod returns the JMAP capability URI a method requires.
// Registry-driven (c4). Unknown methods keep the pre-registry default (core)
// so they pass the capability gate and reach Dispatch's unknownMethod error —
// the RFC 8620 method-level error — instead of a request-level rejection.
func (h *JMAPHandler) capabilityForMethod(method string) string {
	return h.resolveInvocation(method).metadata.Capability
}

// resolveInvocation is the only method-name → executable metadata projection.
// Unknown methods deliberately retain the historic core capability and a
// personal fail-closed gate so they reach Dispatch's method-level
// unknownMethod response after request-level capability validation.
func (h *JMAPHandler) resolveInvocation(method string) invocation {
	entry, ok := h.methods[method]
	if !ok {
		return invocation{
			name: method,
			metadata: invocationMetadata{
				Capability: capCore,
				Gate:       gatePersonal,
			},
		}
	}
	return invocation{
		name: method,
		fn:   entry.fn,
		metadata: invocationMetadata{
			Capability: entry.capability,
			App:        entry.app,
			Gate:       entry.gate,
		},
	}
}

// extractCreatedIDs parses created IDs from a /set method response.
// Returns nil for non-/set methods, saving the JSON unmarshal cost.
func extractCreatedIDs(result json.RawMessage) map[string]string {
	if result == nil {
		return nil
	}
	var setResult struct {
		Created map[string]struct {
			ID string `json:"id"`
		} `json:"created"`
	}
	if json.Unmarshal(result, &setResult) != nil || len(setResult.Created) == 0 {
		return nil
	}
	out := make(map[string]string, len(setResult.Created))
	for clientKey, created := range setResult.Created {
		out[clientKey] = created.ID
	}
	return out
}

func jsonToNull(raw json.RawMessage) interface{} {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	return raw
}

func nullIfZero(n int) interface{} {
	if n <= 0 {
		return nil
	}
	return n
}

// HasCapability checks whether the given capability URI is present in the using list.
func (h *JMAPHandler) HasCapability(using []string, method string) bool {
	if len(using) == 0 {
		return true // permissive: allow requests without using (RFC 8620 §3.2 says it's optional)
	}
	cap := h.capabilityForMethod(method)
	for _, u := range using {
		if u == cap {
			return true
		}
	}
	return false
}

func requestProblem(problemType, detail string) *ProblemDetails {
	return &ProblemDetails{
		Type:   "urn:ietf:params:jmap:error:" + problemType,
		Status: http.StatusBadRequest,
		Detail: detail,
	}
}

// ExecuteBatch is the sole JMAP request execution envelope. It owns request
// validation, ordered result-reference resolution, registry-derived invocation
// metadata, dispatch continuation, and createdIds accumulation. HTTP and
// WebSocket transports decode into BatchRequest and encode BatchResult only.
func (h *JMAPHandler) ExecuteBatch(ctx context.Context, user *auth.Claims, req BatchRequest) BatchResult {
	if len(req.Using) == 0 {
		return BatchResult{Problem: requestProblem("notRequest", "'using' array must not be empty")}
	}

	sessionState := stateUnavailable
	if h.pool != nil {
		sessionState = h.GetSessionState(ctx, user.UserID)
	}
	resp := &Response{
		SessionState:    sessionState,
		MethodResponses: make([]MethodCall, 0, len(req.MethodCalls)),
	}
	if len(req.MethodCalls) > maxCallsInBatch {
		return BatchResult{Problem: requestProblem("requestTooLarge",
			fmt.Sprintf("maxCallsInRequest of 32 exceeded (%d calls)", len(req.MethodCalls)))}
	}

	for _, call := range req.MethodCalls {
		if len(call.Args) > maxCallArgsSize {
			return BatchResult{Problem: requestProblem("requestTooLarge",
				fmt.Sprintf("method call '%s' exceeds 2 MB limit", call.Name))}
		}

		inv := h.resolveInvocation(call.Name)
		if !hasCapability(req.Using, inv.metadata.Capability) {
			return BatchResult{Problem: requestProblem("unknownCapability",
				"Capability not declared in 'using': "+inv.metadata.Capability)}
		}

		resolvedArgs, refErr := resolveReferences(call.Args, resp.MethodResponses)
		if refErr != nil {
			errJSON, _ := json.Marshal(*refErr)
			resp.MethodResponses = append(resp.MethodResponses, MethodCall{
				Name: "error", Args: errJSON, ClientID: call.ClientID,
			})
			continue
		}

		name, result := h.dispatchInvocation(ctx, user, inv, resolvedArgs)
		resp.MethodResponses = append(resp.MethodResponses, MethodCall{
			Name: name, Args: result, ClientID: call.ClientID,
		})
		if strings.HasSuffix(call.Name, "/set") {
			if ids := extractCreatedIDs(result); len(ids) > 0 {
				if resp.CreatedIDs == nil {
					resp.CreatedIDs = make(map[string]string, len(ids))
				}
				for k, v := range ids {
					resp.CreatedIDs[k] = v
				}
			}
		}
	}

	return BatchResult{Response: resp}
}

func hasCapability(using []string, capability string) bool {
	for _, declared := range using {
		if declared == capability {
			return true
		}
	}
	return false
}

// Request handles POST /jmap — the main JMAP API endpoint.
func (h *JMAPHandler) Request(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())

	r.Body = http.MaxBytesReader(w, r.Body, 10_000_000) // maxSizeRequest
	var req Request
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteProblem(w, http.StatusBadRequest, "notJSON", "invalid JSON in request body")
		return
	}

	result := h.ExecuteBatch(r.Context(), user, req)
	if result.Problem != nil {
		problemType := strings.TrimPrefix(result.Problem.Type, "urn:ietf:params:jmap:error:")
		WriteProblem(w, result.Problem.Status, problemType, result.Problem.Detail)
		return
	}
	httputil.WriteJSON(w, http.StatusOK, result.Response)
}

// effectiveCapabilitiesDefault is the safe default returned when pool is nil
// (unit-test mode) or when the DB query fails. App flags fail closed; non-app
// feature defaults retain their existing conservative values.
// ponytail: offline block included here so the deny-by-default invariant (X4/F4)
// holds even on DB error / nil-pool; the DB path overwrites it with the real policy.
func effectiveCapabilitiesDefault() map[string]any {
	return map[string]any{
		"apps": map[string]bool{
			"mail": false, "calendar": false, "contacts": false, "tasks": false,
			"approvals": false, "drive": false, "chat": false, "meet": false,
		},
		"features": map[string]bool{
			"assist": false, "bundles": false,
			"external_labels": false,
			"guest_accounts":  false, "guest_invite": false,
			"mail_search_builder":   false,
			"sender_control_center": false,
			"shared_mail_work":      false,
			"shared_mail_comments":  false,
		},
		"offline": map[string]any{
			"allowed":          false,
			"approvalState":    "pending",
			"maxOfflineDays":   0,
			"wipeOnLogout":     "admin_default",
			"requireApproval":  true,
			"biometricUnlock":  false,
			"windowsSsoUnlock": false,
		},
	}
}

// guestCapabilities is the explicit FAIL-CLOSED capability set for the guest
// claim (guest-accounts P11a, D-m2). Chat requires its org toggle plus the
// derived user entitlement. G3 Meet additionally requires the program-level
// guest toggle, the Meet org toggle, and the derived Meet entitlement. G4
// keeps the standalone Drive app denied while exposing its original-byte
// policy hint only when guest accounts, Drive, and the per-user Drive
// entitlement are all live. Returned at
// function ENTRY of both effectiveCapabilities* paths and at the session
// handler's guest branch — before ANY of the six
// effectiveCapabilitiesDefault() fallback returns (pool-nil/error paths
// included) can fire. Deliberately independent of the G2 substrate fix for
// effectiveCapabilitiesDefault's all-app-false fallback (friction #7).
func (h *JMAPHandler) guestCapabilities(ctx context.Context, userID int64) map[string]any {
	chatOn := h.toggles != nil && h.toggles.IsEnabled(toggle.FeatureChat) &&
		h.entitlementGate != nil && h.entitlementGate.Allowed(ctx, userID, "chat")
	meetOn := h.toggles != nil && h.toggles.IsEnabled(toggle.FeatureGuestAccounts) &&
		h.toggles.IsEnabled(toggle.FeatureMeet) && h.entitlementGate != nil &&
		h.entitlementGate.Allowed(ctx, userID, "meet")
	driveAccessOn := h.toggles != nil && h.toggles.IsEnabled(toggle.FeatureGuestAccounts) &&
		h.toggles.IsEnabled(toggle.FeatureDrive) && h.entitlementGate != nil &&
		h.entitlementGate.Allowed(ctx, userID, "drive")
	guestPolicy := h.guestRuntimePolicy(ctx, userID, meetOn, driveAccessOn)
	return map[string]any{
		"apps": map[string]bool{
			"mail": false, "calendar": false, "contacts": false, "tasks": false,
			"approvals": false, "drive": false, "chat": chatOn, "meet": meetOn,
		},
		"features": map[string]bool{
			"assist": false, "bundles": false, "external_labels": false,
			"guest_accounts": false, "guest_invite": false,
			"mail_search_builder":   false,
			"sender_control_center": false,
			"shared_mail_work":      false,
			"shared_mail_comments":  false,
		},
		"guest": guestPolicy,
		"offline": map[string]any{
			"allowed": false, "approvalState": "pending", "maxOfflineDays": 0,
			"wipeOnLogout": "admin_default", "requireApproval": true,
			"biometricUnlock": false, "windowsSsoUnlock": false,
		},
	}
}

// guestRuntimePolicy returns optional UI hints for the authenticated guest
// shell. Reducers remain the authority; this projection only hides controls
// or original-byte actions the caller cannot use. Every unavailable posture
// fails closed to false (nil pool, missing profile, disabled governing app,
// unknown helper result, or DB error).
func (h *JMAPHandler) guestRuntimePolicy(ctx context.Context, userID int64, meetOn, driveAccessOn bool) map[string]bool {
	policy := map[string]bool{"allowMeetCreate": false, "allowMeetHost": false, "allowDownload": false}
	if h == nil || h.pool == nil || (!meetOn && !driveAccessOn) {
		return policy
	}
	var allowMeetCreate, allowMeetHost, allowDownload bool
	err := dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT guest_profile_flag($1, 'allow_meet_create'),
			guest_profile_flag($1, 'allow_meet_host'),
			guest_profile_flag($1, 'allow_download')`, userID).
			Scan(&allowMeetCreate, &allowMeetHost, &allowDownload)
	})
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("guest runtime policy lookup failed — using deny defaults", "user_id", userID, "error", err)
		}
		return policy
	}
	if meetOn {
		policy["allowMeetCreate"] = allowMeetCreate
		policy["allowMeetHost"] = allowMeetHost
	}
	if driveAccessOn {
		policy["allowDownload"] = allowDownload
	}
	return policy
}

// unlockToggles reports whether the biometric and Windows-domain-SSO unlock
// tiers (P1-T) are org-enabled, deny-by-default when h.toggles is nil (unit
// tests / not yet wired) — same fail-closed posture as the offline block.
func (h *JMAPHandler) unlockToggles() (biometric, windowsSSO bool) {
	if h.toggles == nil {
		return false, false
	}
	return h.toggles.IsEnabled(toggle.FeatureBiometricUnlock), h.toggles.IsEnabled(toggle.FeatureWindowsSsoUnlock)
}

// effectiveCapabilities resolves the caller's per-app entitlement map by
// calling the effective_capabilities(p_account_id) PL/pgSQL function.
// Returns the safe all-app-false default when pool is nil or on any DB error;
// enforcement also happens in the B8.4 middleware.
func (h *JMAPHandler) effectiveCapabilities(ctx context.Context, mailboxID int64) map[string]any {
	if c := auth.UserFromContext(ctx); c != nil && c.IsGuest() {
		return h.guestCapabilities(ctx, c.UserID)
	}
	if h.pool == nil {
		return effectiveCapabilitiesDefault()
	}
	var raw json.RawMessage
	raw, err := h.caller.CallScoped(ctx, mailboxID, "effective_capabilities")
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("effective_capabilities query failed — using default", "mailbox_id", mailboxID, "error", err)
		}
		return effectiveCapabilitiesDefault()
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		if h.logger != nil {
			h.logger.Warn("effective_capabilities unmarshal failed — using default", "mailbox_id", mailboxID, "error", err)
		}
		return effectiveCapabilitiesDefault()
	}
	return result
}

// resolveOfflineDeviceID resolves the caller's NATIVE device fingerprint to its
// user_devices.id (F3), registering the row on first session (§6.0). Offline is
// native-only post-pivot, so this registers an offline device ONLY for native
// platforms (desktop/ios/android). A plain-browser ("web"/"") caller is NOT
// registered as an offline device (returns (0,false) → non-device caps,
// offline.allowed stays false). The fingerprint is the guard-core native device
// identity. Returns (id, true) on success; (0, false) for non-native / missing
// fingerprint so the caller falls back to the non-device caps.
func (h *JMAPHandler) resolveOfflineDeviceID(ctx context.Context, mailboxID int64, fingerprint, platform string) (int64, bool) {
	if h.pool == nil || fingerprint == "" {
		return 0, false
	}
	switch platform {
	case "desktop", "ios", "android":
		// native platform — eligible for an offline-device row
	default:
		// "web"/"" or unknown: plain browser, never an offline device (pivot)
		return 0, false
	}
	raw, err := h.caller.CallScoped(ctx, mailboxID, "offline_device_register", fingerprint, platform)
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("offline_device_register failed", "mailbox_id", mailboxID, "error", err)
		}
		return 0, false
	}
	var id int64
	if err := json.Unmarshal(raw, &id); err != nil {
		return 0, false
	}
	return id, true
}

// effectiveCapabilitiesWithDevice returns the caps payload including the offline
// block resolved for the caller's device via the effective_capabilities(mailboxID,
// deviceID) overload (C1 T10). Falls back to the non-device caps (offline.allowed
// stays false in the default) on any error — fail-open to deny (X4/F4). The DB's
// offline_effective_policy gates on feature.offline_mail, so the offline block's
// allowed flag is the server's seed-issuance authority.
func (h *JMAPHandler) effectiveCapabilitiesWithDevice(ctx context.Context, mailboxID, deviceID int64) map[string]any {
	if c := auth.UserFromContext(ctx); c != nil && c.IsGuest() {
		return h.guestCapabilities(ctx, c.UserID)
	}
	if h.pool == nil {
		return effectiveCapabilitiesDefault()
	}
	raw, err := h.caller.CallScoped(ctx, mailboxID, "effective_capabilities", deviceID)
	if err != nil {
		if h.logger != nil {
			h.logger.Warn("effective_capabilities(device) failed — using default", "mailbox_id", mailboxID, "error", err)
		}
		return effectiveCapabilitiesDefault()
	}
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		return effectiveCapabilitiesDefault()
	}
	// P1-T: fold the biometric/Windows-SSO unlock toggles into the offline
	// block the client reads. The reducer doesn't know about these (they are
	// Go-side toggles, not DB policy), so the gateway adds them post-hoc.
	if offline, ok := result["offline"].(map[string]any); ok {
		biometric, windowsSSO := h.unlockToggles()
		offline["biometricUnlock"] = biometric
		offline["windowsSsoUnlock"] = windowsSSO
	}
	return result
}

// offlineFingerprint extracts the device fingerprint string from the
// authenticated claims (the JWT DeviceClaim.ID, a string fingerprint — F3).
// Empty when no device claim is present (device-trust off / legacy client).
func offlineFingerprint(user *auth.Claims) string {
	if user == nil || user.Device == nil {
		return ""
	}
	return user.Device.ID
}

// nativePlatform reports the native client platform from the shell-set request
// header. Offline is native-only post-pivot: a plain browser sends no such
// header, so this returns "" and the caller skips offline-device registration.
// The header is advisory for platform labeling; the security gate is the
// server-side AND-of-four in offline_effective_policy — a spoofed header cannot
// grant offline (the device must still be admin-approved and the user opted-in).
func nativePlatform(r *http.Request) string {
	switch r.Header.Get("X-Setjoin-Native-Platform") {
	case "desktop":
		return "desktop"
	case "ios":
		return "ios"
	case "android":
		return "android"
	default:
		return ""
	}
}

// maxDelayedSendSeconds is the value advertised for the RFC 8621 §7
// `maxDelayedSend` submission capability: the maximum delay (in seconds) the
// server supports for scheduled send via EmailSubmission/set `sendAt`. The
// reducer (jmap_email_submission_set → message_schedule) imposes no hard upper
// bound, so we report a generous-but-finite one year — a positive value is what
// signals to spec-compliant clients that delayed send is supported at all.
const maxDelayedSendSeconds = 31536000 // 365 * 24 * 60 * 60

// Session handles GET /.well-known/jmap — returns the JMAP Session object.
// Clients fetch this on startup to discover all API endpoint URLs.
func (h *JMAPHandler) Session(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())

	// Guest branch (P11a): a guest has no mailbox — return the minimal
	// session payload with the fail-closed capability set before any
	// mailbox-keyed resolution runs (ResolvePrimaryMailbox below would
	// error for a guest).
	if user != nil && user.IsGuest() {
		httputil.WriteJSON(w, http.StatusOK, map[string]any{
			"capabilities":          map[string]any{},
			"accounts":              map[string]any{},
			"isGuest":               true,
			"effectiveCapabilities": h.guestCapabilities(r.Context(), user.UserID),
		})
		return
	}

	mailboxID, err := identity.ResolvePrimaryMailbox(r.Context(), h.pool, user.UserID)
	if err != nil {
		h.logger.Error("primary mailbox lookup failed", "user_id", user.UserID, "error", err)
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusInternalServerError, Detail: "internal error"})
		return
	}
	var lifecycleAllowed bool
	if err := h.pool.QueryRow(r.Context(), `SELECT mailbox_lifecycle_access_allowed($1)`, mailboxID).Scan(&lifecycleAllowed); err != nil || !lifecycleAllowed {
		httputil.WriteProblem(w, r, &httputil.Problem{Status: http.StatusForbidden, Detail: "mailbox access is suspended"})
		return
	}

	accountID := strconv.FormatInt(mailboxID, 10)
	base := "https://" + h.hostname

	session := map[string]any{
		"capabilities": map[string]any{
			"urn:ietf:params:jmap:core": map[string]any{
				"maxSizeUpload":         h.maxUploadSize,
				"maxConcurrentUpload":   4,
				"maxSizeRequest":        10000000,
				"maxConcurrentRequests": 4,
				"maxCallsInRequest":     32,
				"maxObjectsInGet":       256,
				"maxObjectsInSet":       128,
				"collationAlgorithms":   []string{"i;unicode-casemap"},
			},
			"urn:ietf:params:jmap:mail":      map[string]any{},
			"urn:ietf:params:jmap:calendars": map[string]any{},
			"urn:ietf:params:jmap:contacts":  map[string]any{},
			// sharedLists (Phase 1, V112): the webmail gates its shared-task-list
			// UI on this — no extra round trip needed to discover the toggle.
			"urn:ietf:params:jmap:tasks": map[string]any{"sharedLists": h.sharedTaskListsEnabled()},
			// EmailSubmission/* (RFC 8621 §7). EmailSubmission/set is fully wired,
			// including future scheduled send via the namespaced `sendAt` create
			// property (B2 → message_schedule). The reducer enforces no upper bound
			// on the delay, so advertise a generous-but-finite maxDelayedSend (1 yr,
			// in seconds) — a positive value tells spec-compliant clients delayed
			// send is supported. No submissionExtensions are offered.
			"urn:ietf:params:jmap:submission": map[string]any{
				"maxDelayedSend":       maxDelayedSendSeconds,
				"submissionExtensions": map[string]any{},
			},
			// A6: deferred-action reminder surface (Reminder/get|dismiss|snooze).
			"urn:setjoin:params:jmap:reminders": map[string]any{},
			"urn:ietf:params:jmap:blob": map[string]any{
				"maxSizeBlobSet":     h.maxUploadSize,
				"supportedTypeNames": []string{"application/octet-stream"},
			},
			VendorCapability: map[string]any{
				// Nonstandard surface: snoozeUntil on Email/set, sendAt on
				// EmailSubmission/set, EmailSubmission listing. Documented in
				// docs/specs/JMAP.md.
				"snoozeUntilOnEmailSet":      true,
				"sendAtOnEmailSubmissionSet": true,
				"emailSubmissionGetAndQuery": true,
				// B8.3: server computes per-user app entitlements; surfaced in
				// the top-level effectiveCapabilities session key.
				"effectiveAccess": true,
				// B5.2: computed newsletter bundle list via Email/bundles vendor method.
				"newsletterBundles": true,
				// M7 (S6 layer 1): admin surface — console visibility derived
				// from permissions, plus the caller's OWN resolved permissions
				// so the SPA gates write controls per-permission. See
				// adminCapabilityBlock.
				"admin": adminCapabilityBlock(user.Permissions),
			},
		},
		"accounts": map[string]any{
			accountID: map[string]any{
				"name":       user.Email,
				"isPersonal": true,
				"isReadOnly": false,
				"accountCapabilities": map[string]any{
					"urn:ietf:params:jmap:mail":      map[string]any{},
					"urn:ietf:params:jmap:calendars": map[string]any{},
					"urn:ietf:params:jmap:contacts":  map[string]any{},
					// sharedLists (Phase 1, V112): the webmail gates its shared-task-list
					// UI on this — no extra round trip needed to discover the toggle.
					"urn:ietf:params:jmap:tasks": map[string]any{"sharedLists": h.sharedTaskListsEnabled()},
					"urn:ietf:params:jmap:submission": map[string]any{
						"maxDelayedSend":       maxDelayedSendSeconds,
						"submissionExtensions": map[string]any{},
					},
					"urn:ietf:params:jmap:blob": map[string]any{},
					VendorCapability:            map[string]any{},
				},
			},
		},
		// primaryAccounts always names the caller's OWN primary mailbox —
		// delegated accounts are additional, never primary.
		"primaryAccounts": map[string]string{
			"urn:ietf:params:jmap:mail":      accountID,
			"urn:ietf:params:jmap:calendars": accountID,
			"urn:ietf:params:jmap:contacts":  accountID,
			"urn:ietf:params:jmap:tasks":     accountID,
		},
		"username":       user.Email,
		"apiUrl":         base + "/jmap",
		"downloadUrl":    base + "/jmap/download/{accountId}/{blobId}/{name}?type={type}",
		"uploadUrl":      base + "/jmap/upload/{accountId}",
		"eventSourceUrl": base + "/jmap/eventsource?types={types}&closeafter={closeafter}&ping={ping}",
		"state":          h.GetSessionState(r.Context(), user.UserID),
	}

	// #13 shared-mailbox use-surface: advertise every MAIL-delegated mailbox
	// as an additional account (RFC 8620 multi-account). This payload is ALSO
	// the identity enumeration the compose From Select consumes — one session
	// fetch, no second roundtrip: sendable identities = the caller's own
	// address + every account whose vendor delegateGrants include a send
	// level. From mapping (enforced by send.sql, restated for clients):
	// send_as|full_access may set From = the shared address; send_on_behalf
	// keeps From = the delegate's own address (BZ003 otherwise).
	//
	// manage_calendar-only grants are excluded — calendar delegation is not
	// mail delegation. The lookup rides RunUserScoped: mailbox_delegates is
	// FORCE-RLS (V090) fail-closed, so a bare h.pool read would silently
	// return zero rows under the live flip. A lookup failure degrades to a
	// primary-only session (logged) rather than a 500.
	type delegatedAccount struct {
		id            int64
		email         string
		grants        []string
		sendAsAliases []string
	}
	var delegated []delegatedAccount
	if err := dbscope.RunUserScoped(r.Context(), h.pool, user.UserID, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(),
			`WITH delegated AS (
			   SELECT md.mailbox_id,
			          array_agg(DISTINCT md.permission ORDER BY md.permission) AS grants
			     FROM mailbox_delegates md
			    WHERE md.user_id = $1
			      AND md.permission IN ('read','send_as','send_on_behalf','full_access')
			      AND md.mailbox_id <> $2
			    GROUP BY md.mailbox_id
			 )
			 SELECT d.mailbox_id, mb.email, d.grants,
			        CASE
			          WHEN d.grants && ARRAY['send_as','full_access']::text[]
			          THEN ARRAY(
			            SELECT a.email
			              FROM aliases a
			             WHERE a.mailbox_id = d.mailbox_id
			               AND lower(a.email) <> lower(mb.email)
			             ORDER BY lower(a.email), a.id
			          )
			          ELSE ARRAY[]::text[]
			        END AS send_as_aliases
			   FROM delegated d
			   JOIN mailboxes mb ON mb.id = d.mailbox_id
			  WHERE mb.enabled = TRUE
			  ORDER BY lower(mb.email), d.mailbox_id`,
			user.UserID, mailboxID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d delegatedAccount
			if err := rows.Scan(&d.id, &d.email, &d.grants, &d.sendAsAliases); err != nil {
				return err
			}
			delegated = append(delegated, d)
		}
		return rows.Err()
	}); err != nil {
		h.logger.Warn("delegated-account lookup failed — session serves primary account only",
			"userID", user.UserID, "error", err)
	}
	accounts := session["accounts"].(map[string]any)
	for _, d := range delegated {
		vendor := map[string]any{
			"delegateGrants": d.grants,
			// Only send_as/full_access rows receive aliases from the query.
			// A read or send_on_behalf delegate must not learn or select them.
			"sendAsAliases": d.sendAsAliases,
		}
		caps := map[string]any{
			"urn:ietf:params:jmap:mail": map[string]any{},
			VendorCapability:            vendor,
		}
		if gateSubmit.allows(d.grants) {
			caps["urn:ietf:params:jmap:submission"] = map[string]any{
				"maxDelayedSend":       maxDelayedSendSeconds,
				"submissionExtensions": map[string]any{},
			}
		}
		accounts[strconv.FormatInt(d.id, 10)] = map[string]any{
			"name":       d.email,
			"isPersonal": false,
			// Read-only unless the grant allows mutation (Email/set etc.);
			// send-only grants still read as isReadOnly=true per RFC 8620
			// (the account's DATA is not client-mutable).
			"isReadOnly":          !gateMutate.allows(d.grants),
			"accountCapabilities": caps,
		}
	}

	// Effective purge config for this mailbox
	var deletedDays, spamDays int
	err = h.pool.QueryRow(r.Context(),
		`SELECT
		   COALESCE(mb.deleted_purge_days,
		     COALESCE(NULLIF((SELECT value #>> '{}' FROM system_config WHERE key = 'deleted_items_purge_days'), '0')::INT, 30), 30),
		   COALESCE(mb.spam_purge_days,
		     COALESCE(NULLIF((SELECT value #>> '{}' FROM system_config WHERE key = 'spam_purge_days'), '0')::INT, 30), 30)
		 FROM mailboxes mb WHERE mb.id = $1`,
		mailboxID,
	).Scan(&deletedDays, &spamDays)
	if err != nil {
		h.logger.Warn("purge config lookup failed", "mailbox_id", mailboxID, "error", err)
		deletedDays = 30
		spamDays = 30
	}

	session["purgeConfig"] = map[string]int{
		"deletedPurgeDays": deletedDays,
		"spamPurgeDays":    spamDays,
	}

	// Branding config
	var brandName, brandLogoURL string
	h.pool.QueryRow(r.Context(),
		`SELECT COALESCE((SELECT value #>> '{}' FROM system_config WHERE key = 'brand_name'), 'SetJoin'),
		        COALESCE((SELECT value #>> '{}' FROM system_config WHERE key = 'brand_logo_url'), '')`,
	).Scan(&brandName, &brandLogoURL)
	session["branding"] = map[string]string{
		"name":    brandName,
		"logoUrl": brandLogoURL,
	}

	// IT helpdesk contact email (system_config: help_email).
	// Present only when configured — absence means the client falls back to admin@{domain}.
	var helpEmail string
	h.pool.QueryRow(r.Context(),
		`SELECT COALESCE((SELECT value #>> '{}' FROM system_config WHERE key = 'help_email'), '')`,
	).Scan(&helpEmail)
	if helpEmail != "" {
		session["helpEmail"] = helpEmail
	}

	// TYPES-002 (SJ-FAIL-OPEN-CAPABILITY-DEFAULT): advertise the strict
	// enabled-apps derivation posture to the webmail inside the vendor
	// capability block — the same no-extra-roundtrip toggle delivery the tasks
	// sharedLists flag uses. Controlled by system_config:apps_caps_strict
	// (accepted literals '1'/'true'; absent or any other value ⇒ the field is
	// omitted ⇒ the client keeps the documented B8 default-allow window). A
	// lookup failure degrades to omitted (window posture), never to strict.
	// pgx can populate the destination before a late rows-close/read error, so
	// the destination boolean alone is not trustworthy — advertise only when
	// the scan itself succeeded.
	var appsStrictEntitlements bool
	strictErr := h.pool.QueryRow(r.Context(),
		`SELECT COALESCE((SELECT lower(value #>> '{}') FROM system_config WHERE key = 'apps_caps_strict'), '') IN ('1','true')`,
	).Scan(&appsStrictEntitlements)
	if strictErr != nil && h.logger != nil {
		h.logger.Warn("apps_caps_strict lookup failed — advertising the default-allow window posture", "error", strictErr)
	}
	if strictErr == nil && appsStrictEntitlements {
		if vc, ok := session["capabilities"].(map[string]any); ok {
			if vendorCaps, ok := vc[VendorCapability].(map[string]any); ok {
				vendorCaps["appsStrictEntitlements"] = true
			}
		}
	}

	// B8.3/F3/F4: effective capabilities — per-user app entitlement map.
	// For native devices (desktop/ios/android), resolve the device row and call
	// the device-aware overload which folds in the offline block from
	// offline_effective_policy. Plain browsers and device-trust-off callers get
	// the non-device caps (no offline block widening; fail-open to deny). The
	// offline block's allowed flag is false by default (deny-by-default; X4/F4).
	// ponytail: lazy eval — device path tried first; non-device call skipped when
	// device path succeeds (saves one DB round-trip on every native session).
	var caps map[string]any
	if fp := offlineFingerprint(user); fp != "" {
		platform := nativePlatform(r) // "desktop"/"ios"/"android"; "" on plain browser
		if devID, ok := h.resolveOfflineDeviceID(r.Context(), mailboxID, fp, platform); ok {
			caps = h.effectiveCapabilitiesWithDevice(r.Context(), mailboxID, devID)
		}
	}
	if caps == nil {
		caps = h.effectiveCapabilities(r.Context(), mailboxID)
	}
	session["effectiveCapabilities"] = caps

	// 等保三级 SoD mode: gated entirely behind the default-OFF toggle.
	// When OFF (the default), the "dengbao" key is omitted entirely and NO
	// extra DB query is run — zero latency cost for the default deployment.
	// When ON: one indexed query retrieves the caller's role sod_class values;
	// DeriveSodClass collapses them to a single class or "" if mixed/absent.
	if h.toggles != nil && admin.SodMode(h.toggles) {
		var sodClasses []string
		rows, queryErr := h.pool.Query(r.Context(),
			`SELECT DISTINCT rg.sod_class
			   FROM admin_role_assignments ra
			   JOIN admin_role_groups rg ON rg.id = ra.role_group_id
			  WHERE ra.user_id = $1
			    AND (ra.expires_at IS NULL OR ra.expires_at > now())
			    AND rg.sod_class IS NOT NULL`,
			user.UserID,
		)
		if queryErr != nil {
			if h.logger != nil {
				h.logger.Warn("dengbao sod_class query failed — omitting dengbao block", "user_id", user.UserID, "error", queryErr)
			}
		} else {
			for rows.Next() {
				var cls string
				if scanErr := rows.Scan(&cls); scanErr != nil {
					if h.logger != nil {
						h.logger.Warn("dengbao sod_class scan failed — skipping row", "user_id", user.UserID, "error", scanErr)
					}
				} else {
					sodClasses = append(sodClasses, cls)
				}
			}
			rows.Close()
			session["dengbao"] = map[string]any{
				"sodMode":  true,
				"sodClass": admin.DeriveSodClass(sodClasses),
			}
		}
	}

	httputil.WriteJSON(w, http.StatusOK, session)
}

// adminCapabilityBlock builds the M7/S6 admin surface of the JMAP session vendor
// capability for the caller: the console ids they may SEE (derived from their
// permissions) plus their OWN resolved permissions, which the SPA uses to gate
// write controls per-permission — a read-tier admin gets disabled controls
// instead of buttons that 403.
//
// Exposing the caller's own permissions is self-knowledge: the server enforces
// every write regardless of this hint, and the user could discover the same set
// by clicking. It is therefore not a disclosure boundary — only the prior
// minimalism choice, reversed by the 2026-06-22 decision. This block carries ONLY
// the caller's own perms; it is never the full permission catalog or any other
// user's permissions. perms is coerced to a non-nil slice so the wire form is a
// JSON array (`[]`), not `null`.
func adminCapabilityBlock(perms []string) map[string]any {
	if perms == nil {
		perms = []string{}
	}
	return map[string]any{
		"consoles":    admin.ConsolesForPerms(perms),
		"permissions": perms,
	}
}

// Upload and Download moved to jmap_blob.go (RFC 9404).

// --- Internal helpers ---

func (h *JMAPHandler) Dispatch(ctx context.Context, user *auth.Claims, method string, args json.RawMessage) (string, json.RawMessage) {
	if method == "" || len(method) > 128 {
		return methodError("unknownMethod", "invalid method name")
	}
	inv := h.resolveInvocation(method)
	if inv.fn == nil {
		return methodError("unknownMethod", "")
	}
	return h.dispatchInvocation(ctx, user, inv, args)
}

func (h *JMAPHandler) dispatchInvocation(ctx context.Context, user *auth.Claims, inv invocation, args json.RawMessage) (string, json.RawMessage) {
	if inv.name == "" || len(inv.name) > 128 {
		return methodError("unknownMethod", "invalid method name")
	}
	if inv.fn == nil {
		return methodError("unknownMethod", "")
	}
	ctx = invocationContext{Context: ctx, Metadata: inv.metadata}
	// Basic args validation: must be valid JSON and an object.
	if len(args) > 0 {
		var tmp map[string]any
		if err := json.Unmarshal(args, &tmp); err != nil {
			return methodError("invalidArguments", "args must be a JSON object")
		}
	}

	// B8.4: per-method app entitlement gate. Calendar/*, ContactCard/*, etc. are
	// gated by the per-user entitlement. Mail methods (Email/*, Mailbox/*, etc.)
	// are always allowed. Gate is skipped when entitlementGate is nil (unit tests
	// and legacy nil-pool mode).
	if h.entitlementGate != nil {
		if app := inv.metadata.App; app != "" {
			if !h.entitlementGate.Allowed(ctx, user.UserID, app) {
				if h.logger != nil {
					h.logger.Info("jmap method blocked by app entitlement",
						"user_id", user.UserID, "method", inv.name, "app", app)
				}
				// Write to admin_audit_log so administrators can audit JMAP-level
				// app blocks. Errors are best-effort; do not block the error response.
				if h.pool != nil {
					if err := audit.Write(ctx, h.pool, audit.Entry{
						Actor: user.UserID, Action: "app_blocked", TargetType: "app",
						Notes: app, Tier: audit.TierForAction("app_blocked"),
					}); err != nil && h.logger != nil {
						h.logger.Warn("jmap dispatch: failed to write audit log",
							"user_id", user.UserID, "app", app, "error", err)
					}
				}
				return methodError("forbidden", "access to this app is not permitted")
			}
		}
	}

	start := time.Now()
	resName, resArgs := inv.fn(ctx, user, args)
	if h.metrics != nil {
		h.metrics.RecordMethod("jmap", inv.name, time.Since(start))
	}
	return resName, resArgs
}

// GetSessionState returns a string that changes when the user's server state changes.
// Clients use this to detect when they need to re-fetch the Session object.
//
// RFC 8620 §2: sessionState MUST change when ANY account state changes — not just
// email. It was derived from jmap_email_state ALONE (arch A4), so a folder
// rename, a contact/calendar/task edit, or an identity change did NOT bump it and
// a session-caching client never noticed. Fold every per-capability counter
// (email/mailbox/thread/tag + the calendar/contact/task satellite MAX cursors +
// the identity token) into one opaque string, computed in a SINGLE round-trip so
// the hot per-request path keeps one query.
func (h *JMAPHandler) GetSessionState(ctx context.Context, userID int64) string {
	var c sessionStateComponents
	var updatedAt time.Time
	if err := h.pool.QueryRow(ctx,
		`SELECT m.jmap_email_state, m.jmap_mailbox_state, m.jmap_thread_state, m.jmap_tag_state,
		        COALESCE((SELECT MAX(jmap_state) FROM calendars    WHERE mailbox_id = m.id), 0),
		        COALESCE((SELECT MAX(jmap_state) FROM addressbooks WHERE mailbox_id = m.id), 0),
		        COALESCE((SELECT MAX(jmap_state) FROM tasks        WHERE mailbox_id = m.id), 0),
		        u.updated_at
		   FROM mailboxes m JOIN users u ON u.id = m.user_id
		  WHERE m.user_id = $1 AND m.is_primary = TRUE`,
		userID,
	).Scan(&c.Email, &c.Mailbox, &c.Thread, &c.Tag, &c.Calendar, &c.Contact, &c.Task, &updatedAt); err != nil {
		h.logger.Warn("jmap GetSessionState failed", "user_id", userID, "error", err)
		// NOT "0": that is a valid token a fresh account really produces, so an
		// error emitting it was indistinguishable from real state (c1 fix).
		return stateUnavailable
	}
	c.Identity = updatedAt.Unix()
	return encodeSessionState(c)
}

// JMAPStateTokens holds the per-capability state tokens for a user's primary mailbox.
// These are monotonic counters bumped by reducer functions on every data change.
type JMAPStateTokens struct {
	Email    string
	Mailbox  string
	Thread   string
	Tag      string
	Calendar string
	Contact  string
	Task     string
}

// scanStateTokens reads the four mailbox-level state counters for the single
// row matched by the given WHERE clause (`user_id = $1 AND is_primary` for the
// user-keyed path, `id = $1` for the mailbox-keyed path). Calendar/Contact/Task
// are left "0" here — only the mailbox-keyed WS path resolves them (they live in
// satellite tables, not on mailboxes): satelliteStateForMailbox over
// calendars / addressbooks / tasks.
func (h *JMAPHandler) scanStateTokens(ctx context.Context, where string, arg int64, logKey string) JMAPStateTokens {
	var email, mailbox, thread, tag int64
	if err := h.pool.QueryRow(ctx,
		`SELECT jmap_email_state, jmap_mailbox_state, jmap_thread_state, jmap_tag_state
		 FROM mailboxes WHERE `+where,
		arg,
	).Scan(&email, &mailbox, &thread, &tag); err != nil {
		h.logger.Warn("jmap state-token query failed", logKey, arg, "error", err)
		// NOT "0" (a valid fresh-mailbox token) — see stateUnavailable (c1 fix).
		return JMAPStateTokens{
			Email: stateUnavailable, Mailbox: stateUnavailable, Thread: stateUnavailable,
			Tag: stateUnavailable, Calendar: stateUnavailable, Contact: stateUnavailable,
			Task: stateUnavailable,
		}
	}
	return JMAPStateTokens{
		Email:    encodeStateToken(email),
		Mailbox:  encodeStateToken(mailbox),
		Thread:   encodeStateToken(thread),
		Tag:      encodeStateToken(tag),
		Calendar: encodeStateToken(0),
		Contact:  encodeStateToken(0),
		Task:     encodeStateToken(0),
	}
}

// GetStateTokensByMailbox queries all per-capability state tokens for a mailbox
// keyed by mailboxes.id (the account-scope currency — ADR-003), NOT users.id.
// The WebSocket push path MUST use this: the channel id it subscribes to is the
// primary mailbox id, and a user_id-keyed lookup would mismatch in production
// (independent BIGSERIAL sequences). Adds the mailbox-wide calendar state token
// so a "calendar:{mailbox_id}" notification can carry a Calendar/CalendarEvent
// change in the StateChange payload.
func (h *JMAPHandler) GetStateTokensByMailbox(ctx context.Context, mailboxID int64) JMAPStateTokens {
	tokens := h.scanStateTokens(ctx, "id = $1", mailboxID, "mailbox_id")
	// Calendar/Contact/Task tokens live on satellite tables (per-row jmap_state),
	// not on mailboxes — the mailbox-wide MAX is the per-domain sync cursor the
	// webmail re-fetches on. (calendars: Calendar/CalendarEvent; addressbooks:
	// Contact, bumped by notify_contact_state across every book; tasks: Task.)
	tokens.Calendar = h.satelliteStateForMailbox(ctx, "calendars", mailboxID)
	tokens.Contact = h.satelliteStateForMailbox(ctx, "addressbooks", mailboxID)
	tokens.Task = h.satelliteStateForMailbox(ctx, "tasks", mailboxID)
	return tokens
}

// satelliteStateForMailbox returns the mailbox-wide MAX(jmap_state) for a satellite
// domain table (calendars | addressbooks | tasks) as a string — the per-domain sync
// cursor a "{domain}:{mailbox_id}" push advances. These domains carry their token
// per-row (there is no mailboxes.jmap_{domain}_state), so the max across the
// mailbox's rows is the monotonic "something changed" token the webmail re-fetches
// on. Returns "0" (a real token) when the mailbox has no rows; stateUnavailable
// when the state cannot be read (non-fatal, but never a fake "0" — c1 fix).
//
// table is a fixed in-code constant (never user input), so interpolating it into the
// query is safe — there is no SQL-injection surface (R-rules apply to user data).
func (h *JMAPHandler) satelliteStateForMailbox(ctx context.Context, table string, mailboxID int64) string {
	if mailboxID <= 0 || h.pool == nil {
		return stateUnavailable
	}
	var state int64
	if err := h.pool.QueryRow(ctx,
		`SELECT COALESCE(MAX(jmap_state), 0) FROM `+table+` WHERE mailbox_id = $1`,
		mailboxID,
	).Scan(&state); err != nil {
		return stateUnavailable
	}
	return encodeStateToken(state)
}

func (h *JMAPHandler) GetAccountID(ctx context.Context, userID int64) string {
	id, err := identity.ResolvePrimaryMailbox(ctx, h.pool, userID)
	if err != nil {
		h.logger.Warn("jmap GetAccountID failed", "user_id", userID, "error", err)
		return "0"
	}
	return strconv.FormatInt(id, 10)
}

// HasDriveAdminPerm reports whether userID holds the given Drive admin
// permission (drive.view / drive.manage — drive_has_admin_perm, V114 §B).
// Used by the ws package at WS/SSE connect time to decide whether to append
// the "drive-alarm" push channel to a session's subscription list (Drive P6
// Task 12: channel authorization is server-derived, never a client-chosen
// channel — the same posture as the drive-watch:<uid> channel, just
// perm-gated instead of self-scoped). Fails closed (false) on any error,
// including a nil pool (unit tests never exercising Drive).
func (h *JMAPHandler) HasDriveAdminPerm(ctx context.Context, userID int64, perm string) bool {
	if h.pool == nil {
		return false
	}
	var has bool
	err := dbscope.RunUserScoped(ctx, h.pool, userID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT drive_has_admin_perm($1, $2)`, userID, perm).Scan(&has)
	})
	if err != nil {
		h.logger.Warn("jmap: drive admin perm check failed", "user_id", userID, "perm", perm, "error", err)
		return false
	}
	return has
}

// --- Core method implementations ---

func (h *JMAPHandler) coreEcho(_ context.Context, _ *auth.Claims, args json.RawMessage) (string, json.RawMessage) {
	return "Core/echo", args
}

type SetRequest struct {
	AccountID string          `json:"accountId"`
	Create    json.RawMessage `json:"create,omitempty"`
	Update    json.RawMessage `json:"update,omitempty"`
	Destroy   []string        `json:"destroy,omitempty"`
}

// dispatchSet handles the common create/update/destroy/merge pattern for JMAP Set methods.
// reducerPrefix is the PG function prefix (e.g. "jmap_email" produces "jmap_email_set_create").
//
// c3: one /set = ONE transaction. All present phases run inside a single
// CallScopedBatch — one BEGIN, one GUC set (native-RLS: the GUC holds for
// every statement; harmless where unpoliced), create→update→destroy, one
// COMMIT — so a client batch is atomic per RFC 8620 §3.6.2: an infrastructure
// failure in any phase rolls back ALL phases (creates no longer persist when a
// later phase's reducer raises), and the domain's jmap_*_state bumps become
// visible as one transition. Per-ITEM failures are unchanged: the set reducers
// catch them internally and report notCreated/notUpdated/notDestroyed, so one
// bad item never rolls back the batch.
func (h *JMAPHandler) dispatchSet(ctx context.Context, accountID int64, req *SetRequest, reducerPrefix string) (json.RawMessage, error) {
	var calls []reducercall.ScopedCall
	// Phase → index into the batch results (-1 = phase absent). Order fixed:
	// create, update, destroy (RFC 8620 §5.3).
	idx := [3]int{-1, -1, -1}

	if len(req.Create) > 0 && string(req.Create) != "null" && jsonIsObject(req.Create) {
		idx[0] = len(calls)
		calls = append(calls, reducercall.ScopedCall{Fn: reducerPrefix + "_set_create", Args: []any{req.Create}})
	}
	if len(req.Update) > 0 && string(req.Update) != "null" && jsonIsObject(req.Update) {
		idx[1] = len(calls)
		calls = append(calls, reducercall.ScopedCall{Fn: reducerPrefix + "_set_update", Args: []any{req.Update}})
	}
	var badDestroy []string
	if len(req.Destroy) > 0 {
		// Malformed destroy ids fold into notDestroyed (c4) — an all-malformed
		// list now sends an EMPTY array, never NULL, to the reducer's FOREACH.
		var ids []int64
		ids, badDestroy = parseIDList(req.Destroy)
		idx[2] = len(calls)
		calls = append(calls, reducercall.ScopedCall{Fn: reducerPrefix + "_set_destroy", Args: []any{ids}})
	}

	if len(calls) == 0 {
		return mergeSetResults(nil, nil, nil), nil
	}
	results, err := h.caller.CallScopedBatch(ctx, accountID, calls...)
	if err != nil {
		// The whole batch rolled back; the seam wrapped the raw pgx error with
		// the failing phase's fn name, so the BZ→JMAP map and log context hold.
		return nil, err
	}
	pick := func(i int) json.RawMessage {
		if i < 0 {
			return nil
		}
		return results[i]
	}
	return addSetErrors(mergeSetResults(pick(idx[0]), pick(idx[1]), pick(idx[2])), "notDestroyed", badDestroy), nil
}

// mergeSetResults combines create, update, and destroy JSON results into one object.
func mergeSetResults(createResult, updateResult, destroyResult json.RawMessage) json.RawMessage {
	merged := make(map[string]json.RawMessage)
	if len(createResult) > 0 {
		json.Unmarshal(createResult, &merged)
	}
	if len(updateResult) > 0 {
		var m map[string]json.RawMessage
		json.Unmarshal(updateResult, &m)
		for k, v := range m {
			merged[k] = v
		}
	}
	if len(destroyResult) > 0 {
		var m map[string]json.RawMessage
		json.Unmarshal(destroyResult, &m)
		for k, v := range m {
			merged[k] = v
		}
	}
	result, _ := json.Marshal(merged)
	return result
}

func jsonIsObject(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	trimmed := raw
	for i, b := range raw {
		if b != ' ' && b != '\t' && b != '\n' && b != '\r' {
			trimmed = raw[i:]
			break
		}
	}
	return len(trimmed) > 0 && trimmed[0] == '{'
}
