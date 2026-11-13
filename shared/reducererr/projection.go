package reducererr

import (
	"errors"
	"log/slog"

	"github.com/jackc/pgx/v5/pgconn"
)

// ReplyClass is the protocol-agnostic classification of a reducer business
// error: the single seam every gateway protocol projects a BZ code through to a
// wire reply. Before this, each protocol hand-rolled the BZ→reply map (jmap's
// mapReducerErr, smtp's classifyReducerReply) and the WebDAV bridges mapped
// NOTHING — returning 500 for every reducer error, so quota / forbidden /
// not-found all wrongly became Internal Server Error. A single classified value
// here, with one projection method per protocol, makes "what HTTP/SMTP/JMAP/
// WebDAV reply does this BZ code mean" answerable in exactly one place.
//
// The class is intentionally fine-grained where two codes share a coarse
// meaning but a protocol must still distinguish them — e.g. a mailbox-full
// over-quota and a sender daily-quota both project to JMAP overQuota and HTTP
// 507, but SMTP emits two distinct 552 reply lines, so they are two classes
// (ClassOverQuota / ClassSendQuota). This keeps every projection method a pure
// function of the class, with no second lookup on the underlying code.
type ReplyClass int

const (
	// ClassUnknown is the catch-all: a non-business error (transport blip), a BZ
	// code outside the client-actionable set, or the dual-use BZ001 calendar
	// slug that is NOT over_quota. Every protocol keeps its existing safe
	// fallback for this class (jmap serverFail/500, smtp's transient 451
	// default, WebDAV/HTTP 500) — so routing through the projection is a no-op
	// for unrecognized errors.
	ClassUnknown ReplyClass = iota
	// ClassOverQuota — mailbox/domain storage full (BZ001 over_quota, BZ009).
	ClassOverQuota
	// ClassSendQuota — sender daily sending quota reached (BZ004). Same HTTP/
	// JMAP/WebDAV projection as ClassOverQuota; a distinct SMTP reply line.
	ClassSendQuota
	// ClassForbidden — access denied / policy block (BZ002, BZ003, BZ005).
	ClassForbidden
	// ClassNotFound — recipient/target has no mailbox (BZ007).
	ClassNotFound
	// ClassAccountNotFound — JMAP accountId does not match an account (BZ006).
	ClassAccountNotFound
	// ClassCannotCalc — JMAP state too old to delta from; client must resync
	// (BZ011, RFC 8620 §5.2).
	ClassCannotCalc
	// ClassTransient — a fixable infra/config state, not a caller error (BZ008
	// missing_inbox): the sender should retry. SMTP projects this to 451; the
	// other protocols treat it as an internal fault (it must not leak), so it
	// projects like ClassUnknown for them.
	ClassTransient
	// ClassInvalidArguments — the request arguments are malformed/invalid (BZ040,
	// BZ041): e.g. a SearchSnippet/get with no text filter, a quick-step with no
	// name. JMAP returns invalidArguments, HTTP/WebDAV 400. SMTP has no analog.
	ClassInvalidArguments
	// ClassConflict — the request collides with current state and cannot proceed
	// (illegal state transition, a uniqueness/priority clash, a would-lock-out-all
	// -admins guard, a stale/closed target): HTTP/WebDAV 409 Conflict. These are
	// admin/CA/migration reducer conditions with no JMAP or SMTP path, so JMAPError
	// and SMTPReply fall through to their safe defaults ("" / not-surfaced).
	ClassConflict
	// ClassStateMismatch — an optimistic-concurrency/idempotency fence moved.
	// JMAP clients can refetch and retry through the standard stateMismatch type.
	ClassStateMismatch
	// ClassUnprocessable — the request was well-formed but its CONTENT is
	// semantically invalid (a CA import doc with a too-new schemaVersion or bad
	// shape, an approval with no resolvable approver): HTTP/WebDAV 422
	// Unprocessable Entity. Distinct from ClassInvalidArguments (400 = malformed
	// request) — the split the CA import handler established. Admin-HTTP-only
	// conditions: JMAPError and SMTPReply fall through to their safe defaults.
	ClassUnprocessable
)

// Classify projects a reducer error onto its ReplyClass. It reads the stable BZ
// SQLSTATE directly (the binding identifier — the human message and HINT can
// change), and for the dual-use BZ001 code disambiguates on the HINT.type slug:
// only `over_quota` is the storage-quota meaning, every other BZ001 slug (the
// calendar forbidden/notFound flavors) returns ClassUnknown so it is never
// mislabeled over-quota. A non-pg / non-business error returns ClassUnknown.
func Classify(err error) ReplyClass {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return ClassUnknown
	}
	// Dual-use SQLSTATEs carry two meanings on one code; disambiguate on the
	// HINT.type slug before the flat codeClass lookup.
	switch pgErr.Code {
	case ErrOverQuota: // BZ001 — over_quota (storage) vs calendar not-found/forbidden.
		if rerr, perr := ParseReducerError(err); perr == nil && rerr.Type == "over_quota" {
			return ClassOverQuota
		}
		return ClassUnknown
	case "BZ081": // CA entity not-found vs queue settle_job bad_outcome.
		if rerr, perr := ParseReducerError(err); perr == nil && rerr.Type == "bad_outcome" {
			return ClassInvalidArguments
		}
		return ClassNotFound
	case "BZ099": // offline policy not-found vs last-global delete guard.
		// admin_offline.go DeletePolicy owns the split: the `last_global` slug is
		// a 409 "cannot delete the fallback row" conflict; every other slug
		// (not_found, bad_scope, bad_wipe_on_logout) keeps the primary
		// ClassNotFound meaning from codeClass.
		if rerr, perr := ParseReducerError(err); perr == nil && rerr.Type == "last_global" {
			return ClassConflict
		}
		return ClassNotFound
	}
	if c, ok := codeClass[pgErr.Code]; ok {
		return c
	}
	return ClassUnknown // unrecognized code, or a deliberate intentional500
}

// HTTPStatus projects the class onto the HTTP status a plain JSON/REST gateway
// should return. ClassUnknown / ClassTransient (an internal fault that must not
// leak) map to 500. Over-quota maps to 507 Insufficient Storage (RFC 4918 §11.5).
func (c ReplyClass) HTTPStatus() int {
	switch c {
	case ClassOverQuota, ClassSendQuota:
		return 507 // Insufficient Storage
	case ClassForbidden:
		return 403
	case ClassNotFound, ClassAccountNotFound:
		return 404
	case ClassCannotCalc, ClassConflict, ClassStateMismatch:
		return 409 // Conflict — state moved on / collides; client must re-fetch or resolve
	case ClassInvalidArguments:
		return 400 // Bad Request — malformed/invalid arguments
	case ClassUnprocessable:
		return 422 // Unprocessable Entity — well-formed request, semantically bad content
	default: // ClassUnknown, ClassTransient
		return 500
	}
}

// WebDAVStatus projects the class onto the HTTP status the CalDAV/CardDAV
// bridges should write for a reducer error. It mirrors HTTPStatus (DAV is HTTP),
// so an over-quota PUT yields 507, a forbidden one 403, a missing target 404,
// and a stale-state conflict 409 — instead of the blanket 500 the bridges
// returned before this projection existed.
func (c ReplyClass) WebDAVStatus() int { return c.HTTPStatus() }

// JMAPError projects the class onto the RFC 8620 method-level error TYPE string
// a JMAP method returns on failure. It returns "" for ClassUnknown and
// ClassTransient (the internal/un-actionable classes), signaling the caller to
// fall back to serverFail so reducer internals never leak to the client.
func (c ReplyClass) JMAPError() string {
	switch c {
	case ClassOverQuota, ClassSendQuota:
		return "overQuota"
	case ClassForbidden:
		return "forbidden"
	case ClassNotFound:
		return "notFound"
	case ClassAccountNotFound:
		return "accountNotFound"
	case ClassCannotCalc:
		return "cannotCalculateChanges"
	case ClassInvalidArguments:
		return "invalidArguments"
	case ClassStateMismatch:
		return "stateMismatch"
	default: // ClassUnknown, ClassTransient
		return ""
	}
}

// LogLevel projects the class onto the slog severity a gateway should log a
// reducer error at. A client-actionable business error (forbidden, not-found,
// over-quota, stale-state) is an EXPECTED, recoverable condition the protocol
// reports back to the caller — it logs at Info so it stays observable without
// false-alarming the Error stream. ClassUnknown (an unrecognized/internal error
// that surfaces as 500/serverFail) and ClassTransient (an infra/config fault
// that must not leak) are genuine server-side problems → Error. This is the
// single source of truth for the Info-vs-Error split the WebDAV bridges, SCIM,
// and JMAP reducer-error loggers share, replacing each site's hard-coded Error.
func (c ReplyClass) LogLevel() slog.Level {
	switch c {
	case ClassUnknown, ClassTransient:
		return slog.LevelError
	default: // every client-actionable class
		return slog.LevelInfo
	}
}

// SMTPReply projects the class onto the SMTP reply the inbound/submission
// gateway should send: the 3-digit code plus a message line carrying the
// RFC 3463 enhanced status as its prefix. The bool is false for the classes SMTP
// does not surface to a sending MTA (ClassUnknown — keep the caller's safe
// transient default; ClassAccountNotFound / ClassCannotCalc — JMAP-only client
// conditions that have no SMTP-path analog). The reply text is a fixed generic
// line per class — the reducer's human message is never leaked.
//
// 5xx is permanent (the sending MTA must NOT retry); 4xx is transient (it may).
func (c ReplyClass) SMTPReply() (code int, msg string, ok bool) {
	switch c {
	case ClassOverQuota:
		return 552, "5.2.2 Mailbox full", true
	case ClassSendQuota:
		return 552, "5.2.2 Sending quota exceeded", true
	case ClassForbidden:
		return 550, "5.7.1 Message rejected by policy", true
	case ClassNotFound:
		return 550, "5.1.1 Recipient address rejected: no such user", true
	case ClassTransient:
		return 451, "4.3.0 Temporary failure, please try again later", true
	default: // ClassUnknown, ClassAccountNotFound, ClassCannotCalc, ClassInvalidArguments
		return 0, "", false
	}
}
