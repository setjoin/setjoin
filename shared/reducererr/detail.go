package reducererr

import (
	"errors"

	"github.com/jackc/pgx/v5/pgconn"
)

// detail.go — the wire DETAIL projection: the one place that decides whether a
// reducer's human text (pgErr.Message / HINT) may pass through to the client.
//
// Three tiers, first match wins:
//  1. detailPass — a per-code allowlist of codes whose reducer-authored text IS
//     the wire detail. passMessage carries pgErr.Message (the RAISE line);
//     passHint prefers pgErr.Hint (the CA family writes actionable hints,
//     surfaced verbatim by the SPA — see conditional-access/state-helpers.ts)
//     and falls back to Message. These are the codes the pre-c6 hand-rolled
//     handler switches deliberately surfaced.
//  2. detailFixed — a fixed per-code string (the former jmap per-code wording,
//     kept byte-identical).
//  3. per-class fallback — a fixed generic string. An UNLISTED code never
//     leaks raw SQLERRM/HINT, whatever a handler does with the return value.
type passMode int

const (
	passMessage passMode = iota
	passHint
)

// detailPass is the passthrough allowlist. Every entry names the handler whose
// pre-c6 switch established that the reducer text is user-facing.
var detailPass = map[string]passMode{
	// jmap/quicksteps.go, jmap/email_templates.go, jmap/savedsearches.go —
	// validation messages authored for the composer UI.
	"BZ040": passMessage,
	"BZ041": passMessage,
	"BZ043": passMessage,
	// admin/access_reviews.go — access-review campaign/item messages.
	"BZ060": passMessage,
	"BZ061": passMessage,
	"BZ062": passMessage,
	"BZ063": passMessage,
	"BZ069": passMessage,
	// admin/admin_protection.go — SoD/protection denial messages.
	"BZ064": passMessage,
	"BZ065": passMessage,
	"BZ066": passMessage,
	// admin/admin_offline.go — offline device transition messages.
	"BZ100": passMessage,
	// admin/admin_jit.go — JIT activation messages.
	"BZ104": passMessage,
	"BZ105": passMessage,
	// approval/handler.go — approval decide messages.
	"BZ106": passMessage,
	"BZ107": passMessage,
	"BZ108": passMessage,
	"BZ109": passMessage,
	"BZ110": passMessage,
	// user/sharing.go + admin/admin_sharing.go — sharing/delegation validation
	// and auth-ladder messages authored for the sharing dialogs (§6 error
	// states). BZ114 (not owner / not found) deliberately stays on the class
	// fallback — 404-indistinguishable, no ownership oracle.
	"BZ115": passMessage,
	"BZ116": passMessage,
	"BZ117": passMessage,
	// user/notification_prefs.go — vip_sender_set validation message.
	"BZ122": passMessage,
	// calendar_recurrence.sql jmap_calendar_event_set_occurrence — recurrenceId
	// is not a real occurrence of the series (typo/timezone-shift guard).
	"BZ123": passMessage,
	// approval/hr.go — hr_request_create field-level validation messages.
	// BZ125 (approval_request_cancel) deliberately stays on the class fallback —
	// 404-indistinguishable, no ownership oracle (same posture as BZ114/BZ121).
	"BZ124": passMessage,
	"BZ126": passMessage,
	// task_lists.sql / task_list_tasks.sql / tasks_assigned.sql — shared task
	// list validation messages (name/email/roster/status), user-actionable.
	// BZ130/BZ132 (not found / not a member) deliberately stay on the class
	// fallback — 404-indistinguishable, no membership oracle.
	"BZ131": passMessage,
	"BZ133": passMessage,
	// admin_conditional_access.go caErrorDetail (+ admin_ca_templates,
	// admin_ca_import_export, admin_named_locations, admin_auth_strengths,
	// admin_terms_of_use, admin_device_lockdown) — the CA family surfaces the
	// reducer HINT (actionable remediation text, or a structured JSON hint the
	// SPA parses) and falls back to the message.
	"BZ080": passHint,
	"BZ081": passHint,
	"BZ082": passHint,
	"BZ085": passHint,
	"BZ086": passHint,
	"BZ087": passHint,
	"BZ088": passHint,
	"BZ090": passHint,
	"BZ091": passHint,
	"BZ092": passHint,
	"BZ093": passHint,
	"BZ094": passHint,
	"BZ095": passHint,
	"BZ097": passHint,
	"BZ098": passHint,
	// authserver terms.go touHint surfaces BZ102's HINT the same way (it cannot
	// import this internal package — module boundary — but the contract row is
	// recorded here so the two stay aligned).
	"BZ102": passHint,
}

// detailFixed carries the per-code fixed strings the pre-c6 jmap helpers wrote
// — byte-identical so the JMAP Description wire text does not move.
var detailFixed = map[string]string{
	ErrOverQuota:            "over quota", // BZ001 (over_quota slug; the calendar slugs never reach Detail — Classify sends them to ClassUnknown)
	ErrDomainOverQuota:      "over quota",
	ErrSendingQuotaExceeded: "sending quota exceeded",
	ErrForbidden:            "access denied",
	ErrSendAsUnauthorized:   "not authorized to send from this address",
	ErrDLPBlocked:           "message blocked by policy",
	ErrAccountNotFound:      "accountId does not match an existing account",
	ErrNoMailbox:            "recipient not found",
	ErrCannotCalcChanges:    "client must resync (sinceState too old)",
	"BZ038":                 "reminder not found",
	"BZ039":                 "snooze time must be in the future",
	"BZ042":                 "quick step not found",
	"BZ045":                 "contact group not owned by caller",
}

// Detail projects a reducer error onto the wire detail string. See the file
// comment for the tiering. For an unrecognized/non-business error it returns
// the generic "request failed" — callers that want a bespoke 500 body should
// branch on Classify(err) == ClassUnknown before consulting Detail.
func Detail(err error) string {
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		return "request failed"
	}
	class := Classify(err)
	// A dual-use code whose CURRENT slug classifies to ClassUnknown (the
	// calendar BZ001 flavors) or to a different meaning than its allowlist
	// entry (queue BZ081 bad_outcome — internal worker path, never the
	// CA-family hint passthrough) must not ride the primary meaning's tier.
	if class == ClassUnknown || class == ClassTransient {
		return "request failed"
	}
	if pgErr.Code == "BZ081" && class == ClassInvalidArguments {
		return class.detailFallback()
	}
	// Dual-use BZ099: the last_global slug surfaces the reducer message
	// ("cannot delete the last global offline policy" — admin_offline.go
	// DeletePolicy); the not-found flavor keeps its fixed string.
	if pgErr.Code == "BZ099" {
		if class == ClassConflict && pgErr.Message != "" {
			return pgErr.Message
		}
		return "policy not found"
	}
	if mode, ok := detailPass[pgErr.Code]; ok {
		if mode == passHint && pgErr.Hint != "" {
			return pgErr.Hint
		}
		if pgErr.Message != "" {
			return pgErr.Message
		}
	}
	if s, ok := detailFixed[pgErr.Code]; ok {
		return s
	}
	return class.detailFallback()
}

// detailFallback is the per-class fixed string for codes with no per-code
// entry. For the classes with a JMAP analog it is the RFC 8620 type string —
// exactly what jmap.mapReducerErr's old jmapDetail fallback emitted — so the
// generic JMAP path stays byte-identical.
func (c ReplyClass) detailFallback() string {
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
	case ClassConflict:
		return "conflict"
	case ClassStateMismatch:
		return "stateMismatch"
	case ClassUnprocessable:
		return "unprocessable"
	default: // ClassUnknown, ClassTransient — internal; never leak reducer text
		return "request failed"
	}
}
