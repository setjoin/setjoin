package jmap

import (
	"encoding/json"
	"log/slog"

	"setjoin.com/shared/reducererr"
)

// mapReducerErr translates a reducer error into the JMAP error JSON a method
// returns on failure. It is the single source of truth for the generic
// reducer-error → JMAP-type map, replacing the ~49 identical "log + marshal
// serverFail" blocks that used to collapse EVERY reducer error to serverFail.
//
// Both the BZ-code → reply CLASSIFICATION (reducererr.Classify +
// ReplyClass.JMAPError) and the per-code detail string (reducererr.Detail —
// c6) live in internal/reducererr, the single projection every gateway
// protocol shares. This function keeps only the JMAP-local concerns: the
// Info-vs-Error log level split and the serverFail fallback. The covered set
// is the client-actionable codes from docs/reducer-error-codes.md — codes a
// client can meaningfully branch on; genuinely-internal codes (BZ008
// missing_inbox, BZ010 invalid_side, BZ034 NULL mailbox) project to
// ClassUnknown/ClassTransient whose JMAPError() is "" → the serverFail default,
// so reducer internals never leak.
//
//	BZ011 (jmap state unavailable)    → cannotCalculateChanges (RFC 8620 §5.2 resync)
//	BZ006 (account not found)         → accountNotFound
//	BZ002 / BZ003 / BZ005             → forbidden
//	BZ001 (over_quota) / BZ004 / BZ009 → overQuota
//	BZ007 (no_mailbox for recipient)  → notFound
//	everything else                   → serverFail / "database error"
//
// BZ001 is dual-use (over_quota in mail reducers; forbidden/notFound in calendar
// reducers — the slug, not the code, disambiguates, per the catalog note).
// reducererr.Classify routes it on the HINT.type slug so a calendar BZ001
// reaching this generic default is NOT mis-mapped to overQuota; only the
// `over_quota` slug projects to overQuota, all other BZ001 slugs fall through to
// serverFail (calendar paths map their own BZ001 in calendarA3Error before
// delegating here).
//
// The default arm preserves today's behavior exactly: an unrecognized error
// (transport blip, non-business pgError, a BZ code outside this map) is logged
// at Error level and surfaces as serverFail — the byte-for-byte string the
// hand-written blocks produced. Recognized business errors are logged at Info
// (an expected client-recoverable condition, e.g. a stale sinceState forcing a
// resync — not a server fault) so the signal is kept without false-alarming.
//
// method is the handler name used in the log line (e.g. "emailChanges"), so the
// replaced sites keep their per-method log context.
func mapReducerErr(err error, logger *slog.Logger, method string) json.RawMessage {
	if jmapType := reducererr.Classify(err).JMAPError(); jmapType != "" {
		// The detail string comes from the shared reducererr.Detail projection
		// (c6): per-code passthrough allowlist / fixed wording / per-class
		// fallback — byte-identical to the per-code strings the hand-written
		// blocks (and the former jmapDetail switch) emitted.
		return mapped(logger, method, err, jmapType, reducererr.Detail(err))
	}

	// Default arm — byte-for-byte the old hand-written fallback: log at Error,
	// return serverFail / "database error".
	if logger != nil {
		logger.Error(method+" failed", "error", err)
	}
	j, _ := json.Marshal(Error{Type: "serverFail", Description: "database error"})
	return j
}

// mapped logs a recognized business error at Info (expected, client-recoverable)
// and returns the JMAP Error JSON for the given type. The detail string is kept
// generic — it must not leak reducer internals to the client.
func mapped(logger *slog.Logger, method string, err error, jmapType, detail string) json.RawMessage {
	if logger != nil {
		logger.Info(method+" reducer business error",
			"error", err, "jmapType", jmapType)
	}
	j, _ := json.Marshal(Error{Type: jmapType, Description: detail})
	return j
}
