package jmap

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// statecodec.go — the ONE owner of the JMAP state-token WIRE representation (c1).
//
// Reducers own the raw counters and bump them in-txn (logic-where-the-data-is);
// PL/pgSQL renders its own oldState/newState as the counter's decimal text,
// which encodeStateToken reproduces byte-for-byte. This file owns every GO-side
// rendering/parsing of a state string:
//
//   producers: GetSessionState (composite), scanStateTokens /
//     satelliteStateForMailbox (per-domain counters), identityState
//     (users.updated_at unix seconds), the constant empty-domain states
//     (Blob/get, Reminder/get) and the Mailbox/queryChanges default.
//     internal/ws pushes JMAPStateTokens / GetSessionState output verbatim.
//   consumers: the */changes handlers' sinceState gate (sinceStateError) —
//     a token the codec cannot decode can never delta, so it maps to
//     cannotCalculateChanges (RFC 8620 §5.2) instead of leaking a reducer
//     cast error as serverFail.
//
// The offline SPA persists sinceState across sessions (offline/sync.ts stores
// res.newState and feeds Number(res.newState)), so the encode side MUST stay
// byte-identical to today's wire strings: plain base-10 int64 per domain, and
// the 8-part dash-joined composite for sessionState. Golden-pinned in
// statecodec_test.go — do not change without a client migration plan.

// stateUnavailable is the ERROR-path sentinel. It is deliberately not a valid
// token: "0" (the old sentinel) is a legitimate counter value (fresh mailbox),
// so an error emitting "0" was indistinguishable from real state — a client
// could cache it and believe an empty delta (the c1 "0"-sentinel /
// error-collapse defect). stateUnavailable never decodes, never equals a real
// token, and converges: the next successful read differs, forcing a re-fetch.
const stateUnavailable = "unavailable"

// encodeStateToken renders a per-domain state counter to its wire form:
// plain base-10 — byte-identical to the PL/pgSQL reducers' counter::TEXT.
func encodeStateToken(counter int64) string {
	return strconv.FormatInt(counter, 10)
}

// decodeStateToken parses a client-supplied per-domain token. Valid tokens are
// non-negative base-10 int64 (the counters never go negative). ok=false for
// anything else — including stateUnavailable echoed back by a client.
func decodeStateToken(s string) (int64, bool) {
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil || v < 0 {
		return 0, false
	}
	return v, true
}

// sessionStateComponents are the eight per-capability inputs folded into the
// RFC 8620 §2 sessionState string, in wire order. Identity is
// users.updated_at as unix seconds (the same value identityState renders);
// the rest are the raw counters / satellite MAX cursors.
type sessionStateComponents struct {
	Email, Mailbox, Thread, Tag, Calendar, Contact, Task, Identity int64
}

// encodeSessionState renders the composite sessionState:
// "email-mailbox-thread-tag-calendar-contact-task-identity" (dash-joined
// base-10) — byte-identical to the historical fmt.Sprintf wire format.
func encodeSessionState(c sessionStateComponents) string {
	return fmt.Sprintf("%d-%d-%d-%d-%d-%d-%d-%d",
		c.Email, c.Mailbox, c.Thread, c.Tag, c.Calendar, c.Contact, c.Task, c.Identity)
}

// decodeSessionState parses a composite sessionState. ok=false unless the
// string is exactly eight dash-separated non-negative int64s.
//
//nolint:unused // decode half of the codec contract; used by statecodec_test.go (round-trip + sentinel pins)
func decodeSessionState(s string) (sessionStateComponents, bool) {
	parts := strings.Split(s, "-")
	if len(parts) != 8 {
		return sessionStateComponents{}, false
	}
	var vals [8]int64
	for i, p := range parts {
		v, ok := decodeStateToken(p)
		if !ok {
			return sessionStateComponents{}, false
		}
		vals[i] = v
	}
	return sessionStateComponents{
		Email: vals[0], Mailbox: vals[1], Thread: vals[2], Tag: vals[3],
		Calendar: vals[4], Contact: vals[5], Task: vals[6], Identity: vals[7],
	}, true
}

// sinceStateError validates a client sinceState against the codec. nil means
// the token is well-formed (the reducer still decides stale-vs-current);
// otherwise it returns the cannotCalculateChanges error JSON (RFC 8620 §5.2:
// a state string the server cannot calculate changes from → client resyncs).
// Previously a malformed token hit the reducer's ::BIGINT cast (SQLSTATE
// 22P02) and surfaced as serverFail — a dead end instead of a resync.
func sinceStateError(sinceState string) json.RawMessage {
	if _, ok := decodeStateToken(sinceState); ok {
		return nil
	}
	errJSON, _ := json.Marshal(Error{
		Type:        "cannotCalculateChanges",
		Description: "client must resync (malformed sinceState)",
	})
	return errJSON
}
