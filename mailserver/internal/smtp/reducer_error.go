package smtp

import (
	"setjoin.com/shared/reducererr"
)

// smtpReply is an SMTP reply: a 3-digit code plus a message line (which carries
// the RFC 3463 enhanced status code as its prefix, matching how the inbound and
// submission servers already emit replies, e.g. `c.reply(552, "5.2.2 ...")`).
type smtpReply struct {
	code int
	msg  string
}

// classifyReducerReply maps a reducer error to the SMTP reply the gateway should
// send, deciding PERMANENT (5xx — the sending MTA must NOT retry) vs TRANSIENT
// (4xx — the sender may retry). The BZ-code → reply classification now lives in
// the shared internal/reducererr projection (reducererr.Classify +
// ReplyClass.SMTPReply); this is a thin adapter onto it, so the same BZ→reply
// map that jmap/CalDAV/CardDAV route through also drives SMTP. The second return
// is false when the error is not a recognized SMTP-surfacable business error —
// the caller then keeps its existing behavior (a raw infra error stays a
// transient 451, the safe default, so an MTA still backs off and retries rather
// than bouncing on a blip).
//
// Permanent (5xx) — a retry can never succeed, so bouncing immediately is correct
// and stops the sending MTA from retrying a permanent failure forever:
//
//	BZ001 over_quota / BZ009 domain_over_quota → 552 5.2.2 (mailbox full)
//	BZ004 sending_quota_exceeded               → 552 5.2.2 (sender daily quota)
//	BZ002 forbidden / BZ003 send_as_unauthorized / BZ005 dlp_blocked → 550 5.7.1 (policy)
//	BZ007 no_mailbox (unknown recipient)       → 550 5.1.1 (bad destination address)
//
// Transient (4xx) — the condition may clear, so the sender should retry:
//
//	BZ008 missing_inbox (mailbox provisioned without an Inbox tag — a fixable
//	      config/infra state, not a sender error)           → 451 4.3.0
//
// Codes outside this set (BZ010 invalid_side and the rest, the JMAP-only
// account/state classes, or any non-BZ infra error) return ok=false: the
// caller's default 451 stands. We never leak the reducer's human message — the
// reply text is a fixed generic line per class.
func classifyReducerReply(err error) (smtpReply, bool) {
	code, msg, ok := reducererr.Classify(err).SMTPReply()
	if !ok {
		return smtpReply{}, false
	}
	return smtpReply{code, msg}, true
}
