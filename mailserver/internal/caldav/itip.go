package caldav

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type ITIPMethod string

const (
	MethodRequest ITIPMethod = "REQUEST"
	MethodReply   ITIPMethod = "REPLY"
	MethodCancel  ITIPMethod = "CANCEL"
	MethodCounter ITIPMethod = "COUNTER"
)

type ITIPMessage struct {
	Method ITIPMethod
	Event  CalendarEvent
}

func ParseITIP(icalData string) (*ITIPMessage, error) {
	lines := unfoldLines(icalData)
	var method ITIPMethod
	var inEvent bool
	var eventLines []string
	// RFC 5545 §3.7.1: METHOD MUST NOT occur more than once in an iCalendar
	// object. The old last-value-wins loop let a second METHOD overwrite the
	// first — round 3 (Astra HOLD) rejects the object instead, so an appended
	// "METHOD:CANCEL" can never reinterpret a signed "METHOD:REQUEST".
	methodSeen := false

	for _, line := range lines {
		line = strings.TrimSpace(line)
		upper := strings.ToUpper(line)

		if strings.HasPrefix(upper, "METHOD:") {
			if methodSeen {
				return nil, fmt.Errorf("duplicate METHOD property in iCalendar data")
			}
			methodSeen = true
			m := strings.TrimPrefix(line, "METHOD:")
			switch strings.ToUpper(m) {
			case "REQUEST":
				method = MethodRequest
			case "REPLY":
				method = MethodReply
			case "CANCEL":
				method = MethodCancel
			case "COUNTER":
				method = MethodCounter
			default:
				return nil, fmt.Errorf("unsupported iTIP method: %s", m)
			}
			continue
		}

		if line == "BEGIN:VEVENT" {
			inEvent = true
			eventLines = append(eventLines, line)
			continue
		}
		if line == "END:VEVENT" {
			eventLines = append(eventLines, line)
			inEvent = false
			continue
		}
		if inEvent {
			eventLines = append(eventLines, line)
		}
	}

	if method == "" {
		return nil, fmt.Errorf("no METHOD property found in iCalendar data")
	}

	if len(eventLines) == 0 {
		return nil, fmt.Errorf("no VEVENT component found")
	}

	ev, err := parseICal(strings.Join(eventLines, "\n"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse VEVENT: %w", err)
	}

	return &ITIPMessage{Method: method, Event: ev}, nil
}

// ITIPTransportIdentity is the transport-level evidence an inbound iTIP
// message carries (RFC 6047 iMIP): the SMTP envelope MAIL FROM, the RFC 5322
// From header address, and the cryptographic verdicts that make those claims
// meaningful — a DKIM pass with the signing domain aligned (RFC 7489 relaxed,
// organizational-domain) to the From header domain, the SPF result for the
// envelope sender, and an S/MIME signature verdict with the signer email.
//
// Role-authentication contract (security fix D-MAILSERVER-INTERNAL-CALDAV-001/002,
// round 2; round 3 tightens the S/MIME evidence): an iTIP message is
// AUTHENTICATED for role R (the claimed ATTENDEE for REPLY, the event
// ORGANIZER for CANCEL) iff ANY of:
//
//	(a) the S/MIME signature is valid AND the signer certificate email equals
//	    R's email. "Valid" now means the FULL trust policy held at intake: the
//	    signer cert chains to a trusted root (bundled ∪ deployment-wide ∪
//	    per-domain anchors), carries EmailProtection EKU, is within its validity
//	    window, and matches the From header — a self-signed certificate merely
//	    bearing R's email is UNTRUSTED evidence and never sets SmimeValid.
//	    Round 5 additionally binds the chain to its AUTHORITY: the signer
//	    email's domain must be covered by the trust that validated the chain
//	    (SmimeTrustDomains, derived from the validated chain's anchor) — an
//	    anchor imported by tenant A cannot certify authority over tenant B's
//	    signer emails, so a cert it issued for organizer@B never authenticates
//	    B's organizer; OR
//	(b) DKIM passed with the signing domain aligned to the From header domain
//	    AND the From header address equals R's email in full (local part and
//	    domain — a domain-aligned full-address match). The signing domain is the
//	    d= of the signature that actually verified (parse and verifier share one
//	    parse), so duplicate-tag header tricks cannot make an attacker-domain
//	    signature appear victim-aligned. Round 8 (Astra HOLD r15) additionally
//	    CONTENT-BINDS this evidence: the verified signature's l= signed prefix
//	    must cover the calendar actually processed — the SMTP intake clears
//	    DkimAligned when the processed calendar extends beyond the covered
//	    boundary, so a replayed positive-l= prefix cannot launder appended
//	    content into rule-(b) authentication; OR
//	(c) the envelope MAIL FROM equals R's email AND the SPF result is pass.
//
// A bare envelope match authenticates nothing: anyone may type a victim's
// address at the MAIL FROM prompt (and put the same victim in the body). A
// matching From header without DKIM alignment authenticates nothing: the
// header is attacker-owned bytes. Unsigned, unaligned messages are
// UNAUTHENTICATED for every role; the iMIP intake drops them before any
// reducer call (log + count via ErrITIPUnauthenticated). Local resolution and
// copy ownership alone are not authentication.
//
// Round 4 (Astra HOLD, D-MAILSERVER-INTERNAL-CALDAV-004): the identity also
// answers WHICH trust domain authenticated the role — AuthenticatedSignerDomain
// returns the domain of the evidence that authenticated the address (the
// S/MIME signer email domain under rule (a), the From header domain under rule
// (b) — which the alignment requirement pins to the verified DKIM d=
// organizational domain — or the envelope domain under rule (c)). The series-
// CANCEL sweep is bound to that domain: a signer trusted via one tenant's
// trust pool must not authorize cancelling event copies owned by another
// tenant's domains.
// SmimeTrustScope classifies (round 6, Astra HOLD) what the VALIDATED chain's
// trust anchor actually grants, resolved at intake from smime_trust_anchors by
// the anchor's fingerprint. The zero value is deliberately the fail-closed
// state so an identity that never resolved its anchor can never authenticate.
type SmimeTrustScope int

const (
	// SmimeTrustNone: the validated anchor is unknown, has been removed, is
	// scoped to a domain that no longer resolves, or its grant lookup failed.
	// The S/MIME evidence authenticates NOTHING (fail closed — the round-5
	// "empty set means unrestricted" encoding silently degraded every such
	// failure to unrestricted trust).
	SmimeTrustNone SmimeTrustScope = iota
	// SmimeTrustUnrestricted: the chain anchored at a bundled public root or a
	// deployment-wide anchor (domain_id IS NULL) — no tenant-scoped constraint
	// applies to the signer email's domain.
	SmimeTrustUnrestricted
	// SmimeTrustDomainScoped: the chain anchored at a per-tenant anchor whose
	// row grants exactly SmimeTrustDomains — the signer email's domain must be
	// one of them (tenant A's anchor can never certify authority over
	// tenant B's signer emails).
	SmimeTrustDomainScoped
)

type ITIPTransportIdentity struct {
	EnvelopeFrom     string // SMTP envelope MAIL FROM, as received
	FromHeader       string // RFC 5322 From header address, as parsed
	DkimAligned      bool   // eligible DKIM transport evidence (round 8, content-bound): a pass whose signing domain aligns with the From domain AND whose l= signed prefix covers the calendar actually processed — intake clears this flag when the processed calendar extends beyond the covered boundary, so rule (b) never authenticates content the signature does not cover
	DkimDomain       string // d= of the verified DKIM signature, for diagnostics/logging
	SpfPass          bool   // SPF result for the envelope sender is "pass"
	SmimeValid       bool   // trusted-chain S/MIME signature verified over the processed calendar part
	SmimeSignerEmail string // email SAN of the verified signer certificate
	// SmimeTrust + SmimeTrustDomains (round 6, Astra HOLD) record what the
	// VALIDATED chain's trust anchor actually grants: None (fail closed),
	// Unrestricted (bundled public root or deployment-wide anchor), or
	// DomainScoped to SmimeTrustDomains (a per-tenant anchor row). Rule (a)
	// additionally requires the signer email's domain to be covered — the
	// signer email's domain must be covered by the trust that validated the
	// chain, not merely claimed by the certificate.
	SmimeTrust        SmimeTrustScope
	SmimeTrustDomains []string
}

// ErrITIPUnauthenticated is wrapped by every role-authentication rejection so
// the iMIP intake can tell identity failures (drop + log + count) apart from
// downstream processing errors.
var ErrITIPUnauthenticated = errors.New("itip sender not authenticated for the claimed role")

// smimeAuthenticated evaluates rule (a) for the given role address: the
// trusted-chain S/MIME signature whose signer email equals the role AND —
// round 5 (Astra HOLD) — whose signer email's domain is covered by the trust
// that validated the chain (SmimeTrustDomains, captured from the validated
// chain's anchor at intake). It returns the signer email's domain when the
// rule authenticates the address, and ok=false (empty domain, fail closed)
// otherwise. Both AuthenticatedAs and AuthenticatedSignerDomain share this
// single decision so the authentication verdict and the sweep-binding domain
// can never disagree.
func (id ITIPTransportIdentity) smimeAuthenticated(email string) (signerDomain string, ok bool) {
	if !id.SmimeValid {
		return "", false
	}
	signer := strings.Trim(id.SmimeSignerEmail, "<> \t")
	if !strings.EqualFold(signer, email) {
		return "", false
	}
	signerDomain = signerEmailDomain(signer)
	switch id.SmimeTrust {
	case SmimeTrustUnrestricted:
		// Bundled public root or deployment-wide anchor: no tenant-scoped
		// constraint exists, the signer-email match is authoritative.
	case SmimeTrustDomainScoped:
		covered := false
		for _, d := range id.SmimeTrustDomains {
			if d != "" && strings.EqualFold(d, signerDomain) {
				covered = true
				break
			}
		}
		if !covered {
			// The chain was validated under trust that does not cover the
			// signer email's domain (e.g. tenant A's anchor certifying
			// organizer@B): the certificate asserts authority over B that the
			// validated trust never granted. Fail closed.
			return "", false
		}
	default:
		// SmimeTrustNone: unknown/removed/unresolvable anchor or lookup
		// failure — the chain validated under trust this deployment cannot
		// attribute. Fail closed (round 5 treated every such case as
		// unrestricted).
		return "", false
	}
	return signerDomain, true
}

// dnsEvidenceAuthenticated reports whether the DNS-verified, tenant-agnostic
// transport evidence authenticates the given role address: rule (b) a
// DKIM-aligned From header equal to the role (full address), or rule (c) an
// envelope MAIL FROM equal to the role with SPF pass. Unlike the S/MIME class
// this evidence is bound to DNS, not to any deployment's trust anchors, so
// every affected domain's CANCEL policy accepts it (round 7). Empty role
// address never authenticates — fail closed.
func (id ITIPTransportIdentity) dnsEvidenceAuthenticated(email string) bool {
	email = strings.Trim(email, "<> \t")
	if email == "" {
		return false
	}
	// (b) DKIM-aligned full-address From match: the From header is covered by
	// a passing signature from a domain aligned with it, so a full match with
	// the role address is authoritative even over a different envelope
	// (relayed/rewritten MAIL FROM).
	if id.DkimAligned && strings.EqualFold(strings.Trim(id.FromHeader, "<> \t"), email) {
		return true
	}
	// (c) envelope MAIL FROM equal to the role AND SPF pass: SPF validates the
	// sending IP against the envelope domain, which is what makes the envelope
	// claim meaningful.
	return id.SpfPass && strings.EqualFold(strings.Trim(id.EnvelopeFrom, "<> \t"), email)
}

// AuthenticatedAs reports whether the transport identity authenticates the
// message sender AS the given role address under the contract documented on
// ITIPTransportIdentity (case-insensitive; angle brackets and surrounding
// whitespace ignored). An empty role address or an empty identity never
// authenticates — fail closed.
func (id ITIPTransportIdentity) AuthenticatedAs(email string) bool {
	email = strings.Trim(email, "<> \t")
	if email == "" {
		return false
	}
	// (a) S/MIME: the content-bound signature proves the certificate holder
	// signed this message; the certificate email must be the role itself AND
	// (round 5) the signer email's domain must be covered by the validated
	// chain's trust.
	if _, ok := id.smimeAuthenticated(email); ok {
		return true
	}
	// (b)/(c) DNS-verified transport evidence.
	return id.dnsEvidenceAuthenticated(email)
}

// AuthenticatedSignerDomain reports the DNS domain of the transport evidence
// that authenticates the given role address under the contract documented on
// ITIPTransportIdentity — the S/MIME signer certificate email's domain under
// rule (a) (which round 5 pins to a domain covered by the VALIDATED chain's
// trust anchor), the From header domain under rule (b) (pinned by the alignment
// requirement to the verified DKIM d= organizational domain), or the envelope
// MAIL FROM domain under rule (c). Empty when the identity does NOT
// authenticate the address (fail closed). Since round 6 the series-CANCEL sweep
// no longer binds to this domain (per-affected-mailbox trust policy instead —
// see processCancel); it remains part of the identity contract for diagnostics
// and callers that need the evidence's own domain.
func (id ITIPTransportIdentity) AuthenticatedSignerDomain(email string) string {
	email = strings.Trim(email, "<> \t")
	if email == "" {
		return ""
	}
	if domain, ok := id.smimeAuthenticated(email); ok {
		return domain
	}
	if id.DkimAligned && strings.EqualFold(strings.Trim(id.FromHeader, "<> \t"), email) {
		return signerEmailDomain(id.FromHeader)
	}
	if id.SpfPass && strings.EqualFold(strings.Trim(id.EnvelopeFrom, "<> \t"), email) {
		return signerEmailDomain(id.EnvelopeFrom)
	}
	return ""
}

// signerEmailDomain extracts the lower-cased domain of an email/addr-spec
// token (angle brackets and whitespace tolerated). Empty on any malformed
// input — never a wildcard.
func signerEmailDomain(email string) string {
	email = strings.Trim(strings.TrimSpace(email), "<> \t")
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return ""
	}
	return strings.ToLower(email[at+1:])
}

// unauthRejected emits the structured rejection log (with the full identity as
// the rejection reason) shared by every role check.
func (id ITIPTransportIdentity) unauthRejected(logger *slog.Logger, msg, uid, role string) {
	logger.Warn(msg,
		"uid", uid, "role", role,
		"envelope", id.EnvelopeFrom, "from_header", id.FromHeader,
		"dkim_aligned", id.DkimAligned, "dkim_domain", id.DkimDomain,
		"spf_pass", id.SpfPass,
		"smime_valid", id.SmimeValid, "smime_signer", id.SmimeSignerEmail,
		"smime_trust", int(id.SmimeTrust), "smime_trust_domains", id.SmimeTrustDomains)
}

func ProcessITIP(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, msg *ITIPMessage, accountID int64, identity ITIPTransportIdentity) error {
	switch msg.Method {
	case MethodReply:
		return processReply(ctx, pool, logger, &msg.Event, accountID, identity)
	case MethodCancel:
		return processCancel(ctx, pool, logger, &msg.Event, accountID, identity)
	case MethodRequest:
		return processRequest(ctx, pool, logger, &msg.Event)
	default:
		logger.Warn("iTIP method not yet supported", "method", string(msg.Method))
	}
	return nil
}

func processReply(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, ev *CalendarEvent, accountID int64, identity ITIPTransportIdentity) error {
	if len(ev.Attendees) == 0 {
		return fmt.Errorf("REPLY has no attendee")
	}
	attendee := ev.Attendees[0]
	// Transport binding (security fix D-MAILSERVER-INTERNAL-CALDAV-001, round 2):
	// the sender must authenticate AS the claimed attendee under the contract on
	// ITIPTransportIdentity — S/MIME signer == attendee, or a DKIM-aligned From
	// header == attendee, or envelope MAIL FROM == attendee WITH SPF pass. A bare
	// envelope match authenticates nothing. The reducer's local-resolution +
	// copy-ownership check is authorization, not authentication: without this
	// binding anyone who knows a local attendee's address (visible on any prior
	// invite) forges their REPLY, and REPLY is not idempotent.
	if !identity.AuthenticatedAs(attendee.Email) {
		identity.unauthRejected(logger,
			"iTIP REPLY rejected: sender not authenticated as claimed attendee",
			ev.UID, attendee.Email)
		return fmt.Errorf("reply sender is not the claimed attendee: %w", ErrITIPUnauthenticated)
	}
	status := attendee.Status
	if status == "" {
		status = "needs-action"
	}
	if status != "accepted" && status != "tentative" && status != "declined" {
		status = "needs-action"
	}

	var result []byte
	err := pool.QueryRow(ctx,
		`SELECT calendar_process_itip_reply($1, $2, $3, $4, $5, NULL)`,
		ev.UID, attendee.Email, attendee.Name, status, 0,
	).Scan(&result)
	if err != nil {
		logger.Error("itip reply processing failed", "uid", ev.UID, "error", err)
		return err
	}
	logger.Info("iTIP REPLY processed", "uid", ev.UID, "attendee", attendee.Email, "status", status)
	return nil
}

func processCancel(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, ev *CalendarEvent, accountID int64, identity ITIPTransportIdentity) error {
	// RECURRENCE-ID (Task 10): the organizer cancelled ONE occurrence, not the
	// whole series — exclude just that instance on THIS recipient's local
	// copy (accountID, resolved by the SMTP delivery loop from the envelope
	// RCPT). calendar_process_itip_cancel's org-wide "every copy sharing this
	// uid+organizer" sweep below has no RECURRENCE-ID awareness and would
	// wrongly cancel the entire series for every recipient.
	if !ev.RecurrenceIDTime.IsZero() {
		return processCancelOccurrence(ctx, pool, logger, ev, accountID, identity)
	}

	// Verify the sender is the event organizer
	var dbOrganizer string
	err := pool.QueryRow(ctx,
		`SELECT organizer_email FROM calendar_events WHERE uid = $1 AND status != 'cancelled' LIMIT 1`,
		ev.UID,
	).Scan(&dbOrganizer)
	if err != nil {
		logger.Warn("iTIP CANCEL: event not found or already cancelled", "uid", ev.UID)
		return fmt.Errorf("event not found")
	}
	if ev.Organizer.Email == "" || !strings.EqualFold(ev.Organizer.Email, dbOrganizer) {
		logger.Warn("iTIP CANCEL: sender is not the event organizer",
			"uid", ev.UID, "sender", ev.Organizer.Email, "organizer", dbOrganizer)
		return fmt.Errorf("only the event organizer can cancel")
	}
	// Transport binding (security fix D-MAILSERVER-INTERNAL-CALDAV-002, round 2):
	// the sender must authenticate AS the DB organizer under the contract on
	// ITIPTransportIdentity — S/MIME signer == organizer, or a DKIM-aligned
	// From header == organizer (a relayed CANCEL with a rewritten envelope is
	// legitimate), or envelope MAIL FROM == organizer WITH SPF pass. A body
	// ORGANIZER copied from any prior invite is not authentication, and the
	// reducer's org-wide uid+organizer sweep makes a forged series CANCEL
	// high-impact. This is the SOLE enforcing decision: the old intake-side
	// envelope-only check was removed (it rejected the DKIM rule-(b) case and
	// accepted the unauthenticated spoofed-envelope case). Round 6 adds the
	// S/MIME cancel-specific rule (a) variant that defers the trust-domain
	// coverage question to the per-affected-mailbox policy below.
	if !identity.AuthenticatedAs(dbOrganizer) && !identity.smimeValidForCancel(dbOrganizer) {
		identity.unauthRejected(logger,
			"iTIP CANCEL rejected: sender not authenticated as event organizer",
			ev.UID, dbOrganizer)
		return fmt.Errorf("only the event organizer can cancel: %w", ErrITIPUnauthenticated)
	}

	// Pass the DB-canonical organizer (verified equal to the sender above) so the
	// reducer scopes the cancel to copies sharing this organizer_email — a cross-tenant
	// UID collision cannot cancel an unrelated event.
	//
	// Round 7 per-affected-mailbox trust policy (security fix
	// D-MAILSERVER-INTERNAL-CALDAV-004 reopened, Astra HOLD r14): the sweep is
	// gated per affected mailbox, and the evidence classes are evaluated as an
	// OR for EACH one — role-matching DKIM evidence (rule (b)), role-matching
	// SPF evidence (rule (c)), or mailbox-trusted S/MIME evidence (rule (a),
	// accepted only as far as that domain's own trust reaches: unrestricted,
	// or the domain inside the validated anchor's grant set; SmimeTrustNone
	// accepts nothing, fail closed). Round 6 classified the whole message by a
	// single evidence class and let S/MIME preempt DKIM/SPF, so an external
	// organizer carrying BOTH valid DKIM/SPF AND a tenant-A-scoped S/MIME
	// signature could not cancel tenant B's copy even though the independent
	// DNS-verified evidence satisfies B's trust policy. S/MIME evidence no
	// longer preempts: each affected mailbox accepts whichever evidence class
	// ITS trust policy covers. The reducer is invoked once per accepted owner
	// domain, so copies whose policy rejected every evidence class are never
	// swept. The S/MIME classification still uses the cancel-specific rule (a)
	// (smimeValidForCancel): smimeAuthenticated would additionally demand
	// signer-email-domain coverage and thus reject a legitimate
	// external-organizer S/MIME CANCEL before the per-mailbox policy could
	// accept it for the domains its anchor actually grants.
	smimeEvidence := identity.smimeValidForCancel(dbOrganizer)
	affected, err := cancelAffectedDomains(ctx, pool, ev.UID, dbOrganizer)
	if err != nil {
		logger.Error("iTIP CANCEL: affected-copy resolution failed", "uid", ev.UID, "error", err)
		return err
	}
	var accepted []string
	var rejected []string
	for _, d := range affected {
		if identity.domainAcceptsCancelEvidence(d, dbOrganizer, smimeEvidence) {
			accepted = append(accepted, d)
		} else {
			rejected = append(rejected, d)
		}
	}
	if len(affected) == 0 {
		// No local copy of this uid+organizer exists — nothing to cancel.
		logger.Info("iTIP CANCEL: no local copies for uid+organizer", "uid", ev.UID, "organizer", dbOrganizer)
		return nil
	}
	if len(accepted) == 0 {
		// Fail closed: every affected mailbox's policy rejected the evidence.
		identity.unauthRejected(logger,
			"iTIP CANCEL rejected: no affected mailbox's trust policy accepts the authenticated evidence",
			ev.UID, dbOrganizer)
		return fmt.Errorf("only the event organizer can cancel: %w", ErrITIPUnauthenticated)
	}
	if len(rejected) > 0 {
		logger.Warn("iTIP CANCEL: copies skipped — owner-domain policy rejected the evidence",
			"uid", ev.UID, "organizer", dbOrganizer, "skipped_domains", rejected)
	}
	var firstErr error
	for _, d := range accepted {
		var result []byte
		err = pool.QueryRow(ctx,
			`SELECT calendar_process_itip_cancel($1, NULL, $2, $3)`,
			ev.UID, dbOrganizer, d,
		).Scan(&result)
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		logger.Error("itip cancel processing failed", "uid", ev.UID, "error", firstErr)
		return firstErr
	}
	logger.Info("iTIP CANCEL processed", "uid", ev.UID, "domains", accepted)
	return nil
}

// cancelAffectedDomains enumerates the DISTINCT owner-mailbox domains of every
// non-cancelled local event copy sharing uid+organizer — exactly the sweep
// scope calendar_process_itip_cancel applies (calendars → mailboxes → domains
// join, status <> 'cancelled'), so the per-mailbox policy gate sees the same
// copies the reducer would cancel.
func cancelAffectedDomains(ctx context.Context, pool *pgxpool.Pool, uid, organizer string) ([]string, error) {
	rows, err := pool.Query(ctx,
		`SELECT DISTINCT lower(d.name)
		   FROM calendar_events ce
		   JOIN calendars c ON c.id = ce.calendar_id
		   JOIN mailboxes mb ON mb.id = c.mailbox_id
		   JOIN domains d ON d.id = mb.domain_id
		  WHERE ce.uid = $1
		    AND lower(ce.organizer_email) = lower($2)
		    AND ce.status <> 'cancelled'`,
		uid, organizer,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var domains []string
	for rows.Next() {
		var d string
		if err := rows.Scan(&d); err == nil && d != "" {
			domains = append(domains, d)
		}
	}
	return domains, rows.Err()
}

// smimeValidForCancel reports whether rule (a) authenticates the CANCEL role
// at the identity level (round 6): the S/MIME signature is valid, the signer
// email equals the organizer, and the validated chain anchored at trust this
// deployment can attribute (unrestricted or domain-scoped — never
// SmimeTrustNone). Unlike smimeAuthenticated it does NOT require the signer
// email's domain to be covered by a domain-scoped anchor's grant: that check
// is the PER-AFFECTED-MAILBOX policy (domainAcceptsCancelEvidence), because
// requiring it here too kept suppressing legitimate external-organizer
// cancellations (an anchor imported by the RECIPIENT tenant that certified an
// external organizer could never pass a signer-email-domain match). The
// round-5 protection itself is preserved: tenant A's anchor still cannot
// cancel tenant B's copies, because B's policy rejects evidence its own trust
// never granted.
func (id ITIPTransportIdentity) smimeValidForCancel(email string) bool {
	if !id.SmimeValid {
		return false
	}
	signer := strings.Trim(id.SmimeSignerEmail, "<> \t")
	if !strings.EqualFold(signer, email) {
		return false
	}
	switch id.SmimeTrust {
	case SmimeTrustUnrestricted, SmimeTrustDomainScoped:
		return true
	default:
		return false
	}
}

// domainAcceptsCancelEvidence reports whether owner domain's trust policy
// accepts the evidence that authenticated the organizer for a series-CANCEL
// sweep. Round 7 (Astra HOLD r14): the evidence classes are an OR per affected
// mailbox — role-matching DNS-verified transport evidence (DKIM-aligned From
// under rule (b), SPF'd envelope under rule (c), both matching the organizer)
// is not tenant-scoped, so every domain accepts it and S/MIME evidence never
// preempts it. S/MIME evidence (rule (a)) is trusted only as far as the
// DOMAIN's own trust reaches: unrestricted for a bundled public root or
// deployment-wide anchor, the anchor's granted domains for a per-tenant
// anchor, and NOTHING when the anchor is unknown/removed/unresolvable
// (SmimeTrustNone — fail closed). An empty domain never accepts; with no
// authenticating evidence class the answer is false (fail closed for any
// caller that skips the identity-level gate).
func (id ITIPTransportIdentity) domainAcceptsCancelEvidence(domain, organizer string, smimeEvidence bool) bool {
	if domain == "" {
		return false
	}
	// Rules (b)/(c): DNS-verified transport evidence binds to the DNS that
	// every domain's policy already trusts — accept it regardless of the
	// S/MIME verdict.
	if id.dnsEvidenceAuthenticated(organizer) {
		return true
	}
	if !smimeEvidence {
		return false
	}
	switch id.SmimeTrust {
	case SmimeTrustUnrestricted:
		return true
	case SmimeTrustDomainScoped:
		for _, d := range id.SmimeTrustDomains {
			if d != "" && strings.EqualFold(d, domain) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// processCancelOccurrence excludes ONE occurrence (ev.RecurrenceIDTime) of the
// series on accountID's local master copy, via the same set_occurrence('this',
// {"excluded":true}) path the webmail scope dialog and CalDAV PUT reconciliation
// use. Best-effort: no local master for this recipient/uid is not an error
// (nothing to cancel locally yet). Round 7: the affected copy's owner domain
// must accept the authenticated evidence under the same per-mailbox OR trust
// policy the series sweep applies (the occurrence path touches exactly the
// recipient's mailbox, so its owner domain is the one policy that matters) —
// role-matching DKIM/SPF transport evidence is accepted by every domain, and
// S/MIME evidence no longer preempts it (round 6 stranded mixed-evidence
// organizers whose S/MIME trust did not cover the recipient's domain).
func processCancelOccurrence(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, ev *CalendarEvent, accountID int64, identity ITIPTransportIdentity) error {
	if accountID == 0 {
		logger.Warn("iTIP CANCEL: no local recipient mailbox resolved, skipping occurrence cancel", "uid", ev.UID)
		return nil
	}
	var masterID int64
	var dbOrganizer string
	var ownerDomain string
	err := pool.QueryRow(ctx,
		`SELECT ce.id, ce.organizer_email, lower(d.name)
		   FROM calendar_events ce
		   JOIN calendars c ON c.id = ce.calendar_id
		   JOIN mailboxes m ON m.id = c.mailbox_id
		   LEFT JOIN domains d ON d.id = m.domain_id
		  WHERE ce.uid = $1 AND c.mailbox_id = $2 AND ce.recurrence_override IS NULL`,
		ev.UID, accountID,
	).Scan(&masterID, &dbOrganizer, &ownerDomain)
	if err != nil {
		logger.Warn("iTIP CANCEL: no local master for this occurrence, skipping", "uid", ev.UID)
		return nil
	}
	if ev.Organizer.Email == "" || !strings.EqualFold(ev.Organizer.Email, dbOrganizer) {
		logger.Warn("iTIP CANCEL: sender is not the event organizer",
			"uid", ev.UID, "sender", ev.Organizer.Email, "organizer", dbOrganizer)
		return fmt.Errorf("only the event organizer can cancel")
	}
	// Transport binding, same contract as the series path: the occurrence
	// exclude must also be issued by an authenticated organizer (round 6 adds
	// the S/MIME cancel-specific rule (a) variant).
	smimeEv := identity.smimeValidForCancel(dbOrganizer)
	if !identity.AuthenticatedAs(dbOrganizer) && !smimeEv {
		identity.unauthRejected(logger,
			"iTIP CANCEL occurrence rejected: sender not authenticated as event organizer",
			ev.UID, dbOrganizer)
		return fmt.Errorf("only the event organizer can cancel: %w", ErrITIPUnauthenticated)
	}
	// Round 7 per-mailbox policy: the recipient mailbox's owner domain must
	// accept the evidence under the per-mailbox OR — role-matching DKIM/SPF
	// transport evidence is accepted by every domain; S/MIME evidence must be
	// covered by the domain's own trust. The old round-6 call gated on
	// smimeEv alone, so an A-scoped S/MIME verdict preempted valid DKIM/SPF
	// evidence and rejected the occurrence for mailboxes the anchor never
	// granted.
	if !identity.domainAcceptsCancelEvidence(ownerDomain, dbOrganizer, smimeEv) {
		identity.unauthRejected(logger,
			"iTIP CANCEL occurrence rejected: mailbox owner-domain trust policy rejects the evidence",
			ev.UID, dbOrganizer)
		return fmt.Errorf("only the event organizer can cancel: %w", ErrITIPUnauthenticated)
	}

	patch, _ := json.Marshal(map[string]any{"excluded": true})
	var result []byte
	if err := pool.QueryRow(ctx,
		`SELECT jmap_calendar_event_set_occurrence($1,$2,$3::timestamptz,'this',$4::jsonb)`,
		accountID, masterID, ev.RecurrenceIDTime, string(patch),
	).Scan(&result); err != nil {
		logger.Error("iTIP CANCEL occurrence exclude failed", "uid", ev.UID, "error", err)
		return err
	}
	logger.Info("iTIP CANCEL excluded one occurrence", "uid", ev.UID, "recurrence_id", ev.RecurrenceIDTime)
	return nil
}

func processRequest(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger, ev *CalendarEvent) error {
	logger.Info("iTIP REQUEST received — creating tentative event", "uid", ev.UID, "title", ev.Title)
	// Resolve userID from attendee email(s) — use the first attendee who exists locally
	var userID int64
	var recipientEmail string
	for _, a := range ev.Attendees {
		if a.Email != "" {
			if err := pool.QueryRow(ctx,
				`SELECT id FROM users WHERE email = lower($1) AND enabled = TRUE LIMIT 1`, a.Email,
			).Scan(&userID); err == nil {
				recipientEmail = a.Email
				break
			}
		}
	}
	if userID == 0 {
		logger.Warn("iTIP REQUEST: no local user found for attendees, skipping")
		return nil
	}

	// Rate limit: max 20 iTIP REQUEST events per recipient per hour.
	// Two compounding bugs made this never work: (1) p_window_min is INTEGER
	// minutes, not an interval literal — the previous '1 hour' string made
	// every call error (invalid input syntax for type integer), and the error
	// was silently discarded (bare .Scan with no err check); (2) rate_limit_check
	// already returns TRUE-means-allowed — wrapping it in SQL NOT inverted that,
	// so combined with bug (1)'s swallowed-error zero-value the two bugs
	// happened to cancel out into "always blocked" for ordinary traffic (worse:
	// an ALREADY-blocked key would incorrectly read as "allowed" once the SQL
	// stopped erroring). rateOK is now rate_limit_check's result directly.
	var rateOK bool
	if err := pool.QueryRow(ctx,
		`SELECT rate_limit_check($1, 20, 60)`, fmt.Sprintf("itip:recipient:%d", userID),
	).Scan(&rateOK); err != nil {
		logger.Error("iTIP REQUEST: rate_limit_check failed", "uid", ev.UID, "error", err)
		return err
	}
	if !rateOK {
		logger.Warn("iTIP REQUEST: rate limit exceeded", "uid", ev.UID, "user_id", userID)
		return nil
	}

	// The recipient's primary mailbox — jmap_calendar_event_set_create takes
	// p_mailbox_id, not a user id (ADR-003 divergent ids; see caldav/put PUT fix).
	var mailboxID int64
	if err := pool.QueryRow(ctx,
		`SELECT id FROM mailboxes WHERE user_id = $1 AND is_primary = TRUE LIMIT 1`, userID,
	).Scan(&mailboxID); err != nil {
		logger.Warn("iTIP REQUEST: no primary mailbox for local user, skipping", "user_id", userID)
		return nil
	}

	// RECURRENCE-ID exception (Task 10): apply to the recipient's EXISTING
	// local series instead of falling into the whole-series dedup below — an
	// occurrence-update REQUEST for an already-known series must not be
	// dropped as "already exists, skipping".
	if !ev.RecurrenceIDTime.IsZero() {
		var masterID int64
		err := pool.QueryRow(ctx,
			`SELECT ce.id FROM calendar_events ce JOIN calendars c ON c.id = ce.calendar_id
			 WHERE ce.uid = $1 AND c.mailbox_id = $2 AND ce.recurrence_override IS NULL`,
			ev.UID, mailboxID,
		).Scan(&masterID)
		if err == nil {
			patch, _ := json.Marshal(map[string]any{
				"title": ev.Title, "description": ev.Description, "location": ev.Location,
				"start": ev.Start.Format(time.RFC3339), "end": ev.End.Format(time.RFC3339),
				"isAllDay": ev.AllDay, "status": "tentative",
			})
			var result []byte
			applyErr := pool.QueryRow(ctx,
				`SELECT jmap_calendar_event_set_occurrence($1,$2,$3::timestamptz,'this',$4::jsonb)`,
				mailboxID, masterID, ev.RecurrenceIDTime, string(patch),
			).Scan(&result)
			if applyErr != nil {
				logger.Error("iTIP REQUEST occurrence apply failed", "uid", ev.UID, "error", applyErr)
				return applyErr
			}
			logger.Info("iTIP REQUEST occurrence applied", "uid", ev.UID, "recurrence_id", ev.RecurrenceIDTime)
			return nil
		}
		// No local master yet (e.g. Outlook can send the exception before the
		// series invite). ponytail: no reconciliation pass — fall through to
		// create a standalone row below; the shared uid IS the adoption once
		// the series REQUEST later arrives (it becomes this row's series, and
		// this row is a detached override sharing its uid).
	}

	// Dedup: skip if event with this UID already exists for this user
	var exists bool
	pool.QueryRow(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM calendar_events ce
			JOIN calendars c ON c.id = ce.calendar_id
			WHERE ce.uid = $1 AND c.mailbox_id = $2
		)`, ev.UID, mailboxID,
	).Scan(&exists)
	if exists {
		logger.Info("iTIP REQUEST: event already exists, skipping", "uid", ev.UID)
		return nil
	}

	// Create the event as tentative — user must explicitly accept
	obj := map[string]interface{}{
		"uid":      ev.UID,
		"title":    ev.Title,
		"start":    ev.Start.Format(time.RFC3339),
		"end":      ev.End.Format(time.RFC3339),
		"isAllDay": ev.AllDay,
		"timeZone": ev.Timezone,
		"status":   "tentative",
	}
	if ev.Description != "" {
		obj["description"] = ev.Description
	}
	if ev.Location != "" {
		obj["location"] = ev.Location
	}
	if ev.RRULE != "" {
		obj["recurrenceRule"] = ev.RRULE
	}
	creates := map[string]interface{}{"k1": obj}
	var result []byte
	// jmap_calendar_event_set_create takes (p_mailbox_id, p_actor_id,
	// p_actor_email, p_creates) — the previous 2-arg call raised a raw
	// "function does not exist" error on every inbound REQUEST (same shape as
	// the CalDAV PUT-create bug fixed alongside Task 7).
	err := pool.QueryRow(ctx,
		`SELECT jmap_calendar_event_set_create($1, $2, $3, $4)`,
		mailboxID, userID, recipientEmail, creates,
	).Scan(&result)
	if err != nil {
		logger.Error("iTIP REQUEST create event failed", "uid", ev.UID, "error", err)
		return err
	}
	logger.Info("iTIP REQUEST event created", "uid", ev.UID)
	return nil
}
