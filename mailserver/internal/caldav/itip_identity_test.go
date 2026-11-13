package caldav

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// teardownPeerTenants removes seeded extra-tenant rows (calendar copies,
// calendars, mailboxes, users, domains) in ONE transaction. The mailboxes
// primary-delete check (V085) is a DEFERRED constraint trigger evaluated at
// COMMIT: deleting a peer user's primary mailbox in its own statement raises
// BZ013 ("must have at least one primary mailbox") because the user row still
// exists at that commit — the swallowed per-statement teardown this replaces
// silently left the peer tenant rows behind on every run. Mailboxes and their
// users must vanish in the same transaction.
func teardownPeerTenants(t *testing.T, pool *pgxpool.Pool, calendarIDs []int64, domains []string) {
	t.Helper()
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Errorf("teardown begin tx: %v", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }() // no-op after a successful commit
	for _, cal := range calendarIDs {
		if _, err := tx.Exec(ctx, `DELETE FROM calendar_events WHERE calendar_id=$1`, cal); err != nil {
			t.Errorf("teardown peer events (cal=%d): %v", cal, err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM calendars WHERE id=$1`, cal); err != nil {
			t.Errorf("teardown peer calendar (cal=%d): %v", cal, err)
		}
	}
	for _, domain := range domains {
		if _, err := tx.Exec(ctx, `DELETE FROM mailboxes m USING domains d
			WHERE d.id=m.domain_id AND d.name=$1`, domain); err != nil {
			t.Errorf("teardown peer mailboxes (%s): %v", domain, err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM users u USING domains d
			WHERE d.id=u.domain_id AND d.name=$1`, domain); err != nil {
			t.Errorf("teardown peer users (%s): %v", domain, err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM domains WHERE name=$1`, domain); err != nil {
			t.Errorf("teardown peer domain (%s): %v", domain, err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Errorf("teardown commit: %v", err)
	}
}

// The iTIP role-authentication contract (security fix
// D-MAILSERVER-INTERNAL-CALDAV-001/002, round 2): REPLY authenticates the
// claimed ATTENDEE and CANCEL authenticates the event ORGANIZER iff ANY of —
// (a) valid S/MIME signature with signer email == role; (b) DKIM-aligned From
// header == role (full address, domain-aligned); (c) envelope MAIL FROM ==
// role AND SPF pass. A bare envelope match authenticates nothing.

func TestITIPTransportIdentityAuthenticatedAs(t *testing.T) {
	const attendee = "attendee@local.test"
	const relay = "bounces@relay.mailer.test"
	const forger = "attacker@evil.test"
	tests := []struct {
		name string
		id   ITIPTransportIdentity
		addr string
		want bool
	}{
		// rule (c): envelope + SPF pass.
		{
			name: "envelope match WITH SPF pass authenticates (c)",
			id:   ITIPTransportIdentity{EnvelopeFrom: attendee, SpfPass: true},
			addr: attendee,
			want: true,
		},
		{
			name: "spoofed envelope WITHOUT SPF pass authenticates nothing (the old bypass)",
			id:   ITIPTransportIdentity{EnvelopeFrom: attendee},
			addr: attendee,
			want: false,
		},
		{
			name: "envelope match with SPF pass and angle-bracketed MAIL FROM (c)",
			id:   ITIPTransportIdentity{EnvelopeFrom: "<ATTENDEE@Local.Test>", SpfPass: true},
			addr: attendee,
			want: true,
		},
		// rule (b): DKIM-aligned full-address From match.
		{
			name: "dkim-aligned From header match over a different envelope authenticates (b)",
			id:   ITIPTransportIdentity{EnvelopeFrom: relay, FromHeader: attendee, DkimAligned: true, DkimDomain: "local.test"},
			addr: attendee,
			want: true,
		},
		{
			name: "From header match without DKIM alignment is not authentication",
			id:   ITIPTransportIdentity{EnvelopeFrom: relay, FromHeader: attendee},
			addr: attendee,
			want: false,
		},
		{
			name: "dkim pass with mismatched From header rejected",
			id:   ITIPTransportIdentity{EnvelopeFrom: relay, FromHeader: forger, DkimAligned: true},
			addr: attendee,
			want: false,
		},
		{
			name: "dkim-aligned local-part-only lookalike From header rejected (full address required)",
			id:   ITIPTransportIdentity{EnvelopeFrom: relay, FromHeader: "attendee@evil.test", DkimAligned: true},
			addr: attendee,
			want: false,
		},
		// rule (a): valid S/MIME with signer email == role.
		{
			name: "valid S/MIME signer equals role authenticates (a)",
			id:   ITIPTransportIdentity{EnvelopeFrom: relay, SmimeValid: true, SmimeSignerEmail: attendee, SmimeTrust: SmimeTrustUnrestricted},
			addr: attendee,
			want: true,
		},
		{
			name: "S/MIME signer differs from role rejected even with matching envelope but no SPF",
			id:   ITIPTransportIdentity{EnvelopeFrom: attendee, SmimeValid: true, SmimeSignerEmail: forger},
			addr: attendee,
			want: false,
		},
		{
			name: "signer email present but SmimeValid false rejected",
			id:   ITIPTransportIdentity{SmimeSignerEmail: attendee},
			addr: attendee,
			want: false,
		},
		{
			name: "S/MIME signer match is case-insensitive (a)",
			id:   ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: "<Attendee@Local.Test>", SmimeTrust: SmimeTrustUnrestricted},
			addr: attendee,
			want: true,
		},
		// Round 5 (Astra HOLD): the signer email's domain must be covered by the
		// trust that validated the chain. An anchor scoped to tenant A that
		// certified organizer@B must not authenticate B's organizer.
		{
			name: "S/MIME valid but trust scoped to another tenant's domain rejected (round 5)",
			id:   ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: "organizer@b.test", SmimeTrust: SmimeTrustDomainScoped, SmimeTrustDomains: []string{"a.test"}},
			addr: "organizer@b.test",
			want: false,
		},
		{
			name: "S/MIME valid and trust scoped to the signer's own domain accepted (round 5)",
			id:   ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: "organizer@b.test", SmimeTrust: SmimeTrustDomainScoped, SmimeTrustDomains: []string{"b.test"}},
			addr: "organizer@b.test",
			want: true,
		},
		{
			name: "S/MIME trust domain set containing the signer domain accepted (round 5)",
			id:   ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: "organizer@b.test", SmimeTrust: SmimeTrustDomainScoped, SmimeTrustDomains: []string{"a.test", "b.test"}},
			addr: "organizer@b.test",
			want: true,
		},
		{
			name: "S/MIME trust domain match is case-insensitive (round 5)",
			id:   ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: "organizer@b.test", SmimeTrust: SmimeTrustDomainScoped, SmimeTrustDomains: []string{"B.Test"}},
			addr: "organizer@b.test",
			want: true,
		},
		{
			name: "S/MIME unrestricted trust (bundled/deployment-wide anchor) keeps the email-only binding",
			id:   ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: attendee, SmimeTrust: SmimeTrustUnrestricted},
			addr: attendee,
			want: true,
		},
		// Round 6 (Astra HOLD): the scope is tri-state and its zero value is the
		// fail-closed state — an unresolved/removed anchor or lookup error must
		// authenticate nothing instead of degrading to unrestricted.
		{
			name: "S/MIME valid with unresolved anchor scope (zero value) rejected (round 6)",
			id:   ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: attendee},
			addr: attendee,
			want: false,
		},
		{
			name: "S/MIME valid with explicit SmimeTrustNone rejected (round 6)",
			id:   ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: attendee, SmimeTrust: SmimeTrustNone},
			addr: attendee,
			want: false,
		},
		// fail-closed edges.
		{
			name: "empty role address never authenticates",
			id:   ITIPTransportIdentity{EnvelopeFrom: forger, SpfPass: true},
			addr: "",
			want: false,
		},
		{
			name: "empty identity never authenticates",
			id:   ITIPTransportIdentity{},
			addr: attendee,
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.id.AuthenticatedAs(tc.addr); got != tc.want {
				t.Errorf("AuthenticatedAs(%q) = %v, want %v (identity: %+v)", tc.addr, got, tc.want, tc.id)
			}
		})
	}
}

// TestITIPTransportIdentityAuthenticatedSignerDomain — round 4: the signer
// domain is the domain of the evidence that authenticates the role (S/MIME
// signer email / DKIM-aligned From / SPF'd envelope) and is EMPTY whenever the
// identity would not authenticate the address — the value the series-CANCEL
// sweep binds to, so it can never be a wildcard.
func TestITIPTransportIdentityAuthenticatedSignerDomain(t *testing.T) {
	const attendee = "attendee@local.test"
	tests := []struct {
		name string
		id   ITIPTransportIdentity
		addr string
		want string
	}{
		{
			name: "S/MIME rule yields the signer certificate email domain",
			id:   ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: "<" + attendee + ">", SmimeTrust: SmimeTrustUnrestricted},
			addr: attendee,
			want: "local.test",
		},
		{
			name: "DKIM rule yields the aligned From header domain",
			id:   ITIPTransportIdentity{EnvelopeFrom: "bounces@relay.test", FromHeader: attendee, DkimAligned: true},
			addr: attendee,
			want: "local.test",
		},
		{
			name: "SPF rule yields the envelope domain",
			id:   ITIPTransportIdentity{EnvelopeFrom: "ATTENDEE@Local.Test", SpfPass: true},
			addr: attendee,
			want: "local.test",
		},
		{
			name: "no authenticating rule: empty domain (fail closed)",
			id:   ITIPTransportIdentity{EnvelopeFrom: attendee},
			addr: attendee,
			want: "",
		},
		{
			name: "S/MIME valid but different signer: empty domain",
			id:   ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: "attacker@evil.test"},
			addr: attendee,
			want: "",
		},
		{
			name: "S/MIME trust scoped to another tenant: no domain (round 5, fail closed)",
			id:   ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: "organizer@b.test", SmimeTrust: SmimeTrustDomainScoped, SmimeTrustDomains: []string{"a.test"}},
			addr: "organizer@b.test",
			want: "",
		},
		{
			name: "S/MIME trust scoped to the signer's own domain: signer domain (round 5)",
			id:   ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: "organizer@b.test", SmimeTrust: SmimeTrustDomainScoped, SmimeTrustDomains: []string{"b.test"}},
			addr: "organizer@b.test",
			want: "b.test",
		},
		{
			name: "S/MIME unresolved anchor scope: no domain (round 6, fail closed)",
			id:   ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: "organizer@b.test", SmimeTrust: SmimeTrustNone},
			addr: "organizer@b.test",
			want: "",
		},
		{
			name: "empty role address: empty domain",
			id:   ITIPTransportIdentity{EnvelopeFrom: attendee, SpfPass: true},
			addr: "",
			want: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.id.AuthenticatedSignerDomain(tc.addr); got != tc.want {
				t.Errorf("AuthenticatedSignerDomain(%q) = %q, want %q (identity: %+v)", tc.addr, got, tc.want, tc.id)
			}
		})
	}
}

// TestProcessReply_ForgedRejectedBeforeReducerCall proves the REPLY identity
// check fires BEFORE any SQL: with a nil pool any reducer call would panic,
// so a clean error return means no reducer call was made. The identity below
// is exactly the old round-1 bypass (a spoofed envelope that Matches() let
// through); it must now be unauthenticated.
func TestProcessReply_ForgedRejectedBeforeReducerCall(t *testing.T) {
	ev := &CalendarEvent{
		UID:       "forged-reply-1",
		Organizer: Attendee{Email: "organizer@imip.test"},
		Attendees: []Attendee{{Email: "victim@local.test", Status: "accepted"}},
	}
	err := processReply(context.Background(), nil, slog.Default(), ev, 0,
		ITIPTransportIdentity{EnvelopeFrom: "attacker@evil.test"})
	if err == nil {
		t.Fatal("forged REPLY (unauthenticated sender) must be rejected")
	}
	if !strings.Contains(err.Error(), ErrITIPUnauthenticated.Error()) {
		t.Fatalf("rejection must wrap ErrITIPUnauthenticated, got: %v", err)
	}
}

// TestProcessReply_IdentityBinding: table-driven per-transport-identity
// behavior of the REPLY attendee binding against a real reducer-backed event.
func TestProcessReply_IdentityBinding(t *testing.T) {
	pool, mbID, _, email, cleanup := setupITIPTestAccount(t, "itiprepid")
	defer cleanup()
	ctx := context.Background()
	var calID int64
	if err := pool.QueryRow(ctx, `INSERT INTO calendars (mailbox_id, name) VALUES ($1,'ITIP Reply ID') RETURNING id`, mbID).Scan(&calID); err != nil {
		t.Fatalf("insert calendar: %v", err)
	}

	tests := []struct {
		name        string
		identity    ITIPTransportIdentity
		wantErr     bool
		wantApplied bool // reducer ran and the attendee row exists
	}{
		{
			name:     "forged REPLY: envelope does not match claimed attendee",
			identity: ITIPTransportIdentity{EnvelopeFrom: "attacker@evil.test"},
			wantErr:  true,
		},
		{
			name:     "spoofed envelope equals claimed attendee but SPF none — the old round-1 bypass, now rejected",
			identity: ITIPTransportIdentity{EnvelopeFrom: email},
			wantErr:  true,
		},
		{
			name:        "legit REPLY: envelope equals claimed attendee with SPF pass (c, case-insensitive)",
			identity:    ITIPTransportIdentity{EnvelopeFrom: strings.ToUpper(email), SpfPass: true},
			wantApplied: true,
		},
		{
			name:        "legit REPLY: dkim-aligned From header equals claimed attendee over a relayed envelope (b)",
			identity:    ITIPTransportIdentity{EnvelopeFrom: "bounces@relay.mailer.test", FromHeader: email, DkimAligned: true, DkimDomain: "local.test"},
			wantApplied: true,
		},
		{
			name:     "From header match without DKIM alignment is not authentication",
			identity: ITIPTransportIdentity{EnvelopeFrom: "bounces@relay.mailer.test", FromHeader: email},
			wantErr:  true,
		},
		{
			name:        "valid S/MIME signer equals claimed attendee (a)",
			identity:    ITIPTransportIdentity{EnvelopeFrom: "bounces@relay.mailer.test", SmimeValid: true, SmimeSignerEmail: email, SmimeTrust: SmimeTrustUnrestricted},
			wantApplied: true,
		},
		{
			name:     "valid S/MIME signer differs from claimed attendee rejected",
			identity: ITIPTransportIdentity{EnvelopeFrom: email, SmimeValid: true, SmimeSignerEmail: "attacker@evil.test"},
			wantErr:  true,
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uid := "itip-reply-binding-" + string(rune('a'+i))
			if _, err := pool.Exec(ctx,
				`INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, organizer_email, is_meeting, status, etag)
				 VALUES ($1,$2,'Review','2026-08-03 10:00:00+00','2026-08-03 11:00:00+00','organizer@ext.test',TRUE,'confirmed','m0')`,
				calID, uid); err != nil {
				t.Fatalf("seed event: %v", err)
			}
			ev := &CalendarEvent{
				UID:       uid,
				Organizer: Attendee{Email: "organizer@ext.test"},
				Attendees: []Attendee{{Email: email, Status: "accepted"}},
			}
			err := processReply(ctx, pool, slog.Default(), ev, mbID, tc.identity)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected rejection, got nil error")
				}
				if !strings.Contains(err.Error(), ErrITIPUnauthenticated.Error()) {
					t.Errorf("rejection must wrap ErrITIPUnauthenticated, got: %v", err)
				}
			} else if err != nil {
				t.Fatalf("expected processing, got: %v", err)
			}
			var rows int
			if err := pool.QueryRow(ctx,
				`SELECT count(*) FROM event_attendees ea
				 JOIN calendar_events ce ON ce.id = ea.event_id
				 WHERE ce.uid = $1 AND ea.email = $2`, uid, email).Scan(&rows); err != nil {
				t.Fatalf("count attendee rows: %v", err)
			}
			if tc.wantApplied && rows != 1 {
				t.Errorf("attendee row not written by the reducer (rows=%d)", rows)
			}
			if !tc.wantApplied && rows != 0 {
				t.Errorf("reducer was called despite rejection (rows=%d) — role authentication must precede it", rows)
			}
		})
	}
}

// TestProcessCancel_IdentityBinding: the CANCEL organizer binding — the
// transport identity must authenticate AS the DB organizer under the full
// contract, on both the whole-series path and the occurrence-exclude path.
// A DKIM-aligned organizer From header with a differing (relayed) envelope is
// accepted via rule (b); a bare spoofed organizer envelope without SPF is not.
// Round 7: the sweep is gated per affected mailbox with the evidence classes
// evaluated as an OR — DNS-verified evidence (rules (b)/(c)) is tenant-agnostic
// and S/MIME evidence is bounded by each owner domain's own trust, so the
// cross-copy behavior is pinned by TestProcessCancel_DNSEvidenceCancelsAllCopies
// and TestProcessCancel_PerMailboxEvidenceOR below.
func TestProcessCancel_IdentityBinding(t *testing.T) {
	pool, mbID, _, _, cleanup := setupITIPTestAccount(t, "itipcxlid")
	defer cleanup()
	ctx := context.Background()
	const organizer = "organizer@mk.test" // signer domain == fixture tenant domain
	const forger = "attacker@evil.test"

	var calID int64
	if err := pool.QueryRow(ctx, `INSERT INTO calendars (mailbox_id, name) VALUES ($1,'ITIP Cancel ID') RETURNING id`, mbID).Scan(&calID); err != nil {
		t.Fatalf("insert calendar: %v", err)
	}
	seedMaster := func(t *testing.T, uid string) {
		t.Helper()
		if _, err := pool.Exec(ctx,
			`INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, rrule, organizer_email, is_meeting, status, etag)
			 VALUES ($1,$2,'Standup','2026-08-03 10:00:00+00','2026-08-03 10:30:00+00','FREQ=WEEKLY',$3,TRUE,'confirmed','m0')`,
			calID, uid, organizer); err != nil {
			t.Fatalf("seed master %s: %v", uid, err)
		}
	}
	dbStatus := func(t *testing.T, uid string) string {
		t.Helper()
		var status string
		if err := pool.QueryRow(ctx,
			`SELECT status FROM calendar_events WHERE uid=$1 AND recurrence_override IS NULL`, uid).Scan(&status); err != nil {
			t.Fatalf("master row missing: %v", err)
		}
		return status
	}
	hasExdate := func(t *testing.T, uid string) bool {
		t.Helper()
		var has bool
		if err := pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM calendar_events ce, unnest(ce.exdate) x
			 WHERE ce.uid=$1 AND ce.recurrence_override IS NULL AND x='2026-08-10 10:00:00+00'::timestamptz)`, uid).Scan(&has); err != nil {
			t.Fatalf("check exdate: %v", err)
		}
		return has
	}

	tests := []struct {
		name        string
		uid         string
		recurrence  bool
		bodyOrg     string // body ORGANIZER; empty = omit (target-selection guard)
		identity    ITIPTransportIdentity
		wantErr     bool
		wantStatus  string
		wantExdated bool
	}{
		{
			name:       "forged series CANCEL: body organizer copied, attacker envelope — rejected (a/b/c all fail)",
			uid:        "itip-cxl-forged",
			bodyOrg:    organizer,
			identity:   ITIPTransportIdentity{EnvelopeFrom: forger},
			wantErr:    true,
			wantStatus: "confirmed",
		},
		{
			name:       "spoofed organizer envelope without SPF — round-1 bypass, now rejected",
			uid:        "itip-cxl-spoofed",
			bodyOrg:    organizer,
			identity:   ITIPTransportIdentity{EnvelopeFrom: organizer},
			wantErr:    true,
			wantStatus: "confirmed",
		},
		{
			name:       "legit series CANCEL: envelope equals DB organizer with SPF pass (c, case-insensitive)",
			uid:        "itip-cxl-legit",
			bodyOrg:    organizer,
			identity:   ITIPTransportIdentity{EnvelopeFrom: "ORGANIZER@MK.TEST", SpfPass: true},
			wantStatus: "cancelled",
		},
		{
			name:       "relayed CANCEL: dkim-aligned organizer From header with differing envelope accepted (b)",
			uid:        "itip-cxl-relayed",
			bodyOrg:    organizer,
			identity:   ITIPTransportIdentity{EnvelopeFrom: "bounces@relay.mailer.test", FromHeader: organizer, DkimAligned: true, DkimDomain: "mk.test"},
			wantStatus: "cancelled",
		},
		{
			// Round 5 (Astra HOLD): rule (a) with the signer email matching but
			// the validated chain's trust scoped to a DIFFERENT tenant domain —
			// exactly the "A-only CA certifying organizer@B" shape. The
			// identity must not authenticate, so nothing is cancelled.
			name:       "S/MIME signer==organizer but trust scoped to another tenant — rejected",
			uid:        "itip-cxl-smime-xtrust",
			bodyOrg:    organizer,
			identity:   ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: organizer, SmimeTrust: SmimeTrustDomainScoped, SmimeTrustDomains: []string{"elsewhere.test"}},
			wantErr:    true,
			wantStatus: "confirmed",
		},
		{
			name:       "S/MIME signer==organizer with unresolved anchor scope — rejected fail-closed (round 6)",
			uid:        "itip-cxl-smime-none",
			bodyOrg:    organizer,
			identity:   ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: organizer, SmimeTrust: SmimeTrustNone},
			wantErr:    true,
			wantStatus: "confirmed",
		},
		{
			name:       "S/MIME signer==organizer with trust scoped to the signer's own domain — accepted",
			uid:        "itip-cxl-smime-trust",
			bodyOrg:    organizer,
			identity:   ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: "ORGANIZER@MK.TEST", SmimeTrust: SmimeTrustDomainScoped, SmimeTrustDomains: []string{"mk.test"}},
			wantStatus: "cancelled",
		},
		{
			name:       "series CANCEL with no body ORGANIZER rejected (target-selection guard stands)",
			uid:        "itip-cxl-noorg",
			bodyOrg:    "",
			identity:   ITIPTransportIdentity{EnvelopeFrom: organizer, SpfPass: true},
			wantErr:    true,
			wantStatus: "confirmed",
		},
		{
			name:        "forged occurrence CANCEL rejected: no occurrence excluded",
			uid:         "itip-cxl-occ-forged",
			recurrence:  true,
			bodyOrg:     organizer,
			identity:    ITIPTransportIdentity{EnvelopeFrom: forger},
			wantErr:     true,
			wantStatus:  "confirmed",
			wantExdated: false,
		},
		{
			name:        "legit occurrence CANCEL: occurrence path unchanged for authenticated organizer",
			uid:         "itip-cxl-occ-legit",
			recurrence:  true,
			bodyOrg:     organizer,
			identity:    ITIPTransportIdentity{EnvelopeFrom: organizer, SpfPass: true},
			wantStatus:  "confirmed",
			wantExdated: true,
		},
		{
			name:        "relayed occurrence CANCEL: dkim-aligned organizer From accepted (b)",
			uid:         "itip-cxl-occ-relayed",
			recurrence:  true,
			bodyOrg:     organizer,
			identity:    ITIPTransportIdentity{EnvelopeFrom: "bounces@relay.mailer.test", FromHeader: organizer, DkimAligned: true},
			wantStatus:  "confirmed",
			wantExdated: true,
		},
		{
			// Round 7 (Astra HOLD r14): the A-scoped S/MIME verdict must not
			// preempt the role-matching DKIM evidence — the occurrence exclude
			// goes through even though the anchor grant does not cover mk.test.
			name:       "mixed-evidence occurrence CANCEL: A-scoped S/MIME + dkim-aligned From accepted (round 7 OR)",
			uid:        "itip-cxl-occ-mixed",
			recurrence: true,
			bodyOrg:    organizer,
			identity: ITIPTransportIdentity{
				EnvelopeFrom: "bounces@relay.mailer.test", FromHeader: organizer, DkimAligned: true,
				SmimeValid: true, SmimeSignerEmail: organizer,
				SmimeTrust: SmimeTrustDomainScoped, SmimeTrustDomains: []string{"elsewhere.test"},
			},
			wantStatus:  "confirmed",
			wantExdated: true,
		},
		{
			// S/MIME-only evidence whose validated anchor grant does not cover
			// the recipient's domain stays rejected — the round-7 OR widens
			// nothing for the S/MIME class.
			name:        "S/MIME-only occurrence CANCEL scoped to another tenant — no occurrence excluded",
			uid:         "itip-cxl-occ-xscope",
			recurrence:  true,
			bodyOrg:     organizer,
			identity:    ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: organizer, SmimeTrust: SmimeTrustDomainScoped, SmimeTrustDomains: []string{"elsewhere.test"}},
			wantErr:     true,
			wantStatus:  "confirmed",
			wantExdated: false,
		},
		{
			name:        "deployment-wide S/MIME-only occurrence CANCEL accepted",
			uid:         "itip-cxl-occ-wide",
			recurrence:  true,
			bodyOrg:     organizer,
			identity:    ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: organizer, SmimeTrust: SmimeTrustUnrestricted},
			wantStatus:  "confirmed",
			wantExdated: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			seedMaster(t, tc.uid)
			ev := &CalendarEvent{UID: tc.uid, Organizer: Attendee{Email: tc.bodyOrg}}
			if tc.recurrence {
				ev.RecurrenceIDTime = time.Date(2026, 8, 10, 10, 0, 0, 0, time.UTC)
			}
			err := processCancel(ctx, pool, slog.Default(), ev, mbID, tc.identity)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected rejection, got nil error")
				}
				if !strings.Contains(err.Error(), ErrITIPUnauthenticated.Error()) &&
					tc.bodyOrg != "" {
					t.Errorf("role-auth rejection must wrap ErrITIPUnauthenticated, got: %v", err)
				}
			} else if err != nil {
				t.Fatalf("expected processing, got: %v", err)
			}
			if got := dbStatus(t, tc.uid); got != tc.wantStatus {
				t.Errorf("event status = %q, want %q", got, tc.wantStatus)
			}
			if tc.recurrence {
				if got := hasExdate(t, tc.uid); got != tc.wantExdated {
					t.Errorf("occurrence excluded = %v, want %v", got, tc.wantExdated)
				}
			}
		})
	}
}

// TestProcessCancel_DNSEvidenceCancelsAllCopies — supersedes the round-4
// TestProcessCancel_SweepBoundToSignerTenantDomain, whose cross-domain denial
// expectation was the Astra r14 HOLD reconciliation item: once the sweep is
// gated per affected mailbox (rounds 6-7), role-matching DNS-verified
// transport evidence (here rule (c) SPF'd envelope; rule (b) DKIM is
// equivalent) is tenant-agnostic and NO policy class rejects it, so an
// authenticated organizer's CANCEL sweeps every local copy sharing
// uid+organizer regardless of the copies' owner domains. Cross-tenant denial
// protection lives entirely in the S/MIME evidence class and is pinned by
// TestProcessCancel_PerMailboxEvidenceOR below.
func TestProcessCancel_DNSEvidenceCancelsAllCopies(t *testing.T) {
	pool, mbID, _, _, cleanup := setupITIPTestAccount(t, "itipcxlten")
	defer cleanup()
	ctx := context.Background()
	const (
		uid         = "itip-cxl-tenant"
		organizer   = "organizer@mk.test" // signer domain == the fixture tenant domain
		otherDomain = "itip-elsewhere.test"
	)

	var calID int64
	if err := pool.QueryRow(ctx, `INSERT INTO calendars (mailbox_id, name) VALUES ($1,'ITIP Cancel Tenant') RETURNING id`, mbID).Scan(&calID); err != nil {
		t.Fatalf("insert calendar: %v", err)
	}
	seed := func(t *testing.T, cal int64) {
		t.Helper()
		if _, err := pool.Exec(ctx,
			`INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, organizer_email, is_meeting, status, etag)
			 VALUES ($1,$2,'Standup','2026-08-03 10:00:00+00','2026-08-03 10:30:00+00',$3,TRUE,'confirmed','m0')`,
			cal, uid, organizer); err != nil {
			t.Fatalf("seed event: %v", err)
		}
	}
	seed(t, calID)

	// Domain B: a second tenant whose mailbox owns a copy sharing uid+organizer.
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed other tenant %q: %v", sql, err)
		}
	}
	exec(`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) ON CONFLICT DO NOTHING`, otherDomain)
	exec(`INSERT INTO users (username, domain_id, email, display_name)
	      SELECT 'itipcxlten-peer', d.id, 'peer@'||$1, 'Peer' FROM domains d WHERE d.name=$1
	      ON CONFLICT DO NOTHING`, otherDomain)
	exec(`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
	      SELECT u.id, d.id, 'peer@'||$1, 'Peer', 'personal', TRUE
	      FROM users u, domains d WHERE u.email='peer@'||$1 AND d.name=$1
	      ON CONFLICT DO NOTHING`, otherDomain)
	var otherCal int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO calendars (mailbox_id, name)
		 SELECT m.id, 'Peer Cal' FROM mailboxes m JOIN domains d ON d.id = m.domain_id
		 WHERE d.name = $1 LIMIT 1 RETURNING id`, otherDomain,
	).Scan(&otherCal); err != nil {
		t.Fatalf("insert other-tenant calendar: %v", err)
	}
	seed(t, otherCal)
	// Peer-domain teardown must be a defer, not t.Cleanup: the helper's
	// `defer cleanup()` runs BEFORE t.Cleanup functions and closes the pool,
	// so a t.Cleanup teardown would run against a closed pool. Defers run
	// LIFO — this runs while the pool is still open.
	defer teardownPeerTenants(t, pool, []int64{otherCal}, []string{otherDomain})

	ev := &CalendarEvent{UID: uid, Organizer: Attendee{Email: organizer}}
	identity := ITIPTransportIdentity{EnvelopeFrom: organizer, SpfPass: true} // rule (c)
	if err := processCancel(ctx, pool, slog.Default(), ev, mbID, identity); err != nil {
		t.Fatalf("authenticated CANCEL must process, got: %v", err)
	}

	var ownStatus, otherStatus string
	if err := pool.QueryRow(ctx,
		`SELECT status FROM calendar_events WHERE uid=$1 AND calendar_id=$2`, uid, calID,
	).Scan(&ownStatus); err != nil {
		t.Fatalf("fixture-tenant copy missing: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT status FROM calendar_events WHERE uid=$1 AND calendar_id=$2`, uid, otherCal,
	).Scan(&otherStatus); err != nil {
		t.Fatalf("cross-tenant copy missing: %v", err)
	}
	if ownStatus != "cancelled" {
		t.Errorf("fixture-tenant copy status = %q, want cancelled", ownStatus)
	}
	if otherStatus != "cancelled" {
		t.Errorf("cross-tenant copy status = %q, want cancelled — tenant-agnostic DNS evidence sweeps every affected mailbox (round 7)", otherStatus)
	}
}

// TestProcessCancel_PerMailboxEvidenceOR — round 7 (Astra HOLD r14): the
// series-CANCEL sweep evaluates the evidence classes as an OR per affected
// mailbox. An external organizer (organizer@vendor.test) carrying BOTH valid
// DKIM/SPF AND an S/MIME signature chained to a tenant's domain-scoped anchor
// cancels EVERY copy: mailboxes inside the anchor's grant accept the S/MIME
// class, and every other mailbox accepts the independent DNS-verified evidence
// (round 6 let the S/MIME verdict preempt DNS evidence and stranded exactly
// this organizer). With S/MIME-ONLY evidence the grant set again bounds the
// sweep — copies whose owner domain the anchor never granted survive — and a
// deployment-wide anchor cancels all copies.
func TestProcessCancel_PerMailboxEvidenceOR(t *testing.T) {
	pool, mbID, _, _, cleanup := setupITIPTestAccount(t, "itipcxlor")
	defer cleanup()
	ctx := context.Background()
	const (
		organizer = "organizer@vendor.test" // external organizer domain
		grantDom  = "itip-or-grant.test"    // inside the S/MIME anchor's grant set
		outDom    = "itip-or-out.test"      // outside it
	)

	var ownCal int64
	if err := pool.QueryRow(ctx, `INSERT INTO calendars (mailbox_id, name) VALUES ($1,'ITIP Cancel OR') RETURNING id`, mbID).Scan(&ownCal); err != nil {
		t.Fatalf("insert own calendar: %v", err)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := pool.Exec(ctx, sql, args...); err != nil {
			t.Fatalf("seed %q: %v", sql, err)
		}
	}
	seedTenantCopy := func(label, domain string) int64 {
		exec(`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) ON CONFLICT DO NOTHING`, domain)
		exec(`INSERT INTO users (username, domain_id, email, display_name)
		      SELECT $2, d.id, $3, 'Peer' FROM domains d WHERE d.name=$1
		      ON CONFLICT DO NOTHING`, domain, "itipcxlor-"+label, "itipcxlor-"+label+"@"+domain)
		exec(`INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		      SELECT u.id, d.id, $2, 'Peer', 'personal', TRUE
		      FROM users u, domains d WHERE u.email=$2 AND d.name=$1
		      ON CONFLICT DO NOTHING`, domain, "itipcxlor-"+label+"@"+domain)
		var cal int64
		if err := pool.QueryRow(ctx,
			`INSERT INTO calendars (mailbox_id, name)
			 SELECT m.id, 'Peer Cal' FROM mailboxes m JOIN domains d ON d.id = m.domain_id
			 WHERE d.name = $1 LIMIT 1 RETURNING id`, domain,
		).Scan(&cal); err != nil {
			t.Fatalf("insert %s calendar: %v", domain, err)
		}
		return cal
	}
	grantCal := seedTenantCopy("grant", grantDom)
	outCal := seedTenantCopy("out", outDom)
	// Peer-domain teardown must be a defer, not t.Cleanup: the helper's
	// `defer cleanup()` runs BEFORE t.Cleanup functions and closes the pool.
	// Defers run LIFO — this runs while the pool is still open.
	defer teardownPeerTenants(t, pool, []int64{grantCal, outCal}, []string{grantDom, outDom})

	seedEvent := func(uid string) {
		for _, cal := range []int64{ownCal, grantCal, outCal} {
			exec(`INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, organizer_email, is_meeting, status, etag)
			     VALUES ($1,$2,'Standup','2026-08-03 10:00:00+00','2026-08-03 10:30:00+00',$3,TRUE,'confirmed','m0')`,
				cal, uid, organizer)
		}
	}
	statusOf := func(uid string, cal int64) string {
		t.Helper()
		var status string
		if err := pool.QueryRow(ctx,
			`SELECT status FROM calendar_events WHERE uid=$1 AND calendar_id=$2`, uid, cal,
		).Scan(&status); err != nil {
			t.Fatalf("copy missing (uid=%s cal=%d): %v", uid, cal, err)
		}
		return status
	}

	tests := []struct {
		name      string
		uid       string
		identity  ITIPTransportIdentity
		wantOwn   string // fixture tenant (mk.test) copy
		wantGrant string // copy inside the S/MIME anchor's grant set
		wantOut   string // copy outside the grant set
	}{
		{
			// The r14 HOLD shape: valid DKIM evidence AND an S/MIME signature
			// chained to a domain-scoped anchor whose grant covers only the
			// grant domain. Round 6 let the S/MIME verdict preempt the DNS
			// evidence, leaving the out-domain and fixture copies standing.
			name: "mixed evidence: dkim + grant-scoped S/MIME — every copy cancelled",
			uid:  "itip-or-mixed-dkim",
			identity: ITIPTransportIdentity{
				EnvelopeFrom: "bounces@relay.mailer.test", FromHeader: organizer,
				DkimAligned: true, DkimDomain: "vendor.test",
				SmimeValid: true, SmimeSignerEmail: organizer,
				SmimeTrust: SmimeTrustDomainScoped, SmimeTrustDomains: []string{grantDom},
			},
			wantOwn: "cancelled", wantGrant: "cancelled", wantOut: "cancelled",
		},
		{
			name: "mixed evidence: spf + grant-scoped S/MIME — every copy cancelled",
			uid:  "itip-or-mixed-spf",
			identity: ITIPTransportIdentity{
				EnvelopeFrom: organizer, SpfPass: true,
				SmimeValid: true, SmimeSignerEmail: organizer,
				SmimeTrust: SmimeTrustDomainScoped, SmimeTrustDomains: []string{grantDom},
			},
			wantOwn: "cancelled", wantGrant: "cancelled", wantOut: "cancelled",
		},
		{
			name: "S/MIME-only grant-scoped anchor — copies outside the grant survive",
			uid:  "itip-or-smime-only",
			identity: ITIPTransportIdentity{
				SmimeValid: true, SmimeSignerEmail: organizer,
				SmimeTrust: SmimeTrustDomainScoped, SmimeTrustDomains: []string{grantDom},
			},
			wantOwn: "confirmed", wantGrant: "cancelled", wantOut: "confirmed",
		},
		{
			name: "deployment-wide S/MIME (bundled/deployment anchor) — all copies cancelled",
			uid:  "itip-or-wide",
			identity: ITIPTransportIdentity{
				SmimeValid: true, SmimeSignerEmail: organizer,
				SmimeTrust: SmimeTrustUnrestricted,
			},
			wantOwn: "cancelled", wantGrant: "cancelled", wantOut: "cancelled",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			seedEvent(tc.uid)
			ev := &CalendarEvent{UID: tc.uid, Organizer: Attendee{Email: organizer}}
			if err := processCancel(ctx, pool, slog.Default(), ev, mbID, tc.identity); err != nil {
				t.Fatalf("processCancel: %v", err)
			}
			if got := statusOf(tc.uid, ownCal); got != tc.wantOwn {
				t.Errorf("fixture-tenant copy status = %q, want %q", got, tc.wantOwn)
			}
			if got := statusOf(tc.uid, grantCal); got != tc.wantGrant {
				t.Errorf("grant-domain copy status = %q, want %q", got, tc.wantGrant)
			}
			if got := statusOf(tc.uid, outCal); got != tc.wantOut {
				t.Errorf("out-domain copy status = %q, want %q", got, tc.wantOut)
			}
		})
	}
}

// TestITIPTransportIdentityDomainAcceptsCancelEvidence — pure unit pin of the
// round-7 per-mailbox OR: DNS-verified role-matching evidence (rules (b)/(c))
// is accepted by every non-empty owner domain and is never preempted by an
// S/MIME verdict; S/MIME-only evidence is bounded by the domain's own trust,
// and an empty domain or absent evidence fails closed.
func TestITIPTransportIdentityDomainAcceptsCancelEvidence(t *testing.T) {
	const organizer = "organizer@vendor.test"
	tests := []struct {
		name   string
		id     ITIPTransportIdentity
		domain string
		smime  bool
		want   bool
	}{
		{
			name: "dkim evidence accepted even where the S/MIME grant does not reach (round 7)",
			id: ITIPTransportIdentity{
				FromHeader: organizer, DkimAligned: true,
				SmimeValid: true, SmimeSignerEmail: organizer,
				SmimeTrust: SmimeTrustDomainScoped, SmimeTrustDomains: []string{"a.test"},
			},
			domain: "b.test", smime: true, want: true,
		},
		{
			name: "spf evidence accepted even where the S/MIME grant does not reach (round 7)",
			id: ITIPTransportIdentity{
				EnvelopeFrom: organizer, SpfPass: true,
				SmimeValid: true, SmimeSignerEmail: organizer,
				SmimeTrust: SmimeTrustDomainScoped, SmimeTrustDomains: []string{"a.test"},
			},
			domain: "b.test", smime: true, want: true,
		},
		{
			name:   "dkim evidence accepted with no S/MIME evidence at all",
			id:     ITIPTransportIdentity{FromHeader: organizer, DkimAligned: true},
			domain: "b.test", smime: false, want: true,
		},
		{
			name:   "spf evidence accepted alongside S/MIME trust none (round 6 fail-closed scope stands)",
			id:     ITIPTransportIdentity{EnvelopeFrom: organizer, SpfPass: true, SmimeValid: true, SmimeSignerEmail: organizer, SmimeTrust: SmimeTrustNone},
			domain: "b.test", smime: false, want: true,
		},
		{
			name:   "S/MIME-only with unrestricted trust accepted everywhere",
			id:     ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: organizer, SmimeTrust: SmimeTrustUnrestricted},
			domain: "b.test", smime: true, want: true,
		},
		{
			name:   "S/MIME-only with grant covering the domain accepted",
			id:     ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: organizer, SmimeTrust: SmimeTrustDomainScoped, SmimeTrustDomains: []string{"a.test", "b.test"}},
			domain: "b.test", smime: true, want: true,
		},
		{
			name:   "S/MIME-only with grant not covering the domain rejected",
			id:     ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: organizer, SmimeTrust: SmimeTrustDomainScoped, SmimeTrustDomains: []string{"a.test"}},
			domain: "b.test", smime: true, want: false,
		},
		{
			name:   "S/MIME-only with unresolved anchor scope rejected — fail closed (round 6)",
			id:     ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: organizer, SmimeTrust: SmimeTrustNone},
			domain: "b.test", smime: true, want: false,
		},
		{
			name:   "no authenticating evidence at all rejected — fail closed",
			id:     ITIPTransportIdentity{SmimeValid: true, SmimeSignerEmail: "someone@else.test"},
			domain: "b.test", smime: false, want: false,
		},
		{
			name:   "dkim evidence still rejected for an empty owner domain — fail closed",
			id:     ITIPTransportIdentity{FromHeader: organizer, DkimAligned: true},
			domain: "", smime: false, want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.id.domainAcceptsCancelEvidence(tc.domain, organizer, tc.smime); got != tc.want {
				t.Errorf("domainAcceptsCancelEvidence(%q, %q, %v) = %v, want %v (identity: %+v)",
					tc.domain, organizer, tc.smime, got, tc.want, tc.id)
			}
		})
	}
}
