package smtp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/caldav"
	"setjoin.com/mailserver/internal/smime"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"

	cms "github.com/github/smimesign/ietf-cms"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Intake-side iTIP role authentication (security fix
// D-MAILSERVER-INTERNAL-CALDAV-001/002, round 2): the enforcing decision lives
// entirely in the role-authentication step (REPLY → AuthenticatedAs(claimed
// attendee), CANCEL → AuthenticatedAs(DB organizer)) using the full transport
// identity — S/MIME signer, DKIM-aligned From header, envelope MAIL FROM with
// SPF pass. Unauthenticated messages are dropped before any reducer call
// (logged + counted on InboundServer.imipRejected). The old intake-side
// CANCEL envelope-only check is gone: it wrongly dropped a DKIM-aligned
// organizer From with a differing envelope (legitimate relayed iMIP) while
// accepting a bare spoofed envelope that no longer authenticates.

// buildIMipCalendar renders the iCalendar body for the intake tests (no
// trailing CRLF — the S/MIME builder signs exactly these bytes). attendee is
// the fixture tenant's minted recipient address.
func buildIMipCalendar(method caldav.ITIPMethod, uid, organizer, attendee string) string {
	var b strings.Builder
	b.WriteString("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\n")
	b.WriteString(fmt.Sprintf("METHOD:%s\r\n", method))
	b.WriteString("BEGIN:VEVENT\r\n")
	b.WriteString(fmt.Sprintf("UID:%s\r\n", uid))
	b.WriteString("DTSTART:20260810T100000Z\r\n")
	b.WriteString("DTEND:20260810T103000Z\r\n")
	if organizer != "" {
		b.WriteString(fmt.Sprintf("ORGANIZER:mailto:%s\r\n", organizer))
	}
	b.WriteString("ATTENDEE;PARTSTAT=ACCEPTED:mailto:" + attendee + "\r\n")
	b.WriteString("END:VEVENT\r\n")
	b.WriteString("END:VCALENDAR")
	return b.String()
}

func buildIMipBindingMessage(method caldav.ITIPMethod, uid, organizer, attendee string) string {
	boundary := "imip-binding-boundary"
	var b strings.Builder
	b.WriteString("From: Sender <organizer@imip.test>\r\n")
	b.WriteString("To: " + attendee + "\r\n")
	b.WriteString("Subject: iTIP binding test\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=%s\r\n\r\n", boundary))
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n\r\n")
	b.WriteString("calendar part follows\r\n\r\n")
	b.WriteString("--" + boundary + "\r\n")
	b.WriteString(fmt.Sprintf("Content-Type: text/calendar; method=%s; charset=utf-8\r\n\r\n", method))
	b.WriteString(buildIMipCalendar(method, uid, organizer, attendee))
	b.WriteString("\r\n")
	b.WriteString("--" + boundary + "--\r\n")
	return b.String()
}

// buildIMipSignedMessage assembles a real multipart/signed S/MIME iTIP message
// (round 3): the detached signature is cms.SignDetached over the FULL content
// part (RFC 5751, matching what the intake verifier extracts), embedding the
// given certificate chain. trailingMethod, when non-empty, injects an
// ADDITIONAL unsigned text/calendar part after the signature part — the
// round-3 attacker shape where a trailing METHOD tries to override signed
// content.
func buildIMipSignedMessage(t *testing.T, method caldav.ITIPMethod, uid, organizer string, chain []*x509.Certificate, key *rsa.PrivateKey, trailingMethod caldav.ITIPMethod, attendee string) string {
	t.Helper()
	const boundary = "smime-imip-boundary"
	ical := buildIMipCalendar(method, uid, organizer, attendee)
	contentPart := fmt.Sprintf("Content-Type: text/calendar; method=%s; charset=utf-8\r\n\r\n%s\r\n", method, ical)
	sigDER, err := cms.SignDetached([]byte(contentPart), chain, key)
	if err != nil {
		t.Fatalf("cms.SignDetached: %v", err)
	}
	msg := "From: Signer <" + organizer + ">\r\n" +
		"To: " + attendee + "\r\n" +
		"Subject: signed iTIP\r\n" +
		buildMultipartSigned(t, contentPart, sigDER, boundary)
	if trailingMethod != "" {
		trailing := "--" + boundary + "\r\n" +
			fmt.Sprintf("Content-Type: text/calendar; method=%s; charset=utf-8\r\n\r\n", trailingMethod) +
			buildIMipCalendar(trailingMethod, uid, organizer, attendee) + "\r\n"
		marker := "--" + boundary + "--\r\n"
		msg = strings.Replace(msg, marker, trailing+marker, 1)
	}
	return msg
}

// selfSignedSigner makes a self-signed (chain-of-one) email certificate — the
// exact shape any attacker can mint with the victim's address in the SAN.
func selfSignedSigner(t *testing.T, email string) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:   big.NewInt(time.Now().UnixNano()),
		Subject:        pkix.Name{CommonName: email},
		EmailAddresses: []string{email},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert, key
}

// imipRandSuffix mints 8 hex chars of per-run uniqueness for fixture names on
// the shared test DB.
func imipRandSuffix(t *testing.T) string {
	t.Helper()
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return fmt.Sprintf("%x", b)
}

// imipTenant is one freshly minted iMIP tenant stack: a unique-per-run domain,
// its recipient user + primary mailbox, and the default calendar. The retired
// fixed ids (98100/98101/98111 and the peer series 98120-22/98130-32/98140-42)
// collided across overlapping runs on the shared test DB — on
// domains_name_key, users_email_lower_idx, mailboxes_email_lower_idx, the
// per-recipient rate-limit key, and the trigger-created folder paths — and
// their ON CONFLICT DO NOTHING seeding shared one tenant across runs.
type imipTenant struct {
	pool      *pgxpool.Pool
	domain    string
	domainID  int64
	userID    int64
	mailboxID int64
	calID     int64
	attendee  string // the tenant recipient address every builder must carry
}

// mintIMipTenant creates the tenant stack and registers each row's cleanup
// immediately after that row's own creation succeeds, so a failure partway
// through seeding can never strand an earlier row. t.Cleanup LIFO then tears
// down calendar → mailbox child rows → mailbox+user (one transaction, the
// BZ013-safe mailbox-before-user pattern) → the domain, and every cleanup
// statement's error is verified.
func mintIMipTenant(t *testing.T, pool *pgxpool.Pool, domain, localPart, username, displayName, calName string) *imipTenant {
	t.Helper()
	ctx := context.Background()
	fx := &imipTenant{pool: pool, domain: domain, attendee: localPart + "@" + domain}

	insert := func(what, query string, args ...any) int64 {
		t.Helper()
		var id int64
		if err := pool.QueryRow(ctx, query, args...).Scan(&id); err != nil {
			t.Fatalf("mint iMIP tenant %s: insert %s: %v", domain, what, err)
		}
		return id
	}

	fx.domainID = insert("domain", `INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, fx.domain)
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM domains WHERE id = $1`, fx.domainID); err != nil {
			t.Errorf("cleanup iMIP tenant domain %s: %v", fx.domain, err)
		}
	})

	fx.userID = insert("user", `INSERT INTO users (username, domain_id, email, display_name, enabled)
		VALUES ($1, $2, $3, $4, TRUE) RETURNING id`, username, fx.domainID, fx.attendee, displayName)
	t.Cleanup(func() {
		c := context.Background()
		tx, err := pool.Begin(c)
		if err != nil {
			t.Errorf("cleanup iMIP tenant user %d: begin teardown tx: %v", fx.userID, err)
			return
		}
		if _, err := tx.Exec(c, `DELETE FROM mailboxes WHERE user_id = $1`, fx.userID); err != nil {
			t.Errorf("cleanup iMIP tenant user %d: delete mailboxes: %v", fx.userID, err)
			_ = tx.Rollback(c)
			return
		}
		if _, err := tx.Exec(c, `DELETE FROM users WHERE id = $1`, fx.userID); err != nil {
			t.Errorf("cleanup iMIP tenant user %d: delete user: %v", fx.userID, err)
			_ = tx.Rollback(c)
			return
		}
		if err := tx.Commit(c); err != nil {
			t.Errorf("cleanup iMIP tenant user %d: commit teardown: %v", fx.userID, err)
		}
		// The per-recipient iTIP REQUEST rate limit (rate_limit_check, 20/hour)
		// keys on this user id; only OUR counter is ours to remove.
		if _, err := pool.Exec(c,
			`DELETE FROM rate_limit_counters WHERE key = $1`,
			fmt.Sprintf("itip:recipient:%d", fx.userID),
		); err != nil {
			t.Errorf("cleanup iMIP tenant %s rate-limit counter: %v", fx.domain, err)
		}
	})

	fx.mailboxID = insert("mailbox", `INSERT INTO mailboxes (user_id, domain_id, email, display_name, type, is_primary)
		VALUES ($1, $2, $3, $4, 'personal', TRUE) RETURNING id`, fx.userID, fx.domainID, fx.attendee, displayName)
	t.Cleanup(func() {
		// Trigger-created child rows must precede the mailbox/user teardown or
		// they orphan (and would collide with the next run's folder-path
		// unique index were names still fixed). Aliases are included although
		// no current writer creates one for this mailbox (the occurrence test
		// seeds one explicitly).
		c := context.Background()
		for _, stmt := range [...]string{
			`DELETE FROM folders WHERE mailbox_id = $1`,
			`DELETE FROM mailbox_lifecycle WHERE mailbox_id = $1`,
			`DELETE FROM mailbox_address_claims WHERE mailbox_id = $1`,
			`DELETE FROM aliases WHERE mailbox_id = $1`,
		} {
			if _, err := pool.Exec(c, stmt, fx.mailboxID); err != nil {
				t.Errorf("cleanup iMIP tenant mailbox %d child rows: %v", fx.mailboxID, err)
			}
		}
	})

	fx.calID = insert("calendar", `INSERT INTO calendars (mailbox_id, name, is_default) VALUES ($1, $2, TRUE) RETURNING id`,
		fx.mailboxID, calName)
	// is_default: jmap_calendar_event_set_create (the REQUEST create path)
	// resolves the recipient's calendar via is_default — without it a processed
	// REQUEST silently lands in notCreated ("No default calendar").
	t.Cleanup(func() {
		c := context.Background()
		for _, stmt := range [...]string{
			`DELETE FROM event_attendees ea USING calendar_events ce WHERE ea.event_id = ce.id AND ce.calendar_id = $1`,
			`DELETE FROM calendar_events WHERE calendar_id = $1`,
			`DELETE FROM calendars WHERE id = $1`,
		} {
			if _, err := pool.Exec(c, stmt, fx.calID); err != nil {
				t.Errorf("cleanup iMIP tenant calendar %d (%s): %v", fx.calID, calName, err)
			}
		}
	})

	return fx
}

// setupIMipBindingFixture mints the recipient tenant used by every intake test
// below.
func setupIMipBindingFixture(t *testing.T) *imipTenant {
	t.Helper()
	pool := testsupport.OpenTestPool(t)
	suffix := imipRandSuffix(t)
	return mintIMipTenant(t, pool, "imip-"+suffix+".test", "attendee", "imip_attendee", "Attendee", "IMIP Binding")
}

// seedIMipPeerTenant mints a fresh second tenant for the cross-tenant copy
// tests (rounds 5/6/8 — formerly the fixed 98120-22/98130-32/98140-42 series).
func seedIMipPeerTenant(t *testing.T, pool *pgxpool.Pool, label string) *imipTenant {
	t.Helper()
	suffix := imipRandSuffix(t)
	return mintIMipTenant(t, pool, "imip-"+label+"-"+suffix+".test", "peer", "imip_"+label+"_peer", "Peer", "Peer Cal")
}

// importDomainAnchor inserts rootPEM as a trust anchor scoped to the given
// recipient domain (the fixture tenant's minted domain id — formerly the hard
// coded imip.test id 98100) and registers checked cleanup.
func importDomainAnchor(t *testing.T, pool *pgxpool.Pool, domainID int64, root *x509.Certificate) {
	t.Helper()
	anchorPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}))
	anchorFP := fp(root)
	if _, err := pool.Exec(context.Background(),
		`DELETE FROM smime_trust_anchors WHERE fingerprint = $1`, anchorFP); err != nil {
		t.Fatalf("clear stale anchor: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO smime_trust_anchors (label, cert_pem, fingerprint, domain_id) VALUES ('imip-round3-test-ca',$1,$2,$3)`,
		anchorPEM, anchorFP, domainID); err != nil {
		t.Fatalf("insert trust anchor: %v", err)
	}
	t.Cleanup(func() {
		if _, err := pool.Exec(context.Background(), `DELETE FROM smime_trust_anchors WHERE fingerprint = $1`, anchorFP); err != nil {
			t.Errorf("cleanup domain trust anchor: %v", err)
		}
	})
}

func TestDetectAndProcessIMip_RoleAuthentication(t *testing.T) {
	fx := setupIMipBindingFixture(t)
	pool, calID := fx.pool, fx.calID
	attendee := fx.attendee // the fixture tenant's minted recipient address
	ctx := context.Background()
	const (
		organizer = "organizer@imip.test"
		forger    = "attacker@evil.test"
		relay     = "bounces@relay.mailer.test" // legit iMIP relay: envelope differs from the role
	)

	seedEvent := func(t *testing.T, uid string) {
		t.Helper()
		if _, err := pool.Exec(ctx,
			`INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, organizer_email, is_meeting, status, etag)
			 VALUES ($1,$2,'Standup','2026-08-10 10:00:00+00','2026-08-10 10:30:00+00',$3,TRUE,'confirmed','m0')`,
			calID, uid, organizer); err != nil {
			t.Fatalf("seed event %s: %v", uid, err)
		}
	}
	dbStatus := func(t *testing.T, uid string) string {
		t.Helper()
		var status string
		if err := pool.QueryRow(ctx,
			`SELECT status FROM calendar_events WHERE uid=$1 AND recurrence_override IS NULL`, uid).Scan(&status); err != nil {
			t.Fatalf("event row missing: %v", err)
		}
		return status
	}

	tests := []struct {
		name          string
		uid           string
		method        caldav.ITIPMethod
		bodyOrganizer string
		envelopeFrom  string
		fromHeader    string
		dkimAligned   bool
		spfPass       bool
		wantStatus    string
		wantAttendee  bool // REPLY: the reducer ran and wrote the attendee row
		wantDropped   int64
	}{
		// HOLD item 1: the round-1 bypass — attacker sets BOTH envelope and
		// From header to the victim, with no DKIM/SPF/S-MIME evidence.
		{
			name:          "spoofed REPLY: envelope+From claim the attendee, no evidence — dropped before reducer",
			uid:           "imip-auth-spoofed-reply",
			method:        caldav.MethodReply,
			bodyOrganizer: organizer,
			envelopeFrom:  attendee,
			fromHeader:    attendee,
			wantStatus:    "confirmed",
			wantAttendee:  false,
			wantDropped:   1,
		},
		{
			name:          "REPLY envelope==attendee with SPF pass — accepted via (c)",
			uid:           "imip-auth-spf-reply",
			method:        caldav.MethodReply,
			bodyOrganizer: organizer,
			envelopeFrom:  attendee,
			spfPass:       true,
			wantStatus:    "confirmed",
			wantAttendee:  true,
			wantDropped:   0,
		},
		{
			name:          "REPLY envelope==attendee with SPF none (toggle off) — rejected via (c)",
			uid:           "imip-auth-spfnone-reply",
			method:        caldav.MethodReply,
			bodyOrganizer: organizer,
			envelopeFrom:  attendee,
			wantStatus:    "confirmed",
			wantAttendee:  false,
			wantDropped:   1,
		},
		{
			name:          "REPLY relayed: dkim-aligned From==attendee with differing envelope — accepted via (b)",
			uid:           "imip-auth-dkim-reply",
			method:        caldav.MethodReply,
			bodyOrganizer: organizer,
			envelopeFrom:  relay,
			fromHeader:    attendee,
			dkimAligned:   true,
			wantStatus:    "confirmed",
			wantAttendee:  true,
			wantDropped:   0,
		},
		{
			name:          "forged CANCEL: attacker envelope, no evidence — dropped before reducer",
			uid:           "imip-auth-forged-cancel",
			method:        caldav.MethodCancel,
			bodyOrganizer: organizer,
			envelopeFrom:  forger,
			wantStatus:    "confirmed",
			wantDropped:   1,
		},
		// The r7 nuance: the old intake check dropped this; rule (b) accepts it.
		{
			name:          "CANCEL relayed: dkim-aligned organizer From with differing envelope — accepted via (b)",
			uid:           "imip-auth-dkim-cancel",
			method:        caldav.MethodCancel,
			bodyOrganizer: organizer,
			envelopeFrom:  relay,
			fromHeader:    organizer,
			dkimAligned:   true,
			wantStatus:    "cancelled",
			wantDropped:   0,
		},
		{
			name:          "legit direct CANCEL: envelope==organizer with SPF pass — accepted via (c, case-insensitive)",
			uid:           "imip-auth-legit-cancel",
			method:        caldav.MethodCancel,
			bodyOrganizer: organizer,
			envelopeFrom:  "ORGANIZER@IMIP.TEST",
			spfPass:       true,
			wantStatus:    "cancelled",
			wantDropped:   0,
		},
		{
			name:          "CANCEL with no body ORGANIZER — target-selection guard rejects, not an identity drop",
			uid:           "imip-auth-noorg-cancel",
			method:        caldav.MethodCancel,
			bodyOrganizer: "",
			envelopeFrom:  organizer,
			spfPass:       true,
			wantStatus:    "confirmed",
			wantDropped:   0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			seedEvent(t, tc.uid)
			srv := &InboundServer{
				pool:    pool,
				toggles: toggle.NewStatic(map[string]bool{}),
				logger:  testsupport.TestLogger(),
			}
			c := &inConnState{srv: srv, from: tc.envelopeFrom}
			msg := buildIMipBindingMessage(tc.method, tc.uid, tc.bodyOrganizer, attendee)
			identity := caldav.ITIPTransportIdentity{
				EnvelopeFrom: tc.envelopeFrom,
				FromHeader:   tc.fromHeader,
				DkimAligned:  tc.dkimAligned,
				SpfPass:      tc.spfPass,
			}
			c.detectAndProcessIMip(ctx, msg, identity, 0, "")

			if got := dbStatus(t, tc.uid); got != tc.wantStatus {
				t.Errorf("event status = %q, want %q", got, tc.wantStatus)
			}
			if got := srv.imipRejected.Load(); got != tc.wantDropped {
				t.Errorf("imipRejected = %d, want %d", got, tc.wantDropped)
			}
			var rows int
			if err := pool.QueryRow(ctx,
				`SELECT count(*) FROM event_attendees ea
				 JOIN calendar_events ce ON ce.id = ea.event_id
				 WHERE ce.uid = $1 AND ea.email = $2`, tc.uid, attendee).Scan(&rows); err != nil {
				t.Fatalf("count attendee rows: %v", err)
			}
			if tc.wantAttendee && rows != 1 {
				t.Errorf("authenticated message was not processed (attendee rows=%d)", rows)
			}
			if !tc.wantAttendee && rows != 0 {
				t.Errorf("unauthenticated message reached the reducer (attendee rows=%d) — drop must precede it", rows)
			}
		})
	}
}

// TestDetectAndProcessIMip_SMimeSignerBinding covers the round-3 intake trust
// gate: the signer certificate must CHAIN to a trusted root (anchored for the
// recipient domain) with a From-header email match before SmimeValid is set at
// all; the role binding itself then happens inside AuthenticatedAs. Round 2
// verified signature math only, so a self-signed certificate merely bearing
// the victim's email authenticated the sender — the old false positive.
func TestDetectAndProcessIMip_SMimeSignerBinding(t *testing.T) {
	fx := setupIMipBindingFixture(t)
	pool, calID := fx.pool, fx.calID
	attendee := fx.attendee
	ctx := context.Background()
	const (
		organizer = "organizer@imip.test"
		forger    = "attacker@evil.test"
	)

	seedEvent := func(t *testing.T, uid string) {
		t.Helper()
		if _, err := pool.Exec(ctx,
			`INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, organizer_email, is_meeting, status, etag)
			 VALUES ($1,$2,'Standup','2026-08-10 10:00:00+00','2026-08-10 10:30:00+00',$3,TRUE,'confirmed','m0')`,
			calID, uid, organizer); err != nil {
			t.Fatalf("seed event %s: %v", uid, err)
		}
	}

	// A real CA anchored for the recipient's fixture domain, a leaf for the
	// attendee issued by it, plus a lookalike CA for the forger — ALSO
	// anchored, simulating an attacker who bought a publicly trusted S/MIME
	// cert for their own address (the r7 mismatch case: trusted cert, wrong role).
	caRoot, caLeaf, caKey := testSMIMECA(t, []string{attendee})
	importDomainAnchor(t, pool, fx.domainID, caRoot)
	forgerRoot, forgerLeaf, forgerKey := testSMIMECA(t, []string{forger})
	importDomainAnchor(t, pool, fx.domainID, forgerRoot)
	selfCert, selfKey := selfSignedSigner(t, attendee)

	tests := []struct {
		name         string
		chain        []*x509.Certificate
		key          *rsa.PrivateKey
		fromHeader   string
		envelopeFrom string
		wantAttendee bool
		wantDropped  int64
	}{
		{
			// HOLD item 1: signature math alone must not authenticate. The
			// self-signed cert is dropped at the trust gate, BEFORE the role
			// check, so imipRejected is not bumped (that counter is role-auth
			// rejections only).
			name:         "self-signed cert bearing the attendee email — untrusted, the old false positive",
			chain:        []*x509.Certificate{selfCert},
			key:          selfKey,
			fromHeader:   attendee,
			envelopeFrom: forger,
			wantAttendee: false,
			wantDropped:  0,
		},
		{
			name:         "chained trusted signer==attendee over an attacker envelope — accepted via (a)",
			chain:        []*x509.Certificate{caLeaf, caRoot},
			key:          caKey,
			fromHeader:   attendee,
			envelopeFrom: forger,
			wantAttendee: true,
			wantDropped:  0,
		},
		{
			name:         "chained trusted signer!=attendee — role mismatch still rejected (r7 contract)",
			chain:        []*x509.Certificate{forgerLeaf, forgerRoot},
			key:          forgerKey,
			fromHeader:   forger,
			envelopeFrom: attendee,
			wantAttendee: false,
			wantDropped:  1,
		},
		{
			name:         "trusted attendee signer but From header claims someone else — From-binding fails, dropped",
			chain:        []*x509.Certificate{caLeaf, caRoot},
			key:          caKey,
			fromHeader:   forger,
			envelopeFrom: forger,
			wantAttendee: false,
			wantDropped:  0,
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uid := fmt.Sprintf("imip-smime-bind-%d", i)
			seedEvent(t, uid)
			srv := &InboundServer{
				pool:    pool,
				toggles: toggle.NewStatic(map[string]bool{}),
				logger:  testsupport.TestLogger(),
			}
			c := &inConnState{srv: srv, from: tc.envelopeFrom, to: []string{attendee}}
			msg := buildIMipSignedMessage(t, caldav.MethodReply, uid, organizer, tc.chain, tc.key, "", attendee)
			identity := caldav.ITIPTransportIdentity{
				EnvelopeFrom: tc.envelopeFrom,
				FromHeader:   tc.fromHeader,
			}
			c.detectAndProcessIMip(ctx, msg, identity, 0, "")

			if got := srv.imipRejected.Load(); got != tc.wantDropped {
				t.Errorf("imipRejected = %d, want %d", got, tc.wantDropped)
			}
			var rows int
			if err := pool.QueryRow(ctx,
				`SELECT count(*) FROM event_attendees ea
				 JOIN calendar_events ce ON ce.id = ea.event_id
				 WHERE ce.uid = $1 AND ea.email = $2`, uid, attendee).Scan(&rows); err != nil {
				t.Fatalf("count attendee rows: %v", err)
			}
			if tc.wantAttendee && rows != 1 {
				t.Errorf("trusted S/MIME-authenticated message was not processed (attendee rows=%d)", rows)
			}
			if !tc.wantAttendee && rows != 0 {
				t.Errorf("untrusted/mismatched S/MIME reached the reducer (attendee rows=%d)", rows)
			}
		})
	}
}

// TestDetectAndProcessIMip_SignedRequestTrailingUnsignedCancel — HOLD item 3:
// the calendar processed must be EXACTLY the S/MIME-verified part. A trailing
// unsigned METHOD:CANCEL part after the signature must not turn a signed
// REQUEST into a cancel (old extraction scanned the whole message and
// ParseITIP let the last METHOD win).
func TestDetectAndProcessIMip_SignedRequestTrailingUnsignedCancel(t *testing.T) {
	fx := setupIMipBindingFixture(t)
	pool := fx.pool
	attendee := fx.attendee
	ctx := context.Background()
	const organizer = "organizer@imip.test"
	caRoot, caLeaf, caKey := testSMIMECA(t, []string{organizer})
	importDomainAnchor(t, pool, fx.domainID, caRoot)

	uid := "imip-r3-req-cancel"
	msg := buildIMipSignedMessage(t, caldav.MethodRequest, uid, organizer,
		[]*x509.Certificate{caLeaf, caRoot}, caKey, caldav.MethodCancel, attendee)

	srv := &InboundServer{
		pool:    pool,
		toggles: toggle.NewStatic(map[string]bool{}),
		logger:  testsupport.TestLogger(),
	}
	c := &inConnState{srv: srv, from: organizer, to: []string{attendee}}
	identity := caldav.ITIPTransportIdentity{
		EnvelopeFrom: "bounces@relay.mailer.test",
		FromHeader:   organizer,
	}
	c.detectAndProcessIMip(ctx, msg, identity, 0, "")

	var rows int
	var status string
	if err := pool.QueryRow(ctx,
		`SELECT count(*), coalesce(max(status),'') FROM calendar_events WHERE uid = $1`, uid).Scan(&rows, &status); err != nil {
		t.Fatalf("count event rows: %v", err)
	}
	if rows != 1 {
		t.Fatalf("signed REQUEST must create exactly one event, got %d rows", rows)
	}
	if status != "tentative" {
		t.Errorf("event status = %q, want %q — the trailing unsigned METHOD:CANCEL must not override the signed REQUEST", status, "tentative")
	}
	if got := srv.imipRejected.Load(); got != 0 {
		t.Errorf("imipRejected = %d, want 0 (REQUEST creates without role auth; trust gate passed)", got)
	}
}

// TestDetectAndProcessIMip_UnsignedTrailingCalendarDropped — HOLD item 5: when
// the S/MIME-verified content carries no calendar, a trailing UNSIGNED
// text/calendar part must be dropped unprocessed, never promoted into
// processing by whole-message scanning.
func TestDetectAndProcessIMip_UnsignedTrailingCalendarDropped(t *testing.T) {
	fx := setupIMipBindingFixture(t)
	pool := fx.pool
	attendee := fx.attendee
	ctx := context.Background()
	const organizer = "organizer@imip.test"
	caRoot, caLeaf, caKey := testSMIMECA(t, []string{attendee})
	importDomainAnchor(t, pool, fx.domainID, caRoot)

	const uid = "imip-r3-trailing-only"
	// Signed content is a plain text part; the ONLY calendar is an unsigned
	// trailing REQUEST part after the signature.
	contentPart := "Content-Type: text/plain; charset=utf-8\r\n\r\nnothing calendar-related here\r\n"
	sigDER, err := cms.SignDetached([]byte(contentPart), []*x509.Certificate{caLeaf, caRoot}, caKey)
	if err != nil {
		t.Fatalf("cms.SignDetached: %v", err)
	}
	const boundary = "smime-imip-boundary"
	msg := buildMultipartSigned(t, contentPart, sigDER, boundary)
	trailing := "--" + boundary + "\r\n" +
		"Content-Type: text/calendar; method=REQUEST; charset=utf-8\r\n\r\n" +
		buildIMipCalendar(caldav.MethodRequest, uid, organizer, attendee) + "\r\n"
	msg = strings.Replace(msg, "--"+boundary+"--\r\n", trailing+"--"+boundary+"--\r\n", 1)

	srv := &InboundServer{
		pool:    pool,
		toggles: toggle.NewStatic(map[string]bool{}),
		logger:  testsupport.TestLogger(),
	}
	c := &inConnState{srv: srv, from: attendee, to: []string{attendee}}
	identity := caldav.ITIPTransportIdentity{
		EnvelopeFrom: attendee,
		FromHeader:   attendee,
		SpfPass:      true, // even strong transport evidence must not launder the unsigned part
	}
	c.detectAndProcessIMip(ctx, msg, identity, 0, "")

	var rows int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM calendar_events WHERE uid = $1`, uid).Scan(&rows); err != nil {
		t.Fatalf("count event rows: %v", err)
	}
	if rows != 0 {
		t.Errorf("unsigned trailing calendar part was processed (%d event rows) — must be rejected unauthenticated", rows)
	}
	if got := srv.imipRejected.Load(); got != 0 {
		t.Errorf("imipRejected = %d, want 0 (drop happens at verified-content extraction, before role auth)", got)
	}
}

// TestVerifyDKIM_DuplicateDomainTag_AlignmentFollowsVerifiedSignature — HOLD
// item 2: duplicate d= tags must not let the alignment read one domain while
// the verifier validates another. The attacker signs with a domain they own
// (d= listed LAST, which parseDKIMSignature's last-wins parse selects and
// verifies against the attacker's real DNS key) but lists the victim domain
// FIRST — the old verifyDKIM scraped the FIRST "d=" substring, saw the victim
// domain, and treated the attacker signature as victim-aligned.
func TestVerifyDKIM_DuplicateDomainTag_AlignmentFollowsVerifiedSignature(t *testing.T) {
	attKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&attKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal attacker public key: %v", err)
	}
	keyRecord := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
	setDNSResolvers(func(domain string) ([]string, error) {
		if domain == "sel._domainkey.attacker.evil.test" {
			return []string{keyRecord}, nil
		}
		return nil, fmt.Errorf("NXDOMAIN")
	}, nil, nil, nil)
	t.Cleanup(ResetDNSResolver)

	const (
		from      = "organizer@victim.local.test"
		fromDom   = "victim.local.test"
		attDomain = "attacker.evil.test"
	)
	raw := "From: " + from + "\r\nSubject: poisoned d=\r\n\r\npoisoned body\r\n"

	// Sign EXACTLY like the attacker: over the reconstruction with the
	// attacker-owned d= (the tag the verifier's last-wins parse keeps).
	signAsAttacker := func(headerTags string) string {
		sig := &DKIMSig{
			Domain:    attDomain,
			Selector:  "sel",
			Algorithm: "rsa-sha256",
			Headers:   []string{"from", "subject"},
			Canonical: "relaxed/relaxed",
		}
		_, body := splitHeadersBody([]byte(raw))
		sig.BodyHash = base64.StdEncoding.EncodeToString(dkimBodyHash(body, sig.Canonical, 0))
		hash := sha256.Sum256([]byte(dkimSignedData(raw, sig)))
		b, err := rsa.SignPKCS1v15(rand.Reader, attKey, crypto.SHA256, hash[:])
		if err != nil {
			t.Fatalf("rsa.SignPKCS1v15: %v", err)
		}
		return "DKIM-Signature: " + headerTags + base64.StdEncoding.EncodeToString(b) + "\r\n" + raw
	}

	t.Run("duplicate d= tags: verified signature's domain decides", func(t *testing.T) {
		// victim domain FIRST (what the old scraper read), attacker LAST (what
		// the verifier actually validates).
		_, body := splitHeadersBody([]byte(raw))
		bh := base64.StdEncoding.EncodeToString(dkimBodyHash(body, "relaxed/relaxed", 0))
		msg := signAsAttacker("a=rsa-sha256; c=relaxed/relaxed; d=" + fromDom +
			"; d=" + attDomain + "; s=sel; t=0; x=0; h=from:subject; bh=" + bh + "; b=")

		c := &inConnState{data: []byte(msg)}
		result, domain, _, _ := c.verifyDKIM()
		if result != DKIMPass {
			t.Fatalf("attacker signature must still verify cryptographically, got %s", result)
		}
		if domain != attDomain {
			t.Errorf("dkimDomain = %q, want %q — alignment must follow the VERIFIED signature's domain, not the first d= tag", domain, attDomain)
		}
		dkimAligned := isDMARCAligned(domain, fromDom, DMARCRelaxed)
		if dkimAligned {
			t.Fatal("attacker signing domain must not align with the victim From domain")
		}
		identity := caldav.ITIPTransportIdentity{
			EnvelopeFrom: "bounces@attacker.evil.test",
			FromHeader:   from,
			DkimAligned:  dkimAligned,
			DkimDomain:   domain,
		}
		if identity.AuthenticatedAs(from) {
			t.Error("duplicate d= poisoning authenticated the victim role — the round-3 bypass is open")
		}
	})

	t.Run("single d= tag: control — extraction and verification agree", func(t *testing.T) {
		_, body := splitHeadersBody([]byte(raw))
		bh := base64.StdEncoding.EncodeToString(dkimBodyHash(body, "relaxed/relaxed", 0))
		msg := signAsAttacker("a=rsa-sha256; c=relaxed/relaxed; d=" + attDomain +
			"; s=sel; t=0; x=0; h=from:subject; bh=" + bh + "; b=")

		c := &inConnState{data: []byte(msg)}
		result, domain, _, _ := c.verifyDKIM()
		if result != DKIMPass || domain != attDomain {
			t.Errorf("control: got (%s, %q), want (pass, %q)", result, domain, attDomain)
		}
	})
}

// TestDetectAndProcessIMip_DKIMBodyLengthBinding — round 4 HOLD item 1: an
// accepted DKIM signature carrying an l= tag authenticates only the first l
// bytes of the canonicalized body (RFC 6376 §3.5); every appended byte beyond
// that prefix is UNAUTHENTICATED and must never extend the calendar text fed
// to ParseITIP. verifyDKIM must report the signed length and the iMIP step
// must cut the body to that prefix before extraction.
func TestDetectAndProcessIMip_DKIMBodyLengthBinding(t *testing.T) {
	fx := setupIMipBindingFixture(t)
	pool := fx.pool
	attendee := fx.attendee
	ctx := context.Background()
	const (
		organizer = "organizer@imip.test"
	)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signer key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal signer public key: %v", err)
	}
	keyRecord := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
	setDNSResolvers(func(domain string) ([]string, error) {
		if domain == "sel4._domainkey.imip.test" {
			return []string{keyRecord}, nil
		}
		return nil, fmt.Errorf("NXDOMAIN")
	}, nil, nil, nil)
	t.Cleanup(ResetDNSResolver)

	// signWithLength builds a real DKIM-Signature over raw with an l= tag: bh
	// covers only the first l canonicalized body bytes.
	signWithLength := func(t *testing.T, raw string, l int64) string {
		t.Helper()
		sig := &DKIMSig{
			Domain:    "imip.test",
			Selector:  "sel4",
			Algorithm: "rsa-sha256",
			Headers:   []string{"from", "content-type"},
			Canonical: "relaxed/relaxed",
			Length:    l,
		}
		_, body := splitHeadersBody([]byte(raw))
		sig.BodyHash = base64.StdEncoding.EncodeToString(dkimBodyHash(body, sig.Canonical, l))
		digest := sha256.Sum256([]byte(dkimSignedData(raw, sig)))
		b, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatalf("rsa.SignPKCS1v15: %v", err)
		}
		return "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=imip.test; s=sel4; t=0; x=0; " +
			fmt.Sprintf("l=%d", l) +
			"; h=from:content-type; bh=" + sig.BodyHash +
			"; b=" + base64.StdEncoding.EncodeToString(b) + "\r\n"
	}

	buildMessage := func(body string, l int64) string {
		unsigned := "From: Organizer <" + organizer + ">\r\n" +
			"To: " + attendee + "\r\n" +
			"Subject: dkim l= binding\r\n" +
			"Content-Type: text/calendar; method=REQUEST; charset=utf-8\r\n\r\n" +
			body
		return signWithLength(t, unsigned, l) + unsigned
	}

	t.Run("appended METHOD:CANCEL beyond the signed length: SIGNED REQUEST only", func(t *testing.T) {
		const uid = "imip-r4-len-cancel"
		// The signature covers EXACTLY the complete REQUEST calendar; the whole
		// METHOD:CANCEL block lies beyond the authenticated prefix.
		signedCal := buildIMipCalendar(caldav.MethodRequest, uid, organizer, attendee)
		appended := "\r\n" + buildIMipCalendar(caldav.MethodCancel, uid, organizer, attendee)
		msg := buildMessage(signedCal+appended, int64(len(signedCal)))

		srv := &InboundServer{
			pool:    pool,
			toggles: toggle.NewStatic(map[string]bool{}),
			logger:  testsupport.TestLogger(),
		}
		c := &inConnState{srv: srv, data: []byte(msg), from: organizer, to: []string{attendee}}
		result, domain, signedLen, _ := c.verifyDKIM()
		if result != DKIMPass {
			t.Fatalf("l=-carrying signature must verify, got %s", result)
		}
		if domain != "imip.test" || signedLen != int64(len(signedCal)) {
			t.Fatalf("verifyDKIM = (%q, %d), want (imip.test, %d)", domain, signedLen, len(signedCal))
		}
		identity := caldav.ITIPTransportIdentity{
			EnvelopeFrom: organizer,
			FromHeader:   organizer,
			DkimAligned:  isDMARCAligned(domain, "imip.test", DMARCRelaxed),
			DkimDomain:   domain,
		}
		c.detectAndProcessIMip(ctx, msg, identity, signedLen, "relaxed/relaxed")

		var rows int
		var status string
		if err := pool.QueryRow(ctx,
			`SELECT count(*), coalesce(max(status),'') FROM calendar_events WHERE uid = $1`, uid,
		).Scan(&rows, &status); err != nil {
			t.Fatalf("count event rows: %v", err)
		}
		if rows != 1 || status != "tentative" {
			t.Errorf("appended METHOD:CANCEL beyond the l= prefix was processed: got %d rows status=%q, want exactly the SIGNED REQUEST (1 row, tentative)", rows, status)
		}
		if got := srv.imipRejected.Load(); got != 0 {
			t.Errorf("imipRejected = %d, want 0", got)
		}
	})

	t.Run("attacker-completed calendar cut at the signed prefix: nothing processes", func(t *testing.T) {
		const uid = "imip-r4-len-attacker"
		// The signature covers only the first 80 bytes — through
		// "BEGIN:VEVENT" — of the signed calendar. The attacker completes the
		// event with their own UID and data beyond the signed prefix.
		fullCal := buildIMipCalendar(caldav.MethodRequest, "imip-r4-len-prefix", organizer, attendee)
		const l = 80 // exactly through "BEGIN:VEVENT\r\n" in buildIMipCalendar's layout
		if got := fullCal[:l]; !strings.HasSuffix(got, "BEGIN:VEVENT\r\n") {
			t.Fatalf("test layout drift: byte %d of the calendar no longer ends BEGIN:VEVENT (%q)", l, got)
		}
		completion := "UID:" + uid + "\r\n" +
			"DTSTART:20260810T100000Z\r\n" +
			"DTEND:20260810T103000Z\r\n" +
			"ORGANIZER:mailto:" + organizer + "\r\n" +
			"ATTENDEE;PARTSTAT=ACCEPTED:mailto:" + attendee + "\r\n" +
			"END:VEVENT\r\n" +
			"END:VCALENDAR"
		msg := buildMessage(fullCal[:l]+completion, l)

		srv := &InboundServer{
			pool:    pool,
			toggles: toggle.NewStatic(map[string]bool{}),
			logger:  testsupport.TestLogger(),
		}
		c := &inConnState{srv: srv, data: []byte(msg), from: organizer, to: []string{attendee}}
		result, _, signedLen, _ := c.verifyDKIM()
		if result != DKIMPass {
			t.Fatalf("prefix-only signature must verify, got %s", result)
		}
		identity := caldav.ITIPTransportIdentity{
			EnvelopeFrom: organizer,
			FromHeader:   organizer,
			DkimAligned:  true,
			DkimDomain:   "imip.test",
		}
		c.detectAndProcessIMip(ctx, msg, identity, signedLen, "relaxed/relaxed")

		var rows int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM calendar_events WHERE uid IN ('imip-r4-len-attacker', 'imip-r4-len-prefix')`,
		).Scan(&rows); err != nil {
			t.Fatalf("count event rows: %v", err)
		}
		if rows != 0 {
			t.Errorf("unauthenticated content beyond the l= prefix reached processing (%d rows) — the attacker-completed calendar must be dropped", rows)
		}
	})
}

// TestDetectAndProcessIMip_DKIMLengthCanonicalSpaceBinding — round 5 HOLD
// (D-MAILSERVER-INTERNAL-CALDAV-003 reopened): l= is counted against the
// CANONICALIZED body (RFC 6376 §3.5), but the DATA intake (net/textproto
// DotReader) canonicalizes CRLF→LF BEFORE storage — so for a CRLF-heavy signed
// body the stored form is far SHORTER than l=. The round-4 fence indexed the
// STORED bytes with the raw l= value: when the appended unsigned calendar
// kept the stored body at or below l, the fence skipped the cut entirely and
// the attacker content reached ParseITIP (Astra repro: l=1800 vs a 1429-byte
// stored body). The fence now maps l= back through the same c=
// canonicalization, so the cut lands inside the SIGNED portion regardless of
// how much canonical expansion inflates l.
func TestDetectAndProcessIMip_DKIMLengthCanonicalSpaceBinding(t *testing.T) {
	fx := setupIMipBindingFixture(t)
	pool := fx.pool
	attendee := fx.attendee
	ctx := context.Background()
	const (
		organizer = "organizer@imip.test"
	)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signer key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal signer public key: %v", err)
	}
	keyRecord := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
	setDNSResolvers(func(domain string) ([]string, error) {
		if domain == "sel5._domainkey.imip.test" {
			return []string{keyRecord}, nil
		}
		return nil, fmt.Errorf("NXDOMAIN")
	}, nil, nil, nil)
	t.Cleanup(ResetDNSResolver)

	// signWithLength is the attacker/legit-sender signing oracle: bh covers
	// only the first l CANONICALIZED body bytes (dkimBodyHash).
	signWithLength := func(t *testing.T, raw string, l int64) string {
		t.Helper()
		sig := &DKIMSig{
			Domain:    "imip.test",
			Selector:  "sel5",
			Algorithm: "rsa-sha256",
			Headers:   []string{"from", "content-type"},
			Canonical: "relaxed/relaxed",
			Length:    l,
		}
		_, body := splitHeadersBody([]byte(raw))
		sig.BodyHash = base64.StdEncoding.EncodeToString(dkimBodyHash(body, sig.Canonical, l))
		digest := sha256.Sum256([]byte(dkimSignedData(raw, sig)))
		b, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatalf("rsa.SignPKCS1v15: %v", err)
		}
		return "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=imip.test; s=sel5; t=0; x=0; " +
			fmt.Sprintf("l=%d", l) +
			"; h=from:content-type; bh=" + sig.BodyHash +
			"; b=" + base64.StdEncoding.EncodeToString(b) + "\r\n"
	}

	// crlfHeavyCalendar pads a complete REQUEST calendar with 300 extra lines:
	// the canonical (l=) form of the signed portion grows ~300 bytes beyond
	// its LF-stored form — more than the appended CANCEL calendar, so the
	// WHOLE stored body (signed prefix + append) stays below l= and the
	// round-4 stored-space fence skipped the cut entirely.
	crlfHeavyCalendar := func(uid string) string {
		var b strings.Builder
		b.WriteString("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\n")
		b.WriteString("METHOD:REQUEST\r\nBEGIN:VEVENT\r\n")
		b.WriteString("UID:" + uid + "\r\n")
		b.WriteString("DTSTART:20260810T100000Z\r\nDTEND:20260810T103000Z\r\n")
		b.WriteString("ORGANIZER:mailto:" + organizer + "\r\n")
		b.WriteString("ATTENDEE;PARTSTAT=ACCEPTED:mailto:" + attendee + "\r\n")
		for i := 0; i < 300; i++ {
			b.WriteString(fmt.Sprintf("X-PAD-%03d:0123456789\r\n", i))
		}
		b.WriteString("END:VEVENT\r\nEND:VCALENDAR")
		return b.String()
	}

	process := func(t *testing.T, signedPortion, appended string, uid string) *InboundServer {
		t.Helper()
		l := int64(len(dkimRelaxedBody([]byte(signedPortion))))
		unsigned := "From: Organizer <" + organizer + ">\r\n" +
			"To: " + attendee + "\r\n" +
			"Subject: dkim l= canonical binding\r\n" +
			"Content-Type: text/calendar; method=REQUEST; charset=utf-8\r\n\r\n" +
			signedPortion + appended
		raw := signWithLength(t, unsigned, l) + unsigned
		// Production stores the DotReader-canonicalized form: CRLF→LF.
		stored := strings.ReplaceAll(raw, "\r\n", "\n")
		if len(stored) >= len(raw) {
			t.Fatalf("test premise: stored (LF) form must be shorter than the transmitted CRLF form")
		}

		srv := &InboundServer{
			pool:    pool,
			toggles: toggle.NewStatic(map[string]bool{}),
			logger:  testsupport.TestLogger(),
		}
		c := &inConnState{srv: srv, data: []byte(stored), from: organizer, to: []string{attendee}}
		result, domain, signedLen, canonical := c.verifyDKIM()
		if result != DKIMPass {
			t.Fatalf("l=-carrying signature must verify over the stored form, got %s", result)
		}
		if domain != "imip.test" || signedLen != l {
			t.Fatalf("verifyDKIM = (%q, %d), want (imip.test, %d)", domain, signedLen, l)
		}
		// The old fence skipped the cut entirely at this l=: the whole stored
		// body (signed portion + appended calendar) stays below l.
		if _, body := splitHeadersBody([]byte(stored)); int64(len(body)) <= l {
			t.Logf("premise held: stored body %d <= l %d — the round-4 fence skipped the cut", len(body), l)
		} else {
			t.Fatalf("test premise: stored body %d must fit below l=%d for the round-4 bypass", len(body), l)
		}
		identity := caldav.ITIPTransportIdentity{
			EnvelopeFrom: organizer,
			FromHeader:   organizer,
			DkimAligned:  isDMARCAligned(domain, "imip.test", DMARCRelaxed),
			DkimDomain:   domain,
		}
		c.detectAndProcessIMip(ctx, stored, identity, signedLen, canonical)
		return srv
	}

	t.Run("appended METHOD:CANCEL below the canonical l=: only the SIGNED REQUEST survives", func(t *testing.T) {
		const uid = "imip-r5-crlf-cancel"
		signed := crlfHeavyCalendar(uid)
		appended := "\n" + strings.ReplaceAll(buildIMipCalendar(caldav.MethodCancel, uid, organizer, attendee), "\r\n", "\n")
		srv := process(t, signed, appended, uid)

		var rows int
		var status string
		if err := pool.QueryRow(ctx,
			`SELECT count(*), coalesce(max(status),'') FROM calendar_events WHERE uid = $1`, uid,
		).Scan(&rows, &status); err != nil {
			t.Fatalf("count event rows: %v", err)
		}
		if rows != 1 || status != "tentative" {
			t.Errorf("canonical-space fence failed: got %d rows status=%q, want exactly the SIGNED REQUEST (1 row, tentative)", rows, status)
		}
		if got := srv.imipRejected.Load(); got != 0 {
			t.Errorf("imipRejected = %d, want 0", got)
		}
	})

	t.Run("attacker-completed calendar under the canonical l=: nothing processes", func(t *testing.T) {
		const uid = "imip-r5-crlf-attacker"
		signed := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\n" +
			"METHOD:REQUEST\r\nBEGIN:VEVENT\r\n"
		for i := 0; i < 200; i++ {
			signed += fmt.Sprintf("X-PAD-%03d:0123456789\r\n", i)
		}
		completion := "UID:" + uid + "\n" +
			"DTSTART:20260810T100000Z\nDTEND:20260810T103000Z\n" +
			"ORGANIZER:mailto:" + organizer + "\n" +
			"ATTENDEE;PARTSTAT=ACCEPTED:mailto:" + attendee + "\n" +
			"END:VEVENT\nEND:VCALENDAR"
		srv := process(t, signed, completion, uid)

		var rows int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM calendar_events WHERE uid = $1`, uid,
		).Scan(&rows); err != nil {
			t.Fatalf("count event rows: %v", err)
		}
		if rows != 0 {
			t.Errorf("attacker-completed calendar processed (%d rows) — content beyond the canonical signed prefix must be dropped", rows)
		}
		if got := srv.imipRejected.Load(); got != 0 {
			t.Errorf("imipRejected = %d, want 0 (the drop is extraction-scope, not role auth)", got)
		}
	})
}

// tenantTestCA builds a self-signed root CA plus one leaf per email, returning
// the CA key so further leaves can be issued under the SAME anchor.
func tenantTestCA(t *testing.T, leafEmails []string) (*x509.Certificate, *rsa.PrivateKey, []*x509.Certificate, []*rsa.PrivateKey) {
	t.Helper()
	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate root key: %v", err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Round5 Tenant Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("create root cert: %v", err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("parse root cert: %v", err)
	}
	var leaves []*x509.Certificate
	var leafKeys []*rsa.PrivateKey
	for _, email := range leafEmails {
		leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate leaf key: %v", err)
		}
		leafTmpl := &x509.Certificate{
			SerialNumber:   big.NewInt(time.Now().UnixNano()),
			Subject:        pkix.Name{CommonName: email},
			EmailAddresses: []string{email},
			NotBefore:      time.Now().Add(-time.Hour),
			NotAfter:       time.Now().Add(24 * time.Hour),
			ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageEmailProtection},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, root, &leafKey.PublicKey, rootKey)
		if err != nil {
			t.Fatalf("create leaf cert for %s: %v", email, err)
		}
		leaf, err := x509.ParseCertificate(leafDER)
		if err != nil {
			t.Fatalf("parse leaf cert: %v", err)
		}
		leaves = append(leaves, leaf)
		leafKeys = append(leafKeys, leafKey)
	}
	return root, rootKey, leaves, leafKeys
}

// TestDetectAndProcessIMip_SMimeTrustDomainBinding — round 5 HOLD: S/MIME
// trust is verified under the RECIPIENT's pool, but the round-4 signer-domain
// sweep binding derived its domain from the CERT EMAIL. An A-only CA (the sole
// anchor in recipient tenant A's pool, scoped to imip.test) that certified
// organizer@b.test therefore authenticated B's organizer and the sweep then
// selected B's copies. Round 5 required the signer email's domain to be covered
// by the validated chain's anchor; round 6 (Astra HOLD) moves that coverage
// question into a PER-AFFECTED-MAILBOX trust-policy gate — each affected copy's
// owner domain must trust the evidence, so A's anchor can still never cancel
// B's copies while A's own (importing) tenant's copies are cancellable.
func TestDetectAndProcessIMip_SMimeTrustDomainBinding(t *testing.T) {
	fx := setupIMipBindingFixture(t) // recipient tenant A: the minted fixture domain
	pool, calID := fx.pool, fx.calID
	attendee := fx.attendee
	ctx := context.Background()
	const (
		organizerA = "organizer@imip.test"
		organizerB = "organizer@b.test"
		uidX       = "imip-r5-xtrust"
		uidOwn     = "imip-r5-own"
	)

	// Tenant A's ONLY anchor, also certifying organizer@b.test — the Astra
	// repro shape. importDomainAnchor scopes it to tenant A's domain.
	caRoot, _, leaves, leafKeys := tenantTestCA(t, []string{organizerB, organizerA})
	importDomainAnchor(t, pool, fx.domainID, caRoot)
	leafB, keyB := leaves[0], leafKeys[0]
	leafA, keyA := leaves[1], leafKeys[1]

	seed := func(t *testing.T, cal int64, uid, organizer string) {
		t.Helper()
		if _, err := pool.Exec(ctx,
			`INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, organizer_email, is_meeting, status, etag)
			 VALUES ($1,$2,'Standup','2026-08-10 10:00:00+00','2026-08-10 10:30:00+00',$3,TRUE,'confirmed','m0')`,
			cal, uid, organizer); err != nil {
			t.Fatalf("seed event %s: %v", uid, err)
		}
	}

	// Tenant B owns a copy of the same meeting (uid + organizer@b.test). The
	// peer tenant is minted fresh per run — the retired fixed ids 98120-22
	// ('b.test' / peer@b.test) collided across overlapping runs.
	peerB := seedIMipPeerTenant(t, pool, "r5")
	bCal := peerB.calID
	seed(t, calID, uidX, organizerB) // tenant-A copy of the cross-tenant meeting
	seed(t, bCal, uidX, organizerB)  // tenant-B copy
	seed(t, calID, uidOwn, organizerA)

	status := func(t *testing.T, uid string, cal int64) string {
		t.Helper()
		var s string
		if err := pool.QueryRow(ctx,
			`SELECT status FROM calendar_events WHERE uid=$1 AND calendar_id=$2`, uid, cal,
		).Scan(&s); err != nil {
			t.Fatalf("event row missing (uid=%s cal=%d): %v", uid, cal, err)
		}
		return s
	}

	t.Run("A-only CA certifying organizer@B: per-mailbox policy — B's copies survive, A's copy cancelled", func(t *testing.T) {
		// Round 6 supersedes the round-5 expectation on THIS shape: the CANCEL
		// is now authenticated by rule (a) (the signature is valid, the signer
		// email == DB organizer, the anchor attributable), and the sweep is
		// gated PER AFFECTED MAILBOX instead of being bound to the signer's
		// domain. Tenant B's mailbox policy never granted A's anchor, so B's
		// copy MUST survive — the round-5 cross-tenant protection, now
		// enforced per-mailbox. Tenant A imported the anchor and its policy
		// accepts the evidence, so A's own copy is cancelled.
		msg := buildIMipSignedMessage(t, caldav.MethodCancel, uidX, organizerB,
			[]*x509.Certificate{leafB, caRoot}, keyB, "", attendee)
		srv := &InboundServer{
			pool:    pool,
			toggles: toggle.NewStatic(map[string]bool{}),
			logger:  testsupport.TestLogger(),
		}
		c := &inConnState{srv: srv, from: organizerB, to: []string{attendee}}
		identity := caldav.ITIPTransportIdentity{EnvelopeFrom: organizerB, FromHeader: organizerB}
		c.detectAndProcessIMip(ctx, msg, identity, 0, "")

		if got := srv.imipRejected.Load(); got != 0 {
			t.Errorf("imipRejected = %d, want 0 — the CANCEL authenticated and was policy-filtered, not dropped", got)
		}
		if got := status(t, uidX, bCal); got != "confirmed" {
			t.Errorf("tenant-B copy status = %q, want confirmed — an A-scoped anchor's policy must never cancel B's mailboxes", got)
		}
		if got := status(t, uidX, calID); got != "cancelled" {
			t.Errorf("tenant-A copy status = %q, want cancelled — the importing tenant's own policy accepts its anchor", got)
		}
	})

	t.Run("same CA certifying A's own organizer: A's copies cancellable", func(t *testing.T) {
		msg := buildIMipSignedMessage(t, caldav.MethodCancel, uidOwn, organizerA,
			[]*x509.Certificate{leafA, caRoot}, keyA, "", attendee)
		srv := &InboundServer{
			pool:    pool,
			toggles: toggle.NewStatic(map[string]bool{}),
			logger:  testsupport.TestLogger(),
		}
		c := &inConnState{srv: srv, from: organizerA, to: []string{attendee}}
		identity := caldav.ITIPTransportIdentity{EnvelopeFrom: organizerA, FromHeader: organizerA}
		c.detectAndProcessIMip(ctx, msg, identity, 0, "")

		if got := srv.imipRejected.Load(); got != 0 {
			t.Errorf("imipRejected = %d, want 0 — same-tenant S/MIME CANCEL is legitimate", got)
		}
		if got := status(t, uidOwn, calID); got != "cancelled" {
			t.Errorf("tenant-A own copy status = %q, want cancelled", got)
		}
	})
}

// importDeploymentAnchor inserts rootPEM as a DEPLOYMENT-WIDE trust anchor
// (domain_id NULL — unrestricted grant).
func importDeploymentAnchor(t *testing.T, pool *pgxpool.Pool, root *x509.Certificate) {
	t.Helper()
	anchorPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}))
	anchorFP := fp(root)
	if _, err := pool.Exec(context.Background(),
		`DELETE FROM smime_trust_anchors WHERE fingerprint = $1`, anchorFP); err != nil {
		t.Fatalf("clear stale anchor: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO smime_trust_anchors (label, cert_pem, fingerprint, domain_id) VALUES ('imip-round6-deployment-ca',$1,$2,NULL)`,
		anchorPEM, anchorFP); err != nil {
		t.Fatalf("insert deployment trust anchor: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM smime_trust_anchors WHERE fingerprint = $1`, anchorFP)
	})
}

// TestDetectAndProcessIMip_ExternalOrganizerCancelPolicy — round 6 (Astra
// HOLD, D-MAILSERVER-INTERNAL-CALDAV-004 reopened): the round-4 blanket
// SIGNER-DOMAIN sweep filter suppressed legitimate EXTERNAL-organizer
// cancellations entirely (organizer@vendor could never match any local owner
// domain). The sweep is now gated per affected mailbox: every local copy
// sharing uid+organizer is enumerated, and a copy is cancelled only when its
// owner domain's trust policy accepts the authenticated evidence.
//
//   - S/MIME via a DEPLOYMENT-WIDE anchor: unrestricted ⇒ every affected
//     domain accepts ⇒ both tenants' copies cancelled (the previously
//     suppressed legitimate case).
//   - S/MIME via an A-SCOPED anchor: only A's mailbox policy accepts ⇒ A's
//     copy cancelled, B's copy survives.
//   - DKIM-aligned external organizer (rule (b)): DNS-verified evidence is not
//     tenant-scoped ⇒ every affected domain accepts ⇒ both copies cancelled.
func TestDetectAndProcessIMip_ExternalOrganizerCancelPolicy(t *testing.T) {
	fx := setupIMipBindingFixture(t) // tenant A: the minted fixture domain
	pool, calID := fx.pool, fx.calID
	attendee := fx.attendee
	ctx := context.Background()
	const organizerExt = "organizer@vendor-external.test"

	// Tenant B holds a second copy of the same external-organizer meeting.
	// Minted fresh per run — the retired fixed ids 98130-32 ('b6.test' /
	// peer6@b6.test) collided across overlapping runs whatever order or
	// partial cleanup they ran in.
	peerB := seedIMipPeerTenant(t, pool, "r6")
	bCal := peerB.calID

	// D-2 (Astra r3): every event UID this test seeds is minted PER RUN. The
	// production cancellation sweep searches ALL matching uid+organizer copies
	// across domains, so the retired fixed UIDs let one run's CANCEL
	// processing reach another concurrent run's identically-named copies on
	// the shared test database — unique tenants alone do not prevent that.
	// foreignUID mirrors what a concurrent run's differently-suffixed events
	// look like to this run's CANCEL (same organizer, different uid); every
	// subtest asserts those foreign copies survive untouched.
	run := imipRandSuffix(t)
	foreignUID := "imip-r6-foreign-" + run

	seed := func(t *testing.T, cal int64, uid, organizer string) {
		t.Helper()
		if _, err := pool.Exec(ctx,
			`INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, organizer_email, is_meeting, status, etag)
			 VALUES ($1,$2,'Standup','2026-08-10 10:00:00+00','2026-08-10 10:30:00+00',$3,TRUE,'confirmed','m0')`,
			cal, uid, organizer); err != nil {
			t.Fatalf("seed event %s: %v", uid, err)
		}
	}
	status := func(t *testing.T, uid string, cal int64) string {
		t.Helper()
		var s string
		if err := pool.QueryRow(ctx,
			`SELECT status FROM calendar_events WHERE uid=$1 AND calendar_id=$2`, uid, cal,
		).Scan(&s); err != nil {
			t.Fatalf("event row missing (uid=%s cal=%d): %v", uid, cal, err)
		}
		return s
	}

	// The foreign copies share only the organizer with the cancelled series —
	// the in-run proxy for a concurrent run's differently-suffixed events.
	seed(t, calID, foreignUID, organizerExt)
	seed(t, bCal, foreignUID, organizerExt)
	assertForeignSurvival := func(t *testing.T) {
		t.Helper()
		if got := status(t, foreignUID, calID); got != "confirmed" {
			t.Errorf("foreign-event status = %q, want confirmed — the sweep keys on uid+organizer and must never touch a different uid's copies", got)
		}
		if got := status(t, foreignUID, bCal); got != "confirmed" {
			t.Errorf("foreign-event status = %q, want confirmed — the sweep keys on uid+organizer and must never touch a different uid's copies", got)
		}
	}

	// The external organizer's cert chain; the test re-anchors it per case.
	caRoot, _, leaves, leafKeys := tenantTestCA(t, []string{organizerExt})
	leafExt, keyExt := leaves[0], leafKeys[0]

	// A DKIM key for the external organizer's OWN domain so rule (b) can
	// authenticate the aligned From header (d= must align with the From
	// domain — the organizer's own external domain here).
	dkimKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate dkim key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&dkimKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal dkim public key: %v", err)
	}
	keyRecord := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
	const extDomain = "vendor-external.test"
	setDNSResolvers(func(domain string) ([]string, error) {
		if domain == "sel6._domainkey."+extDomain {
			return []string{keyRecord}, nil
		}
		return nil, fmt.Errorf("NXDOMAIN")
	}, nil, nil, nil)
	t.Cleanup(ResetDNSResolver)

	// signExternalDKIM builds an l=-free (fully signed) DKIM signature for the
	// external organizer's own domain over the CANCEL message.
	signExternalDKIM := func(t *testing.T, msg string) string {
		t.Helper()
		sig := &DKIMSig{
			Domain:    extDomain,
			Selector:  "sel6",
			Algorithm: "rsa-sha256",
			Headers:   []string{"from", "content-type"},
			Canonical: "relaxed/relaxed",
		}
		_, body := splitHeadersBody([]byte(msg))
		sig.BodyHash = base64.StdEncoding.EncodeToString(dkimBodyHash(body, sig.Canonical, 0))
		digest := sha256.Sum256([]byte(dkimSignedData(msg, sig)))
		b, err := rsa.SignPKCS1v15(rand.Reader, dkimKey, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatalf("rsa.SignPKCS1v15: %v", err)
		}
		return "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=" + extDomain + "; s=sel6; t=0; x=0; " +
			"h=from:content-type; bh=" + sig.BodyHash +
			"; b=" + base64.StdEncoding.EncodeToString(b) + "\r\n" + msg
	}

	process := func(t *testing.T, msg string) *InboundServer {
		t.Helper()
		srv := &InboundServer{
			pool:    pool,
			toggles: toggle.NewStatic(map[string]bool{}),
			logger:  testsupport.TestLogger(),
		}
		// c.data is the DotReader-stored message the production intake sets;
		// verifyDKIM and the round-6 l= fence both operate on it.
		c := &inConnState{srv: srv, data: []byte(msg), from: organizerExt, to: []string{attendee}}
		identity := caldav.ITIPTransportIdentity{EnvelopeFrom: organizerExt, FromHeader: organizerExt}
		// deliver() derives these from verifyDKIM before calling
		// detectAndProcessIMip; mirror it for the rule-(b) case.
		if result, domain, _, _ := c.verifyDKIM(); result == DKIMPass {
			identity.DkimDomain = domain
			identity.DkimAligned = isDMARCAligned(domain, extDomain, DMARCRelaxed)
		}
		c.detectAndProcessIMip(ctx, msg, identity, 0, "")
		return srv
	}

	t.Run("deployment-wide anchor: the previously suppressed legit case now cancels both copies", func(t *testing.T) {
		uid := "imip-r6-ext-deploy-" + run
		seed(t, calID, uid, organizerExt)
		seed(t, bCal, uid, organizerExt)
		importDeploymentAnchor(t, pool, caRoot)

		srv := process(t, buildIMipSignedMessage(t, caldav.MethodCancel, uid, organizerExt,
			[]*x509.Certificate{leafExt, caRoot}, keyExt, "", attendee))

		if got := srv.imipRejected.Load(); got != 0 {
			t.Errorf("imipRejected = %d, want 0 — an unrestricted trusted external-organizer CANCEL is legitimate", got)
		}
		if got := status(t, uid, calID); got != "cancelled" {
			t.Errorf("tenant-A copy status = %q, want cancelled — unrestricted trust must not suppress external-organizer cancels", got)
		}
		if got := status(t, uid, bCal); got != "cancelled" {
			t.Errorf("tenant-B copy status = %q, want cancelled — unrestricted trust accepts the evidence for every affected mailbox", got)
		}
		assertForeignSurvival(t)
	})

	t.Run("A-scoped anchor: only A's mailbox policy accepts — B's copy survives", func(t *testing.T) {
		uid := "imip-r6-ext-scoped-" + run
		seed(t, calID, uid, organizerExt)
		seed(t, bCal, uid, organizerExt)
		importDomainAnchor(t, pool, fx.domainID, caRoot) // scoped to tenant A's fixture domain

		srv := process(t, buildIMipSignedMessage(t, caldav.MethodCancel, uid, organizerExt,
			[]*x509.Certificate{leafExt, caRoot}, keyExt, "", attendee))

		if got := srv.imipRejected.Load(); got != 0 {
			t.Errorf("imipRejected = %d, want 0 — the CANCEL authenticated; B's copy is policy-skipped, not dropped", got)
		}
		if got := status(t, uid, calID); got != "cancelled" {
			t.Errorf("tenant-A copy status = %q, want cancelled — A's own anchor policy accepts the evidence", got)
		}
		if got := status(t, uid, bCal); got != "confirmed" {
			t.Errorf("tenant-B copy status = %q, want confirmed — B's policy never granted A's anchor", got)
		}
		assertForeignSurvival(t)
	})

	t.Run("DKIM-aligned external organizer: rule (b) evidence accepted by every affected domain", func(t *testing.T) {
		uid := "imip-r6-ext-dkim-" + run
		seed(t, calID, uid, organizerExt)
		seed(t, bCal, uid, organizerExt)

		unsigned := "From: Organizer <" + organizerExt + ">\r\n" +
			"To: " + attendee + "\r\nSubject: ext cancel\r\n" +
			"Content-Type: text/calendar; method=CANCEL; charset=utf-8\r\n\r\n" +
			buildIMipCalendar(caldav.MethodCancel, uid, organizerExt, attendee) + "\r\n"
		srv := process(t, signExternalDKIM(t, unsigned))

		if got := srv.imipRejected.Load(); got != 0 {
			t.Errorf("imipRejected = %d, want 0 — DKIM-aligned evidence is not tenant-scoped", got)
		}
		if got := status(t, uid, calID); got != "cancelled" {
			t.Errorf("tenant-A copy status = %q, want cancelled", got)
		}
		if got := status(t, uid, bCal); got != "cancelled" {
			t.Errorf("tenant-B copy status = %q, want cancelled", got)
		}
		assertForeignSurvival(t)
	})
}

// captureHandler is a slog handler that records message strings so tests can
// assert which intake branch a crafted message actually reached — the
// InboundServer.logger field is the existing injection seam. The iMIP intake
// logs logSMimeVerified exactly when the S/MIME branch verified a signature
// and logDKIMNotCovering exactly when the round-8 content-binding cleared
// DkimAligned.
type captureHandler struct {
	mu      sync.Mutex
	records []string
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Message)
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

// logged reports whether a record with exactly msg was captured.
func (h *captureHandler) logged(msg string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, m := range h.records {
		if m == msg {
			return true
		}
	}
	return false
}

const (
	// Emitted by detectAndProcessIMip after smime.VerifyDetached returned
	// StatusValid — proof the S/MIME branch was reached AND passed.
	logSMimeVerified = "iMIP: S/MIME signature verified against trusted chain"
	// Emitted when the round-8 coverage check cleared DkimAligned — proof the
	// DKIM evidence was judged against the processed calendar's position.
	logDKIMNotCovering = "iMIP: DKIM pass does not cover the processed calendar — DKIM transport evidence ineligible"
)

// TestDetectAndProcessIMip_MixedEvidenceDKIMContentBinding — round 8 (Astra
// HOLD r15, mixed-evidence l= bypass): DKIM evidence is CONTENT-BOUND. A
// replayed organizer positive-l= DKIM signature whose signed headers omit
// Content-Type lets an attacker replace the top-level Content-Type with
// multipart/signed, preserve the authenticated body as MIME preamble, and
// append an A-trusted S/MIME CANCEL: the S/MIME branch extracts the calendar
// from the VERIFIED content part, which the DKIM signature never covered —
// the old code kept DkimAligned set, and the round-7 per-mailbox OR then let
// rule (b) cancel every tenant's copy although neither evidence class
// authenticates that cancellation outside the S/MIME trust's own reach.
//
// Round 9 (Astra r16, regression-fixture fidelity): every subtest constructs
// the message EXACTLY as production hands it to detectAndProcessIMip —
// buildTraceMessage (inbound.go) prepends CRLF Received/Return-Path trace
// headers to the STORED c.data bytes (the real smtpDataIntake DotReader
// output), never the raw CRLF wire form. The attack replays the ASTRA l=
// geometry: a CRLF-heavy signed REQUEST preamble whose canonical length is
// ~1800 bytes against a ~1429-byte stored body, with the S/MIME CANCEL
// appended beyond it.
//
// Round 10 (Astra r17): the appended S/MIME part is CRLF-signed exactly as
// RFC 8551 §3.1.1 requires of a real sender (the round-9 fixture signed LF
// bytes, which masked the canonicalSignedContent framing residual); the DATA
// intake canonicalizes the part to LF inside c.data, and the fixture asserts
// that LF-stored identity so the round-8 positional coverage verdict (not the
// base<0 fail-closed path) is what defeats the attack. The fence-disabled
// negative control replays the IDENTICAL attack wire — same message bytes,
// same DKIM and S/MIME signatures — and only suppresses the fence input
// (dkimSignedLen=0, production's value when no l= bound exists): the old
// control freshly signed the ENTIRE attack body, i.e. tested a different
// message. Reach into the S/MIME branch is asserted through the captured slog
// records (logSMimeVerified).
//
// D-2 (Astra r2): the seeded event UIDs are minted PER RUN (suffix) because
// the production cancellation search matches by UID + organizer across
// domains — a fixed UID collided with concurrent runs on the shared test
// database, and the control's direct status reset is scoped to this run's
// own calendar ids.
func TestDetectAndProcessIMip_MixedEvidenceDKIMContentBinding(t *testing.T) {
	fx := setupIMipBindingFixture(t) // tenant A: the minted fixture domain
	pool, calA := fx.pool, fx.calID
	attendee := fx.attendee
	ctx := context.Background()
	const (
		organizerExt = "organizer@vendor8.test"
		attackerEnv  = "attacker@evil8.test"
		extDomain    = "vendor8.test"
		boundary     = "atk8-signed-boundary"
	)

	// Tenant B holds a second copy of the same external-organizer meeting.
	// Minted fresh per run — the retired fixed ids 98140-42 ('b8.test' /
	// peer8@b8.test) collided across overlapping runs.
	peerB := seedIMipPeerTenant(t, pool, "r8")
	bCal := peerB.calID

	seed := func(t *testing.T, cal int64, uid string) {
		t.Helper()
		if _, err := pool.Exec(ctx,
			`INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, organizer_email, is_meeting, status, etag)
			 VALUES ($1,$2,'Standup','2026-08-10 10:00:00+00','2026-08-10 10:30:00+00',$3,TRUE,'confirmed','m0')`,
			cal, uid, organizerExt); err != nil {
			t.Fatalf("seed event %s: %v", uid, err)
		}
	}
	status := func(t *testing.T, uid string, cal int64) string {
		t.Helper()
		var s string
		if err := pool.QueryRow(ctx,
			`SELECT status FROM calendar_events WHERE uid=$1 AND calendar_id=$2`, uid, cal,
		).Scan(&s); err != nil {
			t.Fatalf("event row missing (uid=%s cal=%d): %v", uid, cal, err)
		}
		return s
	}

	// A-trusted S/MIME material: tenant A's ONLY anchor (scoped to tenant A's
	// fixture domain) certifying the EXTERNAL organizer — the attack's
	// appended CANCEL carries trust A granted and B never did.
	caRoot, _, leaves, leafKeys := tenantTestCA(t, []string{organizerExt})
	leafExt, keyExt := leaves[0], leafKeys[0]
	importDomainAnchor(t, pool, fx.domainID, caRoot)

	// The external organizer's DKIM key: d= vendor8.test aligns with the From
	// header domain, so rule (b) authenticates on the alignment alone — the
	// bypass the round-8 fence closes.
	dkimKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate dkim key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&dkimKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal dkim public key: %v", err)
	}
	keyRecord := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
	const selector = "selr8"
	setDNSResolvers(func(domain string) ([]string, error) {
		if domain == selector+"._domainkey."+extDomain {
			return []string{keyRecord}, nil
		}
		return nil, fmt.Errorf("NXDOMAIN")
	}, nil, nil, nil)
	t.Cleanup(ResetDNSResolver)

	// lfFrame maps CRLF text onto its LF-stored (DATA-intake) form — the
	// identity c.data holds for wire content after the DotReader canonicalizes
	// every CRLF to LF.
	lfFrame := func(s string) string {
		return strings.ReplaceAll(s, "\r\n", "\n")
	}

	// signReplay is the attacker's replayed organizer signature: a real RSA
	// signature over the listed headers only — Content-Type deliberately
	// UNSIGNED, that is the header the attacker replaces — with bh covering
	// only the first l CANONICALIZED body bytes (RFC 6376 §3.5).
	signReplay := func(t *testing.T, raw string, l int64) string {
		t.Helper()
		sig := &DKIMSig{
			Domain:    extDomain,
			Selector:  selector,
			Algorithm: "rsa-sha256",
			Headers:   []string{"from", "subject"},
			Canonical: "relaxed/relaxed",
			Length:    l,
		}
		_, body := splitHeadersBody([]byte(raw))
		sig.BodyHash = base64.StdEncoding.EncodeToString(dkimBodyHash(body, sig.Canonical, l))
		digest := sha256.Sum256([]byte(dkimSignedData(raw, sig)))
		b, err := rsa.SignPKCS1v15(rand.Reader, dkimKey, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatalf("rsa.SignPKCS1v15: %v", err)
		}
		return "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=" + extDomain + "; s=" + selector + "; t=0; x=0; " +
			fmt.Sprintf("l=%d", l) +
			"; h=from:subject; bh=" + sig.BodyHash +
			"; b=" + base64.StdEncoding.EncodeToString(b) + "\r\n" + raw
	}

	// crlfHeavyPreamble renders the replayed original REQUEST calendar the
	// organizer's positive-l= DKIM signature covers — the Astra repro
	// geometry: very short lines, so the canonical (l=) form is far LONGER
	// than the LF-stored form (l≈1800 against a ~1429-byte stored body).
	crlfHeavyPreamble := func(uid string) string {
		var b strings.Builder
		b.WriteString("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//R8//EN\r\n")
		b.WriteString("METHOD:REQUEST\r\nBEGIN:VEVENT\r\n")
		b.WriteString("UID:" + uid + "\r\n")
		b.WriteString("DTSTART:20260810T100000Z\r\nDTEND:20260810T103000Z\r\n")
		b.WriteString("ORGANIZER:mailto:" + organizerExt + "\r\n")
		b.WriteString("ATTENDEE;PARTSTAT=ACCEPTED:mailto:" + attendee + "\r\n")
		for i := 0; i < 366; i++ {
			switch i % 3 {
			case 0:
				b.WriteString("AB\r\n")
			case 1:
				b.WriteString("ABC\r\n")
			default:
				b.WriteString("AB\r\n")
			}
		}
		b.WriteString("END:VEVENT\r\nEND:VCALENDAR")
		return b.String()
	}

	// attackCore assembles the Astra geometry (without the DKIM header): the
	// DKIM-authenticated body prefix (the replayed original CRLF-heavy REQUEST
	// calendar) is preserved as the MIME preamble of an appended
	// multipart/signed S/MIME CANCEL signed by the A-trusted certificate. The
	// appended part's content is CRLF-signed exactly as RFC 8551 §3.1.1
	// requires of a real sender; the DATA intake canonicalizes it to LF inside
	// c.data (callers assert that LF-stored identity) and the round-8
	// positional check anchors it there through the stored space.
	attackCore := func(t *testing.T, uid string) (core, preamble, contentPart string) {
		t.Helper()
		preamble = crlfHeavyPreamble(uid)
		contentPart = "Content-Type: text/calendar; method=CANCEL; charset=utf-8\r\n\r\n" +
			buildIMipCalendar(caldav.MethodCancel, uid, organizerExt, attendee) + "\r\n"
		sigDER, err := cms.SignDetached([]byte(contentPart), []*x509.Certificate{leafExt, caRoot}, keyExt)
		if err != nil {
			t.Fatalf("cms.SignDetached: %v", err)
		}
		mp := buildMultipartSigned(t, contentPart, sigDER, boundary)
		const marker = "boundary=\"" + boundary + "\"\r\n\r\n"
		if !strings.Contains(mp, marker) {
			t.Fatalf("test layout drift: multipart preamble anchor %q not found", marker)
		}
		core = "From: Organizer <" + organizerExt + ">\r\n" +
			"To: " + attendee + "\r\n" +
			"Subject: r8 mixed evidence\r\n" +
			strings.Replace(mp, marker, marker+preamble+"\r\n", 1)
		return core, preamble, contentPart
	}

	// The attack message is built ONCE: the fence-disabled control below
	// replays the IDENTICAL wire bytes and signature — only the fence input
	// differs (round 10, Astra r17 item 2: the old control freshly signed the
	// ENTIRE attack body, which tested a different message and proved nothing
	// about the fence).
	//
	// D-2 (Astra r2): every event UID this test seeds is minted PER RUN. The
	// production cancellation search intentionally matches by UID + organizer
	// across domains, so a fixed UID let one run's CANCEL processing reach
	// another concurrent run's identically-named copies on the shared test
	// database — unique tenants alone do not prevent that. Every direct
	// assertion/mutation below is additionally scoped to this run's OWN
	// calendar ids.
	run := imipRandSuffix(t)
	attackUID := "imip-r8-mixed-" + run
	coveredUID := "imip-r8-covered-plain-" + run
	spfUID := "imip-r8-spf-" + run
	attackCoreMsg, attackPreamble, attackContentPart := attackCore(t, attackUID)
	attackL := int64(len(dkimRelaxedBody([]byte(attackPreamble))))
	attackWire := signReplay(t, attackCoreMsg, attackL)
	// Astra geometry premises: the canonical signed prefix sits near 1800
	// bytes while its LF-stored form sits near 1429 — the CRLF→LF intake
	// shrink whose gap the round-4 stored-space fence hid unsigned content in.
	storedPreamble := lfFrame(attackPreamble)
	if attackL < 1500 || attackL > 2100 {
		t.Fatalf("test premise: expected the short-line geometry to land l near 1800, got %d", attackL)
	}
	if len(storedPreamble) < 1100 || len(storedPreamble) > 1750 || int64(len(storedPreamble)) >= attackL {
		t.Fatalf("test premise: stored signed prefix %d bytes must sit far below canonical l=%d (Astra ~1429 vs ~1800)", len(storedPreamble), attackL)
	}

	// process drives the REAL production representation end to end: the wire
	// form goes through smtpDataIntake (dot-stuffing + net/textproto DotReader)
	// into c.data, and msg is built EXACTLY like buildTraceMessage (inbound.go)
	// — CRLF Received/Return-Path trace headers prepended to the STORED bytes,
	// never the raw wire form. verifyDKIM runs over c.data; the captured slog
	// records let subtests assert which intake branch actually fired.
	// fenceDisabled suppresses ONLY the round-8 fence input: production passes
	// dkimSignedLen=0 when the verified signature carries no l= bound, which
	// leaves dkimCoveredEnd at -1 and the coverage enforcement inert — the
	// negative control's lever, with every message byte identical.
	process := func(t *testing.T, wire, envelopeFrom string, spfPass, fenceDisabled bool) (*InboundServer, *captureHandler, DKIMResult, int64) {
		t.Helper()
		stored := smtpDataIntake(t, wire) // real DATA intake: dot-stuffing + DotReader
		capture := &captureHandler{}
		srv := &InboundServer{
			pool:    pool,
			toggles: toggle.NewStatic(map[string]bool{}),
			logger:  slog.New(capture),
		}
		msg := "Received: from relay8.test (relay8.test [192.0.2.9]) by mailserver\r\n" +
			"\tvia SMTP; Mon, 10 Aug 2026 10:00:00 +0000\r\n" +
			"Return-Path: <" + envelopeFrom + ">\r\n" + stored
		c := &inConnState{srv: srv, data: []byte(stored), from: envelopeFrom, to: []string{attendee}}
		result, domain, signedLen, canonical := c.verifyDKIM() // the real verifier, over the stored bytes
		identity := caldav.ITIPTransportIdentity{
			EnvelopeFrom: envelopeFrom,
			FromHeader:   organizerExt,
			SpfPass:      spfPass,
		}
		if result == DKIMPass {
			identity.DkimDomain = domain
			identity.DkimAligned = isDMARCAligned(domain, extDomain, DMARCRelaxed)
		}
		fenceLen := signedLen
		if fenceDisabled {
			fenceLen = 0
		}
		c.detectAndProcessIMip(ctx, msg, identity, fenceLen, canonical)
		return srv, capture, result, signedLen
	}

	t.Run("mixed-evidence l= attack: B's copy NOT cancelled — DKIM does not cover the processed calendar", func(t *testing.T) {
		seed(t, calA, attackUID)
		seed(t, bCal, attackUID)

		srv, capture, result, signedLen := process(t, attackWire, attackerEnv, false, false)
		if result != DKIMPass || signedLen != attackL {
			t.Fatalf("replayed positive-l= signature must verify for real: result=%s signedLen=%d want l=%d", result, signedLen, attackL)
		}
		// Reach: the attack MUST traverse the S/MIME branch — the CANCEL is
		// authenticated there, and a fixture that never enters it proves
		// nothing about the mixed-evidence bypass.
		if !capture.logged(logSMimeVerified) {
			t.Fatal("attack never reached the S/MIME branch (no S/MIME verification succeeded for the crafted message)")
		}
		// The CRLF-signed content part survives the LF-storing intake in
		// exactly its CRLF→LF form, so the round-8 POSITIONAL anchor (not the
		// base<0 fail-closed path) issues the coverage verdict.
		if !strings.Contains(smtpDataIntake(t, attackWire), lfFrame(attackContentPart)) {
			t.Fatal("test premise: the LF-stored form of the signed content part is not byte-identical inside the stored c.data — the positional coverage check could not anchor it")
		}
		if !capture.logged(logDKIMNotCovering) {
			t.Error("the DKIM-evidence-ineligible content-binding did not fire — the fence never judged the processed calendar uncovered")
		}
		if got := status(t, attackUID, calA); got != "cancelled" {
			t.Errorf("tenant-A copy status = %q, want cancelled — A's own trust grant accepts the S/MIME evidence", got)
		}
		if got := status(t, attackUID, bCal); got != "confirmed" {
			t.Errorf("tenant-B copy status = %q, want confirmed — the DKIM pass does not cover the processed calendar and B never granted A's anchor", got)
		}
		if got := srv.imipRejected.Load(); got != 0 {
			t.Errorf("imipRejected = %d, want 0 — the CANCEL authenticated; B's copy is policy-skipped, not dropped", got)
		}
	})

	t.Run("fully-covered positive l=, no S/MIME: cancelled via DKIM", func(t *testing.T) {
		uid := coveredUID
		seed(t, calA, uid)
		unsigned := "From: Organizer <" + organizerExt + ">\r\n" +
			"To: " + attendee + "\r\n" +
			"Subject: r8 fully covered\r\n" +
			"Content-Type: text/calendar; method=CANCEL; charset=utf-8\r\n\r\n" +
			buildIMipCalendar(caldav.MethodCancel, uid, organizerExt, attendee) + "\r\n"
		_, body := splitHeadersBody([]byte(unsigned))
		l := int64(len(dkimRelaxedBody(body))) // the signature covers the ENTIRE canonical body
		wire := signReplay(t, unsigned, l)

		srv, capture, result, signedLen := process(t, wire, attackerEnv, false, false)
		if result != DKIMPass || signedLen != l {
			t.Fatalf("fully-covering l= signature must verify: result=%s signedLen=%d want l=%d", result, signedLen, l)
		}
		if capture.logged(logSMimeVerified) {
			t.Error("a plain text/calendar message must never enter the S/MIME branch")
		}
		if capture.logged(logDKIMNotCovering) {
			t.Error("a fully-covering l= leaves no uncovered calendar — the content-binding must stay silent")
		}
		if got := status(t, uid, calA); got != "cancelled" {
			t.Errorf("event status = %q, want cancelled — an l= that covers the whole body keeps full DKIM evidence", got)
		}
		if got := srv.imipRejected.Load(); got != 0 {
			t.Errorf("imipRejected = %d, want 0", got)
		}
	})

	t.Run("fence-disabled control — the IDENTICAL partial-l= attack bytes with the fence input suppressed: both copies cancelled", func(t *testing.T) {
		// Round 10 (Astra r17 item 2): the control replays attackWire — the
		// SAME message bytes, the SAME DKIM signature, the SAME S/MIME
		// signature as the attack subtest above — and changes ONLY the fence
		// input: dkimSignedLen=0, the exact value production passes when no
		// l= bound exists (verifyDKIM reports 0), which leaves dkimCoveredEnd
		// at -1. No covered boundary can be judged, the DKIM evidence stays
		// eligible, and rule (b)'s tenant-agnostic OR cancels both copies.
		// The flip on identical bytes is what proves the fence — not fixture
		// luck — defeated the attack. (The old control freshly signed the
		// ENTIRE attack body, i.e. tested a different message.)
		// The reset is scoped to THIS run's OWN calendar copies (D-2): an
		// unscoped `WHERE uid=$1` also flipped every concurrent run's
		// same-UID events on the shared test database.
		if _, err := pool.Exec(ctx,
			`UPDATE calendar_events SET status='confirmed' WHERE uid=$1 AND calendar_id = ANY($2)`,
			attackUID, []int64{calA, bCal}); err != nil {
			t.Fatalf("reset attack event: %v", err)
		}

		srv, capture, result, signedLen := process(t, attackWire, attackerEnv, false, true)
		if result != DKIMPass || signedLen != attackL {
			t.Fatalf("the identical attack signature must still verify: result=%s signedLen=%d want l=%d", result, signedLen, attackL)
		}
		if !capture.logged(logSMimeVerified) {
			t.Fatal("control never reached the S/MIME branch")
		}
		if capture.logged(logDKIMNotCovering) {
			t.Error("with the fence input suppressed there is no covered boundary to judge — the DKIM evidence must stay eligible")
		}
		if got := status(t, attackUID, calA); got != "cancelled" {
			t.Errorf("tenant-A copy status = %q, want cancelled", got)
		}
		if got := status(t, attackUID, bCal); got != "cancelled" {
			t.Errorf("tenant-B copy status = %q, want cancelled — with the fence disabled the identical attack bytes flip to the bypass (round-7 OR)", got)
		}
		if got := srv.imipRejected.Load(); got != 0 {
			t.Errorf("imipRejected = %d, want 0 — the CANCEL authenticated via rule (b)", got)
		}
	})

	t.Run("SPF-only evidence still cancels every copy — the fence does not touch rule (c)", func(t *testing.T) {
		uid := spfUID
		seed(t, calA, uid)
		seed(t, bCal, uid)
		core, preamble, _ := attackCore(t, uid)
		l := int64(len(dkimRelaxedBody([]byte(preamble))))
		wire := signReplay(t, core, l)

		srv, capture, result, signedLen := process(t, wire, organizerExt, true, false) // envelope == organizer + SPF pass
		if result != DKIMPass || signedLen != l {
			t.Fatalf("replayed positive-l= signature must verify: result=%s signedLen=%d want l=%d", result, signedLen, l)
		}
		if !capture.logged(logSMimeVerified) {
			t.Fatal("SPF-only control never reached the S/MIME branch")
		}
		if got := status(t, uid, calA); got != "cancelled" {
			t.Errorf("tenant-A copy status = %q, want cancelled", got)
		}
		if got := status(t, uid, bCal); got != "cancelled" {
			t.Errorf("tenant-B copy status = %q, want cancelled — SPF rule (c) is envelope-only and stays independent of the content fence", got)
		}
		if got := srv.imipRejected.Load(); got != 0 {
			t.Errorf("imipRejected = %d, want 0 — the CANCEL authenticated via rule (c)", got)
		}
	})
}

// TestDetectAndProcessIMip_TrustedCRLFSignedCalendarViaDataIntake — round 10
// (Astra r17 item 3, P2 S/MIME framing residual): a REAL S/MIME sender signs
// the CRLF-canonical content part (RFC 8551 §3.1.1: S/MIME text
// canonicalization is CRLF), but the SMTP DATA intake (net/textproto
// DotReader) stores every CRLF as LF. CMS verification is byte-sensitive, so
// extraction must hand the verifier the RFC 8551 canonical RECONSTRUCTION of
// the stored part (canonicalSignedContent) — the old code verified the LF
// stored bytes and the digest diverged from the CRLF-signed content, making
// iMIP drop every legitimately CRLF-signed calendar despite valid DKIM/SPF.
// This regression drives the full production framing — real DATA intake
// (dot-stuffing + DotReader), the buildTraceMessage-shaped production msg
// copy, the recipient-domain trust pool — and requires BOTH the StatusValid
// verdict and the verified calendar actually processing end to end. The
// direct-CRLF round-trip coverage in smime_inbound_test.go is unchanged.
func TestDetectAndProcessIMip_TrustedCRLFSignedCalendarViaDataIntake(t *testing.T) {
	fx := setupIMipBindingFixture(t)
	pool := fx.pool
	attendee := fx.attendee
	ctx := context.Background()
	const organizer = "organizer@imip.test"
	const uid = "imip-r10-crlf-sign"

	caRoot, caLeaf, caKey := testSMIMECA(t, []string{organizer})
	importDomainAnchor(t, pool, fx.domainID, caRoot)

	// The signed content part is EXACTLY what an RFC-compliant sender signs:
	// CRLF line endings throughout, including the body's trailing CRLF.
	contentPart := "Content-Type: text/calendar; method=REQUEST; charset=utf-8\r\n\r\n" +
		buildIMipCalendar(caldav.MethodRequest, uid, organizer, attendee) + "\r\n"
	sigDER, err := cms.SignDetached([]byte(contentPart), []*x509.Certificate{caLeaf, caRoot}, caKey)
	if err != nil {
		t.Fatalf("cms.SignDetached: %v", err)
	}
	const boundary = "r10-crlf-signed"
	wire := "From: Signer <" + organizer + ">\r\n" +
		"To: " + attendee + "\r\n" +
		"Subject: r10 crlf signed\r\n" +
		buildMultipartSigned(t, contentPart, sigDER, boundary)

	// Real DATA intake. The stored form is the CRLF→LF canonicalization — the
	// signed content part's exact bytes no longer exist in c.data, which is
	// precisely why verifying the stored bytes was wrong.
	stored := smtpDataIntake(t, wire)
	if strings.Contains(stored, contentPart) {
		t.Fatal("test premise: DATA intake must canonicalize the signed CRLF content to LF")
	}
	if !strings.Contains(stored, strings.ReplaceAll(contentPart, "\r\n", "\n")) {
		t.Fatal("test premise: the LF-stored form of the content part must be present in c.data")
	}

	// Production message copy: CRLF trace headers prepended to the stored
	// bytes (buildTraceMessage shape), and the recipient-domain trust pool
	// (the fixture tenant's minted domain).
	msg := "Received: from relay10.test (relay10.test [192.0.2.10]) by mailserver\r\n" +
		"\tvia SMTP; Mon, 10 Aug 2026 10:00:00 +0000\r\n" +
		"Return-Path: <" + organizer + ">\r\n" + stored
	srv := &InboundServer{
		pool:    pool,
		toggles: toggle.NewStatic(map[string]bool{}),
		logger:  testsupport.TestLogger(),
	}
	res := verifyInboundSMIME(ctx, msg, organizer, srv.smimeRootsForDomain(ctx, fx.domainID), nil)
	if res == nil {
		t.Fatal("a legitimately CRLF-signed calendar must grade, got nil verdict")
	}
	if res.Status != smime.StatusValid {
		t.Fatalf("a legitimately CRLF-signed calendar must verify through real DATA intake: status=%q (the RFC 8551 canonical form was not reconstructed)", res.Status)
	}

	// And the verified calendar must actually process: the iMIP REQUEST
	// creates the tentative event on the attendee's default calendar.
	c := &inConnState{srv: srv, data: []byte(stored), from: organizer, to: []string{attendee}}
	identity := caldav.ITIPTransportIdentity{EnvelopeFrom: organizer, FromHeader: organizer}
	c.detectAndProcessIMip(ctx, msg, identity, 0, "")

	var rows int
	var status string
	if err := pool.QueryRow(ctx,
		`SELECT count(*), coalesce(max(status),'') FROM calendar_events WHERE uid = $1`, uid,
	).Scan(&rows, &status); err != nil {
		t.Fatalf("count event rows: %v", err)
	}
	if rows != 1 || status != "tentative" {
		t.Errorf("CRLF-signed verified calendar did not process: %d rows status=%q, want the REQUEST created (1 row, tentative)", rows, status)
	}
	if got := srv.imipRejected.Load(); got != 0 {
		t.Errorf("imipRejected = %d, want 0", got)
	}
}

// TestDetectAndProcessIMip_FullyCoveredOccurrenceCancelThroughData — round 10
// (Astra r17 item 1): the occurrence-exclude path had no end-to-end coverage —
// every prior occurrence test injected DkimAligned (or SPF) into the
// ITIPTransportIdentity struct directly, so nothing pinned the REAL framing: a
// fully-covering positive-l= DKIM signature over a RECURRENCE-ID CANCEL,
// pushed through the real DATA intake and the real verifyDKIM, must
// authenticate via rule (b) and exclude exactly that occurrence while the
// series survives and no message is dropped.
func TestDetectAndProcessIMip_FullyCoveredOccurrenceCancelThroughData(t *testing.T) {
	fx := setupIMipBindingFixture(t)
	pool := fx.pool
	attendee := fx.attendee
	ctx := context.Background()
	const (
		organizer = "organizer@imip.test"
		relay     = "bounces@relay.mailer.test" // legit iMIP relay: envelope differs from the role (rule (b))
	)
	const uid = "imip-r10-occ-cancel"

	// Recurring master on the attendee's default calendar (fx.calID is the
	// fixture mailbox's is_default calendar); the occurrence the CANCEL
	// excludes is the 2026-08-10 10:00 instance of the weekly series.
	if _, err := pool.Exec(ctx,
		`INSERT INTO calendar_events (calendar_id, uid, title, start_at, end_at, rrule, organizer_email, is_meeting, status, etag)
		 VALUES ($3,$1,'Standup',
			 '2026-08-03 10:00:00+00','2026-08-03 10:30:00+00','FREQ=WEEKLY',$2,TRUE,'confirmed','m0')`,
		uid, organizer, fx.calID); err != nil {
		t.Fatalf("seed recurring master: %v", err)
	}
	// accountID resolution: detectAndProcessIMip resolves the recipient
	// mailbox through aliases (production creates the primary alias). The
	// aliases FK cascades on the fixture's mailbox teardown.
	if _, err := pool.Exec(ctx,
		`INSERT INTO aliases (mailbox_id, email, domain_id, is_primary)
		 SELECT $1,$2,$3,TRUE
		 WHERE NOT EXISTS (SELECT 1 FROM aliases WHERE lower(email) = lower($2))`,
		fx.mailboxID, attendee, fx.domainID); err != nil {
		t.Fatalf("seed recipient alias: %v", err)
	}

	// A real DKIM key for d=imip.test, which aligns with the organizer's From
	// header domain — the rule-(b) evidence class.
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signer key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal signer public key: %v", err)
	}
	keyRecord := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
	const selector = "selr10"
	setDNSResolvers(func(domain string) ([]string, error) {
		if domain == selector+"._domainkey.imip.test" {
			return []string{keyRecord}, nil
		}
		return nil, fmt.Errorf("NXDOMAIN")
	}, nil, nil, nil)
	t.Cleanup(ResetDNSResolver)

	// CRLF calendar with RECURRENCE-ID (buildIMipCalendar has no RECURRENCE-ID
	// — this is the occurrence-scoped CANCEL shape).
	cal := "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Test//EN\r\n" +
		"METHOD:CANCEL\r\nBEGIN:VEVENT\r\n" +
		"UID:" + uid + "\r\n" +
		"RECURRENCE-ID:20260810T100000Z\r\n" +
		"DTSTART:20260810T100000Z\r\n" +
		"DTEND:20260810T103000Z\r\n" +
		"ORGANIZER:mailto:" + organizer + "\r\n" +
		"ATTENDEE;PARTSTAT=ACCEPTED:mailto:" + attendee + "\r\n" +
		"END:VEVENT\r\nEND:VCALENDAR"
	unsigned := "From: Organizer <" + organizer + ">\r\n" +
		"To: " + attendee + "\r\n" +
		"Subject: occurrence cancel\r\n" +
		"Content-Type: text/calendar; method=CANCEL; charset=utf-8\r\n\r\n" +
		cal + "\r\n"

	// Fully-covering l=: the signature covers the ENTIRE canonical body, so no
	// covered boundary exists, the round-8 fence stays silent, and the
	// occurrence exclude rides on pure rule-(b) DKIM evidence.
	sig := &DKIMSig{
		Domain:    "imip.test",
		Selector:  selector,
		Algorithm: "rsa-sha256",
		Headers:   []string{"from", "content-type", "subject"},
		Canonical: "relaxed/relaxed",
	}
	_, body := splitHeadersBody([]byte(unsigned))
	l := int64(len(dkimRelaxedBody(body)))
	sig.Length = l // the l= tag the header carries AND the struct the signer hashes must agree
	sig.BodyHash = base64.StdEncoding.EncodeToString(dkimBodyHash(body, sig.Canonical, l))
	digest := sha256.Sum256([]byte(dkimSignedData(unsigned, sig)))
	b, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15: %v", err)
	}
	wire := "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=imip.test; s=" + selector + "; t=0; x=0; " +
		fmt.Sprintf("l=%d", l) +
		"; h=from:content-type:subject; bh=" + sig.BodyHash +
		"; b=" + base64.StdEncoding.EncodeToString(b) + "\r\n" + unsigned

	// Real DATA intake + real verifier over the stored bytes, production msg
	// copy, real DKIM-derived alignment.
	stored := smtpDataIntake(t, wire)
	msg := "Received: from relay10.test (relay10.test [192.0.2.10]) by mailserver\r\n" +
		"\tvia SMTP; Mon, 10 Aug 2026 10:00:00 +0000\r\n" +
		"Return-Path: <" + relay + ">\r\n" + stored
	srv := &InboundServer{
		pool:    pool,
		toggles: toggle.NewStatic(map[string]bool{}),
		logger:  testsupport.TestLogger(),
	}
	c := &inConnState{srv: srv, data: []byte(stored), from: relay, to: []string{attendee}}
	result, domain, signedLen, canonical := c.verifyDKIM()
	if result != DKIMPass || signedLen != l {
		t.Fatalf("fully-covering l= signature must verify for real over the DATA-intake bytes: result=%s signedLen=%d want l=%d", result, signedLen, l)
	}
	identity := caldav.ITIPTransportIdentity{
		EnvelopeFrom: relay,
		FromHeader:   organizer,
		DkimAligned:  isDMARCAligned(domain, "imip.test", DMARCRelaxed),
		DkimDomain:   domain,
	}
	if !identity.DkimAligned {
		t.Fatalf("test premise: d=%s must align with the organizer's From domain", domain)
	}
	c.detectAndProcessIMip(ctx, msg, identity, signedLen, canonical)

	// The series survives; exactly the targeted occurrence is excluded.
	var status string
	if err := pool.QueryRow(ctx,
		`SELECT status FROM calendar_events WHERE uid=$1 AND recurrence_override IS NULL`, uid,
	).Scan(&status); err != nil {
		t.Fatalf("master row missing: %v", err)
	}
	if status != "confirmed" {
		t.Errorf("series status = %q, want confirmed — an occurrence CANCEL must not cancel the whole series", status)
	}
	var hasExdate bool
	if err := pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM calendar_events ce, unnest(ce.exdate) x
		 WHERE ce.uid=$1 AND ce.recurrence_override IS NULL AND x='2026-08-10 10:00:00+00'::timestamptz)`, uid,
	).Scan(&hasExdate); err != nil {
		t.Fatalf("check exdate: %v", err)
	}
	if !hasExdate {
		t.Error("expected the fully-covered occurrence CANCEL to exclude the 2026-08-10 10:00 instance via exdate")
	}
	if got := srv.imipRejected.Load(); got != 0 {
		t.Errorf("imipRejected = %d, want 0 — rule (b) authenticates the relayed organizer occurrence CANCEL", got)
	}
}
