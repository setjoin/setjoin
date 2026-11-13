package smtp

import (
	"bufio"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/textproto"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/caldav"
	"setjoin.com/shared/testsupport"
	"setjoin.com/shared/toggle"
)

// Round 6 (Astra HOLD, D-MAILSERVER-INTERNAL-CALDAV-003 reopened): the DKIM l=
// fence must be computed AND applied through the REAL SMTP DATA framing. The
// round-5 tests simulated the net/textproto DotReader intake with
// strings.ReplaceAll(raw, "\r\n", "\n"); these tests push the dot-stuffed wire
// form through the ACTUAL textproto dot reader (the exact transformation
// handleData applies) and drive verifyDKIM + detectAndProcessIMip end-to-end:
// a CRLF-heavy signed body with appended content beyond l= must truncate so
// only the SIGNED calendar reaches ParseITIP, and the fence must key off the
// raw stored bytes (c.data) — never off the trace-enriched/ARC-framed msg copy
// that production also carries.

// smtpDataIntake applies the REAL DATA framing: dot-stuffing followed by the
// net/textproto dot reader, exactly what a sending MTA and handleData do.
func smtpDataIntake(t *testing.T, wire string) string {
	t.Helper()
	var stuffed strings.Builder
	for i := 0; i < len(wire); i++ {
		ch := wire[i]
		switch {
		case ch == '\r':
			if i+1 < len(wire) && wire[i+1] == '\n' {
				i++
			}
			stuffed.WriteString("\r\n")
			if i+1 < len(wire) && wire[i+1] == '.' {
				stuffed.WriteByte('.')
			}
		case ch == '\n':
			stuffed.WriteString("\r\n")
			if i+1 < len(wire) && wire[i+1] == '.' {
				stuffed.WriteByte('.')
			}
		default:
			if i == 0 && ch == '.' {
				stuffed.WriteByte('.')
			}
			stuffed.WriteByte(ch)
		}
	}
	stuffed.WriteString("\r\n.\r\n") // DATA terminator

	tp := textproto.NewReader(bufio.NewReader(strings.NewReader(stuffed.String())))
	out, err := tp.ReadDotBytes()
	if err != nil {
		t.Fatalf("real DATA intake (DotReader): %v", err)
	}
	return string(out)
}

// TestDetectAndProcessIMip_DKIMFenceRealDotReaderFraming — end-to-end through
// the real DATA framing: an l=-signed CRLF-heavy REQUEST calendar with an
// appended UNSIGNED CANCEL must process only the signed REQUEST; the appended
// calendar lies beyond the authenticated canonical prefix and must be cut.
func TestDetectAndProcessIMip_DKIMFenceRealDotReaderFraming(t *testing.T) {
	fx := setupIMipBindingFixture(t)
	pool := fx.pool
	attendee := fx.attendee // the fixture tenant's minted recipient address
	ctx := context.Background()
	const (
		organizer = "organizer@imip.test"
		extDomain = "imip.test"
	)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate signer key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	keyRecord := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
	const selector = "selr6"
	setDNSResolvers(func(domain string) ([]string, error) {
		if domain == selector+"._domainkey."+extDomain {
			return []string{keyRecord}, nil
		}
		return nil, fmt.Errorf("NXDOMAIN")
	}, nil, nil, nil)
	t.Cleanup(ResetDNSResolver)

	// signWithLength signs raw so bh covers only the first l CANONICALIZED
	// body bytes (RFC 6376 §3.5) — the attacker/legit-sender oracle.
	signWithLength := func(t *testing.T, raw string, l int64) string {
		t.Helper()
		sig := &DKIMSig{
			Domain:    extDomain,
			Selector:  selector,
			Algorithm: "rsa-sha256",
			Headers:   []string{"from", "content-type"},
			Canonical: "relaxed/relaxed",
			Length:    l,
		}
		_, body := splitHeadersBody([]byte(raw))
		sig.BodyHash = base64.StdEncoding.EncodeToString(dkimBodyHash(body, sig.Canonical, l))
		digest := sha256.Sum256([]byte(dkimSignedData(raw, sig)))
		// RFC 8017 DigestInfo-prefixed signature (crypto.SHA256) — the
		// construction any external RFC 6376 signer/verifier uses.
		b, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatalf("rsa.SignPKCS1v15: %v", err)
		}
		return "DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=" + extDomain + "; s=" + selector + "; t=0; x=0; " +
			fmt.Sprintf("l=%d", l) +
			"; h=from:content-type; bh=" + sig.BodyHash +
			"; b=" + base64.StdEncoding.EncodeToString(b) + "\r\n"
	}

	crlfHeavyCalendar := func(uid string, shortLines bool) string {
		var b strings.Builder
		b.WriteString("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//R6//EN\r\n")
		b.WriteString("METHOD:REQUEST\r\nBEGIN:VEVENT\r\n")
		b.WriteString("UID:" + uid + "\r\n")
		b.WriteString("DTSTART:20260810T100000Z\r\nDTEND:20260810T103000Z\r\n")
		b.WriteString("ORGANIZER:mailto:" + organizer + "\r\n")
		b.WriteString("ATTENDEE;PARTSTAT=ACCEPTED:mailto:" + attendee + "\r\n")
		if shortLines {
			// Astra repro geometry: very short lines so the CRLF→LF intake
			// makes the stored body far shorter than l= (here ~1429 stored
			// bytes against l=1800).
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
		} else {
			for i := 0; i < 300; i++ {
				b.WriteString(fmt.Sprintf("X-PAD-%03d:0123456789\r\n", i))
			}
		}
		b.WriteString("END:VEVENT\r\nEND:VCALENDAR")
		return b.String()
	}

	processFramed := func(t *testing.T, wire, uid string, identity caldav.ITIPTransportIdentity) (DKIMResult, int64) {
		t.Helper()
		stored := smtpDataIntake(t, wire) // the real DATA intake canonicalization
		srv := &InboundServer{
			pool:    pool,
			toggles: toggle.NewStatic(map[string]bool{}),
			logger:  testsupport.TestLogger(),
		}
		// msg carries the production trace header block AND ARC-style CRLF
		// headers prepended ahead of the stored message, so msg != c.data —
		// the fence must be computed from c.data (what VerifyDKIM hashed).
		msg := "Received: from relay.test (relay.test [192.0.2.9]) by mailserver\r\n" +
			"\tvia SMTP; Mon, 10 Aug 2026 10:00:00 +0000\r\n" +
			"ARC-Seal: i=1; a=rsa-sha256; d=relay.test; s=arc; cv=none; b=AAAA\r\n" +
			"ARC-Message-Signature: i=1; a=rsa-sha256; d=relay.test; s=arc; bh=AAAA; b=AAAA\r\n" +
			stored
		c := &inConnState{srv: srv, data: []byte(stored), from: organizer, to: []string{attendee}}
		result, domain, signedLen, canonical := c.verifyDKIM()
		if result == DKIMPass {
			identity.DkimDomain = domain
			identity.DkimAligned = isDMARCAligned(domain, extDomain, DMARCRelaxed)
		}
		c.detectAndProcessIMip(ctx, msg, identity, signedLen, canonical)
		return result, signedLen
	}

	t.Run("CRLF-heavy body, appended CANCEL beyond l=: only the SIGNED REQUEST survives", func(t *testing.T) {
		const uid = "imip-r6-framing-cancel"
		signed := crlfHeavyCalendar(uid, false)
		appended := "\r\n" + strings.ReplaceAll(buildIMipCalendar(caldav.MethodCancel, uid, organizer, attendee), "\n", "\r\n")
		unsigned := "From: Organizer <" + organizer + ">\r\n" +
			"To: " + attendee + "\r\nSubject: r6 framing\r\n" +
			"Content-Type: text/calendar; method=REQUEST; charset=utf-8\r\n\r\n" +
			signed + appended
		l := int64(len(dkimRelaxedBody([]byte(signed))))
		wire := signWithLength(t, unsigned, l) + unsigned

		result, signedLen := processFramed(t, wire, uid, caldav.ITIPTransportIdentity{
			EnvelopeFrom: organizer, FromHeader: organizer,
		})
		if result != DKIMPass || signedLen != l {
			t.Fatalf("l=-carrying signature must verify over the real-framing bytes: result=%s signedLen=%d want l=%d", result, signedLen, l)
		}

		var rows int
		var status string
		if err := pool.QueryRow(ctx,
			`SELECT count(*), coalesce(max(status),'') FROM calendar_events WHERE uid = $1`, uid,
		).Scan(&rows, &status); err != nil {
			t.Fatalf("count event rows: %v", err)
		}
		if rows != 1 || status != "tentative" {
			t.Errorf("real-framing fence failed: %d rows status=%q, want exactly the SIGNED REQUEST (1 row, tentative)", rows, status)
		}
	})

	t.Run("Astra geometry (l=1800, ~1429-byte stored body): appended CANCEL truncated", func(t *testing.T) {
		const uid = "imip-r6-framing-astra"
		signed := crlfHeavyCalendar(uid, true)
		appended := "\n" + strings.ReplaceAll(buildIMipCalendar(caldav.MethodCancel, uid, organizer, attendee), "\r\n", "\n")
		unsigned := "From: Organizer <" + organizer + ">\r\n" +
			"To: " + attendee + "\r\nSubject: r6 astra geometry\r\n" +
			"Content-Type: text/calendar; method=REQUEST; charset=utf-8\r\n\r\n" +
			signed + appended
		l := int64(len(dkimRelaxedBody([]byte(signed))))
		if l < 1500 || l > 2100 {
			t.Fatalf("test premise: expected the short-line geometry to land l near 1800, got %d", l)
		}
		wire := signWithLength(t, unsigned, l) + unsigned

		processFramed(t, wire, uid, caldav.ITIPTransportIdentity{
			EnvelopeFrom: organizer, FromHeader: organizer,
		})

		var rows int
		var status string
		if err := pool.QueryRow(ctx,
			`SELECT count(*), coalesce(max(status),'') FROM calendar_events WHERE uid = $1`, uid,
		).Scan(&rows, &status); err != nil {
			t.Fatalf("count event rows: %v", err)
		}
		if rows != 1 || status != "tentative" {
			t.Errorf("Astra-geometry fence failed: %d rows status=%q, want exactly the SIGNED REQUEST (1 row, tentative)", rows, status)
		}
	})

	t.Run("fence keys off c.data, not the trace/ARC-framed msg copy", func(t *testing.T) {
		const uid = "imip-r6-framing-msgcopy"
		// A real multipart body: the SIGNED first part is a REQUEST calendar,
		// the appended second part an UNSIGNED CANCEL. The l= window covers
		// only the first part; the fence must remove the second part based on
		// the mapping over c.data even though msg carries extra prepended
		// headers with their own CRLF framing (the production divergence the
		// round-6 rework pins down).
		const boundary = "nextr6"
		firstPart := "--" + boundary + "\r\n" +
			"Content-Type: text/calendar; method=REQUEST; charset=utf-8\r\n\r\n" +
			crlfHeavyCalendar(uid, false) + "\r\n"
		secondPart := "--" + boundary + "\r\n" +
			"Content-Type: text/calendar; method=CANCEL; charset=utf-8\r\n\r\n" +
			buildIMipCalendar(caldav.MethodCancel, uid, organizer, attendee) + "\r\n" +
			"--" + boundary + "--\r\n"
		unsigned := "From: Organizer <" + organizer + ">\r\n" +
			"To: " + attendee + "\r\nSubject: r6 msg copy\r\n" +
			"Content-Type: multipart/mixed; boundary=" + boundary + "\r\n\r\n" +
			firstPart + secondPart
		l := int64(len(dkimRelaxedBody([]byte(firstPart))))
		wire := signWithLength(t, unsigned, l) + unsigned

		processFramed(t, wire, uid, caldav.ITIPTransportIdentity{
			EnvelopeFrom: organizer, FromHeader: organizer,
		})

		var rows int
		if err := pool.QueryRow(ctx,
			`SELECT count(*) FROM calendar_events WHERE uid = $1`, uid,
		).Scan(&rows); err != nil {
			t.Fatalf("count event rows: %v", err)
		}
		if rows != 1 {
			t.Errorf("fence over c.data failed: %d rows, want exactly the SIGNED REQUEST (1 row)", rows)
		}
	})
}
