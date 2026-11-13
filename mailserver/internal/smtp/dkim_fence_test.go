package smtp

import (
	"bytes"
	"testing"
)

// TestDKIMSignedBodyCut pins the round-5 fence mapping (Astra HOLD): l= is
// counted in the CANONICALIZED body space (RFC 6376 §3.5) while stored bodies
// are the CRLF→LF intake canonicalization, so the cut that guarantees "content
// processed == content signed" must be computed through the same
// canonicalization the bh= hash was verified with.
//
// The table asserts two properties for every case, brute-force over all byte
// offsets (the bodies are tiny):
//  1. safety — the canonicalized retained prefix fits within the limit;
//  2. maximality — no larger offset still fits (the cut is exact-or-stricter,
//     never looser).
func TestDKIMSignedBodyCut(t *testing.T) {
	const crlfHeavy = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nMETHOD:REQUEST\r\n" +
		"X-PAD:0123456789\r\nX-PAD:0123456789\r\nX-PAD:0123456789\r\n" +
		"END:VCALENDAR"
	// The exact bytes the DATA intake stores: CRLF collapsed to LF.
	const crlfHeavyStored = "BEGIN:VCALENDAR\nVERSION:2.0\nMETHOD:REQUEST\n" +
		"X-PAD:0123456789\nX-PAD:0123456789\nX-PAD:0123456789\n" +
		"END:VCALENDAR"
	const simpleText = "first line\nsecond line  \n\ttabbed\tline\n\n\nlast"

	tests := []struct {
		name      string
		body      string
		canonical string
	}{
		{name: "crlf-heavy relaxed (Astra repro shape)", body: crlfHeavyStored, canonical: "relaxed/relaxed"},
		{name: "crlf-heavy simple", body: crlfHeavyStored, canonical: "simple/simple"},
		{name: "whitespace-heavy relaxed", body: simpleText, canonical: "relaxed/relaxed"},
		{name: "whitespace-heavy simple", body: simpleText, canonical: "simple/simple"},
		{name: "empty body", body: "", canonical: "relaxed/relaxed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := []byte(tc.body)
			fullLen := int64(len(dkimCanonicalBody(body, tc.canonical)))

			for limit := int64(0); limit <= fullLen+4; limit++ {
				cut := dkimSignedBodyCut(body, tc.canonical, limit)

				// Everything signed ⇒ no cut.
				if limit >= fullLen && cut != int64(len(body)) {
					t.Fatalf("limit %d covers the full canonical body (%d bytes): cut = %d, want %d (no cut)",
						limit, fullLen, cut, len(body))
				}
				// 1. safety: the retained prefix canonicalizes within the limit,
				// tolerating only the canonicalization's own two trailing-CRLF
				// normalization bytes (body[:0] canonicalizes to exactly those).
				if kept := int64(len(dkimCanonicalBody(body[:cut], tc.canonical))); kept > limit+2 {
					t.Fatalf("limit %d: cut %d retains %d canonical bytes — unsigned content survives the fence",
						limit, cut, kept)
				}
				// 2. maximality: no larger offset fits (exact-or-stricter).
				for o := int(cut) + 1; o <= len(body); o++ {
					if kept := int64(len(dkimCanonicalBody(body[:o], tc.canonical))); kept <= limit {
						t.Fatalf("limit %d: cut %d is not maximal — offset %d also fits (%d canonical bytes)",
							limit, cut, o, kept)
					}
				}
			}
		})
	}
}

// TestDKIMSignedBodyCut_CanonicalDivergence demonstrates the round-5 bypass
// arithmetic directly: for a CRLF-heavy body the canonical (l=) space is far
// larger than the stored (LF) space, so the OLD stored-space fence
// (`len(body) > l`) would never fire even though large unsigned tails exist.
func TestDKIMSignedBodyCut_CanonicalDivergence(t *testing.T) {
	var signed bytes.Buffer
	signed.WriteString("BEGIN:VCALENDAR\r\nVERSION:2.0\r\n")
	for i := 0; i < 200; i++ {
		signed.WriteString("X-PAD-0123456789:0123456789\r\n")
	}
	signed.WriteString("END:VCALENDAR")
	stored := bytes.ReplaceAll(signed.Bytes(), []byte("\r\n"), []byte("\n"))

	l := int64(len(dkimRelaxedBody(signed.Bytes()))) // what the attacker puts in l=
	if int64(len(stored)) >= l {
		t.Fatalf("test premise: stored body (%d) must be shorter than the canonical l= (%d)", len(stored), l)
	}
	// The attacker appends a complete CANCEL calendar (~46 bytes); the old
	// fence condition len(body) > l still fails after the append.
	appended := []byte("\nBEGIN:VCALENDAR\nMETHOD:CANCEL\nEND:VCALENDAR")
	if int64(len(stored)+len(appended)) > l {
		t.Fatalf("test premise: appended body must still fit below l= (%d)", l)
	}

	// The canonical-space cut lands at the signed boundary; the appended CANCEL
	// content lies beyond it. (The cut may retain the append's leading bare
	// line break — a canonicalization boundary artifact that carries no line
	// content and sits within the signed canonical prefix — but no unsigned
	// content may survive.)
	body := append(append([]byte{}, stored...), appended...)
	cut := dkimSignedBodyCut(body, "relaxed/relaxed", l)
	if kept := int64(len(dkimCanonicalBody(body[:cut], "relaxed/relaxed"))); kept > l {
		t.Fatalf("cut %d retains %d canonical bytes > l=%d", cut, kept, l)
	}
	if bytes.Contains(body[:cut], []byte("METHOD:CANCEL")) {
		t.Fatalf("cut %d retained appended unsigned CANCEL content", cut)
	}
}
