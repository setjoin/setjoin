package linkprotect

// med-shard2-003 (link protection userinfo/host confusion) implementation
// tests: the MIME-aware rewrite/unwrap contract for
// D-MAILSERVER-INTERNAL-LINKPROTECT-002 (unanchored idempotence-guard bypass),
// -003 (UnwrapMessageBody raw-byte splicing / egress rematerialization),
// -004 (base64/quoted-printable parts escaping rewrite+unwrap entirely), and
// -005 (a[href]-only attribute coverage), plus the reconciliation of the
// duplicated RewriteMessageBody with the canonical live smtp seam (fail-closed
// Content-Type handling, absent-Content-Type text/plain default, shared
// mimeutil walker).
//
// Userinfo/host-confusion consumer cases (the package's control family,
// building on the SHIPped LINKPROTECT-001 authority-parser seams) are pinned
// at the message-body level in TestRewriteMessageBody_UserinfoHostConfusion_*.

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime/quotedprintable"
	"strings"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/mimeutil"
)

// msgWith appends top-level headers and a blank line in front of body.
func msgWith(headers string, body string) string {
	if headers != "" {
		headers += "\r\n"
	}
	return "From: sender@external.test\r\nTo: user@local.test\r\nSubject: t\r\n" + headers + "\r\n" + body
}

// multipartMsg builds a multipart/mixed message from raw part strings (each
// part already includes its headers, blank line, and trailing CRLF framing).
func multipartMsg(boundary string, parts ...string) string {
	var b strings.Builder
	b.WriteString("From: sender@external.test\r\nTo: user@local.test\r\nSubject: t\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=\"" + boundary + "\"\r\n\r\n")
	b.WriteString("preamble\r\n")
	for _, p := range parts {
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString(p)
	}
	b.WriteString("--" + boundary + "--\r\n")
	return b.String()
}

// decodedLeafParts walks msg with the shared strict walker and returns each
// leaf part's Content-Type and transfer-decoded body.
func decodedLeafParts(t *testing.T, msg []byte) []struct {
	ct      string
	decoded string
} {
	t.Helper()
	top, err := topLevelBody(msg)
	if err != nil {
		t.Fatalf("topLevelBody: %v", err)
	}
	ct := topLevelContentType(msg)
	var out []struct {
		ct      string
		decoded string
	}
	_, err = mimeutil.WalkMIMEParts(ct, top, func(partHeaders, partBody []byte) []byte {
		partCT := strings.ToLower(mimeutil.ExtractHeader(string(partHeaders), "Content-Type"))
		decoded, _, derr := decodeCTE(mimeutil.ExtractHeader(string(partHeaders), "Content-Transfer-Encoding"), partBody)
		if derr != nil {
			t.Fatalf("decode part: %v", derr)
		}
		out = append(out, struct {
			ct      string
			decoded string
		}{partCT, string(decoded)})
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	return out
}

// topLevelBody splits the body off a full RFC 5322 message.
func topLevelBody(msg []byte) ([]byte, error) {
	idx := bytes.Index(msg, []byte("\r\n\r\n"))
	if idx < 0 {
		return nil, io.ErrUnexpectedEOF
	}
	return msg[idx+4:], nil
}

// topLevelContentType reads the top-level Content-Type header.
func topLevelContentType(msg []byte) string {
	idx := bytes.Index(msg, []byte("\r\n\r\n"))
	if idx < 0 {
		return ""
	}
	return mimeutil.ExtractHeader(string(msg[:idx]), "Content-Type")
}

// decodedQP is a quotedprintable decode helper for assertions.
func decodedQP(t *testing.T, s string) string {
	t.Helper()
	b, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(s)))
	if err != nil {
		t.Fatalf("qp decode: %v", err)
	}
	return string(b)
}

// decodedB64 is a whitespace-tolerant base64 decode helper for assertions.
func decodedB64(t *testing.T, s string) string {
	t.Helper()
	b, _, err := decodeCTE("base64", []byte(s))
	if err != nil {
		t.Fatalf("b64 decode: %v", err)
	}
	return string(b)
}

// --- D-MAILSERVER-INTERNAL-LINKPROTECT-002: anchored, token-aware
// idempotence guard — a sender-embedded "/link-protect?token=" substring must
// not bypass rewriting, scanning, interstitial, or click audit.

func TestRewriteMessageBody_SenderEmbeddedMarkerDoesNotBypass(t *testing.T) {
	body := msgWith("Content-Type: text/html\r\n",
		`<html><body>`+
			`<a href="https://evil.test/safe/link-protect?token=junk">path-suffix</a>`+
			`<a href="https://evil.test/?next=/link-protect?token=junk">query-param</a>`+
			`<a href="//evil.test/link-protect?token=junk">protocol-relative</a>`+
			`<img src="https://evil.test/link-protect?token=junk.png">`+
			`</body></html>`)
	rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
	if count != 4 {
		t.Fatalf("every sender-embedded-marker URL must be rewritten; got count=%d", count)
	}
	if strings.Contains(string(rewritten), "evil.test") {
		t.Errorf("an attacker URL carrying the /link-protect?token= marker survived unrewritten: %s", rewritten)
	}
}

// TestRewriteMessageBody_IdempotentSecondPass pins the guard's real purpose:
// an already-rewritten message re-enters the pipeline unchanged (no double
// rewrite, byte-identical output).
func TestRewriteMessageBody_IdempotentSecondPass(t *testing.T) {
	body := msgWith("Content-Type: text/html\r\n",
		`<html><body><a href="https://evil.test/a">a</a><img src="https://evil.test/p.gif"></body></html>`)
	first, n1, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
	if err != nil || n1 != 2 {
		t.Fatalf("first pass: n=%d err=%v", n1, err)
	}
	second, n2, err := RewriteMessageBody(first, testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if n2 != 0 {
		t.Fatalf("second pass must rewrite nothing, got %d", n2)
	}
	if !bytes.Equal(first, second) {
		t.Error("second pass must be byte-identical")
	}
}

// TestRewriteURL_HostRelativeLookalikeIsInert documents the residual shape the
// anchored guard still exempts: a HOST-RELATIVE /link-protect?token=... URL.
// A sender can craft one, but it resolves against THIS server's /link-protect
// endpoint and fails token verification there — no attacker destination is
// reachable through it, so exempting it from rewriting is fail-safe.
func TestRewriteURL_HostRelativeLookalikeIsInert(t *testing.T) {
	if _, ok := rewriteURL("/link-protect?token=AAA.BBB", TokenKeys{Secret: testSecret}, nil, "m", 1); ok {
		t.Error("host-relative /link-protect?token=... is the emitted shape and must stay exempt")
	}
	for _, s := range []string{
		"/other/link-protect?token=AAA.BBB", // path must be exact
		"/link-protect?token=",              // token parameter required
		"/link-protect",                     // token parameter required
		"//evil.test/link-protect?token=AAA.BBB",
	} {
		if isOwnRedirect(s) {
			t.Errorf("isOwnRedirect(%q) = true, want false", s)
		}
	}
}

// --- D-MAILSERVER-INTERNAL-LINKPROTECT-005: all URL-bearing attributes.

func TestRewriteMessageBody_AttributeCoverage(t *testing.T) {
	body := msgWith("Content-Type: text/html\r\n",
		`<html><body>`+
			`<img src="https://evil.test/px.gif">`+
			`<img lowsrc="https://evil.test/low.gif">`+
			`<iframe src="https://evil.test/frame"></iframe>`+
			`<form action="https://evil.test/collect"><button formaction="https://evil.test/b2">go</button></form>`+
			`<video poster="https://evil.test/poster.jpg"></video>`+
			`<blockquote cite="https://evil.test/src">q</blockquote>`+
			`<object data="https://evil.test/obj"></object>`+
			`<table><tr><td background="https://evil.test/tdbg.png">c</td></tr></table>`+
			`<img srcset="https://evil.test/1x.png 1x, /local.png 2x">`+
			`<div style="background: url(https://evil.test/cssbg.png)">x</div>`+
			`<style>body { background: url("https://evil.test/cssbg2.png") } @import "https://evil.test/x.css";</style>`+
			`</body></html>`)
	rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
	// src + lowsrc + iframe src + action + formaction + poster + cite + data +
	// td background + 1 srcset candidate + style url() + style url() + @import.
	if count != 13 {
		t.Fatalf("expected 13 rewritten URL-bearing attribute targets, got %d", count)
	}
	if strings.Contains(string(rewritten), "evil.test") {
		t.Errorf("an img/iframe/form/CSS URL survived unrewritten (tracking-pixel exfiltration channel): %s", rewritten)
	}
	// The non-absolute srcset candidate and relative/mailto/fragment values
	// must be untouched.
	for _, keep := range []string{"/local.png 2x"} {
		if !strings.Contains(string(rewritten), keep) {
			t.Errorf("value %q must stay untouched", keep)
		}
	}
}

func TestRewriteMessageBody_NonAbsoluteAttributeValuesUntouched(t *testing.T) {
	body := msgWith("Content-Type: text/html\r\n",
		`<html><body><img src="/img.png"><a href="mailto:a@b.test">m</a><a href="#f">f</a><form action="/post"></form></body></html>`)
	_, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
	if count != 0 {
		t.Fatalf("relative/mailto/fragment values must not be rewritten, got %d", count)
	}
}

// --- D-MAILSERVER-INTERNAL-LINKPROTECT-004: transfer-decoded bodies.

func TestRewriteMessageBody_Base64PartsAreDecodedRewrittenReencoded(t *testing.T) {
	b64Body := base64.StdEncoding.EncodeToString([]byte("Visit https://evil.test/pixel now\r\n"))
	msg := multipartMsg("BB",
		"Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n"+b64Body+"\r\n")
	rewritten, count, err := RewriteMessageBody([]byte(msg), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("base64-encoded URL must be rewritten, got count=%d", count)
	}
	parts := decodedLeafParts(t, rewritten)
	if len(parts) != 1 {
		t.Fatalf("expected 1 leaf part, got %d", len(parts))
	}
	if strings.Contains(parts[0].decoded, "https://evil.test/pixel") {
		t.Errorf("base64 part still carries the raw URL after decode: %q", parts[0].decoded)
	}
	if !strings.Contains(parts[0].decoded, "/link-protect?token=") {
		t.Errorf("base64 part decoded content missing the redirect: %q", parts[0].decoded)
	}
	// Re-encoded output must respect the RFC 2045 76-column limit.
	for _, line := range strings.Split(topLevelBodyAsString(t, rewritten), "\r\n") {
		if len(line) > 76 {
			t.Errorf("base64 re-encode exceeded 76 columns: %q", line)
		}
	}
	// Idempotence through the decode/re-encode seam: a second pass must
	// recognize its own redirects and leave the message byte-identical.
	second, count2, err := RewriteMessageBody(rewritten, testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if count2 != 0 {
		t.Fatalf("second pass must rewrite nothing, got %d", count2)
	}
	if !bytes.Equal(rewritten, second) {
		t.Error("second pass must be byte-identical")
	}
}

func TestRewriteMessageBody_QuotedPrintableSoftBreakURLIsRewritten(t *testing.T) {
	// The soft line break splits the URL in the RAW bytes: raw-byte scanners
	// see "https://evil.=" and the URL escapes; decode-before-scan must see it.
	qpBody := "Visit https://evil.=\r\ntest/pixel?id=1 for info"
	msg := multipartMsg("BB",
		"Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"+qpBody+"\r\n")
	rewritten, count, err := RewriteMessageBody([]byte(msg), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("QP soft-break-split URL must be rewritten, got count=%d", count)
	}
	parts := decodedLeafParts(t, rewritten)
	if len(parts) != 1 {
		t.Fatalf("expected 1 leaf part, got %d", len(parts))
	}
	if strings.Contains(parts[0].decoded, "evil.test") {
		t.Errorf("QP part still carries the raw URL after decode: %q", parts[0].decoded)
	}
	if !strings.Contains(parts[0].decoded, "/link-protect?token=") {
		t.Errorf("QP part decoded content missing the redirect: %q", parts[0].decoded)
	}
	for _, line := range strings.Split(topLevelBodyAsString(t, rewritten), "\r\n") {
		if len(line) > 76 {
			t.Errorf("QP re-encode exceeded 76 columns: %q", line)
		}
	}
}

func topLevelBodyAsString(t *testing.T, msg []byte) string {
	t.Helper()
	b, err := topLevelBody(msg)
	if err != nil {
		t.Fatalf("topLevelBody: %v", err)
	}
	return string(b)
}

func TestRewriteMessageBody_SinglePartBase64HTMLRewritten(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte(`<html><a href="https://evil.test/a">x</a></html>`))
	body := msgWith("Content-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n", enc+"\r\n")
	rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("single-part base64 HTML URL must be rewritten, got count=%d", count)
	}
	idx := bytes.Index(rewritten, []byte("\r\n\r\n"))
	decoded := decodedB64(t, string(rewritten[idx+4:]))
	if !strings.Contains(decoded, "/link-protect?token=") || strings.Contains(decoded, "https://evil.test/a") {
		t.Errorf("decoded rewritten body wrong: %q", decoded)
	}
}

func TestRewriteMessageBody_UnknownCTEFailsClosed(t *testing.T) {
	msg := multipartMsg("BB",
		"Content-Type: text/plain\r\nContent-Transfer-Encoding: x-uuencode\r\n\r\nbegin 644 x\r\n"+`https://evil.test/pixel`+"\r\nend\r\n")
	if _, _, err := RewriteMessageBody([]byte(msg), testSecret, nil, "msg-1", 1); err == nil {
		t.Fatal("an undecodable Content-Transfer-Encoding must fail closed, got nil error")
	}
}

func TestRewriteMessageBody_CorruptBase64FailsClosed(t *testing.T) {
	msg := multipartMsg("BB",
		"Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n!!!not-base64!!!\r\n")
	if _, _, err := RewriteMessageBody([]byte(msg), testSecret, nil, "msg-1", 1); err == nil {
		t.Fatal("corrupt base64 must fail closed, got nil error")
	}
}

// --- Absent-Content-Type default (RFC 2045 §5.2), aligned with the live seam.

func TestRewriteMessageBody_AbsentContentTypeDefaultsToPlainText(t *testing.T) {
	body := "From: sender@external.test\r\nTo: user@local.test\r\nSubject: t\r\n\r\nVisit https://evil.test/x now"
	rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("header-less body must take the text/plain default and be rewritten, got count=%d", count)
	}
	if !strings.Contains(string(rewritten), "/link-protect?token=") {
		t.Error("expected redirect in rewritten header-less body")
	}
}

func TestRewriteMessageBody_PartWithoutContentTypeDefaultsToPlainText(t *testing.T) {
	msg := multipartMsg("BB",
		"\r\nVisit https://evil.test/x\r\n") // no headers at all on this part
	rewritten, count, err := RewriteMessageBody([]byte(msg), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("a part with no Content-Type must default to text/plain per RFC 2045 §5.2, got count=%d", count)
	}
	if !strings.Contains(string(rewritten), "/link-protect?token=") {
		t.Error("expected redirect in rewritten part")
	}
}

// --- Duplicate reconciliation: the shared copy now carries the canonical
// fail-closed seam semantics (unparseable PRESENT Content-Type errors).

func TestRewriteMessageBody_PresentMalformedContentTypeFailsClosed(t *testing.T) {
	body := "From: sender@external.test\r\nTo: user@local.test\r\nSubject: t\r\nContent-Type: multipart/mixed\r\n\r\n--nope\r\nhttps://evil.test/x\r\n"
	if _, _, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1); err == nil {
		t.Fatal("unparseable multipart Content-Type (no boundary) must fail closed, got nil error")
	}
}

// --- Userinfo/host-confusion consumer cases (message-body level).

func TestRewriteMessageBody_UserinfoHostConfusionCases(t *testing.T) {
	t.Run("backslash-at-parses-invalid-fails-closed-to-rewrite", func(t *testing.T) {
		// net/url rejects the raw backslash userinfo (invalid userinfo), so the
		// SHIPped fail-closed contract classifies it NOT internal: it is
		// rewritten through the interstitial (and click-scanned) instead of
		// being trusted as the decoy's sibling host.
		body := msgWith("Content-Type: text/html\r\n", `<html><a href="https://evil.test\@good.test/x">c</a></html>`)
		rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, []string{"good.test"}, "msg-1", 1)
		if err != nil {
			t.Fatalf("RewriteMessageBody failed: %v", err)
		}
		if count != 1 {
			t.Fatalf("backslash-at URL must be rewritten (fail closed), got count=%d", count)
		}
		if strings.Contains(string(rewritten), "good.test") {
			t.Error("rewritten output must not retain the lookalike URL unrewritten")
		}
	})

	t.Run("percent-encoded-backslash-host-is-authority", func(t *testing.T) {
		// %5C is userinfo-decodable: the net/url authority host is good.test
		// (userinfo "evil.test%5C" is NOT the host), so it is exempt for the
		// good.test domain and never for a domain matching the userinfo decoy.
		url := "https://evil.test%5C@good.test/x"
		body := msgWith("Content-Type: text/html\r\n", `<html><a href="`+url+`">c</a></html>`)

		_, count, err := RewriteMessageBody([]byte(body), testSecret, []string{"good.test"}, "msg-1", 1)
		if err != nil {
			t.Fatalf("RewriteMessageBody failed: %v", err)
		}
		if count != 0 {
			t.Fatalf("true authority host good.test must stay exempt, got count=%d", count)
		}

		_, count, err = RewriteMessageBody([]byte(body), testSecret, []string{"evil.test"}, "msg-1", 1)
		if err != nil {
			t.Fatalf("RewriteMessageBody failed: %v", err)
		}
		if count != 1 {
			t.Fatalf("userinfo decoy evil.test must never exempt, got count=%d", count)
		}
	})

	t.Run("punycode-lookalikes", func(t *testing.T) {
		cases := []struct {
			url       string
			domain    string
			wantCount int
		}{
			{"https://xn--bcher-kva.example/", "xn--bcher-kva.example", 0},           // exact punycode internal
			{"https://xn--bcher-kva.example.evil.test/", "xn--bcher-kva.example", 1}, // suffix lookalike rewritten
			{"https://xn--bcher-kva.example@evil.com/", "xn--bcher-kva.example", 1},  // punycode decoy in userinfo
		}
		for _, tc := range cases {
			body := msgWith("Content-Type: text/html\r\n", `<html><a href="`+tc.url+`">c</a></html>`)
			_, count, err := RewriteMessageBody([]byte(body), testSecret, []string{tc.domain}, "msg-1", 1)
			if err != nil {
				t.Fatalf("RewriteMessageBody(%q) failed: %v", tc.url, err)
			}
			if count != tc.wantCount {
				t.Errorf("url %q domain %q: count=%d, want %d", tc.url, tc.domain, count, tc.wantCount)
			}
		}
	})

	t.Run("destination-round-trips-byte-faithfully", func(t *testing.T) {
		// The unwrapped claims.URL must round-trip byte-faithfully:
		// scheme/host/path/query/fragment unaltered.
		for _, dest := range []string{
			"https://store.example.test/buy?id=7&x=y#frag",
			"https://evil.test%5C@good.test/x",
			"http://internal.domain:8080@evil.com/",
		} {
			body := msgWith("Content-Type: text/plain\r\n", "Go to "+dest+" today")
			rewritten, n, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
			if err != nil || n != 1 {
				t.Fatalf("rewrite %q: n=%d err=%v", dest, n, err)
			}
			unwrapped, m, err := UnwrapMessageBody(rewritten, testSecret)
			if err != nil || m != 1 {
				t.Fatalf("unwrap %q: m=%d err=%v", dest, m, err)
			}
			if !strings.Contains(string(unwrapped), "Go to "+dest+" today") {
				t.Errorf("destination did not round-trip byte-faithfully:\n got %q\nwant substring %q", string(unwrapped), dest)
			}
		}
	})
}

// --- D-MAILSERVER-INTERNAL-LINKPROTECT-003: MIME-aware unwrap with
// per-output-context serialization.

func TestUnwrapMessageBody_FullMIMEMultipartRoundTrip(t *testing.T) {
	plain := "Visit https://store.example.test/buy?id=7&x=y and https://news.example.test/ soon."
	htmlPart := `<html><body>click <a href="https://evil.test/a">here</a> <img src="https://evil.test/pix.gif"></body></html>`
	b64HTML := base64.StdEncoding.EncodeToString([]byte(`<html><a href="https://evil.test/b64">x</a></html>`))
	msg := multipartMsg("BB",
		"Content-Type: text/plain\r\n\r\n"+plain+"\r\n",
		"Content-Type: text/html\r\n\r\n"+htmlPart+"\r\n",
		"Content-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\n"+b64HTML+"\r\n")

	rewritten, n, err := RewriteMessageBody([]byte(msg), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if n != 5 { // 2 plain + href + img src + 1 base64 html href
		t.Fatalf("rewrite count=%d, want 5", n)
	}

	unwrapped, m, err := UnwrapMessageBody(rewritten, testSecret)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if m != 5 {
		t.Fatalf("unwrap count=%d, want 5", m)
	}
	if strings.Contains(string(unwrapped), "/link-protect?token=") {
		t.Errorf("unwrapped message still contains a redirect: %s", unwrapped)
	}
	// Destination semantics preserved, per part context: the plain part
	// round-trips verbatim; each html part carries its destinations back in
	// attribute positions.
	parts := decodedLeafParts(t, unwrapped)
	if len(parts) != 3 {
		t.Fatalf("expected 3 leaf parts after unwrap, got %d", len(parts))
	}
	var plainOK, hrefA, srcPix, hrefB64 bool
	for _, p := range parts {
		switch {
		case strings.Contains(p.ct, "text/plain"):
			plainOK = strings.Contains(p.decoded, plain)
		case strings.Contains(p.ct, "text/html"):
			if strings.Contains(p.decoded, `href="https://evil.test/a"`) {
				hrefA = true
			}
			if strings.Contains(p.decoded, `src="https://evil.test/pix.gif"`) {
				srcPix = true
			}
			if strings.Contains(p.decoded, `href="https://evil.test/b64"`) {
				hrefB64 = true
			}
		}
	}
	if !plainOK {
		t.Error("plain part did not round-trip the original URLs verbatim")
	}
	if !hrefA || !srcPix || !hrefB64 {
		t.Errorf("html parts did not round-trip destinations into attributes: hrefA=%v srcPix=%v hrefB64=%v", hrefA, srcPix, hrefB64)
	}
}

// TestUnwrapMessageBody_HTMLAttrEntityEncodesDestination pins the egress
// serialization: a destination carrying markup (signable — it can only come
// from a parsed attribute value) must be re-emitted entity-encoded by the HTML
// serializer, never rematerialized as live markup before DKIM signing.
func TestUnwrapMessageBody_HTMLAttrEntityEncodesDestination(t *testing.T) {
	dest := `https://evil.test/"><script>alert(1)</script>`
	token := buildToken(dest)
	msg := multipartMsg("BB",
		"Content-Type: text/html\r\n\r\n"+`<html><a href="/link-protect?token=`+token+`">x</a></html>`+"\r\n")
	unwrapped, count, err := UnwrapMessageBody([]byte(msg), testSecret)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if count != 1 {
		t.Fatalf("unwrap count=%d, want 1", count)
	}
	if bytes.Contains(unwrapped, []byte(`"><script>`)) {
		t.Errorf("live markup rematerialized in the outbound message: %s", unwrapped)
	}
	if !bytes.Contains(unwrapped, []byte("&lt;script&gt;")) {
		t.Errorf("destination must be entity-encoded in the attribute context: %s", unwrapped)
	}
}

// TestUnwrapMessageBody_CRLFDestinationNeverSubstituted pins the universal
// control-character refusal: a (pre-fix or foreign-crafted) token whose
// destination carries CRLF is never spliced back — the inert redirect stays.
func TestUnwrapMessageBody_CRLFDestinationNeverSubstituted(t *testing.T) {
	crlfToken := buildToken("https://evil.test/a\r\nBcc: victim@evil.test")
	cleanToken := buildToken("https://clean.example.test/ok")
	msg := msgWith("Content-Type: text/plain\r\n",
		"see /link-protect?token="+crlfToken+" and /link-protect?token="+cleanToken)
	unwrapped, count, err := UnwrapMessageBody([]byte(msg), testSecret)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if count != 1 {
		t.Fatalf("only the clean destination may be substituted, got count=%d", count)
	}
	if !strings.Contains(string(unwrapped), "https://clean.example.test/ok") {
		t.Error("clean destination must unwrap")
	}
	if !strings.Contains(string(unwrapped), "/link-protect?token="+crlfToken) {
		t.Error("the CRLF-bearing redirect must be left in place, never spliced")
	}
	if strings.Contains(string(unwrapped), "Bcc: victim@evil.test") {
		t.Error("CRLF destination rematerialized — MIME/header injection re-armed")
	}
}

func TestUnwrapMessageBody_PlainTextContextIsInertText(t *testing.T) {
	dest := `https://evil.test/"><b>bold`
	token := buildToken(dest) // markup chars are signable; text context renders none of it
	msg := msgWith("Content-Type: text/plain\r\n", "see /link-protect?token="+token)
	unwrapped, count, err := UnwrapMessageBody([]byte(msg), testSecret)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if count != 1 {
		t.Fatalf("unwrap count=%d, want 1", count)
	}
	if !strings.Contains(string(unwrapped), dest) {
		t.Errorf("plain-text context must emit the destination verbatim as inert text: %s", unwrapped)
	}
}

func TestUnwrapMessageBody_ForeignTokenUntouchedInMultipart(t *testing.T) {
	otherSecret := []byte("a-completely-different-secret-key")
	foreign, _ := SignToken(TokenClaims{URL: "https://evil.example/x", ExpiresAt: tokenExpiryTime()}, otherSecret)
	msg := multipartMsg("BB",
		"Content-Type: text/plain\r\n\r\nsee /link-protect?token="+foreign+"\r\n",
		"Content-Type: text/html\r\n\r\n<html><a href=\"/link-protect?token="+foreign+"\">x</a></html>\r\n")
	unwrapped, count, err := UnwrapMessageBody([]byte(msg), testSecret)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if count != 0 {
		t.Fatalf("foreign-secret tokens must not unwrap, got count=%d", count)
	}
	if !bytes.Equal(unwrapped, []byte(msg)) {
		t.Error("message with only foreign tokens must stay byte-identical")
	}
}

func TestUnwrapMessageBody_AmbiguousContentTypeFailsSafe(t *testing.T) {
	token := buildToken("https://evil.test/x")
	msg := msgWith("Content-Type: multipart/mixed\r\n", "body /link-protect?token="+token)
	if _, _, err := UnwrapMessageBody([]byte(msg), testSecret); err == nil {
		t.Fatal("ambiguous multipart framing must error (fail safe), got nil")
	}
}

func TestUnwrapMessageBody_UnknownCTEFailsSafe(t *testing.T) {
	token := buildToken("https://evil.test/x")
	msg := multipartMsg("BB",
		"Content-Type: text/plain\r\nContent-Transfer-Encoding: x-uuencode\r\n\r\n/link-protect?token="+token+"\r\n")
	if _, _, err := UnwrapMessageBody([]byte(msg), testSecret); err == nil {
		t.Fatal("undecodable part encoding must error (fail safe), got nil")
	}
}

func TestUnwrapMessageBody_CalendarAndNonTextPartsUntouched(t *testing.T) {
	token := buildToken("https://evil.test/x")
	msg := multipartMsg("BB",
		"Content-Type: text/calendar; method=REQUEST\r\n\r\nBEGIN:VCALENDAR\r\n/link-protect?token="+token+"\r\nEND:VCALENDAR\r\n",
		"Content-Type: application/pdf\r\n\r\n%PDF-1.4 /link-protect?token="+token+"\r\n")
	unwrapped, count, err := UnwrapMessageBody([]byte(msg), testSecret)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if count != 0 {
		t.Fatalf("calendar and non-text parts must not be unwrapped, got count=%d", count)
	}
	if !bytes.Equal(unwrapped, []byte(msg)) {
		t.Error("untouched parts must stay byte-exact")
	}
}

func TestUnwrapMessageBody_CSSContextsUnwrap(t *testing.T) {
	tokenURL := buildToken("https://clean.example.test/bg.png")
	tokenImport := buildToken("https://clean.example.test/x.css")
	// Style-block destinations were rewritten as url(/link-protect?token=…)
	// and @import "/link-protect?token=…"; the unwrap must restore them as
	// quoted CSS strings in place.
	msg := multipartMsg("BB",
		"Content-Type: text/html\r\n\r\n"+
			`<html><head><style>body { background: url(/link-protect?token=`+tokenURL+`) } @import "/link-protect?token=`+tokenImport+`";</style></head><body></body></html>`+"\r\n")
	unwrapped, count, err := UnwrapMessageBody([]byte(msg), testSecret)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if count != 2 {
		t.Fatalf("unwrap count=%d, want 2", count)
	}
	out := string(unwrapped)
	if !strings.Contains(out, `url("https://clean.example.test/bg.png")`) {
		t.Errorf("CSS url() destination not unwrapped: %s", out)
	}
	if !strings.Contains(out, `@import "https://clean.example.test/x.css"`) {
		t.Errorf("CSS @import destination not unwrapped: %s", out)
	}
	if strings.Contains(out, "/link-protect?token=") {
		t.Errorf("redirects remain in CSS after unwrap: %s", out)
	}
}

func TestUnwrapMessageBody_HTMLFragmentDegenerateParseStillUnwraps(t *testing.T) {
	// A bare HTML fragment is consumed as "headers" by mail.ReadMessage (empty
	// body): the unknown-context fallback must still unwrap verified tokens.
	token := buildToken("https://vendor.example.test/promo")
	body := []byte(`<a href="/link-protect?token=` + token + `">click</a>`)
	unwrapped, count, err := UnwrapMessageBody(body, testSecret)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if count != 1 {
		t.Fatalf("unwrap count=%d, want 1", count)
	}
	if !strings.Contains(string(unwrapped), `href="https://vendor.example.test/promo"`) {
		t.Errorf("fragment not unwrapped: %s", unwrapped)
	}
}

func TestUnwrapMessageBody_MarkupDestinationRefusedInUnknownContext(t *testing.T) {
	dest := `https://evil.test/"><script>`
	token := buildToken(dest)
	body := []byte("/link-protect?token=" + token)
	unwrapped, count, err := UnwrapMessageBody(body, testSecret)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if count != 0 {
		t.Fatalf("unknown context must refuse markup-bearing destinations, got count=%d", count)
	}
	if !bytes.Equal(unwrapped, body) {
		t.Error("refused substitution must leave the body byte-identical")
	}
}

// tokenExpiryTime is a small helper for building test tokens.
func tokenExpiryTime() int64 { return time.Now().Add(tokenExpiry).Unix() }

// --- med-shard2-003 ROUND 2 (Astra HOLD items 1-5) ---
// 1. raw-text serialization contexts (script/iframe children, </style>),
// 2. quoted-printable writer Close (buffered final line),
// 3. unwrap marker fast path after transfer decoding,
// 4. CSS protocol-relative url()/@import coverage,
// 5. WHATWG srcset candidate parsing (comma-in-URL byte-faithfulness).

// TestUnwrapMessageBody_ScriptRawTextClosingTagRetained (item 1): a verified
// destination carrying "</script>" must never be spliced into <script> text —
// html.Render emits script children literally, so the closing tag would split
// the raw-text block and rematerialize live markup. The verified redirect is
// retained (inert) instead.
func TestUnwrapMessageBody_ScriptRawTextClosingTagRetained(t *testing.T) {
	dest := `https://evil.test/x</script><img src=x onerror=alert(1)>`
	token := buildToken(dest)
	msg := multipartMsg("BB",
		"Content-Type: text/html\r\n\r\n"+
			`<html><body><script>var u="/link-protect?token=`+token+`";</script></body></html>`+"\r\n")
	unwrapped, count, err := UnwrapMessageBody([]byte(msg), testSecret)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if count != 0 {
		t.Fatalf("script raw-text context must not substitute, got count=%d", count)
	}
	out := string(unwrapped)
	if !strings.Contains(out, "/link-protect?token="+token) {
		t.Error("the verified redirect must be retained verbatim in the raw-text context")
	}
	if strings.Contains(out, "onerror") {
		t.Errorf("closing-tag destination rematerialized as live markup: %s", out)
	}
}

// TestUnwrapMessageBody_IFrameRawTextClosingTagRetained (item 1): same contract
// for <iframe> raw-text children.
func TestUnwrapMessageBody_IFrameRawTextClosingTagRetained(t *testing.T) {
	dest := `https://evil.test/f"></iframe><img src=x onerror=alert(1)>`
	token := buildToken(dest)
	msg := multipartMsg("BB",
		"Content-Type: text/html\r\n\r\n"+
			`<html><body><iframe>/link-protect?token=`+token+`</iframe></body></html>`+"\r\n")
	unwrapped, count, err := UnwrapMessageBody([]byte(msg), testSecret)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if count != 0 {
		t.Fatalf("iframe raw-text context must not substitute, got count=%d", count)
	}
	out := string(unwrapped)
	if !strings.Contains(out, "/link-protect?token="+token) {
		t.Error("the verified redirect must be retained verbatim in the raw-text context")
	}
	if strings.Contains(out, "onerror") {
		t.Errorf("closing-tag destination rematerialized as live markup: %s", out)
	}
}

// TestUnwrapMessageBody_StyleClosingTagDestinationRetained (item 1, style
// branch): a destination carrying "</style>" cannot be embedded in a quoted
// CSS string inside <style> text (a raw-text literal context) — the redirect
// is retained instead of closing the element on serialization.
func TestUnwrapMessageBody_StyleClosingTagDestinationRetained(t *testing.T) {
	dest := `https://evil.test/a.png</style><img src=x onerror=alert(1)>`
	token := buildToken(dest)
	msg := multipartMsg("BB",
		"Content-Type: text/html\r\n\r\n"+
			`<html><head><style>a{background:url("/link-protect?token=`+token+`")}</style></head><body></body></html>`+"\r\n")
	unwrapped, count, err := UnwrapMessageBody([]byte(msg), testSecret)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if count != 0 {
		t.Fatalf("CSS string unsafe for a raw-text context must not substitute, got count=%d", count)
	}
	out := string(unwrapped)
	if !strings.Contains(out, "/link-protect?token="+token) {
		t.Error("the verified redirect must be retained verbatim in the style context")
	}
	if strings.Contains(out, "onerror") || strings.Count(out, "</style>") != 1 {
		t.Errorf("</style> closed early or markup rematerialized: %s", out)
	}
}

// TestEncodeCTE_QuotedPrintableRoundTripsWithoutTrailingNewline (item 2): the
// quotedprintable writer buffers its final line until Close — every body shape
// must round-trip byte-exactly, including bodies with NO terminal newline.
func TestEncodeCTE_QuotedPrintableRoundTripsWithoutTrailingNewline(t *testing.T) {
	cases := map[string]string{
		"no-terminal-newline":      "see https://evil.test/tail",
		"multi-line-no-tail":       "line one\r\nfinal line no newline",
		"long-line-soft-breaks":    strings.Repeat("x", 200) + " end",
		"trailing-newline-control": "terminated body\r\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			enc, err := encodeCTE("quoted-printable", []byte(body))
			if err != nil {
				t.Fatalf("encodeCTE: %v", err)
			}
			got, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(enc)))
			if err != nil {
				t.Fatalf("qp decode: %v", err)
			}
			if string(got) != body {
				t.Errorf("QP round-trip lost bytes:\n got %q\nwant %q", got, body)
			}
		})
	}
}

// TestRewriteMessageBody_QuotedPrintableTailWithoutTrailingNewline (item 2,
// end-to-end): a single-line QP body without terminal newline used to lose its
// entire (buffered) final line on re-encode — the token vanished from the
// delivered part.
func TestRewriteMessageBody_QuotedPrintableTailWithoutTrailingNewline(t *testing.T) {
	body := msgWith("Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n",
		"see https://evil.test/tail-no-newline")
	rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody: %v", err)
	}
	if count != 1 {
		t.Fatalf("count=%d, want 1", count)
	}
	idx := bytes.Index(rewritten, []byte("\r\n\r\n"))
	decoded := decodedQP(t, string(rewritten[idx+4:]))
	// (msgWith leaves a leading blank line in this fixture's body — assert on
	// the line content, not the byte offset. Pre-fix, the writer's buffered
	// final line was dropped entirely, so this substring was absent.)
	if !strings.Contains(decoded, "see /link-protect?token=") {
		t.Fatalf("re-encoded QP part lost its buffered tail: %q", decoded)
	}
	// The full token must survive (untruncated), and the destination must
	// round-trip byte-faithfully through unwrap.
	unwrapped, m, err := UnwrapMessageBody(rewritten, testSecret)
	if err != nil || m != 1 {
		t.Fatalf("unwrap: m=%d err=%v", m, err)
	}
	if !strings.Contains(string(unwrapped), "see https://evil.test/tail-no-newline") {
		t.Errorf("destination did not round-trip: %q", string(unwrapped))
	}
}

// TestUnwrapMessageBody_Base64EncodedMarkerStillUnwraps (item 3): base64 hides
// the raw "/link-protect?token=" marker, so the old raw-bytes fast path
// returned before the part was ever decoded, leaving recipient-bound redirects
// intact on forward.
func TestUnwrapMessageBody_Base64EncodedMarkerStillUnwraps(t *testing.T) {
	token := buildToken("https://vendor.example.test/b64-only")
	inner := "see /link-protect?token=" + token + " now"
	enc := base64.StdEncoding.EncodeToString([]byte(inner))
	msg := multipartMsg("BB",
		"Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n"+enc+"\r\n")
	if strings.Contains(msg, protectedMarker) {
		t.Fatal("fixture precondition: the base64 encoding must hide the raw marker")
	}
	unwrapped, count, err := UnwrapMessageBody([]byte(msg), testSecret)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if count != 1 {
		t.Fatalf("encoded-only message must unwrap after transfer decoding, got count=%d", count)
	}
	parts := decodedLeafParts(t, unwrapped)
	if len(parts) != 1 || !strings.Contains(parts[0].decoded, "https://vendor.example.test/b64-only") {
		t.Errorf("destination not restored in the decoded part: %+v", parts)
	}
}

// TestUnwrapMessageBody_QuotedPrintableEncodedMarkerStillUnwraps (item 3): a
// QP-encoded redirect decodes to exactly one substitution — the =3D escape
// artifacts must not confuse the marker or the token.
func TestUnwrapMessageBody_QuotedPrintableEncodedMarkerStillUnwraps(t *testing.T) {
	token := buildToken("https://vendor.example.test/qp-only")
	inner := "see /link-protect?token=" + token
	var buf bytes.Buffer
	w := quotedprintable.NewWriter(&buf)
	if _, err := w.Write([]byte(inner)); err != nil {
		t.Fatalf("qp encode: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("qp close: %v", err)
	}
	msg := multipartMsg("BB",
		"Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n"+buf.String()+"\r\n")
	unwrapped, count, err := UnwrapMessageBody([]byte(msg), testSecret)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if count != 1 {
		t.Fatalf("QP-encoded redirect must unwrap exactly once, got count=%d", count)
	}
	parts := decodedLeafParts(t, unwrapped)
	if len(parts) != 1 || !strings.Contains(parts[0].decoded, "https://vendor.example.test/qp-only") {
		t.Errorf("destination not restored in the decoded part: %+v", parts)
	}
}

// TestUnwrapMessageBody_EncodedPartWithoutMarkerByteExact (item 3 flip side):
// with the fast path moved after decoding, a marker-less encoded message must
// still come back byte-exact with zero substitutions.
func TestUnwrapMessageBody_EncodedPartWithoutMarkerByteExact(t *testing.T) {
	enc := base64.StdEncoding.EncodeToString([]byte("no redirects in this part at all"))
	msg := multipartMsg("BB",
		"Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n"+enc+"\r\n")
	unwrapped, count, err := UnwrapMessageBody([]byte(msg), testSecret)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if count != 0 {
		t.Fatalf("count=%d, want 0", count)
	}
	if !bytes.Equal(unwrapped, []byte(msg)) {
		t.Error("marker-less message must stay byte-exact")
	}
}

// TestRewriteMessageBody_CSSProtocolRelativeRewritten (item 4):
// url("//…") in style attributes and <style> text, and @import "//…", are
// externally fetched in every CSS context and must be rewritten like their
// absolute twins.
func TestRewriteMessageBody_CSSProtocolRelativeRewritten(t *testing.T) {
	body := msgWith("Content-Type: text/html\r\n",
		`<html><head><style>@import "//evil.test/x.css"; body{background:url("//evil.test/bg.png")}</style></head>`+
			`<body><div style="border-image:url('//evil.test/edge.png')">x</div></body></html>`)
	rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody: %v", err)
	}
	if count != 3 {
		t.Fatalf("all three protocol-relative CSS targets must be rewritten, got count=%d", count)
	}
	out := string(rewritten)
	if strings.Contains(out, "//evil.test") {
		t.Errorf("a protocol-relative CSS URL survived as a direct external fetch: %s", out)
	}
	if strings.Count(out, "/link-protect?token=") != 3 {
		t.Errorf("expected 3 redirects in output: %s", out)
	}
}

// TestParseSrcsetCandidates (item 5): WHATWG candidate spans — a comma belongs
// to the URL unless it terminates the candidate.
func TestParseSrcsetCandidates(t *testing.T) {
	cases := []struct {
		name string
		val  string
		want []string
	}{
		{"comma-in-url", "https://evil.test/img,a.png 1x", []string{"https://evil.test/img,a.png"}},
		{"two-candidates", "a.png 1x, b.png 2x", []string{"a.png", "b.png"}},
		{"comma-no-space", "a.png 1x,b.png 2x", []string{"a.png", "b.png"}},
		{"trailing-comma", "a.png,", []string{"a.png"}},
		{"no-whitespace-one-candidate", "https://a.test/x.png,https://b.test/y.png", []string{"https://a.test/x.png,https://b.test/y.png"}},
		{"empty", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, sp := range parseSrcsetCandidates(tc.val) {
				got = append(got, tc.val[sp[0]:sp[1]])
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("parseSrcsetCandidates(%q) = %q, want %q", tc.val, got, tc.want)
			}
		})
	}
}

// TestRewriteMessageBody_SrcsetCommaInURLByteFaithful (item 5): the mid-URL
// comma must stay inside ONE candidate; the signed destination is the full
// URL byte-for-byte (no truncation, no invented phantom candidate), separators
// and the untouched candidate are preserved, and unwrap recovers the attribute
// byte-faithfully.
func TestRewriteMessageBody_SrcsetCommaInURLByteFaithful(t *testing.T) {
	dest := "https://evil.test/img,a.png"
	attrVal := dest + " 1x, /local.png 2x"
	body := msgWith("Content-Type: text/html\r\n", `<html><img srcset="`+attrVal+`"></html>`)
	rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody: %v", err)
	}
	if count != 1 {
		t.Fatalf("mid-URL comma must not split the candidate, got count=%d", count)
	}
	out := string(rewritten)
	i := strings.Index(out, protectedMarker)
	rest := out[i+len(protectedMarker):]
	end := strings.IndexAny(rest, "\"' ")
	if end < 0 {
		t.Fatalf("no descriptor boundary after token: %s", out)
	}
	claims, err := VerifyToken(rest[:end], testSecret)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if claims.URL != dest {
		t.Errorf("destination not byte-faithful: got %q, want %q", claims.URL, dest)
	}
	if !strings.Contains(out, rest[:end]+" 1x, /local.png 2x") {
		t.Errorf("separators/descriptors/untouched candidate not preserved: %s", out)
	}
	unwrapped, m, err := UnwrapMessageBody(rewritten, testSecret)
	if err != nil || m != 1 {
		t.Fatalf("unwrap: m=%d err=%v", m, err)
	}
	if !strings.Contains(string(unwrapped), `srcset="`+attrVal+`"`) {
		t.Errorf("srcset attribute did not round-trip byte-faithfully: %s", unwrapped)
	}
}

// TestUnwrapMessageBody_HeaderlessBodyUnwrapsAsTextPlain pins the RFC 2045
// §5.2 default path: a message with NO Content-Type header and a non-empty
// body unwraps as text/plain (UnwrapMessageBodyN line 869 branch).
func TestUnwrapMessageBody_HeaderlessBodyUnwrapsAsTextPlain(t *testing.T) {
	token := buildToken("https://vendor.example.com/promo")
	// Deliberately NO Content-Type header: only a bare MIME-Version-free
	// header block so mail.ReadMessage sees a header/body split.
	msg := []byte("X-Test: headerless\r\n\r\n/link-protect?token=" + token + "\r\n")
	unwrapped, count, err := UnwrapMessageBodyN(msg, TokenKeys{Secret: testSecret, Version: tokenKeyVersion1})
	if err != nil {
		t.Fatalf("unwrap headerless body: %v", err)
	}
	if count != 1 {
		t.Fatalf("count = %d, want 1 (RFC 2045 §5.2 text/plain default)", count)
	}
	if !strings.Contains(string(unwrapped), "https://vendor.example.com/promo") {
		t.Errorf("headerless body redirect not unwrapped: %q", string(unwrapped))
	}
	if strings.Contains(string(unwrapped), "/link-protect?token=") {
		t.Errorf("unwrapped body still contains a redirect: %q", string(unwrapped))
	}
}
