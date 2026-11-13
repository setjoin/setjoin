package smtp

// D-MAILSERVER-INTERNAL-LINKPROTECT-001 corpus for the LIVE inbound rewrite
// site (link_protect.go rewriteURL / RewriteMessageBody). The same rows run in
// mailserver/internal/linkprotect/url_authority_corpus_test.go against the
// canonical classifier (linkprotect.IsInternalURL — also the Spamhaus scan
// target) and the dead-copy rewrite, so every linkprotect classification site
// shares one net/url authority discipline: userinfo excluded from the host,
// ports stripped, IPv6 unbracketed, malformed URLs fail closed to "NOT
// internal" (they get rewritten and click-scanned instead of exempted).

import (
	"encoding/base64"
	"io"
	"mime/quotedprintable"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/linkprotect"
)

// smtpURLCorpusCase mirrors linkprotect's urlCorpusCase row-for-row; the
// expectations MUST stay identical across the two files.
type smtpURLCorpusCase struct {
	name         string
	url          string
	domain       string
	wantInternal bool
}

var smtpURLCorpus = []smtpURLCorpusCase{
	// Userinfo + port confusion — the reported finding and its variants.
	{name: "userinfo-port-confusion", url: "http://internal.domain:8080@evil.com/", domain: "internal.domain", wantInternal: false},
	{name: "userinfo-https-decoy", url: "https://internal.domain@evil.com/x", domain: "internal.domain", wantInternal: false},
	{name: "userinfo-double-at", url: "http://a@b@evil.com/", domain: "internal.domain", wantInternal: false},
	{name: "userinfo-reversed-decoy", url: "http://evil.com:8080@internal.domain/", domain: "internal.domain", wantInternal: true},
	{name: "userinfo-percent-encoded", url: "http://%69nternal.domain@evil.com/", domain: "internal.domain", wantInternal: false},
	{name: "userinfo-basic-auth-internal", url: "http://user:pass@internal.domain:8443/x", domain: "internal.domain", wantInternal: true},
	{name: "userinfo-trailing-port", url: "http://internal.domain:8080@evil.com:443/p", domain: "internal.domain", wantInternal: false},

	// Ports.
	{name: "internal-with-port", url: "http://internal.domain:8080/page", domain: "internal.domain", wantInternal: true},
	{name: "external-with-port", url: "https://evil.com:8443/", domain: "internal.domain", wantInternal: false},
	{name: "external-default-port", url: "https://evil.com:443", domain: "internal.domain", wantInternal: false},

	// IPv6 literals.
	{name: "ipv6-literal-exact", url: "http://[2001:db8::1]:8080/x", domain: "2001:db8::1", wantInternal: true},
	{name: "ipv6-literal-uppercase", url: "http://[FE80::1]:8080/", domain: "fe80::1", wantInternal: true},
	{name: "ipv6-literal-never-domain-match", url: "http://[2001:db8::1]/", domain: "internal.domain", wantInternal: false},

	// IDNA.
	{name: "idna-punycode-exact", url: "https://xn--bcher-kva.example/", domain: "xn--bcher-kva.example", wantInternal: true},
	{name: "idna-punycode-userinfo", url: "https://xn--bcher-kva.example@evil.com/", domain: "xn--bcher-kva.example", wantInternal: false},
	{name: "idna-percent-encoded-host", url: "https://b%C3%BCcher.example/", domain: "bücher.example", wantInternal: true},
	{name: "idna-percent-encoded-userinfo", url: "https://b%C3%BCcher.example@evil.com/", domain: "bücher.example", wantInternal: false},

	// Malformed / authority-less: fail closed to NOT internal (rewritten).
	{name: "malformed-unclosed-bracket", url: "http://[::1", domain: "internal.domain", wantInternal: false},
	{name: "malformed-space-in-host", url: "http://exa mple.com/", domain: "internal.domain", wantInternal: false},
	{name: "no-authority-empty-host", url: "http:///path", domain: "internal.domain", wantInternal: false},
	{name: "scheme-only", url: "https://", domain: "internal.domain", wantInternal: false},

	// Case and boundary discipline.
	{name: "uppercase-authority", url: "HTTP://INTERNAL.Domain/Page", domain: "internal.domain", wantInternal: true},
	{name: "suffix-confusion", url: "https://internal.domain.evil.com/", domain: "internal.domain", wantInternal: false},
	{name: "prefix-confusion", url: "https://xxinternal.domain/", domain: "internal.domain", wantInternal: false},
	{name: "query-embedded-url", url: "https://evil.com/?u=http://internal.domain/", domain: "internal.domain", wantInternal: false},
}

// TestLiveRewriteSite_URLAuthorityCorpus pins the corpus against the live
// inbound rewrite site's classifier call path (rewriteURL): a URL is exempt
// from rewriting if and only if the net/url authority classification says
// internal.
func TestLiveRewriteSite_URLAuthorityCorpus(t *testing.T) {
	for _, tc := range smtpURLCorpus {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := rewriteURL(tc.url, testSecret, []string{tc.domain}, "msg-1", 1)
			if ok == tc.wantInternal {
				t.Errorf("rewriteURL(%q, domain=%q) rewritten=%v, want rewritten=%v",
					tc.url, tc.domain, ok, !tc.wantInternal)
			}
		})
	}
}

// TestLiveRewriteSite_ClassifierIdentity pins the single-parser discipline:
// the smtp rewrite site's internal classification must be IDENTICAL to the
// canonical linkprotect classifier (the same function the Spamhaus scan target
// uses) for every corpus row — a future re-hand-rolled parser fails here.
func TestLiveRewriteSite_ClassifierIdentity(t *testing.T) {
	for _, tc := range smtpURLCorpus {
		t.Run(tc.name, func(t *testing.T) {
			live := func(u, d string) bool {
				_, ok := rewriteURL(u, testSecret, []string{d}, "msg-1", 1)
				return !ok // not rewritten ⇒ classified internal
			}
			if got, want := live(tc.url, tc.domain), linkprotect.IsInternalURL(tc.url, tc.domain); got != want {
				t.Errorf("live site classification %v != canonical classifier %v for %q", got, want, tc.url)
			}
		})
	}
}

// TestRewriteMessageBody_UserinfoAttackerURL_IsRewritten is the inbound-consumer
// regression for the finding: an attacker URL whose userinfo mimics an internal
// domain must be rewritten through /link-protect — previously the faulty
// internal-domain exemption delivered the body with the link pointing straight
// at the attacker host, bypassing the interstitial.
func TestRewriteMessageBody_UserinfoAttackerURL_IsRewritten(t *testing.T) {
	body := "From: attacker@evil.com\r\nTo: user@test.com\r\nSubject: invoice\r\nContent-Type: text/html\r\n\r\n" +
		"<html><body><a href=\"http://internal.domain:8080@evil.com/\">click</a></body></html>"
	rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, []string{"internal.domain"}, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("userinfo-decoy attacker URL must be rewritten; got count=%d", count)
	}
	out := string(rewritten)
	if !strings.Contains(out, "/link-protect?token=") {
		t.Error("expected /link-protect?token= for userinfo-decoy attacker URL")
	}
	if strings.Contains(out, "internal.domain:8080@evil.com") {
		t.Error("attacker URL must not remain unrewritten in the delivered body")
	}
}

// TestRewriteMessageBody_GenuineInternalWithPortStillExempted pins the
// preserved exemption: a genuinely internal URL on a non-default port is still
// classified by its (port-stripped) authority and stays unrewritten.
func TestRewriteMessageBody_GenuineInternalWithPortStillExempted(t *testing.T) {
	body := "From: test@test.com\r\nTo: user@test.com\r\nSubject: Test\r\nContent-Type: text/html\r\n\r\n" +
		"<html><body><a href=\"http://internal.domain:8080/page\">intranet</a></body></html>"
	_, count, err := RewriteMessageBody([]byte(body), testSecret, []string{"internal.domain"}, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
	if count != 0 {
		t.Errorf("genuine internal URL with port must stay exempt; got count=%d", count)
	}
}

// TestRewriteMessageBody_MalformedURLIsRewritten pins the fail-closed direction
// for malformed input on the live path: a URL the authority parser rejects is
// never treated as internal — it is rewritten so the click goes through the
// interstitial instead of being delivered un-protected.
func TestRewriteMessageBody_MalformedURLIsRewritten(t *testing.T) {
	body := "From: test@test.com\r\nTo: user@test.com\r\nSubject: Test\r\nContent-Type: text/html\r\n\r\n" +
		"<html><body><a href=\"http:///path\">weird</a></body></html>"
	rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, []string{"internal.domain"}, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("malformed URL must fail closed to rewritten; got count=%d", count)
	}
	if !strings.Contains(string(rewritten), "/link-protect?token=") {
		t.Error("expected /link-protect?token= for malformed URL")
	}
}

// TestRewriteMessageBody_RewriteAllDoesNotReplaceClickGate pins the boundary
// from the remediation row: forcing rewriting for ALL links (nil
// internalDomains — no exemption at all) rewrites the attacker URL, but
// containment still requires the click-time Spamhaus parser fix — with rewriting
// forced, the click verdict pipeline still gates the click on the TRUE authority
// host (pinned at the scanner level in the linkprotect package:
// TestSpamhaus_ScansTrueAuthorityNotUserinfoDecoy). This test pins the
// rewrite-all side of that joint requirement.
func TestRewriteMessageBody_RewriteAllDoesNotReplaceClickGate(t *testing.T) {
	body := "From: attacker@evil.com\r\nTo: user@test.com\r\nSubject: hi\r\nContent-Type: text/plain\r\n\r\n" +
		"see http://internal.domain:8080@evil.com/ now"
	rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("rewrite-all must still rewrite the attacker URL; got count=%d", count)
	}
	out := string(rewritten)
	if strings.Contains(out, "http://internal.domain:8080@evil.com/") {
		t.Error("rewrite-all must not leave the attacker URL in the delivered body")
	}
	// The tokenized URL travels in the claims; unwrapping it must yield the
	// attacker URL, which the click-time scanner (Spamhaus, fixed parser) then
	// evaluates at the TRUE host — rewrite-all alone is not complete containment.
	tokens := tokenURLs(out)
	if len(tokens) != 1 {
		t.Fatalf("expected exactly 1 protected redirect, got %d in %q", len(tokens), out)
	}
	claims, err := linkprotect.VerifyToken(tokens[0], testSecret)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if claims.URL != "http://internal.domain:8080@evil.com/" {
		t.Errorf("token must carry the full attacker URL for click-time scanning, got %q", claims.URL)
	}
	// The canonical authority classifier (shared with the Spamhaus scan target)
	// must see evil.com — not the userinfo decoy — when the click is gated.
	if linkprotect.IsInternalURL(claims.URL, "internal.domain") {
		t.Error("click-time classification must not resolve to the userinfo decoy internal.domain")
	}
	if !linkprotect.IsInternalURL(claims.URL, "evil.com") {
		t.Error("click-time classification must resolve to the true authority evil.com")
	}
}

// TestRewriteMessageBody_R2SharedContractFixtures runs the med-shard2-003
// round-2 contract fixtures against the LIVE delivery site. Since the r2
// alignment the live RewriteMessageBody delegates to the canonical
// linkprotect.RewriteMessageBody, so these pin the delegation itself: QP tail
// preservation (writer Close), protocol-relative CSS coverage, srcset
// comma-in-URL byte-faithfulness, and transfer-decoded base64 rewriting.
func TestRewriteMessageBody_R2SharedContractFixtures(t *testing.T) {
	t.Run("qp-tail-without-terminal-newline-preserved", func(t *testing.T) {
		body := "From: test@test.com\r\nTo: user@test.com\r\nSubject: t\r\n" +
			"Content-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n" +
			"see https://evil.test/tail-no-newline"
		rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
		if err != nil {
			t.Fatalf("RewriteMessageBody: %v", err)
		}
		if count != 1 {
			t.Fatalf("count=%d, want 1", count)
		}
		idx := strings.Index(string(rewritten), "\r\n\r\n")
		decodedBytes, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(string(rewritten[idx+4:]))))
		if err != nil {
			t.Fatalf("qp decode: %v", err)
		}
		decoded := string(decodedBytes)
		if !strings.HasPrefix(decoded, "see /link-protect?token=") {
			t.Fatalf("re-encoded QP part lost its buffered tail: %q", decoded)
		}
		unwrapped, m, err := linkprotect.UnwrapMessageBody(rewritten, testSecret)
		if err != nil || m != 1 {
			t.Fatalf("unwrap: m=%d err=%v", m, err)
		}
		if !strings.Contains(string(unwrapped), "see https://evil.test/tail-no-newline") {
			t.Errorf("destination did not round-trip: %q", string(unwrapped))
		}
	})

	t.Run("css-protocol-relative-rewritten", func(t *testing.T) {
		body := "From: test@test.com\r\nTo: user@test.com\r\nSubject: t\r\nContent-Type: text/html\r\n\r\n" +
			`<html><head><style>@import "//evil.test/x.css"; body{background:url("//evil.test/bg.png")}</style></head><body></body></html>`
		rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
		if err != nil {
			t.Fatalf("RewriteMessageBody: %v", err)
		}
		if count != 2 {
			t.Fatalf("protocol-relative CSS targets must be rewritten, got count=%d", count)
		}
		out := string(rewritten)
		if strings.Contains(out, "//evil.test") {
			t.Errorf("protocol-relative CSS URL survived as a direct external fetch: %s", out)
		}
	})

	t.Run("srcset-comma-in-url-byte-faithful", func(t *testing.T) {
		dest := "https://evil.test/img,a.png"
		body := "From: test@test.com\r\nTo: user@test.com\r\nSubject: t\r\nContent-Type: text/html\r\n\r\n" +
			`<html><img srcset="` + dest + ` 1x, /local.png 2x"></html>`
		rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
		if err != nil {
			t.Fatalf("RewriteMessageBody: %v", err)
		}
		if count != 1 {
			t.Fatalf("mid-URL comma must not split the candidate, got count=%d", count)
		}
		tokens := tokenURLs(string(rewritten))
		if len(tokens) != 1 {
			t.Fatalf("expected exactly 1 protected redirect (no phantom candidate), got %d", len(tokens))
		}
		claims, err := linkprotect.VerifyToken(tokens[0], testSecret)
		if err != nil {
			t.Fatalf("verify token: %v", err)
		}
		if claims.URL != dest {
			t.Errorf("destination not byte-faithful: got %q, want %q", claims.URL, dest)
		}
	})

	t.Run("base64-encoded-part-rewritten", func(t *testing.T) {
		body := "From: test@test.com\r\nTo: user@test.com\r\nSubject: t\r\n" +
			"Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
			base64.StdEncoding.EncodeToString([]byte("visit https://evil.test/encoded now")) + "\r\n"
		rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
		if err != nil {
			t.Fatalf("RewriteMessageBody: %v", err)
		}
		if count != 1 {
			t.Fatalf("encoded URL must be rewritten after transfer decoding, got count=%d", count)
		}
		if strings.Contains(string(rewritten), "https://evil.test/encoded") {
			t.Error("encoded attacker URL survived in raw output (it must at least be re-encoded rewritten)")
		}
	})
}

// tokenURLs extracts the token payloads from rewritten output.
func tokenURLs(body string) []string {
	var out []string
	for {
		i := strings.Index(body, "/link-protect?token=")
		if i < 0 {
			return out
		}
		rest := body[i+len("/link-protect?token="):]
		end := strings.IndexAny(rest, "\"' <>)")
		tok := rest
		if end >= 0 {
			tok = rest[:end]
		}
		out = append(out, tok)
		body = rest
	}
}
