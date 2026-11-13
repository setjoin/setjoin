package linkprotect

// D-MAILSERVER-INTERNAL-LINKPROTECT-001 corpus: every linkprotect URL
// classification site must classify by the net/url AUTHORITY host
// (parseURLHost → u.Hostname(): userinfo excluded, port stripped, IPv6
// unbracketed) and must fail CLOSED on malformed or authority-less URLs.
//
// Sites covered by this file:
//   - IsInternalURL / rewriteURL (this package's rewrite copy — production-dead
//     for inbound but must classify identically to the live smtp copy), and
//   - extractURLDomain / SpamhausDBLScanner (the live click-time scan target).
// The live smtp rewrite site runs the SAME table in
// mailserver/internal/smtp/link_protect_corpus_test.go.
//
// No live DNS or network is used: the Spamhaus scanner is exercised through
// its lookupHost injection seam, Safe Browsing through a capturing RoundTripper.

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// urlCorpusCase is one row of the shared userinfo/IPv6/port/IDNA/malformed
// corpus. The same rows (by URL, domain and expectations) run against every
// classification site in both packages.
type urlCorpusCase struct {
	name string
	url  string
	// domain is the configured internal domain for the classification call.
	domain string
	// wantInternal is the expected IsInternalURL(url, domain) result.
	wantInternal bool
	// wantSpamhausHost is the expected extractURLDomain result; empty means
	// extractURLDomain must return an error (fail closed).
	wantSpamhausHost string
	// decoyInUserinfo marks URLs whose textual decoy host appears only in the
	// userinfo component: the OLD hand-rolled parser classified these as
	// internal; the net/url authority says otherwise.
	decoyInUserinfo bool
}

var urlAuthorityCorpus = []urlCorpusCase{
	// Userinfo + port confusion — the reported finding and its variants.
	{name: "userinfo-port-confusion", url: "http://internal.domain:8080@evil.com/", domain: "internal.domain", wantInternal: false, wantSpamhausHost: "evil.com", decoyInUserinfo: true},
	{name: "userinfo-https-decoy", url: "https://internal.domain@evil.com/x", domain: "internal.domain", wantInternal: false, wantSpamhausHost: "evil.com", decoyInUserinfo: true},
	{name: "userinfo-double-at", url: "http://a@b@evil.com/", domain: "internal.domain", wantInternal: false, wantSpamhausHost: "evil.com"},
	{name: "userinfo-reversed-decoy", url: "http://evil.com:8080@internal.domain/", domain: "internal.domain", wantInternal: true, wantSpamhausHost: "internal.domain"},
	{name: "userinfo-percent-encoded", url: "http://%69nternal.domain@evil.com/", domain: "internal.domain", wantInternal: false, wantSpamhausHost: "evil.com", decoyInUserinfo: true},
	{name: "userinfo-basic-auth-internal", url: "http://user:pass@internal.domain:8443/x", domain: "internal.domain", wantInternal: true, wantSpamhausHost: "internal.domain"},
	{name: "userinfo-trailing-port", url: "http://internal.domain:8080@evil.com:443/p", domain: "internal.domain", wantInternal: false, wantSpamhausHost: "evil.com", decoyInUserinfo: true},

	// Ports.
	{name: "internal-with-port", url: "http://internal.domain:8080/page", domain: "internal.domain", wantInternal: true, wantSpamhausHost: "internal.domain"},
	{name: "external-with-port", url: "https://evil.com:8443/", domain: "internal.domain", wantInternal: false, wantSpamhausHost: "evil.com"},
	{name: "external-default-port", url: "https://evil.com:443", domain: "internal.domain", wantInternal: false, wantSpamhausHost: "evil.com"},

	// IPv6 literals: bracketed authority, port stripped, case-normalized.
	{name: "ipv6-literal-exact", url: "http://[2001:db8::1]:8080/x", domain: "2001:db8::1", wantInternal: true, wantSpamhausHost: "2001:db8::1"},
	{name: "ipv6-literal-uppercase", url: "http://[FE80::1]:8080/", domain: "fe80::1", wantInternal: true, wantSpamhausHost: "fe80::1"},
	{name: "ipv6-literal-never-domain-match", url: "http://[2001:db8::1]/", domain: "internal.domain", wantInternal: false, wantSpamhausHost: "2001:db8::1"},

	// IDNA: punycode (wire form) and percent-encoded UTF-8 hosts classify by
	// the net/url-decoded host, userinfo still excluded.
	{name: "idna-punycode-exact", url: "https://xn--bcher-kva.example/", domain: "xn--bcher-kva.example", wantInternal: true, wantSpamhausHost: "xn--bcher-kva.example"},
	{name: "idna-punycode-userinfo", url: "https://xn--bcher-kva.example@evil.com/", domain: "xn--bcher-kva.example", wantInternal: false, wantSpamhausHost: "evil.com", decoyInUserinfo: true},
	{name: "idna-percent-encoded-host", url: "https://b%C3%BCcher.example/", domain: "bücher.example", wantInternal: true, wantSpamhausHost: "bücher.example"},
	{name: "idna-percent-encoded-userinfo", url: "https://b%C3%BCcher.example@evil.com/", domain: "bücher.example", wantInternal: false, wantSpamhausHost: "evil.com", decoyInUserinfo: true},

	// Malformed / authority-less: fail closed (NOT internal ⇒ rewritten;
	// scanner refuses to query).
	{name: "malformed-unclosed-bracket", url: "http://[::1", domain: "internal.domain", wantInternal: false, wantSpamhausHost: ""},
	{name: "malformed-space-in-host", url: "http://exa mple.com/", domain: "internal.domain", wantInternal: false, wantSpamhausHost: ""},
	{name: "no-authority-empty-host", url: "http:///path", domain: "internal.domain", wantInternal: false, wantSpamhausHost: ""},
	{name: "scheme-only", url: "https://", domain: "internal.domain", wantInternal: false, wantSpamhausHost: ""},

	// Case and boundary discipline.
	{name: "uppercase-authority", url: "HTTP://INTERNAL.Domain/Page", domain: "internal.domain", wantInternal: true, wantSpamhausHost: "internal.domain"},
	{name: "suffix-confusion", url: "https://internal.domain.evil.com/", domain: "internal.domain", wantInternal: false, wantSpamhausHost: "internal.domain.evil.com"},
	{name: "prefix-confusion", url: "https://xxinternal.domain/", domain: "internal.domain", wantInternal: false, wantSpamhausHost: "xxinternal.domain"},
	{name: "query-embedded-url", url: "https://evil.com/?u=http://internal.domain/", domain: "internal.domain", wantInternal: false, wantSpamhausHost: "evil.com", decoyInUserinfo: false},
}

// TestURLAuthorityCorpus_IsInternalURL pins the corpus against the canonical
// classifier shared by both rewrite sites.
func TestURLAuthorityCorpus_IsInternalURL(t *testing.T) {
	for _, tc := range urlAuthorityCorpus {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsInternalURL(tc.url, tc.domain); got != tc.wantInternal {
				t.Errorf("IsInternalURL(%q, %q) = %v, want %v", tc.url, tc.domain, got, tc.wantInternal)
			}
		})
	}
}

// TestURLAuthorityCorpus_RewriteSite pins the corpus against this package's
// rewriteURL (the dead copy for inbound): it must rewrite exactly the URLs the
// classifier calls NOT internal, so the corpus classification is identical
// across sites.
func TestURLAuthorityCorpus_RewriteSite(t *testing.T) {
	for _, tc := range urlAuthorityCorpus {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := rewriteURL(tc.url, TokenKeys{Secret: testSecret}, []string{tc.domain}, "msg-1", 1)
			if ok == tc.wantInternal {
				t.Errorf("rewriteURL(%q) rewritten=%v, want rewritten=%v (internal=%v)",
					tc.url, ok, !tc.wantInternal, tc.wantInternal)
			}
		})
	}
}

// TestURLAuthorityCorpus_SpamhausSite pins the corpus against the Spamhaus DBL
// scan-target extractor: it must resolve the TRUE net/url authority host and
// reject malformed/authority-less URLs with an error (never a decoy domain).
func TestURLAuthorityCorpus_SpamhausSite(t *testing.T) {
	for _, tc := range urlAuthorityCorpus {
		t.Run(tc.name, func(t *testing.T) {
			host, err := extractURLDomain(tc.url)
			if tc.wantSpamhausHost == "" {
				if err == nil {
					t.Errorf("extractURLDomain(%q) = %q, want error (fail closed)", tc.url, host)
				}
				return
			}
			if err != nil {
				t.Fatalf("extractURLDomain(%q) unexpected error: %v", tc.url, err)
			}
			if host != tc.wantSpamhausHost {
				t.Errorf("extractURLDomain(%q) = %q, want %q", tc.url, host, tc.wantSpamhausHost)
			}
		})
	}
}

// TestSpamhausAndIsInternalURL_AgreeOnCorpus is the shared-fixture agreement
// test: for every corpus row the scan-target extractor and the internal-domain
// classifier must resolve the SAME authority host.
func TestSpamhausAndIsInternalURL_AgreeOnCorpus(t *testing.T) {
	for _, tc := range urlAuthorityCorpus {
		t.Run(tc.name, func(t *testing.T) {
			host, err := extractURLDomain(tc.url)
			if err != nil {
				if !IsInternalURL(tc.url, tc.domain) {
					return // both fail closed on malformed input — agreement holds
				}
				t.Fatalf("extractURLDomain errored (%v) but classifier called the URL internal", err)
			}
			// The scanner's host and the classifier's host are the same
			// authority: scanning the extracted host must reproduce the
			// classification decision for that host.
			if !IsInternalURL(tc.url, host) {
				t.Errorf("scanner host %q and classifier disagree for %q: classifier does not recognize the scanner's own authority as internal", host, tc.url)
			}
		})
	}
}

// TestURLAuthority_UserinfoDecoyNeverClassifiesInternal is the finding
// regression: for every userinfo-decoy row, the decoy host textually present
// BEFORE the '@' must not classify as internal and must not be the scan target.
func TestURLAuthority_UserinfoDecoyNeverClassifiesInternal(t *testing.T) {
	for _, tc := range urlAuthorityCorpus {
		if !tc.decoyInUserinfo {
			continue
		}
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantInternal {
				t.Fatalf("corpus row %q is malformed: decoy rows must be external", tc.name)
			}
			host, err := extractURLDomain(tc.url)
			if err != nil {
				t.Fatalf("extractURLDomain(%q): %v", tc.url, err)
			}
			if strings.Contains(host, "internal.domain") || strings.Contains(host, "xn--bcher-kva.example") || strings.Contains(host, "bücher.example") {
				t.Errorf("scan target %q resolved to the userinfo decoy for %q", host, tc.url)
			}
		})
	}
}

// TestRewriteMessageBody_UserinfoAttackerURL_IsRewritten pins the consumer
// consequence: an attacker URL whose userinfo mimics an internal domain MUST be
// rewritten through /link-protect (previously the faulty exemption delivered it
// un-rewritten, straight to the attacker host).
func TestRewriteMessageBody_UserinfoAttackerURL_IsRewritten(t *testing.T) {
	body := "From: test@test.com\r\nTo: user@test.com\r\nSubject: Test\r\nContent-Type: text/html\r\n\r\n" +
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
		t.Error("attacker URL must not remain unrewritten in the body")
	}
}

// TestRewriteMessageBody_GenuineInternalWithPortStillExempted pins the other
// half of the fix: the net/url parser strips ports correctly, so a genuinely
// internal URL on a non-default port keeps its rewrite exemption.
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

// TestSpamhaus_ScansTrueAuthorityNotUserinfoDecoy is the rewrite-all boundary
// pin: even with rewriting forced for ALL links (nil internalDomains — no
// exemption), the click-time Spamhaus parser result still gates the click, so
// it must query the TRUE authority host (evil.com), never the userinfo decoy.
// Rewrite-all alone is NOT containment; the parser fix is required too.
func TestSpamhaus_ScansTrueAuthorityNotUserinfoDecoy(t *testing.T) {
	var queried []string
	s := &SpamhausDBLScanner{lookupHost: func(_ context.Context, host string) ([]string, error) {
		queried = append(queried, host)
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}}
	v, err := s.Check(context.Background(), "http://internal.domain:8080@evil.com/")
	if err != nil || v != VerdictSafe {
		t.Fatalf("NXDOMAIN stub must yield Safe/nil; got %v err=%v", v, err)
	}
	if len(queried) != 1 {
		t.Fatalf("expected exactly one DBL query, got %v", queried)
	}
	if queried[0] != "evil.com.dbl.spamhaus.org" {
		t.Errorf("DBL must be queried at the true authority, got %q, want evil.com.dbl.spamhaus.org", queried[0])
	}
	if strings.Contains(queried[0], "internal.domain") {
		t.Errorf("DBL query %q leaked the userinfo decoy", queried[0])
	}
}

// TestScanPipeline_SpamhausSafeOtherMalicious_Blocks pins the scanner
// combination rule: a Spamhaus-Safe verdict on the decoy NEVER implies a
// redirect — any other scanner's Malicious makes the AGGREGATE verdict
// Malicious, in either scanner order (Safe does not short-circuit).
func TestScanPipeline_SpamhausSafeOtherMalicious_Blocks(t *testing.T) {
	for _, order := range []string{"spamhaus-first", "malicious-first"} {
		t.Run(order, func(t *testing.T) {
			spamhaus := &mockScanner{name: "spamhaus", v: VerdictSafe}
			other := &mockScanner{name: "other-scanner", v: VerdictMalicious}
			scanners := []Scanner{spamhaus, other}
			if order == "malicious-first" {
				scanners = []Scanner{other, spamhaus}
			}
			v, results, allErrors := ScanPipeline(context.Background(), scanners, "http://internal.domain:8080@evil.com/")
			if v != VerdictMalicious {
				t.Errorf("aggregate verdict = %v, want Malicious (Spamhaus-Safe alone never implies redirect)", v)
			}
			if allErrors {
				t.Error("a Malicious verdict is not an error outcome")
			}
			if results["spamhaus"] != VerdictSafe {
				t.Errorf("spamhaus decoy-Safe result missing/incorrect: %v", results["spamhaus"])
			}
		})
	}
}

// TestScanPipeline_SpamhausSafeOtherError_IsUnknown pins the scanner-error
// verdict behavior: a scanner ERROR surfaces as VerdictUnknown in the results
// (never silently Safe), so Spamhaus-Safe + another-scanner-error aggregates to
// Unknown with allErrors=false — the reducer then warns (or upgrades in strict
// mode) instead of redirecting on a partially-scanned URL.
func TestScanPipeline_SpamhausSafeOtherError_IsUnknown(t *testing.T) {
	scanners := []Scanner{
		&mockScanner{name: "spamhaus", v: VerdictSafe},
		&mockScanner{name: "other-scanner", err: context.DeadlineExceeded},
	}
	v, results, allErrors := ScanPipeline(context.Background(), scanners, "https://example.com/")
	if v != VerdictUnknown {
		t.Errorf("aggregate verdict = %v, want Unknown when any scanner errors", v)
	}
	if allErrors {
		t.Error("allErrors must be false: the spamhaus scanner returned a real Safe")
	}
	if results["other-scanner"] != VerdictUnknown {
		t.Errorf("erroring scanner must record Unknown, got %v", results["other-scanner"])
	}
}

// TestServeFinalVerdict_AggregateContract pins the Go translation of the
// reducer-confirmed verdict (this switch runs ONLY after decideAndAudit
// succeeded, i.e. with a durable audit row; the audit-failure fail-closed path
// is pinned by TestLinkProtectHandler_FailClosedToWarn /
// TestLinkProtectHandler_ConfirmRequiresAudit, and the audit-time verdict rules
// by mailserver/sql/tests/link_protect_check_and_audit.pg):
//   - Safe            → 302 redirect (audit succeeded)
//   - Malicious       → 200 block page, NEVER a redirect
//   - Unknown         → 200 warn interstitial
//   - Unknown+confirm → 302 with X-LinkProtect-Confirmed (explicit continue)
func TestServeFinalVerdict_AggregateContract(t *testing.T) {
	claims := &TokenClaims{URL: "http://internal.domain:8080@evil.com/", MessageID: "msg-1", MailboxID: 1}

	t.Run("safe-redirects-after-audit", func(t *testing.T) {
		rec := httptest.NewRecorder()
		serveFinalVerdict(rec, httptest.NewRequest(http.MethodGet, "/link-protect?token=x", nil), "safe", claims, "tok")
		if rec.Code != http.StatusFound {
			t.Errorf("confirmed Safe must 302-redirect, got %d", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != claims.URL {
			t.Errorf("redirect target = %q, want the token URL", loc)
		}
	})

	t.Run("malicious-blocks-despite-spamhaus-safe", func(t *testing.T) {
		rec := httptest.NewRecorder()
		serveFinalVerdict(rec, httptest.NewRequest(http.MethodGet, "/link-protect?token=x", nil), "malicious", claims, "tok")
		if rec.Code != http.StatusOK {
			t.Errorf("Malicious must render the block page (200), got %d", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "" {
			t.Errorf("Malicious must NEVER redirect; got Location %q", loc)
		}
		if !strings.Contains(rec.Body.String(), "blocked") {
			t.Error("expected block interstitial body")
		}
	})

	t.Run("unknown-warns-without-confirm", func(t *testing.T) {
		rec := httptest.NewRecorder()
		serveFinalVerdict(rec, httptest.NewRequest(http.MethodGet, "/link-protect?token=x", nil), "unknown", claims, "tok")
		if rec.Code != http.StatusOK {
			t.Errorf("Unknown without confirm must render warn (200), got %d", rec.Code)
		}
		if rec.Header().Get("Location") != "" {
			t.Error("Unknown without confirm must not redirect")
		}
		if !strings.Contains(rec.Body.String(), "Unverified") {
			t.Error("expected warn interstitial body")
		}
	})

	t.Run("unknown-confirm-redirects-after-audit", func(t *testing.T) {
		rec := httptest.NewRecorder()
		serveFinalVerdict(rec, httptest.NewRequest(http.MethodGet, "/link-protect?token=x&confirm=1", nil), "unknown", claims, "tok")
		if rec.Code != http.StatusFound {
			t.Errorf("confirmed Unknown (audit succeeded) must 302-redirect, got %d", rec.Code)
		}
		if rec.Header().Get("X-LinkProtect-Confirmed") != "1" {
			t.Error("confirmed redirect must carry X-LinkProtect-Confirmed: 1")
		}
		if loc := rec.Header().Get("Location"); loc != claims.URL {
			t.Errorf("confirm redirect target = %q, want the token URL", loc)
		}
	})
}

// TestLinkProtectHandler_SpamhausSafeOtherMalicious_FailClosed walks the FULL
// handler with the combination corpus: Spamhaus reports Safe on the decoy, the
// other scanner reports Malicious, and the audit write cannot happen (nil pool)
// — the handler must fail CLOSED to the warn page: Spamhaus-Safe alone never
// produces a redirect, with or without a durable audit.
func TestLinkProtectHandler_SpamhausSafeOtherMalicious_FailClosed(t *testing.T) {
	scanners := []Scanner{
		&mockScanner{name: "spamhaus", v: VerdictSafe},
		&mockScanner{name: "other-scanner", v: VerdictMalicious},
	}
	h := NewLinkProtectHandler(scanners, nil, testLogger(), nil, testSecret)
	token := buildToken("http://internal.domain:8080@evil.com/")

	req := httptest.NewRequest(http.MethodGet, "/link-protect?token="+token, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Header().Get("Location") != "" {
		t.Errorf("Spamhaus-Safe + failed audit must not redirect; got %q", rec.Header().Get("Location"))
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 fail-closed warn page, got %d", rec.Code)
	}
}

// sbCaptureTransport captures the Safe Browsing request body without any
// network I/O (the RoundTripper answers in-process).
type sbCaptureTransport struct {
	gotURL  string
	gotBody string
}

func (c *sbCaptureTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	b, _ := io.ReadAll(req.Body)
	c.gotURL = req.URL.String()
	c.gotBody = string(b)
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"matches":[]}`)), Header: http.Header{}}, nil
}

// TestSafeBrowsingScanner_SendsFullURL pins the counterevidence behavior: Safe
// Browsing is NOT another host parser — it receives the FULL original URL
// (userinfo and all) in threatEntries, so its API-side classification never
// silently reduces to the decoy host.
func TestSafeBrowsingScanner_SendsFullURL(t *testing.T) {
	full := "http://internal.domain:8080@evil.com/x"
	cap := &sbCaptureTransport{}
	s := &SafeBrowsingScanner{apiKey: "test-key", endpoint: "https://safebrowsing.invalid", client: &http.Client{Transport: cap}}

	v, err := s.Check(context.Background(), full)
	if err != nil {
		t.Fatalf("Check error: %v", err)
	}
	if v != VerdictSafe {
		t.Errorf("empty matches must be Safe, got %v", v)
	}
	if !strings.Contains(cap.gotBody, full) {
		t.Errorf("Safe Browsing request body must contain the FULL URL %q, got %s", full, cap.gotBody)
	}
	if strings.Contains(cap.gotURL, full) {
		t.Errorf("the scanned URL must be request BODY data, not the request target; got %q", cap.gotURL)
	}
}
