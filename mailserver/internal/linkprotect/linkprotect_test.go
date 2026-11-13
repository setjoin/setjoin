package linkprotect

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// testSecret is a fixed key for deterministic test tokens.
var testSecret = []byte("test-secret-key-32-bytes-long!")

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func buildToken(originalURL string) string {
	claims := TokenClaims{
		URL:       originalURL,
		MessageID: "msg-test",
		MailboxID: 1,
		ExpiresAt: time.Now().Add(tokenExpiry).Unix(),
	}
	token, _ := SignToken(claims, testSecret)
	return token
}

// --- Token Sign/Verify ---

func TestSignAndVerify_RoundTrip(t *testing.T) {
	claims := TokenClaims{
		URL:       "https://example.com/page",
		MessageID: "msg-001",
		MailboxID: 42,
		ExpiresAt: time.Now().Add(tokenExpiry).Unix(),
	}

	signed, err := SignToken(claims, testSecret)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	verified, err := VerifyToken(signed, testSecret)
	if err != nil {
		t.Fatalf("VerifyToken failed: %v", err)
	}

	if verified.URL != claims.URL {
		t.Errorf("URL mismatch: got %q, want %q", verified.URL, claims.URL)
	}
	if verified.MessageID != claims.MessageID {
		t.Errorf("MessageID mismatch: got %q, want %q", verified.MessageID, claims.MessageID)
	}
	if verified.MailboxID != claims.MailboxID {
		t.Errorf("MailboxID mismatch: got %d, want %d", verified.MailboxID, claims.MailboxID)
	}
}

func TestSignAndVerify_ExpiredToken(t *testing.T) {
	claims := TokenClaims{
		URL:       "https://example.com",
		MessageID: "msg-001",
		MailboxID: 42,
		ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
	}

	signed, err := SignToken(claims, testSecret)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	_, err = VerifyToken(signed, testSecret)
	if err == nil {
		t.Fatal("expected error for expired token, got nil")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("expected 'expired' in error, got: %v", err)
	}
}

func TestSignAndVerify_TamperedToken(t *testing.T) {
	claims := TokenClaims{
		URL:       "https://example.com",
		MessageID: "msg-001",
		MailboxID: 42,
		ExpiresAt: time.Now().Add(tokenExpiry).Unix(),
	}

	signed, err := SignToken(claims, testSecret)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	tampered := signed[:len(signed)-3] + "XXX"

	_, err = VerifyToken(tampered, testSecret)
	if err == nil {
		t.Fatal("expected error for tampered token, got nil")
	}
}

func TestSignAndVerify_WrongSecret(t *testing.T) {
	claims := TokenClaims{
		URL:       "https://example.com",
		MessageID: "msg-001",
		MailboxID: 42,
		ExpiresAt: time.Now().Add(tokenExpiry).Unix(),
	}

	signed, err := SignToken(claims, testSecret)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	_, err = VerifyToken(signed, []byte("wrong-secret-key-32-bytes!!!"))
	if err == nil {
		t.Fatal("expected error for wrong secret, got nil")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("expected 'signature' in error, got: %v", err)
	}
}

func TestVerifyToken_InvalidFormat(t *testing.T) {
	_, err := VerifyToken("not-a-valid-token", testSecret)
	if err == nil {
		t.Fatal("expected error for invalid format, got nil")
	}
}

func TestSignToken_EmptyClaims(t *testing.T) {
	claims := TokenClaims{
		ExpiresAt: time.Now().Add(tokenExpiry).Unix(),
	}
	signed, err := SignToken(claims, testSecret)
	if err != nil {
		t.Fatalf("SignToken with empty claims failed: %v", err)
	}
	if signed == "" {
		t.Fatal("expected non-empty token")
	}

	verified, err := VerifyToken(signed, testSecret)
	if err != nil {
		t.Fatalf("VerifyToken with empty claims failed: %v", err)
	}
	if verified.URL != "" {
		t.Errorf("expected empty URL, got %q", verified.URL)
	}
}

func TestTokenClaims_ExpiryFormat(t *testing.T) {
	claims := TokenClaims{
		URL:       "https://example.com",
		MessageID: "msg-1",
		MailboxID: 42,
		ExpiresAt: time.Now().Add(tokenExpiry).Unix(),
	}

	signed, err := SignToken(claims, testSecret)
	if err != nil {
		t.Fatalf("SignToken failed: %v", err)
	}

	parts := strings.Split(signed, ".")
	if len(parts) != 2 {
		t.Fatalf("expected token in format payload.sig, got %d parts", len(parts))
	}
	if parts[0] == "" || parts[1] == "" {
		t.Fatal("token parts should not be empty")
	}
}

// --- URL Rewriting ---

func TestRewriteMessageBody_HTMLAnchor(t *testing.T) {
	body := "From: test@test.com\r\nTo: user@test.com\r\nSubject: Test\r\nContent-Type: text/html\r\n\r\n<html><body><a href=\"https://evil.com\">click</a></body></html>"
	rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 rewritten URL, got %d", count)
	}
	rewrittenStr := string(rewritten)
	if !strings.Contains(rewrittenStr, "/link-protect?token=") {
		t.Error("expected /link-protect?token= in rewritten body")
	}
	if strings.Contains(rewrittenStr, "https://evil.com") {
		t.Error("original URL should not appear in rewritten body")
	}
}

func TestRewriteMessageBody_PlainTextURL(t *testing.T) {
	body := "From: test@test.com\r\nTo: user@test.com\r\nSubject: Test\r\nContent-Type: text/plain\r\n\r\nVisit https://evil.com for details"
	rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 rewritten URL, got %d", count)
	}
	rewrittenStr := string(rewritten)
	if !strings.Contains(rewrittenStr, "/link-protect?token=") {
		t.Error("expected /link-protect?token= in rewritten body")
	}
}

func TestRewriteMessageBody_SkipMailto(t *testing.T) {
	body := "From: test@test.com\r\nTo: user@test.com\r\nSubject: Test\r\nContent-Type: text/html\r\n\r\n<html><body><a href=\"mailto:admin@test.com\">email</a></body></html>"
	_, _, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
}

func TestRewriteMessageBody_SkipInternalDomains(t *testing.T) {
	body := "From: test@test.com\r\nTo: user@test.com\r\nSubject: Test\r\nContent-Type: text/html\r\n\r\n<html><body><a href=\"https://internal.corp.com/page\">internal</a></body></html>"
	rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, []string{"corp.com"}, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 rewritten URLs for internal domains, got %d", count)
	}
	rewrittenStr := string(rewritten)
	if strings.Contains(rewrittenStr, "/link-protect?token=") {
		t.Error("internal domain URLs should not be rewritten")
	}
}

func TestRewriteMessageBody_SkipAlreadyRewritten(t *testing.T) {
	body := "From: test@test.com\r\nTo: user@test.com\r\nSubject: Test\r\nContent-Type: text/html\r\n\r\n<html><body><a href=\"/link-protect?token=existing\">click</a></body></html>"
	_, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 rewritten URLs, got %d", count)
	}
}

func TestRewriteMessageBody_SkipAnchorFragments(t *testing.T) {
	body := "From: test@test.com\r\nTo: user@test.com\r\nSubject: Test\r\nContent-Type: text/html\r\n\r\n<html><body><a href=\"#section\">jump</a></body></html>"
	_, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 rewritten URLs, got %d", count)
	}
}

func TestRewriteMessageBody_MultipleURLs(t *testing.T) {
	body := "From: test@test.com\r\nTo: user@test.com\r\nSubject: Test\r\nContent-Type: text/html\r\n\r\n<html><body><a href=\"https://evil.com\">bad</a> <a href=\"https://safe.com\">ok</a></body></html>"
	_, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 rewritten URLs, got %d", count)
	}
}

func TestRewriteMessageBody_NoURLs(t *testing.T) {
	body := "From: test@test.com\r\nTo: user@test.com\r\nSubject: Test\r\nContent-Type: text/plain\r\n\r\nHello world, no links here"
	_, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 rewritten URLs, got %d", count)
	}
}

func TestRewriteMessageBody_MultipartMixed(t *testing.T) {
	boundary := "----boundary123"
	body := "From: test@test.com\r\nTo: user@test.com\r\nSubject: Test\r\nContent-Type: multipart/mixed; boundary=\"" + boundary + "\"\r\n\r\n" +
		"This is preamble\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"Visit https://evil.com\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/html\r\n\r\n" +
		"<html><a href=\"https://evil2.com\">click</a></html>\r\n" +
		"--" + boundary + "--\r\n"

	rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 rewritten URLs (1 plain + 1 html), got %d", count)
	}
	rewrittenStr := string(rewritten)
	if strings.Count(rewrittenStr, "/link-protect?token=") != 2 {
		t.Errorf("expected 2 /link-protect tokens in output")
	}
}

func TestRewriteMessageBody_SkipCalendarPart(t *testing.T) {
	boundary := "----boundary123"
	body := "From: test@test.com\r\nTo: user@test.com\r\nSubject: Meeting\r\nContent-Type: multipart/mixed; boundary=\"" + boundary + "\"\r\n\r\n" +
		"This is preamble\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"Meeting info https://evil.com\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/calendar; method=REQUEST\r\n\r\n" +
		"BEGIN:VCALENDAR\r\nhttps://should-not-rewrite.com\r\nEND:VCALENDAR\r\n" +
		"--" + boundary + "--\r\n"

	rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 rewritten URL (only text/plain), got %d", count)
	}
	rewrittenStr := string(rewritten)
	if !strings.Contains(rewrittenStr, "https://should-not-rewrite.com") {
		t.Error("text/calendar part URLs should not be rewritten")
	}
}

func TestRewriteURL_InternalDomainSubdomain(t *testing.T) {
	_, ok := rewriteURL("https://sub.corp.com/page", TokenKeys{Secret: testSecret}, []string{"corp.com"}, "msg-1", 1)
	if ok {
		t.Error("sub.corp.com should be considered internal when corp.com is internal")
	}
}

func TestRewriteURL_InternalDomainExact(t *testing.T) {
	_, ok := rewriteURL("https://corp.com/page", TokenKeys{Secret: testSecret}, []string{"corp.com"}, "msg-1", 1)
	if ok {
		t.Error("corp.com exact match should be internal")
	}
}

func TestRewriteURL_NonHTTP(t *testing.T) {
	_, ok := rewriteURL("ftp://files.example.com", TokenKeys{Secret: testSecret}, nil, "msg-1", 1)
	if ok {
		t.Error("ftp:// URLs should not be rewritten")
	}
}

// --- Scanner Pipeline ---

type mockScanner struct {
	name   string
	v      Verdict
	err    error
	called *bool
}

func (m *mockScanner) Name() string { return m.name }
func (m *mockScanner) Check(ctx context.Context, url string) (Verdict, error) {
	if m.called != nil {
		*m.called = true
	}
	return m.v, m.err
}

func TestScanPipeline_FirstMaliciousShortCircuits(t *testing.T) {
	var thirdCalled bool
	scanners := []Scanner{
		&mockScanner{name: "safe-scan", v: VerdictSafe},
		&mockScanner{name: "mal-scan", v: VerdictMalicious},
		&mockScanner{name: "never-called", called: &thirdCalled, v: VerdictUnknown},
	}

	v, results, _ := ScanPipeline(context.Background(), scanners, "https://evil.com")
	if v != VerdictMalicious {
		t.Errorf("expected VerdictMalicious, got %v", v)
	}
	if thirdCalled {
		t.Error("third scanner should not have been called (short-circuit)")
	}
	if results["mal-scan"] != VerdictMalicious {
		t.Errorf("expected mal-scan result VerdictMalicious, got %v", results["mal-scan"])
	}
}

func TestScanPipeline_AllSafe(t *testing.T) {
	scanners := []Scanner{
		&mockScanner{name: "sb", v: VerdictSafe},
		&mockScanner{name: "sh", v: VerdictSafe},
	}

	v, results, _ := ScanPipeline(context.Background(), scanners, "https://safe.com")
	if v != VerdictSafe {
		t.Errorf("expected VerdictSafe, got %v", v)
	}
	if results["sb"] != VerdictSafe || results["sh"] != VerdictSafe {
		t.Errorf("all scanners should report Safe: %v", results)
	}
}

func TestScanPipeline_AllUnknown(t *testing.T) {
	scanners := []Scanner{
		&mockScanner{name: "sb", v: VerdictUnknown},
		&mockScanner{name: "sh", v: VerdictUnknown},
	}

	v, _, _ := ScanPipeline(context.Background(), scanners, "https://unknown.com")
	if v != VerdictUnknown {
		t.Errorf("expected VerdictUnknown, got %v", v)
	}
}

func TestScanPipeline_AllErrors_Passthrough(t *testing.T) {
	scanners := []Scanner{
		&mockScanner{name: "sb", err: fmt.Errorf("timeout")},
		&mockScanner{name: "sh", err: fmt.Errorf("dns error")},
	}

	v, _, _ := ScanPipeline(context.Background(), scanners, "https://example.com")
	if v != VerdictUnknown {
		t.Errorf("expected VerdictUnknown (passthrough) when all scanners error, got %v", v)
	}
}

func TestScanPipeline_MixedSafeAndUnknown(t *testing.T) {
	scanners := []Scanner{
		&mockScanner{name: "sb", v: VerdictSafe},
		&mockScanner{name: "sh", v: VerdictUnknown},
	}

	v, _, _ := ScanPipeline(context.Background(), scanners, "https://mixed.com")
	if v != VerdictUnknown {
		t.Errorf("expected VerdictUnknown when mixed Safe+Unknown, got %v", v)
	}
}

func TestScanPipeline_EmptyScanners(t *testing.T) {
	v, results, _ := ScanPipeline(context.Background(), nil, "https://example.com")
	if v != VerdictSafe {
		t.Errorf("expected VerdictSafe for empty scanners, got %v", v)
	}
	if len(results) != 0 {
		t.Errorf("expected empty results, got %d", len(results))
	}
}

// --- HTTP Handler ---

// The verdict-routing decision (safe→302, malicious→block, unknown→warn, plus the
// all-errors passthrough and strict_mode unknown→malicious rules) now lives in the
// link_protect_check_and_audit reducer and is covered by
// mailserver/sql/tests/link_protect_check_and_audit.pg — the audit row and the
// verdict are produced in ONE transaction so the audit is durable before redirect.
// The Go handler is a thin translator; its DB-independent behaviours are: token
// validation (400s, below) and the FAIL-CLOSED-TO-WARN path when the audit write
// cannot happen (no durable audit row → never redirect).

// TestLinkProtectHandler_FailClosedToWarn is the load-bearing behaviour-change
// test for §C: when the click-audit write fails (here: no DB pool, so the reducer
// call cannot run), the handler shows the WARN interstitial instead of silently
// redirecting. A redirect without a durable audit row was the integrity gap this
// section closes. Holds for every base verdict — including a SAFE scan, which
// previously redirected on a nil pool.
func TestLinkProtectHandler_FailClosedToWarn(t *testing.T) {
	for _, base := range []Verdict{VerdictSafe, VerdictMalicious, VerdictUnknown} {
		t.Run(base.String(), func(t *testing.T) {
			scanners := []Scanner{&mockScanner{name: "sb", v: base}}
			// nil pool → decideAndAudit cannot write a durable audit row → fail closed.
			h := NewLinkProtectHandler(scanners, nil, testLogger(), nil, testSecret)
			token := buildToken("https://x.example.com")

			req := httptest.NewRequest(http.MethodGet, "/link-protect?token="+token, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("fail-closed must render the warn page (200), got %d", rec.Code)
			}
			if rec.Header().Get("Location") != "" {
				t.Errorf("fail-closed must NOT redirect; got Location %q", rec.Header().Get("Location"))
			}
			body := rec.Body.String()
			if !strings.Contains(body, "Unverified") && !strings.Contains(body, "Continue") {
				t.Error("expected warn interstitial when audit fails")
			}
		})
	}
}

// TestLinkProtectHandler_ConfirmRequiresAudit verifies that even the explicit
// confirm=1 continue link does not redirect when the audit write fails — the
// fail-closed guard runs before the confirm short-circuit.
func TestLinkProtectHandler_ConfirmRequiresAudit(t *testing.T) {
	scanners := []Scanner{&mockScanner{name: "sb", v: VerdictUnknown}}
	h := NewLinkProtectHandler(scanners, nil, testLogger(), nil, testSecret)
	token := buildToken("https://unknown.example.com")

	req := httptest.NewRequest(http.MethodGet, "/link-protect?token="+token+"&confirm=1", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code == http.StatusFound {
		t.Error("confirm=1 must not redirect when the audit write fails (fail-closed)")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 warn page on fail-closed confirm, got %d", rec.Code)
	}
}

func TestLinkProtectHandler_ExpiredToken(t *testing.T) {
	h := NewLinkProtectHandler(nil, nil, testLogger(), nil, testSecret)

	claims := TokenClaims{
		URL:       "https://example.com",
		MessageID: "msg-test",
		MailboxID: 1,
		ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(),
	}
	token, _ := SignToken(claims, testSecret)

	req := httptest.NewRequest(http.MethodGet, "/link-protect?token="+token, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for expired token, got %d", rec.Code)
	}
}

func TestLinkProtectHandler_TamperedToken(t *testing.T) {
	h := NewLinkProtectHandler(nil, nil, testLogger(), nil, testSecret)

	token := buildToken("https://example.com")
	tampered := token[:len(token)-3] + "XXX"

	req := httptest.NewRequest(http.MethodGet, "/link-protect?token="+tampered, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for tampered token, got %d", rec.Code)
	}
}

func TestLinkProtectHandler_MissingToken(t *testing.T) {
	h := NewLinkProtectHandler(nil, nil, testLogger(), nil, testSecret)

	req := httptest.NewRequest(http.MethodGet, "/link-protect", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing token, got %d", rec.Code)
	}
}

// The all-errors passthrough rule (every scanner unreachable → unknown, never
// block on a third-party outage) is now a reducer rule asserted in
// link_protect_check_and_audit.pg (case 2). At the Go handler level, without a
// durable audit row the passthrough still fails closed to warn — the scanner
// outage no longer lets a click slip through unaudited.
func TestLinkProtectHandler_AllScannersUnreachable_FailClosed(t *testing.T) {
	scanners := []Scanner{
		&mockScanner{name: "sb", err: fmt.Errorf("timeout")},
		&mockScanner{name: "sh", err: fmt.Errorf("dns error")},
	}

	h := NewLinkProtectHandler(scanners, nil, testLogger(), nil, testSecret)
	token := buildToken("https://example.com")

	req := httptest.NewRequest(http.MethodGet, "/link-protect?token="+token, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Header().Get("Location") != "" {
		t.Errorf("scanner outage must not redirect without a durable audit row; got %q", rec.Header().Get("Location"))
	}
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 warn page on fail-closed passthrough, got %d", rec.Code)
	}
}

// TestLinkProtectHandler_WarnPreservesURL verifies the (DB-free) warn interstitial
// echoes the original URL, including its query string, so the user can inspect it.
func TestLinkProtectHandler_WarnPreservesURL(t *testing.T) {
	scanners := []Scanner{&mockScanner{name: "sb", v: VerdictUnknown}}
	h := NewLinkProtectHandler(scanners, nil, testLogger(), nil, testSecret)
	token := buildToken("https://example.com/path?q=value&x=y")

	req := httptest.NewRequest(http.MethodGet, "/link-protect?token="+token, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 warn page, got %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "https://example.com/path?q=value&amp;x=y") &&
		!strings.Contains(rec.Body.String(), "https://example.com/path?q=value&x=y") {
		t.Errorf("expected original URL preserved in warn page body")
	}
}

// --- Verdict String ---

func TestVerdict_String(t *testing.T) {
	if VerdictSafe.String() != "safe" {
		t.Errorf("expected 'safe', got %q", VerdictSafe.String())
	}
	if VerdictMalicious.String() != "malicious" {
		t.Errorf("expected 'malicious', got %q", VerdictMalicious.String())
	}
	if VerdictUnknown.String() != "unknown" {
		t.Errorf("expected 'unknown', got %q", VerdictUnknown.String())
	}
}

// --- escapeHTML ---

func TestEscapeHTML(t *testing.T) {
	tests := []struct {
		input, expected string
	}{
		{"hello", "hello"},
		{"<script>", "&lt;script&gt;"},
		{"a & b", "a &amp; b"},
		{`"quoted"`, "&quot;quoted&quot;"},
		{"it's", "it&#39;s"},
		{"<a href='x'>&", "&lt;a href=&#39;x&#39;&gt;&amp;"},
	}

	for _, tc := range tests {
		got := escapeHTML(tc.input)
		if got != tc.expected {
			t.Errorf("escapeHTML(%q) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

// --- UnwrapMessageBody (LINK-PROTECT egress rail, Track A2) ---

func TestUnwrapMessageBody_RoundTripsRewrittenURLs(t *testing.T) {
	orig := []byte("Visit https://store.example.com/buy?id=7 and https://news.example.org soon.")
	rewritten, n, err := rewritePlainText(string(orig), TokenKeys{Secret: testSecret}, nil, "msg-1", 42)
	if err != nil || n != 2 {
		t.Fatalf("rewrite setup: n=%d err=%v", n, err)
	}
	if !strings.Contains(rewritten, "/link-protect?token=") {
		t.Fatalf("expected rewritten body to contain protected redirects, got %q", rewritten)
	}

	unwrapped, count, err := UnwrapMessageBody([]byte(rewritten), testSecret)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 URLs unwrapped, got %d", count)
	}
	got := string(unwrapped)
	if !strings.Contains(got, "https://store.example.com/buy?id=7") ||
		!strings.Contains(got, "https://news.example.org") {
		t.Errorf("unwrapped body missing original URLs: %q", got)
	}
	if strings.Contains(got, "/link-protect?token=") {
		t.Errorf("unwrapped body still contains a protected redirect: %q", got)
	}
}

func TestUnwrapMessageBody_AbsoluteRedirectHost(t *testing.T) {
	token := buildToken("https://vendor.example.com/promo")
	body := []byte(`<a href="https://mail.mycorp.com/link-protect?token=` + token + `">click</a>`)
	unwrapped, count, err := UnwrapMessageBody(body, testSecret)
	if err != nil || count != 1 {
		t.Fatalf("unwrap: count=%d err=%v", count, err)
	}
	if !strings.Contains(string(unwrapped), `href="https://vendor.example.com/promo"`) {
		t.Errorf("absolute redirect not unwrapped: %q", string(unwrapped))
	}
}

func TestUnwrapMessageBody_LeavesForeignTokenUntouched(t *testing.T) {
	// A token signed with a DIFFERENT secret must not be trusted/substituted.
	foreign := []byte("hi")
	otherSecret := []byte("a-completely-different-secret-key")
	claims := TokenClaims{URL: "https://evil.example/x", ExpiresAt: time.Now().Add(tokenExpiry).Unix()}
	tok, _ := SignToken(claims, otherSecret)
	body := []byte("/link-protect?token=" + tok)
	unwrapped, count, err := UnwrapMessageBody(body, testSecret)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if count != 0 {
		t.Errorf("foreign-secret token must not be unwrapped, got count=%d", count)
	}
	if string(unwrapped) != string(body) {
		t.Errorf("body changed for foreign token: %q", string(unwrapped))
	}
	_ = foreign
}

func TestUnwrapMessageBody_NoProtectedURLs(t *testing.T) {
	body := []byte("Plain text with https://example.com and no redirects.")
	unwrapped, count, err := UnwrapMessageBody(body, testSecret)
	if err != nil || count != 0 {
		t.Fatalf("unwrap: count=%d err=%v", count, err)
	}
	if string(unwrapped) != string(body) {
		t.Errorf("body should be unchanged: %q", string(unwrapped))
	}
}

// TestRewriteMessageBody_CapitalBoundary is the regression for the case-sensitive
// TrimPrefix bug: a sender using "Boundary=" (capital B, valid per RFC 2045)
// must still have its parts split + URLs rewritten. Before the fix, extractBoundary
// returned "Boundary=xyz" verbatim, splitMIMEParts found no "--Boundary=xyz"
// delimiters, and the whole body passed through unrewritten (count 0).
func TestRewriteMessageBody_CapitalBoundary(t *testing.T) {
	boundary := "----boundary123"
	body := "From: test@test.com\r\nTo: user@test.com\r\nSubject: Test\r\nContent-Type: multipart/mixed; Boundary=\"" + boundary + "\"\r\n\r\n" +
		"This is preamble\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/plain\r\n\r\n" +
		"Visit https://evil.com\r\n" +
		"--" + boundary + "\r\n" +
		"Content-Type: text/html\r\n\r\n" +
		"<html><a href=\"https://evil2.com\">click</a></html>\r\n" +
		"--" + boundary + "--\r\n"

	rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody failed: %v", err)
	}
	if count != 2 {
		t.Fatalf("capital Boundary= must not bypass rewriting; expected 2 URLs, got %d", count)
	}
	if strings.Count(string(rewritten), "/link-protect?token=") != 2 {
		t.Error("expected 2 /link-protect tokens in output")
	}
}

// TestRewriteMessageBody_CapitalBoundary also covers the retirement of the old
// extractBoundary helper (med-shard2-003 duplicate reconciliation): boundary
// extraction now goes through mimeutil.ExtractBoundaryStrict, whose
// case-insensitive parameter handling is pinned end-to-end by this test
// (capital "Boundary=" must still split + rewrite). The former
// TestExtractBoundary_PreservesValueCase unit test pinned the deleted
// substring-scavenging helper and was retired with it; the boundary VALUE case
// discipline is enforced by mimeutil's own tests.

// TestSpamhausScanner_NXDOMAINIsSafe: NXDOMAIN is the DBL "not listed" signal.
func TestSpamhausScanner_NXDOMAINIsSafe(t *testing.T) {
	s := &SpamhausDBLScanner{lookupHost: func(_ context.Context, _ string) ([]string, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "x.dbl.spamhaus.org", IsNotFound: true}
	}}
	v, err := s.Check(context.Background(), "https://example.com")
	if err != nil || v != VerdictSafe {
		t.Fatalf("NXDOMAIN must be Safe/nil; got %v err=%v", v, err)
	}
}

// TestSpamhausScanner_OutageIsUnknown is the fail-safe regression: a network
// timeout/SERVFAIL is a scanner OUTAGE, not a clean result. It must surface as
// VerdictUnknown + a non-nil error so ScanPipeline counts it toward allErrors —
// the old code returned VerdictSafe and silently defeated the passthrough rail.
func TestSpamhausScanner_OutageIsUnknown(t *testing.T) {
	for name, lerr := range map[string]error{
		"timeout":         &net.DNSError{Err: "i/o timeout", Name: "x", IsTimeout: true},
		"servfail":        &net.DNSError{Err: "server misbehaving", Name: "x"},
		"non-dns network": errors.New("network is unreachable"),
	} {
		t.Run(name, func(t *testing.T) {
			s := &SpamhausDBLScanner{lookupHost: func(_ context.Context, _ string) ([]string, error) {
				return nil, lerr
			}}
			v, err := s.Check(context.Background(), "https://example.com")
			if v != VerdictUnknown || err == nil {
				t.Fatalf("outage must be Unknown + error; got %v err=%v", v, err)
			}
		})
	}
}

// TestTokenKeyDomainSeparation pins the INV6-KEY-SEPARATION hardening
// (D-MAILSERVER-INTERNAL-LINKPROTECT-007): the token HMAC is computed under a
// purpose-derived key, so the raw caller secret (the gateway JWT secret, which
// also keys other token formats) can neither forge nor verify link-protect
// tokens, and round-trips through the package keep working.
func TestTokenKeyDomainSeparation(t *testing.T) {
	claims := TokenClaims{
		URL:       "https://example.com/page",
		MessageID: "msg-1",
		MailboxID: 7,
		ExpiresAt: time.Now().Add(time.Hour).Unix(),
	}
	token, err := SignToken(claims, testSecret)
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}
	if _, err := VerifyToken(token, testSecret); err != nil {
		t.Fatalf("derive-and-verify round trip failed: %v", err)
	}

	// A token forged with the RAW secret under the historical construction
	// (HMAC(raw secret, payload)) must not verify: the two derivations are
	// domain-separated, so a leaked-or-reused raw secret no longer signs
	// valid link-protect tokens.
	payloadB64, _, ok := strings.Cut(token, ".")
	if !ok {
		t.Fatalf("token %q has no separator", token)
	}
	mac := hmac.New(sha256.New, testSecret)
	mac.Write([]byte(payloadB64))
	legacyForged := payloadB64 + "." + base64.URLEncoding.EncodeToString(mac.Sum(nil))
	if legacyForged == token {
		t.Fatal("derived-key signature must differ from the raw-secret signature")
	}
	if _, err := VerifyToken(legacyForged, testSecret); err == nil {
		t.Fatal("raw-secret forged token must not verify")
	}
	// A different purpose label must derive a different key.
	other := tokenKey([]byte("other-purpose-secret"))
	thisKey := tokenKey(testSecret)
	if hmac.Equal(other, thisKey) {
		t.Fatal("different secrets must derive different token keys")
	}
}
