package smtp

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
)

// testSecret is a fixed key for deterministic test tokens.
var testSecret = []byte("test-secret-key-32-bytes-long!")

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
		ExpiresAt: time.Now().Add(-1 * time.Hour).Unix(), // expired 1 hour ago
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

	// Tamper with the token by changing a character in the payload
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

	// Should still verify
	verified, err := VerifyToken(signed, testSecret)
	if err != nil {
		t.Fatalf("VerifyToken with empty claims failed: %v", err)
	}
	if verified.URL != "" {
		t.Errorf("expected empty URL, got %q", verified.URL)
	}
}

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

// TestRewriteMessageBody_AbsentContentTypeDefaultsToPlainText (med-shard2-021
// item 1): RFC 2045 §5.2 makes a header-less body US-ASCII text/plain, so a
// valid plain-text message that omits the header must be REWRITTEN, not
// quarantined — the old code fed the empty header to the strict boundary
// extractor and failed closed on every such message.
func TestRewriteMessageBody_AbsentContentTypeDefaultsToPlainText(t *testing.T) {
	body := "From: test@test.com\r\nTo: user@test.com\r\nSubject: Test\r\n\r\nVisit https://evil.com for details"
	rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("header-less message must take the default text/plain path, got error: %v", err)
	}
	if count != 1 {
		t.Errorf("expected the plain-text URL rewritten, got count=%d", count)
	}
	rewrittenStr := string(rewritten)
	if !strings.Contains(rewrittenStr, "/link-protect?token=") || strings.Contains(rewrittenStr, "https://evil.com") {
		t.Errorf("default text/plain rewrite did not run: %q", rewrittenStr)
	}
}

// TestRewriteMessageBody_PresentMalformedContentTypeStillFailsClosed: the
// default only applies to an ABSENT header — a PRESENT but unparseable
// Content-Type is the first-boundary-decoy state and must still error (the
// delivery caller quarantines).
func TestRewriteMessageBody_PresentMalformedContentTypeStillFailsClosed(t *testing.T) {
	body := "From: test@test.com\r\nTo: user@test.com\r\nSubject: Test\r\n" +
		"Content-Type: multipart/mixed; boundary=\"unterminated\r\n\r\n" +
		"--unterminated--\r\n"
	if _, _, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1); err == nil {
		t.Errorf("malformed PRESENT Content-Type must fail closed, got nil error")
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
	// The calendar part URL should still be the original
	if !strings.Contains(rewrittenStr, "https://should-not-rewrite.com") {
		t.Error("text/calendar part URLs should not be rewritten")
	}
}

func TestRewriteURL_InternalDomainSubdomain(t *testing.T) {
	_, ok := rewriteURL("https://sub.corp.com/page", testSecret, []string{"corp.com"}, "msg-1", 1)
	if ok {
		t.Error("sub.corp.com should be considered internal when corp.com is internal")
	}
}

func TestRewriteURL_InternalDomainExact(t *testing.T) {
	_, ok := rewriteURL("https://corp.com/page", testSecret, []string{"corp.com"}, "msg-1", 1)
	if ok {
		t.Error("corp.com exact match should be internal")
	}
}

func TestRewriteURL_NonHTTP(t *testing.T) {
	_, ok := rewriteURL("ftp://files.example.com", testSecret, nil, "msg-1", 1)
	if ok {
		t.Error("ftp:// URLs should not be rewritten")
	}
}

// mockScanner is a Scanner implementation for testing ScanPipeline.
type mockScanner struct {
	name    string
	verdict Verdict
	err     error
	called  *bool // tracks whether this scanner was called
}

func (m *mockScanner) Name() string { return m.name }
func (m *mockScanner) Check(ctx context.Context, url string) (Verdict, error) {
	if m.called != nil {
		*m.called = true
	}
	return m.verdict, m.err
}

func TestScanPipeline_FirstMaliciousShortCircuits(t *testing.T) {
	var thirdCalled bool
	scanners := []Scanner{
		&mockScanner{name: "safe-scan", verdict: VerdictSafe},
		&mockScanner{name: "mal-scan", verdict: VerdictMalicious},
		&mockScanner{name: "never-called", called: &thirdCalled, verdict: VerdictUnknown},
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
		&mockScanner{name: "sb", verdict: VerdictSafe},
		&mockScanner{name: "sh", verdict: VerdictSafe},
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
		&mockScanner{name: "sb", verdict: VerdictUnknown},
		&mockScanner{name: "sh", verdict: VerdictUnknown},
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
		&mockScanner{name: "sb", verdict: VerdictSafe},
		&mockScanner{name: "sh", verdict: VerdictUnknown},
	}

	v, _, _ := ScanPipeline(context.Background(), scanners, "https://mixed.com")
	// Unknown should win since there's at least one Unknown
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

	// Token should have payload.sig format
	parts := strings.Split(signed, ".")
	if len(parts) != 2 {
		t.Fatalf("expected token in format payload.sig, got %d parts", len(parts))
	}
	if parts[0] == "" || parts[1] == "" {
		t.Fatal("token parts should not be empty")
	}
}
