package smtp

// Occurrence-specific tests for the ER5 smtp-lane link-protect rewrite-
// exemption finding (protection-bypass/link-protect-rewrite-exemption): the
// idempotence guard must exempt ONLY the exact host-relative redirect shape
// this package emits. The live site (link_protect.go rewriteURL) delegates to
// the canonical linkprotect.rewriteURL whose anchored isOwnRedirect guard
// (D-MAILSERVER-INTERNAL-LINKPROTECT-002) replaced the old unanchored
// strings.Contains(url, "/link-protect?token=") check that let any sender
// embed that substring in an EXTERNAL url to skip rewriting, the scan
// pipeline, the interstitial, and click auditing entirely.
//
// The userinfo/authority classification companion finding
// (url-validation/link-protect-userinfo-host-confusion) is pinned against this
// same live seam by link_protect_corpus_test.go
// (TestLiveRewriteSite_URLAuthorityCorpus,
// TestLiveRewriteSite_ClassifierIdentity) and
// TestRewriteMessageBody_UserinfoAttackerURL_IsRewritten.

import (
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/linkprotect"
)

// TestRewriteURL_DecoyProtectedSubstringStillRewritten is the finding's
// bypass: an EXTERNAL url carrying "/link-protect?token=" as a decoy query
// parameter must not skip the rewrite.
func TestRewriteURL_DecoyProtectedSubstringStillRewritten(t *testing.T) {
	decoy := "https://evil.test/?u=/link-protect?token=AAAA.BBBB"
	if _, ok := rewriteURL(decoy, testSecret, nil, "msg-1", 1); !ok {
		t.Fatalf("external URL with decoy protected substring must be rewritten: %q", decoy)
	}
}

// TestRewriteURL_PathSuffixDecoyStillRewritten: a decoy in the PATH segment
// (the old guard matched the substring anywhere) must not skip the rewrite.
func TestRewriteURL_PathSuffixDecoyStillRewritten(t *testing.T) {
	decoy := "https://evil.test/link-protect?token=AAAA.BBBB"
	got, ok := rewriteURL(decoy, testSecret, nil, "msg-1", 1)
	if !ok {
		t.Fatalf("absolute external lookalike must be rewritten as sender content: %q", decoy)
	}
	if !strings.HasPrefix(got, "/link-protect?token=") {
		t.Fatalf("rewrite output = %q, want a fresh /link-protect token", got)
	}
	claims, err := linkprotect.VerifyToken(strings.TrimPrefix(got, "/link-protect?token="), testSecret)
	if err != nil {
		t.Fatalf("minted token does not verify: %v", err)
	}
	if claims.URL != decoy {
		t.Fatalf("token destination = %q, want the full attacker URL %q", claims.URL, decoy)
	}
}

// TestRewriteURL_ProtocolRelativeDecoyStillRewritten: protocol-relative URLs
// inherit http(s) in every rendering context, so a decoy-bearing
// protocol-relative value is navigated content and must be rewritten.
func TestRewriteURL_ProtocolRelativeDecoyStillRewritten(t *testing.T) {
	decoy := "//evil.test/x/link-protect?token=AAAA.BBBB"
	if _, ok := rewriteURL(decoy, testSecret, nil, "msg-1", 1); !ok {
		t.Fatalf("protocol-relative decoy must be rewritten: %q", decoy)
	}
}

// TestRewriteURL_HostRelativeOwnRedirectExempted pins the preserved exemption:
// the EXACT emitted shape (host-relative path /link-protect with a token
// parameter) stays exempt, so a re-delivered/forwarded body is not
// double-rewritten.
func TestRewriteURL_HostRelativeOwnRedirectExempted(t *testing.T) {
	own := "/link-protect?token=existing.payloadsig"
	if got, ok := rewriteURL(own, testSecret, nil, "msg-1", 1); ok || got != own {
		t.Fatalf("host-relative own redirect must be exempt (got %q ok=%v)", got, ok)
	}
}

// TestRewriteMessageBody_ExternalDecoySubstringIsRewritten runs the finding
// end-to-end through the live delivery-site rewriter: the HTML body's decoy
// link must come out protected (tokenized), never delivered verbatim.
func TestRewriteMessageBody_ExternalDecoySubstringIsRewritten(t *testing.T) {
	decoy := "https://evil.test/x#/link-protect?token=AAAA.BBBB"
	body := "From: attacker@evil.test\r\nTo: user@test.local\r\nSubject: decoy\r\n" +
		"Content-Type: text/html\r\n\r\n" +
		"<html><body><a href=\"" + decoy + "\">click</a></body></html>"
	rewritten, count, err := RewriteMessageBody([]byte(body), testSecret, nil, "msg-1", 1)
	if err != nil {
		t.Fatalf("RewriteMessageBody: %v", err)
	}
	if count != 1 {
		t.Fatalf("decoy-substring URL must be rewritten, got count=%d", count)
	}
	out := string(rewritten)
	if strings.Contains(out, decoy) {
		t.Errorf("decoy URL delivered verbatim (rewrite bypassed): %s", out)
	}
	tokens := tokenURLs(out)
	if len(tokens) != 1 {
		t.Fatalf("expected exactly 1 protected redirect, got %d in %q", len(tokens), out)
	}
	claims, err := linkprotect.VerifyToken(tokens[0], testSecret)
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if claims.URL != decoy {
		t.Errorf("token destination = %q, want %q", claims.URL, decoy)
	}
}
