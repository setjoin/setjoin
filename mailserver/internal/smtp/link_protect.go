package smtp

// Link-protect token seams for the live SMTP delivery path.
//
// CONTRACT ALIGNMENT (med-shard2-003 round 2, adjudication): the approved row
// requires the shared linkprotect copy and this live path to satisfy the SAME
// contract. The formerly duplicated rewrite implementation here diverged in
// four ways (unanchored idempotence bypass, a[href]-only coverage, no
// Content-Transfer-Encoding decode/re-encode, per-part absent Content-Type
// skip instead of the RFC 2045 §5.2 text/plain default). Rather than mirror a
// fourth copy, the live site now DELEGATES to the canonical shared
// implementation, so the two paths cannot diverge again:
//
//   - RewriteMessageBody (called by inbound.go's delivery pipeline) is a
//     direct delegate of linkprotect.RewriteMessageBody — anchored idempotence
//     (D-MAILSERVER-INTERNAL-LINKPROTECT-002), full URL-bearing attribute
//     coverage (-005), transfer-decoded base64/quoted-printable parts (-004),
//     absent-Content-Type text/plain default, and the strict mimeutil walker
//     with fail-closed ambiguity handling (D-MAILSERVER-INTERNAL-MIMEUTIL-001)
//     all hold here by construction;
//   - rewriteURL delegates to linkprotect.RewriteURL so the per-URL decisions
//     (internal-domain exemption, scheme coverage, signing) stay identical to
//     the shared copy and the click-time scanner target;
//   - token minting/verification (SignToken/VerifyToken/TokenClaims) remains
//     in this package: the inbound rewrite, the click handler, and the tests
//     share these exact seams.
//
// On rewrite error the delivery caller MUST NOT deliver the original: a parse,
// walk, or decode failure means the body was never proven scanner-visible, so
// the delivery path quarantines fail-closed (D-MAILSERVER-INTERNAL-MIMEUTIL-001).

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"setjoin.com/mailserver/internal/linkprotect"
)

// TokenClaims is the payload embedded in a link-protect token.
type TokenClaims struct {
	URL       string `json:"u"` // original URL
	MessageID string `json:"m"` // message ID for audit trail
	MailboxID int64  `json:"b"` // recipient mailbox ID for audit trail
	ExpiresAt int64  `json:"e"` // Unix timestamp (30-day expiry from sign time)
}

// tokenExpiry is the lifetime of a link-protect token.
//
//nolint:unused // token-lifetime seam: link_protect_test.go and link_protect_e2e_test.go build expiry-dated claims from it (run.tests:false hides their usage)
const tokenExpiry = 30 * 24 * time.Hour

// SignToken creates a self-contained HMAC-SHA256 signed token.
// Format: base64(payload).base64(signature)
func SignToken(claims TokenClaims, secret []byte) (string, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("link_protect: marshal claims: %w", err)
	}

	payloadB64 := base64.URLEncoding.EncodeToString(payload)

	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payloadB64))
	sig := mac.Sum(nil)
	sigB64 := base64.URLEncoding.EncodeToString(sig)

	return payloadB64 + "." + sigB64, nil
}

// VerifyToken validates a token string and returns the claims if valid.
// Returns an error if the token is tampered, expired, or malformed.
func VerifyToken(tokenStr string, secret []byte) (*TokenClaims, error) {
	parts := strings.SplitN(tokenStr, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("link_protect: invalid token format")
	}

	payloadB64, sigB64 := parts[0], parts[1]

	// Verify signature
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payloadB64))
	expectedSig := mac.Sum(nil)

	sig, err := base64.URLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("link_protect: invalid signature encoding")
	}

	if !hmac.Equal(sig, expectedSig) {
		return nil, fmt.Errorf("link_protect: token signature mismatch")
	}

	// Decode payload
	payload, err := base64.URLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("link_protect: invalid payload encoding")
	}

	var claims TokenClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("link_protect: invalid claims: %w", err)
	}

	// Check expiry
	if time.Now().Unix() > claims.ExpiresAt {
		return nil, fmt.Errorf("link_protect: token expired")
	}

	return &claims, nil
}

// RewriteMessageBody rewrites all external URLs in an email message body to
// /link-protect?token=... proxy URLs. It is a DIRECT DELEGATE of the canonical
// shared implementation (see the package-contract comment above): the live
// inbound delivery site and the shared linkprotect copy run the exact same
// MIME-aware rewrite — transfer-decoded parts, full attribute coverage,
// anchored idempotence, RFC 2045 §5.2 absent-Content-Type default. It signs
// under the VERSION-1 key of secret; the live delivery site uses the
// versioned RewriteMessageBodyN with the configured key set.
func RewriteMessageBody(data []byte, secret []byte, internalDomains []string, msgID string, mailboxID int64) ([]byte, int, error) {
	return linkprotect.RewriteMessageBody(data, secret, internalDomains, msgID, mailboxID)
}

// RewriteMessageBodyN is the key-set-aware delivery seam (MAILSERVERD-004
// dual-key overlap rotation): the live inbound delivery site passes the
// configured versioned key set so freshly minted redirect tokens carry the
// CURRENT key version — a token delivered after a rotation verifies by the
// current key alone, and draining the overlap window cannot strand it. Direct
// delegate of linkprotect.RewriteMessageBodyN; the rewrite contract terms are
// identical.
func RewriteMessageBodyN(data []byte, keys linkprotect.TokenKeys, internalDomains []string, msgID string, mailboxID int64) ([]byte, int, error) {
	return linkprotect.RewriteMessageBodyN(data, keys, internalDomains, msgID, mailboxID)
}

// rewriteURL delegates to the canonical shared rewriter. Kept as the live
// per-URL seam for the authority corpus (link_protect_corpus_test.go) and the
// internal-domain exemption tests: classification here is by construction the
// same net/url authority discipline the click-time Spamhaus scanner applies.
//
//nolint:unused // per-URL seam exercised by link_protect_corpus_test.go and link_protect_test.go (the latter is outside the r2 dispatch write scope)
func rewriteURL(rawURL string, secret []byte, internalDomains []string, msgID string, mailboxID int64) (string, bool) {
	return linkprotect.RewriteURL(rawURL, secret, internalDomains, msgID, mailboxID)
}
