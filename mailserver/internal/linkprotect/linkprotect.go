// Package linkprotect provides time-of-click URL protection for email.
//
// At SMTP delivery time, external URLs in message bodies are rewritten to
// /link-protect?token=... proxy URLs. At click time, the token is verified
// and the destination is checked against threat intelligence (Safe Browsing
// API, Spamhaus DBL) before redirecting or showing an interstitial.
//
// Rewrite and unwrap are MIME-aware (med-shard2-003): both operate ONLY on
// transfer-decoded part bodies — base64 and quoted-printable parts are
// decoded before scanning and re-encoded afterwards — never on raw message
// bytes, and never across MIME boundaries (multipart walking is delegated to
// the shared strict mimeutil walker). Unwrap splices the original URL back
// per output context: HTML attribute values are entity-encoded and
// delimiter-quoted by the HTML serializer, plain-text contexts emit inert
// text, HTML raw-text contexts (script/iframe children, which the serializer
// emits literally) retain the redirect, and an unknown context re-materializes
// only provably inert destinations. Destinations themselves round-trip
// byte-faithfully.
package linkprotect

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/quotedprintable"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/html"

	"setjoin.com/mailserver/internal/mimeutil"
)

// TokenClaims is the payload embedded in a link-protect token.
type TokenClaims struct {
	URL       string `json:"u"` // original URL
	MessageID string `json:"m"` // message ID for audit trail
	MailboxID int64  `json:"b"` // recipient mailbox ID for audit trail
	ExpiresAt int64  `json:"e"` // Unix timestamp (30-day expiry from sign time)
}

// tokenExpiry is the lifetime of a link-protect token.
const tokenExpiry = 30 * 24 * time.Hour

// tokenKeyInfo is the domain-separation label for the VERSION-1 token HMAC
// key (D-MAILSERVER-INTERNAL-LINKPROTECT-007, INV6-KEY-SEPARATION): link-protect
// tokens must not be keyed directly by the caller's long-lived secret (the
// gateway JWT secret, which also keys other token formats). Deriving the HMAC
// key through a keyed PRF bound to this token's purpose means a compromise or
// reuse of the raw secret for another consumer cannot forge or verify
// link-protect tokens, and vice versa.
//
// MAILSERVERD-004 (dual-key overlap rotation) made the label VERSIONED:
// tokenKeyInfoN(version) renders the per-version label, and version 1 renders
// EXACTLY this historical string so every pre-rotation token keeps verifying.
//
//nolint:unused // version-1 label pin: the rotation-compatibility anchor asserted byte-identical by TestTokenKeyN_Version1MatchesLegacy (run.tests:false hides its test usage)
const tokenKeyInfo = "link-protect-v1: link-protect token hmac key"

// tokenKeyVersion1 is the initial link-protect key version. It is the default
// whenever no explicit key configuration is wired (behavior OFF unless
// separately admitted): version 1 derivation is byte-identical to the
// pre-rotation key.
const tokenKeyVersion1 = 1

// tokenKeyInfoN renders the versioned domain-separation label for the token
// HMAC key. Version 1 must render byte-identically to the historical
// tokenKeyInfo label (pinned by TestTokenKeyN_Version1MatchesLegacy): rotation
// must never orphan the tokens already delivered in live mail.
func tokenKeyInfoN(version int) string {
	return fmt.Sprintf("link-protect-v%d: link-protect token hmac key", version)
}

// tokenKey derives the purpose-specific HMAC-SHA256 key for version-1
// link-protect tokens: HMAC(secret, purpose label).
//
//nolint:unused // version-1 shorthand: production code signs/verifies through the versioned SignTokenN/VerifyTokenN forms; this is the historical derivation seam exercised by the key-separation and rotation tests (run.tests:false hides their usage)
func tokenKey(secret []byte) []byte {
	return tokenKeyN(secret, tokenKeyVersion1)
}

// tokenKeyN derives the purpose- and VERSION-specific HMAC-SHA256 key for
// link-protect tokens: HMAC(secret, versioned purpose label). Both the sign
// and the verify side flow through this package's SignTokenN/VerifyTokenN (or
// their version-1 shorthands SignToken/VerifyToken), so all sides derive
// identically. Distinct versions derive distinct keys — that separation is
// what makes overlap rotation safe: a token signed under the retiring key
// verifies only while the retiring key is explicitly configured for
// verification.
func tokenKeyN(secret []byte, version int) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(tokenKeyInfoN(version)))
	return mac.Sum(nil)
}

// TokenKeys is the versioned key set for link-protect token signing and
// verification (MAILSERVERD-004 dual-key overlap rotation).
//
// Rotation protocol: the operator supplies a NEW secret, bumps Version, and
// moves the retiring secret into PreviousSecret. Signing always uses
// Secret/Version ("current"); verification tries the current key first, then
// — during the transition window only — the PreviousSecret at Version-1, so
// tokens already delivered in live mail keep resolving for their 30-day
// lifetime. Draining (clearing PreviousSecret) ends the window: old-key
// tokens are rejected again. The token format itself is unchanged — there is
// deliberately no version prefix; the verify side tries the bounded
// (at most two) configured keys.
type TokenKeys struct {
	// Secret is the current master secret; Version (>= 1) selects its
	// derivation label. Signing uses this version and only this version.
	Secret  []byte
	Version int

	// PreviousSecret is the retiring (Version-1) master secret,
	// verification-only, for the rotation overlap window. Empty/nil = drained
	// (or no rotation): old-key tokens are rejected.
	PreviousSecret []byte
}

// NewTokenKeys builds a NORMALIZED TokenKeys from raw config values
// (MAILSERVERD-004): an unset/zero Version clamps to the version-1 default —
// byte-identical to the pre-rotation single-key derivation. This is the
// constructor every config→keys conversion should use, so a partially
// specified key set can never carry a version below the first generation.
func NewTokenKeys(secret, previousSecret []byte, version int) TokenKeys {
	return TokenKeys{Secret: secret, Version: version, PreviousSecret: previousSecret}.normalized()
}

// normalized clamps a possibly zero-valued key set to the safe version-1
// default: an unset Version (0) and a nil Secret behave exactly like the
// pre-rotation single-key wiring.
func (k TokenKeys) normalized() TokenKeys {
	if k.Version < tokenKeyVersion1 {
		k.Version = tokenKeyVersion1
	}
	return k
}

// previousTokenKey returns the derived verification key for the retiring
// secret, or nil when the window is drained (or the current version leaves no
// previous generation). The previous secret always corresponds to
// Version-1 — rotations move one generation at a time.
func (k TokenKeys) previousTokenKey() []byte {
	if len(k.PreviousSecret) == 0 || k.Version <= tokenKeyVersion1 {
		return nil
	}
	return tokenKeyN(k.PreviousSecret, k.Version-1)
}

// protectedPath is the path of the redirect URLs this package emits.
const protectedPath = "/link-protect"

// SignToken creates a self-contained HMAC-SHA256 signed token under the
// VERSION-1 key. Format: base64(payload).base64(signature). The versioned
// form is SignTokenN; version 1 is the default when no rotation is configured.
func SignToken(claims TokenClaims, secret []byte) (string, error) {
	return SignTokenN(claims, TokenKeys{Secret: secret, Version: tokenKeyVersion1})
}

// SignTokenN creates a self-contained HMAC-SHA256 signed token under the
// CURRENT key version of keys (MAILSERVERD-004). Format:
// base64(payload).base64(signature). Signing uses keys.Version ONLY — the
// previous key never signs, so every minted token is verifiable for its full
// 30-day lifetime by the current key alone (draining the previous key cannot
// strand a freshly minted token).
func SignTokenN(claims TokenClaims, keys TokenKeys) (string, error) {
	keys = keys.normalized()
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("link_protect: marshal claims: %w", err)
	}

	payloadB64 := base64.URLEncoding.EncodeToString(payload)

	mac := hmac.New(sha256.New, tokenKeyN(keys.Secret, keys.Version))
	mac.Write([]byte(payloadB64))
	sig := mac.Sum(nil)
	sigB64 := base64.URLEncoding.EncodeToString(sig)

	return payloadB64 + "." + sigB64, nil
}

// VerifyToken validates a token string under the VERSION-1 key and returns the
// claims if valid. Returns an error if the token is tampered, expired, or
// malformed. The rotation-aware form is VerifyTokenN.
func VerifyToken(tokenStr string, secret []byte) (*TokenClaims, error) {
	return VerifyTokenN(tokenStr, TokenKeys{Secret: secret, Version: tokenKeyVersion1})
}

// errTokenSignatureMismatch is the sentinel for a signature that matches none
// of the configured keys. VerifyTokenN falls through to the overlap key only
// on this condition — format/encoding/claims/expiry failures are
// key-independent and surface immediately.
var errTokenSignatureMismatch = errors.New("link_protect: token signature mismatch")

// VerifyTokenN validates a token string against the versioned key set
// (MAILSERVERD-004) and returns the claims if valid. Verification tries the
// CURRENT key (keys.Secret at keys.Version) first, then — only while
// keys.PreviousSecret is configured — the retiring key (keys.PreviousSecret at
// keys.Version-1). After the transition window is drained the previous key no
// longer verifies and old-key tokens are rejected. Returns an error if the
// token is tampered, expired, malformed, or signed under none of the
// configured keys.
func VerifyTokenN(tokenStr string, keys TokenKeys) (*TokenClaims, error) {
	keys = keys.normalized()
	currentKey := tokenKeyN(keys.Secret, keys.Version)
	claims, err := verifyTokenWithKey(tokenStr, currentKey)
	if err == nil {
		return claims, nil
	}
	if !errors.Is(err, errTokenSignatureMismatch) {
		return nil, err
	}
	prevKey := keys.previousTokenKey()
	if prevKey == nil {
		return nil, err
	}
	return verifyTokenWithKey(tokenStr, prevKey)
}

// verifyTokenWithKey validates a token string under ONE derived HMAC key.
// This is the single signature/expiry authority shared by every verify path.
func verifyTokenWithKey(tokenStr string, key []byte) (*TokenClaims, error) {
	parts := strings.SplitN(tokenStr, ".", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("link_protect: invalid token format")
	}

	payloadB64, sigB64 := parts[0], parts[1]

	// Verify signature
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payloadB64))
	expectedSig := mac.Sum(nil)

	sig, err := base64.URLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("link_protect: invalid signature encoding")
	}

	if !hmac.Equal(sig, expectedSig) {
		return nil, errTokenSignatureMismatch
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

// RewriteMessageBody parses an email message body and rewrites all
// external URLs to /link-protect?token=... proxy URLs.
// Returns the modified message, the number of URLs rewritten, and any error.
//
// RewriteMessageBody signs minted redirect tokens under the VERSION-1 key of
// secret. It is the pre-rotation shorthand for RewriteMessageBodyN — the live
// delivery path uses the versioned form with the configured key set so minted
// tokens always carry the current key version (MAILSERVERD-004). The full
// MIME-aware contract and fail-closed delivery rule are documented there and
// hold identically for this shorthand.
func RewriteMessageBody(data []byte, secret []byte, internalDomains []string, msgID string, mailboxID int64) ([]byte, int, error) {
	return RewriteMessageBodyN(data, TokenKeys{Secret: secret}, internalDomains, msgID, mailboxID)
}

// RewriteMessageBodyN is the VERSIONED form of RewriteMessageBody
// (MAILSERVERD-004 dual-key overlap rotation): minted redirect tokens are
// signed under the CURRENT key of keys (keys.Secret at keys.Version) and only
// that key, so a token delivered after a rotation verifies for its full
// 30-day lifetime by the current key alone — draining the overlap window
// cannot strand freshly delivered mail. Every other contract term below is
// unchanged.
//
// MIME-aware contract (med-shard2-003), aligned with the live smtp seam:
//   - only transfer-decoded part bodies are scanned; base64 and
//     quoted-printable parts are decoded before rewriting and re-encoded
//     afterwards, so a Content-Transfer-Encoding header can no longer move a
//     URL out of the rewrite path (D-MAILSERVER-INTERNAL-LINKPROTECT-004);
//   - multipart messages are walked by the shared strict mimeutil walker,
//     never by raw-byte splicing across MIME boundaries;
//   - a body with NO Content-Type defaults to RFC 2045 §5.2 text/plain
//     (med-shard2-021 item 1);
//   - every URL-bearing HTML attribute is rewritten, not just a[href]
//     (D-MAILSERVER-INTERNAL-LINKPROTECT-005).
//
// On error the caller MUST NOT deliver the original: a parse or decode
// failure means the body was never proven fully scanner-visible. (This
// replaces the abandoned fail-open "log a warning and deliver the original"
// prescription; the delivery path quarantines fail-closed — see
// D-MAILSERVER-INTERNAL-MIMEUTIL-001.)
func RewriteMessageBodyN(data []byte, keys TokenKeys, internalDomains []string, msgID string, mailboxID int64) ([]byte, int, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		return nil, 0, fmt.Errorf("link_protect: parse message: %w", err)
	}

	contentType := msg.Header.Get("Content-Type")
	if contentType == "" {
		// RFC 2045 §5.2: a body with no Content-Type header defaults to
		// US-ASCII text/plain. mail.ReadMessage already accepted the message,
		// so the header-less shape is a single text part — never the decoy
		// multipart framing the strict extractor guards against (an attacker
		// cannot frame boundaries through a header that is not there).
		return rewriteSinglePart(data, msg, keys, internalDomains, msgID, mailboxID)
	}
	_, isMultipart, err := mimeutil.ExtractBoundaryStrict(contentType)
	if err != nil {
		// Fail closed: an unparseable PRESENT Content-Type is exactly the
		// first-boundary-decoy state — the strict extractor never falls back
		// to an attacker-chosen token, and the caller quarantines.
		return nil, 0, fmt.Errorf("link_protect: %w", err)
	}
	if isMultipart {
		return rewriteMultipart(data, contentType, keys, internalDomains, msgID, mailboxID)
	}

	return rewriteSinglePart(data, msg, keys, internalDomains, msgID, mailboxID)
}

// rewriteMultipart rewrites external URLs in each text/html and text/plain
// LEAF part of a multipart message (the shared walker recurses into nested
// multipart containers), skipping text/calendar parts (iCalendar invites).
// Each leaf is transfer-decoded before rewriting and re-encoded afterwards,
// so the rewrite output stays a valid part of the same encoding; untouched
// parts are kept byte-exact. Parts are walked through the shared mimeutil
// splitter (RFC 2046 line-anchored, strict), so a boundary-lookalike inside
// a base64/binary part body never false-splits and an ambiguous framing
// surfaces as an error.
func rewriteMultipart(data []byte, contentType string, keys TokenKeys, internalDomains []string, msgID string, mailboxID int64) ([]byte, int, error) {
	total := 0
	var cbErr error
	out, err := mimeutil.WalkMIMEParts(contentType, data, func(partHeaders, partBody []byte) []byte {
		if cbErr != nil {
			return nil
		}
		ct := strings.ToLower(mimeutil.ExtractHeader(string(partHeaders), "Content-Type"))
		if strings.Contains(ct, "text/calendar") || !isRewriteTarget(ct) {
			return nil
		}
		decoded, cte, derr := decodeCTE(mimeutil.ExtractHeader(string(partHeaders), "Content-Transfer-Encoding"), partBody)
		if derr != nil {
			cbErr = derr
			return nil
		}
		rewritten, n, rerr := rewriteDecodedBody(decoded, ct, keys, internalDomains, msgID, mailboxID)
		if rerr != nil {
			cbErr = rerr
			return nil
		}
		if n == 0 {
			return nil // untouched part: keep the original bytes byte-exact
		}
		reencoded, eerr := encodeCTE(cte, rewritten)
		if eerr != nil {
			cbErr = eerr
			return nil
		}
		total += n
		return reencoded
	})
	if cbErr != nil {
		return nil, 0, cbErr
	}
	if err != nil {
		// Fail closed: a walker error means the multipart framing is
		// ambiguous (decoy delimiters, unparseable nested Content-Type,
		// missing blank line, missing close). Propagate so the delivery
		// caller quarantines instead of delivering a body that was never
		// fully scanner-visible (D-MAILSERVER-INTERNAL-MIMEUTIL-001).
		return nil, 0, err
	}
	return out, total, nil
}

// isRewriteTarget reports whether a leaf part (lowercased Content-Type,
// possibly empty) is a part whose transfer-decoded body this package rewrites
// or unwraps: text/html, text/plain, and the RFC 2045 §5.2 empty default
// (text/plain). Every other part is byte-exact untouched — its encoding is
// never decoded, so an exotic encoding in a binary attachment cannot fail a
// message that was never a rewrite target.
func isRewriteTarget(ct string) bool {
	return strings.Contains(ct, "text/html") || strings.Contains(ct, "text/plain") || ct == ""
}

// rewriteDecodedBody rewrites one transfer-DECODED part body of MIME type ct
// (lowercased, possibly empty). A part with no Content-Type defaults to
// text/plain per RFC 2045 §5.2 — a missing part header is not a coverage
// gap. Non-text parts are left to the caller (unchanged).
func rewriteDecodedBody(decoded []byte, ct string, keys TokenKeys, internalDomains []string, msgID string, mailboxID int64) ([]byte, int, error) {
	switch {
	case strings.Contains(ct, "text/html"):
		return rewriteHTML(decoded, keys, internalDomains, msgID, mailboxID)
	case strings.Contains(ct, "text/plain"), ct == "":
		rewritten, count, err := rewritePlainText(string(decoded), keys, internalDomains, msgID, mailboxID)
		if err != nil {
			return nil, 0, err
		}
		return []byte(rewritten), count, nil
	default:
		return decoded, 0, nil
	}
}

// rewriteSinglePart handles non-multipart messages: transfer-decode, rewrite,
// re-encode, splice back behind the header block. A message with zero
// rewrites is returned unchanged (byte-exact).
func rewriteSinglePart(data []byte, msg *mail.Message, keys TokenKeys, internalDomains []string, msgID string, mailboxID int64) ([]byte, int, error) {
	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("link_protect: read body: %w", err)
	}

	contentType := strings.ToLower(msg.Header.Get("Content-Type"))
	if contentType == "" {
		// RFC 2045 §5.2 default: a header-less body is US-ASCII text/plain.
		contentType = "text/plain"
	}
	if strings.Contains(contentType, "text/calendar") || !isRewriteTarget(contentType) {
		return data, 0, nil
	}

	decoded, cte, err := decodeCTE(msg.Header.Get("Content-Transfer-Encoding"), body)
	if err != nil {
		return nil, 0, err
	}
	rewritten, count, err := rewriteDecodedBody(decoded, contentType, keys, internalDomains, msgID, mailboxID)
	if err != nil {
		return nil, 0, err
	}
	if count == 0 {
		return data, 0, nil
	}
	reencoded, err := encodeCTE(cte, rewritten)
	if err != nil {
		return nil, 0, err
	}
	return rebuildMessage(data, reencoded), count, nil
}

// rebuildMessage replaces the body of a message while preserving headers.
func rebuildMessage(original []byte, newBody []byte) []byte {
	headerEnd := bytes.Index(original, []byte("\r\n\r\n"))
	if headerEnd < 0 {
		headerEnd = bytes.Index(original, []byte("\n\n"))
	}
	if headerEnd < 0 {
		return newBody
	}
	sep := "\r\n\r\n"
	if headerEnd+4 <= len(original) && string(original[headerEnd:headerEnd+4]) == "\r\n\r\n" {
		sep = "\r\n\r\n"
	} else {
		sep = "\n\n"
	}

	result := make([]byte, 0, headerEnd+len(sep)+len(newBody))
	result = append(result, original[:headerEnd]...)
	result = append(result, sep...)
	result = append(result, newBody...)

	return result
}

// decodeCTE decodes a transfer-encoded body according to its
// Content-Transfer-Encoding header value. base64 and quoted-printable bodies
// are decoded (D-MAILSERVER-INTERNAL-LINKPROTECT-004: their URLs must be
// scanner-visible); the identity encodings pass through unchanged; any other
// encoding is an ERROR (fail closed) — an undecodable body is a body whose
// URLs cannot be proven scanner-visible, and the caller must not rewrite
// (delivery: quarantine) or splice (unwrap: keep redirects) into it.
func decodeCTE(cte string, body []byte) ([]byte, string, error) {
	switch normalizeCTE(cte) {
	case "base64":
		clean := stripMIMEWhitespace(body)
		decoded := make([]byte, base64.StdEncoding.DecodedLen(len(clean)))
		n, err := base64.StdEncoding.Decode(decoded, clean)
		if err != nil {
			return nil, "base64", fmt.Errorf("link_protect: decode base64 body: %w", err)
		}
		return decoded[:n], "base64", nil
	case "quoted-printable":
		decoded, err := io.ReadAll(quotedprintable.NewReader(bytes.NewReader(body)))
		if err != nil {
			return nil, "quoted-printable", fmt.Errorf("link_protect: decode quoted-printable body: %w", err)
		}
		return decoded, "quoted-printable", nil
	case "", "7bit", "8bit", "binary":
		return body, "7bit", nil
	default:
		return nil, "", fmt.Errorf("link_protect: unsupported Content-Transfer-Encoding %q (fail closed)", cte)
	}
}

// encodeCTE re-encodes a rewritten body with the encoding reported by
// decodeCTE, so the part's Content-Transfer-Encoding header stays truthful.
// base64 wraps at the RFC 2045 76-column limit with CRLF; quoted-printable is
// re-encoded by the standard writer (76-column limit, CRLF breaks).
func encodeCTE(cte string, body []byte) ([]byte, error) {
	switch cte {
	case "base64":
		enc := base64.StdEncoding.EncodeToString(body)
		var buf bytes.Buffer
		for len(enc) > 76 {
			buf.WriteString(enc[:76])
			buf.WriteString("\r\n")
			enc = enc[76:]
		}
		buf.WriteString(enc)
		return buf.Bytes(), nil
	case "quoted-printable":
		var buf bytes.Buffer
		w := quotedprintable.NewWriter(&buf)
		if _, err := w.Write(body); err != nil {
			return nil, fmt.Errorf("link_protect: re-encode quoted-printable body: %w", err)
		}
		// Close flushes the writer's buffered final line. Without it, a body
		// with NO terminal newline loses its last (unterminated) line — the
		// token-bearing line could simply vanish from the re-encoded part
		// (Astra rereview med-shard2-003 item 2).
		if err := w.Close(); err != nil {
			return nil, fmt.Errorf("link_protect: close quoted-printable writer: %w", err)
		}
		return buf.Bytes(), nil
	default:
		return body, nil
	}
}

// normalizeCTE normalizes a Content-Transfer-Encoding header value to its
// lowercase encoding token (empty header → identity "7bit"-equivalent "").
func normalizeCTE(cte string) string {
	fields := strings.Fields(strings.ToLower(cte))
	if len(fields) == 0 {
		return ""
	}
	return fields[0]
}

// stripMIMEWhitespace removes the linear whitespace base64 bodies carry as
// CRLF line breaks so the decoder sees a clean alphabet stream.
func stripMIMEWhitespace(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		switch c {
		case ' ', '\t', '\r', '\n':
		default:
			out = append(out, c)
		}
	}
	return out
}

// rewriteHTML parses HTML and rewrites every URL-bearing attribute (see
// urlAttrs) plus CSS url()/@import targets in style attributes and <style>
// text. Parsing and re-rendering is the HTML output-context serialization:
// the renderer entity-encodes and delimiter-quotes attribute values, so a
// rewritten destination can never rematerialize live markup or CRLF.
func rewriteHTML(data []byte, keys TokenKeys, internalDomains []string, msgID string, mailboxID int64) ([]byte, int, error) {
	doc, err := html.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, 0, fmt.Errorf("link_protect: parse HTML: %w", err)
	}

	count := 0
	rewriteHTMLNode(doc, keys, internalDomains, msgID, mailboxID, &count)

	var buf bytes.Buffer
	if err := html.Render(&buf, doc); err != nil {
		return nil, 0, fmt.Errorf("link_protect: render HTML: %w", err)
	}

	return buf.Bytes(), count, nil
}

// urlAttrs are the URL-bearing HTML attributes the rewrite covers — every
// attribute a rendering client navigates or fetches: links (href), remote
// content (img/iframe/video/audio/source/input/embed via src, lowsrc,
// poster, background, data), forms (action, formaction), citation anchors
// (cite), and responsive image candidates (srcset). An external value in ANY
// of these used to be delivered verbatim with no token, interstitial, or
// click audit (open-tracking pixel exfiltration,
// D-MAILSERVER-INTERNAL-LINKPROTECT-005). <base href> is included
// deliberately: an external base would silently re-anchor this server's
// host-relative /link-protect redirects onto the attacker's origin.
var urlAttrs = map[string]bool{
	"href":       true,
	"src":        true,
	"lowsrc":     true,
	"action":     true,
	"formaction": true,
	"poster":     true,
	"background": true,
	"cite":       true,
	"data":       true,
	"srcset":     true,
}

// rewriteHTMLNode recursively walks HTML nodes and rewrites URLs.
func rewriteHTMLNode(n *html.Node, keys TokenKeys, internalDomains []string, msgID string, mailboxID int64, count *int) {
	if n.Type == html.ElementNode {
		for i, attr := range n.Attr {
			key := strings.ToLower(attr.Key)
			switch {
			case key == "style":
				rewritten, n2 := rewriteCSS(attr.Val, keys, internalDomains, msgID, mailboxID)
				if n2 > 0 {
					n.Attr[i].Val = rewritten
					*count += n2
				}
			case key == "srcset":
				rewritten, n2 := rewriteSrcset(attr.Val, keys, internalDomains, msgID, mailboxID)
				if n2 > 0 {
					n.Attr[i].Val = rewritten
					*count += n2
				}
			case urlAttrs[key]:
				newVal, ok := rewriteURL(attr.Val, keys, internalDomains, msgID, mailboxID)
				if ok {
					n.Attr[i].Val = newVal
					*count++
				}
			}
		}
	}
	if n.Type == html.TextNode && n.Parent != nil && strings.EqualFold(n.Parent.Data, "style") {
		rewritten, n2 := rewriteCSS(n.Data, keys, internalDomains, msgID, mailboxID)
		if n2 > 0 {
			n.Data = rewritten
			*count += n2
		}
	}

	// Walk children
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		rewriteHTMLNode(c, keys, internalDomains, msgID, mailboxID, count)
	}
}

// parseSrcsetCandidates returns the [start,end) byte spans of every candidate
// URL in an HTMLImageElement srcset value, per the WHATWG "parse a srcset
// attribute" algorithm: after skipping separator whitespace and commas, a URL
// is collected up to ASCII whitespace — commas BELONG to the URL unless the
// collected run ends in one, in which case the trailing commas terminate the
// candidate and no descriptor list follows; a whitespace-terminated URL is
// followed by descriptors up to the next comma. The naive strings.Split(val,
// ",") split a valid candidate like "https://evil.test/img,a.png 1x" mid-URL,
// signing a truncated destination and inventing a phantom candidate (Astra
// rereview med-shard2-003 item 5).
func parseSrcsetCandidates(val string) [][2]int {
	isSpace := func(c byte) bool {
		switch c {
		case ' ', '\t', '\n', '\f', '\r':
			return true
		}
		return false
	}
	var spans [][2]int
	pos := 0
	for {
		// Splitting loop: skip whitespace and commas.
		for pos < len(val) && (isSpace(val[pos]) || val[pos] == ',') {
			pos++
		}
		if pos >= len(val) {
			return spans
		}
		start := pos
		// URL: collect up to ASCII whitespace (commas may belong to the URL).
		for pos < len(val) && !isSpace(val[pos]) {
			pos++
		}
		end := pos
		if end > start && val[end-1] == ',' {
			// Trailing commas terminate the candidate: strip them from the URL.
			for end > start && val[end-1] == ',' {
				end--
			}
			spans = append(spans, [2]int{start, end})
			continue
		}
		// Descriptor list: everything up to the next comma (candidate
		// terminator) or end of value.
		for pos < len(val) && val[pos] != ',' {
			pos++
		}
		spans = append(spans, [2]int{start, end})
	}
}

// rewriteSrcset rewrites every external candidate URL of an HTMLImageElement
// srcset value using the WHATWG candidate parser (parseSrcsetCandidates).
// Separators and descriptors are preserved byte-exactly; only matched URL
// spans are replaced.
func rewriteSrcset(val string, keys TokenKeys, internalDomains []string, msgID string, mailboxID int64) (string, int) {
	spans := parseSrcsetCandidates(val)
	count := 0
	var b strings.Builder
	last := 0
	for _, sp := range spans {
		b.WriteString(val[last:sp[0]])
		u := val[sp[0]:sp[1]]
		if newURL, ok := rewriteURL(u, keys, internalDomains, msgID, mailboxID); ok {
			b.WriteString(newURL)
			count++
		} else {
			b.WriteString(u)
		}
		last = sp[1]
	}
	if count == 0 {
		return val, 0
	}
	b.WriteString(val[last:])
	return b.String(), count
}

// cssURLRe matches a CSS url() token carrying an absolute http(s) URL or a
// protocol-relative // URL. Both are externally fetched in every CSS context
// (a protocol-relative value inherits the page scheme), so both must pass
// through the interstitial like their absolute twins (Astra rereview
// med-shard2-003 item 4: url("//evil.test/pixel") used to stay a direct
// external fetch).
var cssURLRe = regexp.MustCompile(`(?i)url\(\s*['"]?((?:https?:)?//[^)'"\s]*)['"]?\s*\)`)

// cssImportRe matches a CSS @import string carrying an absolute http(s) or
// protocol-relative // URL (same coverage rationale as cssURLRe:
// @import "//evil.test/x.css" used to stay uncovered).
var cssImportRe = regexp.MustCompile(`(?i)@import\s+["']((?:https?:)?//[^'"\s]+)["']`)

// rewriteCSS rewrites url() and @import targets in a stylesheet or style
// attribute (CSS-borne remote fetches — backgrounds, custom fonts, imports —
// are tracking-exfiltration channels just like img src).
func rewriteCSS(css string, keys TokenKeys, internalDomains []string, msgID string, mailboxID int64) (string, int) {
	count := 0
	out := cssURLRe.ReplaceAllStringFunc(css, func(match string) string {
		sub := cssURLRe.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		newURL, ok := rewriteURL(sub[1], keys, internalDomains, msgID, mailboxID)
		if !ok {
			return match
		}
		count++
		return "url(" + newURL + ")"
	})
	out = cssImportRe.ReplaceAllStringFunc(out, func(match string) string {
		sub := cssImportRe.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		newURL, ok := rewriteURL(sub[1], keys, internalDomains, msgID, mailboxID)
		if !ok {
			return match
		}
		count++
		return `@import "` + newURL + `"`
	})
	if count == 0 {
		return css, 0
	}
	return out, count
}

// urlRegex matches URLs in plain text (http/https).
var urlRegex = regexp.MustCompile(`https?://[^\s<>"'\]]+`)

// protectedURLRegex matches a link-protect redirect URL, capturing the token.
// The redirect is emitted as ".../link-protect?token=<payloadB64>.<sigB64>"; the
// token alphabet is URL-safe base64 (A–Z a–z 0–9 _ -) plus the "." separator.
// An optional scheme+host prefix is tolerated (HTML hrefs may be absolute).
var protectedURLRegex = regexp.MustCompile(`(?:https?://[^\s<>"'\]]*?)?/link-protect\?token=([A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+)`)

// UnwrapMessageBody reverses RewriteMessageBody on an outbound copy: it finds
// every /link-protect?token=… redirect, verifies + decodes the token, and
// splices the original URL back IN PLACE, per output context. This is the
// LINK-PROTECT egress correctness rail (Track A2): a FORWARDED message must
// not re-emit the recipient's protected redirects — they resolve against THIS
// server (broken for the forward target) and leak the recipient mailbox_id +
// message_id encoded in the token.
//
// MIME-aware splice contract (D-MAILSERVER-INTERNAL-LINKPROTECT-003): the
// old implementation substituted raw URL bytes across the ENTIRE message
// after html.Parse had decoded entity-encoded href payloads, re-arming
// injected markup/CRLF before DKIM signing. This implementation:
//   - splices only inside transfer-decoded part bodies (base64/QP parts are
//     decoded, unwrapped, re-encoded) — never across MIME boundaries;
//   - in HTML parts, splices through the parsed tree and lets the HTML
//     serializer entity-encode and delimiter-quote the destination — no live
//     markup or CRLF rematerialization before DKIM signing;
//   - in plain-text parts, emits the destination as inert text;
//   - in an unknown context (unparseable input), substitutes only provably
//     inert destinations;
//   - never substitutes a destination carrying CR, LF, or NUL in any context;
//   - preserves destination semantics: claims.URL round-trips
//     byte-faithfully (scheme/host/path/query unaltered).
//
// There is deliberately NO raw-bytes marker pre-check at entry: a base64 or
// quoted-printable body hides "/link-protect?token=" from a raw scan (base64
// alphabet; quoted-printable encodes "=" as =3D), so a pre-decode check let
// encoded-only messages return before either body was ever decoded, leaving
// recipient-bound redirects intact (Astra rereview med-shard2-003 item 3).
// The marker fast path moved AFTER transfer decoding (hasProtectedMarker in
// unwrapSinglePart/unwrapMultipart); the unknown-context fallback needs no
// marker check — the substitution regex itself is the test, and a non-match
// leaves the input byte-exact.
//
// The signature is verified before substitution so a tampered or foreign
// token (different secret) is left untouched rather than trusted. Returns the
// rewritten body, the number of URLs unwrapped, and any error; on error the
// caller must fall back to the original data unchanged (our redirects are
// self-verifying and inert — the fail-safe direction).
func UnwrapMessageBody(data []byte, secret []byte) ([]byte, int, error) {
	return UnwrapMessageBodyN(data, TokenKeys{Secret: secret})
}

// UnwrapMessageBodyN is the VERSIONED form of UnwrapMessageBody
// (MAILSERVERD-004 dual-key overlap rotation): tokens are verified against the
// configured key set — the current key first, then the retiring key while the
// overlap window is open — so forwarded copies carrying redirects delivered
// under EITHER generation un-rewrite cleanly. After the window is drained,
// old-key redirects no longer verify and are left in place (inert). Every
// contract term documented below is unchanged.
func UnwrapMessageBodyN(data []byte, keys TokenKeys) ([]byte, int, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(data))
	if err != nil {
		// Not a parseable RFC 5322 message (bare body or HTML fragment): the
		// output context is unknown, so only provably inert destinations are
		// re-materialized, as plain text.
		return unwrapUnknownContext(data, keys)
	}
	body, err := io.ReadAll(msg.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("link_protect: read body: %w", err)
	}

	contentType := msg.Header.Get("Content-Type")
	if contentType == "" {
		if len(bytes.TrimSpace(body)) == 0 {
			// Degenerate parse: mail.ReadMessage consumed the entire input as
			// "headers" and left no body (e.g. a bare HTML fragment). No body
			// context exists, so re-scan the raw bytes under the unknown-
			// context contract. Verified-signature substitution only — this
			// never runs for a real message body, where parts the MIME walk
			// deliberately left alone (calendar, non-text) stay byte-exact.
			return unwrapUnknownContext(data, keys)
		}
		// RFC 2045 §5.2 default: a header-less body is US-ASCII text/plain.
		return unwrapSinglePart(data, body, msg.Header, "text/plain", keys)
	}
	_, isMultipart, err := mimeutil.ExtractBoundaryStrict(contentType)
	if err != nil {
		// Ambiguous framing: fail safe — our redirects are self-verifying
		// and inert; never splice into an unproven body. The caller sends
		// the original (redirects intact) rather than a mangled message.
		return nil, 0, fmt.Errorf("link_protect: %w", err)
	}
	if isMultipart {
		return unwrapMultipart(data, contentType, keys)
	}
	return unwrapSinglePart(data, body, msg.Header, strings.ToLower(contentType), keys)
}

// protectedMarker is the prefix every redirect this package emits carries.
const protectedMarker = protectedPath + "?token="

// hasProtectedMarker reports whether b contains the redirect marker. Only
// meaningful on TRANSFER-DECODED bytes: evaluated on raw message bytes it is
// defeated by base64/quoted-printable encodings, which hide the marker from a
// literal scan (Astra rereview med-shard2-003 item 3).
func hasProtectedMarker(b []byte) bool {
	return bytes.Contains(b, []byte(protectedMarker))
}

// unwrapMultipart unwraps each transfer-decoded text leaf part of a multipart
// message through mimeutil's strict walker; untouched parts stay byte-exact.
func unwrapMultipart(data []byte, contentType string, keys TokenKeys) ([]byte, int, error) {
	total := 0
	var cbErr error
	out, err := mimeutil.WalkMIMEParts(contentType, data, func(partHeaders, partBody []byte) []byte {
		if cbErr != nil {
			return nil
		}
		ct := strings.ToLower(mimeutil.ExtractHeader(string(partHeaders), "Content-Type"))
		if strings.Contains(ct, "text/calendar") || !isRewriteTarget(ct) {
			return nil
		}
		decoded, cte, derr := decodeCTE(mimeutil.ExtractHeader(string(partHeaders), "Content-Transfer-Encoding"), partBody)
		if derr != nil {
			cbErr = derr
			return nil
		}
		if !hasProtectedMarker(decoded) {
			return nil // decoded body carries no redirect: byte-exact keep
		}
		unwrapped, n, uerr := unwrapDecodedBody(decoded, ct, keys)
		if uerr != nil {
			cbErr = uerr
			return nil
		}
		if n == 0 {
			return nil // untouched part: keep the original bytes byte-exact
		}
		reencoded, eerr := encodeCTE(cte, unwrapped)
		if eerr != nil {
			cbErr = eerr
			return nil
		}
		total += n
		return reencoded
	})
	if cbErr != nil {
		return nil, 0, cbErr
	}
	if err != nil {
		return nil, 0, err
	}
	return out, total, nil
}

// unwrapDecodedBody unwraps one transfer-DECODED part body of MIME type ct
// (lowercased, possibly empty → RFC 2045 §5.2 text/plain default).
func unwrapDecodedBody(decoded []byte, ct string, keys TokenKeys) ([]byte, int, error) {
	switch {
	case strings.Contains(ct, "text/html"):
		return unwrapHTMLBody(decoded, keys)
	case strings.Contains(ct, "text/plain"), ct == "":
		unwrapped, count := unwrapProtectedText(string(decoded), keys)
		return []byte(unwrapped), count, nil
	default:
		return decoded, 0, nil
	}
}

// unwrapSinglePart unwraps a non-multipart message body: transfer-decode,
// unwrap, re-encode, splice back behind the header block. Zero unwraps →
// unchanged.
func unwrapSinglePart(data, body []byte, header mail.Header, contentType string, keys TokenKeys) ([]byte, int, error) {
	ct := strings.ToLower(contentType)
	if strings.Contains(ct, "text/calendar") || !isRewriteTarget(ct) {
		return data, 0, nil
	}

	decoded, cte, err := decodeCTE(header.Get("Content-Transfer-Encoding"), body)
	if err != nil {
		return nil, 0, err
	}
	if !hasProtectedMarker(decoded) {
		// Marker check AFTER transfer decoding (Astra rereview med-shard2-003
		// item 3): an encoded body can now only skip the splice because its
		// DECODED bytes carry no redirect — never because the encoding hid
		// the marker.
		return data, 0, nil
	}
	unwrapped, count, err := unwrapDecodedBody(decoded, ct, keys)
	if err != nil {
		return nil, 0, err
	}
	if count == 0 {
		return data, 0, nil
	}
	reencoded, err := encodeCTE(cte, unwrapped)
	if err != nil {
		return nil, 0, err
	}
	return rebuildMessage(data, reencoded), count, nil
}

// unwrapHTMLBody unwraps an HTML part through the parsed tree: attribute
// values (full-value redirects, srcset candidates, style attributes), <style>
// text, and text nodes. Substituted destinations are serialized by
// html.Render — attribute values are delimiter-quoted and entity-encoded, so
// no live markup or CRLF rematerializes in the signed outbound message. The
// raw-text literal contexts (script/iframe/noembed/noframes/noscript/xmp/
// plaintext children — rendered literally by the serializer) are unsupported:
// verified redirects there are retained in place, never substituted.
func unwrapHTMLBody(data []byte, keys TokenKeys) ([]byte, int, error) {
	doc, err := html.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, 0, fmt.Errorf("link_protect: parse HTML: %w", err)
	}
	count := 0
	unwrapHTMLNode(doc, keys, &count)
	if count == 0 {
		// Nothing of ours in this part: keep the original bytes (avoids
		// renderer-normalizing a part we never needed to touch).
		return data, 0, nil
	}
	var buf bytes.Buffer
	if err := html.Render(&buf, doc); err != nil {
		return nil, 0, fmt.Errorf("link_protect: render HTML: %w", err)
	}
	return buf.Bytes(), count, nil
}

// unwrapHTMLNode recursively unwraps protected redirects in the parsed tree.
func unwrapHTMLNode(n *html.Node, keys TokenKeys, count *int) {
	if n.Type == html.ElementNode {
		for i, attr := range n.Attr {
			key := strings.ToLower(attr.Key)
			switch {
			case key == "style":
				unwrapped, n2 := unwrapCSS(attr.Val, keys)
				if n2 > 0 {
					n.Attr[i].Val = unwrapped
					*count += n2
				}
			case key == "srcset":
				unwrapped, n2 := unwrapSrcset(attr.Val, keys)
				if n2 > 0 {
					n.Attr[i].Val = unwrapped
					*count += n2
				}
			case urlAttrs[key]:
				if dest, ok := unwrapFullValue(attr.Val, keys); ok {
					n.Attr[i].Val = dest
					*count++
				}
			}
		}
	}
	if n.Type == html.TextNode {
		switch {
		case n.Parent != nil && strings.EqualFold(n.Parent.Data, "style"):
			unwrapped, n2 := unwrapCSS(n.Data, keys)
			if n2 > 0 {
				n.Data = unwrapped
				*count += n2
			}
		case rawTextLiteralParent(n.Parent):
			// html.Render emits the text children of these elements
			// LITERALLY, and the block is closed only by its own end tag, so
			// a substituted destination carrying the closing tag (e.g.
			// "</script>") would rematerialize as live markup on
			// serialization (Astra rereview med-shard2-003 item 1). These
			// contexts are unsupported for substitution: the verified
			// redirect is retained in place — inert and self-verifying.
		default:
			unwrapped, n2 := unwrapProtectedText(n.Data, keys)
			if n2 > 0 {
				n.Data = unwrapped
				*count += n2
			}
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		unwrapHTMLNode(c, keys, count)
	}
}

// rawTextLiteralParent reports whether el is an element whose text children
// html.Render emits literally (x/net/html childTextNodesAreLiteral: script,
// style, iframe, noembed, noframes, noscript, xmp, plaintext). <style> text is
// handled by the dedicated CSS branch; the remaining literal contexts are
// unsupported for destination substitution — a destination containing the
// element's own closing tag would survive serialization verbatim and split
// the raw-text block (Astra rereview med-shard2-003 item 1).
func rawTextLiteralParent(el *html.Node) bool {
	if el == nil || el.Type != html.ElementNode {
		return false
	}
	switch strings.ToLower(el.Data) {
	case "script", "iframe", "noembed", "noframes", "noscript", "xmp", "plaintext":
		return true
	}
	return false
}

// unwrapFullValue unwraps an attribute value that IS a link-protect redirect
// (with the tolerated optional absolute-host prefix). Redirects embedded
// inside a larger attribute value are left alone: they are part of a larger
// URL whose destination semantics a whole-value substitution would clobber.
func unwrapFullValue(val string, keys TokenKeys) (string, bool) {
	sub := protectedURLRegex.FindStringSubmatch(val)
	if sub == nil || sub[0] != val {
		return "", false
	}
	return verifiedDestination(sub[1], keys)
}

// verifiedDestination verifies a token against the configured key set
// (current key first, retiring key during the overlap window) and returns its
// destination, refusing any destination carrying CR, LF, or NUL: those must
// never rematerialize in a spliced body in any output context (they cannot
// occur in tokens this package mints — rewriteURL refuses control-char URLs —
// so a refusal here only ever leaves an older/pre-fix redirect in place, which
// is inert).
func verifiedDestination(token string, keys TokenKeys) (string, bool) {
	claims, err := VerifyTokenN(token, keys)
	if err != nil || claims.URL == "" {
		// Tampered, expired, or signed with a different secret — leave it.
		return "", false
	}
	if strings.ContainsAny(claims.URL, "\r\n\x00") {
		return "", false
	}
	return claims.URL, true
}

// unwrapSrcset unwraps every srcset candidate that IS a protected redirect,
// using the WHATWG candidate parser (parseSrcsetCandidates) so a comma inside
// a candidate URL never splits it. Substitution is skipped for destinations
// that would forge the srcset grammar (whitespace or commas); separators and
// descriptors are preserved byte-exactly.
func unwrapSrcset(val string, keys TokenKeys) (string, int) {
	spans := parseSrcsetCandidates(val)
	count := 0
	var b strings.Builder
	last := 0
	for _, sp := range spans {
		b.WriteString(val[last:sp[0]])
		u := val[sp[0]:sp[1]]
		// The WHATWG parser keeps interior commas INSIDE a URL, so a
		// comma-bearing destination round-trips byte-faithfully; only
		// whitespace (candidate separator) or a TRAILING comma (candidate
		// terminator stripped by the parser) would forge the grammar.
		if dest, ok := unwrapFullValue(u, keys); ok &&
			!strings.ContainsAny(dest, " \t\n\f\r") && !strings.HasSuffix(dest, ",") {
			b.WriteString(dest)
			count++
		} else {
			b.WriteString(u)
		}
		last = sp[1]
	}
	if count == 0 {
		return val, 0
	}
	b.WriteString(val[last:])
	return b.String(), count
}

// unwrapCSS unwraps protected redirects from CSS url() tokens and @import
// strings. A destination is spliced as a double-quoted CSS string only when
// it cannot forge the string grammar; otherwise the redirect stays (inert).
func unwrapCSS(css string, keys TokenKeys) (string, int) {
	count := 0
	splice := func(re *regexp.Regexp, css, replFmt string) string {
		return re.ReplaceAllStringFunc(css, func(match string) string {
			sub := re.FindStringSubmatch(match)
			if len(sub) < 2 {
				return match
			}
			dest, ok := verifiedDestination(sub[1], keys)
			if !ok || !cssStringSafe(dest) {
				return match
			}
			count++
			return fmt.Sprintf(replFmt, dest)
		})
	}
	out := splice(cssProtectedURLRe, css, `url("%s")`)
	out = splice(cssProtectedImportRe, out, `@import "%s"`)
	if count == 0 {
		return css, 0
	}
	return out, count
}

// cssProtectedURLRe matches a CSS url() token holding a protected redirect.
var cssProtectedURLRe = regexp.MustCompile(`(?i)url\(\s*['"]?(?:https?://[^\s()'"]*?)?/link-protect\?token=([A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+)['"]?\s*\)`)

// cssProtectedImportRe matches a CSS @import string holding a protected redirect.
var cssProtectedImportRe = regexp.MustCompile(`(?i)@import\s+["'](?:https?://[^\s'"]*?)?/link-protect\?token=([A-Za-z0-9_\-=]+\.[A-Za-z0-9_\-=]+)["']`)

// cssStringSafe reports whether s can be embedded verbatim in a double-quoted
// CSS string. < and > are refused because <style> element text is a raw-text
// literal serialization context: a destination carrying "</style>" would close
// the element early on render and re-arm the rest as live markup (Astra
// rereview med-shard2-003 item 1). Quotes/parens/backslash would forge the
// CSS grammar; CR/LF are refused by verifiedDestination already and kept here
// as defense in depth.
func cssStringSafe(s string) bool {
	return !strings.ContainsAny(s, "\"'()\\\r\n<>")
}

// unwrapProtectedText substitutes protected redirects in a plain-text
// context: the destination is emitted verbatim as inert text (a text/plain
// body renders no markup), so only the CR/LF/NUL refusal applies.
func unwrapProtectedText(s string, keys TokenKeys) (string, int) {
	count := 0
	out := protectedURLRegex.ReplaceAllStringFunc(s, func(match string) string {
		sub := protectedURLRegex.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		dest, ok := verifiedDestination(sub[1], keys)
		if !ok {
			return match
		}
		count++
		return dest
	})
	if count == 0 {
		return s, 0
	}
	return out, count
}

// isInertText reports whether s provably stays text in ANY rendering context:
// no markup-structural characters and no control characters. Used only where
// the output context is unknown.
func isInertText(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
		switch r {
		case '<', '>', '"', '\'', '&':
			return false
		}
	}
	return true
}

// unwrapUnknownContext unwraps redirects found in bytes with no proven output
// context (unparseable or degenerate input). Only provably inert destinations
// are substituted; anything else keeps the (inert, self-verifying) redirect.
func unwrapUnknownContext(data []byte, keys TokenKeys) ([]byte, int, error) {
	count := 0
	out := protectedURLRegex.ReplaceAllFunc(data, func(match []byte) []byte {
		sub := protectedURLRegex.FindSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		claims, err := VerifyTokenN(string(sub[1]), keys)
		if err != nil || claims.URL == "" {
			return match
		}
		if !isInertText(claims.URL) {
			return match
		}
		count++
		return []byte(claims.URL)
	})
	return out, count, nil
}

// rewritePlainText finds and replaces URLs in plain text content.
func rewritePlainText(body string, keys TokenKeys, internalDomains []string, msgID string, mailboxID int64) (string, int, error) {
	count := 0
	result := urlRegex.ReplaceAllStringFunc(body, func(match string) string {
		newURL, ok := rewriteURL(match, keys, internalDomains, msgID, mailboxID)
		if ok {
			count++
			return newURL
		}
		return match
	})
	return result, count, nil
}

// RewriteURL is the exported single-URL entry point of the rewriter. The live
// SMTP delivery site (internal/smtp) delegates here so its per-URL decisions —
// idempotence guard, scheme coverage, internal-domain exemption, signing — can
// never diverge from this canonical copy (adjudicated live-SMTP alignment,
// med-shard2-003 r2). It signs under the VERSION-1 key of secret (the
// pre-rotation shorthand); the delivery path mints through
// RewriteMessageBodyN with the configured key set.
func RewriteURL(rawURL string, secret []byte, internalDomains []string, msgID string, mailboxID int64) (string, bool) {
	return rewriteURL(rawURL, TokenKeys{Secret: secret}, internalDomains, msgID, mailboxID)
}

// rewriteURL creates a /link-protect?token=... proxy URL for an external URL,
// signing the token under the CURRENT key of keys (MAILSERVERD-004: keys at
// keys.Version, previous keys never sign). Returns (original, false) if the
// URL should be skipped.
func rewriteURL(rawURL string, keys TokenKeys, internalDomains []string, msgID string, mailboxID int64) (string, bool) {
	if rawURL == "" {
		return rawURL, false
	}

	if strings.HasPrefix(strings.ToLower(rawURL), "mailto:") {
		return rawURL, false
	}

	if strings.HasPrefix(rawURL, "#") {
		return rawURL, false
	}

	// Idempotence guard (D-MAILSERVER-INTERNAL-LINKPROTECT-002): anchored and
	// token-aware. The unanchored strings.Contains(url, "/link-protect?token=")
	// check let any sender embed that substring (even as a decoy query
	// parameter or path suffix of an EXTERNAL url) to skip rewriting, the scan
	// pipeline, the interstitial, and click auditing entirely. The guard now
	// exempts only a HOST-RELATIVE URL whose path is exactly /link-protect and
	// which carries a token parameter — the exact shape this package emits.
	// An absolute or protocol-relative URL (u.Host != "") is sender content and
	// always rewritten; a host-relative lookalike with a junk token cannot
	// reach an attacker destination (it resolves against THIS server's
	// /link-protect endpoint and fails token verification).
	if isOwnRedirect(rawURL) {
		return rawURL, false
	}

	if !strings.HasPrefix(strings.ToLower(rawURL), "http://") &&
		!strings.HasPrefix(strings.ToLower(rawURL), "https://") &&
		!strings.HasPrefix(rawURL, "//") {
		// Scheme-bearing non-web URLs (ftp:, javascript:, ...) are skipped.
		// A leading "//" (protocol-relative) inherits http(s) in every HTML
		// rendering context, so it IS a fetched/navigated web URL in the
		// attributes this rewrite covers and must go through the interstitial
		// like its absolute twin.
		return rawURL, false
	}

	// Never sign a URL carrying control characters: the destination is
	// re-materialized verbatim at unwrap time in plain-text contexts, and a
	// CRLF-bearing destination could forge MIME framing or rematerialize CRLF
	// in the signed outbound message (D-MAILSERVER-INTERNAL-LINKPROTECT-003).
	// Such a URL is already malformed (RFC 3986 excludes control characters);
	// leaving it unrewritten keeps it exactly as inert as the sender wrote it.
	if strings.ContainsAny(rawURL, "\r\n\x00") {
		return rawURL, false
	}

	for _, domain := range internalDomains {
		if domain != "" && IsInternalURL(rawURL, domain) {
			return rawURL, false
		}
	}

	claims := TokenClaims{
		URL:       rawURL,
		MessageID: msgID,
		MailboxID: mailboxID,
		ExpiresAt: time.Now().Add(tokenExpiry).Unix(),
	}

	token, err := SignTokenN(claims, keys)
	if err != nil {
		return rawURL, false
	}

	return protectedPath + "?token=" + token, true
}

// isOwnRedirect reports whether rawURL is exactly the shape of a redirect
// this package emits: host-relative (we never emit an authority), path
// exactly /link-protect, with a non-empty token parameter. Anything else —
// in particular any absolute or protocol-relative URL carrying the
// "/link-protect?token=" text — is sender content and must be rewritten.
func isOwnRedirect(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if u.Host != "" || u.Path != protectedPath {
		return false
	}
	return u.Query().Get("token") != ""
}

// parseURLHost is THE single URL authority parser for every linkprotect
// classification site (the inbound rewrite exemption, the dead-copy rewrite in
// this package, and the Spamhaus DBL scan target). It parses rawURL with
// net/url and returns the lowercase authority host: u.Hostname() — userinfo
// excluded ("http://internal.domain:8080@evil.com/" → "evil.com", RFC 3986 /
// browser semantics), port stripped, IPv6 brackets removed.
//
// D-MAILSERVER-INTERNAL-LINKPROTECT-001: the previous hand-rolled
// scheme-strip + last-colon-cut ignored userinfo, so an attacker URL carrying
// an internal-looking userinfo component classified as internal and skipped
// both the /link-protect rewrite and the DBL scan of the real host.
//
// A parse error or a missing authority host is rejected (error). Callers fail
// CLOSED: the rewrite classifier treats such a URL as NOT internal (it gets
// rewritten through the interstitial), and the scanner surfaces Unknown so the
// click pipeline never treats it as clean.
func parseURLHost(rawURL string) (string, error) {
	if rawURL == "" {
		return "", fmt.Errorf("link_protect: empty URL")
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("link_protect: parse URL %q: %w", rawURL, err)
	}
	if u.Host == "" {
		return "", fmt.Errorf("link_protect: URL %q has no authority host", rawURL)
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return "", fmt.Errorf("link_protect: URL %q has empty hostname", rawURL)
	}
	return host, nil
}

// IsInternalURL reports whether rawURL's parsed net/url authority host belongs
// to domain (exact or dot-bounded subdomain match, case-insensitive). It is the
// single classifier shared by the live inbound rewrite site
// (smtp/link_protect.go) and this package's copy, so both sites — and the
// Spamhaus scan target — classify identically.
//
// Fail closed: a URL whose authority cannot be parsed (malformed, no host,
// non-absolute) is classified NOT internal so it is rewritten through the
// interstitial rather than exempted.
func IsInternalURL(rawURL, domain string) bool {
	host, err := parseURLHost(rawURL)
	if err != nil {
		return false
	}
	domain = strings.ToLower(domain)
	return host == domain || strings.HasSuffix(host, "."+domain)
}

// escapeHTML escapes a string for safe inclusion in HTML.
func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}
