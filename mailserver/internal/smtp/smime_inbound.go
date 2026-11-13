package smtp

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"

	"crypto/x509"

	"setjoin.com/mailserver/internal/smime"
)

// indexHeaderBodySeparator locates the blank line that ends the top-level MIME
// header block and returns the index of its first byte (-1 when absent),
// tolerating CRLF ("\r\n\r\n"), LF ("\n\n"), and the production MIXED framing:
// buildTraceMessage prepends CRLF-framed Received/Return-Path trace headers to
// c.data, whose net/textproto DotReader intake canonicalized every CRLF to LF —
// so the production msg copy contains NO pure-CRLF blank line anywhere, and
// CRLF-only detection here made inbound S/MIME verification unreachable for
// every SMTP-intaked message (both the FeatureSmimeVerify delivery verdict and
// the iMIP rule-(a) branch). CRLF is preferred when present so pure-CRLF inputs
// keep their exact pre-existing behavior.
func indexHeaderBodySeparator(msg string) int {
	if idx := strings.Index(msg, "\r\n\r\n"); idx >= 0 {
		return idx
	}
	return strings.Index(msg, "\n\n")
}

// extractSignedParts is a general detached multipart/signed extractor.
// content is the EXACT canonical bytes that were signed (the content MIME part
// as transmitted between the boundary markers, minus the trailing CRLF that
// precedes the closing boundary line).
// sigDER is the DER-encoded PKCS#7/CMS signature decoded from the base64 body
// of the application/pkcs7-signature (or application/x-pkcs7-signature) part.
//
// It reuses isSMIMESigned and extractSMIMEBoundary from inbound.go (same package).
func extractSignedParts(msg string) (content, sigDER []byte, err error) {
	headerEnd := indexHeaderBodySeparator(msg)
	if headerEnd < 0 {
		return nil, nil, fmt.Errorf("no MIME header boundary found")
	}
	boundary := extractSMIMEBoundary(msg[:headerEnd])
	if boundary == "" {
		return nil, nil, fmt.Errorf("no multipart/signed boundary found")
	}

	// Split on "--<boundary>" to get the parts.
	// parts[0] is the preamble (before first boundary), parts[1..n-1] are the body
	// parts, and the last piece ends with "--" (the closing boundary).
	delimiter := "--" + boundary
	parts := strings.Split(msg, delimiter)
	// parts[0] = everything before first boundary (preamble + top-level headers)
	// parts[1] = content part (starts with \r\n after opening boundary)
	// parts[2] = signature part (starts with \r\n after second boundary)
	// parts[3] = "--\r\n..." (closing boundary suffix)

	var contentBytes []byte
	var sigBytes []byte

	for i := 1; i < len(parts); i++ {
		part := parts[i]

		// Skip the closing boundary fragment (ends with "--")
		stripped := strings.TrimLeft(part, "\r\n")
		if strings.HasPrefix(stripped, "--") {
			continue
		}
		if strings.TrimSpace(part) == "" {
			continue
		}

		// Each part begins with \r\n (the line ending after the opening boundary marker).
		// Strip exactly the leading \r\n before processing the part headers.
		partBody := part
		if strings.HasPrefix(partBody, "\r\n") {
			partBody = partBody[2:]
		} else if strings.HasPrefix(partBody, "\n") {
			partBody = partBody[1:]
		}

		// Find the header/body separator within this part
		sepCRLF := strings.Index(partBody, "\r\n\r\n")
		sepLF := strings.Index(partBody, "\n\n")

		var partHeaders string
		if sepCRLF >= 0 {
			partHeaders = partBody[:sepCRLF]
		} else if sepLF >= 0 {
			partHeaders = partBody[:sepLF]
		} else {
			continue
		}

		headersLower := strings.ToLower(partHeaders)
		isSigPart := strings.Contains(headersLower, "application/pkcs7-signature") ||
			strings.Contains(headersLower, "application/x-pkcs7-signature")

		if isSigPart {
			// Decode base64 body → DER
			var bodyStart int
			if sepCRLF >= 0 {
				bodyStart = sepCRLF + 4
			} else {
				bodyStart = sepLF + 2
			}
			b64Body := partBody[bodyStart:]
			// Strip trailing whitespace / boundary artifacts
			b64Body = strings.TrimRight(b64Body, "\r\n ")
			b64Cleaned := strings.Map(func(r rune) rune {
				if r == '\r' || r == '\n' || r == ' ' || r == '\t' {
					return -1
				}
				return r
			}, b64Body)
			sigBytes, err = base64.StdEncoding.DecodeString(b64Cleaned)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to decode S/MIME signature: %w", err)
			}
		} else if contentBytes == nil {
			// First non-signature, non-empty part is the signed content.
			// The signed bytes are the part as transmitted between the boundary markers,
			// canonicalized per RFC 5751 §3.4: the content part from its first header
			// byte through its last body byte, without the trailing CRLF that separates
			// the part body from the next boundary line.
			contentBytes = canonicalSignedContent([]byte(partBody))
		}
	}

	if len(contentBytes) == 0 || len(sigBytes) == 0 {
		return nil, nil, fmt.Errorf("incomplete S/MIME multipart/signed message")
	}
	return contentBytes, sigBytes, nil
}

// canonicalSignedContent returns the canonical signed-content bytes per
// RFC 5751 §3.4 / RFC 8551 §3.1.1.
//
// The S/MIME spec requires that the content part be taken exactly as it appears
// between the boundary markers. In practice:
//   - The opening boundary is followed by CRLF, then the part begins.
//   - The part body ends at the CRLF that immediately precedes the closing boundary.
//
// This function strips the trailing CRLF (or bare LF) that was added by the
// multipart container — it is the transport separator, not part of the signed
// content — and then reconstructs the RFC 8551 §3.1.1 CRLF canonical form.
//
// Round 10 (Astra r17, P2 framing residual): the SMTP DATA intake
// (net/textproto DotReader) canonicalizes every CRLF to LF BEFORE storage, so
// the part bytes extracted from the stored message hold LF line endings. CMS
// verification (smime.VerifyDetached → sd.VerifyDetached) is BYTE-sensitive:
// handing it those LF bytes digests a different string than the CRLF-canonical
// content the signer signed per RFC 8551 §3.1.1 ("text canonicalization is
// CRLF"), so every legitimately CRLF-signed calendar arriving through real
// DATA intake failed pass 1 as StatusInvalid and iMIP dropped legitimate
// calendars despite valid DKIM/SPF. The reconstruction here maps the stored LF
// form back onto exactly the canonical bytes the signer used (CRLF→LF→CRLF is
// the identity for already-canonical content, so direct-CRLF inputs and
// non-SMTP paths are byte-unchanged). This is a DIFFERENT, well-defined space
// from the DKIM l= coverage fence, which keeps operating on the stored c.data
// bytes (see detectAndProcessIMip in inbound.go).
func canonicalSignedContent(part []byte) []byte {
	// Strip exactly ONE trailing newline (the multipart framing separator).
	// The content part as split gives us (wire form):
	//   "Content-Type: text/plain\r\n\r\nBody text\r\n" + "\r\n"
	//           the last \r\n is the multipart CRLF separator; we keep the
	//   body's own trailing newline, which IS part of the signed content.
	result := string(part)
	if strings.HasSuffix(result, "\r\n") {
		result = result[:len(result)-2]
	} else if strings.HasSuffix(result, "\n") {
		result = result[:len(result)-1]
	}
	// RFC 8551 §3.1.1: reconstruct the CRLF canonical form the signer used.
	// Normalize through LF so mixed/bare-CR input cannot double the CR
	// ("\r\n" → "\r\r\n"); pure-CRLF input round-trips byte-identically and a
	// stored LF body is restored to exactly its pre-intake CRLF form.
	result = strings.ReplaceAll(result, "\r\n", "\n")
	result = strings.ReplaceAll(result, "\n", "\r\n")
	return []byte(result)
}

// verifyInboundSMIME grades an inbound S/MIME detached signature.
// Returns nil (fail-open) when:
//   - the message is not S/MIME-signed
//   - the signed parts cannot be extracted
//
// Otherwise returns the graded smime.VerifyResult. rev carries the settled
// revocation-policy inputs (nil = no revocation checking — every verdict is
// recorded revocation-unknown, fail-open).
// Never panics.
func verifyInboundSMIME(ctx context.Context, msg, fromAddr string, roots *x509.CertPool, rev *smime.RevocationOptions) *smime.VerifyResult {
	if !isSMIMESigned(msg) {
		return nil
	}
	content, sigDER, err := extractSignedParts(msg)
	if err != nil {
		return nil
	}
	return smime.VerifyDetachedWithRevocation(ctx, content, sigDER, fromAddr, roots, rev)
}
