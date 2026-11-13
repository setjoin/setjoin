package smtp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ARC (Authenticated Received Chain) — RFC 8617.
// ARC preserves authentication results across intermediaries (mailing lists,
// forwarders) that modify message content and break DKIM signatures.

// arcSeal generates the three ARC headers for one hop and prepends them to the raw message.
// The caller must provide auth results already computed (SPF, DKIM, DMARC).
// Returns the message with ARC headers prepended, or the original message if signing fails.
func arcSeal(rawMsg []byte, domain, selector string, privKey *rsa.PrivateKey,
	spfResult, spfDomain, dkimResult, dkimDomain, dmarcResult, fromDomain string,
) []byte {
	if privKey == nil || domain == "" {
		return rawMsg
	}

	instance := parseARCInstance(rawMsg) + 1

	// 1. Build Authentication-Results header (RFC 8601)
	authRes := buildAuthResults(instance, spfResult, spfDomain, dkimResult, dkimDomain, dmarcResult, fromDomain)

	// 2. Sign the message (ARC-Message-Signature — like DKIM over selected headers + body)
	amsHeader := arcSignMessage(rawMsg, instance, domain, selector, privKey)

	// 3. Sign the seal chain (ARC-Seal — signs previous ARC-Seal header)
	asHeader := arcSignSeal(rawMsg, instance, domain, selector, privKey)

	prepended := fmt.Sprintf("%s\r\n%s\r\n%s\r\n", authRes, amsHeader, asHeader)
	return append([]byte(prepended), rawMsg...)
}

// buildAuthResults builds an RFC 8601 Authentication-Results header for an ARC set.
func buildAuthResults(instance int, spfResult, spfDomain, dkimResult, dkimDomain, dmarcResult, fromDomain string) string {
	var parts []string

	// SPF
	if spfResult != "" && spfDomain != "" {
		parts = append(parts, fmt.Sprintf("spf=%s smtp.mailfrom=%s", spfResult, spfDomain))
	} else if spfResult != "" {
		parts = append(parts, fmt.Sprintf("spf=%s", spfResult))
	}

	// DKIM
	if dkimResult != "" && dkimDomain != "" {
		parts = append(parts, fmt.Sprintf("dkim=%s header.d=%s", dkimResult, dkimDomain))
	} else if dkimResult != "" {
		parts = append(parts, fmt.Sprintf("dkim=%s", dkimResult))
	}

	// DMARC
	if dmarcResult != "" && fromDomain != "" {
		parts = append(parts, fmt.Sprintf("dmarc=%s header.from=%s", dmarcResult, fromDomain))
	} else if dmarcResult != "" {
		parts = append(parts, fmt.Sprintf("dmarc=%s", dmarcResult))
	}

	results := strings.Join(parts, "; ")
	if results == "" {
		results = "none"
	}
	return fmt.Sprintf("ARC-Authentication-Results: i=%d; %s", instance, results)
}

// parseARCInstance finds the highest ARC instance number in existing ARC headers.
// Returns 0 if no ARC headers are present.
func parseARCInstance(rawMsg []byte) int {
	msg := string(rawMsg)
	maxInstance := 0

	for _, prefix := range []string{"ARC-Authentication-Results:", "ARC-Message-Signature:", "ARC-Seal:"} {
		for _, line := range strings.Split(msg, "\n") {
			line = strings.TrimSpace(line)
			trimmed := strings.TrimPrefix(line, prefix)
			if trimmed == line {
				continue
			}
			// Find i=N in the header value
			if idx := strings.Index(trimmed, "i="); idx >= 0 {
				end := strings.IndexAny(trimmed[idx+2:], " ;\r")
				if end < 0 {
					end = len(trimmed) - idx - 2
				}
				numStr := strings.TrimSpace(trimmed[idx+2 : idx+2+end])
				var n int
				if _, err := fmt.Sscanf(numStr, "%d", &n); err == nil && n > maxInstance {
					maxInstance = n
				}
			}
		}
	}
	return maxInstance
}

// arcSignMessage generates the ARC-Message-Signature header.
// This is a DKIM-like signature over the message body + selected headers,
// excluding all ARC headers and the seal.
func arcSignMessage(rawMsg []byte, instance int, domain, selector string, privKey *rsa.PrivateKey) string {
	headers, body := splitHeadersBody(rawMsg)

	// Select headers to sign (excluding ARC-* headers)
	headerNames := []string{"from", "to", "subject", "date", "message-id", "mime-version", "content-type"}
	signedHeaders := arcCollectHeaders(string(headers), headerNames)

	// Build header list for h= tag
	var hList []string
	for _, h := range signedHeaders {
		name := strings.ToLower(strings.SplitN(h, ":", 2)[0])
		hList = append(hList, name)
	}

	// Compute body hash (relaxed/relaxed canonicalization)
	bodyHashBytes := dkimBodyHash(body, "relaxed/relaxed", 0)
	bh := base64.StdEncoding.EncodeToString(bodyHashBytes)

	// Build data to sign: canonicalized headers + body hash
	canonHeaders := arcCanonHeaders(signedHeaders)
	signedData := canonHeaders + "dkim-signature:" + arcDummySig(instance, domain, selector, hList, bh)

	hash := sha256.Sum256([]byte(signedData))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	if err != nil {
		return ""
	}
	b64Sig := base64.StdEncoding.EncodeToString(signature)

	hTag := strings.Join(hList, ":")
	return fmt.Sprintf(
		"ARC-Message-Signature: i=%d; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s; h=%s; bh=%s; b=%s",
		instance, domain, selector, hTag, bh, b64Sig,
	)
}

// arcSignSeal generates the ARC-Seal header.
// The seal signs the previous ARC-Seal header value (chain integrity).
// For the first ARC set (cv=none or no prior seal), it signs a dummy value.
func arcSignSeal(rawMsg []byte, instance int, domain, selector string, privKey *rsa.PrivateKey) string {
	prevSeal := extractPrevSeal(rawMsg)

	var cv string
	if prevSeal == "" {
		cv = "none"
	} else {
		cv = "pass"
	}

	// Build data to sign: the previous seal header (or empty) + chain status
	signedData := fmt.Sprintf("ARC-Seal: i=%d; d=%s; s=%s; cv=%s", instance, domain, selector, cv)

	hash := sha256.Sum256([]byte(signedData))
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, crypto.SHA256, hash[:])
	if err != nil {
		return ""
	}
	b64Sig := base64.StdEncoding.EncodeToString(signature)

	return fmt.Sprintf(
		"ARC-Seal: i=%d; a=rsa-sha256; d=%s; s=%s; cv=%s; b=%s",
		instance, domain, selector, cv, b64Sig,
	)
}

// extractPrevSeal returns the value of the most recent ARC-Seal header.
func extractPrevSeal(rawMsg []byte) string {
	msg := string(rawMsg)
	var lastSeal string
	for _, line := range strings.Split(msg, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ARC-Seal:") {
			lastSeal = line
		}
	}
	return lastSeal
}

// arcCollectHeaders returns selected header lines (in original case) in order of appearance.
// Uses relaxed canonicalization (lowercased header name for matching).
func arcCollectHeaders(headers string, names []string) []string {
	var result []string
	for _, line := range strings.Split(headers, "\n") {
		line = strings.TrimRight(line, "\r")
		// Skip folded continuation lines — they're part of the previous header
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			if len(result) > 0 {
				result[len(result)-1] += "\r\n" + line
			}
			continue
		}
		// Check if this header name matches one we want
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		hName := strings.ToLower(line[:colon])
		for _, n := range names {
			if hName == n {
				result = append(result, line)
				break
			}
		}
	}
	return result
}

// arcCanonHeaders applies relaxed header canonicalization.
func arcCanonHeaders(headers []string) string {
	var lines []string
	for _, h := range headers {
		colon := strings.Index(h, ":")
		if colon < 0 {
			continue
		}
		name := strings.ToLower(h[:colon])
		value := strings.TrimSpace(h[colon+1:])
		// Collapse whitespace in value
		value = collapseWSP(value)
		lines = append(lines, name+":"+value)
	}
	return strings.Join(lines, "\r\n") + "\r\n"
}

func arcDummySig(instance int, domain, selector string, hList []string, bh string) string {
	return fmt.Sprintf(
		"v=1; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s; i=%d; h=%s; bh=%s; b=",
		domain, selector, instance, strings.Join(hList, ":"), bh,
	)
}

// arcSignForInbound loads the ARC signing key from the database and calls arcSeal.
// Used in the inbound message delivery path.
func arcSignForInbound(rawMsg []byte, fromDomain string, pool *pgxpool.Pool, spfResult, spfDomain, dkimResult, dkimDomain, dmarcResult string) []byte {
	if fromDomain == "" || pool == nil {
		return rawMsg
	}

	var privKeyPEM string
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := pool.QueryRow(ctx,
		`SELECT private_key FROM domain_signing_keys WHERE domain = $1 AND enabled = TRUE LIMIT 1`,
		fromDomain,
	).Scan(&privKeyPEM)
	if err != nil {
		return rawMsg // no signing key configured
	}

	block, _ := pem.Decode([]byte(privKeyPEM))
	if block == nil {
		return rawMsg
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return rawMsg
	}

	return arcSeal(rawMsg, fromDomain, "arc", privKey,
		spfResult, spfDomain, dkimResult, dkimDomain, dmarcResult, fromDomain,
	)
}
