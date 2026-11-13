package smtp

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// DKIMResult is the outcome of DKIM verification.
type DKIMResult string

const (
	DKIMPass    DKIMResult = "pass"
	DKIMFail    DKIMResult = "fail"
	DKIMNone    DKIMResult = "none"
	DKIMTempErr DKIMResult = "temperror"
	DKIMPermErr DKIMResult = "permerror"
)

// DKIMSig holds parsed DKIM-Signature header fields.
type DKIMSig struct {
	Domain     string
	Selector   string
	Algorithm  string
	Headers    []string
	Signature  []byte
	BodyHash   string
	Canonical  string // c=header/body
	Created    int64  // t= timestamp
	Expires    int64  // x= expiry
	Identity   string // i= signing identity
	Length     int64  // l= body length limit
	Query      string // q= query methods
	CopyFields string // z= copied header fields
}

// VerifyDKIM checks DKIM signatures in a raw message.
//
// Round 4 (Astra HOLD, D-MAILSERVER-INTERNAL-CALDAV-003): the second return is
// the AUTHENTICATED body length. When the verified signature carries an l= tag,
// the body hash covers only the first l bytes of the canonicalized body (RFC
// 6376 §3.5) and signedLen is that l — every body byte beyond it is
// UNAUTHENTICATED and downstream content extraction must not process it.
// signedLen is 0 when the signature carries no l= tag (the full body is
// signed) or the signature did not pass.
func VerifyDKIM(rawMsg []byte, fromDomain string) (DKIMResult, int64) {
	msg := string(rawMsg)
	sig := parseDKIMSignature(msg)
	if sig == nil {
		return DKIMNone, 0
	}

	if sig.Algorithm == "rsa-sha1" {
		return DKIMPermErr, 0 // RFC 8301 §3.1
	}

	// Look up public key
	keyRecord, err := lookupTXT(sig.Selector + "._domainkey." + sig.Domain)
	if err != nil {
		return DKIMTempErr, 0
	}

	var pubKeyPEM string
	for _, txt := range keyRecord {
		if strings.Contains(txt, "k=rsa") || strings.Contains(txt, "k=ed25519") || strings.Contains(txt, "p=") {
			pubKeyPEM = txt
			break
		}
	}
	if pubKeyPEM == "" {
		return DKIMPermErr, 0
	}

	pubKey, err := parseDKIMPublicKey(pubKeyPEM)
	if err != nil {
		return DKIMPermErr, 0
	}

	// Validate body hash (bh=) — RFC 6376 §3.4
	// If l= tag is present, the body hash covers only the first l bytes
	// of the canonicalized body per RFC 6376 §3.5.
	_, body := splitHeadersBody(rawMsg)
	bodyHashBytes := dkimBodyHash(body, sig.Canonical, sig.Length)
	expectedBH := base64.StdEncoding.EncodeToString(bodyHashBytes)
	if sig.BodyHash != expectedBH {
		return DKIMFail, 0
	}

	// Simple canonicalization: relaxed/relaxed
	signedData := dkimSignedData(msg, sig)

	switch sig.Algorithm {
	case "rsa-sha256":
		rsaPub, ok := pubKey.(*rsa.PublicKey)
		if !ok {
			return DKIMPermErr, 0
		}
		hash := sha256.Sum256([]byte(signedData))
		// crypto.SHA256 (NOT crypto.Hash(0)) restores the RFC 8017 §9.2
		// DigestInfo prefix: every standards-compliant external DKIM signer
		// signs RSASSA-PKCS1-v1_5 over the DigestInfo-wrapped digest, and hash=0
		// verifies the bare digest only — so external signatures failed here and
		// outbound signatures were nonstandard (D-MAILSERVER-INTERNAL-SMTP-V002).
		err = rsa.VerifyPKCS1v15(rsaPub, crypto.SHA256, hash[:], sig.Signature)
	case "ed25519-sha256":
		edPub, ok := pubKey.(ed25519.PublicKey)
		if !ok {
			return DKIMPermErr, 0
		}
		if !ed25519.Verify(edPub, []byte(signedData), sig.Signature) {
			err = fmt.Errorf("ed25519 verification failed")
		}
	default:
		return DKIMPermErr, 0
	}
	if err != nil {
		return DKIMFail, 0
	}
	return DKIMPass, sig.Length
}

func parseDKIMSignature(msg string) *DKIMSig {
	val := extractHeader(msg, "DKIM-Signature")
	if val == "" {
		return nil
	}

	sig := &DKIMSig{Canonical: "relaxed/relaxed"}
	for _, part := range strings.Split(val, ";") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		k, v := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
		switch k {
		case "d":
			sig.Domain = strings.Trim(v, "\"")
		case "s":
			sig.Selector = strings.Trim(v, "\"")
		case "a":
			sig.Algorithm = v
		case "h":
			sig.Headers = strings.Split(v, ":")
		case "b":
			b, _ := base64.StdEncoding.DecodeString(v)
			sig.Signature = b
		case "bh":
			sig.BodyHash = v
		case "c":
			sig.Canonical = v
		case "t":
			sig.Created, _ = strconv.ParseInt(v, 10, 64)
		case "x":
			sig.Expires, _ = strconv.ParseInt(v, 10, 64)
		case "i":
			sig.Identity = v
		case "l":
			sig.Length, _ = strconv.ParseInt(v, 10, 64)
		case "q":
			sig.Query = v
		case "z":
			sig.CopyFields = v
		}
	}
	if sig.Domain == "" || sig.Selector == "" {
		return nil
	}
	return sig
}

func parseDKIMPublicKey(txt string) (crypto.PublicKey, error) {
	var b64 string
	for _, part := range strings.Split(txt, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, "p=") {
			b64 = strings.TrimPrefix(part, "p=")
			break
		}
	}
	if b64 == "" {
		return nil, fmt.Errorf("no public key in record")
	}
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if ok {
		if rsaPub.N.BitLen() < 1024 {
			return nil, fmt.Errorf("RSA key too small: %d bits (minimum 1024)", rsaPub.N.BitLen())
		}
		return rsaPub, nil
	}
	edPub, ok := pub.(ed25519.PublicKey)
	if ok {
		return edPub, nil
	}
	return nil, fmt.Errorf("unsupported key type: %T", pub)
}

func dkimSignedData(msg string, sig *DKIMSig) string {
	headerMode := "simple"
	if parts := strings.Split(sig.Canonical, "/"); len(parts) >= 1 && parts[0] == "relaxed" {
		headerMode = "relaxed"
	}
	canonicalize := dkimSimpleHeader
	if headerMode == "relaxed" {
		canonicalize = dkimRelaxedHeader
	}

	var parts []string
	headers, _ := splitHeadersBody([]byte(msg))
	headerLines := strings.Split(unfoldHeaders(string(headers)), "\n")

	for _, name := range sig.Headers {
		name = strings.ToLower(strings.TrimSpace(name))
		for _, line := range headerLines {
			if idx := strings.Index(line, ":"); idx > 0 {
				hn := strings.ToLower(strings.TrimSpace(line[:idx]))
				if hn == name {
					parts = append(parts, canonicalize(line))
				}
			}
		}
	}
	return strings.Join(parts, "\r\n") + "\r\ndkim-signature:" + dkimSigBody(sig)
}

func dkimRelaxedHeader(line string) string {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return line
	}
	return strings.ToLower(strings.TrimSpace(parts[0])) + ":" + strings.TrimSpace(parts[1])
}

func dkimSigBody(sig *DKIMSig) string {
	base := fmt.Sprintf("v=1; a=%s; c=%s; d=%s; s=%s; t=%d; x=%d; h=%s",
		sig.Algorithm, sig.Canonical, sig.Domain, sig.Selector,
		sig.Created, sig.Expires,
		strings.Join(sig.Headers, ":"))
	if sig.Length > 0 {
		base += fmt.Sprintf("; l=%d", sig.Length)
	}
	base += fmt.Sprintf("; bh=%s; b=", sig.BodyHash)
	return base
}

// dkimBodyHash computes the canonicalized body hash per RFC 6376 §3.4.
// If bodyLen > 0, the hash covers only the first bodyLen bytes of the
// canonicalized body per RFC 6376 §3.5 (the l= tag).
func dkimBodyHash(body []byte, canonical string, bodyLen int64) []byte {
	mode := "simple"
	if parts := strings.Split(canonical, "/"); len(parts) >= 2 {
		mode = parts[1]
	}
	if mode == "relaxed" {
		body = dkimRelaxedBody(body)
	} else {
		body = dkimSimpleBody(body)
	}
	if bodyLen > 0 && int64(len(body)) > bodyLen {
		body = body[:bodyLen]
	}
	h := sha256.Sum256(body)
	return h[:]
}

func dkimSimpleBody(body []byte) []byte {
	// Ignore all trailing empty lines; ensure exactly one CRLF at end (RFC 6376 §3.4.3)
	s := strings.TrimRight(string(body), "\r\n")
	return []byte(s + "\r\n")
}

func dkimRelaxedBody(body []byte) []byte {
	// Reduce sequences of WSP to single SP; ignore trailing whitespace; collapse empty lines
	lines := strings.Split(string(body), "\n")
	var out []string
	for _, line := range lines {
		// Strip trailing CR first, then whitespace (RFC 6376 §3.4.4 step a)
		line = strings.TrimSuffix(line, "\r")
		line = strings.TrimRight(line, " \t")
		line = collapseWSP(line)
		out = append(out, line)
	}
	bodyStr := strings.TrimRight(strings.Join(out, "\r\n"), "\r\n")
	if bodyStr != "" {
		bodyStr += "\r\n"
	}
	return []byte(bodyStr)
}

func collapseWSP(s string) string {
	var result []byte
	prev := false
	for _, c := range []byte(s) {
		if c == ' ' || c == '\t' {
			if !prev {
				result = append(result, ' ')
				prev = true
			}
		} else {
			result = append(result, c)
			prev = false
		}
	}
	return string(result)
}

// dkimSimpleHeader returns the header line for simple canonicalization.
func dkimSimpleHeader(line string) string {
	return strings.TrimRight(line, "\r\n")
}

// SignDKIM creates a DKIM-Signature header for an outbound message.
func SignDKIM(rawMsg []byte, selector, domain string, privateKey *rsa.PrivateKey) (string, error) {
	now := time.Now()
	sig := &DKIMSig{
		Domain:    domain,
		Selector:  selector,
		Algorithm: "rsa-sha256",
		Headers:   []string{"from", "to", "subject", "date"},
		Canonical: "relaxed/relaxed",
		Created:   now.Unix(),
		Expires:   now.Add(7 * 24 * time.Hour).Unix(),
	}

	// Compute l= (RFC 6376 §3.5) and bh= (§3.7) in the SAME canonical byte
	// space: SignDKIM always signs relaxed/relaxed, so canonicalize the body
	// once, derive l= from it (everything except the final CRLF), and hash bh=
	// over the l=-truncated canonical body. Computing bh= over the UNTRUNCATED
	// body while emitting l= produced an outbound signature no RFC 6376
	// verifier — including our own VerifyDKIM — could accept.
	_, body := splitHeadersBody(rawMsg)
	canonBody := dkimRelaxedBody(body)
	if strings.HasSuffix(string(canonBody), "\r\n") {
		sig.Length = int64(len(canonBody) - 2)
	}
	bodyHashBytes := dkimBodyHash(body, sig.Canonical, sig.Length)
	sig.BodyHash = base64.StdEncoding.EncodeToString(bodyHashBytes)

	// Build signed data
	signedData := dkimSignedData(string(rawMsg), sig)
	hash := sha256.Sum256([]byte(signedData))

	// crypto.SHA256 (NOT crypto.Hash(0)): sign RSASSA-PKCS1-v1_5 over the RFC
	// 8017 §9.2 DigestInfo-wrapped SHA-256 digest so external RFC 6376 verifiers
	// accept our outbound signatures (D-MAILSERVER-INTERNAL-SMTP-V002).
	signature, err := rsa.SignPKCS1v15(nil, privateKey, crypto.SHA256, hash[:])
	if err != nil {
		return "", err
	}
	sig.Signature = signature

	b64Sig := base64.StdEncoding.EncodeToString(signature)
	// Tag order MUST match dkimSigBody (what the signature actually covers):
	// h= before l=. An emitted header that differs from the signed
	// reconstruction is unverifiable by any RFC 6376 verifier.
	header := fmt.Sprintf(
		"v=1; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s; t=%d; x=%d; h=%s; l=%d; bh=%s; b=%s",
		domain, selector, sig.Created, sig.Expires,
		strings.Join(sig.Headers, ":"), sig.Length, sig.BodyHash, b64Sig,
	)
	return header, nil
}

// ParseRSAPrivateKey parses a PEM-encoded RSA private key.
func ParseRSAPrivateKey(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS8
		key8, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, err
		}
		var ok bool
		key, ok = key8.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA key")
		}
	}
	return key, nil
}
