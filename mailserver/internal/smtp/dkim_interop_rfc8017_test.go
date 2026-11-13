package smtp

// RFC 8017 DigestInfo interop for the rsa-sha256 DKIM path
// (D-MAILSERVER-INTERNAL-SMTP-V002). Before the fix both the verifier and
// SignDKIM passed crypto.Hash(0), i.e. RSASSA-PKCS1-v1_5 over the BARE SHA-256
// digest, so every standards-compliant external rsa-sha256 signature verified
// as DKIMFail and our outbound signatures were nonstandard. These cells prove
// the DigestInfo-prefixed construction interops in BOTH directions — external
// signer → our verifier, and our SignDKIM → an independent external RFC 6376
// verifier — and that the bare-digest form is rejected. No network: the
// selector key record is served by the stubbed DNS resolver.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

const (
	dkimInteropDomain   = "interop-rfc8017.test"
	dkimInteropSelector = "probe"
	dkimInteropBody     = "Interoperability body for the RFC 8017 DigestInfo probe.\r\n"
)

func dkimInteropKeyRecord(t *testing.T, key *rsa.PrivateKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal rsa pubkey: %v", err)
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
}

// externalSignMessage plays the standards-compliant EXTERNAL RFC 6376 signer:
// relaxed/relaxed canonicalization, the digest taken over its OWN canonicalized
// DKIM-Signature header (b= value stripped, lowercase field name) plus the
// selected headers, and — when digestInfo is true, the only form real-world
// implementations emit — RSASSA-PKCS1-v1_5 over the RFC 8017 §9.2
// DigestInfo-wrapped SHA-256 digest. digestInfo=false produces the legacy
// bare-digest form the old crypto.Hash(0) verifier used to require. The
// emitted header tag order matches the verifier's reconstruction so the cell
// isolates the DigestInfo property and not header-form quirks.
func externalSignMessage(t *testing.T, key *rsa.PrivateKey, digestInfo bool) string {
	t.Helper()
	bh := sha256.Sum256([]byte(dkimInteropBody))
	headNoB := fmt.Sprintf(
		"DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s; t=1725900000; x=1726504800; h=from:to:subject:date; bh=%s; b=",
		dkimInteropDomain, dkimInteropSelector, base64.StdEncoding.EncodeToString(bh[:]))
	unsigned := "From: Alice <alice@" + dkimInteropDomain + ">\r\n" +
		"To: bob@example.org\r\n" +
		"Subject: external interop probe\r\n" +
		"Date: Thu, 10 Sep 2026 10:00:00 +0000\r\n\r\n" + dkimInteropBody

	// Relaxed header canonicalization (RFC 6376 §3.7): the h= listed headers in
	// order, then the DKIM-Signature header itself (lowercase field name, WSP
	// around the colon removed, b= value stripped) hashed LAST.
	signedData := "from:Alice <alice@" + dkimInteropDomain + ">\r\n" +
		"to:bob@example.org\r\n" +
		"subject:external interop probe\r\n" +
		"date:Thu, 10 Sep 2026 10:00:00 +0000\r\n" +
		"dkim-signature:" + strings.TrimLeft(strings.TrimPrefix(headNoB, "DKIM-Signature:"), " \t")
	digest := sha256.Sum256([]byte(signedData))

	hashID := crypto.SHA256
	if !digestInfo {
		hashID = 0 // crypto.Hash(0): bare digest — the defect form
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, hashID, digest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15: %v", err)
	}
	return headNoB + base64.StdEncoding.EncodeToString(sig) + "\r\n" + unsigned
}

func setDKIMInteropDNS(t *testing.T, key *rsa.PrivateKey) {
	t.Helper()
	record := dkimInteropKeyRecord(t, key)
	setDNSResolvers(func(d string) ([]string, error) {
		if d == dkimInteropSelector+"._domainkey."+dkimInteropDomain {
			return []string{record}, nil
		}
		return nil, fmt.Errorf("NXDOMAIN")
	}, nil, nil, nil)
	t.Cleanup(ResetDNSResolver)
}

// TestDKIMInterop_ExternalStandardSignatureVerifies: a signature produced by a
// standards-compliant external rsa-sha256 implementation (DigestInfo prefix)
// must verify DKIMPass — before the fix it was DKIMFail.
func TestDKIMInterop_ExternalStandardSignatureVerifies(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	setDKIMInteropDNS(t, key)

	msg := externalSignMessage(t, key, true)
	result, signedLen := VerifyDKIM([]byte(msg), dkimInteropDomain)
	if result != DKIMPass {
		t.Fatalf("VerifyDKIM(external DigestInfo signature) = %q, want %q — an external RFC 6376 signer must verify", result, DKIMPass)
	}
	if signedLen != 0 {
		t.Errorf("signedLen = %d, want 0 (no l= tag)", signedLen)
	}
}

// TestDKIMInterop_BareDigestSignatureRejected: the legacy bare-digest form
// (what crypto.Hash(0) produced/accepted) must NOT verify now that the RFC
// 8017 DigestInfo prefix is enforced.
func TestDKIMInterop_BareDigestSignatureRejected(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	setDKIMInteropDNS(t, key)

	msg := externalSignMessage(t, key, false)
	result, _ := VerifyDKIM([]byte(msg), dkimInteropDomain)
	if result != DKIMFail {
		t.Fatalf("VerifyDKIM(bare-digest signature) = %q, want %q — the DigestInfo prefix must be required", result, DKIMFail)
	}
}

// externalRFC6376Verify is an INDEPENDENT minimal external RFC 6376 verifier
// (relaxed/relaxed): it deliberately shares no helper code with dkim.go so it
// can catch drift in our outbound signing. It verifies bh=, reconstructs the
// signed data from the REAL canonicalized headers (b= value stripped), honors
// l=, and checks the RSASSA-PKCS1-v1_5 signature over the RFC 8017
// DigestInfo-wrapped SHA-256 digest.
func externalRFC6376Verify(t *testing.T, wire string, pub *rsa.PublicKey) bool {
	t.Helper()
	sep := strings.Index(wire, "\r\n\r\n")
	if sep < 0 {
		t.Fatal("external verifier: no header/body separator")
	}
	headerBlock, body := wire[:sep], wire[sep+4:]

	var sigLine string
	var headerLines []string
	for _, line := range strings.Split(headerBlock, "\r\n") {
		headerLines = append(headerLines, line)
		if strings.HasPrefix(strings.ToLower(line), "dkim-signature:") {
			sigLine = line
		}
	}
	if sigLine == "" {
		t.Fatal("external verifier: no DKIM-Signature header")
	}

	// Parse the tags of the signature header.
	colon := strings.Index(sigLine, ":")
	// Relaxed: delete WSP on both sides of the colon.
	value := strings.TrimLeft(sigLine[colon+1:], " \t")
	tags := map[string]string{}
	for _, part := range strings.Split(value, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 {
			tags[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
		}
	}
	if tags["a"] != "rsa-sha256" {
		t.Fatalf("external verifier: unexpected algorithm %q", tags["a"])
	}

	// The signature header itself is canonicalized with the b= VALUE removed
	// (RFC 6376 §3.7). Locate the ';'-separated b= segment deterministically
	// (a naive substring search could land inside the base64 payload) and cut
	// the header right after its "b=" tag name.
	segStart := -1
	offset := 0
	for _, seg := range strings.Split(value, ";") {
		if strings.HasPrefix(strings.TrimSpace(seg), "b=") {
			segStart = offset
			break
		}
		offset += len(seg) + 1 // consume the segment plus its ';' separator
	}
	if segStart < 0 {
		t.Fatal("external verifier: no b= tag")
	}
	// value[:segStart] ends at the ';'; relaxed keeps a single SP separator
	// before the tag name, and the b= VALUE is dropped.
	prefix := value[:segStart]
	if segStart > 0 && !strings.HasSuffix(prefix, " ") {
		prefix += " "
	}
	sigHeaderCanon := "dkim-signature:" + prefix + "b="
	sigHeaderCanon = strings.TrimRight(sigHeaderCanon, " \t")

	// Relaxed canonicalization of a header line.
	relax := func(line string) string {
		c := strings.Index(line, ":")
		if c < 0 {
			return line
		}
		name := strings.ToLower(strings.TrimSpace(line[:c]))
		val := strings.TrimLeft(line[c+1:], " \t")
		var buf strings.Builder
		prevSpace := false
		for i := 0; i < len(val); i++ {
			ch := val[i]
			if ch == ' ' || ch == '\t' {
				if !prevSpace {
					buf.WriteByte(' ')
				}
				prevSpace = true
			} else {
				buf.WriteByte(ch)
				prevSpace = false
			}
		}
		return name + ":" + strings.TrimRight(buf.String(), " ")
	}

	// h= listed headers in message order.
	var selected []string
	for _, name := range strings.Split(tags["h"], ":") {
		name = strings.ToLower(strings.TrimSpace(name))
		for _, line := range headerLines {
			c := strings.Index(line, ":")
			if c > 0 && strings.ToLower(strings.TrimSpace(line[:c])) == name {
				selected = append(selected, relax(line))
				break
			}
		}
	}
	signedData := strings.Join(selected, "\r\n") + "\r\n" + sigHeaderCanon

	// Relaxed body canonicalization + l= truncation (RFC 6376 §3.4.4/§3.5).
	lines := strings.Split(body, "\n")
	var canon []string
	for _, line := range lines {
		line = strings.TrimSuffix(line, "\r")
		line = strings.TrimRight(line, " \t")
		var buf strings.Builder
		prevSpace := false
		for i := 0; i < len(line); i++ {
			ch := line[i]
			if ch == ' ' || ch == '\t' {
				if !prevSpace {
					buf.WriteByte(' ')
				}
				prevSpace = true
			} else {
				buf.WriteByte(ch)
				prevSpace = false
			}
		}
		canon = append(canon, buf.String())
	}
	canonicalBody := strings.TrimRight(strings.Join(canon, "\r\n"), "\r\n")
	if canonicalBody != "" {
		canonicalBody += "\r\n"
	}
	var bodyLen int64
	fmt.Sscanf(tags["l"], "%d", &bodyLen)
	if bodyLen > 0 && int64(len(canonicalBody)) > bodyLen {
		canonicalBody = canonicalBody[:bodyLen]
	}

	// bh= check.
	bhDigest := sha256.Sum256([]byte(canonicalBody))
	wantBH, err := base64.StdEncoding.DecodeString(tags["bh"])
	if err != nil || string(wantBH) != string(bhDigest[:]) {
		t.Log("external verifier: bh= mismatch")
		return false
	}

	// b= signature over the RFC 8017 DigestInfo-wrapped digest.
	sigBytes, err := base64.StdEncoding.DecodeString(tags["b"])
	if err != nil {
		t.Fatalf("external verifier: b= not base64: %v", err)
	}
	digest := sha256.Sum256([]byte(signedData))
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sigBytes) == nil
}

// TestDKIMInterop_OutboundSignatureVerifiedByExternalVerifier: SignDKIM's
// outbound signature must verify under an independent external RFC 6376
// verifier — i.e. it is a STANDARD DigestInfo-prefixed signature, not the
// legacy bare-digest form.
func TestDKIMInterop_OutboundSignatureVerifiedByExternalVerifier(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}

	raw := "From: Alice <alice@" + dkimInteropDomain + ">\r\n" +
		"To: bob@example.org\r\n" +
		"Subject: outbound interop probe\r\n" +
		"Date: Thu, 10 Sep 2026 11:00:00 +0000\r\n" +
		"\r\n" +
		"Outbound body for the external verifier probe.\r\n"

	header, err := SignDKIM([]byte(raw), dkimInteropSelector, dkimInteropDomain, key)
	if err != nil {
		t.Fatalf("SignDKIM: %v", err)
	}
	// SignDKIM returns the bare header VALUE; compose it into the full header
	// line the way a message on the wire carries it.
	wire := "DKIM-Signature: " + header + "\r\n" + raw

	if !externalRFC6376Verify(t, wire, &key.PublicKey) {
		t.Fatal("external RFC 6376 verifier rejected our outbound signature — SignDKIM is not emitting a standards-compliant rsa-sha256 signature")
	}
}

// TestDKIMInterop_SignVerifyRoundTrip: the DKIM sign+verify round-trip uses the
// standard RFC 8017 DigestInfo prefix — a signature SignDKIM emits verifies
// under our own verifier with the DNS key published.
func TestDKIMInterop_SignVerifyRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	setDKIMInteropDNS(t, key)

	raw := "From: Alice <alice@" + dkimInteropDomain + ">\r\n" +
		"To: bob@example.org\r\n" +
		"Subject: round trip probe\r\n" +
		"Date: Thu, 10 Sep 2026 12:00:00 +0000\r\n" +
		"\r\n" +
		"Round-trip body for the DigestInfo probe.\r\n"

	header, err := SignDKIM([]byte(raw), dkimInteropSelector, dkimInteropDomain, key)
	if err != nil {
		t.Fatalf("SignDKIM: %v", err)
	}
	wire := "DKIM-Signature: " + header + "\r\n" + raw

	result, _ := VerifyDKIM([]byte(wire), dkimInteropDomain)
	if result != DKIMPass {
		t.Fatalf("SignDKIM→VerifyDKIM round trip = %q, want %q", result, DKIMPass)
	}
}
