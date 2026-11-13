package smime

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	encoding_base64 "encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// ErrNoMatchingKey is returned by DecryptMulti when the EnvelopedData parsed
// cleanly but NONE of the supplied keys matches a RecipientInfo (the "rotated /
// foreign certificate" read state — distinct from a malformed-CMS parse error).
var ErrNoMatchingKey = errors.New("smime: no candidate key matches any RecipientInfo")

// DecryptKey is one of the reader's keystore keypairs (parsed cert + RSA key).
// Decrypt-on-read tries every key the reader holds because key rollover and
// encrypt-to-self mean the EnvelopedData may name any of several of the reader's
// certificates as a recipient.
type DecryptKey struct {
	Cert *x509.Certificate
	Key  *rsa.PrivateKey
}

// DecryptMulti tries each key against the EnvelopedData's RecipientInfos and
// returns the cleartext from the first whose serial matches a RecipientInfo AND
// whose session-key unwrap + body decrypt both succeed. It returns ErrNoMatchingKey
// when the CMS parses but no candidate yields a clean decrypt — whether because no
// serial matched OR because a matched RecipientInfo's unwrap/body failed. Those two
// are DELIBERATELY collapsed into one result to deny a Bleichenbacher padding
// oracle (see the loop body): a chosen-ciphertext probe must not learn from the
// caller whether its RSA padding was valid. Only a malformed-CMS parse error is
// returned distinctly, BEFORE the match loop (so "corrupt blob" stays separable
// from "you don't hold the key").
//
// ciphertextDER is the bare DER-encoded PKCS#7 EnvelopedData or AuthEnvelopedData
// ContentInfo (use DecodeEnvelopedDER first if you hold the MIME/base64 wire
// artifact). Both content types are accepted: RFC 5652 EnvelopedData (AES-CBC,
// S/MIME 3.2 — the backward-compat mandate) and RFC 5083 AuthEnvelopedData
// (AES-GCM, S/MIME 4.0 — what Encrypt now emits); see parseEnvelopedAny.
func DecryptMulti(ciphertextDER []byte, keys []DecryptKey) ([]byte, error) {
	if len(keys) == 0 {
		return nil, errors.New("smime: no candidate keys supplied")
	}

	env, err := parseEnvelopedAny(ciphertextDER)
	if err != nil {
		return nil, err
	}

	for _, k := range keys {
		if k.Cert == nil || k.Key == nil {
			continue
		}
		for _, ri := range env.recipientInfos {
			if ri.IssuerAndSerialNumber.Serial == nil ||
				ri.IssuerAndSerialNumber.Serial.Cmp(k.Cert.SerialNumber) != 0 {
				continue
			}
			// Bleichenbacher (PKCS#1 v1.5) RSA padding-oracle countermeasure:
			// DecryptPKCS1v15SessionKey leaves the pre-randomised, fixed-length
			// buffer untouched (returning NO error) when the padding is invalid, so
			// the symmetric unwrap below fails identically whether the padding was
			// valid-but-wrong or invalid — a chosen-ciphertext probe sees the same
			// ErrNoMatchingKey either way and learns nothing about padding validity.
			// rsa.DecryptPKCS1v15 (the obvious call) MUST NOT be used: its error is
			// the oracle. A returned error here is only a structural (wrong-length)
			// ciphertext, which is padding-independent and known to the sender.
			sessionKey := make([]byte, aesSessionKeyLen)
			if _, err := rand.Read(sessionKey); err != nil {
				return nil, fmt.Errorf("smime: session-key fallback rng: %w", err)
			}
			if err := rsa.DecryptPKCS1v15SessionKey(rand.Reader, k.Key, ri.EncryptedKey, sessionKey); err != nil {
				continue
			}
			// env.decrypt failing (random fallback key, a serial collision across
			// unrelated CAs, or a genuinely corrupt body / failed GCM tag check) is
			// deliberately NOT distinguished from "no recipient matched": keep
			// scanning and fall through to ErrNoMatchingKey so the two states are
			// indistinguishable.
			if pt, err := env.decrypt(sessionKey); err == nil {
				return pt, nil
			}
		}
	}
	return nil, ErrNoMatchingKey
}

// DecodeEnvelopedDER normalizes a stored encrypted-mail artifact into the bare
// EnvelopedData DER that DecryptMulti/Decrypt consume. It accepts either:
//   - the application/pkcs7-mime wire form Encrypt() emits (MIME headers, then a
//     base64 body), in which case the header block is stripped and the body
//     base64-decoded; or
//   - bare DER (no MIME headers — e.g. `openssl cms -encrypt -outform DER`), which
//     is returned unchanged.
//
// It deliberately performs no crypto: it only frames the input. Centralizing this
// (rather than inlining base64 logic at the call site) keeps the wire-format
// knowledge in one package, covered by the smime oracle tests.
func DecodeEnvelopedDER(artifact []byte) ([]byte, error) {
	if len(artifact) == 0 {
		return nil, errors.New("smime: empty enveloped artifact")
	}
	// Bare DER begins with the ASN.1 SEQUENCE tag 0x30; the MIME form begins with
	// "Content-Type:" (ASCII 'C'). Anything starting with 0x30 is treated as DER.
	if artifact[0] == 0x30 {
		return artifact, nil
	}

	s := string(artifact)
	// Split the MIME header block from the body at the first blank line.
	sep := strings.Index(s, "\r\n\r\n")
	bodyStart := sep + 4
	if sep < 0 {
		if sep = strings.Index(s, "\n\n"); sep < 0 {
			return nil, errors.New("smime: no header/body separator in enveloped artifact")
		}
		bodyStart = sep + 2
	}
	body := s[bodyStart:]
	body = strings.ReplaceAll(body, "\r\n", "")
	body = strings.ReplaceAll(body, "\n", "")
	body = strings.TrimSpace(body)
	der, err := encoding_base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, fmt.Errorf("smime: base64 decode of enveloped body: %w", err)
	}
	return der, nil
}
