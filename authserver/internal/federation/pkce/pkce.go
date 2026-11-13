// Package pkce implements the relying-party side of PKCE (Proof Key for Code
// Exchange, RFC 7636) for outbound authorization-code flows.
//
// S256 is the only code_challenge_method implemented: the plain transformation
// is an explicit echo of the verifier and offers no protection against
// authorization-code interception, which is the entire threat model PKCE
// exists for (RFC 7636 §1, RFC 8252 §8.1). The package is standalone and
// dependency-free so the OIDC RP (internal/federation/oidc_rp.go) and any
// future authorization-code client share one audited implementation.
package pkce

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
)

// MethodS256 is the code_challenge_method this package implements
// (RFC 7636 §4.3).
const MethodS256 = "S256"

const (
	// verifierEntropyBytes is the CSPRNG entropy per generated code_verifier.
	// 32 bytes encode to exactly 43 base64url characters, the RFC 7636 §4.1
	// minimum length.
	verifierEntropyBytes = 32

	// minVerifierLength and maxVerifierLength are the RFC 7636 §4.1 bounds on
	// a code_verifier's character count.
	minVerifierLength = 43
	maxVerifierLength = 128
)

// NewVerifier returns a fresh RFC 7636 §4.1 code_verifier: 43 characters from
// the unreserved alphabet (base64url, unpadded, of 32 CSPRNG bytes).
func NewVerifier() (string, error) {
	b := make([]byte, verifierEntropyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("pkce: code_verifier entropy: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// ValidateVerifier enforces the RFC 7636 §4.1 code_verifier syntax: 43-128
// characters drawn from the unreserved set ALPHA / DIGIT / "-" / "." / "_" /
// "~". It is the fail-closed gate applied before a verifier is accepted from
// flow state or presented to a token endpoint.
func ValidateVerifier(verifier string) error {
	if l := len(verifier); l < minVerifierLength {
		return fmt.Errorf("pkce: code_verifier must be at least %d characters, got %d", minVerifierLength, l)
	}
	if l := len(verifier); l > maxVerifierLength {
		return fmt.Errorf("pkce: code_verifier must be at most %d characters, got %d", maxVerifierLength, l)
	}
	for i := 0; i < len(verifier); i++ {
		if !isUnreserved(verifier[i]) {
			return fmt.Errorf("pkce: code_verifier contains invalid character %#02x at offset %d", verifier[i], i)
		}
	}
	return nil
}

// ChallengeS256 derives the S256 code_challenge for verifier (RFC 7636 §4.2):
// BASE64URL-ENCODE(SHA256(ASCII(code_verifier))), unpadded. The verifier must
// pass ValidateVerifier.
func ChallengeS256(verifier string) (string, error) {
	if err := ValidateVerifier(verifier); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// Verify reports whether verifier derives challenge under S256. The comparison
// is constant-time. A malformed verifier or a mismatch is an error.
func Verify(verifier, challenge string) error {
	derived, err := ChallengeS256(verifier)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare([]byte(derived), []byte(challenge)) != 1 {
		return errors.New("pkce: code_verifier does not match code_challenge")
	}
	return nil
}

// isUnreserved reports whether c is in the RFC 7636 §4.1 unreserved alphabet.
func isUnreserved(c byte) bool {
	return (c >= 'A' && c <= 'Z') ||
		(c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}
