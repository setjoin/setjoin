package pwhash

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strconv"
	"strings"

	"github.com/emmansun/gmsm/sm3"
)

const (
	sm3Prefix  = "$sm3$"
	sm3Cost    = 100_000 // OWASP 2026 recommended iterations for PBKDF2
	sm3SaltLen = 16
	sm3KeyLen  = 32
)

// HashPasswordSM3 generates a PBKDF2-SM3 hash in $sm3$iterations$salt$hash format.
func HashPasswordSM3(password string) (string, error) {
	salt := make([]byte, sm3SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("sm3 salt: %w", err)
	}
	dk := pbkdf2KeyWithHMAC([]byte(password), salt, sm3Cost, sm3KeyLen, sm3.New)
	hashB64 := base64.RawStdEncoding.EncodeToString(dk)
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	return fmt.Sprintf("$sm3$%d$%s$%s", sm3Cost, saltB64, hashB64), nil
}

// VerifyPasswordSM3 verifies a password against a $sm3$ hash.
//
// Degenerate parses FAIL CLOSED. Every parseable-but-meaningless form is
// rejected before any KDF work: a zero or negative iteration count collapses
// the PBKDF2 loop (the "hash" becomes a single PRF evaluation an attacker
// could match), and an empty salt or empty stored digest would
// constant-time-compare equal against a degenerately-derived key — turning
// a corrupted/stored-bad row into an ANY-password acceptance. No write path
// can store such a row today (verified by the triage record); the rejection
// keeps a future one from becoming a verifier bypass.
func VerifyPasswordSM3(hashStr, password string) error {
	// Parse: $sm3$iterations$salt$hash
	parts := strings.Split(hashStr, "$")
	if len(parts) != 5 || parts[1] != "sm3" {
		return errors.New("not a valid sm3 hash")
	}
	iterations, err := strconv.Atoi(parts[2])
	if err != nil {
		return fmt.Errorf("sm3: parse iterations: %w", err)
	}
	if iterations <= 0 {
		return fmt.Errorf("sm3: invalid iteration count %d", iterations)
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil {
		return fmt.Errorf("sm3: decode salt: %w", err)
	}
	if len(salt) == 0 {
		return errors.New("not a valid sm3 hash")
	}
	expected, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return fmt.Errorf("sm3: decode hash: %w", err)
	}
	if len(expected) == 0 {
		return errors.New("not a valid sm3 hash")
	}
	dk := pbkdf2KeyWithHMAC([]byte(password), salt, iterations, len(expected), sm3.New)
	if subtle.ConstantTimeCompare(dk, expected) != 1 {
		return ErrInvalidCredentials
	}
	return nil
}

// IsSM3Hash reports whether hash uses the SM3 password format.
func IsSM3Hash(hash string) bool {
	return strings.HasPrefix(hash, sm3Prefix)
}

// sm3IterationsBelowFloor reports whether a $sm3$ hash was stored with fewer
// PBKDF2 iterations than the current floor (sm3Cost) — a downgrade that should be
// re-hashed after a successful auth. A DEGENERATE iteration count (zero or
// negative) reports true: it is by definition below the floor, so the
// detector can never classify the exact rows the verifier now rejects as
// "fine, no downgrade". Unparseable non-numeric forms stay conservative
// false (verification rejects them separately).
func sm3IterationsBelowFloor(hashStr string) bool {
	parts := strings.Split(hashStr, "$")
	if len(parts) != 5 || parts[1] != "sm3" {
		return false
	}
	iter, err := strconv.Atoi(parts[2])
	if err != nil {
		return false
	}
	if iter <= 0 {
		return true
	}
	return iter < sm3Cost
}

// pbkdf2KeyWithHMAC derives a key using PBKDF2 with an arbitrary hash constructor.
// Implements RFC 2898 / PKCS #5 v2.0 Section 5.2.
func pbkdf2KeyWithHMAC(password, salt []byte, iter, keyLen int, h func() hash.Hash) []byte {
	prf := hmac.New(h, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	dk := make([]byte, 0, numBlocks*hashLen)
	u := make([]byte, hashLen)
	var block [4]byte
	for blockIdx := 1; blockIdx <= numBlocks; blockIdx++ {
		prf.Reset()
		prf.Write(salt)
		binary.BigEndian.PutUint32(block[:], uint32(blockIdx))
		prf.Write(block[:])
		t := prf.Sum(nil)
		copy(u, t)

		for i := 2; i <= iter; i++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range t {
				t[j] ^= u[j]
			}
		}
		dk = append(dk, t...)
	}
	return dk[:keyLen]
}
