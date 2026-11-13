// Package continuity defines portable signed rollback-witness and mail-receipt
// artifacts. It contains no database access, authorization, or key persistence.
package continuity

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"
)

const (
	Version          = 1
	MaxCompactBytes  = 16 << 10
	DefaultClockSkew = 5 * time.Minute
)

var (
	ErrMalformed        = errors.New("malformed continuity artifact")
	ErrUnknownKey       = errors.New("unknown continuity signing key")
	ErrInvalidSignature = errors.New("invalid continuity signature")
	ErrExpired          = errors.New("continuity artifact is outside its validity window")
	ErrScope            = errors.New("continuity artifact scope mismatch")
)

type Signer struct {
	KeyID      string
	PrivateKey ed25519.PrivateKey
}

func (s Signer) Validate() error {
	if !validIdentifier(s.KeyID, 1, 64) || len(s.PrivateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("%w: invalid signer", ErrMalformed)
	}
	return nil
}

type VerificationKey struct {
	PublicKey ed25519.PublicKey
	NotBefore time.Time
	NotAfter  time.Time
}

type KeySet struct {
	Keys map[string]VerificationKey
}

func (set KeySet) key(keyID string, issuedAt, now time.Time, skew time.Duration) (ed25519.PublicKey, error) {
	key, ok := set.Keys[keyID]
	if !ok {
		return nil, ErrUnknownKey
	}
	if len(key.PublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: invalid public key", ErrMalformed)
	}
	if skew < 0 {
		return nil, fmt.Errorf("%w: negative clock skew", ErrMalformed)
	}
	if (!key.NotBefore.IsZero() && issuedAt.Add(skew).Before(key.NotBefore)) ||
		(!key.NotAfter.IsZero() && issuedAt.Add(-skew).After(key.NotAfter)) ||
		issuedAt.After(now.Add(skew)) {
		return nil, ErrExpired
	}
	return key.PublicKey, nil
}
