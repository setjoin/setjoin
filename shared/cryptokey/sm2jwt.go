package cryptokey

import (
	"crypto"
	"crypto/ecdsa"
	crand "crypto/rand"
	"errors"
	"fmt"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/sm3"
	"github.com/golang-jwt/jwt/v5"
)

// SigningMethodSM2 is a JWT signing method using SM2 + SM3 (alg: "SM2").
// Implements a private algorithm per RFC 7518 §3.1 — bilateral between
// authserver and gateway only.
type SigningMethodSM2 struct{}

func init() {
	jwt.RegisterSigningMethod("SM2", func() jwt.SigningMethod {
		return &SigningMethodSM2{}
	})
}

func (m *SigningMethodSM2) Alg() string {
	return "SM2"
}

func (m *SigningMethodSM2) Sign(signingString string, key any) ([]byte, error) {
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("SM2 signing requires *ecdsa.PrivateKey, got %T", key)
	}
	if priv.Curve != sm2.P256() {
		return nil, errors.New("SM2 signing requires key on SM2 P-256 curve")
	}

	// Hash the signing string with SM3
	hash := sm3.Sum([]byte(signingString))

	// Wrap as sm2.PrivateKey for signing
	sm2Priv := &sm2.PrivateKey{PrivateKey: *priv}

	return sm2.SignASN1(crand.Reader, sm2Priv, hash[:], nil)
}

func (m *SigningMethodSM2) Verify(signingString string, sig []byte, key any) error {
	var pubKey *ecdsa.PublicKey
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		pubKey = k
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case crypto.PublicKey:
		if pk, ok := k.(*ecdsa.PublicKey); ok {
			pubKey = pk
		}
	default:
		return fmt.Errorf("SM2 verification requires *ecdsa.PublicKey, got %T", key)
	}

	if pubKey == nil {
		return errors.New("SM2 verification: nil public key")
	}
	if pubKey.Curve != sm2.P256() {
		return errors.New("SM2 verification requires key on SM2 P-256 curve")
	}

	// Hash the signing string with SM3
	hash := sm3.Sum([]byte(signingString))

	if !sm2.VerifyASN1(pubKey, hash[:], sig) {
		return errors.New("SM2 signature verification failed")
	}

	return nil
}
