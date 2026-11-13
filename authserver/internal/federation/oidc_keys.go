package federation

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
	"sync"

	jose "github.com/go-jose/go-jose/v4"
)

// OIDCKeyManager manages the RSA keypair for OIDC token signing (RS256).
type OIDCKeyManager struct {
	mu         sync.RWMutex
	key        *rsa.PrivateKey
	keyID      string
	pubDER     []byte
	cachedSign *oidcSigningKey
	cachedPub  *oidcPublicKey
}

// LoadOrGenerateKey loads an RSA keypair from disk or generates a new 2048-bit key.
func LoadOrGenerateKey(privateKeyPath, publicKeyPath string) (*OIDCKeyManager, error) {
	if privateKeyPath == "" || publicKeyPath == "" || privateKeyPath == publicKeyPath {
		return nil, fmt.Errorf("OIDC key paths must be non-empty and distinct")
	}
	km := &OIDCKeyManager{}

	privData, err := os.ReadFile(privateKeyPath)
	switch {
	case err == nil:
		block, _ := pem.Decode(privData)
		if block == nil {
			return nil, fmt.Errorf("parse OIDC private key: PEM block is missing")
		}
		key, parseErr := x509.ParsePKCS8PrivateKey(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("parse OIDC private key: %w", parseErr)
		}
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("parse OIDC private key: key is not RSA")
		}
		if err := rsaKey.Validate(); err != nil {
			return nil, fmt.Errorf("validate OIDC private key: %w", err)
		}
		if err := os.Chmod(privateKeyPath, 0600); err != nil {
			return nil, fmt.Errorf("restrict OIDC private key permissions: %w", err)
		}
		km.key = rsaKey
	case os.IsNotExist(err):
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate RSA key: %w", err)
		}
		km.key = key

		privBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("marshal private key: %w", err)
		}
		privateFile, err := os.OpenFile(
			privateKeyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600,
		)
		if err != nil {
			return nil, fmt.Errorf("write private key: %w", err)
		}
		privateWritten := false
		defer func() {
			if !privateWritten {
				_ = os.Remove(privateKeyPath)
			}
		}()
		if _, err := privateFile.Write(pem.EncodeToMemory(&pem.Block{
			Type: "PRIVATE KEY", Bytes: privBytes,
		})); err != nil {
			_ = privateFile.Close()
			return nil, fmt.Errorf("write private key: %w", err)
		}
		if err := privateFile.Close(); err != nil {
			return nil, fmt.Errorf("close private key: %w", err)
		}
		privateWritten = true
	case err != nil:
		return nil, fmt.Errorf("read OIDC private key: %w", err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&km.key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	if err := os.WriteFile(publicKeyPath, pem.EncodeToMemory(&pem.Block{
		Type: "PUBLIC KEY", Bytes: pubBytes,
	}), 0644); err != nil {
		return nil, fmt.Errorf("write public key: %w", err)
	}
	if err := os.Chmod(publicKeyPath, 0644); err != nil {
		return nil, fmt.Errorf("set OIDC public key permissions: %w", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&km.key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key DER: %w", err)
	}
	km.pubDER = pubDER
	hash := sha256.Sum256(pubDER)
	km.keyID = base64.RawURLEncoding.EncodeToString(hash[:])
	km.cachedSign = &oidcSigningKey{key: km.key, keyID: km.keyID}
	km.cachedPub = &oidcPublicKey{key: &km.key.PublicKey, keyID: km.keyID}

	return km, nil
}

// KeyID returns the key identifier (SHA-256 of public key DER).
func (km *OIDCKeyManager) KeyID() string {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.keyID
}

// PublicKeyJWK returns the public key as a JWK-compatible map.
func (km *OIDCKeyManager) PublicKeyJWK() map[string]interface{} {
	km.mu.RLock()
	defer km.mu.RUnlock()

	eBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(eBytes, uint32(km.key.E))
	// Trim leading zeros for compact encoding.
	eTrimmed := eBytes
	for len(eTrimmed) > 1 && eTrimmed[0] == 0 {
		eTrimmed = eTrimmed[1:]
	}

	return map[string]interface{}{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": km.keyID,
		"n":   base64.RawURLEncoding.EncodeToString(km.key.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(eTrimmed),
	}
}

// Signer returns an RSA SHA-256 signer for JWT signing.
func (km *OIDCKeyManager) Signer() *RS256Signer {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return &RS256Signer{key: km.key, keyID: km.keyID}
}

// SigningKey returns the key as an op.SigningKey for token signing.
func (km *OIDCKeyManager) SigningKey() *oidcSigningKey {
	return km.cachedSign
}

// PublicKey returns the key as an op.Key for the JWK set.
func (km *OIDCKeyManager) PublicKey() *oidcPublicKey {
	return km.cachedPub
}

// ── op.SigningKey / op.Key implementations ──────────────────────────────

// oidcSigningKey wraps an RSA private key as an op.SigningKey.
type oidcSigningKey struct {
	key   *rsa.PrivateKey
	keyID string
}

func (s *oidcSigningKey) SignatureAlgorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (s *oidcSigningKey) Key() any                                    { return s.key }
func (s *oidcSigningKey) ID() string                                  { return s.keyID }

// oidcPublicKey wraps an RSA public key as an op.Key.
type oidcPublicKey struct {
	key   *rsa.PublicKey
	keyID string
}

func (k *oidcPublicKey) ID() string                         { return k.keyID }
func (k *oidcPublicKey) Algorithm() jose.SignatureAlgorithm { return jose.RS256 }
func (k *oidcPublicKey) Use() string                        { return "sig" }
func (k *oidcPublicKey) Key() any                           { return k.key }

// RS256Signer implements JWT signing with RS256.
type RS256Signer struct {
	key   *rsa.PrivateKey
	keyID string
}

// Sign computes the RS256 signature of data (SHA-256 hash + RSA PKCS#1 v1.5).
func (s *RS256Signer) Sign(data []byte) ([]byte, error) {
	h := sha256.Sum256(data)
	return rsa.SignPKCS1v15(nil, s.key, crypto.SHA256, h[:]) //nolint:staticcheck
}

// Algorithm returns the JWS algorithm identifier.
func (s *RS256Signer) Algorithm() string { return "RS256" }

// KeyID returns the key identifier.
func (s *RS256Signer) KeyID() string { return s.keyID }
