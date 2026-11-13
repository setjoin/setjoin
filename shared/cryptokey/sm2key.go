package cryptokey

import (
	"crypto/ecdsa"
	crand "crypto/rand"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

// LoadSM2PrivateKey reads an SM2 private key from a PEM file.
// Accepts both "EC PRIVATE KEY" (SEC 1) and "PRIVATE KEY" (PKCS#8) formats.
func LoadSM2PrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read SM2 key file %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}
	var key *ecdsa.PrivateKey
	switch block.Type {
	case "EC PRIVATE KEY":
		key, err = smx509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse EC private key from %s: %w", path, err)
		}
	case "PRIVATE KEY":
		parsed, err := smx509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 private key from %s: %w", path, err)
		}
		// smx509 returns *sm2.PrivateKey for SM2 keys; extract the embedded *ecdsa.PrivateKey
		switch k := parsed.(type) {
		case *ecdsa.PrivateKey:
			key = k
		case *sm2.PrivateKey:
			key = &k.PrivateKey
		default:
			return nil, fmt.Errorf("key in %s is not an ECDSA/SM2 private key (got %T)", path, parsed)
		}
	default:
		return nil, fmt.Errorf("unsupported PEM block type %q in %s", block.Type, path)
	}
	// Verify the key is on the SM2 curve
	if key.Curve != sm2.P256() {
		return nil, fmt.Errorf("key in %s is not on the SM2 P-256 curve", path)
	}
	return key, nil
}

// GenerateSM2Key generates a new SM2 key pair and returns the key and PEM-encoded
// private key bytes (SEC 1 "EC PRIVATE KEY" format).
func GenerateSM2Key() (*ecdsa.PrivateKey, []byte, error) {
	priv, err := sm2.GenerateKey(crand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate SM2 key: %w", err)
	}
	der, err := smx509.MarshalECPrivateKey(&priv.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal SM2 key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	})
	return &priv.PrivateKey, pemBytes, nil
}
