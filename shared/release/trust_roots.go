package release

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

type TrustRootDocument struct {
	SchemaVersion int             `json:"schema_version"`
	Purpose       KeyPurpose      `json:"purpose"`
	Keys          []TrustRootWire `json:"keys"`
}

type TrustRootWire struct {
	ID        string `json:"id"`
	Algorithm string `json:"algorithm"`
	PublicKey string `json:"public_key"`
	TestOnly  bool   `json:"test_only,omitempty"`
}

func ParseTrustRootDocument(data []byte, expectedPurpose KeyPurpose, allowTestRoots bool) ([]TrustedKey, error) {
	var document TrustRootDocument
	if err := strictDecode(data, &document); err != nil {
		return nil, fmt.Errorf("trust roots: %w", err)
	}
	if document.SchemaVersion != 1 || document.Purpose != expectedPurpose {
		return nil, fmt.Errorf("trust root schema or purpose mismatch")
	}
	if len(document.Keys) == 0 || len(document.Keys) > 16 {
		return nil, fmt.Errorf("trust root key count must be between 1 and 16")
	}
	keys := make([]TrustedKey, 0, len(document.Keys))
	seen := map[string]bool{}
	for _, wire := range document.Keys {
		if !identifierRE.MatchString(wire.ID) || wire.Algorithm != "ed25519" || seen[wire.ID] {
			return nil, fmt.Errorf("invalid or duplicate trust root key")
		}
		seen[wire.ID] = true
		publicKey, err := base64.RawStdEncoding.DecodeString(wire.PublicKey)
		if err != nil || len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid trust root public key")
		}
		if wire.TestOnly && !allowTestRoots {
			return nil, fmt.Errorf("test trust root %q is forbidden by production policy", wire.ID)
		}
		keys = append(keys, TrustedKey{ID: wire.ID, Purpose: wirePurpose(expectedPurpose), PublicKey: ed25519.PublicKey(publicKey), TestOnly: wire.TestOnly})
	}
	return keys, nil
}

func wirePurpose(purpose KeyPurpose) KeyPurpose {
	return purpose
}
