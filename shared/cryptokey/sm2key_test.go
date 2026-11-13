package cryptokey

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/emmansun/gmsm/sm2"
	"github.com/emmansun/gmsm/smx509"
)

func TestGenerateSM2Key(t *testing.T) {
	key, pemBytes, err := GenerateSM2Key()
	if err != nil {
		t.Fatalf("GenerateSM2Key: %v", err)
	}
	if key == nil {
		t.Fatal("GenerateSM2Key returned nil key")
	}
	if key.Curve != sm2.P256() {
		t.Error("generated key not on SM2 P-256 curve")
	}
	if len(pemBytes) == 0 {
		t.Error("PEM bytes should not be empty")
	}

	// Verify PEM can be decoded
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("PEM decode failed")
	}
	if block.Type != "EC PRIVATE KEY" {
		t.Errorf("PEM block type = %q, want %q", block.Type, "EC PRIVATE KEY")
	}
}

func TestLoadSM2PrivateKey_EC_PEM(t *testing.T) {
	_, pemBytes, err := GenerateSM2Key()
	if err != nil {
		t.Fatalf("GenerateSM2Key: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "sm2.key")
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	key, err := LoadSM2PrivateKey(path)
	if err != nil {
		t.Fatalf("LoadSM2PrivateKey: %v", err)
	}
	if key.Curve != sm2.P256() {
		t.Error("loaded key not on SM2 P-256 curve")
	}
}

func TestLoadSM2PrivateKey_PKCS8(t *testing.T) {
	sm2Key, err := sm2.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatalf("sm2.GenerateKey: %v", err)
	}

	der, err := smx509.MarshalPKCS8PrivateKey(sm2Key)
	if err != nil {
		t.Fatalf("x509.MarshalPKCS8PrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	dir := t.TempDir()
	path := filepath.Join(dir, "sm2-pkcs8.key")
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	key, err := LoadSM2PrivateKey(path)
	if err != nil {
		t.Fatalf("LoadSM2PrivateKey PKCS#8: %v", err)
	}
	if key.Curve != sm2.P256() {
		t.Error("loaded key not on SM2 P-256 curve")
	}
}

func TestLoadSM2PrivateKey_NotSM2(t *testing.T) {
	// Generate a NIST P-256 key (not SM2)
	nistKey, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalECPrivateKey(nistKey)
	if err != nil {
		t.Fatalf("x509.MarshalECPrivateKey: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	dir := t.TempDir()
	path := filepath.Join(dir, "nist.key")
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err = LoadSM2PrivateKey(path)
	if err == nil {
		t.Error("LoadSM2PrivateKey with NIST P-256 key should fail")
	}
}

func TestLoadSM2PrivateKey_NoFile(t *testing.T) {
	_, err := LoadSM2PrivateKey("/nonexistent/sm2.key")
	if err == nil {
		t.Error("LoadSM2PrivateKey with nonexistent file should fail")
	}
}

func TestLoadSM2PrivateKey_InvalidPEM(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "invalid.key")
	if err := os.WriteFile(path, []byte("not a pem file"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	_, err := LoadSM2PrivateKey(path)
	if err == nil {
		t.Error("LoadSM2PrivateKey with invalid PEM should fail")
	}
}

func TestGenerateSM2Key_RoundTrip(t *testing.T) {
	original, pemBytes, err := GenerateSM2Key()
	if err != nil {
		t.Fatalf("GenerateSM2Key: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "sm2.key")
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	loaded, err := LoadSM2PrivateKey(path)
	if err != nil {
		t.Fatalf("LoadSM2PrivateKey: %v", err)
	}

	// Keys should match (same D, same curve, same public key)
	if original.D.Cmp(loaded.D) != 0 {
		t.Error("private key D values don't match")
	}
	if !original.PublicKey.Equal(&loaded.PublicKey) {
		t.Error("public keys don't match")
	}
}
