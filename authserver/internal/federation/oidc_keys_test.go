package federation

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrGenerateKeyPersistsRestrictedKeypair(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "oidc-private.pem")
	publicPath := filepath.Join(dir, "oidc-public.pem")

	first, err := LoadOrGenerateKey(privatePath, publicPath)
	if err != nil {
		t.Fatal(err)
	}
	privateInfo, err := os.Stat(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	publicInfo, err := os.Stat(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := privateInfo.Mode().Perm(); got != 0600 {
		t.Fatalf("private key mode=%#o want 0600", got)
	}
	if got := publicInfo.Mode().Perm(); got != 0644 {
		t.Fatalf("public key mode=%#o want 0644", got)
	}

	second, err := LoadOrGenerateKey(privatePath, publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if first.KeyID() != second.KeyID() {
		t.Fatal("reloading the persisted key changed its key ID")
	}
}

func TestLoadOrGenerateKeyRestrictsExistingPrivateKey(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "oidc-private.pem")
	publicPath := filepath.Join(dir, "oidc-public.pem")
	if _, err := LoadOrGenerateKey(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(privatePath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadOrGenerateKey(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0600 {
		t.Fatalf("existing private key mode=%#o want 0600", got)
	}
}

func TestLoadOrGenerateKeyRejectsMalformedExistingPrivateKey(t *testing.T) {
	dir := t.TempDir()
	privatePath := filepath.Join(dir, "oidc-private.pem")
	publicPath := filepath.Join(dir, "oidc-public.pem")
	original := []byte("not a private key")
	if err := os.WriteFile(privatePath, original, 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadOrGenerateKey(privatePath, publicPath); err == nil {
		t.Fatal("malformed existing private key was silently rotated")
	}
	after, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(original) {
		t.Fatal("malformed existing private key was replaced")
	}
}

func TestLoadOrGenerateKeyRejectsIdenticalPaths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "same.pem")
	if _, err := LoadOrGenerateKey(path, path); err == nil {
		t.Fatal("identical private and public key paths were accepted")
	}
}

func TestLoadOrGenerateKeyRejectsInvalidPKCS8AndNonRSAKeys(t *testing.T) {
	tests := []struct {
		name  string
		block *pem.Block
	}{
		{"invalid PKCS8", &pem.Block{Type: "PRIVATE KEY", Bytes: []byte("not-der")}},
		{"non RSA", func() *pem.Block {
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			der, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			return &pem.Block{Type: "PRIVATE KEY", Bytes: der}
		}()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			privatePath := filepath.Join(dir, "private.pem")
			if err := os.WriteFile(privatePath, pem.EncodeToMemory(test.block), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadOrGenerateKey(privatePath, filepath.Join(dir, "public.pem")); err == nil {
				t.Fatal("unsafe existing key was accepted")
			}
		})
	}
}

func TestLoadOrGenerateKeyReportsFilesystemBoundaryFailures(t *testing.T) {
	t.Run("private parent missing", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := LoadOrGenerateKey(
			filepath.Join(dir, "missing", "private.pem"),
			filepath.Join(dir, "public.pem"),
		); err == nil {
			t.Fatal("missing private-key parent unexpectedly succeeded")
		}
	})

	t.Run("private path is directory", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := LoadOrGenerateKey(dir, filepath.Join(dir, "public.pem")); err == nil {
			t.Fatal("directory private-key path unexpectedly succeeded")
		}
	})

	t.Run("public path is directory", func(t *testing.T) {
		dir := t.TempDir()
		privatePath := filepath.Join(dir, "private.pem")
		validPublic := filepath.Join(dir, "public.pem")
		if _, err := LoadOrGenerateKey(privatePath, validPublic); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadOrGenerateKey(privatePath, dir); err == nil {
			t.Fatal("directory public-key path unexpectedly succeeded")
		}
	})
}
