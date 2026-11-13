package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewLegoManager(t *testing.T) {
	directory := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/directory" {
			http.NotFound(w, r)
			return
		}
		baseURL := "https://" + r.Host
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]any{
			"newNonce":   baseURL + "/new-nonce",
			"newAccount": baseURL + "/new-account",
			"newOrder":   baseURL + "/new-order",
			"revokeCert": baseURL + "/revoke-cert",
			"keyChange":  baseURL + "/key-change",
			"meta":       map[string]any{},
		}); err != nil {
			t.Errorf("encode ACME directory: %v", err)
		}
	}))
	t.Cleanup(directory.Close)

	cfg := LegoConfig{
		Domains:     []string{"mail.example.com"},
		Email:       "admin@example.com",
		CacheDir:    t.TempDir(),
		ProviderCfg: ProviderConfig{Provider: "cloudflare", Config: `{"CF_API_TOKEN": "test"}`},
		CADirURL:    directory.URL + "/directory",
		HTTPClient:  directory.Client(),
	}
	mgr, err := NewLegoManager(cfg)
	if err != nil {
		t.Fatalf("NewLegoManager: %v", err)
	}
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
}

func TestLegoConfig_ValidatesDomains(t *testing.T) {
	cfg := LegoConfig{
		Domains:  []string{},
		CacheDir: "/tmp",
	}
	_, err := NewLegoManager(cfg)
	if err == nil {
		t.Fatal("expected error for empty domains")
	}
}

func TestLegoConfig_ValidatesCacheDir(t *testing.T) {
	cfg := LegoConfig{
		Domains:  []string{"example.com"},
		CacheDir: "",
	}
	_, err := NewLegoManager(cfg)
	if err == nil {
		t.Fatal("expected error for empty cache dir")
	}
}

// TestCertCacheBlobFormat is a regression test for a cache bug where obtain()
// stored only certs.Certificate (no private key). On restart, GetCertificate
// called tls.X509KeyPair(blob, blob) which failed — no key block — triggering
// fresh ACME issuance on every restart and hitting Let's Encrypt rate limits.
// Fix: store append(PrivateKey, Certificate...) so the combined blob satisfies
// both args of X509KeyPair (each arg is scanned for its respective block type).
func TestCertCacheBlobFormat(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1)}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	// Old buggy blob: cert only — X509KeyPair must fail (no key block).
	if _, err := tls.X509KeyPair(certPEM, certPEM); err == nil {
		t.Fatal("expected X509KeyPair(certOnly, certOnly) to fail; test is no longer a useful regression guard")
	}

	// Fixed blob: key + cert concatenated — X509KeyPair must succeed.
	blob := append(keyPEM, certPEM...)
	if _, err := tls.X509KeyPair(blob, blob); err != nil {
		t.Fatalf("X509KeyPair(key+cert blob, key+cert blob) failed: %v", err)
	}

	// Verify the round-trip through the dir cache preserves the blob intact.
	cache := &DirCache{Dir: t.TempDir()}
	if err := cache.Put("example.com", blob); err != nil {
		t.Fatal(err)
	}
	got, err := cache.Get("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tls.X509KeyPair(got, got); err != nil {
		t.Fatalf("X509KeyPair after cache round-trip failed: %v", err)
	}
}
