package auth

import (
	"context"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

func TestCertAuthMethodPriorityAndSlug(t *testing.T) {
	m := &certAuthMethod{}
	if m.Slug() != "certificate" {
		t.Fatalf("slug want certificate, got %q", m.Slug())
	}
	if m.Priority() != 5 {
		t.Fatalf("certificate must outrank jwt_bearer(10): want 5, got %d", m.Priority())
	}
}

func TestCertAuthMethodNoTLS(t *testing.T) {
	m := &certAuthMethod{}
	// A nil leaf must not authenticate (returns error).
	if _, err := m.authenticateCert(context.Background(), nil); err == nil {
		t.Fatal("no peer cert must not authenticate")
	}
}

// TestCertAuthMethodRevocationWired confirms that a cert present in m.crls is
// rejected by authenticateCert — i.e. the CRL is actually passed through to
// verifyClientCert and not silently dropped.
func TestCertAuthMethodRevocationWired(t *testing.T) {
	leaf, pool, caCert, caKey := mkCertFull(t, "dave@revoked", time.Now().Add(time.Hour))
	crlDER, err := x509.CreateRevocationList(nil, &x509.RevocationList{
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: leaf.SerialNumber, RevocationTime: time.Now().Add(-time.Minute)},
		},
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}, caCert, caKey)
	if err != nil {
		t.Fatalf("CreateRevocationList: %v", err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}

	m := &certAuthMethod{roots: pool, crls: []*x509.RevocationList{crl}}
	if _, err := m.authenticateCert(context.Background(), leaf); err == nil {
		t.Fatal("revoked cert must not authenticate (CRL not wired)")
	}
}
