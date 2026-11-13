package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

// mkCertFull builds a CA-signed leaf, returning the leaf, the CA trust pool,
// the CA cert, and the CA key — the CA key is needed for signing CRLs.
func mkCertFull(t *testing.T, cn string, notAfter time.Time) (*x509.Certificate, *x509.CertPool, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "test-ca"}, IsCA: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, BasicConstraintsValid: true,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour)}
	caDER, _ := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	caCert, _ := x509.ParseCertificate(caDER)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2),
		Subject: pkix.Name{CommonName: cn}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: notAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, _ := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	leaf, _ := x509.ParseCertificate(leafDER)
	return leaf, pool, caCert, caKey
}

// mkCert is the minimal fixture for callers that don't need the CA key.
func mkCert(t *testing.T, cn string, notAfter time.Time) (*x509.Certificate, *x509.CertPool) {
	t.Helper()
	leaf, pool, _, _ := mkCertFull(t, cn, notAfter)
	return leaf, pool
}

func TestVerifyClientCert(t *testing.T) {
	leaf, pool := mkCert(t, "alice@test", time.Now().Add(time.Hour))
	if err := verifyClientCert(leaf, pool); err != nil {
		t.Fatalf("valid cert must verify: %v", err)
	}
	// Untrusted: a fresh pool with no roots.
	if err := verifyClientCert(leaf, x509.NewCertPool()); err == nil {
		t.Fatal("cert with no trusted root must be rejected")
	}
	// Expired.
	expired, epool := mkCert(t, "bob@test", time.Now().Add(-time.Minute))
	if err := verifyClientCert(expired, epool); err == nil {
		t.Fatal("expired cert must be rejected")
	}
}

func TestVerifyClientCert_Revoked(t *testing.T) {
	leaf, pool, caCert, caKey := mkCertFull(t, "charlie@test", time.Now().Add(time.Hour))

	crlTemplate := &x509.RevocationList{
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: leaf.SerialNumber, RevocationTime: time.Now().Add(-time.Minute)},
		},
		Number:     big.NewInt(1),
		ThisUpdate: time.Now().Add(-time.Hour),
		NextUpdate: time.Now().Add(24 * time.Hour),
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, crlTemplate, caCert, caKey)
	if err != nil {
		t.Fatalf("CreateRevocationList: %v", err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("ParseRevocationList: %v", err)
	}

	// With the CRL: revoked cert must be rejected.
	if err := verifyClientCert(leaf, pool, crl); err == nil {
		t.Fatal("revoked cert must be rejected when CRL is provided")
	}
	// Without the CRL: chain+validity still pass (confirming CRL is the guard).
	if err := verifyClientCert(leaf, pool); err != nil {
		t.Fatalf("cert must verify without CRL: %v", err)
	}
}
