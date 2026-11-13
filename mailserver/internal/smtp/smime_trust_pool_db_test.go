package smtp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"setjoin.com/shared/pgxutil"
)

// selfSignedCA generates a minimal self-signed root CA and returns (PEM, parsed cert).
// The parsed cert is a self-signed root, so cert.Verify against a pool that contains
// its PEM succeeds — the gold-standard "this anchor is actually trusted" membership
// check (not merely "present in the pool").
func selfSignedCA(t *testing.T, cn string) (string, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), cert
}

// trustsRoot reports whether cert (a self-signed root) chains to a trust anchor in pool.
func trustsRoot(pool *x509.CertPool, cert *x509.Certificate) bool {
	_, err := cert.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	return err == nil
}

func fp(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.Raw)
	return hex.EncodeToString(sum[:])
}

// TestSMIMERootsForDomainPerTenantIsolation verifies that a trust anchor imported
// for recipient domain X appears in X's pool but NOT in another domain Y's pool,
// while a deployment-wide (domain_id IS NULL) anchor appears in both. This is the
// Phase B per-tenant scoping invariant: one tenant's imported root must not grant
// trust in another.
func TestSMIMERootsForDomainPerTenantIsolation(t *testing.T) {
	if os.Getenv("TEST_DB_DSN") == "" {
		t.Skip("TEST_DB_DSN not set; skipping database-dependent test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("TEST_DB_DSN"))
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	defer pool.Close()

	// Two distinct local domains. Create our OWN rather than picking the first two
	// existing rows — the latter made this test ORDER-DEPENDENT: on a freshly
	// loaded single-seed-domain DB the "pick domain Y" query found no second row
	// and t.Fatalf'd (it only passed when some earlier test had inserted a domain).
	// Unique names per run; cleaned up after the anchors (LIFO) to respect the
	// smime_trust_anchors.domain_id FK.
	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	var domX, domY int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, "tenant-x-"+suffix+".test").Scan(&domX); err != nil {
		t.Fatalf("create domain X: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name, is_local) VALUES ($1, TRUE) RETURNING id`, "tenant-y-"+suffix+".test").Scan(&domY); err != nil {
		t.Fatalf("create domain Y: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM domains WHERE id = ANY($1)`, []int64{domX, domY})
	})

	xPEM, xCert := selfSignedCA(t, "Tenant X Private CA")
	wPEM, wCert := selfSignedCA(t, "Deployment-Wide CA")

	// Insert: one anchor scoped to domain X, one deployment-wide (NULL).
	xFP, wFP := fp(xCert), fp(wCert)
	cleanup := func() {
		_, _ = pool.Exec(ctx, `DELETE FROM smime_trust_anchors WHERE fingerprint = ANY($1)`, []string{xFP, wFP})
	}
	cleanup()
	t.Cleanup(cleanup)

	if _, err := pool.Exec(ctx,
		`INSERT INTO smime_trust_anchors (label, cert_pem, fingerprint, domain_id) VALUES ($1,$2,$3,$4)`,
		"tenant-x-ca", xPEM, xFP, domX); err != nil {
		t.Fatalf("insert domain-X anchor: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO smime_trust_anchors (label, cert_pem, fingerprint, domain_id) VALUES ($1,$2,$3,NULL)`,
		"deployment-wide-ca", wPEM, wFP); err != nil {
		t.Fatalf("insert deployment-wide anchor: %v", err)
	}

	srv := NewInboundServer(pgxutil.WorkerPool{Pool: pool}, ":0", testLogger(), nil, nil)

	poolX := srv.smimeRootsForDomain(ctx, domX)
	poolY := srv.smimeRootsForDomain(ctx, domY)
	if poolX == nil || poolY == nil {
		t.Fatal("smimeRootsForDomain returned nil pool (would fall back to system store)")
	}

	// Per-tenant isolation: X's anchor trusted in X, NOT in Y.
	if !trustsRoot(poolX, xCert) {
		t.Error("domain X anchor not trusted in domain X pool")
	}
	if trustsRoot(poolY, xCert) {
		t.Error("CROSS-TENANT LEAK: domain X anchor trusted in domain Y pool")
	}

	// Deployment-wide anchor trusted in BOTH.
	if !trustsRoot(poolX, wCert) {
		t.Error("deployment-wide anchor not trusted in domain X pool")
	}
	if !trustsRoot(poolY, wCert) {
		t.Error("deployment-wide anchor not trusted in domain Y pool")
	}

	// Invalidation: after clearing the cache and removing X's anchor, X no longer trusts it.
	if _, err := pool.Exec(ctx, `DELETE FROM smime_trust_anchors WHERE fingerprint = $1`, xFP); err != nil {
		t.Fatalf("delete domain-X anchor: %v", err)
	}
	srv.InvalidateSMIMETrustCache()
	if trustsRoot(srv.smimeRootsForDomain(ctx, domX), xCert) {
		t.Error("domain X anchor still trusted after deletion + cache invalidation (stale cache)")
	}
}

// TestSMIMERootsForDomainNeverNil verifies the fail-open contract: even with no
// anchors and an unknown domain (0), the pool is non-nil (bundle-only).
func TestSMIMERootsForDomainNeverNil(t *testing.T) {
	if os.Getenv("TEST_DB_DSN") == "" {
		t.Skip("TEST_DB_DSN not set; skipping database-dependent test")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, os.Getenv("TEST_DB_DSN"))
	if err != nil {
		t.Fatalf("connect test DB: %v", err)
	}
	defer pool.Close()

	srv := NewInboundServer(pgxutil.WorkerPool{Pool: pool}, ":0", testLogger(), nil, nil)
	if got := srv.smimeRootsForDomain(ctx, 0); got == nil {
		t.Fatal("smimeRootsForDomain(0) returned nil")
	}
}
