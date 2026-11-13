package smtp

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/caldav"
	"setjoin.com/shared/pgxutil"
)

// These tests pin the fail-closed arms of InboundServer.smimeAnchorTrustScope:
// an anchor PEM that is empty, unfingerprintable, or whose trust lookup fails
// must resolve to SmimeTrustNone; only a bundled public root with no granting
// row degrades to SmimeTrustUnrestricted.

// TestSmimeAnchorTrustScopeFailClosedFast covers the arms that return before
// any database access, so they run without a DB.
func TestSmimeAnchorTrustScopeFailClosedFast(t *testing.T) {
	srv := NewInboundServer(pgxutil.WorkerPool{}, ":0", testLogger(), nil, nil)

	t.Run("empty anchor PEM", func(t *testing.T) {
		// An empty anchorPEM means "no validated chain" — trust nothing.
		scope, domains := srv.smimeAnchorTrustScope(context.Background(), "")
		if scope != caldav.SmimeTrustNone {
			t.Errorf("scope = %v, want SmimeTrustNone", scope)
		}
		if domains != nil {
			t.Errorf("domains = %v, want nil", domains)
		}
	})

	t.Run("unparseable anchor PEM", func(t *testing.T) {
		// A validated anchor whose PEM no longer parses cannot be
		// fingerprinted, so its trust row can never be resolved — fail closed.
		scope, domains := srv.smimeAnchorTrustScope(context.Background(), "not a certificate")
		if scope != caldav.SmimeTrustNone {
			t.Errorf("scope = %v, want SmimeTrustNone", scope)
		}
		if domains != nil {
			t.Errorf("domains = %v, want nil", domains)
		}
	})
}

// TestSmimeAnchorTrustScopeWithDB covers the arms behind the trust-row lookup:
// a canceled context fails the lookup (fail closed), an unknown fingerprint of
// a bundled root stays unrestricted, and an unknown self-signed anchor gets no
// trust at all.
func TestSmimeAnchorTrustScopeWithDB(t *testing.T) {
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

	// A valid non-bundled anchor whose fingerprint has NO smime_trust_anchors
	// row in this database (aggregate query still returns one row:
	// deploymentWide=false, domains={}).
	orphanPEM, orphanCert := selfSignedCA(t, "Orphaned Anchor CA")

	t.Run("trust lookup fails (canceled context)", func(t *testing.T) {
		// Any DB lookup ERROR must fail closed (SmimeTrustNone), never
		// degrade to unrestricted. A canceled context forces the lookup to
		// error without depending on specific DB failure injection.
		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		scope, domains := srv.smimeAnchorTrustScope(canceled, orphanPEM)
		if scope != caldav.SmimeTrustNone {
			t.Errorf("scope = %v, want SmimeTrustNone on lookup error", scope)
		}
		if domains != nil {
			t.Errorf("domains = %v, want nil", domains)
		}
	})

	t.Run("bundled root with no granting row stays unrestricted", func(t *testing.T) {
		// Take the first root of the embedded Mozilla bundle: its fingerprint
		// has no smime_trust_anchors row, but public bundled trust needs none.
		pemBytes, err := os.ReadFile("../smime/cacert.pem")
		if err != nil {
			t.Fatalf("read bundled CA bundle: %v", err)
		}
		block, _ := pem.Decode(pemBytes)
		if block == nil {
			t.Fatal("no PEM block in bundled CA bundle")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatalf("parse bundled root: %v", err)
		}
		rootPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}))

		scope, domains := srv.smimeAnchorTrustScope(ctx, rootPEM)
		if scope != caldav.SmimeTrustUnrestricted {
			t.Errorf("scope = %v, want SmimeTrustUnrestricted for bundled root %q (fp %s)",
				scope, cert.Subject.CommonName, fp(cert))
		}
		if domains != nil {
			t.Errorf("domains = %v, want nil", domains)
		}
	})

	t.Run("non-bundled anchor with no granting row fails closed", func(t *testing.T) {
		// A validated anchor that was never imported (or already deleted) has
		// no granting row and is not a bundled public root: trust nothing.
		scope, domains := srv.smimeAnchorTrustScope(ctx, orphanPEM)
		if scope != caldav.SmimeTrustNone {
			t.Errorf("scope = %v, want SmimeTrustNone for orphaned non-bundled anchor %q",
				scope, orphanCert.Subject.CommonName)
		}
		if domains != nil {
			t.Errorf("domains = %v, want nil", domains)
		}
	})
}
