package admin

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/mailserver/internal/smime"
	"setjoin.com/shared/permissions"
	"setjoin.com/shared/testsupport"
)

// Compile-time assertions: handler methods must satisfy http.HandlerFunc's signature.
var _ http.HandlerFunc = (&TrustAnchorHandler{}).List
var _ http.HandlerFunc = (&TrustAnchorHandler{}).Import
var _ http.HandlerFunc = (&TrustAnchorHandler{}).Delete

// makeTrustAnchorCertPEM generates a minimal self-signed root CA PEM for tests.
func makeTrustAnchorCertPEM(t *testing.T, notBefore, notAfter time.Time) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Trust Anchor CA"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// buildImportRequest constructs a multipart POST request for the Import handler.
func buildImportRequest(t *testing.T, label, certPEM string) *http.Request {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("label", label)
	fw, err := mw.CreateFormFile("cert", "cert.pem")
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	_, _ = fw.Write([]byte(certPEM))
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/admin/smime/trust-anchors", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	return req
}

// ── validateAnchorPEM unit tests (pure; no DB) ────────────────────────────────

// validateAnchorPEM fingerprints the FIRST certificate of a PEM for display +
// dedupe assertions (the handler path is validateAnchorChain, which covers
// every certificate of the bundle).
func validateAnchorPEM(certPEM string) (fp, cn string, notBefore, notAfter time.Time, err error) {
	return smime.Fingerprint(certPEM)
}

// TestValidateAnchorPEM_Valid verifies that a valid PEM returns a non-empty
// fingerprint with correct CN and non-zero validity bounds.
func TestValidateAnchorPEM_Valid(t *testing.T) {
	certPEM := makeTrustAnchorCertPEM(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))

	fp, cn, notBefore, notAfter, err := validateAnchorPEM(certPEM)
	if err != nil {
		t.Fatalf("validateAnchorPEM: unexpected error: %v", err)
	}
	if len(fp) != 64 {
		t.Errorf("expected 64-char hex fingerprint, got %d chars: %q", len(fp), fp)
	}
	if cn != "Test Trust Anchor CA" {
		t.Errorf("CN: got %q, want %q", cn, "Test Trust Anchor CA")
	}
	if notBefore.IsZero() || notAfter.IsZero() {
		t.Error("notBefore/notAfter must not be zero")
	}
	if !notAfter.After(notBefore) {
		t.Errorf("notAfter %v must be after notBefore %v", notAfter, notBefore)
	}
}

// TestValidateAnchorPEM_BadPEM verifies that garbage input returns an error.
func TestValidateAnchorPEM_BadPEM(t *testing.T) {
	_, _, _, _, err := validateAnchorPEM("not a certificate")
	if err == nil {
		t.Fatal("expected error on bad PEM, got nil")
	}
}

// ── Import handler tests (no DB; validation runs before any DB call) ──────────

// TestImport_NoAuth verifies that Import returns 401 without an authenticated user.
func TestImport_NoAuth(t *testing.T) {
	h := &TrustAnchorHandler{pool: nil, logger: slog.Default()}

	req := httptest.NewRequest(http.MethodPost, "/admin/smime/trust-anchors", nil)
	w := httptest.NewRecorder()

	h.Import(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 without auth, got %d", w.Code)
	}
}

// TestImport_NonPEMCert verifies that a non-PEM cert body returns 400 before any
// DB call is attempted, so a nil pool is safe for this code path.
func TestImport_NonPEMCert(t *testing.T) {
	h := &TrustAnchorHandler{pool: nil, logger: slog.Default()}

	req := buildImportRequest(t, "test", "this is definitely not a PEM certificate")
	ctx := auth.ContextWithUser(context.Background(), &auth.Claims{UserID: 1, IsAdmin: true})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.Import(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for non-PEM cert, got %d", w.Code)
	}
}

// TestImport_ExpiredCert verifies that an already-expired cert returns 400
// (expiry check runs before any DB call, so nil pool is safe).
func TestImport_ExpiredCert(t *testing.T) {
	h := &TrustAnchorHandler{pool: nil, logger: slog.Default()}

	// Certificate expired well in the past.
	expiredPEM := makeTrustAnchorCertPEM(t,
		time.Now().Add(-48*time.Hour),
		time.Now().Add(-time.Hour),
	)

	req := buildImportRequest(t, "expired-ca", expiredPEM)
	ctx := auth.ContextWithUser(context.Background(), &auth.Claims{UserID: 1, IsAdmin: true})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.Import(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for expired cert, got %d", w.Code)
	}
}

// TestImport_ValidCert_ReachesDB verifies that a valid, non-expired cert passes
// all pre-DB checks and reaches pool.Exec (nil pool → panic or 500).
// A 400 or 401 here would indicate a broken gate.
func TestImport_ValidCert_ReachesDB(t *testing.T) {
	h := &TrustAnchorHandler{pool: nil, logger: slog.Default()}

	validPEM := makeTrustAnchorCertPEM(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	req := buildImportRequest(t, "valid-ca", validPEM)
	ctx := auth.ContextWithUser(context.Background(), &auth.Claims{UserID: 1, IsAdmin: true})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		h.Import(w, req)
	}()

	if !panicked && w.Code == http.StatusBadRequest {
		t.Error("unexpected 400: valid cert was rejected before DB")
	}
	if !panicked && w.Code == http.StatusUnauthorized {
		t.Error("unexpected 401: auth context was not propagated")
	}
	// Any other outcome (panic or 500) proves the handler cleared all gates.
	t.Logf("nil-pool outcome: panicked=%v code=%d (expected panic or 500)", panicked, w.Code)
}

// ── Round-6 import: EVERY certificate of a multi-cert PEM is fingerprinted ────

// TestImport_MultiCertBundle_FingerprintsEveryCert — round 6 (Astra HOLD): the
// pre-round-6 import fingerprinted only the FIRST certificate while storing the
// complete bundle PEM, so the extra certs entered every trust pool with no
// fingerprint row (the anchor resolver then failed open for them). The import
// must persist ONE ROW PER CERTIFICATE, each with its own single-cert PEM and
// fingerprint, under the caller's domain scope.
func TestImport_MultiCertBundle_FingerprintsEveryCert(t *testing.T) {
	pool := testsupport.OpenTestPool(t)

	certA := makeTrustAnchorCertPEM(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	certB := makeTrustAnchorCertPEM(t, time.Now().Add(-2*time.Hour), time.Now().Add(48*time.Hour))
	fpA, cnA, _, _, err := validateAnchorPEM(certA)
	if err != nil {
		t.Fatalf("validate certA: %v", err)
	}
	fpB, cnB, _, _, err := validateAnchorPEM(certB)
	if err != nil {
		t.Fatalf("validate certB: %v", err)
	}

	h := &TrustAnchorHandler{pool: pool, logger: slog.Default()}
	req := buildImportRequest(t, "round6-bundle", certA+certB)
	ctx := middleware.ContextWithDomainScope(
		auth.ContextWithUser(context.Background(), &auth.Claims{UserID: 1, IsAdmin: true}), 0)
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()
	h.Import(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("import status = %d, want 200 (body=%s)", w.Code, w.Body.String())
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM smime_trust_anchors WHERE fingerprint IN ($1, $2)`, fpA, fpB)
	})

	// Exactly two rows — one per certificate — each authorizing its own cert.
	var count int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM smime_trust_anchors WHERE fingerprint IN ($1, $2)`, fpA, fpB,
	).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 rows (one per certificate of the bundle), got %d", count)
	}

	for name, tc := range map[string]struct {
		fp string
		cn string
	}{"cert A": {fpA, cnA}, "cert B": {fpB, cnB}} {
		var storedPEM, subjectCN string
		if err := pool.QueryRow(context.Background(),
			`SELECT cert_pem, COALESCE(subject_cn,'') FROM smime_trust_anchors WHERE fingerprint = $1`, tc.fp,
		).Scan(&storedPEM, &subjectCN); err != nil {
			t.Fatalf("%s row missing: %v", name, err)
		}
		certs, perr := smime.ParseAnchorChain(storedPEM)
		if perr != nil || len(certs) != 1 {
			t.Errorf("%s: stored cert_pem must be exactly one certificate (got %d certs, err=%v)", name, len(certs), perr)
			continue
		}
		if certs[0].Fingerprint != tc.fp {
			t.Errorf("%s: stored PEM fingerprint %q does not match its row %q", name, certs[0].Fingerprint, tc.fp)
		}
		if subjectCN != tc.cn {
			t.Errorf("%s: subject_cn = %q, want %q", name, subjectCN, tc.cn)
		}
	}

	// The second certificate must now be attributable — the round-5 fail-open
	// hole (a bundle member with no fingerprint row) is closed.
	var domainScoped int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM smime_trust_anchors WHERE fingerprint = $1 AND domain_id IS NULL`, fpB,
	).Scan(&domainScoped); err != nil {
		t.Fatalf("count certB rows: %v", err)
	}
	if domainScoped != 1 {
		t.Errorf("second bundle cert has %d rows, want 1 — it must carry its own fingerprint row", domainScoped)
	}
}

// ── Delete handler tests ──────────────────────────────────────────────────────

// TestDelete_BadID verifies that a non-numeric id returns 400.
func TestDelete_BadID(t *testing.T) {
	h := &TrustAnchorHandler{pool: nil, logger: slog.Default()}

	req := httptest.NewRequest(http.MethodDelete, "/admin/smime/trust-anchors/not-a-number", nil)
	req.SetPathValue("id", "not-a-number")

	w := httptest.NewRecorder()
	h.Delete(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for bad id, got %d", w.Code)
	}
}

// TestDelete_ValidID_ReachesDB verifies that a valid numeric id reaches pool.Exec
// (nil pool → panic or 500). A 400 here would mean the id-parse gate is broken.
func TestDelete_ValidID_ReachesDB(t *testing.T) {
	h := &TrustAnchorHandler{pool: nil, logger: slog.Default()}

	req := httptest.NewRequest(http.MethodDelete, "/admin/smime/trust-anchors/42", nil)
	req.SetPathValue("id", "42")

	w := httptest.NewRecorder()

	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		h.Delete(w, req)
	}()

	if !panicked && w.Code == http.StatusBadRequest {
		t.Error("unexpected 400: valid id '42' was rejected")
	}
	// Panic or 500 confirms the handler reached the DB boundary.
	t.Logf("nil-pool outcome: panicked=%v code=%d (expected panic or 500)", panicked, w.Code)
}

// ── Domain scope semantic tests (pure logic, no DB) ───────────────────────────

// TestList_DomainScopeContext verifies that the handler reads domain scope from
// context without panicking, even with a nil pool, when scope is injected.
// The handler will panic at pool.Query — that's expected and proves it cleared
// the scope-read phase (which happens before any DB call).
func TestList_DomainScopeContext(t *testing.T) {
	h := &TrustAnchorHandler{pool: nil, logger: slog.Default()}

	req := httptest.NewRequest(http.MethodGet, "/admin/smime/trust-anchors", nil)
	ctx := middleware.ContextWithDomainScope(req.Context(), 99)
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()

	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		h.List(w, req)
	}()

	// Panic (nil pool dereference) proves the handler read scope and reached pool.Query.
	if !panicked && w.Code != http.StatusInternalServerError {
		t.Errorf("expected panic or 500 when pool is nil, got code=%d", w.Code)
	}
	t.Logf("nil-pool outcome: panicked=%v code=%d", panicked, w.Code)
}

// ── Per-tenant trust-anchor independence tests (DB-backed) ───────────────────
//
// These tests verify the critical security invariant introduced by V010's
// composite unique index (fingerprint, domain_id) NULLS NOT DISTINCT:
//   - Two different domains importing the SAME root CA cert must produce TWO
//     independent rows (domain A cannot be mutated by domain B's import).
//   - Re-importing the SAME cert under the SAME domain deduplicates to one row
//     (the label is updated, no extra row is created).

// TestTrustAnchor_PerTenantIndependence_TwoDomainsTwoRows asserts that importing
// the same cert fingerprint under two distinct domain_ids creates two independent
// rows — the core fix for the cross-tenant write vulnerability.
func TestTrustAnchor_PerTenantIndependence_TwoDomainsTwoRows(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	certPEM := makeTrustAnchorCertPEM(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	fp, cn, notBefore, notAfter, err := validateAnchorPEM(certPEM)
	if err != nil {
		t.Fatalf("validateAnchorPEM: %v", err)
	}

	const domainA int64 = 9901 // synthetic domain IDs (no FK enforced by the schema)
	const domainB int64 = 9902

	// Seed rows directly (bypassing the HTTP handler) to test the DB constraint.
	insertSQL := `INSERT INTO smime_trust_anchors
		(label, cert_pem, subject_cn, fingerprint, domain_id, not_before, not_after, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (fingerprint, domain_id) DO UPDATE SET label = EXCLUDED.label`

	// Cleanup both test rows on exit.
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM smime_trust_anchors WHERE fingerprint = $1 AND domain_id IN ($2, $3)`, fp, domainA, domainB)
	})

	// Import the cert as domain A.
	if _, err := pool.Exec(ctx, insertSQL, "label-domain-a", certPEM, cn, fp, domainA, notBefore, notAfter, int64(1)); err != nil {
		t.Fatalf("insert domain A: %v", err)
	}

	// Import the SAME cert as domain B — must not conflict with domain A's row.
	if _, err := pool.Exec(ctx, insertSQL, "label-domain-b", certPEM, cn, fp, domainB, notBefore, notAfter, int64(1)); err != nil {
		t.Fatalf("insert domain B (same fingerprint): %v — cross-tenant uniqueness constraint violated", err)
	}

	// Assert TWO rows exist: one per domain.
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM smime_trust_anchors WHERE fingerprint = $1 AND domain_id IN ($2, $3)`,
		fp, domainA, domainB,
	).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 rows (one per domain) for fingerprint %s, got %d — cross-tenant isolation broken", fp, count)
	}

	// Assert domain A's label is unchanged (not mutated by domain B's import).
	var labelA string
	if err := pool.QueryRow(ctx,
		`SELECT label FROM smime_trust_anchors WHERE fingerprint = $1 AND domain_id = $2`,
		fp, domainA,
	).Scan(&labelA); err != nil {
		t.Fatalf("read domain A label: %v", err)
	}
	if labelA != "label-domain-a" {
		t.Errorf("domain A label = %q, want %q — cross-tenant write detected (domain B mutated domain A's row)", labelA, "label-domain-a")
	}

	t.Logf("OK: fingerprint %s has 2 independent rows (domain %d, domain %d)", fp, domainA, domainB)
}

// TestTrustAnchor_SameDomainDeduplicates asserts that re-importing the same cert
// under the same domain_id updates the label (no duplicate row created).
func TestTrustAnchor_SameDomainDeduplicates(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := context.Background()

	certPEM := makeTrustAnchorCertPEM(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	fp, cn, notBefore, notAfter, err := validateAnchorPEM(certPEM)
	if err != nil {
		t.Fatalf("validateAnchorPEM: %v", err)
	}

	const domainID int64 = 9903

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM smime_trust_anchors WHERE fingerprint = $1 AND domain_id = $2`, fp, domainID)
	})

	insertSQL := `INSERT INTO smime_trust_anchors
		(label, cert_pem, subject_cn, fingerprint, domain_id, not_before, not_after, created_by)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (fingerprint, domain_id) DO UPDATE SET label = EXCLUDED.label`

	// First import.
	if _, err := pool.Exec(ctx, insertSQL, "original-label", certPEM, cn, fp, domainID, notBefore, notAfter, int64(1)); err != nil {
		t.Fatalf("first insert: %v", err)
	}

	// Re-import with updated label — must deduplicate (not create a second row).
	if _, err := pool.Exec(ctx, insertSQL, "updated-label", certPEM, cn, fp, domainID, notBefore, notAfter, int64(1)); err != nil {
		t.Fatalf("second insert (upsert): %v", err)
	}

	// Exactly ONE row must exist.
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM smime_trust_anchors WHERE fingerprint = $1 AND domain_id = $2`,
		fp, domainID,
	).Scan(&count); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 row after re-import, got %d — upsert created a duplicate", count)
	}

	// Label must reflect the updated value.
	var label string
	if err := pool.QueryRow(ctx,
		`SELECT label FROM smime_trust_anchors WHERE fingerprint = $1 AND domain_id = $2`,
		fp, domainID,
	).Scan(&label); err != nil {
		t.Fatalf("read label: %v", err)
	}
	if label != "updated-label" {
		t.Errorf("label = %q, want %q — upsert did not update label", label, "updated-label")
	}

	t.Logf("OK: fingerprint %s has 1 row under domain %d with label %q", fp, domainID, label)
}

// TestImport_InsertFailure_ClosedPool_500 drives the per-certificate INSERT
// failure arm: a valid, non-expired anchor chain against a closed pool fails
// closed with 500 (the anchor must never be half-stored silently).
func TestImport_InsertFailure_ClosedPool_500(t *testing.T) {
	closed := testsupport.OpenTestPool(t)
	closed.Close()
	h := NewTrustAnchorHandler(closed, testsupport.TestLogger())

	certPEM := makeTrustAnchorCertPEM(t, time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
	req := buildImportRequest(t, "closed-pool-probe", certPEM)
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{
		UserID: 1, IsAdmin: true, Permissions: permissions.AllPermissions,
	}))
	w := httptest.NewRecorder()
	h.Import(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("closed pool import: want 500, got %d (body=%s)", w.Code, w.Body.String())
	}
}
