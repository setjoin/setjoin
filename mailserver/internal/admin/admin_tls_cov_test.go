package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/testsupport"
)

// TestTLSSetConfigWritesCoreAuditRow pins the D-MAILSERVER-INTERNAL-ADMIN-F-009
// contract: a tls_* config mutation by an authenticated admin emits a core-tier
// admin_audit_log row (action tls_config_set) naming the sorted key set — the
// handler owns the audit row because ConfigStore fires only sync/notify hooks.
func TestTLSSetConfigWritesCoreAuditRow(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewTLSHandler(pool, testsupport.TestLogger(), t.TempDir())
	userID := seedUser(t, pool)
	key := "tls_cov_" + rolesTestRandomSuffix(t)

	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM system_config WHERE key = $1`, key) //nolint:errcheck
	})

	body, _ := json.Marshal(map[string]any{
		key:             "mail.cov.test",
		"not_a_tls_key": "ignored",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/tls/config", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.SetConfig(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("SetConfig: want 204, got %d (%s)", rec.Code, rec.Body.String())
	}

	// The tls_-prefixed key persisted; the non-prefixed key was filtered out.
	var val string
	if err := pool.QueryRow(t.Context(),
		`SELECT value #>> '{}' FROM system_config WHERE key = $1`, key).Scan(&val); err != nil {
		t.Fatalf("tls config key not persisted: %v", err)
	}
	if val != "mail.cov.test" {
		t.Fatalf("tls config value = %q", val)
	}
	var nonTLS int
	if err := pool.QueryRow(t.Context(),
		`SELECT count(*) FROM system_config WHERE key = 'not_a_tls_key'`).Scan(&nonTLS); err != nil {
		t.Fatal(err)
	}
	if nonTLS != 0 {
		t.Fatal("SetConfig persisted a non tls_-prefixed key")
	}

	// The audit row: core tier, actor, sorted key list in after_state.
	var count int
	var after string
	if err := pool.QueryRow(t.Context(),
		`SELECT count(*), COALESCE(max(after_state::text),'') FROM admin_audit_log
		  WHERE action = 'tls_config_set' AND user_id = $1 AND notes = $2`,
		userID, key).Scan(&count, &after); err != nil {
		t.Fatalf("read tls audit row: %v", err)
	}
	if count != 1 {
		t.Fatalf("tls_config_set audit rows = %d, want 1", count)
	}
	if !strings.Contains(after, key) || !strings.Contains(after, "TLS configuration") {
		t.Fatalf("audit after_state missing the key set/description: %s", after)
	}
}

// TestTLSImportCertWritesFilesAndCoreAuditRow pins the cert-import contract:
// the uploaded pair lands under certDir with 0600 (key material) and the
// mutation emits a core-tier tls_cert_import audit row.
func TestTLSImportCertWritesFilesAndCoreAuditRow(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	certDir := t.TempDir()
	h := NewTLSHandler(pool, testsupport.TestLogger(), certDir)
	userID := seedUser(t, pool)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	cw, err := mw.CreateFormFile("cert", "cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	cw.Write([]byte("-----BEGIN CERTIFICATE-----\nCOVTEST\n-----END CERTIFICATE-----\n"))
	kw, err := mw.CreateFormFile("key", "key.pem")
	if err != nil {
		t.Fatal(err)
	}
	kw.Write([]byte("-----BEGIN PRIVATE KEY-----\nCOVTEST\n-----END PRIVATE KEY-----\n"))
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/admin/tls/cert", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.ImportCert(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ImportCert: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		CertPath string `json:"certPath"`
		KeyPath  string `json:"keyPath"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode import response: %v", err)
	}
	if resp.CertPath == "" || resp.KeyPath == "" ||
		!strings.HasPrefix(resp.CertPath, certDir) || !strings.HasPrefix(resp.KeyPath, certDir) {
		t.Fatalf("paths not under the handler certDir: %+v", resp)
	}
	// Both files exist; the private key is owner-only.
	for _, p := range []string{resp.CertPath, resp.KeyPath} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("%s mode = %o, want 600", p, got)
		}
	}

	var count int
	if err := pool.QueryRow(t.Context(),
		`SELECT count(*) FROM admin_audit_log
		  WHERE action = 'tls_cert_import' AND user_id = $1
		    AND after_state->>'certPath' = $2 AND after_state->>'keyPath' = $3`,
		userID, resp.CertPath, resp.KeyPath).Scan(&count); err != nil {
		t.Fatalf("read cert-import audit row: %v", err)
	}
	if count != 1 {
		t.Fatalf("tls_cert_import audit rows = %d, want 1", count)
	}
}

// TestTLSSetConfigSurvivesAuditWriteFailure pins the failure arm of the
// D-MAILSERVER-INTERNAL-ADMIN-F-009 audit path in SetConfig: when the audit
// sink is unreachable (dead pool) the tls_* mutation still commits and the
// handler still returns 204 — the audit failure is logged loudly, never fatal
// to the config write.
func TestTLSSetConfigSurvivesAuditWriteFailure(t *testing.T) {
	good := testsupport.OpenTestPool(t)
	dead := testsupport.OpenTestPool(t)
	dead.Close()

	// The store rides the live pool; the audit write rides the dead one —
	// exactly the sink fault the handler must log-and-continue on.
	h := &TLSHandler{pool: dead, logger: testsupport.TestLogger(), certDir: t.TempDir(), store: NewConfigStore(good, nil)}
	userID := seedUser(t, good)
	key := "tls_cov_fail_" + rolesTestRandomSuffix(t)
	t.Cleanup(func() {
		_, _ = good.Exec(context.Background(), `DELETE FROM system_config WHERE key = $1`, key) //nolint:errcheck
	})

	body, _ := json.Marshal(map[string]any{key: "mail.cov.test"})
	req := httptest.NewRequest(http.MethodPost, "/admin/tls/config", bytes.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.SetConfig(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("SetConfig with dead audit sink: want 204, got %d (%s)", rec.Code, rec.Body.String())
	}
	var val string
	if err := good.QueryRow(context.Background(),
		`SELECT value #>> '{}' FROM system_config WHERE key = $1`, key).Scan(&val); err != nil {
		t.Fatalf("tls config key must persist even when the audit write fails: %v", err)
	}
	if val != "mail.cov.test" {
		t.Fatalf("tls config value = %q", val)
	}
}

// TestTLSImportCertSurvivesAuditWriteFailure pins the same log-and-continue
// contract for ImportCert: the uploaded pair still lands on disk with its
// 200 response when the audit write cannot commit.
func TestTLSImportCertSurvivesAuditWriteFailure(t *testing.T) {
	good := testsupport.OpenTestPool(t)
	dead := testsupport.OpenTestPool(t)
	dead.Close()
	certDir := t.TempDir()
	h := &TLSHandler{pool: dead, logger: testsupport.TestLogger(), certDir: certDir, store: NewConfigStore(good, nil)}
	userID := seedUser(t, good)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	cw, err := mw.CreateFormFile("cert", "cert.pem")
	if err != nil {
		t.Fatal(err)
	}
	cw.Write([]byte("-----BEGIN CERTIFICATE-----\nCOVTESTFAIL\n-----END CERTIFICATE-----\n"))
	kw, err := mw.CreateFormFile("key", "key.pem")
	if err != nil {
		t.Fatal(err)
	}
	kw.Write([]byte("-----BEGIN PRIVATE KEY-----\nCOVTESTFAIL\n-----END PRIVATE KEY-----\n"))
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "/admin/tls/cert", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.ImportCert(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ImportCert with dead audit sink: want 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		CertPath string `json:"certPath"`
		KeyPath  string `json:"keyPath"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode import response: %v", err)
	}
	for _, p := range []string{resp.CertPath, resp.KeyPath} {
		if !strings.HasPrefix(p, certDir) {
			t.Fatalf("path %q not under the handler certDir", p)
		}
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
	}
}

// TestTLSImportCertRejectsMissingParts guards the 400 arms (they bound the
// storage/audit path above): a body without the required form parts never
// touches disk.
func TestTLSImportCertRejectsMissingParts(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewTLSHandler(pool, testsupport.TestLogger(), t.TempDir())
	userID := seedUser(t, pool)

	post := func(build func(*multipart.Writer)) *httptest.ResponseRecorder {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		build(mw)
		mw.Close()
		req := httptest.NewRequest(http.MethodPost, "/admin/tls/cert", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
		rec := httptest.NewRecorder()
		h.ImportCert(rec, req)
		return rec
	}

	if rec := post(func(mw *multipart.Writer) {}); rec.Code != http.StatusBadRequest {
		t.Fatalf("no parts: want 400, got %d (%s)", rec.Code, rec.Body.String())
	}
	if rec := post(func(mw *multipart.Writer) {
		fw, _ := mw.CreateFormFile("cert", "cert.pem")
		fw.Write([]byte("cert"))
	}); rec.Code != http.StatusBadRequest {
		t.Fatalf("cert only: want 400, got %d (%s)", rec.Code, rec.Body.String())
	}
}
