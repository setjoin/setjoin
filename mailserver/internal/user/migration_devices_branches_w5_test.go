package user

// Branch-completion tests for the migration + device endpoints (devices.go,
// migration.go): the M365 consent connect/callback guard arms, the
// verify-before-persist connector seam, IMAP self-service admission
// (missing host, malformed body), the global IMAP defaults arm, and the wipe
// acknowledgement success path.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/migration"
	"setjoin.com/shared/permissions"
)

func w5AdminClaims(userID int64) *auth.Claims {
	return &auth.Claims{UserID: userID, Type: auth.TypeAccess, Permissions: []string{permissions.PermMailPipeline}}
}

// TestVerifyM365TenantConnectionArms: the production verifier surfaces both
// the connector-construction failure (bad config) and the live-connection
// failure (unreachable tenant) — never a silent pass.
func TestVerifyM365TenantConnectionArms(t *testing.T) {
	if err := verifyM365TenantConnection(context.Background(), migration.MigrationM365Config{}); err == nil {
		t.Error("empty config must fail connector construction")
	}
	cfg := migration.MigrationM365Config{
		ClientID:     "w5-client",
		ClientSecret: "w5-secret",
		TenantID:     "w5-tenant",
		Cloud:        "global",
	}
	if err := verifyM365TenantConnection(context.Background(), cfg); err == nil {
		t.Error("an unreachable tenant must fail the live connection test")
	}
}

// TestStartMigration_IMAPRequiresHost: a self-service IMAP migration without
// imapConfig.host is rejected 400 before any job is created.
func TestStartMigration_IMAPRequiresHost(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	restoreIMAPDefaults(t, pool)

	userID, _, _ := createTestUserWithMailbox(t, pool)

	body := `{"sourceType":"imap","imapConfig":{"port":993}}`
	req := httptest.NewRequest(http.MethodPost, "/user/migration", strings.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), w5AdminClaims(userID)))
	rec := httptest.NewRecorder()
	h.StartMigration(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400\n%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "imapConfig.host") {
		t.Errorf("body = %q, want the missing-host problem", rec.Body.String())
	}
}

// TestTestIMAPConnection_InvalidBodyAndPolicyArms: a malformed JSON body is a
// 400 before any dial; that arm complements the private-policy reject tests.
func TestTestIMAPConnection_InvalidBody(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)

	userID := createTestUser(t, pool)
	req := httptest.NewRequest(http.MethodPost, "/user/migration/test-imap", strings.NewReader("{not json"))
	req = req.WithContext(auth.ContextWithUser(req.Context(), w5AdminClaims(userID)))
	rec := httptest.NewRecorder()
	h.TestIMAPConnection(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestSaveGlobalIMAPConfig_DefaultsTLS: an admin save without tls_mode or
// port receives the 993/TLS defaults.
func TestSaveGlobalIMAPConfig_DefaultsTLS(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	restoreIMAPDefaults(t, pool)

	userID := createTestUser(t, pool)
	body := `{"host":"imapDefaults.example"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/migration/global-source/imap", strings.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), w5AdminClaims(userID)))
	rec := httptest.NewRecorder()
	h.SaveGlobalIMAPConfig(rec, req)

	if rec.Code != http.StatusOK && rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 2xx\n%s", rec.Code, rec.Body.String())
	}

	var portStr, tlsMode string
	if err := pool.QueryRow(context.Background(),
		`SELECT (value::jsonb)->>'port', COALESCE((value::jsonb)->>'tls_mode','') FROM system_config WHERE key='imap.defaults'`,
	).Scan(&portStr, &tlsMode); err != nil {
		t.Fatalf("read saved defaults: %v", err)
	}
	if portStr != "993" || tlsMode != "tls" {
		t.Errorf("defaults = port %q tls %q, want 993/tls", portStr, tlsMode)
	}
}

// TestM365Connect_CloudParamArms: the default cloud is global; an unknown
// cloud is a 400 before any state is minted.
func TestM365Connect_CloudParamArms(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	restoreM365AppConfig(t, pool)
	seedM365AppProfile(t, h, pool)
	restoreAuditFullLevel(t, pool)

	adminID := createTestUser(t, pool)

	// Default cloud (no param) mints and redirects to the worldwide authority.
	req := httptest.NewRequest(http.MethodGet, "/admin/migration/m365/connect", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), w5AdminClaims(adminID)))
	rec := httptest.NewRecorder()
	h.M365Connect(rec, req)
	if rec.Code != http.StatusFound {
		t.Fatalf("default cloud connect = %d, want 302\n%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Header().Get("Location"), "login.microsoftonline.com") {
		t.Errorf("default cloud redirect = %q, want the worldwide authority", rec.Header().Get("Location"))
	}

	// Unknown cloud is refused.
	req = httptest.NewRequest(http.MethodGet, "/admin/migration/m365/connect?cloud=moon", nil)
	req = req.WithContext(auth.ContextWithUser(req.Context(), w5AdminClaims(adminID)))
	rec = httptest.NewRecorder()
	h.M365Connect(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown cloud = %d, want 400", rec.Code)
	}
}

// TestM365Callback_StateGuardArms: a callback with no state cookie, and one
// whose cookie and query disagree, are refused without consuming anything; a
// matching pair without admin consent is the "not granted" 400.
func TestM365Callback_StateGuardArms(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := newTestMigrationHandler(pool)
	restoreM365AppConfig(t, pool)
	restoreAuditFullLevel(t, pool)

	adminID := createTestUser(t, pool)
	claims := w5AdminClaims(adminID)

	t.Run("missing state cookie", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/migration/m365/callback?state=abc&admin_consent=True&tenant=t", nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
		rec := httptest.NewRecorder()
		h.M365Callback(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "invalid or expired state") {
			t.Errorf("body = %q", rec.Body.String())
		}
	})

	t.Run("state mismatch", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/migration/m365/callback?state=query&admin_consent=True&tenant=t", nil)
		req.AddCookie(&http.Cookie{Name: "m365_oauth_state", Value: "cookie"})
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
		rec := httptest.NewRecorder()
		h.M365Callback(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("consent not granted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/migration/m365/callback?state=same", nil)
		req.AddCookie(&http.Cookie{Name: "m365_oauth_state", Value: "same"})
		req = req.WithContext(auth.ContextWithUser(req.Context(), claims))
		rec := httptest.NewRecorder()
		h.M365Callback(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "Admin consent was not granted") {
			t.Errorf("body = %q", rec.Body.String())
		}
	})
}

// TestWipeAck_SuccessPath: a pending wipe on one of the caller's devices is
// acknowledged 200 (the reducer's transition guard passes).
func TestWipeAck_SuccessPath(t *testing.T) {
	pool := testPool(t)
	requireMailserverSchema(t, pool)
	h := NewDevicesHandler(pool)

	userID, _, _ := createTestUserWithMailbox(t, pool)

	// The wipe ack keys on the canonical devices.id (the client echoes it back).
	sum := sha256.Sum256([]byte("w5-wipe-fingerprint-" + fmt.Sprint(userID)))
	var devID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO devices (user_id, device_name, platform, fingerprint, hmac_secret)
		 VALUES ($1, 'w5 phone', 'ios', $2, $3) RETURNING id`,
		userID, hex.EncodeToString(sum[:]), "w5-hmac-"+fmt.Sprint(userID),
	).Scan(&devID); err != nil {
		t.Fatalf("seed device: %v", err)
	}

	var deviceID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO user_devices (user_id, device_name, platform, device_id, wipe_requested, wipe_type)
		 VALUES ($1, 'w5 phone', 'ios', $2, TRUE, 'full') RETURNING id`,
		userID, devID,
	).Scan(&deviceID); err != nil {
		t.Fatalf("seed user_devices: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM user_devices WHERE id = $1`, deviceID) //nolint:errcheck
		pool.Exec(context.Background(), `DELETE FROM devices WHERE id = $1`, devID)         //nolint:errcheck
	})

	body := `{"device_id":` + fmt.Sprint(devID) + `}`
	req := httptest.NewRequest(http.MethodPost, "/user/devices/wipe-ack", strings.NewReader(body))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
	rec := httptest.NewRecorder()
	h.WipeAck(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200\n%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"ok"`) {
		t.Errorf("body = %q, want an ok status", rec.Body.String())
	}

	var acked bool
	if err := pool.QueryRow(context.Background(),
		`SELECT wipe_acked_at IS NOT NULL FROM user_devices WHERE id = $1`, deviceID,
	).Scan(&acked); err != nil || !acked {
		t.Fatalf("wipe_acked_at must be stamped (acked=%v err=%v)", acked, err)
	}
}
