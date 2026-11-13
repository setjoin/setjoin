package telemetry

// Tests for the med-shard3-017 remediation: device identity for
// POST /telemetry is derived from the auth-context device binding (per-device
// HMAC seam, shared/device.VerifyDeviceRequest) rather than the request-owned
// body device_id, and record creation per device is capped while the toggle is
// ON. The default-OFF toggle path keeps its identical bare-204 behavior.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/cryptokey"
	"setjoin.com/shared/device"
	"setjoin.com/shared/testsupport"
)

// acceptAnyDevice is the stand-in DeviceAuthFunc for tests that exercise the
// non-auth behavior of the handler (toggle, parsing, 405).
func acceptAnyDevice(_ context.Context, _ int64, _ *http.Request) error {
	return nil
}

// capCountingStore counts inserts so the per-device record cap can be asserted
// without a database.
type capCountingStore struct {
	inserts int
}

func (s *capCountingStore) Insert(_ context.Context, _ TelemetryRecord) error {
	s.inserts++
	return nil
}

// TestHandleTelemetry_ForgedDeviceIDForRealDeviceRefused: a claimed device_id
// that fails the auth-context device proof (forged for a real device) is
// refused with 401 and never reaches the store.
func TestHandleTelemetry_ForgedDeviceIDForRealDeviceRefused(t *testing.T) {
	store := &capCountingStore{}
	var challenged int64
	auth := func(_ context.Context, deviceID int64, _ *http.Request) error {
		challenged = deviceID
		return fmt.Errorf("device: HMAC mismatch")
	}
	handler := HandleTelemetry(store, func() bool { return true }, auth)

	req := httptest.NewRequest(http.MethodPost, "/telemetry",
		bytes.NewReader([]byte(`{"device_id":42,"app_version":"1.2.3"}`)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for forged device_id, got %d: %s", rec.Code, rec.Body.String())
	}
	if challenged != 42 {
		t.Errorf("expected authenticator to be challenged with the claimed id 42, got %d", challenged)
	}
	if store.inserts != 0 {
		t.Errorf("expected no record for a refused binding, got %d", store.inserts)
	}
}

// TestHandleTelemetry_RecordAttributedToAuthenticatedDevice: the inserted row
// attributes to exactly the device the authenticator verified; a different id
// from the same caller shape is refused with 401 and creates no record.
func TestHandleTelemetry_RecordAttributedToAuthenticatedDevice(t *testing.T) {
	store := &fakeStore{}
	const boundDevice int64 = 77
	auth := func(_ context.Context, deviceID int64, _ *http.Request) error {
		if deviceID != boundDevice {
			return fmt.Errorf("device: HMAC mismatch")
		}
		return nil // proof verified for boundDevice
	}
	handler := HandleTelemetry(store, func() bool { return true }, auth)

	body, _ := json.Marshal(map[string]any{"device_id": boundDevice, "app_version": "2.0.0"})
	req := httptest.NewRequest(http.MethodPost, "/telemetry", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 for the bound device, got %d: %s", rec.Code, rec.Body.String())
	}
	if !store.called {
		t.Fatal("expected store to be called for the bound device")
	}
	if store.recorded.DeviceID != boundDevice {
		t.Errorf("record attributed to device %d, want the authenticated device %d",
			store.recorded.DeviceID, boundDevice)
	}

	// Same client, forged id for another (real) device: refused, no record.
	store.called = false
	forged, _ := json.Marshal(map[string]any{"device_id": boundDevice + 1, "app_version": "2.0.0"})
	req2 := httptest.NewRequest(http.MethodPost, "/telemetry", bytes.NewReader(forged))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	if rec2.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for forged device_id %d, got %d", boundDevice+1, rec2.Code)
	}
	if store.called {
		t.Error("expected store NOT called for the forged device_id")
	}
}

// TestHandleTelemetry_PerDeviceRecordCap: while the toggle is ON, record
// creation per device is bounded — only the first DefaultPerDeviceReportLimit
// authenticated reports insert; the rest get 429.
func TestHandleTelemetry_PerDeviceRecordCap(t *testing.T) {
	store := &capCountingStore{}
	handler := HandleTelemetry(store, func() bool { return true }, acceptAnyDevice)

	body := []byte(`{"device_id":9,"app_version":"1.0.0"}`)
	const extra = 3
	accepted, limited := 0, 0
	for i := 0; i < DefaultPerDeviceReportLimit+extra; i++ {
		req := httptest.NewRequest(http.MethodPost, "/telemetry", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		switch rec.Code {
		case http.StatusNoContent:
			accepted++
		case http.StatusTooManyRequests:
			limited++
		default:
			t.Fatalf("request %d: unexpected status %d: %s", i, rec.Code, rec.Body.String())
		}
	}

	if accepted != DefaultPerDeviceReportLimit {
		t.Errorf("accepted %d records, want exactly the per-device cap %d",
			accepted, DefaultPerDeviceReportLimit)
	}
	if limited != extra {
		t.Errorf("limited %d reports, want %d", limited, extra)
	}
	if store.inserts != DefaultPerDeviceReportLimit {
		t.Errorf("store saw %d inserts, want the per-device cap %d",
			store.inserts, DefaultPerDeviceReportLimit)
	}
}

// TestHandleTelemetry_ToggleOffUnchanged: regression for the default-OFF
// posture — identical bare 204, no store call, and the device-binding
// requirement does not leak into the disabled path.
func TestHandleTelemetry_ToggleOffUnchanged(t *testing.T) {
	store := &capCountingStore{}
	authCalled := false
	auth := func(_ context.Context, _ int64, _ *http.Request) error {
		authCalled = true
		return fmt.Errorf("authenticator must not be consulted while disabled")
	}
	handler := HandleTelemetry(store, func() bool { return false }, auth)

	req := httptest.NewRequest(http.MethodPost, "/telemetry",
		bytes.NewReader([]byte(`{"device_id":5,"app_version":"1.0.0"}`)))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected identical 204 while disabled, got %d", rec.Code)
	}
	if rec.Body.Len() != 0 {
		t.Errorf("expected empty 204 body while disabled, got %q", rec.Body.String())
	}
	if store.inserts != 0 {
		t.Errorf("expected no records while disabled, got %d", store.inserts)
	}
	if authCalled {
		t.Error("device authenticator must not run while the toggle is OFF")
	}
}

// TestHandleTelemetry_DeviceHMACEndToEnd drives the production wiring end to
// end against the test DB: a real devices row with a per-device HMAC secret,
// the shared VerifyDeviceRequest seam, and the PG store. A correctly signed
// report inserts a row attributed to the authenticated device; a forged id for
// that same real device is refused with 401 and inserts nothing. Skips when
// DB_DSN is unset.
func TestHandleTelemetry_DeviceHMACEndToEnd(t *testing.T) {
	pool := testsupport.OpenTestPool(t) // registers pool.Close via t.Cleanup FIRST
	ctx := context.Background()

	// Fixture: domain → user → device with a known HMAC secret.
	var domainID int64
	domainName := "telemetry-e2e-" + fmt.Sprintf("%d", time.Now().UnixNano()) + ".example"
	if err := pool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ($1) RETURNING id`, domainName,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM domains WHERE id = $1`, domainID)
	})

	var userID int64
	username := "tel-e2e-" + fmt.Sprintf("%d", time.Now().UnixNano())
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, password_hash, domain_id)
		 VALUES ($1, $2, 'Telemetry E2E', '$2a$10$placeholder', $3) RETURNING id`,
		username, username+"@"+domainName, domainID,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
	})

	secret := "e2e-telemetry-device-secret"
	fingerprint := "tel-e2e-" + fmt.Sprintf("%d", time.Now().UnixNano())
	var deviceID int64
	if err := pool.QueryRow(ctx,
		`INSERT INTO devices (user_id, fingerprint, hmac_secret, platform)
		 VALUES ($1, $2, $3, 'ios') RETURNING id`,
		userID, fingerprint, secret,
	).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		pool.Exec(c, `DELETE FROM device_telemetry WHERE device_id = $1`, deviceID)
		pool.Exec(c, `DELETE FROM devices WHERE id = $1`, deviceID)
	})

	// Production wiring: real store + real device-HMAC auth seam.
	store := NewPGStore(pool)
	handler := HandleTelemetry(store, func() bool { return true },
		func(rctx context.Context, id int64, r *http.Request) error {
			return device.VerifyDeviceRequest(rctx, pool, id, r, device.NewSecretCodec([]byte("telemetry-test-master-secret"), cryptokey.ProfileStandard))
		})

	report := func(id int64, macHex string) *httptest.ResponseRecorder {
		t.Helper()
		ts := time.Now().UTC().Format(time.RFC3339)
		body, _ := json.Marshal(map[string]any{
			"device_id":   id,
			"app_version": "1.2.3",
			"crash_count": 0,
		})
		req := httptest.NewRequest(http.MethodPost, "/telemetry", bytes.NewReader(body))
		req.Header.Set("X-Device-ID", fmt.Sprintf("%d", id))
		req.Header.Set("X-Device-Timestamp", ts)
		if macHex == "" {
			// Full remediated proof (med-shard2-006): single-use nonce + the
			// body hash bound INSIDE the HMAC over the canonical request
			// challenge (device, ts, method, request URI, body hash, nonce).
			bodySum := sha256.Sum256(body)
			bodyHash := hex.EncodeToString(bodySum[:])
			nonce := fmt.Sprintf("nonce-tel-e2e-%d-%d", id, time.Now().UnixNano())
			req.Header.Set("X-Device-Nonce", nonce)
			req.Header.Set("X-Device-Body-SHA256", bodyHash)
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write([]byte(device.ChallengeForRequest(id, ts, req.Method, req.URL.RequestURI(), bodyHash, nonce)))
			macHex = hex.EncodeToString(mac.Sum(nil))
		}
		req.Header.Set("X-Device-HMAC", macHex)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// Authenticated report → 204 and one row attributed to the real device.
	if rec := report(deviceID, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("authenticated report: expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	var rows int
	if err := pool.QueryRow(ctx,
		`SELECT count(*)::int FROM device_telemetry WHERE device_id = $1 AND app_version = '1.2.3'`,
		deviceID).Scan(&rows); err != nil {
		t.Fatalf("count telemetry rows: %v", err)
	}
	if rows != 1 {
		t.Fatalf("telemetry rows attributed to device %d = %d, want 1", deviceID, rows)
	}

	// Forged device_id for the SAME real device (no secret) → 401, no new row.
	if rec := report(deviceID, "forged-hex-digest"); rec.Code != http.StatusUnauthorized {
		t.Errorf("forged report for real device: expected 401, got %d", rec.Code)
	}
	// Unknown device id → 401 (no secret to prove against).
	if rec := report(deviceID+987654321, ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("unknown device report: expected 401, got %d", rec.Code)
	}

	if err := pool.QueryRow(ctx,
		`SELECT count(*)::int FROM device_telemetry WHERE device_id = $1`,
		deviceID).Scan(&rows); err != nil {
		t.Fatalf("recount telemetry rows: %v", err)
	}
	if rows != 1 {
		t.Errorf("telemetry rows after refused reports = %d, want 1 (forgery must not create records)", rows)
	}
}

// telemetryRolePool opens a pool whose every physical connection runs AS the
// named cluster role (session-scoped), probed fail-loud — the W4/actual-role
// mechanic (chat rls_scope_live_test.go, admin_mam_forcerls_live_test.go).
// The DB_DSN user ('mail') is a superuser in the test cluster, so it may SET
// ROLE unconditionally.
func telemetryRolePool(t *testing.T, dsn, role string) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse pool config: %v", err)
	}
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET ROLE "+role)
		return err
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	var got string
	if err := pool.QueryRow(context.Background(), "SELECT current_user").Scan(&got); err != nil {
		t.Fatalf("probe current_user: %v", err)
	}
	if got != role {
		t.Fatalf("telemetryRolePool(%s): current_user = %q, want %s (SET ROLE did not take — check scripts/provision-roles.sql)", role, got, role)
	}
	return pool
}

// TestHandleTelemetry_DeviceHMACSeparateAppWorkerCredentials is the C2-I3
// positive constrained-role evidence (astra-impl-l2c2) for the telemetry path:
// the production mount routes the ingest store through the setjoin_worker
// (BYPASSRLS) pool — device_telemetry is Posture D deny-all FORCE, so the app
// role cannot write it — while device attribution (VerifyDeviceRequest) stays
// on the app pool (cmd/mailserverd/main.go, "Telemetry" wiring). This test
// drives the REAL handler over two SEPARATE role-constrained pools in exactly
// that shape. The prior e2e test passed ONE shared fixture pool to both, so a
// credential-routing regression (store back on the app pool) was invisible.
func TestHandleTelemetry_DeviceHMACSeparateAppWorkerCredentials(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is unset but REQUIRE_DB is set — fail-closed: a DB-backed test must not pass as a silent skip in CI")
		}
		t.Skip("DB_DSN not set — skipping DB-backed test")
	}

	fixturePool := testsupport.OpenTestPool(t) // superuser: seeding + read-back counts
	workerPool := telemetryRolePool(t, dsn, "setjoin_worker")
	appPool := telemetryRolePool(t, dsn, "setjoin_app")
	ctx := context.Background()

	// Non-vacuous separation control FIRST: under the V254 deny-all FORCE
	// posture, the app credential must be unable to insert the very row this
	// test then admits through the worker credential — otherwise "success"
	// would prove nothing about which pool the store rode.
	var domainID, userID, deviceID int64
	domainName := "telemetry-roles-" + fmt.Sprintf("%d", time.Now().UnixNano()) + ".example"
	if err := fixturePool.QueryRow(ctx,
		`INSERT INTO domains (name) VALUES ($1) RETURNING id`, domainName,
	).Scan(&domainID); err != nil {
		t.Fatalf("insert domain: %v", err)
	}
	t.Cleanup(func() {
		fixturePool.Exec(context.Background(), `DELETE FROM domains WHERE id = $1`, domainID)
	})
	username := "tel-roles-" + fmt.Sprintf("%d", time.Now().UnixNano())
	if err := fixturePool.QueryRow(ctx,
		`INSERT INTO users (username, email, display_name, password_hash, domain_id)
		 VALUES ($1, $2, 'Telemetry Roles', '$2a$10$placeholder', $3) RETURNING id`,
		username, username+"@"+domainName, domainID,
	).Scan(&userID); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	t.Cleanup(func() {
		fixturePool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, userID)
	})
	secret := "e2e-telemetry-role-device-secret"
	fingerprint := "tel-roles-" + fmt.Sprintf("%d", time.Now().UnixNano())
	if err := fixturePool.QueryRow(ctx,
		`INSERT INTO devices (user_id, fingerprint, hmac_secret, platform)
		 VALUES ($1, $2, $3, 'ios') RETURNING id`,
		userID, fingerprint, secret,
	).Scan(&deviceID); err != nil {
		t.Fatalf("insert device: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		fixturePool.Exec(c, `DELETE FROM device_telemetry WHERE device_id = $1`, deviceID)
		fixturePool.Exec(c, `DELETE FROM devices WHERE id = $1`, deviceID)
	})

	if _, err := appPool.Exec(ctx,
		`INSERT INTO device_telemetry (device_id, app_version) VALUES ($1, 'x')`, deviceID,
	); err != nil {
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Fatalf("app-role direct device_telemetry INSERT: want 42501 (deny-all FORCE), got %v", err)
		}
	} else {
		t.Fatal("app-role direct device_telemetry INSERT succeeded — device_telemetry is Posture D deny-all FORCE; the separation control is vacuous")
	}

	// Production wiring shape: store on the WORKER credential, device
	// attribution on the APP credential — two different role-constrained pools.
	store := NewPGStore(workerPool)
	handler := HandleTelemetry(store, func() bool { return true },
		func(rctx context.Context, id int64, r *http.Request) error {
			return device.VerifyDeviceRequest(rctx, appPool, id, r, device.NewSecretCodec([]byte("telemetry-test-master-secret"), cryptokey.ProfileStandard))
		})

	signedReport := func(macHex string) *httptest.ResponseRecorder {
		t.Helper()
		ts := time.Now().UTC().Format(time.RFC3339)
		body, _ := json.Marshal(map[string]any{"device_id": deviceID, "app_version": "1.2.3"})
		req := httptest.NewRequest(http.MethodPost, "/telemetry", bytes.NewReader(body))
		req.Header.Set("X-Device-ID", fmt.Sprintf("%d", deviceID))
		req.Header.Set("X-Device-Timestamp", ts)
		bodySum := sha256.Sum256(body)
		bodyHash := hex.EncodeToString(bodySum[:])
		nonce := fmt.Sprintf("nonce-tel-roles-%d-%d", deviceID, time.Now().UnixNano())
		req.Header.Set("X-Device-Nonce", nonce)
		req.Header.Set("X-Device-Body-SHA256", bodyHash)
		if macHex == "" {
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write([]byte(device.ChallengeForRequest(deviceID, ts, req.Method, req.URL.RequestURI(), bodyHash, nonce)))
			macHex = hex.EncodeToString(mac.Sum(nil))
		}
		req.Header.Set("X-Device-HMAC", macHex)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// Authenticated report: attribution verified over the APP pool, the row
	// lands through the WORKER pool's Insert.
	if rec := signedReport(""); rec.Code != http.StatusNoContent {
		t.Fatalf("authenticated report over separate app/worker credentials: expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	var rows int
	if err := fixturePool.QueryRow(ctx,
		`SELECT count(*)::int FROM device_telemetry WHERE device_id = $1 AND app_version = '1.2.3'`,
		deviceID,
	).Scan(&rows); err != nil {
		t.Fatalf("count telemetry rows: %v", err)
	}
	if rows != 1 {
		t.Fatalf("telemetry rows attributed via app pool + inserted via worker pool = %d, want 1", rows)
	}

	// The same channel refuses an unproven binding (no record): the app-pool
	// attribution stays the gate even when the store could write anything.
	if rec := signedReport("forged-hex-digest"); rec.Code != http.StatusUnauthorized {
		t.Errorf("forged report over separate credentials: expected 401, got %d", rec.Code)
	}
	if err := fixturePool.QueryRow(ctx,
		`SELECT count(*)::int FROM device_telemetry WHERE device_id = $1`, deviceID,
	).Scan(&rows); err != nil {
		t.Fatalf("recount telemetry rows: %v", err)
	}
	if rows != 1 {
		t.Errorf("telemetry rows after the refused report = %d, want 1", rows)
	}
}
