package user

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/mailserver/internal/auth"
)

func TestDevicesHandler_Unauthenticated(t *testing.T) {
	pool := testPool(t)
	h := NewDevicesHandler(pool)

	req := httptest.NewRequest("GET", "/user/devices", nil)
	w := httptest.NewRecorder()
	h.ListDevices(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestDevicesHandler_EmptyList(t *testing.T) {
	pool := testPool(t)
	h := NewDevicesHandler(pool)

	req := httptest.NewRequest("GET", "/user/devices", nil)
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 999999})
	req = req.WithContext(ctx)

	w := httptest.NewRecorder()
	h.ListDevices(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d — body: %s", w.Code, w.Body.String())
	}
}

func TestDevicesHandler_StructInitialization(t *testing.T) {
	pool := testPool(t)
	h := NewDevicesHandler(pool)
	if h.pool != pool {
		t.Error("pool not set correctly")
	}
}

// appRolePool opens a pool whose every physical connection runs AS the
// NOBYPASSRLS setjoin_app role (session-scoped). Same mechanic as the admin
// package's mamForceRLSPool (admin_mam_forcerls_live_test.go, the accepted
// r3.3 item-14 genre): the DB_DSN user ('mail') is a superuser in the test
// cluster, so it may SET ROLE unconditionally, and the assumption is probed
// fail-loud before any assertion. dbscope.RunUserScoped stays the ONLY
// app.current_user_id source on the handler paths driven over this pool —
// the tests never hand-set the GUC.
func appRolePool(t *testing.T, dsn string) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse pool config: %v", err)
	}
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, "SET ROLE setjoin_app")
		return err
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	var role string
	if err := pool.QueryRow(context.Background(), "SELECT current_user").Scan(&role); err != nil {
		t.Fatalf("probe current_user: %v", err)
	}
	if role != "setjoin_app" {
		t.Fatalf("appRolePool: current_user = %q, want setjoin_app (SET ROLE did not take — check scripts/provision-roles.sql)", role)
	}
	return pool
}

// devicesForceRLSFingerprint returns a per-run unique UUID-shaped fingerprint:
// device_registry.device_fingerprint is the uuid type while devices.fingerprint
// is text, so the fixture value must be a canonical 8-4-4-4-12 hex string that
// is valid for the uuid cast AND matches the authoritative row byte-for-byte
// (the C2-I1 projection resolves platform/device_name through that join).
func devicesForceRLSFingerprint() string {
	nano := time.Now().UnixNano()
	return fmt.Sprintf("%08x-0000-4000-8000-%012x", nano&0xffffffff, nano&0xffffffffffff)
}

// TestDevicesHandler_ListsOwnDevicesThroughAppRole is the C2-I1 positive
// continuity acceptance (astra-impl-l2c2): the REAL ListDevices path driven
// over the NOBYPASSRLS setjoin_app pool under the V254 FORCE flip shows the
// seeded own-device row with REAL projected content. The previous projection
// named non-existent device_registry columns, every request errored, and the
// 200-empty fallback swallowed it — this test fails on that regression instead
// of accepting an empty list.
func TestDevicesHandler_ListsOwnDevicesThroughAppRole(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is unset but REQUIRE_DB is set — fail-closed: a DB-backed test must not pass as a silent skip in CI")
		}
		t.Skip("DB_DSN not set — skipping DB-backed test")
	}

	// Fixtures run on the UNCONSTRAINED pool; the handler runs on the
	// constrained (setjoin_app) pool.
	fixturePool := testPool(t)
	constrained := appRolePool(t, dsn)
	h := NewDevicesHandler(constrained)

	owner := createTestUser(t, fixturePool)
	other := createTestUser(t, fixturePool)

	fp := devicesForceRLSFingerprint()
	if _, err := fixturePool.Exec(context.Background(),
		`INSERT INTO devices (user_id, fingerprint, device_name, platform)
		 VALUES ($1, $2, 'Cat iPhone', 'ios')`,
		owner, fp,
	); err != nil {
		t.Fatalf("seed authoritative devices row: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = fixturePool.Exec(c, `DELETE FROM devices WHERE user_id = $1 AND fingerprint = $2`, owner, fp)
	})

	const deviceHash = "c2-devices-go-hash"
	if _, err := fixturePool.Exec(context.Background(),
		`INSERT INTO device_registry (user_id, device_hash, user_agent, trust_tier, auth_count, device_fingerprint, last_seen, first_seen)
		 VALUES ($1, $2, 'SetjoinMail/1.4 (iOS)', 'known', 3, $3::uuid, now(), now())`,
		owner, deviceHash, fp,
	); err != nil {
		t.Fatalf("seed device_registry row: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = fixturePool.Exec(c, `DELETE FROM device_registry WHERE user_id = $1 AND device_hash = $2`, owner, deviceHash)
	})

	listDevices := func(userID int64) ([]map[string]any, int) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/user/devices", nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: userID}))
		rec := httptest.NewRecorder()
		h.ListDevices(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("ListDevices(user=%d): want 200, got %d (body=%s)", userID, rec.Code, rec.Body.String())
		}
		var body struct {
			Devices []map[string]any `json:"devices"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode list body: %v (raw=%s)", err, rec.Body.String())
		}
		return body.Devices, rec.Code
	}

	// Own device through the real role: exactly one row, real content.
	devices, _ := listDevices(owner)
	if len(devices) != 1 {
		t.Fatalf("own device list over the constrained setjoin_app pool has %d devices, want exactly the seeded row — an empty list here means the C2-I1 projection regressed (non-existent column → 200-empty fallback) or the RunUserScoped GUC pairing is missing under FORCE", len(devices))
	}
	d := devices[0]
	if got, _ := d["device_fingerprint"].(string); got != deviceHash {
		t.Errorf("device_fingerprint = %q, want the seeded hash %q", got, deviceHash)
	}
	// device_name resolves through the authoritative devices join (production
	// mamDeviceResolveQuery identity shape), not the fabricated old column.
	if got, _ := d["device_name"].(string); got != "Cat iPhone" {
		t.Errorf("device_name = %q, want the authoritative devices row's 'Cat iPhone'", got)
	}
	if got, _ := d["platform"].(string); got != "ios" {
		t.Errorf("platform = %q, want the authoritative devices row's 'ios'", got)
	}
	if got, _ := d["trust_tier"].(string); got != "known" {
		t.Errorf("trust_tier = %q, want the seeded registry tier 'known'", got)
	}
	if got, _ := d["created_at"].(string); got == "" {
		t.Error("created_at must be projected from the real first_seen column, got empty")
	}
	if got, _ := d["has_active_session"].(bool); got {
		t.Error("has_active_session = true, want false (sessions carry no device binding in the current schema — the field is held honestly false)")
	}

	// Another authenticated user sees none of it (R1 + FORCE self arm).
	others, _ := listDevices(other)
	if len(others) != 0 {
		t.Fatalf("cross-actor list over the constrained pool saw %d devices, want 0", len(others))
	}
}
