package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"setjoin.com/shared/testsupport"
)

func mamStringPtr(value string) *string { return &value }

func TestMAMDeviceRowWire_RegistryFallbackWhenStateMissing(t *testing.T) {
	lastSeen := time.Date(2026, time.August, 14, 9, 30, 0, 0, time.UTC)
	firstSeen := time.Date(2026, time.August, 1, 8, 0, 0, 0, time.UTC)

	got := (mamDeviceRow{
		id:                41,
		userID:            9001,
		registryLastSeen:  &lastSeen,
		registryFirstSeen: &firstSeen,
	}).wire()

	if got.ID != 41 || got.UserID != 9001 {
		t.Fatalf("identity = (%d, %d), want (41, 9001)", got.ID, got.UserID)
	}
	if got.Platform != "unknown" || got.ComplianceStatus != "unknown" {
		t.Fatalf("missing MDM state = platform %q/status %q, want unknown/unknown", got.Platform, got.ComplianceStatus)
	}
	if got.DeviceName != "" || got.OSVersion != "" || got.AppVersion != "" {
		t.Fatalf("missing MDM fields = name=%q os=%q app=%q, want empty fallbacks", got.DeviceName, got.OSVersion, got.AppVersion)
	}
	if got.LastCheckinAt == nil || !got.LastCheckinAt.Equal(lastSeen) {
		t.Fatalf("last check-in = %v, want registry last_seen %v", got.LastCheckinAt, lastSeen)
	}
	if got.CreatedAt == nil || !got.CreatedAt.Equal(firstSeen) {
		t.Fatalf("created = %v, want registry first_seen %v", got.CreatedAt, firstSeen)
	}
	if got.WipeRequested {
		t.Fatal("missing MDM state must not report a wipe request")
	}
}

func TestMAMDeviceRowWire_PrefersMDMTimestamps(t *testing.T) {
	mdmTimestamp := time.Date(2026, time.August, 14, 10, 15, 0, 0, time.UTC)
	registryTimestamp := mdmTimestamp.Add(-time.Hour)

	got := (mamDeviceRow{
		lastCheckinAt:     &mdmTimestamp,
		createdAt:         &mdmTimestamp,
		registryLastSeen:  &registryTimestamp,
		registryFirstSeen: &registryTimestamp,
	}).wire()

	if got.LastCheckinAt != &mdmTimestamp || got.CreatedAt != &mdmTimestamp {
		t.Fatalf("MDM timestamps were not preferred: last=%v created=%v", got.LastCheckinAt, got.CreatedAt)
	}
}

func TestMAMDeviceRowWire_PreservesComplianceStatesAndWipe(t *testing.T) {
	for _, status := range []string{"compliant", "non_compliant", "grace", "quarantined"} {
		t.Run(status, func(t *testing.T) {
			got := (mamDeviceRow{compliance: mamStringPtr(status)}).wire()
			if got.ComplianceStatus != status {
				t.Fatalf("compliance status = %q, want %q", got.ComplianceStatus, status)
			}
		})
	}

	for _, state := range []struct {
		name string
		want bool
	}{
		{name: "none", want: false},
		{name: "pending", want: true},
		{name: "acknowledged", want: true},
		{name: "executed", want: true},
	} {
		t.Run("wipe_"+state.name, func(t *testing.T) {
			got := (mamDeviceRow{wipeRequested: mamStringPtr(state.name)}).wire()
			if got.WipeRequested != state.want {
				t.Fatalf("wipe_requested(%q) = %t, want %t", state.name, got.WipeRequested, state.want)
			}
		})
	}
}

func TestMAMDeviceListQuery_UsesRegistryIdentityAndStateJoin(t *testing.T) {
	for _, fragment := range []string{
		"FROM device_registry AS d",
		"LEFT JOIN mdm_device_state AS m",
		"m.device_id = d.device_fingerprint",
		"m.user_id = d.user_id",
		"m.compliance_status",
		"m.last_checkin_at",
		"d.last_seen",
	} {
		if !strings.Contains(mamDeviceListQuery, fragment) {
			t.Errorf("MAM list query missing %q", fragment)
		}
	}
	for _, forbidden := range []string{"device_hash", "device_secret", "device_fingerprint,"} {
		if strings.Contains(mamDeviceListQuery, forbidden) {
			t.Errorf("MAM list query must not project sensitive registry field %q", forbidden)
		}
	}
}

func TestMAMListDevices_DatabaseUnavailable(t *testing.T) {
	h := NewMAMHandler(nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/admin/mam/devices", nil)
	rec := httptest.NewRecorder()

	h.ListDevices(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
	}
}

func TestMAMListDevices_ProjectsRegistryAndMDMState(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	ctx := t.Context()
	account := fmt.Sprintf("mam-list-%d", time.Now().UnixNano())
	var mailboxID, userID int64
	if err := pool.QueryRow(ctx, `SELECT mk_account($1)`, account).Scan(&mailboxID); err != nil {
		t.Fatalf("mk_account: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, mailboxID).Scan(&userID); err != nil {
		t.Fatalf("resolve user: %v", err)
	}
	fingerprint := fmt.Sprintf("%08x-0000-4000-8000-%012x", uint32(userID), uint64(time.Now().UnixNano())&0xffffffffffff)
	var deviceID int64
	if err := pool.QueryRow(ctx, `
		INSERT INTO device_registry(user_id, device_hash, device_fingerprint, first_seen, last_seen)
		VALUES($1,$2,$3::uuid,now()-interval '2 hours',now()-interval '1 hour')
		RETURNING id`, userID, account, fingerprint).Scan(&deviceID); err != nil {
		t.Fatalf("insert registry device: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO mdm_device_state(device_id,user_id,platform,device_name,os_version,app_version,
			compliance_status,wipe_requested,last_checkin_at,created_at,updated_at)
		VALUES($1::uuid,$2,'ios','Coverage iPhone','18.0','2.0','compliant','pending',now(),now()-interval '1 day',now())`,
		fingerprint, userID); err != nil {
		t.Fatalf("insert MDM state: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM mdm_device_state WHERE device_id=$1::uuid`, fingerprint)
		_, _ = pool.Exec(context.Background(), `DELETE FROM device_registry WHERE id=$1`, deviceID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM users WHERE id=$1`, userID)
	})

	h := NewMAMHandler(pool, slog.Default())
	req := httptest.NewRequest(http.MethodGet, "/admin/mam/devices", nil)
	rec := httptest.NewRecorder()
	h.ListDevices(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Devices []mamDevice `json:"devices"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	for _, device := range body.Devices {
		if device.ID != deviceID {
			continue
		}
		if device.UserID != userID || device.Platform != "ios" || device.DeviceName != "Coverage iPhone" ||
			device.ComplianceStatus != "compliant" || !device.WipeRequested || device.LastCheckinAt == nil || device.CreatedAt == nil {
			t.Fatalf("projected device = %+v", device)
		}
		return
	}
	t.Fatalf("device %d absent from response", deviceID)
}

func TestMAMListDevices_QueryFailure(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	pool.Close()
	h := NewMAMHandler(pool, slog.Default())
	rec := httptest.NewRecorder()
	h.ListDevices(rec, httptest.NewRequest(http.MethodGet, "/admin/mam/devices", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func openMAMListFixturePool(t *testing.T, setupSQL string) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is unset but REQUIRE_DB is set")
		}
		t.Skip("DB_DSN not set")
	}
	adminPool := testsupport.OpenTestPool(t)
	schema := fmt.Sprintf("mam_scan_test_%d", time.Now().UnixNano())
	if _, err := adminPool.Exec(t.Context(), `CREATE SCHEMA `+schema); err != nil {
		t.Fatalf("create fixture schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = adminPool.Exec(context.Background(), `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
	})
	setupSQL = strings.ReplaceAll(setupSQL, "__SCHEMA__", schema)
	if _, err := adminPool.Exec(t.Context(), setupSQL); err != nil {
		t.Fatalf("create scan fixture: %v", err)
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse DB_DSN: %v", err)
	}
	cfg.MaxConns = 1
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		_, err := conn.Exec(ctx, `SET search_path=`+schema+`,public`)
		return err
	}
	shadowPool, err := pgxpool.NewWithConfig(t.Context(), cfg)
	if err != nil {
		t.Fatalf("open fixture pool: %v", err)
	}
	t.Cleanup(shadowPool.Close)
	return shadowPool
}

const mamFixtureStateTableSQL = `
	CREATE TABLE __SCHEMA__.mdm_device_state(
		device_id uuid, user_id bigint, platform text, device_name text,
		os_version text, app_version text, compliance_status text,
		wipe_requested text, last_checkin_at timestamptz, created_at timestamptz);`

func TestMAMListDevices_ScanFailure(t *testing.T) {
	shadowPool := openMAMListFixturePool(t, mamFixtureStateTableSQL+`
		CREATE TABLE __SCHEMA__.device_registry(
			id text, user_id bigint, device_fingerprint uuid,
			last_seen timestamptz, first_seen timestamptz);
		INSERT INTO __SCHEMA__.device_registry
		VALUES('not-a-bigint', 1, NULL, now(), now())`)

	h := NewMAMHandler(shadowPool, slog.Default())
	rec := httptest.NewRecorder()
	h.ListDevices(rec, httptest.NewRequest(http.MethodGet, "/admin/mam/devices", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rec.Code, rec.Body.String())
	}
}

func TestMAMListDevices_IterationFailure(t *testing.T) {
	shadowPool := openMAMListFixturePool(t, mamFixtureStateTableSQL+`
		CREATE FUNCTION __SCHEMA__.mam_iteration_failure() RETURNS bigint
		LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'planted iteration failure'; END $$;
		CREATE VIEW __SCHEMA__.device_registry AS
		SELECT __SCHEMA__.mam_iteration_failure() AS id,
		       1::bigint AS user_id, NULL::uuid AS device_fingerprint,
		       now() AS last_seen, now() AS first_seen`)

	h := NewMAMHandler(shadowPool, slog.Default())
	rec := httptest.NewRecorder()
	h.ListDevices(rec, httptest.NewRequest(http.MethodGet, "/admin/mam/devices", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500: %s", rec.Code, rec.Body.String())
	}
}
