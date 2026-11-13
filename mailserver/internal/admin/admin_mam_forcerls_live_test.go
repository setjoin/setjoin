package admin

// admin_mam_forcerls_live_test.go — V254 FORCE-RLS actual-role Go-leg
// continuity (L2-C2 r3.3 item 14.2/14.3).
//
// The pgTAP arms (mailserver/sql/tests/V254__mdm_rls_backstop.pg items 1-13)
// prove the SQL level with hand-set GUCs; this file binds the GO level: the
// REAL MAMHandler.ListDevices / GetDeviceEvents paths driven over a pool whose
// connections run AS the NOBYPASSRLS setjoin_app role (the exact role the B1
// flip switches the gateway to — scripts/provision-roles.sql). The production
// dbscope.RunUserScoped wraps (r2.3 (f), r3.2 (g)(h)) are the ONLY source of
// app.current_user_id on these paths: the tests never set the GUC, so a
// missing wrap fails here as an empty console list / empty history under
// FORCE instead of passing through a hand-scoped fixture.
//
// The pool-constraint mechanic mirrors chat's rls_scope_live_test.go (the W4
// actual-role genre): the DB_DSN user ('mail') is a superuser in the test
// cluster, so it may SET ROLE setjoin_app unconditionally; the role assumption
// is probed fail-loud before any assertion. The admin actor's mam.read grant
// is seeded so drive_has_admin_perm (V114) admits the OR-form read arms — the
// same DB-visible grant the route middleware's requireMamRead enforces in
// production.

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

	"setjoin.com/shared/testsupport"
)

// mamForceRLSFingerprint returns a per-run unique UUID-shaped fingerprint.
// device_registry.device_fingerprint is the uuid type and the console
// resolution joins devices.fingerprint = device_registry.device_fingerprint::text,
// so the fixture must be a canonical 8-4-4-4-12 hex string valid for both.
func mamForceRLSFingerprint() string {
	nano := time.Now().UnixNano()
	return fmt.Sprintf("%08x-0000-4000-8000-%012x", nano&0xffffffff, nano&0xffffffffffff)
}

// mamForceRLSPool opens the MAM handler pool whose every physical connection
// runs SET ROLE setjoin_app immediately after connecting (session-scoped — it
// sticks for the connection's whole life). See the file comment.
func mamForceRLSPool(t *testing.T, dsn string) *pgxpool.Pool {
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
	// Fail loudly here, not with a confusing downstream RLS denial, if the
	// test DB's role provisioning ever drifts.
	var role string
	if err := pool.QueryRow(context.Background(), "SELECT current_user").Scan(&role); err != nil {
		t.Fatalf("probe current_user: %v", err)
	}
	if role != "setjoin_app" {
		t.Fatalf("mamForceRLSPool: current_user = %q, want setjoin_app (SET ROLE did not take — check scripts/provision-roles.sql)", role)
	}
	return pool
}

// seedMAMForceRLSAdmin creates the admin actor holding the `mam.read` grant
// (admin_role_groups + admin_role_assignments, cleanup registered), returning
// its user id. drive_has_admin_perm evaluates THIS grant when the Posture A/B
// read arms see the admin GUC the production wrap sets.
func seedMAMForceRLSAdmin(t *testing.T, pool *pgxpool.Pool, domainID int64, domainName string) int64 {
	t.Helper()
	adminID := createScopeTestUser(t, pool, domainID, domainName)
	grpName := fmt.Sprintf("mam-forcerls-%d", adminID)
	var grpID int64
	if err := pool.QueryRow(context.Background(),
		`INSERT INTO admin_role_groups (name, permissions) VALUES ($1, ARRAY['mam.read']::text[]) RETURNING id`,
		grpName,
	).Scan(&grpID); err != nil {
		t.Fatalf("seed admin role group: %v", err)
	}
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO admin_role_assignments (user_id, role_group_id, granted_by) VALUES ($1, $2, $1)`,
		adminID, grpID,
	); err != nil {
		t.Fatalf("seed admin role assignment: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM admin_role_assignments WHERE role_group_id = $1`, grpID)
		_, _ = pool.Exec(c, `DELETE FROM admin_role_groups WHERE id = $1`, grpID)
		_, _ = pool.Exec(c, `DELETE FROM users WHERE id = $1`, adminID)
	})
	return adminID
}

// TestMAMForceRLS_ListDevicesSeesRegistryRows drives the REAL ListDevices
// path as setjoin_app under the V254 FORCE flip: the console device list
// (device_registry LEFT JOIN mdm_device_state — both Posture A) shows the
// seeded registry row. The production RunUserScoped wrap (r3.2 (g)) is the
// only GUC source; the test never sets app.current_user_id.
func TestMAMForceRLS_ListDevicesSeesRegistryRows(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is unset but REQUIRE_DB is set — fail-closed: a DB-backed test must not pass as a silent skip in CI")
		}
		t.Skip("DB_DSN not set — skipping DB-backed test")
	}

	// Fixtures run on the UNCONSTRAINED pool; the handler runs on the
	// constrained (setjoin_app) pool.
	adminPool := testsupport.OpenTestPool(t)
	constrained := mamForceRLSPool(t, dsn)
	h := NewMAMHandler(constrained, testsupport.TestLogger())

	dom := ensureScopeTestDomain(t, adminPool, "mam-forcerls.scope.test")
	owner := createScopeTestUser(t, adminPool, dom, "mam-forcerls.scope.test")
	adminID := seedMAMForceRLSAdmin(t, adminPool, dom, "mam-forcerls.scope.test")

	base := mamScopeIDBase()
	regID := base + 1
	devID := base + 2
	fp := mamForceRLSFingerprint()
	seedMAMRegistryDevice(t, adminPool, owner, regID, fp)
	seedMAMAuthoritativeDevice(t, adminPool, owner, devID, fp)

	req := adminClaimsCtx(httptest.NewRequest(http.MethodGet, "/admin/mam/devices", nil), adminID, 0)
	rec := httptest.NewRecorder()
	h.ListDevices(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("ListDevices: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Devices []mamDevice `json:"devices"`
		Total   int         `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	found := false
	for _, d := range body.Devices {
		if d.ID == regID {
			found = true
		}
	}
	if !found {
		t.Fatalf("MAM console list over the constrained setjoin_app pool does not show seeded registry device %d (total=%d) — the production RunUserScoped GUC wrap (r3.2 (g)) is missing or the V254 FORCE arms regressed", regID, body.Total)
	}
}

// TestMAMForceRLS_GetDeviceEventsSeedsVisible drives the REAL GetDeviceEvents
// path (console-id resolution + device_events SELECT) as setjoin_app under the
// V254 FORCE flip: the seeded evidence row is visible for the resolved
// authoritative device. The production RunUserScoped wraps (r2.3 (f) resolve +
// r3.2 (h) events read) are the only GUC sources; the test never sets
// app.current_user_id.
func TestMAMForceRLS_GetDeviceEventsSeedsVisible(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is unset but REQUIRE_DB is set — fail-closed: a DB-backed test must not pass as a silent skip in CI")
		}
		t.Skip("DB_DSN not set — skipping DB-backed test")
	}

	adminPool := testsupport.OpenTestPool(t)
	constrained := mamForceRLSPool(t, dsn)
	h := NewMAMHandler(constrained, testsupport.TestLogger())

	dom := ensureScopeTestDomain(t, adminPool, "mam-forcerls-events.scope.test")
	owner := createScopeTestUser(t, adminPool, dom, "mam-forcerls-events.scope.test")
	adminID := seedMAMForceRLSAdmin(t, adminPool, dom, "mam-forcerls-events.scope.test")

	base := mamScopeIDBase()
	regID := base + 1
	devID := base + 2
	fp := mamForceRLSFingerprint()
	seedMAMRegistryDevice(t, adminPool, owner, regID, fp)
	seedMAMAuthoritativeDevice(t, adminPool, owner, devID, fp)
	seedMAMDeviceEvent(t, adminPool, devID, "device_locked")

	req := httptest.NewRequest(http.MethodGet,
		fmt.Sprintf("/admin/mam/devices/%d/events", regID), nil)
	req.SetPathValue("device_id", fmt.Sprintf("%d", regID))
	req = adminClaimsCtx(req, adminID, 0)

	rec := httptest.NewRecorder()
	h.GetDeviceEvents(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GetDeviceEvents: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var body mamEventsBody
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode events: %v", err)
	}
	if body.Total != 1 || len(body.Events) != 1 || body.Events[0].EventType != "device_locked" {
		t.Fatalf("device history over the constrained setjoin_app pool is empty or wrong (total=%d, events=%v) — under FORCE a missing GUC pairing (r3.2 (h)) yields a silent empty history", body.Total, body.Events)
	}
}
