package device

// identity_forcerls_live_test.go — V254 FORCE-RLS actual-role Go-leg continuity
// (L2-C2 r3.3 item 14.1).
//
// The pgTAP arms (tests/V254__mdm_rls_backstop.pg items 1-13) prove the SQL
// level with hand-set GUCs; this test binds the GO level: the REAL
// Handler.Register path driven over a pool whose connections run AS the
// NOBYPASSRLS setjoin_app role (the exact role the B1 flip switches the
// gateway to — scripts/provision-roles.sql), where the production
// dbscope.RunUserScoped wrap inside RegisterDevice is the ONLY source of
// app.current_user_id. The test itself never sets the GUC: a missing wrap (or
// a re-introduced `_, _ =` that swallows the evidence INSERT's WITH CHECK
// failure) fails here as a non-201 or an absent `registered` row under FORCE,
// never as a hand-scoped fixture pass.
//
// The pool-constraint mechanic mirrors chat's rls_scope_live_test.go (the W4
// actual-role genre): 'mail' — the TEST_DB_DSN user — is a superuser in the
// test cluster, so it may SET ROLE setjoin_app unconditionally; the role
// assumption is probed fail-loud before any assertion.
//
// Non-vacuousness: before registering, a bare constrained-pool read of a
// seeded OTHER user's device_events row must see 0 rows (empty GUC → the
// Posture B device-join arm filters everything) even though the unconstrained
// fixture pool sees it — proving this connection really is FORCE-bound, so the
// later positive assertion can only pass through the production wrap.

import (
	"bytes"
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
)

// forceRLSConstrainedPool opens a pool whose every physical connection runs
// SET ROLE setjoin_app immediately after connecting (session-scoped). See the
// file comment for why this is the actual-role reproduction the r12 contract
// requires.
func forceRLSConstrainedPool(t *testing.T, dsn string) *pgxpool.Pool {
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
		t.Fatalf("forceRLSConstrainedPool: current_user = %q, want setjoin_app (SET ROLE did not take — check scripts/provision-roles.sql)", role)
	}
	return pool
}

// TestRegisterDeviceForceRLS_EvidenceRowLandsUnderAppRole drives the REAL
// Handler.Register end-to-end as setjoin_app under the V254 FORCE flip: 201 is
// returned AND the device_events `registered` evidence row EXISTS for the new
// device. The production RunUserScoped wrap (r3.1 wrap site (i)) is the only
// GUC source on the path; the test never sets app.current_user_id.
func TestRegisterDeviceForceRLS_EvidenceRowLandsUnderAppRole(t *testing.T) {
	dsn := os.Getenv("TEST_DB_DSN")
	if dsn == "" {
		t.Skip("TEST_DB_DSN not set")
	}
	ctx := context.Background()

	// Fixtures + the row-existence assertion channel run on the UNCONSTRAINED
	// (superuser) pool — setjoin_app has no business seeding fixtures in
	// production either; only the Handler's own wrapped statements must prove
	// themselves under the constrained role.
	adminPool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("admin pool: %v", err)
	}
	defer adminPool.Close()
	constrained := forceRLSConstrainedPool(t, dsn)

	uid, err := insertTestUser(ctx, adminPool, fmt.Sprintf("forcerls-%d@device.test", time.Now().UnixNano()))
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	defer adminPool.Exec(ctx, `DELETE FROM users WHERE id=$1`, uid)

	// A foreign user's device + evidence row, visible through the fixture pool:
	// the constrained, empty-GUC pool must NOT see it (the non-vacuousness
	// proof that this connection is genuinely FORCE-bound).
	fp := fmt.Sprintf("forcerls-fp-%032d", time.Now().UnixNano())
	var foreignDev int64
	if err := adminPool.QueryRow(ctx,
		`INSERT INTO devices (user_id, fingerprint, device_name, platform)
		 VALUES ($1, $2, 'ForceRLS Foreign', 'android') RETURNING id`,
		uid, fp,
	).Scan(&foreignDev); err != nil {
		t.Fatalf("seed foreign device: %v", err)
	}
	if _, err := adminPool.Exec(ctx,
		`INSERT INTO device_events (device_id, event_type, event_data)
		 VALUES ($1, 'registered', '{}'::jsonb)`, foreignDev,
	); err != nil {
		t.Fatalf("seed foreign evidence: %v", err)
	}
	defer func() {
		c := context.Background()
		_, _ = adminPool.Exec(c, `DELETE FROM device_events WHERE device_id = $1`, foreignDev)
		_, _ = adminPool.Exec(c, `DELETE FROM devices WHERE id = $1`, foreignDev)
	}()

	var seen int
	if err := constrained.QueryRow(ctx,
		`SELECT count(*) FROM device_events WHERE device_id = $1`, foreignDev,
	).Scan(&seen); err != nil {
		t.Fatalf("constrained probe: %v", err)
	}
	if seen != 0 {
		t.Fatalf("non-vacuousness probe: constrained setjoin_app pool saw %d rows of another user's device_events with NO GUC — RLS is not binding this connection (role has BYPASSRLS? V254 not applied?)", seen)
	}

	// The REAL registration path: Handler.Register with the auth-context stamp
	// RequireUserAuth would set — and nothing else.
	h := NewHandler(constrained, discardLogger(), testSecretCodec())
	body, _ := json.Marshal(Identity{
		Fingerprint: "forcerls" + fmt.Sprintf("%024d", time.Now().UnixNano()) + "abcdef",
		Platform:    "ios",
		DeviceName:  "ForceRLS Registration",
	})
	req := httptest.NewRequest(http.MethodPost, "/device/register", bytes.NewReader(body))
	req = req.WithContext(WithUserID(ctx, uid))
	rec := httptest.NewRecorder()
	h.Register(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("Register: want 201, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var resp struct {
		DeviceID   int64  `json:"device_id"`
		HMACSecret string `json:"hmac_secret"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode register response: %v", err)
	}
	if resp.DeviceID <= 0 || resp.HMACSecret == "" {
		t.Fatalf("register response incomplete: device_id=%d secret_len=%d", resp.DeviceID, len(resp.HMACSecret))
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = adminPool.Exec(c, `DELETE FROM device_events WHERE device_id = $1`, resp.DeviceID)
		_, _ = adminPool.Exec(c, `DELETE FROM devices WHERE id = $1`, resp.DeviceID)
	})

	// THE r3.3 assertion: the `registered` evidence row EXISTS. Under FORCE a
	// missing GUC pairing (or a swallowed INSERT error — the old `_, _ =`)
	// leaves this row absent; the wrapped, checked write makes it present.
	var n int
	if err := adminPool.QueryRow(ctx,
		`SELECT count(*) FROM device_events WHERE device_id = $1 AND event_type = 'registered'`,
		resp.DeviceID,
	).Scan(&n); err != nil {
		t.Fatalf("evidence count: %v", err)
	}
	if n != 1 {
		t.Fatalf("device_events `registered` evidence row missing for device %d under FORCE — the production GUC wrap or the checked error path regressed (r3.1 wrap site (i))", resp.DeviceID)
	}
}
