package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ── mdm-cross-domain-admin: handler-level domain-scope regression suite ─────
//
// The MDM device handlers must resolve the admin's domain scope from the
// REQUEST CONTEXT (middleware.DomainScopeFromContext, set by RequireAuth from
// claims.DomainScope) and thread it into the engine's SQL predicates:
// list/get see only same-domain-owner devices (R1), wipe arms only same-domain
// devices (R3, predicate in the UPDATE's WHERE). A scoped admin touching an
// out-of-scope device gets 404 "device not found" — indistinguishable from
// missing (no existence oracle); state conflicts (409) surface only for
// in-scope devices. Global-scope admins (scope 0) are unchanged.
//
// Device rows ride on the shared scope fixtures (ensureScopeTestDomain /
// createScopeTestUser); user deletion cascades mdm_device_state away.

// seedMDMScopeDevice inserts an mdm_device_state row for the user with the
// given wipe state/level and registers cleanup.
func seedMDMScopeDevice(t *testing.T, pool *pgxpool.Pool, userID int64, wipeState, wipeLevel string) uuid.UUID {
	t.Helper()
	deviceID := uuid.New()
	var level any
	if wipeLevel != "" {
		level = wipeLevel
	}
	_, err := pool.Exec(context.Background(),
		`INSERT INTO mdm_device_state (device_id, user_id, platform, device_name, os_version, app_version,
		                                compliance_status, wipe_requested, wipe_level)
		 VALUES ($1, $2, 'ios', 'MDM Scope Handler Device', '17.0', '1.0', 'compliant', $3, $4)`,
		deviceID, userID, wipeState, level,
	)
	if err != nil {
		t.Fatalf("seedMDMScopeDevice: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM mdm_device_state WHERE device_id = $1`, deviceID)
	})
	return deviceID
}

func mdmScopeDeviceState(t *testing.T, pool *pgxpool.Pool, deviceID uuid.UUID) (string, string) {
	t.Helper()
	var state, level string
	if err := pool.QueryRow(context.Background(),
		`SELECT wipe_requested, COALESCE(wipe_level, '') FROM mdm_device_state WHERE device_id = $1`,
		deviceID,
	).Scan(&state, &level); err != nil {
		t.Fatalf("read device state: %v", err)
	}
	return state, level
}

// TestMDMDevices_DomainScope_ListGet proves a domain-A admin's device list and
// single-device GET are filtered IN SQL: out-of-scope devices are empty/404,
// same-domain devices are served, and the global admin sees both.
func TestMDMDevices_DomainScope_ListGet(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewMDMHandler(pool, mailboxTestLogger())

	domA := ensureScopeTestDomain(t, pool, "mdm-handler-a.scope.test")
	domB := ensureScopeTestDomain(t, pool, "mdm-handler-b.scope.test")
	userA := createScopeTestUser(t, pool, domA, "mdm-handler-a.scope.test")
	userB := createScopeTestUser(t, pool, domB, "mdm-handler-b.scope.test")
	deviceA := seedMDMScopeDevice(t, pool, userA, "none", "")
	deviceB := seedMDMScopeDevice(t, pool, userB, "none", "")

	// ── list, domain-A scoped: only A devices.
	req := adminClaimsCtx(httptest.NewRequest(http.MethodGet, "/admin/mdm/devices", nil), 1, domA)
	rec := httptest.NewRecorder()
	h.ListDevices(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scoped ListDevices: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var list struct {
		Devices []struct {
			DeviceID uuid.UUID `json:"device_id"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	sawA, sawB := false, false
	for _, d := range list.Devices {
		switch d.DeviceID {
		case deviceA:
			sawA = true
		case deviceB:
			sawB = true
		}
	}
	if !sawA || len(list.Devices) == 0 {
		t.Errorf("scoped admin must see same-domain device %s (got %d devices)", deviceA, len(list.Devices))
	}
	if sawB {
		t.Errorf("scoped admin list leaked out-of-scope device %s (IDOR)", deviceB)
	}

	// ── list, global scope: unchanged, sees both.
	req = adminClaimsCtx(httptest.NewRequest(http.MethodGet, "/admin/mdm/devices", nil), 1, 0)
	rec = httptest.NewRecorder()
	h.ListDevices(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("global ListDevices: want 200, got %d", rec.Code)
	}
	list.Devices = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode global list: %v", err)
	}
	sawA, sawB = false, false
	for _, d := range list.Devices {
		switch d.DeviceID {
		case deviceA:
			sawA = true
		case deviceB:
			sawB = true
		}
	}
	if !sawA || !sawB {
		t.Errorf("global admin must see both devices (sawA=%v sawB=%v)", sawA, sawB)
	}

	// ── get, cross-domain: 404, indistinguishable from missing.
	req = adminClaimsCtx(httptest.NewRequest(http.MethodGet, "/admin/mdm/devices/"+deviceB.String(), nil), 1, domA)
	req.SetPathValue("device_id", deviceB.String())
	rec = httptest.NewRecorder()
	h.GetDevice(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-domain GetDevice: want 404, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	// ── get, same-domain: 200.
	req = adminClaimsCtx(httptest.NewRequest(http.MethodGet, "/admin/mdm/devices/"+deviceA.String(), nil), 1, domA)
	req.SetPathValue("device_id", deviceA.String())
	rec = httptest.NewRecorder()
	h.GetDevice(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("same-domain GetDevice: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}

// TestMDMDevices_DomainScope_Wipe proves the wipe arm carries the context
// scope into the UPDATE's WHERE (R3) and pins the attestation-honesty marker
// plus the executed-terminal contract at the handler boundary.
func TestMDMDevices_DomainScope_Wipe(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewMDMHandler(pool, mailboxTestLogger())

	domA := ensureScopeTestDomain(t, pool, "mdm-wipe-a.scope.test")
	domB := ensureScopeTestDomain(t, pool, "mdm-wipe-b.scope.test")
	userA := createScopeTestUser(t, pool, domA, "mdm-wipe-a.scope.test")
	userB := createScopeTestUser(t, pool, domB, "mdm-wipe-b.scope.test")
	deviceA := seedMDMScopeDevice(t, pool, userA, "none", "")
	deviceB := seedMDMScopeDevice(t, pool, userB, "none", "")
	// The wipe arm is reducer-authoritative and writes a durable device_events
	// row; it has no FK cascade from the device row, so clean it explicitly
	// (only deviceA is ever armed here).
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM device_events
			  WHERE event_type = 'wipe_requested' AND details->>'mdm_device_id' = $1`,
			deviceA.String())
	})

	wipeReq := func(deviceID uuid.UUID, scope int64, level string) *httptest.ResponseRecorder {
		t.Helper()
		body := `{"level":"` + level + `"}`
		req := httptest.NewRequest(http.MethodPost, "/admin/mdm/devices/"+deviceID.String()+"/wipe", stringReader(body))
		req = adminClaimsCtx(req, 1, scope)
		req.SetPathValue("device_id", deviceID.String())
		rec := httptest.NewRecorder()
		h.TriggerWipe(rec, req)
		return rec
	}

	// Cross-domain wipe: 404, indistinguishable from a missing device (no
	// existence oracle for out-of-scope callers); row untouched ('none').
	rec := wipeReq(deviceB, domA, "device")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-domain wipe: want 404, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var problem struct {
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil || problem.Detail != "device not found" {
		t.Fatalf("cross-domain wipe problem body: %s", rec.Body.String())
	}
	if state, _ := mdmScopeDeviceState(t, pool, deviceB); state != "none" {
		t.Errorf("cross-domain wipe mutated out-of-scope device: %s", state)
	}

	// Same-domain wipe: 202, armed, completion labeled client-attested.
	rec = wipeReq(deviceA, domA, "device")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("same-domain wipe: want 202, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var okBody map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &okBody); err != nil {
		t.Fatalf("decode wipe response: %v", err)
	}
	if okBody["completion"] != "client-attested" {
		t.Errorf("wipe response must label completion as client-attested, got %q", okBody["completion"])
	}
	if state, level := mdmScopeDeviceState(t, pool, deviceA); state != "pending" || level != "device" {
		t.Errorf("same-domain wipe did not arm: state=%s level=%s", state, level)
	}

	// Idempotent same-level retry: 202 again, no double transition.
	rec = wipeReq(deviceA, domA, "device")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("pending retry: want 202, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	// In-scope state conflict: same scoped admin re-arms at a DIFFERENT level
	// → 409 preserved. Conflicts are only ever surfaced for IN-SCOPE devices.
	rec = wipeReq(deviceA, domA, "account")
	if rec.Code != http.StatusConflict {
		t.Fatalf("in-scope level conflict: want 409, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var errBody map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil ||
		errBody["error"] != "wipe already in progress at level 'device'" || errBody["field"] != "wipe_level" {
		t.Fatalf("in-scope level conflict body: %s", rec.Body.String())
	}

	// Unknown device: 404 for global and scoped callers alike.
	missing := uuid.New()
	for _, scope := range []int64{0, domA} {
		rec = wipeReq(missing, scope, "device")
		if rec.Code != http.StatusNotFound {
			t.Fatalf("missing-device wipe (scope=%d): want 404, got %d (body=%s)", scope, rec.Code, rec.Body.String())
		}
	}

	// Executed device, global admin: terminal explicit error.
	if _, err := pool.Exec(context.Background(),
		`UPDATE mdm_device_state SET wipe_requested = 'executed' WHERE device_id = $1`, deviceB); err != nil {
		t.Fatalf("force executed: %v", err)
	}
	rec = wipeReq(deviceB, 0, "account")
	if rec.Code != http.StatusConflict {
		t.Fatalf("executed re-request: want 409, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	errBody = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &errBody); err != nil || errBody["error"] != "wipe already executed" {
		t.Fatalf("executed re-request body: %s", rec.Body.String())
	}

	// Executed device stays invisible to a scoped admin (no status leak): the
	// not-found classification is an equivalent 404, never a 409 conflict.
	rec = wipeReq(deviceB, domA, "account")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("scoped executed re-request: want 404, got %d", rec.Code)
	}
	problem = struct {
		Detail string `json:"detail"`
	}{}
	if err := json.Unmarshal(rec.Body.Bytes(), &problem); err != nil || problem.Detail != "device not found" {
		t.Fatalf("scoped executed re-request must not leak status: %s", rec.Body.String())
	}
}

// TestMDMDevices_WipeCompletionMarker_StatusReads proves the client-attested
// completion marker is not confined to the initial 202 wipe response: executed
// and pending devices carry completion "client-attested" in the admin LIST and
// DETAIL status reads (DeviceState serialization), and a device with no wipe
// armed omits the field entirely.
func TestMDMDevices_WipeCompletionMarker_StatusReads(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewMDMHandler(pool, mailboxTestLogger())

	dom := ensureScopeTestDomain(t, pool, "mdm-marker.scope.test")
	user := createScopeTestUser(t, pool, dom, "mdm-marker.scope.test")
	deviceExecuted := seedMDMScopeDevice(t, pool, user, "executed", "device")
	devicePending := seedMDMScopeDevice(t, pool, user, "pending", "account")
	deviceNone := seedMDMScopeDevice(t, pool, user, "none", "")

	// ── list: armed (executed/pending) devices carry the marker; none omits it.
	req := adminClaimsCtx(httptest.NewRequest(http.MethodGet, "/admin/mdm/devices", nil), 1, 0)
	rec := httptest.NewRecorder()
	h.ListDevices(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("global ListDevices: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var list struct {
		Devices []struct {
			DeviceID   uuid.UUID `json:"device_id"`
			Completion string    `json:"completion"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode marker list: %v", err)
	}
	completion := map[uuid.UUID]string{}
	for _, d := range list.Devices {
		completion[d.DeviceID] = d.Completion
	}
	for _, tc := range []struct {
		name     string
		deviceID uuid.UUID
		want     string
	}{
		{"executed", deviceExecuted, "client-attested"},
		{"pending", devicePending, "client-attested"},
		{"none", deviceNone, ""},
	} {
		if got := completion[tc.deviceID]; got != tc.want {
			t.Errorf("list completion for %s device: want %q, got %q", tc.name, tc.want, got)
		}
	}

	// ── detail: same marker contract per state.
	for _, tc := range []struct {
		name     string
		deviceID uuid.UUID
		want     string // "" = field must be absent
	}{
		{"executed", deviceExecuted, "client-attested"},
		{"pending", devicePending, "client-attested"},
		{"none", deviceNone, ""},
	} {
		req := adminClaimsCtx(httptest.NewRequest(http.MethodGet, "/admin/mdm/devices/"+tc.deviceID.String(), nil), 1, 0)
		req.SetPathValue("device_id", tc.deviceID.String())
		rec := httptest.NewRecorder()
		h.GetDevice(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("detail %s: want 200, got %d (body=%s)", tc.name, rec.Code, rec.Body.String())
		}
		var body map[string]interface{}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("decode detail %s: %v", tc.name, err)
		}
		got, present := body["completion"]
		if tc.want == "" {
			if present {
				t.Errorf("detail %s device must omit completion, got %v", tc.name, got)
			}
			continue
		}
		if !present || got != tc.want {
			t.Errorf("detail %s device completion: want %q, got %v (present=%v)", tc.name, tc.want, got, present)
		}
	}
}

// TestMDMDevices_ForceRLS_ListGetThroughAppRole is the C2-I3 positive
// constrained-role continuity evidence (astra-impl-l2c2): the REAL MDM
// ListDevices / GetDevice paths driven over a pool whose connections run AS
// the NOBYPASSRLS setjoin_app role under the V254 FORCE flip. The scope
// suites above share their fixture pool with the handlers (RLS bypassed), so
// they cannot see a missing GUC pairing — here fixtures live on the
// unconstrained pool while the handler pool is constrained, and the production
// dbscope.RunUserScoped wraps are the ONLY app.current_user_id source (the
// tests never set the GUC): a missing wrap fails as an empty list / 404 under
// FORCE instead of passing. The admin's seeded mam.read grant
// (seedMAMForceRLSAdmin, the same DB-visible grant requireMamRead enforces)
// is what the OR-form admin-read arms evaluate.
func TestMDMDevices_ForceRLS_ListGetThroughAppRole(t *testing.T) {
	dsn := os.Getenv("DB_DSN")
	if dsn == "" {
		if os.Getenv("REQUIRE_DB") != "" {
			t.Fatal("DB_DSN is unset but REQUIRE_DB is set — fail-closed: a DB-backed test must not pass as a silent skip in CI")
		}
		t.Skip("DB_DSN not set — skipping DB-backed test")
	}

	// Fixtures run on the UNCONSTRAINED pool; the handler runs on the
	// constrained (setjoin_app) pool — mirroring admin_mam_forcerls_live_test.go.
	adminPool := mailboxTestPool(t)
	constrained := mamForceRLSPool(t, dsn)
	h := NewMDMHandler(constrained, mailboxTestLogger())

	domA := ensureScopeTestDomain(t, adminPool, "mdm-forcerls-a.scope.test")
	domB := ensureScopeTestDomain(t, adminPool, "mdm-forcerls-b.scope.test")
	userA := createScopeTestUser(t, adminPool, domA, "mdm-forcerls-a.scope.test")
	userB := createScopeTestUser(t, adminPool, domB, "mdm-forcerls-b.scope.test")
	adminID := seedMAMForceRLSAdmin(t, adminPool, domA, "mdm-forcerls-a.scope.test")
	deviceA := seedMDMScopeDevice(t, adminPool, userA, "none", "")
	deviceB := seedMDMScopeDevice(t, adminPool, userB, "none", "")

	// ── global list over the constrained pool: BOTH domain devices served.
	req := adminClaimsCtx(httptest.NewRequest(http.MethodGet, "/admin/mdm/devices", nil), adminID, 0)
	rec := httptest.NewRecorder()
	h.ListDevices(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("global ListDevices over the constrained setjoin_app pool: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var list struct {
		Devices []struct {
			DeviceID uuid.UUID `json:"device_id"`
		} `json:"devices"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode constrained list: %v", err)
	}
	sawA, sawB := false, false
	for _, d := range list.Devices {
		switch d.DeviceID {
		case deviceA:
			sawA = true
		case deviceB:
			sawB = true
		}
	}
	if !sawA || !sawB {
		t.Fatalf("MDM list over the constrained setjoin_app pool must serve both seeded devices (sawA=%v sawB=%v, total=%d) — a missing RunUserScoped GUC pairing (r1 item 2a) yields a silent empty list under FORCE", sawA, sawB, len(list.Devices))
	}

	// ── domain-scoped list over the constrained pool: only same-domain A.
	req = adminClaimsCtx(httptest.NewRequest(http.MethodGet, "/admin/mdm/devices", nil), adminID, domA)
	rec = httptest.NewRecorder()
	h.ListDevices(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("scoped ListDevices over the constrained pool: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	list.Devices = nil
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode scoped list: %v", err)
	}
	sawA, sawB = false, false
	for _, d := range list.Devices {
		switch d.DeviceID {
		case deviceA:
			sawA = true
		case deviceB:
			sawB = true
		}
	}
	if !sawA || sawB {
		t.Fatalf("scoped list over the constrained pool must see only same-domain device A (sawA=%v sawB=%v)", sawA, sawB)
	}

	// ── get, same domain: 200 with the seeded owner — the single-device read
	// resolves through the admin GUC arm under FORCE.
	req = adminClaimsCtx(httptest.NewRequest(http.MethodGet, "/admin/mdm/devices/"+deviceA.String(), nil), adminID, domA)
	req.SetPathValue("device_id", deviceA.String())
	rec = httptest.NewRecorder()
	h.GetDevice(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("same-domain GetDevice over the constrained pool: want 200, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		DeviceID uuid.UUID `json:"device_id"`
		UserID   int64     `json:"user_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode constrained get: %v", err)
	}
	if body.DeviceID != deviceA || body.UserID != userA {
		t.Errorf("constrained get returned device %d owner %d, want device %s owner %d", body.DeviceID, body.UserID, deviceA, userA)
	}

	// ── get, cross domain: 404 — the scope predicate in the SAME statement
	// keeps the out-of-scope device indistinguishable from missing under FORCE.
	req = adminClaimsCtx(httptest.NewRequest(http.MethodGet, "/admin/mdm/devices/"+deviceB.String(), nil), adminID, domA)
	req.SetPathValue("device_id", deviceB.String())
	rec = httptest.NewRecorder()
	h.GetDevice(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cross-domain GetDevice over the constrained pool: want 404, got %d (body=%s)", rec.Code, rec.Body.String())
	}
}
