package admin

// Durable-evidence test for the mounted POST /admin/mdm/devices/{device_id}/wipe
// route handler (med-shard3-014): arming a wipe is reducer-authoritative
// (mdm_device_wipe_arm), so after the 202 the evidence must exist IN THE
// DATABASE — a core-tier admin_audit_log row carrying the authenticated admin's
// identity (R1/R2: identity from the auth context, never the request body) and
// a durable device_events lifecycle row (parity with MAM lock/unlock) — not
// just an ephemeral slog line.
//
// Reuses the shared admin harness: mailboxTestPool, mailboxTestLogger,
// ensureScopeTestDomain, createScopeTestUser, adminClaimsCtx, stringReader,
// seedMDMScopeDevice (admin_mdm_scope_test.go).

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// wipeEvidenceTestActor is this test's fixed audit actor id. admin_audit_log is
// append-only (BZ017 on UPDATE/DELETE), so audit rows cannot be deleted; the
// unique actor id scopes both the assertions and the leftover rows (the same
// convention admin_ad_principal_reducer_test.go uses).
const wipeEvidenceTestActor = int64(776411)

// TestMDMWipe_DurableEvidenceAfterMountedPOST drives the TriggerWipe handler
// exactly as the mounted route would (claims + domain scope in context) and
// proves the durable evidence contract:
//  1. the audit row records the CONTEXT identity and the armed device;
//  2. the device_events row is queryable with lock/unlock-grade fields;
//  3. a rejected (conflicting) arm writes no partial evidence.
func TestMDMWipe_DurableEvidenceAfterMountedPOST(t *testing.T) {
	pool := mailboxTestPool(t)
	h := NewMDMHandler(pool, mailboxTestLogger())

	dom := ensureScopeTestDomain(t, pool, "mdm-wipe-evidence.scope.test")
	user := createScopeTestUser(t, pool, dom, "mdm-wipe-evidence.scope.test")
	device := seedMDMScopeDevice(t, pool, user, "none", "")

	// Cleanup the cleanable evidence first (registered BEFORE any fixture
	// teardown that cascades): device_events rows carry no FK cascade, so they
	// outlive the user deletion. mdm_device_state rides the user cascade; the
	// append-only audit row stays, scoped to the unique actor id above.
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(),
			`DELETE FROM device_events
			  WHERE event_type = 'wipe_requested' AND details->>'mdm_device_id' = $1`,
			device.String())
	})

	post := func(level string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost,
			"/admin/mdm/devices/"+device.String()+"/wipe", stringReader(`{"level":"`+level+`"}`))
		req = adminClaimsCtx(req, wipeEvidenceTestActor, dom)
		req.SetPathValue("device_id", device.String())
		rec := httptest.NewRecorder()
		h.TriggerWipe(rec, req)
		return rec
	}

	// Arm through the mounted handler: 202.
	rec := post("account")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("mounted wipe POST: want 202, got %d (body=%s)", rec.Code, rec.Body.String())
	}

	// Durable audit evidence: actor identity comes from the AUTH CONTEXT
	// (adminClaimsCtx), the row names the device and the armed level. The row
	// is keyed by the device uuid (unique per run) because admin_audit_log is
	// append-only across runs.
	var (
		gotTarget string
		gotActor  int64
		gotAfter  []byte
	)
	if err := pool.QueryRow(context.Background(),
		`SELECT target_type, user_id, after_state FROM admin_audit_log
		  WHERE action = 'mdm_device_wipe_arm' AND notes = $1
		  ORDER BY id DESC LIMIT 1`, device.String(),
	).Scan(&gotTarget, &gotActor, &gotAfter); err != nil {
		t.Fatalf("durable audit row missing after mounted POST: %v", err)
	}
	if gotTarget != "mdm_device" {
		t.Errorf("audit target_type = %q, want mdm_device", gotTarget)
	}
	if gotActor != wipeEvidenceTestActor {
		t.Errorf("audit user_id = %d, want the authenticated admin %d (identity per R1/R2)",
			gotActor, wipeEvidenceTestActor)
	}
	var after map[string]any
	if err := json.Unmarshal(gotAfter, &after); err != nil {
		t.Fatalf("decode audit after_state: %v", err)
	}
	if after["device_id"] != device.String() || after["wipe_level"] != "account" || after["wipe_requested"] != "pending" {
		t.Errorf("audit after_state = %v, want device %s armed at level account/pending", after, device)
	}

	// Durable device_events evidence (lock/unlock parity): one queryable
	// lifecycle row for this device, severity critical.
	var (
		evSeverity string
		evDeviceID any
		evLevel    string
	)
	if err := pool.QueryRow(context.Background(),
		`SELECT severity, device_id, details->>'wipe_level' FROM device_events
		  WHERE event_type = 'wipe_requested' AND details->>'mdm_device_id' = $1`,
		device.String(),
	).Scan(&evSeverity, &evDeviceID, &evLevel); err != nil {
		t.Fatalf("durable device_events row missing after mounted POST: %v", err)
	}
	if evSeverity != "critical" || evLevel != "account" {
		t.Errorf("device_events row = (severity=%s level=%s), want critical/account", evSeverity, evLevel)
	}
	if evDeviceID != nil {
		t.Errorf("device_events.device_id = %v, want NULL (FK-honest: an MDM uuid has no canonical devices.id)", evDeviceID)
	}

	// Rejected arm (same device, different level → conflict): the handler
	// answers 409 and writes NO partial evidence.
	rec = post("device")
	if rec.Code != http.StatusConflict {
		t.Fatalf("conflicting mounted wipe POST: want 409, got %d (body=%s)", rec.Code, rec.Body.String())
	}
	var auditRows, eventRows int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM admin_audit_log
		  WHERE action = 'mdm_device_wipe_arm' AND notes = $1`, device.String(),
	).Scan(&auditRows); err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM device_events
		  WHERE event_type = 'wipe_requested' AND details->>'mdm_device_id' = $1`,
		device.String(),
	).Scan(&eventRows); err != nil {
		t.Fatalf("count device_events rows: %v", err)
	}
	if auditRows != 1 || eventRows != 1 {
		t.Errorf("rejected arm wrote partial evidence: audit=%d events=%d, want exactly 1/1", auditRows, eventRows)
	}
}
