package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"setjoin.com/shared/testsupport"
)

// TestWipeDevice_DBWritesStateAndAudit is the DB-backed proof that triggering a
// remote device wipe (POST /admin/offline/devices/{id}/wipe → offline_device_revoke)
// (a) flips user_devices.wipe_requested true AND (b) writes EXACTLY ONE
// admin_audit_log row (action=offline_device_revoke, actor=admin, target=device).
// Idempotency: a second wipe on the now-revoked device is rejected (409 BZ100)
// and writes NO additional audit row — the wipe intent is not re-applied.
func TestWipeDevice_DBWritesStateAndAudit(t *testing.T) {
	pool := testsupport.OpenTestPool(t)
	h := NewOfflineHandler(pool, testsupport.TestLogger())
	ctx := context.Background()

	// Owner account (user + primary mailbox — the reducer's offline.wipe push
	// targets the owner's mailbox tag, so a real mailbox is required) + a
	// separate admin actor account (audit_write FK needs a real users row).
	var ownerMB, ownerUser, adminMB, adminUser int64
	mustScan(t, pool.QueryRow(ctx, `SELECT mk_account('wipedb_owner')`).Scan(&ownerMB))
	mustScan(t, pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, ownerMB).Scan(&ownerUser))
	mustScan(t, pool.QueryRow(ctx, `SELECT mk_account('wipedb_admin')`).Scan(&adminMB))
	mustScan(t, pool.QueryRow(ctx, `SELECT user_id FROM mailboxes WHERE id=$1`, adminMB).Scan(&adminUser))

	// Approved offline device owned by the owner — the only state from which a
	// wipe (revoke) transition is legal.
	var deviceID int64
	mustScan(t, pool.QueryRow(ctx, `SELECT mk_offline_device($1,'approved')`, ownerMB).Scan(&deviceID))

	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM admin_audit_log WHERE target_type='user_device' AND target_id=$1`, deviceID)
		_, _ = pool.Exec(ctx, `DELETE FROM user_devices WHERE id=$1`, deviceID)
		_, _ = pool.Exec(ctx, `DELETE FROM mailboxes WHERE id IN ($1,$2)`, ownerMB, adminMB) // cascades folders/tags
		_, _ = pool.Exec(ctx, `DELETE FROM users WHERE id IN ($1,$2)`, ownerUser, adminUser)
	})

	idStr := strconv.FormatInt(deviceID, 10)

	// ── Trigger the wipe ──────────────────────────────────────────────────────
	req := httptest.NewRequest(http.MethodPost, "/admin/offline/devices/"+idStr+"/wipe", nil)
	req.SetPathValue("id", idStr)
	req = withAdminClaims(req, adminUser)
	rec := httptest.NewRecorder()
	h.WipeDevice(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("WipeDevice: code=%d, want 202; body=%s", rec.Code, rec.Body.String())
	}

	// ── (a) state flipped on the actual row ───────────────────────────────────
	var wipeRequested bool
	var wipeType, approval string
	mustScan(t, pool.QueryRow(ctx,
		`SELECT wipe_requested, COALESCE(wipe_type,''), offline_approval FROM user_devices WHERE id=$1`,
		deviceID).Scan(&wipeRequested, &wipeType, &approval))
	if !wipeRequested {
		t.Errorf("user_devices.wipe_requested = false, want true")
	}
	if wipeType != "selective" {
		t.Errorf("user_devices.wipe_type = %q, want %q", wipeType, "selective")
	}
	if approval != "revoked" {
		t.Errorf("user_devices.offline_approval = %q, want %q", approval, "revoked")
	}

	// ── (b) exactly one audit row, with the right action/actor/target ─────────
	var n int
	mustScan(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_audit_log WHERE target_type='user_device' AND target_id=$1`,
		deviceID).Scan(&n))
	if n != 1 {
		t.Fatalf("admin_audit_log rows for device = %d, want exactly 1", n)
	}
	var action, targetType string
	var actor, targetID int64
	mustScan(t, pool.QueryRow(ctx,
		`SELECT action, user_id, target_type, target_id FROM admin_audit_log
		   WHERE target_type='user_device' AND target_id=$1`,
		deviceID).Scan(&action, &actor, &targetType, &targetID))
	if action != "offline_device_revoke" {
		t.Errorf("audit action = %q, want %q", action, "offline_device_revoke")
	}
	if actor != adminUser {
		t.Errorf("audit user_id (actor) = %d, want %d (admin)", actor, adminUser)
	}
	if targetType != "user_device" {
		t.Errorf("audit target_type = %q, want %q", targetType, "user_device")
	}
	if targetID != deviceID {
		t.Errorf("audit target_id = %d, want %d (device)", targetID, deviceID)
	}

	// ── idempotency: re-wiping an already-revoked device is rejected and does ──
	// NOT write a second audit row.
	req2 := httptest.NewRequest(http.MethodPost, "/admin/offline/devices/"+idStr+"/wipe", nil)
	req2.SetPathValue("id", idStr)
	req2 = withAdminClaims(req2, adminUser)
	rec2 := httptest.NewRecorder()
	h.WipeDevice(rec2, req2)
	if rec2.Code != http.StatusConflict {
		t.Fatalf("second WipeDevice (idempotency): code=%d, want 409; body=%s", rec2.Code, rec2.Body.String())
	}
	var n2 int
	mustScan(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM admin_audit_log WHERE target_type='user_device' AND target_id=$1`,
		deviceID).Scan(&n2))
	if n2 != 1 {
		t.Errorf("admin_audit_log rows after re-wipe = %d, want still 1 (no double-write)", n2)
	}
}

func mustScan(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("db setup/query failed: %v", err)
	}
}
