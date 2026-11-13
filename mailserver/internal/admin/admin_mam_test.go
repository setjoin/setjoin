package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
)

// MAM handler-level permission tests were removed: enforcement moved to the
// audited route middleware and is proven in admin_mam_perms_test.go. These
// tests now assert the handlers assume an authorized caller and proceed to
// their non-auth guards (bad-id 400). A nil pool would panic, so we exercise
// the paths that return before touching the pool.

// TestMAMHandler_GetDeviceEvents_ReachesHandlerAfterAuthz proves the handler no
// longer decides permission: an authorized caller reaches the body, where an
// invalid device_id is rejected with 400 (before any pool use).
func TestMAMHandler_GetDeviceEvents_ReachesHandlerAfterAuthz(t *testing.T) {
	handler := NewMAMHandler(nil, nil)
	req := httptest.NewRequest("GET", "/admin/mam/devices/abc/events", nil)
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1, Permissions: []string{permissions.PermMAMRead}})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.GetDeviceEvents(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 (handler reached, invalid device_id), got %d", w.Code)
	}
}

// TestMAMHandler_LockDevice_ReachesHandlerAfterAuthz: invalid device_id is
// rejected with 400 inside the handler — proving authz is no longer decided
// here.
func TestMAMHandler_LockDevice_ReachesHandlerAfterAuthz(t *testing.T) {
	handler := NewMAMHandler(nil, nil)
	req := httptest.NewRequest("POST", "/admin/mam/devices/not-a-number/lock", nil)
	req.SetPathValue("device_id", "not-a-number")
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1, Permissions: []string{permissions.PermMAMWrite}})
	req = req.WithContext(ctx)
	w := httptest.NewRecorder()

	handler.LockDevice(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("want 400 (handler reached, invalid device_id), got %d", w.Code)
	}
}

func TestMAMHandler_GetDeviceEvents_BadID(t *testing.T) {
	handler := NewMAMHandler(nil, nil)
	req := httptest.NewRequest("GET", "/admin/mam/devices/abc/events", nil)
	w := httptest.NewRecorder()

	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1, Permissions: []string{permissions.PermMAMRead}})
	req = req.WithContext(ctx)

	handler.GetDeviceEvents(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid device_id, got %d", w.Code)
	}
}
