package admin

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/permissions"
)

func TestNewMDMHandler(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	h := NewMDMHandler(nil, logger)
	if h == nil {
		t.Fatal("NewMDMHandler returned nil")
	}
}

// TestMDMHandler_ListDevices_NilPoolAfterAuthz proves the handler no longer
// decides permission: a caller is assumed authorized (authz lives at the
// route middleware now) and reaches the handler body, where the nil pool
// yields 500. Handler-level _NonAdmin/_Unauthenticated tests were removed —
// that enforcement moved to admin_mdm_perms_test.go.
func TestMDMHandler_ListDevices_NilPoolAfterAuthz(t *testing.T) {
	h := NewMDMHandler(nil, slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil)))
	req := httptest.NewRequest("GET", "/admin/mdm/devices", nil)
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1, Permissions: []string{permissions.PermMAMRead}})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	h.ListDevices(rec, req) // handler assumes authz; nil pool -> 500
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("want 500 (handler reached, nil pool), got %d", rec.Code)
	}
}

func TestMDMHandler_CreatePolicy_InvalidJSON(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	h := NewMDMHandler(nil, logger)

	req := httptest.NewRequest("POST", "/admin/mdm/policies", bytes.NewReader([]byte(`not json`)))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1, IsAdmin: true})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	h.CreatePolicy(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", rec.Code)
	}
}

func TestMDMHandler_CreatePolicy_ValidationErrors(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	h := NewMDMHandler(nil, logger)

	tests := []struct {
		name string
		body string
	}{
		{"empty name", `{"name":""}`},
		{"invalid scope type", `{"name":"test","scope_type":"invalid"}`},
		{"invalid passcode complexity", `{"name":"test","passcode_complexity":"invalid"}`},
		{"invalid jailbreak action", `{"name":"test","jailbreak_action":"brick"}`},
		{"negative passcode min length", `{"name":"test","passcode_min_length":-1}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/admin/mdm/policies", bytes.NewReader([]byte(tt.body)))
			ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1, IsAdmin: true})
			req = req.WithContext(ctx)
			rec := httptest.NewRecorder()
			h.CreatePolicy(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("expected 400 for %s, got %d", tt.name, rec.Code)
			}
		})
	}
}

func TestMDMHandler_TriggerWipe_InvalidLevel(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	h := NewMDMHandler(nil, logger)

	body := `{"level":"nuke"}`
	req := httptest.NewRequest("POST", "/admin/mdm/devices/00000000-0000-0000-0000-000000000001/wipe", bytes.NewReader([]byte(body)))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1, IsAdmin: true})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	h.TriggerWipe(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid wipe level, got %d", rec.Code)
	}
}

func TestMDMHandler_TriggerWipe_InvalidDeviceID(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	h := NewMDMHandler(nil, logger)

	body := `{"level":"account"}`
	req := httptest.NewRequest("POST", "/admin/mdm/devices/not-a-uuid/wipe", bytes.NewReader([]byte(body)))
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1, IsAdmin: true})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	h.TriggerWipe(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid device ID, got %d", rec.Code)
	}
}

func TestMDMHandler_DeletePolicy_NilPool(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	h := NewMDMHandler(nil, logger)

	req := httptest.NewRequest("DELETE", "/admin/mdm/policies/1", nil)
	req.SetPathValue("id", "1")
	ctx := auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 1, IsAdmin: true})
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	h.DeletePolicy(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Errorf("expected 500 with nil pool, got %d", rec.Code)
	}
}
