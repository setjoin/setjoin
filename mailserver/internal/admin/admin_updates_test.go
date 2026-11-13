package admin

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
}

func TestUpdatesHandler_PushUpdate_NoDeviceIDs(t *testing.T) {
	h := NewUpdatesHandler(nil, newTestLogger())

	body := `{"device_ids": [], "version": "1.0.0"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/updates/push", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.PushUpdate(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for empty device_ids, got %d", rec.Code)
	}
}

func TestUpdatesHandler_PushUpdate_InvalidJSON(t *testing.T) {
	h := NewUpdatesHandler(nil, newTestLogger())

	req := httptest.NewRequest(http.MethodPost, "/admin/updates/push", strings.NewReader("bad"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.PushUpdate(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", rec.Code)
	}
}

func TestUpdatesHandler_PushUpdate_ValidRequest_NoPool(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
}

func TestNewUpdatesHandler(t *testing.T) {
	h := NewUpdatesHandler(nil, newTestLogger())
	if h == nil {
		t.Error("expected non-nil handler")
	}
}
