package telemetry

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleTelemetry_ValidPayload(t *testing.T) {
	store := &fakeStore{}
	handler := HandleTelemetry(store, func() bool { return true }, acceptAnyDevice)

	body := map[string]any{
		"device_id":    42,
		"app_version":  "1.2.3",
		"os_version":   "iOS 18.1",
		"crash_count":  0,
		"uptime_hours": 120,
		"feature_usage": map[string]any{
			"mail":     42,
			"calendar": 3,
		},
	}
	payload, _ := json.Marshal(body)

	req := httptest.NewRequest(http.MethodPost, "/telemetry", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}

	if !store.called {
		t.Error("expected store to be called")
	}
	if store.recorded.DeviceID != 42 {
		t.Errorf("expected device_id 42, got %d", store.recorded.DeviceID)
	}
	if store.recorded.AppVersion != "1.2.3" {
		t.Errorf("expected app_version 1.2.3, got %s", store.recorded.AppVersion)
	}
}

func TestHandleTelemetry_Disabled(t *testing.T) {
	store := &fakeStore{}
	handler := HandleTelemetry(store, func() bool { return false }, acceptAnyDevice)

	req := httptest.NewRequest(http.MethodPost, "/telemetry", bytes.NewReader([]byte(`{"device_id":1}`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("expected 204 even when disabled, got %d", rec.Code)
	}
	if store.called {
		t.Error("expected store NOT to be called when telemetry is disabled")
	}
}

func TestHandleTelemetry_InvalidJSON(t *testing.T) {
	store := &fakeStore{}
	handler := HandleTelemetry(store, func() bool { return true }, acceptAnyDevice)

	req := httptest.NewRequest(http.MethodPost, "/telemetry", bytes.NewReader([]byte(`not json`)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", rec.Code)
	}
}

func TestHandleTelemetry_MissingDeviceID(t *testing.T) {
	store := &fakeStore{}
	handler := HandleTelemetry(store, func() bool { return true }, acceptAnyDevice)

	body := `{"app_version": "1.0"}`
	req := httptest.NewRequest(http.MethodPost, "/telemetry", bytes.NewReader([]byte(body)))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing device_id, got %d", rec.Code)
	}
}

func TestHandleTelemetry_MethodNotAllowed(t *testing.T) {
	store := &fakeStore{}
	handler := HandleTelemetry(store, func() bool { return true }, acceptAnyDevice)

	req := httptest.NewRequest(http.MethodGet, "/telemetry", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", rec.Code)
	}
}

func TestHandleTelemetry_DynamicToggle(t *testing.T) {
	// isEnabled is called per-request, so a mid-run toggle flip takes effect
	// without a restart. Verify the closure is re-evaluated each call.
	store := &fakeStore{}
	enabled := true
	handler := HandleTelemetry(store, func() bool { return enabled }, acceptAnyDevice)

	body := []byte(`{"device_id":7}`)

	req := httptest.NewRequest(http.MethodPost, "/telemetry", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if !store.called {
		t.Error("expected store called when enabled=true")
	}

	store.called = false
	enabled = false
	req2 := httptest.NewRequest(http.MethodPost, "/telemetry", bytes.NewReader(body))
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if store.called {
		t.Error("expected store NOT called after toggle disabled")
	}
}

// ── fake store ─────────────────────────────────────────────────────────────

type fakeStore struct {
	called   bool
	recorded TelemetryRecord
}

func (f *fakeStore) Insert(ctx context.Context, r TelemetryRecord) error {
	f.called = true
	f.recorded = r
	return nil
}
