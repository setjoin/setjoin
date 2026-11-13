package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSCIMDisable_UserNotFound(t *testing.T) {
	t.Skip("requires database")

	h := &SCIMDisableHandler{Pool: nil}
	body, _ := json.Marshal(map[string]string{"external_id": "nonexistent"})
	req := httptest.NewRequest("POST", "/auth/scim/disable", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
}

func TestSCIMDisable_MissingExternalID(t *testing.T) {
	h := &SCIMDisableHandler{Pool: nil}
	req := httptest.NewRequest("POST", "/auth/scim/disable", bytes.NewReader([]byte(`{}`)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rec.Code)
	}
}
