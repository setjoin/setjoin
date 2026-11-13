package handlers

// ER5 er5-s08 occurrence test (resource-exhaustion/unbounded-preauth-json-body):
// the refresh completion leg — POST /auth/refresh decodes its body through the
// shared bounded ingress, so an oversized body is refused 400 BEFORE any JSON
// decode parks it in memory.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRefresh_OversizedBodyRefused(t *testing.T) {
	h := &sessionHandler{}
	huge := `{"refresh_token":"` + strings.Repeat("x", int(authJSONBodyLimit)+1) + `"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", strings.NewReader(huge))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.Refresh(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("oversized refresh body: got %d, want 400 (bounded ingress)", rr.Code)
	}
	if strings.Contains(rr.Body.String(), "invalid or revoked refresh token") {
		t.Fatal("oversized body must be refused at the ingress, never decoded")
	}
}

func TestRefresh_MalformedJSONRefused(t *testing.T) {
	h := &sessionHandler{}
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", bytes.NewReader([]byte("{not json")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.Refresh(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("malformed refresh JSON: got %d, want 400", rr.Code)
	}
}
