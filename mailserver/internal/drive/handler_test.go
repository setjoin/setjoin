package drive_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/mailserver/internal/drive"
	"setjoin.com/shared/toggle"
)

func TestRoutes404WhenDriveOff(t *testing.T) { // G5 + acceptance §12-9
	h := drive.NewHandler(nil, nil, nil, "", toggle.NewTestFlags(map[string]bool{"feature.drive": false}), slog.Default())
	for _, tc := range []struct{ method, path string }{
		{"GET", "/drive/spaces"}, {"POST", "/drive/spaces"},
		{"GET", "/drive/changes?space=1&since=0"},
		{"POST", "/drive/nodes"}, {"GET", "/drive/spaces/1/tree"},
		{"GET", "/drive/nodes?ids=1,2"},
		{"GET", "/drive/versions/1/preview"},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 7}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("%s %s: want 404 while feature.drive OFF, got %d", tc.method, tc.path, rr.Code)
		}
	}
}

func TestRoutesRequireAuthClaims(t *testing.T) {
	h := drive.NewHandler(nil, nil, nil, "", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), slog.Default())
	req := httptest.NewRequest("GET", "/drive/spaces", nil) // no claims
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("want 401 without claims, got %d", rr.Code)
	}
}

// TestPatchSpaceRejectsInvalidJSON pins the pool-less bad-request path (no DB
// call reached): decode failure short-circuits before RunUserScoped.
func TestPatchSpaceRejectsInvalidJSON(t *testing.T) {
	h := drive.NewHandler(nil, nil, nil, "", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), slog.Default())
	req := httptest.NewRequest("PATCH", "/drive/spaces/1", strings.NewReader("{not json"))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 7}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400 for invalid JSON, got %d: %s", rr.Code, rr.Body.String())
	}
}

// TestPatchSpaceRejectsBadSpaceID pins the pool-less path-param validation
// (no DB call reached): a non-numeric {id} 400s before RunUserScoped.
func TestPatchSpaceRejectsBadSpaceID(t *testing.T) {
	h := drive.NewHandler(nil, nil, nil, "", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), slog.Default())
	req := httptest.NewRequest("PATCH", "/drive/spaces/not-a-number", strings.NewReader(`{"classification":"secure"}`))
	req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 7}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("want 400 for a non-numeric space id, got %d", rr.Code)
	}
}

// TestChangesRequiresSpaceAndSince pins the pool-less query-param validation.
func TestChangesRequiresSpaceAndSince(t *testing.T) {
	h := drive.NewHandler(nil, nil, nil, "", toggle.NewTestFlags(map[string]bool{"feature.drive": true}), slog.Default())
	for _, path := range []string{"/drive/changes", "/drive/changes?space=1", "/drive/changes?since=0"} {
		req := httptest.NewRequest("GET", path, nil)
		req = req.WithContext(auth.ContextWithUser(req.Context(), &auth.Claims{UserID: 7}))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", path, rr.Code)
		}
	}
}
