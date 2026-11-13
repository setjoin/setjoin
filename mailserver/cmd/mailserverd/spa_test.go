package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestSPAHandler(t *testing.T) {
	// Setup temp webmail directory
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "index.html"), []byte("<html>SPA</html>"), 0644)
	os.MkdirAll(filepath.Join(root, "_app", "immutable"), 0755)
	os.WriteFile(filepath.Join(root, "_app", "immutable", "test.js"), []byte("console.log('hi')"), 0644)
	// The vendored-asset shape that shadowed the /meet SPA route (B1 gate):
	// a real static subdirectory whose name collides with an app route.
	os.MkdirAll(filepath.Join(root, "meet", "mediapipe"), 0755)
	os.WriteFile(filepath.Join(root, "meet", "mediapipe", "model.tflite"), []byte("tflite-bytes"), 0644)
	writeStaticTestManifest(t, root, "spa-test", nil)

	spaHandler, err := newSPAStaticHandler(root, nil)
	if err != nil {
		t.Fatalf("newSPAStaticHandler: %v", err)
	}

	tests := []struct {
		name            string
		path            string
		wantStatus      int
		wantBody        string
		wantContentType string
	}{
		{"root serves index.html", "/", 200, "<html>SPA</html>", "text/html; charset=utf-8"},
		{"spa route serves index.html", "/inbox", 200, "<html>SPA</html>", "text/html; charset=utf-8"},
		{"spa route serves index.html", "/settings", 200, "<html>SPA</html>", "text/html; charset=utf-8"},
		{"existing JS file served directly", "/_app/immutable/test.js", 200, "console.log('hi')", "text/javascript; charset=utf-8"},
		{"missing JS asset NOT index.html", "/_app/immutable/missing.js", 404, "", ""},
		{"missing favicon NOT index.html", "/favicon.ico", 404, "", ""},
		{"static dir must NOT shadow the SPA route", "/meet", 200, "<html>SPA</html>", "text/html; charset=utf-8"},
		{"file inside the static dir still served", "/meet/mediapipe/model.tflite", 200, "tflite-bytes", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			r := httptest.NewRequest("GET", tt.path, nil)

			spaHandler.ServeHTTP(w, r)

			if w.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", w.Code, tt.wantStatus)
			}
			if tt.wantBody != "" && w.Body.String() != tt.wantBody {
				t.Errorf("body = %q, want %q", w.Body.String(), tt.wantBody)
			}
			if tt.wantContentType != "" && w.Header().Get("Content-Type") != tt.wantContentType {
				t.Errorf("Content-Type = %q, want %q", w.Header().Get("Content-Type"), tt.wantContentType)
			}
		})
	}
}

func TestIsAssetPath(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/_app/immutable/chunk.js", true},
		{"/_app/", true},
		{"/favicon.ico", true},
		{"/", false},
		{"/inbox", false},
		{"/settings", false},
		{"/jmap", false},
		{"/auth/login", false},
		{"/auth/guest-invite/accept", false},
	}
	for _, tt := range tests {
		got := isAssetPath(tt.path)
		if got != tt.want {
			t.Errorf("isAssetPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestHTTPSRedirectUsesConfiguredHostname(t *testing.T) {
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://evil.invalid/inbox?q=1", nil)
	req.Host = "evil.invalid"
	httpsRedirectHandler("mail.example.com").ServeHTTP(rr, req)

	if rr.Code != http.StatusMovedPermanently {
		t.Fatalf("status=%d want %d", rr.Code, http.StatusMovedPermanently)
	}
	if got := rr.Header().Get("Location"); got != "https://mail.example.com/inbox?q=1" {
		t.Fatalf("Location=%q want canonical configured host", got)
	}
}

// ─── needsSetup tests ─────────────────────────────────────────────────────

// mockRow implements pgx.Row for testing.
type mockRow struct {
	scanFunc func(dest ...any) error
}

func (m *mockRow) Scan(dest ...any) error {
	if m.scanFunc != nil {
		return m.scanFunc(dest...)
	}
	return nil
}

// mockQueryRower implements queryRower for testing.
type mockQueryRower struct {
	row pgx.Row
}

func (m *mockQueryRower) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return m.row
}

func TestNeedsSetup_NoUsers(t *testing.T) {
	q := &mockQueryRower{
		row: &mockRow{
			scanFunc: func(dest ...any) error {
				*(dest[0].(*int)) = 0
				return nil
			},
		},
	}
	if !needsSetup(context.Background(), q) {
		t.Error("needsSetup should return true when user count is 0")
	}
}

func TestNeedsSetup_HasUsers(t *testing.T) {
	q := &mockQueryRower{
		row: &mockRow{
			scanFunc: func(dest ...any) error {
				*(dest[0].(*int)) = 5
				return nil
			},
		},
	}
	if needsSetup(context.Background(), q) {
		t.Error("needsSetup should return false when users exist")
	}
}

func TestNeedsSetup_DBError(t *testing.T) {
	q := &mockQueryRower{
		row: &mockRow{
			scanFunc: func(dest ...any) error {
				return errors.New("connection refused")
			},
		},
	}
	if needsSetup(context.Background(), q) {
		t.Error("needsSetup should return false on DB error (fail open)")
	}
}
