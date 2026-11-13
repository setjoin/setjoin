package downloads

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleDownloadsPage_ReturnsPlatforms(t *testing.T) {
	handler := HandleDownloadsPage()

	req := httptest.NewRequest(http.MethodGet, "/downloads", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}

	contentType := rec.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("expected application/json, got %s", contentType)
	}

	var resp struct {
		Platforms []Platform        `json:"platforms"`
		Versions  map[string]string `json:"versions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if len(resp.Platforms) == 0 {
		t.Error("expected non-empty platforms list")
	}

	// The gateway pins no versions; the map is present but empty.
	if len(resp.Versions) != 0 {
		t.Errorf("expected empty versions map, got %v", resp.Versions)
	}

	// Verify each platform has required fields.
	for _, p := range resp.Platforms {
		if p.Name == "" {
			t.Error("platform has empty name")
		}
		if p.Slug == "" {
			t.Error("platform has empty slug")
		}
		if p.Ext == "" && p.StoreURL == "" {
			t.Error("platform must have ext or store_url")
		}
	}
}

func TestHandleDownloadsPage_MethodNotAllowed(t *testing.T) {
	handler := HandleDownloadsPage()

	req := httptest.NewRequest(http.MethodPost, "/downloads", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for POST, got %d", rec.Code)
	}
}

func TestHandleDownloadAsset_Redirects(t *testing.T) {
	handler := HandleDownloadAsset()

	req := httptest.NewRequest(http.MethodGet, "/downloads/macos-arm64", nil)
	req.SetPathValue("platform", "macos-arm64")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// Should redirect (302) to the download URL.
	if rec.Code != http.StatusFound {
		t.Errorf("expected 302 redirect, got %d", rec.Code)
	}

	location := rec.Header().Get("Location")
	if location == "" {
		t.Fatal("expected Location header")
	}
	// No per-platform version is pinned, so the asset carries the "latest"
	// segment the mirror resolves.
	if !contains(location, "latest") {
		t.Errorf("expected redirect to contain \"latest\", got %s", location)
	}
	if !contains(location, "macos-arm64") {
		t.Errorf("expected redirect to contain platform slug, got %s", location)
	}
}

func TestHandleDownloadAsset_UnknownPlatform(t *testing.T) {
	handler := HandleDownloadAsset()

	req := httptest.NewRequest(http.MethodGet, "/downloads/unknown-platform", nil)
	req.SetPathValue("platform", "unknown-platform")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("expected 404 for unknown platform, got %d", rec.Code)
	}
}

func TestPlatforms_AllHaveUniqueSlugs(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range DesktopPlatforms {
		if seen[p.Slug] {
			t.Errorf("duplicate slug: %s", p.Slug)
		}
		seen[p.Slug] = true
	}
}

func TestPlatforms_CoversMajorOS(t *testing.T) {
	slugs := map[string]bool{}
	for _, p := range DesktopPlatforms {
		slugs[p.Slug] = true
	}

	// At minimum, we should have macOS, Windows, and Linux.
	if !(slugs["macos-arm64"] || slugs["macos-x86_64"]) {
		t.Error("missing macOS platform")
	}
	if !slugs["windows-x86_64"] {
		t.Error("missing Windows platform")
	}
	if !slugs["linux-x86_64"] {
		t.Error("missing Linux platform")
	}
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
