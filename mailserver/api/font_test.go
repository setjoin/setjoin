package apispec

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// TestHandleFontServesWoff2 asserts the font handler returns the embedded woff2
// bytes with the correct content type for the 400 (body) path. The brand font
// must be served same-origin (the gateway CSP is `font-src 'self'`), so the
// handler — not a CDN — is the source of truth for the Redoc page's font.
func TestHandleFontServesWoff2(t *testing.T) {
	req := httptest.NewRequest("GET", "/api/fonts/ibm-plex-sans-400.woff2", nil)
	rec := httptest.NewRecorder()
	HandleFont(rec, req)

	res := rec.Result()
	if res.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); ct != "font/woff2" {
		t.Errorf("Content-Type = %q, want font/woff2", ct)
	}
	if rec.Body.Len() == 0 {
		t.Error("font body is empty")
	}
}

// TestRedocHTMLHasSameOriginFontFace asserts the Redoc page declares an
// @font-face for IBM Plex Sans pointing at a same-origin /api/fonts/ URL — so the
// brand font actually loads under the gateway's `font-src 'self'` CSP instead of
// silently degrading to system-ui.
func TestRedocHTMLHasSameOriginFontFace(t *testing.T) {
	if !strings.Contains(redocHTML, "@font-face") {
		t.Fatal("redocHTML has no @font-face block")
	}
	if !strings.Contains(redocHTML, "IBM Plex Sans") {
		t.Error("redocHTML @font-face does not reference the IBM Plex Sans family")
	}
	if !strings.Contains(redocHTML, "/api/fonts/ibm-plex-sans-400.woff2") {
		t.Error("redocHTML does not reference the same-origin /api/fonts/ 400 woff2 URL")
	}
}
