package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Drive P3 (spec §8.2, locked minimal — batch-1 #1): the gateway CSP header
// gains ONLY media-src's loopback token — the in-app SecureViewer streams
// native AV from the ticketed 127.0.0.1 render server. Every other directive
// (script-src especially — the M9 hash-lockdown lives in the SvelteKit meta
// CSP, not here) must stay unchanged.
func TestSecurityHeadersDriveLoopbackCSPDelta(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Fatal("no Content-Security-Policy header set")
	}
	if !strings.Contains(csp, "media-src 'self' blob: http://127.0.0.1:*;") {
		t.Errorf("media-src must gain the Drive P3 loopback token, got: %s", csp)
	}
	if !strings.Contains(csp, "frame-src 'self'") {
		t.Errorf("frame-src must be unchanged, got: %s", csp)
	}
	if strings.Contains(csp, "script-src 'self' 'unsafe-inline' http://127.0.0.1") {
		t.Errorf("script-src must NOT gain the loopback (media-src only), got: %s", csp)
	}
}

// A4: img-src omitted https: entirely, so the trusted-sender / "load images"
// remote-image opt-in (sanitize.ts's allowRemoteImages) let an <img src="https://…">
// survive DOMPurify but the browser's own CSP enforcement still dropped the
// fetch — the opt-in was dead regardless of user consent. Fix must add https:
// to img-src ONLY; script-src must stay untouched (no loosening the M9 lockdown).
func TestSecurityHeadersImgSrcAllowsHTTPS(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "img-src 'self' data: blob: https:;") {
		t.Errorf("img-src must allow https: for the remote-image opt-in, got: %s", csp)
	}
	if !strings.Contains(csp, "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval';") {
		t.Errorf("script-src must remain unchanged by the img-src fix (Meet B1 Task 16b already added 'wasm-unsafe-eval'), got: %s", csp)
	}
}

// Meet B1 Task 16b (locked triple-lock delta): background blur's WASM
// segmentation model (@livekit/track-processors/@mediapipe/tasks-vision)
// fails WebAssembly.instantiate under Chromium's CSP without 'wasm-unsafe-eval'
// in script-src. This must be the ONLY script-src change — 'unsafe-inline'
// stays present here (this header's own pre-existing, documented reason,
// unrelated to blur) but must never be joined by anything broader.
func TestSecurityHeadersBlurWasmUnsafeEvalDelta(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval';") {
		t.Errorf("script-src must gain 'wasm-unsafe-eval' for the blur WASM delta, got: %s", csp)
	}
	if strings.Contains(csp, "'unsafe-eval'") && !strings.Contains(csp, "'wasm-unsafe-eval'") {
		t.Errorf("must use the narrow 'wasm-unsafe-eval', never the broad 'unsafe-eval', got: %s", csp)
	}
}

// B1 webmail-UI live gate: camera=() / microphone=() denied getUserMedia to
// the whole gateway-served document — the Meet app (same origin) could never
// publish audio/video, and autoplay=() blocked remote-track playback. The fix
// allows exactly (self) for those three; every other feature stays fully
// denied.
func TestSecurityHeadersPermissionsPolicyAllowsMeetMedia(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	pp := rec.Header().Get("Permissions-Policy")
	if pp == "" {
		t.Fatal("no Permissions-Policy header set")
	}
	for _, want := range []string{"camera=(self)", "microphone=(self)", "autoplay=(self)"} {
		if !strings.Contains(pp, want) {
			t.Errorf("Permissions-Policy must carry %s (Meet publishes media from this origin), got: %s", want, pp)
		}
	}
	for _, denied := range []string{"geolocation=()", "payment=()", "usb=()"} {
		if !strings.Contains(pp, denied) {
			t.Errorf("Permissions-Policy must keep %s fully denied, got: %s", denied, pp)
		}
	}
	if strings.Contains(pp, "document-domain") {
		t.Errorf("Permissions-Policy must not emit the unsupported document-domain directive, got: %s", pp)
	}
}
