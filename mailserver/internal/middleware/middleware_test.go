package middleware

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// --- RateLimiter tests ---

func TestRateLimiterAllowFirstRequest(t *testing.T) {
	rl := NewRateLimiter(5, time.Minute)
	if !rl.Allow("192.168.1.1") {
		t.Error("first request should be allowed")
	}
}

func TestRateLimiterBlocksAfterLimit(t *testing.T) {
	rl := NewRateLimiter(2, time.Minute)
	rl.Allow("10.0.0.1")
	rl.Allow("10.0.0.1")
	if rl.Allow("10.0.0.1") {
		t.Error("third request should be blocked")
	}
}

func TestRateLimiterResetsAfterWindow(t *testing.T) {
	rl := NewRateLimiter(1, time.Millisecond)
	rl.Allow("10.0.0.2")
	time.Sleep(2 * time.Millisecond)
	if !rl.Allow("10.0.0.2") {
		t.Error("request after window expiry should be allowed")
	}
}

func TestRateLimiterCleanup(t *testing.T) {
	rl := NewRateLimiter(1, time.Millisecond)
	rl.Allow("10.0.0.3")
	time.Sleep(2 * time.Millisecond)
	rl.Cleanup()
	rl.mu.Lock()
	_, exists := rl.entries["10.0.0.3"]
	rl.mu.Unlock()
	if exists {
		t.Error("expired entry should be cleaned up")
	}
}

func TestRateLimiterIsolatedPerKey(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)
	rl.Allow("a")
	if !rl.Allow("b") {
		t.Error("different key should not be affected")
	}
}

// --- HybridRateLimiter eviction ---

func TestHybridRateLimiterPrunesStaleLocalEntries(t *testing.T) {
	rl := &HybridRateLimiter{
		local:     make(map[string]*windowCounter),
		dirtyKeys: make(map[string]bool),
		limit:     10,
		window:    1 * time.Second,
		syncEvery: 5 * time.Second,
	}

	// Add an old entry that should be pruned (>2*window old).
	oldStart := time.Now().Add(-5 * time.Second).Unix()
	rl.local["old-key"] = &windowCounter{startTime: oldStart, count: 1}

	// Add a fresh entry that should survive.
	freshStart := time.Now().Unix()
	rl.local["fresh-key"] = &windowCounter{startTime: freshStart, count: 1}

	rl.pruneStale()

	rl.mu.Lock()
	defer rl.mu.Unlock()
	if _, exists := rl.local["old-key"]; exists {
		t.Error("stale entry should be pruned from local map")
	}
	if _, exists := rl.local["fresh-key"]; !exists {
		t.Error("fresh entry should survive pruning")
	}
}

// --- clientIP tests ---

func TestClientIPWithoutXFF(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	ip := clientIP(req)
	if ip != "192.168.1.100" {
		t.Errorf("clientIP = %q, want 192.168.1.100", ip)
	}
}

func TestClientIPWithTrustedXFF(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.1, 192.168.1.1")
	ip := clientIP(req)
	// Rightmost XFF entry (the one the trusted proxy itself appended) wins;
	// the leading entry is attacker-controlled. See shared/clientip.
	if ip != "192.168.1.1" {
		t.Errorf("clientIP = %q, want 192.168.1.1", ip)
	}
}

func TestClientIPWithUntrustedXFF(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.1:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	ip := clientIP(req)
	if ip != "203.0.113.1" {
		t.Errorf("clientIP = %q, want 203.0.113.1", ip)
	}
}

func TestClientIPWithSingleXFF(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("X-Forwarded-For", "10.0.0.5")
	ip := clientIP(req)
	if ip != "10.0.0.5" {
		t.Errorf("clientIP = %q, want 10.0.0.5", ip)
	}
}

func TestSetTrustedProxiesExactIP(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.1", "192.168.0.0/16"})
	defer SetTrustedProxies([]string{"127.0.0.1", "::1"}) // restore default

	if !isTrustedProxy("10.0.0.1") {
		t.Error("exact IP 10.0.0.1 should be trusted")
	}
	if isTrustedProxy("10.0.0.2") {
		t.Error("10.0.0.2 should not match exact IP 10.0.0.1")
	}
}

func TestSetTrustedProxiesCIDR(t *testing.T) {
	SetTrustedProxies([]string{"10.0.0.0/8", "172.16.0.0/12"})
	defer SetTrustedProxies([]string{"127.0.0.1", "::1"})

	tests := []struct {
		ip      string
		trusted bool
	}{
		{"10.1.2.3", true},
		{"10.255.255.255", true},
		{"172.16.0.1", true},
		{"172.31.255.254", true},
		{"192.168.1.1", false},
		{"11.0.0.1", false},
	}
	for _, tc := range tests {
		if got := isTrustedProxy(tc.ip); got != tc.trusted {
			t.Errorf("isTrustedProxy(%q) = %v, want %v", tc.ip, got, tc.trusted)
		}
	}
}

// --- SecurityHeaders tests ---

func TestSecurityHeaders(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := SecurityHeaders(next)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	checks := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
	}
	for header, want := range checks {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if csp == "" {
		t.Error("CSP header missing")
	}
	// Every directive that gives this CSP its defense-in-depth value must be present.
	for _, directive := range []string{
		"default-src 'self'",
		"object-src 'self' blob:",
		"base-uri 'self'",
		"form-action 'self'",
		"frame-ancestors 'none'", // clickjacking control (modern X-Frame-Options)
		"frame-src 'self'",
	} {
		if !contains(csp, directive) {
			t.Errorf("CSP missing %q directive: %q", directive, csp)
		}
	}
}

// TestSecurityHeaders_ObjectSrcAllowsSecureViewerBlobPreview is the B5 fix
// (2026-07-11 codebase review): object-src governs <object>/<embed>/<applet>
// resource loading, so a bare "object-src 'none'" silently killed
// SecureViewer.svelte's <embed type="application/pdf" src={blob:...}> render
// for every PDF/ready-office-rendition preview -- the preview just came up
// empty, no error, no console signal a user would report. object-src must
// permit same-origin + blob: (the RAM-blob URL SecureViewer always uses) --
// still zero remote origins, and script-src is untouched.
func TestSecurityHeaders_ObjectSrcAllowsSecureViewerBlobPreview(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	rec := httptest.NewRecorder()
	SecurityHeaders(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	csp := rec.Header().Get("Content-Security-Policy")
	if contains(csp, "object-src 'none'") {
		t.Errorf("object-src 'none' blocks the SecureViewer <embed> blob preview entirely: %q", csp)
	}
	if !contains(csp, "object-src 'self' blob:") {
		t.Errorf("object-src must allow 'self' and 'blob:' (and nothing broader) for the preview: %q", csp)
	}
}

func TestHSTS(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := HSTS(next)
	req := httptest.NewRequest(http.MethodGet, "https://localhost/", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	hsts := rec.Header().Get("Strict-Transport-Security")
	if hsts == "" {
		t.Error("HSTS header missing")
	}
	if !contains(hsts, "max-age=63072000") {
		t.Errorf("HSTS max-age incorrect: %q", hsts)
	}

	// Verify HSTS is NOT added to plain HTTP requests
	plainReq := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
	plainRec := httptest.NewRecorder()
	handler.ServeHTTP(plainRec, plainReq)
	if plainRec.Header().Get("Strict-Transport-Security") != "" {
		t.Error("HSTS should not be added to plain HTTP requests")
	}
}

// --- MetricsAuth tests ---

// TestMetricsAuthNoToken: fail-closed by default. No METRICS_TOKEN and no
// opt-out set means /metrics must refuse the request, not serve it.
func TestMetricsAuthNoToken(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	})
	handler := MetricsAuth(next)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401 (fail-closed when METRICS_TOKEN unset)", rec.Code)
	}
}

// TestMetricsAuthNoTokenWithOptOut: the explicit escape hatch. No
// METRICS_TOKEN but METRICS_ALLOW_UNAUTHENTICATED=1 set means /metrics keeps
// the old warn-and-allow behavior.
func TestMetricsAuthNoTokenWithOptOut(t *testing.T) {
	os.Setenv("METRICS_ALLOW_UNAUTHENTICATED", "1")
	defer os.Unsetenv("METRICS_ALLOW_UNAUTHENTICATED")

	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	handler := MetricsAuth(next)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200 (opt-out set)", rec.Code)
	}
	if !called {
		t.Error("next handler should have been called under the opt-out")
	}
}

func TestMetricsAuthWithValidToken(t *testing.T) {
	os.Setenv("METRICS_TOKEN", "secret-token")
	defer os.Unsetenv("METRICS_TOKEN")

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := MetricsAuth(next)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestMetricsAuthWithInvalidToken(t *testing.T) {
	os.Setenv("METRICS_TOKEN", "secret-token")
	defer os.Unsetenv("METRICS_TOKEN")

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	})
	handler := MetricsAuth(next)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestMetricsAuthMissingHeader(t *testing.T) {
	os.Setenv("METRICS_TOKEN", "secret-token")
	defer os.Unsetenv("METRICS_TOKEN")

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	})
	handler := MetricsAuth(next)
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr))
}

func containsAt(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
