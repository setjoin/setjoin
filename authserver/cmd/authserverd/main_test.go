package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/rs/cors"
	"setjoin.com/authserver/internal/handlers"
)

type countingBody struct {
	reader io.Reader
	read   int
}

func (b *countingBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.read += n
	return n, err
}

func (*countingBody) Close() error { return nil }

func TestLimitRequestBody_PrecedesThreatBodyReader(t *testing.T) {
	source := &countingBody{reader: bytes.NewReader(bytes.Repeat([]byte("x"), int(guestInviteAcceptBodyLimit)+4096))}
	threatReaderCalled := false
	stack := limitRequestBody(guestInviteAcceptBodyLimit, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		threatReaderCalled = true
		_, _ = io.ReadAll(r.Body) // mirrors ThreatInterceptor.extractMeta
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodPost, "/auth/guest-invite/accept", source)
	r.ContentLength = -1 // exercise streaming/chunked input, not a header-only shortcut
	rr := httptest.NewRecorder()

	stack.ServeHTTP(rr, r)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status=%d want 413", rr.Code)
	}
	if threatReaderCalled {
		t.Fatal("outer body cap allowed the threat middleware to read an oversized body")
	}
	if source.read > int(guestInviteAcceptBodyLimit)+1 {
		t.Fatalf("outer cap consumed %d bytes, want at most %d", source.read, guestInviteAcceptBodyLimit+1)
	}
}

func TestLimitRequestBody_ForwardsAcceptedBody(t *testing.T) {
	const body = `{"token":"small"}`
	var got string
	stack := limitRequestBody(guestInviteAcceptBodyLimit, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		got = string(raw)
		w.WriteHeader(http.StatusNoContent)
	}))
	rr := httptest.NewRecorder()
	stack.ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/auth/guest-invite/accept", bytes.NewBufferString(body)))
	if rr.Code != http.StatusNoContent || got != body {
		t.Fatalf("accepted body: status=%d body=%q, want 204 and %q", rr.Code, got, body)
	}
}

func TestOIDCProviderCORSRejectsUnlistedOrigin(t *testing.T) {
	opts := oidcProviderCORSOptions("oidc.example.com", "https://spa.example.com")
	h := cors.New(*opts).Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	for _, tc := range []struct {
		origin      string
		wantAllowed bool
	}{
		{"https://evil.invalid", false},
		{"https://oidc.example.com", true},
		{"https://spa.example.com", true},
	} {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
		req.Header.Set("Origin", tc.origin)
		h.ServeHTTP(rr, req)
		got := rr.Header().Get("Access-Control-Allow-Origin")
		if tc.wantAllowed && got != tc.origin {
			t.Errorf("origin %q ACAO=%q want exact origin", tc.origin, got)
		}
		if !tc.wantAllowed && got != "" {
			t.Errorf("unlisted origin %q unexpectedly allowed as %q", tc.origin, got)
		}
		if rr.Header().Get("Access-Control-Allow-Credentials") != "" {
			t.Errorf("origin %q received credentialed CORS", tc.origin)
		}
	}
}

func TestOIDCProviderCORSNormalizesAndDeduplicatesOrigins(t *testing.T) {
	opts := oidcProviderCORSOptions("oidc.example.com",
		", https://oidc.example.com/, https://spa.example.com/, https://spa.example.com ,")
	want := []string{"https://oidc.example.com", "https://spa.example.com"}
	if !reflect.DeepEqual(opts.AllowedOrigins, want) {
		t.Fatalf("allowed origins = %v, want %v", opts.AllowedOrigins, want)
	}
}

// TestForgotPasswordRoutePatterns verifies that Go 1.22+ ServeMux correctly
// routes requests to the forgot-password endpoints with the exact method+path
// patterns that will be registered in main.go.
func TestForgotPasswordRoutePatterns(t *testing.T) {
	mux := http.NewServeMux()

	// Simulate the 3 routes as they will be registered in main.go.
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	mux.Handle("POST /auth/forgot-password/begin", ok)
	mux.Handle("POST /auth/forgot-password/verify", ok)
	mux.Handle("POST /auth/forgot-password/reset", ok)

	tests := []struct {
		method      string
		path        string
		wantMatched bool
	}{
		// Happy path: correct method + path
		{"POST", "/auth/forgot-password/begin", true},
		{"POST", "/auth/forgot-password/verify", true},
		{"POST", "/auth/forgot-password/reset", true},

		// Wrong method on each path should NOT match
		{"GET", "/auth/forgot-password/begin", false},
		{"GET", "/auth/forgot-password/verify", false},
		{"GET", "/auth/forgot-password/reset", false},
		{"PUT", "/auth/forgot-password/begin", false},
		{"DELETE", "/auth/forgot-password/reset", false},

		// Unregistered paths should NOT match
		{"POST", "/auth/forgot-password/nonexistent", false},
		{"POST", "/auth/forgot-password/", false},
		{"POST", "/auth/forgot-password", false},
	}

	for _, tc := range tests {
		r := httptest.NewRequest(tc.method, tc.path, nil)
		_, pattern := mux.Handler(r)
		matched := pattern != ""
		if matched != tc.wantMatched {
			t.Errorf("%s %s: matched=%v, want=%v", tc.method, tc.path, matched, tc.wantMatched)
		}
	}
}

// TestForgotPasswordRouteRegistrationOrder verifies that the 3 routes
// remain reachable when registered alongside other routes (no pattern
// conflicts with existing routes in main.go).
func TestForgotPasswordRouteRegistrationOrder(t *testing.T) {
	mux := http.NewServeMux()

	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	// Register existing routes that sit near the forgot-password routes in main.go.
	// These are the patterns that come right before and after in the file.
	mux.Handle("POST /auth/backup-codes/generate", ok)
	mux.Handle("POST /auth/backup-codes/verify", ok)
	mux.Handle("POST /auth/admin/users/{id}/impersonate", ok)

	// Forgot-password routes (the new code).
	mux.Handle("POST /auth/forgot-password/begin", ok)
	mux.Handle("POST /auth/forgot-password/verify", ok)
	mux.Handle("POST /auth/forgot-password/reset", ok)

	// All 6 routes must coexist without conflict.
	allRoutes := []struct {
		method string
		path   string
	}{
		{"POST", "/auth/backup-codes/generate"},
		{"POST", "/auth/backup-codes/verify"},
		{"POST", "/auth/admin/users/17/impersonate"},
		{"POST", "/auth/forgot-password/begin"},
		{"POST", "/auth/forgot-password/verify"},
		{"POST", "/auth/forgot-password/reset"},
	}

	for _, rt := range allRoutes {
		r := httptest.NewRequest(rt.method, rt.path, nil)
		_, pattern := mux.Handler(r)
		if pattern == "" {
			t.Errorf("expected route %s %s to be registered, but it was not found", rt.method, rt.path)
		}
	}
}

// TestForgotPasswordHandlerMethodsCompile verifies that the ForgotPassword
// handler methods on *handlers.AuthHandler exist and are compatible with
// http.HandlerFunc, which is required for mux.Handle registration in main.go.
//
// This is a compile-time assertion: if any of these method signatures
// change, this test will fail to compile, catching the mismatch before
// runtime.
func TestForgotPasswordHandlerMethodsCompile(t *testing.T) {
	// The forgot-password handler methods must be compatible with
	// http.HandlerFunc (func(http.ResponseWriter, *http.Request)).
	// We verify this by assigning them to http.HandlerFunc variables.
	// This is a compile-time check only; no runtime behavior is tested.

	// These assignments prove that:
	// 1. The methods exist on *AuthHandler
	// 2. They have the correct signature for mux.Handle
	var _ http.HandlerFunc = (&handlers.AuthHandler{}).ForgotPasswordBegin
	var _ http.HandlerFunc = (&handlers.AuthHandler{}).ForgotPasswordVerify
	var _ http.HandlerFunc = (&handlers.AuthHandler{}).ForgotPasswordReset
}
