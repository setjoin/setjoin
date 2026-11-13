package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestOIDCProviderRoutesReachAuthProxy(t *testing.T) {
	proxied := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Setjoin-Test-Handler", "auth-proxy")
		w.WriteHeader(http.StatusNoContent)
	})
	passthrough := func(next http.Handler) http.Handler { return next }
	d := &gatewayDeps{
		authProxy:                proxied,
		authLimit:                passthrough,
		requireAuth:              passthrough,
		requireIdentityWrite:     passthrough,
		requireUsersImpersonate:  passthrough,
		requireImpersonateTarget: passthrough,
	}
	mux := http.NewServeMux()
	d.registerAuthProxyRoutes(mux)

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/.well-known/openid-configuration"},
		{http.MethodGet, "/.well-known/oauth-authorization-server"},
		{http.MethodGet, "/.well-known/jwks.json"},
		{http.MethodGet, "/keys"},
		{http.MethodGet, "/authorize?client_id=test"},
		{http.MethodGet, "/authorize/callback?id=request"},
		{http.MethodPost, "/oauth/token"},
		{http.MethodPost, "/oauth/introspect"},
		{http.MethodGet, "/userinfo"},
		{http.MethodGet, "/end_session"},
		{http.MethodPost, "/revoke"},
	}
	for _, tt := range tests {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
			}
			if got := rec.Header().Get("X-Setjoin-Test-Handler"); got != "auth-proxy" {
				t.Fatalf("handler marker = %q, want auth-proxy", got)
			}
		})
	}
}

func TestPreAuthGuestBootstrapRoutesReachAuthProxy(t *testing.T) {
	proxied := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Setjoin-Test-Handler", "auth-proxy")
		w.WriteHeader(http.StatusNoContent)
	})
	passthrough := func(next http.Handler) http.Handler { return next }
	d := &gatewayDeps{
		authProxy:                proxied,
		authLimit:                passthrough,
		requireAuth:              passthrough,
		requireIdentityWrite:     passthrough,
		requireUsersImpersonate:  passthrough,
		requireImpersonateTarget: passthrough,
	}
	mux := http.NewServeMux()
	d.registerAuthProxyRoutes(mux)

	for _, path := range []string{
		"/auth/password-policy",
		"/auth/guest-invite/accept?token=opaque",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if rec.Code != http.StatusNoContent {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusNoContent)
			}
			if got := rec.Header().Get("X-Setjoin-Test-Handler"); got != "auth-proxy" {
				t.Fatalf("handler marker = %q, want auth-proxy", got)
			}
		})
	}
}

func TestOAuthUnknownSubtreeDoesNotReachAuthProxy(t *testing.T) {
	proxied := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Setjoin-Test-Handler", "auth-proxy")
		w.WriteHeader(http.StatusNoContent)
	})
	passthrough := func(next http.Handler) http.Handler { return next }
	d := &gatewayDeps{
		authProxy:                proxied,
		authLimit:                passthrough,
		requireAuth:              passthrough,
		requireIdentityWrite:     passthrough,
		requireUsersImpersonate:  passthrough,
		requireImpersonateTarget: passthrough,
	}
	mux := http.NewServeMux()
	d.registerAuthProxyRoutes(mux)

	for _, path := range []string{
		"/oauth",
		"/oauth/admin",
		"/oauth/unknown",
		"/authorize/unknown",
	} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if got := rec.Header().Get("X-Setjoin-Test-Handler"); got == "auth-proxy" {
				t.Fatalf("%s reached auth proxy, want unregistered", path)
			}
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
			}
		})
	}
}

func TestOIDCProviderPathsStayAtURLRoot(t *testing.T) {
	for _, path := range []string{
		"/.well-known/openid-configuration",
		"/.well-known/oauth-authorization-server",
		"/.well-known/jwks.json",
		"/keys",
		"/authorize",
		"/authorize/callback",
		"/oauth/token",
		"/oauth/introspect",
		"/userinfo",
		"/end_session",
		"/revoke",
	} {
		if !isPinnedPath(path) {
			t.Errorf("isPinnedPath(%q) = false, want true", path)
		}
	}
	if isPinnedPath("/oauthical") {
		t.Error("isPinnedPath(/oauthical) = true, want false")
	}
	if !isPinnedPath("/oauth/admin") {
		t.Error("isPinnedPath(/oauth/admin) = false, want true for the local 404 namespace sink")
	}
}
