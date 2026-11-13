package middleware_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/authserver/internal/middleware"
	"setjoin.com/authserver/internal/token"
	"setjoin.com/shared/jwtutil"
	"setjoin.com/shared/threat"
)

// stubAuthenticator is a fake shared/auth.Authenticator so the middleware test
// depends on the seam, not on a concrete *token.JWTProvider.
type stubAuthenticator struct {
	email string
	err   error
}

func (s stubAuthenticator) Authenticate(_ context.Context, _ *http.Request) (*jwtutil.Claims, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &jwtutil.Claims{Email: s.email, Type: jwtutil.TypeAccess}, nil
}

func runMiddleware(t *testing.T, authn stubAuthenticator) (*httptest.ResponseRecorder, bool) {
	t.Helper()
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	mw := middleware.RequireAuth(authn, slog.Default())
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	mw(next).ServeHTTP(rec, req)
	return rec, called
}

func TestRequireAuth_DelegatesToAuthenticator_OK(t *testing.T) {
	rec, called := runMiddleware(t, stubAuthenticator{email: "x@y"})
	if !called {
		t.Fatal("authenticated request must reach the next handler")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestRequireAuth_Anonymous_401(t *testing.T) {
	rec, called := runMiddleware(t, stubAuthenticator{err: token.ErrNoBearer})
	if called {
		t.Fatal("unauthenticated request must NOT reach the next handler")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("401 must carry a WWW-Authenticate challenge")
	}
}

// TestRequireAuth_WrongTokenType_403 is the LOCKED 403-parity test: a valid token
// of the wrong type must yield 403 (not 401), matching the pre-seam middleware's
// "Invalid token type" 403 response.
func TestRequireAuth_WrongTokenType_403(t *testing.T) {
	rec, called := runMiddleware(t, stubAuthenticator{err: token.ErrWrongTokenType})
	if called {
		t.Fatal("wrong-token-type request must NOT reach the next handler")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (token-type parity)", rec.Code)
	}
}

func TestRequireAuthOrRedirect_AnonymousPreservesRelativeContinuation(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	mw := middleware.RequireAuthOrRedirect(
		stubAuthenticator{err: token.ErrNoBearer},
		"/",
	)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(
		http.MethodGet,
		"/auth/oidc/op/complete?id=request-1",
		nil,
	)

	mw(next).ServeHTTP(rec, req)

	if called {
		t.Fatal("anonymous request reached completion handler")
	}
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/?continue=%2Fauth%2Foidc%2Fop%2Fcomplete%3Fid%3Drequest-1" {
		t.Fatalf("Location = %q", got)
	}
}

func TestRequireAuthOrRedirectRejectsWrongTokenType(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })
	mw := middleware.RequireAuthOrRedirect(
		stubAuthenticator{err: token.ErrWrongTokenType}, "/",
	)
	rec := httptest.NewRecorder()
	mw(next).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/authorize?id=request-1", nil))
	if called || rec.Code != http.StatusForbidden {
		t.Fatalf("wrong-token response = status:%d called:%t, want 403/false", rec.Code, called)
	}
}

func TestRequireAuthOrRedirect_AuthenticatedReachesHandler(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	mw := middleware.RequireAuthOrRedirect(stubAuthenticator{email: "x@y"}, "/")
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(
		http.MethodGet,
		"/auth/oidc/op/complete?id=request-1",
		nil,
	)

	mw(next).ServeHTTP(rec, req)

	if !called {
		t.Fatal("authenticated request did not reach completion handler")
	}
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", rec.Code)
	}
}

// TestRequireAuth_TokenBindingRefusalCarriesAdmissionMarker is the per-tab
// recovery contract's middleware half: a DPoP/token-binding refusal
// (token.ErrTokenBinding) keeps the 401 + WWW-Authenticate shape but marks the
// problem body with threat.DPoPAdmissionCode — the ONLY 401 the webmail client
// may replay after its /auth/session/token recovery, because the session is
// alive and only the per-tab proof was inadmissible.
func TestRequireAuth_TokenBindingRefusalCarriesAdmissionMarker(t *testing.T) {
	rec, called := runMiddleware(t, stubAuthenticator{err: token.ErrTokenBinding})
	if called {
		t.Fatal("token-binding-refused request must NOT reach the next handler")
	}
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	if rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("401 must carry a WWW-Authenticate challenge")
	}
	var body struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode problem body %s: %v", rec.Body.String(), err)
	}
	if body.Code != threat.DPoPAdmissionCode {
		t.Fatalf("problem code = %q, want %q — without the admission marker the client cannot tell a replayable refusal from a committed one", body.Code, threat.DPoPAdmissionCode)
	}
}

// The negative half of the marker contract: every OTHER authentication refusal
// stays marker-free, so a genuinely dead/absent session can never drive a
// replay loop.
func TestRequireAuth_OtherAuthFailuresStayUnmarked(t *testing.T) {
	for _, err := range []error{token.ErrNoBearer, token.ErrRevoked} {
		rec, called := runMiddleware(t, stubAuthenticator{err: err})
		if called || rec.Code != http.StatusUnauthorized {
			t.Fatalf("%v: status = %d called = %t, want 401/false", err, rec.Code, called)
		}
		var body struct {
			Code string `json:"code"`
		}
		if jsonErr := json.Unmarshal(rec.Body.Bytes(), &body); jsonErr != nil {
			t.Fatalf("%v: decode problem body %s: %v", err, rec.Body.String(), jsonErr)
		}
		if body.Code == threat.DPoPAdmissionCode {
			t.Fatalf("%v: refusal must NOT carry the admission marker", err)
		}
	}
}
