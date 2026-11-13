package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"setjoin.com/authserver/internal/token"
)

type fakeOIDCAuthRequestCompleter struct {
	id       string
	userID   int64
	authTime time.Time
	acr      string
	amr      []string
	err      error
}

func (f *fakeOIDCAuthRequestCompleter) CompleteAuthRequest(
	_ context.Context,
	id string,
	userID int64,
	authTime time.Time,
	acr string,
	amr []string,
) error {
	f.id = id
	f.userID = userID
	f.authTime = authTime
	f.acr = acr
	f.amr = append([]string(nil), amr...)
	return f.err
}

func TestOIDCProviderCompleteBindsAuthenticatedSession(t *testing.T) {
	completer := &fakeOIDCAuthRequestCompleter{}
	h := &OIDCProviderCompleteHandler{Completer: completer}
	authAt := time.Now().Add(-time.Minute).Unix()
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/op/complete?id=req-1", nil)
	req = req.WithContext(ContextWithUser(req.Context(), &token.Claims{
		UserID:          42,
		ACR:             "aal2",
		AMR:             []string{"pwd", "otp", "mfa"},
		SessionAuthTime: &authAt,
	}))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	if got := rec.Header().Get("Location"); got != "/authorize/callback?id=req-1" {
		t.Fatalf("Location = %q", got)
	}
	if completer.id != "req-1" || completer.userID != 42 {
		t.Fatalf("completion = (%q,%d), want (req-1,42)", completer.id, completer.userID)
	}
	if completer.acr != "aal2" || len(completer.amr) != 3 {
		t.Fatalf("auth context = (%q,%v)", completer.acr, completer.amr)
	}
	if completer.authTime.Unix() != authAt {
		t.Fatalf("auth time = %v, want %v", completer.authTime.Unix(), authAt)
	}
}

func TestOIDCProviderCompleteRejectsMissingSessionOrRequest(t *testing.T) {
	h := &OIDCProviderCompleteHandler{Completer: &fakeOIDCAuthRequestCompleter{}}
	for _, tc := range []struct {
		name   string
		claims *token.Claims
		path   string
		status int
	}{
		{"missing session", nil, "/auth/oidc/op/complete?id=req-1", http.StatusUnauthorized},
		{"missing request", &token.Claims{UserID: 42}, "/auth/oidc/op/complete", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			if tc.claims != nil {
				req = req.WithContext(ContextWithUser(req.Context(), tc.claims))
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d", rec.Code, tc.status)
			}
		})
	}
}

func TestOIDCProviderCompleteRejectsConsumedOrForeignRequest(t *testing.T) {
	completer := &fakeOIDCAuthRequestCompleter{err: errors.New("request already completed")}
	h := &OIDCProviderCompleteHandler{Completer: completer}
	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/op/complete?id=req-1", nil)
	req = req.WithContext(ContextWithUser(req.Context(), &token.Claims{UserID: 42}))
	rec := httptest.NewRecorder()

	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if completer.id != "req-1" || completer.userID != 42 {
		t.Fatalf("completion boundary was not exercised: (%q,%d)", completer.id, completer.userID)
	}
}
