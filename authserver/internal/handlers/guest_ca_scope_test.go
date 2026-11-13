package handlers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/shared/threat"
)

func TestPopulateGuestCAScopeUsesAuthoritativeResolver(t *testing.T) {
	d := &deps{guestScopeResolver: func(_ context.Context, userID int64) (bool, error) {
		if userID != 42 {
			t.Fatalf("resolver user id = %d, want 42", userID)
		}
		return true, nil
	}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	pectx := threat.PolicyEvalContext{}
	if !d.populateGuestCAScope(w, r, &pectx, 42) {
		t.Fatal("authoritative guest lookup unexpectedly stopped evaluation")
	}
	if !pectx.IsGuest {
		t.Fatal("authoritative guest lookup did not set IsGuest")
	}
}

func TestPopulateGuestCAScopeFailsClosedOnLookupError(t *testing.T) {
	d := &deps{guestScopeResolver: func(context.Context, int64) (bool, error) {
		return false, errors.New("database unavailable")
	}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	pectx := threat.PolicyEvalContext{}
	if d.populateGuestCAScope(w, r, &pectx, 42) {
		t.Fatal("failed guest lookup must stop conditional-access evaluation")
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("lookup failure status = %d, want 503", w.Code)
	}
	if pectx.IsGuest {
		t.Fatal("lookup failure must not synthesize guest scope")
	}
}
