package booking_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"setjoin.com/mailserver/internal/booking"
	"setjoin.com/mailserver/internal/middleware"
	"setjoin.com/shared/pgxutil"
	"setjoin.com/shared/toggle"
)

// TestPublicRoutesCarrySecurityHeadersCSP guards against a future mount that
// bypasses middleware.SecurityHeaders: cmd/mailserverd/main.go wraps the
// WHOLE mux in it (secureMux := middleware.SecurityHeaders(sharedmw.CSRF(mux)))
// — this test proves that when the booking PublicHandler is wrapped the SAME
// way, the response still carries frame-ancestors 'none' (the header a <meta>
// CSP cannot express, so it's the one that actually matters for an unauth
// surface embedded nowhere). A nil pool is fine — the toggle-off 404 path
// never touches the DB, and SecurityHeaders sets headers unconditionally
// before the wrapped handler even runs.
func TestPublicRoutesCarrySecurityHeadersCSP(t *testing.T) {
	h := booking.NewPublicHandler(
		pgxutil.WorkerPool{}, // nil pool: fine, toggle is OFF so the DB is never touched
		toggle.NewTestFlags(map[string]bool{"feature.booking_pages": false}),
		nil, "", "https://booking.test", nil, slog.Default(),
	)
	wrapped := middleware.SecurityHeaders(h)

	req := httptest.NewRequest(http.MethodGet, "/api/public/booking/anything", nil)
	req.SetPathValue("slug", "anything")
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("want 404, got %d", rr.Code)
	}
	csp := rr.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("public booking response missing frame-ancestors 'none' in CSP: %q", csp)
	}
	if !strings.Contains(csp, "form-action 'self'") {
		t.Fatalf("public booking response missing form-action 'self' in CSP: %q", csp)
	}
}
