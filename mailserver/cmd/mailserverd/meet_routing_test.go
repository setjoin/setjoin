package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestMeetWebhookRoute_ServeMuxPrecedence proves the Task 13 wiring's central
// safety claim (eng #6, "no dangling deferral"): POST /meet/webhook — LiveKit's
// unauthenticated inbound fact channel — reaches its own handler even though
// it is registered ALONGSIDE the requireAuth-wrapped "/meet/" prefix mount,
// because Go 1.22 ServeMux always prefers the more specific of two matching
// patterns regardless of registration order. An unauthenticated request to
// any OTHER /meet path must still 401 through the wrapped mount.
//
// Mirrors TestImpersonateRoute_ServeMuxPrecedence's shape (a real
// http.ServeMux, patterns registered exactly as main.go's registerUserRoutes
// does, fake handlers that stamp which one served the request).
func TestMeetWebhookRoute_ServeMuxPrecedence(t *testing.T) {
	const (
		headerHandler = "X-Handler"
		valWebhook    = "webhook"
		valMeet       = "meet"
	)

	webhookHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerHandler, valWebhook)
		w.WriteHeader(http.StatusOK)
	})

	// requireAuthStub models d.requireAuth: 401 with no downstream call when
	// the (test-simulated) request carries no auth, exactly what an
	// unauthenticated /meet request must see — the wrapped meetH handler
	// itself is never reached in that case, and the fixture proves that by
	// never stamping X-Handler.
	meetHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerHandler, valMeet)
		w.WriteHeader(http.StatusOK)
	})
	requireAuthStub := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}

	mux := http.NewServeMux()
	// Register in the same order as registerUserRoutes: the prefix mount
	// first, the bare collection, then the specific webhook pattern.
	mux.Handle("/meet/", requireAuthStub(meetHandler))
	mux.Handle("/meet", requireAuthStub(meetHandler))
	mux.Handle("POST /meet/webhook", webhookHandler)

	tests := []struct {
		name       string
		method     string
		path       string
		authed     bool
		wantStatus int
		wantHdr    string // "" = don't check (401 short-circuits before any handler stamps it)
	}{
		{
			name:       "unauthenticated signed webhook POST reaches the webhook handler",
			method:     http.MethodPost,
			path:       "/meet/webhook",
			authed:     false,
			wantStatus: http.StatusOK,
			wantHdr:    valWebhook,
		},
		{
			name:       "unauthenticated POST /meet stays 401",
			method:     http.MethodPost,
			path:       "/meet",
			authed:     false,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "unauthenticated GET /meet stays 401",
			method:     http.MethodGet,
			path:       "/meet",
			authed:     false,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "unauthenticated GET /meet/42 (sibling under the prefix) stays 401",
			method:     http.MethodGet,
			path:       "/meet/42",
			authed:     false,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "authenticated GET /meet reaches the meet handler",
			method:     http.MethodGet,
			path:       "/meet",
			authed:     true,
			wantStatus: http.StatusOK,
			wantHdr:    valMeet,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.authed {
				req.Header.Set("Authorization", "Bearer test")
			}
			h, _ := mux.Handler(req)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Errorf("%s %s: status = %d, want %d", tc.method, tc.path, rec.Code, tc.wantStatus)
			}
			if tc.wantHdr != "" {
				if got := rec.Header().Get(headerHandler); got != tc.wantHdr {
					t.Errorf("%s %s: routed to %q, want %q", tc.method, tc.path, got, tc.wantHdr)
				}
			}
		})
	}
}
