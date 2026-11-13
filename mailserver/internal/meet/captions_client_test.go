// captions_client_test.go — B3 Task 18 pipeline-review finding 1 (gateway
// follow-up): hermetic proof that httpCaptionsClient (captions.go) sends
// `Authorization: Bearer <token>` on every asrbot control-API call
// (/start, /stop, /status) — the header asrbot's own requireAuth now
// demands (asrbot/internal/bot/server.go). No DB/LiveKit/asrbot involved:
// a plain httptest.Server standing in for the loopback control API, the
// fakeCaptions genre applied to the REAL client instead of the double.
package meet

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHTTPCaptionsClientSendsBearerToken pins the header on all three
// routes when NewCaptionsClient is given a non-empty token.
func TestHTTPCaptionsClientSendsBearerToken(t *testing.T) {
	var gotAuth []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = append(gotAuth, r.Header.Get("Authorization"))
		if r.URL.Path == "/status" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"rooms":[]}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewCaptionsClient(srv.URL, "secret-token")

	if err := c.Start(context.Background(), "room-1", "jwt-token"); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := c.Stop(context.Background(), "room-1"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if _, err := c.Status(context.Background()); err != nil {
		t.Fatalf("Status: %v", err)
	}

	if len(gotAuth) != 3 {
		t.Fatalf("want 3 requests (start/stop/status), got %d", len(gotAuth))
	}
	for i, auth := range gotAuth {
		if auth != "Bearer secret-token" {
			t.Errorf("request %d: Authorization = %q, want %q", i, auth, "Bearer secret-token")
		}
	}
}

// TestHTTPCaptionsClientEmptyTokenSendsNoHeader pins the nil/empty-safe
// posture: an empty ASRToken (ASR_URL configured but ASR_TOKEN unset — a
// deploy misconfiguration, not a Go panic) sends no Authorization header at
// all rather than "Bearer " with an empty value.
func TestHTTPCaptionsClientEmptyTokenSendsNoHeader(t *testing.T) {
	var gotAuth string
	var sawHeader bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, sawHeader = r.Header.Get("Authorization"), r.Header["Authorization"] != nil
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewCaptionsClient(srv.URL, "")
	if err := c.Stop(context.Background(), "room-1"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if sawHeader {
		t.Errorf("want no Authorization header with an empty token, got %q", gotAuth)
	}
}
