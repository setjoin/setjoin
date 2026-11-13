package chat

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"setjoin.com/mailserver/internal/auth"
	"setjoin.com/shared/toggle"
)

// TestPresenceRegistryConnectDisconnect pins the counter semantics (grill
// Q2): multiple connections for the same user (multi-tab/device) must all
// close before the user reads offline again — a naive boolean flag would
// flip a still-connected user offline the instant their SECOND tab closes.
func TestPresenceRegistryConnectDisconnect(t *testing.T) {
	r := &PresenceRegistry{counts: make(map[int64]int)}
	if r.IsOnline(1) {
		t.Fatalf("user 1 must start offline")
	}
	r.Connect(1)
	if !r.IsOnline(1) {
		t.Fatalf("user 1 must be online after Connect")
	}
	r.Connect(1) // second tab/device
	r.Disconnect(1)
	if !r.IsOnline(1) {
		t.Fatalf("user 1 must STILL be online — one of two connections closed, one remains")
	}
	r.Disconnect(1)
	if r.IsOnline(1) {
		t.Fatalf("user 1 must be offline once both connections have closed")
	}
	// Disconnect on an already-empty entry must not underflow into a
	// phantom "online" state.
	r.Disconnect(1)
	if r.IsOnline(1) {
		t.Fatalf("an extra Disconnect past zero must not make the user online")
	}
}

// TestGetPresenceRoute pins GET /chat/presence?userIds= — no DB, no push,
// pure in-memory lookup (M2/grill Q2). Uses the package-level Presence
// registry that ws/handler.go and ws/eventsource.go connect to.
func TestGetPresenceRoute(t *testing.T) {
	Presence.mu.Lock()
	Presence.counts = make(map[int64]int) // isolate from any other test in this package
	Presence.mu.Unlock()
	Presence.Connect(42)

	h := NewHandler(nil, toggle.NewTestFlags(map[string]bool{"feature.chat": true}), slog.Default())
	r := httptest.NewRequest("GET", "/chat/presence?userIds=42,43", nil)
	r = r.WithContext(auth.ContextWithUser(r.Context(), &auth.Claims{UserID: 42}))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var out map[string]bool
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !out["42"] {
		t.Errorf("user 42 must read online: %v", out)
	}
	if out["43"] {
		t.Errorf("user 43 must read offline: %v", out)
	}

	Presence.Disconnect(42)
}
