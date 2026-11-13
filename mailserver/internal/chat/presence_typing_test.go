// presence_typing_test.go — Pillar C2 Task 6: the OUTBOUND half of federated
// typing (Q5 — "federated typing", never "presence"). The inbound half +
// the wire/reducer trust matrix live in mailserver/internal/federation
// (ephemeral_test.go) and mailserver/sql/tests/federation_typing.pg.
//
// federationTypingDebounced is pure in-memory logic (a map + a mutex) that
// MUST run — and decide — before any DB work (the codex-hardened Q5
// ordering: a noisy client must not create local DB load even while wire
// frames would end up dropped anyway). Constructing the Handler with a nil
// pool here is the proof: if federationTypingDebounced ever touched h.pool,
// any of these calls would panic instead of returning a plain bool.
package chat

import (
	"log/slog"
	"testing"
	"time"

	"setjoin.com/shared/toggle"
)

func TestFederationTypingDebounced(t *testing.T) {
	// pool: nil — a real DB touch inside federationTypingDebounced would
	// panic here, so a clean pass is itself proof of zero DB work.
	h := NewHandler(nil, toggle.NewTestFlags(nil), slog.Default())

	if h.federationTypingDebounced(1) {
		t.Fatal("the first typing signal for a channel must be admitted (not debounced)")
	}
	if !h.federationTypingDebounced(1) {
		t.Fatal("a second signal for the SAME channel inside the floor must be debounced")
	}
	if !h.federationTypingDebounced(1) {
		t.Fatal("a third signal still inside the floor must also be debounced")
	}

	// A different channel is unaffected by channel 1's debounce state — the
	// map is keyed per-channel, not global.
	if h.federationTypingDebounced(2) {
		t.Fatal("a different channel must be admitted independently of channel 1's debounce state")
	}

	// Simulate the floor elapsing (no real sleep — backdate the recorded
	// timestamp directly, same shape as the federation package's tokenBucket
	// refill test).
	h.typingDebounceMu.Lock()
	h.typingDebounce[1] = time.Now().Add(-2 * typingDebounceFloor)
	h.typingDebounceMu.Unlock()

	if h.federationTypingDebounced(1) {
		t.Fatal("once the debounce floor has elapsed, the next signal must be admitted again")
	}
	if !h.federationTypingDebounced(1) {
		t.Fatal("immediately after being re-admitted, the very next call must debounce again")
	}
}

// TestSetFederationTypingNilSafe proves the SetUnfurl-idiom nil-safety: a
// Handler that never had SetFederationTyping called (every box without
// FEDERATION_LOCAL_DOMAIN/_CERT/_KEY configured) has federationTyping == nil,
// so typingSignal's dispatch guard (`if debounced || h.federationTyping ==
// nil { return }`) short-circuits — never invoking anything, never touching
// the federation package at all.
func TestSetFederationTypingNilSafe(t *testing.T) {
	h := NewHandler(nil, toggle.NewTestFlags(nil), slog.Default())
	if h.federationTyping != nil {
		t.Fatal("federationTyping must be nil until SetFederationTyping is called")
	}
}
